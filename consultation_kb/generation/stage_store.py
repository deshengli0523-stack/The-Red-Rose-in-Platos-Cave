"""Append-only, client-scoped generation artifact storage."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Protocol, cast

from pydantic import ValidationError

from consultation_kb.generation.contracts import (
    FinalTurnBundle,
    GenerationStagePayload,
    QueryPlan,
    validate_generation_payload,
    validate_generation_payload_json,
)
from consultation_kb.generation.query_planning import QueryPlanValidator
from consultation_kb.generation.state_machine import (
    GENERATION_STAGE_ORDER,
    GenerationStateMachine,
)
from consultation_kb.models.common import (
    ObjectId,
    PositiveInt,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    Uuid7String,
)
from consultation_kb.models.generation import GenerationStageName
from consultation_kb.models.session import (
    CandidateReply,
    CandidateSet,
    StoredContentRef,
)
from consultation_kb.session.candidate_sets import (
    CandidateSetConflict,
    candidate_set_from_database,
)
from consultation_kb.session.repository import (
    SessionRepository,
    TurnStateConflict,
    _parse_utc,
    _utc_text,
)
from consultation_kb.storage.connection import transaction


class GenerationStageStoreError(RuntimeError):
    """Base fixed-code stage-store error."""


class GenerationBindingMismatch(GenerationStageStoreError):
    def __init__(self) -> None:
        super().__init__("GENERATION_BINDING_MISMATCH")


class GenerationStageConflict(GenerationStageStoreError):
    def __init__(self, code: str = "GENERATION_STAGE_CONFLICT") -> None:
        super().__init__(code)


class GenerationStageRevisionRequired(GenerationStageStoreError):
    def __init__(self) -> None:
        super().__init__("GENERATION_STAGE_REVISION_REASON_REQUIRED")


class GenerationStageIntegrityError(GenerationStageStoreError):
    def __init__(self) -> None:
        super().__init__("GENERATION_STAGE_INTEGRITY_ERROR")


class GenerationTurnContext(StrictModel):
    session_id: Uuid7String
    turn_id: Uuid7String
    run_id: Uuid7String


class GenerationStageRecord(StrictModel):
    stage_revision_id: ObjectId
    session_id: Uuid7String
    turn_id: Uuid7String
    run_id: Uuid7String
    stage: GenerationStageName
    revision: PositiveInt
    idempotency_key_sha256: Sha256Hex
    artifact: StoredContentRef
    parent_sha256s: tuple[Sha256Hex, ...]
    revision_reason: StoredContentRef | None
    payload: GenerationStagePayload
    created_at: UtcDateTime


class PreparedFinalCandidateSet(StrictModel):
    candidate_set: CandidateSet
    already_persisted: bool


class FinalBundleFinalizer(Protocol):
    """Two-phase port whose second phase owns no transaction boundary."""

    def prepare(
        self,
        context: GenerationTurnContext,
        payload: FinalTurnBundle,
        *,
        idempotency_key: str,
    ) -> PreparedFinalCandidateSet: ...

    def finalize_in_transaction(
        self,
        prepared: PreparedFinalCandidateSet,
    ) -> CandidateSet: ...


def canonical_generation_bytes(payload: GenerationStagePayload) -> bytes:
    return json.dumps(
        payload.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def generation_payload_sha256(payload: GenerationStagePayload) -> str:
    return hashlib.sha256(canonical_generation_bytes(payload)).hexdigest()


def _candidate_set_sha256(payload: FinalTurnBundle, run_id: str) -> str:
    return hashlib.sha256(
        (
            json.dumps(
                {
                    "candidates": [
                        {
                            "label": item.label,
                            "sha256": hashlib.sha256(
                                item.text.encode("utf-8")
                            ).hexdigest(),
                        }
                        for item in payload.client_reply_candidates
                    ],
                    "run_id": run_id,
                },
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    ).hexdigest()


class CandidateSetTransactionFinalizer:
    """Prepare CAS bodies, then atomically persist candidates and turn states."""

    def __init__(self, repository: SessionRepository) -> None:
        self._repository = repository

    def prepare(
        self,
        context: GenerationTurnContext,
        payload: FinalTurnBundle,
        *,
        idempotency_key: str,
    ) -> PreparedFinalCandidateSet:
        if type(idempotency_key) is not str or not idempotency_key.strip():
            raise ValueError("idempotency_key must be nonblank")
        expected_hash = _candidate_set_sha256(payload, context.run_id)
        existing = self._repository.connection.execute(
            "SELECT turn_id, set_sha256 FROM candidate_sets "
            "WHERE session_id = ? AND idempotency_key = ?",
            (context.session_id, idempotency_key),
        ).fetchone()
        if existing is not None:
            if existing != (context.turn_id, expected_hash):
                raise CandidateSetConflict("CANDIDATE_SET_IDEMPOTENCY_CONFLICT")
            candidate_set = candidate_set_from_database(
                self._repository.connection,
                context.session_id,
                context.turn_id,
            )
            self._assert_matches(payload, candidate_set, expected_hash)
            return PreparedFinalCandidateSet(
                candidate_set=candidate_set,
                already_persisted=True,
            )

        stored = tuple(
            self._repository.store_text(item.text, kind="candidate_reply")
            for item in payload.client_reply_candidates
        )
        now = self._repository.clock.now()
        candidate_set_id = self._repository.id_factory.object_id("candidate_set")
        replies = tuple(
            CandidateReply(
                candidate_id=self._repository.id_factory.object_id("candidate_reply"),
                candidate_set_id=candidate_set_id,
                session_id=context.session_id,
                turn_id=context.turn_id,
                ordinal=index,
                label=draft.label,
                content=content,
                run_id=context.run_id,
                created_at=now,
            )
            for index, (draft, content) in enumerate(
                zip(payload.client_reply_candidates, stored, strict=True),
                start=1,
            )
        )
        return PreparedFinalCandidateSet(
            candidate_set=CandidateSet(
                candidate_set_id=candidate_set_id,
                session_id=context.session_id,
                turn_id=context.turn_id,
                run_id=context.run_id,
                idempotency_key=idempotency_key,
                set_sha256=expected_hash,
                candidates=replies,
                created_at=now,
            ),
            already_persisted=False,
        )

    def finalize_in_transaction(
        self,
        prepared: PreparedFinalCandidateSet,
    ) -> CandidateSet:
        if not self._repository.connection.in_transaction:
            raise GenerationStageIntegrityError
        values = prepared.candidate_set
        if prepared.already_persisted:
            return values
        current = self._repository.get_turn(values.session_id, values.turn_id)
        if (
            current.state != "generation_in_progress"
            or current.active_run_id != values.run_id
        ):
            raise TurnStateConflict
        try:
            self._repository.connection.execute(
                """
                INSERT INTO candidate_sets(
                    candidate_set_id, session_id, turn_id, run_id,
                    idempotency_key, set_sha256, candidate_count, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    values.candidate_set_id,
                    values.session_id,
                    values.turn_id,
                    values.run_id,
                    values.idempotency_key,
                    values.set_sha256,
                    len(values.candidates),
                    _utc_text(values.created_at),
                ),
            )
            for reply in values.candidates:
                self._repository.connection.execute(
                    """
                    INSERT INTO candidate_replies(
                        candidate_id, candidate_set_id, session_id, turn_id,
                        ordinal, label, candidate_object_id,
                        candidate_sha256, candidate_media_type,
                        candidate_size_bytes, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        reply.candidate_id,
                        reply.candidate_set_id,
                        reply.session_id,
                        reply.turn_id,
                        reply.ordinal,
                        reply.label,
                        reply.content.object_id,
                        reply.content.content_sha256,
                        reply.content.media_type,
                        reply.content.size_bytes,
                        _utc_text(reply.created_at),
                    ),
                )
            self._repository.transition_turn_in_transaction(
                values.session_id,
                values.turn_id,
                target="candidates_generated",
                payload_sha256=values.set_sha256,
                active_run_id=values.run_id,
            )
            awaiting_hash = hashlib.sha256(
                (
                    json.dumps(
                        {
                            "candidate_set_sha256": values.set_sha256,
                            "state": "awaiting",
                        },
                        ensure_ascii=False,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
            ).hexdigest()
            self._repository.transition_turn_in_transaction(
                values.session_id,
                values.turn_id,
                target="awaiting_actual_reply",
                payload_sha256=awaiting_hash,
                active_run_id=values.run_id,
            )
        except sqlite3.IntegrityError:
            raise CandidateSetConflict("CANDIDATE_SET_WRITE_CONFLICT") from None
        return values

    @staticmethod
    def _assert_matches(
        payload: FinalTurnBundle,
        candidate_set: CandidateSet,
        expected_hash: str,
    ) -> None:
        if (
            candidate_set.set_sha256 != expected_hash
            or tuple(item.label for item in candidate_set.candidates)
            != tuple(item.label for item in payload.client_reply_candidates)
            or tuple(item.content.content_sha256 for item in candidate_set.candidates)
            != tuple(
                hashlib.sha256(item.text.encode("utf-8")).hexdigest()
                for item in payload.client_reply_candidates
            )
        ):
            raise CandidateSetConflict("CANDIDATE_SET_IDEMPOTENCY_CONFLICT")


class GenerationStageStore:
    def __init__(
        self,
        repository: SessionRepository,
        *,
        finalizer: FinalBundleFinalizer | None = None,
    ) -> None:
        if not isinstance(repository, SessionRepository):
            raise TypeError("GenerationStageStore requires SessionRepository")
        self._repository = repository
        self._finalizer = finalizer or CandidateSetTransactionFinalizer(repository)

    def submit(
        self,
        turn_context: GenerationTurnContext | object,
        *,
        stage: GenerationStageName,
        payload: GenerationStagePayload | object,
        idempotency_key: str | None = None,
        revision_reason: str | None = None,
    ) -> GenerationStageRecord:
        context = GenerationTurnContext.model_validate(turn_context, strict=True)
        values = validate_generation_payload(payload)
        if values.envelope.stage != stage or (
            values.envelope.turn_id != context.turn_id
            or values.envelope.run_id != context.run_id
        ):
            raise GenerationBindingMismatch
        if idempotency_key is not None and (
            type(idempotency_key) is not str or not idempotency_key.strip()
        ):
            raise ValueError("idempotency_key must be nonblank")
        if revision_reason is not None and (
            type(revision_reason) is not str or not revision_reason.strip()
        ):
            raise ValueError("revision_reason must be nonblank")
        if isinstance(values, QueryPlan):
            QueryPlanValidator.validate(values)

        turn = self._repository.get_turn(context.session_id, context.turn_id)
        if turn.session_id != context.session_id:
            raise GenerationBindingMismatch
        encoded = canonical_generation_bytes(values)
        digest = hashlib.sha256(encoded).hexdigest()
        effective_key = idempotency_key or f"{stage}:{digest}"
        key_sha256 = hashlib.sha256(effective_key.encode("utf-8")).hexdigest()

        existing = self._latest_records(context)
        existing_hashes = {item.stage: item.artifact.content_sha256 for item in existing}
        active_current = next((item for item in existing if item.stage == stage), None)
        stage_history = tuple(
            item for item in self._all_records(context) if item.stage == stage
        )
        current = None if not stage_history else stage_history[-1]

        by_key = self._find_revision(
            context,
            stage=stage,
            idempotency_key_sha256=key_sha256,
        )
        if by_key is not None:
            if by_key.artifact.content_sha256 != digest:
                raise GenerationStageConflict("GENERATION_STAGE_IDEMPOTENCY_CONFLICT")
            if active_current is not None and by_key.revision == active_current.revision:
                self._verify_final_idempotency(context, values, active_current)
                return active_current
            raise GenerationStageConflict("GENERATION_STAGE_IDEMPOTENCY_STALE")

        if active_current is not None and active_current.artifact.content_sha256 == digest:
            # A replay is idempotent only when it uses the key already persisted
            # on the active revision.  Returning the active record for an unseen
            # alias would leave that alias unbound and allow it to be reused for
            # different content on the next call.
            raise GenerationStageConflict("GENERATION_STAGE_IDEMPOTENCY_CONFLICT")
        by_hash = self._find_revision(context, stage=stage, artifact_sha256=digest)
        if by_hash is not None:
            raise GenerationStageConflict("GENERATION_STAGE_HISTORICAL_ARTIFACT")

        GenerationStateMachine.validate_next(existing_hashes, values)
        GenerationStateMachine.validate_retry_sequence(
            None if current is None else current.payload,
            values,
        )
        if current is not None and revision_reason is None:
            raise GenerationStageRevisionRequired
        if current is not None and turn.state != "generation_in_progress":
            raise GenerationStageConflict("GENERATION_STAGE_REVISION_CLOSED")

        prepared_final: PreparedFinalCandidateSet | None = None
        if isinstance(values, FinalTurnBundle):
            final_key = idempotency_key or f"final-bundle-{context.run_id}"
            prepared_final = self._finalizer.prepare(
                context,
                values,
                idempotency_key=final_key,
            )
            if prepared_final.already_persisted:
                raise GenerationStageIntegrityError

        return self._append_revision(
            context,
            payload=values,
            encoded=encoded,
            idempotency_key_sha256=key_sha256,
            previous=current,
            revision_reason=revision_reason,
            prepared_final=prepared_final,
        )

    def get_latest(
        self,
        turn_context: GenerationTurnContext | object,
        *,
        stage: GenerationStageName | None = None,
    ) -> GenerationStageRecord:
        context = GenerationTurnContext.model_validate(turn_context, strict=True)
        records = self._latest_records(context)
        if stage is not None:
            record = next((item for item in records if item.stage == stage), None)
            if record is None:
                raise KeyError((context.session_id, context.turn_id, stage))
            return record
        if not records:
            raise KeyError((context.session_id, context.turn_id))
        return records[-1]

    def list_records(
        self,
        turn_context: GenerationTurnContext | object,
    ) -> tuple[GenerationStageRecord, ...]:
        context = GenerationTurnContext.model_validate(turn_context, strict=True)
        return self._latest_records(context)

    def get_revision_history(
        self,
        turn_context: GenerationTurnContext | object,
        *,
        stage: GenerationStageName,
    ) -> tuple[GenerationStageRecord, ...]:
        context = GenerationTurnContext.model_validate(turn_context, strict=True)
        return tuple(item for item in self._all_records(context) if item.stage == stage)

    def _verify_final_idempotency(
        self,
        context: GenerationTurnContext,
        payload: GenerationStagePayload,
        record: GenerationStageRecord,
    ) -> None:
        if not isinstance(payload, FinalTurnBundle):
            return
        try:
            candidate_set = candidate_set_from_database(
                self._repository.connection,
                context.session_id,
                context.turn_id,
            )
        except (KeyError, CandidateSetConflict):
            raise GenerationStageIntegrityError from None
        CandidateSetTransactionFinalizer._assert_matches(
            payload,
            candidate_set,
            _candidate_set_sha256(payload, context.run_id),
        )
        if record.stage != "final_bundle":
            raise GenerationStageIntegrityError

    def _append_revision(
        self,
        context: GenerationTurnContext,
        *,
        payload: GenerationStagePayload,
        encoded: bytes,
        idempotency_key_sha256: str,
        previous: GenerationStageRecord | None,
        revision_reason: str | None,
        prepared_final: PreparedFinalCandidateSet | None,
    ) -> GenerationStageRecord:
        stored = self._repository.store_json(encoded, kind="generation_stage")
        reason_ref: StoredContentRef | None = None
        revision = 1 if previous is None else previous.revision + 1
        if previous is not None:
            if revision_reason is None:
                raise GenerationStageRevisionRequired
            reason_ref = self._repository.store_json(
                json.dumps(
                    {
                        "new_sha256": stored.content_sha256,
                        "old_sha256": previous.artifact.content_sha256,
                        "reason": revision_reason,
                    },
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8"),
                kind="generation_revision_reason",
            )
        stage_revision_id = self._repository.id_factory.object_id(
            "generation_stage_revision"
        )
        reason_values: tuple[object | None, ...] = (
            (None, None, None, None)
            if reason_ref is None
            else (
                reason_ref.object_id,
                reason_ref.content_sha256,
                reason_ref.media_type,
                reason_ref.size_bytes,
            )
        )
        try:
            with transaction(self._repository.connection):
                current_turn = self._repository.get_turn(
                    context.session_id, context.turn_id
                )
                if isinstance(payload, QueryPlan) and previous is None:
                    if (
                        current_turn.state != "client_turn_received"
                        or current_turn.active_run_id is not None
                    ):
                        raise TurnStateConflict
                elif (
                    current_turn.state != "generation_in_progress"
                    or current_turn.active_run_id != context.run_id
                ):
                    raise TurnStateConflict
                latest = self._repository.connection.execute(
                    """
                    SELECT revision, artifact_sha256
                      FROM generation_stage_revisions
                     WHERE session_id = ? AND turn_id = ? AND run_id = ? AND stage = ?
                     ORDER BY revision DESC LIMIT 1
                    """,
                    (
                        context.session_id,
                        context.turn_id,
                        context.run_id,
                        payload.envelope.stage,
                    ),
                ).fetchone()
                if previous is None:
                    if latest is not None:
                        raise GenerationStageConflict("GENERATION_STAGE_REVISION_CONFLICT")
                elif latest != (previous.revision, previous.artifact.content_sha256):
                    raise GenerationStageConflict("GENERATION_STAGE_REVISION_CONFLICT")
                self._repository.connection.execute(
                    """
                    INSERT INTO generation_stage_revisions(
                        stage_revision_id, session_id, turn_id, run_id, stage,
                        revision, idempotency_key_sha256, artifact_object_id,
                        artifact_sha256, artifact_media_type, artifact_size_bytes,
                        parent_sha256s_json, revision_reason_object_id,
                        revision_reason_sha256, revision_reason_media_type,
                        revision_reason_size_bytes, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        stage_revision_id,
                        context.session_id,
                        context.turn_id,
                        context.run_id,
                        payload.envelope.stage,
                        revision,
                        idempotency_key_sha256,
                        stored.object_id,
                        stored.content_sha256,
                        stored.media_type,
                        stored.size_bytes,
                        json.dumps(
                            list(payload.envelope.parent_sha256s),
                            separators=(",", ":"),
                        ),
                        *reason_values,
                        _utc_text(payload.envelope.created_at),
                    ),
                )
                if isinstance(payload, QueryPlan) and previous is None:
                    self._repository.transition_turn_in_transaction(
                        context.session_id,
                        context.turn_id,
                        target="generation_in_progress",
                        payload_sha256=stored.content_sha256,
                        active_run_id=context.run_id,
                    )
                if prepared_final is not None:
                    self._finalizer.finalize_in_transaction(prepared_final)
        except sqlite3.IntegrityError:
            exact = self._find_revision(
                context,
                stage=payload.envelope.stage,
                idempotency_key_sha256=idempotency_key_sha256,
            )
            if exact is None or exact.artifact.content_sha256 != stored.content_sha256:
                raise GenerationStageConflict from None
            return exact
        return self._require_revision(context, stage_revision_id)

    def _latest_records(
        self,
        context: GenerationTurnContext,
    ) -> tuple[GenerationStageRecord, ...]:
        by_stage: dict[GenerationStageName, list[GenerationStageRecord]] = {
            stage: [] for stage in GENERATION_STAGE_ORDER
        }
        for record in self._all_records(context):
            by_stage[record.stage].append(record)

        active: list[GenerationStageRecord] = []
        for index, stage in enumerate(GENERATION_STAGE_ORDER):
            candidates = by_stage[stage]
            if not candidates:
                break
            if index == 0:
                eligible = [
                    record for record in candidates if not record.parent_sha256s
                ]
            else:
                if len(active) != index:
                    break
                previous_hash = active[-1].artifact.content_sha256
                eligible = [
                    record
                    for record in candidates
                    if not isinstance(record.payload, QueryPlan)
                    and record.parent_sha256s
                    == tuple(
                        sorted(
                            {
                                previous_hash,
                                record.payload.evidence_pack_sha256,
                            }
                        )
                    )
                ]
            if not eligible:
                break
            active.append(max(eligible, key=lambda record: record.revision))
        return tuple(active)

    def _all_records(
        self,
        context: GenerationTurnContext,
    ) -> tuple[GenerationStageRecord, ...]:
        rows = self._repository.connection.execute(
            """
            SELECT stage_revision_id, session_id, turn_id, run_id, stage,
                   revision, idempotency_key_sha256, artifact_object_id,
                   artifact_sha256, artifact_media_type, artifact_size_bytes,
                   parent_sha256s_json, revision_reason_object_id,
                   revision_reason_sha256, revision_reason_media_type,
                   revision_reason_size_bytes, created_at
              FROM generation_stage_revisions
             WHERE session_id = ? AND turn_id = ? AND run_id = ?
             ORDER BY stage, revision
            """,
            (context.session_id, context.turn_id, context.run_id),
        ).fetchall()
        return tuple(self._record_from_row(tuple(row), context) for row in rows)

    def _find_revision(
        self,
        context: GenerationTurnContext,
        *,
        stage: GenerationStageName,
        idempotency_key_sha256: str | None = None,
        artifact_sha256: str | None = None,
    ) -> GenerationStageRecord | None:
        for record in self._all_records(context):
            if record.stage != stage:
                continue
            if (
                idempotency_key_sha256 is not None
                and record.idempotency_key_sha256 == idempotency_key_sha256
            ):
                return record
            if artifact_sha256 is not None and record.artifact.content_sha256 == artifact_sha256:
                return record
        return None

    def _require_revision(
        self,
        context: GenerationTurnContext,
        stage_revision_id: str,
    ) -> GenerationStageRecord:
        record = next(
            (
                item
                for item in self._all_records(context)
                if item.stage_revision_id == stage_revision_id
            ),
            None,
        )
        if record is None:
            raise GenerationStageIntegrityError
        return record

    def _record_from_row(
        self,
        row: tuple[object, ...],
        context: GenerationTurnContext,
    ) -> GenerationStageRecord:
        if len(row) != 17:
            raise GenerationStageIntegrityError
        try:
            reference = StoredContentRef.model_validate(
                {
                    "object_id": row[7],
                    "content_sha256": row[8],
                    "media_type": row[9],
                    "size_bytes": row[10],
                }
            )
            reason_reference = (
                None
                if row[12] is None
                else StoredContentRef.model_validate(
                    {
                        "object_id": row[12],
                        "content_sha256": row[13],
                        "media_type": row[14],
                        "size_bytes": row[15],
                    }
                )
            )
            encoded = self._repository.read_content(reference)
            payload = validate_generation_payload_json(encoded)
            parents = tuple(json.loads(cast(str, row[11])))
            record = GenerationStageRecord.model_validate(
                {
                    "stage_revision_id": row[0],
                    "session_id": row[1],
                    "turn_id": row[2],
                    "run_id": row[3],
                    "stage": row[4],
                    "revision": row[5],
                    "idempotency_key_sha256": row[6],
                    "artifact": reference,
                    "parent_sha256s": parents,
                    "revision_reason": reason_reference,
                    "payload": payload,
                    "created_at": _parse_utc(row[16]),
                }
            )
            if reason_reference is not None:
                self._repository.read_content(reason_reference)
        except (
            GenerationStageStoreError,
            ValidationError,
            ValueError,
            TypeError,
            json.JSONDecodeError,
        ):
            raise GenerationStageIntegrityError from None
        if (
            record.session_id != context.session_id
            or record.turn_id != context.turn_id
            or record.run_id != context.run_id
            or record.stage != payload.envelope.stage
            or payload.envelope.turn_id != context.turn_id
            or payload.envelope.run_id != context.run_id
            or record.parent_sha256s != payload.envelope.parent_sha256s
            or record.created_at != payload.envelope.created_at
            or canonical_generation_bytes(payload) != encoded
            or hashlib.sha256(encoded).hexdigest() != reference.content_sha256
            or (record.revision == 1) != (record.revision_reason is None)
        ):
            raise GenerationStageIntegrityError
        return record


__all__ = [
    "CandidateSetTransactionFinalizer",
    "FinalBundleFinalizer",
    "GenerationBindingMismatch",
    "GenerationStageConflict",
    "GenerationStageIntegrityError",
    "GenerationStageRecord",
    "GenerationStageRevisionRequired",
    "GenerationStageStore",
    "GenerationStageStoreError",
    "GenerationTurnContext",
    "PreparedFinalCandidateSet",
    "canonical_generation_bytes",
    "generation_payload_sha256",
]
