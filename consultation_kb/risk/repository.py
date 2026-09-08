"""Client-database-only persistence for internal risk observations."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    Field,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)

from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.models.common import (
    NonEmptyStr,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    Uuid7String,
    VersionRef,
)
from consultation_kb.models.risk import InternalRiskObservation
from consultation_kb.storage.connection import transaction


_NONEMPTY_ADAPTER: TypeAdapter[str] = TypeAdapter(NonEmptyStr)
_POLICY_KEY_ADAPTER: TypeAdapter[str] = TypeAdapter(SafePolicyKey)
_UUID_ADAPTER: TypeAdapter[str] = TypeAdapter(Uuid7String)
_SHA256_ADAPTER: TypeAdapter[str] = TypeAdapter(Sha256Hex)


class RiskRepositoryError(RuntimeError):
    def __init__(self, code: str = "RISK_REPOSITORY_INVALID") -> None:
        super().__init__(code)


class RiskLifecycleConflict(RiskRepositoryError):
    def __init__(self, code: str = "RISK_LIFECYCLE_CONFLICT") -> None:
        RuntimeError.__init__(self, code)


class RiskEvaluationAuthorityBinding(StrictModel):
    """Body-free exact authority used to evaluate one client turn."""

    schema_version: Literal["1.0"] = "1.0"
    global_runtime_epoch: Annotated[int, Field(strict=True, gt=0)]
    risk_policy_manifest_ref: VersionRef
    model_mode: Literal["deterministic_only", "approved_model"]
    risk_model_manifest_ref: VersionRef | None = None
    approved_model_ref: VersionRef | None = None

    @model_validator(mode="after")
    def _model_binding(self) -> "RiskEvaluationAuthorityBinding":
        has_model_authority = (
            self.risk_model_manifest_ref is not None
            and self.approved_model_ref is not None
        )
        if (self.model_mode == "approved_model") != has_model_authority:
            raise ValueError("risk model authority binding is inconsistent")
        if (self.risk_model_manifest_ref is None) != (
            self.approved_model_ref is None
        ):
            raise ValueError("risk model authority binding is partial")
        return self


def risk_evaluation_authority_sha256(
    authority: RiskEvaluationAuthorityBinding,
) -> str:
    exact = RiskEvaluationAuthorityBinding.model_validate(authority, strict=True)
    encoded = (
        json.dumps(
            exact.model_dump(mode="json"),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


class TurnRiskEvaluationRecord(StrictModel):
    """Body-free durable closure for one exact client-turn evaluation."""

    schema_version: Literal["1.0"] = "1.0"
    session_id: Uuid7String
    turn_id: Uuid7String
    evaluation_revision: Annotated[int, Field(strict=True, gt=0)]
    client_message_sha256: Sha256Hex
    authority_sha256: Sha256Hex
    authority: RiskEvaluationAuthorityBinding
    status: Literal["pending", "completed"]
    observation_set_sha256: Sha256Hex | None = None
    observation_count: Annotated[int, Field(strict=True, ge=0)] | None = None
    completed_at: UtcDateTime | None = None

    @model_validator(mode="after")
    def _state_shape(self) -> "TurnRiskEvaluationRecord":
        if self.authority_sha256 != risk_evaluation_authority_sha256(
            self.authority
        ):
            raise ValueError("risk evaluation authority hash mismatch")
        completed = (
            self.observation_set_sha256,
            self.observation_count,
            self.completed_at,
        )
        if self.status == "pending" and any(value is not None for value in completed):
            raise ValueError("pending risk evaluation cannot contain a result")
        if self.status == "completed" and any(value is None for value in completed):
            raise ValueError("completed risk evaluation requires a fixed result")
        return self


class RiskTriggerSpan(StrictModel):
    """Private locator for a trigger; deliberately contains no quoted text."""

    turn_id: Uuid7String
    content_ref: VersionRef
    start_offset: Annotated[int, Field(strict=True, ge=0)]
    end_offset: Annotated[int, Field(strict=True, gt=0)]
    span_sha256: Sha256Hex
    normalized_length: Annotated[int, Field(strict=True, gt=0)]
    normalized_span_sha256: Sha256Hex

    @model_validator(mode="after")
    def _valid_offsets(self) -> "RiskTriggerSpan":
        if self.end_offset <= self.start_offset:
            raise ValueError("risk trigger span end must be after start")
        return self


class RiskObservationSource(StrictModel):
    source_kind: Literal["deterministic_rule", "model_observation"]
    source_ref: VersionRef


class InternalRiskObservationRecord(StrictModel):
    """P0 observation plus confidence, private spans, and manual lifecycle."""

    schema_version: Literal["1.0"] = "1.0"
    session_id: Uuid7String
    observation: InternalRiskObservation
    trigger_spans: Annotated[
        tuple[RiskTriggerSpan, ...],
        Field(min_length=1, json_schema_extra={"uniqueItems": True}),
    ]
    sources: Annotated[
        tuple[RiskObservationSource, ...],
        Field(min_length=1, json_schema_extra={"uniqueItems": True}),
    ]
    confidence: Annotated[float, Field(strict=True, ge=0.0, le=1.0)]
    status: Literal["open", "acknowledged", "closed"] = "open"
    acknowledged_at: UtcDateTime | None = None
    counselor_disposition: NonEmptyStr | None = None
    rejection_reason: NonEmptyStr | None = None
    closed_at: UtcDateTime | None = None
    close_decision: SafePolicyKey | None = None
    close_reason: NonEmptyStr | None = None

    @field_validator("trigger_spans")
    @classmethod
    def _canonical_spans(
        cls,
        value: tuple[RiskTriggerSpan, ...],
    ) -> tuple[RiskTriggerSpan, ...]:
        if len(value) != len(set(value)):
            raise ValueError("risk trigger spans must be unique")
        return tuple(
            sorted(
                value,
                key=lambda item: (
                    item.turn_id,
                    item.content_ref.object_id,
                    item.start_offset,
                    item.end_offset,
                    item.span_sha256,
                    item.normalized_length,
                    item.normalized_span_sha256,
                ),
            )
        )

    @field_validator("sources")
    @classmethod
    def _canonical_source_refs(
        cls,
        value: tuple[RiskObservationSource, ...],
    ) -> tuple[RiskObservationSource, ...]:
        if len(value) != len(set(value)):
            raise ValueError("risk observation sources must be unique")
        return tuple(
            sorted(
                value,
                key=lambda item: (
                    item.source_kind,
                    item.source_ref.object_id,
                    item.source_ref.version,
                    item.source_ref.content_sha256,
                ),
            )
        )

    @model_validator(mode="after")
    def _lifecycle_and_closure(self) -> "InternalRiskObservationRecord":
        trigger_turns = {span.turn_id for span in self.trigger_spans}
        if trigger_turns != set(self.observation.trigger_turn_ids):
            raise ValueError("risk trigger spans must exactly cover trigger turn IDs")
        deterministic_sources = tuple(
            source
            for source in self.sources
            if source.source_kind == "deterministic_rule"
        )
        if any(
            source.source_ref != self.observation.rule_ref
            for source in deterministic_sources
        ):
            raise ValueError("deterministic source must match the observation rule")

        acknowledgement = (
            self.acknowledged_at,
            self.counselor_disposition,
            self.rejection_reason,
        )
        closure = (self.closed_at, self.close_decision, self.close_reason)
        if self.status == "open":
            if any(value is not None for value in acknowledgement + closure):
                raise ValueError("open risk records cannot contain lifecycle decisions")
        elif self.status == "acknowledged":
            if self.acknowledged_at is None or not any(
                value is not None
                for value in (self.counselor_disposition, self.rejection_reason)
            ):
                raise ValueError("acknowledgement requires time and manual disposition")
            if any(value is not None for value in closure):
                raise ValueError("acknowledged risk records are not closed")
            assert self.acknowledged_at is not None
            if self.acknowledged_at < self.observation.detected_at:
                raise ValueError("risk acknowledgement cannot predate detection")
        else:
            if self.acknowledged_at is None or not any(
                value is not None
                for value in (self.counselor_disposition, self.rejection_reason)
            ):
                raise ValueError("closed risk records retain acknowledgement")
            if any(value is None for value in closure):
                raise ValueError("close requires time, decision, and reason")
            assert self.acknowledged_at is not None
            if self.acknowledged_at < self.observation.detected_at:
                raise ValueError("risk acknowledgement cannot predate detection")
            assert self.closed_at is not None
            if self.closed_at < self.acknowledged_at:
                raise ValueError("risk close cannot predate acknowledgement")
        return self

    @property
    def visible_to_counselor(self) -> bool:
        return self.status != "closed"


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


_LIFECYCLE_FIELDS = (
    "status",
    "acknowledged_at",
    "counselor_disposition",
    "rejection_reason",
    "closed_at",
    "close_decision",
    "close_reason",
)


def _snapshot_sha256(snapshot_json: str) -> str:
    return hashlib.sha256((snapshot_json + "\n").encode("ascii")).hexdigest()


def _matches_turn_binding(
    connection: sqlite3.Connection,
    record: InternalRiskObservationRecord,
    *,
    session_id: str,
    turn_id: str,
) -> bool:
    row = connection.execute(
        "SELECT client_message_object_id, client_message_sha256 FROM turns "
        "WHERE session_id = ? AND turn_id = ?",
        (session_id, turn_id),
    ).fetchone()
    if (
        row is None
        or type(row[0]) is not str
        or type(row[1]) is not str
        or record.session_id != session_id
        or record.observation.trigger_turn_ids != (turn_id,)
    ):
        return False
    object_id, content_sha256 = str(row[0]), str(row[1])
    return bool(record.trigger_spans) and all(
        span.turn_id == turn_id
        and span.content_ref.object_id == object_id
        and span.content_ref.content_sha256 == content_sha256
        for span in record.trigger_spans
    )


def _matches_source_authority(
    record: InternalRiskObservationRecord,
    *,
    model_mode: str,
    approved_model_ref: VersionRef | None,
) -> bool:
    model_sources = tuple(
        source
        for source in record.sources
        if source.source_kind == "model_observation"
    )
    if model_mode == "deterministic_only":
        return not model_sources and approved_model_ref is None
    if model_mode != "approved_model" or approved_model_ref is None:
        return False
    return all(source.source_ref == approved_model_ref for source in model_sources)


def canonical_risk_observation_set_sha256(
    records: tuple[InternalRiskObservationRecord, ...],
) -> str:
    """Hash deterministic result identity, excluding retry-time lifecycle clocks."""

    exact = tuple(
        InternalRiskObservationRecord.model_validate(item, strict=True)
        for item in records
    )
    identifiers = tuple(item.observation.observation_id for item in exact)
    if identifiers != tuple(sorted(set(identifiers))):
        raise ValueError("risk observations must be canonical")
    identities = tuple(
        json.loads(InternalRiskObservationRepository._retry_identity_json(item))
        for item in exact
    )
    return hashlib.sha256(
        (_canonical_json(identities) + "\n").encode("ascii")
    ).hexdigest()


def _utc_text(value: object) -> str:
    if not hasattr(value, "isoformat"):
        raise TypeError("risk timestamp must support isoformat")
    return str(value.isoformat().replace("+00:00", "Z"))


class InternalRiskObservationRepository:
    """Persist risk objects only when explicitly bound to a client DB."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        database_scope: Literal["client"],
        clock: Clock | None = None,
    ) -> None:
        if database_scope != "client":
            raise ValueError("RISK_REPOSITORY_REQUIRES_CLIENT_DATABASE")
        self.connection = connection
        self.clock = clock if clock is not None else SystemClock()

    @staticmethod
    def install_schema(
        connection: sqlite3.Connection,
        *,
        database_scope: Literal["client"],
    ) -> None:
        """Install the isolated table for tests/embedding migration runners."""

        if database_scope != "client":
            raise ValueError("RISK_REPOSITORY_REQUIRES_CLIENT_DATABASE")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS internal_risk_observations(
                observation_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                immutable_record_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('open','acknowledged','closed')),
                acknowledged_at TEXT,
                counselor_disposition TEXT,
                rejection_reason TEXT,
                closed_at TEXT,
                close_decision TEXT,
                close_reason TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_internal_risk_visible
                ON internal_risk_observations(session_id, status, observation_id);
            """
        )

    @staticmethod
    def _immutable_json(record: InternalRiskObservationRecord) -> str:
        payload = record.model_dump(mode="json")
        for key in _LIFECYCLE_FIELDS:
            payload.pop(key)
        return _canonical_json(payload)

    @staticmethod
    def _retry_identity_json(record: InternalRiskObservationRecord) -> str:
        """Compare retries while retaining the first detection timestamp."""

        payload = record.model_dump(mode="json")
        for key in _LIFECYCLE_FIELDS:
            payload.pop(key)
        observation = payload.get("observation")
        if not isinstance(observation, dict):
            raise RiskRepositoryError("RISK_OBSERVATION_CORRUPT")
        observation.pop("detected_at", None)
        return _canonical_json(payload)

    @staticmethod
    def _semantic_core_json(record: InternalRiskObservationRecord) -> str:
        """Stable lifecycle identity; revision-specific provenance is excluded."""

        observation = record.observation.model_dump(mode="json")
        observation.pop("detected_at", None)
        return _canonical_json(
            {
                "session_id": record.session_id,
                "observation": observation,
                "trigger_spans": [
                    span.model_dump(mode="json") for span in record.trigger_spans
                ],
            }
        )

    @classmethod
    def _from_snapshot(
        cls,
        snapshot_json: object,
        snapshot_sha256: object,
        *,
        lifecycle: InternalRiskObservationRecord,
    ) -> InternalRiskObservationRecord:
        if type(snapshot_json) is not str or type(snapshot_sha256) is not str:
            raise RiskRepositoryError("TURN_RISK_EVALUATION_MEMBERSHIP_CORRUPT")
        if _snapshot_sha256(snapshot_json) != snapshot_sha256:
            raise RiskRepositoryError("TURN_RISK_EVALUATION_MEMBERSHIP_CORRUPT")
        try:
            snapshot = InternalRiskObservationRecord.model_validate_json(
                snapshot_json
            )
        except (TypeError, ValueError, ValidationError):
            raise RiskRepositoryError(
                "TURN_RISK_EVALUATION_MEMBERSHIP_CORRUPT"
            ) from None
        if (
            cls._immutable_json(snapshot) != snapshot_json
            or cls._semantic_core_json(snapshot)
            != cls._semantic_core_json(lifecycle)
        ):
            raise RiskRepositoryError("TURN_RISK_EVALUATION_MEMBERSHIP_CORRUPT")
        payload = snapshot.model_dump()
        lifecycle_payload = lifecycle.model_dump()
        for key in _LIFECYCLE_FIELDS:
            payload[key] = lifecycle_payload[key]
        try:
            return InternalRiskObservationRecord.model_validate(
                payload,
                strict=True,
            )
        except ValidationError:
            raise RiskRepositoryError(
                "TURN_RISK_EVALUATION_MEMBERSHIP_CORRUPT"
            ) from None

    def add(self, record: InternalRiskObservationRecord) -> InternalRiskObservationRecord:
        exact = InternalRiskObservationRecord.model_validate(record)
        if exact.status != "open":
            raise RiskLifecycleConflict("RISK_OBSERVATION_MUST_START_OPEN")
        immutable_json = self._immutable_json(exact)
        try:
            with transaction(self.connection):
                self.connection.execute(
                    """
                    INSERT INTO internal_risk_observations(
                        observation_id, session_id, immutable_record_json, status
                    ) VALUES (?, ?, ?, 'open')
                    """,
                    (
                        exact.observation.observation_id,
                        exact.session_id,
                        immutable_json,
                    ),
                )
        except sqlite3.IntegrityError:
            current = self.get(exact.observation.observation_id)
            if (
                self._semantic_core_json(current)
                == self._semantic_core_json(exact)
            ):
                return current
            raise RiskLifecycleConflict("RISK_OBSERVATION_ID_CONFLICT") from None
        return exact

    def _row(self, observation_id: str) -> tuple[object, ...]:
        row = self.connection.execute(
            """
            SELECT immutable_record_json, status, acknowledged_at,
                   counselor_disposition, rejection_reason, closed_at,
                   close_decision, close_reason
              FROM internal_risk_observations WHERE observation_id = ?
            """,
            (observation_id,),
        ).fetchone()
        if row is None:
            raise RiskRepositoryError("RISK_OBSERVATION_NOT_FOUND")
        return tuple(row)

    def get(self, observation_id: str) -> InternalRiskObservationRecord:
        row = self._row(observation_id)
        try:
            payload = json.loads(str(row[0]))
            payload.update(
                {
                    "status": row[1],
                    "acknowledged_at": row[2],
                    "counselor_disposition": row[3],
                    "rejection_reason": row[4],
                    "closed_at": row[5],
                    "close_decision": row[6],
                    "close_reason": row[7],
                }
            )
            # JSON mode is intentional: canonical JSON uses arrays and RFC3339
            # timestamps while the Python contract remains strict tuples/datetimes.
            return InternalRiskObservationRecord.model_validate_json(
                _canonical_json(payload)
            )
        except (json.JSONDecodeError, TypeError, ValueError, ValidationError):
            raise RiskRepositoryError("RISK_OBSERVATION_CORRUPT") from None

    def list_visible(self, session_id: str) -> tuple[InternalRiskObservationRecord, ...]:
        try:
            exact_session_id = _UUID_ADAPTER.validate_python(session_id, strict=True)
        except ValidationError:
            raise ValueError("session_id must be UUIDv7") from None
        rows = self.connection.execute(
            """
            SELECT observation_id FROM internal_risk_observations
             WHERE session_id = ? AND status != 'closed'
             ORDER BY observation_id
            """,
            (exact_session_id,),
        ).fetchall()
        has_membership_snapshots = self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' "
            "AND name = 'turn_risk_evaluation_observations'"
        ).fetchone() is not None
        visible: list[InternalRiskObservationRecord] = []
        for row in rows:
            observation_id = str(row[0])
            lifecycle = self.get(observation_id)
            if not has_membership_snapshots:
                visible.append(lifecycle)
                continue
            snapshot_row = self.connection.execute(
                """
                SELECT member.record_snapshot_json,
                       member.record_snapshot_sha256,
                       member.session_id, member.turn_id,
                       evaluation.risk_model_mode,
                       evaluation.approved_model_object_id,
                       evaluation.approved_model_version,
                       evaluation.approved_model_sha256
                  FROM turn_risk_evaluation_observations AS member
                  JOIN turn_risk_evaluations AS evaluation
                    ON evaluation.session_id = member.session_id
                   AND evaluation.turn_id = member.turn_id
                   AND evaluation.evaluation_revision =
                       member.evaluation_revision
                  JOIN turns AS turn
                    ON turn.session_id = member.session_id
                   AND turn.turn_id = member.turn_id
                 WHERE member.session_id = ?
                   AND member.observation_id = ?
                   AND evaluation.status = 'completed'
                 ORDER BY turn.ordinal DESC,
                          member.evaluation_revision DESC
                 LIMIT 1
                """,
                (exact_session_id, observation_id),
            ).fetchone()
            if snapshot_row is None:
                # Once evaluation membership exists, only a completed revision
                # may make an observation visible.  ``RiskEngine`` persists the
                # lifecycle row before the evaluation transaction closes; using
                # that row as a fallback would expose a failed/pending result.
                continue
            projected = self._from_snapshot(
                snapshot_row[0],
                snapshot_row[1],
                lifecycle=lifecycle,
            )
            try:
                model_mode = str(snapshot_row[4])
                approved_model_ref = (
                    None
                    if snapshot_row[5] is None
                    else VersionRef.model_validate(
                        {
                            "object_id": snapshot_row[5],
                            "version": snapshot_row[6],
                            "content_sha256": snapshot_row[7],
                        },
                        strict=True,
                    )
                )
            except ValidationError:
                raise RiskRepositoryError(
                    "TURN_RISK_EVALUATION_MEMBERSHIP_CORRUPT"
                ) from None
            if (
                projected.observation.observation_id != observation_id
                or not _matches_source_authority(
                    projected,
                    model_mode=model_mode,
                    approved_model_ref=approved_model_ref,
                )
                or not _matches_turn_binding(
                    self.connection,
                    projected,
                    session_id=str(snapshot_row[2]),
                    turn_id=str(snapshot_row[3]),
                )
            ):
                raise RiskRepositoryError(
                    "TURN_RISK_EVALUATION_MEMBERSHIP_CORRUPT"
                )
            visible.append(projected)
        return tuple(visible)

    def acknowledge(
        self,
        observation_id: str,
        *,
        counselor_disposition: str | None = None,
        rejection_reason: str | None = None,
    ) -> InternalRiskObservationRecord:
        try:
            exact_disposition = (
                None
                if counselor_disposition is None
                else _NONEMPTY_ADAPTER.validate_python(
                    counselor_disposition, strict=True
                )
            )
            exact_rejection = (
                None
                if rejection_reason is None
                else _NONEMPTY_ADAPTER.validate_python(rejection_reason, strict=True)
            )
        except ValidationError:
            raise ValueError("acknowledgement values must be nonblank") from None
        if exact_disposition is None and exact_rejection is None:
            raise ValueError("acknowledgement requires disposition or rejection reason")
        current = self.get(observation_id)
        if current.status in {"acknowledged", "closed"}:
            if (
                current.counselor_disposition == exact_disposition
                and current.rejection_reason == exact_rejection
            ):
                return current
            if current.status == "closed":
                raise RiskLifecycleConflict("RISK_OBSERVATION_ALREADY_CLOSED")
            raise RiskLifecycleConflict("RISK_ACKNOWLEDGEMENT_CONFLICT")
        acknowledged_at = self.clock.now()
        try:
            target = InternalRiskObservationRecord.model_validate(
                {
                    **current.model_dump(),
                    "status": "acknowledged",
                    "acknowledged_at": acknowledged_at,
                    "counselor_disposition": exact_disposition,
                    "rejection_reason": exact_rejection,
                },
                strict=True,
            )
        except ValidationError:
            raise RiskLifecycleConflict("RISK_ACKNOWLEDGEMENT_TIME_INVALID") from None
        with transaction(self.connection):
            changed = self.connection.execute(
                """
                UPDATE internal_risk_observations
                   SET status = 'acknowledged', acknowledged_at = ?,
                       counselor_disposition = ?, rejection_reason = ?
                 WHERE observation_id = ? AND status = 'open'
                """,
                (
                    _utc_text(acknowledged_at),
                    exact_disposition,
                    exact_rejection,
                    observation_id,
                ),
            ).rowcount
        if changed == 1:
            return target
        latest = self.get(observation_id)
        if (
            latest.status in {"acknowledged", "closed"}
            and latest.counselor_disposition == exact_disposition
            and latest.rejection_reason == exact_rejection
        ):
            return latest
        if latest.status == "closed":
            raise RiskLifecycleConflict("RISK_OBSERVATION_ALREADY_CLOSED")
        raise RiskLifecycleConflict("RISK_ACKNOWLEDGEMENT_CONFLICT")

    def close(
        self,
        observation_id: str,
        *,
        decision: SafePolicyKey,
        reason: str,
    ) -> InternalRiskObservationRecord:
        try:
            exact_decision = _POLICY_KEY_ADAPTER.validate_python(decision, strict=True)
            exact_reason = _NONEMPTY_ADAPTER.validate_python(reason, strict=True)
        except ValidationError:
            raise ValueError("risk close requires a valid decision and nonblank manual reason") from None
        current = self.get(observation_id)
        if current.status == "open":
            raise RiskLifecycleConflict("RISK_CLOSE_REQUIRES_ACKNOWLEDGEMENT")
        if current.status == "closed":
            if (
                current.close_decision == exact_decision
                and current.close_reason == exact_reason
            ):
                return current
            raise RiskLifecycleConflict("RISK_CLOSE_CONFLICT")
        closed_at = self.clock.now()
        try:
            target = InternalRiskObservationRecord.model_validate(
                {
                    **current.model_dump(),
                    "status": "closed",
                    "closed_at": closed_at,
                    "close_decision": exact_decision,
                    "close_reason": exact_reason,
                },
                strict=True,
            )
        except ValidationError:
            raise RiskLifecycleConflict(
                "RISK_CLOSE_PREDATES_ACKNOWLEDGEMENT"
            ) from None
        with transaction(self.connection):
            changed = self.connection.execute(
                """
                UPDATE internal_risk_observations
                   SET status = 'closed', closed_at = ?, close_decision = ?,
                       close_reason = ?
                 WHERE observation_id = ? AND status = 'acknowledged'
                """,
                (_utc_text(closed_at), exact_decision, exact_reason, observation_id),
            ).rowcount
        if changed == 1:
            return target
        latest = self.get(observation_id)
        if (
            latest.status == "closed"
            and latest.close_decision == exact_decision
            and latest.close_reason == exact_reason
        ):
            return latest
        raise RiskLifecycleConflict("RISK_CLOSE_CONFLICT")


class TurnRiskEvaluationRepository:
    """Durably gate generation on an atomic risk-result persistence closure."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        database_scope: Literal["client"],
        clock: Clock | None = None,
    ) -> None:
        if database_scope != "client":
            raise ValueError("RISK_REPOSITORY_REQUIRES_CLIENT_DATABASE")
        self.connection = connection
        self.clock = clock if clock is not None else SystemClock()

    def _turn_message_sha256(self, session_id: str, turn_id: str) -> str:
        row = self.connection.execute(
            "SELECT client_message_sha256 FROM turns "
            "WHERE session_id = ? AND turn_id = ?",
            (session_id, turn_id),
        ).fetchone()
        if row is None or type(row[0]) is not str:
            raise RiskRepositoryError("TURN_RISK_EVALUATION_TURN_UNAVAILABLE")
        return str(row[0])

    @staticmethod
    def _from_row(row: tuple[object, ...]) -> TurnRiskEvaluationRecord:
        if len(row) != 20:
            raise RiskRepositoryError("TURN_RISK_EVALUATION_CORRUPT")
        completed_at = row[19]
        if completed_at is not None:
            if type(completed_at) is not str:
                raise RiskRepositoryError("TURN_RISK_EVALUATION_CORRUPT")
            try:
                completed_at = datetime.fromisoformat(
                    completed_at.replace("Z", "+00:00")
                )
            except ValueError:
                raise RiskRepositoryError(
                    "TURN_RISK_EVALUATION_CORRUPT"
                ) from None
        try:
            return TurnRiskEvaluationRecord.model_validate(
                {
                    "session_id": row[0],
                    "turn_id": row[1],
                    "evaluation_revision": row[2],
                    "client_message_sha256": row[3],
                    "authority_sha256": row[4],
                    "authority": {
                        "global_runtime_epoch": row[5],
                        "risk_policy_manifest_ref": {
                            "object_id": row[6],
                            "version": row[7],
                            "content_sha256": row[8],
                        },
                        "model_mode": row[9],
                        "risk_model_manifest_ref": (
                            None
                            if row[10] is None
                            else {
                                "object_id": row[10],
                                "version": row[11],
                                "content_sha256": row[12],
                            }
                        ),
                        "approved_model_ref": (
                            None
                            if row[13] is None
                            else {
                                "object_id": row[13],
                                "version": row[14],
                                "content_sha256": row[15],
                            }
                        ),
                    },
                    "status": row[16],
                    "observation_set_sha256": row[17],
                    "observation_count": row[18],
                    "completed_at": completed_at,
                },
                strict=True,
            )
        except ValidationError:
            raise RiskRepositoryError("TURN_RISK_EVALUATION_CORRUPT") from None

    def get(
        self,
        session_id: str,
        turn_id: str,
        *,
        authority: RiskEvaluationAuthorityBinding | None = None,
    ) -> TurnRiskEvaluationRecord:
        authority_hash = (
            None
            if authority is None
            else risk_evaluation_authority_sha256(authority)
        )
        row = self.connection.execute(
            """
            SELECT session_id, turn_id, evaluation_revision,
                   client_message_sha256, authority_sha256,
                   risk_global_runtime_epoch,
                   risk_policy_manifest_object_id,
                   risk_policy_manifest_version,
                   risk_policy_manifest_sha256,
                   risk_model_mode,
                   risk_model_manifest_object_id,
                   risk_model_manifest_version,
                   risk_model_manifest_sha256,
                   approved_model_object_id,
                   approved_model_version,
                   approved_model_sha256,
                   status, observation_set_sha256, observation_count,
                   completed_at
              FROM turn_risk_evaluations
             WHERE session_id = ? AND turn_id = ?
               AND (? IS NULL OR authority_sha256 = ?)
             ORDER BY evaluation_revision DESC
             LIMIT 1
            """,
            (session_id, turn_id, authority_hash, authority_hash),
        ).fetchone()
        if row is None:
            raise RiskRepositoryError("TURN_RISK_EVALUATION_MISSING")
        return self._from_row(tuple(row))

    def observations_for(
        self,
        evaluation: TurnRiskEvaluationRecord,
    ) -> tuple[InternalRiskObservationRecord, ...]:
        """Read the immutable result membership of one completed revision."""

        try:
            exact = TurnRiskEvaluationRecord.model_validate(
                evaluation,
                strict=True,
            )
        except ValidationError:
            raise RiskRepositoryError(
                "TURN_RISK_EVALUATION_MEMBERSHIP_CORRUPT"
            ) from None
        stored = self.get(
            exact.session_id,
            exact.turn_id,
            authority=exact.authority,
        )
        if stored != exact or exact.status != "completed":
            raise RiskRepositoryError("TURN_RISK_EVALUATION_MEMBERSHIP_CORRUPT")
        rows = self.connection.execute(
            """
            SELECT observation_id, ordinal,
                   record_snapshot_json, record_snapshot_sha256
              FROM turn_risk_evaluation_observations
             WHERE session_id = ? AND turn_id = ?
               AND evaluation_revision = ?
             ORDER BY ordinal
            """,
            (
                exact.session_id,
                exact.turn_id,
                exact.evaluation_revision,
            ),
        ).fetchall()
        identifiers = tuple(str(row[0]) for row in rows)
        ordinals = tuple(int(row[1]) for row in rows)
        if (
            exact.observation_count is None
            or exact.observation_set_sha256 is None
            or len(rows) != exact.observation_count
            or ordinals != tuple(range(len(rows)))
            or identifiers != tuple(sorted(set(identifiers)))
        ):
            raise RiskRepositoryError("TURN_RISK_EVALUATION_MEMBERSHIP_CORRUPT")
        repository = InternalRiskObservationRepository(
            self.connection,
            database_scope="client",
            clock=self.clock,
        )
        observations: tuple[InternalRiskObservationRecord, ...] = tuple(
            repository._from_snapshot(
                row[2],
                row[3],
                lifecycle=repository.get(identifier),
            )
            for identifier, row in zip(identifiers, rows, strict=True)
        )
        if any(
            item.observation.observation_id != identifier
            or not _matches_source_authority(
                item,
                model_mode=exact.authority.model_mode,
                approved_model_ref=exact.authority.approved_model_ref,
            )
            or not _matches_turn_binding(
                self.connection,
                item,
                session_id=exact.session_id,
                turn_id=exact.turn_id,
            )
            for identifier, item in zip(identifiers, observations, strict=True)
        ):
            raise RiskRepositoryError("TURN_RISK_EVALUATION_MEMBERSHIP_CORRUPT")
        if (
            canonical_risk_observation_set_sha256(observations)
            != exact.observation_set_sha256
        ):
            raise RiskRepositoryError("TURN_RISK_EVALUATION_MEMBERSHIP_CORRUPT")
        return observations

    def ensure_pending(
        self,
        session_id: str,
        turn_id: str,
        *,
        client_message_sha256: str,
        authority: RiskEvaluationAuthorityBinding,
    ) -> TurnRiskEvaluationRecord:
        try:
            exact_hash = _SHA256_ADAPTER.validate_python(
                client_message_sha256,
                strict=True,
            )
        except ValidationError:
            raise ValueError("client_message_sha256 must be lowercase SHA-256") from None
        try:
            exact_authority = RiskEvaluationAuthorityBinding.model_validate(
                authority,
                strict=True,
            )
        except ValidationError:
            raise ValueError("risk authority binding is invalid") from None
        if self._turn_message_sha256(session_id, turn_id) != exact_hash:
            raise RiskLifecycleConflict("TURN_RISK_MESSAGE_BINDING_CONFLICT")
        authority_hash = risk_evaluation_authority_sha256(exact_authority)
        model_ref = exact_authority.approved_model_ref
        with transaction(self.connection):
            existing = self.connection.execute(
                "SELECT evaluation_revision FROM turn_risk_evaluations "
                "WHERE session_id = ? AND turn_id = ? AND authority_sha256 = ?",
                (session_id, turn_id, authority_hash),
            ).fetchone()
            if existing is None:
                revision = int(
                    self.connection.execute(
                        "SELECT COALESCE(MAX(evaluation_revision), 0) + 1 "
                        "FROM turn_risk_evaluations "
                        "WHERE session_id = ? AND turn_id = ?",
                        (session_id, turn_id),
                    ).fetchone()[0]
                )
                self.connection.execute(
                    """
                    INSERT INTO turn_risk_evaluations(
                        session_id, turn_id, evaluation_revision,
                        client_message_sha256, authority_sha256,
                        risk_global_runtime_epoch,
                        risk_policy_manifest_object_id,
                        risk_policy_manifest_version,
                        risk_policy_manifest_sha256,
                        risk_model_mode,
                        risk_model_manifest_object_id,
                        risk_model_manifest_version,
                        risk_model_manifest_sha256,
                        approved_model_object_id,
                        approved_model_version,
                        approved_model_sha256,
                        status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              'pending')
                    """,
                    (
                        session_id,
                        turn_id,
                        revision,
                        exact_hash,
                        authority_hash,
                        exact_authority.global_runtime_epoch,
                        exact_authority.risk_policy_manifest_ref.object_id,
                        exact_authority.risk_policy_manifest_ref.version,
                        exact_authority.risk_policy_manifest_ref.content_sha256,
                        exact_authority.model_mode,
                        (
                            None
                            if exact_authority.risk_model_manifest_ref is None
                            else exact_authority.risk_model_manifest_ref.object_id
                        ),
                        (
                            None
                            if exact_authority.risk_model_manifest_ref is None
                            else exact_authority.risk_model_manifest_ref.version
                        ),
                        (
                            None
                            if exact_authority.risk_model_manifest_ref is None
                            else exact_authority.risk_model_manifest_ref.content_sha256
                        ),
                        None if model_ref is None else model_ref.object_id,
                        None if model_ref is None else model_ref.version,
                        None if model_ref is None else model_ref.content_sha256,
                    ),
                )
        current = self.get(session_id, turn_id, authority=exact_authority)
        if current.client_message_sha256 != exact_hash:
            raise RiskLifecycleConflict("TURN_RISK_MESSAGE_BINDING_CONFLICT")
        if current.authority != exact_authority:
            raise RiskLifecycleConflict("TURN_RISK_AUTHORITY_BINDING_CONFLICT")
        return current

    def require_completed(
        self,
        session_id: str,
        turn_id: str,
        *,
        client_message_sha256: str,
        authority: RiskEvaluationAuthorityBinding,
    ) -> TurnRiskEvaluationRecord:
        try:
            exact_authority = RiskEvaluationAuthorityBinding.model_validate(
                authority,
                strict=True,
            )
        except ValidationError:
            raise RiskLifecycleConflict("TURN_RISK_AUTHORITY_BINDING_CONFLICT") from None
        latest = self.get(session_id, turn_id)
        if (
            latest.client_message_sha256 != client_message_sha256
            or self._turn_message_sha256(session_id, turn_id)
            != client_message_sha256
        ):
            raise RiskLifecycleConflict("TURN_RISK_MESSAGE_BINDING_CONFLICT")
        if latest.authority != exact_authority:
            raise RiskLifecycleConflict("TURN_RISK_AUTHORITY_BINDING_STALE")
        try:
            current = self.get(
                session_id,
                turn_id,
                authority=exact_authority,
            )
        except RiskRepositoryError:
            raise RiskLifecycleConflict("TURN_RISK_AUTHORITY_BINDING_STALE")
        if current.status != "completed":
            raise RiskLifecycleConflict("TURN_RISK_EVALUATION_PENDING")
        return current

    def persist_completed(
        self,
        session_id: str,
        turn_id: str,
        *,
        client_message_sha256: str,
        authority: RiskEvaluationAuthorityBinding,
        observations: tuple[InternalRiskObservationRecord, ...],
    ) -> TurnRiskEvaluationRecord:
        try:
            exact_authority = RiskEvaluationAuthorityBinding.model_validate(
                authority,
                strict=True,
            )
        except ValidationError:
            raise RiskLifecycleConflict("TURN_RISK_AUTHORITY_BINDING_CONFLICT") from None
        exact = tuple(
            InternalRiskObservationRecord.model_validate(item, strict=True)
            for item in observations
        )
        if any(
            item.status != "open"
            or not _matches_source_authority(
                item,
                model_mode=exact_authority.model_mode,
                approved_model_ref=exact_authority.approved_model_ref,
            )
            or not _matches_turn_binding(
                self.connection,
                item,
                session_id=session_id,
                turn_id=turn_id,
            )
            for item in exact
        ):
            raise RiskLifecycleConflict("TURN_RISK_EVALUATION_SCOPE_CONFLICT")
        result_sha256 = canonical_risk_observation_set_sha256(exact)
        result_count = len(exact)
        if self._turn_message_sha256(session_id, turn_id) != client_message_sha256:
            raise RiskLifecycleConflict("TURN_RISK_MESSAGE_BINDING_CONFLICT")
        try:
            latest = self.get(session_id, turn_id)
        except RiskRepositoryError:
            raise RiskLifecycleConflict("TURN_RISK_EVALUATION_MISSING") from None
        if latest.authority != exact_authority:
            raise RiskLifecycleConflict("TURN_RISK_AUTHORITY_BINDING_STALE")
        observation_repository = InternalRiskObservationRepository(
            self.connection,
            database_scope="client",
            clock=self.clock,
        )
        authority_hash = risk_evaluation_authority_sha256(exact_authority)
        with transaction(self.connection):
            row = self.connection.execute(
                """
                SELECT session_id, turn_id, evaluation_revision,
                       client_message_sha256, authority_sha256,
                       risk_global_runtime_epoch,
                       risk_policy_manifest_object_id,
                       risk_policy_manifest_version,
                       risk_policy_manifest_sha256,
                       risk_model_mode,
                       risk_model_manifest_object_id,
                       risk_model_manifest_version,
                       risk_model_manifest_sha256,
                       approved_model_object_id,
                       approved_model_version,
                       approved_model_sha256,
                       status, observation_set_sha256, observation_count,
                       completed_at
                  FROM turn_risk_evaluations
                 WHERE session_id = ? AND turn_id = ? AND authority_sha256 = ?
                """,
                (session_id, turn_id, authority_hash),
            ).fetchone()
            if row is None:
                raise RiskLifecycleConflict("TURN_RISK_EVALUATION_MISSING")
            current_evaluation = self._from_row(tuple(row))
            if current_evaluation.client_message_sha256 != client_message_sha256:
                raise RiskLifecycleConflict("TURN_RISK_MESSAGE_BINDING_CONFLICT")
            if (
                current_evaluation.authority != exact_authority
                or current_evaluation.authority_sha256 != authority_hash
            ):
                raise RiskLifecycleConflict(
                    "TURN_RISK_AUTHORITY_BINDING_CONFLICT"
                )
            if current_evaluation.status == "completed":
                if (
                    current_evaluation.observation_set_sha256,
                    current_evaluation.observation_count,
                ) != (result_sha256, result_count):
                    raise RiskLifecycleConflict("TURN_RISK_EVALUATION_CONFLICT")
                self.observations_for(current_evaluation)
                return current_evaluation
            if current_evaluation.status != "pending":
                raise RiskRepositoryError("TURN_RISK_EVALUATION_CORRUPT")

            for ordinal, item in enumerate(exact):
                snapshot_item = item
                existing = self.connection.execute(
                    "SELECT observation_id FROM internal_risk_observations "
                    "WHERE observation_id = ?",
                    (item.observation.observation_id,),
                ).fetchone()
                if existing is None:
                    immutable_json = observation_repository._immutable_json(item)
                    self.connection.execute(
                        """
                        INSERT INTO internal_risk_observations(
                            observation_id, session_id,
                            immutable_record_json, status
                        ) VALUES (?, ?, ?, 'open')
                        """,
                        (
                            item.observation.observation_id,
                            item.session_id,
                            immutable_json,
                        ),
                    )
                else:
                    current = observation_repository.get(
                        item.observation.observation_id
                    )
                    if (
                        observation_repository._semantic_core_json(current)
                        != observation_repository._semantic_core_json(item)
                    ):
                        raise RiskLifecycleConflict(
                            "RISK_OBSERVATION_ID_CONFLICT"
                        )
                    snapshot_item = InternalRiskObservationRecord.model_validate(
                        {
                            **item.model_dump(),
                            "observation": {
                                **item.observation.model_dump(),
                                "detected_at": current.observation.detected_at,
                            },
                        },
                        strict=True,
                    )
                snapshot_json = observation_repository._immutable_json(
                    snapshot_item
                )
                self.connection.execute(
                    """
                    INSERT INTO turn_risk_evaluation_observations(
                        session_id, turn_id, evaluation_revision,
                        observation_id, ordinal, record_snapshot_json,
                        record_snapshot_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        turn_id,
                        current_evaluation.evaluation_revision,
                        item.observation.observation_id,
                        ordinal,
                        snapshot_json,
                        _snapshot_sha256(snapshot_json),
                    ),
                )

            changed = self.connection.execute(
                """
                UPDATE turn_risk_evaluations
                   SET status = 'completed', observation_set_sha256 = ?,
                       observation_count = ?, completed_at = ?
                 WHERE session_id = ? AND turn_id = ? AND status = 'pending'
                   AND evaluation_revision = ? AND authority_sha256 = ?
                """,
                (
                    result_sha256,
                    result_count,
                    _utc_text(self.clock.now()),
                    session_id,
                    turn_id,
                    current_evaluation.evaluation_revision,
                    authority_hash,
                ),
            ).rowcount
            if changed != 1:
                raise RiskLifecycleConflict("TURN_RISK_EVALUATION_CONFLICT")
        completed = self.get(session_id, turn_id, authority=exact_authority)
        self.observations_for(completed)
        return completed


__all__ = [
    "canonical_risk_observation_set_sha256",
    "InternalRiskObservationRecord",
    "InternalRiskObservationRepository",
    "RiskLifecycleConflict",
    "RiskEvaluationAuthorityBinding",
    "RiskObservationSource",
    "RiskRepositoryError",
    "RiskTriggerSpan",
    "risk_evaluation_authority_sha256",
    "TurnRiskEvaluationRecord",
    "TurnRiskEvaluationRepository",
]
