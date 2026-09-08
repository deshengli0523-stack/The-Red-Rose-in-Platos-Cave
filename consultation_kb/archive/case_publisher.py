"""Idempotent source-outbox to global shared-case publication saga."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from datetime import datetime
from typing import Literal, Protocol, runtime_checkable

from pydantic import model_validator

from consultation_kb.archive.case_catalog import CaseCatalog
from consultation_kb.archive.publication_proof import (
    CasePublicationProof,
    CasePublicationProofPayload,
    CasePublicationProofSigner,
)
from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import canonical_json_bytes, canonical_sha256
from consultation_kb.lifecycle.publish import publication_closure_sha256
from consultation_kb.models.cases import (
    CaseContribution,
    CaseProvenanceRecord,
    CaseReleaseDecision,
    CaseReuseAuthorization,
    DeidentificationHumanReview,
    ReviewCategory,
    SharedCaseCandidate,
    case_provenance_payload,
    shared_case_candidate_payload,
)
from consultation_kb.models.common import (
    ObjectId,
    NonNegativeInt,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    VersionRef,
)
from consultation_kb.storage.connection import transaction
from consultation_kb.storage.manifests import ManifestMember, ManifestRepository
from consultation_kb.storage.outbox import (
    CasePublishOutboxPayload,
    OutboxRecord,
    case_publish_payload_bytes,
)
from consultation_kb.vault.content_store import ContentStore


class CasePublishError(RuntimeError):
    def __init__(self, code: str = "CASE_PUBLISH_INVALID") -> None:
        self.code = code
        super().__init__(code)


def case_release_decision_sha256(value: CaseReleaseDecision) -> str:
    exact = CaseReleaseDecision.model_validate(value)
    return canonical_sha256(exact.model_dump(mode="json"))


def shared_candidate_bytes(value: SharedCaseCandidate) -> bytes:
    exact = SharedCaseCandidate.model_validate(value)
    return canonical_json_bytes(
        shared_case_candidate_payload(
            candidate_id=exact.candidate_ref.object_id,
            version=exact.candidate_ref.version,
            source_record_sha256=exact.source_record_sha256,
            actual_transcript_sha256=exact.actual_transcript_sha256,
            sections=exact.sections,
            deidentification=exact.deidentification,
            provenance=exact.provenance,
            requested_allowed_uses=frozenset(exact.requested_allowed_uses),
            incomplete_evidence=exact.incomplete_evidence,
            created_at=exact.created_at,
        )
    )


class CasePublishTransfer(StrictModel):
    """Governed objects resolved by a transfer broker, never by global DB lookup."""

    outbox_payload: CasePublishOutboxPayload
    candidate: SharedCaseCandidate
    authorization: CaseReuseAuthorization
    review: DeidentificationHumanReview
    release_decision: CaseReleaseDecision

    @model_validator(mode="after")
    def _exact_transfer(self) -> "CasePublishTransfer":
        payload = self.outbox_payload
        candidate_bytes = shared_candidate_bytes(self.candidate)
        if (
            payload.candidate_ref != self.candidate.candidate_ref
            or payload.candidate_sha256 != self.candidate.candidate_sha256
            or payload.candidate_media_type != "application/json"
            or payload.candidate_size_bytes != len(candidate_bytes)
            or payload.authorization_ref != self.authorization.authorization_ref
            or payload.review_ref != self.review.review_ref
            or payload.release_policy_ref != self.release_decision.policy_ref
            or payload.provenance_ref != self.candidate.provenance.provenance_ref
            or payload.release_decision_sha256
            != case_release_decision_sha256(self.release_decision)
        ):
            raise ValueError("case transfer does not bind exact governed objects")
        return self


class CasePublishAuthoritySnapshot(StrictModel):
    """Current body-free authority for one exact source publication payload."""

    candidate_ref: VersionRef
    authorization_ref: VersionRef
    review_ref: VersionRef
    release_policy_ref: VersionRef
    release_decision_sha256: Sha256Hex
    provenance_ref: VersionRef
    purpose: SafePolicyKey
    approval_operation_id: ObjectId
    approval_request_id: ObjectId
    approval_descriptor_sha256: Sha256Hex
    approval_draft_sha256: Sha256Hex
    approval_descriptor_base_version: NonNegativeInt
    approval_applied_commit_version: NonNegativeInt
    approval_target_scope_hash: Sha256Hex
    authority_epoch: NonNegativeInt
    state: Literal["active", "revoked", "expired", "superseded"]


@runtime_checkable
class CasePublishAuthorityResolver(Protocol):
    """Resolve current authority without receiving any candidate body."""

    def resolve_case_publish_authority(
        self,
        *,
        payload: CasePublishOutboxPayload,
        as_of: datetime,
    ) -> CasePublishAuthoritySnapshot | None: ...


class CasePublication(StrictModel):
    source_event_id: ObjectId
    case_ref: VersionRef
    manifest_id: ObjectId
    provenance_ref: VersionRef
    state: Literal["ACTIVE"] = "ACTIVE"
    published_global_version: PositiveInt
    proof: CasePublicationProof

    @model_validator(mode="after")
    def _version_binding(self) -> "CasePublication":
        payload = self.proof.payload
        if (
            self.published_global_version != self.case_ref.version
            or payload.source_event_id != self.source_event_id
            or payload.case_ref != self.case_ref
            or payload.manifest_id != self.manifest_id
            or payload.provenance_ref != self.provenance_ref
            or payload.published_global_version != self.published_global_version
            or payload.state != self.state
        ):
            raise ValueError("published case version mismatch")
        return self


class _PublishSaga(StrictModel):
    saga_id: ObjectId
    source_event_id: ObjectId
    idempotency_key_sha256: Sha256Hex
    outbox_payload_sha256: Sha256Hex
    case_id: ObjectId
    case_version: PositiveInt
    candidate_id: ObjectId
    candidate_version: PositiveInt
    candidate_sha256: Sha256Hex
    publication_operation_id: ObjectId
    manifest_id: ObjectId
    provenance_id: ObjectId
    provenance_version: PositiveInt
    global_content_sha256: Sha256Hex | None = None
    global_content_media_type: Literal["application/json"] | None = None
    global_content_size_bytes: PositiveInt | None = None
    state: Literal["RECEIVED", "COPIED", "PREPARED", "ACTIVE"]
    authority_epoch: NonNegativeInt | None = None
    attempt_count: int
    published_global_version: PositiveInt | None = None
    created_at: UtcDateTime
    updated_at: UtcDateTime

    @model_validator(mode="after")
    def _authority_epoch_shape(self) -> "_PublishSaga":
        requires_epoch = self.state in {"PREPARED", "ACTIVE"}
        if requires_epoch != (self.authority_epoch is not None):
            raise ValueError("publish saga authority epoch does not match state")
        return self


FaultHook = Callable[[str], None]


_REQUIRED_REVIEW_CATEGORIES: frozenset[ReviewCategory] = frozenset(
    {
        "direct_identifiers",
        "third_party_people",
        "rare_attributes",
        "location_occupation_family_time",
        "section_boundaries",
        "no_verbatim_quotes",
    }
)


def _utc_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise ValueError("stored saga timestamp must be text")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _idempotency_hash(value: str) -> str:
    return hashlib.sha256(
        b"shared-case-global-publish\0" + value.encode("utf-8", errors="strict")
    ).hexdigest()


def _case_artifact_key(case_id: str) -> str:
    digest = hashlib.sha256(case_id.encode("ascii", errors="strict")).hexdigest()
    return f"case_{digest[:59]}"


def _global_case_body(candidate: SharedCaseCandidate) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": "global_case_body.v1",
            "sections": [
                {
                    "section_kind": section.section_kind,
                    "text": section.text,
                    "text_sha256": section.text_sha256,
                }
                for section in candidate.sections
            ],
        }
    )


class SharedCasePublisher:
    """Publish only from a supplied sealed transfer; never open a client DB."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        content_store: ContentStore,
        *,
        authority_resolver: CasePublishAuthorityResolver,
        publication_proof_signer: CasePublicationProofSigner,
        clock: Clock | None = None,
        id_factory: IdFactory | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SharedCasePublisher requires a global SQLite connection")
        if not isinstance(content_store, ContentStore):
            raise TypeError("SharedCasePublisher requires a global ContentStore")
        if not isinstance(authority_resolver, CasePublishAuthorityResolver):
            raise TypeError("SharedCasePublisher requires an authority resolver")
        if not isinstance(publication_proof_signer, CasePublicationProofSigner):
            raise TypeError("SharedCasePublisher requires a publication proof signer")
        self._connection = connection
        self._content_store = content_store
        self._authority = authority_resolver
        self._proof_signer = publication_proof_signer
        self._clock = clock if clock is not None else SystemClock()
        self._ids = id_factory if id_factory is not None else IdFactory(self._clock)

    def process(
        self,
        event: OutboxRecord,
        transfer: CasePublishTransfer,
        *,
        fault_hook: FaultHook | None = None,
    ) -> CasePublication:
        source_event = OutboxRecord.model_validate(event)
        package = CasePublishTransfer.model_validate(transfer)
        self._validate_outbox_binding(source_event, package.outbox_payload)
        saga = self._load_or_receive(source_event, package)
        if saga.state == "RECEIVED":
            self._fault(fault_hook, "before_copy")
            body = _global_case_body(package.candidate)
            staged = self._content_store.stage_bytes(
                body,
                purpose="shared_case_publish",
                manifest_id=saga.manifest_id,
                media_type="application/json",
            )
            copied = self._content_store.finalize(staged)
            saga = self._mark_copied(
                saga,
                content_sha256=copied.content_sha256,
                content_size_bytes=copied.size_bytes,
            )
            self._fault(fault_hook, "after_copy")
            self._fault(fault_hook, "after_global_copy")
        if saga.state == "COPIED":
            self._fault(fault_hook, "before_catalog_prepare")
            self._validate_release(package)
            saga = self._prepare_catalog(saga, package)
            self._fault(fault_hook, "after_catalog_prepare")
            self._fault(fault_hook, "after_global_prepare")
        if saga.state == "PREPARED":
            self._fault(fault_hook, "before_activate")
            saga = self._activate(saga, package)
            self._fault(fault_hook, "after_activate")
            self._fault(fault_hook, "after_global_activate")
        if saga.state != "ACTIVE":
            raise CasePublishError("CASE_PUBLISH_SAGA_INCOMPLETE")
        authority = self._resolve_live_authority(
            package,
            as_of=self._clock.now(),
            minimum_epoch=saga.authority_epoch,
        )
        return self._publication(saga, package, authority)

    def replay(
        self,
        event: OutboxRecord,
        transfer: CasePublishTransfer,
        *,
        fault_hook: FaultHook | None = None,
    ) -> CasePublication:
        return self.process(event, transfer, fault_hook=fault_hook)

    @staticmethod
    def _fault(hook: FaultHook | None, phase: str) -> None:
        if hook is not None:
            hook(phase)

    @staticmethod
    def _validate_outbox_binding(
        event: OutboxRecord,
        payload: CasePublishOutboxPayload,
    ) -> None:
        serialized = case_publish_payload_bytes(payload)
        if (
            event.event_type != "shared_case_publish"
            or event.idempotency_key != payload.idempotency_key
            or event.payload.media_type != "application/json"
            or event.payload.content_sha256
            != hashlib.sha256(serialized).hexdigest()
            or event.payload.size_bytes != len(serialized)
        ):
            raise CasePublishError("CASE_PUBLISH_OUTBOX_BINDING_INVALID")

    def _load_or_receive(
        self,
        event: OutboxRecord,
        transfer: CasePublishTransfer,
    ) -> _PublishSaga:
        idempotency_sha256 = _idempotency_hash(event.idempotency_key)
        now = self._clock.now()
        with transaction(self._connection):
            rows = self._connection.execute(
                self._SAGA_SELECT
                + " WHERE source_event_id = ? OR idempotency_key_sha256 = ?"
                + " OR (candidate_id = ? AND candidate_version = ?)",
                (
                    event.event_id,
                    idempotency_sha256,
                    transfer.candidate.candidate_ref.object_id,
                    transfer.candidate.candidate_ref.version,
                ),
            ).fetchall()
            if len(rows) > 1:
                raise CasePublishError("CASE_PUBLISH_IDEMPOTENCY_CONFLICT")
            if rows:
                saga = self._saga_from_row(rows[0])
                if (
                    saga.outbox_payload_sha256 != event.payload.content_sha256
                    or saga.candidate_id
                    != transfer.candidate.candidate_ref.object_id
                    or saga.candidate_version
                    != transfer.candidate.candidate_ref.version
                    or saga.candidate_sha256
                    != transfer.candidate.candidate_sha256
                ):
                    raise CasePublishError("CASE_PUBLISH_IDEMPOTENCY_CONFLICT")
            else:
                saga = _PublishSaga(
                    saga_id=self._ids.object_id("global_case_publish_saga"),
                    source_event_id=event.event_id,
                    idempotency_key_sha256=idempotency_sha256,
                    outbox_payload_sha256=event.payload.content_sha256,
                    case_id=self._ids.object_id("case"),
                    case_version=1,
                    candidate_id=transfer.candidate.candidate_ref.object_id,
                    candidate_version=transfer.candidate.candidate_ref.version,
                    candidate_sha256=transfer.candidate.candidate_sha256,
                    publication_operation_id=self._ids.object_id(
                        "case_publication_operation"
                    ),
                    manifest_id=self._ids.object_id("case_manifest"),
                    provenance_id=self._ids.object_id("case_provenance"),
                    provenance_version=1,
                    state="RECEIVED",
                    attempt_count=0,
                    created_at=now,
                    updated_at=now,
                )
                self._connection.execute(
                    """
                    INSERT INTO global_publish_sagas(
                        saga_id, source_event_id, idempotency_key_sha256,
                        outbox_payload_sha256, case_id, case_version,
                        candidate_id, candidate_version, candidate_sha256,
                        publication_operation_id, manifest_id,
                        provenance_id, provenance_version,
                        global_content_sha256, global_content_media_type,
                        global_content_size_bytes, state, authority_epoch,
                        attempt_count,
                        published_global_version, last_error_code,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              NULL, NULL, NULL, 'RECEIVED', NULL, 0,
                              NULL, NULL, ?, ?)
                    """,
                    (
                        saga.saga_id,
                        saga.source_event_id,
                        saga.idempotency_key_sha256,
                        saga.outbox_payload_sha256,
                        saga.case_id,
                        saga.case_version,
                        saga.candidate_id,
                        saga.candidate_version,
                        saga.candidate_sha256,
                        saga.publication_operation_id,
                        saga.manifest_id,
                        saga.provenance_id,
                        saga.provenance_version,
                        _utc_text(saga.created_at),
                        _utc_text(saga.updated_at),
                    ),
                )
            self._connection.execute(
                """
                UPDATE global_publish_sagas
                   SET attempt_count = attempt_count + 1, updated_at = ?,
                       last_error_code = NULL
                 WHERE saga_id = ?
                """,
                (_utc_text(now), saga.saga_id),
            )
        return self._get_saga(saga.saga_id)

    def _mark_copied(
        self,
        saga: _PublishSaga,
        *,
        content_sha256: str,
        content_size_bytes: int,
    ) -> _PublishSaga:
        now = self._clock.now()
        with transaction(self._connection):
            current = self._get_saga(saga.saga_id)
            if current.state == "RECEIVED":
                self._connection.execute(
                    """
                    UPDATE global_publish_sagas
                       SET global_content_sha256 = ?,
                           global_content_media_type = 'application/json',
                           global_content_size_bytes = ?, state = 'COPIED',
                           updated_at = ?
                     WHERE saga_id = ? AND state = 'RECEIVED'
                    """,
                    (
                        content_sha256,
                        content_size_bytes,
                        _utc_text(now),
                        saga.saga_id,
                    ),
                )
        return self._get_saga(saga.saga_id)

    @staticmethod
    def _validate_release(transfer: CasePublishTransfer) -> None:
        candidate = transfer.candidate
        authorization = transfer.authorization
        review = transfer.review
        decision = transfer.release_decision
        evaluated_at = decision.evaluated_at
        contributor_hashes = candidate.provenance.contributor_client_hashes
        allowed = (
            candidate.requested_allowed_uses
            & authorization.allowed_uses
            & review.allowed_uses
        )
        section_kinds = {item.section_kind for item in candidate.sections}
        if (
            decision.outcome != "eligible"
            or decision.reasons
            or not decision.allowed_uses
            or decision.candidate_sha256 != candidate.candidate_sha256
            or decision.authorization_ref != authorization.authorization_ref
            or decision.review_ref != review.review_ref
            or transfer.outbox_payload.purpose not in decision.allowed_uses
            or decision.allowed_uses != allowed
            or not authorization.reuse_authorized
            or authorization.contributor_client_hash not in contributor_hashes
            or evaluated_at < authorization.valid_from
            or (
                authorization.expires_at is not None
                and evaluated_at >= authorization.expires_at
            )
            or (
                authorization.revoked_at is not None
                and evaluated_at >= authorization.revoked_at
            )
            or review.decision != "approved"
            or review.candidate_sha256 != candidate.candidate_sha256
            or review.reviewed_at < candidate.created_at
            or review.reviewed_at > evaluated_at
            or review.residual_risk == "high"
            or review.rare_combination_disposition == "unresolved"
            or not _REQUIRED_REVIEW_CATEGORIES.issubset(
                review.checked_categories
            )
            or not candidate.deidentification.automatic_scan_complete
            or candidate.incomplete_evidence
            or not {"factual_context", "actual_response"}.issubset(section_kinds)
        ):
            raise CasePublishError("CASE_PUBLISH_RELEASE_INVALID")

    def _resolve_live_authority(
        self,
        transfer: CasePublishTransfer,
        *,
        as_of: datetime,
        minimum_epoch: int | None,
    ) -> CasePublishAuthoritySnapshot:
        payload = transfer.outbox_payload
        try:
            resolved = self._authority.resolve_case_publish_authority(
                payload=payload,
                as_of=as_of,
            )
            authority = (
                None
                if resolved is None
                else CasePublishAuthoritySnapshot.model_validate(resolved)
            )
        except Exception:
            raise CasePublishError(
                "CASE_PUBLISH_AUTHORITY_RESOLUTION_FAILED"
            ) from None
        if authority is None:
            raise CasePublishError("CASE_PUBLISH_AUTHORITY_NOT_FOUND")
        if (
            authority.candidate_ref != payload.candidate_ref
            or authority.authorization_ref != payload.authorization_ref
            or authority.review_ref != payload.review_ref
            or authority.release_policy_ref != payload.release_policy_ref
            or authority.release_decision_sha256
            != payload.release_decision_sha256
            or authority.provenance_ref != payload.provenance_ref
            or authority.purpose != payload.purpose
            or authority.approval_operation_id
            != payload.approval_operation_id
            or authority.approval_request_id != payload.approval_request_id
            or authority.approval_descriptor_sha256
            != payload.approval_descriptor_sha256
            or authority.approval_draft_sha256
            != payload.approval_draft_sha256
            or authority.approval_descriptor_base_version
            != payload.candidate_ref.version
            or authority.approval_applied_commit_version <= 0
            or authority.approval_target_scope_hash
            != payload.approval_target_scope_hash
        ):
            raise CasePublishError("CASE_PUBLISH_AUTHORITY_MISMATCH")
        if authority.state != "active":
            raise CasePublishError("CASE_PUBLISH_AUTHORITY_NOT_ACTIVE")
        authorization = transfer.authorization
        if (
            as_of < transfer.release_decision.evaluated_at
            or as_of < authorization.valid_from
            or (
                authorization.expires_at is not None
                and as_of >= authorization.expires_at
            )
            or (
                authorization.revoked_at is not None
                and as_of >= authorization.revoked_at
            )
        ):
            raise CasePublishError("CASE_PUBLISH_AUTHORITY_NOT_ACTIVE")
        if (
            minimum_epoch is not None
            and authority.authority_epoch < minimum_epoch
        ):
            raise CasePublishError("CASE_PUBLISH_AUTHORITY_EPOCH_ROLLBACK")
        return authority

    def _prepare_catalog(
        self,
        saga: _PublishSaga,
        transfer: CasePublishTransfer,
    ) -> _PublishSaga:
        if (
            saga.global_content_sha256 is None
            or saga.global_content_size_bytes is None
        ):
            raise CasePublishError("CASE_PUBLISH_COPY_MISSING")
        expected_body = _global_case_body(transfer.candidate)
        stored_body = self._content_store.read_verified(
            self._content_store.reference(
                content_sha256=saga.global_content_sha256,
                media_type="application/json",
                size_bytes=saga.global_content_size_bytes,
            )
        )
        if stored_body != expected_body:
            raise CasePublishError("CASE_PUBLISH_COPY_MISMATCH")
        now = self._clock.now()
        provenance = self._root_provenance(saga, transfer)
        allowed_json = json.dumps(
            sorted(transfer.release_decision.allowed_uses),
            ensure_ascii=True,
            separators=(",", ":"),
        )
        with transaction(self._connection):
            current = self._get_saga(saga.saga_id)
            if current.state != "COPIED":
                return current
            authority = self._resolve_live_authority(
                transfer,
                as_of=now,
                minimum_epoch=current.authority_epoch,
            )
            active_rows = self._connection.execute(
                "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
            ).fetchall()
            if len(active_rows) > 1:
                raise CasePublishError("CASE_PUBLISH_EPOCH_INTEGRITY_ERROR")
            expected_epoch = None if not active_rows else int(active_rows[0][0])
            self._connection.execute(
                """
                INSERT INTO cases(case_id, state, current_version, created_at, updated_at)
                VALUES (?, 'PREPARED', NULL, ?, ?)
                """,
                (saga.case_id, _utc_text(now), _utc_text(now)),
            )
            self._insert_provenance(provenance)
            self._connection.execute(
                """
                INSERT INTO publication_operations(
                    operation_id, purpose, authority_base_version,
                    approval_request_id, descriptor_sha256, state,
                    required_manifests_json, required_manifest_count,
                    verified_manifest_count, expected_current_epoch,
                    runtime_epoch, created_at, activated_at
                ) VALUES (?, 'case_publish', 1, ?, ?, 'PREPARED', ?, 1, 0,
                          ?, NULL, ?, NULL)
                """,
                (
                    saga.publication_operation_id,
                    transfer.outbox_payload.approval_request_id,
                    transfer.outbox_payload.approval_descriptor_sha256,
                    json.dumps([saga.manifest_id], separators=(",", ":")),
                    expected_epoch,
                    _utc_text(now),
                ),
            )
            manifests = ManifestRepository(self._connection)
            manifests.insert_prepared(
                manifest_id=saga.manifest_id,
                operation_id=saga.publication_operation_id,
                artifact_key=_case_artifact_key(saga.case_id),
                artifact_kind="shared_case",
                source_version=saga.case_version,
                members=(
                    ManifestMember(
                        ordinal=0,
                        object_type="case",
                        object_id=saga.case_id,
                        object_sha256=saga.global_content_sha256,
                        source_version=saga.case_version,
                        media_type="application/json",
                        size_bytes=saga.global_content_size_bytes,
                        source_lineage_hashes=tuple(
                            sorted(
                                {
                                    saga.candidate_sha256,
                                    provenance.closure_sha256,
                                    transfer.outbox_payload.release_decision_sha256,
                                }
                            )
                        ),
                    ),
                ),
                created_at=_utc_text(now),
            )
            manifests.mark_verified(
                saga.manifest_id,
                expected_source_version=saga.case_version,
                verified_at=_utc_text(now),
            )
            closure_sha256 = publication_closure_sha256(
                purpose="case_publish",
                authority_base_version=saga.case_version,
                expected_current_epoch=expected_epoch,
                artifacts=(manifests.get(saga.manifest_id),),
            )
            self._connection.execute(
                """
                INSERT INTO publication_closure_attestations(
                    operation_id, approval_draft_sha256,
                    closure_sha256, created_at
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    saga.publication_operation_id,
                    transfer.outbox_payload.approval_draft_sha256,
                    closure_sha256,
                    _utc_text(now),
                ),
            )
            self._connection.execute(
                """
                UPDATE publication_operations
                   SET verified_manifest_count = 1
                 WHERE operation_id = ? AND state = 'PREPARED'
                """,
                (saga.publication_operation_id,),
            )
            self._connection.execute(
                """
                INSERT INTO case_versions(
                    case_id, version, candidate_id, candidate_version,
                    candidate_sha256, global_content_ref, global_content_sha256,
                    global_content_media_type, global_content_size_bytes,
                    manifest_id, release_decision_sha256, allowed_uses_json,
                    source_grade, provenance_id, provenance_version, state,
                    prepared_at, activated_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, 'sha256:' || ?, ?, 'application/json',
                          ?, ?, ?, ?, ?, ?, ?, 'PREPARED', ?, NULL, NULL)
                """,
                (
                    saga.case_id,
                    saga.case_version,
                    saga.candidate_id,
                    saga.candidate_version,
                    saga.candidate_sha256,
                    saga.global_content_sha256,
                    saga.global_content_sha256,
                    saga.global_content_size_bytes,
                    saga.manifest_id,
                    transfer.outbox_payload.release_decision_sha256,
                    allowed_json,
                    transfer.candidate.source_grade,
                    provenance.provenance_ref.object_id,
                    provenance.provenance_ref.version,
                    _utc_text(now),
                ),
            )
            self._insert_authorization(saga, transfer.authorization)
            self._insert_review(saga, transfer)
            self._connection.execute(
                """
                UPDATE global_publish_sagas
                   SET state = 'PREPARED', authority_epoch = ?, updated_at = ?
                 WHERE saga_id = ? AND state = 'COPIED'
                """,
                (authority.authority_epoch, _utc_text(now), saga.saga_id),
            )
        return self._get_saga(saga.saga_id)

    def _root_provenance(
        self,
        saga: _PublishSaga,
        transfer: CasePublishTransfer,
    ) -> CaseProvenanceRecord:
        if saga.global_content_sha256 is None:
            raise CasePublishError("CASE_PUBLISH_COPY_MISSING")
        candidate = transfer.candidate
        authorization = transfer.authorization
        effective_values = tuple(
            item
            for item in (authorization.expires_at, authorization.revoked_at)
            if item is not None
        )
        effective_to = min(effective_values) if effective_values else None
        case_ref = VersionRef(
            object_id=saga.case_id,
            version=saga.case_version,
            content_sha256=saga.global_content_sha256,
        )
        contribution = CaseContribution(
            case_ref=case_ref,
            source_provenance_ref=candidate.provenance.provenance_ref,
            contributor_client_hashes=(
                candidate.provenance.contributor_client_hashes
            ),
            authorization_ref=authorization.authorization_ref,
            allowed_uses=transfer.release_decision.allowed_uses,
            effective_to=effective_to,
            source_grade="K1",
            source_lineage_sha256=(
                candidate.provenance.provenance_ref.content_sha256
            ),
        )
        payload = case_provenance_payload(
            provenance_id=saga.provenance_id,
            version=saga.provenance_version,
            artifact_ref=case_ref,
            artifact_kind="case",
            parent_provenance_refs=(),
            ancestor_artifact_refs=(),
            case_contributions=(contribution,),
            independent_evidence=(),
            contributor_client_hashes=frozenset(
                candidate.provenance.contributor_client_hashes
            ),
            derivation_rule_ref=candidate.provenance.derivation_rule_ref,
            policy_manifest_ref=transfer.release_decision.policy_ref,
            source_grade="K1",
            provenance_scope="case_derived",
            allowed_uses=frozenset(transfer.release_decision.allowed_uses),
            effective_to=effective_to,
        )
        closure_sha256 = canonical_sha256(payload)
        return CaseProvenanceRecord(
            provenance_ref=VersionRef(
                object_id=saga.provenance_id,
                version=saga.provenance_version,
                content_sha256=closure_sha256,
            ),
            artifact_ref=case_ref,
            artifact_kind="case",
            parent_provenance_refs=(),
            ancestor_artifact_refs=(),
            case_contributions=(contribution,),
            independent_evidence=(),
            contributor_client_hashes=(
                candidate.provenance.contributor_client_hashes
            ),
            derivation_rule_ref=candidate.provenance.derivation_rule_ref,
            policy_manifest_ref=transfer.release_decision.policy_ref,
            source_grade="K1",
            provenance_scope="case_derived",
            allowed_uses=transfer.release_decision.allowed_uses,
            effective_to=effective_to,
            closure_sha256=closure_sha256,
        )

    def _insert_provenance(self, value: CaseProvenanceRecord) -> None:
        closure_json = canonical_json_bytes(
            value.model_dump(mode="json")
        ).decode("ascii")
        self._connection.execute(
            """
            INSERT INTO case_provenance(
                provenance_id, provenance_version, provenance_sha256,
                artifact_object_id, artifact_version, artifact_sha256,
                artifact_kind, contributor_client_hashes_json,
                independent_source_count, derivation_rule_id,
                derivation_rule_version, derivation_rule_sha256,
                policy_manifest_id, policy_manifest_version,
                policy_manifest_sha256, source_grade, provenance_scope,
                allowed_uses_json, effective_to, closure_json, closure_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      ?, ?, ?)
            """,
            (
                value.provenance_ref.object_id,
                value.provenance_ref.version,
                value.closure_sha256,
                value.artifact_ref.object_id,
                value.artifact_ref.version,
                value.artifact_ref.content_sha256,
                value.artifact_kind,
                json.dumps(
                    sorted(value.contributor_client_hashes),
                    separators=(",", ":"),
                ),
                len(value.independent_evidence),
                value.derivation_rule_ref.object_id,
                value.derivation_rule_ref.version,
                value.derivation_rule_ref.content_sha256,
                value.policy_manifest_ref.object_id,
                value.policy_manifest_ref.version,
                value.policy_manifest_ref.content_sha256,
                value.source_grade,
                value.provenance_scope,
                json.dumps(sorted(value.allowed_uses), separators=(",", ":")),
                None if value.effective_to is None else _utc_text(value.effective_to),
                closure_json,
                value.closure_sha256,
            ),
        )

    def _insert_authorization(
        self,
        saga: _PublishSaga,
        value: CaseReuseAuthorization,
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO case_authorizations(
                case_id, case_version, authorization_id,
                authorization_version, authorization_sha256,
                contributor_client_hash, reuse_authorized, allowed_uses_json,
                valid_from, expires_at, revoked_at, terms_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
            """,
            (
                saga.case_id,
                saga.case_version,
                value.authorization_ref.object_id,
                value.authorization_ref.version,
                value.authorization_ref.content_sha256,
                value.contributor_client_hash,
                json.dumps(sorted(value.allowed_uses), separators=(",", ":")),
                _utc_text(value.valid_from),
                None if value.expires_at is None else _utc_text(value.expires_at),
                None if value.revoked_at is None else _utc_text(value.revoked_at),
                value.terms_sha256,
            ),
        )

    def _insert_review(
        self,
        saga: _PublishSaga,
        transfer: CasePublishTransfer,
    ) -> None:
        review = transfer.review
        policy = transfer.release_decision.policy_ref
        self._connection.execute(
            """
            INSERT INTO case_review_decisions(
                case_id, case_version, review_id, review_version,
                review_sha256, candidate_sha256, decision,
                checked_categories_json, residual_risk,
                rare_combination_disposition, allowed_uses_json,
                reviewer_attestation_sha256, release_policy_id,
                release_policy_version, release_policy_sha256,
                release_decision_sha256, reviewed_at, evaluated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'approved', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                saga.case_id,
                saga.case_version,
                review.review_ref.object_id,
                review.review_ref.version,
                review.review_ref.content_sha256,
                review.candidate_sha256,
                json.dumps(
                    sorted(review.checked_categories),
                    separators=(",", ":"),
                ),
                review.residual_risk,
                review.rare_combination_disposition,
                json.dumps(sorted(review.allowed_uses), separators=(",", ":")),
                review.reviewer_attestation_sha256,
                policy.object_id,
                policy.version,
                policy.content_sha256,
                transfer.outbox_payload.release_decision_sha256,
                _utc_text(review.reviewed_at),
                _utc_text(transfer.release_decision.evaluated_at),
            ),
        )

    def _activate(
        self,
        saga: _PublishSaga,
        transfer: CasePublishTransfer,
    ) -> _PublishSaga:
        now = self._clock.now()
        with transaction(self._connection):
            current = self._get_saga(saga.saga_id)
            if current.state != "PREPARED":
                return current
            authority = self._resolve_live_authority(
                transfer,
                as_of=now,
                minimum_epoch=current.authority_epoch,
            )
            active_rows = self._connection.execute(
                "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
            ).fetchall()
            if len(active_rows) > 1:
                raise CasePublishError("CASE_PUBLISH_EPOCH_INTEGRITY_ERROR")
            expected_epoch = None if not active_rows else int(active_rows[0][0])
            operation = self._connection.execute(
                "SELECT purpose, authority_base_version, approval_request_id, "
                "descriptor_sha256, state, expected_current_epoch "
                "FROM publication_operations WHERE operation_id = ?",
                (saga.publication_operation_id,),
            ).fetchone()
            if operation != (
                "case_publish",
                saga.case_version,
                transfer.outbox_payload.approval_request_id,
                transfer.outbox_payload.approval_descriptor_sha256,
                "PREPARED",
                expected_epoch,
            ):
                raise CasePublishError("CASE_PUBLISH_OPERATION_NOT_READY")
            manifest_repository = ManifestRepository(self._connection)
            manifest = manifest_repository.get(saga.manifest_id)
            closure_sha256 = publication_closure_sha256(
                purpose="case_publish",
                authority_base_version=saga.case_version,
                expected_current_epoch=expected_epoch,
                artifacts=(manifest,),
            )
            attestation = self._connection.execute(
                "SELECT approval_draft_sha256, closure_sha256 "
                "FROM publication_closure_attestations WHERE operation_id = ?",
                (saga.publication_operation_id,),
            ).fetchone()
            if attestation != (
                transfer.outbox_payload.approval_draft_sha256,
                closure_sha256,
            ):
                raise CasePublishError("CASE_PUBLISH_CLOSURE_ATTESTATION_INVALID")
            prepared = self._connection.execute(
                """
                UPDATE publication_operations
                   SET state = 'VERIFIED'
                 WHERE operation_id = ? AND state = 'PREPARED'
                   AND verified_manifest_count = required_manifest_count
                   AND required_manifest_count = 1
                   AND expected_current_epoch IS ?
                """,
                (saga.publication_operation_id, expected_epoch),
            ).rowcount
            if prepared != 1:
                raise CasePublishError("CASE_PUBLISH_OPERATION_NOT_READY")
            # A shared case is durable domain authority, not a runtime retrieval
            # root.  It remains VERIFIED and is consumed by the later atomic
            # global rebuild; creating a standalone epoch here would mix
            # publication operations and invalidate the existing retrieval set.
            activated_version = self._connection.execute(
                """
                UPDATE case_versions
                   SET state = 'ACTIVE', activated_at = ?
                 WHERE case_id = ? AND version = ? AND state = 'PREPARED'
                """,
                (_utc_text(now), saga.case_id, saga.case_version),
            ).rowcount
            if activated_version != 1:
                raise CasePublishError(
                    "CASE_PUBLISH_CASE_VERSION_ACTIVATION_FAILED"
                )
            activated_case = self._connection.execute(
                """
                UPDATE cases
                   SET state = 'ACTIVE', current_version = ?, updated_at = ?
                 WHERE case_id = ? AND state = 'PREPARED'
                """,
                (saga.case_version, _utc_text(now), saga.case_id),
            ).rowcount
            if activated_case != 1:
                raise CasePublishError("CASE_PUBLISH_CASE_ACTIVATION_FAILED")
            activated_saga = self._connection.execute(
                """
                UPDATE global_publish_sagas
                   SET state = 'ACTIVE', published_global_version = ?,
                       authority_epoch = ?, updated_at = ?
                 WHERE saga_id = ? AND state = 'PREPARED'
                """,
                (
                    saga.case_version,
                    authority.authority_epoch,
                    _utc_text(now),
                    saga.saga_id,
                ),
            ).rowcount
            if activated_saga != 1:
                raise CasePublishError("CASE_PUBLISH_SAGA_ACTIVATION_FAILED")
        return self._get_saga(saga.saga_id)

    def _publication(
        self,
        saga: _PublishSaga,
        transfer: CasePublishTransfer,
        authority: CasePublishAuthoritySnapshot,
    ) -> CasePublication:
        if saga.global_content_sha256 is None:
            raise CasePublishError("CASE_PUBLISH_COPY_MISSING")
        row = self._connection.execute(
            """
            SELECT provenance_sha256 FROM case_provenance
             WHERE provenance_id = ? AND provenance_version = ?
            """,
            (saga.provenance_id, saga.provenance_version),
        ).fetchone()
        if row is None:
            raise CasePublishError("CASE_PUBLISH_PROVENANCE_MISSING")
        manifest = ManifestRepository(self._connection).get(saga.manifest_id)
        if (
            manifest.state != "VERIFIED"
            or not manifest.verified
            or manifest.artifact_key != _case_artifact_key(saga.case_id)
            or manifest.artifact_kind != "shared_case"
            or len(manifest.members) != 1
            or manifest.members[0].object_id != saga.case_id
            or manifest.members[0].object_sha256 != saga.global_content_sha256
        ):
            raise CasePublishError("CASE_PUBLISH_MANIFEST_INVALID")
        operation = self._connection.execute(
            "SELECT purpose, authority_base_version, approval_request_id, "
            "descriptor_sha256, state, expected_current_epoch, runtime_epoch, "
            "activated_at "
            "FROM publication_operations WHERE operation_id = ?",
            (saga.publication_operation_id,),
        ).fetchone()
        if (
            operation is None
            or operation[:5]
            != (
                "case_publish",
                saga.case_version,
                authority.approval_request_id,
                authority.approval_descriptor_sha256,
                "VERIFIED",
            )
            or operation[6] is not None
            or operation[7] is not None
        ):
            raise CasePublishError("CASE_PUBLISH_OPERATION_INVALID")
        closure_sha256 = publication_closure_sha256(
            purpose="case_publish",
            authority_base_version=saga.case_version,
            expected_current_epoch=operation[5],
            artifacts=(manifest,),
        )
        attestation = self._connection.execute(
            "SELECT approval_draft_sha256, closure_sha256 "
            "FROM publication_closure_attestations WHERE operation_id = ?",
            (saga.publication_operation_id,),
        ).fetchone()
        if attestation != (
            authority.approval_draft_sha256,
            closure_sha256,
        ):
            raise CasePublishError("CASE_PUBLISH_CLOSURE_ATTESTATION_INVALID")
        case_ref = VersionRef(
            object_id=saga.case_id,
            version=saga.case_version,
            content_sha256=saga.global_content_sha256,
        )
        provenance_ref = VersionRef(
            object_id=saga.provenance_id,
            version=saga.provenance_version,
            content_sha256=row[0],
        )
        proof = self._proof_signer.sign(
            CasePublicationProofPayload(
                source_event_id=saga.source_event_id,
                approval_operation_id=authority.approval_operation_id,
                approval_request_id=authority.approval_request_id,
                approval_descriptor_sha256=(
                    authority.approval_descriptor_sha256
                ),
                approval_draft_sha256=authority.approval_draft_sha256,
                approval_descriptor_base_version=(
                    authority.approval_descriptor_base_version
                ),
                approval_applied_commit_version=(
                    authority.approval_applied_commit_version
                ),
                approval_target_scope_hash=(
                    authority.approval_target_scope_hash
                ),
                global_publication_operation_id=(
                    saga.publication_operation_id
                ),
                publication_closure_sha256=closure_sha256,
                case_ref=case_ref,
                manifest_id=saga.manifest_id,
                provenance_ref=provenance_ref,
                published_global_version=saga.case_version,
                authority_epoch=authority.authority_epoch,
            )
        )
        publication = CasePublication(
            source_event_id=saga.source_event_id,
            case_ref=case_ref,
            manifest_id=saga.manifest_id,
            provenance_ref=provenance_ref,
            published_global_version=saga.case_version,
            proof=proof,
        )
        active = CaseCatalog(
            self._connection,
            self._content_store,
            clock=self._clock,
        ).get_active(
            saga.case_id,
            purpose=transfer.outbox_payload.purpose,
        )
        if (
            active is None
            or active.case_ref != publication.case_ref
            or active.manifest_id != publication.manifest_id
            or active.provenance_ref != publication.provenance_ref
            or active.authorization_ref
            != transfer.authorization.authorization_ref
            or active.allowed_uses != transfer.release_decision.allowed_uses
            or active.content_media_type != saga.global_content_media_type
            or active.content_size_bytes != saga.global_content_size_bytes
        ):
            raise CasePublishError("CASE_PUBLISH_ACTIVE_AUTHORITY_INVALID")
        return publication

    def _get_saga(self, saga_id: str) -> _PublishSaga:
        row = self._connection.execute(
            self._SAGA_SELECT + " WHERE saga_id = ?",
            (saga_id,),
        ).fetchone()
        if row is None:
            raise CasePublishError("CASE_PUBLISH_SAGA_MISSING")
        return self._saga_from_row(row)

    _SAGA_SELECT = """
        SELECT saga_id, source_event_id, idempotency_key_sha256,
               outbox_payload_sha256, case_id, case_version,
               candidate_id, candidate_version, candidate_sha256,
               publication_operation_id, manifest_id,
               provenance_id, provenance_version,
               global_content_sha256, global_content_media_type,
               global_content_size_bytes, state, authority_epoch, attempt_count,
               published_global_version, created_at, updated_at
          FROM global_publish_sagas
    """

    @staticmethod
    def _saga_from_row(row: tuple[object, ...]) -> _PublishSaga:
        if len(row) != 22:
            raise CasePublishError("CASE_PUBLISH_SAGA_ROW_INVALID")
        try:
            return _PublishSaga.model_validate(
                {
                    "saga_id": row[0],
                    "source_event_id": row[1],
                    "idempotency_key_sha256": row[2],
                    "outbox_payload_sha256": row[3],
                    "case_id": row[4],
                    "case_version": row[5],
                    "candidate_id": row[6],
                    "candidate_version": row[7],
                    "candidate_sha256": row[8],
                    "publication_operation_id": row[9],
                    "manifest_id": row[10],
                    "provenance_id": row[11],
                    "provenance_version": row[12],
                    "global_content_sha256": row[13],
                    "global_content_media_type": row[14],
                    "global_content_size_bytes": row[15],
                    "state": row[16],
                    "authority_epoch": row[17],
                    "attempt_count": row[18],
                    "published_global_version": row[19],
                    "created_at": _parse_utc(row[20]),
                    "updated_at": _parse_utc(row[21]),
                }
            )
        except (TypeError, ValueError):
            raise CasePublishError("CASE_PUBLISH_SAGA_ROW_INVALID") from None


__all__ = [
    "CasePublishAuthorityResolver",
    "CasePublishAuthoritySnapshot",
    "CasePublication",
    "CasePublishError",
    "CasePublishTransfer",
    "SharedCasePublisher",
    "case_release_decision_sha256",
    "shared_candidate_bytes",
]
