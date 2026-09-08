"""Client-local, body-free outbox records for shared-case publication."""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timedelta
from typing import Literal

from pydantic import field_validator, model_validator

from consultation_kb.approvals.models import descriptor_sha256
from consultation_kb.archive.publication_proof import (
    CasePublicationProof,
    case_publication_proof_bytes,
    case_publication_proof_sha256,
)
from consultation_kb.knowledge._canonical import canonical_json_bytes
from consultation_kb.models.common import (
    NonEmptyStr,
    ObjectId,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    Uuid7String,
    VersionRef,
)
from consultation_kb.models.session import StoredContentRef
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.storage.connection import transaction


class OutboxError(RuntimeError):
    def __init__(self, code: str = "OUTBOX_INVALID") -> None:
        self.code = code
        super().__init__(code)


class OutboxConflict(OutboxError):
    def __init__(self) -> None:
        super().__init__("OUTBOX_IDEMPOTENCY_CONFLICT")


class CasePublishOutboxPayload(StrictModel):
    """No case body or direct client/session identifier may cross this boundary."""

    schema_version: Literal["case_publish_outbox.v1"] = "case_publish_outbox.v1"
    candidate_ref: VersionRef
    candidate_sha256: Sha256Hex
    candidate_media_type: Literal["application/json"] = "application/json"
    candidate_size_bytes: PositiveInt
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
    approval_target_scope_hash: Sha256Hex
    source_review_decision_id: ObjectId
    idempotency_key: NonEmptyStr

    @model_validator(mode="after")
    def _exact_refs(self) -> "CasePublishOutboxPayload":
        if self.candidate_ref.content_sha256 != self.candidate_sha256:
            raise ValueError("candidate reference hash mismatch")
        if self.source_review_decision_id != self.approval_request_id:
            raise ValueError("source review and approval request must match")
        return self


class SourceCaseApproval(StrictModel):
    """Exact persisted execution binding; never authority by itself."""

    operation_id: ObjectId
    decision_id: ObjectId
    descriptor_sha256: Sha256Hex
    draft_sha256: Sha256Hex
    target_scope_hash: Sha256Hex
    session_id: Uuid7String
    candidate_id: ObjectId
    candidate_sha256: Sha256Hex
    reviewer_id_hash: Sha256Hex
    decided_at: UtcDateTime


OutboxState = Literal["PENDING", "CLAIMED", "PUBLISHED", "FAILED"]


class OutboxRecord(StrictModel):
    event_id: ObjectId
    bundle_id: ObjectId
    event_type: Literal["shared_case_publish"] = "shared_case_publish"
    idempotency_key: NonEmptyStr
    payload: StoredContentRef
    state: OutboxState
    attempt_count: int
    published_global_version: PositiveInt | None = None
    last_error_code: NonEmptyStr | None = None
    created_at: UtcDateTime
    updated_at: UtcDateTime

    @field_validator("attempt_count")
    @classmethod
    def _attempt_count(cls, value: int) -> int:
        if type(value) is not int or value < 0:
            raise ValueError("outbox attempt count must be a non-negative integer")
        return value

    @model_validator(mode="after")
    def _published_shape(self) -> "OutboxRecord":
        if (self.state == "PUBLISHED") != (
            self.published_global_version is not None
        ):
            raise ValueError("published outbox state/version mismatch")
        if (self.state == "FAILED") != (self.last_error_code is not None):
            raise ValueError("failed outbox state/error mismatch")
        if self.updated_at < self.created_at:
            raise ValueError("outbox update time precedes creation")
        return self


def case_publish_payload_bytes(value: CasePublishOutboxPayload) -> bytes:
    exact = CasePublishOutboxPayload.model_validate(value)
    return canonical_json_bytes(exact.model_dump(mode="json"))


def case_publish_payload_sha256(value: CasePublishOutboxPayload) -> str:
    return hashlib.sha256(case_publish_payload_bytes(value)).hexdigest()


def _utc_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise ValueError("stored outbox timestamp must be text")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class OutboxRepository:
    """Own the one client transaction that approves and enqueues a case."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("OutboxRepository requires a SQLite connection")
        self._connection = connection

    def enqueue(
        self,
        *,
        event_id: str,
        bundle_id: str,
        approval: SourceCaseApproval,
        payload: CasePublishOutboxPayload,
        payload_ref: StoredContentRef,
        created_at: datetime,
    ) -> OutboxRecord:
        with transaction(self._connection):
            record = self._enqueue_in_transaction(
                event_id=event_id,
                bundle_id=bundle_id,
                approval=approval,
                payload=payload,
                payload_ref=payload_ref,
                created_at=created_at,
                expected_execution_state="APPLIED",
            )
        return record

    def enqueue_in_transaction(
        self,
        *,
        event_id: str,
        bundle_id: str,
        approval: SourceCaseApproval,
        payload: CasePublishOutboxPayload,
        payload_ref: StoredContentRef,
        created_at: datetime,
    ) -> OutboxRecord:
        """Enqueue inside an ApprovalExecutionGuard CLAIMED transaction."""

        if not self._connection.in_transaction:
            raise OutboxError("OUTBOX_APPROVAL_TRANSACTION_REQUIRED")
        return self._enqueue_in_transaction(
            event_id=event_id,
            bundle_id=bundle_id,
            approval=approval,
            payload=payload,
            payload_ref=payload_ref,
            created_at=created_at,
            expected_execution_state="CLAIMED",
        )

    def _enqueue_in_transaction(
        self,
        *,
        event_id: str,
        bundle_id: str,
        approval: SourceCaseApproval,
        payload: CasePublishOutboxPayload,
        payload_ref: StoredContentRef,
        created_at: datetime,
        expected_execution_state: Literal["CLAIMED", "APPLIED"],
    ) -> OutboxRecord:
        approved = SourceCaseApproval.model_validate(approval)
        envelope = CasePublishOutboxPayload.model_validate(payload)
        reference = StoredContentRef.model_validate(payload_ref)
        event = OutboxRecord.model_validate(
            {
                "event_id": event_id,
                "bundle_id": bundle_id,
                "idempotency_key": envelope.idempotency_key,
                "payload": reference,
                "state": "PENDING",
                "attempt_count": 0,
                "created_at": created_at,
                "updated_at": created_at,
            }
        )
        serialized = case_publish_payload_bytes(envelope)
        if (
            reference.media_type != "application/json"
            or reference.content_sha256 != hashlib.sha256(serialized).hexdigest()
            or reference.size_bytes != len(serialized)
        ):
            raise OutboxError("OUTBOX_PAYLOAD_REFERENCE_MISMATCH")
        if (
            approved.operation_id != envelope.approval_operation_id
            or approved.decision_id != envelope.approval_request_id
            or approved.decision_id != envelope.source_review_decision_id
            or approved.descriptor_sha256
            != envelope.approval_descriptor_sha256
            or approved.draft_sha256 != envelope.approval_draft_sha256
            or approved.target_scope_hash
            != envelope.approval_target_scope_hash
            or approved.candidate_id != envelope.candidate_ref.object_id
            or approved.candidate_sha256 != envelope.candidate_sha256
        ):
            raise OutboxError("OUTBOX_APPROVAL_BINDING_MISMATCH")

        client_id, scope_hash = self._assert_source_candidate(
            bundle_id=event.bundle_id,
            approval=approved,
            payload=envelope,
        )
        self._assert_approval_execution(
            approved,
            payload=envelope,
            client_id=client_id,
            scope_hash=scope_hash,
            expected_state=expected_execution_state,
        )
        self._assert_existing_review(approved)
        existing = self._find_existing(
            event.event_id,
            event.idempotency_key,
        )
        if existing is not None:
            if self._same_event(existing, event):
                return existing
            raise OutboxConflict
        updated = self._connection.execute(
                """
                UPDATE archive_purpose_states
                   SET state = 'PREPARED', review_decision_id = ?, updated_at = ?
                 WHERE bundle_id = ? AND purpose = 'shared_case' AND state = 'DRAFT'
                """,
                (
                    approved.decision_id,
                    _utc_text(event.updated_at),
                    event.bundle_id,
                ),
            )
        if updated.rowcount != 1:
            raise OutboxError("OUTBOX_SHARED_CASE_STATE_INVALID")
        self._connection.execute(
                """
                INSERT INTO outbox_events(
                    event_id, bundle_id, event_type, idempotency_key,
                    payload_object_id, payload_sha256, payload_media_type,
                    payload_size_bytes, state, attempt_count,
                    published_global_version, last_error_code,
                    created_at, updated_at
                ) VALUES (?, ?, 'shared_case_publish', ?, ?, ?, ?, ?,
                          'PENDING', 0, NULL, NULL, ?, ?)
                """,
                (
                    event.event_id,
                    event.bundle_id,
                    event.idempotency_key,
                    event.payload.object_id,
                    event.payload.content_sha256,
                    event.payload.media_type,
                    event.payload.size_bytes,
                    _utc_text(event.created_at),
                    _utc_text(event.updated_at),
                ),
        )
        return self.get(event.event_id)

    stage_case_publish = enqueue

    def get(self, event_id: str) -> OutboxRecord:
        row = self._connection.execute(
            self._SELECT + " WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        if row is None:
            raise OutboxError("OUTBOX_EVENT_NOT_FOUND")
        return self._from_row(row)

    def pending(self, *, limit: int = 100) -> tuple[OutboxRecord, ...]:
        if type(limit) is not int or limit <= 0:
            raise ValueError("outbox pending limit must be positive")
        rows = self._connection.execute(
            self._SELECT
            + " WHERE state IN ('PENDING', 'FAILED', 'CLAIMED')"
            + " ORDER BY created_at, event_id LIMIT ?",
            (limit,),
        ).fetchall()
        return tuple(self._from_row(row) for row in rows)

    def claim(self, event_id: str, *, claimed_at: datetime) -> OutboxRecord:
        with transaction(self._connection):
            current = self.get(event_id)
            if current.state in {"PENDING", "FAILED"}:
                self._assert_transition_time(current, claimed_at)
                self._connection.execute(
                    """
                    UPDATE outbox_events
                       SET state = 'CLAIMED', attempt_count = attempt_count + 1,
                           last_error_code = NULL, updated_at = ?
                     WHERE event_id = ?
                    """,
                    (_utc_text(claimed_at), event_id),
                )
        return self.get(event_id)

    def mark_failed(
        self,
        event_id: str,
        *,
        error_code: str,
        failed_at: datetime,
    ) -> OutboxRecord:
        if type(error_code) is not str or not error_code.strip():
            raise ValueError("outbox error code must be nonblank")
        with transaction(self._connection):
            current = self.get(event_id)
            if current.state == "PUBLISHED":
                return current
            self._assert_transition_time(current, failed_at)
            self._connection.execute(
                """
                UPDATE outbox_events
                   SET state = 'FAILED', last_error_code = ?, updated_at = ?
                 WHERE event_id = ?
                """,
                (error_code, _utc_text(failed_at), event_id),
            )
        return self.get(event_id)

    def mark_published(
        self,
        event_id: str,
        *,
        global_version: int,
        published_at: datetime,
        publication_proof: CasePublicationProof,
    ) -> OutboxRecord:
        with transaction(self._connection):
            return self.mark_published_in_transaction(
                event_id,
                global_version=global_version,
                published_at=published_at,
                publication_proof=publication_proof,
            )

    def mark_published_in_transaction(
        self,
        event_id: str,
        *,
        global_version: int,
        published_at: datetime,
        publication_proof: CasePublicationProof,
    ) -> OutboxRecord:
        """Acknowledge one exact global proof in the caller's target transaction."""

        if not self._connection.in_transaction:
            raise OutboxError("OUTBOX_ACK_TRANSACTION_REQUIRED")
        if type(global_version) is not int or global_version <= 0:
            raise ValueError("published global version must be positive")
        exact_proof = CasePublicationProof.model_validate(publication_proof)
        proof_payload = exact_proof.payload
        if (
            proof_payload.source_event_id != event_id
            or proof_payload.published_global_version != global_version
        ):
            raise OutboxConflict
        proof_body = case_publication_proof_bytes(exact_proof)
        proof_sha256 = case_publication_proof_sha256(exact_proof)
        current = self.get(event_id)
        if current.state == "PUBLISHED":
            if (
                current.published_global_version != global_version
                or self.publication_proof(event_id) != exact_proof
            ):
                raise OutboxConflict
            return current
        if self.publication_proof(event_id) is not None:
            raise OutboxConflict
        self._assert_transition_time(current, published_at)
        self._connection.execute(
                """
                INSERT INTO case_publication_proofs(
                    event_id, approval_operation_id, approval_request_id,
                    approval_descriptor_sha256, approval_draft_sha256,
                    approval_descriptor_base_version,
                    approval_applied_commit_version,
                    approval_target_scope_hash,
                    global_publication_operation_id,
                    publication_closure_sha256, manifest_id,
                    published_global_version, attestor_id,
                    proof_sha256, proof_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    proof_payload.approval_operation_id,
                    proof_payload.approval_request_id,
                    proof_payload.approval_descriptor_sha256,
                    proof_payload.approval_draft_sha256,
                    proof_payload.approval_descriptor_base_version,
                    proof_payload.approval_applied_commit_version,
                    proof_payload.approval_target_scope_hash,
                    proof_payload.global_publication_operation_id,
                    proof_payload.publication_closure_sha256,
                    proof_payload.manifest_id,
                    global_version,
                    exact_proof.attestor_id,
                    proof_sha256,
                    proof_body.decode("ascii"),
                    _utc_text(published_at),
                ),
        )
        self._connection.execute(
                """
                UPDATE outbox_events
                   SET state = 'PUBLISHED', published_global_version = ?,
                       last_error_code = NULL, updated_at = ?
                 WHERE event_id = ?
                """,
                (global_version, _utc_text(published_at), event_id),
        )
        return self.get(event_id)

    def publication_proof(self, event_id: str) -> CasePublicationProof | None:
        row = self._connection.execute(
            """
            SELECT approval_operation_id, approval_request_id,
                   approval_descriptor_sha256, approval_draft_sha256,
                   approval_descriptor_base_version,
                   approval_applied_commit_version,
                   approval_target_scope_hash,
                   global_publication_operation_id,
                   publication_closure_sha256, manifest_id,
                   published_global_version, attestor_id,
                   proof_sha256, proof_json
              FROM case_publication_proofs
             WHERE event_id = ?
            """,
            (event_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            proof = CasePublicationProof.model_validate_json(row[13], strict=True)
            payload = proof.payload
            expected = (
                payload.approval_operation_id,
                payload.approval_request_id,
                payload.approval_descriptor_sha256,
                payload.approval_draft_sha256,
                payload.approval_descriptor_base_version,
                payload.approval_applied_commit_version,
                payload.approval_target_scope_hash,
                payload.global_publication_operation_id,
                payload.publication_closure_sha256,
                payload.manifest_id,
                payload.published_global_version,
                proof.attestor_id,
                case_publication_proof_sha256(proof),
            )
        except (TypeError, ValueError):
            raise OutboxError("OUTBOX_PUBLICATION_PROOF_INVALID") from None
        if tuple(row[:13]) != expected or payload.source_event_id != event_id:
            raise OutboxError("OUTBOX_PUBLICATION_PROOF_INVALID")
        return proof

    _SELECT = """
        SELECT event_id, bundle_id, event_type, idempotency_key,
               payload_object_id, payload_sha256, payload_media_type,
               payload_size_bytes, state, attempt_count,
               published_global_version, last_error_code, created_at, updated_at
          FROM outbox_events
    """

    def _find_existing(
        self,
        event_id: str,
        idempotency_key: str,
    ) -> OutboxRecord | None:
        row = self._connection.execute(
            self._SELECT + " WHERE event_id = ? OR idempotency_key = ?",
            (event_id, idempotency_key),
        ).fetchone()
        return None if row is None else self._from_row(row)

    def _assert_source_candidate(
        self,
        *,
        bundle_id: str,
        approval: SourceCaseApproval,
        payload: CasePublishOutboxPayload,
    ) -> tuple[str, str]:
        row = self._connection.execute(
            """
            SELECT b.session_id, s.client_id, s.client_scope_hash,
                   c.candidate_media_type, c.candidate_size_bytes
              FROM shared_case_candidates AS c
              JOIN archive_bundles AS b ON b.bundle_id = c.bundle_id
              JOIN sessions AS s ON s.session_id = b.session_id
             WHERE c.bundle_id = ?
               AND c.candidate_id = ?
               AND c.candidate_object_id = ?
               AND c.candidate_sha256 = ?
            """,
            (
                bundle_id,
                approval.candidate_id,
                approval.candidate_id,
                approval.candidate_sha256,
            ),
        ).fetchone()
        if (
            row is None
            or row[0] != approval.session_id
            or row[3] != payload.candidate_media_type
            or row[4] != payload.candidate_size_bytes
        ):
            raise OutboxError("OUTBOX_SOURCE_CANDIDATE_NOT_APPROVED")
        return str(row[1]), str(row[2])

    def _assert_approval_execution(
        self,
        approval: SourceCaseApproval,
        *,
        payload: CasePublishOutboxPayload,
        client_id: str,
        scope_hash: str,
        expected_state: Literal["CLAIMED", "APPLIED"],
    ) -> None:
        descriptor = DraftDescriptor(
            purpose="case_publish",
            target_id=approval.candidate_id,
            client_id=client_id,
            base_version=payload.candidate_ref.version,
            draft_sha256=approval.draft_sha256,
            session_id=approval.session_id,
        )
        if (
            descriptor_sha256(descriptor) != approval.descriptor_sha256
            or scope_hash != approval.target_scope_hash
        ):
            raise OutboxError("OUTBOX_APPROVAL_DESCRIPTOR_MISMATCH")
        row = self._connection.execute(
            """
            SELECT request_id, descriptor_sha256, draft_sha256,
                   descriptor_base_version, target_scope_hash, state
              FROM approval_executions WHERE operation_id = ?
            """,
            (approval.operation_id,),
        ).fetchone()
        expected = (
            approval.decision_id,
            approval.descriptor_sha256,
            approval.draft_sha256,
            payload.candidate_ref.version,
            approval.target_scope_hash,
            expected_state,
        )
        if row is None or tuple(row) != expected:
            raise OutboxError("OUTBOX_APPROVAL_EXECUTION_REQUIRED")

    def _assert_existing_review(self, approval: SourceCaseApproval) -> None:
        row = self._connection.execute(
            """
            SELECT session_id, object_id, decision, reviewer_id_hash, decided_at
              FROM review_decisions WHERE decision_id = ?
            """,
            (approval.decision_id,),
        ).fetchone()
        expected = (
            approval.session_id,
            approval.candidate_id,
            "APPROVED",
            approval.reviewer_id_hash,
            _utc_text(approval.decided_at),
        )
        if row is None or tuple(row) != expected:
            raise OutboxError("OUTBOX_REVIEW_AUTHORITY_REQUIRED")

    @staticmethod
    def _same_event(existing: OutboxRecord, proposed: OutboxRecord) -> bool:
        return (
            existing.event_id == proposed.event_id
            and existing.bundle_id == proposed.bundle_id
            and existing.event_type == proposed.event_type
            and existing.idempotency_key == proposed.idempotency_key
            and existing.payload == proposed.payload
        )

    @staticmethod
    def _assert_transition_time(current: OutboxRecord, changed_at: datetime) -> None:
        if not isinstance(changed_at, datetime) or changed_at.utcoffset() != timedelta(0):
            raise ValueError("outbox transition time must be UTC")
        if changed_at < current.updated_at:
            raise OutboxError("OUTBOX_TIME_REGRESSION")

    @staticmethod
    def _from_row(row: tuple[object, ...]) -> OutboxRecord:
        if len(row) != 14:
            raise OutboxError("OUTBOX_ROW_INVALID")
        try:
            return OutboxRecord.model_validate(
                {
                    "event_id": row[0],
                    "bundle_id": row[1],
                    "event_type": row[2],
                    "idempotency_key": row[3],
                    "payload": {
                        "object_id": row[4],
                        "content_sha256": row[5],
                        "media_type": row[6],
                        "size_bytes": row[7],
                    },
                    "state": row[8],
                    "attempt_count": row[9],
                    "published_global_version": row[10],
                    "last_error_code": row[11],
                    "created_at": _parse_utc(row[12]),
                    "updated_at": _parse_utc(row[13]),
                }
            )
        except (TypeError, ValueError):
            raise OutboxError("OUTBOX_ROW_INVALID") from None


__all__ = [
    "CasePublishOutboxPayload",
    "OutboxConflict",
    "OutboxError",
    "OutboxRecord",
    "OutboxRepository",
    "SourceCaseApproval",
    "case_publish_payload_bytes",
    "case_publish_payload_sha256",
]
