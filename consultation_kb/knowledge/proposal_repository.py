"""Durable CAS-backed proposal operations for global Claim, Wiki and C1 writes."""

from __future__ import annotations

import hmac
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, TypeAlias, cast

from pydantic import TypeAdapter, ValidationError

from consultation_kb.approvals.models import (
    ApprovalRequest,
    descriptor_sha256 as approval_descriptor_sha256,
)
from consultation_kb.core.clock import Clock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import ObjectId
from consultation_kb.models.manifests import DraftDescriptor, DraftPurpose
from consultation_kb.models.theory import TheoryProposal
from consultation_kb.storage.connection import transaction
from consultation_kb.vault.content_store import ContentStore, ContentStoreError

from ._canonical import canonical_json_bytes, canonical_sha256
from .claims import ClaimProposal
from .wiki import WikiProposal


ProposalKind: TypeAlias = Literal["claim", "wiki", "theory"]
ProposalValue: TypeAlias = ClaimProposal | WikiProposal | TheoryProposal
_OBJECT_ID = TypeAdapter(ObjectId)
_PURPOSE: dict[ProposalKind, DraftPurpose] = {
    "claim": "claim_approve",
    "wiki": "wiki_publish",
    "theory": "theory_approve",
}


class KnowledgeProposalError(RuntimeError):
    """Fixed-code failure for a corrupt, stale, or conflicting proposal row."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class DurableKnowledgeProposal:
    operation_id: str
    operation_sha256: str
    kind: ProposalKind
    proposal_id: str
    descriptor: DraftDescriptor
    proposal: ProposalValue
    approval_request_id: str | None
    state: Literal["proposed", "review_pending", "expired", "applied"]


def _utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise KnowledgeProposalError("KNOWLEDGE_PROPOSAL_TIMESTAMP_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise KnowledgeProposalError(
            "KNOWLEDGE_PROPOSAL_TIMESTAMP_INVALID"
        ) from None
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise KnowledgeProposalError("KNOWLEDGE_PROPOSAL_TIMESTAMP_INVALID")
    return parsed


def _proposal_id(value: ProposalValue) -> str:
    if isinstance(value, TheoryProposal):
        return value.request_id
    return value.proposal_id


def _proposal_draft_sha256(value: ProposalValue) -> str:
    actual = canonical_sha256(value.draft.model_dump(mode="json"))
    if not hmac.compare_digest(actual, value.draft_sha256):
        raise KnowledgeProposalError("KNOWLEDGE_PROPOSAL_DRAFT_HASH_MISMATCH")
    return actual


def _operation_sha256(kind: ProposalKind, descriptor: DraftDescriptor) -> str:
    # Claim descriptors target their generated proposal ID, which is not part
    # of the semantic operation.  Wiki and Theory descriptors target stable
    # governed objects and therefore keep that target in the replay key.
    target_id = "claim_catalog" if kind == "claim" else descriptor.target_id
    return canonical_sha256(
        {
            "base_version": descriptor.base_version,
            "draft_sha256": descriptor.draft_sha256,
            "proposal_kind": kind,
            "schema_version": 1,
            "target_id": target_id,
        }
    )


def _payload_bytes(
    kind: ProposalKind,
    proposal: ProposalValue,
    descriptor: DraftDescriptor,
) -> bytes:
    return canonical_json_bytes(
        {
            "descriptor": descriptor.model_dump(mode="json"),
            "proposal": proposal.model_dump(mode="json"),
            "proposal_kind": kind,
            "schema_version": 1,
        }
    )


class KnowledgeProposalRepository:
    """Persist exact proposal DTOs without putting their bodies in SQLite."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        content_store: ContentStore,
        id_factory: IdFactory,
        clock: Clock,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("proposal repository requires sqlite3.Connection")
        self._connection = connection
        self._store = content_store
        self._ids = id_factory
        self._clock = clock

    def save_claim(
        self,
        proposal: ClaimProposal,
        descriptor: DraftDescriptor,
    ) -> DurableKnowledgeProposal:
        return self._save("claim", ClaimProposal.model_validate(proposal), descriptor)

    def save_wiki(
        self,
        proposal: WikiProposal,
        descriptor: DraftDescriptor,
    ) -> DurableKnowledgeProposal:
        return self._save("wiki", WikiProposal.model_validate(proposal), descriptor)

    def save_theory(
        self,
        proposal: TheoryProposal,
        descriptor: DraftDescriptor,
    ) -> DurableKnowledgeProposal:
        return self._save("theory", TheoryProposal.model_validate(proposal), descriptor)

    def _save(
        self,
        kind: ProposalKind,
        proposal: ProposalValue,
        descriptor: DraftDescriptor,
    ) -> DurableKnowledgeProposal:
        exact_descriptor = DraftDescriptor.model_validate(descriptor)
        expected_purpose = _PURPOSE[kind]
        if (
            exact_descriptor.purpose != expected_purpose
            or exact_descriptor.client_id is not None
            or exact_descriptor.session_id is not None
            or exact_descriptor.draft_sha256 != _proposal_draft_sha256(proposal)
        ):
            raise KnowledgeProposalError("KNOWLEDGE_PROPOSAL_DESCRIPTOR_MISMATCH")
        self._validate_descriptor_target(
            kind,
            proposal,
            exact_descriptor,
            require_current_theory_base=True,
        )
        proposal_id = _proposal_id(proposal)
        fingerprint = _operation_sha256(kind, exact_descriptor)
        existing = self._proposal_id_for_operation(fingerprint)
        if existing is not None:
            return self.load(existing, expected_kind=kind)

        payload = _payload_bytes(kind, proposal, exact_descriptor)
        reference = self._store.finalize(
            self._store.stage_bytes(
                payload,
                purpose="knowledge_proposal",
                manifest_id=proposal_id,
                media_type="application/json",
            )
        )
        operation_id = self._ids.object_id("knowledge_proposal_operation")
        now = self._clock.now()
        try:
            with transaction(self._connection):
                self._connection.execute(
                    """
                    INSERT INTO knowledge_proposal_operations(
                        operation_id, operation_sha256, proposal_kind,
                        proposal_id, target_id, base_version, draft_sha256,
                        proposal_object_ref, proposal_object_sha256,
                        proposal_object_size_bytes, proposal_object_media_type,
                        approval_request_id, approval_descriptor_sha256,
                        approval_expires_at, execution_operation_id,
                        execution_sha256, state, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              NULL, NULL, NULL, NULL, NULL, 'PROPOSED', ?, ?)
                    """,
                    (
                        operation_id,
                        fingerprint,
                        kind.upper(),
                        proposal_id,
                        exact_descriptor.target_id,
                        exact_descriptor.base_version,
                        exact_descriptor.draft_sha256,
                        f"sha256:{reference.content_sha256}",
                        reference.content_sha256,
                        reference.size_bytes,
                        reference.media_type,
                        _utc(now),
                        _utc(now),
                    ),
                )
        except sqlite3.IntegrityError:
            existing = self._proposal_id_for_operation(fingerprint)
            if existing is None:
                raise KnowledgeProposalError("KNOWLEDGE_PROPOSAL_CONFLICT") from None
            return self.load(existing, expected_kind=kind)
        return self.load(proposal_id, expected_kind=kind)

    def _proposal_id_for_operation(self, operation_sha256: str) -> str | None:
        row = self._connection.execute(
            """
            SELECT proposal_id FROM knowledge_proposal_operations
             WHERE operation_sha256 = ?
            """,
            (operation_sha256,),
        ).fetchone()
        return None if row is None else str(row[0])

    def _validate_descriptor_target(
        self,
        kind: ProposalKind,
        proposal: ProposalValue,
        descriptor: DraftDescriptor,
        *,
        require_current_theory_base: bool,
    ) -> None:
        proposal_id = _proposal_id(proposal)
        if kind == "claim":
            if not isinstance(proposal, ClaimProposal) or (
                descriptor.target_id != proposal_id
                or descriptor.base_version != proposal.catalog_base_version
            ):
                raise KnowledgeProposalError(
                    "KNOWLEDGE_PROPOSAL_DESCRIPTOR_MISMATCH"
                )
            return
        if kind == "wiki":
            if not isinstance(proposal, WikiProposal) or (
                descriptor.target_id != proposal.draft.wiki_id
                or descriptor.base_version != proposal.draft.base_revision
            ):
                raise KnowledgeProposalError(
                    "KNOWLEDGE_PROPOSAL_DESCRIPTOR_MISMATCH"
                )
            return
        if not isinstance(proposal, TheoryProposal) or (
            descriptor.target_id != proposal.draft.theory_id
        ):
            raise KnowledgeProposalError("KNOWLEDGE_PROPOSAL_DESCRIPTOR_MISMATCH")
        if require_current_theory_base:
            row = self._connection.execute(
                """
                SELECT coalesce(max(revision), 0) FROM theory_revisions
                 WHERE theory_id = ?
                """,
                (proposal.draft.theory_id,),
            ).fetchone()
            if row is None or descriptor.base_version != int(row[0]):
                raise KnowledgeProposalError(
                    "KNOWLEDGE_PROPOSAL_DESCRIPTOR_MISMATCH"
                )

    def _parse_payload(
        self,
        payload: bytes,
        *,
        kind: ProposalKind,
    ) -> tuple[ProposalValue, DraftDescriptor]:
        try:
            value = json.loads(payload.decode("ascii", errors="strict"))
            if (
                type(value) is not dict
                or set(value)
                != {
                    "descriptor",
                    "proposal",
                    "proposal_kind",
                    "schema_version",
                }
                or value["proposal_kind"] != kind
                or value["schema_version"] != 1
            ):
                raise ValueError
            proposal_value = value["proposal"]
            proposal_json = canonical_json_bytes(proposal_value)
            proposal: ProposalValue
            if kind == "claim":
                proposal = ClaimProposal.model_validate_json(proposal_json)
            elif kind == "wiki":
                proposal = WikiProposal.model_validate_json(proposal_json)
            else:
                proposal = TheoryProposal.model_validate_json(proposal_json)
            descriptor = DraftDescriptor.model_validate_json(
                canonical_json_bytes(value["descriptor"])
            )
            return proposal, descriptor
        except (UnicodeDecodeError, ValueError, TypeError, ValidationError):
            raise KnowledgeProposalError("KNOWLEDGE_PROPOSAL_CONTENT_INVALID") from None

    def load(
        self,
        proposal_id: str,
        *,
        expected_kind: ProposalKind,
    ) -> DurableKnowledgeProposal:
        try:
            exact_id = _OBJECT_ID.validate_python(proposal_id)
        except ValidationError:
            raise KnowledgeProposalError("KNOWLEDGE_PROPOSAL_NOT_FOUND") from None
        row = self._connection.execute(
            """
            SELECT operation_id, operation_sha256, proposal_kind, proposal_id,
                   target_id, base_version, draft_sha256,
                   proposal_object_ref, proposal_object_sha256,
                   proposal_object_size_bytes, proposal_object_media_type,
                   approval_request_id, approval_descriptor_sha256,
                   approval_expires_at, state
              FROM knowledge_proposal_operations WHERE proposal_id = ?
            """,
            (exact_id,),
        ).fetchone()
        if row is None or str(row[2]) != expected_kind.upper():
            raise KnowledgeProposalError("KNOWLEDGE_PROPOSAL_NOT_FOUND")
        try:
            operation_id = _OBJECT_ID.validate_python(row[0])
            operation_sha256 = str(row[1])
            stored_proposal_id = _OBJECT_ID.validate_python(row[3])
            target_id = str(row[4])
            base_version = int(row[5])
            draft_sha256 = str(row[6])
            object_ref = str(row[7])
            object_sha256 = str(row[8])
            object_size = int(row[9])
            media_type = str(row[10])
            state = str(row[14]).lower()
            if (
                stored_proposal_id != exact_id
                or object_ref != f"sha256:{object_sha256}"
                or object_size <= 0
                or media_type != "application/json"
                or state not in {"proposed", "review_pending", "expired", "applied"}
            ):
                raise ValueError
            try:
                payload = self._store.read_hash_verified(object_sha256)
            except ContentStoreError:
                raise KnowledgeProposalError(
                    "KNOWLEDGE_PROPOSAL_CONTENT_INVALID"
                ) from None
            if len(payload) != object_size:
                raise ValueError
            proposal, payload_descriptor = self._parse_payload(
                payload,
                kind=expected_kind,
            )
            if _proposal_id(proposal) != stored_proposal_id:
                raise ValueError
            if _proposal_draft_sha256(proposal) != draft_sha256:
                raise ValueError
            descriptor = DraftDescriptor(
                purpose=_PURPOSE[expected_kind],
                target_id=target_id,
                base_version=base_version,
                draft_sha256=draft_sha256,
            )
            if payload_descriptor != descriptor:
                raise ValueError
            self._validate_descriptor_target(
                expected_kind,
                proposal,
                descriptor,
                require_current_theory_base=False,
            )
            if _operation_sha256(expected_kind, descriptor) != operation_sha256:
                raise ValueError
        except KnowledgeProposalError:
            raise
        except (TypeError, ValueError, ValidationError):
            raise KnowledgeProposalError("KNOWLEDGE_PROPOSAL_CONTENT_INVALID") from None
        approval_request_id = None if row[11] is None else str(row[11])
        if approval_request_id is not None:
            approval_row = self._connection.execute(
                """
                SELECT descriptor_sha256, descriptor_json, expires_at
                  FROM approval_requests WHERE request_id = ?
                """,
                (approval_request_id,),
            ).fetchone()
            try:
                if approval_row is None:
                    raise ValueError
                approval_descriptor = DraftDescriptor.model_validate_json(
                    str(approval_row[1])
                )
                proposal_expiry = _parse_utc(row[13])
                approval_expiry = _parse_utc(approval_row[2])
                if (
                    approval_descriptor != descriptor
                    or str(row[12]) != str(approval_row[0])
                    or str(approval_row[0])
                    != approval_descriptor_sha256(approval_descriptor)
                    or proposal_expiry != approval_expiry
                ):
                    raise ValueError
            except (KnowledgeProposalError, TypeError, ValueError, ValidationError):
                raise KnowledgeProposalError(
                    "KNOWLEDGE_PROPOSAL_APPROVAL_CONFLICT"
                ) from None
        return DurableKnowledgeProposal(
            operation_id=operation_id,
            operation_sha256=operation_sha256,
            kind=expected_kind,
            proposal_id=stored_proposal_id,
            descriptor=descriptor,
            proposal=proposal,
            approval_request_id=approval_request_id,
            state=cast(
                Literal["proposed", "review_pending", "expired", "applied"],
                state,
            ),
        )

    def bind_approval(
        self,
        proposal_id: str,
        *,
        expected_kind: ProposalKind,
        approval: ApprovalRequest,
    ) -> DurableKnowledgeProposal:
        exact = self.load(proposal_id, expected_kind=expected_kind)
        request = ApprovalRequest.model_validate(approval)
        if request.descriptor != exact.descriptor:
            raise KnowledgeProposalError("KNOWLEDGE_PROPOSAL_DESCRIPTOR_MISMATCH")
        now = self._clock.now()
        with transaction(self._connection):
            row = self._connection.execute(
                """
                SELECT approval_request_id, approval_descriptor_sha256,
                       approval_expires_at, state
                  FROM knowledge_proposal_operations
                 WHERE proposal_id = ? AND operation_sha256 = ?
                """,
                (exact.proposal_id, exact.operation_sha256),
            ).fetchone()
            if row is None:
                raise KnowledgeProposalError("KNOWLEDGE_PROPOSAL_NOT_FOUND")
            previous_id = None if row[0] is None else str(row[0])
            if previous_id is not None and previous_id != request.request_id:
                previous = self._connection.execute(
                    """
                    SELECT state, expires_at FROM approval_requests
                     WHERE request_id = ?
                    """,
                    (previous_id,),
                ).fetchone()
                bound = self._connection.execute(
                    """
                    SELECT operation_id FROM approval_receipts
                     WHERE request_id = ?
                    """,
                    (previous_id,),
                ).fetchone()
                replaceable = (
                    previous is not None
                    and str(previous[0]) in {"PENDING", "CONFIRMED", "REJECTED"}
                    and (
                        str(previous[0]) == "REJECTED"
                        or now >= _parse_utc(previous[1])
                    )
                    and (bound is None or bound[0] is None)
                    and str(row[3]) != "APPLIED"
                )
                if not replaceable:
                    raise KnowledgeProposalError(
                        "KNOWLEDGE_PROPOSAL_APPROVAL_CONFLICT"
                    )
            if previous_id == request.request_id:
                if (
                    str(row[1]) != request.descriptor_sha256
                    or _parse_utc(row[2]) != request.expires_at
                ):
                    raise KnowledgeProposalError(
                        "KNOWLEDGE_PROPOSAL_APPROVAL_CONFLICT"
                    )
            else:
                changed = self._connection.execute(
                    """
                    UPDATE knowledge_proposal_operations
                       SET approval_request_id = ?,
                           approval_descriptor_sha256 = ?,
                           approval_expires_at = ?, state = 'REVIEW_PENDING',
                           updated_at = ?
                     WHERE proposal_id = ? AND operation_sha256 = ?
                       AND state != 'APPLIED'
                    """,
                    (
                        request.request_id,
                        request.descriptor_sha256,
                        _utc(request.expires_at),
                        _utc(now),
                        exact.proposal_id,
                        exact.operation_sha256,
                    ),
                ).rowcount
                if changed != 1:
                    raise KnowledgeProposalError(
                        "KNOWLEDGE_PROPOSAL_APPROVAL_CONFLICT"
                    )
        return self.load(exact.proposal_id, expected_kind=expected_kind)

    def load_for_approval(
        self,
        approval_request_id: str,
        *,
        expected_kind: ProposalKind,
    ) -> DurableKnowledgeProposal:
        row = self._connection.execute(
            """
            SELECT proposal_id, approval_expires_at
              FROM knowledge_proposal_operations
             WHERE approval_request_id = ? AND proposal_kind = ?
            """,
            (approval_request_id, expected_kind.upper()),
        ).fetchone()
        if row is None:
            raise KnowledgeProposalError("KNOWLEDGE_PROPOSAL_NOT_FOUND")
        expires_at = _parse_utc(row[1])
        if self._clock.now() >= expires_at:
            receipt = self._connection.execute(
                """
                SELECT operation_id FROM approval_receipts
                 WHERE request_id = ?
                """,
                (approval_request_id,),
            ).fetchone()
            if receipt is None or receipt[0] is None:
                with transaction(self._connection):
                    self._connection.execute(
                        """
                        UPDATE knowledge_proposal_operations
                           SET state = 'EXPIRED', updated_at = ?
                         WHERE approval_request_id = ? AND state = 'REVIEW_PENDING'
                        """,
                        (_utc(self._clock.now()), approval_request_id),
                    )
                raise KnowledgeProposalError(
                    "KNOWLEDGE_PROPOSAL_APPROVAL_EXPIRED"
                )
        exact = self.load(str(row[0]), expected_kind=expected_kind)
        if exact.approval_request_id != approval_request_id:
            raise KnowledgeProposalError("KNOWLEDGE_PROPOSAL_APPROVAL_CONFLICT")
        return exact

    def mark_applied(
        self,
        approval_request_id: str,
        *,
        expected_kind: ProposalKind,
    ) -> DurableKnowledgeProposal:
        exact = self.load_for_approval(
            approval_request_id,
            expected_kind=expected_kind,
        )
        execution = self._connection.execute(
            """
            SELECT operation_id, request_id, descriptor_sha256, draft_sha256,
                   descriptor_base_version, target_scope_hash, nonce_sha256,
                   state, applied_commit_version, applied_at
              FROM approval_executions WHERE request_id = ?
            """,
            (approval_request_id,),
        ).fetchone()
        if (
            execution is None
            or str(execution[1]) != approval_request_id
            or str(execution[2]) != self._approval_descriptor_sha256(
                exact.proposal_id
            )
            or str(execution[3]) != exact.descriptor.draft_sha256
            or int(execution[4]) != exact.descriptor.base_version
            or str(execution[7]) != "APPLIED"
            or execution[8] is None
            or execution[9] is None
        ):
            raise KnowledgeProposalError("KNOWLEDGE_PROPOSAL_EXECUTION_MISMATCH")
        execution_operation_id = _OBJECT_ID.validate_python(execution[0])
        execution_sha256 = canonical_sha256(
            {
                "applied_at": str(execution[9]),
                "applied_commit_version": int(execution[8]),
                "descriptor_base_version": int(execution[4]),
                "descriptor_sha256": str(execution[2]),
                "draft_sha256": str(execution[3]),
                "nonce_sha256": str(execution[6]),
                "operation_id": execution_operation_id,
                "request_id": approval_request_id,
                "state": "APPLIED",
                "target_scope_hash": str(execution[5]),
            }
        )
        now = self._clock.now()
        with transaction(self._connection):
            row = self._connection.execute(
                """
                SELECT execution_operation_id, execution_sha256, state
                  FROM knowledge_proposal_operations
                 WHERE proposal_id = ? AND approval_request_id = ?
                """,
                (exact.proposal_id, approval_request_id),
            ).fetchone()
            if row is None:
                raise KnowledgeProposalError("KNOWLEDGE_PROPOSAL_NOT_FOUND")
            if str(row[2]) == "APPLIED":
                if (
                    str(row[0]) != execution_operation_id
                    or str(row[1]) != execution_sha256
                ):
                    raise KnowledgeProposalError(
                        "KNOWLEDGE_PROPOSAL_EXECUTION_MISMATCH"
                    )
            else:
                changed = self._connection.execute(
                    """
                    UPDATE knowledge_proposal_operations
                       SET execution_operation_id = ?, execution_sha256 = ?,
                           state = 'APPLIED', updated_at = ?
                     WHERE proposal_id = ? AND approval_request_id = ?
                       AND state = 'REVIEW_PENDING'
                    """,
                    (
                        execution_operation_id,
                        execution_sha256,
                        _utc(now),
                        exact.proposal_id,
                        approval_request_id,
                    ),
                ).rowcount
                if changed != 1:
                    raise KnowledgeProposalError(
                        "KNOWLEDGE_PROPOSAL_EXECUTION_MISMATCH"
                    )
        return self.load(exact.proposal_id, expected_kind=expected_kind)

    def _approval_descriptor_sha256(self, proposal_id: str) -> str:
        row = self._connection.execute(
            """
            SELECT approval_descriptor_sha256
              FROM knowledge_proposal_operations WHERE proposal_id = ?
            """,
            (proposal_id,),
        ).fetchone()
        if row is None or type(row[0]) is not str:
            raise KnowledgeProposalError("KNOWLEDGE_PROPOSAL_APPROVAL_CONFLICT")
        return row[0]


__all__ = [
    "DurableKnowledgeProposal",
    "KnowledgeProposalError",
    "KnowledgeProposalRepository",
    "ProposalKind",
]
