from __future__ import annotations

from datetime import timedelta
from typing import cast

from consultation_kb.approvals.attestation import LocalHmacTargetExecutionAttestor
from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.models import ApprovalExecutionTicket, descriptor_sha256
from consultation_kb.approvals.store import ApprovalMismatch, ApprovalService
from consultation_kb.archive.private_review import PrivateArchiveReviewService
from consultation_kb.models.archive import (
    PrivateArchiveDraft,
    PrivateArchivePublication,
    PrivateArchiveReviewDecision,
)
from consultation_kb.models.manifests import ApprovalReceipt, DraftDescriptor
from consultation_kb.session.repository import SessionRepository


class _ExactTicketVerifier:
    def __init__(self, ticket: ApprovalExecutionTicket) -> None:
        self._ticket = ticket

    def verify_ticket(
        self,
        ticket: ApprovalExecutionTicket,
        descriptor: DraftDescriptor,
        *,
        allow_expired: bool,
    ) -> ApprovalReceipt:
        del allow_expired
        if ticket != self._ticket or descriptor != self._ticket.descriptor:
            raise ApprovalMismatch("test approval binding mismatch")
        return self._ticket.receipt


def commit_private_archive_with_guard(
    repository: SessionRepository,
    draft: PrivateArchiveDraft,
) -> tuple[
    PrivateArchiveReviewDecision,
    PrivateArchivePublication,
    PrivateArchivePublication,
]:
    service = PrivateArchiveReviewService(repository)
    preview = service.preview(draft)
    session = repository.get_session(draft.actual_transcript.session_id)
    now = repository.clock.now()
    request_id = repository.id_factory.object_id("approval_request")
    ticket = ApprovalExecutionTicket(
        operation_id=repository.id_factory.object_id("approval_operation"),
        target_scope_hash=session.client_scope_hash,
        descriptor=preview.descriptor,
        receipt=ApprovalReceipt(
            request_id=request_id,
            descriptor_sha256=descriptor_sha256(preview.descriptor),
            approver_role="primary_counselor",
            approved_at=now,
            expires_at=now + timedelta(hours=1),
            nonce=f"private-archive-nonce-{request_id}",
            provider_id="local-review-agent",
            signature="test-provider-signature",
        ),
        issuance_signature="e" * 64,
    )
    result: list[tuple[PrivateArchiveReviewDecision, PrivateArchivePublication]] = []

    def apply(_connection) -> None:  # type: ignore[no-untyped-def]
        decision = service.approve_modified(
            draft,
            approval_ticket=ticket,
        )
        publication = service.commit(
            decision,
            approval_ticket=ticket,
        )
        result.append((decision, publication))

    ApprovalExecutionGuard(
        repository.connection,
        approval_service=cast(ApprovalService, _ExactTicketVerifier(ticket)),
        execution_proof_signer=LocalHmacTargetExecutionAttestor(
            secret=b"t" * 32,
            attestor_id="test-target-writer",
        ),
        clock=repository.clock,
    ).apply_in_transaction(ticket, preview.descriptor, apply)
    if len(result) != 1:
        raise AssertionError("guarded private archive callback did not run exactly once")
    decision, publication = result[0]
    replayed = service.recover_committed(draft, approval_ticket=ticket)
    return decision, publication, replayed
