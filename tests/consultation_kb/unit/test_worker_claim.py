from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from consultation_kb.approvals.models import ApprovalExecutionTicket, descriptor_sha256
from consultation_kb.models.manifests import ApprovalReceipt, DraftDescriptor
from consultation_kb.security.worker_claim import (
    ApprovedCommitClaimPayload,
    AppliedCommitRecoveryPayload,
    AppliedCommitNotAppliedPayload,
    CasePublishRpcPayload,
    CasePublishRpcResultPayload,
    LocalHmacApprovedCommitClaimSigner,
    LocalHmacApprovedCommitClaimVerifier,
    LocalHmacAppliedCommitNotAppliedResult,
    LocalHmacCasePublishRpc,
    decode_approved_commit_claim,
    decode_applied_not_applied_result,
    decode_case_publish_result,
    decode_case_publish_rpc,
    encode_approved_commit_claim,
    encode_applied_not_applied_result,
    encode_case_publish_result,
    encode_case_publish_rpc,
)
from consultation_kb.security.worker_protocol import (
    ArchiveContentRef,
    CommitFactMutationRequest,
    CommitPrivateArchiveRequest,
    WorkerProtocolError,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 18, 8, 0, tzinfo=UTC)
UUID = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
UUID_2 = "017f22e2-79b0-7cc3-98c4-dc0c0c073990"
UUID_3 = "017f22e2-79b0-7cc3-98c4-dc0c0c073991"
OPERATION_ID = f"approval_operation_{UUID}"
REQUEST_ID = f"approval_request_{UUID_2}"
CLAIM_ID = f"worker_claim_{UUID_3}"


def _payload() -> ApprovedCommitClaimPayload:
    draft_hash = "1" * 64
    descriptor = DraftDescriptor(
        purpose="profile_update",
        target_id=f"fact_draft_{UUID}",
        client_id="client_" + "a" * 12,
        base_version=0,
        draft_sha256=draft_hash,
    )
    nonce = "approval-nonce"
    receipt = ApprovalReceipt(
        request_id=REQUEST_ID,
        descriptor_sha256=descriptor_sha256(descriptor),
        approver_role="primary_counselor",
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce=nonce,
        provider_id="test-provider",
        signature="provider-signature",
    )
    ticket = ApprovalExecutionTicket(
        operation_id=OPERATION_ID,
        target_scope_hash="a" * 64,
        descriptor=descriptor,
        receipt=receipt,
        issuance_signature="2" * 64,
    )
    return ApprovedCommitClaimPayload(
        claim_id=CLAIM_ID,
        claim_nonce="one-shot-claim-nonce",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=10),
        target_scope_hash=ticket.target_scope_hash,
        descriptor_sha256=descriptor_sha256(descriptor),
        approval_nonce_sha256=hashlib.sha256(nonce.encode("ascii")).hexdigest(),
        request=CommitFactMutationRequest(
            request_id=UUID,
            draft_event_id=f"fact_draft_{UUID}",
            approval_operation_id=OPERATION_ID,
            preview_sha256=draft_hash,
            base_commit_version=0,
            expected_runtime_epoch=1,
            publication_timestamp=NOW,
        ),
        descriptor=descriptor,
        ticket=ticket,
    )


def test_private_claim_round_trip_and_complete_binding() -> None:
    signer = LocalHmacApprovedCommitClaimSigner(b"c" * 32)
    verifier = LocalHmacApprovedCommitClaimVerifier(b"c" * 32)
    claim = signer.sign(_payload())

    encoded = encode_approved_commit_claim(claim)
    decoded = decode_approved_commit_claim(encoded)

    assert verifier.verify(decoded, now=NOW) == claim.payload
    assert b"CKB-APPROVED-COMMIT-1\0" == encoded[:22]


def test_private_claim_rejects_wrong_signer_and_expiry() -> None:
    claim = LocalHmacApprovedCommitClaimSigner(b"c" * 32).sign(_payload())

    with pytest.raises(WorkerProtocolError, match="WORKER_PROTOCOL_INVALID"):
        LocalHmacApprovedCommitClaimVerifier(b"d" * 32).verify(claim, now=NOW)
    with pytest.raises(WorkerProtocolError, match="WORKER_PROTOCOL_INVALID"):
        LocalHmacApprovedCommitClaimVerifier(b"c" * 32).verify(
            claim,
            now=NOW + timedelta(seconds=10),
        )


def test_recovery_claim_cannot_predate_the_original_approval() -> None:
    approved = _payload()
    with pytest.raises(ValidationError, match="recovery binding mismatch"):
        AppliedCommitRecoveryPayload(
            claim_id=CLAIM_ID,
            claim_nonce="one-shot-recovery-claim",
            issued_at=NOW - timedelta(seconds=1),
            expires_at=NOW + timedelta(seconds=9),
            target_scope_hash=approved.target_scope_hash,
            descriptor_sha256=approved.descriptor_sha256,
            approval_nonce_sha256=approved.approval_nonce_sha256,
            request=approved.request,
            descriptor=approved.descriptor,
            ticket=approved.ticket,
        )


def test_private_archive_claim_round_trip_binds_exact_draft() -> None:
    draft_hash = "4" * 64
    draft_ref = ArchiveContentRef(
        object_id=f"private_archive_draft_{UUID}",
        version=1,
        content_sha256=draft_hash,
        size_bytes=128,
    )
    descriptor = DraftDescriptor(
        purpose="private_archive_publish",
        target_id=draft_ref.object_id,
        client_id="client_" + "a" * 12,
        base_version=0,
        draft_sha256=draft_hash,
        session_id=UUID,
    )
    nonce = "archive-approval-nonce"
    ticket = ApprovalExecutionTicket(
        operation_id=OPERATION_ID,
        target_scope_hash="a" * 64,
        descriptor=descriptor,
        receipt=ApprovalReceipt(
            request_id=REQUEST_ID,
            descriptor_sha256=descriptor_sha256(descriptor),
            approver_role="primary_counselor",
            approved_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            nonce=nonce,
            provider_id="test-provider",
            signature="provider-signature",
        ),
        issuance_signature="5" * 64,
    )
    payload = ApprovedCommitClaimPayload(
        claim_id=CLAIM_ID,
        claim_nonce="archive-private-claim",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=10),
        target_scope_hash=ticket.target_scope_hash,
        descriptor_sha256=descriptor_sha256(descriptor),
        approval_nonce_sha256=hashlib.sha256(
            nonce.encode("ascii")
        ).hexdigest(),
        request=CommitPrivateArchiveRequest(
            request_id=UUID_3,
            session_handle="opaque-session-handle",
            bundle_id=f"archive_bundle_{UUID_2}",
            draft_ref=draft_ref,
            base_version=0,
            approval_operation_id=OPERATION_ID,
            approval_request_id=REQUEST_ID,
        ),
        descriptor=descriptor,
        ticket=ticket,
    )
    claim = LocalHmacApprovedCommitClaimSigner(b"c" * 32).sign(payload)
    decoded = decode_approved_commit_claim(encode_approved_commit_claim(claim))
    assert decoded == claim


def test_case_publish_internal_rpc_is_body_free_sealed_and_not_public() -> None:
    codec = LocalHmacCasePublishRpc(b"r" * 32)
    payload = CasePublishRpcPayload(
        rpc_id=f"case_publish_rpc_{UUID}",
        action="EXPORT",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=10),
        event_id=f"case_outbox_event_{UUID_2}",
    )
    request = codec.sign_request(payload)
    encoded = encode_case_publish_rpc(request)
    decoded = decode_case_publish_rpc(encoded)

    assert codec.verify_request(decoded, now=NOW) == payload
    assert all(
        needle not in encoded
        for needle in (b"client_id", b"session_id", b"path", b"sql", b"sections")
    )
    with pytest.raises(WorkerProtocolError):
        LocalHmacCasePublishRpc(b"s" * 32).verify_request(decoded, now=NOW)

    result_payload = CasePublishRpcResultPayload(
        rpc_id=payload.rpc_id,
        action="EXPORT",
    )
    result = codec.sign_result(result_payload)
    decoded_result = decode_case_publish_result(encode_case_publish_result(result))
    assert codec.verify_result(decoded_result) == result_payload


def test_not_applied_probe_result_is_exact_sealed_and_target_bound() -> None:
    codec = LocalHmacAppliedCommitNotAppliedResult(b"n" * 32)
    payload = AppliedCommitNotAppliedPayload(
        claim_id=CLAIM_ID,
        claim_nonce_sha256="1" * 64,
        worker_request_id=UUID_3,
        request_sha256="2" * 64,
        approval_request_id=REQUEST_ID,
        operation_id=OPERATION_ID,
        descriptor_sha256="3" * 64,
        draft_sha256="4" * 64,
        descriptor_base_version=0,
        target_scope_hash="5" * 64,
        approval_nonce_sha256="6" * 64,
    )
    sealed = codec.sign(payload)
    decoded = decode_applied_not_applied_result(
        encode_applied_not_applied_result(sealed)
    )

    assert codec.verify(decoded) == payload
    with pytest.raises(WorkerProtocolError):
        LocalHmacAppliedCommitNotAppliedResult(b"x" * 32).verify(decoded)
    with pytest.raises(WorkerProtocolError):
        codec.verify(
            decoded.model_copy(
                update={
                    "payload": payload.model_copy(
                        update={"target_scope_hash": "7" * 64}
                    )
                }
            )
        )
