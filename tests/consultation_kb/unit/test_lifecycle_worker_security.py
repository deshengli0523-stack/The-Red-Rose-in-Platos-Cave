from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from consultation_kb.approvals.models import (
    ApprovalExecutionTicket,
    descriptor_sha256,
)
from consultation_kb.models.manifests import ApprovalReceipt, DraftDescriptor
from consultation_kb.security.scoped_worker import ScopedWorkerBroker
from consultation_kb.security.worker_claim import (
    ApprovedCommitClaimPayload,
    LocalHmacApprovedCommitClaimSigner,
    LocalHmacApprovedCommitClaimVerifier,
)
from consultation_kb.security.worker_protocol import (
    ArchiveContentRef,
    CommitClientTombstoneRequest,
    PreviewClientDeleteRequest,
    RebuildClientDerivativesRequest,
    RecoverClientManifestsRequest,
    VerifyClientIntegrityRequest,
    WorkerBaseVersion,
    WorkerProtocolError,
    encode_message,
)


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=UTC)
UUID = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
UUID_2 = "017f22e2-79b0-7cc3-98c4-dc0c0c073990"
UUID_3 = "017f22e2-79b0-7cc3-98c4-dc0c0c073991"
TARGET_SCOPE = "a" * 64
PLAN_SHA256 = "b" * 64
OPERATION_ID = f"approval_operation_{UUID}"
APPROVAL_REQUEST_ID = f"approval_request_{UUID_2}"
JOB_ID = f"rebuild_job_{UUID_3}"


def _base_version(version: int = 3) -> WorkerBaseVersion:
    return WorkerBaseVersion(
        authority_key="tombstone_epoch",
        scope_sha256=TARGET_SCOPE,
        version=version,
    )


def _rebuild_plan_ref() -> ArchiveContentRef:
    return ArchiveContentRef(
        object_id=f"lifecycle_plan_{UUID_3}",
        version=1,
        content_sha256="e" * 64,
        size_bytes=256,
    )


def _rebuild_request(
    action: str,
    *,
    purpose: str = "all",
) -> RebuildClientDerivativesRequest:
    if action == "START":
        return RebuildClientDerivativesRequest(
            request_id=UUID,
            action="START",
            purpose=purpose,
            plan_sha256=PLAN_SHA256,
            base_versions=(_base_version(),),
            idempotency_key="rebuild-once",
            approval_operation_id=OPERATION_ID,
            approval_request_id=APPROVAL_REQUEST_ID,
            plan_ref=_rebuild_plan_ref(),
        )
    if action == "CANCEL":
        return RebuildClientDerivativesRequest(
            request_id=UUID,
            action="CANCEL",
            job_id=JOB_ID,
            plan_sha256=PLAN_SHA256,
            base_versions=(_base_version(),),
            approval_operation_id=OPERATION_ID,
            approval_request_id=APPROVAL_REQUEST_ID,
            plan_ref=_rebuild_plan_ref(),
        )
    if action == "STATUS":
        return RebuildClientDerivativesRequest(
            request_id=UUID,
            action="STATUS",
            job_id=JOB_ID,
        )
    if action == "REPORT":
        return RebuildClientDerivativesRequest(
            request_id=UUID,
            action="REPORT",
            job_id=JOB_ID,
        )
    raise AssertionError("unsupported test action")


def _commit_request() -> CommitClientTombstoneRequest:
    return CommitClientTombstoneRequest(
        request_id=UUID,
        plan_ref=ArchiveContentRef(
            object_id=f"deletion_plan_{UUID_3}",
            version=1,
            content_sha256=PLAN_SHA256,
            size_bytes=128,
        ),
        plan_sha256=PLAN_SHA256,
        target_scope_hash=TARGET_SCOPE,
        base_versions=(_base_version(),),
        approval_operation_id=OPERATION_ID,
        approval_request_id=APPROVAL_REQUEST_ID,
    )


def _rebuild_claim_payload(
    *,
    purpose: str = "all",
) -> ApprovedCommitClaimPayload:
    descriptor = DraftDescriptor(
        purpose="rebuild",
        target_id=f"client_rebuild:{purpose}",
        client_id="client" + "_aaaaaaaaaaaa",
        base_version=3,
        draft_sha256=PLAN_SHA256,
    )
    nonce = "approval-nonce"
    ticket = ApprovalExecutionTicket(
        operation_id=OPERATION_ID,
        target_scope_hash=TARGET_SCOPE,
        descriptor=descriptor,
        receipt=ApprovalReceipt(
            request_id=APPROVAL_REQUEST_ID,
            descriptor_sha256=descriptor_sha256(descriptor),
            approver_role="primary_counselor",
            approved_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            nonce=nonce,
            provider_id="test-provider",
            signature="provider-signature",
        ),
        issuance_signature="c" * 64,
    )
    return ApprovedCommitClaimPayload(
        claim_id=f"worker_claim_{UUID_3}",
        claim_nonce="one-shot-rebuild-claim",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=10),
        target_scope_hash=TARGET_SCOPE,
        descriptor_sha256=descriptor_sha256(descriptor),
        approval_nonce_sha256=hashlib.sha256(
            nonce.encode("ascii")
        ).hexdigest(),
        request=_rebuild_request("START", purpose=purpose),
        descriptor=descriptor,
        ticket=ticket,
    )


def test_lifecycle_permissions_separate_read_draft_and_formal_actions() -> None:
    preview = PreviewClientDeleteRequest(
        request_id=UUID,
        target_type="session",
        target_id=UUID_2,
        target_version=1,
        target_content_sha256="d" * 64,
        reason_code="client_request",
        proposed_operation_id=f"deletion_operation_{UUID_3}",
        requested_at=NOW,
    )

    assert ScopedWorkerBroker._permission(RecoverClientManifestsRequest(
        request_id=UUID,
        dry_run=True,
    )) == "client_read"
    assert ScopedWorkerBroker._permission(RecoverClientManifestsRequest(
        request_id=UUID,
        dry_run=False,
    )) == "formal_write"
    assert ScopedWorkerBroker._permission(preview) == "draft_write"
    assert ScopedWorkerBroker._permission(_commit_request()) == "formal_write"
    assert ScopedWorkerBroker._permission(_rebuild_request("STATUS")) == "client_read"
    assert ScopedWorkerBroker._permission(_rebuild_request("REPORT")) == "client_read"
    assert ScopedWorkerBroker._permission(_rebuild_request("START")) == "formal_write"
    assert ScopedWorkerBroker._permission(_rebuild_request("CANCEL")) == "formal_write"
    assert ScopedWorkerBroker._permission(VerifyClientIntegrityRequest(
        request_id=UUID,
    )) == "client_read"


def test_client_rebuild_rejects_unapproved_extra_base_authority() -> None:
    values = _rebuild_request("START").model_dump(mode="python")
    bases = values["base_versions"]
    assert isinstance(bases, tuple)
    values["base_versions"] = (
        *bases,
        WorkerBaseVersion(
            authority_key="unrelated_epoch",
            scope_sha256="c" * 64,
            version=9,
        ),
    )

    with pytest.raises(ValidationError, match="single tombstone epoch"):
        RebuildClientDerivativesRequest.model_validate(values)


def test_lifecycle_public_frames_are_body_free_and_contain_no_authority_secret() -> None:
    requests = (
        RecoverClientManifestsRequest(request_id=UUID),
        _commit_request(),
        _rebuild_request("START"),
        _rebuild_request("STATUS"),
        VerifyClientIntegrityRequest(request_id=UUID),
    )
    forbidden = (
        b'"client_id"',
        b'"nonce"',
        b'"path"',
        b'"receipt"',
        b'"sql"',
        b'"ticket"',
    )

    for request in requests:
        encoded = encode_message(request)
        assert all(needle not in encoded for needle in forbidden)


def test_rebuild_claim_rejects_forgery_and_read_action_downgrade() -> None:
    payload = _rebuild_claim_payload()
    signer = LocalHmacApprovedCommitClaimSigner(b"s" * 32)
    verifier = LocalHmacApprovedCommitClaimVerifier(b"s" * 32)
    claim = signer.sign(payload)

    with pytest.raises(WorkerProtocolError, match="WORKER_PROTOCOL_INVALID"):
        verifier.verify(
            claim.model_copy(update={"claim_signature": "0" * 64}),
            now=NOW,
        )

    downgraded = payload.model_dump(mode="json")
    request = downgraded["request"]
    assert isinstance(request, dict)
    request.update(
        {
            "action": "STATUS",
            "job_id": JOB_ID,
            "purpose": None,
            "plan_sha256": None,
            "base_versions": [],
            "idempotency_key": None,
            "approval_operation_id": None,
            "approval_request_id": None,
            "plan_ref": None,
        }
    )
    with pytest.raises(ValidationError):
        ApprovedCommitClaimPayload.model_validate(downgraded)


def test_rebuild_claim_rejects_partial_runtime_activation() -> None:
    with pytest.raises(ValidationError, match="client rebuild approval mismatch"):
        _rebuild_claim_payload(purpose="client_profile")
