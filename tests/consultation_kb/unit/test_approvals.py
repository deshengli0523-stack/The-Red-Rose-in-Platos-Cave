from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from consultation_kb.approvals.models import ApprovalExecutionTicket
from consultation_kb.approvals.provider import (
    ApprovalProvider,
    ProtectedProviderSecretStore,
    ProviderSecretUnavailable,
)
from consultation_kb.approvals.store import (
    ApprovalExpired,
    ApprovalMismatch,
    ApprovalProviderRejected,
    ApprovalUsed,
)
from consultation_kb.models.manifests import ApprovalReceipt
from tests.consultation_kb.approval_support import (
    ApprovalHarness,
    TestProtector,
    build_approval_harness,
)


@pytest.fixture
def harness(tmp_path: Path) -> ApprovalHarness:
    value = build_approval_harness(tmp_path)
    yield value
    value.close()


def _confirm(harness: ApprovalHarness, draft=None):
    approved_draft = draft if draft is not None else harness.draft()
    request = harness.service.request(
        approved_draft,
        diff_object_ref=harness.diff_object_ref(),
    )
    event = harness.signer.confirm(
        harness.service.challenge_for_review(request.request_id)
    )
    harness.service.confirm(event)
    return approved_draft, request, event


def test_approval_is_bound_to_hash_version_and_single_operation(
    harness: ApprovalHarness,
) -> None:
    draft, request, _event = _confirm(harness)
    operation_id = harness.operation_id()
    changed = draft.model_copy(update={"draft_sha256": "0" * 64})
    with pytest.raises(ApprovalMismatch):
        harness.service.issue_for_execution(
            request.request_id,
            changed,
            operation_id=operation_id,
        )

    ticket = harness.service.issue_for_execution(
        request.request_id,
        draft,
        operation_id=operation_id,
    )
    assert ticket.descriptor_sha256 == request.descriptor_sha256
    assert (
        harness.service.issue_for_execution(
            request.request_id,
            draft,
            operation_id=operation_id,
        )
        == ticket
    )
    with pytest.raises(ApprovalUsed):
        harness.service.issue_for_execution(
            request.request_id,
            draft,
            operation_id=harness.operation_id(),
        )


def test_nonce_and_receipt_are_protected_at_rest(harness: ApprovalHarness) -> None:
    _draft, request, event = _confirm(harness)
    nonce_row = harness.global_connection.execute(
        "SELECT nonce_ciphertext FROM approval_requests WHERE request_id = ?",
        (request.request_id,),
    ).fetchone()
    receipt_row = harness.global_connection.execute(
        "SELECT receipt_json FROM approval_receipts WHERE request_id = ?",
        (request.request_id,),
    ).fetchone()
    assert nonce_row is not None and event.nonce.encode("ascii") not in nonce_row[0]
    assert receipt_row is not None and event.nonce not in receipt_row[0]


def test_forged_provider_signature_is_rejected(harness: ApprovalHarness) -> None:
    draft = harness.draft()
    request = harness.service.request(
        draft,
        diff_object_ref=harness.diff_object_ref(),
    )
    event = harness.signer.confirm(
        harness.service.challenge_for_review(request.request_id)
    )
    forged = event.model_copy(update={"signature": "0" * 64})
    with pytest.raises(ApprovalProviderRejected):
        harness.service.confirm(forged)
    assert harness.service.get(request.request_id).state == "pending"


def test_confirmed_display_diff_reference_cannot_be_swapped(
    harness: ApprovalHarness,
) -> None:
    draft, request, _event = _confirm(harness)
    replacement = harness.diff_object_ref()
    harness.global_connection.execute(
        "UPDATE approval_requests SET diff_object_ref_json = ? WHERE request_id = ?",
        (
            json.dumps(
                replacement.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            ),
            request.request_id,
        ),
    )
    with pytest.raises(ApprovalProviderRejected):
        harness.service.issue_for_execution(
            request.request_id,
            draft,
            operation_id=harness.operation_id(),
        )


def test_expired_request_cannot_be_confirmed_or_issued(
    harness: ApprovalHarness,
) -> None:
    draft = harness.draft()
    request = harness.service.request(
        draft,
        diff_object_ref=harness.diff_object_ref(),
    )
    challenge = harness.service.challenge_for_review(request.request_id)
    event = harness.signer.confirm(challenge)
    harness.clock.value = request.expires_at
    with pytest.raises(ApprovalExpired):
        harness.service.confirm(event)

    harness.clock.value = request.created_at
    event = harness.signer.confirm(
        harness.service.challenge_for_review(request.request_id)
    )
    harness.service.confirm(event)
    harness.clock.value = request.expires_at + timedelta(seconds=1)
    with pytest.raises(ApprovalExpired):
        harness.service.issue_for_execution(
            request.request_id,
            draft,
            operation_id=harness.operation_id(),
        )


def test_ticket_validation_rejects_field_rebinding(harness: ApprovalHarness) -> None:
    draft, request, _event = _confirm(harness)
    ticket = harness.service.issue_for_execution(
        request.request_id,
        draft,
        operation_id=harness.operation_id(),
    )
    with pytest.raises(ValidationError):
        ticket.operation_id = harness.operation_id()  # type: ignore[misc]
    forged = ApprovalExecutionTicket.model_validate(
        {**ticket.model_dump(), "issuance_signature": "0" * 64}
    )
    with pytest.raises(ApprovalProviderRejected):
        harness.service.verify_ticket(forged, draft, allow_expired=False)


def test_invalid_operation_id_cannot_partially_bind_receipt(
    harness: ApprovalHarness,
) -> None:
    draft, request, _event = _confirm(harness)
    with pytest.raises(ValidationError):
        harness.service.issue_for_execution(
            request.request_id,
            draft,
            operation_id="not-an-object-id",
        )
    assert harness.global_connection.execute(
        "SELECT operation_id FROM approval_receipts WHERE request_id = ?",
        (request.request_id,),
    ).fetchone() == (None,)


def test_receipt_role_is_closed_to_primary_counselor(
    harness: ApprovalHarness,
) -> None:
    _draft, _request, event = _confirm(harness)
    with pytest.raises(ValidationError):
        ApprovalReceipt.model_validate({**event.model_dump(), "approver_role": "model"})


def test_provider_secret_is_explicit_single_create_and_context_bound(
    tmp_path: Path,
) -> None:
    secret_path = (tmp_path / "security" / "review-agent-secret.dpapi").resolve()
    store = ProtectedProviderSecretStore(
        secret_path,
        protector=TestProtector(),
        vault_id="synthetic-vault",
    )
    store.initialize(random_source=lambda size: b"s" * size)
    assert store.load() == b"s" * 32
    assert (
        store.load_execution_secret()
        != store.load_target_execution_attestation_secret()
    )
    with pytest.raises(ProviderSecretUnavailable):
        store.initialize(random_source=lambda size: b"x" * size)
    wrong_context = ProtectedProviderSecretStore(
        secret_path,
        protector=TestProtector(),
        vault_id="other-vault",
    )
    with pytest.raises(ProviderSecretUnavailable):
        wrong_context.load()


def test_control_plane_verifier_has_no_signing_capability(
    harness: ApprovalHarness,
) -> None:
    assert isinstance(harness.verifier, ApprovalProvider)
    assert not hasattr(harness.verifier, "confirm")
