from __future__ import annotations

import hashlib
from datetime import timedelta
from pathlib import Path

import pytest

from consultation_kb.approvals.attestation import (
    LocalHmacTargetExecutionAttestor,
)
from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.store import ApprovalExpired, ApprovalMismatch
from consultation_kb.models.manifests import ApprovalExecution
from tests.consultation_kb.approval_support import (
    ApprovalHarness,
    build_approval_harness,
)


@pytest.fixture
def harness(tmp_path: Path) -> ApprovalHarness:
    value = build_approval_harness(tmp_path)
    yield value
    value.close()


def _issued(harness: ApprovalHarness):
    draft = harness.draft()
    request = harness.service.request(
        draft,
        diff_object_ref=harness.diff_object_ref(),
    )
    event = harness.signer.confirm(
        harness.service.challenge_for_review(request.request_id)
    )
    harness.service.confirm(event)
    ticket = harness.service.issue_for_execution(
        request.request_id,
        draft,
        operation_id=harness.operation_id(),
    )
    return draft, ticket


def test_constructed_execution_cannot_acknowledge_without_target_proof(
    harness: ApprovalHarness,
) -> None:
    draft, ticket = _issued(harness)
    forged = ApprovalExecution(
        operation_id=ticket.operation_id,
        request_id=ticket.request_id,
        descriptor_sha256=ticket.descriptor_sha256,
        target_scope_hash=ticket.target_scope_hash,
        state="applied",
        applied_commit_version=1,
    )

    with pytest.raises(AttributeError):
        getattr(harness.service, "_attest_execution")(ticket, forged)
    with pytest.raises(ApprovalMismatch):
        harness.service.acknowledge(forged)  # type: ignore[arg-type]
    forged_proof = LocalHmacTargetExecutionAttestor(
        secret=b"x" * 32,
        attestor_id="test-target-writer",
    ).attest(
        execution=forged,
        draft_sha256=draft.draft_sha256,
        nonce_sha256=hashlib.sha256(ticket.receipt.nonce.encode("ascii")).hexdigest(),
        issuance_signature=ticket.issuance_signature,
    )
    with pytest.raises(ApprovalMismatch):
        harness.service.acknowledge(forged_proof)

    assert harness.target_connection.execute(
        "SELECT count(*) FROM approval_executions"
    ).fetchone() == (0,)
    assert harness.global_connection.execute(
        "SELECT state FROM approval_receipts WHERE request_id = ?",
        (ticket.request_id,),
    ).fetchone() == ("ISSUED",)


def test_target_write_and_execution_are_atomic_and_retry_is_idempotent(
    harness: ApprovalHarness,
) -> None:
    draft, ticket = _issued(harness)
    callback_calls = 0

    def write_business_row(connection) -> None:
        nonlocal callback_calls
        callback_calls += 1
        connection.execute(
            "INSERT INTO synthetic_business(id, value) VALUES (1, 'safe')"
        )

    execution = harness.guard.apply_in_transaction(ticket, draft, write_business_row)
    acknowledged = harness.service.acknowledge(execution)
    retried = harness.guard.apply_in_transaction(
        ticket,
        draft,
        lambda _connection: pytest.fail("must not rerun callback"),
    )
    assert acknowledged.state == "acknowledged"
    assert retried.operation_id == execution.operation_id
    assert callback_calls == 1
    assert harness.target_connection.execute(
        "SELECT count(*) FROM synthetic_business"
    ).fetchone() == (1,)


def test_callback_failure_rolls_back_business_and_execution(
    harness: ApprovalHarness,
) -> None:
    draft, ticket = _issued(harness)

    def fail_mid_write(connection) -> None:
        connection.execute(
            "INSERT INTO synthetic_business(id, value) VALUES (1, 'rollback')"
        )
        raise RuntimeError("injected")

    with pytest.raises(RuntimeError, match="injected"):
        harness.guard.apply_in_transaction(ticket, draft, fail_mid_write)
    assert harness.target_connection.execute(
        "SELECT count(*) FROM synthetic_business"
    ).fetchone() == (0,)
    assert harness.target_connection.execute(
        "SELECT count(*) FROM approval_executions"
    ).fetchone() == (0,)


def test_callback_runs_only_after_transactional_claim(
    harness: ApprovalHarness,
) -> None:
    draft, ticket = _issued(harness)

    def assert_claimed(connection) -> None:
        row = connection.execute(
            """
            SELECT request_id, descriptor_sha256, target_scope_hash, state,
                   applied_commit_version, applied_at
              FROM approval_executions
             WHERE operation_id = ?
            """,
            (ticket.operation_id,),
        ).fetchone()
        assert row == (
            ticket.request_id,
            ticket.descriptor_sha256,
            ticket.target_scope_hash,
            "CLAIMED",
            None,
            None,
        )

    execution = harness.guard.apply_in_transaction(ticket, draft, assert_claimed)
    assert execution.state == "applied"
    assert harness.target_connection.execute(
        """
        SELECT state, applied_commit_version IS NOT NULL, applied_at IS NOT NULL
          FROM approval_executions WHERE operation_id = ?
        """,
        (ticket.operation_id,),
    ).fetchone() == ("APPLIED", 1, 1)


def test_expired_ticket_can_only_recover_an_existing_operation(
    harness: ApprovalHarness,
) -> None:
    draft, ticket = _issued(harness)
    execution = harness.guard.apply_in_transaction(
        ticket,
        draft,
        lambda connection: connection.execute(
            "INSERT INTO synthetic_business(id, value) VALUES (1, 'committed')"
        ),
    )
    harness.clock.value = ticket.receipt.expires_at + timedelta(seconds=1)
    reconstructed = harness.service.issue_for_execution(
        ticket.request_id,
        draft,
        operation_id=ticket.operation_id,
    )
    recovered = harness.guard.apply_in_transaction(
        reconstructed,
        draft,
        lambda _connection: pytest.fail("must not rerun callback"),
    )
    assert recovered == execution

    other_draft, other_ticket = _issued(harness)
    harness.clock.value = other_ticket.receipt.expires_at + timedelta(seconds=1)
    with pytest.raises(ApprovalExpired):
        harness.guard.apply_in_transaction(
            other_ticket,
            other_draft,
            lambda _connection: None,
        )


@pytest.mark.parametrize(
    "fault_point",
    ("after_approval_claim", "before_target_commit"),
)
def test_process_fault_before_target_commit_rolls_back_claim_and_business(
    harness: ApprovalHarness,
    fault_point: str,
) -> None:
    draft, ticket = _issued(harness)

    def fail_at(point: str) -> None:
        if point == fault_point:
            raise RuntimeError(point)

    guard = ApprovalExecutionGuard(
        harness.target_connection,
        approval_service=harness.service,
        execution_proof_signer=LocalHmacTargetExecutionAttestor(
            secret=b"t" * 32,
            attestor_id="test-target-writer",
        ),
        clock=harness.clock,
        fault_hook=fail_at,
    )
    with pytest.raises(RuntimeError, match=fault_point):
        guard.apply_in_transaction(
            ticket,
            draft,
            lambda connection: connection.execute(
                "INSERT INTO synthetic_business(id, value) VALUES (1, 'rollback')"
            ),
        )

    assert harness.target_connection.execute(
        "SELECT count(*) FROM approval_executions"
    ).fetchone() == (0,)
    assert harness.target_connection.execute(
        "SELECT count(*) FROM synthetic_business"
    ).fetchone() == (0,)


def test_process_fault_after_target_commit_recovers_proof_without_replay(
    harness: ApprovalHarness,
) -> None:
    draft, ticket = _issued(harness)

    def fail_after_commit(point: str) -> None:
        if point == "after_target_commit_before_ack":
            raise RuntimeError(point)

    faulting = ApprovalExecutionGuard(
        harness.target_connection,
        approval_service=harness.service,
        execution_proof_signer=LocalHmacTargetExecutionAttestor(
            secret=b"t" * 32,
            attestor_id="test-target-writer",
        ),
        clock=harness.clock,
        fault_hook=fail_after_commit,
    )
    with pytest.raises(RuntimeError, match="after_target_commit_before_ack"):
        faulting.apply_in_transaction(
            ticket,
            draft,
            lambda connection: connection.execute(
                "INSERT INTO synthetic_business(id, value) VALUES (1, 'committed')"
            ),
        )

    assert harness.target_connection.execute(
        "SELECT state FROM approval_executions WHERE operation_id = ?",
        (ticket.operation_id,),
    ).fetchone() == ("APPLIED",)
    assert harness.target_connection.execute(
        "SELECT count(*) FROM synthetic_business"
    ).fetchone() == (1,)
    proof = harness.guard.apply_in_transaction(
        ticket,
        draft,
        lambda _connection: pytest.fail("committed callback must not replay"),
    )
    assert harness.service.acknowledge(proof).state == "acknowledged"
