from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from consultation_kb.approvals.store import (
    ApprovalMismatch,
    ApprovalRequired,
    ApprovalUsed,
)
from consultation_kb.lifecycle.publish import (
    ArtifactDraft,
    ContentDraft,
    PublicationApprovalRequired,
    PublishCoordinator,
    publication_closure_sha256,
)
from consultation_kb.storage.tombstones import TombstoneRepository, VisibilityGuard
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.approval_support import (
    ApprovalHarness,
    build_approval_harness,
)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.acceptance_id("WRITE-01"),
]


@pytest.fixture
def harness(tmp_path: Path) -> ApprovalHarness:
    value = build_approval_harness(tmp_path)
    yield value
    value.close()


def _confirmed_request(harness: ApprovalHarness):  # type: ignore[no-untyped-def]
    draft = harness.draft()
    request = harness.service.request(
        draft,
        diff_object_ref=harness.diff_object_ref(),
    )
    challenge = harness.service.challenge_for_review(request.request_id)
    harness.service.confirm(harness.signer.confirm(challenge))
    return draft, request


def _business_count(harness: ApprovalHarness) -> int:
    return int(
        harness.target_connection.execute(
            "SELECT count(*) FROM synthetic_business"
        ).fetchone()[0]
    )


def _publication_artifact(
    harness: ApprovalHarness,
    payload: bytes,
    *,
    version: int = 1,
) -> ArtifactDraft:
    return ArtifactDraft(
        manifest_id=harness.ids.object_id("manifest"),
        artifact_key="profile",
        artifact_kind="profile",
        source_version=version,
        members=(
            ContentDraft(
                object_type="artifact",
                object_id=harness.ids.object_id("artifact"),
                data=payload,
                source_version=version,
                media_type="application/json",
                source_lineage=(),
            ),
        ),
    )


def test_unapproved_model_path_cannot_obtain_a_write_ticket(
    harness: ApprovalHarness,
) -> None:
    draft = harness.draft()
    request = harness.service.request(
        draft,
        diff_object_ref=harness.diff_object_ref(),
    )

    with pytest.raises(ApprovalRequired):
        harness.service.issue_for_execution(
            request.request_id,
            draft,
            operation_id=harness.operation_id(),
        )

    assert _business_count(harness) == 0
    assert harness.target_connection.execute(
        "SELECT count(*) FROM approval_executions"
    ).fetchone() == (0,)


def test_publish_coordinator_without_target_claim_writes_no_rows(
    harness: ApprovalHarness,
    tmp_path: Path,
) -> None:
    artifact = _publication_artifact(harness, b"unapproved")
    coordinator = PublishCoordinator(
        harness.target_connection,
        ContentStore(tmp_path / "scope"),
        VisibilityGuard(TombstoneRepository(harness.target_connection)),
        clock=harness.clock,
    )
    staged = coordinator.stage_artifacts(
        purpose="profile_update",
        artifacts=(artifact,),
    )

    with pytest.raises(PublicationApprovalRequired):
        coordinator.prepare(
            operation_id=harness.operation_id(),
            purpose="profile_update",
            authority_base_version=1,
            approval_request_id=harness.ids.object_id("approval_request"),
            descriptor_sha256="a" * 64,
            expected_current_epoch=None,
            artifacts=staged,
        )

    assert harness.target_connection.execute(
        "SELECT count(*) FROM publication_operations"
    ).fetchone() == (0,)
    assert harness.target_connection.execute(
        "SELECT count(*) FROM artifact_manifests"
    ).fetchone() == (0,)
    assert harness.target_connection.execute(
        "SELECT count(*) FROM artifact_members"
    ).fetchone() == (0,)


def test_approval_cannot_be_replayed_for_a_different_operation(
    harness: ApprovalHarness,
) -> None:
    draft, request = _confirmed_request(harness)
    first_operation = harness.operation_id()
    ticket = harness.service.issue_for_execution(
        request.request_id,
        draft,
        operation_id=first_operation,
    )
    harness.guard.apply_in_transaction(
        ticket,
        draft,
        lambda connection: connection.execute(
            "INSERT INTO synthetic_business(id, value) VALUES (1, 'approved')"
        ),
    )

    with pytest.raises(ApprovalUsed):
        harness.service.issue_for_execution(
            request.request_id,
            draft,
            operation_id=harness.operation_id(),
        )

    assert _business_count(harness) == 1


def test_approved_draft_cannot_be_changed_before_execution(
    harness: ApprovalHarness,
) -> None:
    draft, request = _confirmed_request(harness)
    changed = draft.model_copy(update={"draft_sha256": "0" * 64})

    with pytest.raises(ApprovalMismatch):
        harness.service.issue_for_execution(
            request.request_id,
            changed,
            operation_id=harness.operation_id(),
        )

    assert _business_count(harness) == 0


def test_matching_local_approval_executes_exactly_once(
    harness: ApprovalHarness,
) -> None:
    draft, request = _confirmed_request(harness)
    ticket = harness.service.issue_for_execution(
        request.request_id,
        draft,
        operation_id=harness.operation_id(),
    )
    callback_count = 0

    def apply_write(connection) -> None:  # type: ignore[no-untyped-def]
        nonlocal callback_count
        callback_count += 1
        connection.execute(
            "INSERT INTO synthetic_business(id, value) VALUES (1, 'approved')"
        )

    first = harness.guard.apply_in_transaction(ticket, draft, apply_write)
    second = harness.guard.apply_in_transaction(
        ticket,
        draft,
        lambda _connection: pytest.fail("approved callback was replayed"),
    )

    assert second == first
    assert callback_count == 1
    assert _business_count(harness) == 1


def test_approved_closure_cannot_be_substituted_after_staging(
    harness: ApprovalHarness,
    tmp_path: Path,
) -> None:
    approved = _publication_artifact(harness, b"approved-a")
    substituted = replace(
        approved,
        members=(
            replace(
                approved.members[0],
                data=b"substituted-b",
            ),
        ),
    )
    draft = harness.draft().model_copy(
        update={
            "base_version": 0,
            "draft_sha256": publication_closure_sha256(
                purpose="profile_update",
                authority_base_version=1,
                expected_current_epoch=None,
                artifacts=(approved,),
            ),
        }
    )
    request = harness.service.request(
        draft,
        diff_object_ref=harness.diff_object_ref(),
    )
    harness.service.confirm(
        harness.signer.confirm(harness.service.challenge_for_review(request.request_id))
    )
    ticket = harness.service.issue_for_execution(
        request.request_id,
        draft,
        operation_id=harness.operation_id(),
    )
    coordinator = PublishCoordinator(
        harness.target_connection,
        ContentStore(tmp_path / "scope"),
        VisibilityGuard(TombstoneRepository(harness.target_connection)),
        clock=harness.clock,
    )
    staged_b = coordinator.stage_artifacts(
        purpose="profile_update",
        artifacts=(substituted,),
    )

    with pytest.raises(PublicationApprovalRequired):
        harness.guard.apply_in_transaction(
            ticket,
            draft,
            lambda _connection: coordinator.prepare(
                operation_id=ticket.operation_id,
                purpose="profile_update",
                authority_base_version=1,
                approval_request_id=ticket.request_id,
                descriptor_sha256=ticket.descriptor_sha256,
                expected_current_epoch=None,
                artifacts=staged_b,
            ),
        )

    assert harness.target_connection.execute(
        "SELECT count(*) FROM approval_executions"
    ).fetchone() == (0,)
    assert harness.target_connection.execute(
        "SELECT count(*) FROM publication_operations"
    ).fetchone() == (0,)


@pytest.mark.parametrize("mutation", ["authority_version", "expected_epoch"])
def test_stale_publication_approval_cannot_rebind_version_or_epoch(
    harness: ApprovalHarness,
    tmp_path: Path,
    mutation: str,
) -> None:
    approved = _publication_artifact(harness, b"stable-payload", version=2)
    draft = harness.draft().model_copy(
        update={
            "base_version": 1,
            "draft_sha256": publication_closure_sha256(
                purpose="profile_update",
                authority_base_version=2,
                expected_current_epoch=1,
                artifacts=(approved,),
            ),
        }
    )
    request = harness.service.request(
        draft,
        diff_object_ref=harness.diff_object_ref(),
    )
    harness.service.confirm(
        harness.signer.confirm(harness.service.challenge_for_review(request.request_id))
    )
    ticket = harness.service.issue_for_execution(
        request.request_id,
        draft,
        operation_id=harness.operation_id(),
    )
    if mutation == "authority_version":
        changed = replace(
            approved,
            source_version=3,
            members=(replace(approved.members[0], source_version=3),),
        )
        authority_base_version = 3
        expected_current_epoch = 1
    else:
        changed = approved
        authority_base_version = 2
        expected_current_epoch = 2
    coordinator = PublishCoordinator(
        harness.target_connection,
        ContentStore(tmp_path / "scope"),
        VisibilityGuard(TombstoneRepository(harness.target_connection)),
        clock=harness.clock,
    )
    staged = coordinator.stage_artifacts(
        purpose="profile_update",
        artifacts=(changed,),
    )

    with pytest.raises(PublicationApprovalRequired):
        harness.guard.apply_in_transaction(
            ticket,
            draft,
            lambda _connection: coordinator.prepare(
                operation_id=ticket.operation_id,
                purpose="profile_update",
                authority_base_version=authority_base_version,
                approval_request_id=ticket.request_id,
                descriptor_sha256=ticket.descriptor_sha256,
                expected_current_epoch=expected_current_epoch,
                artifacts=staged,
            ),
        )

    assert harness.target_connection.execute(
        "SELECT count(*) FROM approval_executions"
    ).fetchone() == (0,)
    assert harness.target_connection.execute(
        "SELECT count(*) FROM publication_operations"
    ).fetchone() == (0,)


@pytest.mark.parametrize("attempted_authority_version", [2, 3])
def test_old_epoch_one_approval_cannot_publish_epoch_three_after_epoch_two_wins(
    harness: ApprovalHarness,
    tmp_path: Path,
    attempted_authority_version: int,
) -> None:
    coordinator = PublishCoordinator(
        harness.target_connection,
        ContentStore(tmp_path / "scope"),
        VisibilityGuard(TombstoneRepository(harness.target_connection)),
        clock=harness.clock,
    )

    def issue(
        artifact: ArtifactDraft,
        *,
        authority_version: int,
        expected_epoch: int | None,
    ):  # type: ignore[no-untyped-def]
        staged = coordinator.stage_artifacts(
            purpose="profile_update",
            artifacts=(artifact,),
        )
        descriptor = harness.draft().model_copy(
            update={
                "base_version": authority_version - 1,
                "draft_sha256": publication_closure_sha256(
                    purpose="profile_update",
                    authority_base_version=authority_version,
                    expected_current_epoch=expected_epoch,
                    artifacts=(artifact,),
                ),
            }
        )
        request = harness.service.request(
            descriptor,
            diff_object_ref=harness.diff_object_ref(),
        )
        harness.service.confirm(
            harness.signer.confirm(
                harness.service.challenge_for_review(request.request_id)
            )
        )
        ticket = harness.service.issue_for_execution(
            request.request_id,
            descriptor,
            operation_id=harness.operation_id(),
        )
        return descriptor, ticket, staged

    def publish(
        descriptor,  # type: ignore[no-untyped-def]
        ticket,  # type: ignore[no-untyped-def]
        staged,  # type: ignore[no-untyped-def]
        *,
        authority_version: int,
        expected_epoch: int | None,
    ) -> int:
        proof = harness.guard.apply_in_transaction(
            ticket,
            descriptor,
            lambda _connection: coordinator.prepare(
                operation_id=ticket.operation_id,
                purpose="profile_update",
                authority_base_version=authority_version,
                approval_request_id=ticket.request_id,
                descriptor_sha256=ticket.descriptor_sha256,
                expected_current_epoch=expected_epoch,
                artifacts=staged,
            ),
        )
        harness.service.acknowledge(proof)
        coordinator.verify(ticket.operation_id)
        active = coordinator.activate(ticket.operation_id)
        assert active.runtime_epoch is not None
        return active.runtime_epoch

    initial = _publication_artifact(harness, b"epoch-one", version=1)
    initial_descriptor, initial_ticket, initial_staged = issue(
        initial,
        authority_version=1,
        expected_epoch=None,
    )
    assert (
        publish(
            initial_descriptor,
            initial_ticket,
            initial_staged,
            authority_version=1,
            expected_epoch=None,
        )
        == 1
    )

    # This approval is valid only while epoch 1 is current. Keep its ticket
    # unused while a separately approved operation wins the epoch-2 race.
    old_artifact = _publication_artifact(harness, b"old-candidate", version=2)
    old_descriptor, old_ticket, old_staged = issue(
        old_artifact,
        authority_version=2,
        expected_epoch=1,
    )

    winner = _publication_artifact(harness, b"epoch-two-winner", version=2)
    winner_descriptor, winner_ticket, winner_staged = issue(
        winner,
        authority_version=2,
        expected_epoch=1,
    )
    assert (
        publish(
            winner_descriptor,
            winner_ticket,
            winner_staged,
            authority_version=2,
            expected_epoch=1,
        )
        == 2
    )

    attempted_artifact = old_artifact
    attempted_staged = old_staged
    if attempted_authority_version != 2:
        attempted_artifact = replace(
            old_artifact,
            source_version=attempted_authority_version,
            members=(
                replace(
                    old_artifact.members[0],
                    source_version=attempted_authority_version,
                ),
            ),
        )
        attempted_staged = coordinator.stage_artifacts(
            purpose="profile_update",
            artifacts=(attempted_artifact,),
        )

    with pytest.raises(PublicationApprovalRequired):
        harness.guard.apply_in_transaction(
            old_ticket,
            old_descriptor,
            lambda _connection: coordinator.prepare(
                operation_id=old_ticket.operation_id,
                purpose="profile_update",
                authority_base_version=attempted_authority_version,
                approval_request_id=old_ticket.request_id,
                descriptor_sha256=old_ticket.descriptor_sha256,
                expected_current_epoch=2,
                artifacts=attempted_staged,
            ),
        )

    assert harness.target_connection.execute(
        "SELECT epoch, state FROM runtime_epochs ORDER BY epoch"
    ).fetchall() == [(1, "RETIRED"), (2, "ACTIVE")]
    assert harness.target_connection.execute(
        "SELECT count(*) FROM runtime_epochs WHERE epoch = 3"
    ).fetchone() == (0,)
    assert harness.target_connection.execute(
        "SELECT count(*) FROM publication_operations"
    ).fetchone() == (2,)
    assert harness.target_connection.execute(
        "SELECT count(*) FROM publication_operations WHERE operation_id = ?",
        (old_ticket.operation_id,),
    ).fetchone() == (0,)
    assert harness.target_connection.execute(
        "SELECT count(*) FROM approval_executions"
    ).fetchone() == (2,)
