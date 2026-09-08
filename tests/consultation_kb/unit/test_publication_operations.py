from __future__ import annotations

import sqlite3
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.lifecycle.publish import (
    ArtifactDraft,
    ContentDraft,
    PublicationApprovalRequired,
    PublicationIntegrityError,
    PublicationStageTransactionOpen,
    PublishCoordinator,
    RuntimeEpochRepository,
    publication_closure_sha256,
)
from consultation_kb.storage import MigrationRunner, connect_database
from consultation_kb.storage.connection import transaction
from consultation_kb.storage.manifests import (
    ManifestIntegrityError,
    ManifestNotFound,
    ManifestNotReady,
    ManifestRepository,
)
from consultation_kb.storage.tombstones import (
    ObjectIdentity,
    ObjectTombstoned,
    TombstoneRepository,
    VisibilityGuard,
)
from consultation_kb.vault.content_store import ContentHashMismatch, ContentStore
from tests.consultation_kb.approval_support import build_approval_harness


_DESCRIPTOR_SHA256 = "a" * 64
_APPLIED_AT = "2026-07-16T08:00:00.000000Z"


def _coordinator(
    tmp_path: Path,
    fixed_now,  # type: ignore[no-untyped-def]
    *,
    fault_hook=None,  # type: ignore[no-untyped-def]
):
    connection = connect_database(tmp_path / "client.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "client").apply()
    tombstones = TombstoneRepository(connection, clock=FixedClock(fixed_now))
    coordinator = PublishCoordinator(
        connection,
        ContentStore(tmp_path / "scope"),
        VisibilityGuard(tombstones),
        clock=FixedClock(fixed_now),
        fault_hook=fault_hook,
    )
    return connection, tombstones, coordinator


def _artifact(
    factory: IdFactory,
    *,
    key: str,
    version: int,
    payload: bytes,
    source_lineage: tuple[ObjectIdentity, ...] = (),
) -> tuple[ArtifactDraft, str]:
    object_id = factory.object_id("artifact")
    return (
        ArtifactDraft(
            manifest_id=factory.object_id("manifest"),
            artifact_key=key,
            artifact_kind=key,
            source_version=version,
            members=(
                ContentDraft(
                    object_type="artifact",
                    object_id=object_id,
                    data=payload,
                    source_version=version,
                    media_type="application/json",
                    source_lineage=source_lineage,
                ),
            ),
        ),
        object_id,
    )


def _publish(
    connection,
    coordinator: PublishCoordinator,
    factory: IdFactory,
    artifacts: tuple[ArtifactDraft, ...],
    *,
    expected_epoch: int | None,
):  # type: ignore[no-untyped-def]
    prepared_artifacts = coordinator.stage_artifacts(
        purpose="client_snapshot",
        artifacts=artifacts,
    )
    operation_id = factory.object_id("operation")
    approval_request_id = factory.object_id("approval_request")
    authority_base_version = 1 if expected_epoch is None else expected_epoch + 1
    _claim_execution(
        connection,
        operation_id=operation_id,
        approval_request_id=approval_request_id,
        draft_sha256=publication_closure_sha256(
            purpose="client_snapshot",
            authority_base_version=authority_base_version,
            expected_current_epoch=expected_epoch,
            artifacts=prepared_artifacts,
        ),
        descriptor_base_version=authority_base_version - 1,
    )
    operation = coordinator.prepare(
        operation_id=operation_id,
        purpose="client_snapshot",
        authority_base_version=authority_base_version,
        approval_request_id=approval_request_id,
        descriptor_sha256=_DESCRIPTOR_SHA256,
        expected_current_epoch=expected_epoch,
        artifacts=prepared_artifacts,
    )
    _mark_applied(connection, operation_id=operation_id)
    assert operation.state == "PREPARED"
    assert coordinator.verify(operation.operation_id).state == "VERIFIED"
    return coordinator.activate(operation.operation_id)


def _stage(
    coordinator: PublishCoordinator,
    *artifacts: ArtifactDraft,
    purpose: str = "client_snapshot",
):  # type: ignore[no-untyped-def]
    return coordinator.stage_artifacts(purpose=purpose, artifacts=artifacts)


def _claim_execution(
    connection,
    *,
    operation_id: str,
    approval_request_id: str,
    draft_sha256: str,
    descriptor_sha256: str = _DESCRIPTOR_SHA256,
    descriptor_base_version: int = 0,
) -> None:  # type: ignore[no-untyped-def]
    nonce = hashlib.sha256(approval_request_id.encode("ascii")).hexdigest()
    connection.execute(
        """
        INSERT INTO approval_executions(
            operation_id, request_id, descriptor_sha256, draft_sha256,
            descriptor_base_version, target_scope_hash,
            nonce_sha256, state, applied_commit_version, applied_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'CLAIMED', NULL, NULL)
        """,
        (
            operation_id,
            approval_request_id,
            descriptor_sha256,
            draft_sha256,
            descriptor_base_version,
            "b" * 64,
            nonce,
        ),
    )


def _mark_applied(connection, *, operation_id: str) -> None:  # type: ignore[no-untyped-def]
    changed = connection.execute(
        """
        UPDATE approval_executions
        SET state = 'APPLIED',
            applied_commit_version = descriptor_base_version + 1,
            applied_at = ?
        WHERE operation_id = ? AND state = 'CLAIMED'
        """,
        (_APPLIED_AT, operation_id),
    ).rowcount
    assert changed == 1


def test_named_process_fault_points_wrap_the_real_publication_path(
    tmp_path: Path,
    fixed_now,
) -> None:  # type: ignore[no-untyped-def]
    phases: list[str] = []
    connection, _, coordinator = _coordinator(
        tmp_path,
        fixed_now,
        fault_hook=phases.append,
    )
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile, _ = _artifact(factory, key="profile", version=1, payload=b"profile")

    assert _publish(
        connection,
        coordinator,
        factory,
        (profile,),
        expected_epoch=None,
    ).state == "ACTIVE"
    assert phases == [
        "after_stage_write",
        "after_file_fsync",
        "before_prepared_tx",
        "after_prepared_tx",
        "after_verify",
        "before_active_tx",
        "after_active_tx",
        "before_cleanup",
    ]


def test_prepare_without_matching_claim_writes_no_publication_rows(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection, _, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile, _ = _artifact(factory, key="profile", version=1, payload=b"profile")

    with pytest.raises(
        PublicationApprovalRequired,
        match="^PUBLICATION_APPROVAL_REQUIRED$",
    ):
        coordinator.prepare(
            operation_id=factory.object_id("operation"),
            purpose="client_snapshot",
            authority_base_version=1,
            approval_request_id=factory.object_id("approval_request"),
            descriptor_sha256=_DESCRIPTOR_SHA256,
            expected_current_epoch=None,
            artifacts=_stage(coordinator, profile),
        )

    assert (
        connection.execute("SELECT count(*) FROM publication_operations").fetchone()[0]
        == 0
    )
    assert (
        connection.execute("SELECT count(*) FROM artifact_manifests").fetchone()[0] == 0
    )
    assert (
        connection.execute("SELECT count(*) FROM artifact_members").fetchone()[0] == 0
    )


def test_prepare_can_bind_an_approved_selection_distinct_from_artifact_closure(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection, _, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile, _ = _artifact(factory, key="profile", version=1, payload=b"profile")
    operation_id = factory.object_id("operation")
    approval_request_id = factory.object_id("approval_request")
    approved_selection_sha256 = "c" * 64
    prepared = _stage(coordinator, profile, purpose="profile_update")
    closure = publication_closure_sha256(
        purpose="profile_update",
        authority_base_version=1,
        expected_current_epoch=None,
        artifacts=prepared,
    )
    assert closure != approved_selection_sha256
    _claim_execution(
        connection,
        operation_id=operation_id,
        approval_request_id=approval_request_id,
        draft_sha256=approved_selection_sha256,
    )

    coordinator.prepare(
        operation_id=operation_id,
        purpose="profile_update",
        authority_base_version=1,
        approval_request_id=approval_request_id,
        descriptor_sha256=_DESCRIPTOR_SHA256,
        approval_draft_sha256=approved_selection_sha256,
        expected_current_epoch=None,
        artifacts=prepared,
    )
    _mark_applied(connection, operation_id=operation_id)

    assert coordinator.verify(operation_id).state == "VERIFIED"
    assert coordinator.activate(operation_id).state == "ACTIVE"


def test_applied_approval_sequence_is_not_the_publication_authority_version(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection, _, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    for sequence in (1, 2):
        prior_operation = factory.object_id("operation")
        _claim_execution(
            connection,
            operation_id=prior_operation,
            approval_request_id=factory.object_id("approval_request"),
            draft_sha256=hashlib.sha256(
                f"prior-{sequence}".encode("ascii")
            ).hexdigest(),
        )
        connection.execute(
            "UPDATE approval_executions SET state = 'APPLIED', "
            "applied_commit_version = ?, applied_at = ? "
            "WHERE operation_id = ? AND state = 'CLAIMED'",
            (sequence, _APPLIED_AT, prior_operation),
        )

    profile, _ = _artifact(
        factory,
        key="profile",
        version=1,
        payload=b"profile",
    )
    prepared = _stage(coordinator, profile)
    operation_id = factory.object_id("operation")
    request_id = factory.object_id("approval_request")
    closure = publication_closure_sha256(
        purpose="client_snapshot",
        authority_base_version=1,
        expected_current_epoch=None,
        artifacts=prepared,
    )
    _claim_execution(
        connection,
        operation_id=operation_id,
        approval_request_id=request_id,
        draft_sha256=closure,
        descriptor_base_version=0,
    )
    coordinator.prepare(
        operation_id=operation_id,
        purpose="client_snapshot",
        authority_base_version=1,
        approval_request_id=request_id,
        descriptor_sha256=_DESCRIPTOR_SHA256,
        expected_current_epoch=None,
        artifacts=prepared,
    )
    connection.execute(
        "UPDATE approval_executions SET state = 'APPLIED', "
        "applied_commit_version = 3, applied_at = ? "
        "WHERE operation_id = ? AND state = 'CLAIMED'",
        (_APPLIED_AT, operation_id),
    )

    assert coordinator.verify(operation_id).state == "VERIFIED"
    assert coordinator.activate(operation_id).state == "ACTIVE"


@pytest.mark.parametrize("corruption", ["missing", "closure"])
def test_verify_fails_closed_when_publication_closure_attestation_is_corrupt(
    tmp_path: Path,
    fixed_now,
    corruption: str,
) -> None:
    connection, _, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile, _ = _artifact(factory, key="profile", version=1, payload=b"profile")
    operation_id = factory.object_id("operation")
    approval_request_id = factory.object_id("approval_request")
    prepared = _stage(coordinator, profile)
    closure = publication_closure_sha256(
        purpose="client_snapshot",
        authority_base_version=1,
        expected_current_epoch=None,
        artifacts=prepared,
    )
    _claim_execution(
        connection,
        operation_id=operation_id,
        approval_request_id=approval_request_id,
        draft_sha256=closure,
    )
    coordinator.prepare(
        operation_id=operation_id,
        purpose="client_snapshot",
        authority_base_version=1,
        approval_request_id=approval_request_id,
        descriptor_sha256=_DESCRIPTOR_SHA256,
        expected_current_epoch=None,
        artifacts=prepared,
    )

    if corruption == "missing":
        connection.execute("DROP TRIGGER publication_closure_attestations_no_delete")
        connection.execute(
            "DELETE FROM publication_closure_attestations WHERE operation_id = ?",
            (operation_id,),
        )
    else:
        connection.execute("DROP TRIGGER publication_closure_attestations_no_update")
        connection.execute(
            "UPDATE publication_closure_attestations SET closure_sha256 = ? "
            "WHERE operation_id = ?",
            ("f" * 64, operation_id),
        )

    with pytest.raises(PublicationIntegrityError):
        coordinator.verify(operation_id)


def test_activation_fails_closed_when_approved_draft_attestation_is_corrupt(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection, _, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile, _ = _artifact(factory, key="profile", version=1, payload=b"profile")
    operation_id = factory.object_id("operation")
    approval_request_id = factory.object_id("approval_request")
    prepared = _stage(coordinator, profile)
    closure = publication_closure_sha256(
        purpose="client_snapshot",
        authority_base_version=1,
        expected_current_epoch=None,
        artifacts=prepared,
    )
    _claim_execution(
        connection,
        operation_id=operation_id,
        approval_request_id=approval_request_id,
        draft_sha256=closure,
    )
    coordinator.prepare(
        operation_id=operation_id,
        purpose="client_snapshot",
        authority_base_version=1,
        approval_request_id=approval_request_id,
        descriptor_sha256=_DESCRIPTOR_SHA256,
        expected_current_epoch=None,
        artifacts=prepared,
    )
    _mark_applied(connection, operation_id=operation_id)
    assert coordinator.verify(operation_id).state == "VERIFIED"
    connection.execute("DROP TRIGGER publication_closure_attestations_no_update")
    connection.execute(
        "UPDATE publication_closure_attestations SET approval_draft_sha256 = ? "
        "WHERE operation_id = ?",
        ("f" * 64, operation_id),
    )

    with pytest.raises(PublicationApprovalRequired):
        coordinator.activate(operation_id)


def test_prepare_composes_with_the_approval_transaction(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection, _, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile, _ = _artifact(factory, key="profile", version=1, payload=b"profile")
    operation_id = factory.object_id("operation")
    approval_request_id = factory.object_id("approval_request")
    prepared_artifacts = _stage(coordinator, profile)

    with transaction(connection):
        _claim_execution(
            connection,
            operation_id=operation_id,
            approval_request_id=approval_request_id,
            draft_sha256=publication_closure_sha256(
                purpose="client_snapshot",
                authority_base_version=1,
                expected_current_epoch=None,
                artifacts=prepared_artifacts,
            ),
        )
        prepared = coordinator.prepare(
            operation_id=operation_id,
            purpose="client_snapshot",
            authority_base_version=1,
            approval_request_id=approval_request_id,
            descriptor_sha256=_DESCRIPTOR_SHA256,
            expected_current_epoch=None,
            artifacts=prepared_artifacts,
        )
        assert connection.in_transaction
        _mark_applied(connection, operation_id=operation_id)

    assert prepared.descriptor_sha256 == _DESCRIPTOR_SHA256
    assert coordinator.verify(operation_id).state == "VERIFIED"
    assert coordinator.activate(operation_id).state == "ACTIVE"


def test_cas_staging_is_rejected_inside_a_database_transaction(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection, _, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile, _ = _artifact(factory, key="profile", version=1, payload=b"profile")

    with transaction(connection):
        with pytest.raises(
            PublicationStageTransactionOpen,
            match="^PUBLICATION_STAGE_TRANSACTION_OPEN$",
        ):
            coordinator.stage_artifacts(
                purpose="client_snapshot",
                artifacts=(profile,),
            )


def test_raw_and_prepared_publication_closures_have_the_same_hash(
    tmp_path: Path,
    fixed_now,
) -> None:
    _, _, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile, _ = _artifact(factory, key="profile", version=1, payload=b"profile")

    raw_hash = publication_closure_sha256(
        purpose="client_snapshot",
        authority_base_version=1,
        expected_current_epoch=None,
        artifacts=(profile,),
    )
    prepared = _stage(coordinator, profile)

    assert (
        publication_closure_sha256(
            purpose="client_snapshot",
            authority_base_version=1,
            expected_current_epoch=None,
            artifacts=prepared,
        )
        == raw_hash
    )
    assert (
        publication_closure_sha256(
            purpose="client_snapshot",
            authority_base_version=1,
            expected_current_epoch=1,
            artifacts=(profile,),
        )
        != raw_hash
    )
    with pytest.raises(PublicationIntegrityError):
        publication_closure_sha256(
            purpose="client_snapshot",
            authority_base_version=2,
            expected_current_epoch=None,
            artifacts=(profile,),
        )


def test_approved_closure_a_cannot_publish_staged_closure_b(tmp_path: Path) -> None:
    harness = build_approval_harness(tmp_path)
    try:
        approved, _ = _artifact(
            harness.ids,
            key="profile",
            version=1,
            payload=b"approved-a",
        )
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
            harness.signer.confirm(
                harness.service.challenge_for_review(request.request_id)
            )
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
    finally:
        harness.close()


def test_real_approval_guard_composes_with_prepare_and_activation(
    tmp_path: Path,
) -> None:
    harness = build_approval_harness(tmp_path)
    try:
        profile, _ = _artifact(
            harness.ids,
            key="profile",
            version=1,
            payload=b"approved-profile",
        )
        draft = harness.draft().model_copy(
            update={
                "base_version": 0,
                "draft_sha256": publication_closure_sha256(
                    purpose="profile_update",
                    authority_base_version=1,
                    expected_current_epoch=None,
                    artifacts=(profile,),
                ),
            }
        )
        request = harness.service.request(
            draft,
            diff_object_ref=harness.diff_object_ref(),
        )
        harness.service.confirm(
            harness.signer.confirm(
                harness.service.challenge_for_review(request.request_id)
            )
        )
        operation_id = harness.operation_id()
        ticket = harness.service.issue_for_execution(
            request.request_id,
            draft,
            operation_id=operation_id,
        )
        tombstones = TombstoneRepository(harness.target_connection, clock=harness.clock)
        coordinator = PublishCoordinator(
            harness.target_connection,
            ContentStore(tmp_path / "scope"),
            VisibilityGuard(tombstones),
            clock=harness.clock,
        )
        assert not harness.target_connection.in_transaction
        prepared_artifacts = _stage(
            coordinator,
            profile,
            purpose="profile_update",
        )
        assert not harness.target_connection.in_transaction

        execution = harness.guard.apply_in_transaction(
            ticket,
            draft,
            lambda _connection: coordinator.prepare(
                operation_id=operation_id,
                purpose="profile_update",
                authority_base_version=1,
                approval_request_id=ticket.request_id,
                descriptor_sha256=ticket.descriptor_sha256,
                expected_current_epoch=None,
                artifacts=prepared_artifacts,
            ),
        )

        assert execution.state == "applied"
        assert coordinator.verify(operation_id).state == "VERIFIED"
        assert coordinator.activate(operation_id).state == "ACTIVE"
    finally:
        harness.close()


def test_mismatched_descriptor_rejects_and_rolls_back_the_claim(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection, _, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile, _ = _artifact(factory, key="profile", version=1, payload=b"profile")
    operation_id = factory.object_id("operation")
    approval_request_id = factory.object_id("approval_request")
    prepared_artifacts = _stage(coordinator, profile)

    with pytest.raises(PublicationApprovalRequired):
        with transaction(connection):
            _claim_execution(
                connection,
                operation_id=operation_id,
                approval_request_id=approval_request_id,
                draft_sha256=publication_closure_sha256(
                    purpose="client_snapshot",
                    authority_base_version=1,
                    expected_current_epoch=None,
                    artifacts=prepared_artifacts,
                ),
            )
            coordinator.prepare(
                operation_id=operation_id,
                purpose="client_snapshot",
                authority_base_version=1,
                approval_request_id=approval_request_id,
                descriptor_sha256="c" * 64,
                expected_current_epoch=None,
                artifacts=prepared_artifacts,
            )

    assert (
        connection.execute("SELECT count(*) FROM approval_executions").fetchone()[0]
        == 0
    )
    assert (
        connection.execute("SELECT count(*) FROM publication_operations").fetchone()[0]
        == 0
    )


def test_incomplete_closure_cannot_switch_runtime_epoch(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection, _, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile, _ = _artifact(factory, key="profile", version=1, payload=b'{"p":1}\n')
    graph, _ = _artifact(factory, key="graph", version=1, payload=b'{"g":1}\n')
    operation_id = factory.object_id("operation")
    approval_request_id = factory.object_id("approval_request")
    _claim_execution(
        connection,
        operation_id=operation_id,
        approval_request_id=approval_request_id,
        draft_sha256=publication_closure_sha256(
            purpose="client_snapshot",
            authority_base_version=1,
            expected_current_epoch=None,
            artifacts=(profile, graph),
        ),
    )
    operation = coordinator.prepare(
        operation_id=operation_id,
        purpose="client_snapshot",
        authority_base_version=1,
        approval_request_id=approval_request_id,
        descriptor_sha256=_DESCRIPTOR_SHA256,
        expected_current_epoch=None,
        artifacts=_stage(coordinator, profile, graph),
    )
    _mark_applied(connection, operation_id=operation_id)
    graph_manifest = ManifestRepository(connection).get(graph.manifest_id)
    graph_member = graph_manifest.members[0]
    broken = ContentStore(tmp_path / "scope").reference(
        content_sha256=graph_member.object_sha256,
        media_type=graph_member.media_type,
        size_bytes=graph_member.size_bytes,
    )
    broken.path.unlink()

    with pytest.raises(ContentHashMismatch):
        coordinator.verify(operation.operation_id)
    with pytest.raises(ManifestNotReady):
        coordinator.activate(operation.operation_id)
    assert RuntimeEpochRepository(connection).current() is None
    assert (
        connection.execute("SELECT count(*) FROM active_artifacts").fetchone()[0] == 0
    )
    assert (
        connection.execute(
            "SELECT count(*) FROM artifact_manifests WHERE verified = 1"
        ).fetchone()[0]
        == 0
    )


def test_activation_switches_complete_epoch_and_preserves_old_snapshot(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection, _, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile_v1, _ = _artifact(factory, key="profile", version=1, payload=b'{"p":1}\n')
    graph_v1, _ = _artifact(factory, key="graph", version=1, payload=b'{"g":1}\n')
    first = _publish(
        connection,
        coordinator,
        factory,
        (profile_v1, graph_v1),
        expected_epoch=None,
    )
    assert first.runtime_epoch == 1

    profile_v2, _ = _artifact(factory, key="profile", version=2, payload=b'{"p":2}\n')
    graph_v2, _ = _artifact(factory, key="graph", version=2, payload=b'{"g":2}\n')
    second = _publish(
        connection,
        coordinator,
        factory,
        (profile_v2, graph_v2),
        expected_epoch=1,
    )
    assert second.runtime_epoch == 2

    repository = ManifestRepository(connection)
    assert repository.get_active("profile", epoch=1).source_version == 1
    assert repository.get_active("graph", epoch=1).source_version == 1
    assert repository.get_active("profile", epoch=2).source_version == 2
    assert repository.get_active("graph", epoch=2).source_version == 2
    states = connection.execute(
        "SELECT epoch, state FROM runtime_epochs ORDER BY epoch"
    ).fetchall()
    assert states == [(1, "RETIRED"), (2, "ACTIVE")]


def test_tampering_after_verify_still_blocks_activation(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection, _, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile, _ = _artifact(factory, key="profile", version=1, payload=b'{"p":1}\n')
    operation_id = factory.object_id("operation")
    approval_request_id = factory.object_id("approval_request")
    _claim_execution(
        connection,
        operation_id=operation_id,
        approval_request_id=approval_request_id,
        draft_sha256=publication_closure_sha256(
            purpose="client_snapshot",
            authority_base_version=1,
            expected_current_epoch=None,
            artifacts=(profile,),
        ),
    )
    operation = coordinator.prepare(
        operation_id=operation_id,
        purpose="client_snapshot",
        authority_base_version=1,
        approval_request_id=approval_request_id,
        descriptor_sha256=_DESCRIPTOR_SHA256,
        expected_current_epoch=None,
        artifacts=_stage(coordinator, profile),
    )
    _mark_applied(connection, operation_id=operation_id)
    coordinator.verify(operation.operation_id)
    member = ManifestRepository(connection).get(profile.manifest_id).members[0]
    reference = ContentStore(tmp_path / "scope").reference(
        content_sha256=member.object_sha256,
        media_type=member.media_type,
        size_bytes=member.size_bytes,
    )
    reference.path.write_bytes(b'{"p":0}\n')

    with pytest.raises(ContentHashMismatch):
        coordinator.activate(operation.operation_id)
    assert RuntimeEpochRepository(connection).current() is None


def test_tombstoned_lineage_after_verify_blocks_epoch_switch(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection, tombstones, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    first, _ = _artifact(factory, key="profile", version=1, payload=b'{"p":1}\n')
    epoch_one = _publish(
        connection,
        coordinator,
        factory,
        (first,),
        expected_epoch=None,
    )
    assert epoch_one.runtime_epoch == 1

    source = ObjectIdentity("source", factory.object_id("source"))
    second, _ = _artifact(
        factory,
        key="profile",
        version=2,
        payload=b'{"p":2}\n',
        source_lineage=(source,),
    )
    staged = _stage(coordinator, second)
    operation_id = factory.object_id("operation")
    approval_request_id = factory.object_id("approval_request")
    closure = publication_closure_sha256(
        purpose="client_snapshot",
        authority_base_version=2,
        expected_current_epoch=1,
        artifacts=staged,
    )
    _claim_execution(
        connection,
        operation_id=operation_id,
        approval_request_id=approval_request_id,
        draft_sha256=closure,
        descriptor_base_version=1,
    )
    coordinator.prepare(
        operation_id=operation_id,
        purpose="client_snapshot",
        authority_base_version=2,
        approval_request_id=approval_request_id,
        descriptor_sha256=_DESCRIPTOR_SHA256,
        expected_current_epoch=1,
        artifacts=staged,
    )
    _mark_applied(connection, operation_id=operation_id)
    assert coordinator.verify(operation_id).state == "VERIFIED"

    tombstones.add(source, reason_code="consent_revoked")
    with pytest.raises(ObjectTombstoned):
        coordinator.activate(operation_id)

    current = RuntimeEpochRepository(connection).current()
    assert current is not None and current.epoch == 1
    assert connection.execute(
        "SELECT state FROM publication_operations WHERE operation_id = ?",
        (operation_id,),
    ).fetchone() == ("VERIFIED",)
    assert connection.execute(
        "SELECT count(*) FROM active_artifacts WHERE epoch = 2"
    ).fetchone() == (0,)


def test_tombstone_wins_over_an_active_manifest(tmp_path: Path, fixed_now) -> None:
    connection, tombstones, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile, object_id = _artifact(
        factory,
        key="profile",
        version=1,
        payload=b'{"private":true}\n',
    )
    operation = _publish(
        connection, coordinator, factory, (profile,), expected_epoch=None
    )
    target = ObjectIdentity("artifact", object_id)
    assert (
        coordinator.read_active_member(
            target=target,
            artifact_key="profile",
            epoch=operation.runtime_epoch,
        )
        == b'{"private":true}\n'
    )

    tombstones.add(target, reason_code="deletion_requested")
    with pytest.raises(ObjectTombstoned):
        coordinator.read_active_member(
            target=target,
            artifact_key="profile",
            epoch=operation.runtime_epoch,
        )


def test_forged_object_type_cannot_bypass_a_direct_tombstone(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection, tombstones, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile, object_id = _artifact(
        factory,
        key="profile",
        version=1,
        payload=b"private",
    )
    active = _publish(
        connection,
        coordinator,
        factory,
        (profile,),
        expected_epoch=None,
    )
    tombstones.add(
        ObjectIdentity("artifact", object_id),
        reason_code="deletion_requested",
    )

    with pytest.raises(ManifestNotFound):
        coordinator.read_active_member(
            target=ObjectIdentity("case", object_id),
            artifact_key="profile",
            epoch=active.runtime_epoch,
        )


def test_active_read_fails_closed_for_hash_or_source_version_corruption(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection, _, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile, object_id = _artifact(
        factory,
        key="profile",
        version=1,
        payload=b'{"private":true}\n',
    )
    operation = _publish(
        connection, coordinator, factory, (profile,), expected_epoch=None
    )
    target = ObjectIdentity("artifact", object_id)
    manifest = ManifestRepository(connection).get(profile.manifest_id)
    member = manifest.members[0]
    reference = ContentStore(tmp_path / "scope").reference(
        content_sha256=member.object_sha256,
        media_type=member.media_type,
        size_bytes=member.size_bytes,
    )
    reference.path.write_bytes(b'{"private":false}\n')
    with pytest.raises(ContentHashMismatch):
        coordinator.read_active_member(
            target=target,
            artifact_key="profile",
            epoch=operation.runtime_epoch,
        )

    reference.path.write_bytes(b'{"private":true}\n')
    connection.execute(
        "UPDATE artifact_members SET source_version = '2' WHERE manifest_id = ?",
        (profile.manifest_id,),
    )
    with pytest.raises(ManifestIntegrityError):
        coordinator.read_active_member(
            target=target,
            artifact_key="profile",
            epoch=operation.runtime_epoch,
        )


def test_recover_is_idempotent_and_finishes_verified_operation(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection, _, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile, _ = _artifact(factory, key="profile", version=1, payload=b'{"p":1}\n')
    operation_id = factory.object_id("operation")
    approval_request_id = factory.object_id("approval_request")
    _claim_execution(
        connection,
        operation_id=operation_id,
        approval_request_id=approval_request_id,
        draft_sha256=publication_closure_sha256(
            purpose="client_snapshot",
            authority_base_version=1,
            expected_current_epoch=None,
            artifacts=(profile,),
        ),
    )
    prepared = coordinator.prepare(
        operation_id=operation_id,
        purpose="client_snapshot",
        authority_base_version=1,
        approval_request_id=approval_request_id,
        descriptor_sha256=_DESCRIPTOR_SHA256,
        expected_current_epoch=None,
        artifacts=_stage(coordinator, profile),
    )
    _mark_applied(connection, operation_id=operation_id)

    recovered = coordinator.recover(prepared.operation_id)
    assert recovered.state == "ACTIVE"
    assert coordinator.recover(prepared.operation_id) == recovered


def test_activation_requires_the_same_execution_to_be_applied(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection, _, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile, _ = _artifact(factory, key="profile", version=1, payload=b"profile")
    operation_id = factory.object_id("operation")
    approval_request_id = factory.object_id("approval_request")
    _claim_execution(
        connection,
        operation_id=operation_id,
        approval_request_id=approval_request_id,
        draft_sha256=publication_closure_sha256(
            purpose="client_snapshot",
            authority_base_version=1,
            expected_current_epoch=None,
            artifacts=(profile,),
        ),
    )
    coordinator.prepare(
        operation_id=operation_id,
        purpose="client_snapshot",
        authority_base_version=1,
        approval_request_id=approval_request_id,
        descriptor_sha256=_DESCRIPTOR_SHA256,
        expected_current_epoch=None,
        artifacts=_stage(coordinator, profile),
    )
    coordinator.verify(operation_id)

    with pytest.raises(PublicationApprovalRequired):
        coordinator.activate(operation_id)
    assert RuntimeEpochRepository(connection).current() is None

    _mark_applied(connection, operation_id=operation_id)
    assert coordinator.activate(operation_id).state == "ACTIVE"


def test_activation_execution_cannot_be_deleted_inside_epoch_transaction(
    tmp_path: Path,
    fixed_now,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection, _, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    profile, _ = _artifact(factory, key="profile", version=1, payload=b"profile")
    operation_id = factory.object_id("operation")
    approval_request_id = factory.object_id("approval_request")
    _claim_execution(
        connection,
        operation_id=operation_id,
        approval_request_id=approval_request_id,
        draft_sha256=publication_closure_sha256(
            purpose="client_snapshot",
            authority_base_version=1,
            expected_current_epoch=None,
            artifacts=(profile,),
        ),
    )
    coordinator.prepare(
        operation_id=operation_id,
        purpose="client_snapshot",
        authority_base_version=1,
        approval_request_id=approval_request_id,
        descriptor_sha256=_DESCRIPTOR_SHA256,
        expected_current_epoch=None,
        artifacts=_stage(coordinator, profile),
    )
    _mark_applied(connection, operation_id=operation_id)
    coordinator.verify(operation_id)
    original_verify = coordinator._verify_content_closure

    def delete_execution_after_file_verification(operation):  # type: ignore[no-untyped-def]
        manifests = original_verify(operation)
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            connection.execute(
                "DELETE FROM approval_executions WHERE operation_id = ?",
                (operation_id,),
            )
        return manifests

    monkeypatch.setattr(
        coordinator,
        "_verify_content_closure",
        delete_execution_after_file_verification,
    )

    coordinator.activate(operation_id)
    assert connection.execute("SELECT count(*) FROM approval_executions").fetchone() == (1,)
    assert connection.execute("SELECT count(*) FROM runtime_epochs").fetchone()[0] == 1
    assert connection.execute("SELECT count(*) FROM active_artifacts").fetchone()[0] == 1


def test_active_read_uses_hash_bound_manifest_lineage_without_caller_input(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection, tombstones, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    source = ObjectIdentity("case", "source-case-secret")
    profile, object_id = _artifact(
        factory,
        key="profile",
        version=1,
        payload=b"derived-profile",
        source_lineage=(source,),
    )
    active = _publish(
        connection,
        coordinator,
        factory,
        (profile,),
        expected_epoch=None,
    )
    target = ObjectIdentity("artifact", object_id)
    tombstones.add(source, reason_code="consent_revoked")

    with pytest.raises(ObjectTombstoned):
        coordinator.read_active_member(
            target=target,
            artifact_key="profile",
            epoch=active.runtime_epoch,
        )


def test_lineage_omission_tampering_invalidates_the_manifest_hash(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection, _, coordinator = _coordinator(tmp_path, fixed_now)
    factory = IdFactory(clock=FixedClock(fixed_now))
    source = ObjectIdentity("case", "source-case-secret")
    profile, object_id = _artifact(
        factory,
        key="profile",
        version=1,
        payload=b"derived-profile",
        source_lineage=(source,),
    )
    active = _publish(
        connection,
        coordinator,
        factory,
        (profile,),
        expected_epoch=None,
    )
    connection.execute(
        "UPDATE artifact_members SET source_lineage_json = '[]' WHERE manifest_id = ?",
        (profile.manifest_id,),
    )

    with pytest.raises(ManifestIntegrityError):
        coordinator.read_active_member(
            target=ObjectIdentity("artifact", object_id),
            artifact_key="profile",
            epoch=active.runtime_epoch,
        )
