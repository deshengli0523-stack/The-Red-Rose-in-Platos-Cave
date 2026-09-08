from __future__ import annotations

from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.lifecycle.publish import (
    ArtifactDraft,
    ContentDraft,
    PublishCoordinator,
    RuntimeEpochRepository,
    publication_closure_sha256,
)
from consultation_kb.storage.manifests import (
    ManifestIntegrityError,
    ManifestNotReady,
    ManifestRepository,
)
from consultation_kb.storage.tombstones import (
    ObjectIdentity,
    TombstoneRepository,
    VisibilityGuard,
)
from consultation_kb.vault.content_store import ContentHashMismatch, ContentStore
from tests.consultation_kb.approval_support import (
    ApprovalHarness,
    build_approval_harness,
)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.acceptance_id("TX-01"),
    pytest.mark.acceptance_id("VER-01"),
]


@pytest.fixture
def harness(tmp_path: Path) -> ApprovalHarness:
    value = build_approval_harness(tmp_path)
    yield value
    value.close()


def _artifact(
    harness: ApprovalHarness,
    *,
    key: str,
    version: int,
    payload: bytes,
) -> tuple[ArtifactDraft, str]:
    object_id = harness.ids.object_id("artifact")
    return (
        ArtifactDraft(
            manifest_id=harness.ids.object_id("manifest"),
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
                    source_lineage=(),
                ),
            ),
        ),
        object_id,
    )


def _approved_prepare(
    harness: ApprovalHarness,
    coordinator: PublishCoordinator,
    artifacts: tuple[ArtifactDraft, ...],
    *,
    authority_base_version: int,
    expected_epoch: int | None,
):  # type: ignore[no-untyped-def]
    prepared_artifacts = coordinator.stage_artifacts(
        purpose="profile_update",
        artifacts=artifacts,
    )
    draft = harness.draft().model_copy(
        update={
            "base_version": authority_base_version - 1,
            "draft_sha256": publication_closure_sha256(
                purpose="profile_update",
                authority_base_version=authority_base_version,
                expected_current_epoch=expected_epoch,
                artifacts=artifacts,
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
    prepared_operation = None

    def prepare_in_claim(_connection) -> None:  # type: ignore[no-untyped-def]
        nonlocal prepared_operation
        prepared_operation = coordinator.prepare(
            operation_id=ticket.operation_id,
            purpose="profile_update",
            authority_base_version=authority_base_version,
            approval_request_id=ticket.request_id,
            descriptor_sha256=ticket.descriptor_sha256,
            expected_current_epoch=expected_epoch,
            artifacts=prepared_artifacts,
        )

    execution = harness.guard.apply_in_transaction(
        ticket,
        draft,
        prepare_in_claim,
    )
    harness.service.acknowledge(execution)
    assert prepared_operation is not None
    return prepared_operation


def test_complete_and_incomplete_prepared_closures_never_replace_old_active(
    harness: ApprovalHarness,
    tmp_path: Path,
    fixed_now,
) -> None:
    scope = tmp_path / "scope"
    scope.mkdir()
    store = ContentStore(scope)
    tombstones = TombstoneRepository(
        harness.target_connection,
        clock=FixedClock(fixed_now),
    )
    coordinator = PublishCoordinator(
        harness.target_connection,
        store,
        VisibilityGuard(tombstones),
        clock=FixedClock(fixed_now),
    )

    profile_v1, profile_v1_id = _artifact(
        harness,
        key="profile",
        version=1,
        payload=b'{"profile":1}\n',
    )
    graph_v1, graph_v1_id = _artifact(
        harness,
        key="graph",
        version=1,
        payload=b'{"graph":1}\n',
    )
    first = _approved_prepare(
        harness,
        coordinator,
        (profile_v1, graph_v1),
        authority_base_version=1,
        expected_epoch=None,
    )
    coordinator.verify(first.operation_id)
    active = coordinator.activate(first.operation_id)
    assert active.runtime_epoch == 1

    profile_v2, _profile_v2_id = _artifact(
        harness,
        key="profile",
        version=2,
        payload=b'{"profile":2}\n',
    )
    graph_v2, _graph_v2_id = _artifact(
        harness,
        key="graph",
        version=2,
        payload=b'{"graph":2}\n',
    )
    complete_prepared = _approved_prepare(
        harness,
        coordinator,
        (profile_v2, graph_v2),
        authority_base_version=2,
        expected_epoch=1,
    )

    profile_v3, _profile_v3_id = _artifact(
        harness,
        key="profile",
        version=3,
        payload=b'{"profile":3}\n',
    )
    graph_v3, _graph_v3_id = _artifact(
        harness,
        key="graph",
        version=3,
        payload=b'{"graph":3}\n',
    )
    incomplete_prepared = _approved_prepare(
        harness,
        coordinator,
        (profile_v3, graph_v3),
        authority_base_version=3,
        expected_epoch=1,
    )
    broken_manifest = ManifestRepository(harness.target_connection).get(
        graph_v3.manifest_id
    )
    broken_member = broken_manifest.members[0]
    store.reference(
        content_sha256=broken_member.object_sha256,
        media_type=broken_member.media_type,
        size_bytes=broken_member.size_bytes,
    ).path.unlink()

    with pytest.raises(ManifestNotReady, match="MANIFEST_NOT_READY"):
        coordinator.activate(complete_prepared.operation_id)
    with pytest.raises(ContentHashMismatch, match="CONTENT_HASH_MISMATCH"):
        coordinator.verify(incomplete_prepared.operation_id)

    current = RuntimeEpochRepository(harness.target_connection).current()
    assert current is not None and current.epoch == 1
    manifests = ManifestRepository(harness.target_connection)
    assert manifests.get_active("profile", epoch=1).source_version == 1
    assert manifests.get_active("graph", epoch=1).source_version == 1
    assert (
        coordinator.read_active_member(
            target=ObjectIdentity("artifact", profile_v1_id),
            artifact_key="profile",
            epoch=1,
        )
        == b'{"profile":1}\n'
    )
    assert (
        coordinator.read_active_member(
            target=ObjectIdentity("artifact", graph_v1_id),
            artifact_key="graph",
            epoch=1,
        )
        == b'{"graph":1}\n'
    )
    assert harness.target_connection.execute(
        "SELECT operation_id FROM publication_operations "
        "WHERE state = 'PREPARED' ORDER BY operation_id"
    ).fetchall() == sorted(
        [
            (complete_prepared.operation_id,),
            (incomplete_prepared.operation_id,),
        ]
    )


@pytest.mark.parametrize(
    ("corruption", "expected_error"),
    [
        ("missing", ContentHashMismatch),
        ("bad_hash", ContentHashMismatch),
        ("source_version", ManifestIntegrityError),
    ],
)
def test_active_manifest_corruption_fails_closed_before_bytes_are_returned(
    harness: ApprovalHarness,
    tmp_path: Path,
    fixed_now,
    corruption: str,
    expected_error: type[Exception],
) -> None:
    store = ContentStore(tmp_path / "scope")
    coordinator = PublishCoordinator(
        harness.target_connection,
        store,
        VisibilityGuard(
            TombstoneRepository(
                harness.target_connection,
                clock=FixedClock(fixed_now),
            )
        ),
        clock=FixedClock(fixed_now),
    )
    profile, object_id = _artifact(
        harness,
        key="profile",
        version=1,
        payload=b'{"profile":1}\n',
    )
    operation = _approved_prepare(
        harness,
        coordinator,
        (profile,),
        authority_base_version=1,
        expected_epoch=None,
    )
    coordinator.verify(operation.operation_id)
    active = coordinator.activate(operation.operation_id)
    manifest = ManifestRepository(harness.target_connection).get(profile.manifest_id)
    member = manifest.members[0]
    reference = store.reference(
        content_sha256=member.object_sha256,
        media_type=member.media_type,
        size_bytes=member.size_bytes,
    )
    if corruption == "missing":
        reference.path.unlink()
    elif corruption == "bad_hash":
        reference.path.write_bytes(b'{"profile":0}\n')
    else:
        harness.target_connection.execute(
            "UPDATE artifact_members SET source_version = '2' WHERE manifest_id = ?",
            (profile.manifest_id,),
        )

    with pytest.raises(expected_error):
        coordinator.read_active_member(
            target=ObjectIdentity("artifact", object_id),
            artifact_key="profile",
            epoch=active.runtime_epoch,
        )


def test_runtime_observes_only_the_complete_old_or_complete_new_epoch(
    harness: ApprovalHarness,
    tmp_path: Path,
    fixed_now,
) -> None:
    coordinator = PublishCoordinator(
        harness.target_connection,
        ContentStore(tmp_path / "scope"),
        VisibilityGuard(
            TombstoneRepository(
                harness.target_connection,
                clock=FixedClock(fixed_now),
            )
        ),
        clock=FixedClock(fixed_now),
    )
    profile_v1, profile_v1_id = _artifact(
        harness,
        key="profile",
        version=1,
        payload=b'{"profile":1}\n',
    )
    graph_v1, graph_v1_id = _artifact(
        harness,
        key="graph",
        version=1,
        payload=b'{"graph":1}\n',
    )
    first = _approved_prepare(
        harness,
        coordinator,
        (profile_v1, graph_v1),
        authority_base_version=1,
        expected_epoch=None,
    )
    coordinator.verify(first.operation_id)
    epoch_one = coordinator.activate(first.operation_id)
    assert epoch_one.runtime_epoch == 1

    profile_v2, profile_v2_id = _artifact(
        harness,
        key="profile",
        version=2,
        payload=b'{"profile":2}\n',
    )
    graph_v2, graph_v2_id = _artifact(
        harness,
        key="graph",
        version=2,
        payload=b'{"graph":2}\n',
    )
    second = _approved_prepare(
        harness,
        coordinator,
        (profile_v2, graph_v2),
        authority_base_version=2,
        expected_epoch=1,
    )
    assert RuntimeEpochRepository(harness.target_connection).current().epoch == 1  # type: ignore[union-attr]
    coordinator.verify(second.operation_id)
    assert RuntimeEpochRepository(harness.target_connection).current().epoch == 1  # type: ignore[union-attr]
    epoch_two = coordinator.activate(second.operation_id)
    assert epoch_two.runtime_epoch == 2

    manifests = ManifestRepository(harness.target_connection)
    assert (
        manifests.get_active("profile", epoch=1).source_version,
        manifests.get_active("graph", epoch=1).source_version,
    ) == (1, 1)
    assert (
        manifests.get_active("profile", epoch=2).source_version,
        manifests.get_active("graph", epoch=2).source_version,
    ) == (2, 2)
    assert (
        coordinator.read_active_member(
            target=ObjectIdentity("artifact", profile_v1_id),
            artifact_key="profile",
            epoch=1,
        )
        == b'{"profile":1}\n'
    )
    assert (
        coordinator.read_active_member(
            target=ObjectIdentity("artifact", graph_v1_id),
            artifact_key="graph",
            epoch=1,
        )
        == b'{"graph":1}\n'
    )
    assert (
        coordinator.read_active_member(
            target=ObjectIdentity("artifact", profile_v2_id),
            artifact_key="profile",
            epoch=2,
        )
        == b'{"profile":2}\n'
    )
    assert (
        coordinator.read_active_member(
            target=ObjectIdentity("artifact", graph_v2_id),
            artifact_key="graph",
            epoch=2,
        )
        == b'{"graph":2}\n'
    )
