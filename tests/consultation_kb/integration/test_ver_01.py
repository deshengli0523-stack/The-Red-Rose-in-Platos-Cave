from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.lifecycle.publish import (
    ArtifactDraft,
    ContentDraft,
    PublishCoordinator,
    publication_closure_sha256,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import AuthoritativeFilterSnapshot
from consultation_kb.retrieval.evidence_pack import (
    ActiveArtifactVersionGate,
    ArtifactVersionMismatch,
    RootManifestSet,
)
from consultation_kb.storage.manifests import ManifestRepository
from consultation_kb.storage.integrity import (
    ActiveArtifact,
    ActiveIntegrityGate,
    ArtifactUnavailable,
    IntegrityStore,
)
from consultation_kb.storage.tombstones import TombstoneRepository, VisibilityGuard
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.approval_support import ApprovalHarness, build_approval_harness


pytestmark = [pytest.mark.integration, pytest.mark.acceptance_id("VER-01")]

_KEYS = ("graph", "lexical", "vector", "wiki_index")


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[ApprovalHarness]:
    value = build_approval_harness(tmp_path)
    yield value
    value.close()


def _artifact(harness: ApprovalHarness, key: str) -> ArtifactDraft:
    data = f'{{"artifact":"{key}","version":1}}\n'.encode("ascii")
    return ArtifactDraft(
        manifest_id=harness.ids.object_id("manifest"),
        artifact_key=key,
        artifact_kind=key,
        source_version=1,
        members=(
            ContentDraft(
                object_type="artifact",
                object_id=harness.ids.object_id("artifact"),
                data=data,
                source_version=1,
                media_type="application/json",
                source_lineage=(),
            ),
        ),
    )


def _publish_roots(
    harness: ApprovalHarness,
    tmp_path: Path,
) -> tuple[ContentStore, AuthoritativeFilterSnapshot, RootManifestSet]:
    scope_root = tmp_path / "active-artifacts"
    scope_root.mkdir()
    store = ContentStore(scope_root)
    coordinator = PublishCoordinator(
        harness.target_connection,
        store,
        VisibilityGuard(
            TombstoneRepository(
                harness.target_connection,
                clock=FixedClock(harness.clock.now()),
            )
        ),
        clock=FixedClock(harness.clock.now()),
    )
    harness.target_connection.execute(
        "UPDATE client_fact_authority SET commit_version = 1, client_id = ? "
        "WHERE singleton = 1",
        ("client_" + "a" * 12,),
    )
    artifacts = tuple(_artifact(harness, key) for key in _KEYS)
    staged = coordinator.stage_artifacts(purpose="profile_update", artifacts=artifacts)
    descriptor = harness.draft().model_copy(
        update={
            "base_version": 0,
            "draft_sha256": publication_closure_sha256(
                purpose="profile_update",
                authority_base_version=1,
                expected_current_epoch=None,
                artifacts=artifacts,
            ),
        }
    )
    request = harness.service.request(
        descriptor,
        diff_object_ref=harness.diff_object_ref(),
    )
    harness.service.confirm(
        harness.signer.confirm(harness.service.challenge_for_review(request.request_id))
    )
    ticket = harness.service.issue_for_execution(
        request.request_id,
        descriptor,
        operation_id=harness.operation_id(),
    )

    def prepare(_connection: object) -> None:
        coordinator.prepare(
            operation_id=ticket.operation_id,
            purpose="profile_update",
            authority_base_version=1,
            approval_request_id=ticket.request_id,
            descriptor_sha256=ticket.descriptor_sha256,
            expected_current_epoch=None,
            artifacts=staged,
        )

    execution = harness.guard.apply_in_transaction(ticket, descriptor, prepare)
    harness.service.acknowledge(execution)
    coordinator.verify(ticket.operation_id)
    active = coordinator.activate(ticket.operation_id)
    runtime_epoch = active.runtime_epoch
    assert runtime_epoch is not None
    repository = ManifestRepository(harness.target_connection)

    def root(key: str) -> VersionRef:
        manifest = repository.get_active(key, epoch=runtime_epoch)
        return VersionRef(
            object_id=manifest.manifest_id,
            version=manifest.source_version,
            content_sha256=manifest.manifest_sha256,
        )

    roots = RootManifestSet(
        catalog_version=1,
        wiki_manifest_ref=root("wiki_index"),
        lexical_manifest_ref=root("lexical"),
        vector_manifest_ref=root("vector"),
        graph_manifest_ref=root("graph"),
    )
    snapshot = AuthoritativeFilterSnapshot(
        run_id=harness.ids.uuid7(),
        global_runtime_epoch=runtime_epoch,
        client_runtime_epoch=0,
        tombstone_epoch=0,
        authorization_epoch=0,
        allowed_ref_ids=frozenset(),
        policy_ref=VersionRef(
            object_id=harness.ids.object_id("authority_policy"),
            version=1,
            content_sha256=hashlib.sha256(b"authority-policy").hexdigest(),
        ),
        created_at=harness.clock.now(),
    )
    return store, snapshot, roots


def _member_path(
    harness: ApprovalHarness,
    store: ContentStore,
    snapshot: AuthoritativeFilterSnapshot,
    key: str,
) -> Path:
    manifest = ManifestRepository(harness.target_connection).get_active(
        key,
        epoch=snapshot.global_runtime_epoch,
    )
    member = manifest.members[0]
    return store.reference(
        content_sha256=member.object_sha256,
        media_type=member.media_type,
        size_bytes=member.size_bytes,
    ).path


def _verify_p8_active_gate(
    harness: ApprovalHarness,
    store: ContentStore,
    snapshot: AuthoritativeFilterSnapshot,
    roots: RootManifestSet,
) -> None:
    gate = ActiveIntegrityGate(
        IntegrityStore(
            scope="client_private",
            connection=harness.target_connection,
            content_store=store,
            client_id="client_" + "a" * 12,
        )
    )
    gate.verify(
        epoch=snapshot.global_runtime_epoch,
        artifacts=(
            ActiveArtifact(
                artifact_key="graph",
                manifest_ref=roots.graph_manifest_ref,
            ),
            ActiveArtifact(
                artifact_key="lexical",
                manifest_ref=roots.lexical_manifest_ref,
            ),
            ActiveArtifact(
                artifact_key="vector",
                manifest_ref=roots.vector_manifest_ref,
            ),
            ActiveArtifact(
                artifact_key="wiki_index",
                manifest_ref=roots.wiki_manifest_ref,
            ),
        ),
        source_version=roots.catalog_version,
        tombstone_epoch=0,
    )


@pytest.mark.parametrize(
    "corruption",
    ["graph_missing_file", "lexical_bad_bytes", "vector_source_version", "wiki_missing_manifest"],
)
def test_ver_01_rejects_every_required_root_corruption_before_pack(
    harness: ApprovalHarness,
    tmp_path: Path,
    corruption: str,
) -> None:
    store, snapshot, roots = _publish_roots(harness, tmp_path)
    if corruption == "graph_missing_file":
        _member_path(harness, store, snapshot, "graph").unlink()
    elif corruption == "lexical_bad_bytes":
        _member_path(harness, store, snapshot, "lexical").write_bytes(b"tampered\n")
    elif corruption == "vector_source_version":
        roots = RootManifestSet(
            catalog_version=2,
            wiki_manifest_ref=roots.wiki_manifest_ref.model_copy(update={"version": 2}),
            lexical_manifest_ref=roots.lexical_manifest_ref.model_copy(update={"version": 2}),
            vector_manifest_ref=roots.vector_manifest_ref.model_copy(update={"version": 2}),
            graph_manifest_ref=roots.graph_manifest_ref.model_copy(update={"version": 2}),
        )
    else:
        roots = roots.model_copy(
            update={
                "wiki_manifest_ref": roots.wiki_manifest_ref.model_copy(
                    update={"object_id": harness.ids.object_id("manifest")}
                )
            }
        )

    gate = ActiveArtifactVersionGate(harness.target_connection, store)
    with pytest.raises(ArtifactVersionMismatch, match="ARTIFACT_VERSION_MISMATCH"):
        gate.verify(snapshot, roots)
    with pytest.raises(ArtifactUnavailable, match="ARTIFACT_UNAVAILABLE"):
        _verify_p8_active_gate(harness, store, snapshot, roots)


def test_ver_01_accepts_one_complete_exact_active_root_set(
    harness: ApprovalHarness,
    tmp_path: Path,
) -> None:
    store, snapshot, roots = _publish_roots(harness, tmp_path)
    ActiveArtifactVersionGate(harness.target_connection, store).verify(snapshot, roots)
    _verify_p8_active_gate(harness, store, snapshot, roots)
