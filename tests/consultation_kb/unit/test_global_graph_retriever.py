from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.graph.authority_filter import (
    GraphEdgeAuthorityResolver,
    StaticGraphEdgeAuthorityCatalog,
)
from consultation_kb.lifecycle.publish import (
    PublishCoordinator,
    publication_closure_sha256,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import RetrievalScope
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.retrieval.artifact_contracts import (
    ArtifactBinding,
    derived_artifact_role_layout,
)
from consultation_kb.retrieval.artifact_discovery import (
    ActiveRetrievalArtifactDiscovery,
)
from consultation_kb.retrieval.artifact_publication import (
    ArtifactPublicationIds,
    RetrievalArtifactDraftFactory,
)
from consultation_kb.retrieval.global_graph import (
    GlobalGraphRetriever,
    GlobalGraphRetrieverError,
    GraphCandidateCatalogSnapshot,
    GraphNodeQuery,
    GraphRouteCandidate,
)
from consultation_kb.storage.manifests import ManifestRepository
from consultation_kb.storage.tombstones import (
    TombstoneRepository,
    VisibilityGuard,
)
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.approval_support import build_approval_harness
from tests.consultation_kb.graph_support import (
    CLIENT_A,
    NOW,
    graph_authority_snapshot,
    ref,
)
from tests.consultation_kb.retrieval_support import object_id
from tests.consultation_kb.unit.test_graph_artifact_contracts import (
    _closure,
    _member_closure,
)


@dataclass
class CountingNodeResolver:
    pairs: tuple[GraphNodeQuery, ...]
    calls: int = 0
    body_reads: int = 0

    def resolve(self, query, scope, *, limit):  # type: ignore[no-untyped-def]
        del query, scope
        self.calls += 1
        return self.pairs[:limit]


@dataclass
class CountingCandidateCatalog:
    value: GraphCandidateCatalogSnapshot
    snapshot_reads: int = 0
    body_reads: int = 0

    def snapshot(self, *, graph_root_ref, graph_version, runtime_epoch):  # type: ignore[no-untyped-def]
        self.snapshot_reads += 1
        if (
            self.value.graph_root_ref != graph_root_ref
            or self.value.graph_version != graph_version
            or self.value.runtime_epoch != runtime_epoch
        ):
            raise GlobalGraphRetrieverError("GLOBAL_GRAPH_ROUTE_ROOT_MISMATCH")
        return self.value


def _publish_graph_binding(
    tmp_path: Path,
    *,
    artifact,
    builder_input,
    payloads,
    members,
):  # type: ignore[no-untyped-def]
    staging = tmp_path / "staging"
    staging.mkdir(parents=True)
    paths: dict[str, Path] = {}
    media_types: dict[str, str] = {}
    for role in derived_artifact_role_layout("graph")[1:]:
        path = staging / f"{role}.json"
        path.write_bytes(payloads[role])
        paths[role] = path
        media_types[role] = "application/json"
    member_ids = {member.role: member.object_id for member in members}
    draft = RetrievalArtifactDraftFactory(staging).fixed_layout(
        artifact_kind="graph",
        builder_input=builder_input,
        member_paths=paths,
        member_media_types=media_types,
        ids=ArtifactPublicationIds(
            manifest_id=object_id("manifest", 81_000),
            member_object_ids=member_ids,
        ),
        source_lineage=(),
    )
    approval_root = tmp_path / "approval"
    approval_root.mkdir()
    harness = build_approval_harness(approval_root)
    vault = tmp_path / "vault"
    vault.mkdir()
    store = ContentStore(vault)
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
    artifacts = (draft,)
    staged = coordinator.stage_artifacts(
        purpose="rebuild",
        artifacts=artifacts,
    )
    closure_sha256 = publication_closure_sha256(
        purpose="rebuild",
        authority_base_version=artifact.source_catalog_version,
        expected_current_epoch=None,
        artifacts=artifacts,
    )
    descriptor = DraftDescriptor(
        purpose="rebuild",
        target_id="global-graph",
        base_version=artifact.source_catalog_version - 1,
        draft_sha256=closure_sha256,
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
    operation_id = harness.operation_id()
    ticket = harness.service.issue_for_execution(
        request.request_id,
        descriptor,
        operation_id=operation_id,
    )
    proof = harness.guard.apply_in_transaction(
        ticket,
        descriptor,
        lambda _connection: coordinator.prepare(
            operation_id=operation_id,
            purpose="rebuild",
            authority_base_version=artifact.source_catalog_version,
            approval_request_id=request.request_id,
            descriptor_sha256=ticket.descriptor_sha256,
            expected_current_epoch=None,
            artifacts=staged,
        ),
    )
    harness.service.acknowledge(proof)
    coordinator.verify(operation_id)
    active = coordinator.activate(operation_id)
    assert active.runtime_epoch == artifact.source_runtime_epoch == 1
    stored = ManifestRepository(harness.target_connection).get_active(
        "graph",
        epoch=active.runtime_epoch,
    )
    root_ref = VersionRef(
        object_id=stored.manifest_id,
        version=stored.source_version,
        content_sha256=stored.manifest_sha256,
    )
    discovery_snapshot = graph_authority_snapshot(artifact)
    binding = ActiveRetrievalArtifactDiscovery(
        harness.target_connection,
        store,
    ).discover_root(
        discovery_snapshot,
        expected_ref=root_ref,
        artifact_kind="graph",
        source_catalog_version=artifact.source_catalog_version,
    )
    return binding, harness


def _setup(
    tmp_path: Path,
    *,
    candidate_manifest_is_root: bool = False,
    catalog_live: bool = True,
    multiple_passages: bool = False,
):
    closure = _closure(
        passage_count=2 if multiple_passages else 1,
        runtime_epoch=1,
    )
    artifact, builder_input, graph_candidates, protected_catalog, _manifest = (
        closure
    )
    payloads, members, _bound_manifest = _member_closure(closure)
    artifact_binding, harness = _publish_graph_binding(
        tmp_path,
        artifact=artifact,
        builder_input=builder_input,
        payloads=payloads,
        members=members,
    )
    identity = artifact_binding.identity
    member_by_role = {member.role: member for member in identity.members}
    graph_version = VersionRef(
        object_id=member_by_role["global_graph"].object_id,
        version=identity.source_catalog_version,
        content_sha256=member_by_role["global_graph"].content_sha256,
    )
    catalog_ref = VersionRef(
        object_id=member_by_role["graph_build_manifest"].object_id,
        version=identity.source_catalog_version,
        content_sha256=member_by_role["graph_build_manifest"].content_sha256,
    )
    candidate_by_pair = {
        (value.reference, value.content_ref): value for value in graph_candidates
    }
    route_entries = []
    for row in protected_catalog.edge_mapping.rows:
        value = candidate_by_pair[(row.candidate_ref, row.content_ref)]
        if candidate_manifest_is_root:
            value = value.model_copy(
                update={
                    "metadata": value.metadata.model_copy(
                        update={"manifest_ref": identity.root_ref}
                    )
                }
            )
        route_entries.append(
            GraphRouteCandidate(
                relation_refs=tuple(
                    link.relation_ref for link in row.relation_links
                ),
                candidate=value,
            )
        )
    catalog_snapshot = GraphCandidateCatalogSnapshot(
        build_manifest_ref=catalog_ref,
        graph_root_ref=identity.root_ref,
        graph_version=graph_version,
        runtime_epoch=artifact.source_runtime_epoch,
        entries=tuple(route_entries),
    )
    catalog = CountingCandidateCatalog(catalog_snapshot)
    nodes = CountingNodeResolver(
        (GraphNodeQuery(source_node_id="source", target_node_id="target"),)
    )
    snapshot = graph_authority_snapshot(artifact)
    if catalog_live:
        snapshot = snapshot.model_copy(
            update={
                "allowed_ref_ids": snapshot.allowed_ref_ids
                | frozenset({catalog_ref.object_id})
            }
        )
    scope = RetrievalScope(
        current_client_id=CLIENT_A,
        allowed_uses=frozenset({"consultation"}),
        maximum_sensitivity=3,
        effective_at=NOW,
        known_at=NOW,
    )
    retriever = GlobalGraphRetriever(
        artifact,
        artifact_binding=artifact_binding,
        edge_authority_resolver=GraphEdgeAuthorityResolver(
            StaticGraphEdgeAuthorityCatalog(
                protected_catalog.records,
                runtime_epoch=artifact.source_runtime_epoch,
            )
        ),
        node_resolver=nodes,
        candidate_catalog=catalog,
    )
    return (
        retriever,
        scope,
        snapshot,
        graph_candidates[0],
        catalog,
        nodes,
        identity.root_ref,
        artifact_binding,
        harness,
    )


@pytest.fixture
def graph_setup_factory(tmp_path: Path):  # type: ignore[no-untyped-def]
    harnesses = []
    counter = 0

    def build(**kwargs):  # type: ignore[no-untyped-def]
        nonlocal counter
        counter += 1
        result = _setup(tmp_path / f"setup-{counter}", **kwargs)
        harnesses.append(result[-1])
        return result[:-1]

    yield build
    for harness in harnesses:
        harness.close()


def test_global_graph_retriever_returns_exact_body_free_candidates(
    graph_setup_factory,
) -> None:  # type: ignore[no-untyped-def]
    retriever, scope, snapshot, expected, catalog, nodes, graph_root, binding = (
        graph_setup_factory()
    )

    result = retriever.search("relationship pattern", scope, snapshot, limit=5)

    assert len(result) == 1
    assert result[0].reference == expected.reference
    assert result[0].content_ref == expected.content_ref
    assert result[0].channel == "global_graph"
    assert result[0].filter_binding is None
    assert result[0].metadata.manifest_ref != graph_root
    assert result[0].score > 0
    assert result[0].score_components[0].channel == "global_graph_path"
    assert catalog.snapshot_reads == 1
    assert catalog.body_reads == nodes.body_reads == 0
    assert nodes.calls == 1
    assert retriever.artifact_binding is binding


def test_one_graph_claim_expands_every_governed_supporting_passage(
    graph_setup_factory,
) -> None:  # type: ignore[no-untyped-def]
    retriever, scope, snapshot, expected, catalog, _nodes, _root, _binding = (
        graph_setup_factory(multiple_passages=True)
    )

    result = retriever.search("relationship pattern", scope, snapshot, limit=5)

    assert len(result) == 2
    assert {value.reference for value in result} == {expected.reference}
    assert {value.content_ref for value in result} == {
        entry.candidate.content_ref for entry in catalog.value.entries
    }


def test_graph_route_catalog_cannot_drop_one_passage_of_a_claim(
    graph_setup_factory,
) -> None:  # type: ignore[no-untyped-def]
    retriever, scope, snapshot, _expected, catalog, _nodes, _root, _binding = (
        graph_setup_factory(multiple_passages=True)
    )
    catalog.value = catalog.value.model_copy(
        update={"entries": catalog.value.entries[:1]}
    )

    with pytest.raises(
        GlobalGraphRetrieverError,
        match="GLOBAL_GRAPH_ROUTE_CATALOG_INVALID",
    ):
        retriever.search("relationship pattern", scope, snapshot, limit=5)


def test_graph_route_root_never_substitutes_for_authority_content_manifest(
    graph_setup_factory,
) -> None:  # type: ignore[no-untyped-def]
    retriever, scope, snapshot, _expected, _catalog, _nodes, _root, _binding = (
        graph_setup_factory(candidate_manifest_is_root=True)
    )
    with pytest.raises(
        GlobalGraphRetrieverError,
        match="GLOBAL_GRAPH_ROUTE_CATALOG_INVALID",
    ):
        retriever.search("relationship pattern", scope, snapshot, limit=5)


def test_graph_candidate_catalog_must_be_live_in_same_authority_snapshot(
    graph_setup_factory,
) -> None:  # type: ignore[no-untyped-def]
    retriever, scope, snapshot, _expected, _catalog, _nodes, _root, _binding = (
        graph_setup_factory(catalog_live=False)
    )
    with pytest.raises(
        GlobalGraphRetrieverError,
        match="GLOBAL_GRAPH_ROUTE_CATALOG_STALE",
    ):
        retriever.search("relationship pattern", scope, snapshot, limit=5)


def test_same_graph_payload_cannot_be_queried_through_another_route_root(
    graph_setup_factory,
) -> None:  # type: ignore[no-untyped-def]
    retriever, scope, snapshot, _expected, catalog, _nodes, _root, _binding = (
        graph_setup_factory()
    )
    other_root = ref("artifact_manifest", "6").model_copy(
        update={"version": catalog.value.graph_root_ref.version}
    )
    catalog.value = catalog.value.model_copy(
        update={"graph_root_ref": other_root}
    )
    with pytest.raises(
        GlobalGraphRetrieverError,
        match="GLOBAL_GRAPH_ROUTE_ROOT_MISMATCH",
    ):
        retriever.search("relationship pattern", scope, snapshot, limit=5)


def test_graph_candidate_catalog_cannot_omit_an_artifact_edge(
    graph_setup_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # type: ignore[no-untyped-def]
    retriever, scope, snapshot, _expected, catalog, _nodes, _root, _binding = (
        graph_setup_factory()
    )
    catalog.value = catalog.value.model_copy(update={"entries": ()})
    original = ArtifactBinding.verify_current
    calls = 0

    def counted(self):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        return original(self)

    monkeypatch.setattr(ArtifactBinding, "verify_current", counted)
    with pytest.raises(
        GlobalGraphRetrieverError,
        match="GLOBAL_GRAPH_ROUTE_CATALOG_INVALID",
    ):
        retriever.search("relationship pattern", scope, snapshot, limit=5)
    assert calls == 2


def test_zero_result_still_verifies_binding_before_and_after(
    graph_setup_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # type: ignore[no-untyped-def]
    retriever, scope, snapshot, _expected, _catalog, nodes, _root, _binding = (
        graph_setup_factory()
    )
    nodes.pairs = ()
    original = ArtifactBinding.verify_current
    calls = 0

    def counted(self):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        return original(self)

    monkeypatch.setattr(ArtifactBinding, "verify_current", counted)

    assert retriever.search("no route", scope, snapshot, limit=5) == ()
    assert calls == 2


def test_invalid_query_still_verifies_binding_before_and_after(
    graph_setup_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # type: ignore[no-untyped-def]
    retriever, scope, snapshot, _expected, _catalog, _nodes, _root, _binding = (
        graph_setup_factory()
    )
    original = ArtifactBinding.verify_current
    calls = 0

    def counted(self):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        return original(self)

    monkeypatch.setattr(ArtifactBinding, "verify_current", counted)

    with pytest.raises(
        GlobalGraphRetrieverError,
        match="GLOBAL_GRAPH_QUERY_INVALID",
    ):
        retriever.search("", scope, snapshot, limit=5)
    assert calls == 2


def test_invalid_binding_fails_closed_without_route_fallback(
    graph_setup_factory,
) -> None:  # type: ignore[no-untyped-def]
    retriever, scope, snapshot, _expected, catalog, nodes, _root, binding = (
        graph_setup_factory()
    )
    binding.path_for("graph_build_manifest").write_bytes(b"drift")

    with pytest.raises(
        GlobalGraphRetrieverError,
        match="GLOBAL_GRAPH_ARTIFACT_BINDING_STALE",
    ):
        retriever.search("relationship pattern", scope, snapshot, limit=5)

    assert catalog.snapshot_reads == 0
    assert nodes.calls == 0
