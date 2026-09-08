from __future__ import annotations

import networkx as nx
import pytest

from graphify.cluster import ClusterResult

from consultation_kb.graph.graphify_adapter import (
    GraphifyProjectionError,
    GraphifyBackendError,
    GraphifyProjectionAdapter,
    ProjectionClusterResult,
    build_graph_manifest,
)
from tests.consultation_kb.graph_support import NOW, global_graph_artifact, ref


def _canonical_graph() -> nx.MultiDiGraph:
    graph = nx.MultiDiGraph()
    graph.graph.update(
        builder_policy_version="consultation-global-graph.v1",
        effective_at=NOW,
        source_catalog_version=5,
        source_runtime_epoch=7,
    )
    edge_b = ref("graph_edge", "b")
    graph.add_edge(
        "alpha",
        "beta",
        key=edge_b.object_id,
        confidence=0.6,
        relation="CONTRADICTS",
        relation_ref=edge_b,
        wiki_ref=ref("wiki", "b"),
        source_refs=(ref("source", "b"),),
        claim_ref=ref("claim", "b"),
        passage_refs=(ref("passage", "b"),),
        theory_ref=None,
        provenance_scope="global_source",
    )
    edge_a = ref("graph_edge", "a")
    graph.add_edge(
        "alpha",
        "beta",
        key=edge_a.object_id,
        confidence=0.8,
        relation="SUPPORTS",
        relation_ref=edge_a,
        wiki_ref=ref("wiki", "a"),
        source_refs=(ref("source", "a"),),
        claim_ref=ref("claim", "a"),
        passage_refs=(ref("passage", "a"),),
        theory_ref=None,
        provenance_scope="global_source",
    )
    return graph


def test_projection_aggregates_parallel_edges_without_impersonating_code_graph() -> None:
    graph = _canonical_graph()
    projection = GraphifyProjectionAdapter().project(global_graph_artifact(graph))

    attributes = projection["alpha"]["beta"]
    assert attributes == {
        "aggregate_confidence": pytest.approx(0.92),
        "edge_count": 2,
        "relation_counts": {"CONTRADICTS": 1, "SUPPORTS": 1},
        "source_count": 2,
        "weight": pytest.approx(0.92),
    }
    banned = {"source_file", "relation", "confidence", "_src", "_tgt"}
    assert banned.isdisjoint(attributes)
    assert graph.number_of_edges("alpha", "beta") == 2


def test_projection_counts_stable_sources_not_versions() -> None:
    graph = nx.MultiDiGraph()
    source_v1 = ref("source", "1")
    source_v2 = source_v1.model_copy(
        update={"version": 2, "content_sha256": "2" * 64}
    )
    for key, source_ref in (("edge-1", source_v1), ("edge-2", source_v2)):
        edge_ref = ref("graph_edge", "3" if key == "edge-1" else "4")
        graph.add_edge(
            "alpha",
            "beta",
            key=edge_ref.object_id,
            confidence=0.8,
            relation="SUPPORTS",
            relation_ref=edge_ref,
            wiki_ref=ref("wiki", "9" if key == "edge-1" else "a"),
            source_refs=(source_ref,),
            claim_ref=ref("claim", "5" if key == "edge-1" else "6"),
            passage_refs=(ref("passage", "7" if key == "edge-1" else "8"),),
            theory_ref=None,
            provenance_scope="global_source",
        )
    projection = GraphifyProjectionAdapter().project(global_graph_artifact(graph))
    assert projection["alpha"]["beta"]["source_count"] == 1


def test_persistent_projection_ignores_case_and_mixed_topology() -> None:
    baseline_artifact = global_graph_artifact(_canonical_graph())
    scoped_graph = _canonical_graph()
    case_edge = ref("graph_edge", "c")
    scoped_graph.add_edge(
        "case-left",
        "case-right",
        key=case_edge.object_id,
        confidence=1.0,
        relation="SUPPORTS",
        relation_ref=case_edge,
        wiki_ref=ref("wiki", "c"),
        source_refs=(ref("source", "c"),),
        claim_ref=ref("claim", "c"),
        passage_refs=(ref("passage", "c"),),
        theory_ref=None,
        provenance_scope="case_derived",
    )
    scoped_artifact = global_graph_artifact(scoped_graph)
    adapter = GraphifyProjectionAdapter(seed=42)

    baseline = adapter.cluster(baseline_artifact)
    scoped = adapter.cluster(scoped_artifact)

    assert set(scoped.projection.nodes) == set(baseline.projection.nodes)
    assert set(scoped.projection.edges) == set(baseline.projection.edges)
    assert scoped.communities == baseline.communities


def test_cluster_uses_actual_metadata_and_canonicalizes_community_ids(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_cluster(graph, *, seed):  # type: ignore[no-untyped-def]
        assert sorted(graph.nodes) == ["alpha", "beta"]
        assert seed == 17
        return ClusterResult(
            {4: ["beta", "alpha"]},
            "leiden",
            17,
            False,
            True,
        )

    monkeypatch.setattr(
        "consultation_kb.graph.graphify_adapter.cluster_with_metadata",
        fake_cluster,
    )
    result = GraphifyProjectionAdapter(seed=17).cluster(
        global_graph_artifact(_canonical_graph())
    )

    assert result.communities == {0: ("alpha", "beta")}
    assert result.metadata.backend == "leiden"
    assert result.metadata.seed == 17


def test_python312_production_mode_rejects_degraded_backend(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_cluster(graph, *, seed):  # type: ignore[no-untyped-def]
        return ClusterResult(
            {0: sorted(graph.nodes)}, "louvain", seed, True, True
        )

    monkeypatch.setattr(
        "consultation_kb.graph.graphify_adapter.cluster_with_metadata",
        fake_cluster,
    )
    with pytest.raises(GraphifyBackendError, match="GRAPHIFY_PRODUCTION_BACKEND_INVALID"):
        GraphifyProjectionAdapter(seed=42, production=True).cluster(
            global_graph_artifact(_canonical_graph())
        )


def test_manifest_records_runtime_backend_seed_versions_and_artifact_hashes() -> None:
    artifact = global_graph_artifact(_canonical_graph())
    result = GraphifyProjectionAdapter(seed=42).cluster(artifact)
    manifest = build_graph_manifest(
        artifact=artifact,
        cluster_result=result,
        seed=42,
    )

    assert manifest.backend == result.metadata.backend
    assert manifest.seed == 42
    assert manifest.degraded == result.metadata.degraded
    assert manifest.graphify_version
    assert manifest.networkx_version == nx.__version__
    assert len(manifest.cluster_module_sha256) == 64
    assert len(manifest.canonical_graph_sha256) == 64
    assert len(manifest.projection_sha256) == 64
    assert len(manifest.communities_sha256) == 64
    assert len(manifest.manifest_sha256) == 64


def test_manifest_rejects_cluster_seed_that_does_not_match_runtime_result() -> None:
    artifact = global_graph_artifact(_canonical_graph())
    result = GraphifyProjectionAdapter(seed=42).cluster(artifact)
    with pytest.raises(
        GraphifyProjectionError, match="GRAPH_MANIFEST_SEED_MISMATCH"
    ):
        build_graph_manifest(
            artifact=artifact,
            cluster_result=result,
            seed=41,
        )


def test_manifest_rejects_arbitrary_covering_partition_not_produced_by_seed() -> None:
    artifact = global_graph_artifact(_canonical_graph())
    result = GraphifyProjectionAdapter(seed=42).cluster(artifact)
    arbitrary = {0: tuple(sorted(result.projection.nodes))}
    if arbitrary == result.communities:
        arbitrary = {
            index: (node,)
            for index, node in enumerate(sorted(result.projection.nodes))
        }

    with pytest.raises(
        GraphifyProjectionError,
        match="GRAPH_MANIFEST_CLUSTER_BINDING_MISMATCH",
    ):
        build_graph_manifest(
            artifact=artifact,
            cluster_result=ProjectionClusterResult(
                result.projection,
                arbitrary,
                result.metadata,
            ),
            seed=42,
        )
