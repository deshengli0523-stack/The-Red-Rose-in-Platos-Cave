from __future__ import annotations

import ast
from pathlib import Path
from types import MappingProxyType

import networkx as nx
import pytest

from consultation_kb.graph.global_builder import (
    GlobalGraphArtifact,
    GlobalGraphBuildError,
    graph_dependencies_from_graph,
)
from consultation_kb.graph.authority_filter import GraphAuthoritySnapshotError
from consultation_kb.graph.path_cost import PathCostContext, PathCostPolicy
from consultation_kb.graph.serialization import graph_payload_from_parts, graph_sha256
from consultation_kb.graph.weighted_path import (
    GlobalGraphPathError,
    PathSearchBudgetExceeded,
    WeightedPathQuery,
)
from consultation_kb.models.evidence import C1ApplicabilityDecision
from tests.consultation_kb.graph_support import (
    NOW,
    graph_authority_snapshot,
    graph_query_authority,
    ref,
)


def _edge_attributes(
    edge_ref,
    claim_ref,
    passage_ref,
    *,
    relation: str = "SUPPORTS",
    cognitive_type: str = "explicit",
    source_grade: str = "C2",
    confidence: float = 0.9,
    source_count: int = 2,
    **overrides: object,
):  # type: ignore[no-untyped-def]
    independent_refs = tuple(ref("source", str(index % 10)).object_id for index in range(source_count))
    values: dict[str, object] = {
        "edge_id": edge_ref.object_id,
        "relation_ref": edge_ref,
        "wiki_ref": ref("wiki", "b"),
        "claim_ref": claim_ref,
        "passage_refs": (passage_ref,),
        "source_refs": (ref("source", "1"),),
        "relation": relation,
        "relation_scope": ("consultation",),
        "confidence": confidence,
        "cognitive_type": cognitive_type,
        "source_grade": source_grade,
        "privacy_scope": "global",
        "provenance_scope": "global_source",
        "case_contributor_count": 0,
        "empirical_support": "guideline_consistent",
        "framework_eligibility": "eligible",
        "review_status": "approved",
        "passage_review_status": "approved",
        "effective_from": NOW,
        "effective_to": None,
        "review_due_at": None,
        "allowed_uses": ("consultation",),
        "independent_source_count": source_count,
        "independent_source_ids": independent_refs,
        "theory_ref": None,
        "theory_status": None,
        "truth_type": "interpretation",
        "statement_text_sha256": "a" * 64,
        "authorized": True,
        "tombstoned": False,
    }
    values.update(overrides)
    return values


def _context(*, c1=None) -> PathCostContext:  # type: ignore[no-untyped-def]
    return PathCostContext(
        effective_at=NOW,
        required_use="consultation",
        c1_applicability=c1,
    )


def _artifact(
    graph: nx.MultiDiGraph,
    *,
    adversarial_prefreeze: bool = False,
) -> GlobalGraphArtifact:
    graph.graph.update(
        source_catalog_version=7,
        source_runtime_epoch=3,
        effective_at=NOW,
        builder_policy_version="consultation-global-graph.v1",
    )
    digest = graph_sha256(
        graph_payload_from_parts(
            graph,
            source_catalog_version=7,
            source_runtime_epoch=3,
            effective_at=NOW,
            builder_policy_version="consultation-global-graph.v1",
        )
    )
    dependencies = graph_dependencies_from_graph(graph)
    if adversarial_prefreeze:
        nx.freeze(graph)
        graph.graph = MappingProxyType(dict(graph.graph))  # type: ignore[assignment]
    return GlobalGraphArtifact(
        graph=graph,
        source_catalog_version=7,
        source_runtime_epoch=3,
        effective_at=NOW,
        builder_policy_version="consultation-global-graph.v1",
        canonical_sha256=digest,
        dependencies=dependencies,
    )


def _graph_ref(artifact: GlobalGraphArtifact):  # type: ignore[no-untyped-def]
    return ref("global_graph", "d").model_copy(
        update={"version": 7, "content_sha256": artifact.canonical_sha256}
    )


def _query_bundle(artifact, snapshot=None, graph_version=None):  # type: ignore[no-untyped-def]
    exact_snapshot = snapshot or graph_authority_snapshot(artifact)
    exact_graph_version = graph_version or _graph_ref(artifact)
    resolver, scope, binding = graph_query_authority(
        artifact,
        exact_snapshot,
        graph_version=exact_graph_version,
    )
    return (
        WeightedPathQuery(
            artifact,
            graph_version=exact_graph_version,
            edge_authority_resolver=resolver,
        ),
        exact_snapshot,
        scope,
        binding,
        resolver,
    )


def test_path_cost_rewards_direct_current_diverse_sources_and_explains_every_term() -> None:
    policy = PathCostPolicy()
    direct = _edge_attributes(ref("graph_edge", "1"), ref("claim", "2"), ref("passage", "3"))
    inferred = _edge_attributes(
        ref("graph_edge", "4"),
        ref("claim", "5"),
        ref("passage", "6"),
        relation="ANALOGOUS_TO",
        cognitive_type="model_inference",
        confidence=0.5,
        source_count=1,
    )

    direct_cost = policy.evaluate(direct, _context())
    inferred_cost = policy.evaluate(inferred, _context())

    assert direct_cost is not None and inferred_cost is not None
    assert direct_cost.total < inferred_cost.total
    assert direct_cost.components["source_diversity_adjustment"] < 0
    assert inferred_cost.components["analogy_penalty"] > 0
    assert inferred_cost.components["inference_penalty"] > 0
    assert direct_cost.policy_version == PathCostPolicy.VERSION


@pytest.mark.parametrize(
    ("override", "expected_reason"),
    [
        ({"review_status": "reviewed"}, "review_not_approved"),
        ({"passage_review_status": "revoked"}, "passage_not_approved"),
        ({"authorized": False}, "not_authorized"),
        ({"tombstoned": True}, "tombstoned"),
        ({"effective_to": NOW}, "not_effective"),
    ],
)
def test_hard_authority_gates_are_impassable_not_expensive(
    override: dict[str, object], expected_reason: str
) -> None:
    attributes = _edge_attributes(
        ref("graph_edge", "7"), ref("claim", "8"), ref("passage", "9"), **override
    )
    decision = PathCostPolicy().assess(attributes, _context())
    assert decision.cost is None
    assert decision.impassable_reason == expected_reason


def test_applicable_active_c1_gets_framework_adjustment_without_mutating_truth() -> None:
    theory_ref = ref("theory", "a")
    c1 = C1ApplicabilityDecision(
        status="applicable",
        revision=theory_ref,
        scope_policy_ref=ref("scope_policy", "b"),
        matched_rule_ids=("relationship_consultation",),
        missing_context_fields=(),
        effective_status="active",
        empirical_support="case_supported",
        conflict_evidence_ids=(),
    )
    attributes = _edge_attributes(
        ref("graph_edge", "c"),
        ref("claim", "d"),
        ref("passage", "e"),
        source_grade="C1",
        theory_ref=theory_ref,
        theory_status="active",
        truth_type="theory_framework",
        statement_text_sha256="f" * 64,
    )
    original = dict(attributes)

    applicable = PathCostPolicy().evaluate(attributes, _context(c1=c1))
    unavailable = PathCostPolicy().evaluate(attributes, _context())

    assert applicable is not None and unavailable is not None
    assert applicable.components["c1_framework_adjustment"] < 0
    assert unavailable.components["c1_framework_adjustment"] == 0
    assert applicable.total < unavailable.total
    assert attributes == original
    assert attributes["truth_type"] == "theory_framework"
    assert attributes["statement_text_sha256"] == "f" * 64


def test_weighted_query_preserves_parallel_evidence_and_uses_bounded_uniform_cost() -> None:
    graph = nx.MultiDiGraph()
    source = ref("concept", "1")
    middle = ref("concept", "2")
    target = ref("concept", "3")
    for node in (source, middle, target):
        graph.add_node(node.object_id, reference=node)
    first = ref("graph_edge", "4")
    second = ref("graph_edge", "5")
    tail = ref("graph_edge", "6")
    graph.add_edge(
        source.object_id,
        middle.object_id,
        key=first.object_id,
        **_edge_attributes(first, ref("claim", "7"), ref("passage", "8")),
    )
    graph.add_edge(
        source.object_id,
        middle.object_id,
        key=second.object_id,
        **_edge_attributes(
            second,
            ref("claim", "9"),
            ref("passage", "a"),
            relation="CONTRADICTS",
            confidence=0.8,
        ),
    )
    graph.add_edge(
        middle.object_id,
        target.object_id,
        key=tail.object_id,
        **_edge_attributes(tail, ref("claim", "b"), ref("passage", "c")),
    )

    artifact = _artifact(graph)
    graph_ref = _graph_ref(artifact)
    authority_snapshot = graph_authority_snapshot(artifact)
    query, _, scope, binding, _ = _query_bundle(
        artifact, authority_snapshot, graph_ref
    )
    paths = query.search(
        source.object_id,
        target.object_id,
        context=_context(),
        authority_snapshot=authority_snapshot,
        scope=scope,
        edge_authority_binding=binding,
        max_hops=2,
        top_k=2,
        max_expansions=20,
        max_candidates=5,
    )

    assert [path.edge_ids for path in paths] == [
        (first.object_id, tail.object_id),
        (second.object_id, tail.object_id),
    ]
    assert all(path.graph_version == graph_ref for path in paths)
    assert all(all(step.claim_ref for step in path.steps) for path in paths)
    assert all(all(step.passage_refs for step in path.steps) for path in paths)
    assert paths[1].contains_contradiction is True

    revoked_snapshot = graph_authority_snapshot(
        artifact,
        excluded_ref_ids=frozenset(
            {graph[source.object_id][middle.object_id][first.object_id]["claim_ref"].object_id}
        ),
    )
    revoked_query, _, revoked_scope, revoked_binding, _ = _query_bundle(
        artifact, revoked_snapshot
    )
    after_revocation = revoked_query.search(
        source.object_id,
        target.object_id,
        context=_context(),
        authority_snapshot=revoked_snapshot,
        scope=revoked_scope,
        edge_authority_binding=revoked_binding,
        max_hops=2,
        top_k=2,
        max_expansions=20,
        max_candidates=5,
    )
    assert [path.edge_ids for path in after_revocation] == [
        (second.object_id, tail.object_id)
    ]
    assert all(
        path.authority_binding.run_id == revoked_snapshot.run_id
        for path in after_revocation
    )

    with pytest.raises(PathSearchBudgetExceeded, match="GLOBAL_GRAPH_PATH_BUDGET_EXCEEDED"):
        query.search(
            source.object_id,
            target.object_id,
            context=_context(),
            authority_snapshot=authority_snapshot,
            scope=scope,
            edge_authority_binding=binding,
            max_hops=2,
            top_k=2,
            max_expansions=1,
            max_candidates=5,
        )


def test_weighted_query_rejects_mutated_artifact_and_mismatched_context_epoch() -> None:
    graph = nx.MultiDiGraph()
    source = ref("concept", "1")
    target = ref("concept", "2")
    graph.add_node(source.object_id, reference=source)
    graph.add_node(target.object_id, reference=target)
    edge = ref("graph_edge", "3")
    graph.add_edge(
        source.object_id,
        target.object_id,
        key=edge.object_id,
        **_edge_attributes(edge, ref("claim", "4"), ref("passage", "5")),
    )
    artifact = _artifact(graph)
    graph_ref = _graph_ref(artifact)
    authority_snapshot = graph_authority_snapshot(artifact)
    query, _, scope, binding, resolver = _query_bundle(
        artifact, authority_snapshot
    )

    with pytest.raises(
        GlobalGraphPathError,
        match="GLOBAL_GRAPH_CONTEXT_EPOCH_MISMATCH",
    ):
        query.search(
            source.object_id,
            target.object_id,
            context=PathCostContext(
                effective_at=NOW.replace(year=NOW.year + 1),
                required_use="consultation",
            ),
            authority_snapshot=authority_snapshot,
            scope=scope,
            edge_authority_binding=binding,
        )

    with pytest.raises(TypeError):
        graph[source.object_id][target.object_id][edge.object_id]["confidence"] = 0.1
    object.__setattr__(artifact, "canonical_sha256", "0" * 64)
    with pytest.raises(
        GlobalGraphBuildError,
        match="GRAPH_ARTIFACT_HASH_MISMATCH",
    ):
        WeightedPathQuery(
            artifact,
            graph_version=graph_ref,
            edge_authority_resolver=resolver,
        )


def test_newer_runtime_with_same_stable_ids_cannot_reauthorize_old_versions() -> None:
    graph = nx.MultiDiGraph()
    source = ref("concept", "6")
    target = ref("concept", "7")
    graph.add_node(source.object_id, reference=source)
    graph.add_node(target.object_id, reference=target)
    edge = ref("graph_edge", "8")
    graph.add_edge(
        source.object_id,
        target.object_id,
        key=edge.object_id,
        **_edge_attributes(edge, ref("claim", "9"), ref("passage", "a")),
    )
    artifact = _artifact(graph)
    current = graph_authority_snapshot(artifact)
    query, _, scope, binding, _ = _query_bundle(artifact, current)
    newer_same_ids = current.model_copy(
        update={"global_runtime_epoch": artifact.source_runtime_epoch + 1}
    )

    with pytest.raises(
        GraphAuthoritySnapshotError,
        match="GLOBAL_GRAPH_AUTHORITY_SNAPSHOT_STALE",
    ):
        query.search(
            source.object_id,
            target.object_id,
            context=_context(),
            authority_snapshot=newer_same_ids,
            scope=scope,
            edge_authority_binding=binding,
        )


def test_graph_version_rejects_non_graph_identity_even_with_matching_hash() -> None:
    graph = nx.MultiDiGraph()
    source = ref("concept", "b")
    target = ref("concept", "c")
    graph.add_node(source.object_id, reference=source)
    graph.add_node(target.object_id, reference=target)
    edge = ref("graph_edge", "d")
    graph.add_edge(
        source.object_id,
        target.object_id,
        key=edge.object_id,
        **_edge_attributes(edge, ref("claim", "e"), ref("passage", "f")),
    )
    artifact = _artifact(graph)
    false_identity = ref("claim", "1").model_copy(
        update={"content_sha256": artifact.canonical_sha256}
    )

    with pytest.raises(
        GlobalGraphPathError,
        match="GLOBAL_GRAPH_VERSION_IDENTITY_INVALID",
    ):
        WeightedPathQuery(
            artifact,
            graph_version=false_identity,
            edge_authority_resolver=_query_bundle(artifact)[4],
        )


def test_adversarial_prefreeze_cannot_leave_edge_attributes_mutable() -> None:
    graph = nx.MultiDiGraph()
    source = ref("concept", "1")
    target = ref("concept", "2")
    graph.add_node(source.object_id, reference=source)
    graph.add_node(target.object_id, reference=target)
    edge = ref("graph_edge", "3")
    graph.add_edge(
        source.object_id,
        target.object_id,
        key=edge.object_id,
        **_edge_attributes(edge, ref("claim", "4"), ref("passage", "5")),
    )

    artifact = _artifact(graph, adversarial_prefreeze=True)

    with pytest.raises(TypeError):
        artifact.graph[source.object_id][target.object_id][edge.object_id][
            "confidence"
        ] = 0.0


def test_path_source_diversity_counts_stable_ids_not_source_versions() -> None:
    graph = nx.MultiDiGraph()
    source = ref("concept", "2")
    target = ref("concept", "3")
    graph.add_node(source.object_id, reference=source)
    graph.add_node(target.object_id, reference=target)
    edge = ref("graph_edge", "4")
    source_v1 = ref("source", "5")
    source_v2 = source_v1.model_copy(
        update={"version": 2, "content_sha256": "6" * 64}
    )
    attributes = _edge_attributes(
        edge,
        ref("claim", "7"),
        ref("passage", "8"),
        source_count=1,
    )
    attributes.update(
        source_refs=(source_v1, source_v2),
        independent_source_ids=(source_v1.object_id,),
    )
    graph.add_edge(
        source.object_id,
        target.object_id,
        key=edge.object_id,
        **attributes,
    )
    artifact = _artifact(graph)
    query, snapshot, scope, binding, _ = _query_bundle(artifact)
    result = query.search(
        source.object_id,
        target.object_id,
        context=_context(),
        authority_snapshot=snapshot,
        scope=scope,
        edge_authority_binding=binding,
        top_k=1,
    )

    assert result[0].source_limits["independent_source_count"] == 1


def test_global_path_implementation_never_calls_networkx_shortest_path() -> None:
    path = Path("consultation_kb/graph/weighted_path.py")
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
    }
    assert "shortest_path" not in names
    assert "shortest_simple_paths" not in names
