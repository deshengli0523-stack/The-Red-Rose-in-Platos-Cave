from __future__ import annotations

import ast
import inspect
from pathlib import Path

import networkx as nx

from consultation_kb.graph.navigation_analysis import StructuralNavigationAnalyzer
from tests.consultation_kb.graph_support import (
    global_graph_artifact,
    graph_authority_snapshot,
    graph_query_authority,
    ref,
)


def _analyze(artifact, *, snapshot=None):  # type: ignore[no-untyped-def]
    exact_snapshot = snapshot or graph_authority_snapshot(artifact)
    resolver, scope, binding = graph_query_authority(artifact, exact_snapshot)
    return StructuralNavigationAnalyzer(
        max_hints=20,
        edge_authority_resolver=resolver,
    ).analyze(
        artifact,
        authority_snapshot=exact_snapshot,
        scope=scope,
        edge_authority_binding=binding,
    )


def test_navigation_hints_require_exact_claim_and_passage_backlinks() -> None:
    graph = nx.MultiDiGraph()
    claim_ref = ref("claim", "1")
    passage_ref = ref("passage", "2")
    governed_edge = ref("graph_edge", "8")
    graph.add_edge(
        "a",
        "b",
        key=governed_edge.object_id,
        edge_id=governed_edge.object_id,
        relation_ref=governed_edge,
        wiki_ref=ref("wiki", "8"),
        relation="SUPPORTS",
        relation_scope=("consultation",),
        confidence=0.9,
        claim_ref=claim_ref,
        passage_refs=(passage_ref,),
        source_refs=(ref("source", "8"),),
        theory_ref=None,
        review_status="approved",
        passage_review_status="approved",
        allowed_uses=("consultation",),
        effective_from=None,
        effective_to=None,
        review_due_at=None,
        source_grade="C2",
        privacy_scope="global",
        provenance_scope="global_source",
        case_contributor_count=0,
        independent_source_count=1,
        authorized=True,
        tombstoned=False,
    )
    orphan_edge = ref("graph_edge", "9")
    graph.add_edge(
        "b",
        "c",
        key=orphan_edge.object_id,
        edge_id=orphan_edge.object_id,
        relation_ref=orphan_edge,
        wiki_ref=ref("wiki", "9"),
        relation="ANALOGOUS_TO",
        confidence=0.9,
        claim_ref=ref("claim", "3"),
        passage_refs=(),
        source_refs=(ref("source", "9"),),
        theory_ref=None,
        review_status="approved",
        passage_review_status="approved",
        authorized=True,
        tombstoned=False,
    )

    # Malformed backlink closure is rejected before navigation can inspect it.
    graph.remove_edge("b", "c", orphan_edge.object_id)
    artifact = global_graph_artifact(graph)
    result = _analyze(artifact)

    assert result.hints
    assert all(hint.claim_refs for hint in result.hints)
    assert all(hint.passage_refs for hint in result.hints)
    assert all(orphan_edge.object_id not in hint.edge_ids for hint in result.hints)


def test_high_degree_sink_with_only_incoming_edges_is_analyzed_without_crash() -> None:
    graph = nx.MultiDiGraph()
    for digit, source in (("4", "left"), ("5", "right")):
        edge_ref = ref("graph_edge", digit)
        graph.add_edge(
            source,
            "sink",
            key=edge_ref.object_id,
            edge_id=edge_ref.object_id,
            relation_ref=edge_ref,
            wiki_ref=ref("wiki", digit),
            relation="SUPPORTS",
            relation_scope=("consultation",),
            confidence=0.9,
            claim_ref=ref("claim", digit),
            passage_refs=(ref("passage", digit),),
            source_refs=(ref("source", digit),),
            theory_ref=None,
            review_status="approved",
            passage_review_status="approved",
            allowed_uses=("consultation",),
            effective_from=None,
            effective_to=None,
            review_due_at=None,
            source_grade="C2",
            privacy_scope="global",
            provenance_scope="global_source",
            case_contributor_count=0,
            independent_source_count=1,
            authorized=True,
            tombstoned=False,
        )

    artifact = global_graph_artifact(graph)
    result = _analyze(artifact)

    high_degree = [hint for hint in result.hints if hint.kind == "high_degree"]
    assert any(hint.node_ids == ("sink",) for hint in high_degree)
    assert all(hint.claim_refs and hint.passage_refs for hint in high_degree)


def test_navigation_excludes_edges_without_approved_passage_status() -> None:
    graph = nx.MultiDiGraph()
    for key, passage_status in (("approved", "approved"), ("revoked", "revoked")):
        edge_ref = ref("graph_edge", "6" if key == "approved" else "7")
        graph.add_edge(
            "a",
            key,
            key=edge_ref.object_id,
            edge_id=edge_ref.object_id,
            relation_ref=edge_ref,
            wiki_ref=ref("wiki", "8"),
            relation="SUPPORTS",
            relation_scope=("consultation",),
            confidence=0.9,
            claim_ref=ref("claim", "6"),
            passage_refs=(ref("passage", "7"),),
            source_refs=(ref("source", "8"),),
            theory_ref=None,
            review_status="approved",
            passage_review_status=passage_status,
            allowed_uses=("consultation",),
            effective_from=None,
            effective_to=None,
            review_due_at=None,
            source_grade="C2",
            privacy_scope="global",
            provenance_scope="global_source",
            case_contributor_count=0,
            independent_source_count=1,
            authorized=True,
            tombstoned=False,
        )

    artifact = global_graph_artifact(graph)
    snapshot = graph_authority_snapshot(artifact)
    result = _analyze(artifact, snapshot=snapshot)

    assert result.eligible_edge_count == 1
    assert result.excluded_orphan_edge_count == 1
    assert all(
        edge_ref.object_id not in hint.edge_ids for hint in result.hints
    )


def test_navigation_live_authority_filters_revoked_high_score_before_topology() -> None:
    graph = nx.MultiDiGraph()
    approved_edge = ref("graph_edge", "1")
    revoked_edge = ref("graph_edge", "2")
    approved_claim = ref("claim", "3")
    revoked_claim = ref("claim", "4")
    for edge_ref, claim_ref, confidence, target in (
        (approved_edge, approved_claim, 0.2, "approved-target"),
        (revoked_edge, revoked_claim, 0.99, "revoked-target"),
    ):
        graph.add_edge(
            "root",
            target,
            key=edge_ref.object_id,
            edge_id=edge_ref.object_id,
            relation_ref=edge_ref,
            wiki_ref=ref("wiki", "7"),
            relation="SUPPORTS",
            relation_scope=("consultation",),
            confidence=confidence,
            claim_ref=claim_ref,
            passage_refs=(ref("passage", "5"),),
            source_refs=(ref("source", "6"),),
            theory_ref=None,
            review_status="approved",
            passage_review_status="approved",
            allowed_uses=("consultation",),
            effective_from=None,
            effective_to=None,
            review_due_at=None,
            source_grade="C2",
            privacy_scope="global",
            provenance_scope="global_source",
            case_contributor_count=0,
            independent_source_count=1,
            authorized=True,
            tombstoned=False,
        )
    artifact = global_graph_artifact(graph)
    snapshot = graph_authority_snapshot(
        artifact,
        excluded_ref_ids=frozenset({revoked_claim.object_id}),
    )

    result = _analyze(artifact, snapshot=snapshot)

    assert result.eligible_edge_count == 1
    assert result.excluded_orphan_edge_count == 1
    assert all(revoked_edge.object_id not in hint.edge_ids for hint in result.hints)
    assert result.authority_binding.run_id == snapshot.run_id


def test_parallel_evidence_does_not_inflate_structural_degree() -> None:
    graph = nx.MultiDiGraph()
    for digit in ("1", "2", "3"):
        edge_ref = ref("graph_edge", digit)
        graph.add_edge(
            "left",
            "right",
            key=edge_ref.object_id,
            edge_id=edge_ref.object_id,
            relation_ref=edge_ref,
            wiki_ref=ref("wiki", digit),
            relation="SUPPORTS",
            relation_scope=("consultation",),
            confidence=0.8,
            claim_ref=ref("claim", digit),
            passage_refs=(ref("passage", digit),),
            source_refs=(ref("source", digit),),
            theory_ref=None,
            review_status="approved",
            passage_review_status="approved",
            allowed_uses=("consultation",),
            effective_from=None,
            effective_to=None,
            review_due_at=None,
            source_grade="C2",
            privacy_scope="global",
            provenance_scope="global_source",
            case_contributor_count=0,
            independent_source_count=1,
            authorized=True,
            tombstoned=False,
        )
    artifact = global_graph_artifact(graph)
    result = _analyze(artifact)

    assert all(hint.kind != "high_degree" for hint in result.hints)


def test_consultation_graph_modules_only_use_graphify_cluster_adapter_boundary() -> None:
    package = Path("consultation_kb/graph")
    graphify_imports: list[tuple[str, str]] = []
    for path in sorted(package.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("graphify"):
                        graphify_imports.append((path.name, alias.name))
            elif isinstance(node, ast.ImportFrom) and (
                (node.module or "") == "graphify"
                or (node.module or "").startswith("graphify.")
            ):
                graphify_imports.append((path.name, node.module or ""))

    assert graphify_imports == [("graphify_adapter.py", "graphify.cluster")]


def test_navigation_does_not_accept_raw_or_stale_community_annotations() -> None:
    parameters = inspect.signature(StructuralNavigationAnalyzer.analyze).parameters
    assert "communities" not in parameters
