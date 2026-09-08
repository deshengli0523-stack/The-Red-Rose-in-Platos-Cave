from __future__ import annotations

from datetime import timedelta

import pytest

from consultation_kb.graph.global_builder import (
    ClaimRelation,
    GlobalGraphBuilder,
    GraphAuthoritySnapshot,
    GovernedClaim,
    GovernedPassage,
    StaticGraphAuthority,
)
from consultation_kb.graph.path_cost import PathCostContext
from consultation_kb.graph.weighted_path import WeightedPathQuery
from tests.consultation_kb.graph_support import (
    NOW,
    approved_passage,
    governed_claim,
    graph_authority_snapshot,
    graph_query_authority,
    governed_wikis_for_relations,
    graph_relation,
    ref,
)


pytestmark = [pytest.mark.golden, pytest.mark.acceptance_id("GRAPH-01")]


def test_graph_01_global_keeps_parallel_claims_and_returns_only_current_evidence_paths() -> None:
    source = ref("concept", "1")
    target = ref("concept", "2")
    claims: list[GovernedClaim] = []
    passages: list[GovernedPassage] = []
    relations: list[ClaimRelation] = []
    for digit, relation_kind in (("3", "SUPPORTS"), ("4", "CONTRADICTS")):
        passage_ref, passage = approved_passage(digit=digit)
        claim_ref, claim = governed_claim(
            passage_ref=passage_ref,
            passage=passage,
            text=f"global-{relation_kind}",
        )
        claims.append(GovernedClaim(reference=claim_ref, record=claim))
        passages.append(GovernedPassage(reference=passage_ref, record=passage))
        relations.append(
            graph_relation(
                source_ref=source,
                target_ref=target,
                claim_ref=claim_ref,
                relation=relation_kind,
                digit=digit,
                claim_record=claim,
            )
        )
    old_passage_ref, old_passage = approved_passage(digit="5")
    old_claim_ref, old_claim = governed_claim(
        passage_ref=old_passage_ref,
        passage=old_passage,
        text="expired",
        effective_to=NOW + timedelta(seconds=1),
    )
    claims.append(GovernedClaim(reference=old_claim_ref, record=old_claim))
    passages.append(GovernedPassage(reference=old_passage_ref, record=old_passage))
    relations.append(
        graph_relation(
            source_ref=source,
            target_ref=target,
            claim_ref=old_claim_ref,
            relation="SUPPORTS",
            digit="5",
            claim_record=old_claim,
        )
    )
    artifact = GlobalGraphBuilder(
        StaticGraphAuthority(
            GraphAuthoritySnapshot(
                catalog_version=8,
                runtime_epoch=3,
                effective_at=NOW + timedelta(seconds=2),
                claims=tuple(claims),
                passages=tuple(passages),
                theories=(),
                wikis=governed_wikis_for_relations(
                    tuple(relations), tuple(claims)
                ),
                relations=tuple(relations),
            )
        )
    ).build(8, target_runtime_epoch=3)
    graph_ref = ref("global_graph", "f").model_copy(
        update={"version": 8, "content_sha256": artifact.canonical_sha256}
    )
    authority_snapshot = graph_authority_snapshot(artifact)
    resolver, scope, binding = graph_query_authority(
        artifact, authority_snapshot, graph_version=graph_ref
    )

    assert artifact.graph.number_of_edges(source.object_id, target.object_id) == 2
    paths = WeightedPathQuery(
        artifact,
        graph_version=graph_ref,
        edge_authority_resolver=resolver,
    ).search(
        source.object_id,
        target.object_id,
        context=PathCostContext(
            effective_at=NOW + timedelta(seconds=2),
            required_use="consultation",
        ),
        authority_snapshot=authority_snapshot,
        scope=scope,
        edge_authority_binding=binding,
        max_hops=1,
        top_k=2,
    )
    assert len(paths) == 2
    assert {path.steps[0].relation for path in paths} == {"SUPPORTS", "CONTRADICTS"}
    assert all(path.steps[0].claim_ref for path in paths)
    assert all(path.steps[0].passage_refs for path in paths)
    assert all(path.source_limits["minimum_independent_sources"] >= 1 for path in paths)
