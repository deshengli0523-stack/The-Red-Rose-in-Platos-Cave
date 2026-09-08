from __future__ import annotations

import pytest
from pydantic import ValidationError

from consultation_kb.evaluation.variants import (
    ABLATION_VARIANTS,
    ALL_EVIDENCE_CHANNELS,
    ALL_SYSTEM_VARIANTS,
    BASELINE_VARIANTS,
    FULL_SYSTEM,
    SYSTEM_VARIANTS_BY_NAME,
    SystemVariant,
    VariantFeatures,
    system_variant,
)


def test_five_baselines_and_three_ablations_are_exact_and_frozen() -> None:
    assert tuple(item.name for item in BASELINE_VARIANTS) == (
        "general_model_only",
        "hybrid_rag_only",
        "wiki_hybrid_rag",
        "full_without_c1_priority",
        "full_system",
    )
    assert tuple(item.name for item in ABLATION_VARIANTS) == (
        "full_without_graphify_navigation",
        "full_without_cases",
        "full_without_reranker",
    )
    assert tuple(SYSTEM_VARIANTS_BY_NAME) == tuple(
        item.name for item in ALL_SYSTEM_VARIANTS
    )
    assert len({item.canonical_sha256 for item in ALL_SYSTEM_VARIANTS}) == 8
    assert all(item.features.multi_stage_critique for item in ALL_SYSTEM_VARIANTS)
    assert system_variant("full_system") is FULL_SYSTEM
    with pytest.raises(ValidationError):
        FULL_SYSTEM.name = "general_model_only"  # type: ignore[misc]


def test_baseline_route_and_c1_boundaries_are_precise() -> None:
    general, hybrid, wiki, ordinary_c1, full = BASELINE_VARIANTS

    assert general.features.routes == ()
    assert general.features.c1_mode == "disabled"
    assert not general.features.reranker

    assert hybrid.features.routes == ("lexical", "vector")
    assert hybrid.features.c1_mode == "disabled"
    assert hybrid.features.reranker

    assert wiki.features.routes == ("wiki", "lexical", "vector")
    assert wiki.features.c1_mode == "disabled"
    assert not wiki.features.graphify_navigation

    assert ordinary_c1.features.routes == ALL_EVIDENCE_CHANNELS
    assert ordinary_c1.features.c1_mode == "ordinary"
    assert full.features.routes == ALL_EVIDENCE_CHANNELS
    assert full.features.c1_mode == "priority"

    for variant in BASELINE_VARIANTS:
        assert set(variant.features.routes).isdisjoint(
            variant.features.prohibited_routes
        )
        assert set(variant.features.routes) | set(
            variant.features.prohibited_routes
        ) == set(ALL_EVIDENCE_CHANNELS)


def test_each_ablation_changes_only_its_named_knowledge_layer() -> None:
    graph, cases, reranker = ABLATION_VARIANTS

    assert set(FULL_SYSTEM.features.routes) - set(graph.features.routes) == {
        "client_history",
        "global_graph",
    }
    assert not graph.features.graphify_navigation
    assert graph.features.cases and graph.features.reranker
    assert graph.features.c1_mode == "priority"

    assert set(FULL_SYSTEM.features.routes) - set(cases.features.routes) == {"case"}
    assert not cases.features.cases
    assert cases.features.graphify_navigation and cases.features.reranker
    assert cases.features.c1_mode == "priority"

    assert reranker.features.routes == FULL_SYSTEM.features.routes
    assert not reranker.features.reranker
    assert reranker.features.graphify_navigation and reranker.features.cases
    assert reranker.features.c1_mode == "priority"


def test_variant_contract_rejects_noncanonical_or_incoherent_flags() -> None:
    with pytest.raises(ValidationError, match="canonical channel order"):
        VariantFeatures(
            routes=("vector", "lexical"),
            c1_mode="disabled",
            graphify_navigation=False,
            cases=False,
            reranker=True,
        )
    with pytest.raises(ValidationError, match="Graphify navigation"):
        VariantFeatures(
            routes=("client_history",),
            c1_mode="disabled",
            graphify_navigation=False,
            cases=False,
            reranker=False,
        )
    with pytest.raises(ValidationError, match="case flag"):
        VariantFeatures(
            routes=("case",),
            c1_mode="disabled",
            graphify_navigation=False,
            cases=False,
            reranker=False,
        )
    altered = SystemVariant(
        name="full_system",
        family="baseline",
        features=FULL_SYSTEM.features.model_copy(update={"c1_mode": "ordinary"}),
    )
    assert altered.canonical_sha256 != FULL_SYSTEM.canonical_sha256
