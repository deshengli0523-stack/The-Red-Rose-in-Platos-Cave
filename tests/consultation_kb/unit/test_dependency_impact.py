from __future__ import annotations

import pytest

from consultation_kb.client.dependencies import (
    DependencyImpactBudgetExceeded,
    DependencyImpactService,
    DependencyRepository,
)
from consultation_kb.models.dependencies import DependencyEdge


def test_partner_change_splits_direct_and_indirect_impact() -> None:
    repository = DependencyRepository(
        (
            DependencyEdge(
                edge_id="dep-weekend",
                dependent_fact_id="weekend-plan",
                prerequisite_fact_id="partner-a",
                dependency_type="direct_deterministic",
                confidence=1.0,
                source_event_id="event-source",
                reviewer_id="counselor",
            ),
            DependencyEdge(
                edge_id="dep-preference",
                dependent_fact_id="partner-preference",
                prerequisite_fact_id="partner-a",
                dependency_type="direct_deterministic",
                confidence=0.95,
                source_event_id="event-source",
                reviewer_id="counselor",
            ),
            DependencyEdge(
                edge_id="dep-communication",
                dependent_fact_id="communication-pattern",
                prerequisite_fact_id="partner-a",
                dependency_type="direct_conditional",
                confidence=0.8,
                source_event_id="event-source",
                reviewer_id="counselor",
            ),
            DependencyEdge(
                edge_id="dep-attachment",
                dependent_fact_id="attachment-hypothesis",
                prerequisite_fact_id="communication-pattern",
                dependency_type="indirect_inferred",
                confidence=0.7,
                source_event_id="event-source",
                reviewer_id="counselor",
            ),
        )
    )
    proposal = DependencyImpactService(repository).preview(
        changed_fact_id="partner-a",
        old_value="甲",
        new_value="乙",
        replacement_fact_id="partner-b",
    )

    assert {item.fact_id for item in proposal.direct_invalidations} == {
        "weekend-plan",
        "partner-preference",
    }
    assert {item.fact_id for item in proposal.manual_reviews} == {
        "communication-pattern",
        "attachment-hypothesis",
    }
    assert proposal.applied_mutations == ()
    attachment = next(
        item for item in proposal.manual_reviews if item.fact_id == "attachment-hypothesis"
    )
    assert attachment.path_edge_ids == ("dep-communication", "dep-attachment")
    assert attachment.path_confidence == pytest.approx(0.8 * 0.7 * 0.85)


def test_two_hop_deterministic_path_is_still_manual_review() -> None:
    proposal = DependencyImpactService(
        DependencyRepository(
            (
                DependencyEdge(
                    edge_id="dep-one",
                    dependent_fact_id="middle",
                    prerequisite_fact_id="changed",
                    dependency_type="direct_deterministic",
                    confidence=1.0,
                    source_event_id="source-one",
                    reviewer_id="counselor",
                ),
                DependencyEdge(
                    edge_id="dep-two",
                    dependent_fact_id="indirect",
                    prerequisite_fact_id="middle",
                    dependency_type="direct_deterministic",
                    confidence=1.0,
                    source_event_id="source-two",
                    reviewer_id="counselor",
                ),
            )
        )
    ).preview(changed_fact_id="changed", old_value="old", new_value="new")

    indirect = next(
        item for item in proposal.manual_reviews if item.fact_id == "indirect"
    )
    assert indirect.path_edge_ids == ("dep-one", "dep-two")
    assert indirect.recommended_mutation.operation == "REVIEW"


def test_no_replacement_uses_validity_correct_not_a_seventh_operation() -> None:
    proposal = DependencyImpactService(
        DependencyRepository(
            (
                DependencyEdge(
                    edge_id="dep-one",
                    dependent_fact_id="dependent",
                    prerequisite_fact_id="changed",
                    dependency_type="direct_deterministic",
                    confidence=1.0,
                    source_event_id="source-one",
                    reviewer_id="counselor",
                ),
            )
        )
    ).preview(changed_fact_id="changed", old_value="old", new_value="new")

    recommendation = proposal.direct_invalidations[0].recommended_mutation
    assert recommendation.operation == "CORRECT"
    assert recommendation.correction_kind == "validity"
    assert recommendation.new_validity_status == "invalidated"


def test_high_fanout_dependency_impact_fails_closed_at_expansion_budget() -> None:
    edges = tuple(
        DependencyEdge(
            edge_id=f"fanout-{index:03d}",
            dependent_fact_id=f"dependent-{index:03d}",
            prerequisite_fact_id="root-fact",
            dependency_type="direct_conditional",
            confidence=0.8,
            source_event_id=f"source-{index:03d}",
            reviewer_id="counselor",
        )
        for index in range(20)
    )
    service = DependencyImpactService(
        DependencyRepository(edges),
        max_expansions=10,
    )
    with pytest.raises(
        DependencyImpactBudgetExceeded,
        match="DEPENDENCY_IMPACT_BUDGET_EXCEEDED",
    ):
        service.preview(
            changed_fact_id="root-fact",
            old_value="old",
            new_value="new",
        )
