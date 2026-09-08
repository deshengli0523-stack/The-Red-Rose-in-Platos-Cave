from __future__ import annotations

from datetime import datetime, timezone

import pytest

from consultation_kb.client.bitemporal import BitemporalFactQuery, FactQuery
from consultation_kb.client.dependencies import DependencyImpactService, DependencyRepository
from consultation_kb.client.graph_query import TemporalGraphQuery
from consultation_kb.client.mutations import ApprovedMutation, FactMutationService
from consultation_kb.client.profile import ProfileMaterializer
from consultation_kb.client.temporal_graph import TemporalGraphBuilder
from consultation_kb.models.dependencies import DependencyEdge
from consultation_kb.models.facts import SupersedeMutation
from tests.consultation_kb.unit.test_fact_repository import _repository
from tests.consultation_kb.unit.test_fact_schema import _event


pytestmark = pytest.mark.integration
UTC = timezone.utc


def _at(day: int) -> datetime:
    return datetime(2026, 7, day, 12, tzinfo=UTC)


def test_partner_change_updates_current_profile_graph_and_only_proposes_impacts() -> None:
    repository = _repository()
    partner_a = _event(
        event_id="partner-a-event",
        fact_id="partner-a-fact",
        canonical_key="partner-a",
        object_json='"甲"',
        relation_type="CURRENT_RELATIONSHIP",
        effective_from=_at(1),
        recorded_at=_at(2),
        approved_at=_at(2),
        reported_at=_at(2),
        epistemic_status="asserted",
    )
    weekend = _event(
        event_id="weekend-event",
        fact_id="weekend-fact",
        canonical_key="weekend",
        predicate="weekend_plan",
        object_json='"与甲出行"',
        effective_from=_at(1),
        recorded_at=_at(2),
        approved_at=_at(2),
        reported_at=_at(2),
        epistemic_status="asserted",
    )
    communication = _event(
        event_id="communication-event",
        fact_id="communication-fact",
        canonical_key="communication",
        predicate="communication_pattern",
        object_json='"冲突时沉默"',
        cognitive_type="hypothesis",
        source_kind="session_derived",
        effective_from=_at(1),
        recorded_at=_at(2),
        approved_at=_at(2),
        reported_at=_at(2),
    )
    dependencies = (
        DependencyEdge(
            edge_id="dep-weekend",
            dependent_fact_id="weekend-fact",
            prerequisite_fact_id="partner-a-fact",
            dependency_type="direct_deterministic",
            confidence=1.0,
            source_event_id="weekend-event",
            reviewer_id="counselor",
        ),
        DependencyEdge(
            edge_id="dep-communication",
            dependent_fact_id="communication-fact",
            prerequisite_fact_id="partner-a-fact",
            dependency_type="direct_conditional",
            confidence=0.8,
            source_event_id="communication-event",
            reviewer_id="counselor",
        ),
    )
    repository.append_batch(
        base_commit_version=0,
        events=(partner_a, weekend, communication),
    )
    v1_query = FactQuery(effective_at=_at(10), known_at=_at(10), fixed_epoch=1)
    v1_snapshot = BitemporalFactQuery(repository).snapshot(v1_query)
    v1_profile = ProfileMaterializer().build(v1_snapshot)
    v1_graph = TemporalGraphBuilder().build(
        v1_snapshot,
        publication_operation_id="profile-v1",
        runtime_epoch=1,
        dependencies=dependencies,
    )
    assert any('"甲"' == item.object_json for section in v1_profile.sections for item in section.items)
    assert TemporalGraphQuery(v1_graph.graph).edges_at(
        effective_at=_at(10), known_at=_at(10)
    )

    partner_b = _event(
        event_id="partner-b-event",
        fact_id="partner-b-fact",
        canonical_key="partner-b",
        object_json='"乙"',
        relation_type="CURRENT_RELATIONSHIP",
        effective_from=_at(1),
        recorded_at=_at(16),
        approved_at=_at(16),
        reported_at=_at(16),
        commit_version=2,
        visible_runtime_epoch=2,
        epistemic_status="asserted",
    )
    mutation = SupersedeMutation(
        target_event_id="partner-a-event",
        replacement=partner_b,
        effective_at=_at(1),
        reason="7月16日获准知晓7月1日已分手并有现伴侣乙",
    )
    mutation_service = FactMutationService(repository)
    preview = mutation_service.preview(mutation)
    impact = DependencyImpactService(DependencyRepository(dependencies)).preview(
        changed_fact_id="partner-a-fact",
        old_value="甲",
        new_value="乙",
        replacement_fact_id="partner-b-fact",
    )
    assert [item.fact_id for item in impact.direct_invalidations] == ["weekend-fact"]
    assert [item.fact_id for item in impact.manual_reviews] == ["communication-fact"]
    assert impact.applied_mutations == ()

    mutation_service.commit(
        preview,
        ApprovedMutation(
            preview_sha256=preview.preview_sha256,
            approval_operation_id="profile-v2",
            runtime_epoch=2,
            source="unit_test",
            approved_at=_at(16),
        ),
    )
    v2_query = FactQuery(effective_at=_at(17), known_at=_at(17), fixed_epoch=2)
    v2_snapshot = BitemporalFactQuery(repository).snapshot(v2_query)
    v2_profile = ProfileMaterializer().build(v2_snapshot)
    relationship_values = [
        item.object_json
        for section in v2_profile.sections
        for item in section.items
        if item.predicate == "current_partner"
    ]
    assert relationship_values == ['"乙"']
    v2_graph = TemporalGraphBuilder().build(
        v2_snapshot,
        publication_operation_id="profile-v2",
        runtime_epoch=2,
        dependencies=dependencies,
    )
    current_edges = TemporalGraphQuery(v2_graph.graph).edges_at(
        effective_at=_at(17), known_at=_at(17)
    )
    assert any(target == "乙" for _source, target, _key, _attrs in current_edges)
    assert all(target != "甲" for _source, target, _key, _attrs in current_edges)

    assert not any(
        attrs["relation_type"] == "DEPENDS_ON"
        for _source, _target, _key, attrs in current_edges
    )
    historical_snapshot = BitemporalFactQuery(repository).snapshot(
        FactQuery(effective_at=_at(1), known_at=_at(10), fixed_epoch=2)
    )
    historical_graph = TemporalGraphBuilder().build(
        historical_snapshot,
        publication_operation_id="profile-v2-history",
        runtime_epoch=2,
        dependencies=dependencies,
    )
    assert {
        key
        for _source, _target, key, attrs in TemporalGraphQuery(
            historical_graph.graph
        ).edges_at(effective_at=_at(1), known_at=_at(10))
        if attrs["relation_type"] == "DEPENDS_ON"
    } == {"dep-weekend", "dep-communication"}

    historical = BitemporalFactQuery(repository).execute(
        FactQuery(effective_at=_at(1), known_at=_at(10), fixed_epoch=2)
    )
    assert any(event.object_json == '"甲"' for event in historical)
