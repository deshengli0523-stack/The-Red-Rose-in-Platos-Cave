from __future__ import annotations

from datetime import datetime, timezone

import pytest

from consultation_kb.client.bitemporal import BitemporalFactQuery, FactQuery
from consultation_kb.client.graph_query import TemporalGraphQuery
from consultation_kb.client.temporal_graph import TemporalGraphBuilder
from tests.consultation_kb.unit.test_fact_repository import _repository
from tests.consultation_kb.unit.test_fact_schema import _event


pytestmark = [pytest.mark.golden, pytest.mark.acceptance_id("GRAPH-01")]
UTC = timezone.utc


def test_graph_01_client_keeps_parallel_sources_and_filters_time() -> None:
    repository = _repository()
    current = _event(
        event_id="current-edge",
        fact_id="relationship-current",
        canonical_key="current",
        object_json='"partner-a"',
        relation_type="CURRENT_RELATIONSHIP",
        epistemic_status="asserted",
    )
    support = _event(
        event_id="support-edge",
        fact_id="relationship-support",
        canonical_key="support",
        object_json='"partner-a"',
        relation_type="SUPPORTS",
        epistemic_status="asserted",
    )
    repository.append_batch(base_commit_version=0, events=(current, support))
    query = FactQuery(
        effective_at=datetime(2026, 7, 17, tzinfo=UTC),
        known_at=datetime(2026, 7, 17, tzinfo=UTC),
        fixed_epoch=1,
    )
    derived = TemporalGraphBuilder().build(
        BitemporalFactQuery(repository).snapshot(query),
        publication_operation_id="graph-operation",
        runtime_epoch=1,
    )

    assert derived.graph.number_of_edges("来访者", "partner-a") == 2
    edges = TemporalGraphQuery(derived.graph).edges_at(
        effective_at=query.effective_at,
        known_at=query.known_at,
    )
    assert [edge[2] for edge in edges] == ["current-edge", "support-edge"]
