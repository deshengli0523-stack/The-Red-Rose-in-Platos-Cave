from __future__ import annotations

from datetime import datetime, timezone

from consultation_kb.client.bitemporal import BitemporalFactQuery, FactQuery
from consultation_kb.client.temporal_graph import TemporalGraphBuilder
from tests.consultation_kb.unit.test_fact_repository import _repository
from tests.consultation_kb.unit.test_fact_schema import _event


UTC = timezone.utc


def test_next_session_graph_excludes_private_session_and_disallowed_purpose() -> None:
    repository = _repository()
    repository.append_batch(
        base_commit_version=0,
        events=(
            _event(event_id="allowed", fact_id="allowed", object_json='"allowed"'),
            _event(
                event_id="session-private",
                fact_id="session-private",
                object_json='"session-secret"',
                privacy_level="private_session",
            ),
            _event(
                event_id="case-only",
                fact_id="case-only",
                object_json='"case-secret"',
                allowed_purposes_json='["case_archive"]',
            ),
        ),
    )
    snapshot = BitemporalFactQuery(repository).snapshot(
        FactQuery(
            effective_at=datetime(2026, 7, 17, tzinfo=UTC),
            known_at=datetime(2026, 7, 17, tzinfo=UTC),
            fixed_epoch=1,
        )
    )
    graph = TemporalGraphBuilder().build(
        snapshot,
        publication_operation_id="privacy-publication",
        runtime_epoch=1,
    ).graph
    assert "allowed" in graph
    assert "session-secret" not in graph
    assert "case-secret" not in graph


def test_multidigraph_preserves_parallel_sources_and_temporal_edges() -> None:
    repository = _repository()
    source_a = _event(
        event_id="source-a",
        fact_id="source-fact-a",
        canonical_key="source-a",
        object_json='"evidence-a"',
        relation_type="SUPPORTS",
    )
    source_b = _event(
        event_id="source-b",
        fact_id="source-fact-b",
        canonical_key="source-b",
        object_json='"evidence-b"',
        relation_type="SUPPORTS",
    )
    first = _event(
        event_id="event-1",
        fact_id="relationship-1",
        canonical_key="relationship-1",
        object_json='"partner-a"',
        relation_type="CURRENT_RELATIONSHIP",
        source_event_ids=("source-a",),
    )
    second = _event(
        event_id="event-2",
        fact_id="relationship-2",
        canonical_key="relationship-2",
        object_json='"partner-a"',
        relation_type="SUPPORTS",
        source_event_ids=("source-b",),
    )
    repository.append_batch(
        base_commit_version=0,
        events=(source_a, source_b, first, second),
    )
    query = FactQuery(
        effective_at=datetime(2026, 7, 17, tzinfo=UTC),
        known_at=datetime(2026, 7, 17, tzinfo=UTC),
        fixed_epoch=1,
    )
    snapshot = BitemporalFactQuery(repository).snapshot(query)
    graph = TemporalGraphBuilder().build(
        snapshot,
        publication_operation_id="publication-1",
        runtime_epoch=1,
    )

    assert graph.graph.number_of_edges("来访者", "partner-a") == 2
    assert set(graph.graph["来访者"]["partner-a"]) == {"event-1", "event-2"}
