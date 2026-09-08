from __future__ import annotations

from datetime import datetime, timezone

import networkx as nx
import pytest

from consultation_kb.client.graph_query import (
    PathSearchBudgetExceeded,
    TemporalGraphQuery,
)


UTC = timezone.utc


def _edge(graph: nx.MultiDiGraph, source: str, target: str, key: str, **extra: object) -> None:
    graph.add_edge(
        source,
        target,
        key=key,
        edge_id=key,
        review_status="approved",
        epistemic_status="asserted",
        dependency_type="direct_deterministic",
        confidence=extra.pop("confidence", 0.9),
        effective_from=datetime(2026, 1, 1, tzinfo=UTC),
        effective_to=None,
        recorded_at=datetime(2026, 1, 1, tzinfo=UTC),
        approved_at=datetime(2026, 1, 1, tzinfo=UTC),
        fact_id=key,
        source_event_ids=(key,),
        **extra,
    )


def test_weighted_paths_are_source_aware_deterministic_and_hop_bounded() -> None:
    graph = nx.MultiDiGraph()
    _edge(graph, "client", "middle", "edge-a", confidence=0.95)
    _edge(graph, "client", "middle", "edge-b", confidence=0.5)
    _edge(graph, "middle", "goal", "edge-c", confidence=0.9)
    _edge(graph, "goal", "client", "cycle", confidence=1.0)
    service = TemporalGraphQuery(graph)

    paths = service.weighted_paths(
        "client",
        "goal",
        effective_at=datetime(2026, 7, 17, tzinfo=UTC),
        known_at=datetime(2026, 7, 17, tzinfo=UTC),
        max_hops=2,
        top_k=2,
    )

    assert [path.edge_ids for path in paths] == [
        ("edge-a", "edge-c"),
        ("edge-b", "edge-c"),
    ]
    assert all(len(path.edge_ids) <= 2 for path in paths)


def test_uniform_cost_stops_after_top_k_without_enumerating_branching_graph() -> None:
    graph = nx.MultiDiGraph()
    _edge(graph, "source", "target", "cheap", confidence=1.0)
    for branch in range(20):
        first = f"branch-{branch}"
        _edge(graph, "source", first, f"expensive-{branch}", confidence=0.0)
        previous = first
        for depth in range(1, 7):
            current = f"branch-{branch}-{depth}"
            _edge(
                graph,
                previous,
                current,
                f"edge-{branch}-{depth}",
                confidence=0.0,
            )
            previous = current
        _edge(graph, previous, "target", f"tail-{branch}", confidence=0.0)

    class CountingQuery(TemporalGraphQuery):
        def __init__(self, value: nx.MultiDiGraph) -> None:
            super().__init__(value)
            self.cost_calls = 0

        def _edge_cost(self, attributes: dict[str, object]) -> float:
            self.cost_calls += 1
            return super()._edge_cost(attributes)

    service = CountingQuery(graph)
    paths = service.weighted_paths(
        "source",
        "target",
        effective_at=datetime(2026, 7, 17, tzinfo=UTC),
        known_at=datetime(2026, 7, 17, tzinfo=UTC),
        max_hops=12,
        top_k=1,
        max_expansions=30,
    )

    assert [path.edge_ids for path in paths] == [("cheap",)]
    assert service.cost_calls == 21

    with pytest.raises(
        PathSearchBudgetExceeded,
        match="CLIENT_GRAPH_PATH_BUDGET_EXCEEDED",
    ):
        service.weighted_paths(
            "source",
            "target",
            effective_at=datetime(2026, 7, 17, tzinfo=UTC),
            known_at=datetime(2026, 7, 17, tzinfo=UTC),
            max_hops=12,
            top_k=1,
            max_expansions=10,
        )
