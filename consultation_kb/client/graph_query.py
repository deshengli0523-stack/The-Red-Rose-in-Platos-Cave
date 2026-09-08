"""Source-aware temporal queries for the client MultiDiGraph."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import heapq
import itertools

import networkx as nx


@dataclass(frozen=True, slots=True)
class PathStep:
    source: str
    target: str
    edge_id: str
    fact_id: str
    source_event_ids: tuple[str, ...]
    restrictions: tuple[str, ...]
    cost: float


@dataclass(frozen=True, slots=True)
class WeightedPath:
    total_cost: float
    edge_ids: tuple[str, ...]
    steps: tuple[PathStep, ...]


class PathSearchBudgetExceeded(RuntimeError):
    def __init__(self) -> None:
        super().__init__("CLIENT_GRAPH_PATH_BUDGET_EXCEEDED")


def _as_datetime(value: object) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    raise ValueError("CLIENT_GRAPH_TIME_INVALID")


class TemporalGraphQuery:
    """Bounded uniform-cost temporal paths, independent of upstream queries."""

    def __init__(
        self,
        graph: nx.MultiDiGraph[str, dict[str, object], dict[str, object]],
    ) -> None:
        if not isinstance(graph, nx.MultiDiGraph):
            raise TypeError("TemporalGraphQuery requires MultiDiGraph")
        self._graph = graph

    def edges_at(
        self,
        *,
        effective_at: datetime,
        known_at: datetime,
    ) -> tuple[tuple[str, str, str, dict[str, object]], ...]:
        result: list[tuple[str, str, str, dict[str, object]]] = []
        for source, target, key, attributes in self._graph.edges(keys=True, data=True):
            if attributes.get("review_status") != "approved":
                continue
            if attributes.get("validity_status", "active") not in {"active", "historical"}:
                continue
            if attributes.get("resolution_status", "open") != "open":
                continue
            if _as_datetime(attributes["recorded_at"]) > known_at:
                continue
            if _as_datetime(attributes["approved_at"]) > known_at:
                continue
            if _as_datetime(attributes["effective_from"]) > effective_at:
                continue
            end = attributes.get("effective_to")
            if end is not None and effective_at >= _as_datetime(end):
                continue
            result.append((str(source), str(target), str(key), dict(attributes)))
        return tuple(sorted(result, key=lambda item: (item[0], item[1], item[2])))

    def weighted_paths(
        self,
        source: str,
        target: str,
        *,
        effective_at: datetime,
        known_at: datetime,
        max_hops: int = 4,
        top_k: int = 3,
        max_expansions: int = 10_000,
    ) -> tuple[WeightedPath, ...]:
        if type(max_hops) is not int or not 1 <= max_hops <= 12:
            raise ValueError("max_hops must be between 1 and 12")
        if type(top_k) is not int or not 1 <= top_k <= 20:
            raise ValueError("top_k must be between 1 and 20")
        if type(max_expansions) is not int or not 1 <= max_expansions <= 100_000:
            raise ValueError("max_expansions must be between 1 and 100000")
        allowed = self.edges_at(effective_at=effective_at, known_at=known_at)
        adjacency: dict[str, list[tuple[str, str, dict[str, object]]]] = {}
        for edge_source, edge_target, edge_id, attributes in allowed:
            adjacency.setdefault(edge_source, []).append((edge_target, edge_id, attributes))
        for values in adjacency.values():
            values.sort(key=lambda item: (item[0], item[1]))

        candidates: list[WeightedPath] = []
        sequence = itertools.count()
        queue: list[
            tuple[
                float,
                tuple[str, ...],
                str,
                int,
                tuple[PathStep, ...],
                frozenset[str],
            ]
        ] = [(0.0, (), source, next(sequence), (), frozenset({source}))]
        generated_states = 1
        while queue and len(candidates) < top_k:
            total_cost, edge_ids, current, _ordinal, steps, visited = heapq.heappop(
                queue
            )
            if current == target and steps:
                candidates.append(
                    WeightedPath(
                        total_cost=round(total_cost, 12),
                        edge_ids=edge_ids,
                        steps=steps,
                    )
                )
                continue
            if len(steps) >= max_hops:
                continue
            outgoing = adjacency.get(current, ())
            for edge_target, edge_id, attributes in outgoing:
                if edge_target in visited:
                    continue
                cost = self._edge_cost(attributes)
                raw_source_event_ids = attributes.get("source_event_ids", ())
                source_event_ids = (
                    tuple(str(value) for value in raw_source_event_ids)
                    if isinstance(raw_source_event_ids, (tuple, list))
                    else ()
                )
                step = PathStep(
                    source=current,
                    target=edge_target,
                    edge_id=edge_id,
                    fact_id=str(attributes.get("fact_id", edge_id)),
                    source_event_ids=source_event_ids,
                    restrictions=(
                        f"review={attributes.get('review_status')}",
                        f"epistemic={attributes.get('epistemic_status')}",
                        f"dependency={attributes.get('dependency_type')}",
                    ),
                    cost=cost,
                )
                if generated_states >= max_expansions:
                    raise PathSearchBudgetExceeded
                generated_states += 1
                heapq.heappush(
                    queue,
                    (
                        round(total_cost + cost, 12),
                        (*edge_ids, edge_id),
                        edge_target,
                        next(sequence),
                        (*steps, step),
                        visited | {edge_target},
                    )
                )
        return tuple(candidates)

    def _edge_cost(self, attributes: dict[str, object]) -> float:
        raw_confidence = attributes.get("confidence", 0.0)
        confidence = (
            float(raw_confidence)
            if isinstance(raw_confidence, (str, int, float))
            and not isinstance(raw_confidence, bool)
            else 0.0
        )
        dependency_penalty = {
            "direct_deterministic": 0.0,
            "direct_conditional": 0.35,
            "indirect_inferred": 0.7,
        }.get(str(attributes.get("dependency_type")), 0.5)
        epistemic_penalty = {
            "asserted": 0.0,
            "uncertain": 0.4,
            "disputed": 0.8,
        }.get(str(attributes.get("epistemic_status")), 1.0)
        review_penalty = 0.0 if attributes.get("review_status") == "approved" else 2.0
        return round(1.0 + (1.0 - confidence) + dependency_penalty + epistemic_penalty + review_penalty, 12)


__all__ = [
    "PathSearchBudgetExceeded",
    "PathStep",
    "TemporalGraphQuery",
    "WeightedPath",
]
