"""Dependency propagation that produces proposals but never applies mutations."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass

from consultation_kb.models.dependencies import (
    DependencyEdge,
    ImpactItem,
    ImpactProposal,
    RecommendedImpactMutation,
)


class DependencyImpactBudgetExceeded(RuntimeError):
    def __init__(self) -> None:
        super().__init__("DEPENDENCY_IMPACT_BUDGET_EXCEEDED")


class DependencyRepository:
    """Deterministic dependency reader over an immutable edge set."""

    def __init__(self, edges: Iterable[DependencyEdge]) -> None:
        validated = tuple(DependencyEdge.model_validate(edge) for edge in edges)
        if len({edge.edge_id for edge in validated}) != len(validated):
            raise ValueError("dependency edge IDs must be unique")
        self._edges = tuple(sorted(validated, key=lambda edge: edge.edge_id))

    def dependents_of(self, prerequisite_fact_id: str) -> tuple[DependencyEdge, ...]:
        return tuple(
            edge
            for edge in self._edges
            if edge.prerequisite_fact_id == prerequisite_fact_id
        )

    def all_edges(self) -> tuple[DependencyEdge, ...]:
        return self._edges


@dataclass(frozen=True, slots=True)
class _Path:
    fact_id: str
    edges: tuple[DependencyEdge, ...]

    @property
    def confidence(self) -> float:
        product = 1.0
        inferred_hops = 0
        for edge in self.edges:
            product *= edge.confidence
            if edge.dependency_type == "indirect_inferred":
                inferred_hops += 1
        return product * (0.85**inferred_hops)

    @property
    def edge_ids(self) -> tuple[str, ...]:
        return tuple(edge.edge_id for edge in self.edges)

    @property
    def deterministic(self) -> bool:
        return (
            len(self.edges) == 1
            and self.edges[0].dependency_type == "direct_deterministic"
        )


class DependencyImpactService:
    POLICY_VERSION = "dependency-impact.v1"

    def __init__(
        self,
        repository: DependencyRepository,
        *,
        max_hops: int = 8,
        max_expansions: int = 10_000,
    ) -> None:
        if type(max_hops) is not int or max_hops <= 0:
            raise ValueError("max_hops must be a positive integer")
        if (
            type(max_expansions) is not int
            or not 1 <= max_expansions <= 100_000
        ):
            raise ValueError("max_expansions must be between 1 and 100000")
        self._repository = repository
        self._max_hops = max_hops
        self._max_expansions = max_expansions

    def preview(
        self,
        *,
        changed_fact_id: str,
        old_value: str,
        new_value: str,
        replacement_fact_id: str | None = None,
    ) -> ImpactProposal:
        queue: deque[_Path] = deque((_Path(changed_fact_id, ()),))
        best: dict[str, _Path] = {}
        generated_states = 1
        while queue:
            current = queue.popleft()
            if len(current.edges) >= self._max_hops:
                continue
            visited_facts = {changed_fact_id}
            visited_facts.update(edge.dependent_fact_id for edge in current.edges)
            for edge in self._repository.dependents_of(current.fact_id):
                if edge.dependent_fact_id in visited_facts:
                    continue
                if generated_states >= self._max_expansions:
                    raise DependencyImpactBudgetExceeded
                generated_states += 1
                candidate = _Path(edge.dependent_fact_id, (*current.edges, edge))
                previous = best.get(candidate.fact_id)
                if previous is None or self._rank(candidate) < self._rank(previous):
                    best[candidate.fact_id] = candidate
                    queue.append(candidate)

        direct: list[ImpactItem] = []
        reviews: list[ImpactItem] = []
        for fact_id, path in sorted(best.items()):
            confidence = min(1.0, max(0.0, path.confidence))
            if path.deterministic:
                direct.append(
                    ImpactItem(
                        fact_id=fact_id,
                        path_edge_ids=path.edge_ids,
                        path_confidence=confidence,
                        classification="direct_invalidation",
                        recommended_mutation=(
                            RecommendedImpactMutation(operation="SUPERSEDE")
                            if replacement_fact_id is not None
                            else RecommendedImpactMutation(
                                operation="CORRECT",
                                correction_kind="validity",
                                new_validity_status="invalidated",
                            )
                        ),
                        reason=(
                            "direct deterministic dependency changed; preserve the old fact "
                            "as history and require counselor approval"
                        ),
                    )
                )
            else:
                reviews.append(
                    ImpactItem(
                        fact_id=fact_id,
                        path_edge_ids=path.edge_ids,
                        path_confidence=confidence,
                        classification="manual_review",
                        recommended_mutation=RecommendedImpactMutation(
                            operation="REVIEW"
                        ),
                        reason=(
                            "conditional or inferred dependency changed; retain the fact and "
                            "route it to manual review"
                        ),
                    )
                )
        return ImpactProposal(
            changed_fact_id=changed_fact_id,
            old_value=old_value,
            new_value=new_value,
            direct_invalidations=tuple(direct),
            manual_reviews=tuple(reviews),
            applied_mutations=(),
        )

    @staticmethod
    def _rank(path: _Path) -> tuple[float, int, tuple[str, ...]]:
        return (-path.confidence, len(path.edges), path.edge_ids)


__all__ = [
    "DependencyImpactBudgetExceeded",
    "DependencyImpactService",
    "DependencyRepository",
]
