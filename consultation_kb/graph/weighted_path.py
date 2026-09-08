"""Bounded k-shortest simple paths over the governed global MultiDiGraph."""

from __future__ import annotations

import heapq
import itertools
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from consultation_kb.graph.global_builder import (
    CanonicalGraph,
    GlobalGraphArtifact,
    verify_global_graph_artifact,
)
from consultation_kb.graph.authority_filter import (
    GraphAuthorityBinding,
    GraphEdgeAuthorityResolver,
    edge_visible_in_snapshot,
)
from consultation_kb.graph.path_cost import (
    EdgeCostBreakdown,
    PathCostContext,
    PathCostPolicy,
)
from consultation_kb.graph.serialization import graph_payload, graph_sha256
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    RetrievalScope,
)


class GlobalGraphPathError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class PathSearchBudgetExceeded(GlobalGraphPathError):
    def __init__(self) -> None:
        super().__init__("GLOBAL_GRAPH_PATH_BUDGET_EXCEEDED")


@dataclass(frozen=True, slots=True)
class EvidencePathStep:
    source_node_ref: VersionRef
    target_node_ref: VersionRef
    relation_ref: VersionRef
    claim_ref: VersionRef
    passage_refs: tuple[VersionRef, ...]
    source_refs: tuple[VersionRef, ...]
    independent_source_ids: tuple[str, ...]
    relation: str
    source_grade: str
    truth_type: str
    statement_text_sha256: str
    independent_source_count: int
    restrictions: tuple[str, ...]
    cost: EdgeCostBreakdown


@dataclass(frozen=True, slots=True)
class EvidencePath:
    total_cost: float
    cost_breakdown: Mapping[str, float]
    node_refs: tuple[VersionRef, ...]
    edge_refs: tuple[VersionRef, ...]
    edge_ids: tuple[str, ...]
    steps: tuple[EvidencePathStep, ...]
    contains_support: bool
    contains_contradiction: bool
    source_limits: Mapping[str, int]
    graph_version: VersionRef
    authority_binding: GraphAuthorityBinding


def _node_ref(graph: CanonicalGraph, node: str) -> VersionRef:
    value = graph.nodes[node].get("reference")
    if not isinstance(value, VersionRef):
        raise GlobalGraphPathError("GLOBAL_GRAPH_NODE_AUTHORITY_INVALID")
    return value


def _step(
    graph: CanonicalGraph,
    source: str,
    target: str,
    attributes: Mapping[str, object],
    cost: EdgeCostBreakdown,
) -> EvidencePathStep:
    relation_ref = attributes["relation_ref"]
    claim_ref = attributes["claim_ref"]
    passage_refs = attributes["passage_refs"]
    source_refs = attributes.get("source_refs", ())
    independent_source_ids = attributes.get("independent_source_ids")
    if (
        not isinstance(relation_ref, VersionRef)
        or not isinstance(claim_ref, VersionRef)
        or not isinstance(passage_refs, tuple)
        or not passage_refs
        or any(not isinstance(value, VersionRef) for value in passage_refs)
        or not isinstance(source_refs, tuple)
        or any(not isinstance(value, VersionRef) for value in source_refs)
        or not isinstance(independent_source_ids, tuple)
        or not independent_source_ids
        or any(
            not isinstance(value, str) or not value
            for value in independent_source_ids
        )
    ):
        raise GlobalGraphPathError("GLOBAL_GRAPH_EDGE_AUTHORITY_INVALID")
    independent_sources = attributes["independent_source_count"]
    assert isinstance(independent_sources, int) and not isinstance(
        independent_sources, bool
    )
    if len(set(independent_source_ids)) != independent_sources:
        raise GlobalGraphPathError("GLOBAL_GRAPH_EDGE_AUTHORITY_INVALID")
    allowed_uses = attributes.get("allowed_uses")
    if not isinstance(allowed_uses, tuple | list | set | frozenset):
        raise GlobalGraphPathError("GLOBAL_GRAPH_EDGE_AUTHORITY_INVALID")
    return EvidencePathStep(
        source_node_ref=_node_ref(graph, source),
        target_node_ref=_node_ref(graph, target),
        relation_ref=relation_ref,
        claim_ref=claim_ref,
        passage_refs=passage_refs,
        source_refs=source_refs,
        independent_source_ids=tuple(sorted(set(independent_source_ids))),
        relation=str(attributes["relation"]),
        source_grade=str(attributes["source_grade"]),
        truth_type=str(attributes.get("truth_type", "unknown")),
        statement_text_sha256=str(attributes.get("statement_text_sha256", "")),
        independent_source_count=independent_sources,
        restrictions=(
            f"review={attributes['review_status']}",
            f"effective_to={attributes.get('effective_to')}",
            f"allowed_uses={','.join(str(value) for value in allowed_uses)}",
            f"independent_sources={independent_sources}",
        ),
        cost=cost,
    )


class WeightedPathQuery:
    """Uniform-cost enumeration with explicit expansion and result budgets."""

    def __init__(
        self,
        artifact: GlobalGraphArtifact,
        *,
        graph_version: VersionRef,
        edge_authority_resolver: GraphEdgeAuthorityResolver,
        policy: PathCostPolicy | None = None,
    ) -> None:
        verify_global_graph_artifact(artifact)
        exact_version = VersionRef.model_validate(graph_version)
        graph_version_kind = exact_version.object_id.rsplit("_", maxsplit=1)[0]
        if graph_version_kind != "global_graph":
            raise GlobalGraphPathError("GLOBAL_GRAPH_VERSION_IDENTITY_INVALID")
        recomputed_sha256 = graph_sha256(graph_payload(artifact))
        metadata = artifact.graph.graph
        if (
            recomputed_sha256 != artifact.canonical_sha256
            or exact_version.content_sha256 != artifact.canonical_sha256
            or metadata.get("source_catalog_version")
            != artifact.source_catalog_version
            or metadata.get("source_runtime_epoch") != artifact.source_runtime_epoch
            or metadata.get("effective_at") != artifact.effective_at
            or metadata.get("builder_policy_version")
            != artifact.builder_policy_version
        ):
            raise GlobalGraphPathError("GLOBAL_GRAPH_ARTIFACT_BINDING_INVALID")
        self._graph = artifact.graph
        self._artifact = artifact
        self._graph_version = exact_version
        self._edge_authority = edge_authority_resolver
        self._effective_at = artifact.effective_at
        self._policy = policy if policy is not None else PathCostPolicy()

    def search(
        self,
        source: str,
        target: str,
        *,
        context: PathCostContext,
        authority_snapshot: AuthoritativeFilterSnapshot,
        scope: RetrievalScope | None = None,
        edge_authority_binding: GraphAuthorityBinding | None = None,
        max_hops: int = 4,
        top_k: int = 3,
        max_expansions: int = 10_000,
        max_candidates: int = 100,
    ) -> tuple[EvidencePath, ...]:
        if scope is None or edge_authority_binding is None:
            raise GlobalGraphPathError(
                "GLOBAL_GRAPH_EDGE_AUTHORITY_BINDING_REQUIRED"
            )
        self._edge_authority.assert_binding_current(
            edge_authority_binding,
            self._artifact,
            scope=scope,
            authority_snapshot=authority_snapshot,
            required_use=context.required_use,
            graph_root_ref=edge_authority_binding.graph_root_ref,
            graph_version=self._graph_version,
        )
        authority_binding = edge_authority_binding
        if context.effective_at != scope.effective_at:
            raise GlobalGraphPathError("GLOBAL_GRAPH_CONTEXT_EPOCH_MISMATCH")
        if source not in self._graph or target not in self._graph:
            return ()
        if type(max_hops) is not int or not 1 <= max_hops <= 12:
            raise ValueError("max_hops must be between 1 and 12")
        if type(top_k) is not int or not 1 <= top_k <= 20:
            raise ValueError("top_k must be between 1 and 20")
        if type(max_expansions) is not int or not 1 <= max_expansions <= 100_000:
            raise ValueError("max_expansions must be between 1 and 100000")
        if type(max_candidates) is not int or not top_k <= max_candidates <= 10_000:
            raise ValueError("max_candidates must be between top_k and 10000")
        adjacency: dict[str, list[tuple[str, str, dict[str, object]]]] = {}
        for edge_source, edge_target, edge_id, attributes in sorted(
            self._graph.edges(keys=True, data=True),
            key=lambda item: (str(item[0]), str(item[1]), str(item[2])),
        ):
            if not edge_visible_in_snapshot(
                attributes,
                authority_snapshot,
                required_use=context.required_use,
                effective_at=scope.effective_at,
                known_at=scope.known_at,
            ) or not self._edge_authority.relation_allowed(
                attributes,
                authority_binding,
            ):
                continue
            adjacency.setdefault(str(edge_source), []).append(
                (str(edge_target), str(edge_id), dict(attributes))
            )

        sequence = itertools.count()
        queue: list[
            tuple[
                float,
                tuple[str, ...],
                str,
                int,
                tuple[str, ...],
                tuple[EvidencePathStep, ...],
                tuple[tuple[str, float], ...],
                frozenset[str],
            ]
        ] = [
            (
                0.0,
                (),
                source,
                next(sequence),
                (source,),
                (),
                (),
                frozenset({source}),
            )
        ]
        generated_states = 1
        completed_candidates = 0
        results: list[EvidencePath] = []
        while queue and len(results) < top_k:
            (
                total_cost,
                edge_ids,
                current,
                _ordinal,
                node_ids,
                steps,
                raw_breakdown,
                visited,
            ) = heapq.heappop(queue)
            if current == target and steps:
                completed_candidates += 1
                if completed_candidates > max_candidates:
                    raise PathSearchBudgetExceeded
                breakdown = dict(raw_breakdown)
                sources = {
                    value
                    for step in steps
                    for value in step.independent_source_ids
                }
                results.append(
                    EvidencePath(
                        total_cost=round(total_cost, 12),
                        cost_breakdown=MappingProxyType(
                            {key: round(value, 12) for key, value in breakdown.items()}
                        ),
                        node_refs=tuple(_node_ref(self._graph, node) for node in node_ids),
                        edge_refs=tuple(step.relation_ref for step in steps),
                        edge_ids=edge_ids,
                        steps=steps,
                        contains_support=any(
                            step.relation == "SUPPORTS" for step in steps
                        ),
                        contains_contradiction=any(
                            step.relation == "CONTRADICTS" for step in steps
                        ),
                        source_limits=MappingProxyType(
                            {
                                "independent_source_count": len(sources),
                                "minimum_independent_sources": min(
                                    step.independent_source_count for step in steps
                                ),
                            }
                        ),
                        graph_version=self._graph_version,
                        authority_binding=authority_binding,
                    )
                )
                continue
            if len(steps) >= max_hops:
                continue
            for edge_target, edge_id, attributes in adjacency.get(current, ()):
                if edge_target in visited:
                    continue
                cost = self._policy.evaluate(attributes, context)
                if cost is None:
                    continue
                if generated_states >= max_expansions:
                    raise PathSearchBudgetExceeded
                generated_states += 1
                step = _step(self._graph, current, edge_target, attributes, cost)
                combined = dict(raw_breakdown)
                for key, value in cost.components.items():
                    combined[key] = combined.get(key, 0.0) + value
                heapq.heappush(
                    queue,
                    (
                        round(total_cost + cost.total, 12),
                        (*edge_ids, edge_id),
                        edge_target,
                        next(sequence),
                        (*node_ids, edge_target),
                        (*steps, step),
                        tuple(sorted(combined.items())),
                        visited | {edge_target},
                    ),
                )
        return tuple(results)


__all__ = [
    "EvidencePath",
    "EvidencePathStep",
    "GlobalGraphPathError",
    "PathSearchBudgetExceeded",
    "WeightedPathQuery",
]
