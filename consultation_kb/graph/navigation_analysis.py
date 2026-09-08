"""Consultation-owned structural navigation over already-filtered graph data."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

import networkx as nx

from consultation_kb.graph.authority_filter import (
    GraphAuthorityBinding,
    GraphEdgeAuthorityResolver,
    edge_visible_in_snapshot,
)
from consultation_kb.graph.global_builder import (
    CanonicalGraph,
    GlobalGraphArtifact,
    verify_global_graph_artifact,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    RetrievalScope,
)


@dataclass(frozen=True, slots=True)
class NavigationHint:
    kind: str
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    claim_refs: tuple[VersionRef, ...]
    passage_refs: tuple[VersionRef, ...]
    score: float
    question: str


@dataclass(frozen=True, slots=True)
class StructuralAnalysis:
    hints: tuple[NavigationHint, ...]
    eligible_edge_count: int
    excluded_orphan_edge_count: int
    authority_binding: GraphAuthorityBinding


def _ref_identity(value: VersionRef) -> str:
    return f"{value.object_id}@{value.version}:{value.content_sha256}"


class StructuralNavigationAnalyzer:
    """Find navigational signals without treating topology as evidence."""

    def __init__(
        self,
        *,
        edge_authority_resolver: GraphEdgeAuthorityResolver,
        max_hints: int = 25,
    ) -> None:
        if type(max_hints) is not int or not 1 <= max_hints <= 500:
            raise ValueError("max_hints must be between 1 and 500")
        self._max_hints = max_hints
        self._edge_authority = edge_authority_resolver

    def analyze(
        self,
        artifact: GlobalGraphArtifact,
        *,
        authority_snapshot: AuthoritativeFilterSnapshot,
        scope: RetrievalScope | None = None,
        edge_authority_binding: GraphAuthorityBinding | None = None,
    ) -> StructuralAnalysis:
        verify_global_graph_artifact(artifact)
        if scope is None or edge_authority_binding is None:
            raise ValueError("GLOBAL_GRAPH_EDGE_AUTHORITY_BINDING_REQUIRED")
        self._edge_authority.assert_binding_current(
            edge_authority_binding,
            artifact,
            scope=scope,
            authority_snapshot=authority_snapshot,
            required_use="consultation",
            graph_root_ref=edge_authority_binding.graph_root_ref,
            graph_version=edge_authority_binding.graph_version,
        )
        authority_binding = edge_authority_binding
        graph = artifact.graph
        eligible: list[tuple[str, str, str, dict[str, object]]] = []
        excluded = 0
        for source, target, key, raw_attributes in sorted(
            graph.edges(keys=True, data=True),
            key=lambda item: (str(item[0]), str(item[1]), str(item[2])),
        ):
            attributes = dict(raw_attributes)
            claim = attributes.get("claim_ref")
            passages = attributes.get("passage_refs")
            if (
                not isinstance(claim, VersionRef)
                or not isinstance(passages, tuple | list)
                or not passages
                or attributes.get("review_status") != "approved"
                or attributes.get("passage_review_status") != "approved"
                or attributes.get("authorized") is not True
                or attributes.get("tombstoned") is not False
                or not edge_visible_in_snapshot(
                    attributes,
                    authority_snapshot,
                    required_use="consultation",
                    effective_at=scope.effective_at,
                    known_at=scope.known_at,
                )
                or not self._edge_authority.relation_allowed(
                    attributes,
                    authority_binding,
                )
            ):
                excluded += 1
                continue
            if any(not isinstance(value, VersionRef) for value in passages):
                excluded += 1
                continue
            eligible.append((str(source), str(target), str(key), attributes))

        filtered: CanonicalGraph = nx.MultiDiGraph()
        for source, target, key, attributes in eligible:
            filtered.add_edge(source, target, key=key, **attributes)
        simple: nx.Graph[str] = nx.Graph()
        simple.add_nodes_from(sorted(filtered.nodes))
        simple_edges: set[tuple[str, str]] = set()
        for source, target, _key, _attributes in eligible:
            first, second = sorted((source, target))
            simple_edges.add((first, second))
        simple.add_edges_from(sorted(simple_edges))

        hints: list[NavigationHint] = []
        bridge_pairs: set[tuple[str, str]] = set()
        if simple.number_of_edges():
            bridges = cast(Iterable[tuple[str, str]], nx.bridges(simple))
            for source, target in bridges:
                bridge_pairs.add((str(source), str(target)))
                bridge_pairs.add((str(target), str(source)))
        # Query-time communities are recomputed from the already authorized
        # simple graph.  Raw or stale external community maps are never an
        # input to navigation and therefore cannot reintroduce revoked edges.
        computed_communities = (
            tuple(nx.community.greedy_modularity_communities(simple))
            if simple.number_of_edges()
            else ()
        )
        ordered_communities = sorted(
            (tuple(sorted(str(node) for node in values)) for values in computed_communities),
            key=lambda values: values,
        )
        community_by_node = {
            node: community_id
            for community_id, nodes in enumerate(ordered_communities)
            for node in nodes
        }

        for source, target, key, attributes in eligible:
            relation = str(attributes.get("relation", "RELATED_TO"))
            kinds: list[str] = []
            if (source, target) in bridge_pairs:
                kinds.append("bridge")
            if relation in {"ANALOGOUS_TO", "CONTRADICTS", "DISTINCT_FROM"}:
                kinds.append("surprising_connection")
            if (
                source in community_by_node
                and target in community_by_node
                and community_by_node[source] != community_by_node[target]
            ):
                kinds.append("cross_community")
            if not kinds:
                kinds.append("navigation_question")
            raw_passages = attributes["passage_refs"]
            assert isinstance(raw_passages, tuple | list)
            claim = attributes["claim_ref"]
            assert isinstance(claim, VersionRef)
            claim_refs = (claim,)
            passage_refs = tuple(raw_passages)
            confidence = attributes.get("confidence", 0.0)
            score = (
                float(confidence)
                if isinstance(confidence, int | float) and not isinstance(confidence, bool)
                else 0.0
            )
            for kind in kinds:
                hints.append(
                    NavigationHint(
                        kind=kind,
                        node_ids=(source, target),
                        edge_ids=(key,),
                        claim_refs=claim_refs,
                        passage_refs=passage_refs,
                        score=round(score, 12),
                        question=(
                            f"inspect:{kind}:{source}:{target}:"
                            f"{_ref_identity(claim)}"
                        ),
                    )
                )

        # High-degree nodes are useful only when an incident governed edge can
        # carry the hint back to evidence.
        for node, degree in sorted(
            simple.degree,
            key=lambda item: (-int(item[1]), str(item[0])),
        ):
            if degree < 2:
                continue
            incident = sorted(
                (
                    *filtered.in_edges(node, keys=True, data=True),
                    *filtered.out_edges(node, keys=True, data=True),
                ),
                key=lambda item: (str(item[0]), str(item[1]), str(item[2])),
            )
            if not incident:
                continue
            source, target, key, attributes = incident[0]
            claim = attributes["claim_ref"]
            passages = attributes["passage_refs"]
            assert isinstance(claim, VersionRef)
            assert isinstance(passages, tuple | list)
            hints.append(
                NavigationHint(
                    kind="high_degree",
                    node_ids=(str(node),),
                    edge_ids=(str(key),),
                    claim_refs=(claim,),
                    passage_refs=tuple(passages),
                    score=float(degree),
                    question=f"inspect:high_degree:{node}:{_ref_identity(claim)}",
                )
            )

        hints.sort(
            key=lambda hint: (
                -hint.score,
                hint.kind,
                hint.node_ids,
                hint.edge_ids,
            )
        )
        return StructuralAnalysis(
            hints=tuple(hints[: self._max_hints]),
            eligible_edge_count=len(eligible),
            excluded_orphan_edge_count=excluded,
            authority_binding=authority_binding,
        )


__all__ = [
    "NavigationHint",
    "StructuralAnalysis",
    "StructuralNavigationAnalyzer",
]
