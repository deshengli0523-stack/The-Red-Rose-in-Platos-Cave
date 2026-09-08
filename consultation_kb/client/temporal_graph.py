"""Build the client-private temporal MultiDiGraph from one fact snapshot."""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from consultation_kb.client.bitemporal import BitemporalSnapshot
from consultation_kb.client.graph_serialization import graph_payload, graph_sha256
from consultation_kb.models.dependencies import DependencyEdge
from consultation_kb.models.facts import canonical_json


@dataclass(frozen=True, slots=True)
class TemporalGraphSnapshot:
    graph: nx.MultiDiGraph[str, dict[str, object], dict[str, object]]
    publication_operation_id: str
    source_client_commit_version: int
    runtime_epoch: int
    builder_policy_version: str
    canonical_sha256: str


class TemporalGraphBuilder:
    POLICY_VERSION = "client-temporal-graph.v1"

    def build(
        self,
        snapshot: BitemporalSnapshot,
        *,
        publication_operation_id: str,
        runtime_epoch: int,
        dependencies: tuple[DependencyEdge, ...] = (),
        purpose: str = "next_session_context",
    ) -> TemporalGraphSnapshot:
        if not publication_operation_id:
            raise ValueError("publication_operation_id is required")
        if type(runtime_epoch) is not int or runtime_epoch <= 0:
            raise ValueError("runtime_epoch must be positive")
        if type(purpose) is not str or not purpose:
            raise ValueError("graph purpose must be nonempty")
        graph: nx.MultiDiGraph[
            str, dict[str, object], dict[str, object]
        ] = nx.MultiDiGraph()
        publishable_events = tuple(
            event
            for event in snapshot.events
            if event.privacy_level == "private_client"
            and event.allows_purpose(purpose)
        )
        current_events = tuple(
            event
            for event in publishable_events
            if event.review_status == "approved"
            and event.validity_status == "active"
            and event.resolution_status == "open"
        )
        events_by_id = {event.event_id: event for event in current_events}
        events_by_fact_id = {event.fact_id: event for event in current_events}
        for event in publishable_events:
            target_value = event.object_value
            target = (
                target_value
                if isinstance(target_value, str)
                else canonical_json(target_value)
            )
            graph.add_node(event.subject, node_type="Client" if event.subject == "来访者" else "Entity")
            graph.add_node(target, node_type="PersonRole" if event.relation_type else "Value")
            graph.add_edge(
                event.subject,
                target,
                key=event.event_id,
                edge_id=event.event_id,
                fact_id=event.fact_id,
                relation_type=event.relation_type or "ABOUT_ENTITY",
                review_status=event.review_status,
                validity_status=event.validity_status,
                resolution_status=event.resolution_status,
                epistemic_status=event.epistemic_status,
                confidence=event.fact_confidence,
                dependency_type="direct_deterministic",
                effective_from=event.effective_from,
                effective_to=event.effective_to,
                recorded_at=event.recorded_at,
                approved_at=event.approved_at,
                source_event_ids=(event.event_id, *event.source_event_ids),
                source_session_id=event.source_session_id,
                source_turn_id=event.source_turn_id,
                privacy_level=event.privacy_level,
            )
        for dependency in sorted(dependencies, key=lambda edge: edge.edge_id):
            prerequisite = events_by_fact_id.get(dependency.prerequisite_fact_id)
            dependent = events_by_fact_id.get(dependency.dependent_fact_id)
            source_event = events_by_id.get(dependency.source_event_id)
            # A dependency is a derived view over the same bitemporal snapshot,
            # not a timeless row copied from the authority table.  Requiring all
            # three facts to be visible prevents a superseded/invalidated fact's
            # old dependency from leaking into the current graph.  If a current
            # replacement should retain the dependency it must be reviewed and
            # recorded against a current source event.
            if prerequisite is None or dependent is None or source_event is None:
                continue
            effective_to_candidates = tuple(
                value
                for value in (
                    prerequisite.effective_to,
                    dependent.effective_to,
                    source_event.effective_to,
                )
                if value is not None
            )
            graph.add_node(dependency.prerequisite_fact_id, node_type="Fact")
            graph.add_node(dependency.dependent_fact_id, node_type="Fact")
            graph.add_edge(
                dependency.prerequisite_fact_id,
                dependency.dependent_fact_id,
                key=dependency.edge_id,
                edge_id=dependency.edge_id,
                fact_id=dependency.dependent_fact_id,
                relation_type="DEPENDS_ON",
                review_status=source_event.review_status,
                validity_status=source_event.validity_status,
                resolution_status=source_event.resolution_status,
                epistemic_status=source_event.epistemic_status,
                confidence=dependency.confidence,
                dependency_type=dependency.dependency_type,
                effective_from=max(
                    prerequisite.effective_from,
                    dependent.effective_from,
                    source_event.effective_from,
                ),
                effective_to=(
                    min(effective_to_candidates)
                    if effective_to_candidates
                    else None
                ),
                recorded_at=max(
                    prerequisite.recorded_at,
                    dependent.recorded_at,
                    source_event.recorded_at,
                ),
                approved_at=max(
                    prerequisite.approved_at,
                    dependent.approved_at,
                    source_event.approved_at,
                ),
                source_event_ids=(dependency.source_event_id,),
                privacy_level="private_client",
            )
        payload = graph_payload(
            graph,
            publication_operation_id=publication_operation_id,
            source_client_commit_version=snapshot.client_commit_version,
            runtime_epoch=runtime_epoch,
            effective_at=snapshot.query.effective_at,
            known_at=snapshot.query.known_at,
            builder_policy_version=self.POLICY_VERSION,
        )
        return TemporalGraphSnapshot(
            graph=graph,
            publication_operation_id=publication_operation_id,
            source_client_commit_version=snapshot.client_commit_version,
            runtime_epoch=runtime_epoch,
            builder_policy_version=self.POLICY_VERSION,
            canonical_sha256=graph_sha256(payload),
        )


__all__ = ["TemporalGraphBuilder", "TemporalGraphSnapshot"]
