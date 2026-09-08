"""One approved client fact/profile/graph publication closure."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from consultation_kb.approvals.attestation import TargetExecutionAttestorSigner
from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.models import ApprovalExecutionProof, ApprovalExecutionTicket
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.client.bitemporal import BitemporalFactQuery, BitemporalSnapshot, FactQuery
from consultation_kb.client.dependencies import DependencyImpactService, DependencyRepository
from consultation_kb.client.graph_serialization import canonical_graph_bytes, graph_payload
from consultation_kb.client.mutations import FactMutationService, MutationPreview
from consultation_kb.client.profile import ProfileMaterializer
from consultation_kb.client.temporal_graph import TemporalGraphBuilder, TemporalGraphSnapshot
from consultation_kb.core.clock import Clock, FixedClock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.lifecycle.publish import (
    ArtifactDraft,
    ContentDraft,
    PublishCoordinator,
    RuntimeEpochRepository,
    publication_closure_sha256,
)
from consultation_kb.models.dependencies import DependencyEdge, ImpactProposal
from consultation_kb.models.common import VersionRef
from consultation_kb.models.facts import (
    CorrectMutation,
    FactEvent,
    FactEvidence,
    FactMutation,
    ResolveMutation,
    SupersedeMutation,
)
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.profile import ProfileSnapshot
from consultation_kb.storage.client_ledger import FactEventRepository, StaleFactPreview
from consultation_kb.storage.tombstones import ObjectIdentity, TombstoneRepository, VisibilityGuard
from consultation_kb.vault.content_store import ContentStore


PUBLICATION_PURPOSE = "profile_update"


class ClientPublicationError(RuntimeError):
    """Fixed-code failure for a mismatched or incomplete publication plan."""

    def __init__(self) -> None:
        super().__init__("CLIENT_PUBLICATION_INVALID")


FaultInjector = Callable[[str], None]


def _noop_fault(_point: str) -> None:
    return None


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _utc_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class ClientPublicationPlan:
    draft_event_id: str
    operation_id: str
    publication_timestamp: datetime
    expected_current_epoch: int | None
    runtime_epoch: int
    authority_version: int
    mutation_preview: MutationPreview
    descriptor: DraftDescriptor
    events: tuple[FactEvent, ...]
    merge_members: tuple[tuple[str, tuple[str, ...]], ...]
    evidence: tuple[tuple[str, tuple[FactEvidence, ...]], ...]
    dependency_edges: tuple[DependencyEdge, ...]
    dependency_impact: ImpactProposal | None
    snapshot: BitemporalSnapshot
    profile: ProfileSnapshot
    graph: TemporalGraphSnapshot
    profile_revision_id: str
    profile_json_object_id: str
    profile_markdown_object_id: str
    mutation_diff_bytes: bytes
    diff_object_ref: VersionRef
    artifacts: tuple[ArtifactDraft, ...]

    @property
    def preview_sha256(self) -> str:
        return self.descriptor.draft_sha256


class ClientPublicationPlanner:
    """Prepare the exact immutable closure that the counselor will approve."""

    def __init__(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SQLITE_CONNECTION_REQUIRED")
        self._connection = connection
        self._repository = FactEventRepository(connection)

    def prepare(
        self,
        mutation: FactMutation,
        *,
        draft_event_id: str,
        operation_id: str,
        expected_runtime_epoch: int,
        publication_timestamp: datetime,
        draft_session_id: str | None = None,
    ) -> ClientPublicationPlan:
        if type(expected_runtime_epoch) is not int or expected_runtime_epoch <= 0:
            raise ClientPublicationError
        current = RuntimeEpochRepository(self._connection).current()
        expected_current_epoch = None if current is None else current.epoch
        if expected_runtime_epoch != (expected_current_epoch or 0) + 1:
            raise ClientPublicationError

        ids = self._plan_id_factory(
            mutation,
            draft_event_id=draft_event_id,
            operation_id=operation_id,
            expected_runtime_epoch=expected_runtime_epoch,
            publication_timestamp=publication_timestamp,
        )

        mutation_service = FactMutationService(
            self._repository,
            id_factory=ids,
            allow_test_approvals=False,
        )
        mutation_preview = mutation_service.preview(mutation)
        authority_version = mutation_preview.base_commit_version + 1
        events, merge_members, evidence = mutation_service.materialize(
            mutation_preview.mutation,
            commit_version=authority_version,
            operation_id=operation_id,
            runtime_epoch=expected_runtime_epoch,
            now=publication_timestamp,
        )
        projected_events = self._repository.list_events() + events
        query = FactQuery(
            effective_at=publication_timestamp,
            known_at=publication_timestamp,
            fixed_epoch=expected_runtime_epoch,
        )
        snapshot = BitemporalFactQuery.snapshot_events(
            projected_events,
            query,
            client_commit_version=authority_version,
        )
        snapshot = BitemporalFactQuery.snapshot_events(
            tuple(
                event
                for event in snapshot.events
                if event.privacy_level == "private_client"
                and event.allows_purpose("next_session_context")
            ),
            query,
            client_commit_version=authority_version,
        )
        merged_ids = self._repository.list_merge_member_ids() | frozenset(
            member
            for _projection, members in merge_members.items()
            for member in members
        )
        profile_materializer = ProfileMaterializer()
        profile = profile_materializer.build(
            snapshot,
            merge_member_event_ids=merged_ids,
        )
        new_dependencies = mutation_service.dependency_edges(
            mutation_preview.mutation
        )
        dependencies = tuple(
            sorted((*self._dependencies(), *new_dependencies), key=lambda edge: edge.edge_id)
        )
        if len({edge.edge_id for edge in dependencies}) != len(dependencies):
            raise ClientPublicationError
        dependency_impact = self._dependency_impact(
            mutation_preview.mutation,
            dependencies=dependencies,
        )
        if dependency_impact is not None:
            mutation_preview = mutation_preview.model_copy(
                update={
                    "direct_dependency_fact_ids": tuple(
                        item.fact_id
                        for item in dependency_impact.direct_invalidations
                    )
                }
            )
        graph = TemporalGraphBuilder().build(
            snapshot,
            publication_operation_id=operation_id,
            runtime_epoch=expected_runtime_epoch,
            dependencies=dependencies,
        )

        profile_json = profile_materializer.render_json(profile)
        profile_markdown = profile_materializer.render_markdown(profile)
        graph_bytes = canonical_graph_bytes(
            graph_payload(
                graph.graph,
                publication_operation_id=operation_id,
                source_client_commit_version=authority_version,
                runtime_epoch=expected_runtime_epoch,
                effective_at=query.effective_at,
                known_at=query.known_at,
                builder_policy_version=graph.builder_policy_version,
            )
        )
        fact_snapshot_bytes = _canonical_bytes(
            {
                "dependencies": [
                    dependency.model_dump(mode="json")
                    for dependency in dependencies
                ],
                "schema_version": "client_fact_snapshot.v2",
                "snapshot": snapshot.model_dump(mode="json"),
            }
        )
        mutation_diff_bytes = _canonical_bytes(
            {
                "base_commit_version": mutation_preview.base_commit_version,
                "human_diff": mutation_preview.human_diff,
                "dependency_impact": (
                    None
                    if dependency_impact is None
                    else dependency_impact.model_dump(mode="json")
                ),
                "mutation": mutation_preview.mutation.model_dump(mode="json"),
                "mutation_preview_sha256": mutation_preview.preview_sha256,
                "schema_version": "client_mutation_diff.v1",
            }
        )
        mutation_review_commitment_bytes = _canonical_bytes(
            {
                "mutation_diff_sha256": hashlib.sha256(
                    mutation_diff_bytes
                ).hexdigest(),
                "schema_version": "client_mutation_review_commitment.v1",
            }
        )

        profile_revision_id = ids.object_id("profile_revision")
        profile_json_object_id = ids.object_id("profile_json")
        profile_markdown_object_id = ids.object_id("profile_markdown")
        mutation_diff_object_id = ids.object_id("mutation_diff")
        mutation_review_commitment_object_id = ids.object_id(
            "mutation_review_commitment"
        )
        lineage = self._source_lineage(
            snapshot,
            projected_events=projected_events,
            merge_members=merge_members,
            evidence=evidence,
            dependencies=dependencies,
        )
        artifacts = (
            ArtifactDraft(
                manifest_id=ids.object_id("artifact_manifest"),
                artifact_key="client_fact_snapshot",
                artifact_kind="fact_snapshot",
                source_version=authority_version,
                members=(
                    ContentDraft(
                        object_type="fact_snapshot",
                        object_id=ids.object_id("fact_snapshot"),
                        data=fact_snapshot_bytes,
                        source_version=authority_version,
                        media_type="application/json",
                        source_lineage=lineage,
                    ),
                    ContentDraft(
                        object_type="mutation_review_commitment",
                        object_id=mutation_review_commitment_object_id,
                        data=mutation_review_commitment_bytes,
                        source_version=authority_version,
                        media_type="application/json",
                        source_lineage=(),
                    ),
                ),
            ),
            ArtifactDraft(
                manifest_id=ids.object_id("artifact_manifest"),
                artifact_key="client_profile",
                artifact_kind="profile",
                source_version=authority_version,
                members=(
                    ContentDraft(
                        object_type="profile_json",
                        object_id=profile_json_object_id,
                        data=profile_json,
                        source_version=authority_version,
                        media_type="application/json",
                        source_lineage=lineage,
                    ),
                    ContentDraft(
                        object_type="profile_markdown",
                        object_id=profile_markdown_object_id,
                        data=profile_markdown,
                        source_version=authority_version,
                        media_type="text/markdown",
                        source_lineage=lineage,
                    ),
                ),
            ),
            ArtifactDraft(
                manifest_id=ids.object_id("artifact_manifest"),
                artifact_key="client_graph",
                artifact_kind="graph",
                source_version=authority_version,
                members=(
                    ContentDraft(
                        object_type="client_graph",
                        object_id=ids.object_id("client_graph"),
                        data=graph_bytes,
                        source_version=authority_version,
                        media_type="application/json",
                        source_lineage=lineage,
                    ),
                ),
            ),
        )
        closure_sha256 = publication_closure_sha256(
            purpose=PUBLICATION_PURPOSE,
            authority_base_version=authority_version,
            expected_current_epoch=expected_current_epoch,
            artifacts=artifacts,
        )
        descriptor = DraftDescriptor(
            purpose="profile_update",
            target_id=draft_event_id,
            client_id=mutation_preview.descriptor.client_id,
            base_version=mutation_preview.base_commit_version,
            draft_sha256=closure_sha256,
            session_id=draft_session_id,
        )
        return ClientPublicationPlan(
            draft_event_id=draft_event_id,
            operation_id=operation_id,
            publication_timestamp=publication_timestamp,
            expected_current_epoch=expected_current_epoch,
            runtime_epoch=expected_runtime_epoch,
            authority_version=authority_version,
            mutation_preview=mutation_preview,
            descriptor=descriptor,
            events=events,
            merge_members=tuple(sorted(merge_members.items())),
            evidence=tuple(sorted(evidence.items())),
            dependency_edges=new_dependencies,
            dependency_impact=dependency_impact,
            snapshot=snapshot,
            profile=profile,
            graph=graph,
            profile_revision_id=profile_revision_id,
            profile_json_object_id=profile_json_object_id,
            profile_markdown_object_id=profile_markdown_object_id,
            mutation_diff_bytes=mutation_diff_bytes,
            diff_object_ref=VersionRef(
                object_id=mutation_diff_object_id,
                version=authority_version,
                content_sha256=hashlib.sha256(mutation_diff_bytes).hexdigest(),
            ),
            artifacts=artifacts,
        )

    @staticmethod
    def _plan_id_factory(
        mutation: FactMutation,
        *,
        draft_event_id: str,
        operation_id: str,
        expected_runtime_epoch: int,
        publication_timestamp: datetime,
    ) -> IdFactory:
        seed = hashlib.sha256(
            _canonical_bytes(
                {
                    "draft_event_id": draft_event_id,
                    "expected_runtime_epoch": expected_runtime_epoch,
                    "mutation": mutation.model_dump(mode="json"),
                    "operation_id": operation_id,
                    "publication_timestamp": _utc_text(publication_timestamp),
                    "schema_version": "client_publication_plan_seed.v1",
                }
            )
        ).digest()
        counter = 0

        def random_source() -> int:
            nonlocal counter
            counter += 1
            digest = hashlib.sha256(
                seed + counter.to_bytes(8, "big", signed=False)
            ).digest()
            return int.from_bytes(digest, "big", signed=False) & ((1 << 74) - 1)

        return IdFactory(FixedClock(publication_timestamp), random_source)

    def _dependencies(self) -> tuple[DependencyEdge, ...]:
        rows = self._connection.execute(
            "SELECT edge_id, dependent_fact_id, prerequisite_fact_id, "
            "dependency_type, confidence, source_event_id, reviewer_id "
            "FROM fact_dependencies ORDER BY edge_id"
        ).fetchall()
        return tuple(DependencyEdge.model_validate(dict(zip(
            (
                "edge_id",
                "dependent_fact_id",
                "prerequisite_fact_id",
                "dependency_type",
                "confidence",
                "source_event_id",
                "reviewer_id",
            ),
            row,
            strict=True,
        ))) for row in rows)

    def _dependency_impact(
        self,
        mutation: FactMutation,
        *,
        dependencies: tuple[DependencyEdge, ...],
    ) -> ImpactProposal | None:
        if not isinstance(mutation, (CorrectMutation, SupersedeMutation, ResolveMutation)):
            return None
        target = self._repository.get_event(mutation.target_event_id)
        replacement_fact_id: str | None = None
        new_value = target.object_json
        if isinstance(mutation, SupersedeMutation):
            new_value = mutation.replacement.object_json
            replacement_fact_id = mutation.replacement.fact_id
        elif isinstance(mutation, CorrectMutation):
            if mutation.correction_kind == "value":
                new_value = cast(str, mutation.new_value_json)
            elif mutation.correction_kind == "validity":
                new_value = cast(str, mutation.new_validity_status)
            else:
                new_value = _utc_text(cast(datetime, mutation.new_effective_from))
        else:
            new_value = "resolved"
        return DependencyImpactService(
            DependencyRepository(dependencies)
        ).preview(
            changed_fact_id=target.fact_id,
            old_value=target.object_json,
            new_value=new_value,
            replacement_fact_id=replacement_fact_id,
        )

    def _source_lineage(
        self,
        snapshot: BitemporalSnapshot,
        *,
        projected_events: tuple[FactEvent, ...],
        merge_members: dict[str, tuple[str, ...]],
        evidence: dict[str, tuple[FactEvidence, ...]],
        dependencies: tuple[DependencyEdge, ...],
    ) -> tuple[ObjectIdentity, ...]:
        identities: set[tuple[str, str]] = set()
        events_by_id = {event.event_id: event for event in projected_events}
        visible_event_ids = {event.event_id for event in snapshot.events}
        merge_members_by_projection: dict[str, set[str]] = {}
        for projection_event_id, member_event_id in self._connection.execute(
            "SELECT projection_event_id, member_event_id FROM fact_merge_members"
        ).fetchall():
            merge_members_by_projection.setdefault(
                str(projection_event_id), set()
            ).add(str(member_event_id))
        for projection_event_id, member_event_ids in merge_members.items():
            merge_members_by_projection.setdefault(projection_event_id, set()).update(
                member_event_ids
            )
        evidence_by_event: dict[str, set[str]] = {}
        for event_id, source_ref in self._connection.execute(
            "SELECT event_id, source_ref FROM fact_evidence"
        ).fetchall():
            evidence_by_event.setdefault(str(event_id), set()).add(str(source_ref))
        for event_id, event_evidence in evidence.items():
            evidence_by_event.setdefault(event_id, set()).update(
                item.source_ref for item in event_evidence
            )

        pending = list(visible_event_ids)
        visible_fact_ids = {event.fact_id for event in snapshot.events}
        pending.extend(
            dependency.source_event_id
            for dependency in dependencies
            if dependency.dependent_fact_id in visible_fact_ids
            or dependency.prerequisite_fact_id in visible_fact_ids
        )
        visited: set[str] = set()
        while pending:
            event_id = pending.pop()
            if event_id in visited:
                continue
            visited.add(event_id)
            identities.add(("fact_event", event_id))
            event = events_by_id.get(event_id)
            if event is None:
                continue
            if event.source_session_id is not None:
                identities.add(("source_session", event.source_session_id))
            if event.source_turn_id is not None:
                identities.add(("source_turn", event.source_turn_id))
            if event.source_ref is not None:
                identities.add(("source_ref", event.source_ref))
            identities.update(
                ("evidence_source", source_ref)
                for source_ref in evidence_by_event.get(event_id, set())
            )
            references = {
                *event.source_event_ids,
                *merge_members_by_projection.get(event_id, set()),
            }
            references.update(
                reference
                for reference in (
                    event.previous_event_id,
                    event.supersedes_event_id,
                    event.replacement_event_id,
                )
                if reference is not None
            )
            pending.extend(sorted(references, reverse=True))
        return tuple(
            ObjectIdentity(object_type, object_id)
            for object_type, object_id in sorted(identities)
        )


class _ClaimBoundApprovalVerifier:
    """Target-only verification adapter for one broker-verified ticket."""

    def __init__(self, ticket: ApprovalExecutionTicket, descriptor: DraftDescriptor) -> None:
        self._ticket = ticket
        self._descriptor = descriptor

    def verify_ticket(
        self,
        ticket: ApprovalExecutionTicket,
        descriptor: DraftDescriptor,
        *,
        allow_expired: bool,
    ) -> object:
        del allow_expired
        if ticket != self._ticket or descriptor != self._descriptor:
            raise ClientPublicationError
        return self._ticket.receipt


class ClientPublicationExecutor:
    """Apply the plan under P1 Guard, then verify and switch one epoch."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        scope_root: object,
        execution_proof_signer: TargetExecutionAttestorSigner,
        clock: Clock | None = None,
        fault_injector: FaultInjector = _noop_fault,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SQLITE_CONNECTION_REQUIRED")
        from pathlib import Path

        if not isinstance(scope_root, Path):
            raise TypeError("SCOPE_ROOT_REQUIRED")
        self._connection = connection
        self._scope_root = scope_root
        self._proof_signer = execution_proof_signer
        self._clock = clock if clock is not None else SystemClock()
        self._fault = fault_injector

    def execute(
        self,
        plan: ClientPublicationPlan,
        ticket: ApprovalExecutionTicket,
    ) -> ApprovalExecutionProof:
        self._assert_plan_integrity(plan)
        if ticket.operation_id != plan.operation_id or ticket.descriptor != plan.descriptor:
            raise ClientPublicationError
        current_version = FactEventRepository(self._connection).current_commit_version()
        if current_version not in {
            plan.mutation_preview.base_commit_version,
            plan.authority_version,
        }:
            raise StaleFactPreview
        if current_version == plan.authority_version:
            existing = self._connection.execute(
                "SELECT state FROM approval_executions WHERE operation_id = ?",
                (plan.operation_id,),
            ).fetchone()
            if existing != ("APPLIED",):
                raise StaleFactPreview
        raw_closure = publication_closure_sha256(
            purpose=PUBLICATION_PURPOSE,
            authority_base_version=plan.authority_version,
            expected_current_epoch=plan.expected_current_epoch,
            artifacts=plan.artifacts,
        )
        if raw_closure != plan.descriptor.draft_sha256:
            raise ClientPublicationError

        coordinator = PublishCoordinator(
            self._connection,
            ContentStore(self._scope_root / "cas"),
            VisibilityGuard(TombstoneRepository(self._connection, clock=self._clock)),
            clock=self._clock,
            fault_hook=self._fault,
        )
        prepared = coordinator.stage_artifacts(
            purpose=PUBLICATION_PURPOSE,
            artifacts=plan.artifacts,
        )
        self._fault("graph_finalize")
        if publication_closure_sha256(
            purpose=PUBLICATION_PURPOSE,
            authority_base_version=plan.authority_version,
            expected_current_epoch=plan.expected_current_epoch,
            artifacts=prepared,
        ) != plan.descriptor.draft_sha256:
            raise ClientPublicationError

        guard = ApprovalExecutionGuard(
            self._connection,
            approval_service=cast(
                ApprovalService,
                _ClaimBoundApprovalVerifier(ticket, plan.descriptor),
            ),
            execution_proof_signer=self._proof_signer,
            clock=self._clock,
            commit_version_allocator=lambda _connection: plan.authority_version,
            fault_hook=self._fault,
        )

        def apply_closure(_connection: sqlite3.Connection) -> None:
            repository = FactEventRepository(self._connection)
            repository.append_batch_in_transaction(
                base_commit_version=plan.mutation_preview.base_commit_version,
                events=plan.events,
                merge_members=dict(plan.merge_members),
                evidence=dict(plan.evidence),
                dependencies=plan.dependency_edges,
            )
            self._fault("authoritative_event_transaction")
            self._insert_profile_revision(plan)
            self._fault("profile_finalize")
            coordinator.prepare(
                operation_id=plan.operation_id,
                purpose=PUBLICATION_PURPOSE,
                authority_base_version=plan.authority_version,
                approval_request_id=ticket.request_id,
                descriptor_sha256=ticket.descriptor_sha256,
                expected_current_epoch=plan.expected_current_epoch,
                artifacts=prepared,
            )
            self._fault("prepared")

        proof = guard.apply_in_transaction(ticket, plan.descriptor, apply_closure)
        self._fault("verify")
        coordinator.verify(plan.operation_id)
        self._fault("epoch_switch")
        operation = coordinator.activate(plan.operation_id)
        if operation.runtime_epoch != plan.runtime_epoch:
            raise ClientPublicationError
        return proof

    @staticmethod
    def _assert_plan_integrity(plan: ClientPublicationPlan) -> None:
        base_version = plan.mutation_preview.base_commit_version
        if (
            plan.authority_version != base_version + 1
            or plan.descriptor.base_version != base_version
            or plan.runtime_epoch != (plan.expected_current_epoch or 0) + 1
            or plan.snapshot.client_commit_version != plan.authority_version
            or plan.snapshot.query.fixed_epoch != plan.runtime_epoch
            or plan.profile.source_client_commit_version != plan.authority_version
            or plan.profile.fixed_epoch != plan.runtime_epoch
            or plan.graph.source_client_commit_version != plan.authority_version
            or plan.graph.runtime_epoch != plan.runtime_epoch
            or plan.graph.publication_operation_id != plan.operation_id
            or plan.dependency_edges
            != FactMutationService.dependency_edges(plan.mutation_preview.mutation)
            or any(
                event.commit_version != plan.authority_version
                or event.visible_runtime_epoch != plan.runtime_epoch
                or event.publication_operation_id != plan.operation_id
                for event in plan.events
            )
            or any(
                artifact.source_version != plan.authority_version
                for artifact in plan.artifacts
            )
        ):
            raise ClientPublicationError

    def _insert_profile_revision(self, plan: ClientPublicationPlan) -> None:
        self._connection.execute(
            "INSERT INTO profile_revisions("
            "revision_id, publication_operation_id, source_commit_version, "
            "visible_runtime_epoch, profile_sha256, json_object_id, "
            "markdown_object_id, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                plan.profile_revision_id,
                plan.operation_id,
                plan.authority_version,
                plan.runtime_epoch,
                plan.profile.canonical_sha256,
                plan.profile_json_object_id,
                plan.profile_markdown_object_id,
                _utc_text(plan.publication_timestamp),
            ),
        )
        ordinal = 0
        for section in plan.profile.sections:
            for item in section.items:
                self._connection.execute(
                    "INSERT INTO profile_members("
                    "revision_id, ordinal, section, fact_id, event_id"
                    ") VALUES (?, ?, ?, ?, ?)",
                    (
                        plan.profile_revision_id,
                        ordinal,
                        section.name,
                        item.fact_id,
                        item.event_id,
                    ),
                )
                ordinal += 1


def result_event_count(plan: ClientPublicationPlan) -> int:
    return len(plan.events)


__all__ = [
    "ClientPublicationError",
    "ClientPublicationExecutor",
    "ClientPublicationPlan",
    "ClientPublicationPlanner",
    "PUBLICATION_PURPOSE",
    "result_event_count",
]
