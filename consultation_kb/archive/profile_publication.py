"""Atomic publication of a reviewed multi-mutation profile diff.

The P2 single-mutation publisher remains the authority for ordinary fact
changes.  Archiving is the one place where several independently reviewed
mutations must become visible together.  This adapter materializes every
selected mutation at one commit version, prepares the fact/profile/graph
closure, and switches one runtime epoch only after the complete closure has
verified.
"""

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
from consultation_kb.approvals.models import (
    ApprovalExecutionProof,
    ApprovalExecutionTicket,
)
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.archive.profile_review import PreparedProfileDiffApproval
from consultation_kb.client.bitemporal import BitemporalFactQuery, FactQuery
from consultation_kb.client.graph_serialization import canonical_graph_bytes, graph_payload
from consultation_kb.client.mutations import FactMutationService
from consultation_kb.client.profile import ProfileMaterializer
from consultation_kb.client.temporal_graph import TemporalGraphBuilder
from consultation_kb.core.clock import Clock, FixedClock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.lifecycle.publish import (
    ArtifactDraft,
    ContentDraft,
    PublishCoordinator,
    RuntimeEpochRepository,
    publication_closure_sha256,
)
from consultation_kb.models.dependencies import DependencyEdge
from consultation_kb.models.facts import (
    AddMutation,
    ConfirmMutation,
    CorrectMutation,
    FactEvent,
    FactEvidence,
    MergeMutation,
    ResolveMutation,
    SupersedeMutation,
)
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.storage.client_ledger import FactEventRepository, StaleFactPreview
from consultation_kb.storage.connection import transaction
from consultation_kb.storage.tombstones import ObjectIdentity, TombstoneRepository, VisibilityGuard
from consultation_kb.vault.content_store import ContentStore


class AtomicProfilePublicationError(RuntimeError):
    def __init__(self, code: str = "ATOMIC_PROFILE_PUBLICATION_INVALID") -> None:
        self.code = code
        super().__init__(code)


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


def _target_event_ids(operation: object) -> tuple[str, ...]:
    mutation = operation
    if isinstance(mutation, (ConfirmMutation, CorrectMutation, SupersedeMutation, ResolveMutation)):
        return (mutation.target_event_id,)
    if isinstance(mutation, MergeMutation):
        return tuple(mutation.member_event_ids)
    if isinstance(mutation, AddMutation):
        return ()
    raise AtomicProfilePublicationError()


@dataclass(frozen=True, slots=True)
class AtomicProfilePublicationPlan:
    bundle_id: str
    session_id: str
    operation_id: str
    publication_timestamp: datetime
    expected_current_epoch: int | None
    runtime_epoch: int
    authority_version: int
    base_commit_version: int
    selection_sha256: str
    publication_closure_sha256: str
    descriptor: DraftDescriptor
    events: tuple[FactEvent, ...]
    merge_members: tuple[tuple[str, tuple[str, ...]], ...]
    evidence: tuple[tuple[str, tuple[FactEvidence, ...]], ...]
    dependency_edges: tuple[DependencyEdge, ...]
    profile_revision_id: str
    profile_json_object_id: str
    profile_markdown_object_id: str
    artifacts: tuple[ArtifactDraft, ...]

    @property
    def event_count(self) -> int:
        return len(self.events)


@dataclass(frozen=True, slots=True)
class AtomicProfilePublicationResult:
    new_commit_version: int
    runtime_epoch: int
    event_count: int
    manifest_ids: tuple[str, ...]
    proof: ApprovalExecutionProof


class AtomicProfilePublicationPlanner:
    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SQLITE_CONNECTION_REQUIRED")
        self._connection = connection
        self._repository = FactEventRepository(connection)

    def prepare(
        self,
        approval: PreparedProfileDiffApproval,
        *,
        bundle_id: str,
        operation_id: str,
        expected_runtime_epoch: int,
        publication_timestamp: datetime,
    ) -> AtomicProfilePublicationPlan:
        reviewed = PreparedProfileDiffApproval.model_validate(approval, strict=True)
        if (
            reviewed.pending_indirect_review_fact_ids
            or reviewed.unapproved_direct_impact_fact_ids
        ):
            raise AtomicProfilePublicationError("PROFILE_DIFF_REVIEW_INCOMPLETE")
        if self._repository.current_commit_version() != reviewed.base_client_commit_version:
            raise StaleFactPreview
        bundle = self._connection.execute(
            "SELECT session_id, actual_transcript_sha256 FROM archive_bundles "
            "WHERE bundle_id = ?",
            (bundle_id,),
        ).fetchone()
        if bundle != (reviewed.session_id, reviewed.base_session_sha256):
            raise AtomicProfilePublicationError("PROFILE_DIFF_SESSION_BINDING_MISMATCH")
        stored = self._connection.execute(
            "SELECT draft_sha256, base_profile_version, base_profile_sha256 "
            "FROM profile_diff_drafts WHERE bundle_id = ? AND draft_id = ?",
            (bundle_id, reviewed.diff_id),
        ).fetchone()
        if stored != (
            reviewed.source_diff_sha256,
            reviewed.base_client_commit_version,
            reviewed.base_profile_sha256,
        ):
            raise AtomicProfilePublicationError("PROFILE_DIFF_DRAFT_BINDING_MISMATCH")

        current = RuntimeEpochRepository(self._connection).current()
        expected_current_epoch = None if current is None else current.epoch
        if expected_runtime_epoch != (expected_current_epoch or 0) + 1:
            raise AtomicProfilePublicationError("PROFILE_DIFF_RUNTIME_EPOCH_MISMATCH")
        ids = self._ids(
            reviewed,
            operation_id=operation_id,
            expected_runtime_epoch=expected_runtime_epoch,
            publication_timestamp=publication_timestamp,
        )
        mutation_service = FactMutationService(
            self._repository,
            id_factory=ids,
            allow_test_approvals=False,
        )
        target_ids = tuple(
            target
            for item in reviewed.selected_operations
            for target in _target_event_ids(item.mutation)
        )
        if len(target_ids) != len(set(target_ids)):
            raise AtomicProfilePublicationError("PROFILE_DIFF_TARGET_DUPLICATE")

        authority_version = reviewed.base_client_commit_version + 1
        all_events: list[FactEvent] = []
        merge_members: dict[str, tuple[str, ...]] = {}
        evidence: dict[str, tuple[FactEvidence, ...]] = {}
        new_dependencies: list[DependencyEdge] = []
        for selected in reviewed.selected_operations:
            preview = mutation_service.preview(selected.mutation)
            if preview.base_commit_version != reviewed.base_client_commit_version:
                raise StaleFactPreview
            events, merges, proofs = mutation_service.materialize(
                preview.mutation,
                commit_version=authority_version,
                operation_id=operation_id,
                runtime_epoch=expected_runtime_epoch,
                now=publication_timestamp,
            )
            all_events.extend(events)
            for event_id, members in merges.items():
                if event_id in merge_members:
                    raise AtomicProfilePublicationError()
                merge_members[event_id] = members
            for event_id, items in proofs.items():
                if event_id in evidence:
                    raise AtomicProfilePublicationError()
                evidence[event_id] = items
            new_dependencies.extend(mutation_service.dependency_edges(preview.mutation))

        events_tuple = tuple(all_events)
        if not events_tuple or len({item.event_id for item in events_tuple}) != len(events_tuple):
            raise AtomicProfilePublicationError("PROFILE_DIFF_EVENT_CONFLICT")
        if len({item.edge_id for item in new_dependencies}) != len(new_dependencies):
            raise AtomicProfilePublicationError("PROFILE_DIFF_DEPENDENCY_CONFLICT")
        add_signatures = [
            (item.client_id, item.canonical_key, item.object_json)
            for item in events_tuple
            if item.mutation_type == "ADD"
        ]
        if len(add_signatures) != len(set(add_signatures)):
            raise AtomicProfilePublicationError("PROFILE_DIFF_DUPLICATE_ADD")

        projected_events = self._repository.list_events() + events_tuple
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
            for members in merge_members.values()
            for member in members
        )
        materializer = ProfileMaterializer()
        profile = materializer.build(snapshot, merge_member_event_ids=merged_ids)
        dependencies = tuple(
            sorted((*self._dependencies(), *new_dependencies), key=lambda item: item.edge_id)
        )
        if len({item.edge_id for item in dependencies}) != len(dependencies):
            raise AtomicProfilePublicationError("PROFILE_DIFF_DEPENDENCY_CONFLICT")
        graph = TemporalGraphBuilder().build(
            snapshot,
            publication_operation_id=operation_id,
            runtime_epoch=expected_runtime_epoch,
            dependencies=dependencies,
        )
        lineage = tuple(
            ObjectIdentity("fact_event", event.event_id)
            for event in sorted(snapshot.events, key=lambda item: item.event_id)
        )
        fact_snapshot = _canonical_bytes(
            {
                "dependencies": [item.model_dump(mode="json") for item in dependencies],
                "schema_version": "client_fact_snapshot.v2",
                "snapshot": snapshot.model_dump(mode="json"),
            }
        )
        review_commitment = _canonical_bytes(
            {
                "schema_version": "profile_diff_review_commitment.v1",
                "selection_sha256": reviewed.selection_sha256,
                "source_diff_sha256": reviewed.source_diff_sha256,
            }
        )
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
        profile_json_object_id = ids.object_id("profile_json")
        profile_markdown_object_id = ids.object_id("profile_markdown")
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
                        data=fact_snapshot,
                        source_version=authority_version,
                        media_type="application/json",
                        source_lineage=lineage,
                    ),
                    ContentDraft(
                        object_type="profile_diff_review_commitment",
                        object_id=ids.object_id("profile_diff_review_commitment"),
                        data=review_commitment,
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
                        data=materializer.render_json(profile),
                        source_version=authority_version,
                        media_type="application/json",
                        source_lineage=lineage,
                    ),
                    ContentDraft(
                        object_type="profile_markdown",
                        object_id=profile_markdown_object_id,
                        data=materializer.render_markdown(profile),
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
        closure = publication_closure_sha256(
            purpose="profile_update",
            authority_base_version=authority_version,
            expected_current_epoch=expected_current_epoch,
            artifacts=artifacts,
        )
        client_id = self._repository.bound_client_id()
        if client_id is None or client_id != reviewed.client_id:
            raise AtomicProfilePublicationError("PROFILE_DIFF_CLIENT_BINDING_MISMATCH")
        descriptor = reviewed.descriptor
        if descriptor.client_id != client_id:
            raise AtomicProfilePublicationError(
                "PROFILE_DIFF_DESCRIPTOR_CLIENT_MISMATCH"
            )
        return AtomicProfilePublicationPlan(
            bundle_id=bundle_id,
            session_id=reviewed.session_id,
            operation_id=operation_id,
            publication_timestamp=publication_timestamp,
            expected_current_epoch=expected_current_epoch,
            runtime_epoch=expected_runtime_epoch,
            authority_version=authority_version,
            base_commit_version=reviewed.base_client_commit_version,
            selection_sha256=reviewed.selection_sha256,
            publication_closure_sha256=closure,
            descriptor=descriptor,
            events=events_tuple,
            merge_members=tuple(sorted(merge_members.items())),
            evidence=tuple(sorted(evidence.items())),
            dependency_edges=tuple(sorted(new_dependencies, key=lambda item: item.edge_id)),
            profile_revision_id=ids.object_id("profile_revision"),
            profile_json_object_id=profile_json_object_id,
            profile_markdown_object_id=profile_markdown_object_id,
            artifacts=artifacts,
        )

    @staticmethod
    def _ids(
        approval: PreparedProfileDiffApproval,
        *,
        operation_id: str,
        expected_runtime_epoch: int,
        publication_timestamp: datetime,
    ) -> IdFactory:
        seed = hashlib.sha256(
            _canonical_bytes(
                {
                    "expected_runtime_epoch": expected_runtime_epoch,
                    "operation_id": operation_id,
                    "publication_timestamp": _utc_text(publication_timestamp),
                    "schema_version": "atomic_profile_publication_seed.v1",
                    "selection_sha256": approval.selection_sha256,
                }
            )
        ).digest()
        counter = 0

        def random_source() -> int:
            nonlocal counter
            counter += 1
            digest = hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
            return int.from_bytes(digest, "big") & ((1 << 74) - 1)

        return IdFactory(FixedClock(publication_timestamp), random_source)

    def _dependencies(self) -> tuple[DependencyEdge, ...]:
        columns = (
            "edge_id",
            "dependent_fact_id",
            "prerequisite_fact_id",
            "dependency_type",
            "confidence",
            "source_event_id",
            "reviewer_id",
        )
        return tuple(
            DependencyEdge.model_validate(dict(zip(columns, row, strict=True)))
            for row in self._connection.execute(
                "SELECT edge_id, dependent_fact_id, prerequisite_fact_id, "
                "dependency_type, confidence, source_event_id, reviewer_id "
                "FROM fact_dependencies ORDER BY edge_id"
            ).fetchall()
        )


class _TicketVerifier:
    def __init__(self, ticket: ApprovalExecutionTicket) -> None:
        self._ticket = ticket

    def verify_ticket(
        self,
        ticket: ApprovalExecutionTicket,
        descriptor: DraftDescriptor,
        *,
        allow_expired: bool,
    ) -> object:
        del allow_expired
        if ticket != self._ticket or descriptor != self._ticket.descriptor:
            raise AtomicProfilePublicationError("PROFILE_APPROVAL_TICKET_MISMATCH")
        return ticket.receipt


class AtomicProfilePublicationExecutor:
    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        scope_root: object,
        execution_proof_signer: TargetExecutionAttestorSigner,
        clock: Clock | None = None,
        fault_injector: FaultInjector = _noop_fault,
    ) -> None:
        from pathlib import Path

        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SQLITE_CONNECTION_REQUIRED")
        if not isinstance(scope_root, Path):
            raise TypeError("SCOPE_ROOT_REQUIRED")
        self._connection = connection
        self._scope_root = scope_root
        self._signer = execution_proof_signer
        self._clock = clock if clock is not None else SystemClock()
        self._fault = fault_injector

    def execute(
        self,
        plan: AtomicProfilePublicationPlan,
        ticket: ApprovalExecutionTicket,
    ) -> AtomicProfilePublicationResult:
        approved = ApprovalExecutionTicket.model_validate(ticket)
        if (
            approved.operation_id != plan.operation_id
            or approved.descriptor != plan.descriptor
            or approved.receipt.request_id == plan.operation_id
        ):
            raise AtomicProfilePublicationError("PROFILE_APPROVAL_TICKET_MISMATCH")
        closure = publication_closure_sha256(
            purpose="profile_update",
            authority_base_version=plan.authority_version,
            expected_current_epoch=plan.expected_current_epoch,
            artifacts=plan.artifacts,
        )
        if closure != plan.publication_closure_sha256:
            raise AtomicProfilePublicationError("PROFILE_PUBLICATION_CLOSURE_MISMATCH")
        coordinator = PublishCoordinator(
            self._connection,
            ContentStore(self._scope_root / "cas"),
            VisibilityGuard(TombstoneRepository(self._connection, clock=self._clock)),
            clock=self._clock,
            fault_hook=self._fault,
        )
        prepared = coordinator.stage_artifacts(
            purpose="profile_update",
            artifacts=plan.artifacts,
        )
        if publication_closure_sha256(
            purpose="profile_update",
            authority_base_version=plan.authority_version,
            expected_current_epoch=plan.expected_current_epoch,
            artifacts=prepared,
        ) != plan.publication_closure_sha256:
            raise AtomicProfilePublicationError("PROFILE_PUBLICATION_CLOSURE_MISMATCH")

        guard = ApprovalExecutionGuard(
            self._connection,
            approval_service=cast(ApprovalService, _TicketVerifier(approved)),
            execution_proof_signer=self._signer,
            clock=self._clock,
            commit_version_allocator=lambda _connection: plan.authority_version,
            fault_hook=self._fault,
        )

        def apply(_connection: sqlite3.Connection) -> None:
            repository = FactEventRepository(self._connection)
            repository.append_batch_in_transaction(
                base_commit_version=plan.base_commit_version,
                events=plan.events,
                merge_members=dict(plan.merge_members),
                evidence=dict(plan.evidence),
                dependencies=plan.dependency_edges,
            )
            self._fault("after_fact_batch")
            self._insert_review_and_profile(plan, approved)
            self._fault("after_profile")
            coordinator.prepare(
                operation_id=plan.operation_id,
                purpose="profile_update",
                authority_base_version=plan.authority_version,
                approval_request_id=approved.request_id,
                descriptor_sha256=approved.descriptor_sha256,
                approval_draft_sha256=plan.selection_sha256,
                expected_current_epoch=plan.expected_current_epoch,
                artifacts=prepared,
            )
            self._fault("after_prepare")

        proof = guard.apply_in_transaction(approved, plan.descriptor, apply)
        coordinator.verify(plan.operation_id)
        self._fault("before_epoch_switch")
        operation = coordinator.activate(plan.operation_id)
        if operation.runtime_epoch != plan.runtime_epoch:
            raise AtomicProfilePublicationError("PROFILE_RUNTIME_EPOCH_MISMATCH")
        manifests = self._connection.execute(
            "SELECT manifest_id, artifact_key FROM artifact_manifests "
            "WHERE operation_id = ? ORDER BY manifest_id",
            (plan.operation_id,),
        ).fetchall()
        manifest_ids = tuple(str(row[0]) for row in manifests)
        profile_manifest = next(
            (str(row[0]) for row in manifests if row[1] == "client_profile"),
            None,
        )
        if profile_manifest is None:
            raise AtomicProfilePublicationError("PROFILE_MANIFEST_MISSING")
        with transaction(self._connection):
            changed = self._connection.execute(
                "UPDATE archive_purpose_states SET state = 'ACTIVE', manifest_id = ?, "
                "updated_at = ? WHERE bundle_id = ? AND purpose = 'profile_diff' "
                "AND state = 'PREPARED' AND review_decision_id = ?",
                (
                    profile_manifest,
                    _utc_text(self._clock.now()),
                    plan.bundle_id,
                    approved.request_id,
                ),
            ).rowcount
            if changed != 1:
                current = self._connection.execute(
                    "SELECT state, manifest_id, review_decision_id FROM "
                    "archive_purpose_states WHERE bundle_id = ? AND purpose = 'profile_diff'",
                    (plan.bundle_id,),
                ).fetchone()
                if current != ("ACTIVE", profile_manifest, approved.request_id):
                    raise AtomicProfilePublicationError("PROFILE_ARCHIVE_STATE_CONFLICT")
        return AtomicProfilePublicationResult(
            new_commit_version=plan.authority_version,
            runtime_epoch=plan.runtime_epoch,
            event_count=plan.event_count,
            manifest_ids=manifest_ids,
            proof=proof,
        )

    def _insert_review_and_profile(
        self,
        plan: AtomicProfilePublicationPlan,
        ticket: ApprovalExecutionTicket,
    ) -> None:
        reviewer_hash = hashlib.sha256(
            ("profile-update\0" + ticket.receipt.provider_id).encode("utf-8")
        ).hexdigest()
        existing = self._connection.execute(
            "SELECT session_id, object_id, decision FROM review_decisions "
            "WHERE decision_id = ?",
            (ticket.request_id,),
        ).fetchone()
        expected = (plan.session_id, plan.descriptor.target_id, "APPROVED")
        if existing is None:
            self._connection.execute(
                "INSERT INTO review_decisions(decision_id, session_id, object_id, "
                "decision, reviewer_id_hash, decided_at) VALUES (?, ?, ?, 'APPROVED', ?, ?)",
                (
                    ticket.request_id,
                    plan.session_id,
                    plan.descriptor.target_id,
                    reviewer_hash,
                    _utc_text(ticket.receipt.approved_at),
                ),
            )
        elif tuple(existing) != expected:
            raise AtomicProfilePublicationError("PROFILE_APPROVAL_RECEIPT_REUSED")
        changed = self._connection.execute(
            "UPDATE archive_purpose_states SET state = 'PREPARED', "
            "review_decision_id = ?, updated_at = ? WHERE bundle_id = ? "
            "AND purpose = 'profile_diff' AND state = 'DRAFT'",
            (
                ticket.request_id,
                _utc_text(ticket.receipt.approved_at),
                plan.bundle_id,
            ),
        ).rowcount
        if changed != 1:
            current = self._connection.execute(
                "SELECT state, review_decision_id FROM archive_purpose_states "
                "WHERE bundle_id = ? AND purpose = 'profile_diff'",
                (plan.bundle_id,),
            ).fetchone()
            if current not in {
                ("PREPARED", ticket.request_id),
                ("ACTIVE", ticket.request_id),
            }:
                raise AtomicProfilePublicationError("PROFILE_ARCHIVE_STATE_CONFLICT")
        self._connection.execute(
            "INSERT INTO profile_revisions(revision_id, publication_operation_id, "
            "source_commit_version, visible_runtime_epoch, profile_sha256, "
            "json_object_id, markdown_object_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                plan.profile_revision_id,
                plan.operation_id,
                plan.authority_version,
                plan.runtime_epoch,
                self._profile_sha256(plan),
                plan.profile_json_object_id,
                plan.profile_markdown_object_id,
                _utc_text(plan.publication_timestamp),
            ),
        )
        profile = self._profile_payload(plan)
        ordinal = 0
        sections = profile.get("sections")
        if type(sections) is not list:
            raise AtomicProfilePublicationError("PROFILE_ARTIFACT_INVALID")
        for section in sections:
            if type(section) is not dict or type(section.get("items")) is not list:
                raise AtomicProfilePublicationError("PROFILE_ARTIFACT_INVALID")
            for item in section["items"]:
                if type(item) is not dict:
                    raise AtomicProfilePublicationError("PROFILE_ARTIFACT_INVALID")
                self._connection.execute(
                    "INSERT INTO profile_members(revision_id, ordinal, section, "
                    "fact_id, event_id) VALUES (?, ?, ?, ?, ?)",
                    (
                        plan.profile_revision_id,
                        ordinal,
                        section["name"],
                        item["fact_id"],
                        item["event_id"],
                    ),
                )
                ordinal += 1

    @staticmethod
    def _profile_payload(plan: AtomicProfilePublicationPlan) -> dict[str, object]:
        artifact = next(item for item in plan.artifacts if item.artifact_key == "client_profile")
        member = next(item for item in artifact.members if item.object_type == "profile_json")
        payload = json.loads(member.data.decode("utf-8"))
        if type(payload) is not dict:
            raise AtomicProfilePublicationError("PROFILE_ARTIFACT_INVALID")
        return payload

    @classmethod
    def _profile_sha256(cls, plan: AtomicProfilePublicationPlan) -> str:
        value = cls._profile_payload(plan).get("canonical_sha256")
        if type(value) is not str:
            raise AtomicProfilePublicationError("PROFILE_ARTIFACT_INVALID")
        return value


__all__ = [
    "AtomicProfilePublicationError",
    "AtomicProfilePublicationExecutor",
    "AtomicProfilePublicationPlan",
    "AtomicProfilePublicationPlanner",
    "AtomicProfilePublicationResult",
]
