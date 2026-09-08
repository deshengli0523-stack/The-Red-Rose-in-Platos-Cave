"""Exact, append-only rollback planning and target-transaction execution.

Rollback is a governed successor write.  The caller names only an existing
identity and two versions; this module reads the authoritative current and
historical objects itself, writes an immutable CAS plan, and re-reads that CAS
plan and both authority versions inside the one-shot approval transaction.

Derived artifacts are deliberately not rewound one manifest at a time.  A
profile-fact rollback appends an inverse event and queues the complete client
``purpose=all`` rebuild in the same transaction.  Wiki and C1 rollbacks create
new PREPARED successor revisions through their normal review writers.  The
legacy single-manifest API is retained only as a fixed fail-closed boundary.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol, cast

from pydantic import model_validator

from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.models import (
    ApprovalExecutionProof,
    ApprovalExecutionTicket,
    ApprovalRequest,
    descriptor_sha256,
)
from consultation_kb.client.mutations import FactMutationService
from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import (
    canonical_json_bytes,
    canonical_sha256,
    text_sha256,
)
from consultation_kb.knowledge.approval import GovernedWriteExecutor
from consultation_kb.knowledge.scope_policy import ScopePolicyRepository
from consultation_kb.knowledge.theory import TheoryRevisionService
from consultation_kb.knowledge.wiki import WikiProposal, WikiRevisionService
from consultation_kb.lifecycle.rebuild import (
    RebuildCoordinator,
    RebuildPlan,
    RebuildRequest,
)
from consultation_kb.lifecycle.rebuild_registry import DatabaseScope
from consultation_kb.models.common import (
    ClientId,
    NonEmptyStr,
    NonNegativeInt,
    ObjectId,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    VersionRef,
)
from consultation_kb.models.facts import CorrectMutation, FactEvent
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.theory import (
    TheoryProposal,
    TheoryRevision,
    TheoryRevisionDraft,
)
from consultation_kb.models.wiki import WikiRevision, WikiRevisionDraft
from consultation_kb.retrieval.artifact_contracts import (
    DerivedArtifactBuilderInputV2,
)
from consultation_kb.security.worker_protocol import ArchiveContentRef
from consultation_kb.storage.client_ledger import FactEventRepository
from consultation_kb.storage.connection import transaction
from consultation_kb.storage.manifests import (
    ArtifactManifest,
    ManifestRepository,
)
from consultation_kb.storage.tombstones import (
    ObjectIdentity,
    TombstoneRepository,
    lineage_hash,
)
from consultation_kb.vault.content_store import ContentStore


class RollbackError(RuntimeError):
    """A fixed-code rejection safe for an operator boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


RollbackKind = Literal["profile_fact", "wiki", "theory", "artifact"]


def _utc_text(value: UtcDateTime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


class RollbackBaseVersion(StrictModel):
    """One body-free authority CAS captured by a rollback preview."""

    authority_key: SafePolicyKey
    scope_sha256: Sha256Hex
    version: NonNegativeInt


class RollbackReview(StrictModel):
    """Human-review binding shared by every rollback draft."""

    rollback_kind: RollbackKind
    target_id: NonEmptyStr
    current_version: PositiveInt
    restore_version: PositiveInt
    reason: NonEmptyStr
    required_approver_role: Literal["primary_counselor"] = "primary_counselor"
    review_status: Literal["proposed"] = "proposed"

    @model_validator(mode="after")
    def _different_versions(self) -> "RollbackReview":
        if self.current_version == self.restore_version:
            raise ValueError("rollback must restore a different historical version")
        return self


def _validate_base_versions(
    values: tuple[RollbackBaseVersion, ...],
    *,
    scope_sha256: str,
) -> None:
    keys = tuple((item.authority_key, item.scope_sha256) for item in values)
    if (
        not values
        or keys != tuple(sorted(set(keys)))
        or any(item.scope_sha256 != scope_sha256 for item in values)
    ):
        raise ValueError("rollback base versions are not canonical")


class FactRollbackPlan(StrictModel):
    """Exact inverse event plus the complete post-write client rebuild plan."""

    operation_id: ObjectId
    scope_sha256: Sha256Hex
    current_event_ref: VersionRef
    restore_event_ref: VersionRef
    fact_id: NonEmptyStr
    inverse_mutation: CorrectMutation
    new_event: FactEvent
    base_versions: tuple[RollbackBaseVersion, ...]
    rebuild_plan: RebuildPlan
    review: RollbackReview
    plan_sha256: Sha256Hex
    descriptor: DraftDescriptor

    @model_validator(mode="after")
    def _bindings_match(self) -> "FactRollbackPlan":
        _validate_base_versions(self.base_versions, scope_sha256=self.scope_sha256)
        base_map = {item.authority_key: item.version for item in self.base_versions}
        if (
            set(base_map) != {"client_fact", "client_runtime", "tombstone_epoch"}
            or self.inverse_mutation.target_event_id
            != self.current_event_ref.object_id
            or self.restore_event_ref.version >= self.current_event_ref.version
            or self.restore_event_ref.object_id == self.current_event_ref.object_id
            or self.new_event.fact_id != self.fact_id
            or self.new_event.event_id in {
                self.current_event_ref.object_id,
                self.restore_event_ref.object_id,
            }
            or self.new_event.event_version != self.current_event_ref.version + 1
            or self.new_event.previous_event_id != self.current_event_ref.object_id
            or self.new_event.object_json != self.inverse_mutation.new_value_json
            or self.new_event.commit_version != base_map.get("client_fact", -1) + 1
            or self.new_event.visible_runtime_epoch
            != base_map.get("client_runtime", -1) + 1
            or self.new_event.transaction_id != self.operation_id
            or self.new_event.publication_operation_id != self.operation_id
            or self.new_event.mutation_type != "CORRECT"
            or self.new_event.review_status != "approved"
            or self.rebuild_plan.database_scope != "client"
            or self.rebuild_plan.scope_sha256 != self.scope_sha256
            or self.rebuild_plan.purpose != "all"
            or self.rebuild_plan.source_intent_id != self.operation_id
            or self.rebuild_plan.tombstone_epoch
            != base_map.get("tombstone_epoch", -1)
            or self.review.rollback_kind != "profile_fact"
            or self.review.target_id != self.fact_id
            or self.review.current_version != self.current_event_ref.version
            or self.review.restore_version != self.restore_event_ref.version
            or self.descriptor.purpose != "rollback"
            or self.descriptor.target_id != self.fact_id
            or self.descriptor.base_version != self.current_event_ref.version
            or self.descriptor.draft_sha256 != self.plan_sha256
            or self.descriptor.client_id != self.new_event.client_id
        ):
            raise ValueError("fact rollback bindings do not match")
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"plan_sha256", "descriptor"})
        )
        if expected != self.plan_sha256:
            raise ValueError("fact rollback plan hash mismatch")
        return self


class WikiRollbackPlan(StrictModel):
    operation_id: ObjectId
    scope_sha256: Sha256Hex
    current_revision_ref: VersionRef
    restore_revision_ref: VersionRef
    new_revision: PositiveInt
    proposal: WikiProposal
    base_versions: tuple[RollbackBaseVersion, ...]
    review: RollbackReview
    plan_sha256: Sha256Hex
    descriptor: DraftDescriptor

    @property
    def draft(self) -> WikiRevisionDraft:
        return self.proposal.draft

    @model_validator(mode="after")
    def _bindings_match(self) -> "WikiRollbackPlan":
        _validate_base_versions(self.base_versions, scope_sha256=self.scope_sha256)
        if (
            self.proposal.draft.wiki_id != self.current_revision_ref.object_id
            or self.restore_revision_ref.object_id
            != self.current_revision_ref.object_id
            or self.restore_revision_ref.version
            >= self.current_revision_ref.version
            or self.proposal.draft.base_revision
            != self.current_revision_ref.version
            or self.new_revision != self.current_revision_ref.version + 1
            or canonical_sha256(self.proposal.draft.model_dump(mode="json"))
            != self.proposal.draft_sha256
            or self.review.rollback_kind != "wiki"
            or self.review.target_id != self.current_revision_ref.object_id
            or self.review.current_version != self.current_revision_ref.version
            or self.review.restore_version != self.restore_revision_ref.version
            or self.descriptor.purpose != "rollback"
            or self.descriptor.target_id != self.current_revision_ref.object_id
            or self.descriptor.base_version != self.current_revision_ref.version
            or self.descriptor.draft_sha256 != self.plan_sha256
            or self.descriptor.client_id is not None
            or self.descriptor.session_id is not None
        ):
            raise ValueError("Wiki rollback bindings do not match")
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"plan_sha256", "descriptor"})
        )
        if expected != self.plan_sha256:
            raise ValueError("Wiki rollback plan hash mismatch")
        return self


class TheoryRollbackPlan(StrictModel):
    operation_id: ObjectId
    scope_sha256: Sha256Hex
    current_revision_ref: VersionRef
    restore_revision_ref: VersionRef
    new_revision: PositiveInt
    proposal: TheoryProposal
    expected_claim_refs: tuple[VersionRef, ...]
    base_versions: tuple[RollbackBaseVersion, ...]
    review: RollbackReview
    plan_sha256: Sha256Hex
    descriptor: DraftDescriptor

    @property
    def draft(self) -> TheoryRevisionDraft:
        return self.proposal.draft

    @model_validator(mode="after")
    def _bindings_match(self) -> "TheoryRollbackPlan":
        _validate_base_versions(self.base_versions, scope_sha256=self.scope_sha256)
        expected_claim_hashes = tuple(text_sha256(value) for value in self.draft.core_claims)
        if (
            self.draft.theory_id != self.current_revision_ref.object_id
            or self.restore_revision_ref.object_id
            != self.current_revision_ref.object_id
            or self.restore_revision_ref.version
            >= self.current_revision_ref.version
            or self.draft.supersedes_ref != self.current_revision_ref
            or self.draft.revokes_ref is not None
            or self.new_revision != self.current_revision_ref.version + 1
            or canonical_sha256(self.draft.model_dump(mode="json"))
            != self.proposal.draft_sha256
            or tuple(item.content_sha256 for item in self.expected_claim_refs)
            != expected_claim_hashes
            or any(item.version != 1 for item in self.expected_claim_refs)
            or len({item.object_id for item in self.expected_claim_refs})
            != len(self.expected_claim_refs)
            or self.review.rollback_kind != "theory"
            or self.review.target_id != self.current_revision_ref.object_id
            or self.review.current_version != self.current_revision_ref.version
            or self.review.restore_version != self.restore_revision_ref.version
            or self.review.required_approver_role != "primary_counselor"
            or self.descriptor.purpose != "rollback"
            or self.descriptor.target_id != self.current_revision_ref.object_id
            or self.descriptor.base_version != self.current_revision_ref.version
            or self.descriptor.draft_sha256 != self.plan_sha256
            or self.descriptor.client_id is not None
            or self.descriptor.session_id is not None
        ):
            raise ValueError("C1 rollback bindings do not match")
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"plan_sha256", "descriptor"})
        )
        if expected != self.plan_sha256:
            raise ValueError("C1 rollback plan hash mismatch")
        return self


class ArtifactClosureRoot(StrictModel):
    """One hash-bound root in a complete historical runtime closure."""

    artifact_key: SafePolicyKey
    manifest_ref: VersionRef


class ArtifactRollbackPlan(StrictModel):
    """Source-first artifact rollback; historical bytes are never cloned.

    The historical/current closures prove which derived output prompted the
    rollback.  ``source_plan_ref`` identifies the already-previewed Fact/Wiki/C1
    successor that is allowed to change authority.  Only that successor can
    then drive a complete ``purpose=all`` publication at the next source
    version.
    """

    operation_id: ObjectId
    database_scope: DatabaseScope
    scope_sha256: Sha256Hex
    target_artifact_key: SafePolicyKey
    current_runtime_epoch: PositiveInt
    restore_runtime_epoch: PositiveInt
    current_closure: tuple[ArtifactClosureRoot, ...]
    restore_closure: tuple[ArtifactClosureRoot, ...]
    source_plan_ref: ArchiveContentRef
    source_plan_sha256: Sha256Hex
    source_rollback_kind: Literal["profile_fact", "wiki", "theory"]
    new_source_version: PositiveInt
    full_closure_purpose: Literal["all"] = "all"
    requires_combined_publication: bool
    base_versions: tuple[RollbackBaseVersion, ...]
    review: RollbackReview
    plan_sha256: Sha256Hex
    descriptor: DraftDescriptor

    @model_validator(mode="after")
    def _bindings_match(self) -> "ArtifactRollbackPlan":
        _validate_base_versions(self.base_versions, scope_sha256=self.scope_sha256)
        current_keys = tuple(value.artifact_key for value in self.current_closure)
        restore_keys = tuple(value.artifact_key for value in self.restore_closure)
        expected_keys = (
            (
                "c1_revision",
                "claims",
                "graph",
                "knowledge_registry",
                "lexical",
                "vector",
                "wiki_index",
                "wiki_page",
            )
            if self.database_scope == "global"
            else (
                "client_fact_snapshot",
                "client_graph",
                "client_profile",
                "private_archive",
            )
        )
        base_map = {value.authority_key: value.version for value in self.base_versions}
        authority_key = (
            "global_publication"
            if self.database_scope == "global"
            else "client_fact"
        )
        runtime_key = (
            "global_runtime"
            if self.database_scope == "global"
            else "client_runtime"
        )
        if (
            current_keys != expected_keys
            or restore_keys != expected_keys
            or any(
                root.manifest_ref.version != self.review.current_version
                for root in self.current_closure
            )
            or any(
                root.manifest_ref.version != self.review.restore_version
                for root in self.restore_closure
            )
            or self.target_artifact_key not in current_keys
            or self.review.rollback_kind != "artifact"
            or self.review.target_id != self.target_artifact_key
            or self.review.restore_version >= self.review.current_version
            or self.new_source_version != self.review.current_version + 1
            or base_map.get(authority_key) != self.review.current_version
            or base_map.get(runtime_key) != self.current_runtime_epoch
            or self.current_runtime_epoch == self.restore_runtime_epoch
            or self.requires_combined_publication
            != (self.source_rollback_kind != "profile_fact")
            or self.descriptor.purpose != "rollback"
            or self.descriptor.target_id != self.target_artifact_key
            or self.descriptor.base_version != self.review.current_version
            or self.descriptor.draft_sha256 != self.plan_sha256
            or (
                self.database_scope == "client"
                and (
                    self.descriptor.client_id is None
                    or self.descriptor.session_id is None
                )
            )
            or (
                self.database_scope == "global"
                and (
                    self.descriptor.client_id is not None
                    or self.descriptor.session_id is not None
                )
            )
        ):
            raise ValueError("artifact rollback bindings do not match")
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"plan_sha256", "descriptor"})
        )
        if expected != self.plan_sha256:
            raise ValueError("artifact rollback plan hash mismatch")
        return self


SourceRollbackPlan = FactRollbackPlan | WikiRollbackPlan | TheoryRollbackPlan
RollbackPlan = SourceRollbackPlan | ArtifactRollbackPlan


class RollbackPlanEnvelope(StrictModel):
    schema_version: Literal["rollback_plan.v2"] = "rollback_plan.v2"
    database_scope: DatabaseScope
    rollback_kind: RollbackKind
    scope_sha256: Sha256Hex
    operation_id: ObjectId
    plan: RollbackPlan

    @model_validator(mode="after")
    def _plan_binding(self) -> "RollbackPlanEnvelope":
        expected_kind: RollbackKind
        if isinstance(self.plan, FactRollbackPlan):
            expected_kind = "profile_fact"
            expected_scope: DatabaseScope = "client"
        elif isinstance(self.plan, WikiRollbackPlan):
            expected_kind = "wiki"
            expected_scope = "global"
        elif isinstance(self.plan, TheoryRollbackPlan):
            expected_kind = "theory"
            expected_scope = "global"
        else:
            expected_kind = "artifact"
            expected_scope = self.plan.database_scope
        if (
            self.rollback_kind != expected_kind
            or self.database_scope != expected_scope
            or self.scope_sha256 != self.plan.scope_sha256
            or self.operation_id != self.plan.operation_id
        ):
            raise ValueError("rollback envelope bindings do not match")
        return self


class RollbackPreview(StrictModel):
    status: Literal["pending_local_review"] = "pending_local_review"
    rollback_kind: RollbackKind
    plan_ref: ArchiveContentRef
    plan_sha256: Sha256Hex
    proposed_operation_id: ObjectId
    descriptor: DraftDescriptor
    base_versions: tuple[RollbackBaseVersion, ...]
    current_version: PositiveInt
    restore_version: PositiveInt


class RollbackCommitSummary(StrictModel):
    status: Literal["rollback_prepared"] = "rollback_prepared"
    rollback_kind: RollbackKind
    operation_id: ObjectId
    request_id: ObjectId
    applied_commit_version: PositiveInt
    successor_ref: VersionRef
    rebuild_job_id: ObjectId | None = None
    requires_combined_publication: bool


@dataclass(frozen=True, slots=True)
class RollbackCommit:
    summary: RollbackCommitSummary
    proof: ApprovalExecutionProof


class _ExactClaimIdFactory:
    """One-use ID source binding C1 successor claims to the reviewed plan."""

    def __init__(self, references: tuple[VersionRef, ...]) -> None:
        self._references = list(references)

    def object_id(self, kind: str) -> str:
        if kind != "claim" or not self._references:
            raise RollbackError("ROLLBACK_THEORY_CLAIM_ID_MISMATCH")
        return self._references.pop(0).object_id


class _RollbackApprovalBridge(GovernedWriteExecutor):
    """Run a normal knowledge writer under the exact outer rollback approval."""

    def __init__(
        self,
        *,
        guard: ApprovalExecutionGuard,
        ticket: ApprovalExecutionTicket,
        outer_descriptor: DraftDescriptor,
        expected_inner_descriptor: DraftDescriptor,
        expected_operation_kind: str,
        before_write: Callable[[sqlite3.Connection], None],
        attestation_writer: Callable[[sqlite3.Connection], None],
    ) -> None:
        self._guard = guard
        self._ticket = ticket
        self._outer = outer_descriptor
        self._inner = expected_inner_descriptor
        self._operation_kind = expected_operation_kind
        self._before_write = before_write
        self._attestation_writer = attestation_writer
        self.proof: ApprovalExecutionProof | None = None

    def execute(
        self,
        *,
        approval_request_id: str,
        descriptor: DraftDescriptor,
        operation_kind: str,
        apply: Callable[[sqlite3.Connection], None],
    ) -> str:
        if (
            approval_request_id != self._ticket.request_id
            or descriptor != self._inner
            or operation_kind != self._operation_kind
            or self._ticket.descriptor != self._outer
            or self._ticket.receipt.approver_role != "primary_counselor"
        ):
            raise RollbackError("ROLLBACK_APPROVAL_BINDING_MISMATCH")

        def governed(connection: sqlite3.Connection) -> None:
            self._before_write(connection)
            self._attestation_writer(connection)
            apply(connection)

        self.proof = self._guard.apply_in_transaction(
            self._ticket,
            self._outer,
            governed,
        )
        return self._ticket.operation_id


class RollbackPlanner:
    """Pure constructors retained for unit-level semantic planning."""

    @staticmethod
    def _reference(object_id: str, version: int, digest: str) -> VersionRef:
        return VersionRef(
            object_id=object_id,
            version=version,
            content_sha256=digest,
        )

    def profile_fact(
        self,
        *,
        operation_id: str,
        current: FactEvent,
        restore: FactEvent,
        effective_at: UtcDateTime,
        reason: str,
        scope_sha256: str | None = None,
        session_id: str | None = None,
        new_event: FactEvent | None = None,
        base_versions: tuple[RollbackBaseVersion, ...] = (),
        rebuild_plan: RebuildPlan | None = None,
    ) -> FactRollbackPlan:
        """Build a complete fact plan; production requires rebuild bindings."""

        del new_event, base_versions, rebuild_plan, scope_sha256, session_id
        current_event = FactEvent.model_validate(current)
        historical = FactEvent.model_validate(restore)
        if (
            current_event.fact_id != historical.fact_id
            or current_event.client_id != historical.client_id
            or historical.event_version >= current_event.event_version
            or current_event.event_id == historical.event_id
        ):
            raise RollbackError("ROLLBACK_FACT_LINEAGE_MISMATCH")
        if current_event.object_json == historical.object_json:
            raise RollbackError("ROLLBACK_FACT_VALUE_UNCHANGED")
        del operation_id, effective_at, reason
        raise RollbackError("ROLLBACK_PRODUCTION_WORKFLOW_REQUIRED")

    def wiki(
        self,
        *,
        operation_id: str,
        current: WikiRevision,
        restore: WikiRevision,
        current_revision_ref: VersionRef,
        restore_revision_ref: VersionRef,
        reason: str,
    ) -> WikiRollbackPlan:
        del operation_id, current, restore, current_revision_ref
        del restore_revision_ref, reason
        raise RollbackError("ROLLBACK_PRODUCTION_WORKFLOW_REQUIRED")

    def theory(
        self,
        *,
        operation_id: str,
        current: TheoryRevision,
        restore: TheoryRevision,
        current_revision_ref: VersionRef,
        restore_revision_ref: VersionRef,
        reason: str,
    ) -> TheoryRollbackPlan:
        del operation_id, current, restore, current_revision_ref
        del restore_revision_ref, reason
        raise RollbackError("ROLLBACK_PRODUCTION_WORKFLOW_REQUIRED")

    def artifact(
        self,
        *,
        operation_id: str,
        new_manifest_id: str,
        current: ArtifactManifest,
        restore: ArtifactManifest,
        reason: str,
        client_id: ClientId | None = None,
    ) -> ArtifactRollbackPlan:
        del operation_id, new_manifest_id, current, restore, reason, client_id
        raise RollbackError("ROLLBACK_ARTIFACT_FULL_REBUILD_REQUIRED")

    @staticmethod
    def insert_prepared_artifact(
        repository: ManifestRepository,
        plan: ArtifactRollbackPlan,
        *,
        created_at: str,
    ) -> ArtifactManifest:
        del repository, plan, created_at
        raise RollbackError("ROLLBACK_ARTIFACT_SINGLE_ROOT_FORBIDDEN")


class RollbackRebuildConfig(Protocol):
    policy_sha256: str
    model_descriptor_sha256: str | None


class SqliteRollbackWorkflow:
    """Production exact-plan workflow for one already-pinned database scope."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        database_scope: DatabaseScope,
        scope_sha256: str,
        content_store: ContentStore,
        clock: Clock | None = None,
        id_factory: IdFactory | None = None,
        approval_guard: ApprovalExecutionGuard | None = None,
        rebuild_coordinator: RebuildCoordinator | None = None,
        rebuild_policy_sha256: str | None = None,
        rebuild_model_descriptor_sha256: str | None = None,
        bound_session_id: str | None = None,
        wiki_service: WikiRevisionService | None = None,
        theory_service: TheoryRevisionService | None = None,
        scope_policy_repository: ScopePolicyRepository | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("ROLLBACK_SQLITE_CONNECTION_REQUIRED")
        if database_scope not in {"global", "client"}:
            raise ValueError("ROLLBACK_DATABASE_SCOPE_INVALID")
        if not isinstance(content_store, ContentStore):
            raise TypeError("ROLLBACK_CONTENT_STORE_REQUIRED")
        if approval_guard is not None and (
            not isinstance(approval_guard, ApprovalExecutionGuard)
            or getattr(approval_guard, "_connection", None) is not connection
        ):
            raise TypeError("ROLLBACK_APPROVAL_GUARD_INVALID")
        self._connection = connection
        self._database_scope = database_scope
        self._scope_sha256 = Sha256Hex(scope_sha256)
        self._store = content_store
        self._clock = clock if clock is not None else SystemClock()
        self._ids = id_factory if id_factory is not None else IdFactory(self._clock)
        self._guard = approval_guard
        self._rebuild = rebuild_coordinator
        self._rebuild_policy = rebuild_policy_sha256
        self._rebuild_model = rebuild_model_descriptor_sha256
        self._session_id = bound_session_id
        self._wikis = wiki_service
        self._theories = theory_service
        self._scope_policies = scope_policy_repository
        self._tombstones = TombstoneRepository(connection, clock=self._clock)

    @staticmethod
    def _wiki_successor_draft(
        current: WikiRevision,
        restore: WikiRevision,
    ) -> WikiRevisionDraft:
        """Rebuild the only allowed Wiki successor from authority revisions."""

        return WikiRevisionDraft(
            wiki_id=current.wiki_id,
            slug=restore.slug,
            title=restore.title,
            base_revision=current.revision,
            diff_kind="correct",
            sections=restore.sections,
            theory_revision_refs=restore.theory_revision_refs,
            relationships=restore.relationships,
            graph_relations=restore.graph_relations,
            review_due_at=restore.review_due_at,
            unresolved_questions=restore.unresolved_questions,
        )

    @staticmethod
    def _theory_successor_draft(
        current: TheoryRevision,
        restore: TheoryRevision,
        *,
        current_ref: VersionRef,
    ) -> TheoryRevisionDraft:
        """Rebuild the only allowed C1 successor from authority revisions."""

        return TheoryRevisionDraft(
            theory_id=current.theory_id,
            source_ref=restore.source_ref,
            document_sha256=restore.document_sha256,
            author=restore.author,
            declared_version=restore.declared_version,
            effective_from=restore.effective_from,
            effective_to=restore.effective_to,
            scope=restore.scope,
            core_claims=restore.core_claims,
            methods=restore.methods,
            contraindications=restore.contraindications,
            counterexamples=restore.counterexamples,
            passage_refs=restore.passage_refs,
            citation_refs=restore.citation_refs,
            empirical_support=restore.empirical_support,
            scope_policy_ref=restore.scope_policy_ref,
            supersedes_ref=current_ref,
        )

    def preview_profile_fact(
        self,
        *,
        fact_id: str,
        current_version: int,
        restore_version: int,
        reason: str,
    ) -> RollbackPreview:
        self._require_scope("client")
        if self._session_id is None:
            raise RollbackError("ROLLBACK_BOUND_SESSION_REQUIRED")
        coordinator = self._rebuild
        if coordinator is None or self._rebuild_policy is None:
            raise RollbackError("ROLLBACK_FULL_REBUILD_REQUIRED")
        repository = FactEventRepository(self._connection)
        current = repository.get_latest_event(fact_id)
        restore = self._fact_version(fact_id, restore_version)
        if current.event_version != current_version:
            raise RollbackError("ROLLBACK_CURRENT_VERSION_STALE")
        self._assert_fact_authority(current, restore)
        operation_id = self._ids.object_id("rollback_operation")
        mutation = CorrectMutation(
            target_event_id=current.event_id,
            correction_kind="value",
            previous_value_json=current.object_json,
            new_value_json=restore.object_json,
            reason=reason,
            effective_at=self._clock.now(),
        )
        base_versions = self._base_versions()
        base_map = {item.authority_key: item.version for item in base_versions}
        mutation_service = FactMutationService(
            repository,
            id_factory=self._ids,
            allow_test_approvals=False,
        )
        events, _merges, _evidence = mutation_service.materialize(
            mutation,
            commit_version=base_map["client_fact"] + 1,
            operation_id=operation_id,
            runtime_epoch=base_map["client_runtime"] + 1,
            now=self._clock.now(),
        )
        if len(events) != 1:
            raise RollbackError("ROLLBACK_FACT_EVENT_INVALID")
        new_event = events[0]
        rebuild_plan = self._prospective_fact_rebuild(
            new_event,
            operation_id=operation_id,
        )
        current_ref = self._fact_ref(current)
        restore_ref = self._fact_ref(restore)
        review = RollbackReview(
            rollback_kind="profile_fact",
            target_id=fact_id,
            current_version=current.event_version,
            restore_version=restore.event_version,
            reason=reason,
        )
        seed = FactRollbackPlan.model_construct(
            operation_id=operation_id,
            scope_sha256=self._scope_sha256,
            current_event_ref=current_ref,
            restore_event_ref=restore_ref,
            fact_id=fact_id,
            inverse_mutation=mutation,
            new_event=new_event,
            base_versions=base_versions,
            rebuild_plan=rebuild_plan,
            review=review,
            plan_sha256="0" * 64,
            descriptor=DraftDescriptor(
                purpose="rollback",
                target_id=fact_id,
                client_id=current.client_id,
                base_version=current.event_version,
                draft_sha256="0" * 64,
                session_id=self._session_id,
            ),
        )
        plan = self._finish_plan(seed)
        return self._store_preview("profile_fact", plan)

    def preview_wiki(
        self,
        *,
        wiki_id: str,
        current_version: int,
        restore_version: int,
        reason: str,
    ) -> RollbackPreview:
        self._require_scope("global")
        service = self._wikis
        if service is None:
            raise RollbackError("ROLLBACK_WIKI_SERVICE_REQUIRED")
        current = service.get(wiki_id, current_version)
        restore = service.get(wiki_id, restore_version)
        self._assert_wiki_authority(current, restore)
        operation_id = self._ids.object_id("rollback_operation")
        current_ref = self._wiki_ref(current)
        restore_ref = self._wiki_ref(restore)
        draft = self._wiki_successor_draft(current, restore)
        proposal = WikiProposal(
            proposal_id=self._ids.object_id("wiki_proposal"),
            draft=draft,
            draft_sha256=canonical_sha256(draft.model_dump(mode="json")),
            created_at=self._clock.now(),
        )
        base_versions = self._base_versions()
        review = RollbackReview(
            rollback_kind="wiki",
            target_id=wiki_id,
            current_version=current.revision,
            restore_version=restore.revision,
            reason=reason,
        )
        seed = WikiRollbackPlan.model_construct(
            operation_id=operation_id,
            scope_sha256=self._scope_sha256,
            current_revision_ref=current_ref,
            restore_revision_ref=restore_ref,
            new_revision=current.revision + 1,
            proposal=proposal,
            base_versions=base_versions,
            review=review,
            plan_sha256="0" * 64,
            descriptor=DraftDescriptor(
                purpose="rollback",
                target_id=wiki_id,
                base_version=current.revision,
                draft_sha256="0" * 64,
            ),
        )
        plan = self._finish_plan(seed)
        return self._store_preview("wiki", plan)

    def preview_theory(
        self,
        *,
        theory_id: str,
        current_version: int,
        restore_version: int,
        reason: str,
    ) -> RollbackPreview:
        self._require_scope("global")
        service = self._theories
        if service is None or self._scope_policies is None:
            raise RollbackError("ROLLBACK_THEORY_SERVICE_REQUIRED")
        current = service.get(theory_id, current_version)
        restore = service.get(theory_id, restore_version)
        self._assert_theory_authority(current, restore)
        operation_id = self._ids.object_id("rollback_operation")
        current_ref = service.version_ref(theory_id, current_version)
        restore_ref = service.version_ref(theory_id, restore_version)
        draft = self._theory_successor_draft(
            current,
            restore,
            current_ref=current_ref,
        )
        proposal = TheoryProposal(
            request_id=self._ids.object_id("theory_request"),
            draft=draft,
            draft_sha256=canonical_sha256(draft.model_dump(mode="json")),
            actor="rollback_workflow",
            created_at=self._clock.now(),
        )
        expected_claim_refs = tuple(
            VersionRef(
                object_id=self._ids.object_id("claim"),
                version=1,
                content_sha256=text_sha256(text),
            )
            for text in draft.core_claims
        )
        base_versions = self._base_versions()
        review = RollbackReview(
            rollback_kind="theory",
            target_id=theory_id,
            current_version=current.revision,
            restore_version=restore.revision,
            reason=reason,
        )
        seed = TheoryRollbackPlan.model_construct(
            operation_id=operation_id,
            scope_sha256=self._scope_sha256,
            current_revision_ref=current_ref,
            restore_revision_ref=restore_ref,
            new_revision=current.revision + 1,
            proposal=proposal,
            expected_claim_refs=expected_claim_refs,
            base_versions=base_versions,
            review=review,
            plan_sha256="0" * 64,
            descriptor=DraftDescriptor(
                purpose="rollback",
                target_id=theory_id,
                base_version=current.revision,
                draft_sha256="0" * 64,
            ),
        )
        plan = self._finish_plan(seed)
        return self._store_preview("theory", plan)

    def preview_artifact(
        self,
        *,
        artifact_key: str,
        current_version: int,
        restore_version: int,
        reason: str,
        source_plan_ref: ArchiveContentRef,
    ) -> RollbackPreview:
        """Bind one derived rollback request to an exact source successor.

        Both runtime closures are read only as immutable provenance evidence.
        Their bytes are never copied into a new manifest.  The source plan is
        the sole mutation authority and must lead to a complete next-version
        closure through the normal client rebuild or global combined
        publication path.
        """

        if restore_version >= current_version:
            raise RollbackError("ROLLBACK_ARTIFACT_VERSION_INVALID")
        source_ref = ArchiveContentRef.model_validate(source_plan_ref)
        source_envelope = self._read_envelope(source_ref)
        source_plan = source_envelope.plan
        if isinstance(source_plan, ArtifactRollbackPlan):
            raise RollbackError("ROLLBACK_ARTIFACT_SOURCE_PLAN_REQUIRED")
        if isinstance(source_plan, FactRollbackPlan):
            source_kind: Literal["profile_fact", "wiki", "theory"] = (
                "profile_fact"
            )
        elif isinstance(source_plan, WikiRollbackPlan):
            source_kind = "wiki"
        else:
            source_kind = "theory"
        if source_envelope.rollback_kind != source_kind:
            raise RollbackError("ROLLBACK_ARTIFACT_SOURCE_PLAN_MISMATCH")
        self._assert_plan_row(source_ref, source_envelope)
        if source_plan.review.reason != reason:
            raise RollbackError("ROLLBACK_ARTIFACT_SOURCE_PLAN_MISMATCH")
        current_epoch, current_closure = self._artifact_closure(
            current_version,
            require_active=True,
        )
        restore_epoch, restore_closure = self._artifact_closure(
            restore_version,
            require_active=False,
        )
        current_by_key = {
            root.artifact_key: ManifestRepository(self._connection).get(
                root.manifest_ref.object_id
            )
            for root in current_closure
        }
        restore_by_key = {
            root.artifact_key: ManifestRepository(self._connection).get(
                root.manifest_ref.object_id
            )
            for root in restore_closure
        }
        try:
            current_target = current_by_key[artifact_key]
            restore_target = restore_by_key[artifact_key]
        except KeyError:
            raise RollbackError("ROLLBACK_ARTIFACT_TARGET_INVALID") from None
        self._assert_artifact_source_lineage(
            source_plan,
            current=current_target,
            restore=restore_target,
        )
        base_versions = self._base_versions()
        if base_versions != source_plan.base_versions:
            raise RollbackError("ROLLBACK_ARTIFACT_SOURCE_PLAN_STALE")
        base_map = {value.authority_key: value.version for value in base_versions}
        authority_key = (
            "global_publication"
            if self._database_scope == "global"
            else "client_fact"
        )
        if base_map.get(authority_key) != current_version:
            raise RollbackError("ROLLBACK_ARTIFACT_AUTHORITY_VERSION_MISMATCH")
        if self._database_scope == "client":
            if not isinstance(source_plan, FactRollbackPlan):
                raise RollbackError("ROLLBACK_ARTIFACT_SOURCE_PLAN_MISMATCH")
            if (
                source_plan.rebuild_plan.purpose != "all"
                or source_plan.rebuild_plan.database_scope != "client"
            ):
                raise RollbackError("ROLLBACK_FULL_REBUILD_REQUIRED")
            client_id = source_plan.new_event.client_id
            session_id = source_plan.descriptor.session_id
            if session_id is None or session_id != self._session_id:
                raise RollbackError("ROLLBACK_ARTIFACT_SOURCE_PLAN_MISMATCH")
        else:
            if isinstance(source_plan, FactRollbackPlan):
                raise RollbackError("ROLLBACK_ARTIFACT_SOURCE_PLAN_MISMATCH")
            client_id = None
            session_id = None
        operation_id = self._ids.object_id("rollback_operation")
        review = RollbackReview(
            rollback_kind="artifact",
            target_id=artifact_key,
            current_version=current_version,
            restore_version=restore_version,
            reason=reason,
        )
        seed = ArtifactRollbackPlan.model_construct(
            operation_id=operation_id,
            database_scope=self._database_scope,
            scope_sha256=self._scope_sha256,
            target_artifact_key=artifact_key,
            current_runtime_epoch=current_epoch,
            restore_runtime_epoch=restore_epoch,
            current_closure=current_closure,
            restore_closure=restore_closure,
            source_plan_ref=source_ref,
            source_plan_sha256=source_plan.plan_sha256,
            source_rollback_kind=source_kind,
            new_source_version=current_version + 1,
            full_closure_purpose="all",
            requires_combined_publication=not isinstance(
                source_plan, FactRollbackPlan
            ),
            base_versions=base_versions,
            review=review,
            plan_sha256="0" * 64,
            descriptor=DraftDescriptor(
                purpose="rollback",
                target_id=artifact_key,
                client_id=client_id,
                base_version=current_version,
                draft_sha256="0" * 64,
                session_id=session_id,
            ),
        )
        plan = self._finish_plan(seed)
        return self._store_preview("artifact", plan)

    def commit(
        self,
        *,
        plan_ref: ArchiveContentRef,
        plan_sha256: str,
        base_versions: tuple[RollbackBaseVersion, ...],
        ticket: ApprovalExecutionTicket,
        approval_request: ApprovalRequest,
    ) -> RollbackCommit:
        guard = self._guard
        if guard is None:
            raise RollbackError("ROLLBACK_APPROVAL_REQUIRED")
        envelope = self._read_envelope(plan_ref)
        plan = envelope.plan
        approved = ApprovalExecutionTicket.model_validate(ticket)
        if (
            envelope.database_scope != self._database_scope
            or envelope.scope_sha256 != self._scope_sha256
            or plan.plan_sha256 != plan_sha256
            or plan.base_versions != base_versions
            or approved.operation_id != plan.operation_id
            or approved.descriptor != plan.descriptor
            or approved.target_scope_hash != self._scope_sha256
            or approved.receipt.approver_role != "primary_counselor"
        ):
            raise RollbackError("ROLLBACK_APPROVAL_BINDING_MISMATCH")
        request = ApprovalRequest.model_validate(approval_request)
        if (
            request.request_id != approved.request_id
            or request.descriptor != plan.descriptor
            or request.diff_object_ref != plan_ref.version_ref
        ):
            raise RollbackError("ROLLBACK_APPROVAL_BINDING_MISMATCH")
        self._assert_plan_row(plan_ref, envelope)
        if self._execution_applied(approved):
            return self._recover_applied(envelope, plan_ref, approved)
        if isinstance(plan, FactRollbackPlan):
            return self._commit_fact(plan, plan_ref, approved)
        if isinstance(plan, WikiRollbackPlan):
            return self._commit_wiki(plan, plan_ref, approved)
        if isinstance(plan, TheoryRollbackPlan):
            return self._commit_theory(plan, plan_ref, approved)
        return self._commit_artifact(plan, plan_ref, approved)

    def preflight_commit(
        self,
        *,
        plan_ref: ArchiveContentRef,
        plan_sha256: str,
        base_versions: tuple[RollbackBaseVersion, ...],
        approval_operation_id: str,
        approval_request: ApprovalRequest,
    ) -> None:
        """Validate the exact reviewed plan before binding a one-shot receipt.

        This check is intentionally read-only.  The target transaction repeats
        every authority check after ticket issuance, but malformed commit
        parameters must be rejected before ``issue_for_execution`` consumes the
        approval by binding it to an operation ID.
        """

        request = ApprovalRequest.model_validate(approval_request)
        self.preflight_plan_binding(
            plan_ref=plan_ref,
            plan_sha256=plan_sha256,
            base_versions=base_versions,
            approval_operation_id=approval_operation_id,
            approval_request_id=request.request_id,
        )
        envelope = self._read_envelope(plan_ref)
        plan = envelope.plan
        if (
            request.descriptor != plan.descriptor
            or request.diff_object_ref != plan_ref.version_ref
        ):
            raise RollbackError("ROLLBACK_APPROVAL_BINDING_MISMATCH")

    def preflight_plan_binding(
        self,
        *,
        plan_ref: ArchiveContentRef,
        plan_sha256: str,
        base_versions: tuple[RollbackBaseVersion, ...],
        approval_operation_id: str,
        approval_request_id: str,
    ) -> None:
        """Read-only exact-plan check usable inside a scoped client worker."""

        envelope = self._read_envelope(plan_ref)
        plan = envelope.plan
        if (
            plan.plan_sha256 != plan_sha256
            or plan.base_versions != base_versions
            or plan.operation_id != approval_operation_id
        ):
            raise RollbackError("ROLLBACK_APPROVAL_BINDING_MISMATCH")
        self._assert_plan_row(plan_ref, envelope)
        if isinstance(plan, ArtifactRollbackPlan):
            self._artifact_source_plan(plan)
        if not self._operation_preflight_applied(
            plan,
            approval_request_id=approval_request_id,
            approval_descriptor_sha256=descriptor_sha256(plan.descriptor),
        ):
            self._assert_base_versions(plan.base_versions)

    def _commit_fact(
        self,
        plan: FactRollbackPlan,
        plan_ref: ArchiveContentRef,
        ticket: ApprovalExecutionTicket,
        *,
        artifact_plan: ArtifactRollbackPlan | None = None,
    ) -> RollbackCommit:
        coordinator = self._rebuild
        guard = self._guard
        if coordinator is None or guard is None:
            raise RollbackError("ROLLBACK_FULL_REBUILD_REQUIRED")
        approval_plan: RollbackPlan = (
            plan if artifact_plan is None else artifact_plan
        )
        queued: list[str] = []

        def apply(connection: sqlite3.Connection) -> None:
            self._assert_target_transaction(connection)
            if artifact_plan is None:
                self._revalidate_plan_cas(plan_ref, plan)
            else:
                self._revalidate_artifact_plan(
                    plan_ref,
                    artifact_plan,
                    expected_source=plan,
                )
            self._assert_base_versions(plan.base_versions)
            current = FactEventRepository(connection).get_latest_event(plan.fact_id)
            restore = self._fact_version(plan.fact_id, plan.restore_event_ref.version)
            self._assert_fact_authority(current, restore)
            if (
                self._fact_ref(current) != plan.current_event_ref
                or self._fact_ref(restore) != plan.restore_event_ref
                or current.object_json != plan.inverse_mutation.previous_value_json
                or restore.object_json != plan.inverse_mutation.new_value_json
            ):
                raise RollbackError("ROLLBACK_AUTHORITY_CHANGED")
            FactEventRepository(connection).append_batch_in_transaction(
                base_commit_version=plan.new_event.commit_version - 1,
                events=(plan.new_event,),
            )
            current_plan = coordinator.plan(
                RebuildRequest(
                    database_scope="client",
                    source_intent_id=plan.operation_id,
                    scope_sha256=self._scope_sha256,
                    purpose="all",
                    policy_sha256=plan.rebuild_plan.policy_sha256,
                    model_descriptor_sha256=(
                        plan.rebuild_plan.model_descriptor_sha256
                    ),
                )
            )
            if current_plan != plan.rebuild_plan:
                raise RollbackError("ROLLBACK_REBUILD_AUTHORITY_CHANGED")
            self._write_lifecycle_attestation(
                connection,
                plan_ref,
                approval_plan,
                ticket,
            )
            job = coordinator.start_in_transaction(
                plan.rebuild_plan,
                idempotency_key=f"rollback:{approval_plan.operation_id}",
                approval_operation_id=ticket.operation_id,
                approval_request_id=ticket.request_id,
            )
            queued.append(job.job_id)

        proof = guard.apply_in_transaction(ticket, approval_plan.descriptor, apply)
        if not queued:
            row = self._connection.execute(
                "SELECT job_id FROM rebuild_jobs WHERE approval_operation_id = ? "
                "AND approval_request_id = ? AND plan_sha256 = ?",
                (ticket.operation_id, ticket.request_id, plan.rebuild_plan.plan_sha256),
            ).fetchone()
            if row is None:
                raise RollbackError("ROLLBACK_REBUILD_JOB_MISSING")
            queued.append(str(row[0]))
        stored = FactEventRepository(self._connection).get_event(plan.new_event.event_id)
        if stored != plan.new_event:
            raise RollbackError("ROLLBACK_COMMIT_ATTESTATION_INVALID")
        return RollbackCommit(
            summary=RollbackCommitSummary(
                rollback_kind=(
                    "profile_fact" if artifact_plan is None else "artifact"
                ),
                operation_id=approval_plan.operation_id,
                request_id=ticket.request_id,
                applied_commit_version=proof.applied_commit_version,
                successor_ref=self._fact_ref(stored),
                rebuild_job_id=queued[0],
                requires_combined_publication=False,
            ),
            proof=proof,
        )

    def _commit_wiki(
        self,
        plan: WikiRollbackPlan,
        plan_ref: ArchiveContentRef,
        ticket: ApprovalExecutionTicket,
        *,
        artifact_plan: ArtifactRollbackPlan | None = None,
    ) -> RollbackCommit:
        base_service = self._wikis
        guard = self._guard
        if base_service is None or guard is None:
            raise RollbackError("ROLLBACK_WIKI_SERVICE_REQUIRED")
        approval_plan: RollbackPlan = (
            plan if artifact_plan is None else artifact_plan
        )
        inner = DraftDescriptor(
            purpose="wiki_publish",
            target_id=plan.draft.wiki_id,
            base_version=plan.draft.base_revision,
            draft_sha256=plan.proposal.draft_sha256,
        )
        bridge = _RollbackApprovalBridge(
            guard=guard,
            ticket=ticket,
            outer_descriptor=approval_plan.descriptor,
            expected_inner_descriptor=inner,
            expected_operation_kind="wiki_approval_operation",
            before_write=(
                (lambda connection: self._revalidate_wiki(
                    connection, plan_ref, plan
                ))
                if artifact_plan is None
                else (
                    lambda connection: self._revalidate_artifact_source_wiki(
                        connection,
                        plan_ref,
                        artifact_plan,
                        plan,
                    )
                )
            ),
            attestation_writer=lambda connection: self._write_lifecycle_attestation(
                connection, plan_ref, approval_plan, ticket
            ),
        )
        # Never swap the executor on the shared service.  Two concurrent
        # requests must not be able to observe (or use) one another's one-shot
        # approval bridge.  This isolated facade shares only immutable
        # resolver callables and the scoped DB/CAS authority.
        service = WikiRevisionService(
            claim_resolver=getattr(base_service, "_claims", None),  # noqa: SLF001
            passage_resolver=getattr(  # noqa: SLF001
                base_service, "_passages", None
            ),
            theory_resolver=getattr(  # noqa: SLF001
                base_service, "_theories", None
            ),
            id_factory=self._ids,
            clock=self._clock,
            connection=self._connection,
            approval_executor=bridge,
            content_store=self._store,
        )
        service.restore_proposal(plan.proposal)
        revision = service.approve(
            plan.proposal.proposal_id,
            actor="primary_counselor",
            approval_request_id=ticket.request_id,
        )
        proof = bridge.proof
        if proof is None:
            raise RollbackError("ROLLBACK_COMMIT_ATTESTATION_INVALID")
        self._assert_prepared_wiki(plan, revision, ticket.request_id)
        return RollbackCommit(
            summary=RollbackCommitSummary(
                rollback_kind="wiki" if artifact_plan is None else "artifact",
                operation_id=approval_plan.operation_id,
                request_id=ticket.request_id,
                applied_commit_version=proof.applied_commit_version,
                successor_ref=self._wiki_ref(revision),
                requires_combined_publication=True,
            ),
            proof=proof,
        )

    def _commit_theory(
        self,
        plan: TheoryRollbackPlan,
        plan_ref: ArchiveContentRef,
        ticket: ApprovalExecutionTicket,
        *,
        artifact_plan: ArtifactRollbackPlan | None = None,
    ) -> RollbackCommit:
        base_service = self._theories
        guard = self._guard
        if base_service is None or guard is None or self._scope_policies is None:
            raise RollbackError("ROLLBACK_THEORY_SERVICE_REQUIRED")
        approval_plan: RollbackPlan = (
            plan if artifact_plan is None else artifact_plan
        )
        inner = DraftDescriptor(
            purpose="theory_approve",
            target_id=plan.draft.theory_id,
            base_version=plan.current_revision_ref.version,
            draft_sha256=plan.proposal.draft_sha256,
        )
        bridge = _RollbackApprovalBridge(
            guard=guard,
            ticket=ticket,
            outer_descriptor=approval_plan.descriptor,
            expected_inner_descriptor=inner,
            expected_operation_kind="theory_approval_operation",
            before_write=(
                (lambda connection: self._revalidate_theory(
                    connection, plan_ref, plan
                ))
                if artifact_plan is None
                else (
                    lambda connection: self._revalidate_artifact_source_theory(
                        connection,
                        plan_ref,
                        artifact_plan,
                        plan,
                    )
                )
            ),
            attestation_writer=lambda connection: self._write_lifecycle_attestation(
                connection, plan_ref, approval_plan, ticket
            ),
        )
        service = TheoryRevisionService(
            id_factory=cast(IdFactory, _ExactClaimIdFactory(plan.expected_claim_refs)),
            clock=self._clock,
            connection=self._connection,
            primary_role="primary_counselor",
            approval_executor=bridge,
            content_store=self._store,
            scope_policy_repository=self._scope_policies,
        )
        service.restore_proposal(plan.proposal)
        revision = service.approve(
            plan.proposal.request_id,
            actor="primary_counselor",
            approval_request_id=ticket.request_id,
        )
        proof = bridge.proof
        if proof is None:
            raise RollbackError("ROLLBACK_COMMIT_ATTESTATION_INVALID")
        self._assert_prepared_theory(plan, revision, ticket.request_id)
        return RollbackCommit(
            summary=RollbackCommitSummary(
                rollback_kind="theory" if artifact_plan is None else "artifact",
                operation_id=approval_plan.operation_id,
                request_id=ticket.request_id,
                applied_commit_version=proof.applied_commit_version,
                successor_ref=service.version_ref(
                    revision.theory_id,
                    revision.revision,
                ),
                requires_combined_publication=True,
            ),
            proof=proof,
        )

    def _commit_artifact(
        self,
        plan: ArtifactRollbackPlan,
        plan_ref: ArchiveContentRef,
        ticket: ApprovalExecutionTicket,
    ) -> RollbackCommit:
        source = self._artifact_source_plan(plan)
        if isinstance(source, FactRollbackPlan):
            return self._commit_fact(
                source,
                plan_ref,
                ticket,
                artifact_plan=plan,
            )
        if isinstance(source, WikiRollbackPlan):
            return self._commit_wiki(
                source,
                plan_ref,
                ticket,
                artifact_plan=plan,
            )
        return self._commit_theory(
            source,
            plan_ref,
            ticket,
            artifact_plan=plan,
        )

    def _recover_applied(
        self,
        envelope: RollbackPlanEnvelope,
        plan_ref: ArchiveContentRef,
        ticket: ApprovalExecutionTicket,
    ) -> RollbackCommit:
        guard = self._guard
        if guard is None:
            raise RollbackError("ROLLBACK_APPROVAL_REQUIRED")
        self._revalidate_plan_cas(plan_ref, envelope.plan)
        proof = guard.apply_in_transaction(
            ticket,
            envelope.plan.descriptor,
            lambda _connection: (_ for _ in ()).throw(
                RollbackError("ROLLBACK_REPLAY_EXECUTED_CALLBACK")
            ),
        )
        plan = envelope.plan
        if isinstance(plan, FactRollbackPlan):
            event = FactEventRepository(self._connection).get_event(
                plan.new_event.event_id
            )
            if event != plan.new_event:
                raise RollbackError("ROLLBACK_COMMIT_ATTESTATION_INVALID")
            row = self._connection.execute(
                "SELECT job_id FROM rebuild_jobs WHERE approval_operation_id = ? "
                "AND approval_request_id = ? AND plan_sha256 = ?",
                (ticket.operation_id, ticket.request_id, plan.rebuild_plan.plan_sha256),
            ).fetchone()
            if row is None:
                raise RollbackError("ROLLBACK_REBUILD_JOB_MISSING")
            summary = RollbackCommitSummary(
                rollback_kind="profile_fact",
                operation_id=plan.operation_id,
                request_id=ticket.request_id,
                applied_commit_version=proof.applied_commit_version,
                successor_ref=self._fact_ref(event),
                rebuild_job_id=str(row[0]),
                requires_combined_publication=False,
            )
        elif isinstance(plan, WikiRollbackPlan):
            wiki_service = self._wikis
            if wiki_service is None:
                raise RollbackError("ROLLBACK_WIKI_SERVICE_REQUIRED")
            wiki_revision = wiki_service.get(
                plan.draft.wiki_id,
                plan.new_revision,
            )
            self._assert_prepared_wiki(plan, wiki_revision, ticket.request_id)
            summary = RollbackCommitSummary(
                rollback_kind="wiki",
                operation_id=plan.operation_id,
                request_id=ticket.request_id,
                applied_commit_version=proof.applied_commit_version,
                successor_ref=self._wiki_ref(wiki_revision),
                requires_combined_publication=True,
            )
        elif isinstance(plan, TheoryRollbackPlan):
            theory_service = self._theories
            if theory_service is None:
                raise RollbackError("ROLLBACK_THEORY_SERVICE_REQUIRED")
            theory_revision = theory_service.get(
                plan.draft.theory_id,
                plan.new_revision,
            )
            self._assert_prepared_theory(
                plan,
                theory_revision,
                ticket.request_id,
            )
            summary = RollbackCommitSummary(
                rollback_kind="theory",
                operation_id=plan.operation_id,
                request_id=ticket.request_id,
                applied_commit_version=proof.applied_commit_version,
                successor_ref=theory_service.version_ref(
                    theory_revision.theory_id,
                    theory_revision.revision,
                ),
                requires_combined_publication=True,
            )
        else:
            source = self._artifact_source_plan(plan)
            if isinstance(source, FactRollbackPlan):
                event = FactEventRepository(self._connection).get_event(
                    source.new_event.event_id
                )
                if event != source.new_event:
                    raise RollbackError("ROLLBACK_COMMIT_ATTESTATION_INVALID")
                row = self._connection.execute(
                    "SELECT job_id FROM rebuild_jobs "
                    "WHERE approval_operation_id = ? "
                    "AND approval_request_id = ? AND plan_sha256 = ?",
                    (
                        ticket.operation_id,
                        ticket.request_id,
                        source.rebuild_plan.plan_sha256,
                    ),
                ).fetchone()
                if row is None:
                    raise RollbackError("ROLLBACK_REBUILD_JOB_MISSING")
                successor_ref = self._fact_ref(event)
                rebuild_job_id: str | None = str(row[0])
            elif isinstance(source, WikiRollbackPlan):
                wiki_service = self._wikis
                if wiki_service is None:
                    raise RollbackError("ROLLBACK_WIKI_SERVICE_REQUIRED")
                wiki_revision = wiki_service.get(
                    source.draft.wiki_id,
                    source.new_revision,
                )
                self._assert_prepared_wiki(
                    source,
                    wiki_revision,
                    ticket.request_id,
                )
                successor_ref = self._wiki_ref(wiki_revision)
                rebuild_job_id = None
            else:
                theory_service = self._theories
                if theory_service is None:
                    raise RollbackError("ROLLBACK_THEORY_SERVICE_REQUIRED")
                theory_revision = theory_service.get(
                    source.draft.theory_id,
                    source.new_revision,
                )
                self._assert_prepared_theory(
                    source,
                    theory_revision,
                    ticket.request_id,
                )
                successor_ref = theory_service.version_ref(
                    theory_revision.theory_id,
                    theory_revision.revision,
                )
                rebuild_job_id = None
            summary = RollbackCommitSummary(
                rollback_kind="artifact",
                operation_id=plan.operation_id,
                request_id=ticket.request_id,
                applied_commit_version=proof.applied_commit_version,
                successor_ref=successor_ref,
                rebuild_job_id=rebuild_job_id,
                requires_combined_publication=plan.requires_combined_publication,
            )
        return RollbackCommit(summary=summary, proof=proof)

    def _prospective_fact_rebuild(
        self,
        event: FactEvent,
        *,
        operation_id: str,
    ) -> RebuildPlan:
        coordinator = self._rebuild
        if coordinator is None:
            raise RollbackError("ROLLBACK_FULL_REBUILD_REQUIRED")
        savepoint = "rollback_fact_preview"
        self._connection.execute(f"SAVEPOINT {savepoint}")
        try:
            repository = FactEventRepository(self._connection)
            repository.append_batch_in_transaction(
                base_commit_version=event.commit_version - 1,
                events=(event,),
            )
            plan = coordinator.plan(
                RebuildRequest(
                    database_scope="client",
                    source_intent_id=operation_id,
                    scope_sha256=self._scope_sha256,
                    purpose="all",
                    policy_sha256=self._rebuild_policy,
                    model_descriptor_sha256=self._rebuild_model,
                )
            )
            coordinator.assert_executable(plan)
        finally:
            self._connection.execute(f"ROLLBACK TO {savepoint}")
            self._connection.execute(f"RELEASE {savepoint}")
        return plan

    def _artifact_source_plan(
        self,
        plan: ArtifactRollbackPlan,
    ) -> SourceRollbackPlan:
        envelope = self._read_envelope(plan.source_plan_ref)
        source = envelope.plan
        if (
            isinstance(source, ArtifactRollbackPlan)
            or envelope.rollback_kind != plan.source_rollback_kind
            or source.plan_sha256 != plan.source_plan_sha256
            or source.base_versions != plan.base_versions
            or envelope.database_scope != plan.database_scope
            or envelope.scope_sha256 != plan.scope_sha256
        ):
            raise RollbackError("ROLLBACK_ARTIFACT_SOURCE_PLAN_MISMATCH")
        self._assert_plan_row(plan.source_plan_ref, envelope)
        return source

    def _revalidate_artifact_plan(
        self,
        plan_ref: ArchiveContentRef,
        plan: ArtifactRollbackPlan,
        *,
        expected_source: SourceRollbackPlan,
    ) -> None:
        self._revalidate_plan_cas(plan_ref, plan)
        source = self._artifact_source_plan(plan)
        if source != expected_source:
            raise RollbackError("ROLLBACK_ARTIFACT_SOURCE_PLAN_MISMATCH")
        self._assert_base_versions(plan.base_versions)
        current_epoch, current = self._artifact_closure(
            plan.review.current_version,
            require_active=True,
        )
        restore_epoch, restore = self._artifact_closure(
            plan.review.restore_version,
            require_active=False,
        )
        if (
            current_epoch != plan.current_runtime_epoch
            or restore_epoch != plan.restore_runtime_epoch
            or current != plan.current_closure
            or restore != plan.restore_closure
        ):
            raise RollbackError("ROLLBACK_ARTIFACT_CLOSURE_CHANGED")
        repository = ManifestRepository(self._connection)
        current_target = repository.get(
            next(
                root.manifest_ref.object_id
                for root in current
                if root.artifact_key == plan.target_artifact_key
            )
        )
        restore_target = repository.get(
            next(
                root.manifest_ref.object_id
                for root in restore
                if root.artifact_key == plan.target_artifact_key
            )
        )
        self._assert_artifact_source_lineage(
            source,
            current=current_target,
            restore=restore_target,
        )

    def _revalidate_artifact_source_wiki(
        self,
        connection: sqlite3.Connection,
        plan_ref: ArchiveContentRef,
        artifact_plan: ArtifactRollbackPlan,
        source_plan: WikiRollbackPlan,
    ) -> None:
        self._assert_target_transaction(connection)
        self._revalidate_artifact_plan(
            plan_ref,
            artifact_plan,
            expected_source=source_plan,
        )
        self._revalidate_wiki(connection, artifact_plan.source_plan_ref, source_plan)

    def _revalidate_artifact_source_theory(
        self,
        connection: sqlite3.Connection,
        plan_ref: ArchiveContentRef,
        artifact_plan: ArtifactRollbackPlan,
        source_plan: TheoryRollbackPlan,
    ) -> None:
        self._assert_target_transaction(connection)
        self._revalidate_artifact_plan(
            plan_ref,
            artifact_plan,
            expected_source=source_plan,
        )
        self._revalidate_theory(
            connection,
            artifact_plan.source_plan_ref,
            source_plan,
        )

    def _artifact_closure(
        self,
        source_version: int,
        *,
        require_active: bool,
    ) -> tuple[int, tuple[ArtifactClosureRoot, ...]]:
        if type(source_version) is not int or source_version <= 0:
            raise RollbackError("ROLLBACK_ARTIFACT_VERSION_INVALID")
        if require_active:
            rows = self._connection.execute(
                "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
            ).fetchall()
        else:
            rows = self._connection.execute(
                "SELECT epoch FROM runtime_epochs WHERE state IN ('ACTIVE','RETIRED') "
                "ORDER BY epoch DESC"
            ).fetchall()
        if require_active and len(rows) != 1:
            raise RollbackError("ROLLBACK_ACTIVE_EPOCH_INVALID")
        for row in rows:
            epoch = int(row[0])
            try:
                roots = self._artifact_closure_at_epoch(
                    epoch,
                    source_version=source_version,
                )
            except RollbackError:
                if require_active:
                    raise
                continue
            return epoch, roots
        raise RollbackError("ROLLBACK_ARTIFACT_CLOSURE_NOT_FOUND")

    def _artifact_closure_at_epoch(
        self,
        epoch: int,
        *,
        source_version: int,
    ) -> tuple[ArtifactClosureRoot, ...]:
        expected_keys = (
            (
                "c1_revision",
                "claims",
                "graph",
                "knowledge_registry",
                "lexical",
                "vector",
                "wiki_index",
                "wiki_page",
            )
            if self._database_scope == "global"
            else (
                "client_fact_snapshot",
                "client_graph",
                "client_profile",
                "private_archive",
            )
        )
        rows = self._connection.execute(
            "SELECT artifact_key, manifest_id FROM active_artifacts "
            "WHERE epoch = ? ORDER BY artifact_key",
            (epoch,),
        ).fetchall()
        if tuple(str(row[0]) for row in rows) != expected_keys:
            raise RollbackError("ROLLBACK_ARTIFACT_CLOSURE_INCOMPLETE")
        repository = ManifestRepository(self._connection)
        roots: list[ArtifactClosureRoot] = []
        for artifact_key, manifest_id in rows:
            manifest = repository.get(str(manifest_id))
            if (
                manifest.artifact_key != str(artifact_key)
                or manifest.source_version != source_version
                or manifest.state != "ACTIVE"
                or not manifest.verified
            ):
                raise RollbackError("ROLLBACK_ARTIFACT_CLOSURE_VERSION_MISMATCH")
            self._verify_manifest_cas_and_visibility(manifest)
            roots.append(
                ArtifactClosureRoot(
                    artifact_key=str(artifact_key),
                    manifest_ref=VersionRef(
                        object_id=manifest.manifest_id,
                        version=manifest.source_version,
                        content_sha256=manifest.manifest_sha256,
                    ),
                )
            )
        return tuple(roots)

    def _verify_manifest_cas_and_visibility(
        self,
        manifest: ArtifactManifest,
    ) -> None:
        for member in manifest.members:
            self._store.read_verified(
                self._store.reference(
                    content_sha256=member.object_sha256,
                    media_type=member.media_type,
                    size_bytes=member.size_bytes,
                )
            )
            identity = ObjectIdentity(member.object_type, member.object_id)
            if self._tombstones.has_direct(identity) or any(
                self._tombstones.has_lineage_hash(value)
                for value in member.source_lineage_hashes
            ):
                raise RollbackError("ROLLBACK_DEPENDENCY_TOMBSTONED")

    def _assert_artifact_source_lineage(
        self,
        plan: SourceRollbackPlan,
        *,
        current: ArtifactManifest,
        restore: ArtifactManifest,
    ) -> None:
        if isinstance(plan, FactRollbackPlan):
            current_lineage = {
                value
                for member in current.members
                for value in member.source_lineage_hashes
            }
            restore_lineage = {
                value
                for member in restore.members
                for value in member.source_lineage_hashes
            }
            expected_current = {
                lineage_hash("fact_event", plan.current_event_ref.object_id)
            }
            expected_restore = {
                lineage_hash("fact_event", plan.restore_event_ref.object_id)
            }
        elif isinstance(plan, WikiRollbackPlan):
            wiki_service = self._wikis
            if wiki_service is None:
                raise RollbackError("ROLLBACK_WIKI_SERVICE_REQUIRED")
            current_revision = wiki_service.get(
                plan.current_revision_ref.object_id,
                plan.current_revision_ref.version,
            )
            restore_revision = wiki_service.get(
                plan.restore_revision_ref.object_id,
                plan.restore_revision_ref.version,
            )
            if current.artifact_key == "wiki_page" and restore.artifact_key == (
                "wiki_page"
            ):
                if not (
                    self._manifest_has_member(
                        current,
                        object_type="wiki",
                        object_id=current_revision.wiki_id,
                        content_sha256=current_revision.body_sha256,
                    )
                    and self._manifest_has_member(
                        restore,
                        object_type="wiki",
                        object_id=restore_revision.wiki_id,
                        content_sha256=restore_revision.body_sha256,
                    )
                ):
                    raise RollbackError("ROLLBACK_ARTIFACT_SOURCE_LINEAGE_MISMATCH")
                return
            self._assert_derived_artifact_authority(
                current,
                authority_kind="wiki",
                object_id=current_revision.wiki_id,
                version=current_revision.revision,
                object_sha256=current_revision.body_sha256,
            )
            self._assert_derived_artifact_authority(
                restore,
                authority_kind="wiki",
                object_id=restore_revision.wiki_id,
                version=restore_revision.revision,
                object_sha256=restore_revision.body_sha256,
            )
            return
        else:
            theory_service = self._theories
            if theory_service is None:
                raise RollbackError("ROLLBACK_THEORY_SERVICE_REQUIRED")
            current_theory = theory_service.get(
                plan.current_revision_ref.object_id,
                plan.current_revision_ref.version,
            )
            restore_theory = theory_service.get(
                plan.restore_revision_ref.object_id,
                plan.restore_revision_ref.version,
            )
            if current.artifact_key == "c1_revision" and restore.artifact_key == (
                "c1_revision"
            ):
                current_digest = self._theory_object_digest(
                    current_theory.theory_id,
                    current_theory.revision,
                )
                restore_digest = self._theory_object_digest(
                    restore_theory.theory_id,
                    restore_theory.revision,
                )
                if not (
                    self._manifest_has_member(
                        current,
                        object_type="theory",
                        object_id=current_theory.theory_id,
                        content_sha256=current_digest,
                    )
                    and self._manifest_has_member(
                        restore,
                        object_type="theory",
                        object_id=restore_theory.theory_id,
                        content_sha256=restore_digest,
                    )
                ):
                    raise RollbackError("ROLLBACK_ARTIFACT_SOURCE_LINEAGE_MISMATCH")
                return
            self._assert_derived_artifact_authority(
                current,
                authority_kind="theory",
                object_id=current_theory.theory_id,
                version=current_theory.revision,
                object_sha256=self._theory_object_digest(
                    current_theory.theory_id,
                    current_theory.revision,
                ),
            )
            self._assert_derived_artifact_authority(
                restore,
                authority_kind="theory",
                object_id=restore_theory.theory_id,
                version=restore_theory.revision,
                object_sha256=self._theory_object_digest(
                    restore_theory.theory_id,
                    restore_theory.revision,
                ),
            )
            return
        if (
            not expected_current
            or not expected_restore
            or not expected_current <= current_lineage
            or not expected_restore <= restore_lineage
        ):
            raise RollbackError("ROLLBACK_ARTIFACT_SOURCE_LINEAGE_MISMATCH")

    def _assert_derived_artifact_authority(
        self,
        manifest: ArtifactManifest,
        *,
        authority_kind: Literal["wiki", "theory"],
        object_id: str,
        version: int,
        object_sha256: str,
    ) -> None:
        """Require an exact revision tuple in the derived builder snapshot."""

        derived_keys = {
            "wiki_index",
            "knowledge_registry",
            "graph",
            "lexical",
            "vector",
        }
        if manifest.artifact_key not in derived_keys:
            raise RollbackError("ROLLBACK_ARTIFACT_SOURCE_LINEAGE_MISMATCH")
        role = f"{manifest.artifact_key}_builder_input"
        members = tuple(
            member for member in manifest.members if member.object_type == role
        )
        if len(members) != 1:
            raise RollbackError("ROLLBACK_ARTIFACT_SOURCE_LINEAGE_MISMATCH")
        member = members[0]
        try:
            payload = self._store.read_verified(
                self._store.reference(
                    content_sha256=member.object_sha256,
                    media_type=member.media_type,
                    size_bytes=member.size_bytes,
                )
            )
            builder = DerivedArtifactBuilderInputV2.model_validate_json(
                payload,
                strict=True,
            )
        except (OSError, TypeError, ValueError):
            raise RollbackError(
                "ROLLBACK_ARTIFACT_SOURCE_LINEAGE_MISMATCH"
            ) from None
        authority = getattr(builder.authority_snapshot, authority_kind)
        if (
            canonical_json_bytes(builder.model_dump(mode="json")) != payload
            or builder.artifact_kind != manifest.artifact_key
            or builder.source_catalog_version != manifest.source_version
            or member.source_version != manifest.source_version
            or authority is None
            or authority.object_id != object_id
            or authority.version != version
            or authority.object_sha256 != object_sha256
        ):
            raise RollbackError("ROLLBACK_ARTIFACT_SOURCE_LINEAGE_MISMATCH")

    @staticmethod
    def _manifest_has_member(
        manifest: ArtifactManifest,
        *,
        object_type: str,
        object_id: str,
        content_sha256: str,
    ) -> bool:
        return any(
            member.object_type == object_type
            and member.object_id == object_id
            and member.object_sha256 == content_sha256
            for member in manifest.members
        )

    def _wiki_source_lineages(self, revision: WikiRevision) -> set[str]:
        source_ids = {
            source.object_id
            for relationship in revision.relationships
            for source in relationship.source_refs
        }
        for section in revision.sections:
            for claim in section.claim_refs:
                row = self._connection.execute(
                    "SELECT source_id FROM claims WHERE claim_id = ? AND version = ?",
                    (claim.object_id, claim.version),
                ).fetchone()
                if row is None:
                    raise RollbackError("ROLLBACK_DEPENDENCY_STALE")
                source_ids.add(str(row[0]))
            for passage in section.passage_refs:
                row = self._connection.execute(
                    "SELECT source_id FROM passages "
                    "WHERE passage_id = ? AND version = ?",
                    (passage.object_id, passage.version),
                ).fetchone()
                if row is None:
                    raise RollbackError("ROLLBACK_DEPENDENCY_STALE")
                source_ids.add(str(row[0]))
        for theory in revision.theory_revision_refs:
            row = self._connection.execute(
                "SELECT source_id FROM theory_revisions "
                "WHERE theory_id = ? AND revision = ?",
                (theory.object_id, theory.version),
            ).fetchone()
            if row is None:
                raise RollbackError("ROLLBACK_DEPENDENCY_STALE")
            source_ids.add(str(row[0]))
        return {lineage_hash("source", value) for value in source_ids}

    def _theory_source_lineages(self, revision: TheoryRevision) -> set[str]:
        source_ids = {
            revision.source_ref.object_id,
            *(value.object_id for value in revision.citation_refs),
        }
        for passage in revision.passage_refs:
            row = self._connection.execute(
                "SELECT source_id FROM passages "
                "WHERE passage_id = ? AND version = ?",
                (passage.object_id, passage.version),
            ).fetchone()
            if row is None:
                raise RollbackError("ROLLBACK_DEPENDENCY_STALE")
            source_ids.add(str(row[0]))
        return {lineage_hash("source", value) for value in source_ids}

    def _theory_object_digest(self, theory_id: str, revision: int) -> str:
        row = self._connection.execute(
            "SELECT revision_object_ref FROM theory_revisions "
            "WHERE theory_id = ? AND revision = ?",
            (theory_id, revision),
        ).fetchone()
        if row is None or not str(row[0]).startswith("sha256:"):
            raise RollbackError("ROLLBACK_DEPENDENCY_STALE")
        digest = str(row[0])[7:]
        if len(digest) != 64:
            raise RollbackError("ROLLBACK_DEPENDENCY_STALE")
        return digest

    def _revalidate_wiki(
        self,
        connection: sqlite3.Connection,
        plan_ref: ArchiveContentRef,
        plan: WikiRollbackPlan,
    ) -> None:
        self._assert_target_transaction(connection)
        self._revalidate_plan_cas(plan_ref, plan)
        self._assert_base_versions(plan.base_versions)
        service = self._wikis
        if service is None:
            raise RollbackError("ROLLBACK_WIKI_SERVICE_REQUIRED")
        current = service.get(
            plan.current_revision_ref.object_id,
            plan.current_revision_ref.version,
        )
        restore = service.get(
            plan.restore_revision_ref.object_id,
            plan.restore_revision_ref.version,
        )
        self._assert_wiki_authority(current, restore)
        if (
            self._wiki_ref(current) != plan.current_revision_ref
            or self._wiki_ref(restore) != plan.restore_revision_ref
        ):
            raise RollbackError("ROLLBACK_AUTHORITY_CHANGED")
        expected_draft = self._wiki_successor_draft(current, restore)
        expected_proposal = WikiProposal(
            proposal_id=plan.proposal.proposal_id,
            draft=expected_draft,
            draft_sha256=canonical_sha256(expected_draft.model_dump(mode="json")),
            created_at=plan.proposal.created_at,
        )
        if plan.proposal != expected_proposal:
            raise RollbackError("ROLLBACK_PROPOSAL_AUTHORITY_MISMATCH")

    def _revalidate_theory(
        self,
        connection: sqlite3.Connection,
        plan_ref: ArchiveContentRef,
        plan: TheoryRollbackPlan,
    ) -> None:
        self._assert_target_transaction(connection)
        self._revalidate_plan_cas(plan_ref, plan)
        self._assert_base_versions(plan.base_versions)
        service = self._theories
        if service is None:
            raise RollbackError("ROLLBACK_THEORY_SERVICE_REQUIRED")
        current = service.get(
            plan.current_revision_ref.object_id,
            plan.current_revision_ref.version,
        )
        restore = service.get(
            plan.restore_revision_ref.object_id,
            plan.restore_revision_ref.version,
        )
        self._assert_theory_authority(current, restore)
        if (
            service.version_ref(current.theory_id, current.revision)
            != plan.current_revision_ref
            or service.version_ref(restore.theory_id, restore.revision)
            != plan.restore_revision_ref
        ):
            raise RollbackError("ROLLBACK_AUTHORITY_CHANGED")
        expected_draft = self._theory_successor_draft(
            current,
            restore,
            current_ref=plan.current_revision_ref,
        )
        expected_proposal = TheoryProposal(
            request_id=plan.proposal.request_id,
            draft=expected_draft,
            draft_sha256=canonical_sha256(expected_draft.model_dump(mode="json")),
            actor="rollback_workflow",
            created_at=plan.proposal.created_at,
        )
        if plan.proposal != expected_proposal:
            raise RollbackError("ROLLBACK_PROPOSAL_AUTHORITY_MISMATCH")

    def _assert_fact_authority(
        self,
        current: FactEvent,
        restore: FactEvent,
    ) -> None:
        if (
            current.fact_id != restore.fact_id
            or current.client_id != restore.client_id
            or restore.event_version >= current.event_version
            or current.event_id == restore.event_id
            or current.review_status != "approved"
            or current.validity_status != "active"
            or current.resolution_status != "open"
            or restore.review_status != "approved"
            or restore.validity_status == "invalidated"
            or current.object_json == restore.object_json
        ):
            raise RollbackError("ROLLBACK_FACT_LINEAGE_MISMATCH")
        for event in (current, restore):
            for event_id in (event.event_id, *event.source_event_ids):
                self._assert_not_tombstoned("fact_event", event_id)

    def _assert_wiki_authority(
        self,
        current: WikiRevision,
        restore: WikiRevision,
    ) -> None:
        if (
            current.wiki_id != restore.wiki_id
            or restore.revision >= current.revision
            or current.status != "active"
            or restore.status in {"revoked", "rejected"}
        ):
            raise RollbackError("ROLLBACK_WIKI_LINEAGE_MISMATCH")
        self._assert_not_tombstoned("wiki_revision", current.wiki_id)
        self._assert_not_tombstoned("wiki_revision", f"{current.wiki_id}@{current.revision}")
        self._assert_not_tombstoned("wiki_revision", f"{restore.wiki_id}@{restore.revision}")
        for reference in restore.theory_revision_refs:
            row = self._connection.execute(
                "SELECT revision_sha256, status FROM theory_revisions "
                "WHERE theory_id = ? AND revision = ?",
                (reference.object_id, reference.version),
            ).fetchone()
            if row is None or row[0] != reference.content_sha256 or row[1] not in {
                "ACTIVE",
                "PREPARED",
            }:
                raise RollbackError("ROLLBACK_DEPENDENCY_STALE")
            self._assert_not_tombstoned("theory_revision", reference.object_id)
            self._assert_not_tombstoned(
                "theory_revision", f"{reference.object_id}@{reference.version}"
            )
        for section in restore.sections:
            for claim in section.claim_refs:
                row = self._connection.execute(
                    "SELECT claim_sha256, review_status FROM claims "
                    "WHERE claim_id = ? AND version = ?",
                    (claim.object_id, claim.version),
                ).fetchone()
                if row != (claim.content_sha256, "APPROVED"):
                    raise RollbackError("ROLLBACK_DEPENDENCY_STALE")
                self._assert_not_tombstoned("claim", claim.object_id)
                self._assert_not_tombstoned(
                    "claim_revision", f"{claim.object_id}@{claim.version}"
                )
            for passage in section.passage_refs:
                row = self._connection.execute(
                    "SELECT normalized_text_sha256, review_status FROM passages "
                    "WHERE passage_id = ? AND version = ?",
                    (passage.object_id, passage.version),
                ).fetchone()
                if row != (passage.content_sha256, "APPROVED"):
                    raise RollbackError("ROLLBACK_DEPENDENCY_STALE")
                self._assert_not_tombstoned("passage", passage.object_id)
        for relationship in restore.relationships:
            for source in relationship.source_refs:
                row = self._connection.execute(
                    "SELECT content_sha256, status FROM source_versions "
                    "WHERE source_id = ? AND version = ?",
                    (source.object_id, source.version),
                ).fetchone()
                if row is None or row[0] != source.content_sha256 or row[1] not in {
                    "REVIEWED",
                    "APPROVED",
                }:
                    raise RollbackError("ROLLBACK_DEPENDENCY_STALE")
                self._assert_not_tombstoned("source", source.object_id)

    def _assert_theory_authority(
        self,
        current: TheoryRevision,
        restore: TheoryRevision,
    ) -> None:
        if (
            current.theory_id != restore.theory_id
            or restore.revision >= current.revision
            or current.status != "active"
            or restore.status in {"revoked", "expired"}
        ):
            raise RollbackError("ROLLBACK_THEORY_LINEAGE_MISMATCH")
        for identity in (
            current.theory_id,
            f"{current.theory_id}@{current.revision}",
            f"{restore.theory_id}@{restore.revision}",
        ):
            self._assert_not_tombstoned("theory_revision", identity)
        source_refs = tuple({restore.source_ref, *restore.citation_refs})
        for source in source_refs:
            row = self._connection.execute(
                "SELECT content_sha256, status FROM source_versions "
                "WHERE source_id = ? AND version = ?",
                (source.object_id, source.version),
            ).fetchone()
            if row is None or row[0] != source.content_sha256 or row[1] not in {
                "DRAFT",
                "REVIEWED",
                "APPROVED",
            }:
                raise RollbackError("ROLLBACK_DEPENDENCY_STALE")
            self._assert_not_tombstoned("source", source.object_id)
        for passage in restore.passage_refs:
            row = self._connection.execute(
                "SELECT normalized_text_sha256, review_status FROM passages "
                "WHERE passage_id = ? AND version = ?",
                (passage.object_id, passage.version),
            ).fetchone()
            if row != (passage.content_sha256, "APPROVED"):
                raise RollbackError("ROLLBACK_DEPENDENCY_STALE")
            self._assert_not_tombstoned("passage", passage.object_id)
        policy = restore.scope_policy_ref
        row = self._connection.execute(
            "SELECT cas_object_sha256, status FROM scope_policy_versions "
            "WHERE policy_id = ? AND version = ?",
            (policy.object_id, policy.version),
        ).fetchone()
        if row != (policy.content_sha256, "APPROVED"):
            raise RollbackError("ROLLBACK_DEPENDENCY_STALE")
        self._assert_not_tombstoned("scope_policy", policy.object_id)

    def _assert_not_tombstoned(self, object_type: str, object_id: str) -> None:
        if self._tombstones.has_lineage(ObjectIdentity(object_type, object_id)):
            raise RollbackError("ROLLBACK_DEPENDENCY_TOMBSTONED")

    def _fact_version(self, fact_id: str, version: int) -> FactEvent:
        rows = self._connection.execute(
            "SELECT event_id FROM fact_events WHERE fact_id = ? AND event_version = ?",
            (fact_id, version),
        ).fetchall()
        if len(rows) != 1:
            raise RollbackError("ROLLBACK_FACT_VERSION_NOT_FOUND")
        return FactEventRepository(self._connection).get_event(str(rows[0][0]))

    @staticmethod
    def _fact_ref(event: FactEvent) -> VersionRef:
        return VersionRef(
            object_id=event.event_id,
            version=event.event_version,
            content_sha256=canonical_sha256(event.model_dump(mode="json")),
        )

    @staticmethod
    def _wiki_ref(revision: WikiRevision) -> VersionRef:
        return VersionRef(
            object_id=revision.wiki_id,
            version=revision.revision,
            content_sha256=canonical_sha256(revision.model_dump(mode="json")),
        )

    def _base_versions(self) -> tuple[RollbackBaseVersion, ...]:
        tombstone = self._connection.execute(
            "SELECT tombstone_epoch FROM deletion_authority_state WHERE singleton = 1"
        ).fetchone()
        if tombstone is None or type(tombstone[0]) is not int:
            raise RollbackError("ROLLBACK_AUTHORITY_STATE_INVALID")
        runtime_rows = self._connection.execute(
            "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
        ).fetchall()
        if len(runtime_rows) != 1 or type(runtime_rows[0][0]) is not int:
            raise RollbackError("ROLLBACK_ACTIVE_EPOCH_INVALID")
        values: list[RollbackBaseVersion]
        if self._database_scope == "client":
            fact = self._connection.execute(
                "SELECT commit_version FROM client_fact_authority WHERE singleton = 1"
            ).fetchone()
            if fact is None or type(fact[0]) is not int:
                raise RollbackError("ROLLBACK_AUTHORITY_STATE_INVALID")
            values = [
                RollbackBaseVersion(
                    authority_key="client_fact",
                    scope_sha256=self._scope_sha256,
                    version=int(fact[0]),
                ),
                RollbackBaseVersion(
                    authority_key="client_runtime",
                    scope_sha256=self._scope_sha256,
                    version=int(runtime_rows[0][0]),
                ),
            ]
        else:
            catalog = self._connection.execute(
                "SELECT catalog_version, authorization_epoch, tombstone_epoch "
                "FROM knowledge_catalog_state WHERE singleton = 1"
            ).fetchone()
            if (
                catalog is None
                or any(type(value) is not int for value in catalog)
                or int(catalog[2]) != int(tombstone[0])
            ):
                raise RollbackError("ROLLBACK_AUTHORITY_STATE_INVALID")
            publication_rows = self._connection.execute(
                "SELECT active.artifact_key, manifest.source_version, "
                "manifest.operation_id, manifest.state, manifest.verified, "
                "operation.state, operation.authority_base_version "
                "FROM runtime_epochs AS epoch "
                "JOIN active_artifacts AS active ON active.epoch = epoch.epoch "
                "JOIN artifact_manifests AS manifest "
                "ON manifest.manifest_id = active.manifest_id "
                "JOIN publication_operations AS operation "
                "ON operation.operation_id = manifest.operation_id "
                "WHERE epoch.state = 'ACTIVE' ORDER BY active.artifact_key"
            ).fetchall()
            expected_keys = (
                "c1_revision",
                "claims",
                "graph",
                "knowledge_registry",
                "lexical",
                "vector",
                "wiki_index",
                "wiki_page",
            )
            publication_versions = {int(row[1]) for row in publication_rows}
            publication_operations = {str(row[2]) for row in publication_rows}
            publication_version = next(iter(publication_versions), 0)
            if (
                tuple(str(row[0]) for row in publication_rows) != expected_keys
                or len(publication_versions) != 1
                or publication_version <= 0
                or len(publication_operations) != 1
                or any(
                    str(row[3]) != "ACTIVE"
                    or int(row[4]) != 1
                    or str(row[5]) != "ACTIVE"
                    or int(row[6]) != publication_version
                    for row in publication_rows
                )
            ):
                raise RollbackError("ROLLBACK_PUBLICATION_AUTHORITY_INVALID")
            values = [
                RollbackBaseVersion(
                    authority_key="authorization",
                    scope_sha256=self._scope_sha256,
                    version=int(catalog[1]),
                ),
                RollbackBaseVersion(
                    authority_key="catalog",
                    scope_sha256=self._scope_sha256,
                    version=int(catalog[0]),
                ),
                RollbackBaseVersion(
                    authority_key="global_runtime",
                    scope_sha256=self._scope_sha256,
                    version=int(runtime_rows[0][0]),
                ),
                RollbackBaseVersion(
                    authority_key="global_publication",
                    scope_sha256=self._scope_sha256,
                    version=publication_version,
                ),
            ]
        values.append(
            RollbackBaseVersion(
                authority_key="tombstone_epoch",
                scope_sha256=self._scope_sha256,
                version=int(tombstone[0]),
            )
        )
        return tuple(sorted(values, key=lambda item: item.authority_key))

    def _assert_base_versions(
        self,
        expected: tuple[RollbackBaseVersion, ...],
    ) -> None:
        if self._base_versions() != expected:
            raise RollbackError("ROLLBACK_AUTHORITY_CHANGED")

    def _store_preview(
        self,
        kind: RollbackKind,
        plan: RollbackPlan,
    ) -> RollbackPreview:
        if not self._table_exists("lifecycle_plan_objects") or not (
            self._table_exists("rebuild_source_intents")
        ):
            raise RollbackError("ROLLBACK_LIFECYCLE_SCHEMA_REQUIRED")
        envelope = RollbackPlanEnvelope(
            database_scope=self._database_scope,
            rollback_kind=kind,
            scope_sha256=self._scope_sha256,
            operation_id=plan.operation_id,
            plan=plan,
        )
        object_id = self._ids.object_id("lifecycle_plan")
        stored = self._store.finalize(
            self._store.stage_bytes(
                canonical_json_bytes(envelope.model_dump(mode="json")),
                purpose="rollback",
                manifest_id=object_id,
                media_type="application/json",
            )
        )
        plan_ref = ArchiveContentRef(
            object_id=object_id,
            version=1,
            content_sha256=stored.content_sha256,
            media_type="application/json",
            size_bytes=stored.size_bytes,
        )
        with transaction(self._connection):
            created_at = _utc_text(self._clock.now())
            self._connection.execute(
                "INSERT INTO lifecycle_plan_objects(object_id, version, "
                "content_sha256, size_bytes, media_type, purpose, operation_id, "
                "plan_sha256, base_version, target_scope_hash, created_at) "
                "VALUES (?, 1, ?, ?, 'application/json', 'rollback', ?, ?, ?, ?, ?)",
                (
                    object_id,
                    stored.content_sha256,
                    stored.size_bytes,
                    plan.operation_id,
                    plan.plan_sha256,
                    plan.descriptor.base_version,
                    self._scope_sha256,
                    created_at,
                ),
            )
            self._connection.execute(
                "INSERT INTO rebuild_source_intents("
                "intent_id, intent_kind, created_at"
                ") VALUES (?, 'rollback', ?)",
                (plan.operation_id, created_at),
            )
        return RollbackPreview(
            rollback_kind=kind,
            plan_ref=plan_ref,
            plan_sha256=plan.plan_sha256,
            proposed_operation_id=plan.operation_id,
            descriptor=plan.descriptor,
            base_versions=plan.base_versions,
            current_version=plan.review.current_version,
            restore_version=plan.review.restore_version,
        )

    def _read_envelope(self, plan_ref: ArchiveContentRef) -> RollbackPlanEnvelope:
        exact = ArchiveContentRef.model_validate(plan_ref)
        payload = self._store.read_verified(
            self._store.reference(
                content_sha256=exact.content_sha256,
                media_type=exact.media_type,
                size_bytes=exact.size_bytes,
            )
        )
        try:
            envelope = RollbackPlanEnvelope.model_validate_json(payload, strict=True)
        except ValueError:
            raise RollbackError("ROLLBACK_PLAN_INVALID") from None
        if (
            envelope.database_scope != self._database_scope
            or envelope.scope_sha256 != self._scope_sha256
        ):
            raise RollbackError("ROLLBACK_PLAN_SCOPE_MISMATCH")
        return envelope

    def _revalidate_plan_cas(
        self,
        plan_ref: ArchiveContentRef,
        expected: RollbackPlan,
    ) -> None:
        current = self._read_envelope(plan_ref)
        if current.plan != expected:
            raise RollbackError("ROLLBACK_PLAN_CHANGED")

    def _assert_plan_row(
        self,
        plan_ref: ArchiveContentRef,
        envelope: RollbackPlanEnvelope,
    ) -> None:
        if not self._table_exists("lifecycle_plan_objects"):
            raise RollbackError("ROLLBACK_LIFECYCLE_SCHEMA_REQUIRED")
        row = self._connection.execute(
            "SELECT version, content_sha256, size_bytes, media_type, purpose, "
            "operation_id, plan_sha256, base_version, target_scope_hash "
            "FROM lifecycle_plan_objects WHERE object_id = ?",
            (plan_ref.object_id,),
        ).fetchone()
        expected = (
            plan_ref.version,
            plan_ref.content_sha256,
            plan_ref.size_bytes,
            plan_ref.media_type,
            "rollback",
            envelope.operation_id,
            envelope.plan.plan_sha256,
            envelope.plan.descriptor.base_version,
            self._scope_sha256,
        )
        if row is None or tuple(row) != expected:
            raise RollbackError("ROLLBACK_PLAN_ATTESTATION_MISMATCH")

    def _write_lifecycle_attestation(
        self,
        connection: sqlite3.Connection,
        plan_ref: ArchiveContentRef,
        plan: RollbackPlan,
        ticket: ApprovalExecutionTicket,
    ) -> None:
        if not self._table_exists("lifecycle_approval_attestations"):
            raise RollbackError("ROLLBACK_LIFECYCLE_SCHEMA_REQUIRED")
        connection.execute(
            "INSERT INTO lifecycle_approval_attestations(operation_id, request_id, "
            "descriptor_sha256, plan_object_id, plan_version, plan_content_sha256, "
            "plan_size_bytes, plan_media_type, purpose, base_version, "
            "target_scope_hash, attested_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, "
            "'rollback', ?, ?, ?)",
            (
                ticket.operation_id,
                ticket.request_id,
                ticket.descriptor_sha256,
                plan_ref.object_id,
                plan_ref.version,
                plan_ref.content_sha256,
                plan_ref.size_bytes,
                plan_ref.media_type,
                plan.descriptor.base_version,
                self._scope_sha256,
                _utc_text(self._clock.now()),
            ),
        )

    def _execution_applied(self, ticket: ApprovalExecutionTicket) -> bool:
        nonce_sha256 = hashlib.sha256(ticket.receipt.nonce.encode("ascii")).hexdigest()
        row = self._connection.execute(
            "SELECT request_id, descriptor_sha256, draft_sha256, "
            "descriptor_base_version, target_scope_hash, nonce_sha256, state "
            "FROM approval_executions WHERE operation_id = ?",
            (ticket.operation_id,),
        ).fetchone()
        if row is None:
            return False
        expected = (
            ticket.request_id,
            ticket.descriptor_sha256,
            ticket.descriptor.draft_sha256,
            ticket.descriptor.base_version,
            ticket.target_scope_hash,
            nonce_sha256,
            "APPLIED",
        )
        if tuple(row) != expected:
            raise RollbackError("ROLLBACK_APPROVAL_BINDING_MISMATCH")
        return True

    def _operation_preflight_applied(
        self,
        plan: RollbackPlan,
        *,
        approval_request_id: str,
        approval_descriptor_sha256: str,
    ) -> bool:
        """Recognize only the exact APPLIED operation for replay preflight."""

        row = self._connection.execute(
            "SELECT request_id, descriptor_sha256, draft_sha256, "
            "descriptor_base_version, target_scope_hash, state "
            "FROM approval_executions WHERE operation_id = ?",
            (plan.operation_id,),
        ).fetchone()
        if row is None:
            return False
        expected = (
            approval_request_id,
            approval_descriptor_sha256,
            plan.descriptor.draft_sha256,
            plan.descriptor.base_version,
            self._scope_sha256,
            "APPLIED",
        )
        if tuple(row) != expected:
            raise RollbackError("ROLLBACK_APPROVAL_BINDING_MISMATCH")
        return True

    def _assert_prepared_wiki(
        self,
        plan: WikiRollbackPlan,
        revision: WikiRevision,
        request_id: str,
    ) -> None:
        if (
            revision.wiki_id != plan.draft.wiki_id
            or revision.revision != plan.new_revision
            or revision.status != "prepared"
            or revision.approval_request_id != request_id
            or revision.base_revision != plan.draft.base_revision
            or revision.slug != plan.draft.slug
            or revision.title != plan.draft.title
            or revision.sections != plan.draft.sections
            or revision.theory_revision_refs != plan.draft.theory_revision_refs
            or revision.relationships != plan.draft.relationships
            or revision.graph_relations != plan.draft.graph_relations
        ):
            raise RollbackError("ROLLBACK_COMMIT_ATTESTATION_INVALID")

    def _assert_prepared_theory(
        self,
        plan: TheoryRollbackPlan,
        revision: TheoryRevision,
        request_id: str,
    ) -> None:
        if (
            revision.theory_id != plan.draft.theory_id
            or revision.revision != plan.new_revision
            or revision.status != "prepared"
            or revision.approval_request_id != request_id
            or revision.source_ref != plan.draft.source_ref
            or revision.document_sha256 != plan.draft.document_sha256
            or revision.scope != plan.draft.scope
            or revision.core_claims != plan.draft.core_claims
            or revision.methods != plan.draft.methods
            or revision.contraindications != plan.draft.contraindications
            or revision.counterexamples != plan.draft.counterexamples
            or revision.empirical_support != plan.draft.empirical_support
            or revision.claim_refs != plan.expected_claim_refs
            or revision.supersedes_ref != plan.current_revision_ref
            or revision.revokes_ref is not None
        ):
            raise RollbackError("ROLLBACK_COMMIT_ATTESTATION_INVALID")

    def _require_scope(self, expected: DatabaseScope) -> None:
        if self._database_scope != expected:
            raise RollbackError("ROLLBACK_SCOPE_DENIED")

    def _assert_target_transaction(self, connection: sqlite3.Connection) -> None:
        if connection is not self._connection or not connection.in_transaction:
            raise RollbackError("ROLLBACK_TARGET_TRANSACTION_REQUIRED")

    def _table_exists(self, table: str) -> bool:
        return (
            self._connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (table,),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _finish_plan(plan: RollbackPlan) -> RollbackPlan:
        plan_hash = canonical_sha256(
            plan.model_dump(mode="json", exclude={"plan_sha256", "descriptor"})
        )
        return plan.model_copy(
            update={
                "plan_sha256": plan_hash,
                "descriptor": plan.descriptor.model_copy(
                    update={"draft_sha256": plan_hash}
                ),
            }
        )


__all__ = [
    "ArtifactRollbackPlan",
    "FactRollbackPlan",
    "RollbackBaseVersion",
    "RollbackCommit",
    "RollbackCommitSummary",
    "RollbackError",
    "RollbackKind",
    "RollbackPlanEnvelope",
    "RollbackPlanner",
    "RollbackPreview",
    "RollbackReview",
    "SqliteRollbackWorkflow",
    "TheoryRollbackPlan",
    "WikiRollbackPlan",
]
