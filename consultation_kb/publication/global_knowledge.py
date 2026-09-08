"""Build and atomically activate one complete global-knowledge epoch.

The planner is the production composition seam between P3 authority rows and
the P4 artifact builders.  Planning performs only immutable file/CAS writes;
activation remains approval-bound and the authority-row/runtime-epoch switch
is delegated to :class:`KnowledgePublicationService` in one SQLite
transaction.

There is intentionally no embedding fallback.  A caller must inject both an
embedder and its exact pinned model descriptor, otherwise planning fails with
a stable error code before an approval can be issued.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, Protocol

from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.models import descriptor_sha256
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.core.clock import Clock
from consultation_kb.core.ids import IdFactory
from consultation_kb.graph.artifact_contracts import (
    GraphBuildManifestPayload,
    GraphEdgeAuthorityCatalogPayload,
    build_expected_graph_edge_mapping,
)
from consultation_kb.graph.authority_filter import (
    GraphEdgeAuthorityRecord,
    graph_edge_authority_sha256,
)
from consultation_kb.graph.global_builder import (
    ClaimRelation,
    GlobalGraphBuilder,
    GovernedClaim,
    GovernedPassage,
    GovernedTheory,
    GovernedWiki,
    GraphAuthoritySnapshot,
    StaticGraphAuthority,
    claim_relation_sha256,
)
from consultation_kb.graph.graphify_adapter import GraphifyProjectionAdapter
from consultation_kb.graph.serialization import canonical_graph_bytes, graph_payload
from consultation_kb.knowledge.claims import ClaimProposalService
from consultation_kb.knowledge.publication import KnowledgePublicationService
from consultation_kb.knowledge.theory import TheoryRevisionService
from consultation_kb.knowledge.wiki import WikiRevisionService
from consultation_kb.lifecycle.publish import (
    ArtifactDraft,
    ContentDraft,
    PreparedArtifactDraft,
    PublicationOperation,
    PublishCoordinator,
    publication_closure_sha256,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.knowledge import ClaimRecord, PassageRecord
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.theory import TheoryRevision
from consultation_kb.models.wiki import WikiRevision
from consultation_kb.retrieval.artifact_contracts import (
    DerivedArtifactBuilderInputV2,
    DerivedArtifactKind,
    GenericDerivedBuildManifestV2,
    KnowledgeRegistryPayloadV1,
    derived_artifact_media_type_layout,
    derived_artifact_role_layout,
)
from consultation_kb.retrieval.artifact_publication import (
    ArtifactPublicationIds,
    RetrievalArtifactDraftFactory,
)
from consultation_kb.retrieval.authority_descriptor import (
    AuthorityManifestMember,
    RebuiltPublicationAuthority,
    canonical_retrieval_route_policy_bytes,
    rebuild_publication_authority,
)
from consultation_kb.retrieval.contracts import CandidateRef, canonical_json_bytes
from consultation_kb.retrieval.embeddings import Embedder, ModelDescriptor
from consultation_kb.retrieval.lexical_builder import (
    LexicalDocument,
    LexicalIndexBuilder,
)
from consultation_kb.retrieval.vector_builder import (
    ExactVectorIndexBuilder,
    VectorDocument,
)
from consultation_kb.retrieval.wiki_builder import WikiNavigationIndexBuilder
from consultation_kb.storage.manifests import ManifestMember, manifest_sha256
from consultation_kb.storage.tombstones import (
    ObjectIdentity,
    TombstoneRepository,
    VisibilityGuard,
    lineage_hash,
)
from consultation_kb.vault.content_store import ContentStore


_DERIVED_KINDS: Final[tuple[DerivedArtifactKind, ...]] = (
    "wiki_index",
    "knowledge_registry",
    "graph",
    "lexical",
    "vector",
)
_BASE_KINDS: Final[tuple[str, ...]] = ("wiki_page", "claims")


class GlobalPublicationPlanningError(RuntimeError):
    """Stable, non-sensitive production-planning failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class PassageReader(Protocol):
    def get(self, passage_id: str, version: int) -> PassageRecord: ...


@dataclass(frozen=True, slots=True)
class GlobalPublicationBuilders:
    """All non-authority builder dependencies required by production.

    ``model_descriptor`` is supplied separately from ``embedder`` so a model
    adapter cannot silently substitute a different revision after runtime
    composition.
    """

    embedder: Embedder
    model_descriptor: ModelDescriptor
    lexical: LexicalIndexBuilder
    wiki: WikiNavigationIndexBuilder
    graphify: GraphifyProjectionAdapter

    def __post_init__(self) -> None:
        try:
            descriptor = ModelDescriptor.model_validate(self.model_descriptor)
            actual = ModelDescriptor.model_validate(self.embedder.descriptor)
        except (AttributeError, TypeError, ValueError):
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_VECTOR_MODEL_INVALID"
            ) from None
        if actual != descriptor or actual.id != descriptor.id:
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_VECTOR_MODEL_DESCRIPTOR_MISMATCH"
            )
        if not isinstance(self.lexical, LexicalIndexBuilder):
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_LEXICAL_BUILDER_REQUIRED"
            )
        if not isinstance(self.wiki, WikiNavigationIndexBuilder):
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_WIKI_BUILDER_REQUIRED"
            )
        if not isinstance(self.graphify, GraphifyProjectionAdapter):
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_GRAPH_BUILDER_REQUIRED"
            )


@dataclass(frozen=True, slots=True)
class GlobalKnowledgePublicationPlan:
    """Approval-ready immutable closure; contains CAS refs, never raw bodies."""

    operation_id: str
    descriptor: DraftDescriptor
    authority_base_version: int
    expected_current_epoch: int | None
    target_runtime_epoch: int
    wiki_ref: VersionRef
    theory_ref: VersionRef | None
    artifacts: tuple[PreparedArtifactDraft, ...]
    artifact_kinds: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.operation_id[:-37] != "knowledge_publication":
            raise GlobalPublicationPlanningError("KNOWLEDGE_OPERATION_ID_INVALID")
        if (
            self.descriptor.purpose != "wiki_publish"
            or self.descriptor.target_id != "global-knowledge"
            or self.descriptor.base_version != self.authority_base_version - 1
            or self.descriptor.client_id is not None
            or self.descriptor.session_id is not None
            or self.target_runtime_epoch <= 0
        ):
            raise GlobalPublicationPlanningError("KNOWLEDGE_PLAN_INVALID")
        kinds = tuple(artifact.artifact_kind for artifact in self.artifacts)
        if kinds != self.artifact_kinds or len(kinds) != len(set(kinds)):
            raise GlobalPublicationPlanningError("KNOWLEDGE_PLAN_INVALID")
        closure = publication_closure_sha256(
            purpose="wiki_publish",
            authority_base_version=self.authority_base_version,
            expected_current_epoch=self.expected_current_epoch,
            artifacts=self.artifacts,
        )
        if closure != self.descriptor.draft_sha256:
            raise GlobalPublicationPlanningError("KNOWLEDGE_PLAN_CLOSURE_MISMATCH")


@dataclass(frozen=True, slots=True)
class _CatalogObject:
    object_id: str
    data: bytes
    media_type: str


@dataclass(frozen=True, slots=True)
class _BuildState:
    operation_id: str
    authority_version: int
    expected_epoch: int | None
    wiki: WikiRevision
    theory: TheoryRevision | None
    wikis: tuple[WikiRevision, ...]
    theories: tuple[TheoryRevision, ...]
    claims: tuple[ClaimRecord, ...]
    passages: Mapping[VersionRef, PassageRecord]
    lineage: tuple[ObjectIdentity, ...]
    manifest_ids: Mapping[str, str]
    derived_ids: Mapping[DerivedArtifactKind, ArtifactPublicationIds]
    base_drafts: Mapping[str, ArtifactDraft]
    authority: RebuiltPublicationAuthority
    builder_inputs: Mapping[DerivedArtifactKind, DerivedArtifactBuilderInputV2]
    build_root: Path


class GlobalKnowledgePublicationPlanner:
    """Compile, approve, verify, and activate one global knowledge closure."""

    def __init__(
        self,
        *,
        connection: sqlite3.Connection,
        content_store: ContentStore,
        approval_service: ApprovalService,
        execution_guard: ApprovalExecutionGuard,
        claim_service: ClaimProposalService,
        passage_reader: PassageReader,
        theory_service: TheoryRevisionService,
        wiki_service: WikiRevisionService,
        builders: GlobalPublicationBuilders | None,
        build_root: Path,
        id_factory: IdFactory,
        clock: Clock,
        lint_error_count: Callable[[], int],
        failure_hook: Callable[[str], None] | None = None,
    ) -> None:
        if builders is None:
            raise GlobalPublicationPlanningError("KNOWLEDGE_VECTOR_MODEL_REQUIRED")
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("global publication requires sqlite3.Connection")
        if not isinstance(content_store, ContentStore):
            raise TypeError("global publication requires ContentStore")
        if not isinstance(build_root, Path) or not build_root.is_absolute():
            raise GlobalPublicationPlanningError("KNOWLEDGE_BUILD_ROOT_INVALID")
        if not callable(lint_error_count):
            raise TypeError("global publication requires knowledge linter")
        self._connection = connection
        self._store = content_store
        self._approvals = approval_service
        self._guard = execution_guard
        self._claims = claim_service
        self._passages = passage_reader
        self._theories = theory_service
        self._wikis = wiki_service
        self._builders = builders
        self._root = build_root
        self._ids = id_factory
        self._clock = clock
        self._lint_errors = lint_error_count
        self._failure_hook = failure_hook
        self._coordinator = PublishCoordinator(
            connection,
            content_store,
            VisibilityGuard(TombstoneRepository(connection)),
            clock=clock,
            fault_hook=failure_hook,
        )

    def plan_wiki(
        self,
        *,
        wiki_id: str,
        wiki_revision: int,
    ) -> GlobalKnowledgePublicationPlan:
        """Build the exact P3/P4 closure and return its approval descriptor."""

        try:
            wiki = self._wikis.get(wiki_id, wiki_revision)
            if wiki.status != "prepared":
                raise GlobalPublicationPlanningError(
                    "KNOWLEDGE_WIKI_NOT_PREPARED"
                )
            theory = self._theory_for_wiki(wiki)
            authority_version, expected_epoch = self._next_publication_identity()
            state = self._build_state(
                wiki=wiki,
                theory=theory,
                authority_version=authority_version,
                expected_epoch=expected_epoch,
            )
            artifacts = self._build_artifacts(state)
            prepared = self._coordinator.stage_artifacts(
                purpose="wiki_publish",
                artifacts=artifacts,
            )
            closure = publication_closure_sha256(
                purpose="wiki_publish",
                authority_base_version=authority_version,
                expected_current_epoch=expected_epoch,
                artifacts=prepared,
            )
            descriptor = DraftDescriptor(
                purpose="wiki_publish",
                target_id="global-knowledge",
                base_version=authority_version - 1,
                draft_sha256=closure,
            )
            return GlobalKnowledgePublicationPlan(
                operation_id=state.operation_id,
                descriptor=descriptor,
                authority_base_version=authority_version,
                expected_current_epoch=expected_epoch,
                target_runtime_epoch=state.authority.snapshot.target_runtime_epoch,
                wiki_ref=VersionRef(
                    object_id=wiki.wiki_id,
                    version=wiki.revision,
                    content_sha256=wiki.body_sha256,
                ),
                theory_ref=(
                    None
                    if theory is None
                    else self._theories.version_ref(
                        theory.theory_id,
                        theory.revision,
                    )
                ),
                artifacts=prepared,
                artifact_kinds=tuple(item.artifact_kind for item in prepared),
            )
        except GlobalPublicationPlanningError:
            raise
        except Exception as exc:
            code = getattr(exc, "code", None)
            raise GlobalPublicationPlanningError(
                code if isinstance(code, str) else "KNOWLEDGE_PUBLICATION_BUILD_FAILED"
            ) from exc

    def execute(
        self,
        plan: GlobalKnowledgePublicationPlan,
        *,
        approval_request_id: str,
    ) -> PublicationOperation:
        """Consume one exact approval and atomically activate the planned epoch."""

        exact = plan
        if not isinstance(exact, GlobalKnowledgePublicationPlan):
            raise TypeError("global publication plan required")
        closure = publication_closure_sha256(
            purpose="wiki_publish",
            authority_base_version=exact.authority_base_version,
            expected_current_epoch=exact.expected_current_epoch,
            artifacts=exact.artifacts,
        )
        if closure != exact.descriptor.draft_sha256:
            raise GlobalPublicationPlanningError("KNOWLEDGE_PLAN_CLOSURE_MISMATCH")
        recovered = self._recover_active(
            exact,
            approval_request_id=approval_request_id,
        )
        if recovered is not None:
            return recovered
        ticket = self._approvals.issue_for_execution(
            approval_request_id,
            exact.descriptor,
            operation_id=exact.operation_id,
        )
        proof = self._guard.apply_in_transaction(
            ticket,
            exact.descriptor,
            lambda _connection: self._coordinator.prepare(
                operation_id=exact.operation_id,
                purpose="wiki_publish",
                authority_base_version=exact.authority_base_version,
                approval_request_id=approval_request_id,
                descriptor_sha256=ticket.descriptor_sha256,
                expected_current_epoch=exact.expected_current_epoch,
                artifacts=exact.artifacts,
            ),
        )
        self._approvals.acknowledge(proof)
        self._coordinator.verify(exact.operation_id)
        required = frozenset(exact.artifact_kinds)
        publisher = KnowledgePublicationService(
            coordinator=self._coordinator,
            theory_service=self._theories,
            wiki_service=self._wikis,
            connection=self._connection,
            required_artifact_kinds=required,
            lint_error_count=self._lint_errors,
            failure_hook=self._failure_hook,
            content_store=self._store,
        )
        if exact.theory_ref is None:
            return publisher.publish_wiki(
                exact.operation_id,
                wiki_id=exact.wiki_ref.object_id,
                wiki_revision=exact.wiki_ref.version,
            )
        return publisher.publish_theory_and_wiki(
            exact.operation_id,
            theory_id=exact.theory_ref.object_id,
            theory_revision=exact.theory_ref.version,
            wiki_id=exact.wiki_ref.object_id,
            wiki_revision=exact.wiki_ref.version,
        )

    def _recover_active(
        self,
        plan: GlobalKnowledgePublicationPlan,
        *,
        approval_request_id: str,
    ) -> PublicationOperation | None:
        row = self._connection.execute(
            "SELECT approval_request_id, descriptor_sha256, state "
            "FROM publication_operations WHERE operation_id = ?",
            (plan.operation_id,),
        ).fetchone()
        if row is None or str(row[2]) != "ACTIVE":
            return None
        if (
            str(row[0]) != approval_request_id
            or str(row[1]) != descriptor_sha256(plan.descriptor)
        ):
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_ACTIVE_OPERATION_MISMATCH"
            )
        return self._coordinator.recover(plan.operation_id)

    def _theory_for_wiki(self, wiki: WikiRevision) -> TheoryRevision | None:
        if not wiki.theory_revision_refs:
            return None
        if len(wiki.theory_revision_refs) != 1:
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_WIKI_THEORY_CARDINALITY_INVALID"
            )
        reference = wiki.theory_revision_refs[0]
        theory = self._theories.get(reference.object_id, reference.version)
        if (
            theory.status not in {"prepared", "active"}
            or self._theories.version_ref(theory.theory_id, theory.revision)
            != reference
        ):
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_THEORY_NOT_PREPARED"
            )
        return theory if theory.status == "prepared" else None

    def _governed_wikis(self, target: WikiRevision) -> tuple[WikiRevision, ...]:
        rows = self._connection.execute(
            "SELECT wiki_id, revision FROM wiki_revisions "
            "WHERE review_status = 'ACTIVE' ORDER BY wiki_id, revision"
        ).fetchall()
        by_id = {
            str(row[0]): self._wikis.get(str(row[0]), int(row[1]))
            for row in rows
            if str(row[0]) != target.wiki_id
        }
        by_id[target.wiki_id] = target
        values = tuple(by_id[key] for key in sorted(by_id))
        if any(value.status not in {"prepared", "active"} for value in values):
            raise GlobalPublicationPlanningError("KNOWLEDGE_WIKI_NOT_GOVERNED")
        return values

    def _governed_theories(
        self,
        wikis: tuple[WikiRevision, ...],
    ) -> tuple[TheoryRevision, ...]:
        references = {
            reference.object_id: reference
            for wiki in wikis
            for reference in wiki.theory_revision_refs
        }
        raw_count = sum(len(wiki.theory_revision_refs) for wiki in wikis)
        unique_refs = {
            (
                reference.object_id,
                reference.version,
                reference.content_sha256,
            )
            for wiki in wikis
            for reference in wiki.theory_revision_refs
        }
        if len(references) != len(unique_refs) or len(unique_refs) > raw_count:
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_THEORY_VERSION_CONFLICT"
            )
        values: list[TheoryRevision] = []
        for theory_id in sorted(references):
            reference = references[theory_id]
            theory = self._theories.get(reference.object_id, reference.version)
            if (
                theory.status not in {"prepared", "active"}
                or self._theories.version_ref(theory.theory_id, theory.revision)
                != reference
            ):
                raise GlobalPublicationPlanningError(
                    "KNOWLEDGE_THEORY_NOT_GOVERNED"
                )
            values.append(theory)
        return tuple(values)

    def _next_publication_identity(self) -> tuple[int, int | None]:
        active = self._connection.execute(
            "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
        ).fetchall()
        if len(active) > 1:
            raise GlobalPublicationPlanningError("KNOWLEDGE_RUNTIME_EPOCH_INVALID")
        expected = None if not active else int(active[0][0])
        row = self._connection.execute(
            "SELECT COALESCE(MAX(authority_base_version), 0) "
            "FROM publication_operations"
        ).fetchone()
        if row is None:
            raise GlobalPublicationPlanningError("KNOWLEDGE_VERSION_UNAVAILABLE")
        version = int(row[0]) + 1
        if version <= 0:
            raise GlobalPublicationPlanningError("KNOWLEDGE_VERSION_INVALID")
        return version, expected

    def _build_state(
        self,
        *,
        wiki: WikiRevision,
        theory: TheoryRevision | None,
        authority_version: int,
        expected_epoch: int | None,
    ) -> _BuildState:
        operation_id = self._ids.object_id("knowledge_publication")
        wikis = self._governed_wikis(wiki)
        theories = self._governed_theories(wikis)
        required_kinds = (*_BASE_KINDS, *_DERIVED_KINDS)
        if theories:
            required_kinds = (*required_kinds, "c1_revision")
        manifest_ids = {
            kind: self._ids.object_id("manifest")
            for kind in sorted(required_kinds)
        }
        derived_ids = {
            kind: ArtifactPublicationIds(
                manifest_id=manifest_ids[kind],
                member_object_ids={
                    role: self._ids.object_id(role)
                    for role in derived_artifact_role_layout(kind)
                },
            )
            for kind in _DERIVED_KINDS
        }
        claim_rows = self._target_claim_rows(
            wikis=wikis,
            theories=theories,
        )
        claims = tuple(
            self._claims.get(str(row[0]), int(str(row[1])))
            for row in claim_rows
        )
        for claim, row in zip(claims, claim_rows, strict=True):
            if (
                claim.claim_id != str(row[0])
                or claim.version != int(str(row[1]))
                or claim.text_sha256 != self._digest_ref(str(row[2]))
                or claim.privacy_scope != "global"
                or claim.provenance.provenance_scope != "global_source"
                or claim.provenance.client_ids
                or claim.provenance.case_contributor_client_ids
            ):
                raise GlobalPublicationPlanningError(
                    "KNOWLEDGE_CLAIM_NOT_PUBLISHABLE"
                )
        source_ids = frozenset(
            source_id
            for claim in claims
            for source_id in claim.provenance.source_ids
        )
        if not source_ids:
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_SOURCE_LINEAGE_REQUIRED"
            )
        lineage = tuple(
            ObjectIdentity("source", source_id)
            for source_id in sorted(source_ids)
        )

        wiki_objects = tuple(
            self._catalog_object(
                table="wiki",
                object_id=value.wiki_id,
                version=value.revision,
                allowed_statuses=frozenset({"PREPARED", "ACTIVE"}),
            )
            for value in wikis
        )
        base_drafts: dict[str, ArtifactDraft] = {
            "wiki_page": ArtifactDraft(
                manifest_id=manifest_ids["wiki_page"],
                artifact_key="wiki_page",
                artifact_kind="wiki_page",
                source_version=authority_version,
                members=tuple(
                    ContentDraft(
                        object_type="wiki",
                        object_id=wiki_object.object_id,
                        data=wiki_object.data,
                        source_version=authority_version,
                        media_type=wiki_object.media_type,
                        source_lineage=lineage,
                    )
                    for wiki_object in wiki_objects
                ),
            ),
            "claims": ArtifactDraft(
                manifest_id=manifest_ids["claims"],
                artifact_key="claims",
                artifact_kind="claims",
                source_version=authority_version,
                members=tuple(
                    ContentDraft(
                        object_type="claim",
                        object_id=str(row[0]),
                        data=self._read_catalog_payload(
                            object_ref=str(row[2]),
                            size_bytes=int(str(row[3])),
                            media_type=str(row[4]),
                        ),
                        source_version=authority_version,
                        media_type=str(row[4]),
                        source_lineage=lineage,
                    )
                    for row in claim_rows
                ),
            ),
        }
        if theories:
            theory_objects = tuple(
                self._catalog_object(
                    table="theory",
                    object_id=value.theory_id,
                    version=value.revision,
                    allowed_statuses=frozenset({"PREPARED", "ACTIVE"}),
                )
                for value in theories
            )
            base_drafts["c1_revision"] = ArtifactDraft(
                manifest_id=manifest_ids["c1_revision"],
                artifact_key="c1_revision",
                artifact_kind="c1_revision",
                source_version=authority_version,
                members=tuple(
                    ContentDraft(
                        object_type="theory",
                        object_id=theory_object.object_id,
                        data=theory_object.data,
                        source_version=authority_version,
                        media_type=theory_object.media_type,
                        source_lineage=lineage,
                    )
                    for theory_object in theory_objects
                ),
            )

        claim_manifest_members = self._manifest_members(
            base_drafts["claims"],
            lineage=lineage,
        )
        claim_manifest_digest = manifest_sha256(
            manifest_id=manifest_ids["claims"],
            operation_id=operation_id,
            artifact_key="claims",
            artifact_kind="claims",
            source_version=authority_version,
            members=claim_manifest_members,
        )
        claims_manifest_ref = VersionRef(
            object_id=manifest_ids["claims"],
            version=authority_version,
            content_sha256=claim_manifest_digest,
        )
        authority_claim_members = tuple(
            AuthorityManifestMember(
                object_type=member.object_type,
                object_id=member.object_id,
                object_sha256=member.object_sha256,
                source_version=member.source_version,
                source_lineage_hashes=member.source_lineage_hashes,
                media_type=member.media_type,
                size_bytes=member.size_bytes,
            )
            for member in claim_manifest_members
        )
        policy_payload = canonical_retrieval_route_policy_bytes()
        self._store.finalize(
            self._store.stage_bytes(
                policy_payload,
                purpose="wiki_publish",
                manifest_id=manifest_ids["knowledge_registry"],
                media_type="application/json",
            )
        )
        policy_id = derived_ids["knowledge_registry"].member_object_ids[
            "retrieval_route_policy"
        ]
        policy_member = AuthorityManifestMember(
            object_type="retrieval_route_policy",
            object_id=policy_id,
            object_sha256=hashlib.sha256(policy_payload).hexdigest(),
            source_version=authority_version,
            source_lineage_hashes=self._lineage_hashes(lineage),
            media_type="application/json",
            size_bytes=len(policy_payload),
        )
        authority = rebuild_publication_authority(
            self._connection,
            self._store,
            publication_authority_version=authority_version,
            expected_current_epoch=expected_epoch,
            theory_id=None if theory is None else theory.theory_id,
            theory_revision=None if theory is None else theory.revision,
            wiki_id=wiki.wiki_id,
            wiki_revision=wiki.revision,
            governed_wiki_refs=tuple(
                VersionRef(
                    object_id=value.wiki_id,
                    version=value.revision,
                    content_sha256=value.body_sha256,
                )
                for value in wikis
            ),
            governed_theory_refs=tuple(
                VersionRef(
                    object_id=value.theory_id,
                    version=value.revision,
                    content_sha256=self._catalog_digest(
                        table="theory",
                        object_id=value.theory_id,
                        version=value.revision,
                    ),
                )
                for value in theories
            ),
            claims_manifest_ref=claims_manifest_ref,
            claim_members=authority_claim_members,
            route_policy_member=policy_member,
        )
        closure_sha256 = hashlib.sha256(
            canonical_json_bytes(authority.snapshot.model_dump(mode="json"))
        ).hexdigest()
        builder_inputs = {
            kind: DerivedArtifactBuilderInputV2(
                artifact_kind=kind,
                authority_closure_sha256=closure_sha256,
                authority_snapshot=authority.snapshot,
                retrieval_input_descriptor=authority.descriptor,
                target_runtime_epoch=authority.snapshot.target_runtime_epoch,
            )
            for kind in _DERIVED_KINDS
        }
        passages: dict[VersionRef, PassageRecord] = {}
        for assignment in authority.assignments:
            reference = assignment.authority.content_ref
            passage = self._passages.get(reference.object_id, reference.version)
            if (
                passage.normalized_text_sha256 != reference.content_sha256
                or passage.privacy_scope != "global"
                or passage.review_status != "approved"
            ):
                raise GlobalPublicationPlanningError(
                    "KNOWLEDGE_PASSAGE_CLOSURE_MISMATCH"
                )
            passages[reference] = passage
        build_root = self._root / operation_id
        try:
            self._root.mkdir(parents=True, exist_ok=True)
            build_root.mkdir(exist_ok=False)
        except OSError:
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_BUILD_ROOT_UNAVAILABLE"
            ) from None
        return _BuildState(
            operation_id=operation_id,
            authority_version=authority_version,
            expected_epoch=expected_epoch,
            wiki=wiki,
            theory=theory,
            wikis=wikis,
            theories=theories,
            claims=claims,
            passages=passages,
            lineage=lineage,
            manifest_ids=manifest_ids,
            derived_ids=derived_ids,
            base_drafts=base_drafts,
            authority=authority,
            builder_inputs=builder_inputs,
            build_root=build_root,
        )

    def _target_claim_rows(
        self,
        *,
        wikis: tuple[WikiRevision, ...],
        theories: tuple[TheoryRevision, ...],
    ) -> tuple[tuple[object, ...], ...]:
        by_key: dict[tuple[str, int], tuple[object, ...]] = {}
        for wiki in wikis:
            rows = self._connection.execute(
                "SELECT DISTINCT c.claim_id, c.version, c.claim_object_ref, "
                "c.claim_object_size_bytes, c.claim_object_media_type "
                "FROM wiki_revision_claims AS wc JOIN claims AS c "
                "ON c.claim_id = wc.claim_id AND c.version = wc.claim_version "
                "WHERE wc.wiki_id = ? AND wc.wiki_revision = ?",
                (wiki.wiki_id, wiki.revision),
            ).fetchall()
            by_key.update(
                {(str(row[0]), int(row[1])): tuple(row) for row in rows}
            )
        for theory in theories:
            for row in self._connection.execute(
                "SELECT claim_id, version, claim_object_ref, "
                "claim_object_size_bytes, claim_object_media_type FROM claims "
                "WHERE source_grade = 'C1' AND theory_revision_id = ? "
                "AND theory_revision = ?",
                (theory.theory_id, theory.revision),
            ):
                by_key[(str(row[0]), int(row[1]))] = tuple(row)
        values = tuple(
            value for _key, value in sorted(by_key.items(), key=lambda item: item[0])
        )
        if not values:
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_RETRIEVAL_INPUT_EMPTY"
            )
        return values

    def _catalog_object(
        self,
        *,
        table: Literal["wiki", "theory"],
        object_id: str,
        version: int,
        allowed_statuses: frozenset[str] = frozenset({"PREPARED"}),
    ) -> _CatalogObject:
        if not allowed_statuses or not allowed_statuses <= frozenset(
            {"PREPARED", "ACTIVE"}
        ):
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_AUTHORITY_STATUS_INVALID"
            )
        placeholders = ",".join("?" for _value in sorted(allowed_statuses))
        status_values = tuple(sorted(allowed_statuses))
        if table == "wiki":
            row = self._connection.execute(
                "SELECT body_object_ref, body_object_size_bytes, "
                "body_object_media_type FROM wiki_revisions "
                f"WHERE wiki_id = ? AND revision = ? "
                f"AND review_status IN ({placeholders})",
                (object_id, version, *status_values),
            ).fetchone()
        else:
            row = self._connection.execute(
                "SELECT revision_object_ref, revision_object_size_bytes, "
                "revision_object_media_type FROM theory_revisions "
                f"WHERE theory_id = ? AND revision = ? "
                f"AND status IN ({placeholders})",
                (object_id, version, *status_values),
            ).fetchone()
        if row is None:
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_AUTHORITY_ROW_MISSING"
            )
        return _CatalogObject(
            object_id=object_id,
            data=self._read_catalog_payload(
                object_ref=str(row[0]),
                size_bytes=int(row[1]),
                media_type=str(row[2]),
            ),
            media_type=str(row[2]),
        )

    def _catalog_digest(
        self,
        *,
        table: Literal["wiki", "theory"],
        object_id: str,
        version: int,
    ) -> str:
        column = "body_object_ref" if table == "wiki" else "revision_object_ref"
        id_column = "wiki_id" if table == "wiki" else "theory_id"
        version_column = "revision"
        table_name = "wiki_revisions" if table == "wiki" else "theory_revisions"
        row = self._connection.execute(
            f"SELECT {column} FROM {table_name} "
            f"WHERE {id_column} = ? AND {version_column} = ?",
            (object_id, version),
        ).fetchone()
        if row is None:
            raise GlobalPublicationPlanningError("KNOWLEDGE_AUTHORITY_ROW_MISSING")
        return self._digest_ref(str(row[0]))

    def _read_catalog_payload(
        self,
        *,
        object_ref: str,
        size_bytes: int,
        media_type: str,
    ) -> bytes:
        digest = self._digest_ref(object_ref)
        payload = self._store.read_verified(
            self._store.reference(
                content_sha256=digest,
                size_bytes=size_bytes,
                media_type=media_type,
            )
        )
        if hashlib.sha256(payload).hexdigest() != digest:
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_AUTHORITY_CAS_INVALID"
            )
        return payload

    @staticmethod
    def _digest_ref(value: str) -> str:
        if not value.startswith("sha256:") or len(value) != 71:
            raise GlobalPublicationPlanningError("KNOWLEDGE_CONTENT_REF_INVALID")
        digest = value.removeprefix("sha256:")
        if any(character not in "0123456789abcdef" for character in digest):
            raise GlobalPublicationPlanningError("KNOWLEDGE_CONTENT_REF_INVALID")
        return digest

    @staticmethod
    def _lineage_hashes(
        lineage: tuple[ObjectIdentity, ...],
    ) -> tuple[str, ...]:
        return tuple(
            sorted(
                lineage_hash(item.object_type, item.object_id) for item in lineage
            )
        )

    @classmethod
    def _manifest_members(
        cls,
        draft: ArtifactDraft,
        *,
        lineage: tuple[ObjectIdentity, ...],
    ) -> tuple[ManifestMember, ...]:
        hashes = cls._lineage_hashes(lineage)
        return tuple(
            ManifestMember(
                ordinal=ordinal,
                object_type=member.object_type,
                object_id=member.object_id,
                object_sha256=hashlib.sha256(member.data).hexdigest(),
                source_version=member.source_version,
                media_type=member.media_type,
                size_bytes=len(member.data),
                source_lineage_hashes=hashes,
            )
            for ordinal, member in enumerate(draft.members)
        )

    def _build_artifacts(
        self,
        state: _BuildState,
    ) -> tuple[ArtifactDraft, ...]:
        factory = RetrievalArtifactDraftFactory(state.build_root)
        derived: dict[DerivedArtifactKind, ArtifactDraft] = {
            "wiki_index": self._build_wiki_index(state, factory),
            "knowledge_registry": self._build_registry(state, factory),
            "graph": self._build_graph(state, factory),
            "lexical": self._build_lexical(state, factory),
            "vector": self._build_vector(state, factory),
        }
        artifacts: dict[str, ArtifactDraft] = dict(state.base_drafts)
        for kind, artifact in derived.items():
            artifacts[kind] = artifact
        expected = {*_BASE_KINDS, *_DERIVED_KINDS}
        if state.theories:
            expected.add("c1_revision")
        if set(artifacts) != expected:
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_CLOSURE_INCOMPLETE"
            )
        return tuple(artifacts[kind] for kind in sorted(artifacts))

    def _candidate_for(
        self,
        state: _BuildState,
        channel: Literal["lexical", "vector", "global_graph"],
    ) -> tuple[CandidateRef, ...]:
        target = "graph" if channel == "global_graph" else channel
        return tuple(
            CandidateRef(
                reference=assignment.authority.reference,
                content_ref=assignment.authority.content_ref,
                object_type=assignment.authority.object_type,
                channel=channel,
                metadata=assignment.authority.metadata,
                provenance=assignment.authority.provenance,
                location=assignment.authority.location,
                freshness=assignment.authority.freshness,
                score=0.0,
            )
            for assignment in state.authority.assignments
            if target in assignment.target_channels
        )

    def _candidate_text(self, candidate: CandidateRef) -> str:
        payload = self._store.read_hash_verified(
            candidate.content_ref.content_sha256
        )
        if hashlib.sha256(payload).hexdigest() != candidate.content_ref.content_sha256:
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_PASSAGE_CAS_INVALID"
            )
        try:
            return payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_PASSAGE_ENCODING_INVALID"
            ) from None

    @staticmethod
    def _write_payloads(
        root: Path,
        payloads: Mapping[str, bytes],
    ) -> dict[str, Path]:
        try:
            root.mkdir(parents=True, exist_ok=False)
            paths: dict[str, Path] = {}
            for role, payload in payloads.items():
                path = root / role
                with path.open("xb") as stream:
                    stream.write(payload)
                    stream.flush()
                paths[role] = path
            return paths
        except OSError:
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_BUILD_OUTPUT_INVALID"
            ) from None

    def _build_wiki_index(
        self,
        state: _BuildState,
        factory: RetrievalArtifactDraftFactory,
    ) -> ArtifactDraft:
        builder_input = state.builder_inputs["wiki_index"]
        artifacts = self._builders.wiki.build_many(
            tuple(
                assignment
                for assignment in state.authority.assignments
                if "wiki_index" in assignment.target_channels
            ),
            state.wikis,
            target_wiki_ref=VersionRef(
                object_id=state.wiki.wiki_id,
                version=state.wiki.revision,
                content_sha256=state.wiki.body_sha256,
            ),
            builder_input=builder_input,
        )
        payloads = {
            "wiki_index_build_manifest": canonical_json_bytes(
                artifacts.build_manifest.model_dump(mode="json")
            ),
            "wiki_index": artifacts.index_bytes,
        }
        paths = self._write_payloads(
            state.build_root / "wiki-index",
            payloads,
        )
        return factory.fixed_layout(
            artifact_kind="wiki_index",
            builder_input=builder_input,
            member_paths=paths,
            member_media_types={role: "application/json" for role in paths},
            ids=state.derived_ids["wiki_index"],
            source_lineage=state.lineage,
        )

    def _build_registry(
        self,
        state: _BuildState,
        factory: RetrievalArtifactDraftFactory,
    ) -> ArtifactDraft:
        builder_input = state.builder_inputs["knowledge_registry"]
        policy = canonical_retrieval_route_policy_bytes()
        registry = canonical_json_bytes(
            KnowledgeRegistryPayloadV1.from_descriptor(
                state.authority.descriptor
            ).model_dump(mode="json")
        )
        member_payloads = {
            "retrieval_route_policy": policy,
            "knowledge_registry": registry,
        }
        manifest = GenericDerivedBuildManifestV2.create(
            artifact_kind="knowledge_registry",
            builder_input=builder_input,
            member_content_sha256={
                role: hashlib.sha256(payload).hexdigest()
                for role, payload in member_payloads.items()
            },
        )
        payloads = {
            "knowledge_registry_build_manifest": canonical_json_bytes(
                manifest.model_dump(mode="json")
            ),
            **member_payloads,
        }
        paths = self._write_payloads(
            state.build_root / "knowledge-registry",
            payloads,
        )
        return factory.fixed_layout(
            artifact_kind="knowledge_registry",
            builder_input=builder_input,
            member_paths=paths,
            member_media_types={role: "application/json" for role in paths},
            ids=state.derived_ids["knowledge_registry"],
            source_lineage=state.lineage,
        )

    def _build_lexical(
        self,
        state: _BuildState,
        factory: RetrievalArtifactDraftFactory,
    ) -> ArtifactDraft:
        builder_input = state.builder_inputs["lexical"]
        candidates = self._candidate_for(state, "lexical")
        documents = tuple(
            LexicalDocument(
                candidate=candidate,
                text=self._candidate_text(candidate),
            )
            for candidate in candidates
        )
        path = state.build_root / "lexical-index.sqlite3"
        manifest = self._builders.lexical.build(
            documents,
            path,
            builder_input=builder_input,
        )
        return factory.lexical(
            builder_input=builder_input,
            build_manifest=manifest,
            index_path=path,
            ids=state.derived_ids["lexical"],
            source_lineage=state.lineage,
        )

    def _build_vector(
        self,
        state: _BuildState,
        factory: RetrievalArtifactDraftFactory,
    ) -> ArtifactDraft:
        builder_input = state.builder_inputs["vector"]
        candidates = self._candidate_for(state, "vector")
        documents = tuple(
            VectorDocument(
                candidate=candidate,
                text=self._candidate_text(candidate),
            )
            for candidate in candidates
        )
        path = state.build_root / "vector-index"
        manifest = ExactVectorIndexBuilder(self._builders.embedder).build(
            documents,
            path,
            builder_input=builder_input,
        )
        if manifest.model_descriptor != self._builders.model_descriptor:
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_VECTOR_MODEL_DESCRIPTOR_MISMATCH"
            )
        return factory.vector(
            builder_input=builder_input,
            build_manifest=manifest,
            vector_directory=path,
            ids=state.derived_ids["vector"],
            source_lineage=state.lineage,
        )

    def _build_graph(
        self,
        state: _BuildState,
        factory: RetrievalArtifactDraftFactory,
    ) -> ArtifactDraft:
        builder_input = state.builder_inputs["graph"]
        candidates = self._candidate_for(state, "global_graph")
        candidate_passages: dict[VersionRef, frozenset[VersionRef]] = {}
        for candidate in candidates:
            candidate_passages[candidate.reference] = (
                candidate_passages.get(candidate.reference, frozenset())
                | frozenset({candidate.content_ref})
            )
        claims_by_ref = {
            VersionRef(
                object_id=claim.claim_id,
                version=claim.version,
                content_sha256=claim.text_sha256,
            ): claim
            for claim in state.claims
        }
        wikis_by_ref = {
            VersionRef(
                object_id=value.wiki_id,
                version=value.revision,
                content_sha256=value.body_sha256,
            ): value.model_copy(update={"status": "active"})
            for value in state.wikis
        }
        graph_claims: dict[VersionRef, GovernedClaim] = {}
        graph_passages: dict[VersionRef, GovernedPassage] = {}
        relations: list[ClaimRelation] = []
        graph_wiki_refs: set[VersionRef] = set()
        for binding in state.authority.graph_relation_bindings:
            declaration = binding.declaration
            wiki_ref = binding.wiki_ref
            wiki_active = wikis_by_ref.get(wiki_ref)
            if wiki_active is None:
                raise GlobalPublicationPlanningError(
                    "KNOWLEDGE_GRAPH_WIKI_CLOSURE_MISMATCH"
                )
            graph_wiki_refs.add(wiki_ref)
            claim = claims_by_ref.get(declaration.claim_ref)
            if claim is None or frozenset(claim.passage_refs) != candidate_passages.get(
                declaration.claim_ref,
                frozenset(),
            ):
                raise GlobalPublicationPlanningError(
                    "KNOWLEDGE_GRAPH_PASSAGE_CLOSURE_MISMATCH"
                )
            exact_claim = (
                claim.model_copy(update={"review_status": "approved"})
                if claim.source_grade == "C1"
                else claim
            )
            graph_claims[declaration.claim_ref] = GovernedClaim(
                reference=declaration.claim_ref,
                record=exact_claim,
            )
            for passage_ref in claim.passage_refs:
                passage = state.passages.get(passage_ref)
                if passage is None:
                    raise GlobalPublicationPlanningError(
                        "KNOWLEDGE_GRAPH_PASSAGE_CLOSURE_MISMATCH"
                    )
                graph_passages[passage_ref] = GovernedPassage(
                    reference=passage_ref,
                    record=passage,
                )
            relation_ref = VersionRef(
                object_id=self._ids.object_id("graph_edge"),
                version=state.authority_version,
                content_sha256=claim_relation_sha256(
                    wiki_ref=wiki_ref,
                    source_ref=declaration.source_ref,
                    target_ref=declaration.target_ref,
                    claim_ref=declaration.claim_ref,
                    relation=declaration.relation,
                    scope=declaration.scope,
                    review_status=declaration.review_status,
                    effective_from=declaration.effective_from,
                    effective_to=declaration.effective_to,
                    confidence_override=declaration.confidence_override,
                ),
            )
            relations.append(
                ClaimRelation(
                    relation_ref=relation_ref,
                    wiki_ref=wiki_ref,
                    source_ref=declaration.source_ref,
                    target_ref=declaration.target_ref,
                    claim_ref=declaration.claim_ref,
                    relation=declaration.relation,
                    scope=declaration.scope,
                    review_status=declaration.review_status,
                    effective_from=declaration.effective_from,
                    effective_to=declaration.effective_to,
                    confidence_override=declaration.confidence_override,
                )
            )
        if bool(relations) != bool(candidates):
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_GRAPH_RELATION_CLOSURE_MISMATCH"
            )

        graph_theories: tuple[GovernedTheory, ...] = ()
        if any(value.record.source_grade == "C1" for value in graph_claims.values()):
            if not state.theories:
                raise GlobalPublicationPlanningError(
                    "KNOWLEDGE_GRAPH_C1_THEORY_MISSING"
                )
            graph_theories = tuple(
                GovernedTheory(
                    reference=self._theories.version_ref(
                        theory_active.theory_id,
                        theory_active.revision,
                    ),
                    record=theory_active,
                )
                for theory_active in (
                    value.model_copy(update={"status": "active"})
                    for value in state.theories
                )
            )
        snapshot = GraphAuthoritySnapshot(
            catalog_version=state.authority_version,
            runtime_epoch=state.authority.snapshot.target_runtime_epoch,
            effective_at=self._clock.now(),
            claims=tuple(
                graph_claims[key]
                for key in sorted(
                    graph_claims,
                    key=lambda item: (
                        item.object_id,
                        item.version,
                        item.content_sha256,
                    ),
                )
            ),
            passages=tuple(
                graph_passages[key]
                for key in sorted(
                    graph_passages,
                    key=lambda item: (
                        item.object_id,
                        item.version,
                        item.content_sha256,
                    ),
                )
            ),
            theories=graph_theories,
            wikis=tuple(
                GovernedWiki(
                    reference=reference,
                    record=wikis_by_ref[reference],
                )
                for reference in sorted(
                    graph_wiki_refs,
                    key=lambda value: (
                        value.object_id,
                        value.version,
                        value.content_sha256,
                    ),
                )
            ),
            relations=tuple(
                sorted(
                    relations,
                    key=lambda item: (
                        item.relation_ref.object_id,
                        item.relation_ref.version,
                        item.relation_ref.content_sha256,
                    ),
                )
            ),
        )
        graph = GlobalGraphBuilder(StaticGraphAuthority(snapshot)).build(
            state.authority_version,
            target_runtime_epoch=state.authority.snapshot.target_runtime_epoch,
        )
        graph_bytes = canonical_graph_bytes(graph_payload(graph))
        if hashlib.sha256(graph_bytes).hexdigest() != graph.canonical_sha256:
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_GRAPH_CANONICAL_HASH_MISMATCH"
            )
        projection = self._builders.graphify.project(graph)
        projection_bytes = canonical_json_bytes(
            {
                "edges": [
                    {
                        "source": str(source),
                        "target": str(target),
                        "attributes": dict(sorted(attributes.items())),
                    }
                    for source, target, attributes in sorted(
                        projection.edges(data=True),
                        key=lambda item: (str(item[0]), str(item[1])),
                    )
                ],
                "nodes": sorted(str(node) for node in projection.nodes),
                "schema_version": "consultation_graphify_projection.v1",
            }
        )
        communities = (
            {}
            if projection.number_of_nodes() == 0
            else {
                str(index): list(members)
                for index, members in self._builders.graphify.cluster(
                    graph
                ).communities.items()
            }
        )
        communities_bytes = canonical_json_bytes(communities)
        graph_ids = state.derived_ids["graph"]
        graph_ref = VersionRef(
            object_id=graph_ids.member_object_ids["global_graph"],
            version=state.authority_version,
            content_sha256=hashlib.sha256(graph_bytes).hexdigest(),
        )
        authority_records = tuple(
            sorted(
                (
                    self._graph_authority_record(
                        state,
                        relation=relation,
                        claim=graph_claims[relation.claim_ref].record,
                    )
                    for relation in relations
                ),
                key=lambda item: item.relation_ref.object_id,
            )
        )
        mapping = build_expected_graph_edge_mapping(
            graph,
            builder_input=builder_input,
            candidates=candidates,
            authority_records=authority_records,
        )
        catalog = GraphEdgeAuthorityCatalogPayload.create(
            graph_version=graph_ref,
            target_runtime_epoch=state.authority.snapshot.target_runtime_epoch,
            builder_input_sha256=builder_input.canonical_sha256,
            retrieval_input_descriptor_sha256=(
                state.authority.descriptor.descriptor_sha256
            ),
            assigned_input_set_sha256=(
                state.authority.descriptor.assigned_input_set_sha256("graph")
            ),
            edge_mapping=mapping,
            records=authority_records,
        )
        catalog_bytes = canonical_json_bytes(catalog.model_dump(mode="json"))
        builder_bytes = canonical_json_bytes(builder_input.model_dump(mode="json"))

        def member_ref(role: str, payload: bytes) -> VersionRef:
            return VersionRef(
                object_id=graph_ids.member_object_ids[role],
                version=state.authority_version,
                content_sha256=hashlib.sha256(payload).hexdigest(),
            )

        manifest = GraphBuildManifestPayload.create(
            builder_input_ref=member_ref("graph_builder_input", builder_bytes),
            graph_ref=graph_ref,
            edge_authority_catalog_ref=member_ref(
                "graph_edge_authority_catalog",
                catalog_bytes,
            ),
            graphify_projection_ref=member_ref(
                "graphify_projection",
                projection_bytes,
            ),
            graph_community_annotations_ref=member_ref(
                "graph_community_annotations",
                communities_bytes,
            ),
            target_runtime_epoch=state.authority.snapshot.target_runtime_epoch,
            source_catalog_version=state.authority_version,
            builder_input_sha256=builder_input.canonical_sha256,
            edge_authority_catalog_sha256=catalog.catalog_sha256,
            retrieval_input_descriptor_sha256=(
                state.authority.descriptor.descriptor_sha256
            ),
            assigned_input_set_sha256=(
                state.authority.descriptor.assigned_input_set_sha256("graph")
            ),
            expected_row_mapping_sha256=(
                state.authority.descriptor.expected_row_mapping_sha256("graph")
            ),
            edge_mapping_sha256=mapping.mapping_sha256,
            node_count=graph.graph.number_of_nodes(),
            edge_count=graph.graph.number_of_edges(),
            candidate_count=len(candidates),
        )
        payloads = {
            "graph_build_manifest": canonical_json_bytes(
                manifest.model_dump(mode="json")
            ),
            "global_graph": graph_bytes,
            "graph_edge_authority_catalog": catalog_bytes,
            "graphify_projection": projection_bytes,
            "graph_community_annotations": communities_bytes,
        }
        paths = self._write_payloads(
            state.build_root / "graph-artifact",
            payloads,
        )
        media_types = dict(
            zip(
                derived_artifact_role_layout("graph")[1:],
                derived_artifact_media_type_layout("graph")[1:],
                strict=True,
            )
        )
        return factory.fixed_layout(
            artifact_kind="graph",
            builder_input=builder_input,
            member_paths=paths,
            member_media_types=media_types,
            ids=graph_ids,
            source_lineage=state.lineage,
        )

    def _graph_authority_record(
        self,
        state: _BuildState,
        *,
        relation: ClaimRelation,
        claim: ClaimRecord,
    ) -> GraphEdgeAuthorityRecord:
        if (
            claim.provenance.provenance_scope != "global_source"
            or claim.provenance.client_ids
            or claim.provenance.case_contributor_client_ids
        ):
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_GRAPH_PRIVATE_PROVENANCE_FORBIDDEN"
            )
        independent = len(claim.provenance.source_ids)
        if independent <= 0:
            raise GlobalPublicationPlanningError(
                "KNOWLEDGE_GRAPH_SOURCE_COUNT_INVALID"
            )
        target_epoch = state.authority.snapshot.target_runtime_epoch
        digest = graph_edge_authority_sha256(
            relation_ref=relation.relation_ref,
            runtime_epoch=target_epoch,
            provenance_scope="global_source",
            independent_source_count=independent,
            minimum_leave_one_out_sources=1,
            contributor_client_ids=frozenset(),
            leave_one_out_grants=(),
            leave_one_out_parent_ref=None,
            excluded_client_ids=frozenset(),
        )
        return GraphEdgeAuthorityRecord(
            authority_ref=VersionRef(
                object_id=self._ids.object_id("graph_edge_authority"),
                version=state.authority_version,
                content_sha256=digest,
            ),
            relation_ref=relation.relation_ref,
            runtime_epoch=target_epoch,
            provenance_scope="global_source",
            independent_source_count=independent,
            minimum_leave_one_out_sources=1,
            contributor_client_ids=frozenset(),
            leave_one_out_grants=(),
            leave_one_out_parent_ref=None,
            excluded_client_ids=frozenset(),
        )


__all__ = [
    "GlobalKnowledgePublicationPlan",
    "GlobalKnowledgePublicationPlanner",
    "GlobalPublicationBuilders",
    "GlobalPublicationPlanningError",
]
