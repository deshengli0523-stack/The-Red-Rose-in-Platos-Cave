from __future__ import annotations

import hashlib
import itertools
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, cast

import numpy as np

from consultation_kb.approvals.attestation import (
    LocalHmacTargetExecutionAttestor,
    LocalHmacTargetExecutionProofVerifier,
)
from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.provider import (
    LocalHmacApprovalSigner,
    LocalHmacApprovalVerifier,
)
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.approval import P1GovernedWriteExecutor
from consultation_kb.knowledge.extractors import DocumentExtractor
from consultation_kb.knowledge.claims import ClaimProposalService
from consultation_kb.knowledge.provenance import ProvenancePolicyManifest
from consultation_kb.knowledge.review import ClaimReviewResolver
from consultation_kb.knowledge.scope_policy import ScopePolicyRepository
from consultation_kb.knowledge.theory import TheoryRevisionService
from consultation_kb.knowledge.wiki import (
    WikiClaimAuthority,
    WikiRevisionService,
    wiki_revision_body_sha256,
)
from consultation_kb.knowledge.wiki_renderer import REQUIRED_SECTION_KEYS
from consultation_kb.knowledge.publication import KnowledgePublicationService
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
from consultation_kb.lifecycle.publish import (
    ArtifactDraft,
    ContentDraft,
    PublishCoordinator,
    publication_closure_sha256,
)
from consultation_kb.knowledge.passages import PassageCatalog, PassageSegmenter
from consultation_kb.knowledge.registrar import SourceRegistrar
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import EvidenceLocator, Provenance
from consultation_kb.models.evidence import SourceGrade
from consultation_kb.models.knowledge import (
    ClaimApplicability,
    ClaimDraft,
    ClaimEvidenceRef,
    ClaimRecord,
    PassageRecord,
    SourceMetadata,
    SourceRecord,
)
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.scope_policy import (
    ScopePolicyDocument,
    ScopePolicyFieldValueMembers,
)
from consultation_kb.models.theory import TheoryRevision, TheoryRevisionDraft, TheoryScope
from consultation_kb.models.wiki import (
    WikiGraphRelationDeclaration,
    WikiRelationship,
    WikiRevision,
    WikiRevisionDraft,
    WikiSection,
)
from consultation_kb.storage.connection import connect_database
from consultation_kb.retrieval.artifact_contracts import (
    DerivedArtifactBuilderInputV2,
    GenericDerivedBuildManifestV2,
    KnowledgeRegistryPayloadV1,
    derived_artifact_role_layout,
)
from consultation_kb.retrieval.artifact_publication import (
    ArtifactPublicationIds,
    RetrievalArtifactDraftFactory,
)
from consultation_kb.retrieval.authority_descriptor import (
    AuthorityManifestMember,
    canonical_retrieval_route_policy_bytes,
    rebuild_publication_authority,
)
from consultation_kb.retrieval.contracts import (
    CandidateRef,
    canonical_json_bytes as retrieval_json_bytes,
)
from consultation_kb.retrieval.embeddings import DeterministicFakeEmbedder
from consultation_kb.retrieval.lexical_builder import (
    LexicalBuildManifest,
    LexicalDocument,
    LexicalIndexBuilder,
)
from consultation_kb.retrieval.vector_builder import (
    ExactVectorIndexBuilder,
    VectorDocument,
)
from consultation_kb.retrieval.wiki_builder import WikiNavigationIndexBuilder
from consultation_kb.storage.manifests import ManifestMember, manifest_sha256
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.storage.tombstones import (
    ObjectIdentity,
    TombstoneRepository,
    VisibilityGuard,
    lineage_hash,
)
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.approval_support import MutableClock, TestProtector
from tests.consultation_kb.retrieval_support import model_descriptor


@dataclass
class GlobalKnowledgeHarness:
    root: Path
    connection: sqlite3.Connection
    clock: MutableClock
    ids: IdFactory
    signer: LocalHmacApprovalSigner
    approvals: ApprovalService
    guard: ApprovalExecutionGuard
    executor: P1GovernedWriteExecutor
    store: ContentStore
    registrar: SourceRegistrar
    scope_policies: ScopePolicyRepository

    def diff_ref(self, descriptor: DraftDescriptor) -> VersionRef:
        return VersionRef(
            object_id=self.ids.object_id("approval_diff"),
            version=1,
            content_sha256=hashlib.sha256(
                descriptor.model_dump_json().encode("utf-8")
            ).hexdigest(),
        )

    def confirm(self, descriptor: DraftDescriptor) -> str:
        request = self.approvals.request(
            descriptor,
            diff_object_ref=self.diff_ref(descriptor),
        )
        challenge = self.approvals.challenge_for_review(request.request_id)
        self.approvals.confirm(self.signer.confirm(challenge))
        return request.request_id

    def register(
        self,
        relative: str,
        text: str,
        *,
        grade: SourceGrade,
        domain: str,
    ) -> tuple[SourceRecord, tuple[PassageRecord, ...], dict[str, str]]:
        path = self.root / "sources" / Path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        record = self.registrar.register_local_file(
            path,
            SourceMetadata(
                license="user_authorized",
                domain=domain,
                language="zh-CN",
                sensitivity="internal",
                source_grade=grade,
                document_type="md",
                author="synthetic_author",
            ),
        )
        changed = self.connection.execute(
            "UPDATE source_versions SET status = 'APPROVED' "
            "WHERE source_id = ? AND version = ? AND status = 'DRAFT'",
            (record.source_id, record.version),
        ).rowcount
        if changed != 1:
            raise AssertionError("synthetic source approval failed")
        source_ref = VersionRef(
            object_id=record.source_id,
            version=record.version,
            content_sha256=record.content_sha256,
        )
        extraction = DocumentExtractor().extract(path)
        passage_drafts = PassageSegmenter(
            logical_source_id=record.source_id,
            source_ref=source_ref,
            content_store=self.store,
            id_factory=self.ids,
        ).segment("md", extraction.blocks, review_status="draft", created_at=self.clock.now())
        texts = {
            passage.passage_id: extraction.blocks[index].text
            for index, passage in enumerate(passage_drafts)
        }
        catalog = PassageCatalog(
            self.connection,
            content_store=self.store,
            approval_executor=self.executor,
            id_factory=self.ids,
            clock=self.clock,
        )
        persisted = catalog.persist_drafts(passage_drafts)
        passages = tuple(
            catalog.approve(
                passage.passage_id,
                passage.version,
                approval_request_id=self.confirm(
                    catalog.preview_approval(passage.passage_id, passage.version)
                ),
            )
            for passage in persisted
        )
        return record, passages, texts

    def close(self) -> None:
        self.connection.close()


@dataclass
class PreparedKnowledge:
    claims: tuple[ClaimRecord, ...]
    claim_service: ClaimProposalService
    claim_drafts: tuple[ClaimDraft, ...]
    theory: TheoryRevision
    wiki: WikiRevision
    theory_service: TheoryRevisionService
    wiki_service: WikiRevisionService
    source_ids: tuple[str, ...]


PUBLICATION_KINDS = frozenset(
    {
        "wiki_page",
        "wiki_index",
        "knowledge_registry",
        "c1_revision",
        "claims",
        "graph",
        "lexical",
        "vector",
    }
)


@dataclass
class PreparedPublication:
    operation_id: str
    coordinator: PublishCoordinator
    service: KnowledgePublicationService


def rebuild_authority_services(
    harness: GlobalKnowledgeHarness,
) -> tuple[TheoryRevisionService, WikiRevisionService]:
    """Recreate authority services using only SQLite rows and verified CAS bytes."""

    theory_service = TheoryRevisionService(
        id_factory=harness.ids,
        clock=harness.clock,
        connection=harness.connection,
        approval_executor=harness.executor,
        content_store=harness.store,
        scope_policy_repository=ScopePolicyRepository(
            harness.connection,
            content_store=harness.store,
            approval_executor=harness.executor,
            clock=harness.clock,
        ),
    )

    def claim_status(reference: VersionRef) -> WikiClaimAuthority:
        row = harness.connection.execute(
            """
            SELECT claim_sha256, review_status, source_grade,
                   theory_revision_id, theory_revision,
                   theory_revision_sha256
              FROM claims WHERE claim_id = ? AND version = ?
            """,
            (reference.object_id, reference.version),
        ).fetchone()
        if row is None or str(row[0]) != reference.content_sha256:
            return WikiClaimAuthority(status="unavailable", source_grade="C2")
        theory_ref = None
        if row[3] is not None:
            theory_ref = VersionRef(
                object_id=str(row[3]),
                version=int(row[4]),
                content_sha256=str(row[5]),
            )
        return WikiClaimAuthority(
            status=(
                "approved"
                if str(row[1]) == "APPROVED"
                else "prepared" if str(row[1]) == "REVIEWED" else "unavailable"
            ),
            source_grade=cast(SourceGrade, str(row[2])),
            theory_revision_ref=theory_ref,
        )

    def passage_exists(reference: VersionRef) -> EvidenceLocator:
        row = harness.connection.execute(
            """
            SELECT normalized_text_sha256, locator_json FROM passages
             WHERE passage_id = ? AND version = ?
            """,
            (reference.object_id, reference.version),
        ).fetchone()
        if row is None or str(row[0]) != reference.content_sha256:
            raise ValueError("passage unavailable")
        return EvidenceLocator.model_validate_json(str(row[1]))

    wiki_service = WikiRevisionService(
        claim_resolver=claim_status,
        passage_resolver=passage_exists,
        theory_resolver=lambda ref: theory_service.get_by_ref(ref).status,
        id_factory=harness.ids,
        clock=harness.clock,
        connection=harness.connection,
        approval_executor=harness.executor,
        content_store=harness.store,
    )
    return theory_service, wiki_service


def prepare_governed_knowledge(
    harness: GlobalKnowledgeHarness,
    *,
    second_claim_multi_support: bool = False,
    include_graph_relation: bool = False,
) -> PreparedKnowledge:
    classic, classic_passages, classic_texts = harness.register(
        "classics/synthetic.md",
        "# 合成古籍\n\n## 章句\n\n无为不等于不行动。",
        grade="T1",
        domain="traditional_culture",
    )
    counseling, counseling_passages, counseling_texts = harness.register(
        "counseling/synthetic.md",
        "# 合成咨询资料\n\n## 定义\n\n接纳不等于赞同。",
        grade="C2",
        domain="emotional_consultation",
    )
    c1_source, c1_passages, c1_texts = harness.register(
        "consultant-theory/formal.md",
        "# 主咨询师正式理论\n\n## 命题\n\n先澄清事实，再解释关系模式。",
        grade="C1",
        domain="emotional_consultation",
    )
    texts = {**classic_texts, **counseling_texts, **c1_texts}
    locators = {
        passage.passage_id: passage.locator
        for passage in (*classic_passages, *counseling_passages, *c1_passages)
    }

    def resolve_passage(
        reference: VersionRef,
    ) -> tuple[str, None, None, EvidenceLocator]:
        text = texts[reference.object_id]
        locator = locators[reference.object_id]
        return text, None, None, locator

    policy = VersionRef(
        object_id=harness.ids.object_id("policy"),
        version=1,
        content_sha256="8" * 64,
    )
    claim_service = ClaimProposalService(
        review_resolver=ClaimReviewResolver(resolve_passage),
        id_factory=harness.ids,
        clock=harness.clock,
        connection=harness.connection,
        approval_executor=harness.executor,
        content_store=harness.store,
        provenance_policy=ProvenancePolicyManifest(
            manifest_ref=VersionRef(
                object_id=harness.ids.object_id("provenance_manifest"),
                version=1,
                content_sha256="7" * 64,
            ),
            rule_members=(policy,),
        ),
    )
    applicability = ClaimApplicability(
        domains=frozenset({"emotional_consultation"}),
        populations=frozenset({"adult"}),
        contexts=frozenset({"relationship"}),
        required_conditions=frozenset(),
        exclusions=frozenset(),
        contraindications=frozenset({"medical_diagnosis"}),
    )
    classic_ref = passage_ref(classic_passages[-1])
    counseling_ref = passage_ref(counseling_passages[-1])
    claim_drafts = (
        ClaimDraft(
            text="无为在该章句中不能直接等同于不行动。",
            cognitive_type="explicit",
            source_grade="T1",
            empirical_support="unassessed",
            applicability=applicability,
            privacy_scope="global",
            allowed_uses=frozenset({"consultation"}),
            evidence=(
                ClaimEvidenceRef(
                    passage_ref=classic_ref,
                    relation="supports",
                    evidence_role="primary",
                ),
            ),
            provenance=Provenance(
                source_ids=frozenset({classic.source_id}),
                passage_ids=frozenset({classic_ref.object_id}),
                provenance_scope="global_source",
                derivation_rule_ref=policy,
            ),
        ),
        ClaimDraft(
            text="接纳与无为可以类比，但现有资料不支持二者等同。",
            cognitive_type="cross_theory_analogy",
            source_grade="C2",
            empirical_support="conflicting",
            applicability=applicability,
            privacy_scope="global",
            allowed_uses=frozenset({"consultation"}),
            evidence=(
                ClaimEvidenceRef(
                    passage_ref=counseling_ref,
                    relation="supports",
                    evidence_role="primary",
                ),
                ClaimEvidenceRef(
                    passage_ref=classic_ref,
                    relation=(
                        "supports"
                        if second_claim_multi_support
                        else "contradicts"
                    ),
                    evidence_role=(
                        "corroborating"
                        if second_claim_multi_support
                        else "counterevidence"
                    ),
                ),
            ),
            provenance=Provenance(
                source_ids=frozenset({classic.source_id, counseling.source_id}),
                passage_ids=frozenset(
                    {classic_ref.object_id, counseling_ref.object_id}
                ),
                provenance_scope="global_source",
                derivation_rule_ref=policy,
            ),
        ),
    )
    claims: list[ClaimRecord] = []
    for draft in claim_drafts:
        proposal = claim_service.propose(draft)
        preview = claim_service.preview(proposal.proposal_id)
        claims.append(
            claim_service.commit(
                proposal.proposal_id,
                descriptor=preview.descriptor,
                approval_request_id=harness.confirm(preview.descriptor),
            )
        )

    scope_policy = ScopePolicyDocument(
        policy_id=harness.ids.object_id("scope_policy"),
        version=1,
        evaluator_id="deterministic_c1_scope",
        evaluator_version=1,
        rule_members=frozenset(
            {
                "contraindication_match",
                "context_match",
                "domain_match",
                "population_match",
            }
        ),
        context_fields=frozenset(
            {"contraindications", "context", "domain", "population"}
        ),
        field_value_members=(
            ScopePolicyFieldValueMembers(
                context_field="context",
                value_members=frozenset({"relationship"}),
            ),
            ScopePolicyFieldValueMembers(
                context_field="contraindications",
                value_members=frozenset({"medical_diagnosis", "none_observed"}),
            ),
            ScopePolicyFieldValueMembers(
                context_field="domain",
                value_members=frozenset({"emotional_consultation"}),
            ),
            ScopePolicyFieldValueMembers(
                context_field="population",
                value_members=frozenset({"adult"}),
            ),
        ),
    )
    prepared_scope_policy = harness.scope_policies.prepare(
        scope_policy,
        effective_from=harness.clock.now(),
    )
    scope_policy_ref = harness.scope_policies.approve(
        prepared_scope_policy.semantic_ref,
        approval_request_id=harness.confirm(
            harness.scope_policies.preview_approval(prepared_scope_policy.semantic_ref)
        ),
    ).semantic_ref
    theory_service = TheoryRevisionService(
        id_factory=harness.ids,
        clock=harness.clock,
        connection=harness.connection,
        approval_executor=harness.executor,
        content_store=harness.store,
        scope_policy_repository=harness.scope_policies,
    )
    theory_draft = TheoryRevisionDraft(
        theory_id=harness.ids.object_id("theory"),
        source_ref=source_ref(c1_source),
        document_sha256=c1_source.content_sha256,
        author="主咨询师",
        declared_version="1.0",
        effective_from=harness.clock.now(),
        effective_to=None,
        scope=TheoryScope(
            domains=frozenset({"emotional_consultation"}),
            populations=frozenset({"adult"}),
            contexts=frozenset({"relationship"}),
            required_conditions=frozenset(),
            exclusions=frozenset(),
            contraindications=frozenset({"medical_diagnosis"}),
        ),
        core_claims=("先澄清事实，再解释关系模式。",),
        methods=("时序澄清",),
        contraindications=("不可替代医学诊断",),
        counterexamples=("事实不足时不得作确定判断",),
        passage_refs=(passage_ref(c1_passages[-1]),),
        citation_refs=(source_ref(c1_source),),
        empirical_support="unassessed",
        scope_policy_ref=scope_policy_ref,
    )
    theory_proposal = theory_service.propose(theory_draft, actor="codex")
    theory_descriptor = theory_service.preview(theory_proposal.request_id)
    theory = theory_service.approve(
        theory_proposal.request_id,
        actor="primary_counselor",
        approval_request_id=harness.confirm(theory_descriptor),
    )

    def claim_status(reference: VersionRef) -> WikiClaimAuthority:
        row = harness.connection.execute(
            """
            SELECT claim_sha256, review_status, source_grade,
                   theory_revision_id, theory_revision,
                   theory_revision_sha256
              FROM claims WHERE claim_id = ? AND version = ?
            """,
            (reference.object_id, reference.version),
        ).fetchone()
        if row is None or row[0] != reference.content_sha256:
            return WikiClaimAuthority(
                status="unavailable",
                source_grade="C2",
            )
        theory_ref = None
        if row[3] is not None:
            theory_ref = VersionRef(
                object_id=str(row[3]),
                version=int(row[4]),
                content_sha256=str(row[5]),
            )
        review_status = str(row[1])
        status: Literal["approved", "prepared", "unavailable"] = (
            "approved"
            if review_status == "APPROVED"
            else "prepared" if review_status == "REVIEWED" else "unavailable"
        )
        return WikiClaimAuthority(
            status=status,
            source_grade=cast(SourceGrade, str(row[2])),
            theory_revision_ref=theory_ref,
        )

    def passage_exists(reference: VersionRef) -> EvidenceLocator:
        row = harness.connection.execute(
            "SELECT normalized_text_sha256, locator_json FROM passages WHERE passage_id = ? AND version = ?",
            (reference.object_id, reference.version),
        ).fetchone()
        if row is None or row[0] != reference.content_sha256:
            raise ValueError("passage unavailable")
        return EvidenceLocator.model_validate_json(row[1])

    wiki_service = WikiRevisionService(
        claim_resolver=claim_status,
        passage_resolver=passage_exists,
        theory_resolver=lambda ref: theory_service.get_by_ref(ref).status,
        id_factory=harness.ids,
        clock=harness.clock,
        connection=harness.connection,
        approval_executor=harness.executor,
        content_store=harness.store,
    )
    all_claim_refs = tuple(
        VersionRef(
            object_id=claim.claim_id,
            version=claim.version,
            content_sha256=claim.text_sha256,
        )
        for claim in claims
    ) + theory.claim_refs
    all_passage_refs = (
        classic_ref,
        counseling_ref,
        passage_ref(c1_passages[-1]),
    )
    sections = tuple(
        WikiSection(
            key=key,
            heading=key,
            body=f"{key} 的合成审核内容",
            claim_refs=all_claim_refs,
            passage_refs=all_passage_refs,
            stance=(
                "oppose"
                if key == "opposition"
                else "support" if key == "support" else "context"
            ),
        )
        for key in sorted(REQUIRED_SECTION_KEYS)
    )
    wiki_draft = WikiRevisionDraft(
        wiki_id=harness.ids.object_id("wiki"),
        slug="wu-wei-acceptance-boundary",
        title="无为与接纳的边界",
        base_revision=0,
        diff_kind="add",
        sections=sections,
        theory_revision_refs=(theory_service.version_ref(theory.theory_id, theory.revision),),
        relationships=(
            WikiRelationship(
                target_id=harness.ids.object_id("concept"),
                relationship="ANALOGOUS_TO",
                scope=("cultural_interpretation",),
                source_refs=(source_ref(classic), source_ref(counseling)),
                reviewed=True,
            ),
        ),
        graph_relations=(
            (
                WikiGraphRelationDeclaration(
                    source_ref=VersionRef(
                        object_id=harness.ids.object_id("concept"),
                        version=1,
                        content_sha256="a" * 64,
                    ),
                    target_ref=VersionRef(
                        object_id=harness.ids.object_id("practice"),
                        version=1,
                        content_sha256="b" * 64,
                    ),
                    claim_ref=all_claim_refs[0],
                    relation="ANALOGOUS_TO",
                    scope=("relationship",),
                    review_status="approved",
                    effective_from=harness.clock.now(),
                    confidence_override=0.8,
                ),
            )
            if include_graph_relation
            else ()
        ),
        review_due_at=None,
        unresolved_questions=("仍需补充独立外部实证",),
    )
    wiki_proposal = wiki_service.propose_diff(wiki_draft)
    wiki_descriptor = wiki_service.preview(wiki_proposal.proposal_id)
    wiki = wiki_service.approve(
        wiki_proposal.proposal_id,
        actor="primary_counselor",
        approval_request_id=harness.confirm(wiki_descriptor),
    )
    return PreparedKnowledge(
        claims=tuple(claims),
        claim_service=claim_service,
        claim_drafts=claim_drafts,
        theory=theory,
        wiki=wiki,
        theory_service=theory_service,
        wiki_service=wiki_service,
        source_ids=(classic.source_id, counseling.source_id, c1_source.source_id),
    )


def prepare_successor_knowledge(
    harness: GlobalKnowledgeHarness,
    previous: PreparedKnowledge,
    *,
    declared_version: str = "2.0",
) -> PreparedKnowledge:
    """Prepare a real-P1 successor C1 revision and its dependent Wiki revision."""

    prior_theory = previous.theory
    theory_draft = TheoryRevisionDraft(
        theory_id=prior_theory.theory_id,
        source_ref=prior_theory.source_ref,
        document_sha256=prior_theory.document_sha256,
        author=prior_theory.author,
        declared_version=declared_version,
        effective_from=harness.clock.now(),
        effective_to=prior_theory.effective_to,
        scope=prior_theory.scope,
        core_claims=tuple(f"{claim}（{declared_version} 修订）" for claim in prior_theory.core_claims),
        methods=prior_theory.methods,
        contraindications=prior_theory.contraindications,
        counterexamples=prior_theory.counterexamples,
        passage_refs=prior_theory.passage_refs,
        citation_refs=prior_theory.citation_refs,
        empirical_support=prior_theory.empirical_support,
        scope_policy_ref=prior_theory.scope_policy_ref,
        supersedes_ref=previous.theory_service.version_ref(
            prior_theory.theory_id,
            prior_theory.revision,
        ),
    )
    theory_proposal = previous.theory_service.propose(theory_draft, actor="codex")
    theory_descriptor = previous.theory_service.preview(theory_proposal.request_id)
    theory = previous.theory_service.approve(
        theory_proposal.request_id,
        actor="primary_counselor",
        approval_request_id=harness.confirm(theory_descriptor),
    )

    prior_c1_claim_ids = frozenset(
        reference.object_id for reference in prior_theory.claim_refs
    )
    sections = tuple(
        section.model_copy(
            update={
                "body": f"{section.body}（{declared_version} 修订）",
                "claim_refs": tuple(
                    reference
                    for reference in section.claim_refs
                    if reference.object_id not in prior_c1_claim_ids
                )
                + theory.claim_refs,
            }
        )
        for section in previous.wiki.sections
    )
    wiki_draft = WikiRevisionDraft(
        wiki_id=previous.wiki.wiki_id,
        slug=previous.wiki.slug,
        title=f"{previous.wiki.title}（{declared_version}）",
        base_revision=previous.wiki.revision,
        diff_kind="supersede",
        sections=sections,
        theory_revision_refs=(
            previous.theory_service.version_ref(theory.theory_id, theory.revision),
        ),
        relationships=previous.wiki.relationships,
        review_due_at=previous.wiki.review_due_at,
        unresolved_questions=previous.wiki.unresolved_questions,
    )
    wiki_proposal = previous.wiki_service.propose_diff(wiki_draft)
    wiki_descriptor = previous.wiki_service.preview(wiki_proposal.proposal_id)
    wiki = previous.wiki_service.approve(
        wiki_proposal.proposal_id,
        actor="primary_counselor",
        approval_request_id=harness.confirm(wiki_descriptor),
    )
    return PreparedKnowledge(
        claims=previous.claims,
        claim_service=previous.claim_service,
        claim_drafts=previous.claim_drafts,
        theory=theory,
        wiki=wiki,
        theory_service=previous.theory_service,
        wiki_service=previous.wiki_service,
        source_ids=previous.source_ids,
    )


def prepare_global_publication(
    harness: GlobalKnowledgeHarness,
    knowledge: PreparedKnowledge,
    *,
    authority_base_version: int = 1,
    expected_current_epoch: int | None = None,
    failure_hook: Callable[[str], None] | None = None,
    extra_claim_ids: tuple[str, ...] = (),
    invalid_derived_kind: str | None = None,
    legacy_derived_kind: str | None = None,
    duplicate_derived_kind: str | None = None,
    drop_lexical_support_row: bool = False,
    forge_graph_relation_scope: bool = False,
) -> PreparedPublication:
    coordinator = PublishCoordinator(
        harness.connection,
        harness.store,
        VisibilityGuard(TombstoneRepository(harness.connection)),
        clock=harness.clock,
    )
    lineage = tuple(
        ObjectIdentity("source", source_id) for source_id in knowledge.source_ids
    )
    lineage_hashes = tuple(
        sorted(lineage_hash(item.object_type, item.object_id) for item in lineage)
    )
    operation_id = harness.ids.object_id("knowledge_publication")
    manifest_ids = {
        kind: harness.ids.object_id("manifest") for kind in sorted(PUBLICATION_KINDS)
    }
    derived_ids = {
        kind: ArtifactPublicationIds(
            manifest_id=manifest_ids[kind],
            member_object_ids={
                role: harness.ids.object_id(role)
                for role in derived_artifact_role_layout(kind)
            },
        )
        for kind in (
            "wiki_index",
            "knowledge_registry",
            "graph",
            "lexical",
            "vector",
        )
    }

    def content_from_row(row) -> bytes:  # type: ignore[no-untyped-def]
        value = str(row[0])
        assert value.startswith("sha256:")
        return harness.store.read_verified(
            harness.store.reference(
                content_sha256=value.removeprefix("sha256:"),
                size_bytes=int(row[1]),
                media_type=str(row[2]),
            )
        )

    theory_row = harness.connection.execute(
        """
        SELECT revision_object_ref, revision_object_size_bytes,
               revision_object_media_type
          FROM theory_revisions WHERE theory_id = ? AND revision = ?
        """,
        (knowledge.theory.theory_id, knowledge.theory.revision),
    ).fetchone()
    wiki_row = harness.connection.execute(
        """
        SELECT body_object_ref, body_object_size_bytes, body_object_media_type
          FROM wiki_revisions WHERE wiki_id = ? AND revision = ?
        """,
        (knowledge.wiki.wiki_id, knowledge.wiki.revision),
    ).fetchone()
    assert theory_row is not None and wiki_row is not None
    target_claim_rows = {
        (str(row[0]), int(row[1])): row
        for row in harness.connection.execute(
            "SELECT DISTINCT c.claim_id, c.version, c.claim_object_ref, "
            "c.claim_object_size_bytes, c.claim_object_media_type "
            "FROM wiki_revision_claims AS wc JOIN claims AS c "
            "ON c.claim_id = wc.claim_id AND c.version = wc.claim_version "
            "WHERE wc.wiki_id = ? AND wc.wiki_revision = ?",
            (knowledge.wiki.wiki_id, knowledge.wiki.revision),
        )
    }
    for row in harness.connection.execute(
        "SELECT claim_id, version, claim_object_ref, claim_object_size_bytes, "
        "claim_object_media_type FROM claims WHERE source_grade = 'C1' "
        "AND theory_revision_id = ? AND theory_revision = ?",
        (knowledge.theory.theory_id, knowledge.theory.revision),
    ):
        target_claim_rows[(str(row[0]), int(row[1]))] = row
    claim_rows = sorted(
        target_claim_rows.values(), key=lambda row: (str(row[0]), int(row[1]))
    )
    known_claim_ids = {str(row[0]) for row in claim_rows}
    extra_rows = []
    for claim_id in extra_claim_ids:
        if claim_id in known_claim_ids:
            continue
        row = harness.connection.execute(
            """
            SELECT claim_id, version, claim_object_ref,
                   claim_object_size_bytes, claim_object_media_type
              FROM claims WHERE claim_id = ?
            """,
            (claim_id,),
        ).fetchone()
        if row is None:
            raise AssertionError("extra publication claim does not exist")
        extra_rows.append(row)

    exact_members: dict[str, tuple[ContentDraft, ...]] = {
        "c1_revision": (
            ContentDraft(
                object_type="theory",
                object_id=knowledge.theory.theory_id,
                data=content_from_row(theory_row),
                source_version=authority_base_version,
                media_type=str(theory_row[2]),
                source_lineage=lineage,
            ),
        ),
        "wiki_page": (
            ContentDraft(
                object_type="wiki",
                object_id=knowledge.wiki.wiki_id,
                data=content_from_row(wiki_row),
                source_version=authority_base_version,
                media_type=str(wiki_row[2]),
                source_lineage=lineage,
            ),
        ),
        "claims": tuple(
            ContentDraft(
                object_type="claim",
                object_id=str(row[0]),
                data=content_from_row((row[2], row[3], row[4])),
                source_version=authority_base_version,
                media_type=str(row[4]),
                source_lineage=lineage,
            )
            for row in claim_rows
        ),
    }

    def manifest_members(
        drafts: tuple[ContentDraft, ...],
    ) -> tuple[ManifestMember, ...]:
        return tuple(
            ManifestMember(
                ordinal=ordinal,
                object_type=draft.object_type,
                object_id=draft.object_id,
                object_sha256=hashlib.sha256(draft.data).hexdigest(),
                source_version=draft.source_version,
                media_type=draft.media_type,
                size_bytes=len(draft.data),
                source_lineage_hashes=lineage_hashes,
            )
            for ordinal, draft in enumerate(drafts)
        )

    claim_manifest_members = manifest_members(exact_members["claims"])
    claim_manifest_sha256 = manifest_sha256(
        manifest_id=manifest_ids["claims"],
        operation_id=operation_id,
        artifact_key="claims",
        artifact_kind="claims",
        source_version=authority_base_version,
        members=claim_manifest_members,
    )
    claims_manifest_ref = VersionRef(
        object_id=manifest_ids["claims"],
        version=authority_base_version,
        content_sha256=claim_manifest_sha256,
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
    route_policy_payload = canonical_retrieval_route_policy_bytes()
    harness.store.finalize(
        harness.store.stage_bytes(
            route_policy_payload,
            purpose="wiki_publish",
            manifest_id=manifest_ids["knowledge_registry"],
            media_type="application/json",
        )
    )
    route_policy_id = derived_ids["knowledge_registry"].member_object_ids[
        "retrieval_route_policy"
    ]
    route_policy_member = AuthorityManifestMember(
        object_type="retrieval_route_policy",
        object_id=route_policy_id,
        object_sha256=hashlib.sha256(route_policy_payload).hexdigest(),
        source_version=authority_base_version,
        source_lineage_hashes=lineage_hashes,
        media_type="application/json",
        size_bytes=len(route_policy_payload),
    )
    rebuilt = rebuild_publication_authority(
        harness.connection,
        harness.store,
        publication_authority_version=authority_base_version,
        expected_current_epoch=expected_current_epoch,
        theory_id=knowledge.theory.theory_id,
        theory_revision=knowledge.theory.revision,
        wiki_id=knowledge.wiki.wiki_id,
        wiki_revision=knowledge.wiki.revision,
        claims_manifest_ref=claims_manifest_ref,
        claim_members=authority_claim_members,
        route_policy_member=route_policy_member,
    )
    authority_closure_sha256 = hashlib.sha256(
        retrieval_json_bytes(rebuilt.snapshot.model_dump(mode="json"))
    ).hexdigest()
    builder_inputs = {
        kind: DerivedArtifactBuilderInputV2(
            artifact_kind=kind,
            authority_closure_sha256=authority_closure_sha256,
            authority_snapshot=rebuilt.snapshot,
            retrieval_input_descriptor=rebuilt.descriptor,
            target_runtime_epoch=rebuilt.snapshot.target_runtime_epoch,
        )
        for kind in (
            "wiki_index",
            "knowledge_registry",
            "graph",
            "lexical",
            "vector",
        )
    }

    build_root = harness.root / "derived-builds" / operation_id
    build_root.mkdir(parents=True)
    factory = RetrievalArtifactDraftFactory(build_root)

    def candidate_for(
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
            for assignment in rebuilt.assignments
            if target in assignment.target_channels
        )

    lexical_candidates = candidate_for("lexical")
    vector_candidates = candidate_for("vector")

    def candidate_text(candidate: CandidateRef) -> str:
        return harness.store.read_hash_verified(
            candidate.content_ref.content_sha256
        ).decode("utf-8", errors="strict")

    lexical_path = build_root / "lexical.sqlite3"
    lexical_manifest = LexicalIndexBuilder().build(
        tuple(
            LexicalDocument(candidate=candidate, text=candidate_text(candidate))
            for candidate in lexical_candidates
        ),
        lexical_path,
        builder_input=builder_inputs["lexical"],
    )
    if drop_lexical_support_row:
        connection = sqlite3.connect(lexical_path)
        try:
            repeated_claim = connection.execute(
                "SELECT evidence_id FROM lexical_documents "
                "GROUP BY evidence_id HAVING COUNT(*) > 1 "
                "ORDER BY evidence_id LIMIT 1"
            ).fetchone()
            if repeated_claim is None:
                raise AssertionError("no multi-support lexical row to drop")
            removed = connection.execute(
                "SELECT row_id FROM lexical_documents "
                "WHERE evidence_id = ? ORDER BY content_object_id DESC LIMIT 1",
                (str(repeated_claim[0]),),
            ).fetchone()
            assert removed is not None
            row_id = str(removed[0])
            connection.execute(
                "DELETE FROM lexical_word_fts WHERE row_id = ?", (row_id,)
            )
            connection.execute(
                "DELETE FROM lexical_char_fts WHERE row_id = ?", (row_id,)
            )
            connection.execute(
                "DELETE FROM lexical_provenance WHERE row_id = ?", (row_id,)
            )
            connection.execute(
                "DELETE FROM lexical_documents WHERE row_id = ?", (row_id,)
            )
            connection.commit()
        finally:
            connection.close()
        lexical_manifest = LexicalBuildManifest.model_validate(
            {
                **lexical_manifest.model_dump(mode="python"),
                "index_sha256": hashlib.sha256(lexical_path.read_bytes()).hexdigest(),
            },
            strict=True,
        )
    lexical_draft = factory.lexical(
        builder_input=builder_inputs["lexical"],
        build_manifest=lexical_manifest,
        index_path=lexical_path,
        ids=derived_ids["lexical"],
        source_lineage=lineage,
    )
    vocabulary = {
        candidate_text(candidate): np.asarray([1.0, 0.0], dtype=np.float32)
        for candidate in vector_candidates
    }
    embedder = DeterministicFakeEmbedder(model_descriptor(), vocabulary)
    vector_path = build_root / "vector-artifact"
    vector_manifest = ExactVectorIndexBuilder(embedder).build(
        tuple(
            VectorDocument(candidate=candidate, text=candidate_text(candidate))
            for candidate in vector_candidates
        ),
        vector_path,
        builder_input=builder_inputs["vector"],
    )
    vector_draft = factory.vector(
        builder_input=builder_inputs["vector"],
        build_manifest=vector_manifest,
        vector_directory=vector_path,
        ids=derived_ids["vector"],
        source_lineage=lineage,
    )

    def fixed_projection(
        kind: Literal["wiki_index", "knowledge_registry"],
    ) -> ArtifactDraft:
        if kind == "wiki_index":
            wiki_artifacts = WikiNavigationIndexBuilder().build(
                tuple(
                    assignment
                    for assignment in rebuilt.assignments
                    if "wiki_index" in assignment.target_channels
                ),
                knowledge.wiki,
                builder_input=builder_inputs["wiki_index"],
            )
            data_payloads = {
                "wiki_index": wiki_artifacts.index_bytes,
            }
            manifest = wiki_artifacts.build_manifest
        else:
            data_payloads = {
                "retrieval_route_policy": route_policy_payload,
                "knowledge_registry": retrieval_json_bytes(
                    KnowledgeRegistryPayloadV1.from_descriptor(
                        rebuilt.descriptor
                    ).model_dump(mode="json")
                ),
            }
            manifest = GenericDerivedBuildManifestV2.create(
                artifact_kind=kind,
                builder_input=builder_inputs[kind],
                member_content_sha256={
                    role: hashlib.sha256(payload).hexdigest()
                    for role, payload in data_payloads.items()
                },
            )
        payloads = {
            f"{kind}_build_manifest": retrieval_json_bytes(
                manifest.model_dump(mode="json")
            ),
            **data_payloads,
        }
        paths = {}
        for role, payload in payloads.items():
            path = build_root / kind / f"{role}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            paths[role] = path
        return factory.fixed_layout(
            artifact_kind=kind,
            builder_input=builder_inputs[kind],
            member_paths=paths,
            member_media_types={role: "application/json" for role in paths},
            ids=derived_ids[kind],
            source_lineage=lineage,
        )

    graph_candidates = candidate_for("global_graph")
    graph_declarations = knowledge.wiki.graph_relations
    graph_wiki_record = knowledge.wiki.model_copy(update={"status": "active"})
    if forge_graph_relation_scope:
        if not graph_declarations:
            raise AssertionError("no graph relation available to forge")
        graph_declarations = tuple(
            declaration.model_copy(update={"scope": ("forged_scope",)})
            for declaration in graph_declarations
        )
        graph_wiki_record = graph_wiki_record.model_copy(
            update={"graph_relations": graph_declarations}
        )
        graph_wiki_record = graph_wiki_record.model_copy(
            update={"body_sha256": wiki_revision_body_sha256(graph_wiki_record)}
        )
    wiki_ref = VersionRef(
        object_id=graph_wiki_record.wiki_id,
        version=graph_wiki_record.revision,
        content_sha256=graph_wiki_record.body_sha256,
    )
    graph_claims: dict[str, GovernedClaim] = {}
    graph_passages: dict[str, GovernedPassage] = {}
    graph_relations: list[ClaimRelation] = []
    graph_claim_passages = {
        candidate.reference: frozenset(
            item.content_ref
            for item in graph_candidates
            if item.reference == candidate.reference
        )
        for candidate in graph_candidates
    }
    passage_catalog = PassageCatalog(
        harness.connection,
        content_store=harness.store,
        approval_executor=harness.executor,
        id_factory=harness.ids,
        clock=harness.clock,
    )
    for declaration in graph_declarations:
        claim_record = knowledge.claim_service.get(
            declaration.claim_ref.object_id,
            declaration.claim_ref.version,
        )
        if (
            claim_record.text_sha256 != declaration.claim_ref.content_sha256
            or frozenset(claim_record.passage_refs)
            != graph_claim_passages.get(declaration.claim_ref, frozenset())
        ):
            raise AssertionError(
                "graph declaration must map to every SUPPORTS Passage and no other edge"
            )
        graph_claim_record = (
            claim_record.model_copy(update={"review_status": "approved"})
            if claim_record.source_grade == "C1"
            else claim_record
        )
        graph_claims[claim_record.claim_id] = GovernedClaim(
            reference=declaration.claim_ref,
            record=graph_claim_record,
        )
        for passage_ref_value in claim_record.passage_refs:
            graph_passages[passage_ref_value.object_id] = GovernedPassage(
                reference=passage_ref_value,
                record=passage_catalog.get(
                    passage_ref_value.object_id,
                    passage_ref_value.version,
                ),
            )
        relation_values = {
            "wiki_ref": wiki_ref,
            "source_ref": declaration.source_ref,
            "target_ref": declaration.target_ref,
            "claim_ref": declaration.claim_ref,
            "relation": declaration.relation,
            "scope": declaration.scope,
            "review_status": declaration.review_status,
            "effective_from": declaration.effective_from,
            "effective_to": declaration.effective_to,
            "confidence_override": declaration.confidence_override,
        }
        relation_ref = VersionRef(
            object_id=harness.ids.object_id("graph_edge"),
            version=authority_base_version,
            content_sha256=claim_relation_sha256(**relation_values),
        )
        graph_relations.append(
            ClaimRelation(
                relation_ref=relation_ref,
                **relation_values,
            )
        )
    if bool(graph_relations) != bool(graph_candidates):
        raise AssertionError("graph declarations and routed candidates diverged")

    graph_theories: tuple[GovernedTheory, ...] = ()
    if any(value.record.source_grade == "C1" for value in graph_claims.values()):
        active_theory = knowledge.theory.model_copy(update={"status": "active"})
        graph_theories = (
            GovernedTheory(
                reference=knowledge.theory_service.version_ref(
                    active_theory.theory_id,
                    active_theory.revision,
                ),
                record=active_theory,
            ),
        )

    graph_snapshot = GraphAuthoritySnapshot(
        catalog_version=authority_base_version,
        runtime_epoch=rebuilt.snapshot.target_runtime_epoch,
        effective_at=harness.clock.now(),
        claims=tuple(
            graph_claims[key] for key in sorted(graph_claims)
        ),
        passages=tuple(
            graph_passages[key] for key in sorted(graph_passages)
        ),
        theories=graph_theories,
        wikis=(
            (
                GovernedWiki(
                    reference=wiki_ref,
                    record=graph_wiki_record,
                ),
            )
            if graph_relations
            else ()
        ),
        relations=tuple(graph_relations),
    )
    graph_artifact = GlobalGraphBuilder(
        StaticGraphAuthority(graph_snapshot)
    ).build(
        authority_base_version,
        target_runtime_epoch=rebuilt.snapshot.target_runtime_epoch,
    )
    graph_bytes = canonical_graph_bytes(graph_payload(graph_artifact))
    if hashlib.sha256(graph_bytes).hexdigest() != graph_artifact.canonical_sha256:
        raise AssertionError("production graph bytes do not match artifact closure")
    projection_adapter = GraphifyProjectionAdapter(seed=42)
    projection = projection_adapter.project(graph_artifact)
    projection_bytes = retrieval_json_bytes(
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
    if projection.number_of_nodes() == 0:
        communities: dict[str, list[str]] = {}
    else:
        clustered = projection_adapter.cluster(graph_artifact)
        communities = {
            str(index): list(members)
            for index, members in clustered.communities.items()
        }
    communities_bytes = retrieval_json_bytes(communities)
    graph_builder_bytes = retrieval_json_bytes(
        builder_inputs["graph"].model_dump(mode="json")
    )
    graph_ref = VersionRef(
        object_id=derived_ids["graph"].member_object_ids["global_graph"],
        version=authority_base_version,
        content_sha256=hashlib.sha256(graph_bytes).hexdigest(),
    )
    authority_records: list[GraphEdgeAuthorityRecord] = []
    for relation in graph_relations:
        claim_record = graph_claims[relation.claim_ref.object_id].record
        independent_source_count = len(
            set(claim_record.provenance.source_ids)
            | set(claim_record.provenance.case_ids)
        )
        authority_values = {
            "relation_ref": relation.relation_ref,
            "runtime_epoch": rebuilt.snapshot.target_runtime_epoch,
            "provenance_scope": claim_record.provenance.provenance_scope,
            "independent_source_count": independent_source_count,
            "minimum_leave_one_out_sources": 1,
            "contributor_client_ids": frozenset(),
            "leave_one_out_grants": (),
            "leave_one_out_parent_ref": None,
            "excluded_client_ids": frozenset(),
        }
        authority_records.append(
            GraphEdgeAuthorityRecord(
                authority_ref=VersionRef(
                    object_id=harness.ids.object_id("graph_edge_authority"),
                    version=authority_base_version,
                    content_sha256=graph_edge_authority_sha256(
                        **authority_values
                    ),
                ),
                **authority_values,
            )
        )
    exact_authority_records = tuple(
        sorted(authority_records, key=lambda item: item.relation_ref.object_id)
    )
    graph_mapping = build_expected_graph_edge_mapping(
        graph_artifact,
        builder_input=builder_inputs["graph"],
        candidates=graph_candidates,
        authority_records=exact_authority_records,
    )
    graph_catalog = GraphEdgeAuthorityCatalogPayload.create(
        graph_version=graph_ref,
        target_runtime_epoch=rebuilt.snapshot.target_runtime_epoch,
        builder_input_sha256=builder_inputs["graph"].canonical_sha256,
        retrieval_input_descriptor_sha256=rebuilt.descriptor.descriptor_sha256,
        assigned_input_set_sha256=rebuilt.descriptor.assigned_input_set_sha256(
            "graph"
        ),
        edge_mapping=graph_mapping,
        records=exact_authority_records,
    )
    graph_catalog_bytes = retrieval_json_bytes(
        graph_catalog.model_dump(mode="json")
    )

    def graph_member_ref(role: str, payload: bytes) -> VersionRef:
        return VersionRef(
            object_id=derived_ids["graph"].member_object_ids[role],
            version=authority_base_version,
            content_sha256=hashlib.sha256(payload).hexdigest(),
        )

    graph_manifest = GraphBuildManifestPayload.create(
        builder_input_ref=graph_member_ref(
            "graph_builder_input", graph_builder_bytes
        ),
        graph_ref=graph_ref,
        edge_authority_catalog_ref=graph_member_ref(
            "graph_edge_authority_catalog", graph_catalog_bytes
        ),
        graphify_projection_ref=graph_member_ref(
            "graphify_projection", projection_bytes
        ),
        graph_community_annotations_ref=graph_member_ref(
            "graph_community_annotations", communities_bytes
        ),
        target_runtime_epoch=rebuilt.snapshot.target_runtime_epoch,
        source_catalog_version=authority_base_version,
        builder_input_sha256=builder_inputs["graph"].canonical_sha256,
        edge_authority_catalog_sha256=graph_catalog.catalog_sha256,
        retrieval_input_descriptor_sha256=rebuilt.descriptor.descriptor_sha256,
        assigned_input_set_sha256=rebuilt.descriptor.assigned_input_set_sha256(
            "graph"
        ),
        expected_row_mapping_sha256=rebuilt.descriptor.expected_row_mapping_sha256(
            "graph"
        ),
        edge_mapping_sha256=graph_mapping.mapping_sha256,
        node_count=graph_artifact.graph.number_of_nodes(),
        edge_count=graph_artifact.graph.number_of_edges(),
        candidate_count=len(graph_candidates),
    )
    graph_payloads = {
        "graph_build_manifest": retrieval_json_bytes(
            graph_manifest.model_dump(mode="json")
        ),
        "global_graph": graph_bytes,
        "graph_edge_authority_catalog": graph_catalog_bytes,
        "graphify_projection": projection_bytes,
        "graph_community_annotations": communities_bytes,
    }
    graph_paths = {}
    for role, payload in graph_payloads.items():
        path = build_root / "graph" / f"{role}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        graph_paths[role] = path
    graph_draft = factory.fixed_layout(
        artifact_kind="graph",
        builder_input=builder_inputs["graph"],
        member_paths=graph_paths,
        member_media_types={role: "application/json" for role in graph_paths},
        ids=derived_ids["graph"],
        source_lineage=lineage,
    )

    actual_claim_members = exact_members["claims"] + tuple(
        ContentDraft(
            object_type="claim",
            object_id=str(row[0]),
            data=content_from_row((row[2], row[3], row[4])),
            source_version=authority_base_version,
            media_type=str(row[4]),
            source_lineage=lineage,
        )
        for row in extra_rows
    )
    artifacts_by_kind = {
        "c1_revision": ArtifactDraft(
            manifest_id=manifest_ids["c1_revision"],
            artifact_key="c1_revision",
            artifact_kind="c1_revision",
            source_version=authority_base_version,
            members=exact_members["c1_revision"],
        ),
        "wiki_page": ArtifactDraft(
            manifest_id=manifest_ids["wiki_page"],
            artifact_key="wiki_page",
            artifact_kind="wiki_page",
            source_version=authority_base_version,
            members=exact_members["wiki_page"],
        ),
        "claims": ArtifactDraft(
            manifest_id=manifest_ids["claims"],
            artifact_key="claims",
            artifact_kind="claims",
            source_version=authority_base_version,
            members=actual_claim_members,
        ),
        "wiki_index": fixed_projection("wiki_index"),
        "knowledge_registry": fixed_projection("knowledge_registry"),
        "graph": graph_draft,
        "lexical": lexical_draft,
        "vector": vector_draft,
    }
    replaced_kind = invalid_derived_kind or legacy_derived_kind
    if replaced_kind is not None:
        invalid = artifacts_by_kind[replaced_kind]
        first, *rest = invalid.members
        replacement = b'{"placeholder":true}'
        if legacy_derived_kind is not None:
            replacement = retrieval_json_bytes(
                {
                    "artifact_kind": legacy_derived_kind,
                    "authority_closure_sha256": authority_closure_sha256,
                    "authority_snapshot": rebuilt.snapshot.model_dump(mode="json"),
                    "contract": "knowledge_builder_input_v1",
                }
            )
        artifacts_by_kind[replaced_kind] = ArtifactDraft(
            manifest_id=invalid.manifest_id,
            artifact_key=invalid.artifact_key,
            artifact_kind=invalid.artifact_kind,
            source_version=invalid.source_version,
            members=(
                ContentDraft(
                    object_type=first.object_type,
                    object_id=first.object_id,
                    data=replacement,
                    source_version=first.source_version,
                    media_type=first.media_type,
                    source_lineage=first.source_lineage,
                ),
                *rest,
            ),
        )
    artifacts_list = [artifacts_by_kind[kind] for kind in sorted(PUBLICATION_KINDS)]
    if duplicate_derived_kind is not None:
        duplicated = artifacts_by_kind[duplicate_derived_kind]
        artifacts_list.append(
            ArtifactDraft(
                manifest_id=harness.ids.object_id("manifest"),
                artifact_key=f"{duplicate_derived_kind}_duplicate",
                artifact_kind=duplicate_derived_kind,
                source_version=authority_base_version,
                members=duplicated.members,
            )
        )
    artifacts = tuple(artifacts_list)
    staged = coordinator.stage_artifacts(purpose="wiki_publish", artifacts=artifacts)
    descriptor = DraftDescriptor(
        purpose="wiki_publish",
        target_id="global-knowledge",
        base_version=authority_base_version - 1,
        draft_sha256=publication_closure_sha256(
            purpose="wiki_publish",
            authority_base_version=authority_base_version,
            expected_current_epoch=expected_current_epoch,
            artifacts=artifacts,
        ),
    )
    request_id = harness.confirm(descriptor)
    ticket = harness.approvals.issue_for_execution(
        request_id,
        descriptor,
        operation_id=operation_id,
    )
    proof = harness.guard.apply_in_transaction(
        ticket,
        descriptor,
        lambda _connection: coordinator.prepare(
            operation_id=operation_id,
            purpose="wiki_publish",
            authority_base_version=authority_base_version,
            approval_request_id=request_id,
            descriptor_sha256=ticket.descriptor_sha256,
            expected_current_epoch=expected_current_epoch,
            artifacts=staged,
        ),
    )
    harness.approvals.acknowledge(proof)
    coordinator.verify(operation_id)

    service = KnowledgePublicationService(
        coordinator=coordinator,
        theory_service=knowledge.theory_service,
        wiki_service=knowledge.wiki_service,
        connection=harness.connection,
        required_artifact_kinds=PUBLICATION_KINDS,
        lint_error_count=lambda: 0,
        failure_hook=failure_hook,
        content_store=harness.store,
    )
    return PreparedPublication(
        operation_id=operation_id,
        coordinator=coordinator,
        service=service,
    )


def build_global_knowledge_harness(
    tmp_path: Path,
    *,
    root: Path | None = None,
    database_name: str = "global.sqlite3",
) -> GlobalKnowledgeHarness:
    root = tmp_path / "knowledge-vault" if root is None else root
    (root / "sources").mkdir(parents=True)
    connection = connect_database(root / database_name, mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    clock = MutableClock()
    random_values = itertools.count(1)
    nonce_values = itertools.count(1)
    ids = IdFactory(clock, lambda: next(random_values))
    signer = LocalHmacApprovalSigner(
        secret=b"p" * 32,
        provider_id="local-review-agent",
        clock=clock,
    )
    verifier = LocalHmacApprovalVerifier(
        secret=b"p" * 32,
        provider_id="local-review-agent",
    )
    approvals = ApprovalService(
        connection,
        provider=verifier,
        protector=TestProtector(),
        clock=clock,
        id_factory=ids,
        target_scope_hash="a" * 64,
        vault_id="synthetic-global-vault",
        execution_secret=b"e" * 32,
        execution_proof_verifier=LocalHmacTargetExecutionProofVerifier(
            secret=b"t" * 32,
            attestor_id="knowledge-target-writer",
        ),
        nonce_source=lambda size: next(nonce_values).to_bytes(size, "big"),
    )
    guard = ApprovalExecutionGuard(
        connection,
        approval_service=approvals,
        execution_proof_signer=LocalHmacTargetExecutionAttestor(
            secret=b"t" * 32,
            attestor_id="knowledge-target-writer",
        ),
        clock=clock,
    )
    executor = P1GovernedWriteExecutor(
        approval_service=approvals,
        execution_guard=guard,
        id_factory=ids,
    )
    store = ContentStore(root / "global-content")
    scope_policies = ScopePolicyRepository(
        connection,
        content_store=store,
        approval_executor=executor,
        clock=clock,
    )
    registrar = SourceRegistrar(
        connection,
        sources_root=root / "sources",
        content_store=store,
        id_factory=ids,
        clock=clock,
    )
    return GlobalKnowledgeHarness(
        root=root,
        connection=connection,
        clock=clock,
        ids=ids,
        signer=signer,
        approvals=approvals,
        guard=guard,
        executor=executor,
        store=store,
        registrar=registrar,
        scope_policies=scope_policies,
    )


def passage_ref(value: PassageRecord) -> VersionRef:
    return VersionRef(
        object_id=value.passage_id,
        version=value.version,
        content_sha256=value.normalized_text_sha256,
    )


def source_ref(value: SourceRecord) -> VersionRef:
    return VersionRef(
        object_id=value.source_id,
        version=value.version,
        content_sha256=value.content_sha256,
    )


def _utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
