from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from consultation_kb.knowledge.wiki import wiki_revision_body_sha256
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import (
    EvidenceFreshnessSnapshot,
    EvidenceLocator,
    Provenance,
)
from consultation_kb.models.wiki import (
    WikiGraphRelationDeclaration,
    WikiRelationship,
    WikiRevision,
    WikiRevisionDraft,
    WikiSection,
)
from consultation_kb.retrieval.artifact_contracts import (
    ArtifactBinding,
    ArtifactBindingIdentity,
    ArtifactMemberIdentity,
    DerivedArtifactBuilderInputV2,
    DerivedAuthorityObjectVersion,
    DerivedAuthoritySnapshotV2,
    RetrievalInputAssignment,
    RetrievalInputDescriptor,
    _new_artifact_binding,
)
from consultation_kb.retrieval.contracts import (
    CandidateMetadata,
    CandidateRef,
    canonical_json_bytes,
)
from consultation_kb.retrieval.wiki_builder import (
    WikiIndexBuildArtifacts,
    WikiNavigationIndexBuilder,
)
from consultation_kb.retrieval.wiki_index import WikiIndexRetriever
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.retrieval_support import NOW, object_id, reference


@dataclass(frozen=True, slots=True)
class WikiFixture:
    assignments: tuple[RetrievalInputAssignment, ...]
    builder_input: DerivedArtifactBuilderInputV2
    candidates: tuple[CandidateRef, ...]
    revision: WikiRevision


@dataclass(slots=True)
class BindingState:
    calls: int = 0
    stale: bool = False

    def verify(self, _identity: ArtifactBindingIdentity) -> None:
        self.calls += 1
        if self.stale:
            raise RuntimeError("stale")


@dataclass(frozen=True, slots=True)
class BoundWikiIndex:
    binding: ArtifactBinding
    retriever: WikiIndexRetriever
    state: BindingState
    store: ContentStore


def _candidate(
    claim_ref: VersionRef,
    passage_ref: VersionRef,
    *,
    index: int,
    passage_ids: frozenset[str],
) -> CandidateRef:
    provenance = Provenance(
        source_ids=frozenset({object_id("source", index + 100)}),
        passage_ids=passage_ids,
        provenance_scope="global_source",
        derivation_rule_ref=reference("derivation_rule", index + 200),
    )
    return CandidateRef(
        reference=claim_ref,
        content_ref=passage_ref,
        object_type="claim",
        channel="wiki",
        metadata=CandidateMetadata(
            manifest_ref=reference("artifact_manifest", index + 300),
            review_status="approved",
            allowed_uses=frozenset({"consultation"}),
            approved_at=NOW - timedelta(days=1),
            effective_from=NOW - timedelta(days=30),
            review_due_at=NOW + timedelta(days=30),
            sensitivity=1,
            source_grade="T1",
            framework_priority="normal",
            empirical_support="guideline_consistent",
            source_count=2,
            media_type="text/plain",
            size_bytes=64,
        ),
        provenance=provenance,
        location=EvidenceLocator(
            locator_kind="source_line_span",
            anchor_refs=(passage_ref,),
            display_locator=f"lines:{index}-{index}",
            locator_policy_ref=reference("locator_policy", index + 400),
        ),
        freshness=EvidenceFreshnessSnapshot(
            status="not_time_sensitive",
            evaluated_at=NOW,
            source_observed_at=NOW - timedelta(days=2),
            last_reviewed_at=NOW - timedelta(days=1),
            review_due_at=None,
            policy_ref=reference("freshness_policy", index + 500),
        ),
        score=0.0,
    )


def wiki_fixture() -> WikiFixture:
    claim_a = reference("claim", 10)
    claim_b = reference("claim", 20)
    passages_a = (reference("passage", 11), reference("passage", 12))
    passages_b = (reference("passage", 21),)
    candidates = (
        *(
            _candidate(
                claim_a,
                passage,
                index=30 + ordinal,
                passage_ids=frozenset(item.object_id for item in passages_a),
            )
            for ordinal, passage in enumerate(passages_a)
        ),
        _candidate(
            claim_b,
            passages_b[0],
            index=40,
            passage_ids=frozenset(item.object_id for item in passages_b),
        ),
    )
    assignments = tuple(
        RetrievalInputAssignment.from_candidate(
            candidate,
            target_channels=frozenset({"wiki_index", "lexical", "vector"}),
        )
        for candidate in candidates
    )
    sections = (
        WikiSection(
            key="relationship_repair",
            heading="依恋关系修复",
            body=(
                "来访者在关系破裂后先辨认重复出现的依恋循环，再选择能够"
                "验证的新行动；这一段只负责导航，不能替代证据原文。"
            ),
            claim_refs=(claim_a,),
            passage_refs=passages_a,
            stance="support",
        ),
        WikiSection(
            key="career_transition",
            heading="生涯转换中的小步实验",
            body="生涯转换可从一项可执行的小步实验开始，也可能带来关系修复。",
            claim_refs=(claim_b,),
            passage_refs=passages_b,
            stance="context",
        ),
    )
    wiki_id = object_id("wiki", 60)
    draft = WikiRevisionDraft(
        wiki_id=wiki_id,
        slug="attachment-and-career-navigation",
        title="关系修复与生涯转换导航",
        base_revision=0,
        diff_kind="add",
        sections=sections,
        theory_revision_refs=(reference("theory", 61),),
        relationships=(
            WikiRelationship(
                target_id=object_id("concept", 62),
                relationship="DISTINCT_FROM",
                scope=("relationship",),
                source_refs=(reference("source", 63),),
                reviewed=True,
            ),
        ),
        graph_relations=(
            WikiGraphRelationDeclaration(
                source_ref=reference("concept", 64),
                target_ref=reference("practice", 65),
                claim_ref=claim_a,
                relation="APPLIES_TO",
                scope=("relationship",),
                review_status="approved",
            ),
        ),
        review_due_at=NOW + timedelta(days=90),
        unresolved_questions=("何时应把关系修复转为边界重建？",),
    )
    revision = WikiRevision(
        wiki_id=wiki_id,
        revision=1,
        slug=draft.slug,
        title=draft.title,
        base_revision=draft.base_revision,
        diff_kind=draft.diff_kind,
        sections=draft.sections,
        theory_revision_refs=draft.theory_revision_refs,
        relationships=draft.relationships,
        graph_relations=draft.graph_relations,
        review_due_at=draft.review_due_at,
        unresolved_questions=draft.unresolved_questions,
        body_sha256=wiki_revision_body_sha256(draft),
        diff_sha256=hashlib.sha256(
            canonical_json_bytes(draft.model_dump(mode="json"))
        ).hexdigest(),
        status="prepared",
        approval_request_id=object_id("approval_request", 66),
        created_at=NOW,
    )
    descriptor = RetrievalInputDescriptor.from_assignments(
        assignments,
        route_policy_ref=reference(
            "retrieval_route_policy", 67, version=7
        ),
    )
    snapshot = DerivedAuthoritySnapshotV2(
        catalog_version=6,
        authorization_epoch=0,
        tombstone_epoch=0,
        publication_authority_version=7,
        expected_current_epoch=1,
        maximum_runtime_epoch=1,
        target_runtime_epoch=2,
        theory=DerivedAuthorityObjectVersion(
            object_id=draft.theory_revision_refs[0].object_id,
            version=draft.theory_revision_refs[0].version,
            object_sha256=draft.theory_revision_refs[0].content_sha256,
        ),
        wiki=DerivedAuthorityObjectVersion(
            object_id=revision.wiki_id,
            version=revision.revision,
            object_sha256=revision.body_sha256,
        ),
        claims=tuple(
            DerivedAuthorityObjectVersion(
                object_id=claim.object_id,
                version=claim.version,
                object_sha256=claim.content_sha256,
            )
            for claim in (claim_a, claim_b)
        ),
    )
    builder_input = DerivedArtifactBuilderInputV2(
        artifact_kind="wiki_index",
        authority_closure_sha256=hashlib.sha256(
            canonical_json_bytes(snapshot.model_dump(mode="json"))
        ).hexdigest(),
        authority_snapshot=snapshot,
        retrieval_input_descriptor=descriptor,
        target_runtime_epoch=2,
    )
    return WikiFixture(
        assignments=assignments,
        builder_input=builder_input,
        candidates=candidates,
        revision=revision,
    )


def build_fixture(value: WikiFixture | None = None) -> WikiIndexBuildArtifacts:
    source = value if value is not None else wiki_fixture()
    return WikiNavigationIndexBuilder().build(
        source.assignments,
        source.revision,
        builder_input=source.builder_input,
    )


def _finalize(
    store: ContentStore,
    payload: bytes,
    *,
    role: str,
    manifest_id: str,
) -> Any:
    return store.finalize(
        store.stage_bytes(
            payload,
            purpose=role,
            manifest_id=manifest_id,
            media_type="application/json",
        )
    )


def bound_wiki_index(
    root: Path,
    *,
    value: WikiFixture | None = None,
    artifacts: WikiIndexBuildArtifacts | None = None,
    state: BindingState | None = None,
) -> BoundWikiIndex:
    source = value if value is not None else wiki_fixture()
    built = artifacts if artifacts is not None else build_fixture(source)
    root.mkdir()
    store = ContentStore(root)
    root_id = object_id("artifact_manifest", 700)
    payloads = {
        "wiki_index_builder_input": canonical_json_bytes(
            source.builder_input.model_dump(mode="json")
        ),
        "wiki_index_build_manifest": built.build_manifest_bytes,
        "wiki_index": built.index_bytes,
    }
    members: list[tuple[ArtifactMemberIdentity, Any]] = []
    for ordinal, (role, payload) in enumerate(payloads.items(), start=1):
        reference_value = _finalize(
            store,
            payload,
            role=role,
            manifest_id=root_id,
        )
        members.append(
            (
                ArtifactMemberIdentity(
                    role=role,
                    object_id=object_id(role, 700 + ordinal),
                    content_sha256=hashlib.sha256(payload).hexdigest(),
                    media_type="application/json",
                    size_bytes=len(payload),
                ),
                reference_value,
            )
        )
    identity = ArtifactBindingIdentity.create(
        artifact_key="wiki_index",
        root_ref=VersionRef(
            object_id=root_id,
            version=source.builder_input.source_catalog_version,
            content_sha256="f" * 64,
        ),
        active_runtime_epoch=source.builder_input.target_runtime_epoch,
        source_catalog_version=source.builder_input.source_catalog_version,
        target_runtime_epoch=source.builder_input.target_runtime_epoch,
        members=tuple(member for member, _reference in members),
    )
    live = state if state is not None else BindingState()
    binding = _new_artifact_binding(
        identity=identity,
        members=tuple(members),
        store=store,
        live_verifier=live.verify,
    )
    return BoundWikiIndex(
        binding=binding,
        retriever=WikiIndexRetriever(binding),
        state=live,
        store=store,
    )


__all__ = [
    "BindingState",
    "BoundWikiIndex",
    "WikiFixture",
    "bound_wiki_index",
    "build_fixture",
    "wiki_fixture",
]
