from __future__ import annotations

import hashlib
import itertools
from datetime import datetime, timezone

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.anchors import locator_policy_ref
from consultation_kb.knowledge.wiki import wiki_revision_body_sha256
from consultation_kb.graph.global_builder import (
    ClaimRelation,
    GlobalGraphArtifact,
    GovernedClaim,
    GovernedPassage,
    GovernedWiki,
    claim_relation_sha256,
    graph_dependencies_from_graph,
)
from consultation_kb.graph.authority_filter import (
    GraphAuthorityBinding,
    GraphEdgeAuthorityRecord,
    GraphEdgeAuthorityResolver,
    StaticGraphEdgeAuthorityCatalog,
    graph_edge_authority_sha256,
)
from consultation_kb.graph.serialization import graph_payload_from_parts, graph_sha256
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    EvidenceLocator,
    Provenance,
    RetrievalScope,
    SourceGrade,
)
from consultation_kb.models.knowledge import (
    ClaimApplicability,
    ClaimRecord,
    PassageRecord,
)
from consultation_kb.models.theory import TheoryRevision, TheoryScope
from consultation_kb.models.wiki import (
    WikiGraphRelationDeclaration,
    WikiRevision,
    WikiSection,
)


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
CLIENT_A = "client_" + "a" * 12
CLIENT_B = "client_" + "b" * 12
_COUNTER = itertools.count(10_000)


def ids() -> IdFactory:
    return IdFactory(FixedClock(NOW), lambda: next(_COUNTER))


def global_graph_artifact(
    graph,  # type: ignore[no-untyped-def]
    *,
    catalog_version: int = 5,
    runtime_epoch: int = 7,
    effective_at: datetime = NOW,
) -> GlobalGraphArtifact:
    policy_version = "consultation-global-graph.v1"
    graph.graph.update(
        source_catalog_version=catalog_version,
        source_runtime_epoch=runtime_epoch,
        effective_at=effective_at,
        builder_policy_version=policy_version,
    )
    digest = graph_sha256(
        graph_payload_from_parts(
            graph,
            source_catalog_version=catalog_version,
            source_runtime_epoch=runtime_epoch,
            effective_at=effective_at,
            builder_policy_version=policy_version,
        )
    )
    return GlobalGraphArtifact(
        graph=graph,
        source_catalog_version=catalog_version,
        source_runtime_epoch=runtime_epoch,
        effective_at=effective_at,
        builder_policy_version=policy_version,
        canonical_sha256=digest,
        dependencies=graph_dependencies_from_graph(graph),
    )


def graph_authority_snapshot(
    artifact: GlobalGraphArtifact,
    *,
    excluded_ref_ids: frozenset[str] = frozenset(),
    created_at: datetime | None = None,
) -> AuthoritativeFilterSnapshot:
    allowed: set[str] = set()
    for *_edge, attributes in artifact.graph.edges(data=True):
        for name in ("claim_ref", "theory_ref", "wiki_ref"):
            value = attributes.get(name)
            if isinstance(value, VersionRef):
                allowed.add(value.object_id)
        relation_ref = attributes.get("relation_ref")
        if isinstance(relation_ref, VersionRef):
            allowed.add(relation_ref.object_id)
            allowed.add(
                f"graph_edge_authority_{relation_ref.object_id[-36:]}"
            )
        passages = attributes.get("passage_refs", ())
        if isinstance(passages, tuple):
            allowed.update(
                value.object_id
                for value in passages
                if isinstance(value, VersionRef)
            )
    return AuthoritativeFilterSnapshot(
        run_id=ids().uuid7(),
        global_runtime_epoch=artifact.source_runtime_epoch,
        client_runtime_epoch=1,
        tombstone_epoch=1,
        authorization_epoch=1,
        allowed_ref_ids=frozenset(allowed) - excluded_ref_ids,
        policy_ref=ref("filter_policy", "f"),
        created_at=created_at or artifact.effective_at,
    )


def graph_query_authority(
    artifact: GlobalGraphArtifact,
    authority_snapshot: AuthoritativeFilterSnapshot,
    *,
    client_id: str = CLIENT_A,
    required_use: str = "consultation",
    graph_version: VersionRef | None = None,
    graph_root_ref: VersionRef | None = None,
) -> tuple[GraphEdgeAuthorityResolver, RetrievalScope, GraphAuthorityBinding]:
    records: list[GraphEdgeAuthorityRecord] = []
    for *_edge, attributes in artifact.graph.edges(data=True):
        relation_ref = attributes.get("relation_ref")
        if not isinstance(relation_ref, VersionRef):
            raise AssertionError("test graph edge lacks relation authority")
        if attributes.get("provenance_scope") != "global_source":
            raise AssertionError("use explicit case authority records in this test")
        independent_source_count = attributes.get("independent_source_count")
        if type(independent_source_count) is not int or independent_source_count < 1:
            raise AssertionError("test graph edge lacks source authority")
        authority_ref = VersionRef(
            object_id=f"graph_edge_authority_{relation_ref.object_id[-36:]}",
            version=relation_ref.version,
            content_sha256="0" * 64,
        )
        digest = graph_edge_authority_sha256(
            relation_ref=relation_ref,
            runtime_epoch=artifact.source_runtime_epoch,
            provenance_scope="global_source",
            independent_source_count=independent_source_count,
            minimum_leave_one_out_sources=1,
            contributor_client_ids=frozenset(),
            leave_one_out_grants=(),
            leave_one_out_parent_ref=None,
            excluded_client_ids=frozenset(),
        )
        records.append(
            GraphEdgeAuthorityRecord(
                authority_ref=authority_ref.model_copy(
                    update={"content_sha256": digest}
                ),
                relation_ref=relation_ref,
                runtime_epoch=artifact.source_runtime_epoch,
                provenance_scope="global_source",
                independent_source_count=independent_source_count,
            )
        )
    resolver = GraphEdgeAuthorityResolver(
        StaticGraphEdgeAuthorityCatalog(
            tuple(records), runtime_epoch=artifact.source_runtime_epoch
        )
    )
    scope = RetrievalScope.model_validate(
        {
            "current_client_id": client_id,
            "allowed_uses": frozenset({required_use}),
            "maximum_sensitivity": 0,
            "effective_at": authority_snapshot.created_at,
            "known_at": authority_snapshot.created_at,
        }
    )
    binding = resolver.resolve(
        artifact,
        scope=scope,
        authority_snapshot=authority_snapshot,
        required_use=required_use,
        graph_version=(
            graph_version
            if graph_version is not None
            else ref("global_graph", "c").model_copy(
                update={
                    "version": artifact.source_catalog_version,
                    "content_sha256": artifact.canonical_sha256,
                }
            )
        ),
        graph_root_ref=(
            graph_root_ref
            if graph_root_ref is not None
            else ref("artifact_manifest", "d").model_copy(
                update={"version": artifact.source_catalog_version}
            )
        ),
    )
    return resolver, scope, binding


def graph_relation(
    *,
    source_ref: VersionRef,
    target_ref: VersionRef,
    claim_ref: VersionRef,
    relation: str,
    digit: str,
    scope: tuple[str, ...] = ("consultation",),
    wiki_ref: VersionRef | None = None,
    review_status: str = "approved",
    effective_from: datetime | None = NOW,
    effective_to: datetime | None = None,
    confidence_override: float | None = None,
    claim_record: ClaimRecord | None = None,
) -> ClaimRelation:
    exact_wiki_ref = wiki_ref or ref("wiki", digit)
    if claim_record is not None:
        declaration = WikiGraphRelationDeclaration.model_validate(
            {
                "source_ref": source_ref,
                "target_ref": target_ref,
                "claim_ref": claim_ref,
                "relation": relation,
                "scope": scope,
                "review_status": review_status,
                "effective_from": effective_from,
                "effective_to": effective_to,
                "confidence_override": confidence_override,
            }
        )
        _record, exact_wiki_ref = _canonical_test_wiki(
            exact_wiki_ref,
            declarations=(declaration,),
            claims_by_ref={claim_ref: claim_record},
        )
    provisional = ref("graph_edge", digit)
    digest = claim_relation_sha256(
        wiki_ref=exact_wiki_ref,
        source_ref=source_ref,
        target_ref=target_ref,
        claim_ref=claim_ref,
        relation=relation,  # type: ignore[arg-type]
        scope=scope,
        review_status=review_status,  # type: ignore[arg-type]
        effective_from=effective_from,
        effective_to=effective_to,
        confidence_override=confidence_override,
    )
    return ClaimRelation.model_validate(
        {
            "relation_ref": provisional.model_copy(
                update={"content_sha256": digest}
            ),
            "wiki_ref": exact_wiki_ref,
            "source_ref": source_ref,
            "target_ref": target_ref,
            "claim_ref": claim_ref,
            "relation": relation,
            "scope": scope,
            "review_status": review_status,
            "effective_from": effective_from,
            "effective_to": effective_to,
            "confidence_override": confidence_override,
        }
    )


def _canonical_test_wiki(
    identity: VersionRef,
    *,
    declarations: tuple[WikiGraphRelationDeclaration, ...],
    claims_by_ref: dict[VersionRef, ClaimRecord],
) -> tuple[WikiRevision, VersionRef]:
    unique_claims = sorted(
        {value.claim_ref for value in declarations},
        key=lambda value: (
            value.object_id,
            value.version,
            value.content_sha256,
        ),
    )
    sections = tuple(
        WikiSection(
            key=f"section_{index}",
            heading=f"Section {index}",
            body="governed relation",
            claim_refs=(claim_ref,),
            passage_refs=claims_by_ref[claim_ref].passage_refs,
            stance="context",
        )
        for index, claim_ref in enumerate(unique_claims, start=1)
    )
    record = WikiRevision(
        wiki_id=identity.object_id,
        revision=identity.version,
        slug=f"wiki-{identity.object_id[-8:]}",
        title="Governed graph relations",
        base_revision=0 if identity.version == 1 else identity.version - 1,
        diff_kind="add" if identity.version == 1 else "correct",
        sections=sections,
        theory_revision_refs=tuple(
            sorted(
                {
                    claims_by_ref[claim_ref].theory_revision_ref
                    for claim_ref in unique_claims
                    if claims_by_ref[claim_ref].theory_revision_ref is not None
                },
                key=lambda value: (
                    value.object_id,
                    value.version,
                    value.content_sha256,
                ),
            )
        ),
        relationships=(),
        graph_relations=declarations,
        review_due_at=None,
        unresolved_questions=(),
        body_sha256="0" * 64,
        diff_sha256="d" * 64,
        status="active",
        approval_request_id=ids().object_id("approval_request"),
        created_at=NOW,
    )
    digest = wiki_revision_body_sha256(record)
    return (
        record.model_copy(update={"body_sha256": digest}),
        identity.model_copy(update={"content_sha256": digest}),
    )


def governed_wikis_for_relations(
    relations: tuple[ClaimRelation, ...],
    claims: tuple[GovernedClaim, ...],
    passages: tuple[GovernedPassage, ...] = (),
) -> tuple[GovernedWiki, ...]:
    claims_by_ref = {claim.reference: claim.record for claim in claims}
    del passages
    grouped: dict[VersionRef, list[ClaimRelation]] = {}
    for relation in relations:
        grouped.setdefault(relation.wiki_ref, []).append(relation)
    governed: list[GovernedWiki] = []
    for wiki_ref, values in sorted(
        grouped.items(),
        key=lambda item: (
            item[0].object_id,
            item[0].version,
            item[0].content_sha256,
        ),
    ):
        declarations = tuple(
            WikiGraphRelationDeclaration(
                source_ref=relation.source_ref,
                target_ref=relation.target_ref,
                claim_ref=relation.claim_ref,
                relation=relation.relation,
                scope=relation.scope,
                review_status="approved",
                effective_from=relation.effective_from,
                effective_to=relation.effective_to,
                confidence_override=relation.confidence_override,
            )
            for relation in values
            if relation.claim_ref in claims_by_ref
        )
        record, _canonical_ref = _canonical_test_wiki(
            wiki_ref,
            declarations=declarations,
            claims_by_ref=claims_by_ref,
        )
        governed.append(GovernedWiki(reference=wiki_ref, record=record))
    return tuple(governed)
def ref(kind: str, digit: str = "a") -> VersionRef:
    return VersionRef(
        object_id=ids().object_id(kind),
        version=1,
        content_sha256=digit * 64,
    )


def approved_passage(
    *,
    digit: str,
    review_status: str = "approved",
) -> tuple[VersionRef, PassageRecord]:
    source_ref = ref("source", digit)
    passage_ref = ref("passage", digit)
    policy_ref = ref("derivation_policy", "d")
    record = PassageRecord.model_validate(
        {
            "passage_id": passage_ref.object_id,
            "version": passage_ref.version,
            "source_ref": source_ref,
            "document_type": "md",
            "structural_path": f"section-{digit}",
            "locator": EvidenceLocator(
                locator_kind="source_line_span",
                anchor_refs=(passage_ref,),
                display_locator="lines:1-1",
                locator_policy_ref=locator_policy_ref(),
            ),
            "normalized_text_sha256": passage_ref.content_sha256,
            "raw_content_ref": f"sha256:{source_ref.content_sha256}",
            "retrieval_content_ref": f"sha256:{passage_ref.content_sha256}",
            "extractor_version": "test-extractor.v1",
            "privacy_scope": "global",
            "provenance": Provenance(
                source_ids=frozenset({source_ref.object_id}),
                passage_ids=frozenset({passage_ref.object_id}),
                provenance_scope="global_source",
                derivation_rule_ref=policy_ref,
            ),
            "review_status": review_status,
            "created_at": NOW,
        }
    )
    return passage_ref, record


def governed_claim(
    *,
    passage_ref: VersionRef,
    passage: PassageRecord,
    text: str,
    grade: SourceGrade = "C2",
    review_status: str = "approved",
    effective_to: datetime | None = None,
    theory_ref: VersionRef | None = None,
    relation_kind: str = "explicit",
) -> tuple[VersionRef, ClaimRecord]:
    text_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    claim_ref = VersionRef(
        object_id=ids().object_id("claim"),
        version=1,
        content_sha256=text_sha256,
    )
    return claim_ref, ClaimRecord.model_validate(
        {
            "claim_id": claim_ref.object_id,
            "version": 1,
            "text": text,
            "text_sha256": text_sha256,
            "cognitive_type": relation_kind,
            "source_grade": grade,
            "framework_eligibility": "eligible",
            "empirical_support": "guideline_consistent",
            "model_confidence": 0.8,
            "review_status": review_status,
            "effective_from": NOW,
            "effective_to": effective_to,
            "review_due_at": None,
            "applicability": ClaimApplicability(
                domains=frozenset({"emotional_consultation"}),
                populations=frozenset(),
                contexts=frozenset(),
                required_conditions=frozenset(),
                exclusions=frozenset(),
                contraindications=frozenset(),
            ),
            "privacy_scope": "global",
            "allowed_uses": frozenset({"consultation"}),
            "passage_refs": (passage_ref,),
            "provenance": Provenance(
                source_ids=passage.provenance.source_ids,
                passage_ids=frozenset({passage_ref.object_id}),
                provenance_scope="global_source",
                derivation_rule_ref=passage.provenance.derivation_rule_ref,
            ),
            "theory_revision_ref": theory_ref,
            "created_at": NOW,
        }
    )


def theory(
    *,
    theory_ref: VersionRef,
    claim_ref: VersionRef,
    passage_ref: VersionRef,
    status: str,
) -> TheoryRevision:
    source_ref = ref("source", "e")
    return TheoryRevision.model_validate(
        {
            "theory_id": theory_ref.object_id,
            "revision": theory_ref.version,
            "source_ref": source_ref,
            "document_sha256": source_ref.content_sha256,
            "author": "primary counselor",
            "declared_version": "1.0",
            "empirical_support": "case_supported",
            "status": status,
            "approval_request_id": ids().object_id("approval_request"),
            "approved_at": NOW,
            "effective_from": NOW,
            "effective_to": None,
            "scope": TheoryScope(
                domains=frozenset({"emotional_consultation"}),
                populations=frozenset({"adult"}),
                contexts=frozenset(),
                required_conditions=frozenset(),
                exclusions=frozenset(),
                contraindications=frozenset(),
            ),
            "core_claims": ("core",),
            "methods": ("method",),
            "contraindications": ("contraindication",),
            "counterexamples": ("counterexample",),
            "passage_refs": (passage_ref,),
            "claim_refs": (claim_ref,),
            "citation_refs": (passage_ref,),
            "scope_policy_ref": ref("scope_policy", "f"),
            "created_at": NOW,
        }
    )


__all__ = [
    "NOW",
    "approved_passage",
    "governed_claim",
    "ids",
    "ref",
    "theory",
]
