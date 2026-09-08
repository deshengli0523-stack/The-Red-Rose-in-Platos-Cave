from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import itertools

import pytest

from consultation_kb.archive.case_indexing import (
    CaseContributorBinding,
    CaseIndexGovernance,
    CaseIndexRootAuthority,
    CaseIndexTextSet,
    CaseIndexingService,
)
from consultation_kb.archive.provenance import (
    CaseContributorHasher,
    CaseProvenanceService,
)
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.graph.global_builder import (
    GlobalGraphBuildError,
    GlobalGraphBuilder,
    GovernedClaim,
    GovernedPassage,
    GraphAuthoritySnapshot,
    StaticGraphAuthority,
)
from consultation_kb.models.cases import (
    CaseContribution,
    CaseReleaseDecision,
    CaseReuseAuthorization,
    DeidentificationHumanReview,
    case_reuse_authorization_payload,
    deidentification_human_review_payload,
)
from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    RetrievalScope,
    Provenance,
)
from consultation_kb.retrieval.filters import CandidateFilter, StaticAuthorityGuard
from consultation_kb.retrieval.lexical_builder import LexicalDocument
from consultation_kb.retrieval.vector_builder import VectorDocument
from tests.consultation_kb.graph_support import (
    approved_passage,
    governed_claim,
    governed_wikis_for_relations,
    graph_relation,
    ref,
)
from tests.consultation_kb.case_index_support import (
    StaticCaseIndexAuthority,
    StaticCaseSourceAuthority,
)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.acceptance_id("CASE-01"),
]

NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
CLIENT_A = "client_" + "a" * 12
CLIENT_B = "client_" + "b" * 12
HASH_KEY = b"task-six-case-contributor-key-material"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ids(counter_start: int = 70000) -> IdFactory:
    values = itertools.count(counter_start)
    return IdFactory(FixedClock(NOW), lambda: next(values))


def _ref(ids: IdFactory, kind: str, seed: str) -> VersionRef:
    return VersionRef(
        object_id=ids.object_id(kind),
        version=1,
        content_sha256=_digest(seed),
    )


def _release_authority(
    ids: IdFactory,
    authorization: CaseReuseAuthorization,
    policy_ref: VersionRef,
) -> tuple[DeidentificationHumanReview, CaseReleaseDecision]:
    candidate_sha256 = _digest("deidentified-candidate")
    review_id = ids.object_id("case_deidentification_review")
    checked_categories = frozenset(
        {
            "direct_identifiers",
            "third_party_people",
            "rare_attributes",
            "location_occupation_family_time",
            "section_boundaries",
            "no_verbatim_quotes",
        }
    )
    attestation = _digest("reviewer-attestation")
    review_ref = VersionRef(
        object_id=review_id,
        version=1,
        content_sha256=canonical_sha256(
            deidentification_human_review_payload(
                review_id=review_id,
                version=1,
                candidate_sha256=candidate_sha256,
                decision="approved",
                checked_categories=checked_categories,
                residual_risk="low",
                rare_combination_disposition="not_present",
                allowed_uses=frozenset({"answer_support"}),
                reviewed_at=NOW,
                reviewer_attestation_sha256=attestation,
            )
        ),
    )
    review = DeidentificationHumanReview(
        review_ref=review_ref,
        candidate_sha256=candidate_sha256,
        decision="approved",
        checked_categories=checked_categories,
        residual_risk="low",
        rare_combination_disposition="not_present",
        allowed_uses=frozenset({"answer_support"}),
        reviewed_at=NOW,
        reviewer_attestation_sha256=attestation,
    )
    return review, CaseReleaseDecision(
        candidate_sha256=candidate_sha256,
        outcome="eligible",
        reasons=(),
        authorization_ref=authorization.authorization_ref,
        review_ref=review.review_ref,
        policy_ref=policy_ref,
        allowed_uses=frozenset({"answer_support"}),
        evaluated_at=NOW,
    )


def _fixture(*, counter_start: int = 70000):
    ids = _ids(counter_start)
    hasher = CaseContributorHasher(hash_key=HASH_KEY)
    rule = _ref(ids, "case_derivation_rule", "case-index-rule")
    source_authority = StaticCaseSourceAuthority()
    provenance = CaseProvenanceService(
        id_factory=ids,
        policy_manifest_ref=_ref(ids, "case_provenance_policy", "policy"),
        approved_derivation_rules=(rule,),
        authority_resolver=source_authority,
        clock=FixedClock(NOW),
    )
    case_ref = _ref(ids, "case", "deidentified-global-case-body")
    contributor_hash = hasher.hash_client_id(CLIENT_A)
    authorization_id = ids.object_id("case_authorization")
    terms_sha256 = _digest("terms")
    authorization_ref = VersionRef(
        object_id=authorization_id,
        version=1,
        content_sha256=canonical_sha256(
            case_reuse_authorization_payload(
                authorization_id=authorization_id,
                version=1,
                contributor_client_hash=contributor_hash,
                reuse_authorized=True,
                allowed_uses=frozenset({"answer_support"}),
                valid_from=NOW,
                expires_at=None,
                revoked_at=None,
                terms_sha256=terms_sha256,
            )
        ),
    )
    contribution = CaseContribution(
        case_ref=case_ref,
        source_provenance_ref=_ref(ids, "case_source_provenance", "source"),
        contributor_client_hashes=frozenset({contributor_hash}),
        authorization_ref=authorization_ref,
        allowed_uses=frozenset({"answer_support"}),
        source_grade="K1",
        source_lineage_sha256=_digest("source-lineage"),
    )
    source_authority.authorize_case(contribution)
    root = provenance.root_case(
        case_ref,
        contribution,
        derivation_rule_ref=rule,
    )
    authorization = CaseReuseAuthorization(
        authorization_ref=authorization_ref,
        contributor_client_hash=contributor_hash,
        reuse_authorized=True,
        allowed_uses=frozenset({"answer_support"}),
        valid_from=NOW,
        terms_sha256=terms_sha256,
    )
    release_policy_ref = _ref(ids, "case_release_policy", "release-policy")
    review, release_decision = _release_authority(
        ids, authorization, release_policy_ref
    )
    source_candidate_ref = VersionRef(
        object_id=ids.object_id("shared_case_candidate"),
        version=1,
        content_sha256=review.candidate_sha256,
    )
    authority_manifest_ref = _ref(
        ids, "case_authority_manifest", "manifest"
    )
    index_authority = StaticCaseIndexAuthority()
    index_authority.authorize(
        CaseIndexRootAuthority(
            case_ref=root.artifact_ref,
            source_candidate_ref=source_candidate_ref,
            authorization=authorization,
            review=review,
            release_decision=release_decision,
            authority_manifest_ref=authority_manifest_ref,
            source_catalog_version=7,
        )
    )
    service = CaseIndexingService(
        id_factory=ids,
        provenance_service=provenance,
        contributor_hasher=hasher,
        authority_resolver=index_authority,
        clock=FixedClock(NOW),
    )
    bundle = service.build(
        root,
        authorization=authorization,
        review=review,
        release_decision=release_decision,
        contributor=CaseContributorBinding(
            client_id=CLIENT_A,
            contributor_client_hash=contributor_hash,
        ),
        texts=CaseIndexTextSet(
            case_record="一位来访者在关系冲突后先稳定情绪，再澄清双方需求",
            reviewed_pattern="在相似条件下，先降低唤醒水平有助于后续沟通",
            conditional_claim="当情绪唤醒较高时，可先尝试短时暂停并确认需求",
            wiki_section="可把稳定情绪与澄清需求作为有条件的咨询参考顺序",
            graph_relation="情绪稳定可能为需求澄清提供前置条件",
        ),
        governance=CaseIndexGovernance(
            source_candidate_ref=source_candidate_ref,
            authority_manifest_ref=authority_manifest_ref,
            release_policy_ref=release_policy_ref,
            locator_policy_ref=_ref(ids, "locator_policy", "locator"),
            freshness_policy_ref=_ref(ids, "freshness_policy", "freshness"),
            source_catalog_version=7,
            indexed_at=NOW,
        ),
        derivation_rule_ref=rule,
    )
    return bundle, contributor_hash


def _snapshot(bundle) -> AuthoritativeFilterSnapshot:
    return AuthoritativeFilterSnapshot(
        run_id="019f743d-4400-7000-8000-000000000001",
        global_runtime_epoch=8,
        client_runtime_epoch=2,
        tombstone_epoch=0,
        authorization_epoch=1,
        allowed_ref_ids=frozenset(
            candidate.reference.object_id for candidate in bundle.candidates
        ),
        policy_ref=bundle.artifacts[0].candidate.metadata.manifest_ref,
        created_at=NOW,
    )


def _scope(client_id: str) -> RetrievalScope:
    return RetrievalScope(
        current_client_id=client_id,
        allowed_uses=frozenset({"answer_support"}),
        maximum_sensitivity=1,
        effective_at=NOW,
        known_at=NOW,
    )


def _run_every_stage(bundle, client_id: str):
    snapshot = _snapshot(bundle)
    candidate_filter = CandidateFilter(
        StaticAuthorityGuard(snapshot),
        contributor_identity_hasher=CaseContributorHasher(hash_key=HASH_KEY),
    )
    channels: dict[str, tuple] = {}
    for candidate in bundle.candidates:
        channels[candidate.channel] = candidate_filter.filter(
            _scope(client_id), (candidate,), snapshot
        ).allowed
    # Fusion, reranking and final packing deliberately receive only the
    # body-free candidates that survived the deterministic gate.
    fusion = tuple(item for values in channels.values() for item in values)
    reranker_input = tuple((item, bundle.body_for(item)) for item in fusion)
    reranked = tuple(
        item for item, _body in sorted(reranker_input, key=lambda pair: pair[0].channel)
    )
    final_pack = tuple(bundle.body_for(item) for item in reranked)
    return channels, fusion, reranker_input, final_pack


def test_current_client_is_removed_from_every_derived_channel_and_stage() -> None:
    bundle, contributor_hash = _fixture()

    expected_kinds = (
        "case",
        "case_pattern",
        "claim",
        "wiki_section",
        "graph_edge",
        "lexical_row",
        "vector_row",
    )
    assert tuple(item.artifact_kind for item in bundle.artifacts) == expected_kinds
    for artifact in bundle.artifacts:
        assert artifact.provenance.contributor_client_hashes == frozenset(
            {contributor_hash}
        )
        assert artifact.authorization_refs == (
            bundle.artifacts[0].authorization_refs[0],
        )
        assert artifact.review_ref == bundle.artifacts[0].review_ref
        assert artifact.release_decision_sha256 == (
            bundle.artifacts[0].release_decision_sha256
        )
        assert artifact.source_catalog_version == 7
        if artifact.candidate is not None:
            serialized = artifact.candidate.model_dump_json()
            assert CLIENT_A not in serialized
            assert artifact.candidate.metadata.contributor_identity_scheme == (
                "hmac_alias_v1"
            )

    channels, fusion, reranker_input, final_pack = _run_every_stage(bundle, CLIENT_A)
    assert set(channels) == {"case", "wiki", "global_graph", "lexical", "vector"}
    assert all(not values for values in channels.values())
    assert fusion == ()
    assert reranker_input == ()
    assert final_pack == ()


def test_other_client_can_use_authorized_case_without_identity_or_universal_claim() -> (
    None
):
    bundle, contributor_hash = _fixture()

    channels, fusion, reranker_input, final_pack = _run_every_stage(bundle, CLIENT_B)

    assert all(len(values) == 1 for values in channels.values())
    assert len(fusion) == len(reranker_input) == len(final_pack) == 5
    for body in final_pack:
        decoded = body.decode("utf-8")
        assert CLIENT_A not in decoded
        assert contributor_hash not in decoded
        assert "不代表普遍规律" in decoded


def test_hmac_case_candidate_fails_closed_without_identity_hasher() -> None:
    bundle, _ = _fixture()
    snapshot = _snapshot(bundle)
    candidate = bundle.candidates[0]

    decision = CandidateFilter(StaticAuthorityGuard(snapshot)).filter(
        _scope(CLIENT_B),
        (candidate,),
        snapshot,
    )

    assert decision.allowed == ()
    assert decision.proof.reasons == {"leave_one_out_ineligible": 1}


def test_lexical_and_vector_entry_points_reject_stable_client_id_in_text() -> None:
    bundle, _ = _fixture()
    lexical = next(item for item in bundle.candidates if item.channel == "lexical")
    vector = next(item for item in bundle.candidates if item.channel == "vector")

    with pytest.raises(ValueError, match="CASE_INDEX_TEXT_CONTAINS_CLIENT_ID"):
        LexicalDocument(candidate=lexical, text=f"安全摘要 {CLIENT_A}")
    with pytest.raises(ValueError, match="CASE_INDEX_TEXT_CONTAINS_CLIENT_ID"):
        VectorDocument(candidate=vector, text=f"安全摘要 {CLIENT_A}")


def test_global_graph_entry_point_rejects_client_id_before_edge_publication() -> None:
    passage_ref, global_passage = approved_passage(digit="7")
    case_ref = ref("case", "8")
    derivation_rule = global_passage.provenance.derivation_rule_ref
    case_provenance = Provenance(
        passage_ids=frozenset({passage_ref.object_id}),
        case_ids=frozenset({case_ref.object_id}),
        client_ids=frozenset({CLIENT_A}),
        provenance_scope="case_derived",
        case_contributor_client_ids=frozenset({CLIENT_A}),
        derivation_rule_ref=derivation_rule,
    )
    case_passage = global_passage.model_copy(
        update={"privacy_scope": "case", "provenance": case_provenance}
    )
    claim_ref, global_claim = governed_claim(
        passage_ref=passage_ref,
        passage=global_passage,
        text=f"unsafe {CLIENT_A}",
        grade="K1",
    )
    claim = global_claim.model_copy(
        update={"privacy_scope": "case", "provenance": case_provenance}
    )
    relation = graph_relation(
        source_ref=ref("concept", "9"),
        target_ref=ref("concept", "a"),
        claim_ref=claim_ref,
        relation="SUPPORTS",
        digit="b",
        claim_record=claim,
    )
    governed_claim_value = GovernedClaim(reference=claim_ref, record=claim)
    snapshot = GraphAuthoritySnapshot(
        catalog_version=1,
        runtime_epoch=1,
        effective_at=NOW,
        claims=(governed_claim_value,),
        passages=(GovernedPassage(reference=passage_ref, record=case_passage),),
        theories=(),
        wikis=governed_wikis_for_relations((relation,), (governed_claim_value,)),
        relations=(relation,),
    )

    with pytest.raises(
        GlobalGraphBuildError, match="GRAPH_CASE_TEXT_CONTAINS_CLIENT_ID"
    ):
        GlobalGraphBuilder(StaticGraphAuthority(snapshot)).build(
            1, target_runtime_epoch=1
        )
