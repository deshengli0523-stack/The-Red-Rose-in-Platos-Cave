from __future__ import annotations

import pytest

from consultation_kb.retrieval.contracts import (
    CandidateMetadata,
    CandidateRef,
    FilterCapabilityBinding,
)
from consultation_kb.retrieval.fusion import (
    FusionEvidence,
    ReciprocalRankFusion,
)
from consultation_kb.core.ids import IdFactory
from consultation_kb.core.clock import FixedClock
from consultation_kb.models.evidence import (
    C1ApplicabilityDecision,
    EvidenceCandidate,
    EvidenceFreshnessSnapshot,
    EvidenceLocator,
    EvidenceProvenanceView,
    Provenance,
)
from tests.consultation_kb.graph_support import NOW, ref


_BINDING_POLICY_REF = ref("filter_policy", "4")
_RUN_ID = IdFactory(FixedClock(NOW), lambda: 91).uuid7()


def candidate(
    *,
    channel: str,
    grade: str = "C2",
    claim_ref=None,  # type: ignore[no-untyped-def]
    passage_ref=None,  # type: ignore[no-untyped-def]
    source_ref=None,  # type: ignore[no-untyped-def]
) -> CandidateRef:
    claim_ref = claim_ref or ref("claim", "1")
    passage_ref = passage_ref or ref("passage", "2")
    source_ref = source_ref or ref("source", "3")
    policy_ref = _BINDING_POLICY_REF
    return CandidateRef.model_validate(
        {
            "reference": claim_ref,
            "content_ref": passage_ref,
            "object_type": "claim",
            "channel": channel,
            "metadata": CandidateMetadata(
                manifest_ref=ref("manifest", "5"),
                review_status="approved",
                allowed_uses=frozenset({"consultation"}),
                approved_at=NOW,
                sensitivity=0,
                source_grade=grade,
                source_count=1,
                media_type="text/plain",
                size_bytes=32,
            ),
            "provenance": Provenance(
                source_ids=frozenset({source_ref.object_id}),
                passage_ids=frozenset({passage_ref.object_id}),
                provenance_scope="global_source",
                derivation_rule_ref=ref("derivation_policy", "6"),
            ),
            "location": EvidenceLocator(
                locator_kind="source_line_span",
                anchor_refs=(passage_ref,),
                display_locator="lines:1-1",
                locator_policy_ref=ref("locator_policy", "8"),
            ),
            "freshness": EvidenceFreshnessSnapshot(
                status="current",
                evaluated_at=NOW,
                source_observed_at=NOW,
                last_reviewed_at=NOW,
                review_due_at=None,
                policy_ref=ref("freshness_policy", "9"),
            ),
            "score": 1.0,
            "filter_binding": FilterCapabilityBinding(
                run_id=_RUN_ID,
                global_runtime_epoch=1,
                client_runtime_epoch=1,
                tombstone_epoch=1,
                authorization_epoch=1,
                policy_ref=policy_ref,
                decision_sha256="7" * 64,
            ),
        }
    )


def test_rrf_uses_exact_one_based_formula_and_stable_evidence_id_tie_breaker() -> None:
    claim_a = ref("claim", "a")
    claim_b = ref("claim", "b")
    a_lexical = FusionEvidence(
        candidate=candidate(channel="lexical", claim_ref=claim_a), stance="support"
    )
    b_lexical = FusionEvidence(
        candidate=candidate(channel="lexical", claim_ref=claim_b), stance="support"
    )
    b_vector = FusionEvidence(
        candidate=candidate(channel="vector", claim_ref=claim_b), stance="support"
    )
    a_vector = FusionEvidence(
        candidate=candidate(channel="vector", claim_ref=claim_a), stance="support"
    )

    fused = ReciprocalRankFusion(k=60).fuse(
        {"lexical": (a_lexical, b_lexical), "vector": (b_vector, a_vector)}
    )

    assert len(fused) == 2
    assert [item.evidence_id for item in fused] == sorted(
        item.evidence_id for item in fused
    )
    assert all(item.rrf_score == pytest.approx(1 / 61 + 1 / 62) for item in fused)
    assert all(item.channel_ranks == {"lexical": 1 if item.claim_ref == claim_a else 2,
                                      "vector": 2 if item.claim_ref == claim_a else 1}
               for item in fused)


def test_same_claim_passages_aggregate_without_losing_independent_sources_or_stance() -> None:
    claim_ref = ref("claim", "c")
    first = FusionEvidence(
        candidate=candidate(
            channel="lexical",
            claim_ref=claim_ref,
            passage_ref=ref("passage", "d"),
            source_ref=ref("source", "e"),
        ),
        stance="support",
    )
    second = FusionEvidence(
        candidate=candidate(
            channel="lexical",
            claim_ref=claim_ref,
            passage_ref=ref("passage", "f"),
            source_ref=ref("source", "1"),
        ),
        stance="support",
    )
    opposition = FusionEvidence(
        candidate=candidate(
            channel="vector",
            claim_ref=claim_ref,
            passage_ref=ref("passage", "2"),
            source_ref=ref("source", "3"),
        ),
        stance="contradiction",
    )

    fused = ReciprocalRankFusion().fuse(
        {"lexical": (first, second), "vector": (opposition,)}
    )

    support = next(item for item in fused if item.stance == "support")
    contradiction = next(item for item in fused if item.stance == "contradiction")
    assert len(support.passage_refs) == 2
    assert len(support.passages) == 2
    assert {item.candidate.content_ref for item in support.passages} == set(
        support.passage_refs
    )
    assert len({item.evidence_id for item in support.passages}) == 2
    assert len(support.source_keys) == 2
    assert support.channel_ranks == {"lexical": 1}
    assert contradiction.claim_ref == support.claim_ref
    assert contradiction.evidence_id != support.evidence_id


def test_fused_and_per_passage_ids_construct_p0_evidence_candidates() -> None:
    claim_ref = ref("claim", "c")
    first = FusionEvidence(
        candidate=candidate(
            channel="lexical",
            claim_ref=claim_ref,
            passage_ref=ref("passage", "d"),
            source_ref=ref("source", "e"),
        ),
        stance="support",
    )
    second = FusionEvidence(
        candidate=candidate(
            channel="lexical",
            claim_ref=claim_ref,
            passage_ref=ref("passage", "f"),
            source_ref=ref("source", "1"),
        ),
        stance="support",
    )

    fused = ReciprocalRankFusion().fuse({"lexical": (first, second)})[0]

    for passage in fused.passages:
        source = passage.candidate
        packed = EvidenceCandidate(
            evidence_id=passage.evidence_id,
            text_ref=source.content_ref,
            location=source.location,
            freshness=source.freshness,
            channel=source.channel,
            review_status="approved",
            source_grade=fused.source_grade,
            framework_priority="normal",
            empirical_support=fused.empirical_support,
            provenance=EvidenceProvenanceView(
                provenance_ref=source.provenance.derivation_rule_ref,
                provenance_scope="global_source",
                derivation_rule_ref=source.provenance.derivation_rule_ref,
                source_count=len(source.provenance.source_ids),
                passage_count=len(source.provenance.passage_ids),
                case_count=0,
                case_contributor_count=0,
                independent_source_count=len(passage.source_keys),
                client_exclusion_status="not_applicable",
            ),
            supports_evidence_ids=(),
            contradicts_evidence_ids=(),
            score=fused.rrf_score,
        )
        assert packed.evidence_id == passage.evidence_id
        if passage == fused.passages[0]:
            group_payload = packed.model_dump(mode="python")
            group_payload["evidence_id"] = fused.evidence_id
            group_candidate = EvidenceCandidate.model_validate(group_payload)
            assert group_candidate.evidence_id == fused.evidence_id


def test_applicable_c1_is_primary_framework_but_contradiction_floor_survives_limit() -> None:
    theory_ref = ref("theory", "4")
    decision = C1ApplicabilityDecision(
        status="applicable",
        revision=theory_ref,
        scope_policy_ref=ref("scope_policy", "5"),
        matched_rule_ids=("relationship_consultation",),
        missing_context_fields=(),
        effective_status="active",
        empirical_support="case_supported",
        conflict_evidence_ids=(),
    )
    c1 = FusionEvidence(
        candidate=candidate(channel="wiki", grade="C1"),
        stance="support",
        theory_ref=theory_ref,
    )
    contradiction = FusionEvidence(
        candidate=candidate(channel="lexical", grade="C2"),
        stance="contradiction",
    )
    alternative = FusionEvidence(
        candidate=candidate(channel="vector", grade="C3"),
        stance="alternative",
    )

    fused = ReciprocalRankFusion().fuse(
        {
            "wiki": (c1,),
            "lexical": (contradiction,),
            "vector": (alternative,),
        },
        c1_applicability=decision,
        limit=3,
        minimum_contradictions=1,
        minimum_alternatives=1,
    )

    assert fused[0].primary_framework is True
    assert fused[0].framework_boost == 1.0
    assert fused[0].source_grade == "C1"
    assert {item.stance for item in fused} == {
        "support",
        "contradiction",
        "alternative",
    }


def test_fusion_rejects_unbound_or_mixed_authority_candidates() -> None:
    bound = candidate(channel="lexical")
    unbound = bound.model_copy(update={"filter_binding": None})
    with pytest.raises(ValueError, match="FUSION_FILTER_BINDING_REQUIRED"):
        FusionEvidence(candidate=unbound, stance="support")

    other = candidate(channel="vector")
    assert other.filter_binding is not None
    mixed = other.model_copy(
        update={
            "filter_binding": other.filter_binding.model_copy(
                update={"authorization_epoch": 2}
            )
        }
    )
    with pytest.raises(ValueError, match="FUSION_AUTHORITY_BINDING_MISMATCH"):
        ReciprocalRankFusion().fuse(
            {
                "lexical": (FusionEvidence(candidate=bound, stance="support"),),
                "vector": (FusionEvidence(candidate=mixed, stance="support"),),
            }
        )

    mixed_decision = other.model_copy(
        update={
            "filter_binding": other.filter_binding.model_copy(
                update={"decision_sha256": "8" * 64}
            )
        }
    )
    with pytest.raises(ValueError, match="FUSION_AUTHORITY_BINDING_MISMATCH"):
        ReciprocalRankFusion().fuse(
            {
                "lexical": (FusionEvidence(candidate=bound, stance="support"),),
                "vector": (
                    FusionEvidence(candidate=mixed_decision, stance="support"),
                ),
            }
        )
