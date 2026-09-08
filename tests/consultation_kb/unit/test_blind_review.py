from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from consultation_kb.evaluation.blind_review import (
    RUBRIC_IDS,
    BlindPairSource,
    BlindReviewError,
    CriterionReview,
    ReviewImporter,
    build_blind_review_packets,
    build_blind_review_pair,
    make_review_submission,
    pseudonymize_reviewer_id,
    verify_blind_mapping,
)
from consultation_kb.models.evaluation import EvaluationTurn


MAPPING_SECRET = b"mapping-secret-for-tests-32bytes"
REVIEWER_SECRET = b"reviewer-secret-for-tests-32bytes"


def _source(case_id: str = "syn_case_blind") -> BlindPairSource:
    return BlindPairSource(
        case_id=case_id,
        context=(EvaluationTurn(role="client", text="我在关系选择上有些犹豫。"),),
        full_system_response="先分清你的需要，再设计一个可验证的小步骤。",
        hybrid_rag_only_response="可以列出选项的优点和缺点后再决定。",
    )


def _criteria(preference: str) -> tuple[CriterionReview, ...]:
    if preference == "left":
        left, right = 5, 3
    elif preference == "right":
        left, right = 3, 5
    else:
        left = right = 4
    return tuple(
        CriterionReview(
            criterion_id=criterion_id,
            left_score=left,
            right_score=right,
            preference=preference,
            reason_codes=("clear_reason",),
            rationale="评分依据已按维度记录。",
        )
        for criterion_id in RUBRIC_IDS
    )


def _submission(bundle, reviewer_id: str, preference: str):
    return make_review_submission(
        packet_id=bundle.packet.packet_id,
        mapping_sha256=bundle.packet.mapping_sha256,
        reviewer_id=reviewer_id,
        reviewer_secret=REVIEWER_SECRET,
        overall_preference=preference,
        overall_reason_codes=("overall_quality",),
        overall_rationale="综合各项维度后作出选择。",
        criteria=_criteria(preference),
    )


def test_pair_packet_is_randomized_deterministic_and_blind() -> None:
    sources = tuple(_source(f"syn_case_blind_{index}") for index in range(24))
    first = build_blind_review_packets(
        sources,
        seed=17,
        mapping_secret=MAPPING_SECRET,
    )
    second = build_blind_review_packets(
        sources,
        seed=17,
        mapping_secret=MAPPING_SECRET,
    )

    assert first == second
    assert {item.mapping.left_variant for item in first} == {
        "full_system",
        "hybrid_rag_only",
    }
    for bundle in first:
        assert verify_blind_mapping(bundle.mapping, MAPPING_SECRET)
        visible = json.dumps(bundle.packet.model_dump(mode="json"), ensure_ascii=False)
        for forbidden in (
            "full_system",
            "hybrid_rag_only",
            "run_id",
            "model_version",
            "internal_risk",
            "high_attention",
        ):
            assert forbidden not in visible
        assert tuple(item.criterion_id for item in bundle.packet.rubric) == RUBRIC_IDS


def test_packet_rejects_identity_source_or_internal_risk_metadata() -> None:
    with pytest.raises(ValidationError, match="hidden identity"):
        BlindPairSource(
            case_id="syn_case_leak",
            context=(EvaluationTurn(role="client", text="source_hidden 是依据。"),),
            full_system_response="回答一。",
            hybrid_rag_only_response="回答二。",
        )
    with pytest.raises(ValidationError, match="hidden identity"):
        BlindPairSource(
            case_id="syn_case_risk_leak",
            context=(EvaluationTurn(role="client", text="这是一般情境。"),),
            full_system_response="risk_level 是 high_attention。",
            hybrid_rag_only_response="回答二。",
        )


def test_mapping_hash_is_keyed_and_tamper_evident() -> None:
    bundle = build_blind_review_pair(_source(), seed=3, mapping_secret=MAPPING_SECRET)
    tampered = bundle.mapping.model_copy(
        update={
            "left_variant": bundle.mapping.right_variant,
            "right_variant": bundle.mapping.left_variant,
        }
    )

    assert not verify_blind_mapping(tampered, MAPPING_SECRET)
    with pytest.raises(BlindReviewError) as caught:
        ReviewImporter(mapping_secret=MAPPING_SECRET).import_reviews(
            (bundle.model_copy(update={"mapping": tampered}),),
            (),
        )
    assert caught.value.code == "BLIND_REVIEW_MAPPING_HASH_MISMATCH"


def test_reviewer_identity_is_only_a_keyed_irreversible_digest() -> None:
    bundle = build_blind_review_pair(_source(), seed=5, mapping_secret=MAPPING_SECRET)
    review = _submission(bundle, "expert@example.invalid", "left")
    serialized = json.dumps(review.model_dump(mode="json"))

    assert "expert@example.invalid" not in serialized
    assert review.reviewer_id_hash == pseudonymize_reviewer_id(
        "expert@example.invalid", REVIEWER_SECRET
    )
    assert review.reviewer_id_hash != pseudonymize_reviewer_id(
        "expert@example.invalid", b"another-reviewer-secret-32bytes"
    )


def test_import_resolves_variants_reports_ci_and_multi_reviewer_agreement() -> None:
    bundle = build_blind_review_pair(_source(), seed=11, mapping_secret=MAPPING_SECRET)
    full_side = "left" if bundle.mapping.left_variant == "full_system" else "right"
    reviews = (
        _submission(bundle, "reviewer-one", full_side),
        _submission(bundle, "reviewer-two", full_side),
    )

    imported = ReviewImporter(
        mapping_secret=MAPPING_SECRET,
        bootstrap_replicates=200,
    ).import_reviews(
        (bundle,),
        reviews,
        expected_reviewer_hashes=tuple(
            sorted(review.reviewer_id_hash for review in reviews)
        ),
    )

    assert imported.summary.full_system_wins == 2
    assert imported.summary.full_system_preference.value == 1.0
    assert imported.summary.full_system_preference.ci_lower == 1.0
    assert imported.summary.reviewer_agreement == 1.0
    assert imported.summary.agreement_pair_count == 1
    assert imported.summary.conclusion_eligible is True


def test_import_rejects_duplicate_missing_and_mapping_mismatch() -> None:
    bundle = build_blind_review_pair(_source(), seed=13, mapping_secret=MAPPING_SECRET)
    review = _submission(bundle, "reviewer-one", "tie")
    importer = ReviewImporter(mapping_secret=MAPPING_SECRET)

    with pytest.raises(BlindReviewError) as duplicate:
        importer.import_reviews((bundle,), (review, review))
    assert duplicate.value.code == "BLIND_REVIEW_DUPLICATE_REVIEW"

    with pytest.raises(BlindReviewError) as missing:
        importer.import_reviews((bundle,), ())
    assert missing.value.code == "BLIND_REVIEW_MISSING_REVIEW"

    wrong_hash = review.model_copy(update={"mapping_sha256": "0" * 64})
    with pytest.raises(BlindReviewError) as mismatch:
        importer.import_reviews((bundle,), (wrong_hash,))
    assert mismatch.value.code == "BLIND_REVIEW_MAPPING_HASH_MISMATCH"

    expected = (
        review.reviewer_id_hash,
        pseudonymize_reviewer_id("reviewer-two", REVIEWER_SECRET),
    )
    with pytest.raises(BlindReviewError) as absent_reviewer:
        importer.import_reviews(
            (bundle,),
            (review,),
            expected_reviewer_hashes=tuple(sorted(expected)),
        )
    assert absent_reviewer.value.code == "BLIND_REVIEW_MISSING_REVIEWER"


def test_submission_rejects_missing_or_self_contradictory_rubric_scores() -> None:
    bundle = build_blind_review_pair(_source(), seed=19, mapping_secret=MAPPING_SECRET)
    with pytest.raises(ValidationError, match="numeric scores"):
        CriterionReview(
            criterion_id=RUBRIC_IDS[0],
            left_score=5,
            right_score=1,
            preference="right",
            reason_codes=("contradiction",),
            rationale="这一评分故意自相矛盾。",
        )

    with pytest.raises(ValidationError, match="every rubric criterion"):
        make_review_submission(
            packet_id=bundle.packet.packet_id,
            mapping_sha256=bundle.packet.mapping_sha256,
            reviewer_id="reviewer-one",
            reviewer_secret=REVIEWER_SECRET,
            overall_preference="tie",
            overall_reason_codes=("incomplete",),
            overall_rationale="缺失一项评分。",
            criteria=_criteria("tie")[:-1],
        )
