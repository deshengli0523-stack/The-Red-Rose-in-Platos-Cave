from __future__ import annotations

import math
from pathlib import Path

import pytest

from consultation_kb.evaluation.datasets import load_evaluation_dataset
from consultation_kb.evaluation.metrics import (
    MetricObservation,
    aggregate_registered_metric,
)
from consultation_kb.evaluation.scorers import (
    GoldEvidence,
    PrefilterDecision,
    RetrievalScoringInput,
    RetrievedEvidence,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
    reciprocal_rank,
    score_acceptable_evidence_path,
    score_retrieval_at_10,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
GOLD_RETRIEVAL = (
    REPOSITORY_ROOT
    / "tests"
    / "fixtures"
    / "consultation_kb"
    / "evaluation"
    / "gold_retrieval.jsonl"
)


def test_recall_precision_ndcg_and_rr_match_hand_calculation() -> None:
    ranked = ("a", "x", "b", "c")
    relevant = {"a", "b", "c"}
    relevance = {"a": 3, "b": 2, "c": 1}
    actual_dcg = 7.0 + 3.0 / math.log2(4)
    ideal_dcg = 7.0 + 3.0 / math.log2(3) + 1.0 / math.log2(4)

    assert recall_at_k(ranked, relevant, 3) == pytest.approx(2 / 3)
    assert precision_at_k(ranked, relevant, 3) == pytest.approx(2 / 3)
    assert ndcg_at_k(ranked, relevance, 3) == pytest.approx(actual_dcg / ideal_dcg)
    assert reciprocal_rank(ranked, {"b", "c"}) == pytest.approx(1 / 3)


def test_empty_gold_is_undefined_and_unfilled_precision_positions_are_errors() -> None:
    assert recall_at_k(("a",), set(), 3) is None
    assert ndcg_at_k(("a",), {}, 3) is None
    assert reciprocal_rank(("a",), set()) is None
    assert precision_at_k(("a",), {"a"}, 3) == pytest.approx(1 / 3)


def _retrieval_input() -> RetrievalScoringInput:
    return RetrievalScoringInput(
        case_id="syn_case_metrics",
        ranked=(
            RetrievedEvidence(
                evidence_id="a",
                source_id="source_one",
                duplicate_group_id="group_one",
                exact_quote_match=True,
                exact_location_match=True,
            ),
            RetrievedEvidence(
                evidence_id="x",
                source_id="source_one",
                duplicate_group_id="group_one",
                exact_quote_match=False,
                exact_location_match=False,
            ),
            RetrievedEvidence(
                evidence_id="b",
                source_id="source_two",
                duplicate_group_id="group_two",
                exact_quote_match=False,
                exact_location_match=False,
            ),
        ),
        gold=(
            GoldEvidence(
                evidence_id="a",
                source_id="source_one",
                relevance_grade=3,
                is_counterevidence=False,
                requires_exact_quote=True,
                requires_exact_location=True,
            ),
            GoldEvidence(
                evidence_id="b",
                source_id="source_two",
                relevance_grade=2,
                is_counterevidence=True,
                requires_exact_quote=False,
                requires_exact_location=False,
            ),
            GoldEvidence(
                evidence_id="c",
                source_id="source_three",
                relevance_grade=1,
                is_counterevidence=False,
                requires_exact_quote=True,
                requires_exact_location=False,
            ),
        ),
        prefilter_decisions=(
            PrefilterDecision(
                candidate_id="allowed",
                expected_allowed=True,
                actual_allowed=True,
            ),
            PrefilterDecision(
                candidate_id="denied",
                expected_allowed=False,
                actual_allowed=True,
            ),
        ),
    )


def test_retrieval_suite_uses_explicit_denominators_and_duplicate_groups() -> None:
    observations = {
        observation.metric_id: observation
        for observation in score_retrieval_at_10(_retrieval_input())
    }

    assert observations["critical_evidence_recall_at_10"].numerator == 2
    assert observations["critical_evidence_recall_at_10"].denominator == 3
    assert observations["retrieval_precision_at_10"].numerator == 2
    assert observations["retrieval_precision_at_10"].denominator == 10
    assert observations["exact_quote_hit_rate"].numerator == 1
    assert observations["exact_quote_hit_rate"].denominator == 2
    assert observations["exact_location_hit_rate"].numerator == 1
    assert observations["exact_location_hit_rate"].denominator == 1
    assert observations["source_diversity_rate"].numerator == 2
    assert observations["source_diversity_rate"].denominator == 3
    assert observations["retrieval_duplicate_rate"].numerator == 1
    assert observations["retrieval_duplicate_rate"].denominator == 3
    assert observations["counterevidence_recall"].numerator == 1
    assert observations["counterevidence_recall"].denominator == 1

    prefilter = aggregate_registered_metric(
        "metadata_prefilter_accuracy",
        (observations["metadata_prefilter_accuracy"],),
        bootstrap_replicates=200,
    )
    assert prefilter.primary is not None
    assert prefilter.primary.value == pytest.approx(0.5)
    assert prefilter.threshold_met is False
    assert prefilter.zero_tolerance_violated is True


def test_micro_macro_and_case_bootstrap_are_deterministic() -> None:
    observations = (
        MetricObservation(
            metric_id="source_diversity_rate",
            case_id="case_one",
            numerator=1,
            denominator=1,
        ),
        MetricObservation(
            metric_id="source_diversity_rate",
            case_id="case_two",
            numerator=1,
            denominator=3,
        ),
    )

    first = aggregate_registered_metric(
        "source_diversity_rate",
        observations,
        bootstrap_seed=7,
        bootstrap_replicates=500,
    )
    second = aggregate_registered_metric(
        "source_diversity_rate",
        observations,
        bootstrap_seed=7,
        bootstrap_replicates=500,
    )

    assert first == second
    assert first.micro is not None
    assert first.macro is not None
    assert first.micro.value == pytest.approx(2 / 4)
    assert first.macro.value == pytest.approx((1 + 1 / 3) / 2)
    assert first.micro.ci_lower == pytest.approx(1 / 3)
    assert first.micro.ci_upper == pytest.approx(1.0)
    assert first.macro.ci_lower == pytest.approx(1 / 3)
    assert first.macro.ci_upper == pytest.approx(1.0)


def test_zero_denominator_is_reported_undefined_not_one_hundred_percent() -> None:
    result = aggregate_registered_metric(
        "counterevidence_recall",
        (
            MetricObservation(
                metric_id="counterevidence_recall",
                case_id="case_no_counterevidence",
                numerator=0,
                denominator=0,
            ),
        ),
        bootstrap_replicates=200,
    )

    assert result.status == "undefined"
    assert result.micro is None
    assert result.macro is None
    assert result.threshold_met is None


def test_exact_versioned_acceptable_path_can_use_any_declared_alternative() -> None:
    case = load_evaluation_dataset(GOLD_RETRIEVAL).cases[0]
    alternative_path = case.acceptable_evidence_paths[1]

    observation = score_acceptable_evidence_path(
        case,
        tuple(reversed(alternative_path.evidence_refs)),
    )

    assert observation.metric_id == "acceptable_evidence_path_match"
    assert observation.numerator == 1
    assert observation.denominator == 1
