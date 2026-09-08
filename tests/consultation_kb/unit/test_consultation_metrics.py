from __future__ import annotations

from pathlib import Path

import pytest

from consultation_kb.evaluation.datasets import load_evaluation_dataset
from consultation_kb.evaluation.metrics import (
    MACHINE_METRIC_DEFINITIONS,
    MetricObservation,
    aggregate_registered_metric,
    summarize_correctness,
)
from consultation_kb.evaluation.scorers import (
    ArchiveFieldScoringInput,
    ObservedProfileDiff,
    adverse_event_observation,
    machine_metric_requirements,
    pending_human_annotations,
    score_archive_fields,
    score_profile_diff,
)
from consultation_kb.models.evaluation import ExpectedProfileDiff


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
EVALUATION_FIXTURES = (
    REPOSITORY_ROOT / "tests" / "fixtures" / "consultation_kb" / "evaluation"
)


def test_every_machine_metric_declares_aggregation_ci_and_undefined_policy() -> None:
    assert MACHINE_METRIC_DEFINITIONS
    for definition in MACHINE_METRIC_DEFINITIONS:
        assert definition.undefined_policy == "report_undefined"
        assert definition.aggregation_policy == "micro_and_macro"
        assert definition.confidence_interval == "case_bootstrap_percentile_95"
        assert definition.threshold_direction in {
            "higher_is_better",
            "lower_is_better",
        }
        if definition.zero_tolerance:
            assert definition.threshold_value in {0.0, 1.0}


def test_profile_diff_match_omission_and_forbidden_rates_are_hand_calculable() -> None:
    expected = ExpectedProfileDiff(
        set_fields=("current_goal",),
        invalidate_fields=("old_goal",),
        resolve_fields=("old_problem",),
        forbidden_fields=("diagnostic_label",),
    )
    actual = ObservedProfileDiff(
        set_fields=("current_goal", "extra_field"),
        invalidate_fields=("old_goal",),
        resolve_fields=(),
    )

    match, omission, forbidden = score_profile_diff(
        "syn_case_profile",
        expected,
        actual,
    )

    assert (match.numerator, match.denominator) == (2, 4)
    assert (omission.numerator, omission.denominator) == (1, 3)
    assert (forbidden.numerator, forbidden.denominator) == (0, 1)
    match_result = aggregate_registered_metric(
        match.metric_id,
        (match,),
        bootstrap_replicates=200,
    )
    assert match_result.primary is not None
    assert match_result.primary.value == pytest.approx(0.5)


def test_two_archive_products_keep_separate_accuracy_and_combined_omissions() -> None:
    private_accuracy, profile_accuracy, omission = score_archive_fields(
        ArchiveFieldScoringInput(
            case_id="syn_case_archive",
            expected_private_fields=("analysis", "transcript"),
            actual_private_fields=("analysis", "extra"),
            expected_profile_fields=("current_goal", "resolved_issue"),
            actual_profile_fields=("current_goal",),
        )
    )

    assert (private_accuracy.numerator, private_accuracy.denominator) == (1, 3)
    assert (profile_accuracy.numerator, profile_accuracy.denominator) == (1, 2)
    assert (omission.numerator, omission.denominator) == (2, 4)


def test_any_zero_tolerance_failure_makes_correctness_summary_fail() -> None:
    leak = aggregate_registered_metric(
        "cross_client_leak_rate",
        (
            adverse_event_observation(
                "cross_client_leak_rate",
                "syn_case_leak",
                occurred=True,
            ),
        ),
        bootstrap_replicates=200,
    )
    no_label_leak = aggregate_registered_metric(
        "risk_label_client_leak_rate",
        (
            adverse_event_observation(
                "risk_label_client_leak_rate",
                "syn_case_risk",
                occurred=False,
            ),
        ),
        bootstrap_replicates=200,
    )

    summary = summarize_correctness(
        (leak, no_label_leak),
        expected_metric_ids=(
            "cross_client_leak_rate",
            "risk_label_client_leak_rate",
        ),
    )

    assert summary.passed is False
    assert summary.failed_metric_ids == ("cross_client_leak_rate",)
    assert summary.undefined_metric_ids == ()
    assert summary.missing_metric_ids == ()


def test_undefined_or_missing_zero_tolerance_metric_fails_closed() -> None:
    undefined = aggregate_registered_metric(
        "cross_client_leak_rate",
        (
            MetricObservation(
                metric_id="cross_client_leak_rate",
                case_id="syn_case_no_probe",
                numerator=0,
                denominator=0,
            ),
        ),
        bootstrap_replicates=200,
    )

    undefined_summary = summarize_correctness(
        (undefined,),
        expected_metric_ids=("cross_client_leak_rate",),
    )
    missing_summary = summarize_correctness(
        (),
        expected_metric_ids=("cross_client_leak_rate",),
    )

    assert undefined_summary.passed is False
    assert undefined_summary.undefined_metric_ids == ("cross_client_leak_rate",)
    assert missing_summary.passed is False
    assert missing_summary.missing_metric_ids == ("cross_client_leak_rate",)


def test_human_rubrics_create_pending_work_without_machine_quality_scores() -> None:
    case = load_evaluation_dataset(EVALUATION_FIXTURES / "gold_cases.jsonl").cases[0]

    pending = pending_human_annotations(case)

    assert len(pending) == 1
    assert pending[0].criterion_id == "human_helpfulness"
    assert pending[0].status == "pending"
    assert "score" not in pending[0].model_dump()
    assert "value" not in pending[0].model_dump()
    assert machine_metric_requirements(case) == ("deterministic_constraint_pass",)


def test_all_tracked_machine_rubrics_resolve_to_the_closed_catalog() -> None:
    for name in ("gold_cases.jsonl", "gold_retrieval.jsonl", "canary_cases.jsonl"):
        dataset = load_evaluation_dataset(EVALUATION_FIXTURES / name)
        for case in dataset.cases:
            assert machine_metric_requirements(case)
