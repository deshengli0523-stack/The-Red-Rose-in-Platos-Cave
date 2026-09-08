from __future__ import annotations

from consultation_kb.evaluation.blind_review import (
    BlindReviewSummary,
    PreferenceEstimate,
)
from consultation_kb.evaluation.metrics import (
    MetricObservation,
    aggregate_registered_metric,
    summarize_correctness,
)
from consultation_kb.evaluation.report import (
    QUALITY_TARGETS,
    ComponentVersion,
    DegradationRecord,
    FailureSample,
    MissingEvaluation,
    SliceResult,
    build_quality_report,
    quality_report_json_bytes,
    render_quality_report_markdown,
)


VERSION_A = "a" * 64
VERSION_B = "b" * 64


def _result(metric_id: str, numerator: int, denominator: int):
    return aggregate_registered_metric(
        metric_id,
        (
            MetricObservation(
                metric_id=metric_id,
                case_id="syn_case_report",
                numerator=numerator,
                denominator=denominator,
            ),
        ),
        bootstrap_replicates=200,
    )


def _report_inputs():
    values = {
        "c1_permission_accuracy": (1, 1),
        "c1_active_version_accuracy": (1, 1),
        "c1_external_overclaim_rate": (0, 1),
        "c1_applicability_accuracy": (19, 20),
        "c1_out_of_scope_accuracy": (19, 20),
        "c1_empirical_status_accuracy": (19, 20),
        "critical_evidence_recall_at_10": (9, 10),
        "supported_claim_rate": (19, 20),
        "unexplained_contradiction_free_rate": (19, 20),
        "cross_client_leak_rate": (0, 1),
    }
    results = tuple(
        _result(metric_id, *numbers) for metric_id, numbers in values.items()
    )
    zero_results = tuple(item for item in results if item.definition.zero_tolerance)
    correctness = summarize_correctness(
        zero_results,
        expected_metric_ids=tuple(item.definition.metric_id for item in zero_results),
    )
    expert = BlindReviewSummary(
        packet_count=1,
        review_count=2,
        independent_reviewer_count=2,
        full_system_wins=1,
        hybrid_rag_only_wins=0,
        ties=1,
        full_system_preference=PreferenceEstimate(
            value=0.75,
            ci_lower=0.5,
            ci_upper=1.0,
            bootstrap_seed=17,
            bootstrap_replicates=200,
        ),
        reviewer_agreement=0.875,
        agreement_pair_count=1,
        conclusion_eligible=True,
    )
    return results, correctness, expert


def test_targets_encode_quality_goals_without_creating_an_approval_gate() -> None:
    targets = {item.metric_id: item for item in QUALITY_TARGETS}

    assert targets["c1_permission_accuracy"].threshold == 1.0
    assert targets["c1_active_version_accuracy"].threshold == 1.0
    assert targets["c1_applicability_accuracy"].threshold == 0.95
    assert targets["c1_out_of_scope_accuracy"].threshold == 0.95
    assert targets["c1_empirical_status_accuracy"].threshold == 0.95
    assert targets["c1_external_overclaim_rate"].threshold == 0.0
    assert targets["critical_evidence_recall_at_10"].threshold == 0.90
    assert targets["supported_claim_rate"].threshold == 0.95
    assert targets["unexplained_contradiction_free_rate"].threshold == 0.95
    assert targets["full_vs_hybrid_expert_preference"].threshold == 0.70
    assert all(item.continuous_quality_target for item in QUALITY_TARGETS)
    assert all(not item.operational_approval_gate for item in QUALITY_TARGETS)


def test_small_synthetic_report_is_deterministic_and_has_five_peer_sections() -> None:
    results, correctness, expert = _report_inputs()
    kwargs = dict(
        report_id="quality_report_alpha",
        versions=(
            ComponentVersion(component_id="dataset", content_sha256=VERSION_A),
            ComponentVersion(component_id="system", content_sha256=VERSION_B),
        ),
        metric_results=results,
        correctness_summary=correctness,
        expert_summary=expert,
        slice_results=(
            SliceResult(
                slice_id="relationship_consulting",
                status="passed",
                metric_ids=("supported_claim_rate",),
                failure_sample_ids=(),
                version_sha256s=(VERSION_A, VERSION_B),
            ),
        ),
        failure_samples=(),
    )

    first = build_quality_report(**kwargs)
    second = build_quality_report(**kwargs)

    assert first == second
    assert quality_report_json_bytes(first) == quality_report_json_bytes(second)
    assert tuple(item.section_id for item in first.sections) == (
        "deterministic_correctness",
        "retrieval_evidence",
        "consistency_update",
        "privacy_risk_archive",
        "expert_preference",
    )
    assert all(item.status == "passed" for item in first.sections)
    assert first.quality_policy.endswith("not_operational_approval_gate")


def test_markdown_never_hides_missing_degradation_failures_or_versions() -> None:
    results, correctness, expert = _report_inputs()
    failure = FailureSample(
        sample_id="failure_relationship",
        case_id="syn_case_report",
        slice_id="relationship_consulting",
        reason_codes=("missing_counterevidence",),
        version_sha256s=(VERSION_A, VERSION_B),
    )
    report = build_quality_report(
        report_id="quality_report_visible_failures",
        versions=(
            ComponentVersion(component_id="dataset", content_sha256=VERSION_A),
            ComponentVersion(component_id="system", content_sha256=VERSION_B),
        ),
        metric_results=results,
        correctness_summary=correctness,
        expert_summary=expert.model_copy(
            update={
                "independent_reviewer_count": 1,
                "conclusion_eligible": False,
            }
        ),
        slice_results=(
            SliceResult(
                slice_id="relationship_consulting",
                status="failed",
                metric_ids=("supported_claim_rate",),
                failure_sample_ids=(failure.sample_id,),
                version_sha256s=(VERSION_A, VERSION_B),
            ),
        ),
        failure_samples=(failure,),
        missing_evaluations=(
            MissingEvaluation(
                item_id="missing_career_slice",
                section_id="retrieval_evidence",
                reason_code="queue_item_not_submitted",
                version_sha256s=(VERSION_A,),
            ),
        ),
        degradations=(
            DegradationRecord(
                degradation_code="reranker_unavailable",
                section_id="privacy_risk_archive",
                affected_sample_ids=(failure.sample_id,),
                version_sha256s=(VERSION_B,),
            ),
        ),
    )

    markdown = render_quality_report_markdown(report)

    assert "missing_career_slice" in markdown
    assert "queue_item_not_submitted" in markdown
    assert "reranker_unavailable" in markdown
    assert "failure_relationship" in markdown
    assert "missing_counterevidence" in markdown
    assert VERSION_A in markdown and VERSION_B in markdown
    assert "single reviewer is not conclusive" in markdown
    assert "not an additional operational approval or release gate" in markdown
    assert (
        next(
            item for item in report.sections if item.section_id == "retrieval_evidence"
        ).status
        == "incomplete"
    )
    assert (
        next(
            item
            for item in report.sections
            if item.section_id == "privacy_risk_archive"
        ).status
        == "degraded"
    )
    assert (
        next(
            item for item in report.sections if item.section_id == "expert_preference"
        ).status
        == "incomplete"
    )
