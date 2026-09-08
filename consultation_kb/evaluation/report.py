"""Deterministic JSON and Markdown quality reports for consultation evaluation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal, TypeAlias

from pydantic import model_validator
from typing_extensions import Self

from consultation_kb.evaluation.blind_review import BlindReviewSummary
from consultation_kb.evaluation.metrics import CorrectnessSummary, MetricResult
from consultation_kb.knowledge._canonical import canonical_json_bytes, canonical_sha256
from consultation_kb.models.common import (
    FiniteFloat,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
)


QualitySectionId: TypeAlias = Literal[
    "deterministic_correctness",
    "retrieval_evidence",
    "consistency_update",
    "privacy_risk_archive",
    "expert_preference",
]
SectionStatus: TypeAlias = Literal["passed", "failed", "degraded", "incomplete"]
TargetStatus: TypeAlias = Literal[
    "met", "not_met", "missing", "undefined", "insufficient_reviewers"
]


SECTION_ORDER: tuple[QualitySectionId, ...] = (
    "deterministic_correctness",
    "retrieval_evidence",
    "consistency_update",
    "privacy_risk_archive",
    "expert_preference",
)


class QualityTarget(StrictModel):
    target_id: SafePolicyKey
    section_id: QualitySectionId
    metric_id: SafePolicyKey
    direction: Literal["higher_is_better", "lower_is_better"]
    threshold: FiniteFloat
    continuous_quality_target: Literal[True] = True
    operational_approval_gate: Literal[False] = False

    @model_validator(mode="after")
    def _target_range(self) -> Self:
        if not 0.0 <= self.threshold <= 1.0:
            raise ValueError("quality target threshold must be in [0, 1]")
        return self


QUALITY_TARGETS: tuple[QualityTarget, ...] = (
    QualityTarget(
        target_id="c1_permission_target",
        section_id="deterministic_correctness",
        metric_id="c1_permission_accuracy",
        direction="higher_is_better",
        threshold=1.0,
    ),
    QualityTarget(
        target_id="c1_active_version_target",
        section_id="deterministic_correctness",
        metric_id="c1_active_version_accuracy",
        direction="higher_is_better",
        threshold=1.0,
    ),
    QualityTarget(
        target_id="c1_external_overclaim_target",
        section_id="deterministic_correctness",
        metric_id="c1_external_overclaim_rate",
        direction="lower_is_better",
        threshold=0.0,
    ),
    QualityTarget(
        target_id="c1_applicability_target",
        section_id="retrieval_evidence",
        metric_id="c1_applicability_accuracy",
        direction="higher_is_better",
        threshold=0.95,
    ),
    QualityTarget(
        target_id="c1_out_of_scope_target",
        section_id="retrieval_evidence",
        metric_id="c1_out_of_scope_accuracy",
        direction="higher_is_better",
        threshold=0.95,
    ),
    QualityTarget(
        target_id="c1_empirical_status_target",
        section_id="retrieval_evidence",
        metric_id="c1_empirical_status_accuracy",
        direction="higher_is_better",
        threshold=0.95,
    ),
    QualityTarget(
        target_id="recall_at_10_target",
        section_id="retrieval_evidence",
        metric_id="critical_evidence_recall_at_10",
        direction="higher_is_better",
        threshold=0.90,
    ),
    QualityTarget(
        target_id="supported_claim_target",
        section_id="retrieval_evidence",
        metric_id="supported_claim_rate",
        direction="higher_is_better",
        threshold=0.95,
    ),
    QualityTarget(
        target_id="contradiction_free_target",
        section_id="consistency_update",
        metric_id="unexplained_contradiction_free_rate",
        direction="higher_is_better",
        threshold=0.95,
    ),
    QualityTarget(
        target_id="expert_preference_target",
        section_id="expert_preference",
        metric_id="full_vs_hybrid_expert_preference",
        direction="higher_is_better",
        threshold=0.70,
    ),
)


class ComponentVersion(StrictModel):
    component_id: SafePolicyKey
    content_sha256: Sha256Hex


class SliceResult(StrictModel):
    slice_id: SafePolicyKey
    status: Literal["passed", "failed", "degraded", "missing"]
    metric_ids: tuple[SafePolicyKey, ...]
    failure_sample_ids: tuple[SafePolicyKey, ...]
    version_sha256s: tuple[Sha256Hex, ...]

    @model_validator(mode="after")
    def _slice_contract(self) -> Self:
        for values, field_name in (
            (self.metric_ids, "metric_ids"),
            (self.failure_sample_ids, "failure_sample_ids"),
            (self.version_sha256s, "version_sha256s"),
        ):
            if values and tuple(sorted(set(values))) != values:
                raise ValueError(f"{field_name} must be sorted and unique")
        if not self.version_sha256s:
            raise ValueError("every slice result must expose exact versions")
        if self.status == "failed" and not self.failure_sample_ids:
            raise ValueError("failed slice must identify at least one sample")
        if self.status == "passed" and self.failure_sample_ids:
            raise ValueError("passed slice cannot contain failed samples")
        return self


class FailureSample(StrictModel):
    sample_id: SafePolicyKey
    case_id: SafePolicyKey
    slice_id: SafePolicyKey
    reason_codes: tuple[SafePolicyKey, ...]
    version_sha256s: tuple[Sha256Hex, ...]

    @model_validator(mode="after")
    def _failure_contract(self) -> Self:
        if not self.reason_codes or tuple(sorted(set(self.reason_codes))) != (
            self.reason_codes
        ):
            raise ValueError("failure reasons must be sorted and non-empty")
        if (
            not self.version_sha256s
            or tuple(sorted(set(self.version_sha256s))) != self.version_sha256s
        ):
            raise ValueError("failure samples must carry sorted exact versions")
        return self


class MissingEvaluation(StrictModel):
    item_id: SafePolicyKey
    section_id: QualitySectionId
    reason_code: SafePolicyKey
    version_sha256s: tuple[Sha256Hex, ...]

    @model_validator(mode="after")
    def _missing_contract(self) -> Self:
        if (
            not self.version_sha256s
            or tuple(sorted(set(self.version_sha256s))) != self.version_sha256s
        ):
            raise ValueError("missing evaluation must retain exact versions")
        return self


class DegradationRecord(StrictModel):
    degradation_code: SafePolicyKey
    section_id: QualitySectionId
    affected_sample_ids: tuple[SafePolicyKey, ...]
    version_sha256s: tuple[Sha256Hex, ...]

    @model_validator(mode="after")
    def _degradation_contract(self) -> Self:
        if (
            self.affected_sample_ids
            and tuple(sorted(set(self.affected_sample_ids))) != self.affected_sample_ids
        ):
            raise ValueError("affected sample IDs must be sorted and unique")
        if (
            not self.version_sha256s
            or tuple(sorted(set(self.version_sha256s))) != self.version_sha256s
        ):
            raise ValueError("degradation must retain exact versions")
        return self


class TargetAssessment(StrictModel):
    target: QualityTarget
    status: TargetStatus
    observed_value: FiniteFloat | None
    ci_lower: FiniteFloat | None
    ci_upper: FiniteFloat | None
    sample_count: int

    @model_validator(mode="after")
    def _assessment_contract(self) -> Self:
        if type(self.sample_count) is not int or self.sample_count < 0:
            raise ValueError("target sample count must be a nonnegative integer")
        values = (self.observed_value, self.ci_lower, self.ci_upper)
        if self.status in {"missing", "undefined"}:
            if any(value is not None for value in values):
                raise ValueError("missing or undefined target cannot carry a score")
        else:
            if any(value is None for value in values):
                raise ValueError(
                    "scored target must include value and confidence interval"
                )
            observed = self.observed_value
            lower = self.ci_lower
            upper = self.ci_upper
            if observed is None or lower is None or upper is None:
                raise AssertionError("validated scored target lost its estimate")
            if not (0.0 <= lower <= observed <= upper <= 1.0):
                raise ValueError("target confidence interval is invalid")
        return self


class QualityReportSection(StrictModel):
    section_id: QualitySectionId
    status: SectionStatus
    metric_ids: tuple[SafePolicyKey, ...]
    target_assessments: tuple[TargetAssessment, ...]
    missing_item_ids: tuple[SafePolicyKey, ...]
    degradation_codes: tuple[SafePolicyKey, ...]

    @model_validator(mode="after")
    def _section_contract(self) -> Self:
        for values, field_name in (
            (self.metric_ids, "metric_ids"),
            (self.missing_item_ids, "missing_item_ids"),
            (self.degradation_codes, "degradation_codes"),
        ):
            if values and tuple(sorted(set(values))) != values:
                raise ValueError(f"{field_name} must be sorted and unique")
        target_ids = tuple(item.target.target_id for item in self.target_assessments)
        if tuple(sorted(set(target_ids))) != target_ids:
            raise ValueError("target assessments must be sorted and unique")
        if any(
            item.target.section_id != self.section_id
            for item in self.target_assessments
        ):
            raise ValueError("section contains a target from another domain")
        if self.status == "passed" and (
            self.missing_item_ids
            or self.degradation_codes
            or any(item.status != "met" for item in self.target_assessments)
        ):
            raise ValueError("passed section hides an incomplete target or degradation")
        return self


class QualityReport(StrictModel):
    record_type: Literal["consultation_quality_report"] = "consultation_quality_report"
    schema_version: Literal["consultation_quality_report.v1"] = (
        "consultation_quality_report.v1"
    )
    report_id: SafePolicyKey
    quality_policy: Literal[
        "continuous_quality_target_not_operational_approval_gate"
    ] = "continuous_quality_target_not_operational_approval_gate"
    versions: tuple[ComponentVersion, ...]
    sections: tuple[QualityReportSection, ...]
    slice_results: tuple[SliceResult, ...]
    failure_samples: tuple[FailureSample, ...]
    missing_evaluations: tuple[MissingEvaluation, ...]
    degradations: tuple[DegradationRecord, ...]
    metric_results: tuple[MetricResult, ...]
    correctness_summary: CorrectnessSummary
    expert_summary: BlindReviewSummary | None
    report_sha256: Sha256Hex

    @model_validator(mode="after")
    def _report_contract(self) -> Self:
        version_ids = tuple(item.component_id for item in self.versions)
        if not version_ids or tuple(sorted(set(version_ids))) != version_ids:
            raise ValueError("report versions must be sorted, non-empty, and unique")
        if tuple(item.section_id for item in self.sections) != SECTION_ORDER:
            raise ValueError("quality report sections are incomplete or out of order")
        key_groups = (
            tuple(item.slice_id for item in self.slice_results),
            tuple(item.sample_id for item in self.failure_samples),
            tuple(item.item_id for item in self.missing_evaluations),
            tuple(item.degradation_code for item in self.degradations),
            tuple(item.definition.metric_id for item in self.metric_results),
        )
        for keys in key_groups:
            if tuple(sorted(set(keys))) != keys:
                raise ValueError("quality report collections must be sorted and unique")
        failure_ids = {item.sample_id for item in self.failure_samples}
        if any(
            not set(item.failure_sample_ids).issubset(failure_ids)
            for item in self.slice_results
        ):
            raise ValueError("slice references an unknown failure sample")
        if self.report_sha256 != _report_digest(self.model_dump(mode="json")):
            raise ValueError("quality report hash mismatch")
        return self


_DOMAINS_BY_SECTION: Mapping[QualitySectionId, frozenset[str]] = {
    "deterministic_correctness": frozenset(),
    "retrieval_evidence": frozenset({"retrieval", "evidence_answer"}),
    "consistency_update": frozenset({"consistency", "profile_update"}),
    "privacy_risk_archive": frozenset({"isolation_boundary", "risk", "archive"}),
    "expert_preference": frozenset(),
}


def _report_digest(value: Mapping[str, object]) -> str:
    projection = dict(value)
    projection.pop("report_sha256", None)
    return canonical_sha256(
        {"domain": "consultation_kb.quality_report.v1", "report": projection}
    )


def _machine_assessment(
    target: QualityTarget, result_by_id: Mapping[str, MetricResult]
) -> TargetAssessment:
    result = result_by_id.get(target.metric_id)
    if result is None:
        return TargetAssessment(
            target=target,
            status="missing",
            observed_value=None,
            ci_lower=None,
            ci_upper=None,
            sample_count=0,
        )
    estimate = result.primary
    if result.status == "undefined" or estimate is None:
        return TargetAssessment(
            target=target,
            status="undefined",
            observed_value=None,
            ci_lower=None,
            ci_upper=None,
            sample_count=0,
        )
    met = (
        estimate.value >= target.threshold
        if target.direction == "higher_is_better"
        else estimate.value <= target.threshold
    )
    return TargetAssessment(
        target=target,
        status="met" if met else "not_met",
        observed_value=float(estimate.value),
        ci_lower=float(estimate.ci_lower),
        ci_upper=float(estimate.ci_upper),
        sample_count=result.eligible_case_count,
    )


def _expert_assessment(
    target: QualityTarget, expert_summary: BlindReviewSummary | None
) -> TargetAssessment:
    if expert_summary is None:
        return TargetAssessment(
            target=target,
            status="missing",
            observed_value=None,
            ci_lower=None,
            ci_upper=None,
            sample_count=0,
        )
    estimate = expert_summary.full_system_preference
    if not expert_summary.conclusion_eligible:
        status: TargetStatus = "insufficient_reviewers"
    else:
        status = "met" if estimate.value >= target.threshold else "not_met"
    return TargetAssessment(
        target=target,
        status=status,
        observed_value=float(estimate.value),
        ci_lower=float(estimate.ci_lower),
        ci_upper=float(estimate.ci_upper),
        sample_count=expert_summary.review_count,
    )


def _section_status(
    *,
    assessments: tuple[TargetAssessment, ...],
    metric_results: tuple[MetricResult, ...],
    missing_ids: tuple[str, ...],
    degradation_codes: tuple[str, ...],
    deterministic_passed: bool | None = None,
) -> SectionStatus:
    if (
        missing_ids
        or any(
            item.status in {"missing", "undefined", "insufficient_reviewers"}
            for item in assessments
        )
        or any(item.status == "undefined" for item in metric_results)
    ):
        return "incomplete"
    if (
        deterministic_passed is False
        or any(item.status == "not_met" for item in assessments)
        or any(item.threshold_met is False for item in metric_results)
    ):
        return "failed"
    if degradation_codes:
        return "degraded"
    return "passed"


def build_quality_report(
    *,
    report_id: str,
    versions: Sequence[ComponentVersion],
    metric_results: Sequence[MetricResult],
    correctness_summary: CorrectnessSummary,
    expert_summary: BlindReviewSummary | None,
    slice_results: Sequence[SliceResult],
    failure_samples: Sequence[FailureSample],
    missing_evaluations: Sequence[MissingEvaluation] = (),
    degradations: Sequence[DegradationRecord] = (),
) -> QualityReport:
    """Build a fail-visible report; absent or undefined data never becomes pass."""

    exact_metrics = tuple(
        sorted(
            (MetricResult.model_validate(item) for item in metric_results),
            key=lambda item: item.definition.metric_id,
        )
    )
    metric_ids = tuple(item.definition.metric_id for item in exact_metrics)
    if len(set(metric_ids)) != len(metric_ids):
        raise ValueError("quality report metric IDs must be unique")
    by_id = {item.definition.metric_id: item for item in exact_metrics}
    exact_correctness = CorrectnessSummary.model_validate(correctness_summary)
    exact_expert = (
        None
        if expert_summary is None
        else BlindReviewSummary.model_validate(expert_summary)
    )
    exact_missing = tuple(
        sorted(
            (MissingEvaluation.model_validate(item) for item in missing_evaluations),
            key=lambda item: item.item_id,
        )
    )
    exact_degradations = tuple(
        sorted(
            (DegradationRecord.model_validate(item) for item in degradations),
            key=lambda item: item.degradation_code,
        )
    )
    exact_versions = tuple(
        sorted(
            (ComponentVersion.model_validate(item) for item in versions),
            key=lambda item: item.component_id,
        )
    )
    exact_slices = tuple(
        sorted(
            (SliceResult.model_validate(item) for item in slice_results),
            key=lambda item: item.slice_id,
        )
    )
    exact_failures = tuple(
        sorted(
            (FailureSample.model_validate(item) for item in failure_samples),
            key=lambda item: item.sample_id,
        )
    )

    sections: list[QualityReportSection] = []
    for section_id in SECTION_ORDER:
        section_targets = tuple(
            target for target in QUALITY_TARGETS if target.section_id == section_id
        )
        assessments = tuple(
            sorted(
                (
                    _expert_assessment(target, exact_expert)
                    if section_id == "expert_preference"
                    else _machine_assessment(target, by_id)
                    for target in section_targets
                ),
                key=lambda item: item.target.target_id,
            )
        )
        if section_id == "deterministic_correctness":
            section_metrics = tuple(
                item for item in exact_metrics if item.definition.zero_tolerance
            )
            implicit_missing = exact_correctness.missing_metric_ids
            deterministic_passed: bool | None = exact_correctness.passed
        elif section_id == "expert_preference":
            section_metrics = ()
            implicit_missing = () if exact_expert is not None else ("expert_reviews",)
            deterministic_passed = None
        else:
            domains = _DOMAINS_BY_SECTION[section_id]
            section_metrics = tuple(
                item for item in exact_metrics if item.definition.domain in domains
            )
            implicit_missing = () if section_metrics else ("section_metrics",)
            deterministic_passed = None
        explicit_missing = tuple(
            item.item_id for item in exact_missing if item.section_id == section_id
        )
        missing_ids = tuple(sorted(set((*implicit_missing, *explicit_missing))))
        degradation_codes = tuple(
            item.degradation_code
            for item in exact_degradations
            if item.section_id == section_id
        )
        sections.append(
            QualityReportSection(
                section_id=section_id,
                status=_section_status(
                    assessments=assessments,
                    metric_results=section_metrics,
                    missing_ids=missing_ids,
                    degradation_codes=degradation_codes,
                    deterministic_passed=deterministic_passed,
                ),
                metric_ids=tuple(
                    sorted(item.definition.metric_id for item in section_metrics)
                ),
                target_assessments=assessments,
                missing_item_ids=missing_ids,
                degradation_codes=degradation_codes,
            )
        )

    exact_sections = tuple(sections)
    projection: dict[str, object] = {
        "record_type": "consultation_quality_report",
        "schema_version": "consultation_quality_report.v1",
        "report_id": report_id,
        "quality_policy": ("continuous_quality_target_not_operational_approval_gate"),
        "versions": [item.model_dump(mode="json") for item in exact_versions],
        "sections": [item.model_dump(mode="json") for item in exact_sections],
        "slice_results": [item.model_dump(mode="json") for item in exact_slices],
        "failure_samples": [item.model_dump(mode="json") for item in exact_failures],
        "missing_evaluations": [item.model_dump(mode="json") for item in exact_missing],
        "degradations": [item.model_dump(mode="json") for item in exact_degradations],
        "metric_results": [item.model_dump(mode="json") for item in exact_metrics],
        "correctness_summary": exact_correctness.model_dump(mode="json"),
        "expert_summary": (
            None if exact_expert is None else exact_expert.model_dump(mode="json")
        ),
    }
    return QualityReport(
        report_id=report_id,
        versions=exact_versions,
        sections=exact_sections,
        slice_results=exact_slices,
        failure_samples=exact_failures,
        missing_evaluations=exact_missing,
        degradations=exact_degradations,
        metric_results=exact_metrics,
        correctness_summary=exact_correctness,
        expert_summary=exact_expert,
        report_sha256=_report_digest(projection),
    )


def quality_report_json_bytes(report: QualityReport) -> bytes:
    exact = QualityReport.model_validate(report)
    return canonical_json_bytes(exact.model_dump(mode="json")) + b"\n"


_SECTION_TITLES: Mapping[QualitySectionId, str] = {
    "deterministic_correctness": "Deterministic correctness",
    "retrieval_evidence": "Retrieval and evidence",
    "consistency_update": "Consistency and update",
    "privacy_risk_archive": "Privacy, risk, and archive",
    "expert_preference": "Expert preference",
}


def _format_value(value: float | None) -> str:
    return "MISSING" if value is None else f"{value:.3f}"


def render_quality_report_markdown(report: QualityReport) -> str:
    """Render all missing/degraded evidence explicitly in a stable order."""

    exact = QualityReport.model_validate(report)
    lines = [
        f"# Consultation quality report: {exact.report_id}",
        "",
        (
            "This report defines continuous quality targets; it is not an "
            "additional operational approval or release gate."
        ),
        "",
        f"Report SHA-256: `{exact.report_sha256}`",
        "",
        "## Exact versions",
        "",
        "| Component | SHA-256 |",
        "|---|---|",
    ]
    lines.extend(
        f"| {item.component_id} | `{item.content_sha256}` |" for item in exact.versions
    )
    for section in exact.sections:
        lines.extend(
            [
                "",
                f"## {_SECTION_TITLES[section.section_id]}",
                "",
                f"Status: **{section.status.upper()}**",
                "",
                "| Target | Observed | 95% CI | Target | Result | N |",
                "|---|---:|---:|---:|---|---:|",
            ]
        )
        if section.target_assessments:
            for item in section.target_assessments:
                interval = (
                    "MISSING"
                    if item.ci_lower is None or item.ci_upper is None
                    else f"[{item.ci_lower:.3f}, {item.ci_upper:.3f}]"
                )
                operator = ">=" if item.target.direction == "higher_is_better" else "<="
                lines.append(
                    "| "
                    f"{item.target.metric_id} | {_format_value(item.observed_value)} | "
                    f"{interval} | {operator} {item.target.threshold:.2f} | "
                    f"{item.status} | {item.sample_count} |"
                )
        else:
            lines.append("| none declared | MISSING | MISSING | n/a | missing | 0 |")
        lines.extend(
            [
                "",
                "Missing: " + (", ".join(section.missing_item_ids) or "none"),
                "",
                "Degradation: " + (", ".join(section.degradation_codes) or "none"),
            ]
        )

    lines.extend(
        [
            "",
            "## Slice outcomes",
            "",
            "| Slice | Status | Metrics | Failed samples | Versions |",
            "|---|---|---|---|---|",
        ]
    )
    if exact.slice_results:
        lines.extend(
            "| "
            f"{item.slice_id} | {item.status} | "
            f"{', '.join(item.metric_ids) or 'none'} | "
            f"{', '.join(item.failure_sample_ids) or 'none'} | "
            f"{', '.join(item.version_sha256s)} |"
            for item in exact.slice_results
        )
    else:
        lines.append("| none | missing | none | none | none |")

    lines.extend(
        [
            "",
            "## Failure samples",
            "",
            "| Sample | Case | Slice | Reasons | Versions |",
            "|---|---|---|---|---|",
        ]
    )
    if exact.failure_samples:
        lines.extend(
            "| "
            f"{item.sample_id} | {item.case_id} | {item.slice_id} | "
            f"{', '.join(item.reason_codes)} | "
            f"{', '.join(item.version_sha256s)} |"
            for item in exact.failure_samples
        )
    else:
        lines.append("| none | none | none | none | none |")

    lines.extend(["", "## Explicitly missing evaluation", ""])
    if exact.missing_evaluations:
        lines.extend(
            f"- {item.item_id}: {item.section_id} / {item.reason_code} / "
            f"versions={','.join(item.version_sha256s)}"
            for item in exact.missing_evaluations
        )
    else:
        lines.append("- none")
    lines.extend(["", "## Runtime degradation", ""])
    if exact.degradations:
        lines.extend(
            f"- {item.degradation_code}: {item.section_id} / "
            f"samples={','.join(item.affected_sample_ids) or 'none'} / "
            f"versions={','.join(item.version_sha256s)}"
            for item in exact.degradations
        )
    else:
        lines.append("- none")
    if exact.expert_summary is not None:
        lines.extend(
            [
                "",
                "## Expert-review evidence",
                "",
                f"Independent reviewers: {exact.expert_summary.independent_reviewer_count}",
                "",
                "Reviewer agreement: "
                + (
                    "not estimable"
                    if exact.expert_summary.reviewer_agreement is None
                    else f"{exact.expert_summary.reviewer_agreement:.3f}"
                ),
                "",
                (
                    "Conclusion eligible: yes"
                    if exact.expert_summary.conclusion_eligible
                    else "Conclusion eligible: no; a single reviewer is not conclusive"
                ),
            ]
        )
    return "\n".join(lines) + "\n"


generate_quality_report = build_quality_report
render_quality_report = render_quality_report_markdown


__all__ = [
    "QUALITY_TARGETS",
    "SECTION_ORDER",
    "ComponentVersion",
    "DegradationRecord",
    "FailureSample",
    "MissingEvaluation",
    "QualityReport",
    "QualityReportSection",
    "QualitySectionId",
    "QualityTarget",
    "SectionStatus",
    "SliceResult",
    "TargetAssessment",
    "TargetStatus",
    "build_quality_report",
    "generate_quality_report",
    "quality_report_json_bytes",
    "render_quality_report",
    "render_quality_report_markdown",
]
