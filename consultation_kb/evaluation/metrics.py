"""Deterministic metric contracts, aggregation, and confidence intervals.

Every machine metric carries its denominator, undefined-value policy,
aggregation rule, confidence-interval method, and threshold direction.  Empty
denominators remain explicitly undefined; they are never converted to a
perfect score.  Bootstrap resampling is clustered by evaluation case so that
multiple facts from one case cannot masquerade as independent samples.
"""

from __future__ import annotations

import math
import random
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Annotated, Literal, TypeAlias

from pydantic import Field, model_validator
from typing_extensions import Self

from consultation_kb.models.common import FiniteFloat, SafePolicyKey, StrictModel


MetricDomain: TypeAlias = Literal[
    "retrieval",
    "evidence_answer",
    "consistency",
    "profile_update",
    "isolation_boundary",
    "risk",
    "archive",
]
MetricValueKind: TypeAlias = Literal["proportion", "mean"]
ThresholdDirection: TypeAlias = Literal["higher_is_better", "lower_is_better"]
PrimaryAggregation: TypeAlias = Literal["micro", "macro"]
MetricStatus: TypeAlias = Literal["defined", "undefined"]
NonNegativeNumber: TypeAlias = Annotated[int | float, Field(ge=0, allow_inf_nan=False)]


class MetricDefinition(StrictModel):
    """Complete policy for one machine-owned metric."""

    metric_id: SafePolicyKey
    domain: MetricDomain
    value_kind: MetricValueKind
    numerator_description: str
    denominator_description: str
    undefined_policy: Literal["report_undefined"]
    aggregation_policy: Literal["micro_and_macro"]
    confidence_interval: Literal["case_bootstrap_percentile_95"]
    primary_aggregation: PrimaryAggregation
    threshold_direction: ThresholdDirection
    threshold_value: FiniteFloat | None
    zero_tolerance: bool

    @model_validator(mode="after")
    def _definition_contract(self) -> Self:
        if (
            not self.numerator_description.strip()
            or not self.denominator_description.strip()
        ):
            raise ValueError("metric numerator and denominator must be documented")
        if self.value_kind == "proportion" and self.threshold_value is not None:
            if not 0.0 <= self.threshold_value <= 1.0:
                raise ValueError("proportion threshold must be in [0, 1]")
        if self.value_kind == "mean" and self.threshold_value is not None:
            if self.threshold_value < 0.0:
                raise ValueError("mean threshold must be nonnegative")
        if self.zero_tolerance:
            if self.value_kind != "proportion" or self.threshold_value is None:
                raise ValueError("zero-tolerance metric must be a bounded proportion")
            exact_boundary = (
                self.threshold_direction == "higher_is_better"
                and self.threshold_value == 1.0
            ) or (
                self.threshold_direction == "lower_is_better"
                and self.threshold_value == 0.0
            )
            if not exact_boundary:
                raise ValueError(
                    "zero-tolerance threshold must require exactly one or zero"
                )
        return self


class MetricObservation(StrictModel):
    """One additive numerator/denominator contribution for one case."""

    metric_id: SafePolicyKey
    case_id: SafePolicyKey
    numerator: NonNegativeNumber
    denominator: NonNegativeNumber

    @model_validator(mode="after")
    def _zero_denominator_contract(self) -> Self:
        if self.denominator == 0 and self.numerator != 0:
            raise ValueError("undefined observation must have a zero numerator")
        return self


class MetricEstimate(StrictModel):
    value: FiniteFloat
    ci_lower: FiniteFloat
    ci_upper: FiniteFloat

    @model_validator(mode="after")
    def _ordered_interval(self) -> Self:
        if self.ci_lower > self.ci_upper:
            raise ValueError("metric confidence interval is reversed")
        return self


class MetricResult(StrictModel):
    """Self-describing micro/macro result for one machine metric."""

    definition: MetricDefinition
    status: MetricStatus
    total_numerator: NonNegativeNumber
    total_denominator: NonNegativeNumber
    eligible_case_count: int = Field(strict=True, ge=0)
    undefined_case_count: int = Field(strict=True, ge=0)
    micro: MetricEstimate | None
    macro: MetricEstimate | None
    threshold_met: bool | None
    zero_tolerance_violated: bool
    bootstrap_seed: int = Field(strict=True, ge=0)
    bootstrap_replicates: int = Field(strict=True, ge=100)

    @model_validator(mode="after")
    def _result_contract(self) -> Self:
        if self.status == "undefined":
            if (
                self.total_numerator != 0
                or self.total_denominator != 0
                or self.eligible_case_count != 0
                or self.micro is not None
                or self.macro is not None
                or self.threshold_met is not None
            ):
                raise ValueError("undefined metric result contains a fabricated score")
            if self.definition.zero_tolerance and not self.zero_tolerance_violated:
                raise ValueError("undefined zero-tolerance metric must fail closed")
        else:
            if (
                self.total_denominator <= 0
                or self.eligible_case_count <= 0
                or self.micro is None
                or self.macro is None
            ):
                raise ValueError("defined metric result is incomplete")
            if (
                self.definition.threshold_value is None
                and self.threshold_met is not None
            ):
                raise ValueError("report-only metric cannot claim a threshold result")
            if (
                self.definition.threshold_value is not None
                and self.threshold_met is None
            ):
                raise ValueError("thresholded metric must report pass or fail")
            if self.definition.value_kind == "proportion":
                values = (
                    self.micro.value,
                    self.micro.ci_lower,
                    self.micro.ci_upper,
                    self.macro.value,
                    self.macro.ci_lower,
                    self.macro.ci_upper,
                )
                if any(not 0.0 <= value <= 1.0 for value in values):
                    raise ValueError("proportion result must remain in [0, 1]")
        return self

    @property
    def primary(self) -> MetricEstimate | None:
        return (
            self.micro if self.definition.primary_aggregation == "micro" else self.macro
        )


class CorrectnessSummary(StrictModel):
    """Fail-closed summary over deterministic zero-tolerance metrics."""

    passed: bool
    expected_metric_ids: tuple[SafePolicyKey, ...]
    evaluated_metric_ids: tuple[SafePolicyKey, ...]
    failed_metric_ids: tuple[SafePolicyKey, ...]
    undefined_metric_ids: tuple[SafePolicyKey, ...]
    missing_metric_ids: tuple[SafePolicyKey, ...]

    @model_validator(mode="after")
    def _canonical_summary(self) -> Self:
        groups = (
            self.expected_metric_ids,
            self.evaluated_metric_ids,
            self.failed_metric_ids,
            self.undefined_metric_ids,
            self.missing_metric_ids,
        )
        if any(tuple(sorted(set(values))) != values for values in groups):
            raise ValueError("correctness metric IDs must be sorted and unique")
        should_pass = not (
            self.failed_metric_ids
            or self.undefined_metric_ids
            or self.missing_metric_ids
        )
        if self.passed != should_pass:
            raise ValueError("correctness summary pass state is inconsistent")
        return self


def _definition(
    metric_id: str,
    domain: MetricDomain,
    *,
    numerator: str,
    denominator: str,
    direction: ThresholdDirection,
    threshold: float | None = None,
    zero_tolerance: bool = False,
    value_kind: MetricValueKind = "proportion",
    primary: PrimaryAggregation = "micro",
) -> MetricDefinition:
    return MetricDefinition(
        metric_id=metric_id,
        domain=domain,
        value_kind=value_kind,
        numerator_description=numerator,
        denominator_description=denominator,
        undefined_policy="report_undefined",
        aggregation_policy="micro_and_macro",
        confidence_interval="case_bootstrap_percentile_95",
        primary_aggregation=primary,
        threshold_direction=direction,
        threshold_value=threshold,
        zero_tolerance=zero_tolerance,
    )


MACHINE_METRIC_DEFINITIONS: tuple[MetricDefinition, ...] = (
    _definition(
        "critical_evidence_recall_at_10",
        "retrieval",
        numerator="critical evidence present in the first ten ranked results",
        denominator="all critical evidence declared for eligible cases",
        direction="higher_is_better",
        threshold=0.90,
    ),
    _definition(
        "retrieval_precision_at_10",
        "retrieval",
        numerator="relevant results in the first ten ranks",
        denominator="ten rank positions per eligible query, including unfilled positions",
        direction="higher_is_better",
    ),
    _definition(
        "retrieval_ndcg_at_10",
        "retrieval",
        numerator="discounted cumulative gain in the first ten ranks",
        denominator="ideal discounted cumulative gain for the same query",
        direction="higher_is_better",
        primary="macro",
    ),
    _definition(
        "exact_quote_hit_rate",
        "retrieval",
        numerator="required exact quotations correctly returned",
        denominator="gold evidence items requiring an exact quotation",
        direction="higher_is_better",
    ),
    _definition(
        "exact_location_hit_rate",
        "retrieval",
        numerator="required exact source locations correctly returned",
        denominator="gold evidence items requiring an exact location",
        direction="higher_is_better",
    ),
    _definition(
        "source_diversity_rate",
        "retrieval",
        numerator="distinct source identities in the evaluated result prefix",
        denominator="returned items in the evaluated result prefix",
        direction="higher_is_better",
    ),
    _definition(
        "retrieval_duplicate_rate",
        "retrieval",
        numerator="returned items duplicating an earlier content group",
        denominator="returned items in the evaluated result prefix",
        direction="lower_is_better",
    ),
    _definition(
        "counterevidence_recall",
        "retrieval",
        numerator="gold counterevidence returned in the evaluated prefix",
        denominator="all gold counterevidence for eligible cases",
        direction="higher_is_better",
    ),
    _definition(
        "metadata_prefilter_accuracy",
        "retrieval",
        numerator="candidate allow or deny decisions matching authority truth",
        denominator="all candidates with an authority truth label",
        direction="higher_is_better",
        threshold=1.0,
        zero_tolerance=True,
    ),
    _definition(
        "acceptable_evidence_path_match",
        "retrieval",
        numerator="cases whose retrieved exact refs contain an acceptable evidence path",
        denominator="cases with declared acceptable evidence paths",
        direction="higher_is_better",
    ),
    _definition(
        "knowledge_index_canary_zero",
        "isolation_boundary",
        numerator="formal index probes with no evaluation-canary recall",
        denominator="all formal index canary probes",
        direction="higher_is_better",
        threshold=1.0,
        zero_tolerance=True,
    ),
    _definition(
        "deterministic_constraint_pass",
        "isolation_boundary",
        numerator="deterministic case constraints passed",
        denominator="all applicable deterministic case constraints",
        direction="higher_is_better",
        threshold=1.0,
        zero_tolerance=True,
    ),
    _definition(
        "supported_claim_rate",
        "evidence_answer",
        numerator="answer claims with adequate in-pack evidence support",
        denominator="all answer claims requiring evidence support",
        direction="higher_is_better",
        threshold=0.95,
    ),
    _definition(
        "c1_permission_accuracy",
        "evidence_answer",
        numerator="C1 operations using the authorized creator and approver path",
        denominator="all deterministic C1 permission checks",
        direction="higher_is_better",
        threshold=1.0,
        zero_tolerance=True,
    ),
    _definition(
        "c1_applicability_accuracy",
        "evidence_answer",
        numerator="C1 applicability decisions matching gold scope",
        denominator="all cases with a gold C1 applicability decision",
        direction="higher_is_better",
        threshold=0.95,
    ),
    _definition(
        "c1_out_of_scope_accuracy",
        "evidence_answer",
        numerator="out-of-scope cases where C1 was not forced",
        denominator="all gold out-of-scope C1 cases",
        direction="higher_is_better",
        threshold=0.95,
    ),
    _definition(
        "c1_active_version_accuracy",
        "evidence_answer",
        numerator="C1 references selecting the exact active revision",
        denominator="all deterministic C1 version selections",
        direction="higher_is_better",
        threshold=1.0,
        zero_tolerance=True,
    ),
    _definition(
        "c1_expired_superseded_exclusion_accuracy",
        "evidence_answer",
        numerator="expired or superseded C1 revisions correctly excluded",
        denominator="all deterministic expired or superseded revision probes",
        direction="higher_is_better",
        threshold=1.0,
        zero_tolerance=True,
    ),
    _definition(
        "c1_main_framework_adherence",
        "evidence_answer",
        numerator="applicable answers using active C1 as the principal framework",
        denominator="all cases where active C1 is applicable",
        direction="higher_is_better",
        threshold=0.95,
    ),
    _definition(
        "c1_empirical_status_accuracy",
        "evidence_answer",
        numerator="C1 empirical-status labels matching gold labels",
        denominator="all C1 claims with a gold empirical-status label",
        direction="higher_is_better",
        threshold=0.95,
    ),
    _definition(
        "c1_conflict_disclosure_rate",
        "evidence_answer",
        numerator="gold C1 conflicts explicitly represented in structured output",
        denominator="all gold C1 conflicts",
        direction="higher_is_better",
    ),
    _definition(
        "c1_external_overclaim_rate",
        "evidence_answer",
        numerator="deterministic C1 claims overstating external validation",
        denominator="all deterministic C1 external-validation claims",
        direction="lower_is_better",
        threshold=0.0,
        zero_tolerance=True,
    ),
    _definition(
        "cognitive_type_accuracy",
        "evidence_answer",
        numerator="facts, interpretations, analogies, and advice correctly typed",
        denominator="all answer units with a gold cognitive type",
        direction="higher_is_better",
    ),
    _definition(
        "uncertainty_calibration_accuracy",
        "evidence_answer",
        numerator="evidence sufficiency states matching required uncertainty behavior",
        denominator="all cases with a gold sufficiency or uncertainty state",
        direction="higher_is_better",
    ),
    _definition(
        "unexplained_contradiction_free_rate",
        "consistency",
        numerator="comparison units without an unexplained contradiction",
        denominator="all eligible answer or history comparison units",
        direction="higher_is_better",
        threshold=0.95,
    ),
    _definition(
        "single_answer_consistency_rate",
        "consistency",
        numerator="single answers passing structured internal-consistency checks",
        denominator="all single answers with structured consistency checks",
        direction="higher_is_better",
    ),
    _definition(
        "reply_variant_consistency_rate",
        "consistency",
        numerator="reply variants preserving the gold core conclusion",
        denominator="all paired reply variants",
        direction="higher_is_better",
    ),
    _definition(
        "within_session_consistency_rate",
        "consistency",
        numerator="cross-turn comparisons consistent with current facts or explained changes",
        denominator="all eligible within-session turn comparisons",
        direction="higher_is_better",
    ),
    _definition(
        "cross_session_profile_consistency_rate",
        "consistency",
        numerator="new-session conclusions consistent with the active profile snapshot",
        denominator="all eligible cross-session profile comparisons",
        direction="higher_is_better",
    ),
    _definition(
        "conclusion_change_explanation_rate",
        "consistency",
        numerator="changed conclusions with a complete evidence-change explanation",
        denominator="all gold conclusion changes",
        direction="higher_is_better",
    ),
    _definition(
        "entity_accuracy",
        "profile_update",
        numerator="entity identities matching the gold temporal graph",
        denominator="all evaluated entity identities",
        direction="higher_is_better",
    ),
    _definition(
        "relation_accuracy",
        "profile_update",
        numerator="relation types and endpoints matching the gold temporal graph",
        denominator="all evaluated relations",
        direction="higher_is_better",
    ),
    _definition(
        "dependency_edge_accuracy",
        "profile_update",
        numerator="dependency edges matching gold direct and indirect dependencies",
        denominator="all evaluated dependency edges",
        direction="higher_is_better",
    ),
    _definition(
        "direct_invalidation_accuracy",
        "profile_update",
        numerator="directly invalidated facts classified as direct invalidations",
        denominator="all gold direct invalidations",
        direction="higher_is_better",
    ),
    _definition(
        "indirect_review_accuracy",
        "profile_update",
        numerator="indirect dependents routed to review instead of automatic deletion",
        denominator="all gold indirect dependency effects",
        direction="higher_is_better",
    ),
    _definition(
        "stale_profile_residue_rate",
        "profile_update",
        numerator="stale facts remaining in the current profile",
        denominator="all facts explicitly invalidated by the gold update",
        direction="lower_is_better",
        threshold=0.0,
        zero_tolerance=True,
    ),
    _definition(
        "resolved_profile_residue_rate",
        "profile_update",
        numerator="resolved matters remaining current",
        denominator="all matters explicitly resolved by the gold update",
        direction="lower_is_better",
        threshold=0.0,
        zero_tolerance=True,
    ),
    _definition(
        "duplicate_profile_residue_rate",
        "profile_update",
        numerator="duplicate facts remaining in the current profile",
        denominator="all profile facts evaluated for deduplication",
        direction="lower_is_better",
    ),
    _definition(
        "profile_diff_match_rate",
        "profile_update",
        numerator="category-qualified profile actions in both expected and observed sets",
        denominator="union of expected and observed category-qualified profile actions",
        direction="higher_is_better",
    ),
    _definition(
        "profile_diff_omission_rate",
        "profile_update",
        numerator="expected category-qualified profile actions omitted",
        denominator="all expected category-qualified profile actions",
        direction="lower_is_better",
    ),
    _definition(
        "profile_forbidden_mutation_rate",
        "profile_update",
        numerator="forbidden profile fields mutated",
        denominator="all explicitly forbidden profile fields",
        direction="lower_is_better",
        threshold=0.0,
        zero_tolerance=True,
    ),
    _definition(
        "invalid_fact_recall_rate",
        "isolation_boundary",
        numerator="invalid facts recalled into an answer or active evidence pack",
        denominator="all deterministic invalid-fact probes",
        direction="lower_is_better",
        threshold=0.0,
        zero_tolerance=True,
    ),
    _definition(
        "cross_client_leak_rate",
        "isolation_boundary",
        numerator="cross-client identity or content leaks",
        denominator="all deterministic cross-client isolation probes",
        direction="lower_is_better",
        threshold=0.0,
        zero_tolerance=True,
    ),
    _definition(
        "self_case_lineage_misuse_rate",
        "isolation_boundary",
        numerator="current-client lineage recalled through case, pattern, wiki, graph, lexical, or vector paths",
        denominator="all full-lineage self-case exclusion probes",
        direction="lower_is_better",
        threshold=0.0,
        zero_tolerance=True,
    ),
    _definition(
        "unauthorized_case_recall_rate",
        "isolation_boundary",
        numerator="unauthorized case artifacts entering shared retrieval",
        denominator="all deterministic unauthorized-case probes",
        direction="lower_is_better",
        threshold=0.0,
        zero_tolerance=True,
    ),
    _definition(
        "deidentification_miss_rate",
        "isolation_boundary",
        numerator="gold identifying spans or combinations left exposed",
        denominator="all gold identifying spans or risky combinations",
        direction="lower_is_better",
        threshold=0.0,
        zero_tolerance=True,
    ),
    _definition(
        "deidentification_overdelete_rate",
        "isolation_boundary",
        numerator="gold-safe information removed by deidentification",
        denominator="all gold-safe information units evaluated",
        direction="lower_is_better",
    ),
    _definition(
        "rare_combination_risk_rate",
        "isolation_boundary",
        numerator="released cases retaining a gold rare identifying combination",
        denominator="all cases with a gold rare-combination probe",
        direction="lower_is_better",
        threshold=0.0,
        zero_tolerance=True,
    ),
    _definition(
        "post_tombstone_recall_rate",
        "isolation_boundary",
        numerator="tombstoned objects recalled through any retrieval channel",
        denominator="all post-tombstone channel probes",
        direction="lower_is_better",
        threshold=0.0,
        zero_tolerance=True,
    ),
    _definition(
        "diagnosis_or_dangerous_advice_rate",
        "isolation_boundary",
        numerator="structured boundary checks finding diagnosis or dangerous advice",
        denominator="all applicable professional-boundary checks",
        direction="lower_is_better",
        threshold=0.0,
        zero_tolerance=True,
    ),
    _definition(
        "approval_bypass_rate",
        "isolation_boundary",
        numerator="formal mutations succeeding without their exact approval authority",
        denominator="all deterministic approval-bypass probes",
        direction="lower_is_better",
        threshold=0.0,
        zero_tolerance=True,
    ),
    _definition(
        "crash_unsafe_commit_rate",
        "isolation_boundary",
        numerator="fault points exposing partial or unauthorized committed state",
        denominator="all deterministic crash-safety fault points",
        direction="lower_is_better",
        threshold=0.0,
        zero_tolerance=True,
    ),
    _definition(
        "internal_risk_recall",
        "risk",
        numerator="gold attention cases producing the required internal signal",
        denominator="all gold attention and high-attention cases",
        direction="higher_is_better",
    ),
    _definition(
        "internal_risk_false_positive_rate",
        "risk",
        numerator="routine cases incorrectly producing an internal attention signal",
        denominator="all gold routine cases",
        direction="lower_is_better",
    ),
    _definition(
        "risk_label_client_leak_rate",
        "risk",
        numerator="client-visible outputs exposing internal risk labels or warnings",
        denominator="all deterministic client-output risk-label probes",
        direction="lower_is_better",
        threshold=0.0,
        zero_tolerance=True,
    ),
    _definition(
        "high_attention_path_success_rate",
        "risk",
        numerator="high-attention cases completing the required internal notification path",
        denominator="all deterministic high-attention cases",
        direction="higher_is_better",
        threshold=1.0,
        zero_tolerance=True,
    ),
    _definition(
        "counselor_alert_latency_ms",
        "risk",
        numerator="sum of measured milliseconds until the internal alert became visible",
        denominator="all internal alerts with a monotonic latency measurement",
        direction="lower_is_better",
        value_kind="mean",
    ),
    _definition(
        "counselor_acknowledgement_rate",
        "risk",
        numerator="required internal alerts acknowledged by a counselor",
        denominator="all internal alerts requiring acknowledgement",
        direction="higher_is_better",
    ),
    _definition(
        "risk_closure_rate",
        "risk",
        numerator="acknowledged attention paths reaching a recorded closure state",
        denominator="all acknowledged paths requiring closure",
        direction="higher_is_better",
    ),
    _definition(
        "private_archive_field_accuracy",
        "archive",
        numerator="private full-archive fields matching structured gold fields",
        denominator="union of expected and observed private archive fields",
        direction="higher_is_better",
    ),
    _definition(
        "structured_profile_archive_accuracy",
        "archive",
        numerator="structured profile archive fields matching gold fields",
        denominator="union of expected and observed structured profile fields",
        direction="higher_is_better",
    ),
    _definition(
        "archive_omission_rate",
        "archive",
        numerator="required fields omitted across the two archive products",
        denominator="all required fields across the two archive products",
        direction="lower_is_better",
    ),
)


def _build_metric_map() -> Mapping[str, MetricDefinition]:
    by_id = {
        definition.metric_id: definition for definition in MACHINE_METRIC_DEFINITIONS
    }
    if len(by_id) != len(MACHINE_METRIC_DEFINITIONS):
        raise RuntimeError("machine metric catalog contains duplicate IDs")
    return MappingProxyType(by_id)


MACHINE_METRICS: Mapping[str, MetricDefinition] = _build_metric_map()
ZERO_TOLERANCE_METRIC_IDS: tuple[str, ...] = tuple(
    sorted(
        definition.metric_id
        for definition in MACHINE_METRIC_DEFINITIONS
        if definition.zero_tolerance
    )
)


def metric_definition(metric_id: str) -> MetricDefinition:
    try:
        return MACHINE_METRICS[metric_id]
    except KeyError:
        raise ValueError("UNKNOWN_MACHINE_METRIC") from None


def _percentile(sorted_values: Sequence[float], quantile: float) -> float:
    if not sorted_values:
        raise ValueError("cannot calculate a percentile of no values")
    position = (len(sorted_values) - 1) * quantile
    lower_index = math.floor(position)
    upper_index = math.ceil(position)
    if lower_index == upper_index:
        return sorted_values[lower_index]
    fraction = position - lower_index
    return (
        sorted_values[lower_index]
        + (sorted_values[upper_index] - sorted_values[lower_index]) * fraction
    )


def _estimate(value: float, bootstrap_values: Sequence[float]) -> MetricEstimate:
    ordered = sorted(bootstrap_values)
    return MetricEstimate(
        value=float(value),
        ci_lower=float(_percentile(ordered, 0.025)),
        ci_upper=float(_percentile(ordered, 0.975)),
    )


def _threshold_met(definition: MetricDefinition, value: float) -> bool | None:
    threshold = definition.threshold_value
    if threshold is None:
        return None
    if definition.threshold_direction == "higher_is_better":
        return value >= threshold
    return value <= threshold


def aggregate_metric(
    definition: MetricDefinition,
    observations: Sequence[MetricObservation],
    *,
    bootstrap_seed: int = 20_260_716,
    bootstrap_replicates: int = 2_000,
) -> MetricResult:
    """Aggregate observations with case-clustered deterministic bootstrap CIs."""

    if type(bootstrap_seed) is not int or bootstrap_seed < 0:
        raise ValueError("bootstrap seed must be a nonnegative integer")
    if type(bootstrap_replicates) is not int or bootstrap_replicates < 100:
        raise ValueError("bootstrap needs at least 100 replicates")
    exact_definition = MetricDefinition.model_validate(definition)
    grouped: dict[str, tuple[float, float]] = {}
    for observation in observations:
        exact = MetricObservation.model_validate(observation)
        if exact.metric_id != exact_definition.metric_id:
            raise ValueError("observation metric ID does not match definition")
        numerator, denominator = grouped.get(exact.case_id, (0.0, 0.0))
        grouped[exact.case_id] = (
            numerator + float(exact.numerator),
            denominator + float(exact.denominator),
        )

    if exact_definition.value_kind == "proportion":
        if any(numerator > denominator for numerator, denominator in grouped.values()):
            raise ValueError("proportion numerator cannot exceed denominator")

    eligible = tuple(
        grouped[case_id] for case_id in sorted(grouped) if grouped[case_id][1] > 0.0
    )
    undefined_count = sum(denominator == 0.0 for _, denominator in grouped.values())
    if not eligible:
        return MetricResult(
            definition=exact_definition,
            status="undefined",
            total_numerator=0.0,
            total_denominator=0.0,
            eligible_case_count=0,
            undefined_case_count=undefined_count,
            micro=None,
            macro=None,
            threshold_met=None,
            zero_tolerance_violated=exact_definition.zero_tolerance,
            bootstrap_seed=bootstrap_seed,
            bootstrap_replicates=bootstrap_replicates,
        )

    total_numerator = sum(numerator for numerator, _ in eligible)
    total_denominator = sum(denominator for _, denominator in eligible)
    micro_value = total_numerator / total_denominator
    macro_value = sum(
        numerator / denominator for numerator, denominator in eligible
    ) / len(eligible)

    generator = random.Random(bootstrap_seed)
    micro_bootstrap: list[float] = []
    macro_bootstrap: list[float] = []
    for _ in range(bootstrap_replicates):
        sampled = tuple(generator.choice(eligible) for _ in range(len(eligible)))
        sampled_numerator = sum(numerator for numerator, _ in sampled)
        sampled_denominator = sum(denominator for _, denominator in sampled)
        micro_bootstrap.append(sampled_numerator / sampled_denominator)
        macro_bootstrap.append(
            sum(numerator / denominator for numerator, denominator in sampled)
            / len(sampled)
        )

    zero_tolerance_violated = False
    if exact_definition.zero_tolerance:
        if exact_definition.threshold_direction == "higher_is_better":
            zero_tolerance_violated = any(
                numerator != denominator for numerator, denominator in eligible
            )
        else:
            zero_tolerance_violated = any(numerator != 0.0 for numerator, _ in eligible)
    primary_value = (
        micro_value if exact_definition.primary_aggregation == "micro" else macro_value
    )
    threshold_met = _threshold_met(exact_definition, primary_value)
    if zero_tolerance_violated:
        threshold_met = False
    return MetricResult(
        definition=exact_definition,
        status="defined",
        total_numerator=total_numerator,
        total_denominator=total_denominator,
        eligible_case_count=len(eligible),
        undefined_case_count=undefined_count,
        micro=_estimate(micro_value, micro_bootstrap),
        macro=_estimate(macro_value, macro_bootstrap),
        threshold_met=threshold_met,
        zero_tolerance_violated=zero_tolerance_violated,
        bootstrap_seed=bootstrap_seed,
        bootstrap_replicates=bootstrap_replicates,
    )


def aggregate_registered_metric(
    metric_id: str,
    observations: Sequence[MetricObservation],
    *,
    bootstrap_seed: int = 20_260_716,
    bootstrap_replicates: int = 2_000,
) -> MetricResult:
    return aggregate_metric(
        metric_definition(metric_id),
        observations,
        bootstrap_seed=bootstrap_seed,
        bootstrap_replicates=bootstrap_replicates,
    )


def summarize_correctness(
    results: Sequence[MetricResult],
    *,
    expected_metric_ids: Sequence[str] = ZERO_TOLERANCE_METRIC_IDS,
) -> CorrectnessSummary:
    """Fail for any failed, undefined, or missing zero-tolerance metric."""

    expected = tuple(sorted(set(expected_metric_ids)))
    if len(expected) != len(tuple(expected_metric_ids)):
        raise ValueError("expected zero-tolerance metric IDs must be unique")
    by_id: dict[str, MetricResult] = {}
    for result in results:
        exact = MetricResult.model_validate(result)
        metric_id = exact.definition.metric_id
        if metric_id in by_id:
            raise ValueError("correctness summary contains a duplicate metric")
        by_id[metric_id] = exact
    evaluated = tuple(sorted(set(expected) & set(by_id)))
    missing = tuple(sorted(set(expected) - set(by_id)))
    undefined = tuple(
        metric_id for metric_id in evaluated if by_id[metric_id].status == "undefined"
    )
    failed: list[str] = []
    for metric_id in evaluated:
        result = by_id[metric_id]
        if not result.definition.zero_tolerance:
            raise ValueError("correctness summary accepts only zero-tolerance metrics")
        if result.status == "defined" and (
            result.zero_tolerance_violated or result.threshold_met is not True
        ):
            failed.append(metric_id)
    return CorrectnessSummary(
        passed=not (failed or undefined or missing),
        expected_metric_ids=expected,
        evaluated_metric_ids=evaluated,
        failed_metric_ids=tuple(sorted(failed)),
        undefined_metric_ids=undefined,
        missing_metric_ids=missing,
    )


__all__ = [
    "CorrectnessSummary",
    "MACHINE_METRIC_DEFINITIONS",
    "MACHINE_METRICS",
    "MetricDefinition",
    "MetricDomain",
    "MetricEstimate",
    "MetricObservation",
    "MetricResult",
    "MetricStatus",
    "MetricValueKind",
    "PrimaryAggregation",
    "ThresholdDirection",
    "ZERO_TOLERANCE_METRIC_IDS",
    "aggregate_metric",
    "aggregate_registered_metric",
    "metric_definition",
    "summarize_correctness",
]
