"""Structured deterministic scorers for consultation evaluation.

The scorers consume exact IDs, labels, booleans, and field sets emitted by
governed evaluators.  They deliberately do not inspect answer wording to infer
empathy, helpfulness, paraphrase fidelity, or other expert judgments.  Human
rubric fields become pending annotation requests and receive no synthetic
machine score.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence, Set
from typing import Literal

from pydantic import field_validator, model_validator
from typing_extensions import Self

from consultation_kb.evaluation.metrics import (
    MetricObservation,
    metric_definition,
)
from consultation_kb.models.common import (
    NonEmptyStr,
    PositiveInt,
    SafePolicyKey,
    StrictModel,
    VersionRef,
)
from consultation_kb.models.evaluation import EvaluationCase, ExpectedProfileDiff


def _validate_cutoff(k: int) -> int:
    if type(k) is not int or k <= 0:
        raise ValueError("retrieval cutoff must be a positive integer")
    return k


def _validate_ranked_ids(ranked_ids: Sequence[str]) -> tuple[str, ...]:
    ranked = tuple(ranked_ids)
    if any(type(item) is not str or not item for item in ranked):
        raise ValueError("ranked evidence IDs must be nonempty strings")
    if len(set(ranked)) != len(ranked):
        raise ValueError("ranked evidence IDs must be unique")
    return ranked


def _validate_relevant_ids(relevant_ids: Set[str]) -> frozenset[str]:
    relevant = frozenset(relevant_ids)
    if any(type(item) is not str or not item for item in relevant):
        raise ValueError("relevant evidence IDs must be nonempty strings")
    return relevant


def recall_at_k(
    ranked_ids: Sequence[str],
    relevant_ids: Set[str],
    k: int,
) -> float | None:
    """Return hits/all relevant; no relevant items is explicitly undefined."""

    ranked = _validate_ranked_ids(ranked_ids)
    relevant = _validate_relevant_ids(relevant_ids)
    cutoff = _validate_cutoff(k)
    if not relevant:
        return None
    return len(set(ranked[:cutoff]) & relevant) / len(relevant)


def precision_at_k(
    ranked_ids: Sequence[str],
    relevant_ids: Set[str],
    k: int,
) -> float:
    """Return relevant hits/k; unfilled rank positions count as nonrelevant."""

    ranked = _validate_ranked_ids(ranked_ids)
    relevant = _validate_relevant_ids(relevant_ids)
    cutoff = _validate_cutoff(k)
    return len(set(ranked[:cutoff]) & relevant) / cutoff


def _validate_relevance(
    relevance_by_id: Mapping[str, int],
) -> dict[str, int]:
    result: dict[str, int] = {}
    for evidence_id, grade in relevance_by_id.items():
        if type(evidence_id) is not str or not evidence_id:
            raise ValueError("relevance IDs must be nonempty strings")
        if type(grade) is not int or grade < 0:
            raise ValueError("relevance grades must be nonnegative integers")
        result[evidence_id] = grade
    return result


def _dcg(grades: Sequence[int]) -> float:
    return float(
        sum(
            (2**grade - 1) / math.log2(rank + 1)
            for rank, grade in enumerate(grades, start=1)
        )
    )


def ndcg_at_k(
    ranked_ids: Sequence[str],
    relevance_by_id: Mapping[str, int],
    k: int,
) -> float | None:
    """Use exponential gain and log2 discount; zero ideal gain is undefined."""

    ranked = _validate_ranked_ids(ranked_ids)
    relevance = _validate_relevance(relevance_by_id)
    cutoff = _validate_cutoff(k)
    actual = [relevance.get(evidence_id, 0) for evidence_id in ranked[:cutoff]]
    ideal = sorted(relevance.values(), reverse=True)[:cutoff]
    ideal_dcg = _dcg(ideal)
    if ideal_dcg == 0.0:
        return None
    return _dcg(actual) / ideal_dcg


def reciprocal_rank(
    ranked_ids: Sequence[str],
    relevant_ids: Set[str],
) -> float | None:
    """Return the reciprocal rank of the first relevant result."""

    ranked = _validate_ranked_ids(ranked_ids)
    relevant = _validate_relevant_ids(relevant_ids)
    if not relevant:
        return None
    for rank, evidence_id in enumerate(ranked, start=1):
        if evidence_id in relevant:
            return 1.0 / rank
    return 0.0


class GoldEvidence(StrictModel):
    evidence_id: NonEmptyStr
    source_id: NonEmptyStr
    relevance_grade: PositiveInt
    is_counterevidence: bool
    requires_exact_quote: bool
    requires_exact_location: bool


class RetrievedEvidence(StrictModel):
    evidence_id: NonEmptyStr
    source_id: NonEmptyStr
    duplicate_group_id: NonEmptyStr
    exact_quote_match: bool
    exact_location_match: bool


class PrefilterDecision(StrictModel):
    candidate_id: NonEmptyStr
    expected_allowed: bool
    actual_allowed: bool


class RetrievalScoringInput(StrictModel):
    case_id: SafePolicyKey
    ranked: tuple[RetrievedEvidence, ...]
    gold: tuple[GoldEvidence, ...]
    prefilter_decisions: tuple[PrefilterDecision, ...]

    @model_validator(mode="after")
    def _unique_ids(self) -> Self:
        ranked_ids = tuple(item.evidence_id for item in self.ranked)
        gold_ids = tuple(item.evidence_id for item in self.gold)
        decision_ids = tuple(item.candidate_id for item in self.prefilter_decisions)
        if len(set(ranked_ids)) != len(ranked_ids):
            raise ValueError("ranked evidence IDs must be unique")
        if len(set(gold_ids)) != len(gold_ids):
            raise ValueError("gold evidence IDs must be unique")
        if len(set(decision_ids)) != len(decision_ids):
            raise ValueError("prefilter candidate IDs must be unique")
        return self


def machine_metric_observation(
    metric_id: str,
    case_id: str,
    *,
    numerator: int | float,
    denominator: int | float,
) -> MetricObservation:
    """Create one observation only for a registered machine-owned metric."""

    definition = metric_definition(metric_id)
    observation = MetricObservation(
        metric_id=metric_id,
        case_id=case_id,
        numerator=numerator,
        denominator=denominator,
    )
    if definition.value_kind == "proportion" and float(observation.numerator) > float(
        observation.denominator
    ):
        raise ValueError("proportion numerator cannot exceed denominator")
    return observation


def binary_accuracy_observation(
    metric_id: str,
    case_id: str,
    *,
    expected: object,
    actual: object,
    applicable: bool = True,
) -> MetricObservation:
    """Score exact structured equality; no text interpretation is performed."""

    definition = metric_definition(metric_id)
    if definition.value_kind != "proportion" or definition.threshold_direction != (
        "higher_is_better"
    ):
        raise ValueError("binary accuracy requires a higher-is-better proportion")
    return machine_metric_observation(
        metric_id,
        case_id,
        numerator=int(applicable and expected == actual),
        denominator=int(applicable),
    )


def adverse_event_observation(
    metric_id: str,
    case_id: str,
    *,
    occurred: bool,
    applicable: bool = True,
) -> MetricObservation:
    """Score a structured adverse event for a lower-is-better metric."""

    definition = metric_definition(metric_id)
    if definition.value_kind != "proportion" or definition.threshold_direction != (
        "lower_is_better"
    ):
        raise ValueError("adverse event requires a lower-is-better proportion")
    return machine_metric_observation(
        metric_id,
        case_id,
        numerator=int(applicable and occurred),
        denominator=int(applicable),
    )


def score_retrieval_at_10(
    values: RetrievalScoringInput,
) -> tuple[MetricObservation, ...]:
    """Score the tracked retrieval suite at the fixed production cutoff of ten."""

    exact = RetrievalScoringInput.model_validate(values)
    top = exact.ranked[:10]
    top_by_id = {item.evidence_id: item for item in top}
    gold_by_id = {item.evidence_id: item for item in exact.gold}
    relevant = set(gold_by_id)
    hits = relevant & set(top_by_id)
    actual_grades = [
        gold_by_id[item.evidence_id].relevance_grade
        if item.evidence_id in gold_by_id
        else 0
        for item in top
    ]
    ideal_grades = sorted(
        (item.relevance_grade for item in exact.gold),
        reverse=True,
    )[:10]
    ideal_dcg = _dcg(ideal_grades)
    quote_gold = tuple(item for item in exact.gold if item.requires_exact_quote)
    location_gold = tuple(item for item in exact.gold if item.requires_exact_location)
    counter_gold = tuple(item for item in exact.gold if item.is_counterevidence)
    quote_hits = sum(
        item.evidence_id in top_by_id and top_by_id[item.evidence_id].exact_quote_match
        for item in quote_gold
    )
    location_hits = sum(
        item.evidence_id in top_by_id
        and top_by_id[item.evidence_id].exact_location_match
        for item in location_gold
    )
    counter_hits = sum(item.evidence_id in top_by_id for item in counter_gold)
    distinct_sources = len({item.source_id for item in top})
    distinct_groups = len({item.duplicate_group_id for item in top})
    correct_prefilters = sum(
        item.actual_allowed == item.expected_allowed
        for item in exact.prefilter_decisions
    )
    return (
        machine_metric_observation(
            "critical_evidence_recall_at_10",
            exact.case_id,
            numerator=len(hits),
            denominator=len(relevant),
        ),
        machine_metric_observation(
            "retrieval_precision_at_10",
            exact.case_id,
            numerator=len(hits),
            denominator=10,
        ),
        machine_metric_observation(
            "retrieval_ndcg_at_10",
            exact.case_id,
            numerator=_dcg(actual_grades) if ideal_dcg > 0.0 else 0.0,
            denominator=ideal_dcg,
        ),
        machine_metric_observation(
            "exact_quote_hit_rate",
            exact.case_id,
            numerator=quote_hits,
            denominator=len(quote_gold),
        ),
        machine_metric_observation(
            "exact_location_hit_rate",
            exact.case_id,
            numerator=location_hits,
            denominator=len(location_gold),
        ),
        machine_metric_observation(
            "source_diversity_rate",
            exact.case_id,
            numerator=distinct_sources,
            denominator=len(top),
        ),
        machine_metric_observation(
            "retrieval_duplicate_rate",
            exact.case_id,
            numerator=len(top) - distinct_groups,
            denominator=len(top),
        ),
        machine_metric_observation(
            "counterevidence_recall",
            exact.case_id,
            numerator=counter_hits,
            denominator=len(counter_gold),
        ),
        machine_metric_observation(
            "metadata_prefilter_accuracy",
            exact.case_id,
            numerator=correct_prefilters,
            denominator=len(exact.prefilter_decisions),
        ),
    )


def _ref_key(reference: VersionRef) -> tuple[str, int, str]:
    return (reference.object_id, reference.version, reference.content_sha256)


def score_acceptable_evidence_path(
    case: EvaluationCase,
    retrieved_refs: Sequence[VersionRef],
) -> MetricObservation:
    """Match exact immutable refs against any declared acceptable path."""

    exact_case = EvaluationCase.model_validate(case)
    keys = tuple(_ref_key(VersionRef.model_validate(item)) for item in retrieved_refs)
    if len(set(keys)) != len(keys):
        raise ValueError("retrieved evaluation refs must be unique")
    retrieved = set(keys)
    matched = any(
        {_ref_key(reference) for reference in path.evidence_refs}.issubset(retrieved)
        for path in exact_case.acceptable_evidence_paths
    )
    return machine_metric_observation(
        "acceptable_evidence_path_match",
        exact_case.case_id,
        numerator=int(matched),
        denominator=1,
    )


class ObservedProfileDiff(StrictModel):
    set_fields: tuple[SafePolicyKey, ...] = ()
    invalidate_fields: tuple[SafePolicyKey, ...] = ()
    resolve_fields: tuple[SafePolicyKey, ...] = ()

    @model_validator(mode="after")
    def _canonical_fields(self) -> Self:
        groups = (self.set_fields, self.invalidate_fields, self.resolve_fields)
        if any(tuple(sorted(set(values))) != values for values in groups):
            raise ValueError("observed profile fields must be sorted and unique")
        flattened = tuple(value for values in groups for value in values)
        if len(set(flattened)) != len(flattened):
            raise ValueError("one observed field cannot have multiple actions")
        return self


def _profile_actions(
    set_fields: Sequence[str],
    invalidate_fields: Sequence[str],
    resolve_fields: Sequence[str],
) -> set[tuple[str, str]]:
    return {
        *(("set", field) for field in set_fields),
        *(("invalidate", field) for field in invalidate_fields),
        *(("resolve", field) for field in resolve_fields),
    }


def score_profile_diff(
    case_id: str,
    expected: ExpectedProfileDiff,
    actual: ObservedProfileDiff,
) -> tuple[MetricObservation, MetricObservation, MetricObservation]:
    """Score exact action+field sets, omissions, and forbidden mutations."""

    exact_expected = ExpectedProfileDiff.model_validate(expected)
    exact_actual = ObservedProfileDiff.model_validate(actual)
    expected_actions = _profile_actions(
        exact_expected.set_fields,
        exact_expected.invalidate_fields,
        exact_expected.resolve_fields,
    )
    actual_actions = _profile_actions(
        exact_actual.set_fields,
        exact_actual.invalidate_fields,
        exact_actual.resolve_fields,
    )
    union = expected_actions | actual_actions
    intersection = expected_actions & actual_actions
    omitted = expected_actions - actual_actions
    actual_fields = {field for _, field in actual_actions}
    forbidden = set(exact_expected.forbidden_fields)
    return (
        machine_metric_observation(
            "profile_diff_match_rate",
            case_id,
            numerator=len(intersection),
            denominator=len(union),
        ),
        machine_metric_observation(
            "profile_diff_omission_rate",
            case_id,
            numerator=len(omitted),
            denominator=len(expected_actions),
        ),
        machine_metric_observation(
            "profile_forbidden_mutation_rate",
            case_id,
            numerator=len(actual_fields & forbidden),
            denominator=len(forbidden),
        ),
    )


class ArchiveFieldScoringInput(StrictModel):
    case_id: SafePolicyKey
    expected_private_fields: tuple[SafePolicyKey, ...]
    actual_private_fields: tuple[SafePolicyKey, ...]
    expected_profile_fields: tuple[SafePolicyKey, ...]
    actual_profile_fields: tuple[SafePolicyKey, ...]

    @field_validator(
        "expected_private_fields",
        "actual_private_fields",
        "expected_profile_fields",
        "actual_profile_fields",
    )
    @classmethod
    def _canonical_field_set(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(values))) != values:
            raise ValueError("archive fields must be sorted and unique")
        return values


def score_archive_fields(
    values: ArchiveFieldScoringInput,
) -> tuple[MetricObservation, MetricObservation, MetricObservation]:
    exact = ArchiveFieldScoringInput.model_validate(values)
    expected_private = set(exact.expected_private_fields)
    actual_private = set(exact.actual_private_fields)
    expected_profile = set(exact.expected_profile_fields)
    actual_profile = set(exact.actual_profile_fields)
    private_union = expected_private | actual_private
    profile_union = expected_profile | actual_profile
    omission_count = len(expected_private - actual_private) + len(
        expected_profile - actual_profile
    )
    return (
        machine_metric_observation(
            "private_archive_field_accuracy",
            exact.case_id,
            numerator=len(expected_private & actual_private),
            denominator=len(private_union),
        ),
        machine_metric_observation(
            "structured_profile_archive_accuracy",
            exact.case_id,
            numerator=len(expected_profile & actual_profile),
            denominator=len(profile_union),
        ),
        machine_metric_observation(
            "archive_omission_rate",
            exact.case_id,
            numerator=omission_count,
            denominator=len(expected_private) + len(expected_profile),
        ),
    )


class PendingHumanAnnotation(StrictModel):
    """An expert-owned rubric item awaiting a real blinded annotation."""

    case_id: SafePolicyKey
    criterion_id: SafePolicyKey
    required: bool
    weight_milli: PositiveInt
    prompt: NonEmptyStr
    status: Literal["pending"] = "pending"


def pending_human_annotations(
    case: EvaluationCase,
) -> tuple[PendingHumanAnnotation, ...]:
    """Return expert work items without deriving any score from answer text."""

    exact = EvaluationCase.model_validate(case)
    return tuple(
        PendingHumanAnnotation(
            case_id=exact.case_id,
            criterion_id=criterion.criterion_id,
            required=criterion.required,
            weight_milli=criterion.weight_milli,
            prompt=criterion.human_prompt,
        )
        for criterion in exact.evaluator_rubric
        if criterion.owner == "human" and criterion.human_prompt is not None
    )


def machine_metric_requirements(case: EvaluationCase) -> tuple[str, ...]:
    """Resolve machine rubric declarations against the closed metric catalog."""

    exact = EvaluationCase.model_validate(case)
    metric_ids = tuple(
        criterion.machine_metric
        for criterion in exact.evaluator_rubric
        if criterion.owner == "machine" and criterion.machine_metric is not None
    )
    for metric_id in metric_ids:
        metric_definition(metric_id)
    return metric_ids


__all__ = [
    "ArchiveFieldScoringInput",
    "GoldEvidence",
    "ObservedProfileDiff",
    "PendingHumanAnnotation",
    "PrefilterDecision",
    "RetrievalScoringInput",
    "RetrievedEvidence",
    "adverse_event_observation",
    "binary_accuracy_observation",
    "machine_metric_observation",
    "machine_metric_requirements",
    "ndcg_at_k",
    "pending_human_annotations",
    "precision_at_k",
    "recall_at_k",
    "reciprocal_rank",
    "score_acceptable_evidence_path",
    "score_archive_fields",
    "score_profile_diff",
    "score_retrieval_at_10",
]
