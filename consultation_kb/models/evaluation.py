"""Strict immutable contracts for synthetic evaluation datasets.

Git-tracked evaluation fixtures are deliberately a narrower type than future
vault-registered controlled evaluations.  Every identifier, object reference,
and prose field in this module is synthetic-only; controlled client material
must use a separate catalog-backed boundary and cannot be parsed as this type.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal, TypeAlias

from pydantic import AfterValidator, Field, StringConstraints, model_validator
from typing_extensions import Self

from consultation_kb.models.common import (
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    VersionRef,
)


EvaluationSplit: TypeAlias = Literal["train", "dev", "test", "canary"]
EvaluationDatasetKind: TypeAlias = Literal[
    "gold_cases",
    "gold_retrieval",
    "canary_cases",
]
EvaluationSlice: TypeAlias = Literal[
    "authorization",
    "c1_aligned",
    "c1_applicable",
    "c1_conflicting",
    "c1_expired",
    "c1_out_of_scope",
    "c1_superseded",
    "career_freshness",
    "classical_commentary",
    "classical_original",
    "client_isolation",
    "cross_theory_analogy",
    "deduplication",
    "dependency_propagation",
    "evidence_conflict",
    "evidence_insufficient",
    "invalidation",
    "modern_interpretation",
    "problem_temporal_change",
    "relationship_consulting",
    "relationship_temporal_change",
    "risk",
    "self_case_exclusion",
    "goal_temporal_change",
]
RubricOwner: TypeAlias = Literal["machine", "human"]


MANDATORY_EVALUATION_SLICES: tuple[EvaluationSlice, ...] = (
    "authorization",
    "c1_aligned",
    "c1_applicable",
    "c1_conflicting",
    "c1_expired",
    "c1_out_of_scope",
    "c1_superseded",
    "career_freshness",
    "classical_commentary",
    "classical_original",
    "client_isolation",
    "cross_theory_analogy",
    "deduplication",
    "dependency_propagation",
    "evidence_conflict",
    "evidence_insufficient",
    "goal_temporal_change",
    "invalidation",
    "modern_interpretation",
    "problem_temporal_change",
    "relationship_consulting",
    "relationship_temporal_change",
    "risk",
    "self_case_exclusion",
)


_CLIENT_ID_RE = re.compile(r"client_[a-z0-9]{12}")
_EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?!\w)")
_MOBILE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
_NATIONAL_ID_RE = re.compile(r"(?<!\d)\d{17}[0-9Xx](?!\d)")


def _require_synthetic_text(value: str) -> str:
    """Reject common stable identity forms at the Git-fixture boundary."""

    if not value.strip():
        raise ValueError("synthetic evaluation text must not be blank")
    if _CLIENT_ID_RE.search(value):
        raise ValueError("synthetic evaluation text must not contain a client ID")
    if _EMAIL_RE.search(value) or _MOBILE_RE.search(value) or _NATIONAL_ID_RE.search(value):
        raise ValueError("synthetic evaluation text must not contain direct identity data")
    return value


SyntheticText: TypeAlias = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=4096),
    AfterValidator(_require_synthetic_text),
]


def _ref_key(reference: VersionRef) -> tuple[str, int, str]:
    return (reference.object_id, reference.version, reference.content_sha256)


def _require_canonical_keys(values: tuple[SafePolicyKey, ...], field_name: str) -> None:
    if not values:
        raise ValueError(f"{field_name} must not be empty")
    if tuple(sorted(set(values))) != values:
        raise ValueError(f"{field_name} must be sorted and unique")


def _require_canonical_refs(values: tuple[VersionRef, ...], field_name: str) -> None:
    if not values:
        raise ValueError(f"{field_name} must not be empty")
    keys = tuple(_ref_key(value) for value in values)
    if tuple(sorted(set(keys))) != keys:
        raise ValueError(f"{field_name} must be sorted and unique")


def _require_synthetic_ref(reference: VersionRef, field_name: str) -> None:
    if not reference.object_id.startswith("synthetic_"):
        raise ValueError(f"{field_name} must reference a synthetic object")


class EvaluationTurn(StrictModel):
    role: Literal["client", "consultant"]
    text: SyntheticText


class EvidencePath(StrictModel):
    path_id: SafePolicyKey
    evidence_refs: tuple[VersionRef, ...]
    reasoning_features: tuple[SafePolicyKey, ...]

    @model_validator(mode="after")
    def _canonical_path(self) -> Self:
        if not self.path_id.startswith("path_"):
            raise ValueError("evidence path ID must start with path_")
        _require_canonical_refs(self.evidence_refs, "evidence_refs")
        _require_canonical_keys(self.reasoning_features, "reasoning_features")
        for reference in self.evidence_refs:
            _require_synthetic_ref(reference, "evidence_refs")
        return self


class ConditionalPath(StrictModel):
    path_id: SafePolicyKey
    condition: SyntheticText
    expected_direction: SyntheticText

    @model_validator(mode="after")
    def _canonical_id(self) -> Self:
        if not self.path_id.startswith("condition_"):
            raise ValueError("conditional path ID must start with condition_")
        return self


class ExpectedProfileDiff(StrictModel):
    set_fields: tuple[SafePolicyKey, ...]
    invalidate_fields: tuple[SafePolicyKey, ...]
    resolve_fields: tuple[SafePolicyKey, ...]
    forbidden_fields: tuple[SafePolicyKey, ...]

    @model_validator(mode="after")
    def _canonical_fields(self) -> Self:
        groups = (
            (self.set_fields, "set_fields"),
            (self.invalidate_fields, "invalidate_fields"),
            (self.resolve_fields, "resolve_fields"),
            (self.forbidden_fields, "forbidden_fields"),
        )
        for values, field_name in groups:
            if tuple(sorted(set(values))) != values:
                raise ValueError(f"{field_name} must be sorted and unique")
        if not any(values for values, _ in groups):
            raise ValueError("profile diff must declare at least one expectation")
        changed = set(self.set_fields) | set(self.invalidate_fields) | set(self.resolve_fields)
        if changed & set(self.forbidden_fields):
            raise ValueError("profile diff cannot both require and forbid one field")
        return self


class RiskExpectation(StrictModel):
    level: Literal["routine", "attention", "high_attention"]
    counselor_attention_required: bool
    client_visible_warning: Literal[False] = False
    internal_actions: tuple[SafePolicyKey, ...]

    @model_validator(mode="after")
    def _risk_consistency(self) -> Self:
        if tuple(sorted(set(self.internal_actions))) != self.internal_actions:
            raise ValueError("internal_actions must be sorted and unique")
        if self.level == "routine" and self.counselor_attention_required:
            raise ValueError("routine risk cannot require counselor attention")
        if self.level != "routine" and not self.counselor_attention_required:
            raise ValueError("non-routine risk must require counselor attention")
        return self


class ArchiveExpectation(StrictModel):
    full_case_archive: Literal[True] = True
    structured_profile_update: bool
    shared_case_candidate: bool
    exclude_from_same_client_examples: Literal[True] = True
    required_actions: tuple[SafePolicyKey, ...]

    @model_validator(mode="after")
    def _canonical_actions(self) -> Self:
        _require_canonical_keys(self.required_actions, "required_actions")
        return self


class RubricCriterion(StrictModel):
    criterion_id: SafePolicyKey
    owner: RubricOwner
    required: bool
    weight_milli: Annotated[int, Field(strict=True, ge=1, le=1000)]
    machine_metric: SafePolicyKey | None = None
    human_prompt: SyntheticText | None = None

    @model_validator(mode="after")
    def _owner_contract(self) -> Self:
        if self.owner == "machine":
            if self.machine_metric is None or self.human_prompt is not None:
                raise ValueError("machine rubric must declare only machine_metric")
        elif self.human_prompt is None or self.machine_metric is not None:
            raise ValueError("human rubric must declare only human_prompt")
        return self


class EvaluationCase(StrictModel):
    record_type: Literal["case"] = "case"
    schema_version: Literal["evaluation_case.v1"] = "evaluation_case.v1"
    dataset_id: SafePolicyKey
    case_id: SafePolicyKey
    synthetic_client_key: SafePolicyKey
    sensitivity: Literal["synthetic"] = "synthetic"
    split: EvaluationSplit
    scenario_family: SafePolicyKey
    synthetic_client_snapshot_ref: VersionRef
    input_turns: tuple[EvaluationTurn, ...]
    critical_evidence_refs: tuple[VersionRef, ...]
    alternative_evidence_refs: tuple[VersionRef, ...]
    acceptable_evidence_paths: tuple[EvidencePath, ...]
    forbidden_source_refs: tuple[VersionRef, ...]
    forbidden_conclusions: tuple[SyntheticText, ...]
    core_answer_features: tuple[SafePolicyKey, ...]
    expected_profile_diff: ExpectedProfileDiff
    allowed_uncertainty: tuple[SyntheticText, ...]
    conditional_paths: tuple[ConditionalPath, ...]
    risk_expectation: RiskExpectation
    archive_expectation: ArchiveExpectation
    evaluator_rubric: tuple[RubricCriterion, ...]
    slices: tuple[EvaluationSlice, ...]

    @model_validator(mode="after")
    def _case_contract(self) -> Self:
        if not self.dataset_id.startswith("syn_dataset_"):
            raise ValueError("dataset ID must use the synthetic namespace")
        if not self.case_id.startswith("syn_case_"):
            raise ValueError("case ID must use the synthetic namespace")
        if not self.synthetic_client_key.startswith("syn_subject_"):
            raise ValueError("synthetic client key must use the synthetic namespace")
        if not self.scenario_family.startswith("syn_family_"):
            raise ValueError("scenario family must use the synthetic namespace")
        _require_synthetic_ref(
            self.synthetic_client_snapshot_ref,
            "synthetic_client_snapshot_ref",
        )
        if not self.synthetic_client_snapshot_ref.object_id.startswith(
            "synthetic_snapshot_"
        ):
            raise ValueError("client snapshot must use the synthetic snapshot kind")
        if not self.input_turns or self.input_turns[-1].role != "client":
            raise ValueError("input turns must end with a client turn")

        _require_canonical_refs(self.critical_evidence_refs, "critical_evidence_refs")
        _require_canonical_refs(
            self.alternative_evidence_refs,
            "alternative_evidence_refs",
        )
        _require_canonical_refs(self.forbidden_source_refs, "forbidden_source_refs")
        for reference in (
            *self.critical_evidence_refs,
            *self.alternative_evidence_refs,
            *self.forbidden_source_refs,
        ):
            _require_synthetic_ref(reference, "evaluation evidence")

        critical = {_ref_key(value) for value in self.critical_evidence_refs}
        alternatives = {_ref_key(value) for value in self.alternative_evidence_refs}
        forbidden = {_ref_key(value) for value in self.forbidden_source_refs}
        if critical & alternatives or (critical | alternatives) & forbidden:
            raise ValueError("critical, alternative, and forbidden evidence must be disjoint")

        if len(self.acceptable_evidence_paths) < 2:
            raise ValueError("each case must support at least two acceptable evidence paths")
        path_ids = tuple(path.path_id for path in self.acceptable_evidence_paths)
        if tuple(sorted(set(path_ids))) != path_ids:
            raise ValueError("acceptable evidence paths must be sorted and uniquely named")
        path_ref_sets: list[frozenset[tuple[str, int, str]]] = []
        for path in self.acceptable_evidence_paths:
            path_refs = frozenset(_ref_key(value) for value in path.evidence_refs)
            if not critical.issubset(path_refs):
                raise ValueError("every acceptable path must contain all critical evidence")
            if not path_refs & alternatives:
                raise ValueError("every acceptable path must select alternative evidence")
            if path_refs - critical - alternatives:
                raise ValueError("acceptable path references undeclared evidence")
            path_ref_sets.append(path_refs)
        if len(set(path_ref_sets)) != len(path_ref_sets):
            raise ValueError("acceptable evidence paths must be materially distinct")

        _require_canonical_keys(self.core_answer_features, "core_answer_features")
        if not self.forbidden_conclusions:
            raise ValueError("forbidden_conclusions must not be empty")
        if not self.allowed_uncertainty:
            raise ValueError("allowed_uncertainty must not be empty")
        condition_ids = tuple(path.path_id for path in self.conditional_paths)
        if not condition_ids or tuple(sorted(set(condition_ids))) != condition_ids:
            raise ValueError("conditional paths must be sorted, non-empty, and unique")

        rubric_ids = tuple(item.criterion_id for item in self.evaluator_rubric)
        if tuple(sorted(set(rubric_ids))) != rubric_ids:
            raise ValueError("rubric criteria must be sorted and unique")
        owners = {item.owner for item in self.evaluator_rubric}
        if owners != {"machine", "human"}:
            raise ValueError("rubric must explicitly assign machine and human criteria")
        if tuple(sorted(set(self.slices))) != self.slices:
            raise ValueError("slices must be sorted, non-empty, and unique")
        if not self.slices:
            raise ValueError("slices must not be empty")
        return self

    def referenced_objects(self) -> tuple[VersionRef, ...]:
        """Return all exact object versions required to validate this case."""

        refs = {
            _ref_key(reference): reference
            for reference in (
                self.synthetic_client_snapshot_ref,
                *self.critical_evidence_refs,
                *self.alternative_evidence_refs,
                *self.forbidden_source_refs,
            )
        }
        for path in self.acceptable_evidence_paths:
            refs.update({_ref_key(reference): reference for reference in path.evidence_refs})
        return tuple(refs[key] for key in sorted(refs))


class EvaluationDatasetManifest(StrictModel):
    record_type: Literal["manifest"] = "manifest"
    schema_version: Literal["evaluation_dataset_manifest.v1"] = (
        "evaluation_dataset_manifest.v1"
    )
    dataset_id: SafePolicyKey
    dataset_kind: EvaluationDatasetKind
    dataset_version: PositiveInt
    synthetic_only: Literal[True] = True
    sensitivity: Literal["synthetic"] = "synthetic"
    knowledge_index_use: Literal["forbidden"] = "forbidden"
    policy_ref: VersionRef
    object_catalog: tuple[VersionRef, ...]
    declared_splits: tuple[EvaluationSplit, ...]
    declared_slices: tuple[EvaluationSlice, ...]
    record_count: PositiveInt
    records_sha256: Sha256Hex

    @model_validator(mode="after")
    def _manifest_contract(self) -> Self:
        if not self.dataset_id.startswith("syn_dataset_"):
            raise ValueError("dataset ID must use the synthetic namespace")
        _require_synthetic_ref(self.policy_ref, "policy_ref")
        if not self.policy_ref.object_id.startswith("synthetic_policy_"):
            raise ValueError("evaluation policy must use the synthetic policy kind")
        _require_canonical_refs(self.object_catalog, "object_catalog")
        catalog = {_ref_key(value) for value in self.object_catalog}
        if _ref_key(self.policy_ref) not in catalog:
            raise ValueError("policy_ref must resolve through object_catalog")
        for reference in self.object_catalog:
            _require_synthetic_ref(reference, "object_catalog")
        if tuple(sorted(set(self.declared_splits))) != self.declared_splits:
            raise ValueError("declared_splits must be sorted and unique")
        if tuple(sorted(set(self.declared_slices))) != self.declared_slices:
            raise ValueError("declared_slices must be sorted and unique")
        if self.dataset_kind == "canary_cases":
            if self.declared_splits != ("canary",):
                raise ValueError("canary dataset may contain only the canary split")
        elif "canary" in self.declared_splits:
            raise ValueError("gold datasets cannot contain the canary split")
        return self


class EvaluationDataset(StrictModel):
    manifest: EvaluationDatasetManifest
    cases: tuple[EvaluationCase, ...]
    file_sha256: Sha256Hex

    @model_validator(mode="after")
    def _dataset_contract(self) -> Self:
        if len(self.cases) != self.manifest.record_count:
            raise ValueError("dataset record count does not match manifest")
        case_ids = tuple(case.case_id for case in self.cases)
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("dataset case IDs must be unique")
        if any(case.dataset_id != self.manifest.dataset_id for case in self.cases):
            raise ValueError("case dataset ID does not match manifest")
        actual_splits = tuple(sorted({case.split for case in self.cases}))
        actual_slices = tuple(sorted({item for case in self.cases for item in case.slices}))
        if actual_splits != self.manifest.declared_splits:
            raise ValueError("dataset split declaration does not match records")
        if actual_slices != self.manifest.declared_slices:
            raise ValueError("dataset slice declaration does not match records")
        catalog = {_ref_key(reference) for reference in self.manifest.object_catalog}
        for case in self.cases:
            missing = {
                _ref_key(reference)
                for reference in case.referenced_objects()
                if _ref_key(reference) not in catalog
            }
            if missing:
                raise ValueError("case object reference is absent from immutable catalog")
        return self

    def cases_for_split(self, split: EvaluationSplit) -> tuple[EvaluationCase, ...]:
        return tuple(case for case in self.cases if case.split == split)


class SliceCoverage(StrictModel):
    slice: EvaluationSlice
    count: PositiveInt


class EvaluationDatasetBundle(StrictModel):
    datasets: tuple[EvaluationDataset, ...]
    slice_coverage: tuple[SliceCoverage, ...]
    bundle_sha256: Sha256Hex

    @model_validator(mode="after")
    def _bundle_contract(self) -> Self:
        dataset_ids = tuple(dataset.manifest.dataset_id for dataset in self.datasets)
        if tuple(sorted(set(dataset_ids))) != dataset_ids:
            raise ValueError("bundle datasets must be sorted and uniquely named")
        case_ids = tuple(case.case_id for dataset in self.datasets for case in dataset.cases)
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("bundle case IDs must be globally unique")
        slices = tuple(item.slice for item in self.slice_coverage)
        if tuple(sorted(set(slices))) != slices:
            raise ValueError("slice coverage must be sorted and unique")
        return self


__all__ = [
    "ArchiveExpectation",
    "ConditionalPath",
    "EvaluationCase",
    "EvaluationDataset",
    "EvaluationDatasetBundle",
    "EvaluationDatasetKind",
    "EvaluationDatasetManifest",
    "EvaluationSlice",
    "EvaluationSplit",
    "EvaluationTurn",
    "EvidencePath",
    "ExpectedProfileDiff",
    "MANDATORY_EVALUATION_SLICES",
    "RiskExpectation",
    "RubricCriterion",
    "RubricOwner",
    "SliceCoverage",
    "SyntheticText",
]
