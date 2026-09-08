"""Body-free durable work queue contracts for paired evaluation runs."""

from __future__ import annotations

import os
import threading
import uuid
from collections import Counter
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, field_validator, model_validator
from typing_extensions import Self

from consultation_kb.generation.contracts import FinalTurnBundle
from consultation_kb.knowledge._canonical import canonical_json_bytes, canonical_sha256
from consultation_kb.models.common import (
    NonNegativeInt,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    Uuid7String,
    VersionRef,
)
from consultation_kb.models.evaluation import EvaluationSplit
from consultation_kb.models.evidence import EvidenceChannel
from consultation_kb.observability.runs import (
    NamedVersionRef,
    RunManifestV2,
    RunReproducibilitySnapshot,
    RunVersionSnapshot,
    RuntimeEnvironmentSnapshot,
)
from consultation_kb.observability.audit import (
    ObservabilityStoreError,
    _exclusive_store_lock,
)

from .variants import (
    ALL_EVIDENCE_CHANNELS,
    SYSTEM_VARIANTS_BY_NAME,
    C1Mode,
    SystemVariant,
    SystemVariantName,
)


ModelLabel = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=120,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:+/-]*$",
    ),
]
ReasoningEffort = Literal["low", "medium", "high", "xhigh", "max", "ultra"]


def _ref_key(reference: VersionRef) -> tuple[str, int, str]:
    return reference.object_id, reference.version, reference.content_sha256


def _canonical_refs(
    values: tuple[VersionRef, ...],
    *,
    field_name: str,
) -> tuple[VersionRef, ...]:
    keys = tuple(_ref_key(reference) for reference in values)
    if len(keys) != len(set(keys)):
        raise ValueError(f"{field_name} must contain unique exact references")
    ordered = tuple(sorted(values, key=_ref_key))
    if values != ordered:
        raise ValueError(f"{field_name} must use canonical exact-reference order")
    return values


class EvaluationFairnessContract(StrictModel):
    """Fields that must be identical in every paired variant execution."""

    schema_version: Literal["evaluation_fairness.v1"] = "evaluation_fairness.v1"
    model_label: ModelLabel
    reasoning_effort: ReasoningEffort
    model_descriptor_ref: VersionRef
    model_parameters_ref: VersionRef
    prompt_refs: tuple[NamedVersionRef, ...]
    skill_refs: tuple[NamedVersionRef, ...]
    schema_ref: VersionRef
    reply_contract_ref: VersionRef
    wiki_manifest_ref: VersionRef
    case_manifest_ref: VersionRef
    graph_manifest_ref: VersionRef
    lexical_manifest_ref: VersionRef
    vector_manifest_ref: VersionRef
    reranker_descriptor_ref: VersionRef
    authority_snapshot_ref: VersionRef
    authority_policy_ref: VersionRef
    c1_revision_ref: VersionRef
    c1_scope_policy_ref: VersionRef
    c1_applicability_ref: VersionRef
    exclusion_proof_ref: VersionRef
    runtime: RuntimeEnvironmentSnapshot
    reproducibility: RunReproducibilitySnapshot
    retry_budget: Annotated[int, Field(strict=True, ge=0, le=2)]

    @field_validator("prompt_refs", "skill_refs")
    @classmethod
    def _canonical_named_refs(
        cls,
        value: tuple[NamedVersionRef, ...],
    ) -> tuple[NamedVersionRef, ...]:
        names = tuple(item.name for item in value)
        if len(names) != len(set(names)):
            raise ValueError("fairness named refs must use unique names")
        if value != tuple(sorted(value, key=lambda item: item.name)):
            raise ValueError("fairness named refs must use canonical name order")
        if not value:
            raise ValueError("fairness named refs must not be empty")
        return value

    @property
    def canonical_sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


class VariantRoutePolicy(StrictModel):
    variant_name: SystemVariantName
    route_policy_ref: VersionRef


class EvaluationCaseBinding(StrictModel):
    """Immutable no-body case projection placed into the queue plan."""

    dataset_id: SafePolicyKey
    dataset_file_sha256: Sha256Hex
    dataset_records_sha256: Sha256Hex
    case_id: SafePolicyKey
    split: EvaluationSplit
    client_snapshot_ref: VersionRef
    evidence_catalog_sha256: Sha256Hex


class EvaluationWorkItem(StrictModel):
    """One case/variant/repetition assignment without input or output prose."""

    schema_version: Literal["evaluation_work_item.v1"] = "evaluation_work_item.v1"
    work_item_id: Sha256Hex
    evaluation_run_id: Uuid7String
    queue_index: NonNegativeInt
    dataset_id: SafePolicyKey
    dataset_file_sha256: Sha256Hex
    dataset_records_sha256: Sha256Hex
    case_id: SafePolicyKey
    split: EvaluationSplit
    variant_name: SystemVariantName
    variant_sha256: Sha256Hex
    route_policy_ref: VersionRef
    repetition_index: NonNegativeInt
    client_snapshot_ref: VersionRef
    evidence_catalog_sha256: Sha256Hex
    fairness_sha256: Sha256Hex


class EvaluationRunPlan(StrictModel):
    """Frozen paired-run identity and the hash of its randomized queue."""

    schema_version: Literal["evaluation_run_plan.v1"] = "evaluation_run_plan.v1"
    evaluation_run_id: Uuid7String
    dataset_bundle_sha256: Sha256Hex
    cases: tuple[EvaluationCaseBinding, ...]
    variants: tuple[SystemVariant, ...]
    route_policies: tuple[VariantRoutePolicy, ...]
    repetition_count: Annotated[int, Field(strict=True, ge=2, le=100)]
    queue_order_seed: NonNegativeInt
    fairness: EvaluationFairnessContract
    expected_item_count: PositiveInt
    queue_sha256: Sha256Hex

    @field_validator("cases")
    @classmethod
    def _unique_cases(
        cls,
        value: tuple[EvaluationCaseBinding, ...],
    ) -> tuple[EvaluationCaseBinding, ...]:
        case_ids = tuple(item.case_id for item in value)
        if not value or len(case_ids) != len(set(case_ids)):
            raise ValueError("run plan cases must be non-empty and unique")
        return value

    @field_validator("variants")
    @classmethod
    def _exact_unique_variants(
        cls,
        value: tuple[SystemVariant, ...],
    ) -> tuple[SystemVariant, ...]:
        names = tuple(item.name for item in value)
        if not value or len(names) != len(set(names)):
            raise ValueError("run plan variants must be non-empty and unique")
        for variant in value:
            if SYSTEM_VARIANTS_BY_NAME[variant.name] != variant:
                raise ValueError("run plan variant differs from the frozen registry")
        return value

    @field_validator("route_policies")
    @classmethod
    def _unique_route_policies(
        cls,
        value: tuple[VariantRoutePolicy, ...],
    ) -> tuple[VariantRoutePolicy, ...]:
        names = tuple(item.variant_name for item in value)
        if len(names) != len(set(names)):
            raise ValueError("variant route policies must be unique")
        return value

    @model_validator(mode="after")
    def _complete_pairing(self) -> Self:
        if self.queue_order_seed != self.fairness.reproducibility.queue_order_seed:
            raise ValueError("queue seed and fairness reproducibility disagree")
        variant_names = tuple(variant.name for variant in self.variants)
        policy_names = tuple(policy.variant_name for policy in self.route_policies)
        if set(variant_names) != set(policy_names):
            raise ValueError(
                "route policy set must cover every selected variant exactly"
            )
        expected = len(self.cases) * len(self.variants) * self.repetition_count
        if self.expected_item_count != expected:
            raise ValueError(
                "run plan expected item count does not form complete pairs"
            )
        return self

    @property
    def canonical_sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


class ChannelUsageCount(StrictModel):
    channel: EvidenceChannel
    count: NonNegativeInt


class RoutedEvidenceUse(StrictModel):
    evidence_ref: VersionRef
    channel: EvidenceChannel


class EvaluationExecutionTrace(StrictModel):
    """Observable controls and channel use; contains no generated prose."""

    channel_counts: tuple[ChannelUsageCount, ...]
    c1_mode: C1Mode
    c1_evidence_refs: tuple[VersionRef, ...]
    graph_navigation_count: NonNegativeInt
    reranker_application_count: NonNegativeInt
    critique_stage_count: NonNegativeInt
    configured_retry_budget: Annotated[int, Field(strict=True, ge=0, le=2)]
    model_label: ModelLabel
    reasoning_effort: ReasoningEffort
    schema_ref: VersionRef
    reply_contract_ref: VersionRef

    @field_validator("channel_counts")
    @classmethod
    def _complete_channel_counts(
        cls,
        value: tuple[ChannelUsageCount, ...],
    ) -> tuple[ChannelUsageCount, ...]:
        channels = tuple(item.channel for item in value)
        if channels != ALL_EVIDENCE_CHANNELS:
            raise ValueError(
                "channel counts must cover all channels in canonical order"
            )
        return value

    @field_validator("c1_evidence_refs")
    @classmethod
    def _canonical_c1_refs(
        cls,
        value: tuple[VersionRef, ...],
    ) -> tuple[VersionRef, ...]:
        return _canonical_refs(value, field_name="c1_evidence_refs")


class EvaluationStageResult(StrictModel):
    """Exact stage result accepted at the controlled submission boundary."""

    final_bundle: FinalTurnBundle
    final_bundle_ref: VersionRef
    run_manifest: RunManifestV2
    evidence_uses: tuple[RoutedEvidenceUse, ...]
    trace: EvaluationExecutionTrace

    @field_validator("evidence_uses")
    @classmethod
    def _canonical_evidence_uses(
        cls,
        value: tuple[RoutedEvidenceUse, ...],
    ) -> tuple[RoutedEvidenceUse, ...]:
        identities = tuple(
            (ALL_EVIDENCE_CHANNELS.index(item.channel), *_ref_key(item.evidence_ref))
            for item in value
        )
        if len(identities) != len(set(identities)):
            raise ValueError("routed evidence uses must be unique")
        if identities != tuple(sorted(identities)):
            raise ValueError("routed evidence uses must use canonical order")
        return value

    @model_validator(mode="after")
    def _hash_and_run_closure(self) -> Self:
        final_sha256 = canonical_sha256(self.final_bundle.model_dump(mode="json"))
        if self.final_bundle_ref.content_sha256 != final_sha256:
            raise ValueError("final bundle reference does not match exact bundle")
        if (
            self.final_bundle.envelope.run_id != self.run_manifest.run_id
            or self.final_bundle.evidence_pack_sha256
            != self.run_manifest.evidence.evidence_pack_canonical_sha256
            or self.run_manifest.result_sha256 != final_sha256
        ):
            raise ValueError("final bundle and evaluation run manifest disagree")
        return self


class EvaluationSubmission(StrictModel):
    """Persisted no-body projection of an accepted exact stage result."""

    schema_version: Literal["evaluation_submission.v1"] = "evaluation_submission.v1"
    work_item_id: Sha256Hex
    evaluation_run_id: Uuid7String
    case_id: SafePolicyKey
    variant_name: SystemVariantName
    repetition_index: NonNegativeInt
    final_bundle_ref: VersionRef
    final_bundle_sha256: Sha256Hex
    run_manifest: RunManifestV2
    evidence_uses: tuple[RoutedEvidenceUse, ...]
    trace: EvaluationExecutionTrace

    @model_validator(mode="after")
    def _projection_closure(self) -> Self:
        if (
            self.final_bundle_ref.content_sha256 != self.final_bundle_sha256
            or self.run_manifest.result_sha256 != self.final_bundle_sha256
        ):
            raise ValueError("submission result hashes disagree")
        return self


class MissingEvaluationItem(StrictModel):
    work_item_id: Sha256Hex
    reason_code: SafePolicyKey


class VariantCompletion(StrictModel):
    variant_name: SystemVariantName
    expected_count: PositiveInt
    completed_count: NonNegativeInt
    missing_count: NonNegativeInt

    @model_validator(mode="after")
    def _balanced(self) -> Self:
        if self.completed_count + self.missing_count != self.expected_count:
            raise ValueError("variant completion counts do not balance")
        return self


class EvaluationFinalSummary(StrictModel):
    schema_version: Literal["evaluation_final_summary.v1"] = (
        "evaluation_final_summary.v1"
    )
    evaluation_run_id: Uuid7String
    plan_sha256: Sha256Hex
    queue_sha256: Sha256Hex
    submissions_sha256: Sha256Hex
    status: Literal["succeeded", "incomplete"]
    expected_count: PositiveInt
    completed_count: NonNegativeInt
    missing: tuple[MissingEvaluationItem, ...]
    variants: tuple[VariantCompletion, ...]

    @field_validator("missing")
    @classmethod
    def _canonical_missing(
        cls,
        value: tuple[MissingEvaluationItem, ...],
    ) -> tuple[MissingEvaluationItem, ...]:
        identifiers = tuple(item.work_item_id for item in value)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("missing item reasons must be unique")
        if identifiers != tuple(sorted(identifiers)):
            raise ValueError("missing item reasons must use canonical order")
        return value

    @model_validator(mode="after")
    def _completion_contract(self) -> Self:
        missing_count = len(self.missing)
        if self.completed_count + missing_count != self.expected_count:
            raise ValueError("final evaluation counts do not balance")
        if (self.status == "succeeded") != (missing_count == 0):
            raise ValueError("only a complete evaluation may be marked succeeded")
        if sum(item.expected_count for item in self.variants) != self.expected_count:
            raise ValueError("variant expected counts do not match final total")
        if sum(item.completed_count for item in self.variants) != self.completed_count:
            raise ValueError("variant completed counts do not match final total")
        if sum(item.missing_count for item in self.variants) != missing_count:
            raise ValueError("variant missing counts do not match final total")
        return self


class QueueStateError(RuntimeError):
    """Raised when an immutable queue is missing, stale, or would be overwritten."""


class DuplicateSubmissionError(QueueStateError):
    """Raised when a work item is submitted with a different immutable result."""


class ReportStateError(QueueStateError):
    """Raised when a persisted evaluation report differs from recomputed bytes."""


def _render_summary_markdown(summary: EvaluationFinalSummary) -> str:
    lines = [
        "# Evaluation run summary",
        "",
        f"- Run: `{summary.evaluation_run_id}`",
        f"- Status: `{summary.status}`",
        f"- Completed: `{summary.completed_count}/{summary.expected_count}`",
        f"- Plan SHA-256: `{summary.plan_sha256}`",
        f"- Queue SHA-256: `{summary.queue_sha256}`",
        f"- Submissions SHA-256: `{summary.submissions_sha256}`",
        "",
        "## Variant completion",
        "",
        "| Variant | Completed | Missing | Expected |",
        "|---|---:|---:|---:|",
    ]
    lines.extend(
        f"| `{item.variant_name}` | {item.completed_count} | "
        f"{item.missing_count} | {item.expected_count} |"
        for item in summary.variants
    )
    if summary.missing:
        lines.extend(("", "## Missing work items", ""))
        lines.extend(
            f"- `{item.work_item_id}`: `{item.reason_code}`" for item in summary.missing
        )
    return "\n".join(lines) + "\n"


def _atomic_create(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            descriptor = -1
            raise
        if path.exists() or path.is_symlink():
            raise QueueStateError("evaluation queue artifact already exists")
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _read_regular_file(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise QueueStateError("evaluation queue artifact is unavailable")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise QueueStateError("evaluation queue artifact cannot be read") from exc


class EvaluationWorkQueue:
    """Small durable queue whose shared artifacts contain no case/output body."""

    PLAN_NAME = "plan.json"
    ITEMS_NAME = "queue.jsonl"
    SUBMISSIONS_NAME = "submissions.jsonl"
    REPORT_JSON_NAME = "report.json"
    REPORT_MARKDOWN_NAME = "report.md"

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path):
            raise TypeError("evaluation queue root must be pathlib.Path")
        self._root = root
        self._lock = threading.RLock()

    @property
    def root(self) -> Path:
        return self._root

    @property
    def plan_path(self) -> Path:
        return self._root / self.PLAN_NAME

    @property
    def items_path(self) -> Path:
        return self._root / self.ITEMS_NAME

    @property
    def submissions_path(self) -> Path:
        return self._root / self.SUBMISSIONS_NAME

    def initialize(
        self,
        plan: EvaluationRunPlan,
        items: tuple[EvaluationWorkItem, ...],
    ) -> None:
        with self._lock:
            if self._root.is_symlink():
                raise QueueStateError("evaluation queue root must not be a symlink")
            try:
                self._root.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise QueueStateError(
                    "evaluation queue root cannot be created"
                ) from exc
            if any(self._root.iterdir()):
                raise QueueStateError("evaluation queue root must be empty")
            validated_items = tuple(
                EvaluationWorkItem.model_validate(item) for item in items
            )
            self._validate_plan_items(plan, validated_items)
            plan_payload = canonical_json_bytes(plan.model_dump(mode="json")) + b"\n"
            item_payload = b"".join(
                canonical_json_bytes(item.model_dump(mode="json")) + b"\n"
                for item in validated_items
            )
            _atomic_create(self.items_path, item_payload)
            _atomic_create(self.plan_path, plan_payload)

    def load_plan(self) -> EvaluationRunPlan:
        raw = _read_regular_file(self.plan_path)
        if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
            raise QueueStateError("evaluation plan has an invalid record layout")
        try:
            return EvaluationRunPlan.model_validate_json(raw[:-1], strict=True)
        except ValueError as exc:
            raise QueueStateError("evaluation plan is invalid") from exc

    def load_items(self) -> tuple[EvaluationWorkItem, ...]:
        raw = _read_regular_file(self.items_path)
        if not raw or not raw.endswith(b"\n"):
            raise QueueStateError("evaluation queue has an invalid record layout")
        try:
            items = tuple(
                EvaluationWorkItem.model_validate_json(line, strict=True)
                for line in raw.splitlines()
            )
        except ValueError as exc:
            raise QueueStateError("evaluation queue contains an invalid item") from exc
        self._validate_plan_items(self.load_plan(), items)
        return items

    def load_submissions(self) -> tuple[EvaluationSubmission, ...]:
        if (
            not self.submissions_path.exists()
            and not self.submissions_path.is_symlink()
        ):
            return ()
        raw = _read_regular_file(self.submissions_path)
        if not raw or not raw.endswith(b"\n"):
            raise QueueStateError(
                "evaluation submissions have an invalid record layout"
            )
        try:
            submissions = tuple(
                EvaluationSubmission.model_validate_json(line, strict=True)
                for line in raw.splitlines()
            )
        except ValueError as exc:
            raise QueueStateError(
                "evaluation submissions contain an invalid record"
            ) from exc
        identifiers = tuple(item.work_item_id for item in submissions)
        if len(identifiers) != len(set(identifiers)):
            raise QueueStateError(
                "evaluation submissions contain a duplicate work item"
            )
        plan = self.load_plan()
        items_by_id = {item.work_item_id: item for item in self.load_items()}
        for submission in submissions:
            item = items_by_id.get(submission.work_item_id)
            if item is None:
                raise QueueStateError(
                    "evaluation submission references an unknown work item"
                )
            self._validate_submission_binding(plan, item, submission)
        return submissions

    def append_submission(
        self, submission: EvaluationSubmission
    ) -> EvaluationSubmission:
        validated = EvaluationSubmission.model_validate_json(
            submission.model_dump_json(),
            strict=True,
        )
        with self._lock:
            try:
                with _exclusive_store_lock(self.submissions_path):
                    if any(
                        path.exists() or path.is_symlink()
                        for path in (
                            self._root / self.REPORT_JSON_NAME,
                            self._root / self.REPORT_MARKDOWN_NAME,
                        )
                    ):
                        raise QueueStateError("evaluation queue is finalized")
                    existing = self.load_submissions()
                    plan = self.load_plan()
                    items_by_id = {
                        item.work_item_id: item for item in self.load_items()
                    }
                    item = items_by_id.get(validated.work_item_id)
                    if item is None:
                        raise QueueStateError(
                            "submission references an unknown work item"
                        )
                    self._validate_submission_binding(plan, item, validated)
                    previous = next(
                        (
                            item
                            for item in existing
                            if item.work_item_id == validated.work_item_id
                        ),
                        None,
                    )
                    if previous is not None:
                        if previous == validated:
                            return previous
                        raise DuplicateSubmissionError(
                            "work item already has a different immutable submission"
                        )
                    payload = b"".join(
                        canonical_json_bytes(item.model_dump(mode="json")) + b"\n"
                        for item in (*existing, validated)
                    )
                    temporary = self.submissions_path.with_name(
                        f".{self.SUBMISSIONS_NAME}.{uuid.uuid4().hex}.tmp"
                    )
                    try:
                        temporary.write_bytes(payload)
                        os.replace(temporary, self.submissions_path)
                    except OSError as exc:
                        raise QueueStateError(
                            "evaluation submission cannot be committed"
                        ) from exc
                    finally:
                        temporary.unlink(missing_ok=True)
                    return validated
            except ObservabilityStoreError as exc:
                raise QueueStateError("evaluation queue lock is unavailable") from exc

    def write_reports(self, summary: EvaluationFinalSummary) -> None:
        validated = EvaluationFinalSummary.model_validate(summary)
        json_path = self._root / self.REPORT_JSON_NAME
        markdown_path = self._root / self.REPORT_MARKDOWN_NAME
        json_payload = canonical_json_bytes(validated.model_dump(mode="json")) + b"\n"
        markdown_payload = _render_summary_markdown(validated).encode(
            "utf-8",
            errors="strict",
        )
        with self._lock:
            try:
                with _exclusive_store_lock(self.submissions_path):
                    plan = self.load_plan()
                    items = self.load_items()
                    submissions = self.load_submissions()
                    submission_sha256 = canonical_sha256(
                        [item.model_dump(mode="json") for item in submissions]
                    )
                    completed_ids = {
                        submission.work_item_id for submission in submissions
                    }
                    missing_items = tuple(
                        item for item in items if item.work_item_id not in completed_ids
                    )
                    expected_missing_ids = tuple(
                        sorted(item.work_item_id for item in missing_items)
                    )
                    completed_by_variant = Counter(
                        item.variant_name for item in submissions
                    )
                    missing_by_variant = Counter(
                        item.variant_name for item in missing_items
                    )
                    expected_by_variant = Counter(item.variant_name for item in items)
                    expected_variants = tuple(
                        VariantCompletion(
                            variant_name=variant.name,
                            expected_count=expected_by_variant[variant.name],
                            completed_count=completed_by_variant[variant.name],
                            missing_count=missing_by_variant[variant.name],
                        )
                        for variant in plan.variants
                    )
                    if (
                        validated.evaluation_run_id != plan.evaluation_run_id
                        or validated.plan_sha256 != plan.canonical_sha256
                        or validated.queue_sha256 != plan.queue_sha256
                        or validated.expected_count != plan.expected_item_count
                        or validated.completed_count != len(submissions)
                        or validated.submissions_sha256 != submission_sha256
                        or tuple(item.work_item_id for item in validated.missing)
                        != expected_missing_ids
                        or validated.variants != expected_variants
                    ):
                        raise ReportStateError(
                            "evaluation report differs from current queue state"
                        )
                    json_exists = self._verify_report_bytes(json_path, json_payload)
                    markdown_exists = self._verify_report_bytes(
                        markdown_path,
                        markdown_payload,
                    )
                    if not markdown_exists:
                        _atomic_create(markdown_path, markdown_payload)
                    if not json_exists:
                        _atomic_create(json_path, json_payload)
            except ObservabilityStoreError as exc:
                raise ReportStateError("evaluation report lock is unavailable") from exc

    @staticmethod
    def _verify_report_bytes(path: Path, expected: bytes) -> bool:
        if not path.exists() and not path.is_symlink():
            return False
        try:
            actual = _read_regular_file(path)
        except QueueStateError as exc:
            raise ReportStateError("evaluation report artifact is invalid") from exc
        if actual != expected:
            raise ReportStateError("evaluation report differs from recomputed content")
        return True

    @staticmethod
    def _validate_submission_binding(
        plan: EvaluationRunPlan,
        item: EvaluationWorkItem,
        submission: EvaluationSubmission,
    ) -> None:
        variant = next(
            (
                candidate
                for candidate in plan.variants
                if candidate.name == item.variant_name
            ),
            None,
        )
        if variant is None:
            raise QueueStateError("evaluation work item has no frozen plan variant")
        fairness = plan.fairness
        manifest = submission.run_manifest
        trace = submission.trace
        expected_versions = RunVersionSnapshot(
            model_descriptor_ref=fairness.model_descriptor_ref,
            model_parameters_ref=fairness.model_parameters_ref,
            prompt_refs=fairness.prompt_refs,
            skill_refs=fairness.skill_refs,
            client_snapshot_ref=item.client_snapshot_ref,
            wiki_manifest_ref=fairness.wiki_manifest_ref,
            case_manifest_ref=fairness.case_manifest_ref,
            graph_manifest_ref=fairness.graph_manifest_ref,
            lexical_manifest_ref=fairness.lexical_manifest_ref,
            vector_manifest_ref=fairness.vector_manifest_ref,
            reranker_descriptor_ref=fairness.reranker_descriptor_ref,
        )
        expected_c1_ref = (
            None if variant.features.c1_mode == "disabled" else fairness.c1_revision_ref
        )
        expected_scope_sha256 = canonical_sha256(
            {
                "evaluation_run_id": item.evaluation_run_id,
                "case_id": item.case_id,
            }
        )
        fixed_fields = (
            submission.work_item_id == item.work_item_id,
            submission.evaluation_run_id == item.evaluation_run_id,
            submission.case_id == item.case_id,
            submission.variant_name == item.variant_name,
            submission.repetition_index == item.repetition_index,
            manifest.run_kind == "evaluation",
            manifest.lineage.phase == "evaluation",
            manifest.lineage.parent_run_id is None,
            manifest.scope_sha256 == expected_scope_sha256,
            manifest.versions == expected_versions,
            manifest.runtime == fairness.runtime,
            manifest.reproducibility == fairness.reproducibility,
            manifest.routing.routes == variant.features.routes,
            manifest.routing.route_policy_ref == item.route_policy_ref,
            manifest.evidence.client_snapshot_ref == item.client_snapshot_ref,
            manifest.evidence.authority_snapshot_ref == fairness.authority_snapshot_ref,
            manifest.evidence.authority_policy_ref == fairness.authority_policy_ref,
            manifest.evidence.c1_revision_ref == expected_c1_ref,
            manifest.evidence.c1_scope_policy_ref == fairness.c1_scope_policy_ref,
            manifest.evidence.c1_applicability_ref == fairness.c1_applicability_ref,
            manifest.evidence.exclusion_proof_ref == fairness.exclusion_proof_ref,
            manifest.evidence.wiki_manifest_ref == fairness.wiki_manifest_ref,
            manifest.evidence.lexical_manifest_ref == fairness.lexical_manifest_ref,
            manifest.evidence.vector_manifest_ref == fairness.vector_manifest_ref,
            manifest.evidence.graph_manifest_ref == fairness.graph_manifest_ref,
            manifest.evidence.reranker_descriptor_ref
            == fairness.reranker_descriptor_ref,
            manifest.retry_count <= fairness.retry_budget,
            trace.model_label == fairness.model_label,
            trace.reasoning_effort == fairness.reasoning_effort,
            trace.schema_ref == fairness.schema_ref,
            trace.reply_contract_ref == fairness.reply_contract_ref,
            trace.configured_retry_budget == fairness.retry_budget,
            trace.c1_mode == variant.features.c1_mode,
        )
        if not all(fixed_fields):
            raise QueueStateError(
                "evaluation submission disagrees with frozen plan or work item"
            )

        counts = {entry.channel: entry.count for entry in trace.channel_counts}
        observed = Counter(use.channel for use in submission.evidence_uses)
        trace_closure = (
            all(
                counts[channel] == observed[channel]
                for channel in ALL_EVIDENCE_CHANNELS
            ),
            all(counts[channel] == 0 for channel in variant.features.prohibited_routes),
            len(manifest.evidence.candidates) == len(submission.evidence_uses),
            manifest.routing.filter_counts.after == len(submission.evidence_uses),
            variant.features.graphify_navigation or trace.graph_navigation_count == 0,
            trace.graph_navigation_count
            <= counts["client_history"] + counts["global_graph"],
            variant.features.reranker or trace.reranker_application_count == 0,
            variant.features.multi_stage_critique or trace.critique_stage_count == 0,
            not variant.features.multi_stage_critique or trace.critique_stage_count > 0,
            variant.features.c1_mode != "disabled" or not trace.c1_evidence_refs,
        )
        if not all(trace_closure):
            raise QueueStateError(
                "evaluation submission trace disagrees with frozen plan or work item"
            )

    @staticmethod
    def _validate_plan_items(
        plan: EvaluationRunPlan,
        items: tuple[EvaluationWorkItem, ...],
    ) -> None:
        if len(items) != plan.expected_item_count:
            raise QueueStateError("evaluation queue item count differs from plan")
        indices = tuple(item.queue_index for item in items)
        if indices != tuple(range(len(items))):
            raise QueueStateError("evaluation queue indices are not contiguous")
        identifiers = tuple(item.work_item_id for item in items)
        if len(identifiers) != len(set(identifiers)):
            raise QueueStateError("evaluation queue item IDs are not unique")
        if (
            canonical_sha256([item.model_dump(mode="json") for item in items])
            != plan.queue_sha256
        ):
            raise QueueStateError("evaluation queue hash differs from plan")

        cases = {item.case_id: item for item in plan.cases}
        variants = {item.name: item for item in plan.variants}
        policies = {
            item.variant_name: item.route_policy_ref for item in plan.route_policies
        }
        pairings: set[tuple[str, str, int]] = set()
        for item in items:
            case = cases.get(item.case_id)
            variant = variants.get(item.variant_name)
            if case is None or variant is None:
                raise QueueStateError(
                    "evaluation queue references an undeclared case or variant"
                )
            expected_values = (
                item.evaluation_run_id == plan.evaluation_run_id,
                item.dataset_id == case.dataset_id,
                item.dataset_file_sha256 == case.dataset_file_sha256,
                item.dataset_records_sha256 == case.dataset_records_sha256,
                item.split == case.split,
                item.client_snapshot_ref == case.client_snapshot_ref,
                item.evidence_catalog_sha256 == case.evidence_catalog_sha256,
                item.variant_sha256 == variant.canonical_sha256,
                item.route_policy_ref == policies[item.variant_name],
                item.fairness_sha256 == plan.fairness.canonical_sha256,
                item.repetition_index < plan.repetition_count,
            )
            if not all(expected_values):
                raise QueueStateError(
                    "evaluation queue item disagrees with frozen plan"
                )
            pairings.add((item.case_id, item.variant_name, item.repetition_index))
        expected_pairings = {
            (case.case_id, variant.name, repetition)
            for case in plan.cases
            for variant in plan.variants
            for repetition in range(plan.repetition_count)
        }
        if pairings != expected_pairings:
            raise QueueStateError("evaluation queue is not a complete paired design")


__all__ = [
    "ChannelUsageCount",
    "DuplicateSubmissionError",
    "EvaluationCaseBinding",
    "EvaluationExecutionTrace",
    "EvaluationFairnessContract",
    "EvaluationFinalSummary",
    "EvaluationRunPlan",
    "EvaluationStageResult",
    "EvaluationSubmission",
    "EvaluationWorkItem",
    "EvaluationWorkQueue",
    "MissingEvaluationItem",
    "ModelLabel",
    "QueueStateError",
    "ReportStateError",
    "ReasoningEffort",
    "RoutedEvidenceUse",
    "VariantCompletion",
    "VariantRoutePolicy",
]
