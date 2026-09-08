"""Restart-safe local orchestration for controlled synthetic evaluations.

The durable queue is deliberately body-free.  Dataset prose is loaded only
from the repository's immutable synthetic fixtures and is projected through
``get_next`` for one opaque evaluation scope.  No caller-controlled path or
client identity crosses this boundary.
"""

from __future__ import annotations

import hmac
import os
import re
import stat
import threading
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, TypeAdapter, model_validator
from typing_extensions import Self

from consultation_kb.evaluation.datasets import load_evaluation_bundle
from consultation_kb.evaluation.runner import EvaluationRunner
from consultation_kb.evaluation.variants import (
    ALL_SYSTEM_VARIANTS,
    SYSTEM_VARIANTS_BY_NAME,
    SystemVariant,
    SystemVariantName,
)
from consultation_kb.evaluation.work_queue import (
    EvaluationFairnessContract,
    EvaluationFinalSummary,
    EvaluationRunPlan,
    EvaluationStageResult,
    EvaluationSubmission,
    EvaluationWorkItem,
    EvaluationWorkQueue,
    ReportStateError,
)
from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.common import (
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    Uuid7String,
    VersionRef,
)
from consultation_kb.models.evaluation import (
    EvaluationCase,
    EvaluationDatasetBundle,
    EvaluationSplit,
    EvaluationTurn,
)
from consultation_kb.observability.audit import (
    ObservabilityStoreError,
    _exclusive_store_lock,
)


EvaluationHandle = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$"),
]
_HANDLE_ADAPTER = TypeAdapter(EvaluationHandle)
_RUN_ID_ADAPTER = TypeAdapter(Uuid7String)
_REPARSE_ATTRIBUTE = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
_RUN_DIRECTORY_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_DEFAULT_VARIANT_NAMES: tuple[SystemVariantName, ...] = tuple(
    variant.name for variant in ALL_SYSTEM_VARIANTS
)


class EvaluationRuntimeError(RuntimeError):
    """Fixed-code local evaluation failure safe for an MCP error boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class SyntheticEvaluationPrompt(StrictModel):
    """Generation-only case projection; hidden gold labels are not exposed."""

    schema_version: Literal["synthetic_evaluation_prompt.v1"] = (
        "synthetic_evaluation_prompt.v1"
    )
    case_id: SafePolicyKey
    split: EvaluationSplit
    client_snapshot_ref: VersionRef
    input_turns: tuple[EvaluationTurn, ...]


class PreparedEvaluation(StrictModel):
    evaluation_handle: EvaluationHandle
    plan_sha256: Sha256Hex
    queue_sha256: Sha256Hex
    dataset_bundle_sha256: Sha256Hex
    expected_count: int = Field(strict=True, gt=0)
    case_count: int = Field(strict=True, gt=0)
    variant_count: int = Field(strict=True, gt=0)


class NextEvaluationCase(StrictModel):
    """One pending assignment, including prose only for a synthetic case."""

    evaluation_handle: EvaluationHandle
    plan_sha256: Sha256Hex
    queue_sha256: Sha256Hex
    pending: bool
    completed_count: int = Field(strict=True, ge=0)
    expected_count: int = Field(strict=True, gt=0)
    work_item: EvaluationWorkItem | None = None
    variant: SystemVariant | None = None
    fairness: EvaluationFairnessContract | None = None
    prompt: SyntheticEvaluationPrompt | None = None
    case_payload_sha256: Sha256Hex | None = None

    @model_validator(mode="after")
    def _closed_pending_state(self) -> Self:
        payload = (
            self.work_item,
            self.variant,
            self.fairness,
            self.prompt,
            self.case_payload_sha256,
        )
        if self.pending != all(item is not None for item in payload):
            raise ValueError("pending evaluation state has an incomplete payload")
        if self.completed_count > self.expected_count:
            raise ValueError("evaluation completion exceeds the frozen queue")
        if not self.pending and self.completed_count != self.expected_count:
            raise ValueError("unfinished evaluation must expose a pending item")
        return self


class AcceptedEvaluation(StrictModel):
    evaluation_handle: EvaluationHandle
    work_item_id: Sha256Hex
    case_id: SafePolicyKey
    variant_name: SystemVariantName
    final_bundle_sha256: Sha256Hex
    accepted_count: int = Field(strict=True, ge=1)
    expected_count: int = Field(strict=True, ge=1)


def _is_reparse(status: os.stat_result) -> bool:
    return stat.S_ISLNK(status.st_mode) or bool(
        int(getattr(status, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
    )


def _require_plain_directory(path: Path, *, create: bool) -> None:
    if create:
        try:
            path.mkdir(mode=0o700, exist_ok=True)
        except OSError as exc:
            raise EvaluationRuntimeError("EVALUATION_STORAGE_UNAVAILABLE") from exc
    try:
        status = os.lstat(path)
    except OSError as exc:
        raise EvaluationRuntimeError("EVALUATION_STORAGE_UNAVAILABLE") from exc
    if not stat.S_ISDIR(status.st_mode) or _is_reparse(status):
        raise EvaluationRuntimeError("EVALUATION_STORAGE_UNSAFE")


def _prompt_for(case: EvaluationCase) -> SyntheticEvaluationPrompt:
    if case.sensitivity != "synthetic" or not case.case_id.startswith("syn_case_"):
        raise EvaluationRuntimeError("EVALUATION_CASE_NOT_SYNTHETIC")
    return SyntheticEvaluationPrompt(
        case_id=case.case_id,
        split=case.split,
        client_snapshot_ref=case.synthetic_client_snapshot_ref,
        input_turns=case.input_turns,
    )


class EvaluationRuntime:
    """Local, offline runtime for immutable paired evaluation queues."""

    DATASET_FILENAMES = (
        "gold_cases.jsonl",
        "gold_retrieval.jsonl",
        "canary_cases.jsonl",
    )

    def __init__(self, *, repo_root: Path, vault_root: Path) -> None:
        if not isinstance(repo_root, Path) or not isinstance(vault_root, Path):
            raise TypeError("evaluation runtime roots must be pathlib.Path")
        self._repo_root = repo_root.resolve(strict=True)
        self._vault_root = vault_root.resolve(strict=True)
        _require_plain_directory(self._repo_root, create=False)
        _require_plain_directory(self._vault_root, create=False)
        fixture_root = (
            self._repo_root / "tests" / "fixtures" / "consultation_kb" / "evaluation"
        )
        self._dataset_paths = tuple(
            fixture_root / name for name in self.DATASET_FILENAMES
        )
        self._bundle: EvaluationDatasetBundle | None = None
        self._evaluation_root = self._vault_root / "evaluation"
        self._runs_root = self._evaluation_root / "runs"
        self._staging_root = self._evaluation_root / "staging"
        self._locks_root = self._evaluation_root / "locks"
        self._lock = threading.RLock()

    def _load_bundle(self) -> EvaluationDatasetBundle:
        bundle = self._bundle
        if bundle is not None:
            return bundle
        _require_plain_directory(self._dataset_paths[0].parent, create=False)
        try:
            bundle = load_evaluation_bundle(self._dataset_paths)
        except Exception as exc:
            raise EvaluationRuntimeError("EVALUATION_DATASET_UNAVAILABLE") from exc
        self._bundle = bundle
        return bundle

    def _ensure_storage(self) -> None:
        _require_plain_directory(self._evaluation_root, create=True)
        _require_plain_directory(self._runs_root, create=True)
        _require_plain_directory(self._staging_root, create=True)
        _require_plain_directory(self._locks_root, create=True)

    def _run_root(self, evaluation_run_id: str) -> Path:
        validated = _RUN_ID_ADAPTER.validate_python(evaluation_run_id, strict=True)
        return self._runs_root / validated

    def _open(
        self,
        evaluation_handle: str,
    ) -> tuple[EvaluationRunner, EvaluationWorkQueue, EvaluationRunPlan]:
        handle = _HANDLE_ADAPTER.validate_python(evaluation_handle, strict=True)
        self._ensure_storage()
        matches: list[tuple[EvaluationWorkQueue, EvaluationRunPlan]] = []
        try:
            entries = tuple(self._runs_root.iterdir())
        except OSError as exc:
            raise EvaluationRuntimeError("EVALUATION_STORAGE_UNAVAILABLE") from exc
        for entry in entries:
            if not _RUN_DIRECTORY_RE.fullmatch(entry.name):
                raise EvaluationRuntimeError("EVALUATION_STORAGE_UNSAFE")
            _require_plain_directory(entry, create=False)
            queue = EvaluationWorkQueue(entry)
            try:
                plan = queue.load_plan()
            except Exception as exc:
                raise EvaluationRuntimeError("EVALUATION_QUEUE_INVALID") from exc
            if hmac.compare_digest(plan.canonical_sha256, handle):
                matches.append((queue, plan))
        if len(matches) != 1:
            raise EvaluationRuntimeError("EVALUATION_SCOPE_UNAVAILABLE")
        queue, plan = matches[0]
        runner = EvaluationRunner(queue)
        try:
            runner.bind_dataset(self._load_bundle())
        except Exception as exc:
            raise EvaluationRuntimeError("EVALUATION_DATASET_DRIFT") from exc
        return runner, queue, plan

    def prepare(
        self,
        *,
        evaluation_run_id: str,
        fairness: EvaluationFairnessContract,
        route_policy_refs: Mapping[SystemVariantName, VersionRef],
        variants: Sequence[SystemVariantName] = _DEFAULT_VARIANT_NAMES,
        repetition_count: int = 2,
        case_ids: Sequence[str] = (),
        include_canary: bool = False,
    ) -> PreparedEvaluation:
        """Create or idempotently reopen one exact frozen evaluation plan."""

        with self._lock:
            bundle = self._load_bundle()
            self._ensure_storage()
            run_root = self._run_root(evaluation_run_id)
            selected_variants = tuple(
                SYSTEM_VARIANTS_BY_NAME[name] for name in variants
            )
            requested_cases = tuple(case_ids) or None
            requested_case_set = (
                None if requested_cases is None else set(requested_cases)
            )
            if requested_cases is not None and len(set(requested_cases)) != len(
                requested_cases
            ):
                raise EvaluationRuntimeError("EVALUATION_PREPARE_FAILED")
            expected_case_ids = tuple(
                case.case_id
                for dataset in bundle.datasets
                for case in dataset.cases
                if (include_canary or case.split != "canary")
                and (requested_case_set is None or case.case_id in requested_case_set)
            )
            if requested_case_set is not None and set(expected_case_ids) != (
                requested_case_set
            ):
                raise EvaluationRuntimeError("EVALUATION_PREPARE_FAILED")
            lock_target = self._locks_root / evaluation_run_id
            try:
                with _exclusive_store_lock(lock_target):
                    queue = EvaluationWorkQueue(run_root)
                    if run_root.exists() or run_root.is_symlink():
                        _require_plain_directory(run_root, create=False)
                        try:
                            plan = queue.load_plan()
                            queue.load_items()
                            queue.load_submissions()
                        except Exception as exc:
                            raise EvaluationRuntimeError(
                                "EVALUATION_QUEUE_INVALID"
                            ) from exc
                        exact = (
                            plan.evaluation_run_id == evaluation_run_id
                            and plan.dataset_bundle_sha256 == bundle.bundle_sha256
                            and plan.fairness == fairness
                            and plan.variants == selected_variants
                            and plan.repetition_count == repetition_count
                            and tuple(item.case_id for item in plan.cases)
                            == expected_case_ids
                            and {
                                item.variant_name: item.route_policy_ref
                                for item in plan.route_policies
                            }
                            == dict(route_policy_refs)
                        )
                        if not exact:
                            raise EvaluationRuntimeError("EVALUATION_RUN_ID_CONFLICT")
                    else:
                        staging_root = self._staging_root / (
                            f"{evaluation_run_id}.{uuid.uuid4().hex}.tmp"
                        )
                        staging_queue = EvaluationWorkQueue(staging_root)
                        try:
                            plan = EvaluationRunner(staging_queue).prepare(
                                bundle=bundle,
                                fairness=fairness,
                                evaluation_run_id=evaluation_run_id,
                                route_policy_refs=route_policy_refs,
                                variants=selected_variants,
                                repetition_count=repetition_count,
                                case_ids=requested_cases,
                                include_canary=include_canary,
                            )
                            os.replace(staging_root, run_root)
                            _require_plain_directory(run_root, create=False)
                        except EvaluationRuntimeError:
                            raise
                        except Exception as exc:
                            raise EvaluationRuntimeError(
                                "EVALUATION_PREPARE_FAILED"
                            ) from exc
            except ObservabilityStoreError as exc:
                raise EvaluationRuntimeError("EVALUATION_STORAGE_UNAVAILABLE") from exc
            return PreparedEvaluation(
                evaluation_handle=plan.canonical_sha256,
                plan_sha256=plan.canonical_sha256,
                queue_sha256=plan.queue_sha256,
                dataset_bundle_sha256=plan.dataset_bundle_sha256,
                expected_count=plan.expected_item_count,
                case_count=len(plan.cases),
                variant_count=len(plan.variants),
            )

    def get_next(self, evaluation_handle: str) -> NextEvaluationCase:
        """Return at most one synthetic case body for the authorized scope."""

        with self._lock:
            bundle = self._load_bundle()
            _runner, queue, plan = self._open(evaluation_handle)
            submissions = queue.load_submissions()
            finalized = any(
                path.exists() or path.is_symlink()
                for path in (
                    queue.root / queue.REPORT_JSON_NAME,
                    queue.root / queue.REPORT_MARKDOWN_NAME,
                )
            )
            if finalized and len(submissions) < plan.expected_item_count:
                raise EvaluationRuntimeError("EVALUATION_RUN_FINALIZED")
            completed = {item.work_item_id for item in submissions}
            pending = next(
                (
                    item
                    for item in queue.load_items()
                    if item.work_item_id not in completed
                ),
                None,
            )
            if pending is None:
                return NextEvaluationCase(
                    evaluation_handle=evaluation_handle,
                    plan_sha256=plan.canonical_sha256,
                    queue_sha256=plan.queue_sha256,
                    pending=False,
                    completed_count=len(submissions),
                    expected_count=plan.expected_item_count,
                )
            case = next(
                case
                for dataset in bundle.datasets
                for case in dataset.cases
                if case.case_id == pending.case_id
            )
            prompt = _prompt_for(case)
            variant = next(
                item for item in plan.variants if item.name == pending.variant_name
            )
            return NextEvaluationCase(
                evaluation_handle=evaluation_handle,
                plan_sha256=plan.canonical_sha256,
                queue_sha256=plan.queue_sha256,
                pending=True,
                completed_count=len(submissions),
                expected_count=plan.expected_item_count,
                work_item=pending,
                variant=variant,
                fairness=plan.fairness,
                prompt=prompt,
                case_payload_sha256=canonical_sha256(prompt.model_dump(mode="json")),
            )

    def submit(
        self,
        *,
        evaluation_handle: str,
        work_item_id: str,
        case_payload_sha256: str,
        variant_sha256: str,
        client_snapshot_ref: VersionRef,
        evidence_catalog_sha256: str,
        evidence_pack_sha256: str,
        result: EvaluationStageResult,
    ) -> AcceptedEvaluation:
        """Bind a result to every frozen case/variant/snapshot/pack hash."""

        with self._lock:
            bundle = self._load_bundle()
            runner, queue, plan = self._open(evaluation_handle)
            item = next(
                (
                    candidate
                    for candidate in queue.load_items()
                    if candidate.work_item_id == work_item_id
                ),
                None,
            )
            if item is None:
                raise EvaluationRuntimeError("EVALUATION_WORK_ITEM_UNAVAILABLE")
            case = next(
                case
                for dataset in bundle.datasets
                for case in dataset.cases
                if case.case_id == item.case_id
            )
            prompt_sha256 = canonical_sha256(_prompt_for(case).model_dump(mode="json"))
            exact = (
                hmac.compare_digest(case_payload_sha256, prompt_sha256)
                and hmac.compare_digest(variant_sha256, item.variant_sha256)
                and client_snapshot_ref == item.client_snapshot_ref
                and hmac.compare_digest(
                    evidence_catalog_sha256,
                    item.evidence_catalog_sha256,
                )
                and hmac.compare_digest(
                    evidence_pack_sha256,
                    result.final_bundle.evidence_pack_sha256,
                )
                and hmac.compare_digest(
                    evidence_pack_sha256,
                    result.run_manifest.evidence.evidence_pack_canonical_sha256,
                )
            )
            if not exact:
                raise EvaluationRuntimeError("EVALUATION_SUBMISSION_BINDING_MISMATCH")
            try:
                accepted: EvaluationSubmission = runner.submit(
                    work_item_id=work_item_id,
                    result=result,
                )
            except Exception as exc:
                raise EvaluationRuntimeError("EVALUATION_SUBMISSION_REJECTED") from exc
            return AcceptedEvaluation(
                evaluation_handle=evaluation_handle,
                work_item_id=accepted.work_item_id,
                case_id=accepted.case_id,
                variant_name=accepted.variant_name,
                final_bundle_sha256=accepted.final_bundle_sha256,
                accepted_count=len(queue.load_submissions()),
                expected_count=plan.expected_item_count,
            )

    def finalize(
        self,
        evaluation_handle: str,
        *,
        missing_reasons: Mapping[str, SafePolicyKey] | None = None,
    ) -> EvaluationFinalSummary:
        """Finalize only a complete queue or an exact reason for every gap."""

        with self._lock:
            runner, _queue, _plan = self._open(evaluation_handle)
            try:
                return runner.finalize(missing_reasons=missing_reasons)
            except ReportStateError as exc:
                raise EvaluationRuntimeError("EVALUATION_REPORT_INVALID") from exc
            except Exception as exc:
                raise EvaluationRuntimeError("EVALUATION_FINALIZE_INCOMPLETE") from exc


__all__ = [
    "AcceptedEvaluation",
    "EvaluationHandle",
    "EvaluationRuntime",
    "EvaluationRuntimeError",
    "NextEvaluationCase",
    "PreparedEvaluation",
    "SyntheticEvaluationPrompt",
]
