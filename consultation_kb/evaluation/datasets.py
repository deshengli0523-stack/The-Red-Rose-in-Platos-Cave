"""Fail-closed loader and cross-split validation for synthetic gold datasets."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from consultation_kb.knowledge._canonical import canonical_json_bytes, canonical_sha256
from consultation_kb.models.evaluation import (
    MANDATORY_EVALUATION_SLICES,
    EvaluationCase,
    EvaluationDataset,
    EvaluationDatasetBundle,
    EvaluationDatasetManifest,
    EvaluationSlice,
    SliceCoverage,
)


MAX_DATASET_BYTES = 8 * 1024 * 1024
MAX_JSONL_LINE_BYTES = 256 * 1024
MAX_RECORDS = 10_000
NEAR_DUPLICATE_SEQUENCE_THRESHOLD = 0.90
NEAR_DUPLICATE_SHINGLE_THRESHOLD = 0.82


class DatasetValidationError(ValueError):
    """Body-free failure raised for malformed or unsafe evaluation fixtures."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DatasetValidationError("JSON object contains a duplicate key")
        result[key] = value
    return result


def _parse_json_object(line: bytes, *, line_number: int) -> dict[str, Any]:
    if len(line) > MAX_JSONL_LINE_BYTES:
        raise DatasetValidationError(f"dataset line {line_number} exceeds the size limit")
    try:
        text = line.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, DatasetValidationError) as exc:
        raise DatasetValidationError(f"dataset line {line_number} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise DatasetValidationError(f"dataset line {line_number} must be a JSON object")
    return value


def canonical_records_bytes(cases: Sequence[EvaluationCase]) -> bytes:
    """Return the stable semantic JSONL bytes covered by ``records_sha256``."""

    return b"".join(
        canonical_json_bytes(case.model_dump(mode="json")) + b"\n" for case in cases
    )


def records_sha256(cases: Sequence[EvaluationCase]) -> str:
    return hashlib.sha256(canonical_records_bytes(cases)).hexdigest()


def load_evaluation_dataset(
    path: str | Path,
    *,
    expected_file_sha256: str | None = None,
) -> EvaluationDataset:
    """Load one immutable synthetic JSONL dataset.

    The embedded manifest anchors canonical case records and their exact object
    catalog.  ``expected_file_sha256`` optionally pins the raw checked-in bytes
    as an additional release/CI guard.
    """

    source = Path(path)
    if source.is_symlink():
        raise DatasetValidationError("evaluation dataset must not be a symlink")
    try:
        stat = source.stat()
    except OSError as exc:
        raise DatasetValidationError("evaluation dataset is unavailable") from exc
    if not source.is_file():
        raise DatasetValidationError("evaluation dataset must be a regular file")
    if stat.st_size <= 0 or stat.st_size > MAX_DATASET_BYTES:
        raise DatasetValidationError("evaluation dataset has an invalid size")
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise DatasetValidationError("evaluation dataset cannot be read") from exc
    if raw.startswith(b"\xef\xbb\xbf"):
        raise DatasetValidationError("evaluation dataset must be BOM-free UTF-8")
    if not raw.endswith(b"\n"):
        raise DatasetValidationError("evaluation dataset must end with a newline")

    lines = raw.splitlines()
    if not lines or len(lines) > MAX_RECORDS + 1 or any(not line for line in lines):
        raise DatasetValidationError("evaluation dataset has an invalid record layout")
    objects = [
        _parse_json_object(line, line_number=index)
        for index, line in enumerate(lines, start=1)
    ]
    try:
        manifest = EvaluationDatasetManifest.model_validate_json(
            canonical_json_bytes(objects[0])
        )
    except ValidationError as exc:
        raise DatasetValidationError("evaluation dataset manifest is invalid") from exc
    if any(value.get("record_type") == "manifest" for value in objects[1:]):
        raise DatasetValidationError("evaluation dataset contains multiple manifests")
    try:
        cases = tuple(
            EvaluationCase.model_validate_json(canonical_json_bytes(value))
            for value in objects[1:]
        )
    except ValidationError as exc:
        raise DatasetValidationError("evaluation dataset contains an invalid case") from exc

    calculated_records_sha256 = records_sha256(cases)
    if calculated_records_sha256 != manifest.records_sha256:
        raise DatasetValidationError("evaluation dataset record hash does not match manifest")
    file_sha256 = hashlib.sha256(raw).hexdigest()
    if expected_file_sha256 is not None and file_sha256 != expected_file_sha256:
        raise DatasetValidationError("evaluation dataset file hash does not match lock")
    try:
        return EvaluationDataset(
            manifest=manifest,
            cases=cases,
            file_sha256=file_sha256,
        )
    except ValidationError as exc:
        raise DatasetValidationError("evaluation dataset closure is invalid") from exc


def _normalized_case_text(case: EvaluationCase) -> str:
    text = "".join(turn.text for turn in case.input_turns)
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return "".join(character for character in normalized if character.isalnum())


def _shingles(value: str, *, width: int = 3) -> frozenset[str]:
    if len(value) < width:
        return frozenset({value})
    return frozenset(value[index : index + width] for index in range(len(value) - width + 1))


def _near_duplicate(left: EvaluationCase, right: EvaluationCase) -> bool:
    left_text = _normalized_case_text(left)
    right_text = _normalized_case_text(right)
    if left_text == right_text:
        return True
    sequence_score = SequenceMatcher(None, left_text, right_text, autojunk=False).ratio()
    left_shingles = _shingles(left_text)
    right_shingles = _shingles(right_text)
    union = left_shingles | right_shingles
    shingle_score = len(left_shingles & right_shingles) / len(union) if union else 1.0
    return (
        sequence_score >= NEAR_DUPLICATE_SEQUENCE_THRESHOLD
        or shingle_score >= NEAR_DUPLICATE_SHINGLE_THRESHOLD
    )


def _validate_catalog_consistency(datasets: Sequence[EvaluationDataset]) -> None:
    versions: dict[tuple[str, int], str] = {}
    for dataset in datasets:
        for reference in dataset.manifest.object_catalog:
            key = (reference.object_id, reference.version)
            previous = versions.setdefault(key, reference.content_sha256)
            if previous != reference.content_sha256:
                raise DatasetValidationError(
                    "bundle catalogs disagree about one immutable object version"
                )


def _validate_family_and_duplicate_boundaries(
    datasets: Sequence[EvaluationDataset],
) -> None:
    gold_cases = tuple(
        case
        for dataset in datasets
        if dataset.manifest.dataset_kind != "canary_cases"
        for case in dataset.cases
    )
    family_splits: dict[str, str] = {}
    for case in gold_cases:
        previous = family_splits.setdefault(case.scenario_family, case.split)
        if previous != case.split:
            raise DatasetValidationError("scenario family crosses gold dataset splits")

    for index, left in enumerate(gold_cases):
        for right in gold_cases[index + 1 :]:
            if left.split != right.split and _near_duplicate(left, right):
                raise DatasetValidationError("near-duplicate cases cross gold dataset splits")

    gold_families = set(family_splits)
    for dataset in datasets:
        if dataset.manifest.dataset_kind != "canary_cases":
            continue
        for case in dataset.cases:
            if not case.scenario_family.startswith("syn_family_canary_"):
                raise DatasetValidationError("canary family must use the canary namespace")
            if case.scenario_family in gold_families:
                raise DatasetValidationError("canary scenario family overlaps gold data")


def _slice_coverage(
    datasets: Sequence[EvaluationDataset],
) -> tuple[SliceCoverage, ...]:
    counts: dict[EvaluationSlice, int] = {}
    for dataset in datasets:
        if dataset.manifest.dataset_kind == "canary_cases":
            continue
        for case in dataset.cases:
            for slice_name in case.slices:
                counts[slice_name] = counts.get(slice_name, 0) + 1
    return tuple(
        SliceCoverage(slice=slice_name, count=counts[slice_name])
        for slice_name in sorted(counts)
    )


def load_evaluation_bundle(
    paths: Iterable[str | Path],
    *,
    expected_file_sha256: Mapping[str, str] | None = None,
    require_full_slice_coverage: bool = True,
) -> EvaluationDatasetBundle:
    """Load datasets and enforce boundaries that only exist across files."""

    inputs = tuple(Path(path) for path in paths)
    if not inputs:
        raise DatasetValidationError("evaluation bundle must contain datasets")
    normalized_paths = tuple(str(path.resolve(strict=False)) for path in inputs)
    if len(set(normalized_paths)) != len(normalized_paths):
        raise DatasetValidationError("evaluation bundle contains a duplicate path")
    locks = expected_file_sha256 or {}
    if expected_file_sha256 is not None:
        input_names = tuple(path.name for path in inputs)
        if len(set(input_names)) != len(input_names):
            raise DatasetValidationError("locked evaluation paths need unique file names")
        if set(locks) != set(input_names):
            raise DatasetValidationError("evaluation bundle lock set is incomplete or stale")
    datasets = tuple(
        sorted(
            (
                load_evaluation_dataset(
                    path,
                    expected_file_sha256=locks.get(path.name),
                )
                for path in inputs
            ),
            key=lambda dataset: dataset.manifest.dataset_id,
        )
    )
    dataset_ids = tuple(dataset.manifest.dataset_id for dataset in datasets)
    if len(set(dataset_ids)) != len(dataset_ids):
        raise DatasetValidationError("evaluation bundle contains a duplicate dataset ID")
    _validate_catalog_consistency(datasets)
    _validate_family_and_duplicate_boundaries(datasets)
    coverage = _slice_coverage(datasets)
    covered = {item.slice for item in coverage}
    if require_full_slice_coverage:
        missing = set(MANDATORY_EVALUATION_SLICES) - covered
        if missing:
            raise DatasetValidationError("evaluation bundle does not cover every required slice")
    bundle_sha256 = canonical_sha256(
        [
            {
                "dataset_id": dataset.manifest.dataset_id,
                "dataset_version": dataset.manifest.dataset_version,
                "file_sha256": dataset.file_sha256,
                "records_sha256": dataset.manifest.records_sha256,
            }
            for dataset in datasets
        ]
    )
    try:
        return EvaluationDatasetBundle(
            datasets=datasets,
            slice_coverage=coverage,
            bundle_sha256=bundle_sha256,
        )
    except ValidationError as exc:
        raise DatasetValidationError("evaluation bundle contract is invalid") from exc


def assert_not_knowledge_index_input(dataset: EvaluationDataset) -> None:
    """Fail closed if an evaluation fixture is offered to a knowledge index."""

    del dataset
    raise DatasetValidationError("evaluation datasets are forbidden knowledge-index inputs")


__all__ = [
    "DatasetValidationError",
    "MAX_DATASET_BYTES",
    "MAX_JSONL_LINE_BYTES",
    "MAX_RECORDS",
    "NEAR_DUPLICATE_SEQUENCE_THRESHOLD",
    "NEAR_DUPLICATE_SHINGLE_THRESHOLD",
    "assert_not_knowledge_index_input",
    "canonical_records_bytes",
    "load_evaluation_bundle",
    "load_evaluation_dataset",
    "records_sha256",
]
