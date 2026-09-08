from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from consultation_kb.evaluation.datasets import (
    DatasetValidationError,
    assert_not_knowledge_index_input,
    load_evaluation_bundle,
    load_evaluation_dataset,
    records_sha256,
)
from consultation_kb.knowledge._canonical import canonical_json_bytes
from consultation_kb.models.evaluation import (
    MANDATORY_EVALUATION_SLICES,
    EvaluationCase,
)


FIXTURE_ROOT = Path(__file__).parents[2] / "fixtures" / "consultation_kb" / "evaluation"
FIXTURES = (
    FIXTURE_ROOT / "gold_cases.jsonl",
    FIXTURE_ROOT / "gold_retrieval.jsonl",
    FIXTURE_ROOT / "canary_cases.jsonl",
)
EXPECTED_FILE_SHA256 = {
    "canary_cases.jsonl": "cd8107078ebb31960ec67d51fe8c10e81e08c190d76c48d3da606980ac83c959",
    "gold_cases.jsonl": "a98f572c6ae4a3637431c83ac662fc8785ac989ced52e3c9153b74a83ec64c31",
    "gold_retrieval.jsonl": "e77cc7be4970a068d2e4cb9c0d90301fb612f5959dc32bb5b6901c01544b06d4",
}
EXPECTED_BUNDLE_SHA256 = "6e6a014cc44afad10a395d96d5053e017549f3416e348af3c61ee386d73965d9"
DATASET_FILE_BY_ID = {
    "syn_dataset_canary_cases": "canary_cases.jsonl",
    "syn_dataset_gold_cases": "gold_cases.jsonl",
    "syn_dataset_gold_retrieval": "gold_retrieval.jsonl",
}


def _read_rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _write_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    rendered = "\n".join(
        json.dumps(row, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        for row in rows
    )
    path.write_text(rendered + "\n", encoding="utf-8", newline="\n")


def _rehash(rows: list[dict[str, Any]]) -> None:
    cases = tuple(
        EvaluationCase.model_validate_json(canonical_json_bytes(row)) for row in rows[1:]
    )
    rows[0]["records_sha256"] = records_sha256(cases)


def test_checked_in_bundle_is_locked_synthetic_complete_and_not_indexable() -> None:
    bundle = load_evaluation_bundle(
        FIXTURES,
        expected_file_sha256=EXPECTED_FILE_SHA256,
    )

    assert bundle.bundle_sha256 == EXPECTED_BUNDLE_SHA256
    assert sum(len(dataset.cases) for dataset in bundle.datasets) == 10
    assert tuple(item.slice for item in bundle.slice_coverage) == tuple(
        sorted(MANDATORY_EVALUATION_SLICES)
    )
    assert all(item.count > 0 for item in bundle.slice_coverage)
    with pytest.raises(DatasetValidationError, match="lock set"):
        load_evaluation_bundle(FIXTURES, expected_file_sha256={})

    for dataset in bundle.datasets:
        assert dataset.manifest.synthetic_only is True
        assert dataset.manifest.sensitivity == "synthetic"
        assert dataset.manifest.knowledge_index_use == "forbidden"
        assert dataset.file_sha256 == EXPECTED_FILE_SHA256[
            DATASET_FILE_BY_ID[dataset.manifest.dataset_id]
        ]
        with pytest.raises(DatasetValidationError, match="forbidden"):
            assert_not_knowledge_index_input(dataset)
        for case in dataset.cases:
            assert case.sensitivity == "synthetic"
            assert case.case_id.startswith("syn_case_")
            assert case.synthetic_client_key.startswith("syn_subject_")
            assert len(case.acceptable_evidence_paths) >= 2
            assert len(
                {
                    tuple(path.evidence_refs)
                    for path in case.acceptable_evidence_paths
                }
            ) >= 2
            assert {item.owner for item in case.evaluator_rubric} == {"machine", "human"}


def test_loader_rejects_tampering_identity_data_duplicate_keys_and_unresolved_refs(
    tmp_path: Path,
) -> None:
    source = FIXTURE_ROOT / "gold_cases.jsonl"

    tampered_rows = _read_rows(source)
    tampered_rows[1]["input_turns"][0]["text"] += "篡改"
    tampered = tmp_path / "tampered.jsonl"
    _write_rows(tampered, tampered_rows)
    with pytest.raises(DatasetValidationError, match="record hash"):
        load_evaluation_dataset(tampered)

    identity_rows = _read_rows(source)
    identity_rows[1]["input_turns"][0]["text"] = "联系号码13800138000"
    identity = tmp_path / "identity.jsonl"
    _write_rows(identity, identity_rows)
    with pytest.raises(DatasetValidationError, match="invalid case"):
        load_evaluation_dataset(identity)

    unresolved_rows = _read_rows(source)
    required_ref = unresolved_rows[1]["critical_evidence_refs"][0]
    unresolved_rows[0]["object_catalog"] = [
        reference
        for reference in unresolved_rows[0]["object_catalog"]
        if reference != required_ref
    ]
    unresolved = tmp_path / "unresolved.jsonl"
    _write_rows(unresolved, unresolved_rows)
    with pytest.raises(DatasetValidationError, match="closure"):
        load_evaluation_dataset(unresolved)

    stale_policy_rows = _read_rows(source)
    stale_policy_rows[0]["policy_ref"]["version"] = 2
    stale_policy = tmp_path / "stale-policy.jsonl"
    _write_rows(stale_policy, stale_policy_rows)
    with pytest.raises(DatasetValidationError, match="manifest"):
        load_evaluation_dataset(stale_policy)

    duplicate = tmp_path / "duplicate-key.jsonl"
    raw = source.read_text(encoding="utf-8")
    raw = raw.replace(
        '{"record_type":"manifest",',
        '{"record_type":"manifest","record_type":"manifest",',
        1,
    )
    duplicate.write_text(raw, encoding="utf-8", newline="\n")
    with pytest.raises(DatasetValidationError, match="not valid JSON"):
        load_evaluation_dataset(duplicate)


def test_bundle_rejects_family_split_leak_and_cross_split_near_duplicate(
    tmp_path: Path,
) -> None:
    gold_cases = FIXTURE_ROOT / "gold_cases.jsonl"
    canary = FIXTURE_ROOT / "canary_cases.jsonl"
    retrieval_source = FIXTURE_ROOT / "gold_retrieval.jsonl"

    family_rows = _read_rows(retrieval_source)
    family_rows[2]["scenario_family"] = "syn_family_classics_relationship"
    _rehash(family_rows)
    family_leak = tmp_path / "family-leak.jsonl"
    _write_rows(family_leak, family_rows)
    with pytest.raises(DatasetValidationError, match="family crosses"):
        load_evaluation_bundle((gold_cases, family_leak, canary))

    near_rows = _read_rows(retrieval_source)
    gold_rows = _read_rows(gold_cases)
    near_rows[2]["input_turns"] = copy.deepcopy(gold_rows[1]["input_turns"])
    _rehash(near_rows)
    near_duplicate = tmp_path / "near-duplicate.jsonl"
    _write_rows(near_duplicate, near_rows)
    with pytest.raises(DatasetValidationError, match="near-duplicate"):
        load_evaluation_bundle((gold_cases, near_duplicate, canary))


def test_case_contract_requires_distinct_paths_and_explicit_rubric_ownership() -> None:
    case_payload = _read_rows(FIXTURE_ROOT / "gold_cases.jsonl")[1]

    one_path = copy.deepcopy(case_payload)
    one_path["acceptable_evidence_paths"] = one_path["acceptable_evidence_paths"][:1]
    with pytest.raises(ValidationError, match="at least two"):
        EvaluationCase.model_validate_json(canonical_json_bytes(one_path))

    ambiguous_owner = copy.deepcopy(case_payload)
    ambiguous_owner["evaluator_rubric"][0]["owner"] = "machine"
    ambiguous_owner["evaluator_rubric"][0]["machine_metric"] = "helpfulness_guess"
    ambiguous_owner["evaluator_rubric"][0]["human_prompt"] = None
    with pytest.raises(ValidationError, match="machine and human"):
        EvaluationCase.model_validate_json(canonical_json_bytes(ambiguous_owner))

    controlled = copy.deepcopy(case_payload)
    controlled["sensitivity"] = "controlled"
    with pytest.raises(ValidationError):
        EvaluationCase.model_validate_json(canonical_json_bytes(controlled))
