from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from consultation_kb import cli
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.evaluation.datasets import load_evaluation_bundle
from consultation_kb.evaluation.runner import DeterministicFakeStageRunner
from consultation_kb.evaluation.runtime import (
    EvaluationRuntime,
    NextEvaluationCase,
)
from consultation_kb.evaluation.variants import SYSTEM_VARIANTS_BY_NAME
from consultation_kb.evaluation.work_queue import (
    EvaluationFairnessContract,
    EvaluationWorkItem,
)
from consultation_kb.mcp import (
    HandlerServices,
    McpHandlerContext,
    P9_TOOL_NAMES,
    TransportBindingRegistry,
    build_handler_registry,
)
from consultation_kb.mcp.context import BoundTransport
from consultation_kb.mcp.evaluation_tools import EvaluationToolRuntime
from consultation_kb.models.common import StrictModel, VersionRef
from consultation_kb.observability.runs import (
    NamedVersionRef,
    RunReproducibilitySnapshot,
    RuntimeEnvironmentSnapshot,
)


NOW = datetime(2026, 7, 22, 16, 0, tzinfo=timezone.utc)
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = REPOSITORY_ROOT / "tests" / "fixtures" / "consultation_kb" / "evaluation"
FIXTURES = tuple(
    FIXTURE_ROOT / name
    for name in ("gold_cases.jsonl", "gold_retrieval.jsonl", "canary_cases.jsonl")
)


def _sha(index: int) -> str:
    return f"{index:064x}"


def _uuid7(index: int) -> str:
    return IdFactory(FixedClock(NOW), lambda: index).uuid7()


def _ref(kind: str, index: int) -> VersionRef:
    return VersionRef(
        object_id=IdFactory(FixedClock(NOW), lambda: index).object_id(kind),
        version=index + 1,
        content_sha256=_sha(index + 1),
    )


def _fairness(seed: int = 417) -> EvaluationFairnessContract:
    return EvaluationFairnessContract(
        model_label="gpt-5.6-codex",
        reasoning_effort="high",
        model_descriptor_ref=_ref("model", 1),
        model_parameters_ref=_ref("model_parameters", 2),
        prompt_refs=(
            NamedVersionRef(name="query_plan", ref=_ref("prompt", 3)),
            NamedVersionRef(name="reply", ref=_ref("prompt", 4)),
        ),
        skill_refs=(
            NamedVersionRef(name="consultation", ref=_ref("skill", 5)),
            NamedVersionRef(name="evaluation", ref=_ref("skill", 6)),
        ),
        schema_ref=_ref("schema", 7),
        reply_contract_ref=_ref("reply_contract", 8),
        wiki_manifest_ref=_ref("wiki_manifest", 9),
        case_manifest_ref=_ref("case_manifest", 10),
        graph_manifest_ref=_ref("graph_manifest", 11),
        lexical_manifest_ref=_ref("lexical_manifest", 12),
        vector_manifest_ref=_ref("vector_manifest", 13),
        reranker_descriptor_ref=_ref("reranker", 14),
        authority_snapshot_ref=_ref("authority_snapshot", 15),
        authority_policy_ref=_ref("authority_policy", 16),
        c1_revision_ref=_ref("c1_revision", 17),
        c1_scope_policy_ref=_ref("c1_scope_policy", 18),
        c1_applicability_ref=_ref("c1_applicability", 19),
        exclusion_proof_ref=_ref("exclusion_proof", 20),
        runtime=RuntimeEnvironmentSnapshot(
            python_version="3.12.10",
            base_executable_sha256=_sha(21),
            runtime_source_tag="dedicated_venv",
            runtime_source_sha256=_sha(22),
            schema_bundle_sha256=_sha(23),
            package_set_sha256=_sha(24),
            dependency_lock_sha256=_sha(25),
        ),
        reproducibility=RunReproducibilitySnapshot(
            queue_order_seed=seed,
            generation_seed=None,
            temperature_milli=None,
            host_unknown_fields=("generation_seed", "temperature"),
        ),
        retry_budget=2,
    )


class _UnusedService:
    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object:
        del tool_name, request, binding
        raise AssertionError("unrelated service invoked")


def _registry(tmp_path: Path):  # type: ignore[no-untyped-def]
    unused = _UnusedService()
    evaluation = EvaluationToolRuntime(
        EvaluationRuntime(repo_root=REPOSITORY_ROOT, vault_root=tmp_path)
    )
    return build_handler_registry(
        McpHandlerContext(
            transport_session_id="evaluation-test-transport",
            bindings=TransportBindingRegistry(),
            services=HandlerServices(
                read=unused,
                graph=unused,
                session=unused,
                knowledge=unused,
                write=unused,
                evaluation=evaluation,
            ),
        )
    )


def _invoke(handler, arguments):  # type: ignore[no-untyped-def]
    return asyncio.run(handler(arguments))


def _prepare(registry, run_index: int = 500):  # type: ignore[no-untyped-def]
    return _invoke(
        registry["prepare_evaluation"],
        {
            "evaluation_run_id": _uuid7(run_index),
            "fairness": _fairness().model_dump(mode="json"),
            "route_policies": [
                {
                    "variant_name": "general_model_only",
                    "route_policy_ref": _ref("route_policy", 100).model_dump(
                        mode="json"
                    ),
                }
            ],
            "variants": ["general_model_only"],
            "repetition_count": 2,
            "case_ids": ["syn_case_classics_relationship"],
            "include_canary": False,
        },
    )


def _next(registry, handle: str):  # type: ignore[no-untyped-def]
    envelope = _invoke(
        registry["get_next_evaluation_case"],
        {"evaluation_handle": handle},
    )
    assert envelope.ok
    return NextEvaluationCase.model_validate_json(
        json.dumps(envelope.result, ensure_ascii=False),
        strict=True,
    )


def _stage_result(next_case: NextEvaluationCase):  # type: ignore[no-untyped-def]
    assert next_case.work_item is not None
    assert next_case.variant is not None
    assert next_case.fairness is not None
    bundle = load_evaluation_bundle(FIXTURES)
    case = next(
        case
        for dataset in bundle.datasets
        for case in dataset.cases
        if case.case_id == next_case.work_item.case_id
    )
    return DeterministicFakeStageRunner().run(
        case=case,
        item=next_case.work_item,
        variant=next_case.variant,
        fairness=next_case.fairness,
    )


def _submission_arguments(next_case: NextEvaluationCase) -> dict[str, object]:
    assert next_case.work_item is not None
    assert next_case.case_payload_sha256 is not None
    result = _stage_result(next_case)
    return {
        "evaluation_handle": next_case.evaluation_handle,
        "work_item_id": next_case.work_item.work_item_id,
        "case_payload_sha256": next_case.case_payload_sha256,
        "variant_sha256": next_case.work_item.variant_sha256,
        "client_snapshot_ref": next_case.work_item.client_snapshot_ref.model_dump(
            mode="json"
        ),
        "evidence_catalog_sha256": next_case.work_item.evidence_catalog_sha256,
        "evidence_pack_sha256": result.final_bundle.evidence_pack_sha256,
        "result": result.model_dump(mode="json"),
    }


def test_evaluation_registry_uses_real_local_runtime_and_discloses_body_only_on_get(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    assert tuple(registry) == P9_TOOL_NAMES

    prepared = _prepare(registry)
    assert prepared.ok
    serialized_prepare = json.dumps(prepared.result, ensure_ascii=False)
    assert "来访者甲" not in serialized_prepare
    assert str(tmp_path) not in serialized_prepare
    assert "client_" not in serialized_prepare
    assert isinstance(prepared.result, dict)
    handle = prepared.result["evaluation_handle"]
    assert isinstance(handle, str)

    next_case = _next(registry, handle)
    assert next_case.pending
    assert next_case.prompt is not None
    assert next_case.prompt.case_id.startswith("syn_case_")
    assert "来访者甲" in next_case.prompt.input_turns[0].text
    serialized_next = json.dumps(next_case.model_dump(mode="json"), ensure_ascii=False)
    assert re.search(r"client_[a-z0-9]{12}", serialized_next) is None
    assert '"client_id"' not in serialized_next

    queue_bytes = b"".join(
        path.read_bytes()
        for path in (tmp_path / "evaluation" / "runs" / _uuid7(500)).iterdir()
        if path.is_file()
    )
    assert "来访者甲".encode() not in queue_bytes

    denied = _invoke(
        registry["get_next_evaluation_case"],
        {"evaluation_handle": "f" * 64},
    )
    assert not denied.ok
    assert denied.result is None
    assert denied.error is not None and denied.error.code == "INTERNAL_ERROR"


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("case_payload_sha256", "a" * 64),
        ("variant_sha256", "b" * 64),
        ("evidence_catalog_sha256", "c" * 64),
        ("evidence_pack_sha256", "d" * 64),
    ),
)
def test_submit_fails_closed_on_every_external_hash_binding(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    registry = _registry(tmp_path)
    prepared = _prepare(registry)
    assert prepared.ok and isinstance(prepared.result, dict)
    next_case = _next(registry, str(prepared.result["evaluation_handle"]))
    arguments = _submission_arguments(next_case)
    arguments[field] = replacement

    rejected = _invoke(registry["submit_evaluation_result"], arguments)

    assert not rejected.ok
    assert rejected.result is None
    assert rejected.error is not None and rejected.error.code == "INTERNAL_ERROR"
    assert _next(registry, next_case.evaluation_handle).completed_count == 0


def test_submit_binds_snapshot_and_finalize_requires_exact_missing_set(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    prepared = _prepare(registry)
    assert prepared.ok and isinstance(prepared.result, dict)
    handle = str(prepared.result["evaluation_handle"])
    first = _next(registry, handle)
    arguments = _submission_arguments(first)
    arguments["client_snapshot_ref"] = _ref("synthetic_snapshot", 999).model_dump(
        mode="json"
    )
    rejected = _invoke(registry["submit_evaluation_result"], arguments)
    assert not rejected.ok

    accepted = _invoke(
        registry["submit_evaluation_result"],
        _submission_arguments(first),
    )
    assert accepted.ok
    assert "来访者甲" not in json.dumps(accepted.result, ensure_ascii=False)

    incomplete = _invoke(
        registry["finalize_evaluation"],
        {"evaluation_handle": handle, "missing_reasons": []},
    )
    assert not incomplete.ok

    second = _next(registry, handle)
    assert second.work_item is not None
    finalized = _invoke(
        registry["finalize_evaluation"],
        {
            "evaluation_handle": handle,
            "missing_reasons": [
                {
                    "work_item_id": second.work_item.work_item_id,
                    "reason_code": "host_interrupted",
                }
            ],
        },
    )
    assert finalized.ok
    assert isinstance(finalized.result, dict)
    assert finalized.result["status"] == "incomplete"
    assert finalized.result["completed_count"] == 1
    assert "来访者甲" not in json.dumps(finalized.result, ensure_ascii=False)


def test_submit_schema_never_reflects_candidate_body_on_validation_error(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    prepared = _prepare(registry)
    assert prepared.ok and isinstance(prepared.result, dict)
    next_case = _next(registry, str(prepared.result["evaluation_handle"]))
    arguments = _submission_arguments(next_case)
    result = arguments["result"]
    assert isinstance(result, dict)
    result["unexpected_body"] = "PRIVATE-EVALUATION-CANARY"

    rejected = _invoke(registry["submit_evaluation_result"], arguments)

    serialized = rejected.model_dump_json()
    assert not rejected.ok
    assert "PRIVATE-EVALUATION-CANARY" not in serialized
    assert "来访者甲" not in serialized


def test_restart_reopens_queue_by_plan_hash_without_a_path_argument(
    tmp_path: Path,
) -> None:
    first_registry = _registry(tmp_path)
    prepared = _prepare(first_registry)
    assert prepared.ok and isinstance(prepared.result, dict)
    handle = str(prepared.result["evaluation_handle"])
    before = _next(first_registry, handle)

    restarted_registry = _registry(tmp_path)
    after = _next(restarted_registry, handle)

    assert after.work_item == before.work_item
    assert after.case_payload_sha256 == before.case_payload_sha256
    assert after.prompt == before.prompt
    assert all(
        "path" not in field
        for name in P9_TOOL_NAMES[-4:]
        for field in registry_model_fields(restarted_registry[name])
    )


def registry_model_fields(handler) -> tuple[str, ...]:  # type: ignore[no-untyped-def]
    return tuple(handler.input_model.model_fields)


def test_work_item_transport_model_round_trip_remains_body_free(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    prepared = _prepare(registry)
    assert prepared.ok and isinstance(prepared.result, dict)
    next_case = _next(registry, str(prepared.result["evaluation_handle"]))
    assert next_case.work_item is not None
    item = EvaluationWorkItem.model_validate_json(
        next_case.work_item.model_dump_json(), strict=True
    )
    assert item == next_case.work_item
    assert "来访者甲" not in item.model_dump_json()
    assert SYSTEM_VARIANTS_BY_NAME[item.variant_name] == next_case.variant


def test_evaluation_cli_mirrors_strict_prepare_and_next_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("CONSULTATION_VAULT_ROOT", raising=False)
    vault = tmp_path / "vault"
    vault.mkdir()
    prepare_request = tmp_path / "prepare.json"
    prepare_request.write_text(
        json.dumps(
            {
                "evaluation_run_id": _uuid7(700),
                "fairness": _fairness().model_dump(mode="json"),
                "route_policies": [
                    {
                        "variant_name": "general_model_only",
                        "route_policy_ref": _ref("route_policy", 300).model_dump(
                            mode="json"
                        ),
                    }
                ],
                "variants": ["general_model_only"],
                "repetition_count": 2,
                "case_ids": ["syn_case_classics_relationship"],
                "include_canary": False,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    assert (
        cli.main(
            (
                "evaluation-prepare",
                "--request",
                str(prepare_request),
                "--repo-root",
                str(REPOSITORY_ROOT),
                "--vault-root",
                str(vault),
                "--json",
            )
        )
        == 0
    )
    prepared_output = capsys.readouterr()
    assert prepared_output.err == ""
    prepared = json.loads(prepared_output.out)
    assert prepared["ok"] is True
    assert "来访者甲" not in prepared_output.out

    next_request = tmp_path / "next.json"
    next_request.write_text(
        json.dumps(
            {
                "evaluation_handle": prepared["result"]["evaluation_handle"],
            }
        ),
        encoding="utf-8",
    )
    assert (
        cli.main(
            (
                "evaluation-next",
                "--request",
                str(next_request),
                "--repo-root",
                str(REPOSITORY_ROOT),
                "--vault-root",
                str(vault),
                "--json",
            )
        )
        == 0
    )
    next_output = capsys.readouterr()
    assert next_output.err == ""
    next_payload = json.loads(next_output.out)
    assert "来访者甲" in next_payload["result"]["prompt"]["input_turns"][0]["text"]
    assert str(vault) not in next_output.out
