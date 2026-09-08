from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from consultation_kb.evaluation import work_queue as work_queue_module
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.evaluation.datasets import load_evaluation_bundle
from consultation_kb.evaluation.runner import (
    DeterministicFakeStageRunner,
    EvaluationRunner,
    EvaluationValidationError,
    IncompleteEvaluationError,
)
from consultation_kb.evaluation.runtime import EvaluationRuntime, EvaluationRuntimeError
from consultation_kb.evaluation.variants import (
    ALL_EVIDENCE_CHANNELS,
    ALL_SYSTEM_VARIANTS,
    SystemVariantName,
)
from consultation_kb.evaluation.work_queue import (
    ChannelUsageCount,
    EvaluationFairnessContract,
    EvaluationWorkQueue,
    QueueStateError,
    ReportStateError,
    RoutedEvidenceUse,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evaluation import EvaluationDatasetBundle
from consultation_kb.observability.runs import (
    NamedVersionRef,
    RunReproducibilitySnapshot,
    RuntimeEnvironmentSnapshot,
)


NOW = datetime(2026, 7, 22, 16, 0, tzinfo=timezone.utc)
FIXTURE_ROOT = Path(__file__).parents[2] / "fixtures" / "consultation_kb" / "evaluation"
FIXTURES = (
    FIXTURE_ROOT / "gold_cases.jsonl",
    FIXTURE_ROOT / "gold_retrieval.jsonl",
    FIXTURE_ROOT / "canary_cases.jsonl",
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


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


def _route_policy_refs() -> dict[SystemVariantName, VersionRef]:
    return {
        variant.name: _ref("route_policy", 100 + index)
        for index, variant in enumerate(ALL_SYSTEM_VARIANTS)
    }


def _bundle() -> EvaluationDatasetBundle:
    return load_evaluation_bundle(FIXTURES)


def _completed_runtime(
    tmp_path: Path,
    *,
    run_index: int,
) -> tuple[EvaluationRuntime, str, EvaluationWorkQueue]:
    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    runtime = EvaluationRuntime(repo_root=REPOSITORY_ROOT, vault_root=vault_root)
    evaluation_run_id = _uuid7(run_index)
    prepared = runtime.prepare(
        evaluation_run_id=evaluation_run_id,
        fairness=_fairness(),
        route_policy_refs={"general_model_only": _ref("route_policy", run_index)},
        variants=("general_model_only",),
        repetition_count=2,
        case_ids=("syn_case_classics_relationship",),
    )
    queue = EvaluationWorkQueue(vault_root / "evaluation" / "runs" / evaluation_run_id)
    runner = EvaluationRunner(
        queue,
        stage_runner=DeterministicFakeStageRunner(),
    )
    runner.bind_dataset(_bundle())
    assert len(runner.run_pending()) == 2
    return runtime, prepared.evaluation_handle, queue


def test_runner_executes_all_variants_with_paired_fairness_and_no_body_queue(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    case = next(
        item
        for dataset in bundle.datasets
        for item in dataset.cases
        if item.case_id == "syn_case_classics_relationship"
    )
    queue = EvaluationWorkQueue(tmp_path / "evaluation-queue")
    fake = DeterministicFakeStageRunner()
    runner = EvaluationRunner(queue, stage_runner=fake)
    fairness = _fairness()

    plan = runner.prepare(
        bundle=bundle,
        fairness=fairness,
        evaluation_run_id=_uuid7(500),
        route_policy_refs=_route_policy_refs(),
        case_ids=(case.case_id,),
        repetition_count=2,
    )

    assert plan.expected_item_count == 16
    assert tuple(item.queue_index for item in queue.load_items()) == tuple(range(16))
    assert {
        (item.case_id, item.variant_name, item.repetition_index)
        for item in queue.load_items()
    } == {
        (case.case_id, variant.name, repetition)
        for variant in ALL_SYSTEM_VARIANTS
        for repetition in range(2)
    }
    assert all(
        item.client_snapshot_ref == case.synthetic_client_snapshot_ref
        for item in queue.load_items()
    )

    submissions = runner.run_pending()
    assert len(submissions) == 16
    assert runner.run_pending() == ()
    variants = {variant.name: variant for variant in ALL_SYSTEM_VARIANTS}
    for submission in submissions:
        variant = variants[submission.variant_name]
        counts = {item.channel: item.count for item in submission.trace.channel_counts}
        assert all(
            counts[channel] == 0 for channel in variant.features.prohibited_routes
        )
        assert submission.trace.model_label == fairness.model_label
        assert submission.trace.reasoning_effort == fairness.reasoning_effort
        assert submission.trace.schema_ref == fairness.schema_ref
        assert submission.trace.reply_contract_ref == fairness.reply_contract_ref
        assert submission.trace.configured_retry_budget == fairness.retry_budget
        assert submission.run_manifest.runtime == fairness.runtime
        assert submission.run_manifest.reproducibility == fairness.reproducibility
        assert submission.run_manifest.versions.client_snapshot_ref == (
            case.synthetic_client_snapshot_ref
        )
        assert submission.run_manifest.routing.routes == variant.features.routes

    persisted = b"".join(
        path.read_bytes()
        for path in (queue.plan_path, queue.items_path, queue.submissions_path)
    )
    for turn in case.input_turns:
        assert turn.text.encode("utf-8") not in persisted
    assert "我理解这件事让你很为难".encode() not in persisted

    summary = runner.finalize()
    assert summary.status == "succeeded"
    assert summary.completed_count == summary.expected_count == 16
    assert not summary.missing
    assert (queue.root / queue.REPORT_JSON_NAME).is_file()
    assert (queue.root / queue.REPORT_MARKDOWN_NAME).is_file()


def test_runner_rejects_forbidden_channel_evidence_and_snapshot_drift(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    case = next(
        item
        for dataset in bundle.datasets
        for item in dataset.cases
        if item.case_id == "syn_case_classics_relationship"
    )
    base_fake = DeterministicFakeStageRunner()

    def leaking_factory(case, item, variant, fairness):  # type: ignore[no-untyped-def]
        result = base_fake.run(
            case=case,
            item=item,
            variant=variant,
            fairness=fairness,
        )
        leaked = RoutedEvidenceUse(
            evidence_ref=case.critical_evidence_refs[0],
            channel="lexical",
        )
        counts = tuple(
            ChannelUsageCount(
                channel=channel,
                count=1 if channel == "lexical" else 0,
            )
            for channel in ALL_EVIDENCE_CHANNELS
        )
        return result.model_copy(
            update={
                "evidence_uses": (leaked,),
                "trace": result.trace.model_copy(update={"channel_counts": counts}),
            }
        )

    queue = EvaluationWorkQueue(tmp_path / "leaking-queue")
    runner = EvaluationRunner(
        queue,
        stage_runner=DeterministicFakeStageRunner(leaking_factory),
    )
    runner.prepare(
        bundle=bundle,
        fairness=_fairness(),
        evaluation_run_id=_uuid7(501),
        route_policy_refs={"general_model_only": _ref("route_policy", 201)},
        variants=(ALL_SYSTEM_VARIANTS[0],),
        case_ids=(case.case_id,),
        repetition_count=2,
    )
    with pytest.raises(EvaluationValidationError, match="prohibited variant channel"):
        runner.run_pending(limit=1)

    clean_queue = EvaluationWorkQueue(tmp_path / "snapshot-queue")
    clean_runner = EvaluationRunner(
        clean_queue,
        stage_runner=DeterministicFakeStageRunner(),
    )
    clean_runner.prepare(
        bundle=bundle,
        fairness=_fairness(),
        evaluation_run_id=_uuid7(502),
        route_policy_refs={"general_model_only": _ref("route_policy", 202)},
        variants=(ALL_SYSTEM_VARIANTS[0],),
        case_ids=(case.case_id,),
        repetition_count=2,
    )
    item = clean_queue.load_items()[0]
    result = DeterministicFakeStageRunner().run(
        case=case,
        item=item,
        variant=ALL_SYSTEM_VARIANTS[0],
        fairness=_fairness(),
    )
    drifted = _ref("synthetic_snapshot", 999)
    manifest = result.run_manifest.model_copy(
        update={
            "versions": result.run_manifest.versions.model_copy(
                update={"client_snapshot_ref": drifted}
            ),
            "evidence": result.run_manifest.evidence.model_copy(
                update={"client_snapshot_ref": drifted}
            ),
        }
    )
    with pytest.raises(EvaluationValidationError, match="frozen fairness"):
        clean_runner.submit(
            work_item_id=item.work_item_id,
            result=result.model_copy(update={"run_manifest": manifest}),
        )


def test_finalize_fails_closed_or_reports_explicit_missing_without_success(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    case = next(
        item
        for dataset in bundle.datasets
        for item in dataset.cases
        if item.case_id == "syn_case_classics_relationship"
    )
    queue = EvaluationWorkQueue(tmp_path / "incomplete-queue")
    runner = EvaluationRunner(queue, stage_runner=DeterministicFakeStageRunner())
    runner.prepare(
        bundle=bundle,
        fairness=_fairness(),
        evaluation_run_id=_uuid7(503),
        route_policy_refs={"general_model_only": _ref("route_policy", 203)},
        variants=(ALL_SYSTEM_VARIANTS[0],),
        case_ids=(case.case_id,),
        repetition_count=2,
    )
    runner.run_pending(limit=1)

    with pytest.raises(IncompleteEvaluationError, match="every missing item"):
        runner.finalize()
    missing_id = next(
        item.work_item_id
        for item in queue.load_items()
        if item.work_item_id
        not in {submission.work_item_id for submission in queue.load_submissions()}
    )
    summary = runner.finalize(missing_reasons={missing_id: "host_interrupted"})
    assert summary.status == "incomplete"
    assert summary.completed_count == 1
    assert summary.missing[0].reason_code == "host_interrupted"
    with pytest.raises(QueueStateError, match="finalized"):
        runner.run_pending()
    assert len(queue.load_submissions()) == 1


def test_queue_order_seed_randomizes_order_but_not_generation_claims(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    case_ids = tuple(
        case.case_id
        for dataset in bundle.datasets
        for case in dataset.cases
        if case.split != "canary"
    )[:2]
    queue = EvaluationWorkQueue(tmp_path / "seeded-queue")
    fairness = _fairness(seed=991)
    runner = EvaluationRunner(queue)
    plan = runner.prepare(
        bundle=bundle,
        fairness=fairness,
        evaluation_run_id=_uuid7(504),
        route_policy_refs={
            "general_model_only": _ref("route_policy", 204),
            "hybrid_rag_only": _ref("route_policy", 205),
        },
        variants=ALL_SYSTEM_VARIANTS[:2],
        case_ids=case_ids,
        repetition_count=2,
    )

    assert plan.queue_order_seed == 991
    assert plan.fairness.reproducibility.generation_seed is None
    assert plan.fairness.reproducibility.temperature_milli is None
    assert plan.fairness.reproducibility.host_unknown_fields == (
        "generation_seed",
        "temperature",
    )
    with pytest.raises(EvaluationValidationError, match="queue order seed"):
        EvaluationRunner(EvaluationWorkQueue(tmp_path / "wrong-seed")).prepare(
            bundle=bundle,
            fairness=fairness,
            evaluation_run_id=_uuid7(505),
            route_policy_refs={"general_model_only": _ref("route_policy", 206)},
            variants=(ALL_SYSTEM_VARIANTS[0],),
            repetition_count=2,
            queue_order_seed=992,
        )


def test_append_submission_rejects_a_known_item_with_forged_projection(
    tmp_path: Path,
) -> None:
    _runtime, _handle, queue = _completed_runtime(tmp_path, run_index=506)
    submissions = queue.load_submissions()
    items = queue.load_items()
    queue.submissions_path.write_bytes(
        json.dumps(
            submissions[0].model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    forged = submissions[0].model_copy(update={"work_item_id": items[1].work_item_id})

    with pytest.raises(QueueStateError, match="frozen plan|work item"):
        queue.append_submission(forged)


def test_independent_queue_instances_serialize_submission_read_modify_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _runtime, _handle, seeded = _completed_runtime(tmp_path, run_index=510)
    submissions = seeded.load_submissions()
    seeded.submissions_path.unlink()
    queues = (EvaluationWorkQueue(seeded.root), EvaluationWorkQueue(seeded.root))
    barrier = threading.Barrier(2)

    def gated_loader(queue: EvaluationWorkQueue):
        original = queue.load_submissions
        first_call = True

        def load():
            nonlocal first_call
            loaded = original()
            if first_call:
                first_call = False
                try:
                    barrier.wait(timeout=0.25)
                except threading.BrokenBarrierError:
                    pass
            return loaded

        return load

    for queue in queues:
        monkeypatch.setattr(queue, "load_submissions", gated_loader(queue))

    accepted: list[str] = []
    errors: list[BaseException] = []

    def submit(index: int) -> None:
        try:
            accepted.append(
                queues[index].append_submission(submissions[index]).work_item_id
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = tuple(
        threading.Thread(target=submit, args=(index,), daemon=True)
        for index in range(2)
    )
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    assert errors == []
    assert set(accepted) == {item.work_item_id for item in submissions}
    assert {
        item.work_item_id
        for item in EvaluationWorkQueue(seeded.root).load_submissions()
    } == set(accepted)


def test_independent_processes_serialize_submission_read_modify_write(
    tmp_path: Path,
) -> None:
    _runtime, _handle, seeded = _completed_runtime(tmp_path, run_index=511)
    submissions = seeded.load_submissions()
    seeded.submissions_path.unlink()
    worker_source = """
import sys
import time
from pathlib import Path

from consultation_kb.evaluation.work_queue import (
    EvaluationSubmission,
    EvaluationWorkQueue,
)

root, submission_path, ready_path, start_path = map(Path, sys.argv[1:])
queue = EvaluationWorkQueue(root)
submission = EvaluationSubmission.model_validate_json(
    submission_path.read_text(encoding="utf-8"),
    strict=True,
)
original_load = queue.load_submissions

def slow_load():
    loaded = original_load()
    time.sleep(0.3)
    return loaded

queue.load_submissions = slow_load
ready_path.write_text("ready", encoding="ascii")
while not start_path.exists():
    time.sleep(0.01)
queue.append_submission(submission)
"""
    start_path = tmp_path / "start"
    processes: list[subprocess.Popen[str]] = []
    ready_paths: list[Path] = []
    for index, submission in enumerate(submissions):
        submission_path = tmp_path / f"submission-{index}.json"
        submission_path.write_text(submission.model_dump_json(), encoding="utf-8")
        ready_path = tmp_path / f"ready-{index}"
        ready_paths.append(ready_path)
        processes.append(
            subprocess.Popen(
                (
                    sys.executable,
                    "-c",
                    worker_source,
                    str(seeded.root),
                    str(submission_path),
                    str(ready_path),
                    str(start_path),
                ),
                cwd=Path.cwd(),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        )

    deadline = time.monotonic() + 10
    while not all(path.exists() for path in ready_paths):
        if time.monotonic() >= deadline:
            pytest.fail("evaluation submission workers did not become ready")
        time.sleep(0.01)
    start_path.write_text("start", encoding="ascii")

    results = [process.communicate(timeout=15) for process in processes]
    assert [
        (process.returncode, stderr)
        for process, (_stdout, stderr) in zip(processes, results, strict=True)
    ] == [(0, ""), (0, "")]
    assert {
        item.work_item_id
        for item in EvaluationWorkQueue(seeded.root).load_submissions()
    } == {item.work_item_id for item in submissions}


def test_report_commit_recomputes_missing_and_variant_projections(
    tmp_path: Path,
) -> None:
    variant_root = tmp_path / "variant-projection"
    variant_root.mkdir()
    _runtime, _handle, variant_queue = _completed_runtime(
        variant_root,
        run_index=512,
    )
    variant_runner = EvaluationRunner(variant_queue)
    complete = variant_runner.finalize()
    (variant_queue.root / variant_queue.REPORT_JSON_NAME).unlink()
    (variant_queue.root / variant_queue.REPORT_MARKDOWN_NAME).unlink()
    forged_variant = complete.variants[0].model_copy(
        update={"variant_name": "hybrid_rag_only"}
    )

    with pytest.raises(ReportStateError, match="current queue state"):
        variant_queue.write_reports(
            complete.model_copy(update={"variants": (forged_variant,)})
        )

    missing_root = tmp_path / "missing-projection"
    missing_root.mkdir()
    _runtime, _handle, missing_queue = _completed_runtime(
        missing_root,
        run_index=513,
    )
    submissions = missing_queue.load_submissions()
    missing_queue.submissions_path.write_bytes(
        json.dumps(
            submissions[0].model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    missing_id = next(
        item.work_item_id
        for item in missing_queue.load_items()
        if item.work_item_id != submissions[0].work_item_id
    )
    incomplete = EvaluationRunner(missing_queue).finalize(
        missing_reasons={missing_id: "host_interrupted"}
    )
    (missing_queue.root / missing_queue.REPORT_JSON_NAME).unlink()
    (missing_queue.root / missing_queue.REPORT_MARKDOWN_NAME).unlink()
    forged_missing = incomplete.missing[0].model_copy(
        update={"work_item_id": submissions[0].work_item_id}
    )

    with pytest.raises(ReportStateError, match="current queue state"):
        missing_queue.write_reports(
            incomplete.model_copy(update={"missing": (forged_missing,)})
        )


@pytest.mark.parametrize(
    "field",
    (
        "evaluation_run_id",
        "case_id",
        "variant_name",
        "repetition_index",
        "manifest_scope",
        "manifest_versions",
        "manifest_runtime",
        "manifest_reproducibility",
        "manifest_route_policy",
        "manifest_authority",
        "manifest_retry_budget",
        "trace_model",
        "trace_schema",
        "trace_c1_mode",
        "trace_channel_counts",
    ),
)
def test_restart_revalidates_submission_against_frozen_plan_item_and_fairness(
    tmp_path: Path,
    field: str,
) -> None:
    _runtime, _handle, queue = _completed_runtime(tmp_path, run_index=507)
    records = [
        json.loads(line)
        for line in queue.submissions_path.read_text(encoding="utf-8").splitlines()
    ]
    record = records[0]
    if field == "evaluation_run_id":
        record[field] = _uuid7(900)
    elif field == "case_id":
        record[field] = "syn_case_forged"
    elif field == "variant_name":
        record[field] = "hybrid_rag_only"
    elif field == "repetition_index":
        record[field] = 99
    elif field == "manifest_scope":
        record["run_manifest"]["scope_sha256"] = "f" * 64
    elif field == "manifest_versions":
        record["run_manifest"]["versions"]["model_descriptor_ref"] = _ref(
            "model", 901
        ).model_dump(mode="json")
    elif field == "manifest_runtime":
        record["run_manifest"]["runtime"]["python_version"] = "3.13.1"
    elif field == "manifest_reproducibility":
        record["run_manifest"]["reproducibility"]["queue_order_seed"] = 418
    elif field == "manifest_route_policy":
        record["run_manifest"]["routing"]["route_policy_ref"] = _ref(
            "route_policy", 902
        ).model_dump(mode="json")
    elif field == "manifest_authority":
        record["run_manifest"]["evidence"]["authority_snapshot_ref"] = _ref(
            "authority_snapshot", 903
        ).model_dump(mode="json")
    elif field == "manifest_retry_budget":
        record["run_manifest"]["retry_count"] = 3
    elif field == "trace_model":
        record["trace"]["model_label"] = "tampered-model"
    elif field == "trace_schema":
        record["trace"]["schema_ref"] = _ref("schema", 904).model_dump(mode="json")
    elif field == "trace_c1_mode":
        record["trace"]["c1_mode"] = "ordinary"
    elif field == "trace_channel_counts":
        record["trace"]["channel_counts"][3]["count"] = 1
    else:  # pragma: no cover - the parameter list is exhaustive
        raise AssertionError(field)
    queue.submissions_path.write_bytes(
        b"".join(
            json.dumps(
                item,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
            for item in records
        )
    )

    restarted = EvaluationWorkQueue(queue.root)
    with pytest.raises(QueueStateError, match="frozen plan|work item"):
        restarted.load_submissions()


@pytest.mark.parametrize("report_name", ("report.json", "report.md"))
def test_runtime_finalize_recomputes_and_rejects_report_drift_after_restart(
    tmp_path: Path,
    report_name: str,
) -> None:
    runtime, handle, queue = _completed_runtime(tmp_path, run_index=508)
    runtime.finalize(handle)
    report_path = queue.root / report_name
    if report_name == "report.json":
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        payload["submissions_sha256"] = "0" * 64
        report_path.write_text(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    else:
        report_path.write_text(
            report_path.read_text(encoding="utf-8").replace(
                "Status: `succeeded`",
                "Status: `incomplete`",
            ),
            encoding="utf-8",
        )

    restarted = EvaluationRuntime(
        repo_root=REPOSITORY_ROOT,
        vault_root=tmp_path / "vault",
    )
    with pytest.raises(EvaluationRuntimeError) as failure:
        restarted.finalize(handle)
    assert failure.value.code == "EVALUATION_REPORT_INVALID"


def test_repeated_finalize_repairs_either_exact_single_report(
    tmp_path: Path,
) -> None:
    runtime, handle, queue = _completed_runtime(tmp_path, run_index=509)
    first = runtime.finalize(handle)
    json_path = queue.root / queue.REPORT_JSON_NAME
    markdown_path = queue.root / queue.REPORT_MARKDOWN_NAME
    expected_json = json_path.read_bytes()
    expected_markdown = markdown_path.read_bytes()

    restarted = EvaluationRuntime(
        repo_root=REPOSITORY_ROOT,
        vault_root=tmp_path / "vault",
    )
    assert restarted.finalize(handle) == first
    assert json_path.read_bytes() == expected_json
    assert markdown_path.read_bytes() == expected_markdown

    markdown_path.unlink()
    assert restarted.finalize(handle) == first
    assert markdown_path.read_bytes() == expected_markdown

    json_path.unlink()
    assert restarted.finalize(handle) == first
    assert json_path.read_bytes() == expected_json


def test_markdown_precedes_json_commit_marker_and_restart_repairs_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, handle, queue = _completed_runtime(tmp_path, run_index=510)
    original_atomic_create = work_queue_module._atomic_create
    calls: list[str] = []

    def interrupt_json(path: Path, payload: bytes) -> None:
        calls.append(path.name)
        if path.name == queue.REPORT_JSON_NAME:
            raise OSError("injected JSON commit interruption")
        original_atomic_create(path, payload)

    monkeypatch.setattr(work_queue_module, "_atomic_create", interrupt_json)
    with pytest.raises(OSError, match="JSON commit interruption"):
        EvaluationRunner(queue).finalize()
    assert calls == [queue.REPORT_MARKDOWN_NAME, queue.REPORT_JSON_NAME]
    assert (queue.root / queue.REPORT_MARKDOWN_NAME).is_file()
    assert not (queue.root / queue.REPORT_JSON_NAME).exists()

    monkeypatch.setattr(work_queue_module, "_atomic_create", original_atomic_create)
    restarted = EvaluationRuntime(
        repo_root=REPOSITORY_ROOT,
        vault_root=tmp_path / "vault",
    )
    summary = restarted.finalize(handle)
    assert summary.status == "succeeded"
    assert (queue.root / queue.REPORT_JSON_NAME).is_file()


def test_parallel_conflicting_prepare_publishes_one_complete_run(
    tmp_path: Path,
) -> None:
    vault_root = tmp_path / "vault"
    vault_root.mkdir()
    fairness_path = tmp_path / "fairness.json"
    fairness_path.write_text(_fairness().model_dump_json(), encoding="utf-8")
    route_path = tmp_path / "route.json"
    route_path.write_text(
        _ref("route_policy", 514).model_dump_json(),
        encoding="utf-8",
    )
    evaluation_run_id = _uuid7(514)
    start_path = tmp_path / "prepare-start"
    worker_source = """
import json
import sys
import time
from pathlib import Path

from consultation_kb.evaluation import work_queue as work_queue_module
from consultation_kb.evaluation.runtime import EvaluationRuntime, EvaluationRuntimeError
from consultation_kb.evaluation.work_queue import (
    EvaluationFairnessContract,
    EvaluationWorkQueue,
)
from consultation_kb.models.common import VersionRef

(
    repo_root,
    vault_root,
    fairness_path,
    route_path,
    ready_path,
    start_path,
) = map(Path, sys.argv[1:7])
evaluation_run_id = sys.argv[7]
repetition_count = int(sys.argv[8])
original_atomic_create = work_queue_module._atomic_create

def delayed_atomic_create(path, payload):
    original_atomic_create(path, payload)
    if path.name == EvaluationWorkQueue.ITEMS_NAME:
        time.sleep(0.3)

work_queue_module._atomic_create = delayed_atomic_create
runtime = EvaluationRuntime(repo_root=repo_root, vault_root=vault_root)
fairness = EvaluationFairnessContract.model_validate_json(
    fairness_path.read_text(encoding="utf-8"),
    strict=True,
)
route_ref = VersionRef.model_validate_json(
    route_path.read_text(encoding="utf-8"),
    strict=True,
)
ready_path.write_text("ready", encoding="ascii")
while not start_path.exists():
    time.sleep(0.01)
try:
    prepared = runtime.prepare(
        evaluation_run_id=evaluation_run_id,
        fairness=fairness,
        route_policy_refs={"general_model_only": route_ref},
        variants=("general_model_only",),
        repetition_count=repetition_count,
        case_ids=("syn_case_classics_relationship",),
    )
    result = {"status": "ok", "handle": prepared.evaluation_handle}
except EvaluationRuntimeError as exc:
    result = {"status": "error", "code": exc.code}
print(json.dumps(result, separators=(",", ":")))
"""
    processes: list[subprocess.Popen[str]] = []
    ready_paths: list[Path] = []
    for index, repetition_count in enumerate((2, 3)):
        ready_path = tmp_path / f"prepare-ready-{index}"
        ready_paths.append(ready_path)
        processes.append(
            subprocess.Popen(
                (
                    sys.executable,
                    "-c",
                    worker_source,
                    str(REPOSITORY_ROOT),
                    str(vault_root),
                    str(fairness_path),
                    str(route_path),
                    str(ready_path),
                    str(start_path),
                    evaluation_run_id,
                    str(repetition_count),
                ),
                cwd=Path.cwd(),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        )

    deadline = time.monotonic() + 10
    while not all(path.exists() for path in ready_paths):
        if time.monotonic() >= deadline:
            pytest.fail("evaluation prepare workers did not become ready")
        time.sleep(0.01)
    start_path.write_text("start", encoding="ascii")
    outputs = [process.communicate(timeout=15) for process in processes]
    assert [process.returncode for process in processes] == [0, 0]
    assert [stderr for _stdout, stderr in outputs] == ["", ""]
    results = [json.loads(stdout) for stdout, _stderr in outputs]
    assert sorted(result["status"] for result in results) == ["error", "ok"]
    assert next(
        result["code"] for result in results if result["status"] == "error"
    ) == ("EVALUATION_RUN_ID_CONFLICT")
    handle = next(result["handle"] for result in results if result["status"] == "ok")
    restarted = EvaluationRuntime(
        repo_root=REPOSITORY_ROOT,
        vault_root=vault_root,
    )
    pending = restarted.get_next(handle)
    assert pending.pending is True
    assert pending.expected_count in (2, 3)


def test_incomplete_staging_directory_does_not_poison_published_run(
    tmp_path: Path,
) -> None:
    _runtime, handle, queue = _completed_runtime(tmp_path, run_index=515)
    orphan = queue.root.parents[1] / "staging" / f"{_uuid7(516)}.dead.tmp"
    orphan.mkdir()
    (orphan / queue.ITEMS_NAME).write_text("partial\n", encoding="ascii")

    restarted = EvaluationRuntime(
        repo_root=REPOSITORY_ROOT,
        vault_root=tmp_path / "vault",
    )
    state = restarted.get_next(handle)
    assert state.pending is False
    assert state.completed_count == state.expected_count


@pytest.mark.parametrize(
    "case_ids",
    (
        (
            "syn_case_classics_relationship",
            "syn_case_classics_relationship",
        ),
        ("syn_case_classics_relationship", "syn_case_absent"),
    ),
)
def test_existing_run_reopen_rejects_unresolved_or_duplicate_case_requests(
    tmp_path: Path,
    case_ids: tuple[str, ...],
) -> None:
    runtime, _handle, _queue = _completed_runtime(tmp_path, run_index=517)

    with pytest.raises(EvaluationRuntimeError) as failure:
        runtime.prepare(
            evaluation_run_id=_uuid7(517),
            fairness=_fairness(),
            route_policy_refs={"general_model_only": _ref("route_policy", 517)},
            variants=("general_model_only",),
            repetition_count=2,
            case_ids=case_ids,
        )
    assert failure.value.code == "EVALUATION_PREPARE_FAILED"


def test_existing_run_reopen_validates_the_published_queue_closure(
    tmp_path: Path,
) -> None:
    runtime, _handle, queue = _completed_runtime(tmp_path, run_index=518)
    queue.items_path.unlink()

    with pytest.raises(EvaluationRuntimeError) as failure:
        runtime.prepare(
            evaluation_run_id=_uuid7(518),
            fairness=_fairness(),
            route_policy_refs={"general_model_only": _ref("route_policy", 518)},
            variants=("general_model_only",),
            repetition_count=2,
            case_ids=("syn_case_classics_relationship",),
        )
    assert failure.value.code == "EVALUATION_QUEUE_INVALID"


def test_get_next_rejects_a_terminal_incomplete_run_after_restart(
    tmp_path: Path,
) -> None:
    runtime, handle, queue = _completed_runtime(tmp_path, run_index=519)
    submissions = queue.load_submissions()
    queue.submissions_path.write_bytes(
        json.dumps(
            submissions[0].model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    missing_id = next(
        item.work_item_id
        for item in queue.load_items()
        if item.work_item_id != submissions[0].work_item_id
    )
    summary = runtime.finalize(
        handle,
        missing_reasons={missing_id: "host_interrupted"},
    )
    assert summary.status == "incomplete"

    restarted = EvaluationRuntime(
        repo_root=REPOSITORY_ROOT,
        vault_root=tmp_path / "vault",
    )
    with pytest.raises(EvaluationRuntimeError) as failure:
        restarted.get_next(handle)
    assert failure.value.code == "EVALUATION_RUN_FINALIZED"
