from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from consultation_kb import cli
from consultation_kb.evaluation import model_benchmark
from consultation_kb.evaluation.model_benchmark import (
    CandidateBenchmarkResult,
    ModelBenchmarkReport,
)
import consultation_kb.models.model_lock as model_lock_module


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
TRACKED_MODELS = REPOSITORY_ROOT / "models" / "consultation-models.json"
TRACKED_SUITE = REPOSITORY_ROOT / "models" / "consultation-model-benchmark.json"


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    (repository / ".git").mkdir(parents=True)
    (repository / "models").mkdir()
    shutil.copyfile(TRACKED_MODELS, repository / "models" / TRACKED_MODELS.name)
    shutil.copyfile(TRACKED_SUITE, repository / "models" / TRACKED_SUITE.name)
    return repository.resolve()


def _report() -> ModelBenchmarkReport:
    candidate = CandidateBenchmarkResult(
        embedding_model_id="bge_m3",
        reranker_model_id="bge_reranker_v2_m3",
        embedding_descriptor_sha256="1" * 64,
        reranker_descriptor_sha256="2" * 64,
        case_count=5,
        constraint_failures=0,
        passed_constraints=True,
        recall_at_10=0.9,
        counterevidence_recall=1.0,
        ndcg_at_10=0.8,
        mrr=0.75,
        rerank_gain=0.1,
        mean_cpu_latency_ms=10.0,
        peak_memory_bytes=1024,
    )
    return ModelBenchmarkReport(
        runtime_manifest_sha256="3" * 64,
        suite_sha256="4" * 64,
        case_count=5,
        required_query_kinds=model_benchmark.REQUIRED_BENCHMARK_QUERY_KINDS,
        candidates=(candidate,),
        selected_embedding_model_id=candidate.embedding_model_id,
        selected_reranker_model_id=candidate.reranker_model_id,
    )


def test_model_benchmark_cli_writes_only_body_free_report_by_safe_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = _repository(tmp_path)
    vault = (tmp_path / "vault").resolve()
    (vault / "models").mkdir(parents=True)
    report = _report()
    observed: dict[str, object] = {}

    def fake_load_manifest(
        path: Path,
        *,
        candidates: object,
        artifact_root: Path,
    ) -> object:
        del candidates
        observed["manifest_path"] = path
        observed["artifact_root"] = artifact_root
        return object()

    monkeypatch.setattr(
        model_lock_module,
        "load_runtime_model_manifest",
        fake_load_manifest,
    )
    monkeypatch.setattr(
        model_benchmark,
        "load_model_benchmark_suite",
        lambda path: observed.setdefault("suite_path", path) or (object(),),
    )
    monkeypatch.setattr(
        model_benchmark,
        "build_sentence_transformers_benchmark_backends",
        lambda **kwargs: observed.setdefault("builder", kwargs) or (object(),),
    )
    monkeypatch.setattr(
        model_benchmark,
        "run_model_benchmark",
        lambda cases, backends, *, runtime_manifest: (
            observed.update(
                cases=cases,
                backends=backends,
                runtime_manifest=runtime_manifest,
            )
            or report
        ),
    )

    exit_code = cli.main(
        (
            "model-benchmark",
            "--output-ref",
            "task5_synthetic_run",
            "--repo-root",
            str(repository),
            "--vault-root",
            str(vault),
            "--json",
        )
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert captured.err == ""
    assert payload == {
        "candidate_count": 1,
        "ok": True,
        "output_ref": "task5_synthetic_run",
        "report_sha256": payload["report_sha256"],
        "runtime_manifest_sha256": "3" * 64,
        "selected_embedding_model_id": "bge_m3",
        "selected_reranker_model_id": "bge_reranker_v2_m3",
        "suite_sha256": "4" * 64,
    }
    assert len(payload["report_sha256"]) == 64
    output = (
        repository / ".consultation-models" / "benchmarks" / "task5_synthetic_run.json"
    )
    stored = output.read_text(encoding="utf-8")
    stored_payload = json.loads(stored)
    assert stored_payload == report.model_dump(mode="json")
    assert stored_payload["latency_measurement_scope"] == ("warmed_cpu_case_wall_clock")
    assert stored_payload["memory_measurement_scope"] == (
        "python_tracemalloc_delta_diagnostic_only"
    )
    assert stored_payload["memory_used_for_selection"] is False
    combined = captured.out + stored
    assert str(repository) not in combined
    assert str(vault) not in combined
    assert "合成问题" not in combined
    assert "passages" not in combined
    assert '"query":' not in combined
    assert "预热查询" not in combined
    assert "预热文档" not in combined
