from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
from numpy.typing import NDArray
import pytest

from consultation_kb.evaluation import model_benchmark
from consultation_kb.evaluation.model_benchmark import (
    BenchmarkPassage,
    BenchmarkQueryKind,
    BenchmarkQueryResult,
    ModelBenchmarkCase,
    ModelBenchmarkError,
    run_model_benchmark,
)
from consultation_kb.models.importer import (
    LocalRepositorySnapshot,
    ModelImporter,
)
from consultation_kb.models.model_lock import (
    RuntimeLibraryVersions,
    RuntimeModelManifest,
    load_tracked_model_spec,
)


pytestmark = pytest.mark.model

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
TRACKED_MODELS = REPOSITORY_ROOT / "models" / "consultation-models.json"
TRACKED_SUITE = REPOSITORY_ROOT / "models" / "consultation-model-benchmark.json"
VERSIONS = RuntimeLibraryVersions(
    sentence_transformers_version="5.6.0",
    transformers_version="4.57.0",
    tokenizer_version="0.22.0",
)
QUERY_KINDS: tuple[BenchmarkQueryKind, ...] = (
    "chinese_original",
    "paraphrase",
    "cross_domain",
    "counterevidence",
    "c1_scope",
)


def _snapshot(
    tmp_path: Path,
    *,
    model_id: str,
    repo: str,
    license_id: str,
    revision_digit: str,
) -> LocalRepositorySnapshot:
    source = tmp_path / f"fake_{model_id}"
    (source / "weights").mkdir(parents=True)
    (source / "config.json").write_text("{}", encoding="utf-8")
    (source / "tokenizer.json").write_text("{}", encoding="utf-8")
    (source / "weights" / "model.safetensors").write_bytes(
        f"synthetic-{model_id}".encode("ascii")
    )
    if license_id == "mit":
        license_text = (
            "MIT License\nPermission is hereby granted for this synthetic fixture."
        )
    else:
        license_text = "Apache License\nVersion 2.0\nSynthetic fixture."
    (source / "LICENSE").write_text(license_text, encoding="utf-8")
    return LocalRepositorySnapshot(
        directory=source,
        repo=repo,
        revision=revision_digit * 40,
        license_id=license_id,
    )


def _runtime_manifest(tmp_path: Path) -> RuntimeModelManifest:
    candidates = load_tracked_model_spec(TRACKED_MODELS)
    importer = ModelImporter(
        artifact_root=(tmp_path / "vault" / "models").resolve(),
        runtime_manifest_path=(
            tmp_path / "state" / ".consultation-models" / "runtime-manifest.json"
        ).resolve(),
        candidates=candidates,
    )
    model_inputs = (
        ("bge_m3", "BAAI/bge-m3", "mit", "1"),
        ("bge_small_zh_v1_5", "BAAI/bge-small-zh-v1.5", "mit", "2"),
        (
            "bge_reranker_v2_m3",
            "BAAI/bge-reranker-v2-m3",
            "apache-2.0",
            "3",
        ),
        (
            "bge_reranker_base",
            "BAAI/bge-reranker-base",
            "mit",
            "4",
        ),
    )
    manifest: RuntimeModelManifest | None = None
    for model_id, repo, license_id, revision_digit in model_inputs:
        manifest = importer.import_snapshot(
            model_id,
            _snapshot(
                tmp_path,
                model_id=model_id,
                repo=repo,
                license_id=license_id,
                revision_digit=revision_digit,
            ),
            versions=VERSIONS,
        )
    assert manifest is not None
    return manifest


def _suite() -> tuple[ModelBenchmarkCase, ...]:
    cases: list[ModelBenchmarkCase] = []
    for index, kind in enumerate(QUERY_KINDS, start=1):
        prefix = f"evidence_{index}"
        cases.append(
            ModelBenchmarkCase(
                case_id=f"syn_model_case_{index}",
                query_kind=kind,
                query=f"合成中文检索问题 {index}，用于验证固定离线模型基准。",
                passages=(
                    BenchmarkPassage(
                        evidence_id=f"{prefix}_primary",
                        text="合成的主要证据材料。",
                        relevance_grade=3,
                        is_counterevidence=False,
                        allowed=True,
                    ),
                    BenchmarkPassage(
                        evidence_id=f"{prefix}_secondary",
                        text="合成的次要证据或反证材料。",
                        relevance_grade=1,
                        is_counterevidence=kind == "counterevidence",
                        allowed=True,
                    ),
                    BenchmarkPassage(
                        evidence_id=f"{prefix}_irrelevant",
                        text="合成的无关材料。",
                        relevance_grade=0,
                        is_counterevidence=False,
                        allowed=True,
                    ),
                    BenchmarkPassage(
                        evidence_id=f"{prefix}_forbidden",
                        text="合成的越权材料，只用于验证预过滤约束。",
                        relevance_grade=0,
                        is_counterevidence=False,
                        allowed=False,
                    ),
                ),
            )
        )
    return tuple(cases)


@dataclass(frozen=True)
class _FakeBackend:
    embedding_model_id: str
    reranker_model_id: str
    mode: str
    latency_ms: float
    peak_memory: int

    def evaluate(self, case: ModelBenchmarkCase) -> BenchmarkQueryResult:
        ids = {
            item.evidence_id.rsplit("_", 1)[-1]: item.evidence_id
            for item in case.passages
        }
        initial: tuple[str, ...]
        final: tuple[str, ...]
        if self.mode == "quality":
            initial = (ids["secondary"], ids["irrelevant"], ids["primary"])
            final = (ids["primary"], ids["secondary"], ids["irrelevant"])
        elif self.mode == "weak_recall":
            initial = (ids["irrelevant"], ids["primary"])
            final = (ids["primary"], ids["irrelevant"])
        elif self.mode == "poor_ndcg":
            initial = (ids["primary"], ids["secondary"], ids["irrelevant"])
            final = (ids["irrelevant"], ids["primary"], ids["secondary"])
        elif self.mode == "forbidden":
            initial = (ids["secondary"], ids["primary"], ids["forbidden"])
            final = (ids["primary"], ids["secondary"], ids["forbidden"])
        else:
            raise AssertionError("unknown synthetic backend mode")
        return BenchmarkQueryResult(
            initial_ranked_ids=initial,
            reranked_ids=final,
            cpu_latency_ms=self.latency_ms,
            peak_memory_bytes=self.peak_memory,
        )


def test_offline_benchmark_reports_metrics_and_selects_quality_before_resources(
    tmp_path: Path,
) -> None:
    manifest = _runtime_manifest(tmp_path)
    quality = _FakeBackend(
        "bge_m3",
        "bge_reranker_v2_m3",
        "quality",
        25.0,
        4096,
    )
    faster_but_weaker = _FakeBackend(
        "bge_small_zh_v1_5",
        "bge_reranker_base",
        "weak_recall",
        1.0,
        128,
    )

    report = run_model_benchmark(
        _suite(),
        (faster_but_weaker, quality),
        runtime_manifest=manifest,
    )

    assert report.selected_embedding_model_id == "bge_m3"
    assert report.selected_reranker_model_id == "bge_reranker_v2_m3"
    assert report.candidates[0].recall_at_10 == 1.0
    assert report.candidates[0].counterevidence_recall == 1.0
    assert report.candidates[0].rerank_gain > 0.0
    assert report.candidates[0].mean_cpu_latency_ms == 25.0
    assert report.candidates[0].peak_memory_bytes == 4096
    assert report.candidates[1].recall_at_10 == 0.5
    assert len(report.runtime_manifest_sha256) == 64
    assert len(report.suite_sha256) == 64


def test_constraint_failure_cannot_win_even_with_better_resources(
    tmp_path: Path,
) -> None:
    manifest = _runtime_manifest(tmp_path)
    eligible = _FakeBackend(
        "bge_small_zh_v1_5",
        "bge_reranker_base",
        "weak_recall",
        50.0,
        8192,
    )
    violating = _FakeBackend(
        "bge_m3",
        "bge_reranker_v2_m3",
        "forbidden",
        0.1,
        1,
    )

    report = run_model_benchmark(
        _suite(),
        (violating, eligible),
        runtime_manifest=manifest,
    )

    assert report.candidates[0].passed_constraints is True
    assert report.candidates[0].embedding_model_id == "bge_small_zh_v1_5"
    assert report.candidates[1].passed_constraints is False
    assert report.candidates[1].constraint_failures == len(_suite())


def test_ndcg_precedes_resource_cost_after_recall_and_counterevidence_tie(
    tmp_path: Path,
) -> None:
    manifest = _runtime_manifest(tmp_path)
    quality = _FakeBackend(
        "bge_m3",
        "bge_reranker_v2_m3",
        "quality",
        50.0,
        8192,
    )
    faster_lower_ndcg = _FakeBackend(
        "bge_small_zh_v1_5",
        "bge_reranker_base",
        "poor_ndcg",
        0.1,
        1,
    )

    report = run_model_benchmark(
        _suite(),
        (faster_lower_ndcg, quality),
        runtime_manifest=manifest,
    )

    assert report.candidates[0].embedding_model_id == "bge_m3"
    assert report.candidates[0].recall_at_10 == report.candidates[1].recall_at_10
    assert report.candidates[0].counterevidence_recall == (
        report.candidates[1].counterevidence_recall
    )
    assert report.candidates[0].ndcg_at_10 > report.candidates[1].ndcg_at_10


def test_benchmark_is_order_stable_and_bound_to_descriptor_hashes(
    tmp_path: Path,
) -> None:
    manifest = _runtime_manifest(tmp_path)
    first = _FakeBackend(
        "bge_m3",
        "bge_reranker_v2_m3",
        "quality",
        10.0,
        100,
    )
    second = _FakeBackend(
        "bge_small_zh_v1_5",
        "bge_reranker_base",
        "weak_recall",
        2.0,
        50,
    )

    forward = run_model_benchmark(_suite(), (first, second), runtime_manifest=manifest)
    reverse = run_model_benchmark(
        tuple(reversed(_suite())),
        (second, first),
        runtime_manifest=manifest,
    )

    assert forward == reverse
    by_id = {item.model_id: item for item in manifest.models}
    assert forward.candidates[0].embedding_descriptor_sha256 == (
        by_id["bge_m3"].descriptor_sha256
    )
    assert forward.candidates[0].reranker_descriptor_sha256 == (
        by_id["bge_reranker_v2_m3"].descriptor_sha256
    )


def test_python_heap_diagnostic_does_not_bias_equal_quality_latency_winner(
    tmp_path: Path,
) -> None:
    manifest = _runtime_manifest(tmp_path)
    lexicographic_first = _FakeBackend(
        "bge_m3",
        "bge_reranker_v2_m3",
        "quality",
        10.0,
        10_000_000,
    )
    lower_python_heap_diagnostic = _FakeBackend(
        "bge_small_zh_v1_5",
        "bge_reranker_base",
        "quality",
        10.0,
        1,
    )

    forward = run_model_benchmark(
        _suite(),
        (lexicographic_first, lower_python_heap_diagnostic),
        runtime_manifest=manifest,
    )
    reverse = run_model_benchmark(
        _suite(),
        (lower_python_heap_diagnostic, lexicographic_first),
        runtime_manifest=manifest,
    )

    assert forward == reverse
    assert forward.selected_embedding_model_id == "bge_m3"
    assert forward.candidates[0].peak_memory_bytes == 10_000_000
    assert forward.latency_measurement_scope == "warmed_cpu_case_wall_clock"
    assert (
        forward.memory_measurement_scope == "python_tracemalloc_delta_diagnostic_only"
    )
    assert forward.memory_used_for_selection is False


def test_benchmark_rejects_incomplete_suite_and_unimported_model(
    tmp_path: Path,
) -> None:
    manifest = _runtime_manifest(tmp_path)
    backend = _FakeBackend(
        "bge_m3",
        "bge_reranker_v2_m3",
        "quality",
        1.0,
        1,
    )

    with pytest.raises(ModelBenchmarkError) as incomplete:
        run_model_benchmark(_suite()[:-1], (backend,), runtime_manifest=manifest)
    assert incomplete.value.code == "MODEL_BENCHMARK_SUITE_INCOMPLETE"

    unimported = _FakeBackend(
        "not_imported",
        "bge_reranker_v2_m3",
        "quality",
        1.0,
        1,
    )
    with pytest.raises(ModelBenchmarkError) as missing:
        run_model_benchmark(_suite(), (unimported,), runtime_manifest=manifest)
    assert missing.value.code == "MODEL_BENCHMARK_MODEL_NOT_IMPORTED"


def test_benchmark_fails_closed_when_every_candidate_violates_constraints(
    tmp_path: Path,
) -> None:
    manifest = _runtime_manifest(tmp_path)
    backend = _FakeBackend(
        "bge_m3",
        "bge_reranker_v2_m3",
        "forbidden",
        1.0,
        1,
    )

    with pytest.raises(ModelBenchmarkError) as caught:
        run_model_benchmark(_suite(), (backend,), runtime_manifest=manifest)

    assert caught.value.code == "MODEL_BENCHMARK_NO_ELIGIBLE_CANDIDATE"


def test_tracked_synthetic_suite_loader_covers_all_required_query_kinds() -> None:
    loader = getattr(model_benchmark, "load_model_benchmark_suite")

    cases = loader(TRACKED_SUITE)

    assert tuple(sorted({case.query_kind for case in cases})) == tuple(
        sorted(QUERY_KINDS)
    )
    assert len(cases) >= 5
    assert all(
        any("\u3400" <= char <= "\u9fff" for char in case.query) for case in cases
    )
    assert all(
        sum(passage.allowed for passage in case.passages) >= 12 for case in cases
    )


def test_sentence_transformers_backend_builder_creates_full_two_by_two_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _runtime_manifest(tmp_path)
    prewarmed_embeddings: set[str] = set()
    prewarmed_rerankers: set[str] = set()

    class _FakeSentenceTransformer:
        def __init__(self, model_name: str, **kwargs: object) -> None:
            del kwargs
            self.model_name = model_name
            self.dimension = 1024 if "bge-m3" in model_name else 512

        def encode(
            self,
            texts: list[str],
            **kwargs: object,
        ) -> NDArray[np.float32]:
            del kwargs
            prewarmed_embeddings.add(Path(self.model_name).name)
            matrix = np.ones((len(texts), self.dimension), dtype=np.float32)
            matrix /= np.linalg.norm(matrix, axis=1, keepdims=True)
            return matrix

    class _FakeCrossEncoder:
        def __init__(self, model_name: str, **kwargs: object) -> None:
            del kwargs
            self.model_name = model_name

        def predict(
            self,
            pairs: list[tuple[str, str]],
            **kwargs: object,
        ) -> NDArray[np.float32]:
            del kwargs
            prewarmed_rerankers.add(Path(self.model_name).name)
            return np.arange(len(pairs), dtype=np.float32)

    monkeypatch.setitem(
        __import__("sys").modules,
        "sentence_transformers",
        __import__("types").SimpleNamespace(
            SentenceTransformer=_FakeSentenceTransformer,
            CrossEncoder=_FakeCrossEncoder,
        ),
    )
    clock_calls: list[int] = []

    def fake_clock() -> float:
        clock_calls.append(len(clock_calls))
        return float(len(clock_calls))

    monkeypatch.setattr(
        model_benchmark,
        "time",
        __import__("types").SimpleNamespace(perf_counter=fake_clock),
    )
    builder = getattr(
        model_benchmark,
        "build_sentence_transformers_benchmark_backends",
    )

    backends = builder(
        runtime_manifest=manifest,
        artifact_root=(tmp_path / "vault" / "models").resolve(),
    )

    assert {
        (backend.embedding_model_id, backend.reranker_model_id) for backend in backends
    } == {
        ("bge_m3", "bge_reranker_base"),
        ("bge_m3", "bge_reranker_v2_m3"),
        ("bge_small_zh_v1_5", "bge_reranker_base"),
        ("bge_small_zh_v1_5", "bge_reranker_v2_m3"),
    }
    assert clock_calls == []
    assert prewarmed_embeddings == {"bge-m3", "bge-small-zh-v1.5"}
    assert prewarmed_rerankers == {"bge-reranker-base", "bge-reranker-v2-m3"}
    assert all(backend._embedder._model is not None for backend in backends)
    assert all(backend._reranker._model is not None for backend in backends)
    assert len({id(backend._embedder) for backend in backends}) == 2
    assert len({id(backend._reranker) for backend in backends}) == 2

    backends[0].evaluate(_suite()[0])

    assert len(clock_calls) == 2


def test_sentence_transformers_backend_prefilters_and_returns_only_rank_ids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _runtime_manifest(tmp_path)

    class _FakeSentenceTransformer:
        def __init__(self, model_name: str, **kwargs: object) -> None:
            self.dimension = 1024 if "bge-m3" in model_name else 512
            assert kwargs["device"] == "cpu"
            assert kwargs["local_files_only"] is True
            assert kwargs["trust_remote_code"] is False

        def encode(
            self,
            texts: list[str],
            **kwargs: object,
        ) -> NDArray[np.float32]:
            del kwargs
            matrix = np.zeros((len(texts), self.dimension), dtype=np.float32)
            for row, text in enumerate(texts):
                if "无关" in text:
                    matrix[row, 1] = 1.0
                elif "次要" in text or "反证" in text:
                    matrix[row, 0] = 0.8
                    matrix[row, 1] = 0.2
                else:
                    matrix[row, 0] = 1.0
                matrix[row] /= np.linalg.norm(matrix[row])
            return matrix

    class _FakeCrossEncoder:
        def __init__(self, model_name: str, **kwargs: object) -> None:
            del model_name
            assert kwargs["device"] == "cpu"
            assert kwargs["local_files_only"] is True
            assert kwargs["trust_remote_code"] is False

        def predict(
            self,
            pairs: list[tuple[str, str]],
            **kwargs: object,
        ) -> NDArray[np.float32]:
            del kwargs
            return np.asarray(
                [
                    3.0 if "主要" in passage else 2.0 if "次要" in passage else 1.0
                    for _, passage in pairs
                ],
                dtype=np.float32,
            )

    monkeypatch.setattr(
        model_benchmark,
        "SentenceTransformersEmbedder",
        __import__(
            "consultation_kb.retrieval.model_adapters",
            fromlist=["SentenceTransformersEmbedder"],
        ).SentenceTransformersEmbedder,
        raising=False,
    )
    monkeypatch.setitem(
        __import__("sys").modules,
        "sentence_transformers",
        __import__("types").SimpleNamespace(
            SentenceTransformer=_FakeSentenceTransformer,
            CrossEncoder=_FakeCrossEncoder,
        ),
    )
    builder = getattr(
        model_benchmark,
        "build_sentence_transformers_benchmark_backends",
    )
    backend = builder(
        runtime_manifest=manifest,
        artifact_root=(tmp_path / "vault" / "models").resolve(),
    )[0]

    result = backend.evaluate(_suite()[0])

    assert result.initial_ranked_ids[0].endswith("_primary")
    assert result.reranked_ids[0].endswith("_primary")
    assert all("forbidden" not in evidence_id for evidence_id in result.reranked_ids)
    assert result.cpu_latency_ms >= 0.0
    assert result.peak_memory_bytes >= 0
    assert "合成" not in result.model_dump_json()
