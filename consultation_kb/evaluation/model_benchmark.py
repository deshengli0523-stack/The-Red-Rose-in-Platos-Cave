"""Deterministic scoring and local execution for embedding/reranker runs.

The model framework is imported lazily by the local adapters.  This module has
no network adapter and reports only ranked IDs, hashes, metrics, and resource
telemetry; synthetic query and passage bodies never enter the report.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import time
import tracemalloc
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol, TypeAlias

import numpy as np

from pydantic import Field, ValidationError, model_validator
from typing_extensions import Self

from consultation_kb.evaluation.scorers import (
    ndcg_at_k,
    recall_at_k,
    reciprocal_rank,
)
from consultation_kb.knowledge._canonical import canonical_json_bytes
from consultation_kb.models.common import (
    FiniteFloat,
    NonNegativeInt,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
)
from consultation_kb.models.evaluation import SyntheticText
from consultation_kb.models.model_lock import (
    RuntimeModelManifest,
    RuntimeModelRecord,
)
from consultation_kb.retrieval.model_adapters import (
    LocalModelUnavailable,
    SentenceTransformersCrossEncoderReranker,
    SentenceTransformersEmbedder,
)
from consultation_kb.retrieval.embeddings import EmbeddingContractError


BenchmarkQueryKind: TypeAlias = Literal[
    "chinese_original",
    "paraphrase",
    "cross_domain",
    "counterevidence",
    "c1_scope",
]
REQUIRED_BENCHMARK_QUERY_KINDS: tuple[BenchmarkQueryKind, ...] = (
    "c1_scope",
    "chinese_original",
    "counterevidence",
    "cross_domain",
    "paraphrase",
)
MODEL_BENCHMARK_SUITE_SCHEMA_VERSION = "consultation_model_benchmark_suite.v1"
MODEL_BENCHMARK_SUITE_RELPATH = "models/consultation-model-benchmark.json"
MAX_MODEL_BENCHMARK_SUITE_BYTES = 2 * 1024 * 1024
_PREWARM_QUERY = "预热查询"
_PREWARM_DOCUMENT = "预热文档"

RelevanceGrade: TypeAlias = Annotated[int, Field(strict=True, ge=0, le=3)]
NonNegativeFloat: TypeAlias = Annotated[
    float,
    Field(strict=True, ge=0.0, allow_inf_nan=False),
]


class ModelBenchmarkError(RuntimeError):
    """A fixed-code benchmark contract or execution rejection."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class BenchmarkPassage(StrictModel):
    evidence_id: SafePolicyKey
    text: SyntheticText
    relevance_grade: RelevanceGrade
    is_counterevidence: bool
    allowed: bool

    @model_validator(mode="after")
    def _gold_is_retrievable(self) -> Self:
        if self.relevance_grade > 0 and not self.allowed:
            raise ValueError("gold benchmark evidence must be allowed")
        if self.is_counterevidence and self.relevance_grade == 0:
            raise ValueError("counterevidence must carry positive relevance")
        return self


class ModelBenchmarkCase(StrictModel):
    case_id: SafePolicyKey
    query_kind: BenchmarkQueryKind
    query: SyntheticText
    passages: tuple[BenchmarkPassage, ...]

    @model_validator(mode="after")
    def _case_contract(self) -> Self:
        evidence_ids = tuple(item.evidence_id for item in self.passages)
        if not any("\u3400" <= character <= "\u9fff" for character in self.query):
            raise ValueError("model benchmark query must contain Chinese text")
        if len(self.passages) < 2 or len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("benchmark passages must be nonempty and unique")
        if not any(item.relevance_grade > 0 for item in self.passages):
            raise ValueError("benchmark case must declare relevant evidence")
        if self.query_kind == "counterevidence" and not any(
            item.is_counterevidence for item in self.passages
        ):
            raise ValueError("counterevidence benchmark case lacks counterevidence")
        if self.query_kind == "c1_scope" and not any(
            not item.allowed for item in self.passages
        ):
            raise ValueError("C1 scope benchmark case lacks an out-of-scope passage")
        return self


class _ModelBenchmarkSuiteFile(StrictModel):
    schema_version: Literal["consultation_model_benchmark_suite.v1"]
    cases: tuple[ModelBenchmarkCase, ...]


class BenchmarkQueryResult(StrictModel):
    """One backend result; reranking may only reorder retrieved candidates."""

    initial_ranked_ids: tuple[SafePolicyKey, ...]
    reranked_ids: tuple[SafePolicyKey, ...]
    cpu_latency_ms: NonNegativeFloat
    peak_memory_bytes: NonNegativeInt

    @model_validator(mode="after")
    def _ranking_contract(self) -> Self:
        if not self.initial_ranked_ids or not self.reranked_ids:
            raise ValueError("benchmark rankings must not be empty")
        if len(set(self.initial_ranked_ids)) != len(self.initial_ranked_ids):
            raise ValueError("initial ranking contains duplicate evidence")
        if len(set(self.reranked_ids)) != len(self.reranked_ids):
            raise ValueError("reranked result contains duplicate evidence")
        if set(self.initial_ranked_ids) != set(self.reranked_ids):
            raise ValueError("reranker may only reorder retrieved evidence")
        return self


class OfflineBenchmarkBackend(Protocol):
    """Adapter seam for two already-loaded, local-only model records."""

    @property
    def embedding_model_id(self) -> str: ...

    @property
    def reranker_model_id(self) -> str: ...

    def evaluate(self, case: ModelBenchmarkCase) -> BenchmarkQueryResult: ...


def _plain_single_link_file(path: Path) -> bool:
    try:
        status = os.lstat(path)
    except OSError:
        return False
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    attributes = int(getattr(status, "st_file_attributes", 0))
    return (
        stat.S_ISREG(status.st_mode)
        and not stat.S_ISLNK(status.st_mode)
        and not bool(attributes & reparse_flag)
        and int(status.st_nlink) == 1
    )


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load_model_benchmark_suite(path: Path) -> tuple[ModelBenchmarkCase, ...]:
    """Load one fixed synthetic suite without accepting links or loose text."""

    if not isinstance(path, Path):
        raise TypeError("MODEL_BENCHMARK_SUITE_PATH_REQUIRED")
    if not _plain_single_link_file(path):
        raise ModelBenchmarkError("MODEL_BENCHMARK_SUITE_UNAVAILABLE")
    try:
        raw = path.read_bytes()
    except OSError:
        raise ModelBenchmarkError("MODEL_BENCHMARK_SUITE_UNAVAILABLE") from None
    if (
        not raw
        or len(raw) > MAX_MODEL_BENCHMARK_SUITE_BYTES
        or raw.startswith(b"\xef\xbb\xbf")
        or b"\x00" in raw
    ):
        raise ModelBenchmarkError("MODEL_BENCHMARK_SUITE_INVALID")
    try:
        parsed = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
        suite = _ModelBenchmarkSuiteFile.model_validate_json(
            canonical_json_bytes(parsed),
            strict=True,
        )
    except (UnicodeError, json.JSONDecodeError, ValidationError, ValueError):
        raise ModelBenchmarkError("MODEL_BENCHMARK_SUITE_INVALID") from None
    return _suite(suite.cases)


class SentenceTransformersBenchmarkBackend:
    """One verified local embedding/reranker pair, loaded lazily on CPU."""

    def __init__(
        self,
        *,
        artifact_root: Path,
        embedding_record: RuntimeModelRecord,
        reranker_record: RuntimeModelRecord,
        embedder_adapter: SentenceTransformersEmbedder | None = None,
        reranker_adapter: SentenceTransformersCrossEncoderReranker | None = None,
    ) -> None:
        if not isinstance(artifact_root, Path) or not artifact_root.is_absolute():
            raise ModelBenchmarkError("MODEL_BENCHMARK_ARTIFACT_ROOT_INVALID")
        try:
            embedding = RuntimeModelRecord.model_validate(
                embedding_record,
                strict=True,
            )
            reranker = RuntimeModelRecord.model_validate(
                reranker_record,
                strict=True,
            )
        except (TypeError, ValidationError, ValueError):
            raise ModelBenchmarkError("MODEL_BENCHMARK_RECORD_INVALID") from None
        if embedding.role != "embedding" or reranker.role != "reranker":
            raise ModelBenchmarkError("MODEL_BENCHMARK_MODEL_ROLE_INVALID")
        self._embedding_model_id = embedding.model_id
        self._reranker_model_id = reranker.model_id
        try:
            self._embedder = (
                SentenceTransformersEmbedder(
                    artifact_root / Path(embedding.artifact_relpath),
                    embedding.descriptor,
                )
                if embedder_adapter is None
                else embedder_adapter
            )
            self._reranker = (
                SentenceTransformersCrossEncoderReranker(
                    artifact_root / Path(reranker.artifact_relpath),
                    reranker.descriptor,
                )
                if reranker_adapter is None
                else reranker_adapter
            )
        except LocalModelUnavailable:
            raise ModelBenchmarkError("MODEL_BENCHMARK_MODEL_UNAVAILABLE") from None
        if (
            self._embedder.descriptor != embedding.descriptor
            or self._reranker.descriptor != reranker.descriptor
        ):
            raise ModelBenchmarkError("MODEL_BENCHMARK_ADAPTER_BINDING_INVALID")

    @property
    def embedding_model_id(self) -> str:
        return self._embedding_model_id

    @property
    def reranker_model_id(self) -> str:
        return self._reranker_model_id

    def evaluate(self, case: ModelBenchmarkCase) -> BenchmarkQueryResult:
        try:
            exact_case = ModelBenchmarkCase.model_validate(case, strict=True)
        except (TypeError, ValidationError, ValueError):
            raise ModelBenchmarkError("MODEL_BENCHMARK_CASE_INVALID") from None
        allowed = tuple(passage for passage in exact_case.passages if passage.allowed)
        if not allowed:
            raise ModelBenchmarkError("MODEL_BENCHMARK_CASE_INVALID")

        tracing_was_active = tracemalloc.is_tracing()
        if not tracing_was_active:
            tracemalloc.start()
        memory_before, peak_before = tracemalloc.get_traced_memory()
        started = time.perf_counter()
        try:
            query_vector = self._embedder.encode_query(exact_case.query)
            document_matrix = self._embedder.encode_documents(
                tuple(passage.text for passage in allowed)
            )
            similarities = np.asarray(
                document_matrix @ query_vector,
                dtype=np.float32,
            )
            initial_order = tuple(
                sorted(
                    range(len(allowed)),
                    key=lambda index: (
                        -float(similarities[index]),
                        allowed[index].evidence_id,
                    ),
                )[:10]
            )
            retrieved = tuple(allowed[index] for index in initial_order)
            reranker_scores = self._reranker.score(
                exact_case.query,
                tuple(passage.text for passage in retrieved),
            )
            reranked_order = tuple(
                sorted(
                    range(len(retrieved)),
                    key=lambda index: (
                        -float(reranker_scores[index]),
                        retrieved[index].evidence_id,
                    ),
                )
            )
            initial_ids = tuple(passage.evidence_id for passage in retrieved)
            reranked_ids = tuple(
                retrieved[index].evidence_id for index in reranked_order
            )
        except ModelBenchmarkError:
            raise
        except Exception:
            raise ModelBenchmarkError("MODEL_BENCHMARK_EXECUTION_FAILED") from None
        finally:
            elapsed_ms = max(0.0, (time.perf_counter() - started) * 1000.0)
            memory_after, peak_after = tracemalloc.get_traced_memory()
            if not tracing_was_active:
                tracemalloc.stop()
        peak_memory = max(
            0,
            memory_after - memory_before,
            peak_after - peak_before,
        )
        try:
            return BenchmarkQueryResult(
                initial_ranked_ids=initial_ids,
                reranked_ids=reranked_ids,
                cpu_latency_ms=elapsed_ms,
                peak_memory_bytes=peak_memory,
            )
        except (ValidationError, ValueError):
            raise ModelBenchmarkError("MODEL_BENCHMARK_RESULT_INVALID") from None


def build_sentence_transformers_benchmark_backends(
    *,
    runtime_manifest: RuntimeModelManifest,
    artifact_root: Path,
) -> tuple[SentenceTransformersBenchmarkBackend, ...]:
    """Build the fixed two-embedding by two-reranker local candidate matrix."""

    try:
        manifest = RuntimeModelManifest.model_validate(
            runtime_manifest,
            strict=True,
        )
    except (TypeError, ValidationError, ValueError):
        raise ModelBenchmarkError("MODEL_BENCHMARK_MANIFEST_INVALID") from None
    embeddings = tuple(
        sorted(
            (record for record in manifest.models if record.role == "embedding"),
            key=lambda record: record.model_id,
        )
    )
    rerankers = tuple(
        sorted(
            (record for record in manifest.models if record.role == "reranker"),
            key=lambda record: record.model_id,
        )
    )
    if len(embeddings) != 2 or len(rerankers) != 2:
        raise ModelBenchmarkError("MODEL_BENCHMARK_CANDIDATE_SET_INCOMPLETE")
    try:
        embedders = {
            record.model_id: SentenceTransformersEmbedder(
                artifact_root / Path(record.artifact_relpath),
                record.descriptor,
            )
            for record in embeddings
        }
        reranker_adapters = {
            record.model_id: SentenceTransformersCrossEncoderReranker(
                artifact_root / Path(record.artifact_relpath),
                record.descriptor,
            )
            for record in rerankers
        }
        # Load every shared model and initialize its inference path before a
        # particular pair can enter the timed loop.  Iterating by model id
        # keeps the prewarm sequence independent of manifest/pair ordering.
        for model_id in sorted(embedders):
            embedder = embedders[model_id]
            embedder.encode_query(_PREWARM_QUERY)
            embedder.encode_documents((_PREWARM_DOCUMENT,))
        for model_id in sorted(reranker_adapters):
            reranker_adapters[model_id].score(
                _PREWARM_QUERY,
                (_PREWARM_DOCUMENT,),
            )
    except LocalModelUnavailable:
        raise ModelBenchmarkError("MODEL_BENCHMARK_MODEL_UNAVAILABLE") from None
    except EmbeddingContractError:
        raise ModelBenchmarkError("MODEL_BENCHMARK_PREWARM_FAILED") from None
    return tuple(
        SentenceTransformersBenchmarkBackend(
            artifact_root=artifact_root,
            embedding_record=embedding,
            reranker_record=reranker,
            embedder_adapter=embedders[embedding.model_id],
            reranker_adapter=reranker_adapters[reranker.model_id],
        )
        for embedding in embeddings
        for reranker in rerankers
    )


def _plain_directory(path: Path) -> bool:
    try:
        status = os.lstat(path)
    except OSError:
        return False
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    attributes = int(getattr(status, "st_file_attributes", 0))
    return (
        stat.S_ISDIR(status.st_mode)
        and not stat.S_ISLNK(status.st_mode)
        and not bool(attributes & reparse_flag)
    )


def write_model_benchmark_report_atomic(
    output_root: Path,
    output_ref: str,
    report: ModelBenchmarkReport,
) -> str:
    """Persist exactly one body-free report under a safe opaque reference."""

    if not isinstance(output_root, Path) or not output_root.is_absolute():
        raise ModelBenchmarkError("MODEL_BENCHMARK_OUTPUT_ROOT_INVALID")
    if (
        type(output_ref) is not str
        or re.fullmatch(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*", output_ref) is None
    ):
        raise ModelBenchmarkError("MODEL_BENCHMARK_OUTPUT_REF_INVALID")
    try:
        exact_report = ModelBenchmarkReport.model_validate(report, strict=True)
    except (TypeError, ValidationError, ValueError):
        raise ModelBenchmarkError("MODEL_BENCHMARK_REPORT_INVALID") from None
    serialized = canonical_json_bytes(exact_report.model_dump(mode="json")) + b"\n"
    report_sha256 = hashlib.sha256(serialized).hexdigest()
    temporary: Path | None = None
    try:
        output_root.mkdir(parents=True, exist_ok=True)
        exact_root = output_root.resolve(strict=True)
        if exact_root != output_root or not _plain_directory(output_root):
            raise ModelBenchmarkError("MODEL_BENCHMARK_OUTPUT_ROOT_INVALID")
        target = exact_root / f"{output_ref}.json"
        if os.path.lexists(target):
            if not _plain_single_link_file(target):
                raise ModelBenchmarkError("MODEL_BENCHMARK_REPORT_CONFLICT")
            if target.read_bytes() != serialized:
                raise ModelBenchmarkError("MODEL_BENCHMARK_REPORT_CONFLICT")
            return report_sha256
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output_ref}.",
            suffix=".tmp",
            dir=exact_root,
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        temporary = None
        if not _plain_single_link_file(target) or target.read_bytes() != serialized:
            raise ModelBenchmarkError("MODEL_BENCHMARK_REPORT_WRITE_FAILED")
        return report_sha256
    except ModelBenchmarkError:
        raise
    except OSError:
        raise ModelBenchmarkError("MODEL_BENCHMARK_REPORT_WRITE_FAILED") from None
    finally:
        if temporary is not None and os.path.lexists(temporary):
            try:
                if temporary.parent == output_root and temporary.name.startswith(
                    f".{output_ref}."
                ):
                    temporary.unlink()
            except OSError:
                pass


class CandidateBenchmarkResult(StrictModel):
    embedding_model_id: SafePolicyKey
    reranker_model_id: SafePolicyKey
    embedding_descriptor_sha256: Sha256Hex
    reranker_descriptor_sha256: Sha256Hex
    case_count: PositiveInt
    constraint_failures: NonNegativeInt
    passed_constraints: bool
    recall_at_10: NonNegativeFloat
    counterevidence_recall: NonNegativeFloat
    ndcg_at_10: NonNegativeFloat
    mrr: NonNegativeFloat
    rerank_gain: FiniteFloat
    mean_cpu_latency_ms: NonNegativeFloat
    peak_memory_bytes: NonNegativeInt

    @model_validator(mode="after")
    def _metric_contract(self) -> Self:
        bounded = (
            self.recall_at_10,
            self.counterevidence_recall,
            self.ndcg_at_10,
            self.mrr,
        )
        if any(value > 1.0 for value in bounded):
            raise ValueError("benchmark quality metrics must remain in [0, 1]")
        if self.passed_constraints != (self.constraint_failures == 0):
            raise ValueError("benchmark constraint status is inconsistent")
        return self


class ModelBenchmarkReport(StrictModel):
    schema_version: Literal["consultation_model_benchmark.v1"] = (
        "consultation_model_benchmark.v1"
    )
    runtime_manifest_sha256: Sha256Hex
    suite_sha256: Sha256Hex
    case_count: PositiveInt
    required_query_kinds: tuple[BenchmarkQueryKind, ...]
    latency_measurement_scope: Literal["warmed_cpu_case_wall_clock"] = (
        "warmed_cpu_case_wall_clock"
    )
    memory_measurement_scope: Literal["python_tracemalloc_delta_diagnostic_only"] = (
        "python_tracemalloc_delta_diagnostic_only"
    )
    memory_used_for_selection: Literal[False] = False
    candidates: tuple[CandidateBenchmarkResult, ...]
    selected_embedding_model_id: SafePolicyKey
    selected_reranker_model_id: SafePolicyKey

    @model_validator(mode="after")
    def _selection_contract(self) -> Self:
        if self.required_query_kinds != REQUIRED_BENCHMARK_QUERY_KINDS:
            raise ValueError("benchmark query-kind coverage is incomplete")
        pairs = tuple(
            (item.embedding_model_id, item.reranker_model_id)
            for item in self.candidates
        )
        if not pairs or len(pairs) != len(set(pairs)):
            raise ValueError("benchmark candidate pairs must be nonempty and unique")
        selected = (self.selected_embedding_model_id, self.selected_reranker_model_id)
        if selected != pairs[0] or not self.candidates[0].passed_constraints:
            raise ValueError(
                "selected benchmark pair must be the first eligible result"
            )
        return self


def _suite(
    cases: Sequence[ModelBenchmarkCase],
) -> tuple[ModelBenchmarkCase, ...]:
    try:
        exact = tuple(
            ModelBenchmarkCase.model_validate(case, strict=True) for case in cases
        )
    except (TypeError, ValidationError, ValueError):
        raise ModelBenchmarkError("MODEL_BENCHMARK_SUITE_INVALID") from None
    case_ids = tuple(item.case_id for item in exact)
    kinds = tuple(sorted({item.query_kind for item in exact}))
    if (
        not exact
        or len(case_ids) != len(set(case_ids))
        or kinds != REQUIRED_BENCHMARK_QUERY_KINDS
    ):
        raise ModelBenchmarkError("MODEL_BENCHMARK_SUITE_INCOMPLETE")
    return tuple(sorted(exact, key=lambda item: item.case_id))


def _suite_sha256(cases: tuple[ModelBenchmarkCase, ...]) -> str:
    return hashlib.sha256(
        canonical_json_bytes([item.model_dump(mode="json") for item in cases])
    ).hexdigest()


def _result_sort_key(
    result: CandidateBenchmarkResult,
) -> tuple[object, ...]:
    """Zero failures, recall/counterevidence, nDCG, then resources."""

    return (
        not result.passed_constraints,
        result.constraint_failures,
        -result.recall_at_10,
        -result.counterevidence_recall,
        -result.ndcg_at_10,
        result.mean_cpu_latency_ms,
        result.embedding_model_id,
        result.reranker_model_id,
    )


def _evaluate_backend(
    *,
    cases: tuple[ModelBenchmarkCase, ...],
    backend: OfflineBenchmarkBackend,
    embedding_descriptor_sha256: str,
    reranker_descriptor_sha256: str,
) -> CandidateBenchmarkResult:
    recalls: list[float] = []
    ndcgs: list[float] = []
    initial_ndcgs: list[float] = []
    reciprocal_ranks: list[float] = []
    total_counterevidence = 0
    recalled_counterevidence = 0
    constraint_failures = 0
    total_latency = 0.0
    peak_memory = 0

    for case in cases:
        try:
            observed = BenchmarkQueryResult.model_validate(
                backend.evaluate(case),
                strict=True,
            )
        except Exception:
            raise ModelBenchmarkError("MODEL_BENCHMARK_EXECUTION_FAILED") from None
        passage_by_id = {item.evidence_id: item for item in case.passages}
        observed_ids = set(observed.initial_ranked_ids)
        if not observed_ids.issubset(passage_by_id):
            raise ModelBenchmarkError("MODEL_BENCHMARK_RESULT_INVALID")

        relevant_ids = {
            item.evidence_id for item in case.passages if item.relevance_grade > 0
        }
        relevance = {
            item.evidence_id: item.relevance_grade
            for item in case.passages
            if item.relevance_grade > 0
        }
        counterevidence_ids = {
            item.evidence_id for item in case.passages if item.is_counterevidence
        }
        final_prefix = observed.reranked_ids[:10]
        recall = recall_at_k(observed.reranked_ids, relevant_ids, 10)
        initial_ndcg = ndcg_at_k(observed.initial_ranked_ids, relevance, 10)
        final_ndcg = ndcg_at_k(observed.reranked_ids, relevance, 10)
        rr = reciprocal_rank(observed.reranked_ids, relevant_ids)
        if recall is None or initial_ndcg is None or final_ndcg is None or rr is None:
            raise ModelBenchmarkError("MODEL_BENCHMARK_RESULT_UNDEFINED")

        recalls.append(recall)
        initial_ndcgs.append(initial_ndcg)
        ndcgs.append(final_ndcg)
        reciprocal_ranks.append(rr)
        total_counterevidence += len(counterevidence_ids)
        recalled_counterevidence += len(counterevidence_ids & set(final_prefix))
        constraint_failures += len(
            {
                evidence_id
                for evidence_id in observed_ids
                if not passage_by_id[evidence_id].allowed
            }
        )
        total_latency += observed.cpu_latency_ms
        peak_memory = max(peak_memory, observed.peak_memory_bytes)

    count = len(cases)
    counterevidence_recall = (
        recalled_counterevidence / total_counterevidence
        if total_counterevidence
        else 0.0
    )
    try:
        return CandidateBenchmarkResult(
            embedding_model_id=backend.embedding_model_id,
            reranker_model_id=backend.reranker_model_id,
            embedding_descriptor_sha256=embedding_descriptor_sha256,
            reranker_descriptor_sha256=reranker_descriptor_sha256,
            case_count=count,
            constraint_failures=constraint_failures,
            passed_constraints=constraint_failures == 0,
            recall_at_10=sum(recalls) / count,
            counterevidence_recall=counterevidence_recall,
            ndcg_at_10=sum(ndcgs) / count,
            mrr=sum(reciprocal_ranks) / count,
            rerank_gain=(sum(ndcgs) - sum(initial_ndcgs)) / count,
            mean_cpu_latency_ms=total_latency / count,
            peak_memory_bytes=peak_memory,
        )
    except (ValidationError, ValueError):
        raise ModelBenchmarkError("MODEL_BENCHMARK_RESULT_INVALID") from None


def run_model_benchmark(
    cases: Sequence[ModelBenchmarkCase],
    backends: Sequence[OfflineBenchmarkBackend],
    *,
    runtime_manifest: RuntimeModelManifest,
) -> ModelBenchmarkReport:
    """Evaluate local model pairs and choose the quality-first eligible pair."""

    exact_cases = _suite(cases)
    try:
        manifest = RuntimeModelManifest.model_validate(runtime_manifest, strict=True)
    except (TypeError, ValidationError, ValueError):
        raise ModelBenchmarkError("MODEL_BENCHMARK_MANIFEST_INVALID") from None
    records = {item.model_id: item for item in manifest.models}
    exact_backends = tuple(backends)
    if not exact_backends:
        raise ModelBenchmarkError("MODEL_BENCHMARK_BACKENDS_REQUIRED")

    seen_pairs: set[tuple[str, str]] = set()
    results: list[CandidateBenchmarkResult] = []
    for backend in exact_backends:
        try:
            embedding_model_id = backend.embedding_model_id
            reranker_model_id = backend.reranker_model_id
        except Exception:
            raise ModelBenchmarkError("MODEL_BENCHMARK_BACKEND_INVALID") from None
        if type(embedding_model_id) is not str or type(reranker_model_id) is not str:
            raise ModelBenchmarkError("MODEL_BENCHMARK_BACKEND_INVALID")
        pair = (embedding_model_id, reranker_model_id)
        if pair in seen_pairs:
            raise ModelBenchmarkError("MODEL_BENCHMARK_BACKEND_DUPLICATE")
        seen_pairs.add(pair)
        embedding = records.get(embedding_model_id)
        reranker = records.get(reranker_model_id)
        if embedding is None or reranker is None:
            raise ModelBenchmarkError("MODEL_BENCHMARK_MODEL_NOT_IMPORTED")
        if embedding.role != "embedding" or reranker.role != "reranker":
            raise ModelBenchmarkError("MODEL_BENCHMARK_MODEL_ROLE_INVALID")
        if (
            not embedding.load_policy.local_files_only
            or embedding.load_policy.trust_remote_code
            or not reranker.load_policy.local_files_only
            or reranker.load_policy.trust_remote_code
        ):
            raise ModelBenchmarkError("MODEL_BENCHMARK_OFFLINE_POLICY_INVALID")
        results.append(
            _evaluate_backend(
                cases=exact_cases,
                backend=backend,
                embedding_descriptor_sha256=embedding.descriptor_sha256,
                reranker_descriptor_sha256=reranker.descriptor_sha256,
            )
        )

    ranked = tuple(sorted(results, key=_result_sort_key))
    if not ranked[0].passed_constraints:
        raise ModelBenchmarkError("MODEL_BENCHMARK_NO_ELIGIBLE_CANDIDATE")
    try:
        return ModelBenchmarkReport(
            runtime_manifest_sha256=manifest.canonical_sha256,
            suite_sha256=_suite_sha256(exact_cases),
            case_count=len(exact_cases),
            required_query_kinds=REQUIRED_BENCHMARK_QUERY_KINDS,
            candidates=ranked,
            selected_embedding_model_id=ranked[0].embedding_model_id,
            selected_reranker_model_id=ranked[0].reranker_model_id,
        )
    except (ValidationError, ValueError):
        raise ModelBenchmarkError("MODEL_BENCHMARK_REPORT_INVALID") from None


__all__ = [
    "BenchmarkPassage",
    "BenchmarkQueryKind",
    "BenchmarkQueryResult",
    "CandidateBenchmarkResult",
    "MAX_MODEL_BENCHMARK_SUITE_BYTES",
    "MODEL_BENCHMARK_SUITE_RELPATH",
    "MODEL_BENCHMARK_SUITE_SCHEMA_VERSION",
    "ModelBenchmarkCase",
    "ModelBenchmarkError",
    "ModelBenchmarkReport",
    "OfflineBenchmarkBackend",
    "REQUIRED_BENCHMARK_QUERY_KINDS",
    "SentenceTransformersBenchmarkBackend",
    "build_sentence_transformers_benchmark_backends",
    "load_model_benchmark_suite",
    "run_model_benchmark",
    "write_model_benchmark_report_atomic",
]
