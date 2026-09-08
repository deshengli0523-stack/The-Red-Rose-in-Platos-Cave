from __future__ import annotations

import sqlite3
from pathlib import Path

import numpy as np
import pytest

from consultation_kb.retrieval.embeddings import DeterministicFakeEmbedder
from consultation_kb.retrieval.artifact_contracts import retrieval_row_id
from consultation_kb.retrieval.vector import ExactVectorIndexError, ExactVectorRetriever
from consultation_kb.retrieval.vector_builder import (
    ExactVectorIndexBuilder,
    VectorBuildError,
    VectorDocument,
)
from tests.consultation_kb.retrieval_support import (
    candidate,
    derived_builder_input,
    model_descriptor,
    reference,
    scope,
    snapshot,
)


class _TrackingEmbedder(DeterministicFakeEmbedder):
    def __init__(self) -> None:
        super().__init__(
            model_descriptor(query_prompt="", document_prompt=""),
            {
                "query": np.asarray([1.0, 0.0], dtype=np.float32),
                "high": np.asarray([1.0, 0.0], dtype=np.float32),
                "low": np.asarray([0.8, 0.6], dtype=np.float32),
                "tie": np.asarray([1.0, 0.0], dtype=np.float32),
            },
        )
        self.query_calls = 0

    def encode_query(self, text: str) -> np.ndarray:
        self.query_calls += 1
        return super().encode_query(text)


def _build(directory: Path, model: _TrackingEmbedder):
    high = candidate(11, text="high", channel="vector")
    low = candidate(12, text="low", channel="vector")
    manifest = ExactVectorIndexBuilder(model).build(
        (
            VectorDocument(candidate=high, text="high"),
            VectorDocument(candidate=low, text="low"),
        ),
        directory,
        builder_input=derived_builder_input(
            "vector",
            high,
            low,
            source_catalog_version=9,
        ),
    )
    return high, low, manifest


def test_allowed_metadata_intersection_precedes_model_and_mmap(tmp_path: Path) -> None:
    directory = tmp_path / "vectors"
    model = _TrackingEmbedder()
    high, low, _manifest = _build(directory, model)
    model.query_calls = 0
    loaded: list[Path] = []

    def load(path: Path) -> np.ndarray:
        loaded.append(path)
        return np.load(path, mmap_mode="r", allow_pickle=False)

    retriever = ExactVectorRetriever._from_unbound_directory_for_test(
        directory, embedder=model, matrix_loader=load
    )

    assert retriever.search("query", scope(), snapshot(), limit=1) == ()
    assert model.query_calls == 0
    assert loaded == []

    result = retriever.search("query", scope(), snapshot(low), limit=1)
    assert [item.reference.object_id for item in result] == [low.reference.object_id]
    assert high.reference.object_id not in {
        item.reference.object_id for item in result
    }
    assert model.query_calls == 1
    assert loaded == [directory / "vectors.npy"]


def test_equal_scores_are_stable_by_exact_claim_content_row_id(tmp_path: Path) -> None:
    directory = tmp_path / "ties"
    model = _TrackingEmbedder()
    first = candidate(21, text="tie", channel="vector")
    second = candidate(22, text="tie", channel="vector")
    ExactVectorIndexBuilder(model).build(
        (
            VectorDocument(candidate=second, text="tie"),
            VectorDocument(candidate=first, text="tie"),
        ),
        directory,
        builder_input=derived_builder_input(
            "vector",
            first,
            second,
            source_catalog_version=1,
        ),
    )

    result = ExactVectorRetriever._from_unbound_directory_for_test(
        directory, embedder=model
    ).search(
        "query",
        scope(),
        snapshot(first, second),
        limit=2,
    )

    assert [item.content_ref for item in result] == [
        item.content_ref for item in sorted((first, second), key=retrieval_row_id)
    ]


def test_builder_emits_hashes_and_never_overwrites_a_shard(tmp_path: Path) -> None:
    directory = tmp_path / "vectors"
    model = _TrackingEmbedder()
    _high, _low, manifest = _build(directory, model)

    assert manifest.row_count == 2
    assert len(manifest.row_content_hashes) == 2
    assert (directory / manifest.vector_filename).is_file()
    assert (directory / manifest.metadata_filename).is_file()
    assert (directory / "vector-manifest.json").is_file()
    with pytest.raises(VectorBuildError, match="VECTOR_IMMUTABLE_TARGET_EXISTS"):
        _build(directory, model)


def test_existing_shard_rejects_descriptor_drift(tmp_path: Path) -> None:
    directory = tmp_path / "vectors"
    model = _TrackingEmbedder()
    high, low, _manifest = _build(directory, model)
    drifted = DeterministicFakeEmbedder(
        model_descriptor(query_prompt="drift: ", document_prompt=""),
        {"query": np.asarray([1.0, 0.0], dtype=np.float32)},
    )

    with pytest.raises(
        ExactVectorIndexError,
        match="VECTOR_MODEL_DESCRIPTOR_MISMATCH",
    ):
        ExactVectorRetriever._from_unbound_directory_for_test(
            directory, embedder=drifted
        ).search(
            "query",
            scope(),
            snapshot(high, low),
            limit=2,
        )


def test_vector_row_binds_indexed_body_ref_separately_from_evidence_ref(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "body-ref"
    model = DeterministicFakeEmbedder(
        model_descriptor(query_prompt="", document_prompt=""),
        {"body": np.asarray([1.0, 0.0], dtype=np.float32)},
    )
    value = candidate(30, text="body", channel="vector")
    value = value.model_copy(
        update={"reference": reference("claim", 730), "object_type": "claim"}
    )
    ExactVectorIndexBuilder(model).build(
        (VectorDocument(candidate=value, text="body"),),
        directory,
        builder_input=derived_builder_input(
            "vector",
            value,
            source_catalog_version=1,
        ),
    )
    connection = sqlite3.connect(directory / "vector-meta.sqlite3")
    try:
        stored = str(
            connection.execute("SELECT content_sha256 FROM vector_rows").fetchone()[0]
        )
    finally:
        connection.close()

    assert stored == value.content_ref.content_sha256
    assert stored != value.reference.content_sha256
    result = ExactVectorRetriever._from_unbound_directory_for_test(
        directory, embedder=model
    ).search(
        "body",
        scope(),
        snapshot(value),
        limit=1,
    )
    assert tuple(item.reference for item in result) == (value.reference,)


def test_one_claim_version_can_index_and_return_multiple_passages(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "multi-passage"
    model = _TrackingEmbedder()
    first = candidate(50, text="tie", channel="vector")
    second = candidate(51, text="tie", channel="vector").model_copy(
        update={"reference": first.reference}
    )
    ExactVectorIndexBuilder(model).build(
        (
            VectorDocument(candidate=first, text="tie"),
            VectorDocument(candidate=second, text="tie"),
        ),
        directory,
        builder_input=derived_builder_input(
            "vector",
            first,
            second,
            source_catalog_version=2,
        ),
    )

    result = ExactVectorRetriever._from_unbound_directory_for_test(
        directory, embedder=model
    ).search(
        "query",
        scope(),
        snapshot(first),
        limit=2,
    )
    assert {item.content_ref for item in result} == {
        first.content_ref,
        second.content_ref,
    }
