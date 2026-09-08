from __future__ import annotations

import numpy as np
import pytest
from pydantic import ValidationError

from consultation_kb.retrieval.embeddings import (
    DeterministicFakeEmbedder,
    EmbeddingContractError,
    ModelFileHash,
    validate_matrix,
    validate_vector,
)
from tests.consultation_kb.retrieval_support import model_descriptor


def test_descriptor_id_changes_for_every_runtime_semantic() -> None:
    base = model_descriptor()
    variants = (
        model_descriptor(query_prompt="q: "),
        model_descriptor(document_prompt="doc: "),
        model_descriptor(pooling="cls"),
        model_descriptor(max_sequence_length=256),
        model_descriptor(truncation="only_first"),
        model_descriptor(adapter_version="2"),
        model_descriptor(tokenizer_sha256="d" * 64),
        model_descriptor(normalize_embeddings=False, score_function="dot"),
        model_descriptor(dimension=3),
    )

    assert len({base.id, *(item.id for item in variants)}) == len(variants) + 1
    with pytest.raises(ValidationError):
        model_descriptor(dtype="float16")


@pytest.mark.parametrize(
    "relative_path",
    ["../model.bin", "/model.bin", r"C:\model.bin", "a//model.bin", "a/./b"],
)
def test_model_file_paths_are_relative_nontraversing(relative_path: str) -> None:
    with pytest.raises(ValidationError):
        ModelFileHash(relative_path=relative_path, sha256="a" * 64)


def test_deterministic_fake_is_normalized_float32_and_rejects_unknown_text() -> None:
    model = model_descriptor(query_prompt="", document_prompt="")
    embedder = DeterministicFakeEmbedder(
        model,
        {
            "仁义": np.asarray([1.0, 1.0], dtype=np.float32),
        },
    )

    query = embedder.encode_query("仁义")
    documents = embedder.encode_documents(("仁义",))

    assert query.dtype == np.float32
    assert documents.dtype == np.float32
    assert query.shape == (2,)
    assert documents.shape == (1, 2)
    assert np.isclose(np.linalg.norm(query), 1.0)
    assert np.allclose(np.linalg.norm(documents, axis=1), np.ones(1))
    with pytest.raises(EmbeddingContractError, match="EMBEDDING_ZERO_VECTOR"):
        embedder.encode_query("unmapped")


@pytest.mark.parametrize(
    "value",
    [
        np.asarray([0.0, 0.0], dtype=np.float32),
        np.asarray([np.nan, 0.0], dtype=np.float32),
        np.asarray([1.0, 0.0, 0.0], dtype=np.float32),
        np.asarray([1.0, 0.0], dtype=np.float64),
    ],
)
def test_vector_validation_rejects_zero_nan_dimension_or_dtype(
    value: np.ndarray,
) -> None:
    with pytest.raises(EmbeddingContractError, match="EMBEDDING_CONTRACT_INVALID"):
        validate_vector(value, model_descriptor())


def test_matrix_validation_rejects_wrong_row_contract() -> None:
    with pytest.raises(EmbeddingContractError, match="EMBEDDING_CONTRACT_INVALID"):
        validate_matrix(
            np.asarray([[1.0, 0.0]], dtype=np.float32),
            model_descriptor(),
            expected_rows=2,
        )
