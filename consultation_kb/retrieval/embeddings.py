"""Pinned local embedding/reranking contracts and deterministic validation."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Literal, Protocol

import numpy as np
from numpy.typing import NDArray
from pydantic import field_validator, model_validator

from consultation_kb.models.common import (
    NonEmptyStr,
    PositiveInt,
    Sha256Hex,
    StrictModel,
)

from .contracts import canonical_json_bytes


_REVISION = re.compile(r"[0-9a-f]{40}\Z")


class EmbeddingContractError(ValueError):
    def __init__(self, code: str = "EMBEDDING_CONTRACT_INVALID") -> None:
        super().__init__(code)


class ModelFileHash(StrictModel):
    relative_path: NonEmptyStr
    sha256: Sha256Hex

    @field_validator("relative_path")
    @classmethod
    def _safe_relative_path(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        parts = normalized.split("/")
        if (
            normalized.startswith("/")
            or ":" in normalized
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise ValueError("model file path must be relative and non-traversing")
        return normalized


class ModelDescriptor(StrictModel):
    repo: NonEmptyStr
    revision: NonEmptyStr
    model_files: tuple[ModelFileHash, ...]
    adapter_class: NonEmptyStr
    adapter_version: NonEmptyStr
    sentence_transformers_version: NonEmptyStr
    transformers_version: NonEmptyStr
    tokenizer_version: NonEmptyStr
    tokenizer_sha256: Sha256Hex
    query_prompt: str
    document_prompt: str
    pooling: Literal["cls", "mean", "max", "last_token", "model_defined"]
    normalize_embeddings: bool
    max_sequence_length: PositiveInt
    truncation: Literal["longest_first", "only_first", "do_not_truncate"]
    dtype: Literal["float32"] = "float32"
    precision: Literal["float32"] = "float32"
    dimension: PositiveInt
    score_function: Literal["cosine", "dot"]

    @field_validator("revision")
    @classmethod
    def _pinned_revision(cls, value: str) -> str:
        if _REVISION.fullmatch(value) is None:
            raise ValueError("model revision must be a pinned 40-hex commit")
        return value

    @field_validator("model_files")
    @classmethod
    def _canonical_files(
        cls, value: tuple[ModelFileHash, ...]
    ) -> tuple[ModelFileHash, ...]:
        paths = [item.relative_path for item in value]
        if not value or len(paths) != len(set(paths)):
            raise ValueError("model files must be nonempty and unique")
        return tuple(sorted(value, key=lambda item: item.relative_path))

    @model_validator(mode="after")
    def _score_contract(self) -> "ModelDescriptor":
        if self.score_function == "cosine" and not self.normalize_embeddings:
            raise ValueError("cosine descriptor requires normalized embeddings")
        return self

    @property
    def id(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(self.model_dump(mode="json"))
        ).hexdigest()


class Embedder(Protocol):
    @property
    def descriptor(self) -> ModelDescriptor: ...

    def encode_query(self, text: str) -> NDArray[np.float32]: ...

    def encode_documents(
        self, texts: Sequence[str]
    ) -> NDArray[np.float32]: ...


class Reranker(Protocol):
    @property
    def descriptor(self) -> ModelDescriptor: ...

    def score(
        self,
        query: str,
        passages: Sequence[str],
    ) -> NDArray[np.float32]: ...


def validate_vector(
    value: NDArray[np.float32],
    descriptor: ModelDescriptor,
) -> NDArray[np.float32]:
    if (
        not isinstance(value, np.ndarray)
        or value.dtype != np.float32
        or value.ndim != 1
        or value.shape != (descriptor.dimension,)
        or not np.isfinite(value).all()
    ):
        raise EmbeddingContractError
    norm = float(np.linalg.norm(value))
    if norm == 0.0 or (
        descriptor.normalize_embeddings and not np.isclose(norm, 1.0, atol=1e-5)
    ):
        raise EmbeddingContractError
    return np.ascontiguousarray(value, dtype=np.float32)


def validate_matrix(
    value: NDArray[np.float32],
    descriptor: ModelDescriptor,
    *,
    expected_rows: int,
) -> NDArray[np.float32]:
    if (
        not isinstance(value, np.ndarray)
        or value.dtype != np.float32
        or value.ndim != 2
        or value.shape != (expected_rows, descriptor.dimension)
        or not np.isfinite(value).all()
    ):
        raise EmbeddingContractError
    norms = np.linalg.norm(value, axis=1)
    if np.any(norms == 0.0) or (
        descriptor.normalize_embeddings
        and not np.allclose(norms, np.ones_like(norms), atol=1e-5)
    ):
        raise EmbeddingContractError
    return np.ascontiguousarray(value, dtype=np.float32)


class DeterministicFakeEmbedder:
    """Offline test embedder backed by an explicit fixed vocabulary."""

    def __init__(
        self,
        descriptor: ModelDescriptor,
        vocabulary: Mapping[str, NDArray[np.float32]],
    ) -> None:
        self._descriptor = descriptor
        checked: dict[str, NDArray[np.float32]] = {}
        for token, vector in vocabulary.items():
            if type(token) is not str or not token:
                raise EmbeddingContractError
            array = np.asarray(vector, dtype=np.float32)
            if array.shape != (descriptor.dimension,) or not np.isfinite(array).all():
                raise EmbeddingContractError
            checked[token] = array
        if not checked:
            raise EmbeddingContractError
        self._vocabulary = checked

    @property
    def descriptor(self) -> ModelDescriptor:
        return self._descriptor

    def _encode(self, text: str) -> NDArray[np.float32]:
        if type(text) is not str or not text:
            raise EmbeddingContractError
        vector = np.zeros(self._descriptor.dimension, dtype=np.float32)
        for token, contribution in self._vocabulary.items():
            if token in text:
                vector += contribution
        norm = float(np.linalg.norm(vector))
        if norm == 0.0:
            raise EmbeddingContractError("EMBEDDING_ZERO_VECTOR")
        if self._descriptor.normalize_embeddings:
            vector /= norm
        return validate_vector(vector, self._descriptor)

    def encode_query(self, text: str) -> NDArray[np.float32]:
        return self._encode(self._descriptor.query_prompt + text)

    def encode_documents(
        self,
        texts: Sequence[str],
    ) -> NDArray[np.float32]:
        if not texts:
            raise EmbeddingContractError
        matrix = np.stack(
            [self._encode(self._descriptor.document_prompt + text) for text in texts]
        ).astype(np.float32, copy=False)
        return validate_matrix(
            matrix,
            self._descriptor,
            expected_rows=len(texts),
        )


__all__ = [
    "DeterministicFakeEmbedder",
    "Embedder",
    "EmbeddingContractError",
    "ModelDescriptor",
    "ModelFileHash",
    "Reranker",
    "validate_matrix",
    "validate_vector",
]
