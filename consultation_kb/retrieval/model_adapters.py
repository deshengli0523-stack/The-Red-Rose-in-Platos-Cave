"""Offline-only, lazy local Sentence Transformers adapter."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

import numpy as np
from numpy.typing import NDArray

from consultation_kb.models.model_lock import ModelLockError, hash_model_tree

from .embeddings import (
    EmbeddingContractError,
    ModelDescriptor,
    validate_matrix,
    validate_vector,
)


_RERANKER_ADAPTER_CLASS = (
    "consultation_kb.retrieval.model_adapters.SentenceTransformersCrossEncoderReranker"
)


class LocalModelUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__("LOCAL_MODEL_NOT_INSTALLED")


def _verify_local_model_tree(
    model_directory: Path,
    descriptor: ModelDescriptor,
) -> None:
    try:
        if hash_model_tree(model_directory) != descriptor.model_files:
            raise LocalModelUnavailable
    except ModelLockError:
        raise LocalModelUnavailable from None


class SentenceTransformersEmbedder:
    """Fixed-revision adapter that cannot initiate a network download."""

    def __init__(
        self,
        model_directory: Path,
        descriptor: ModelDescriptor,
    ) -> None:
        if not isinstance(model_directory, Path):
            raise TypeError("LOCAL_MODEL_PATH_REQUIRED")
        self._directory = model_directory.resolve(strict=False)
        self._descriptor = descriptor
        self._model: Any | None = None
        self._verify_local_files()

    @property
    def descriptor(self) -> ModelDescriptor:
        return self._descriptor

    def _verify_local_files(self) -> None:
        _verify_local_model_tree(self._directory, self._descriptor)

    def _load(self) -> Any:
        if self._model is None:
            try:
                from sentence_transformers import (  # type: ignore[import-not-found,unused-ignore]
                    SentenceTransformer,
                )

                self._model = SentenceTransformer(
                    str(self._directory),
                    revision=self._descriptor.revision,
                    local_files_only=True,
                    trust_remote_code=False,
                    device="cpu",
                )
            except Exception:
                raise LocalModelUnavailable from None
        return self._model

    def _encode(self, texts: Sequence[str], *, prompt: str) -> NDArray[np.float32]:
        if not texts or any(type(text) is not str or not text for text in texts):
            raise EmbeddingContractError
        model = self._load()
        try:
            encoded = model.encode(
                [prompt + text for text in texts],
                batch_size=min(32, len(texts)),
                show_progress_bar=False,
                convert_to_numpy=True,
                normalize_embeddings=self._descriptor.normalize_embeddings,
                precision="float32",
            )
        except Exception:
            raise EmbeddingContractError from None
        return cast(NDArray[np.float32], np.asarray(encoded, dtype=np.float32))

    def encode_query(self, text: str) -> NDArray[np.float32]:
        matrix = self._encode((text,), prompt=self._descriptor.query_prompt)
        return validate_vector(matrix[0], self._descriptor)

    def encode_documents(
        self,
        texts: Sequence[str],
    ) -> NDArray[np.float32]:
        matrix = self._encode(texts, prompt=self._descriptor.document_prompt)
        return validate_matrix(
            matrix,
            self._descriptor,
            expected_rows=len(texts),
        )


class SentenceTransformersCrossEncoderReranker:
    """Pinned local CrossEncoder adapter implementing the reranker protocol."""

    def __init__(
        self,
        model_directory: Path,
        descriptor: ModelDescriptor,
    ) -> None:
        if not isinstance(model_directory, Path):
            raise TypeError("LOCAL_MODEL_PATH_REQUIRED")
        if not isinstance(descriptor, ModelDescriptor):
            raise TypeError("MODEL_DESCRIPTOR_REQUIRED")
        if (
            descriptor.adapter_class != _RERANKER_ADAPTER_CLASS
            or descriptor.adapter_version != "1"
            or descriptor.dimension != 1
            or descriptor.pooling != "model_defined"
            or descriptor.normalize_embeddings
            or descriptor.score_function != "dot"
        ):
            raise EmbeddingContractError("RERANKER_DESCRIPTOR_INVALID")
        self._directory = model_directory.resolve(strict=False)
        self._descriptor = descriptor
        self._model: Any | None = None
        _verify_local_model_tree(self._directory, self._descriptor)

    @property
    def descriptor(self) -> ModelDescriptor:
        return self._descriptor

    def _load(self) -> Any:
        if self._model is None:
            try:
                from sentence_transformers import (
                    CrossEncoder,
                )

                self._model = CrossEncoder(
                    str(self._directory),
                    revision=self._descriptor.revision,
                    local_files_only=True,
                    trust_remote_code=False,
                    device="cpu",
                    max_length=self._descriptor.max_sequence_length,
                )
            except Exception:
                raise LocalModelUnavailable from None
        return self._model

    def score(
        self,
        query: str,
        passages: Sequence[str],
    ) -> NDArray[np.float32]:
        if (
            type(query) is not str
            or not query
            or isinstance(passages, (str, bytes))
            or not passages
            or any(type(passage) is not str or not passage for passage in passages)
        ):
            raise EmbeddingContractError("RERANKER_INPUT_INVALID")
        pairs = [
            (
                self._descriptor.query_prompt + query,
                self._descriptor.document_prompt + passage,
            )
            for passage in passages
        ]
        try:
            predicted = self._load().predict(
                pairs,
                batch_size=min(32, len(pairs)),
                show_progress_bar=False,
                convert_to_numpy=True,
            )
            scores = np.asarray(predicted, dtype=np.float32)
        except LocalModelUnavailable:
            raise
        except Exception:
            raise EmbeddingContractError("RERANKER_EXECUTION_FAILED") from None
        if scores.shape == (len(pairs), 1):
            scores = scores[:, 0]
        if scores.shape != (len(pairs),) or not np.isfinite(scores).all():
            raise EmbeddingContractError("RERANKER_OUTPUT_INVALID")
        return cast(
            NDArray[np.float32],
            np.ascontiguousarray(scores, dtype=np.float32),
        )


__all__ = [
    "LocalModelUnavailable",
    "SentenceTransformersCrossEncoderReranker",
    "SentenceTransformersEmbedder",
]
