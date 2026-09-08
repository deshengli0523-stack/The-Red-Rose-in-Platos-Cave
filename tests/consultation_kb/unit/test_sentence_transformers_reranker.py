from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from consultation_kb.retrieval import model_adapters
from consultation_kb.retrieval.embeddings import (
    EmbeddingContractError,
    ModelDescriptor,
    ModelFileHash,
)


REVISION = "1" * 40
RERANKER_CLASS = (
    "consultation_kb.retrieval.model_adapters.SentenceTransformersCrossEncoderReranker"
)


def _descriptor(model_directory: Path) -> ModelDescriptor:
    files = tuple(
        ModelFileHash(
            relative_path=path.relative_to(model_directory).as_posix(),
            sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in sorted(model_directory.rglob("*"))
        if path.is_file()
    )
    tokenizer = next(item for item in files if item.relative_path == "tokenizer.json")
    return ModelDescriptor(
        repo="BAAI/bge-reranker-base",
        revision=REVISION,
        model_files=files,
        adapter_class=RERANKER_CLASS,
        adapter_version="1",
        sentence_transformers_version="5.6.0",
        transformers_version="4.57.0",
        tokenizer_version="0.22.0",
        tokenizer_sha256=tokenizer.sha256,
        query_prompt="问题：",
        document_prompt="材料：",
        pooling="model_defined",
        normalize_embeddings=False,
        max_sequence_length=512,
        truncation="longest_first",
        dtype="float32",
        precision="float32",
        dimension=1,
        score_function="dot",
    )


def _model_directory(tmp_path: Path) -> Path:
    root = tmp_path / "reranker"
    (root / "weights").mkdir(parents=True)
    (root / "config.json").write_text("{}", encoding="utf-8")
    (root / "tokenizer.json").write_text("{}", encoding="utf-8")
    (root / "weights" / "model.safetensors").write_bytes(b"synthetic")
    return root


def test_cross_encoder_reranker_is_lazy_cpu_only_and_offline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_directory = _model_directory(tmp_path)
    descriptor = _descriptor(model_directory)
    observed: dict[str, object] = {}

    class _FakeCrossEncoder:
        def __init__(self, model_name: str, **kwargs: object) -> None:
            observed["model_name"] = model_name
            observed["init"] = kwargs

        def predict(
            self,
            pairs: list[tuple[str, str]],
            **kwargs: object,
        ) -> np.ndarray:
            observed["pairs"] = pairs
            observed["predict"] = kwargs
            return np.asarray([[0.25], [0.75]], dtype=np.float64)

    monkeypatch.setitem(
        sys.modules,
        "sentence_transformers",
        SimpleNamespace(CrossEncoder=_FakeCrossEncoder),
    )
    adapter_class = getattr(
        model_adapters,
        "SentenceTransformersCrossEncoderReranker",
    )
    adapter = adapter_class(model_directory, descriptor)

    assert adapter._model is None
    scores = adapter.score("选择", ("第一条", "第二条"))

    assert scores.dtype == np.float32
    assert scores.shape == (2,)
    assert scores.tolist() == pytest.approx([0.25, 0.75])
    assert observed["model_name"] == str(model_directory.resolve())
    assert observed["init"] == {
        "device": "cpu",
        "local_files_only": True,
        "max_length": 512,
        "revision": REVISION,
        "trust_remote_code": False,
    }
    assert observed["pairs"] == [
        ("问题：选择", "材料：第一条"),
        ("问题：选择", "材料：第二条"),
    ]
    assert observed["predict"] == {
        "batch_size": 2,
        "convert_to_numpy": True,
        "show_progress_bar": False,
    }


def test_cross_encoder_reranker_rejects_untracked_file_before_loading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_directory = _model_directory(tmp_path)
    descriptor = _descriptor(model_directory)
    (model_directory / "untracked.bin").write_bytes(b"unexpected")
    monkeypatch.delitem(sys.modules, "sentence_transformers", raising=False)
    adapter_class = getattr(
        model_adapters,
        "SentenceTransformersCrossEncoderReranker",
    )

    with pytest.raises(model_adapters.LocalModelUnavailable):
        adapter_class(model_directory, descriptor)


def test_cross_encoder_reranker_validates_inputs_and_output_shape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_directory = _model_directory(tmp_path)
    descriptor = _descriptor(model_directory)

    class _BadCrossEncoder:
        def __init__(self, model_name: str, **kwargs: object) -> None:
            del model_name, kwargs

        def predict(self, pairs: object, **kwargs: object) -> np.ndarray:
            del pairs, kwargs
            return np.asarray([[1.0, 2.0]], dtype=np.float32)

    monkeypatch.setitem(
        sys.modules,
        "sentence_transformers",
        SimpleNamespace(CrossEncoder=_BadCrossEncoder),
    )
    adapter_class = getattr(
        model_adapters,
        "SentenceTransformersCrossEncoderReranker",
    )
    adapter = adapter_class(model_directory, descriptor)

    with pytest.raises(EmbeddingContractError):
        adapter.score("", ("材料",))
    with pytest.raises(EmbeddingContractError):
        adapter.score("问题", ())
    with pytest.raises(EmbeddingContractError):
        adapter.score("问题", ("材料",))


def test_cross_encoder_reranker_rejects_non_reranker_descriptor(
    tmp_path: Path,
) -> None:
    model_directory = _model_directory(tmp_path)
    descriptor = _descriptor(model_directory).model_copy(
        update={
            "adapter_class": (
                "consultation_kb.retrieval.model_adapters.SentenceTransformersEmbedder"
            ),
            "dimension": 8,
            "normalize_embeddings": True,
            "pooling": "cls",
            "score_function": "cosine",
        }
    )
    adapter_class = getattr(
        model_adapters,
        "SentenceTransformersCrossEncoderReranker",
    )

    with pytest.raises(EmbeddingContractError) as caught:
        adapter_class(model_directory, descriptor)

    assert str(caught.value) == "RERANKER_DESCRIPTOR_INVALID"
