from __future__ import annotations

import os
from pathlib import Path

import numpy as np
import pytest

from consultation_kb.retrieval.embeddings import ModelDescriptor
from consultation_kb.retrieval.model_adapters import SentenceTransformersEmbedder


pytestmark = pytest.mark.model


def test_pinned_sentence_transformers_adapter_is_offline_and_lazy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_value = os.environ.get("CONSULTATION_KB_LOCAL_MODEL")
    descriptor_value = os.environ.get("CONSULTATION_KB_LOCAL_MODEL_DESCRIPTOR")
    if model_value is None or descriptor_value is None:
        pytest.skip("local model not installed")
    model_path = Path(model_value)
    descriptor_path = Path(descriptor_value)
    if not model_path.is_dir() or not descriptor_path.is_file():
        pytest.skip("local model not installed")

    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("TRANSFORMERS_OFFLINE", "1")
    descriptor = ModelDescriptor.model_validate_json(
        descriptor_path.read_text(encoding="utf-8"),
        strict=True,
    )
    adapter = SentenceTransformersEmbedder(model_path, descriptor)
    assert adapter._model is None

    query = adapter.encode_query("仁义")
    documents = adapter.encode_documents(("仁义",))

    assert query.dtype == np.float32
    assert query.shape == (descriptor.dimension,)
    assert documents.shape == (1, descriptor.dimension)
