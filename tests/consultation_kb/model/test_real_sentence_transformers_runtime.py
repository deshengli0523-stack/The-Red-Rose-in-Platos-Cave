from __future__ import annotations

import hashlib
import importlib.metadata
from pathlib import Path
from typing import Literal

import numpy as np
import pytest

from consultation_kb.models.model_lock import hash_model_tree
from consultation_kb.retrieval.embeddings import ModelDescriptor
from consultation_kb.retrieval.model_adapters import (
    SentenceTransformersCrossEncoderReranker,
    SentenceTransformersEmbedder,
)


pytestmark = pytest.mark.model


def _descriptor(
    model_directory: Path,
    *,
    adapter_class: str,
    revision_digit: str,
    tokenizer_sha256: str,
    pooling: Literal["mean", "model_defined"],
    normalize_embeddings: bool,
    dimension: int,
    score_function: Literal["cosine", "dot"],
) -> ModelDescriptor:
    return ModelDescriptor(
        repo="synthetic/tiny-bert",
        revision=revision_digit * 40,
        model_files=hash_model_tree(model_directory),
        adapter_class=adapter_class,
        adapter_version="1",
        sentence_transformers_version=importlib.metadata.version(
            "sentence-transformers"
        ),
        transformers_version=importlib.metadata.version("transformers"),
        tokenizer_version=importlib.metadata.version("tokenizers"),
        tokenizer_sha256=tokenizer_sha256,
        query_prompt="",
        document_prompt="",
        pooling=pooling,
        normalize_embeddings=normalize_embeddings,
        max_sequence_length=16,
        truncation="longest_first",
        dimension=dimension,
        score_function=score_function,
    )


def test_locked_real_sentence_transformers_adapters_run_offline_on_cpu(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    torch = pytest.importorskip("torch")
    sentence_transformers = pytest.importorskip("sentence_transformers")
    transformers = pytest.importorskip("transformers")
    from sentence_transformers import SentenceTransformer
    from sentence_transformers.sentence_transformer.modules import Pooling, Transformer
    from transformers import (
        BertConfig,
        BertForSequenceClassification,
        BertModel,
        BertTokenizerFast,
    )

    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("TRANSFORMERS_OFFLINE", "1")
    monkeypatch.setenv("HF_DATASETS_OFFLINE", "1")
    monkeypatch.setenv("TOKENIZERS_PARALLELISM", "false")
    torch.manual_seed(417)
    assert torch.cuda.is_available() is False
    assert sentence_transformers.__version__ == importlib.metadata.version(
        "sentence-transformers"
    )
    assert transformers.__version__ == importlib.metadata.version("transformers")

    vocabulary = tmp_path / "vocab.txt"
    vocabulary.write_text(
        "\n".join(
            ("[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]", "仁", "义", "关系", "边界")
        )
        + "\n",
        encoding="utf-8",
    )
    tokenizer_sha256 = hashlib.sha256(vocabulary.read_bytes()).hexdigest()
    tokenizer = BertTokenizerFast(
        vocab_file=str(vocabulary),
        do_lower_case=False,
    )
    common_config = {
        "vocab_size": tokenizer.vocab_size,
        "hidden_size": 16,
        "num_hidden_layers": 1,
        "num_attention_heads": 2,
        "intermediate_size": 32,
        "max_position_embeddings": 64,
    }

    backbone = tmp_path / "embedding-backbone"
    backbone.mkdir()
    BertModel(BertConfig(**common_config)).save_pretrained(
        backbone,
        safe_serialization=True,
    )
    tokenizer.save_pretrained(backbone)
    transformer_module = Transformer(str(backbone), max_seq_length=16)
    pooling_module = Pooling(
        transformer_module.get_embedding_dimension(),
        pooling_mode="mean",
    )
    embedding_directory = tmp_path / "embedding-model"
    SentenceTransformer(
        modules=[transformer_module, pooling_module],
        device="cpu",
    ).save_pretrained(str(embedding_directory))
    embedder = SentenceTransformersEmbedder(
        embedding_directory,
        _descriptor(
            embedding_directory,
            adapter_class=(
                "consultation_kb.retrieval.model_adapters.SentenceTransformersEmbedder"
            ),
            revision_digit="1",
            tokenizer_sha256=tokenizer_sha256,
            pooling="mean",
            normalize_embeddings=True,
            dimension=16,
            score_function="cosine",
        ),
    )
    query = embedder.encode_query("仁义")
    documents = embedder.encode_documents(("关系", "边界"))
    assert query.dtype == np.float32 and query.shape == (16,)
    assert documents.dtype == np.float32 and documents.shape == (2, 16)
    assert np.isclose(np.linalg.norm(query), 1.0, atol=1e-5)

    reranker_directory = tmp_path / "reranker-model"
    reranker_directory.mkdir()
    BertForSequenceClassification(
        BertConfig(**common_config, num_labels=1)
    ).save_pretrained(
        reranker_directory,
        safe_serialization=True,
    )
    tokenizer.save_pretrained(reranker_directory)
    reranker = SentenceTransformersCrossEncoderReranker(
        reranker_directory,
        _descriptor(
            reranker_directory,
            adapter_class=(
                "consultation_kb.retrieval.model_adapters."
                "SentenceTransformersCrossEncoderReranker"
            ),
            revision_digit="2",
            tokenizer_sha256=tokenizer_sha256,
            pooling="model_defined",
            normalize_embeddings=False,
            dimension=1,
            score_function="dot",
        ),
    )
    scores = reranker.score("仁义", ("关系", "边界"))
    assert scores.dtype == np.float32 and scores.shape == (2,)
    assert np.isfinite(scores).all()
