from __future__ import annotations

import numpy as np

from consultation_kb.retrieval.contracts import ResolvedEvidence
from consultation_kb.retrieval.embeddings import ModelDescriptor, ModelFileHash
from consultation_kb.retrieval.fusion import FusionEvidence, ReciprocalRankFusion
from consultation_kb.retrieval.rerank import EvidenceReranker
from tests.consultation_kb.graph_support import ref
from tests.consultation_kb.unit.test_rrf_fusion import candidate


def _descriptor() -> ModelDescriptor:
    return ModelDescriptor(
        repo="local/test-reranker",
        revision="1" * 40,
        model_files=(ModelFileHash(relative_path="model.bin", sha256="2" * 64),),
        adapter_class="tests.DeterministicReranker",
        adapter_version="1",
        sentence_transformers_version="test",
        transformers_version="test",
        tokenizer_version="test",
        tokenizer_sha256="3" * 64,
        query_prompt="",
        document_prompt="",
        pooling="model_defined",
        normalize_embeddings=False,
        max_sequence_length=128,
        truncation="longest_first",
        dimension=1,
        score_function="dot",
    )


class RecordingReranker:
    def __init__(self, *, fail: bool = False) -> None:
        self._descriptor = _descriptor()
        self.fail = fail
        self.inputs: tuple[str, ...] = ()

    @property
    def descriptor(self) -> ModelDescriptor:
        return self._descriptor

    def score(self, query: str, passages):  # type: ignore[no-untyped-def]
        self.inputs = tuple(passages)
        if self.fail:
            raise RuntimeError("model unavailable")
        return np.asarray(
            [float(len(value)) for value in passages], dtype=np.float32
        )


def test_only_filter_bound_resolved_bodies_reach_reranker() -> None:
    allowed_short = candidate(channel="lexical")
    allowed_long = candidate(channel="vector")
    unresolved_secret = candidate(channel="wiki")
    fused = ReciprocalRankFusion().fuse(
        {
            "lexical": (FusionEvidence(candidate=allowed_short, stance="support"),),
            "vector": (FusionEvidence(candidate=allowed_long, stance="support"),),
            "wiki": (
                FusionEvidence(candidate=unresolved_secret, stance="support"),
            ),
        }
    )
    model = RecordingReranker()
    result = EvidenceReranker(model).rerank(
        "query",
        fused,
        (
            ResolvedEvidence(candidate=allowed_short, body="短文".encode()),
            ResolvedEvidence(candidate=allowed_long, body="更长的正文".encode()),
        ),
    )

    assert set(model.inputs) == {"短文", "更长的正文"}
    assert all("secret" not in value for value in model.inputs)
    assert len(result.candidates) == 2
    assert result.manifest.status == "degraded"
    assert result.manifest.degraded_components == ("unresolved_evidence",)
    assert result.manifest.descriptor_id == model.descriptor.id
    assert result.manifest.descriptor_revision == model.descriptor.revision


def test_model_failure_explicitly_degrades_and_preserves_rrf_order() -> None:
    first = candidate(channel="lexical")
    second = candidate(channel="vector")
    fused = ReciprocalRankFusion().fuse(
        {
            "lexical": (FusionEvidence(candidate=first, stance="support"),),
            "vector": (FusionEvidence(candidate=second, stance="support"),),
        }
    )
    model = RecordingReranker(fail=True)

    result = EvidenceReranker(model).rerank(
        "query",
        fused,
        (
            ResolvedEvidence(candidate=first, body=b"first"),
            ResolvedEvidence(candidate=second, body=b"second"),
        ),
    )

    assert [item.fused.evidence_id for item in result.candidates] == [
        item.evidence_id for item in fused
    ]
    assert all(item.model_score is None for item in result.candidates)
    assert result.manifest.status == "degraded"
    assert result.manifest.degraded_components == ("reranker",)
    assert result.manifest.error_code == "RERANKER_MODEL_FAILURE"


def test_same_claim_passage_across_channels_resolves_the_exact_fused_candidate() -> None:
    claim_ref = candidate(channel="lexical").reference
    passage_ref = candidate(channel="lexical").content_ref
    source_ref = ref("source", "a")
    lexical = candidate(
        channel="lexical",
        claim_ref=claim_ref,
        passage_ref=passage_ref,
        source_ref=source_ref,
    )
    vector = candidate(
        channel="vector",
        claim_ref=claim_ref,
        passage_ref=passage_ref,
        source_ref=source_ref,
    )
    wiki = candidate(
        channel="wiki",
        claim_ref=claim_ref,
        passage_ref=passage_ref,
        source_ref=source_ref,
    )
    fused = ReciprocalRankFusion().fuse(
        {
            "lexical": (FusionEvidence(candidate=lexical, stance="support"),),
            "vector": (FusionEvidence(candidate=vector, stance="support"),),
            "wiki": (FusionEvidence(candidate=wiki, stance="support"),),
        }
    )
    assert fused[0].passages[0].candidate == lexical
    model = RecordingReranker()

    result = EvidenceReranker(model).rerank(
        "query",
        fused,
        (
            ResolvedEvidence(candidate=lexical, body=b"lexical-authorized"),
            ResolvedEvidence(candidate=vector, body=b"vector-authorized"),
            ResolvedEvidence(candidate=wiki, body=b"wiki-authorized"),
        ),
    )

    assert model.inputs == ("lexical-authorized",)
    assert result.manifest.status == "applied"
    assert result.manifest.degraded_components == ()
    assert result.candidates[0].passages[0].resolved.candidate == lexical


def test_same_pair_from_another_channel_cannot_supply_the_fused_body() -> None:
    claim_ref = candidate(channel="lexical").reference
    passage_ref = candidate(channel="lexical").content_ref
    source_ref = ref("source", "b")
    lexical = candidate(
        channel="lexical",
        claim_ref=claim_ref,
        passage_ref=passage_ref,
        source_ref=source_ref,
    )
    wiki = candidate(
        channel="wiki",
        claim_ref=claim_ref,
        passage_ref=passage_ref,
        source_ref=source_ref,
    )
    fused = ReciprocalRankFusion().fuse(
        {"lexical": (FusionEvidence(candidate=lexical, stance="support"),)}
    )
    model = RecordingReranker()

    result = EvidenceReranker(model).rerank(
        "query",
        fused,
        (ResolvedEvidence(candidate=wiki, body=b"wrong-channel-body"),),
    )

    assert model.inputs == ()
    assert result.candidates == ()
    assert result.manifest.status == "degraded"
    assert result.manifest.degraded_components == ("unresolved_evidence",)
    assert result.manifest.error_code == "RERANK_INPUT_EMPTY"


def test_rerank_preserves_each_passage_identity_for_lossless_pack_expansion() -> None:
    claim = candidate(channel="lexical").reference
    first = candidate(channel="lexical", claim_ref=claim)
    second = candidate(channel="lexical", claim_ref=claim)
    fused = ReciprocalRankFusion().fuse(
        {
            "lexical": (
                FusionEvidence(candidate=first, stance="support"),
                FusionEvidence(candidate=second, stance="support"),
            )
        }
    )

    result = EvidenceReranker(RecordingReranker()).rerank(
        "query",
        fused,
        (
            ResolvedEvidence(candidate=first, body=b"first"),
            ResolvedEvidence(candidate=second, body=b"second"),
        ),
    )

    expanded = result.candidates[0].passages
    assert len(expanded) == 2
    assert len({item.evidence_id for item in expanded}) == 2
    assert {item.resolved.body for item in expanded} == {b"first", b"second"}
