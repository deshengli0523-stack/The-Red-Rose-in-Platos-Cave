"""Local reranking boundary over filter-bound, already-resolved evidence."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

from consultation_kb.retrieval.contracts import CandidateRef, ResolvedEvidence
from consultation_kb.retrieval.embeddings import Reranker
from consultation_kb.retrieval.fusion import (
    FusedCandidate,
    FusedPassage,
    FusionAuthorityBinding,
)


@dataclass(frozen=True, slots=True)
class RerankedPassage:
    """Stable P0-ready identity paired with one resolved Passage body."""

    evidence_id: str
    fused: FusedPassage
    resolved: ResolvedEvidence


@dataclass(frozen=True, slots=True)
class RerankedCandidate:
    fused: FusedCandidate
    resolved: tuple[ResolvedEvidence, ...]
    passages: tuple[RerankedPassage, ...]
    model_score: float | None


@dataclass(frozen=True, slots=True)
class RerankRunManifest:
    status: str
    degraded_components: tuple[str, ...]
    error_code: str | None
    descriptor_id: str
    descriptor_revision: str
    input_candidate_count: int
    resolved_passage_count: int
    output_candidate_count: int


@dataclass(frozen=True, slots=True)
class RerankRun:
    candidates: tuple[RerankedCandidate, ...]
    manifest: RerankRunManifest


class RerankBoundaryError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _candidate_key(
    candidate: CandidateRef,
) -> tuple[tuple[str, int, str], tuple[str, int, str], str]:
    reference = candidate.reference
    content = candidate.content_ref
    return (
        (reference.object_id, reference.version, reference.content_sha256),
        (content.object_id, content.version, content.content_sha256),
        candidate.channel,
    )


class EvidenceReranker:
    """Never receives a body that lacks the filter decision capability."""

    def __init__(self, model: Reranker) -> None:
        self._model = model

    def rerank(
        self,
        query: str,
        fused: tuple[FusedCandidate, ...],
        resolved: tuple[ResolvedEvidence, ...],
    ) -> RerankRun:
        if type(query) is not str or not query:
            raise ValueError("rerank query must be nonempty")
        descriptor = self._model.descriptor
        bindings = {item.authority_binding for item in fused}
        if len(bindings) > 1:
            raise RerankBoundaryError("RERANK_AUTHORITY_BINDING_MISMATCH")
        expected_binding = next(iter(bindings), None)
        resolved_by_key = {
            _candidate_key(value.candidate): value
            for value in resolved
            if (
                value.candidate.filter_binding is not None
                and (
                    expected_binding is None
                    or FusionAuthorityBinding.from_candidate(value.candidate)
                    == expected_binding
                )
            )
        }
        degraded: set[str] = set()
        eligible: list[
            tuple[FusedCandidate, tuple[RerankedPassage, ...]]
        ] = []
        flat_bodies: list[str] = []
        group_indices: list[tuple[int, ...]] = []
        for item in fused:
            passage_members: list[RerankedPassage] = []
            passage_indices: list[int] = []
            for passage in item.passages:
                candidate = passage.candidate
                value = resolved_by_key.get(_candidate_key(candidate))
                if value is None or value.candidate != candidate:
                    degraded.add("unresolved_evidence")
                    continue
                try:
                    body = value.body.decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    degraded.add("unresolved_evidence")
                    continue
                passage_indices.append(len(flat_bodies))
                flat_bodies.append(body)
                passage_members.append(
                    RerankedPassage(
                        evidence_id=passage.evidence_id,
                        fused=passage,
                        resolved=value,
                    )
                )
            if passage_members:
                eligible.append((item, tuple(passage_members)))
                group_indices.append(tuple(passage_indices))
            else:
                degraded.add("unresolved_evidence")

        model_scores: NDArray[np.float32] | None = None
        error_code: str | None = None
        if flat_bodies:
            try:
                raw_scores = self._model.score(query, tuple(flat_bodies))
                if (
                    not isinstance(raw_scores, np.ndarray)
                    or raw_scores.dtype != np.float32
                    or raw_scores.shape != (len(flat_bodies),)
                    or not np.isfinite(raw_scores).all()
                ):
                    raise ValueError("reranker returned an invalid score vector")
                model_scores = raw_scores
            except Exception:
                degraded.add("reranker")
                error_code = "RERANKER_MODEL_FAILURE"
        else:
            error_code = "RERANK_INPUT_EMPTY"

        candidates: list[RerankedCandidate] = []
        for (item, member_group), index_group in zip(
            eligible, group_indices, strict=True
        ):
            score = (
                None
                if model_scores is None
                else float(
                    max(model_scores[index] for index in index_group)
                )
            )
            candidates.append(
                RerankedCandidate(
                    fused=item,
                    resolved=tuple(
                        passage.resolved for passage in member_group
                    ),
                    passages=member_group,
                    model_score=score,
                )
            )
        if model_scores is not None:
            candidates.sort(
                key=lambda item: (
                    -int(item.fused.primary_framework),
                    -float(item.model_score if item.model_score is not None else -np.inf),
                    -item.fused.rrf_score,
                    item.fused.evidence_id,
                )
            )
        # With a model failure, ``eligible`` was built in fused/RRF order and
        # is intentionally not re-sorted.
        component_order = ("unresolved_evidence", "reranker")
        degraded_components = tuple(
            value for value in component_order if value in degraded
        )
        manifest = RerankRunManifest(
            status="degraded" if degraded_components else "applied",
            degraded_components=degraded_components,
            error_code=error_code,
            descriptor_id=descriptor.id,
            descriptor_revision=descriptor.revision,
            input_candidate_count=len(fused),
            resolved_passage_count=len(flat_bodies),
            output_candidate_count=len(candidates),
        )
        return RerankRun(tuple(candidates), manifest)


__all__ = [
    "EvidenceReranker",
    "RerankRun",
    "RerankBoundaryError",
    "RerankRunManifest",
    "RerankedCandidate",
    "RerankedPassage",
]
