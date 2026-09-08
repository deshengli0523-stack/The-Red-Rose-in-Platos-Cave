"""Production adapters used by the generation retrieval composition.

The adapters are intentionally small: active artifact bindings remain the
authority, the existing P4 retrievers remain the search implementations, and
every reference accepted by the pack closure must occur in that verified
artifact closure or in one explicitly validated invocation dependency.
"""

from __future__ import annotations

import json
import math
import sqlite3
from collections.abc import Mapping, Sequence
from typing import cast

import numpy as np
from numpy.typing import NDArray

from consultation_kb.generation.retrieval_orchestrator import GenerationC1Context
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import AuthoritativeFilterSnapshot, RetrievalScope
from consultation_kb.retrieval.artifact_discovery import ActiveRetrievalArtifactSet
from consultation_kb.retrieval.contracts import CandidateRef, Retriever
from consultation_kb.retrieval.coordinator import CandidateSemantics
from consultation_kb.retrieval.embeddings import Embedder, ModelDescriptor
from consultation_kb.retrieval.evidence_pack import (
    C1PolicyVocabulary,
    ClosureRequirement,
    EvidenceClosureMismatch,
)
from consultation_kb.retrieval.global_graph import GraphNodeQuery


def _ref_key(reference: VersionRef) -> tuple[str, int, str]:
    return reference.object_id, reference.version, reference.content_sha256


def _embedded_refs(value: object) -> set[VersionRef]:
    found: set[VersionRef] = set()
    if isinstance(value, dict):
        if {"object_id", "version", "content_sha256"} <= set(value):
            try:
                found.add(VersionRef.model_validate(value, strict=True))
            except (TypeError, ValueError):
                pass
        for child in value.values():
            found.update(_embedded_refs(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_embedded_refs(child))
    return found


class ActiveArtifactGlobalClosureVerifier:
    """Resolve global pack refs only through one verified active closure."""

    def __init__(
        self,
        active: ActiveRetrievalArtifactSet,
        *,
        c1_context: GenerationC1Context,
        explicit_refs: tuple[VersionRef, ...],
    ) -> None:
        allowed: set[VersionRef] = set(explicit_refs)
        try:
            for binding in active.bindings():
                identity = binding.verify_current()
                allowed.add(identity.root_ref)
                for member in identity.members:
                    allowed.add(
                        VersionRef(
                            object_id=member.object_id,
                            version=identity.source_catalog_version,
                            content_sha256=member.content_sha256,
                        )
                    )
                    payload = binding.path_for(member.role).read_bytes()
                    try:
                        decoded = json.loads(payload)
                    except (UnicodeError, json.JSONDecodeError):
                        continue
                    allowed.update(_embedded_refs(decoded))
                binding.verify_current()
        except Exception:
            raise EvidenceClosureMismatch from None
        self._allowed = frozenset(allowed)
        self._vocabulary = c1_context.vocabulary

    def verify(
        self,
        requirements: tuple[ClosureRequirement, ...],
        *,
        vocabulary: C1PolicyVocabulary,
    ) -> None:
        if vocabulary != self._vocabulary:
            raise EvidenceClosureMismatch
        for requirement in requirements:
            if (
                requirement.scope != "global"
                or requirement.reference not in self._allowed
                or (
                    requirement.root_manifest_ref is not None
                    and requirement.root_manifest_ref not in self._allowed
                )
            ):
                raise EvidenceClosureMismatch


class EmbeddingEvidenceReranker:
    """Use the exact active vector model as a deterministic bi-encoder reranker."""

    def __init__(self, embedder: Embedder) -> None:
        if not callable(getattr(embedder, "encode_query", None)) or not callable(
            getattr(embedder, "encode_documents", None)
        ):
            raise TypeError("GENERATION_EMBEDDER_REQUIRED")
        self._embedder = embedder

    @property
    def descriptor(self) -> ModelDescriptor:
        return self._embedder.descriptor

    def score(
        self,
        query: str,
        passages: Sequence[str],
    ) -> NDArray[np.float32]:
        query_vector = self._embedder.encode_query(query)
        document_vectors = self._embedder.encode_documents(passages)
        descriptor = self.descriptor
        if (
            not isinstance(query_vector, np.ndarray)
            or query_vector.dtype != np.float32
            or query_vector.shape != (descriptor.dimension,)
            or not np.isfinite(query_vector).all()
            or not isinstance(document_vectors, np.ndarray)
            or document_vectors.dtype != np.float32
            or document_vectors.shape != (len(passages), descriptor.dimension)
            or not np.isfinite(document_vectors).all()
        ):
            raise ValueError("GENERATION_RERANK_VECTOR_INVALID")
        scores = document_vectors @ query_vector
        if scores.dtype != np.float32:
            scores = scores.astype(np.float32)
        if not np.isfinite(scores).all():
            raise ValueError("GENERATION_RERANK_SCORE_INVALID")
        return cast(NDArray[np.float32], scores)


class CharacterTokenCounter:
    """Conservative local counter used only for whole-passage budget selection."""

    def count(self, payload: bytes) -> int:
        text = payload.decode("utf-8", errors="strict")
        return max(1, math.ceil(len(text) / 2))


class ActiveC1CandidateSemantics:
    """Resolve C1 Claim -> theory revision from the governed global catalog."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        c1_context: GenerationC1Context,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("GENERATION_GLOBAL_CONNECTION_REQUIRED")
        self._connection = connection
        self._c1 = c1_context

    def resolve(self, candidate: CandidateRef) -> CandidateSemantics:
        if candidate.metadata.source_grade != "C1":
            return CandidateSemantics(stance="support")
        row = self._connection.execute(
            "SELECT theory_revision_id, theory_revision, theory_revision_sha256 "
            "FROM claims WHERE claim_id = ? AND version = ? "
            "AND source_grade = 'C1' AND review_status = 'APPROVED'",
            (candidate.reference.object_id, candidate.reference.version),
        ).fetchone()
        if row is None:
            raise ValueError("GENERATION_C1_CLAIM_BINDING_MISSING")
        revision = VersionRef(
            object_id=str(row[0]),
            version=int(str(row[1])),
            content_sha256=str(row[2]),
        )
        if (
            self._c1.decision.revision is None
            or revision != self._c1.decision.revision
        ):
            raise ValueError("GENERATION_C1_REVISION_MISMATCH")
        return CandidateSemantics(stance="support", theory_ref=revision)


class QueryMatchedGraphNodeResolver:
    """Map each question to graph endpoints through real wiki/lexical search."""

    def __init__(
        self,
        *,
        retrievers: Mapping[str, Retriever],
        snapshot: AuthoritativeFilterSnapshot,
        graph: object,
    ) -> None:
        if set(retrievers) != {"wiki", "lexical"}:
            raise ValueError("GENERATION_GRAPH_SEED_ROUTES_INVALID")
        self._retrievers = dict(retrievers)
        self._snapshot = snapshot
        self._graph = graph

    def resolve(
        self,
        query: str,
        scope: RetrievalScope,
        *,
        limit: int,
    ) -> tuple[GraphNodeQuery, ...]:
        claim_scores: dict[tuple[str, int, str], float] = {}
        for route in ("wiki", "lexical"):
            candidates = self._retrievers[route].search(
                query,
                scope,
                self._snapshot,
                limit=max(20, limit * 5),
            )
            for candidate in candidates:
                key = _ref_key(candidate.reference)
                claim_scores[key] = max(claim_scores.get(key, 0.0), candidate.score)
        pairs: dict[tuple[str, str], float] = {}
        edges = getattr(self._graph, "edges", None)
        if not callable(edges):
            raise ValueError("GENERATION_GRAPH_ARTIFACT_INVALID")
        for source, target, attributes in edges(data=True):
            if not isinstance(attributes, dict):
                continue
            claim_ref = attributes.get("claim_ref")
            if not isinstance(claim_ref, VersionRef):
                continue
            score = claim_scores.get(_ref_key(claim_ref))
            if score is None or str(source) == str(target):
                continue
            pair_key = str(source), str(target)
            pairs[pair_key] = max(pairs.get(pair_key, 0.0), score)
        ordered = sorted(pairs.items(), key=lambda item: (-item[1], item[0]))[:limit]
        return tuple(
            GraphNodeQuery(
                source_node_id=source,
                target_node_id=target,
                score=score,
            )
            for (source, target), score in ordered
        )


__all__ = [
    "ActiveArtifactGlobalClosureVerifier",
    "ActiveC1CandidateSemantics",
    "CharacterTokenCounter",
    "EmbeddingEvidenceReranker",
    "QueryMatchedGraphNodeResolver",
]
