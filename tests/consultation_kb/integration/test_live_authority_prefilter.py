from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Sequence
from pathlib import Path

import numpy as np
from numpy.typing import NDArray

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import AuthoritativeFilterSnapshot
from consultation_kb.retrieval.authority_snapshot import AuthoritativeSnapshotRepository
from consultation_kb.retrieval.client_history import (
    ClientHistoryQuery,
    ClientHistoryResult,
    ClientHistoryRetriever,
    ScopedClientHistoryService,
    client_history_derivation_rule_ref,
)
from consultation_kb.retrieval.contracts import CandidateRef
from consultation_kb.retrieval.embeddings import (
    DeterministicFakeEmbedder,
    ModelDescriptor,
)
from consultation_kb.retrieval.filters import CandidateFilter
from consultation_kb.retrieval.fusion import FusionEvidence, ReciprocalRankFusion
from consultation_kb.retrieval.lexical import LexicalRetriever
from consultation_kb.retrieval.lexical_builder import LexicalDocument, LexicalIndexBuilder
from consultation_kb.retrieval.rerank import EvidenceReranker
from consultation_kb.retrieval.resolver import EvidenceResolver
from consultation_kb.retrieval.vector import ExactVectorRetriever
from consultation_kb.retrieval.vector_builder import (
    ExactVectorIndexBuilder,
    VectorDocument,
)
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.tombstones import target_hash
from tests.consultation_kb.retrieval_db_support import (
    activate_epoch,
    add_approved_global_claim_passage,
    add_active_candidate,
    add_manifest_candidate,
    migrate_database,
)
from tests.consultation_kb.retrieval_support import (
    CLIENT_A,
    NOW,
    candidate,
    derived_builder_input,
    global_provenance,
    model_descriptor,
    private_provenance,
    reference,
    scope,
)


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _global_claim_candidate(
    index: int,
    *,
    text: str,
    channel: str,
    manifest_ref: VersionRef,
) -> CandidateRef:
    body = text.encode("utf-8")
    value = candidate(
        index,
        text=text,
        provenance=global_provenance(index),
        channel=channel,
        object_type="claim",
    )
    passage_ref = VersionRef(
        object_id=reference("passage", index).object_id,
        version=1,
        content_sha256=hashlib.sha256(body).hexdigest(),
    )
    return value.model_copy(
        update={
            "content_ref": passage_ref,
            "metadata": value.metadata.model_copy(
                update={
                    "manifest_ref": manifest_ref,
                    "media_type": "text/plain",
                    "size_bytes": len(body),
                }
            ),
            "location": value.location.model_copy(
                update={"anchor_refs": (passage_ref,)}
            ),
        }
    )


def _seed_global_authority(
    root: Path,
    candidates: tuple[CandidateRef, ...],
) -> tuple[Path, Path]:
    global_path = root / "global.sqlite3"
    client_path = root / "client.sqlite3"
    migrate_database(global_path, "global")
    migrate_database(client_path, "client")
    connection = sqlite3.connect(global_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        manifests = {value.metadata.manifest_ref for value in candidates}
        if len(manifests) != 1:
            raise AssertionError("global Claim candidates must share one claims root")
        operation = activate_epoch(
            connection,
            epoch=1,
            index=8100,
            required_manifest_count=1,
        )
        for value in candidates:
            add_approved_global_claim_passage(connection, candidate=value)
        add_active_candidate(
            connection,
            epoch=1,
            operation_id=operation,
            artifact_key="claims",
            artifact_kind="claims",
            candidate=candidates[0],
        )
        for ordinal, value in enumerate(candidates[1:], start=1):
            add_manifest_candidate(
                connection,
                manifest_id=candidates[0].metadata.manifest_ref.object_id,
                candidate=value,
                ordinal=ordinal,
            )
        connection.commit()
    finally:
        connection.close()
    return global_path, client_path


def _seed_client_authority(
    root: Path,
    artifacts: tuple[tuple[str, str, CandidateRef], ...],
) -> tuple[Path, Path]:
    global_path = root / "global.sqlite3"
    client_path = root / "client.sqlite3"
    migrate_database(global_path, "global")
    migrate_database(client_path, "client")
    connection = sqlite3.connect(client_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        operation = activate_epoch(
            connection,
            epoch=1,
            index=8200,
            required_manifest_count=len(artifacts),
        )
        for artifact_key, artifact_kind, value in artifacts:
            add_active_candidate(
                connection,
                epoch=1,
                operation_id=operation,
                artifact_key=artifact_key,
                artifact_kind=artifact_kind,
                candidate=value,
            )
        connection.commit()
    finally:
        connection.close()
    return global_path, client_path


def _authority(
    global_path: Path,
    client_path: Path,
    *,
    random_bits: int,
) -> AuthoritativeSnapshotRepository:
    return AuthoritativeSnapshotRepository.open(
        global_path,
        client_path,
        policy_ref_provider=lambda: reference("authority_policy", 8800),
        clock=FixedClock(NOW),
        id_factory=IdFactory(FixedClock(NOW), lambda: random_bits),
    )


def _insert_tombstone(
    database: Path,
    value: CandidateRef,
    *,
    index: int,
    lineage_sha256: str | None = None,
    global_scope: bool,
) -> None:
    connection = sqlite3.connect(database)
    try:
        target_type = value.object_type if lineage_sha256 is None else "source"
        target_id = (
            value.reference.object_id
            if lineage_sha256 is None
            else reference("source", index + 100).object_id
        )
        connection.execute(
            "INSERT INTO tombstones("
            "tombstone_id, target_type, target_id_hash, source_lineage_hash, "
            "reason_code, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?)",
            (
                reference("tombstone", index).object_id,
                target_type,
                target_hash(target_type, target_id),
                "" if lineage_sha256 is None else lineage_sha256,
                "live_prefilter_test",
                NOW.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            ),
        )
        if global_scope:
            connection.execute(
                "UPDATE knowledge_catalog_state "
                "SET tombstone_epoch = tombstone_epoch + 1 WHERE singleton = 1"
            )
        connection.commit()
    finally:
        connection.close()


class _TrackingReader:
    def __init__(self, bodies: dict[str, bytes]) -> None:
        self._bodies = bodies
        self.requested: list[str] = []

    def read_verified(self, value: CandidateRef) -> bytes:
        identifier = value.reference.object_id
        self.requested.append(identifier)
        return self._bodies[identifier]


class _TrackingReranker:
    def __init__(self) -> None:
        self._descriptor = model_descriptor(
            adapter_class="LivePrefilterTrackingReranker",
            query_prompt="",
            document_prompt="",
        )
        self.passages: list[str] = []

    @property
    def descriptor(self) -> ModelDescriptor:
        return self._descriptor

    def score(
        self,
        query: str,
        passages: Sequence[str],
    ) -> NDArray[np.float32]:
        del query
        self.passages.extend(passages)
        return np.ones(len(passages), dtype=np.float32)


def _assert_denied_never_reaches_body_or_reranker(
    repository: AuthoritativeSnapshotRepository,
    authority_snapshot: AuthoritativeFilterSnapshot,
    *,
    denied: CandidateRef,
    legal: CandidateRef,
    legal_body: bytes,
) -> None:
    decision = CandidateFilter(repository).filter(
        scope(),
        (denied, legal),
        authority_snapshot,
    )
    assert decision.proof.reasons == {"tombstoned": 1}
    assert tuple(item.reference for item in decision.allowed) == (legal.reference,)
    reader = _TrackingReader({legal.reference.object_id: legal_body})
    resolved = EvidenceResolver(repository, reader).resolve_many(decision.allowed)
    fused = ReciprocalRankFusion().fuse(
        {
            decision.allowed[0].channel: (
                FusionEvidence(candidate=decision.allowed[0], stance="support"),
            )
        }
    )
    reranker = _TrackingReranker()
    run = EvidenceReranker(reranker).rerank("query", fused, resolved)

    assert run.manifest.status == "applied"
    assert reader.requested == [legal.reference.object_id]
    assert reranker.passages == [legal_body.decode("utf-8")]
    assert denied.reference.object_id not in reader.requested


def test_lexical_source_lineage_tombstone_prefilters_before_bm25_and_limit(
    tmp_path: Path,
) -> None:
    high_text = "仁义 仁义 仁义 仁义"
    low_text = "仁义"
    manifest_ref = reference("artifact_manifest", 8_401)
    high = _global_claim_candidate(
        101,
        text=high_text,
        channel="lexical",
        manifest_ref=manifest_ref,
    )
    high = high.model_copy(
        update={
            "metadata": high.metadata.model_copy(
                update={"source_lineage_hashes": ("e" * 64,)}
            )
        }
    )
    low = _global_claim_candidate(
        102,
        text=low_text,
        channel="lexical",
        manifest_ref=manifest_ref,
    )
    index = tmp_path / "lexical.sqlite3"
    LexicalIndexBuilder().build(
        (
            LexicalDocument(candidate=high, text=high_text),
            LexicalDocument(candidate=low, text=low_text),
        ),
        index,
        builder_input=derived_builder_input(
            "lexical",
            high,
            low,
            source_catalog_version=1,
        ),
    )
    immutable_sha256 = _file_sha256(index)
    global_path, client_path = _seed_global_authority(tmp_path, (high, low))

    with _authority(global_path, client_path, random_bits=9101) as repository:
        before = repository.freeze(scope())
        retriever = LexicalRetriever._from_unbound_path_for_test(index)
        before_result = retriever.search("仁义", scope(), before, limit=2)
        high_result = next(
            item for item in before_result if item.reference == high.reference
        )
        assert len(
            CandidateFilter(repository).filter(
                scope(), (high_result,), before
            ).allowed
        ) == 1

        _insert_tombstone(
            global_path,
            high,
            index=9102,
            lineage_sha256="e" * 64,
            global_scope=True,
        )
        after = repository.freeze(scope())
        after_result = retriever.search("仁义", scope(), after, limit=1)

        assert tuple(item.reference for item in after_result) == (low.reference,)
        assert high.reference.object_id not in after.allowed_ref_ids
        assert _file_sha256(index) == immutable_sha256
        _assert_denied_never_reaches_body_or_reranker(
            repository,
            after,
            denied=high,
            legal=after_result[0],
            legal_body=low_text.encode("utf-8"),
        )


class _CountingEmbedder(DeterministicFakeEmbedder):
    def __init__(self) -> None:
        super().__init__(
            model_descriptor(query_prompt="", document_prompt=""),
            {
                "query": np.asarray([1.0, 0.0], dtype=np.float32),
                "high": np.asarray([1.0, 0.0], dtype=np.float32),
                "low": np.asarray([0.6, 0.8], dtype=np.float32),
            },
        )
        self.query_calls = 0

    def encode_query(self, text: str) -> NDArray[np.float32]:
        self.query_calls += 1
        return super().encode_query(text)


class _ObservedMatrix(np.ndarray):
    requested_rows: list[tuple[int, ...]]

    def __new__(
        cls,
        value: NDArray[np.float32],
        requested_rows: list[tuple[int, ...]],
    ) -> "_ObservedMatrix":
        instance = np.asarray(value, dtype=np.float32).view(cls)
        instance.requested_rows = requested_rows
        return instance

    def __array_finalize__(self, parent: object) -> None:
        self.requested_rows = getattr(parent, "requested_rows", [])

    def __getitem__(self, key: object) -> object:
        if isinstance(key, np.ndarray) and key.ndim == 1:
            self.requested_rows.append(tuple(int(value) for value in key.tolist()))
        return super().__getitem__(key)


def test_vector_direct_tombstone_prefilters_before_encode_mmap_slice_and_topk(
    tmp_path: Path,
) -> None:
    model = _CountingEmbedder()
    manifest_ref = reference("artifact_manifest", 8_402)
    high = _global_claim_candidate(
        201,
        text="high",
        channel="vector",
        manifest_ref=manifest_ref,
    )
    low = _global_claim_candidate(
        202,
        text="low",
        channel="vector",
        manifest_ref=manifest_ref,
    )
    index = tmp_path / "vector-index"
    ExactVectorIndexBuilder(model).build(
        (
            VectorDocument(candidate=high, text="high"),
            VectorDocument(candidate=low, text="low"),
        ),
        index,
        builder_input=derived_builder_input(
            "vector",
            high,
            low,
            source_catalog_version=1,
        ),
    )
    immutable_hashes = tuple(
        _file_sha256(index / name)
        for name in ("vectors.npy", "vector-meta.sqlite3", "vector-manifest.json")
    )
    global_path, client_path = _seed_global_authority(tmp_path, (high, low))

    with _authority(global_path, client_path, random_bits=9201) as repository:
        before = repository.freeze(scope())
        before_result = ExactVectorRetriever._from_unbound_directory_for_test(
            index, embedder=model
        ).search(
            "query", scope(), before, limit=1
        )
        assert tuple(item.reference for item in before_result) == (high.reference,)
        _insert_tombstone(
            global_path,
            high,
            index=9202,
            global_scope=True,
        )
        after = repository.freeze(scope())
        row_connection = sqlite3.connect(index / "vector-meta.sqlite3")
        try:
            row_by_id = {
                str(row[0]): int(row[1])
                for row in row_connection.execute(
                    "SELECT evidence_id, row_index FROM vector_rows"
                )
            }
        finally:
            row_connection.close()
        requested_rows: list[tuple[int, ...]] = []
        loader_calls: list[Path] = []

        def load(path: Path) -> NDArray[np.float32]:
            loader_calls.append(path)
            matrix = np.load(path, mmap_mode="r", allow_pickle=False)
            return _ObservedMatrix(matrix, requested_rows)

        model.query_calls = 0
        after_result = ExactVectorRetriever._from_unbound_directory_for_test(
            index,
            embedder=model,
            matrix_loader=load,
        ).search("query", scope(), after, limit=1)

        assert tuple(item.reference for item in after_result) == (low.reference,)
        assert model.query_calls == 1
        assert loader_calls == [index / "vectors.npy"]
        assert requested_rows == [(row_by_id[low.reference.object_id],)]
        assert row_by_id[high.reference.object_id] not in requested_rows[0]
        assert tuple(
            _file_sha256(index / name)
            for name in (
                "vectors.npy",
                "vector-meta.sqlite3",
                "vector-manifest.json",
            )
        ) == immutable_hashes
        _assert_denied_never_reaches_body_or_reranker(
            repository,
            after,
            denied=high,
            legal=after_result[0],
            legal_body=b"low",
        )


class _ServiceTransport:
    def __init__(self, service: ScopedClientHistoryService) -> None:
        self._service = service

    def query_client_history(
        self,
        request: ClientHistoryQuery,
    ) -> ClientHistoryResult:
        return self._service.query(request)


class _RequestIds:
    def __init__(self) -> None:
        self._values = iter((9301, 9302))

    def uuid7(self) -> str:
        return IdFactory(FixedClock(NOW), lambda: next(self._values)).uuid7()


def test_client_history_direct_tombstone_prefilters_before_final_limit(
    tmp_path: Path,
) -> None:
    allowed_uses = frozenset(
        {"answer_support", "consultation", "continuity", "next_session_context"}
    )
    fact = candidate(
        301,
        text="high private fact",
        provenance=private_provenance(301, CLIENT_A),
        channel="client_history",
        object_type="fact_snapshot",
        allowed_uses=allowed_uses,
    )
    graph = candidate(
        302,
        text="legal temporal graph",
        provenance=private_provenance(302, CLIENT_A),
        channel="client_history",
        object_type="client_graph",
        allowed_uses=allowed_uses,
    )
    profile = candidate(
        303,
        text="legal profile",
        provenance=private_provenance(303, CLIENT_A),
        channel="profile",
        object_type="profile_json",
        allowed_uses=allowed_uses,
    )
    global_path, client_path = _seed_client_authority(
        tmp_path,
        (
            ("client_fact_snapshot", "fact_snapshot", fact),
            ("client_graph", "graph", graph),
            ("client_profile", "profile", profile),
        ),
    )
    service_connection = connect_database(client_path, "reader")
    try:
        retriever = ClientHistoryRetriever(
            _ServiceTransport(
                ScopedClientHistoryService(
                    service_connection,
                    current_client_id=CLIENT_A,
                    derivation_rule_ref=client_history_derivation_rule_ref(),
                )
            ),
            session_handle="opaque-session-handle",
            query_category="continuity",
            request_id_factory=_RequestIds(),
        )
        with _authority(global_path, client_path, random_bits=9300) as repository:
            before = repository.freeze(scope())
            before_result = retriever.search("", scope(), before, limit=1)
            assert tuple(item.reference for item in before_result) == (fact.reference,)
            denied = before_result[0]
            _insert_tombstone(
                client_path,
                denied,
                index=9302,
                global_scope=False,
            )
            after = repository.freeze(scope())
            after_result = retriever.search("", scope(), after, limit=1)

            assert tuple(item.reference for item in after_result) == (graph.reference,)
            assert denied.reference.object_id not in after.allowed_ref_ids
            _assert_denied_never_reaches_body_or_reranker(
                repository,
                after,
                denied=denied,
                legal=after_result[0],
                legal_body=b"legal temporal graph",
            )
    finally:
        service_connection.close()
