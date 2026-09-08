from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import numpy as np

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.anchors import deterministic_object_id
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    C1ApplicabilityDecision,
    EvidenceFreshnessSnapshot,
    EvidenceLocator,
    Provenance,
    RetrievalScope,
)
from consultation_kb.retrieval.budget import ContextBudget
from consultation_kb.retrieval.contracts import CandidateMetadata, CandidateRef
from consultation_kb.retrieval.coordinator import (
    CandidateSemantics,
    RetrievalCoordinator,
    RetrievalRequest,
)
from consultation_kb.retrieval.embeddings import ModelDescriptor, ModelFileHash
from consultation_kb.retrieval.evidence_pack import (
    C1PolicyVocabulary,
    EvidencePackBuilder,
    RootManifestSet,
)
from consultation_kb.retrieval.filters import CandidateFilter, StaticAuthorityGuard
from consultation_kb.retrieval.fusion import ReciprocalRankFusion
from consultation_kb.retrieval.rerank import EvidenceReranker
from consultation_kb.retrieval.resolver import EvidenceResolver


NOW = datetime(2026, 7, 18, 8, 0, tzinfo=timezone.utc)
CLIENT_A = "client_" + "a" * 12
CLIENT_B = "client_" + "b" * 12


def _id(kind: str, index: int) -> str:
    return IdFactory(FixedClock(NOW), lambda: index).object_id(kind)


def _uuid(index: int) -> str:
    return IdFactory(FixedClock(NOW), lambda: index).uuid7()


def _ref(kind: str, index: int, *, version: int = 1, data: bytes | None = None) -> VersionRef:
    payload = data if data is not None else f"{kind}:{index}".encode()
    return VersionRef(
        object_id=_id(kind, index),
        version=version,
        content_sha256=hashlib.sha256(payload).hexdigest(),
    )


class StaticSnapshotRepository:
    def __init__(self, snapshot: AuthoritativeFilterSnapshot) -> None:
        self.snapshot = snapshot
        self.assertions = 0

    def freeze(self, scope: RetrievalScope) -> AuthoritativeFilterSnapshot:
        assert scope.current_client_id == CLIENT_A
        return self.snapshot

    def assert_snapshot_current(self, snapshot: AuthoritativeFilterSnapshot) -> None:
        assert snapshot == self.snapshot
        self.assertions += 1


class StaticRetriever:
    def __init__(self, candidates: tuple[CandidateRef, ...]) -> None:
        self.candidates = candidates
        self.snapshots: list[AuthoritativeFilterSnapshot] = []

    def search(self, query, scope, authority_snapshot, *, limit):  # type: ignore[no-untyped-def]
        assert query == "我该怎样理解目前的关系困境？"
        assert scope.current_client_id == CLIENT_A
        self.snapshots.append(authority_snapshot)
        return self.candidates[:limit]


class TrackingReader:
    def __init__(self, bodies: dict[str, bytes]) -> None:
        self.bodies = bodies
        self.requested: list[str] = []

    def read_verified(self, candidate: CandidateRef) -> bytes:
        self.requested.append(candidate.reference.object_id)
        return self.bodies[candidate.content_ref.content_sha256]


class Semantics:
    def __init__(self, c1_revision: VersionRef, contradiction_id: str) -> None:
        self.c1_revision = c1_revision
        self.contradiction_id = contradiction_id

    def resolve(self, candidate: CandidateRef) -> CandidateSemantics:
        if candidate.metadata.source_grade == "C1":
            return CandidateSemantics(stance="support", theory_ref=self.c1_revision)
        if candidate.reference.object_id == self.contradiction_id:
            return CandidateSemantics(stance="contradiction")
        return CandidateSemantics(stance="support")


class FakeReranker:
    def __init__(self) -> None:
        self._descriptor = ModelDescriptor(
            repo="local/retrieval-slice",
            revision="1" * 40,
            model_files=(
                ModelFileHash(relative_path="model.bin", sha256="2" * 64),
            ),
            adapter_class="tests.FakeReranker",
            adapter_version="1",
            sentence_transformers_version="test",
            transformers_version="test",
            tokenizer_version="test",
            tokenizer_sha256="3" * 64,
            query_prompt="",
            document_prompt="",
            pooling="model_defined",
            normalize_embeddings=False,
            max_sequence_length=512,
            truncation="longest_first",
            dimension=1,
            score_function="dot",
        )
        self.passages: tuple[str, ...] = ()

    @property
    def descriptor(self) -> ModelDescriptor:
        return self._descriptor

    def score(self, query, passages):  # type: ignore[no-untyped-def]
        del query
        self.passages = tuple(passages)
        return np.asarray(
            [float(index + 1) for index, _ in enumerate(passages)],
            dtype=np.float32,
        )


class Publisher:
    def publish(self, object_type: str, payload: bytes) -> VersionRef:
        digest = hashlib.sha256(payload).hexdigest()
        return VersionRef(
            object_id=deterministic_object_id(object_type, digest),
            version=1,
            content_sha256=digest,
        )


class ClosureVerifier:
    def __init__(self) -> None:
        self.roles: set[str] = set()

    def verify(self, requirements, *, vocabulary):  # type: ignore[no-untyped-def]
        assert vocabulary.approved_rule_ids == frozenset({"relationship_context"})
        self.roles = {item.role for item in requirements}


class VersionGate:
    def __init__(self) -> None:
        self.calls = 0

    def verify(self, snapshot, roots):  # type: ignore[no-untyped-def]
        assert snapshot.global_runtime_epoch == 3
        assert roots.catalog_version == 3
        self.calls += 1


class StaticArtifactGate:
    def __init__(self) -> None:
        self.calls = 0

    def verify(self, snapshot, roots, retrievers, routes):  # type: ignore[no-untyped-def]
        assert snapshot.global_runtime_epoch == roots.catalog_version
        assert set(routes) <= set(retrievers)
        self.calls += 1


class CharacterCounter:
    def count(self, payload: bytes) -> int:
        return max(1, len(payload.decode("utf-8")))


def _locator(index: int) -> EvidenceLocator:
    return EvidenceLocator(
        locator_kind="source_line_span",
        anchor_refs=(_ref("source_anchor", index),),
        display_locator=f"lines:{index}-{index}",
        locator_policy_ref=_ref("locator_policy", 700),
    )


def _candidate(
    *,
    index: int,
    body: str,
    channel: str,
    manifest_ref: VersionRef,
    source_grade: str,
    provenance: Provenance,
    framework_priority: str = "normal",
) -> tuple[CandidateRef, bytes]:
    encoded = body.encode("utf-8")
    return (
        CandidateRef(
            reference=_ref("claim", index),
            content_ref=_ref("passage", index + 100, data=encoded),
            object_type="claim",
            channel=channel,
            metadata=CandidateMetadata(
                manifest_ref=manifest_ref,
                review_status="approved",
                allowed_uses=frozenset({"consultation_answer"}),
                approved_at=NOW,
                review_due_at=NOW + timedelta(days=30),
                sensitivity=1,
                source_grade=source_grade,
                framework_priority=framework_priority,
                empirical_support=(
                    "case_supported" if source_grade == "C1" else "empirically_supported"
                ),
                source_count=max(1, len(provenance.source_ids)),
                media_type="text/plain",
                size_bytes=len(encoded),
            ),
            provenance=provenance,
            location=_locator(index),
            freshness=EvidenceFreshnessSnapshot(
                status="current",
                evaluated_at=NOW,
                source_observed_at=NOW - timedelta(days=1),
                last_reviewed_at=NOW,
                review_due_at=NOW + timedelta(days=30),
                policy_ref=_ref("freshness_policy", 701),
            ),
            score=1.0,
        ),
        encoded,
    )


def _global_provenance(index: int, passage_id: str) -> Provenance:
    return Provenance(
        source_ids=frozenset({_id("source", index)}),
        passage_ids=frozenset({passage_id}),
        provenance_scope="global_source",
        derivation_rule_ref=_ref("derivation_rule", 710),
    )


def test_retrieval_slice_preserves_exact_quote_c1_counterevidence_and_private_history() -> None:
    wiki_root = _ref("manifest", 10, version=3)
    lexical_root = _ref("manifest", 11, version=3)
    vector_root = _ref("manifest", 12, version=3)
    graph_root = _ref("manifest", 13, version=3)
    roots = RootManifestSet(
        catalog_version=3,
        wiki_manifest_ref=wiki_root,
        lexical_manifest_ref=lexical_root,
        vector_manifest_ref=vector_root,
        graph_manifest_ref=graph_root,
    )
    c1_revision = _ref("theory_revision", 20)

    lexical_passage = _ref("passage", 131, data="道可道，非常道。".encode())
    exact, exact_body = _candidate(
        index=31,
        body="道可道，非常道。",
        channel="lexical",
        manifest_ref=lexical_root,
        source_grade="T1",
        provenance=_global_provenance(31, lexical_passage.object_id),
    )
    c1_passage = _ref("passage", 132, data="先澄清事实，再解释关系模式。".encode())
    c1, c1_body = _candidate(
        index=32,
        body="先澄清事实，再解释关系模式。",
        channel="wiki",
        manifest_ref=wiki_root,
        source_grade="C1",
        framework_priority="highest",
        provenance=_global_provenance(32, c1_passage.object_id),
    )
    contradiction_passage = _ref(
        "passage", 133, data="单一理论不足以解释全部关系变化。".encode()
    )
    contradiction, contradiction_body = _candidate(
        index=33,
        body="单一理论不足以解释全部关系变化。",
        channel="vector",
        manifest_ref=vector_root,
        source_grade="C2",
        provenance=_global_provenance(33, contradiction_passage.object_id),
    )
    private_passage = _ref("passage", 134, data="本次咨询延续上次未完成目标。".encode())
    private_provenance = Provenance(
        passage_ids=frozenset({private_passage.object_id}),
        client_ids=frozenset({CLIENT_A}),
        provenance_scope="client_private",
        private_owner_client_id=CLIENT_A,
        derivation_rule_ref=_ref("derivation_rule", 710),
    )
    private, private_body = _candidate(
        index=34,
        body="本次咨询延续上次未完成目标。",
        channel="client_history",
        manifest_ref=_ref("manifest", 14, version=3),
        source_grade="K1",
        provenance=private_provenance,
    )
    self_case_passage = _ref("passage", 135, data="不应读取的本人案例正文".encode())
    self_case_provenance = Provenance(
        passage_ids=frozenset({self_case_passage.object_id}),
        case_ids=frozenset({_id("case", 35)}),
        client_ids=frozenset({CLIENT_A}),
        provenance_scope="case_derived",
        case_contributor_client_ids=frozenset({CLIENT_A}),
        derivation_rule_ref=_ref("derivation_rule", 710),
    )
    self_case, self_case_body = _candidate(
        index=35,
        body="不应读取的本人案例正文",
        channel="case",
        manifest_ref=_ref("manifest", 15, version=3),
        source_grade="K2",
        provenance=self_case_provenance,
    )
    candidates = (exact, c1, contradiction, private, self_case)
    snapshot = AuthoritativeFilterSnapshot(
        run_id=_uuid(800),
        global_runtime_epoch=3,
        client_runtime_epoch=3,
        tombstone_epoch=0,
        authorization_epoch=1,
        allowed_ref_ids=frozenset(item.reference.object_id for item in candidates),
        policy_ref=_ref("authority_policy", 801),
        created_at=NOW,
    )
    repository = StaticSnapshotRepository(snapshot)
    guard = StaticAuthorityGuard(snapshot)
    reader = TrackingReader(
        {
            exact.content_ref.content_sha256: exact_body,
            c1.content_ref.content_sha256: c1_body,
            contradiction.content_ref.content_sha256: contradiction_body,
            private.content_ref.content_sha256: private_body,
            self_case.content_ref.content_sha256: self_case_body,
        }
    )
    model = FakeReranker()
    closure = ClosureVerifier()
    version_gate = VersionGate()
    artifact_gate = StaticArtifactGate()
    coordinator = RetrievalCoordinator(
        snapshot_repository=repository,
        artifact_gate=artifact_gate,
        retrievers={
            "lexical": StaticRetriever((exact,)),
            "wiki": StaticRetriever((c1,)),
            "vector": StaticRetriever((contradiction,)),
            "client_history": StaticRetriever((private,)),
            "case": StaticRetriever((self_case,)),
        },
        candidate_filter=CandidateFilter(guard),
        resolver=EvidenceResolver(guard, reader),
        semantics_resolver=Semantics(c1_revision, contradiction.reference.object_id),
        fusion=ReciprocalRankFusion(),
        reranker=EvidenceReranker(model),
        context_budget=ContextBudget(
            max_tokens=1000,
            minimum_supporting=1,
            minimum_contradictions=1,
            minimum_exact_quotes=1,
        ),
        token_counter=CharacterCounter(),
        object_publisher=Publisher(),
        pack_builder=EvidencePackBuilder(
            closure_verifier=closure,
            version_gate=version_gate,
        ),
    )
    c1_decision = C1ApplicabilityDecision(
        status="applicable",
        revision=c1_revision,
        scope_policy_ref=_ref("scope_policy", 802),
        matched_rule_ids=("relationship_context",),
        missing_context_fields=(),
        effective_status="active",
        empirical_support="case_supported",
        conflict_evidence_ids=(),
    )
    descriptor_ref = VersionRef(
        object_id=_id("reranker_descriptor", 803),
        version=1,
        content_sha256=model.descriptor.id,
    )
    result = coordinator.retrieve(
        RetrievalRequest(
            query="我该怎样理解目前的关系困境？",
            scope=RetrievalScope(
                current_client_id=CLIENT_A,
                allowed_uses=frozenset({"consultation_answer"}),
                maximum_sensitivity=2,
                effective_at=NOW,
                known_at=NOW,
            ),
            routes=("lexical", "wiki", "vector", "client_history", "case"),
            required_routes=frozenset({"lexical", "wiki", "vector", "client_history"}),
            per_route_limit=5,
            fusion_limit=10,
            minimum_contradictions=1,
            client_snapshot_ref=_ref("client_snapshot", 804),
            temporary_fact_refs=(),
            unresolved_conflict_refs=(),
            mandatory_conflict_claim_refs=(contradiction.reference,),
            c1_applicability=c1_decision,
            c1_policy_vocabulary=C1PolicyVocabulary(
                scope_policy_ref=c1_decision.scope_policy_ref,
                approved_rule_ids=frozenset({"relationship_context"}),
                approved_context_fields=frozenset({"relationship_stage"}),
            ),
            roots=roots,
            reranker_descriptor_ref=descriptor_ref,
        )
    )

    pack = result.evidence_pack.pack
    all_candidates = pack.supporting + pack.contradicting
    assert {item.channel for item in all_candidates} == {
        "lexical",
        "wiki",
        "vector",
        "client_history",
    }
    assert len(pack.contradicting) == 1
    assert pack.c1_applicability.conflict_evidence_ids == (
        pack.contradicting[0].evidence_id,
    )
    assert any(
        item.source_grade == "C1" and item.framework_priority == "highest"
        for item in pack.supporting
    )
    assert pack.c1_applicability.revision == c1_revision
    assert self_case.reference.object_id not in reader.requested
    assert "不应读取的本人案例正文" not in model.passages
    assert set(reader.requested) == {
        exact.reference.object_id,
        c1.reference.object_id,
        contradiction.reference.object_id,
        private.reference.object_id,
    }
    safe_json = pack.model_dump_json()
    assert CLIENT_A not in safe_json and CLIENT_B not in safe_json
    assert "allowed_ref_ids" not in safe_json
    assert exact_body.decode() not in safe_json
    assert version_gate.calls == 2
    assert artifact_gate.calls >= len(result.route_candidate_counts) + 3
    assert repository.assertions == 2
    assert {"candidate_text", "candidate_provenance", "exclusion_proof"} <= closure.roles
