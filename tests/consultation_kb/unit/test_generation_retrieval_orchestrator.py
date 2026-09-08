from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

from consultation_kb.client.graph_serialization import canonical_graph_bytes
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.generation.c1_context import C1ApplicabilityInput
from consultation_kb.generation.contracts import (
    QueryGuardrails,
    QueryPlan,
    Subquery,
)
from consultation_kb.generation.retrieval_orchestrator import (
    GenerationC1Context,
    GenerationRetrievalDependencies,
    GenerationRetrievalOrchestrator,
    GenerationRetrievalOrchestratorError,
)
from consultation_kb.generation.evidence_registry import GenerationRiskContextBinding
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    C1ApplicabilityDecision,
    EvidenceChannel,
    EvidenceFreshnessSnapshot,
    EvidenceLocator,
    Provenance,
    RetrievalScope,
)
from consultation_kb.models.generation import GenerationStageEnvelope
from consultation_kb.retrieval.budget import ContextBudget
from consultation_kb.retrieval.contracts import (
    CandidateMetadata,
    CandidateRef,
    canonical_json_bytes,
)
from consultation_kb.retrieval.coordinator import CandidateSemantics
from consultation_kb.retrieval.embeddings import ModelDescriptor, ModelFileHash
from consultation_kb.retrieval.evidence_pack import (
    C1PolicyVocabulary,
    RootManifestSet,
)
from consultation_kb.retrieval.filters import (
    AuthoritySnapshotStale,
    CandidateAuthorityStatus,
)
from consultation_kb.retrieval.fusion import ReciprocalRankFusion
from consultation_kb.retrieval.rerank import EvidenceReranker
from consultation_kb.security.worker_protocol import (
    GenerationClientBinding,
    PrivateGenerationEvidence,
)
from tests.consultation_kb.risk_support import deterministic_risk_authority
from consultation_kb.vault.content_store import ContentStore


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
CLIENT = "client_" + "aaaaaaaaaaaa"
OTHER_CLIENT = "client_" + "bbbbbbbbbbbb"


def oid(kind: str, index: int) -> str:
    return IdFactory(FixedClock(NOW), lambda: index).object_id(kind)


def uuid7(index: int) -> str:
    return IdFactory(FixedClock(NOW), lambda: index).uuid7()


def ref(
    kind: str,
    index: int,
    *,
    version: int = 1,
    body: bytes | None = None,
) -> VersionRef:
    payload = body if body is not None else f"{kind}:{index}".encode()
    return VersionRef(
        object_id=oid(kind, index),
        version=version,
        content_sha256=hashlib.sha256(payload).hexdigest(),
    )


ROOTS = RootManifestSet(
    catalog_version=10,
    wiki_manifest_ref=ref("wiki_manifest", 10, version=10),
    lexical_manifest_ref=ref("lexical_manifest", 11, version=10),
    vector_manifest_ref=ref("vector_manifest", 12, version=10),
    graph_manifest_ref=ref("graph_manifest", 13, version=10),
)
POLICY_REF = ref("authority_policy", 20)
CLIENT_SNAPSHOT_REF = ref("client_snapshot", 21)
SCOPE_POLICY_REF = ref("scope_policy", 22)


def locator(index: int, *, private: bool = False) -> EvidenceLocator:
    anchor = ref("anchor", index)
    return EvidenceLocator(
        locator_kind="client_fact" if private else "source_line_span",
        anchor_refs=(anchor,),
        display_locator=(
            f"fact:{anchor.object_id}" if private else "lines:1-2"
        ),
        locator_policy_ref=ref("locator_policy", index + 100),
    )


def candidate(
    index: int,
    *,
    channel: EvidenceChannel,
    body: str,
    private: bool = False,
    object_type: str | None = None,
    case_derived: bool = False,
    allowed_uses: frozenset[str] = frozenset({"consultation_answer"}),
) -> CandidateRef:
    encoded = body.encode()
    exact_object_type = object_type or ("profile_json" if private else "claim")
    reference = ref(exact_object_type, index, body=encoded)
    content = reference if private else ref("passage", index + 1000, body=encoded)
    provenance = (
        Provenance(
            client_ids=frozenset({CLIENT}),
            provenance_scope="client_private",
            private_owner_client_id=CLIENT,
            derivation_rule_ref=ref("derivation_rule", index + 2000),
        )
        if private
        else Provenance(
            case_ids=frozenset({oid("case", index)}),
            client_ids=frozenset({OTHER_CLIENT}),
            case_contributor_client_ids=frozenset({OTHER_CLIENT}),
            provenance_scope="case_derived",
            derivation_rule_ref=ref("derivation_rule", index + 2000),
        )
        if case_derived
        else Provenance(
            source_ids=frozenset({oid("source", index)}),
            passage_ids=frozenset({content.object_id}),
            provenance_scope="global_source",
            derivation_rule_ref=ref("derivation_rule", index + 2000),
        )
    )
    return CandidateRef(
        reference=reference,
        content_ref=content,
        object_type=exact_object_type,
        channel=channel,
        metadata=CandidateMetadata(
            manifest_ref=(
                ref("client_manifest", 30, version=7)
                if private
                else ROOTS.lexical_manifest_ref
            ),
            review_status="approved",
            allowed_uses=allowed_uses,
            approved_at=NOW - timedelta(days=2),
            review_due_at=NOW + timedelta(days=30),
            sensitivity=1,
            source_grade="K1" if private else "T1",
            empirical_support="unassessed" if private else "empirically_supported",
            source_count=1,
            media_type=(
                "application/json"
                if exact_object_type == "client_graph"
                else "text/plain"
            ),
            size_bytes=len(encoded),
        ),
        provenance=provenance,
        location=locator(index, private=private),
        freshness=EvidenceFreshnessSnapshot(
            status="current",
            evaluated_at=NOW,
            source_observed_at=NOW - timedelta(days=1),
            last_reviewed_at=NOW - timedelta(days=1),
            review_due_at=NOW + timedelta(days=30),
            policy_ref=ref("freshness_policy", index + 3000),
        ),
        score=float(index),
    )


class FakeBinding:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.current_checks = 0

    def verify_authority_connection(self, connection: sqlite3.Connection) -> None:
        if connection is not self.connection:
            raise ValueError

    def verify_current(self) -> None:
        self.current_checks += 1


class FakeActiveArtifacts:
    active_runtime_epoch = 3
    roots = ROOTS

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.binding = FakeBinding(connection)

    def bindings(self) -> tuple[object, ...]:
        return (self.binding,)


class FakeGlobalAuthority:
    def __init__(self, allowed: frozenset[str]) -> None:
        self.snapshot = AuthoritativeFilterSnapshot(
            run_id=uuid7(100),
            global_runtime_epoch=3,
            client_runtime_epoch=0,
            tombstone_epoch=2 << 32,
            authorization_epoch=4,
            allowed_ref_ids=allowed,
            policy_ref=POLICY_REF,
            created_at=NOW,
        )
        self.current_checks = 0

    def freeze(self, scope: RetrievalScope) -> AuthoritativeFilterSnapshot:
        assert scope.current_client_id == CLIENT
        return self.snapshot

    def assert_snapshot_current(self, snapshot: AuthoritativeFilterSnapshot) -> None:
        if snapshot != self.snapshot:
            raise AuthoritySnapshotStale
        self.current_checks += 1

    def candidate_status(
        self,
        value: CandidateRef,
        snapshot: AuthoritativeFilterSnapshot,
    ) -> CandidateAuthorityStatus:
        if snapshot != self.snapshot:
            raise AuthoritySnapshotStale
        return (
            "visible"
            if value.reference.object_id in snapshot.allowed_ref_ids
            else "unauthorized"
        )


class RecordingRetriever:
    artifact_binding = None

    def __init__(
        self,
        value: CandidateRef | None,
        *,
        on_search: object | None = None,
    ) -> None:
        self.value = value
        self.questions: list[str] = []
        self.on_search = on_search

    def search(self, query, scope, authority_snapshot, *, limit):  # type: ignore[no-untyped-def]
        del scope, authority_snapshot, limit
        self.questions.append(query)
        if callable(self.on_search):
            self.on_search()
        return () if self.value is None else (self.value,)


class BodyReader:
    def __init__(self, bodies: dict[str, bytes]) -> None:
        self.bodies = bodies

    def read_verified(self, value: CandidateRef) -> bytes:
        return self.bodies[value.content_ref.content_sha256]


class Semantics:
    def __init__(self, stance: str = "support") -> None:
        self.stance = stance

    def resolve(self, value: CandidateRef) -> CandidateSemantics:
        del value
        return CandidateSemantics(stance=self.stance)  # type: ignore[arg-type]


class RerankerModel:
    descriptor = ModelDescriptor(
        repo="local/test",
        revision="1" * 40,
        model_files=(ModelFileHash(relative_path="model.bin", sha256="2" * 64),),
        adapter_class="tests.RerankerModel",
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

    def score(self, query, passages):  # type: ignore[no-untyped-def]
        del query
        return np.asarray(
            [float(index) for index, _ in enumerate(passages, start=1)],
            dtype=np.float32,
        )


class ArtifactGate:
    def verify(self, snapshot, roots, retrievers, routes):  # type: ignore[no-untyped-def]
        assert snapshot.global_runtime_epoch == 3
        assert roots == ROOTS
        assert set(routes) == set(retrievers)


class VersionGate:
    def verify(self, snapshot, roots):  # type: ignore[no-untyped-def]
        assert snapshot.global_runtime_epoch == 3
        assert roots == ROOTS


class ClosureVerifier:
    def verify(self, requirements, *, vocabulary):  # type: ignore[no-untyped-def]
        assert requirements
        assert vocabulary.scope_policy_ref == SCOPE_POLICY_REF


class Counter:
    def count(self, payload: bytes) -> int:
        return len(payload.decode())


def c1_context(query_plan: QueryPlan | None = None) -> GenerationC1Context:
    exact_plan = query_plan or plan()
    exact_input = C1ApplicabilityInput.bind(
        exact_plan,
        client_snapshot_ref=binding().client_snapshot_ref,
        client_runtime_epoch=binding().client_runtime_epoch,
        client_tombstone_count=binding().client_tombstone_count,
        temporary_fact_refs=binding().temporary_fact_refs,
    )
    return GenerationC1Context(
        decision=C1ApplicabilityDecision(
            status="unavailable",
            revision=None,
            scope_policy_ref=SCOPE_POLICY_REF,
            matched_rule_ids=(),
            missing_context_fields=(),
            effective_status="none",
            empirical_support="unassessed",
            conflict_evidence_ids=(),
        ),
        vocabulary=C1PolicyVocabulary(
            scope_policy_ref=SCOPE_POLICY_REF,
            approved_rule_ids=frozenset(),
            approved_context_fields=frozenset(),
        ),
        structured_context_trusted=False,
        applicability_input_sha256=exact_input.canonical_sha256,
    )


def applicable_c1_context(query_plan: QueryPlan) -> GenerationC1Context:
    exact_input = C1ApplicabilityInput.bind(
        query_plan,
        client_snapshot_ref=binding().client_snapshot_ref,
        client_runtime_epoch=binding().client_runtime_epoch,
        client_tombstone_count=binding().client_tombstone_count,
        temporary_fact_refs=binding().temporary_fact_refs,
    )
    return GenerationC1Context(
        decision=C1ApplicabilityDecision(
            status="applicable",
            revision=ref("theory", 8_001),
            scope_policy_ref=SCOPE_POLICY_REF,
            matched_rule_ids=("emotional_consultation",),
            missing_context_fields=(),
            effective_status="active",
            empirical_support="case_supported",
            conflict_evidence_ids=(),
        ),
        vocabulary=C1PolicyVocabulary(
            scope_policy_ref=SCOPE_POLICY_REF,
            approved_rule_ids=frozenset({"emotional_consultation"}),
            approved_context_fields=frozenset(),
        ),
        structured_context_trusted=True,
        applicability_input_sha256=exact_input.canonical_sha256,
    )


def exact_c1_context(
    query_plan: QueryPlan,
    decision: C1ApplicabilityDecision,
) -> GenerationC1Context:
    exact_input = C1ApplicabilityInput.bind(
        query_plan,
        client_snapshot_ref=binding().client_snapshot_ref,
        client_runtime_epoch=binding().client_runtime_epoch,
        client_tombstone_count=binding().client_tombstone_count,
        temporary_fact_refs=binding().temporary_fact_refs,
    )
    return GenerationC1Context(
        decision=decision,
        vocabulary=C1PolicyVocabulary(
            scope_policy_ref=decision.scope_policy_ref,
            approved_rule_ids=frozenset(decision.matched_rule_ids),
            approved_context_fields=frozenset(decision.missing_context_fields),
        ),
        structured_context_trusted=True,
        applicability_input_sha256=exact_input.canonical_sha256,
    )


class Factory:
    def __init__(
        self,
        *,
        global_candidate: CandidateRef,
        retriever: RecordingRetriever,
        missing_c1: bool = False,
        query_plan: QueryPlan | None = None,
        c1_override: GenerationC1Context | None = None,
        global_body: bytes = b"global evidence",
        stance: str = "support",
        allowed_uses: frozenset[str] = frozenset({"consultation_answer"}),
    ) -> None:
        self.authority = FakeGlobalAuthority(
            frozenset({global_candidate.reference.object_id})
        )
        self.dependencies = GenerationRetrievalDependencies(
            global_snapshot_repository=self.authority,
            artifact_gate=ArtifactGate(),
            global_retrievers={global_candidate.channel: retriever},
            global_content_reader=BodyReader(
                {global_candidate.content_ref.content_sha256: global_body}
            ),
            semantics_resolver=Semantics(stance),
            fusion=ReciprocalRankFusion(),
            reranker=EvidenceReranker(RerankerModel()),
            context_budget=ContextBudget(
                max_tokens=10_000,
                minimum_supporting=0 if stance == "contradiction" else 1,
                minimum_contradictions=1 if stance == "contradiction" else 0,
                minimum_exact_quotes=0,
            ),
            token_counter=Counter(),
            closure_verifier=ClosureVerifier(),
            version_gate=VersionGate(),
            c1_context=(
                None
                if missing_c1
                else c1_override or c1_context(query_plan)
            ),
            reranker_descriptor_ref=VersionRef(
                object_id=oid("reranker_descriptor", 40),
                version=1,
                content_sha256=RerankerModel.descriptor.id,
            ),
            allowed_uses=allowed_uses,
        )

    def build(self, **kwargs):  # type: ignore[no-untyped-def]
        assert kwargs["plan"].global_runtime_epoch == 3
        assert kwargs["active_artifacts"].roots == ROOTS
        assert isinstance(kwargs["global_connection"], sqlite3.Connection)
        assert type(kwargs["global_content_store"]) is ContentStore
        return self.dependencies


def plan() -> QueryPlan:
    envelope = GenerationStageEnvelope(
        stage="query_plan",
        turn_id=uuid7(200),
        run_id=uuid7(201),
        parent_sha256s=("4" * 64,),
        created_at=NOW,
    )
    return QueryPlan(
        envelope=envelope,
        intent="mixed",
        client_snapshot_ref=CLIENT_SNAPSHOT_REF,
        global_runtime_epoch=3,
        client_runtime_epoch=7,
        tombstone_epoch=(2 << 32) | 5,
        authorization_epoch=4,
        guardrails=QueryGuardrails(),
        subqueries=(
            Subquery(
                subquery_id="relationship",
                category="emotion_needs_relationship",
                question="How is the relationship changing?",
                routes=("lexical", "profile"),
                required_evidence_types=(),
                scope="both",
            ),
            Subquery(
                subquery_id="knowledge",
                category="emotion_needs_relationship",
                question="Which governed knowledge is relevant?",
                routes=("lexical",),
                required_evidence_types=(),
                scope="global_knowledge",
            ),
        ),
        route_omissions=(),
        rationale_summary="Retrieve current facts and governed knowledge.",
    )


def binding() -> GenerationClientBinding:
    return GenerationClientBinding(
        client_snapshot_ref=CLIENT_SNAPSHOT_REF,
        client_runtime_epoch=7,
        client_tombstone_count=5,
        temporary_fact_refs=(ref("temporary_fact", 50),),
    )


def historical_plan() -> QueryPlan:
    return plan().model_copy(
        update={
            "intent": "fact_change",
            "subqueries": (
                Subquery(
                    subquery_id="relationship_history",
                    category="historical_change",
                    question="What changed in the relationship over time?",
                    routes=("client_history",),
                    required_evidence_types=("temporal_graph_edge",),
                    scope="client_private",
                ),
            ),
        }
    )


def temporal_graph_body(*, with_edge: bool) -> str:
    edge_id = oid("fact_event", 700)
    payload = {
        "builder_policy_version": "client-temporal-graph.v1",
        "edges": (
            [
                {
                    "source": "client",
                    "target": "partner",
                    "edge_id": edge_id,
                    "attributes": {
                        "approved_at": "2026-07-18T08:00:00.000000Z",
                        "confidence": 0.9,
                        "dependency_type": "direct_deterministic",
                        "edge_id": edge_id,
                        "effective_from": "2026-06-01T08:00:00.000000Z",
                        "effective_to": None,
                        "epistemic_status": "client_reported",
                        "fact_id": oid("fact", 701),
                        "privacy_level": "private_client",
                        "recorded_at": "2026-07-18T08:00:00.000000Z",
                        "relation_type": "PARTNER_IS",
                        "resolution_status": "open",
                        "review_status": "approved",
                        "source_event_ids": [edge_id],
                        "validity_status": "active",
                    },
                }
            ]
            if with_edge
            else []
        ),
        "nodes": [
            {"node_id": "client", "attributes": {"node_type": "Client"}},
            {"node_id": "partner", "attributes": {"node_type": "PersonRole"}},
        ],
        "publication_operation_id": uuid7(702),
        "query": {
            "effective_at": "2026-07-19T08:00:00.000000Z",
            "known_at": "2026-07-19T08:00:00.000000Z",
        },
        "runtime_epoch": 7,
        "schema_version": "client_temporal_graph.v1",
        "source_client_commit_version": 9,
    }
    return canonical_graph_bytes(payload).decode("utf-8")


def private_item() -> PrivateGenerationEvidence:
    value = candidate(2, channel="profile", body="private evidence", private=True)
    return PrivateGenerationEvidence(candidate=value, body="private evidence")


def orchestrator(
    tmp_path: Path,
    connection: sqlite3.Connection,
    factory: Factory,
) -> GenerationRetrievalOrchestrator:
    return GenerationRetrievalOrchestrator(
        active_artifacts=FakeActiveArtifacts(connection),
        global_connection=connection,
        global_content_store=ContentStore(tmp_path / "global"),
        dependency_factory=factory,
    )


def test_real_coordinator_joins_composite_snapshot_and_runs_each_subquery(
    tmp_path: Path,
) -> None:
    connection = sqlite3.connect(":memory:")
    global_value = candidate(1, channel="lexical", body="global evidence")
    retriever = RecordingRetriever(global_value)
    factory = Factory(global_candidate=global_value, retriever=retriever)
    exact_binding = binding()

    result = orchestrator(tmp_path, connection, factory).retrieve(
        plan(),
        CLIENT,
        exact_binding,
        (private_item(),),
        lambda: exact_binding,
    )

    assert retriever.questions == [
        "Which governed knowledge is relevant?",
        "How is the relationship changing?",
    ]
    assert result.evidence_pack.run_id == plan().envelope.run_id
    assert result.evidence_pack.authority.global_runtime_epoch == 3
    assert result.evidence_pack.authority.client_runtime_epoch == 7
    assert result.evidence_pack.authority.tombstone_epoch == (2 << 32) | 5
    assert {item.channel for item in result.evidence_pack.supporting} == {
        "lexical",
        "profile",
    }
    assert result.metadata.route_candidate_counts == {"lexical": 1, "profile": 1}
    assert result.evidence_pack_sha256 == hashlib.sha256(
        canonical_json_bytes(result.evidence_pack.model_dump(mode="json"))
    ).hexdigest()
    assert tuple(item.object_type for item in result.run_objects) == tuple(
        sorted(item.object_type for item in result.run_objects)
    )
    assert {item.object_type for item in result.run_objects} == {
        "authority_snapshot",
        "exclusion_proof",
        "provenance",
    }
    assert "private evidence" not in result.evidence_pack.model_dump_json()
    assert {
        item.body for item in result.evidence_context
    } == {"global evidence", "private evidence"}
    assert all(
        item.context_kind == "retrieved_candidate"
        for item in result.evidence_context
    )
    assert all(
        item.text_ref
        == {
            evidence.evidence_id: evidence
            for evidence in result.evidence_pack.supporting
        }[item.evidence_id].text_ref
        for item in result.evidence_context
    )
    assert CLIENT not in str(
        [item.model_dump(mode="json") for item in result.evidence_context]
    )
    assert factory.authority.current_checks >= 3


def test_worker_binding_change_during_retrieval_fails_closed(
    tmp_path: Path,
) -> None:
    connection = sqlite3.connect(":memory:")
    global_value = candidate(1, channel="lexical", body="global evidence")
    state = {"stale": False}
    retriever = RecordingRetriever(
        global_value,
        on_search=lambda: state.__setitem__("stale", True),
    )
    factory = Factory(global_candidate=global_value, retriever=retriever)
    exact_binding = binding()
    changed = exact_binding.model_copy(update={"client_runtime_epoch": 8})

    with pytest.raises(
        GenerationRetrievalOrchestratorError,
        match="RETRIEVAL_FILTER_OR_RESOLUTION_FAILED",
    ):
        orchestrator(tmp_path, connection, factory).retrieve(
            plan(),
            CLIENT,
            exact_binding,
            (private_item(),),
            lambda: changed if state["stale"] else exact_binding,
        )


def test_required_route_with_no_candidates_cannot_produce_partial_pack(
    tmp_path: Path,
) -> None:
    connection = sqlite3.connect(":memory:")
    global_value = candidate(1, channel="lexical", body="global evidence")
    factory = Factory(
        global_candidate=global_value,
        retriever=RecordingRetriever(None),
    )
    exact_binding = binding()

    with pytest.raises(
        GenerationRetrievalOrchestratorError,
        match="GENERATION_REQUIRED_ROUTE_EMPTY",
    ):
        orchestrator(tmp_path, connection, factory).retrieve(
            plan(),
            CLIENT,
            exact_binding,
            (private_item(),),
            lambda: exact_binding,
        )


def test_historical_change_requires_selected_verified_temporal_graph_edge(
    tmp_path: Path,
) -> None:
    connection = sqlite3.connect(":memory:")
    exact_plan = historical_plan()
    global_value = candidate(1, channel="lexical", body="global evidence")
    factory = Factory(
        global_candidate=global_value,
        retriever=RecordingRetriever(global_value),
        query_plan=exact_plan,
    )
    exact_binding = binding()
    fact_snapshot = candidate(
        70,
        channel="client_history",
        body="A relationship fact snapshot without a graph edge.",
        private=True,
        object_type="fact_snapshot",
    )

    with pytest.raises(
        GenerationRetrievalOrchestratorError,
        match="GENERATION_REQUIRED_EVIDENCE_TYPE_UNFULFILLED",
    ):
        orchestrator(tmp_path, connection, factory).retrieve(
            exact_plan,
            CLIENT,
            exact_binding,
            (PrivateGenerationEvidence(candidate=fact_snapshot, body=(
                "A relationship fact snapshot without a graph edge."
            )),),
            lambda: exact_binding,
        )


def test_client_graph_object_type_without_an_actual_edge_does_not_fulfill_requirement(
    tmp_path: Path,
) -> None:
    connection = sqlite3.connect(":memory:")
    exact_plan = historical_plan()
    global_value = candidate(1, channel="lexical", body="global evidence")
    factory = Factory(
        global_candidate=global_value,
        retriever=RecordingRetriever(global_value),
        query_plan=exact_plan,
    )
    exact_binding = binding()
    body = temporal_graph_body(with_edge=False)
    empty_graph = candidate(
        71,
        channel="client_history",
        body=body,
        private=True,
        object_type="client_graph",
    )

    with pytest.raises(
        GenerationRetrievalOrchestratorError,
        match="GENERATION_REQUIRED_EVIDENCE_TYPE_UNFULFILLED",
    ):
        orchestrator(tmp_path, connection, factory).retrieve(
            exact_plan,
            CLIENT,
            exact_binding,
            (PrivateGenerationEvidence(candidate=empty_graph, body=body),),
            lambda: exact_binding,
        )


def test_selected_canonical_client_graph_edge_fulfills_historical_requirement(
    tmp_path: Path,
) -> None:
    connection = sqlite3.connect(":memory:")
    exact_plan = historical_plan()
    global_value = candidate(1, channel="lexical", body="global evidence")
    factory = Factory(
        global_candidate=global_value,
        retriever=RecordingRetriever(global_value),
        query_plan=exact_plan,
    )
    exact_binding = binding()
    body = temporal_graph_body(with_edge=True)
    graph_candidate = candidate(
        72,
        channel="client_history",
        body=body,
        private=True,
        object_type="client_graph",
    )

    result = orchestrator(tmp_path, connection, factory).retrieve(
        exact_plan,
        CLIENT,
        exact_binding,
        (PrivateGenerationEvidence(candidate=graph_candidate, body=body),),
        lambda: exact_binding,
    )

    proof = result.metadata.evidence_type_proofs
    assert len(proof) == 1
    assert proof[0].subquery_id == "relationship_history"
    assert proof[0].evidence_type == "temporal_graph_edge"
    assert set(proof[0].evidence_ids) <= {
        item.evidence_id
        for item in (
            *result.evidence_pack.supporting,
            *result.evidence_pack.contradicting,
        )
    }


def test_theory_requirements_bind_active_c1_revision_and_scope_policy(
    tmp_path: Path,
) -> None:
    connection = sqlite3.connect(":memory:")
    exact_plan = plan().model_copy(
        update={
            "intent": "theory_guidance",
            "subqueries": (
                Subquery(
                    subquery_id="theory_use",
                    category="theory_method_boundary",
                    question="Which active C1 theory and boundary apply?",
                    routes=("lexical",),
                    required_evidence_types=(
                        "theory_applicability",
                        "theory_boundary",
                    ),
                    scope="global_knowledge",
                ),
            ),
        }
    )
    global_value = candidate(41, channel="lexical", body="global evidence")
    c1 = applicable_c1_context(exact_plan)
    factory = Factory(
        global_candidate=global_value,
        retriever=RecordingRetriever(global_value),
        query_plan=exact_plan,
        c1_override=c1,
    )
    exact_binding = binding()

    result = orchestrator(tmp_path, connection, factory).retrieve(
        exact_plan,
        CLIENT,
        exact_binding,
        (private_item(),),
        lambda: exact_binding,
    )

    proofs = result.metadata.evidence_type_proofs
    assert tuple(item.evidence_type for item in proofs) == (
        "theory_applicability",
        "theory_boundary",
    )
    assert all(
        item.proof_kind == "c1_authority"
        and item.c1_revision_ref == c1.decision.revision
        and item.c1_scope_policy_ref == c1.decision.scope_policy_ref
        and item.c1_decision_status == "applicable"
        and item.c1_effective_status == "active"
        and not item.evidence_ids
        for item in proofs
    )


@pytest.mark.parametrize(
    ("status", "revision", "matched", "missing", "effective", "empirical"),
    [
        (
            "not_applicable",
            ref("theory", 8_010),
            ("outside_scope",),
            (),
            "active",
            "case_supported",
        ),
        (
            "insufficient_context",
            ref("theory", 8_011),
            (),
            ("relationship_stage",),
            "active",
            "case_supported",
        ),
        ("unavailable", None, (), (), "none", "unassessed"),
    ],
)
def test_theory_requirements_prove_non_applicable_c1_states_exactly(
    tmp_path: Path,
    status: str,
    revision: VersionRef | None,
    matched: tuple[str, ...],
    missing: tuple[str, ...],
    effective: str,
    empirical: str,
) -> None:
    connection = sqlite3.connect(":memory:")
    exact_plan = plan().model_copy(
        update={
            "intent": "theory_guidance",
            "subqueries": (
                Subquery(
                    subquery_id="theory_use",
                    category="theory_method_boundary",
                    question="Which active C1 theory and boundary apply?",
                    routes=("lexical",),
                    required_evidence_types=(
                        "theory_applicability",
                        "theory_boundary",
                    ),
                    scope="global_knowledge",
                ),
            ),
        }
    )
    global_value = candidate(42, channel="lexical", body="global evidence")
    decision = C1ApplicabilityDecision.model_validate(
        {
            "status": status,
            "revision": revision,
            "scope_policy_ref": SCOPE_POLICY_REF,
            "matched_rule_ids": matched,
            "missing_context_fields": missing,
            "effective_status": effective,
            "empirical_support": empirical,
            "conflict_evidence_ids": (),
        },
        strict=True,
    )
    c1 = exact_c1_context(exact_plan, decision)
    factory = Factory(
        global_candidate=global_value,
        retriever=RecordingRetriever(global_value),
        query_plan=exact_plan,
        c1_override=c1,
    )
    exact_binding = binding()

    result = orchestrator(tmp_path, connection, factory).retrieve(
        exact_plan,
        CLIENT,
        exact_binding,
        (private_item(),),
        lambda: exact_binding,
    )

    assert len(result.metadata.evidence_type_proofs) == 2
    assert all(
        proof.c1_decision_status == decision.status
        and proof.c1_revision_ref == decision.revision
        and proof.c1_scope_policy_ref == decision.scope_policy_ref
        and proof.c1_effective_status == decision.effective_status
        for proof in result.metadata.evidence_type_proofs
    )


def test_case_provenance_proof_uses_selected_excluded_case_candidate(
    tmp_path: Path,
) -> None:
    connection = sqlite3.connect(":memory:")
    exact_plan = plan().model_copy(
        update={
            "intent": "case_comparison",
            "subqueries": (
                Subquery(
                    subquery_id="case_compare",
                    category="case_analogy",
                    question="Which governed case is comparable?",
                    routes=("case",),
                    required_evidence_types=("case_provenance",),
                    scope="global_knowledge",
                ),
            ),
        }
    )
    body = b"deidentified case evidence"
    global_value = candidate(
        43,
        channel="case",
        body=body.decode(),
        object_type="case_record",
        case_derived=True,
        allowed_uses=frozenset({"answer_support"}),
    )
    factory = Factory(
        global_candidate=global_value,
        retriever=RecordingRetriever(global_value),
        query_plan=exact_plan,
        global_body=body,
        allowed_uses=frozenset({"consultation"}),
    )
    exact_binding = binding()

    result = orchestrator(tmp_path, connection, factory).retrieve(
        exact_plan,
        CLIENT,
        exact_binding,
        (private_item(),),
        lambda: exact_binding,
    )

    proof = result.metadata.evidence_type_proofs[0]
    assert proof.evidence_type == "case_provenance"
    assert proof.evidence_ids == tuple(
        item.evidence_id
        for item in (*result.evidence_pack.supporting, *result.evidence_pack.contradicting)
    )
    assert all(item.channel == "case" for item in proof.candidate_sources)
    assert all(
        item.provenance.client_exclusion_status == "no_subject_contribution"
        for item in result.evidence_pack.supporting
    )


def test_contradicting_requirement_uses_actual_contradicting_pack_role(
    tmp_path: Path,
) -> None:
    connection = sqlite3.connect(":memory:")
    exact_plan = plan().model_copy(
        update={
            "subqueries": (
                Subquery(
                    subquery_id="counter",
                    category="counterevidence_conflict",
                    question="What selected evidence contradicts the claim?",
                    routes=("lexical",),
                    required_evidence_types=("contradicting_evidence",),
                    scope="global_knowledge",
                ),
            ),
        }
    )
    global_value = candidate(44, channel="lexical", body="global evidence")
    factory = Factory(
        global_candidate=global_value,
        retriever=RecordingRetriever(global_value),
        query_plan=exact_plan,
        stance="contradiction",
    )
    exact_binding = binding()

    result = orchestrator(tmp_path, connection, factory).retrieve(
        exact_plan,
        CLIENT,
        exact_binding,
        (private_item(),),
        lambda: exact_binding,
    )

    proof = result.metadata.evidence_type_proofs[0]
    assert proof.evidence_ids == tuple(
        item.evidence_id for item in result.evidence_pack.contradicting
    )
    assert proof.candidate_sources
    assert all(item.pack_role == "contradicting" for item in proof.candidate_sources)


def test_risk_context_proof_carries_prior_visible_risk_when_turn_set_is_empty(
    tmp_path: Path,
) -> None:
    connection = sqlite3.connect(":memory:")
    exact_plan = plan().model_copy(
        update={
            "subqueries": (
                Subquery(
                    subquery_id="normal_context",
                    category="emotion_needs_relationship",
                    question="What context supports a normal response?",
                    routes=("lexical",),
                    required_evidence_types=(),
                    scope="global_knowledge",
                ),
                Subquery(
                    subquery_id="internal_risk",
                    category="internal_risk",
                    question="Which counselor-only observations require attention?",
                    routes=(),
                    required_evidence_types=("risk_context",),
                    scope="internal_only",
                ),
            ),
        }
    )
    global_value = candidate(45, channel="lexical", body="global evidence")
    factory = Factory(
        global_candidate=global_value,
        retriever=RecordingRetriever(global_value),
        query_plan=exact_plan,
    )
    exact_binding = binding()
    risk = GenerationRiskContextBinding(
        turn_id=exact_plan.envelope.turn_id,
        client_message_sha256="8" * 64,
        authority=deterministic_risk_authority(epoch=3, suffix=918_000),
        evaluation_observation_ids=(),
        evaluation_set_sha256="9" * 64,
        evaluation_count=0,
        visible_observation_ids=(oid("risk_observation", 918_001),),
        visible_set_sha256="a" * 64,
        visible_count=1,
    )

    result = orchestrator(tmp_path, connection, factory).retrieve(
        exact_plan,
        CLIENT,
        exact_binding,
        (private_item(),),
        lambda: exact_binding,
        risk_context_binding=risk,
    )

    proof = result.metadata.evidence_type_proofs[0]
    assert proof.evidence_type == "risk_context"
    assert proof.evidence_ids == risk.visible_observation_ids
    assert proof.risk_evaluation_observation_ids == ()
    assert proof.risk_evaluation_set_sha256 == risk.evaluation_set_sha256
    assert proof.risk_visible_set_sha256 == risk.visible_set_sha256
    assert proof.risk_authority == risk.authority


def test_missing_c1_policy_fails_before_retrieval(tmp_path: Path) -> None:
    connection = sqlite3.connect(":memory:")
    global_value = candidate(1, channel="lexical", body="global evidence")
    factory = Factory(
        global_candidate=global_value,
        retriever=RecordingRetriever(global_value),
        missing_c1=True,
    )
    exact_binding = binding()

    with pytest.raises(
        GenerationRetrievalOrchestratorError,
        match="GENERATION_C1_POLICY_UNAVAILABLE",
    ):
        orchestrator(tmp_path, connection, factory).retrieve(
            plan(),
            CLIENT,
            exact_binding,
            (private_item(),),
            lambda: exact_binding,
        )


def test_active_c1_without_trusted_context_must_be_insufficient() -> None:
    exact_input = C1ApplicabilityInput.bind(
        plan(),
        client_snapshot_ref=binding().client_snapshot_ref,
        client_runtime_epoch=binding().client_runtime_epoch,
        client_tombstone_count=binding().client_tombstone_count,
        temporary_fact_refs=binding().temporary_fact_refs,
    )
    decision = C1ApplicabilityDecision(
        status="applicable",
        revision=ref("theory_revision", 60),
        scope_policy_ref=SCOPE_POLICY_REF,
        matched_rule_ids=("relationship_context",),
        missing_context_fields=(),
        effective_status="active",
        empirical_support="case_supported",
        conflict_evidence_ids=(),
    )
    vocabulary = C1PolicyVocabulary(
        scope_policy_ref=SCOPE_POLICY_REF,
        approved_rule_ids=frozenset({"relationship_context"}),
        approved_context_fields=frozenset({"relationship_stage"}),
    )

    with pytest.raises(ValueError, match="GENERATION_C1_CONTEXT_UNTRUSTED"):
        GenerationC1Context(
            decision=decision,
            vocabulary=vocabulary,
            structured_context_trusted=False,
            applicability_input_sha256=exact_input.canonical_sha256,
        )

    insufficient = decision.model_copy(
        update={
            "status": "insufficient_context",
            "matched_rule_ids": (),
            "missing_context_fields": ("relationship_stage",),
        }
    )
    assert GenerationC1Context(
        decision=insufficient,
        vocabulary=vocabulary,
        structured_context_trusted=False,
        applicability_input_sha256=exact_input.canonical_sha256,
    ).decision.status == "insufficient_context"


def test_c1_input_must_match_exact_worker_binding(tmp_path: Path) -> None:
    connection = sqlite3.connect(":memory:")
    global_value = candidate(1, channel="lexical", body="global evidence")
    factory = Factory(
        global_candidate=global_value,
        retriever=RecordingRetriever(global_value),
    )
    exact_binding = binding()
    mismatched = C1ApplicabilityInput.bind(
        plan(),
        client_snapshot_ref=exact_binding.client_snapshot_ref,
        client_runtime_epoch=exact_binding.client_runtime_epoch,
        client_tombstone_count=exact_binding.client_tombstone_count,
        temporary_fact_refs=(ref("temporary_fact", 99),),
    )

    with pytest.raises(
        GenerationRetrievalOrchestratorError,
        match="GENERATION_C1_INPUT_BINDING_MISMATCH",
    ):
        orchestrator(tmp_path, connection, factory).retrieve(
            plan(),
            CLIENT,
            exact_binding,
            (private_item(),),
            lambda: exact_binding,
            c1_applicability_input=mismatched,
        )


def test_provider_result_must_bind_exact_c1_input(tmp_path: Path) -> None:
    connection = sqlite3.connect(":memory:")
    global_value = candidate(1, channel="lexical", body="global evidence")
    factory = Factory(
        global_candidate=global_value,
        retriever=RecordingRetriever(global_value),
    )
    exact_binding = binding()
    asserted = C1ApplicabilityInput.bind(
        plan(),
        client_snapshot_ref=exact_binding.client_snapshot_ref,
        client_runtime_epoch=exact_binding.client_runtime_epoch,
        client_tombstone_count=exact_binding.client_tombstone_count,
        temporary_fact_refs=exact_binding.temporary_fact_refs,
        known_empty_fields=("population",),
    )

    with pytest.raises(
        GenerationRetrievalOrchestratorError,
        match="GENERATION_C1_INPUT_CLOSURE_MISMATCH",
    ):
        orchestrator(tmp_path, connection, factory).retrieve(
            plan(),
            CLIENT,
            exact_binding,
            (private_item(),),
            lambda: exact_binding,
            c1_applicability_input=asserted,
        )
