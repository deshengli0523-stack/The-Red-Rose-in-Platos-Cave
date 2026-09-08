from __future__ import annotations

import hashlib
import itertools
import json
import re
import shutil
import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import numpy as np
import pytest
from numpy.typing import NDArray

from consultation_kb.approvals.attestation import LocalHmacTargetExecutionAttestor
from consultation_kb.client.publication import (
    ClientPublicationExecutor,
    ClientPublicationPlanner,
)
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.anchors import deterministic_object_id
from consultation_kb.mcp.context import BoundTransport
from consultation_kb.mcp.retrieval_runtime import (
    ACTIVE_INTEGRITY_REBUILD_REQUIRED,
    ActiveRetrievalRuntime,
    RetrievalCapabilityUnavailable,
)
from consultation_kb.mcp.schemas import (
    QueryGlobalGraphInput,
    SearchLexicalInput,
    SearchVectorInput,
    WeightedPathInput,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import (
    C1ApplicabilityDecision,
    EvidencePack,
    RetrievalScope,
)
from consultation_kb.models.facts import AddMutation
from consultation_kb.retrieval.artifact_discovery import (
    ActiveRetrievalArtifactDiscovery,
    ActiveRetrievalArtifactGate,
)
from consultation_kb.retrieval.authority_snapshot import (
    AuthoritativeSnapshotRepository,
)
from consultation_kb.retrieval.budget import ContextBudget
from consultation_kb.retrieval.client_history import (
    ClientHistoryQuery,
    ClientHistoryResult,
    ClientHistoryRetriever,
    ScopedClientHistoryService,
    client_history_derivation_rule_ref,
)
from consultation_kb.retrieval.contracts import CandidateRef, Retriever
from consultation_kb.retrieval.coordinator import (
    CandidateSemantics,
    RetrievalCoordinator,
    RetrievalRequest,
)
from consultation_kb.retrieval.embeddings import (
    DeterministicFakeEmbedder,
    ModelDescriptor,
)
from consultation_kb.retrieval.evidence_pack import (
    ActiveArtifactVersionGate,
    ArtifactVersionMismatch,
    C1PolicyVocabulary,
    ClosureRequirement,
    EvidencePackBuilder,
)
from consultation_kb.retrieval.filters import CandidateFilter
from consultation_kb.retrieval.fusion import ReciprocalRankFusion
from consultation_kb.retrieval.global_graph import (
    GlobalGraphRetriever,
    GraphNodeQuery,
)
from consultation_kb.retrieval.global_graph_runtime import GlobalGraphRuntime
from consultation_kb.retrieval.lexical import LexicalRetriever
from consultation_kb.retrieval.rerank import EvidenceReranker
from consultation_kb.retrieval.resolver import (
    EvidenceResolver,
    ScopeRoutingContentReader,
    ScopedManifestContentReader,
)
from consultation_kb.retrieval.vector import ExactVectorRetriever
from consultation_kb.retrieval.wiki_index import WikiIndexRetriever
from consultation_kb.storage.connection import connect_database
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.approval_support import (
    ApprovalHarness,
    build_approval_harness,
)
from tests.consultation_kb.knowledge_integration_support import (
    build_global_knowledge_harness,
    prepare_global_publication,
    prepare_governed_knowledge,
)
from tests.consultation_kb.retrieval_support import NOW, model_descriptor
from tests.consultation_kb.unit.test_fact_schema import _event


pytestmark = pytest.mark.integration

QUERY = "无为不等于不行动。 acceptance"
PRIVATE_HISTORY_CANARY = "PRIVATE_HISTORY_BODY_MUST_NOT_LEAVE_CLIENT_VAULT"


class _ClientHistoryTransport:
    def __init__(self, service: ScopedClientHistoryService) -> None:
        self._service = service

    def query_client_history(
        self,
        request: ClientHistoryQuery,
    ) -> ClientHistoryResult:
        return self._service.query(request)


class _BoundClientScopes:
    def __init__(self, client_id: str) -> None:
        self._client_id = client_id

    def client_id_for_binding(self, binding: BoundTransport) -> str:
        del binding
        return self._client_id


class _GraphEndpoints:
    """Deterministic query-composition seam over the restarted graph."""

    def __init__(self, runtime: GlobalGraphRuntime) -> None:
        edge = next(iter(runtime.artifact.graph.edges), None)
        if edge is None:
            raise AssertionError("the real published graph must contain an edge")
        self._pair = GraphNodeQuery(
            source_node_id=str(edge[0]),
            target_node_id=str(edge[1]),
        )
        self.calls = 0

    def resolve(
        self,
        query: str,
        scope: RetrievalScope,
        *,
        limit: int,
    ) -> tuple[GraphNodeQuery, ...]:
        del query, scope
        self.calls += 1
        return (self._pair,)[:limit]


class _Semantics:
    def __init__(self, theory_ref: VersionRef) -> None:
        self._theory_ref = theory_ref

    def resolve(self, candidate: CandidateRef) -> CandidateSemantics:
        if candidate.metadata.source_grade == "C1":
            return CandidateSemantics(
                stance="support",
                theory_ref=self._theory_ref,
            )
        if candidate.metadata.empirical_support == "conflicting":
            return CandidateSemantics(stance="contradiction")
        if candidate.channel == "global_graph":
            return CandidateSemantics(stance="context")
        return CandidateSemantics(stance="support")


class _DeterministicReranker:
    def __init__(self) -> None:
        self._descriptor = model_descriptor(
            repo="local/retrieval-graph-restart-slice",
            adapter_class="RetrievalGraphRestartSliceReranker",
            query_prompt="",
            document_prompt="",
        )
        self.passages: tuple[str, ...] = ()

    @property
    def descriptor(self) -> ModelDescriptor:
        return self._descriptor

    def score(
        self,
        query: str,
        passages: Sequence[str],
    ) -> NDArray[np.float32]:
        del query
        self.passages = tuple(passages)
        return np.linspace(1.0, 0.5, len(passages), dtype=np.float32)


class _TokenCounter:
    def count(self, payload: bytes) -> int:
        return max(1, len(payload.decode("utf-8", errors="strict")))


class _ClosureVerifier:
    """Composition seam: production scope resolvers are tested separately."""

    def __init__(self) -> None:
        self.requirements: tuple[ClosureRequirement, ...] = ()

    def verify(
        self,
        requirements: tuple[ClosureRequirement, ...],
        *,
        vocabulary: C1PolicyVocabulary,
    ) -> None:
        if vocabulary.approved_rule_ids != frozenset({"relationship_context"}):
            raise AssertionError("unexpected C1 vocabulary")
        self.requirements = requirements


class _ObjectPublisher:
    """Hash-addressed run-object publisher seam used by the coordinator."""

    def publish(self, object_type: str, payload: bytes) -> VersionRef:
        digest = hashlib.sha256(payload).hexdigest()
        return VersionRef(
            object_id=deterministic_object_id(object_type, digest),
            version=1,
            content_sha256=digest,
        )


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {
            key
            for child in value.values()
            for key in _all_keys(child)
        }
    if isinstance(value, list):
        return {key for child in value for key in _all_keys(child)}
    return set()


def _approve_client_plan(
    harness: ApprovalHarness,
    *,
    scope_root: Path,
) -> None:
    client_id = "client_" + "a" * 12
    plan = ClientPublicationPlanner(harness.target_connection).prepare(
        AddMutation(
            new_fact=_event(
                client_id=client_id,
                event_id=harness.ids.object_id("fact_event"),
                fact_id=harness.ids.object_id("fact"),
                object_json=json.dumps(PRIVATE_HISTORY_CANARY),
            )
        ),
        draft_event_id=harness.ids.object_id("fact_draft"),
        operation_id=harness.operation_id(),
        expected_runtime_epoch=1,
        publication_timestamp=harness.clock.now(),
    )
    request = harness.service.request(
        plan.descriptor,
        diff_object_ref=harness.diff_object_ref(),
    )
    harness.service.confirm(
        harness.signer.confirm(
            harness.service.challenge_for_review(request.request_id)
        )
    )
    ticket = harness.service.issue_for_execution(
        request.request_id,
        plan.descriptor,
        operation_id=plan.operation_id,
    )
    proof = ClientPublicationExecutor(
        harness.target_connection,
        scope_root=scope_root,
        execution_proof_signer=LocalHmacTargetExecutionAttestor(
            secret=b"t" * 32,
            attestor_id="test-target-writer",
        ),
        clock=harness.clock,
    ).execute(plan, ticket)
    harness.service.acknowledge(proof)


def _publish_and_restart_client(tmp_path: Path) -> tuple[Path, Path, str]:
    scope_root = tmp_path / "client-vault"
    scope_root.mkdir()
    harness = build_approval_harness(scope_root)
    try:
        _approve_client_plan(harness, scope_root=scope_root)
    finally:
        harness.close()
    return (
        scope_root / "client.sqlite3",
        scope_root / "cas",
        "client_" + "a" * 12,
    )


def _open_routing_reader(
    global_database: Path,
    client_database: Path,
) -> sqlite3.Connection:
    connection = sqlite3.connect(
        f"{global_database.resolve(strict=True).as_uri()}?mode=ro",
        uri=True,
        isolation_level=None,
        timeout=5.0,
    )
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute(
            "ATTACH DATABASE ? AS client_authority",
            (f"{client_database.resolve(strict=True).as_uri()}?mode=ro",),
        )
        connection.execute("PRAGMA query_only = ON")
        return connection
    except BaseException:
        connection.close()
        raise


def _theory_ref(theory_id: str, revision: int, sha256: str) -> VersionRef:
    return VersionRef(
        object_id=theory_id,
        version=revision,
        content_sha256=sha256,
    )


def _reranker_ref(descriptor: ModelDescriptor) -> VersionRef:
    return VersionRef(
        object_id=deterministic_object_id("reranker_descriptor", descriptor.id),
        version=1,
        content_sha256=descriptor.id,
    )


def _set_forbidden_search(retriever: LexicalRetriever) -> list[int]:
    calls = [0]

    def forbidden_search(
        query: str,
        scope: RetrievalScope,
        authority_snapshot: object,
        *,
        limit: int,
    ) -> tuple[CandidateRef, ...]:
        del query, scope, authority_snapshot, limit
        calls[0] += 1
        raise AssertionError("artifact gate must fail before route search")

    retriever.search = forbidden_search  # type: ignore[method-assign]
    return calls


def test_real_retrieval_graph_slice_restarts_and_builds_safe_pack(
    tmp_path: Path,
) -> None:
    global_harness = build_global_knowledge_harness(tmp_path)
    knowledge = prepare_governed_knowledge(
        global_harness,
        second_claim_multi_support=True,
        include_graph_relation=True,
    )
    theory_ref = global_harness.connection.execute(
        "SELECT revision_sha256 FROM theory_revisions "
        "WHERE theory_id = ? AND revision = ?",
        (knowledge.theory.theory_id, knowledge.theory.revision),
    ).fetchone()
    assert theory_ref is not None
    exact_theory_ref = _theory_ref(
        knowledge.theory.theory_id,
        knowledge.theory.revision,
        str(theory_ref[0]),
    )
    conflicting_claim_id = knowledge.claims[1].claim_id
    scope_policy_ref = knowledge.theory.scope_policy_ref
    publication = prepare_global_publication(global_harness, knowledge)
    active_operation = publication.service.publish_theory_and_wiki(
        publication.operation_id,
        theory_id=knowledge.theory.theory_id,
        theory_revision=knowledge.theory.revision,
        wiki_id=knowledge.wiki.wiki_id,
        wiki_revision=knowledge.wiki.revision,
    )
    assert active_operation.runtime_epoch == 1
    global_database = global_harness.root / "global.sqlite3"
    global_store_root = global_harness.root / "global-content"
    global_harness.close()

    client_database, client_store_root, client_id = _publish_and_restart_client(
        tmp_path
    )

    # Cold start: no service, SQLite connection, ContentStore, or in-memory
    # graph object from either publication phase is reused below.
    global_store = ContentStore(global_store_root)
    client_store = ContentStore(client_store_root)
    global_connection = connect_database(global_database, "reader")
    client_connection = connect_database(client_database, "reader")
    routing_connection = _open_routing_reader(global_database, client_database)
    try:
        discovery = ActiveRetrievalArtifactDiscovery(
            global_connection,
            global_store,
        )
        active = discovery.discover_current_set()
        assert active is not None
        assert active.active_runtime_epoch == 1
        assert len(active.bindings()) == 5

        lexical = LexicalRetriever.from_artifact_binding(active.lexical)
        query_embedder = DeterministicFakeEmbedder(
            model_descriptor(),
            {QUERY: np.asarray([1.0, 0.0], dtype=np.float32)},
        )
        vector = ExactVectorRetriever.from_artifact_binding(
            active.vector,
            embedder=query_embedder,
        )
        wiki = WikiIndexRetriever(active.wiki_index)
        conflict_refs = {
            row.authority.reference
            for row in wiki.payload.rows
            if row.authority.reference.object_id == conflicting_claim_id
        }
        assert len(conflict_refs) == 1
        exact_conflict_ref = next(iter(conflict_refs))
        graph_runtime = GlobalGraphRuntime.from_artifact_binding(
            active.graph,
            global_connection=global_connection,
        )
        graph_nodes = _GraphEndpoints(graph_runtime)
        graph = GlobalGraphRetriever(
            graph_runtime.artifact,
            artifact_binding=active.graph,
            edge_authority_resolver=graph_runtime.edge_authority_resolver,
            node_resolver=graph_nodes,
            candidate_catalog=graph_runtime.candidate_catalog,
        )

        # The production MCP adapter consumes the same cold-started active
        # closure while opening no client database in its control process.
        mcp_retrieval = ActiveRetrievalRuntime(
            global_database=global_database,
            global_connection=global_connection,
            content_store=global_store,
            client_scopes=_BoundClientScopes(client_id),
            clock=FixedClock(NOW),
            id_factory=IdFactory(
                FixedClock(NOW),
                itertools.count(9_050).__next__,
            ),
            embedder_provider=lambda _descriptor: query_embedder,
        )
        mcp_result = mcp_retrieval.invoke(
            "search_lexical",
            SearchLexicalInput(
                session_handle="opaque-current-session",
                query=QUERY,
                limit=20,
            ),
            binding=BoundTransport(
                "transport-retrieval-slice",
                "opaque-current-session",
            ),
        )
        assert isinstance(mcp_result, dict)
        assert mcp_result["status"] == "ok"
        assert int(mcp_result["count"]) > 0
        assert mcp_result["authority"]["scope"] == "global_only"
        assert client_id not in json.dumps(
            mcp_result,
            ensure_ascii=False,
            default=str,
        )
        mcp_empty_result = mcp_retrieval.invoke(
            "search_lexical",
            SearchLexicalInput(
                session_handle="opaque-current-session",
                query="zzzz-no-such-token-928341",
                limit=20,
            ),
            binding=BoundTransport(
                "transport-retrieval-slice",
                "opaque-current-session",
            ),
        )
        assert isinstance(mcp_empty_result, dict)
        assert mcp_empty_result["status"] == "no_matches"
        assert mcp_empty_result["items"] == ()
        assert mcp_empty_result["exclusion"]["input_count"] == 0
        mcp_vector_result = mcp_retrieval.invoke(
            "search_vector",
            SearchVectorInput(
                session_handle="opaque-current-session",
                query=QUERY,
                limit=20,
            ),
            binding=BoundTransport(
                "transport-retrieval-slice",
                "opaque-current-session",
            ),
        )
        assert isinstance(mcp_vector_result, dict)
        assert mcp_vector_result["status"] == "ok"
        assert int(mcp_vector_result["count"]) > 0
        mcp_graph_result = mcp_retrieval.invoke(
            "query_global_graph",
            QueryGlobalGraphInput(
                session_handle="opaque-current-session",
                query=QUERY,
                limit=20,
                max_depth=4,
            ),
            binding=BoundTransport(
                "transport-retrieval-slice",
                "opaque-current-session",
            ),
        )
        assert isinstance(mcp_graph_result, dict)
        assert mcp_graph_result["status"] == "ok"
        assert int(mcp_graph_result["count"]) > 0
        assert all(
            item["steps"]
            and all(step["source_refs"] for step in item["steps"])
            for item in mcp_graph_result["items"]
        )
        assert client_id not in json.dumps(
            mcp_graph_result,
            ensure_ascii=False,
            default=str,
        )
        first_graph_path = mcp_graph_result["items"][0]
        mcp_weighted_result = mcp_retrieval.invoke(
            "weighted_path",
            WeightedPathInput(
                session_handle="opaque-current-session",
                graph_scope="global",
                source_ref=first_graph_path["node_refs"][0]["object_id"],
                target_ref=first_graph_path["node_refs"][-1]["object_id"],
                max_paths=3,
                max_hops=8,
            ),
            binding=BoundTransport(
                "transport-retrieval-slice",
                "opaque-current-session",
            ),
        )
        assert isinstance(mcp_weighted_result, dict)
        assert mcp_weighted_result["status"] == "ok"
        assert int(mcp_weighted_result["count"]) > 0
        lexical_path = active.lexical.path_for("lexical_index")
        lexical_bytes = lexical_path.read_bytes()
        lexical_path.write_bytes(b"tampered active lexical index")
        try:
            with pytest.raises(RetrievalCapabilityUnavailable) as integrity_error:
                mcp_retrieval.invoke(
                    "search_lexical",
                    SearchLexicalInput(
                        session_handle="opaque-current-session",
                        query=QUERY,
                        limit=20,
                    ),
                    binding=BoundTransport(
                        "transport-retrieval-slice",
                        "opaque-current-session",
                    ),
                )
            assert integrity_error.value.code == ACTIVE_INTEGRITY_REBUILD_REQUIRED
        finally:
            lexical_path.write_bytes(lexical_bytes)
        mcp_retrieval.close()

        client_service = ScopedClientHistoryService(
            client_connection,
            current_client_id=client_id,
            derivation_rule_ref=client_history_derivation_rule_ref(),
        )
        request_ids = IdFactory(FixedClock(NOW), itertools.count(9_100).__next__)
        initial_history = client_service.query(
            ClientHistoryQuery(
                request_id=request_ids.uuid7(),
                session_handle="opaque-current-session",
                query_category="continuity",
                limit=100,
            )
        )
        profile_candidates = tuple(
            candidate
            for candidate in initial_history.candidates
            if candidate.channel == "profile"
        )
        assert len(profile_candidates) == 1
        client_snapshot_ref = profile_candidates[0].reference
        client_history = ClientHistoryRetriever(
            _ClientHistoryTransport(client_service),
            session_handle="opaque-current-session",
            query_category="continuity",
            request_id_factory=request_ids,
        )

        route_policy_ref = (
            graph_runtime.builder_input.retrieval_input_descriptor.route_policy_ref
        )
        consultation_scope = RetrievalScope(
            current_client_id=client_id,
            allowed_uses=frozenset({"consultation"}),
            maximum_sensitivity=3,
            effective_at=NOW,
            known_at=NOW,
        )
        retrievers: dict[str, Retriever] = {
            "client_history": cast(Retriever, client_history),
            "global_graph": cast(Retriever, graph),
            "lexical": cast(Retriever, lexical),
            "vector": cast(Retriever, vector),
            "wiki": cast(Retriever, wiki),
        }
        routes = tuple(retrievers)
        reranker = _DeterministicReranker()
        closure = _ClosureVerifier()
        publisher = _ObjectPublisher()

        with AuthoritativeSnapshotRepository.open(
            global_database,
            client_database,
            policy_ref_provider=lambda: route_policy_ref,
            clock=FixedClock(NOW),
            id_factory=IdFactory(
                FixedClock(NOW),
                itertools.count(9_200).__next__,
            ),
            global_content_store=global_store,
        ) as repository:
            content_reader = ScopeRoutingContentReader(
                global_reader=ScopedManifestContentReader(
                    routing_connection,
                    global_store,
                    schema="main",
                ),
                client_reader=ScopedManifestContentReader(
                    routing_connection,
                    client_store,
                    schema="client_authority",
                ),
            )

            def coordinator(
                route_registry: dict[str, Retriever],
            ) -> RetrievalCoordinator:
                return RetrievalCoordinator(
                    snapshot_repository=repository,
                    artifact_gate=ActiveRetrievalArtifactGate(discovery),
                    retrievers=route_registry,
                    candidate_filter=CandidateFilter(repository),
                    resolver=EvidenceResolver(repository, content_reader),
                    semantics_resolver=_Semantics(exact_theory_ref),
                    fusion=ReciprocalRankFusion(),
                    reranker=EvidenceReranker(reranker),
                    context_budget=ContextBudget(
                        max_tokens=20_000,
                        minimum_supporting=1,
                        minimum_contradictions=1,
                        minimum_exact_quotes=1,
                    ),
                    token_counter=_TokenCounter(),
                    object_publisher=publisher,
                    pack_builder=EvidencePackBuilder(
                        closure_verifier=closure,
                        version_gate=ActiveArtifactVersionGate(
                            global_connection,
                            global_store,
                        ),
                    ),
                )

            request = RetrievalRequest(
                query=QUERY,
                scope=consultation_scope,
                routes=routes,
                required_routes=frozenset(routes),
                per_route_limit=20,
                fusion_limit=20,
                minimum_contradictions=1,
                client_snapshot_ref=client_snapshot_ref,
                temporary_fact_refs=(),
                unresolved_conflict_refs=(),
                mandatory_conflict_claim_refs=(exact_conflict_ref,),
                c1_applicability=C1ApplicabilityDecision(
                    status="applicable",
                    revision=exact_theory_ref,
                    scope_policy_ref=scope_policy_ref,
                    matched_rule_ids=("relationship_context",),
                    missing_context_fields=(),
                    effective_status="active",
                    empirical_support=knowledge.theory.empirical_support,
                    conflict_evidence_ids=(),
                ),
                c1_policy_vocabulary=C1PolicyVocabulary(
                    scope_policy_ref=scope_policy_ref,
                    approved_rule_ids=frozenset({"relationship_context"}),
                    approved_context_fields=frozenset(
                        {"relationship_stage"}
                    ),
                ),
                roots=active.roots,
                reranker_descriptor_ref=_reranker_ref(reranker.descriptor),
            )
            result = coordinator(retrievers).retrieve(request)

            assert set(result.route_candidate_counts) == set(routes)
            assert all(result.route_candidate_counts[route] > 0 for route in routes)
            assert result.degraded_components == ()
            assert graph_nodes.calls == 1
            assert "case" not in result.route_candidate_counts

            pack = result.evidence_pack.pack
            packed = (*pack.supporting, *pack.contradicting)
            assert any(
                item.source_grade == "C1"
                and item.framework_priority == "highest"
                for item in pack.supporting
            )
            assert any(
                item.empirical_support == "conflicting"
                for item in pack.contradicting
            )
            assert pack.c1_applicability.conflict_evidence_ids
            assert set(pack.c1_applicability.conflict_evidence_ids) <= {
                item.evidence_id for item in pack.contradicting
            }
            assert {"profile", "client_history"} <= {
                item.channel
                for item in packed
                if item.provenance.provenance_scope == "client_private"
            }
            assert all(item.provenance.case_count == 0 for item in packed)
            assert all(
                item.provenance.client_exclusion_status
                in {"not_applicable", "current_subject_private"}
                for item in packed
            )

            # Both an unbound copy and a route with a substituted binding are
            # rejected by the production artifact gate before any route search.
            unrelated_index = tmp_path / "unrelated-lexical.sqlite3"
            shutil.copyfile(
                active.lexical.path_for("lexical_index"),
                unrelated_index,
            )
            unbound = LexicalRetriever._from_unbound_path_for_test(
                unrelated_index
            )
            unbound_calls = _set_forbidden_search(unbound)
            unbound_routes = {
                **retrievers,
                "lexical": cast(Retriever, unbound),
            }
            with pytest.raises(ArtifactVersionMismatch):
                coordinator(unbound_routes).retrieve(request)
            assert unbound_calls == [0]

            substituted = LexicalRetriever.from_artifact_binding(active.lexical)
            substituted._artifact_binding = active.vector
            substituted_calls = _set_forbidden_search(substituted)
            substituted_routes = {
                **retrievers,
                "lexical": cast(Retriever, substituted),
            }
            with pytest.raises(ArtifactVersionMismatch):
                coordinator(substituted_routes).retrieve(request)
            assert substituted_calls == [0]

        safe_dump = pack.model_dump(
            mode="json",
            exclude_defaults=False,
            exclude_none=False,
        )
        safe_json = json.dumps(
            safe_dump,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        assert safe_dump["schema_version"] == "1.0"
        assert EvidencePack.model_validate_json(safe_json, strict=True) == pack
        assert {
            "allowed_ref_ids",
            "allowed_uses",
            "body",
            "case_contributor_client_ids",
            "client_ids",
            "current_client_id",
            "private_owner_client_id",
            "raw_content",
            "source_ids",
        }.isdisjoint(_all_keys(safe_dump))
        assert re.findall(r"client_[a-z0-9]{12}", safe_json) == []
        assert client_id not in safe_json
        assert PRIVATE_HISTORY_CANARY not in safe_json
        assert "无为不等于不行动。" not in safe_json
        assert {
            "authority_snapshot",
            "candidate_provenance",
            "candidate_text",
            "client_snapshot",
            "exclusion_proof",
            "graph_manifest",
            "lexical_manifest",
            "vector_manifest",
            "wiki_manifest",
        } <= {requirement.role for requirement in closure.requirements}
    finally:
        routing_connection.close()
        client_connection.close()
        global_connection.close()
