from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Iterator, cast

import pytest

import consultation_kb.mcp.retrieval_runtime as runtime_module
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.generation.contracts import (
    QueryGuardrails,
    QueryPlan,
    Subquery,
)
from consultation_kb.generation.retrieval_orchestrator import GenerationC1Context
from consultation_kb.mcp.context import BoundTransport
from consultation_kb.mcp.retrieval_runtime import (
    ActiveGenerationRetrievalDependencyFactory,
    ActiveRetrievalRuntime,
    GenerationGlobalBinding,
    RetrievalCapabilityUnavailable,
    _CaseRetriever,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    C1ApplicabilityDecision,
)
from consultation_kb.models.generation import GenerationStageEnvelope
from consultation_kb.retrieval.embeddings import ModelDescriptor, ModelFileHash
from consultation_kb.retrieval.evidence_pack import C1PolicyVocabulary, RootManifestSet
from consultation_kb.security.worker_protocol import GenerationClientBinding
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.retrieval_support import (
    CLIENT_B,
    candidate,
    case_provenance,
    scope,
    snapshot,
)


NOW = datetime(2026, 7, 19, 9, 0, tzinfo=timezone.utc)
CLIENT_ID = "client_" + "aaaaaaaaaaaa"


def oid(kind: str, index: int) -> str:
    return IdFactory(FixedClock(NOW), lambda: index).object_id(kind)


def uuid7(index: int) -> str:
    return IdFactory(FixedClock(NOW), lambda: index).uuid7()


def ref(kind: str, index: int, *, version: int = 1) -> VersionRef:
    return VersionRef(
        object_id=oid(kind, index),
        version=version,
        content_sha256=f"{index:064x}",
    )


ROOTS = RootManifestSet(
    catalog_version=10,
    wiki_manifest_ref=ref("wiki_manifest", 10, version=10),
    lexical_manifest_ref=ref("lexical_manifest", 11, version=10),
    vector_manifest_ref=ref("vector_manifest", 12, version=10),
    graph_manifest_ref=ref("graph_manifest", 13, version=10),
)
CLIENT_SNAPSHOT = ref("client_snapshot", 20)


class Scopes:
    def client_id_for_binding(self, binding: BoundTransport) -> str:
        del binding
        return CLIENT_ID

    def invoke_scoped_graph(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("not used")


def runtime(tmp_path: Path, **kwargs: object) -> tuple[ActiveRetrievalRuntime, sqlite3.Connection]:
    database = tmp_path / "global.sqlite3"
    connection = sqlite3.connect(database, isolation_level=None)
    return (
        ActiveRetrievalRuntime(
            global_database=database,
            global_connection=connection,
            content_store=ContentStore(tmp_path / "global-content"),
            client_scopes=Scopes(),
            clock=FixedClock(NOW),
            id_factory=IdFactory(FixedClock(NOW), lambda: 100),
            **kwargs,  # type: ignore[arg-type]
        ),
        connection,
    )


def plan() -> QueryPlan:
    return QueryPlan(
        envelope=GenerationStageEnvelope(
            stage="query_plan",
            turn_id=uuid7(30),
            run_id=uuid7(31),
            parent_sha256s=("a" * 64,),
            created_at=NOW,
        ),
        intent="theory_guidance",
        client_snapshot_ref=CLIENT_SNAPSHOT,
        global_runtime_epoch=3,
        client_runtime_epoch=4,
        tombstone_epoch=5,
        authorization_epoch=6,
        guardrails=QueryGuardrails(),
        subqueries=(
            Subquery(
                subquery_id="theory",
                category="theory_method_boundary",
                question="Which boundary applies?",
                routes=("wiki",),
                required_evidence_types=(
                    "theory_applicability",
                    "theory_boundary",
                ),
                scope="global_knowledge",
            ),
        ),
        route_omissions=(),
        rationale_summary="Retrieve governed theory evidence.",
    )


def client_binding() -> GenerationClientBinding:
    return GenerationClientBinding(
        client_snapshot_ref=CLIENT_SNAPSHOT,
        client_runtime_epoch=4,
        client_tombstone_count=5,
        temporary_fact_refs=(),
    )


def test_generation_binding_can_truthfully_advertise_no_routes() -> None:
    invocation = SimpleNamespace(
        snapshot=AuthoritativeFilterSnapshot(
            run_id=uuid7(40),
            global_runtime_epoch=3,
            client_runtime_epoch=0,
            tombstone_epoch=0,
            authorization_epoch=6,
            allowed_ref_ids=frozenset(),
            policy_ref=ref("authority_policy", 41),
            created_at=NOW,
        ),
        active=SimpleNamespace(roots=ROOTS),
    )

    result = GenerationGlobalBinding.from_invocation(
        invocation,  # type: ignore[arg-type]
        available_routes=(),
    )

    assert result.available_routes == ()


def test_generation_retrieval_fails_before_artifact_access_without_dependencies(
    tmp_path: Path,
) -> None:
    service, connection = runtime(tmp_path)
    transport = BoundTransport("transport", "h" * 32)
    exact_binding = client_binding()
    try:
        assert service._generation_available_routes(  # noqa: SLF001
            SimpleNamespace()  # type: ignore[arg-type]
        ) == ()
        with pytest.raises(
            RetrievalCapabilityUnavailable,
            match="GENERATION_RETRIEVAL_DEPENDENCY_UNAVAILABLE",
        ):
            service.retrieve_generation_plan(
                plan(),
                exact_binding,
                (),
                binding=transport,
                revalidate_binding=lambda: exact_binding,
            )
    finally:
        service.close()
        connection.close()


class C1Provider:
    def is_available(self, **kwargs: object) -> bool:
        del kwargs
        return True

    def resolve(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("factory is not executed in this wiring test")


def test_generation_runtime_passes_exact_scope_to_orchestrator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, connection = runtime(
        tmp_path,
        embedder_provider=lambda descriptor: descriptor,
        generation_c1_provider=C1Provider(),
    )
    transport = BoundTransport("transport", "h" * 32)
    exact_plan = plan()
    exact_binding = client_binding()
    active = SimpleNamespace(active_runtime_epoch=3, roots=ROOTS)
    invocation = SimpleNamespace(active=active)
    calls: dict[str, object] = {}
    outcome = object()

    @contextmanager
    def fake_invocation(*args: object, **kwargs: object) -> Iterator[object]:
        calls["invocation"] = (args, kwargs)
        yield invocation

    class FakeOrchestrator:
        def __init__(self, **kwargs: object) -> None:
            calls["constructor"] = kwargs

        def retrieve(self, *args: object, **kwargs: object) -> object:
            calls["retrieve"] = (args, kwargs)
            return outcome

    monkeypatch.setattr(service, "_invocation", fake_invocation)
    monkeypatch.setattr(
        service,
        "_generation_available_routes",
        lambda value: ("wiki",),
    )
    monkeypatch.setattr(
        runtime_module,
        "GenerationRetrievalOrchestrator",
        FakeOrchestrator,
    )
    try:
        result = service.retrieve_generation_plan(
            exact_plan,
            exact_binding,
            (),
            binding=transport,
            revalidate_binding=lambda: exact_binding,
        )
    finally:
        service.close()
        connection.close()

    assert result is outcome
    constructor = calls["constructor"]
    assert isinstance(constructor, dict)
    assert constructor["active_artifacts"] is active
    assert constructor["global_connection"] is connection
    retrieve_args, retrieve_kwargs = cast(
        tuple[tuple[object, ...], dict[str, object]],
        calls["retrieve"],
    )
    assert retrieve_args[:4] == (
        exact_plan,
        CLIENT_ID,
        exact_binding,
        (),
    )
    assert retrieve_kwargs == {"risk_context_binding": None}


def test_production_generation_factory_uses_genuine_vector_case_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exact_case = candidate(
        901,
        provenance=case_provenance(901, CLIENT_B),
        channel="case",
        object_type="case",
        allowed_uses=frozenset({"answer_support"}),
        text="semantic-only governed case",
    )
    lexical_binding = object()

    class _VectorBinding:
        @staticmethod
        def path_for(_role: str) -> object:
            return SimpleNamespace(read_bytes=lambda: b"{}")

    vector_binding = _VectorBinding()

    class _Delegate:
        def __init__(self, binding: object, values: tuple[object, ...]) -> None:
            self.artifact_binding = binding
            self._values = values

        def search(self, *args: object, **kwargs: object) -> tuple[object, ...]:
            del args, kwargs
            return self._values

    lexical = _Delegate(lexical_binding, ())
    vector = _Delegate(vector_binding, (exact_case,))
    wiki = _Delegate(object(), ())
    graph = _Delegate(object(), ())
    descriptor = ModelDescriptor(
        repo="local/test",
        revision="1" * 40,
        model_files=(ModelFileHash(relative_path="model.bin", sha256="2" * 64),),
        adapter_class="tests.ProductionCaseEmbedder",
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
    embedder = SimpleNamespace(descriptor=descriptor)
    exact_c1 = GenerationC1Context(
        decision=C1ApplicabilityDecision(
            status="unavailable",
            revision=None,
            scope_policy_ref=ref("scope_policy", 902),
            matched_rule_ids=(),
            missing_context_fields=(),
            effective_status="none",
            empirical_support="unassessed",
            conflict_evidence_ids=(),
        ),
        vocabulary=C1PolicyVocabulary(
            scope_policy_ref=ref("scope_policy", 902),
            approved_rule_ids=frozenset(),
            approved_context_fields=frozenset(),
        ),
        structured_context_trusted=False,
        applicability_input_sha256="4" * 64,
    )

    class _Manifest:
        @staticmethod
        def model_validate_json(*args: object, **kwargs: object) -> object:
            del args, kwargs
            return SimpleNamespace(model_descriptor=descriptor)

    monkeypatch.setattr(runtime_module, "VectorBuildManifest", _Manifest)
    monkeypatch.setattr(runtime_module, "WikiIndexRetriever", lambda _binding: wiki)
    monkeypatch.setattr(
        runtime_module.LexicalRetriever,
        "from_artifact_binding",
        staticmethod(lambda _binding: lexical),
    )
    monkeypatch.setattr(
        runtime_module.ExactVectorRetriever,
        "from_artifact_binding",
        staticmethod(lambda _binding, *, embedder: vector),
    )
    graph_runtime = SimpleNamespace(
        artifact=SimpleNamespace(graph=object()),
        edge_authority_resolver=object(),
        candidate_catalog=object(),
    )
    monkeypatch.setattr(
        runtime_module.GlobalGraphRuntime,
        "from_artifact_binding",
        staticmethod(lambda *args, **kwargs: graph_runtime),
    )
    monkeypatch.setattr(
        runtime_module,
        "QueryMatchedGraphNodeResolver",
        lambda **kwargs: object(),
    )
    monkeypatch.setattr(
        runtime_module,
        "GlobalGraphRetriever",
        lambda *args, **kwargs: graph,
    )
    for name in (
        "ActiveArtifactGlobalClosureVerifier",
        "ActiveC1CandidateSemantics",
        "ActiveArtifactVersionGate",
        "ActiveRetrievalArtifactGate",
        "EmbeddingEvidenceReranker",
        "EvidenceReranker",
        "ScopedManifestContentReader",
    ):
        monkeypatch.setattr(runtime_module, name, lambda *args, **kwargs: object())

    class _C1Provider:
        def resolve(self, *args: object, **kwargs: object) -> GenerationC1Context:
            del args, kwargs
            return exact_c1

    connection = sqlite3.connect(":memory:")
    store = ContentStore(tmp_path / "global-content")
    active = SimpleNamespace(
        wiki_index=object(),
        lexical=lexical_binding,
        vector=vector_binding,
        graph=object(),
    )
    invocation = SimpleNamespace(
        active=active,
        authority=object(),
        authority_connection=connection,
        snapshot=snapshot(exact_case),
    )
    factory = ActiveGenerationRetrievalDependencyFactory(
        invocation=invocation,
        discovery=object(),  # type: ignore[arg-type]
        global_connection=connection,
        global_content_store=store,
        embedder_provider=lambda _descriptor: embedder,  # type: ignore[arg-type]
        c1_provider=_C1Provider(),  # type: ignore[arg-type]
    )
    try:
        dependencies = factory.build(
            plan=plan(),
            c1_applicability_input=cast(object, None),  # type: ignore[arg-type]
            active_artifacts=active,
            global_connection=connection,
            global_content_store=store,
        )
        case_retriever = dependencies.global_retrievers["case"]
        assert isinstance(case_retriever, _CaseRetriever)
        assert case_retriever.artifact_bindings == {
            "lexical": lexical_binding,
            "vector": vector_binding,
        }
        assert case_retriever.search(
            "same meaning, different wording",
            scope(use="answer_support"),
            invocation.snapshot,
            limit=5,
        ) == (exact_case,)
    finally:
        connection.close()
