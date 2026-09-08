from __future__ import annotations

import sqlite3
import shutil
import threading
from pathlib import Path
from typing import cast

import pytest

from consultation_kb.core.config import AppConfig
from consultation_kb.core.clock import SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.mcp.context import BoundTransport, HandlerServices, ToolService
from consultation_kb.mcp.knowledge_runtime import GlobalKnowledgeToolRuntime
from consultation_kb.models.common import StrictModel
from consultation_kb.mcp.retrieval_runtime import (
    ACTIVE_INTEGRITY_REBUILD_REQUIRED,
    ActiveRetrievalRuntime,
    GenerationC1Provider,
    RetrievalCapabilityUnavailable,
    VectorEmbedderProvider,
)
from consultation_kb.mcp.runtime import ProductionRuntime
from consultation_kb.mcp.runtime import RuntimeCompositionError
from consultation_kb.mcp.risk_runtime import RiskEvaluationRuntime
from consultation_kb.mcp.schemas import (
    QueryGlobalGraphInput,
    SearchClientHistoryInput,
    SearchWikiInput,
)
from consultation_kb.mcp.session_runtime import (
    SessionRuntimeManager,
    SessionScopeDenied,
    _LiveSession,
)
from consultation_kb.policy.loader import PolicyLoader
from consultation_kb.publication.global_knowledge import GlobalPublicationBuilders
from consultation_kb.retrieval.artifact_contracts import ArtifactBinding
from consultation_kb.risk.composition import RiskModelDraftProvider
from consultation_kb.security.scoped_worker import ScopedWorkerBroker
from consultation_kb.security.worker_protocol import BeginSessionResponse
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from tests.consultation_kb.approval_support import TestProtector
from tests.consultation_kb.risk_support import insert_approved_risk_policy_epoch


class _AliveWorker:
    @property
    def is_alive(self) -> bool:
        return True


class _RetrievalSpy:
    def __init__(
        self,
        close_order: list[str] | None = None,
        *,
        startup_error: str | None = None,
    ) -> None:
        self.calls: list[tuple[str, BoundTransport | None]] = []
        self.closed = False
        self.startup_verifications = 0
        self._startup_error = startup_error
        self._close_order = close_order

    def invoke(
        self,
        tool_name: str,
        request: object,
        *,
        binding: BoundTransport | None,
    ) -> object:
        del request
        self.calls.append((tool_name, binding))
        return {"routed_to": "retrieval", "tool": tool_name}

    def close(self) -> None:
        self.closed = True
        if self._close_order is not None:
            self._close_order.append("retrieval")

    def verify_startup_integrity(self) -> bool:
        self.startup_verifications += 1
        if self._startup_error is not None:
            raise RetrievalCapabilityUnavailable(self._startup_error)
        return False

    def generation_global_binding(self, **kwargs: object) -> object:
        del kwargs
        raise AssertionError("generation binding is not used by this routing test")

    def retrieve_generation_plan(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("generation retrieval is not used by this routing test")


class _CloseSessionSpy:
    def __init__(self, close_order: list[str]) -> None:
        self._close_order = close_order

    def close(self) -> None:
        self._close_order.append("sessions")


class _CloseConnectionSpy:
    def __init__(self, close_order: list[str]) -> None:
        self._close_order = close_order

    def close(self) -> None:
        self._close_order.append("connection")


class _UnavailableSpy:
    def invoke(
        self,
        tool_name: str,
        request: object,
        *,
        binding: BoundTransport | None,
    ) -> object:
        del tool_name, request, binding
        raise AssertionError("unused service")


class _RouteSpy:
    def __init__(self, name: str) -> None:
        self.name = name
        self.calls: list[str] = []

    def invoke(
        self,
        tool_name: str,
        request: object,
        *,
        binding: BoundTransport | None,
    ) -> object:
        del request, binding
        self.calls.append(tool_name)
        return {"routed_to": self.name}


class _KnowledgeRouteSpy(_RouteSpy):
    """Routing spy that preserves the complete rollback authority protocol."""

    def __init__(self, delegate: GlobalKnowledgeToolRuntime) -> None:
        super().__init__("knowledge")
        self._delegate = delegate

    @property
    def rollback_wiki_service(self) -> object:
        return self._delegate.rollback_wiki_service

    @property
    def rollback_theory_service(self) -> object:
        return self._delegate.rollback_theory_service

    @property
    def rollback_scope_policy_repository(self) -> object:
        return self._delegate.rollback_scope_policy_repository


def _migrated_workspace(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    shutil.copytree(Path.cwd() / "policies", repo / "policies")
    vault = tmp_path / "vault"
    (vault / "clients").mkdir(parents=True)
    (vault / "global").mkdir()
    connection = connect_database(
        vault / "global" / "catalog.sqlite3",
        mode="writer",
    )
    try:
        MigrationRunner.for_scope(connection, "global").apply()
        risk_policy = PolicyLoader.from_config(
            AppConfig.from_values(repo, vault)
        ).load_all().risk_rules
        insert_approved_risk_policy_epoch(
            connection,
            risk_policy,
            epoch=1,
            suffix=918_000,
        )
    finally:
        connection.close()
    return repo, vault


def test_session_runtime_resolves_only_an_exact_live_binding() -> None:
    manager = object.__new__(SessionRuntimeManager)
    manager._lock = threading.RLock()
    manager._by_handle = {}
    manager._by_client = {}
    live = _LiveSession(
        client_id="client_" + "aaaaaaaaaaaa",
        session_id="019f55c5-5e2c-7e20-bfe3-65480ce3bb0d",
        session_handle="opaque-session-handle-0001",
        capability_epoch=1,
        scope_marker_sha256="a" * 64,
        worker=cast(ScopedWorkerBroker, _AliveWorker()),
        start=cast(BeginSessionResponse, None),  # not inspected by this lookup
    )
    manager._by_handle[live.session_handle] = live

    assert manager.client_id_for_binding(
        BoundTransport("transport-1", live.session_handle)
    ) == live.client_id
    with pytest.raises(SessionScopeDenied, match="SCOPE_DENIED"):
        manager.client_id_for_binding(
            BoundTransport("transport-1", "opaque-session-handle-unknown")
        )


def test_production_open_routes_global_reads_and_graphs_to_active_retrieval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from consultation_kb.mcp import runtime as runtime_module

    repo, vault = _migrated_workspace(tmp_path)
    retrieval = _RetrievalSpy()
    captured: dict[str, object] = {}
    opened_databases: list[tuple[Path, str]] = []
    real_connect = runtime_module.connect_database

    def observed_connect(path: Path, mode: str) -> sqlite3.Connection:
        opened_databases.append((path.resolve(), mode))
        return real_connect(path, mode)  # type: ignore[arg-type]

    def build_retrieval(**kwargs: object) -> _RetrievalSpy:
        captured.update(kwargs)
        return retrieval

    monkeypatch.setattr(
        runtime_module,
        "build_active_retrieval_runtime",
        build_retrieval,
    )
    monkeypatch.setattr(runtime_module, "connect_database", observed_connect)
    monkeypatch.setattr(
        SessionRuntimeManager,
        "search_client_history",
        lambda self, request, *, binding: ({"routed_to": "session"},),
    )

    runtime = ProductionRuntime.open(config=AppConfig.from_values(repo, vault))
    binding = BoundTransport("transport-1", "opaque-session-handle-0001")
    try:
        history = runtime.handler_services.read.invoke(
            "search_client_history",
            SearchClientHistoryInput(
                session_handle=binding.session_handle,
                query="current profile",
            ),
            binding=binding,
        )
        wiki = runtime.handler_services.read.invoke(
            "search_wiki",
            SearchWikiInput(
                session_handle=binding.session_handle,
                query="relationship change",
            ),
            binding=binding,
        )
        graph = runtime.handler_services.graph.invoke(
            "query_global_graph",
            QueryGlobalGraphInput(
                session_handle=binding.session_handle,
                query="relationship change",
            ),
            binding=binding,
        )

        assert history == ({"routed_to": "session"},)
        assert wiki == {"routed_to": "retrieval", "tool": "search_wiki"}
        assert graph == {
            "routed_to": "retrieval",
            "tool": "query_global_graph",
        }
        assert retrieval.calls == [
            ("search_wiki", binding),
            ("query_global_graph", binding),
        ]
        assert captured["config"] == AppConfig.from_values(repo, vault)
        assert captured["connection"] is runtime._connection
        assert captured["client_scopes"] is runtime._sessions
        assert captured["embedder_provider"] is None
        assert captured["generation_c1_provider"] is None
        assert retrieval.startup_verifications == 1
        assert opened_databases == [
            ((vault / "global" / "catalog.sqlite3").resolve(), "writer")
        ]
        risk_evaluator = runtime._sessions._risk_evaluation
        assert isinstance(risk_evaluator, RiskEvaluationRuntime)
        assert risk_evaluator._model_draft_provider is None
    finally:
        runtime.close()
    assert retrieval.closed


def test_production_open_fails_before_handler_install_when_active_integrity_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from consultation_kb.mcp import runtime as runtime_module

    repo, vault = _migrated_workspace(tmp_path)
    retrieval = _RetrievalSpy(
        startup_error=ACTIVE_INTEGRITY_REBUILD_REQUIRED
    )
    monkeypatch.setattr(
        runtime_module,
        "build_active_retrieval_runtime",
        lambda **_kwargs: retrieval,
    )

    with pytest.raises(
        RuntimeCompositionError,
        match=f"^{ACTIVE_INTEGRITY_REBUILD_REQUIRED}$",
    ):
        ProductionRuntime.open(config=AppConfig.from_values(repo, vault))

    assert retrieval.startup_verifications == 1
    assert retrieval.closed


def test_production_open_injects_generation_and_risk_providers_explicitly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from consultation_kb.mcp import runtime as runtime_module

    repo, vault = _migrated_workspace(tmp_path)
    retrieval = _RetrievalSpy()
    captured: dict[str, object] = {}
    embedder = cast(VectorEmbedderProvider, object())
    c1_provider = cast(GenerationC1Provider, object())
    factory_clocks: list[object] = []
    risk_runtime_kwargs: dict[str, object] = {}

    class _RiskRuntimeSpy:
        def __init__(self, **kwargs: object) -> None:
            risk_runtime_kwargs.update(kwargs)

        def evaluate_turn(self, **_kwargs: object) -> tuple[object, ...]:
            return ()

        def current_authority(self) -> object:
            return object()

    def build_retrieval(**kwargs: object) -> _RetrievalSpy:
        captured.update(kwargs)
        return retrieval

    def build_c1(clock: object) -> GenerationC1Provider:
        factory_clocks.append(clock)
        return c1_provider

    def build_risk_model(_clock: object) -> RiskModelDraftProvider:
        raise AssertionError("RiskEvaluationRuntime owns factory invocation")

    monkeypatch.setattr(
        runtime_module,
        "build_active_retrieval_runtime",
        build_retrieval,
    )
    monkeypatch.setattr(runtime_module, "RiskEvaluationRuntime", _RiskRuntimeSpy)

    runtime = ProductionRuntime.open(
        config=AppConfig.from_values(repo, vault),
        embedder_provider=embedder,
        generation_c1_provider_factory=build_c1,
        risk_model_draft_provider_factory=build_risk_model,
    )
    try:
        assert captured["embedder_provider"] is embedder
        assert captured["generation_c1_provider"] is c1_provider
        assert len(factory_clocks) == 1
        assert isinstance(factory_clocks[0], SystemClock)
        assert risk_runtime_kwargs["config"] == AppConfig.from_values(repo, vault)
        assert isinstance(risk_runtime_kwargs["clock"], SystemClock)
        assert isinstance(risk_runtime_kwargs["id_factory"], IdFactory)
        assert (
            risk_runtime_kwargs["model_draft_provider_factory"]
            is build_risk_model
        )
    finally:
        runtime.close()

    assert retrieval.closed


def test_production_composition_shares_one_authority_set_for_client_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from consultation_kb.mcp import runtime as runtime_module

    repo, vault = _migrated_workspace(tmp_path)
    config = AppConfig.from_values(repo, vault)
    protector = TestProtector()
    vault_id = runtime_module.vault_security_id(vault)
    secret_path = vault / "security" / "review-agent-secret.dpapi"
    secret_path.parent.mkdir()
    secret_path.write_bytes(
        protector.protect(
            b"p" * 32,
            purpose="review_agent_hmac",
            vault_id=vault_id,
        )
    )
    knowledge: _KnowledgeRouteSpy | None = None
    client_creation = _RouteSpy("client_creation")
    captured: dict[str, dict[str, object]] = {}
    real_build_knowledge = runtime_module.build_global_knowledge_runtime

    def build_knowledge(**kwargs: object) -> _KnowledgeRouteSpy:
        nonlocal knowledge
        captured["knowledge"] = kwargs
        delegate = real_build_knowledge(**kwargs)  # type: ignore[arg-type]
        knowledge = _KnowledgeRouteSpy(delegate)
        return knowledge

    def build_client_creation(**kwargs: object) -> _RouteSpy:
        captured["client_creation"] = kwargs
        return client_creation

    monkeypatch.setattr(
        runtime_module,
        "create_secret_protector",
        lambda: protector,
    )
    monkeypatch.setattr(
        runtime_module,
        "build_global_knowledge_runtime",
        build_knowledge,
    )
    monkeypatch.setattr(
        runtime_module,
        "build_production_client_creation_runtime",
        build_client_creation,
    )
    connection = connect_database(
        vault / "global" / "catalog.sqlite3",
        mode="writer",
    )
    try:
        configured = runtime_module._configured_knowledge_runtime(
            config=config,
            connection=connection,
            clock=SystemClock(),
            ids=IdFactory(),
            publication_builders=cast(GlobalPublicationBuilders, object()),
        )
    finally:
        connection.close()

    assert configured is not None
    assert knowledge is not None
    assert configured.knowledge is knowledge
    assert configured.client_creation is client_creation
    archive_approvals = configured.archive_approval_factory("d" * 64)
    assert archive_approvals.target_scope_hash == "d" * 64
    assert len(configured.execution_attestor_secret) == 32
    assert configured.execution_attestor_id == "target-approval-execution"
    knowledge_args = captured["knowledge"]
    creation_args = captured["client_creation"]
    assert creation_args["approval_service"] is knowledge_args["approval_service"]
    assert (
        creation_args["execution_guard"]
        is knowledge_args["publication_execution_guard"]
    )
    assert creation_args["content_store"] is knowledge_args["content_store"]
    assert creation_args["id_factory"] is knowledge_args["id_factory"]
    assert creation_args["clock"] is knowledge_args["clock"]
    assert creation_args["protector"] is protector
    assert creation_args["vault_id"] == vault_id
    protected_store = creation_args["protected_secret_store"]
    assert getattr(protected_store, "_protector") is protector
    assert getattr(protected_store, "_vault_id") == vault_id

    router = runtime_module._FormalWriteRouter(knowledge, client_creation)
    request = cast(StrictModel, object())
    assert router.invoke("create_client", request, binding=None) == {
        "routed_to": "client_creation"
    }
    assert router.invoke("approve_claim", request, binding=None) == {
        "routed_to": "knowledge"
    }
    assert client_creation.calls == ["create_client"]
    assert knowledge.calls == ["approve_claim"]


def test_production_close_orders_retrieval_before_sessions_and_database() -> None:
    order: list[str] = []
    retrieval = _RetrievalSpy(order)
    unavailable = cast(ToolService, _UnavailableSpy())
    runtime = ProductionRuntime(
        connection=cast(sqlite3.Connection, _CloseConnectionSpy(order)),
        sessions=cast(SessionRuntimeManager, _CloseSessionSpy(order)),
        retrieval=cast(ActiveRetrievalRuntime, retrieval),
        services=HandlerServices(
            read=unavailable,
            graph=unavailable,
            session=unavailable,
            knowledge=unavailable,
            write=unavailable,
        ),
        knowledge_available=False,
    )

    runtime.close()
    runtime.close()

    assert order == ["retrieval", "sessions", "connection"]


def test_production_runtime_has_no_synthetic_vector_provider(
    tmp_path: Path,
) -> None:
    repo, vault = _migrated_workspace(tmp_path)
    runtime = ProductionRuntime.open(config=AppConfig.from_values(repo, vault))
    try:
        assert runtime._retrieval._embedder_provider is None
        with pytest.raises(RetrievalCapabilityUnavailable) as error:
            runtime._retrieval._vector(cast(ArtifactBinding, None))
    finally:
        runtime.close()

    assert error.value.code == "VECTOR_MODEL_UNAVAILABLE"
