"""Owned production composition for the local consultation MCP lifespan.

The control process owns only the global catalog and capability records.
Client databases remain behind :class:`ScopedWorkerBroker`, reached through
``SessionRuntimeManager``.  Retrieval channels without an activated P4
artifact fail closed instead of returning a misleading empty result.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import threading
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Callable
from typing import cast, final

from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.provider import ProtectedProviderSecretStore
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.archive.provenance import CaseContributorHasher
from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.config import AppConfig
from consultation_kb.core.errors import ChannelUnavailableError
from consultation_kb.core.ids import IdFactory
from consultation_kb.evaluation.runtime import EvaluationRuntime
from consultation_kb.knowledge.approval import P1GovernedWriteExecutor
from consultation_kb.lifecycle.recovery import RecoveryCoordinator, RecoveryError
from consultation_kb.lifecycle.rollback import SqliteRollbackWorkflow
from consultation_kb.lifecycle.sqlite_recovery import (
    SqliteRecoveryBackend,
    global_database_reference,
)
from consultation_kb.lifecycle.whole_client_cleanup import (
    WholeClientCleanupCoordinator,
)
from consultation_kb.lifecycle.whole_client_saga import (
    WholeClientDeletionSaga,
)
from consultation_kb.models.common import StrictModel
from consultation_kb.publication.global_knowledge import GlobalPublicationBuilders
from consultation_kb.security.capability import CapabilityService
from consultation_kb.security.dpapi import create_secret_protector
from consultation_kb.security.scope_broker import ScopeBroker
from consultation_kb.security.scope_identity import global_approval_scope_sha256
from consultation_kb.storage.catalog import ClientCatalog
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore
from consultation_kb.vault.layout import VaultLayout

from .context import BoundTransport, HandlerServices, ToolService
from .global_lifecycle_runtime import (
    ProductionGlobalLifecycleRuntime,
    TargetScopedDeletionAuthority,
)
from .evaluation_tools import EvaluationToolRuntime
from .client_creation_runtime import (
    ClientCreationRuntime,
    build_production_client_creation_runtime,
    vault_security_id,
)
from .knowledge_runtime import (
    GlobalKnowledgeToolRuntime,
    build_global_knowledge_runtime,
)
from .retrieval_runtime import (
    ActiveRetrievalRuntime,
    GenerationC1Provider,
    RetrievalCapabilityUnavailable,
    VectorEmbedderProvider,
    build_active_retrieval_runtime,
)
from .risk_runtime import (
    RiskEvaluationRuntime,
    RiskEvaluationRuntimeError,
    RiskModelDraftProviderFactory,
)
from .schemas import SearchClientHistoryInput
from .session_runtime import SessionRuntimeManager


_REPARSE_ATTRIBUTE = int(
    getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
)


class RuntimeCompositionError(RuntimeError):
    """Content-free startup failure safe for stderr diagnostics."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RuntimeChannelUnavailable(ChannelUnavailableError):
    """A channel has no activated artifact or configured authority service."""


GenerationC1ProviderFactory = Callable[[Clock], GenerationC1Provider]


def _is_reparse(status: os.stat_result) -> bool:
    return stat.S_ISLNK(status.st_mode) or bool(
        int(getattr(status, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
    )


def _require_plain_directory(path: Path, code: str) -> None:
    try:
        status = os.lstat(path)
    except OSError:
        raise RuntimeCompositionError(code) from None
    if not stat.S_ISDIR(status.st_mode) or _is_reparse(status):
        raise RuntimeCompositionError(code)


def _require_plain_file(path: Path, code: str) -> None:
    try:
        status = os.lstat(path)
    except OSError:
        raise RuntimeCompositionError(code) from None
    if (
        not stat.S_ISREG(status.st_mode)
        or _is_reparse(status)
        or int(status.st_nlink) != 1
    ):
        raise RuntimeCompositionError(code)


@final
class _UnavailableToolRuntime:
    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object:
        del tool_name, request, binding
        raise RuntimeChannelUnavailable


@final
class _UnavailableCreationRuntime:
    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object:
        del tool_name, request, binding
        raise ChannelUnavailableError()


@final
class _ReadToolRuntime:
    _RETRIEVAL_TOOLS = frozenset(
        {"search_wiki", "search_lexical", "search_vector", "search_cases"}
    )

    def __init__(
        self,
        sessions: SessionRuntimeManager,
        retrieval: ActiveRetrievalRuntime,
    ) -> None:
        self._sessions = sessions
        self._retrieval = retrieval

    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object:
        if tool_name == "search_client_history":
            return self._sessions.search_client_history(
                cast(SearchClientHistoryInput, request),
                binding=binding,
            )
        if tool_name in self._RETRIEVAL_TOOLS:
            return self._retrieval.invoke(tool_name, request, binding=binding)
        raise RuntimeChannelUnavailable


@final
class _FormalWriteRouter:
    def __init__(
        self,
        knowledge: ToolService,
        client_creation: ToolService,
    ) -> None:
        self._knowledge = knowledge
        self._client_creation = client_creation

    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object:
        if tool_name == "create_client":
            return self._client_creation.invoke(
                tool_name,
                request,
                binding=binding,
            )
        return self._knowledge.invoke(tool_name, request, binding=binding)


@dataclass(frozen=True, slots=True)
class _ConfiguredGlobalRuntimes:
    knowledge: GlobalKnowledgeToolRuntime
    client_creation: ClientCreationRuntime | None
    content_store: ContentStore
    archive_approval_factory: Callable[[str], ApprovalService]
    deletion_approval_factory: Callable[
        [str], TargetScopedDeletionAuthority
    ]
    execution_attestor_secret: bytes
    execution_attestor_id: str
    approval_service: ApprovalService
    execution_guard: ApprovalExecutionGuard
    rollback_workflow: SqliteRollbackWorkflow


def _configured_knowledge_runtime(
    *,
    config: AppConfig,
    connection: sqlite3.Connection,
    clock: SystemClock,
    ids: IdFactory,
    publication_builders: GlobalPublicationBuilders | None = None,
) -> _ConfiguredGlobalRuntimes | None:
    """Build both global writers from one exact protected authority set."""

    secret_path = config.vault_root / "security" / "review-agent-secret.dpapi"
    if not secret_path.exists():
        return None
    vault_id = vault_security_id(config.vault_root)
    try:
        # All global authority-changing channels share this one protected
        # capability.  If it cannot be established, keep the MCP read/session
        # process alive and expose both writers as unavailable.  Database,
        # migration, and required vault-layout checks occur outside this
        # optional-authority boundary and therefore still fail startup.
        _require_plain_file(secret_path, "MCP_APPROVAL_SECRET_INVALID")
        protector = create_secret_protector()
        secrets_store = ProtectedProviderSecretStore(
            secret_path,
            protector=protector,
            vault_id=vault_id,
        )
        provider_verifier = secrets_store.load_verifier()
        execution_secret = secrets_store.load_execution_secret()
        proof_verifier = secrets_store.load_target_execution_proof_verifier()
        execution_attestor_secret = (
            secrets_store.load_target_execution_attestation_secret()
        )
        execution_attestor_id = "target-approval-execution"
        approval_service = ApprovalService(
            connection,
            provider=provider_verifier,
            protector=protector,
            clock=clock,
            id_factory=ids,
            target_scope_hash=global_approval_scope_sha256(config.vault_root),
            vault_id=vault_id,
            execution_secret=execution_secret,
            execution_proof_verifier=proof_verifier,
        )
        execution_guard = ApprovalExecutionGuard(
            connection,
            approval_service=approval_service,
            execution_proof_signer=(
                secrets_store.load_target_execution_attestor()
            ),
            clock=clock,
        )
    except Exception:
        return None
    executor = P1GovernedWriteExecutor(
        approval_service=approval_service,
        execution_guard=execution_guard,
        id_factory=ids,
    )
    content_store = ContentStore(config.vault_root / "global")
    knowledge = build_global_knowledge_runtime(
        config=config,
        connection=connection,
        content_store=content_store,
        approval_service=approval_service,
        approval_executor=executor,
        id_factory=ids,
        clock=clock,
        publication_builders=publication_builders,
        publication_execution_guard=(
            execution_guard if publication_builders is not None else None
        ),
    )
    rollback_workflow = SqliteRollbackWorkflow(
        connection,
        database_scope="global",
        scope_sha256=global_approval_scope_sha256(config.vault_root),
        content_store=content_store,
        approval_guard=execution_guard,
        wiki_service=knowledge.rollback_wiki_service,
        theory_service=knowledge.rollback_theory_service,
        scope_policy_repository=(
            knowledge.rollback_scope_policy_repository
        ),
        clock=clock,
        id_factory=ids,
    )
    try:
        client_creation: ClientCreationRuntime | None = (
            build_production_client_creation_runtime(
                config=config,
                connection=connection,
                approval_service=approval_service,
                execution_guard=execution_guard,
                protector=protector,
                protected_secret_store=secrets_store,
                content_store=content_store,
                vault_id=vault_id,
                clock=clock,
                id_factory=ids,
            )
        )
    except ChannelUnavailableError:
        client_creation = None

    def deletion_approval_factory(
        scope_hash: str,
    ) -> TargetScopedDeletionAuthority:
        service = ApprovalService(
            connection,
            provider=provider_verifier,
            protector=protector,
            clock=clock,
            id_factory=ids,
            target_scope_hash=scope_hash,
            vault_id=vault_id,
            execution_secret=execution_secret,
            execution_proof_verifier=proof_verifier,
        )
        return TargetScopedDeletionAuthority(
            approval_service=service,
            execution_guard=ApprovalExecutionGuard(
                connection,
                approval_service=service,
                execution_proof_signer=(
                    secrets_store.load_target_execution_attestor()
                ),
                clock=clock,
            ),
        )

    return _ConfiguredGlobalRuntimes(
        knowledge=knowledge,
        client_creation=client_creation,
        content_store=content_store,
        archive_approval_factory=lambda scope_hash: ApprovalService(
            connection,
            provider=provider_verifier,
            protector=protector,
            clock=clock,
            id_factory=ids,
            target_scope_hash=scope_hash,
            vault_id=vault_id,
            execution_secret=execution_secret,
            execution_proof_verifier=proof_verifier,
        ),
        deletion_approval_factory=deletion_approval_factory,
        execution_attestor_secret=execution_attestor_secret,
        execution_attestor_id=execution_attestor_id,
        approval_service=approval_service,
        execution_guard=execution_guard,
        rollback_workflow=rollback_workflow,
    )


@final
class ProductionRuntime:
    """One idempotently closeable set of services for a single MCP process."""

    def __init__(
        self,
        *,
        connection: sqlite3.Connection,
        sessions: SessionRuntimeManager,
        retrieval: ActiveRetrievalRuntime,
        services: HandlerServices,
        knowledge_available: bool,
        client_creation_available: bool = False,
    ) -> None:
        self._connection = connection
        self._sessions = sessions
        self._retrieval = retrieval
        self._services = services
        self._knowledge_available = knowledge_available
        self._client_creation_available = client_creation_available
        self._closed = False
        self._close_lock = threading.Lock()

    @classmethod
    def open(
        cls,
        *,
        config: AppConfig | None = None,
        publication_builders: GlobalPublicationBuilders | None = None,
        embedder_provider: VectorEmbedderProvider | None = None,
        generation_c1_provider_factory: GenerationC1ProviderFactory | None = None,
        risk_model_draft_provider_factory: RiskModelDraftProviderFactory | None = None,
    ) -> ProductionRuntime:
        selected = config
        if selected is None:
            selected = AppConfig.load(repo_root=Path.cwd())
        elif type(selected) is not AppConfig:
            raise TypeError("production runtime requires AppConfig")
        layout = VaultLayout.from_config(selected)  # type: ignore[attr-defined]
        _require_plain_directory(selected.vault_root, "MCP_VAULT_UNAVAILABLE")
        _require_plain_directory(layout.clients_root, "MCP_CLIENTS_UNAVAILABLE")
        _require_plain_directory(layout.global_db.parent, "MCP_GLOBAL_UNAVAILABLE")
        _require_plain_file(layout.global_db, "MCP_DATABASE_UNAVAILABLE")

        clock = SystemClock()
        try:
            startup_recovery = RecoveryCoordinator(
                backend=SqliteRecoveryBackend(
                    database=layout.global_db,
                    content_store=ContentStore(layout.global_db.parent),
                    database_scope="global",
                    database_ref_sha256=global_database_reference(
                        selected.vault_root
                    ),
                    clock=clock,
                ),
                clock=clock,
            )
            startup_report = startup_recovery.recover()
            startup_recovery.require_query_ready(startup_report.scan)
        except RecoveryError as error:
            raise RuntimeCompositionError(error.code) from None
        except Exception:
            raise RuntimeCompositionError("MCP_RECOVERY_FAILED") from None

        connection = connect_database(layout.global_db, mode="writer")
        retrieval: ActiveRetrievalRuntime | None = None
        try:
            MigrationRunner.for_scope(connection, "global").check()
            ids = IdFactory(clock)
            catalog = ClientCatalog(connection)
            capabilities = CapabilityService(
                connection,
                catalog=catalog,
                clock=clock,
                id_factory=ids,
            )
            scopes = ScopeBroker(
                capability_service=capabilities,
                catalog=catalog,
                clients_root=layout.clients_root,
                global_database=layout.global_db,
            )
            sessions = SessionRuntimeManager(
                catalog=catalog,
                capability_service=capabilities,
                scope_broker=scopes,
                clock=clock,
                id_factory=ids,
            )
            unavailable = _UnavailableToolRuntime()
            unavailable_creation = _UnavailableCreationRuntime()
            configured = _configured_knowledge_runtime(
                config=selected,
                connection=connection,
                clock=clock,
                ids=ids,
                publication_builders=publication_builders,
            )
            sessions.configure_global_lifecycle(
                ProductionGlobalLifecycleRuntime(
                    connection,
                    global_root=layout.global_db.parent.resolve(strict=False),
                    scope_sha256=global_approval_scope_sha256(
                        selected.vault_root
                    ),
                    approval_service=(
                        None if configured is None else configured.approval_service
                    ),
                    execution_guard=(
                        None if configured is None else configured.execution_guard
                    ),
                    rollback_workflow=(
                        None
                        if configured is None
                        else configured.rollback_workflow
                    ),
                    target_approval_factory=(
                        None
                        if configured is None
                        else configured.deletion_approval_factory
                    ),
                    content_store=(
                        None if configured is None else configured.content_store
                    ),
                    clock=clock,
                    id_factory=ids,
                )
            )
            if configured is not None:
                sessions.configure_archive_approval(
                    approval_factory=configured.archive_approval_factory,
                    execution_attestor_secret=(
                        configured.execution_attestor_secret
                    ),
                    execution_attestor_id=configured.execution_attestor_id,
                )
                sessions.configure_case_publication(
                    connection=connection,
                    content_store=configured.content_store,
                )
                if configured.client_creation is not None:
                    contributor_hasher = CaseContributorHasher(
                        hash_key=configured.execution_attestor_secret
                    )
                    cleanup = WholeClientCleanupCoordinator(
                        lambda: connect_database(
                            layout.global_db,
                            mode="writer",
                        ),
                        global_database_path=layout.global_db,
                        clients_root=layout.clients_root,
                        contributor_hasher=contributor_hasher,
                        quiescer=sessions,
                        identity_registry=(
                            configured.client_creation.lifecycle_identity_registry
                        ),
                        clock=clock.now,
                    )
                    whole_client_saga = WholeClientDeletionSaga(
                        connection,
                        content_store=configured.content_store,
                        approval_factory=configured.deletion_approval_factory,
                        contributor_hasher=contributor_hasher,
                        quiescer=sessions,
                        clock=clock,
                        id_factory=ids,
                        cleanup_coordinator=cleanup,
                    )
                    sessions.configure_whole_client_lifecycle(
                        whole_client_saga
                    )
                    whole_client_saga.recover_pending_cleanup()
            generation_c1_provider = (
                None
                if generation_c1_provider_factory is None
                else generation_c1_provider_factory(clock)
            )
            retrieval = build_active_retrieval_runtime(
                config=selected,
                connection=connection,
                client_scopes=sessions,
                clock=clock,
                id_factory=ids,
                embedder_provider=embedder_provider,
                generation_c1_provider=generation_c1_provider,
                case_contributor_hash_key=(
                    None
                    if configured is None
                    else configured.execution_attestor_secret
                ),
            )
            try:
                retrieval.verify_startup_integrity()
            except RetrievalCapabilityUnavailable as error:
                raise RuntimeCompositionError(error.code) from None
            sessions.configure_generation_retrieval(retrieval)
            risk_runtime = RiskEvaluationRuntime(
                config=selected,
                clock=clock,
                id_factory=ids,
                model_draft_provider_factory=risk_model_draft_provider_factory,
            )
            try:
                # Risk policy/model manifests have an independent version
                # domain and a dedicated resolver.  Validate that exact
                # closure before making any MCP handler available.
                risk_runtime.current_authority()
            except RiskEvaluationRuntimeError as error:
                raise RuntimeCompositionError(error.code) from None
            sessions.configure_risk_evaluation(risk_runtime)
            knowledge_service: ToolService = (
                unavailable if configured is None else configured.knowledge
            )
            client_creation_service: ToolService = (
                unavailable_creation
                if configured is None or configured.client_creation is None
                else configured.client_creation
            )
            services = HandlerServices(
                read=_ReadToolRuntime(sessions, retrieval),
                graph=retrieval,
                session=sessions,
                knowledge=knowledge_service,
                write=_FormalWriteRouter(
                    knowledge_service,
                    client_creation_service,
                ),
                evaluation=EvaluationToolRuntime(
                    EvaluationRuntime(
                        repo_root=selected.repo_root,
                        vault_root=selected.vault_root,
                    )
                ),
            )
            return cls(
                connection=connection,
                sessions=sessions,
                retrieval=retrieval,
                services=services,
                knowledge_available=configured is not None,
                client_creation_available=(
                    configured is not None
                    and configured.client_creation is not None
                ),
            )
        except BaseException:
            if retrieval is not None:
                retrieval.close()
            connection.close()
            raise

    @property
    def handler_services(self) -> HandlerServices:
        return self._services

    @property
    def is_closed(self) -> bool:
        return self._closed

    @property
    def knowledge_available(self) -> bool:
        return self._knowledge_available

    @property
    def client_creation_available(self) -> bool:
        return self._client_creation_available

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        try:
            self._retrieval.close()
        finally:
            try:
                self._sessions.close()
            finally:
                self._connection.close()


__all__ = [
    "ProductionRuntime",
    "RuntimeChannelUnavailable",
    "RuntimeCompositionError",
]
