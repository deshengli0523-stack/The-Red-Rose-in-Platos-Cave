"""Production MCP adapter for capability-bound consultation sessions."""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol, cast, final

from consultation_kb.core.clock import Clock
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.archive.case_publisher import SharedCasePublisher
from consultation_kb.archive.publication_proof import (
    LocalHmacCasePublicationProofSigner,
)
from consultation_kb.core.errors import (
    ChannelUnavailableError,
    ScopedObjectAccessDeniedError,
    WorkflowOperationalError,
)
from consultation_kb.core.ids import IdFactory
from consultation_kb.generation.c1_context import C1ApplicabilityInput
from consultation_kb.generation.contracts import QueryPlan
from consultation_kb.generation.evidence_registry import GenerationRiskContextBinding
from consultation_kb.generation.retrieval_orchestrator import (
    GenerationRetrievalOutcome,
)
from consultation_kb.mcp.context import BoundTransport
from consultation_kb.mcp.retrieval_runtime import GenerationGlobalBinding
from consultation_kb.mcp.schemas import (
    AcknowledgeRiskObservationInput,
    ApproveCaseInput,
    AppendSessionTurnInput,
    AppendTemporaryFactInput,
    CancelRebuildInput,
    CommitDeleteInput,
    CommitPrivateArchiveInput,
    CommitProfileUpdateInput,
    GetRebuildReportInput,
    GetRebuildStatusInput,
    LoadClientContextInput,
    GetGenerationStateInput,
    PreviewDependencyImpactInput,
    PreviewDeleteInput,
    PreviewRebuildInput,
    RollbackVersionInput,
    PreviewPrivateArchiveInput,
    PreviewProfileDiffInput,
    ProposeArchiveInput,
    QueryClientGraphInput,
    RecordActualReplyInput,
    SearchClientHistoryInput,
    StoreCandidateSetInput,
    StartRebuildInput,
    SubmitGenerationStageInput,
    WeightedPathInput,
)
from consultation_kb.models.common import StrictModel, VersionRef
from consultation_kb.models.evidence import EvidencePack
from consultation_kb.models.deletion import DeletionBaseVersion
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.session import CandidateDraft
from consultation_kb.lifecycle.whole_client_cleanup import (
    ClientQuiescenceProof,
    client_quiescence_proof_sha256,
)
from consultation_kb.lifecycle.whole_client_saga import (
    WholeClientDeletionCommit,
    WholeClientDeletionPreview,
)
from consultation_kb.security.capability import CapabilityService
from consultation_kb.security.scope_broker import ScopeBroker
from consultation_kb.security.scoped_worker import ScopedWorkerBroker
from consultation_kb.security.worker_protocol import (
    AcknowledgeRiskObservationRequest,
    AcknowledgeRiskObservationResponse,
    ArchiveContentRef,
    AppendClientTurnRequest,
    AppendClientTurnResponse,
    AppendTemporaryFactRequest,
    AppendTemporaryFactResponse,
    BeginGenerationRequest,
    BeginSessionRequest,
    BeginSessionResponse,
    BuildPrivateArchiveRequest,
    BuildPrivateArchiveResponse,
    BuildProfileDiffRequest,
    BuildProfileDiffResponse,
    ClientHistoryQueryCategory,
    CommitClientTombstoneRequest,
    CommitClientTombstoneResponse,
    CommitClientRollbackRequest,
    CommitClientRollbackResponse,
    CommitPrivateArchiveRequest,
    CommitPrivateArchiveResponse,
    CommitProfileUpdateRequest,
    CommitProfileUpdateResponse,
    GetGenerationStateRequest,
    GetGenerationStateResponse,
    GetGenerationBindingRequest,
    GetGenerationBindingResponse,
    GenerationClientBinding,
    GetGenerationEvidenceForPlanRequest,
    GetGenerationEvidenceForPlanResponse,
    QueryClientHistoryCandidatesRequest,
    QueryClientHistoryCandidatesResponse,
    QueryClientWeightedPathRequest,
    QueryClientWeightedPathResponse,
    ReadSessionStateRequest,
    ReadSessionStateResponse,
    RecordActualReplyRequest,
    RecordActualReplyResponse,
    RebuildClientDerivativesRequest,
    RebuildClientDerivativesResponse,
    ResumeSessionRequest,
    ResumeSessionResponse,
    SearchClientGraphRequest,
    SearchClientGraphResponse,
    PreviewTargetDependencyImpactRequest,
    PreviewTargetDependencyImpactResponse,
    PrepareGenerationRetrievalRequest,
    PrepareGenerationRetrievalResponse,
    PrepareTurnRiskEvaluationRequest,
    PrepareTurnRiskEvaluationResponse,
    PreviewClientDeleteRequest,
    PreviewClientDeleteResponse,
    PreviewClientRebuildRequest,
    PreviewClientRebuildResponse,
    PreviewClientRollbackRequest,
    PreviewClientRollbackResponse,
    PersistRiskObservationsRequest,
    PersistRiskObservationsResponse,
    PreflightClientLifecycleCommitRequest,
    PreflightClientLifecycleCommitResponse,
    PrivateGenerationEvidence,
    StoreCandidateSetRequest,
    StoreCandidateSetResponse,
    StoreGenerationEvidencePackRequest,
    StoreGenerationEvidencePackResponse,
    StageSharedCaseOutboxRequest,
    StageSharedCaseOutboxResponse,
    SubmitGenerationStageRequest,
    SubmitGenerationStageResponse,
    WorkerBaseVersion,
    record_actual_reply_response_matches_request,
    risk_lifecycle_response_matches_request,
    submit_generation_stage_response_matches_request,
)
from consultation_kb.storage.catalog import ClientCatalog, ClientCatalogError
from consultation_kb.storage.outbox import OutboxRecord
from consultation_kb.vault.content_store import ContentStore
from consultation_kb.risk.repository import (
    InternalRiskObservationRecord,
    RiskEvaluationAuthorityBinding,
    canonical_risk_observation_set_sha256,
)
from consultation_kb.risk.text_normalization import normalized_sensitive_fingerprint


_PERMISSIONS = frozenset(
    {"client_read", "session_append", "draft_write", "formal_write"}
)


class SessionRuntimeError(RuntimeError):
    """Fixed-code, content-free session composition failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class SessionScopeDenied(ScopedObjectAccessDeniedError):
    """Uniform unknown/cross-scope session denial."""


class GenerationRetrievalRuntime(Protocol):
    def generation_global_binding(
        self,
        *,
        binding: BoundTransport | None,
    ) -> GenerationGlobalBinding: ...

    def retrieve_generation_plan(
        self,
        plan: QueryPlan,
        client_binding: GenerationClientBinding,
        private_evidence: tuple[PrivateGenerationEvidence, ...],
        *,
        binding: BoundTransport | None,
        revalidate_binding: Callable[[], GenerationClientBinding],
        c1_applicability_input: C1ApplicabilityInput,
        risk_context_binding: GenerationRiskContextBinding,
    ) -> GenerationRetrievalOutcome: ...


class TurnRiskEvaluationRuntime(Protocol):
    def current_authority(self) -> RiskEvaluationAuthorityBinding: ...

    def evaluate_turn(
        self,
        *,
        session_id: str,
        turn_id: str,
        content_ref: VersionRef,
        text: str,
        approved_context_keys: frozenset[str],
        authority: RiskEvaluationAuthorityBinding | None = None,
    ) -> tuple[InternalRiskObservationRecord, ...]: ...


class GlobalLifecycleRuntime(Protocol):
    """Global-only lifecycle adapter; it never receives a client root."""

    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object: ...


class WholeClientLifecycleRuntime(Protocol):
    """Current-client adapter; the public request never carries its identity."""

    def preview(
        self,
        *,
        bound_client_id: str,
        reason_code: str,
    ) -> WholeClientDeletionPreview: ...

    def commit(
        self,
        *,
        bound_client_id: str,
        plan_ref: ArchiveContentRef,
        plan_sha256: str,
        target_scope_hash: str,
        base_versions: tuple[DeletionBaseVersion, ...],
        approval_operation_id: str,
        approval_request_id: str,
    ) -> WholeClientDeletionCommit: ...


@dataclass(slots=True)
class _LiveSession:
    client_id: str
    session_id: str
    session_handle: str
    capability_epoch: int
    scope_marker_sha256: str
    worker: ScopedWorkerBroker
    start: BeginSessionResponse | ResumeSessionResponse
    archive_approvals: ApprovalService | None = None


@final
class SessionRuntimeManager:
    """Own live workers while keeping client databases out of the MCP process."""

    def __init__(
        self,
        *,
        catalog: ClientCatalog,
        capability_service: CapabilityService,
        scope_broker: ScopeBroker,
        clock: Clock,
        id_factory: IdFactory,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        self._catalog = catalog
        self._capabilities = capability_service
        self._scopes = scope_broker
        self._clock = clock
        self._ids = id_factory
        self._fault = fault_injector or (lambda _point: None)
        self._lock = threading.RLock()
        self._by_handle: dict[str, _LiveSession] = {}
        self._by_client: dict[str, _LiveSession] = {}
        self._generation_retrieval: GenerationRetrievalRuntime | None = None
        self._risk_evaluation: TurnRiskEvaluationRuntime | None = None
        self._global_lifecycle: GlobalLifecycleRuntime | None = None
        self._whole_client_lifecycle: WholeClientLifecycleRuntime | None = None
        self._archive_approval_factory: Callable[[str], ApprovalService] | None = None
        self._archive_execution_attestor_secret: bytes | None = None
        self._archive_execution_attestor_id: str | None = None
        self._case_publication_connection: sqlite3.Connection | None = None
        self._case_publication_store: ContentStore | None = None
        self._private_archive_previews: dict[
            tuple[str, str], BuildPrivateArchiveResponse
        ] = {}

    def configure_generation_retrieval(
        self,
        runtime: GenerationRetrievalRuntime,
    ) -> None:
        """Bind the sole global-only generation retrieval runtime once."""

        if not callable(getattr(runtime, "generation_global_binding", None)):
            raise TypeError("GENERATION_RETRIEVAL_RUNTIME_REQUIRED")
        with self._lock:
            if self._generation_retrieval is not None:
                raise RuntimeError("GENERATION_RETRIEVAL_RUNTIME_ALREADY_CONFIGURED")
            self._generation_retrieval = runtime

    def configure_risk_evaluation(
        self,
        runtime: TurnRiskEvaluationRuntime,
    ) -> None:
        """Bind the global-only deterministic risk evaluator once."""

        if (
            not callable(getattr(runtime, "current_authority", None))
            or not callable(getattr(runtime, "evaluate_turn", None))
        ):
            raise TypeError("RISK_EVALUATION_RUNTIME_REQUIRED")
        with self._lock:
            if self._risk_evaluation is not None:
                raise RuntimeError("RISK_EVALUATION_RUNTIME_ALREADY_CONFIGURED")
            self._risk_evaluation = runtime

    def configure_global_lifecycle(
        self,
        runtime: GlobalLifecycleRuntime,
    ) -> None:
        """Install one global adapter without granting it scoped client paths."""

        if not callable(getattr(runtime, "invoke", None)):
            raise TypeError("GLOBAL_LIFECYCLE_RUNTIME_REQUIRED")
        with self._lock:
            if self._global_lifecycle is not None or self._by_handle:
                raise RuntimeError("GLOBAL_LIFECYCLE_RUNTIME_ALREADY_CONFIGURED")
            self._global_lifecycle = runtime

    def configure_whole_client_lifecycle(
        self,
        runtime: WholeClientLifecycleRuntime,
    ) -> None:
        """Install the sole internal current-client deletion saga."""

        if not callable(getattr(runtime, "preview", None)) or not callable(
            getattr(runtime, "commit", None)
        ):
            raise TypeError("WHOLE_CLIENT_LIFECYCLE_RUNTIME_REQUIRED")
        with self._lock:
            if self._whole_client_lifecycle is not None or self._by_handle:
                raise RuntimeError(
                    "WHOLE_CLIENT_LIFECYCLE_RUNTIME_ALREADY_CONFIGURED"
                )
            self._whole_client_lifecycle = runtime

    def configure_archive_approval(
        self,
        *,
        approval_factory: Callable[[str], ApprovalService],
        execution_attestor_secret: bytes,
        execution_attestor_id: str,
    ) -> None:
        """Install the existing protected P1 authority for client archives.

        The factory receives only the worker-authoritative scope-marker hash.
        No key, nonce, receipt, or execution ticket crosses the MCP boundary.
        """

        if (
            not callable(approval_factory)
            or type(execution_attestor_secret) is not bytes
            or len(execution_attestor_secret) != 32
            or type(execution_attestor_id) is not str
            or not execution_attestor_id
        ):
            raise TypeError("ARCHIVE_APPROVAL_AUTHORITY_INVALID")
        with self._lock:
            if self._archive_approval_factory is not None or self._by_handle:
                raise RuntimeError("ARCHIVE_APPROVAL_AUTHORITY_ALREADY_CONFIGURED")
            self._archive_approval_factory = approval_factory
            self._archive_execution_attestor_secret = bytes(
                execution_attestor_secret
            )
            self._archive_execution_attestor_id = execution_attestor_id

    def configure_case_publication(
        self,
        *,
        connection: sqlite3.Connection,
        content_store: ContentStore,
    ) -> None:
        """Bind the global-only publisher without granting client DB access."""

        if not isinstance(connection, sqlite3.Connection) or not isinstance(
            content_store, ContentStore
        ):
            raise TypeError("CASE_PUBLICATION_RUNTIME_INVALID")
        with self._lock:
            if self._case_publication_connection is not None or self._by_handle:
                raise RuntimeError("CASE_PUBLICATION_RUNTIME_ALREADY_CONFIGURED")
            self._case_publication_connection = connection
            self._case_publication_store = content_store

    def _request_id(self) -> str:
        return self._ids.uuid7()

    def _start_worker(
        self,
        *,
        client_id: str,
        session_id: str,
        session_handle: str,
    ) -> tuple[ScopedWorkerBroker, int, str, ApprovalService | None]:
        scoped = self._scopes.authorize(
            session_handle,
            session_id=session_id,
            client_id=client_id,
            required_permissions=_PERMISSIONS,
        )
        approvals = (
            None
            if self._archive_approval_factory is None
            else self._archive_approval_factory(scoped.scope_marker_sha256)
        )
        if approvals is not None and not isinstance(approvals, ApprovalService):
            raise TypeError("ARCHIVE_APPROVAL_AUTHORITY_INVALID")
        worker = ScopedWorkerBroker.for_scoped_session(
            session=scoped,
            capability_token=session_handle,
            capability_service=self._capabilities,
            target_execution_attestor_secret=(
                self._archive_execution_attestor_secret
            ),
            target_execution_attestor_id=self._archive_execution_attestor_id,
            startup_timeout_seconds=30.0,
            call_timeout_seconds=60.0,
        )
        worker.start()
        return (
            worker,
            scoped.capability_epoch,
            scoped.scope_marker_sha256,
            approvals,
        )

    @staticmethod
    def _safe_snapshot(
        response: BeginSessionResponse | ResumeSessionResponse,
    ) -> dict[str, object]:
        return response.snapshot.model_dump(
            mode="json",
            exclude={"client_id"},
        )

    @classmethod
    def _start_result(cls, live: _LiveSession) -> dict[str, object]:
        result: dict[str, object] = {
            "session_handle": live.session_handle,
            "session_id": live.session_id,
            "capability_epoch": live.capability_epoch,
            "scope_sha256": live.scope_marker_sha256,
            "snapshot": cls._safe_snapshot(live.start),
        }
        if type(live.start) is ResumeSessionResponse:
            result["recovery"] = live.start.recovery.model_dump(mode="json")
        return result

    def _drain_case_publications(
        self,
        live: _LiveSession,
        *,
        event_id: str | None = None,
    ) -> OutboxRecord | None:
        connection = self._case_publication_connection
        store = self._case_publication_store
        if connection is None or store is None:
            return None
        if (
            self._archive_execution_attestor_secret is None
            or self._archive_execution_attestor_id is None
        ):
            raise SessionRuntimeError("CASE_PUBLICATION_PROOF_SIGNER_UNAVAILABLE")
        proof_signer = LocalHmacCasePublicationProofSigner(
            secret=self._archive_execution_attestor_secret,
            attestor_id=self._archive_execution_attestor_id,
        )
        latest: OutboxRecord | None = None
        while True:
            exported = live.worker.export_pending_case_publish(event_id=event_id)
            if exported is None:
                return latest
            event, transfer = exported
            publication = SharedCasePublisher(
                connection,
                store,
                authority_resolver=live.worker,
                publication_proof_signer=proof_signer,
                clock=self._clock,
                id_factory=self._ids,
            ).process(event, transfer)
            self._fault("before_source_ack")
            acknowledged = live.worker.acknowledge_case_publication(publication)
            if (
                acknowledged.event_id != event.event_id
                or acknowledged.state != "PUBLISHED"
                or acknowledged.published_global_version
                != publication.published_global_version
            ):
                raise SessionRuntimeError("CASE_PUBLICATION_ACK_FAILED")
            latest = acknowledged
            if event_id is not None:
                return latest

    def _recover_case_publications(self, live: _LiveSession) -> None:
        try:
            self._drain_case_publications(live)
        except Exception:
            if not live.worker.is_alive:
                raise ChannelUnavailableError("CHANNEL_UNAVAILABLE") from None

    def _remember(self, live: _LiveSession) -> None:
        previous = self._by_client.get(live.client_id)
        if previous is not None and previous is not live:
            previous.worker.close()
            self._by_handle.pop(previous.session_handle, None)
        self._by_client[live.client_id] = live
        self._by_handle[live.session_handle] = live

    def _begin(self, client_id: str) -> dict[str, object]:
        try:
            self._catalog.require_active(client_id)
        except ClientCatalogError:
            raise SessionScopeDenied("SCOPE_DENIED") from None
        existing = self._by_client.get(client_id)
        if existing is not None and existing.worker.is_alive:
            return self._start_result(existing)
        session_id = self._ids.uuid7()
        session_handle = self._capabilities.issue(
            client_id=client_id,
            session_id=session_id,
            permissions=_PERMISSIONS,
        )
        worker: ScopedWorkerBroker | None = None
        try:
            worker, epoch, scope_marker_sha256, archive_approvals = (
                self._start_worker(
                    client_id=client_id,
                    session_id=session_id,
                    session_handle=session_handle,
                )
            )
            response = worker.call(
                BeginSessionRequest(
                    request_id=self._request_id(),
                    session_id=session_id,
                    capability_epoch=epoch,
                )
            )
            if type(response) is not BeginSessionResponse:
                raise SessionRuntimeError("SESSION_BEGIN_FAILED")
            live = _LiveSession(
                client_id=client_id,
                session_id=session_id,
                session_handle=session_handle,
                capability_epoch=epoch,
                scope_marker_sha256=scope_marker_sha256,
                worker=worker,
                start=response,
                archive_approvals=archive_approvals,
            )
            self._remember(live)
            self._recover_case_publications(live)
            return self._start_result(live)
        except Exception as error:
            if worker is not None:
                worker.close()
            try:
                self._capabilities.revoke(session_handle)
            except Exception:
                pass
            if isinstance(error, ScopedObjectAccessDeniedError):
                raise SessionScopeDenied("SCOPE_DENIED") from None
            if isinstance(error, ChannelUnavailableError):
                raise
            raise ChannelUnavailableError("CHANNEL_UNAVAILABLE") from None

    def _resume(self, client_id: str, session_id: str) -> dict[str, object]:
        try:
            self._catalog.require_active(client_id)
        except ClientCatalogError:
            raise SessionScopeDenied("SCOPE_DENIED") from None
        try:
            previous_epoch = self._capabilities.current_epoch(
                client_id=client_id,
                session_id=session_id,
            )
        except Exception:
            raise SessionScopeDenied("SCOPE_DENIED") from None
        old_live = self._by_client.get(client_id)
        worker: ScopedWorkerBroker | None = None
        session_handle: str | None = None
        try:
            session_handle = self._capabilities.renew(
                client_id=client_id,
                session_id=session_id,
                previous_epoch=previous_epoch,
            )
            self._fault("after_capability_renewal")
            worker, epoch, scope_marker_sha256, archive_approvals = (
                self._start_worker(
                    client_id=client_id,
                    session_id=session_id,
                    session_handle=session_handle,
                )
            )
            response = worker.call(
                ResumeSessionRequest(
                    request_id=self._request_id(),
                    session_id=session_id,
                    previous_capability_epoch=previous_epoch,
                    capability_epoch=epoch,
                )
            )
            if type(response) is not ResumeSessionResponse:
                raise SessionRuntimeError("SESSION_RESUME_FAILED")
            live = _LiveSession(
                client_id=client_id,
                session_id=session_id,
                session_handle=session_handle,
                capability_epoch=epoch,
                scope_marker_sha256=scope_marker_sha256,
                worker=worker,
                start=response,
                archive_approvals=archive_approvals,
            )
            self._remember(live)
            self._recover_case_publications(live)
            return self._start_result(live)
        except Exception as error:
            if worker is not None:
                worker.close()
            if (
                session_handle is not None
                and old_live is not None
                and old_live.session_id == session_id
            ):
                # Renewal invalidates the old token immediately.  Keep its
                # handle mapped for a stable CHANNEL_UNAVAILABLE response, but
                # never leave a process that only appears usable alive.
                old_live.worker.close()
            if session_handle is not None:
                try:
                    self._capabilities.revoke(session_handle)
                except Exception:
                    pass
            if isinstance(error, ScopedObjectAccessDeniedError):
                raise SessionScopeDenied("SCOPE_DENIED") from None
            if isinstance(error, ChannelUnavailableError):
                raise
            raise ChannelUnavailableError("CHANNEL_UNAVAILABLE") from None

    def _require(self, binding: BoundTransport | None) -> _LiveSession:
        if binding is None:
            raise SessionScopeDenied("SCOPE_DENIED")
        live = self._by_handle.get(binding.session_handle)
        if live is None:
            raise SessionScopeDenied("SCOPE_DENIED")
        if not live.worker.is_alive:
            raise ChannelUnavailableError("CHANNEL_UNAVAILABLE")
        return live

    def client_id_for_binding(self, binding: BoundTransport) -> str:
        """Resolve the private subject only for an exact live internal binding.

        This adapter exists solely for in-process leave-one-client-out retrieval;
        MCP handlers never expose the returned identity in their result models.
        """

        with self._lock:
            return self._require(binding).client_id

    def close_and_verify(self, client_id: str) -> ClientQuiescenceProof:
        """Close every in-process handle for one internal client authority."""

        with self._lock:
            lives = tuple(
                {
                    id(live): live
                    for live in self._by_handle.values()
                    if live.client_id == client_id
                }.values()
            )
            current = self._by_client.get(client_id)
            if current is not None and all(current is not item for item in lives):
                lives = (*lives, current)
            for live in lives:
                self._by_handle.pop(live.session_handle, None)
                for key in tuple(self._private_archive_previews):
                    if key[0] == live.session_id:
                        self._private_archive_previews.pop(key, None)
            self._by_client.pop(client_id, None)
            for live in lives:
                live.worker.close()
            closed = all(not live.worker.is_alive for live in lives)
            proof = ClientQuiescenceProof(
                client_id=client_id,
                worker_handles_closed=closed,
                sqlite_handles_closed=closed,
                mmap_handles_closed=closed,
                proof_sha256=client_quiescence_proof_sha256(
                    client_id=client_id,
                    worker_handles_closed=closed,
                    sqlite_handles_closed=closed,
                    mmap_handles_closed=closed,
                ),
            )
            if not self.verify_closed(proof):
                raise SessionRuntimeError("CLIENT_HANDLES_OPEN")
            return proof

    def verify_closed(self, proof: ClientQuiescenceProof) -> bool:
        """Recheck that a quiesced client cannot be reached by any live handle."""

        if not isinstance(proof, ClientQuiescenceProof):
            return False
        with self._lock:
            return bool(
                proof.worker_handles_closed
                and proof.sqlite_handles_closed
                and proof.mmap_handles_closed
                and proof.client_id not in self._by_client
                and all(
                    live.client_id != proof.client_id
                    for live in self._by_handle.values()
                )
            )

    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object:
        with self._lock:
            if tool_name == "load_client_context":
                values = cast(LoadClientContextInput, request)
                if values.resume_session_id is None:
                    return self._begin(values.client_id)
                return self._resume(values.client_id, values.resume_session_id)
            live = self._require(binding)
            exact_binding = cast(BoundTransport, binding)
            if tool_name == "append_session_turn":
                return self._append(live, cast(AppendSessionTurnInput, request))
            if tool_name == "append_temporary_fact":
                return self._append_temporary_fact(
                    live,
                    cast(AppendTemporaryFactInput, request),
                )
            if tool_name == "store_candidate_set":
                if self._generation_retrieval is not None:
                    raise WorkflowOperationalError(
                        "GENERATION_STAGE_ORDER_INVALID"
                    )
                return self._store_candidates(
                    live,
                    cast(StoreCandidateSetInput, request),
                )
            if tool_name == "record_actual_reply":
                return self._record_actual(
                    live,
                    cast(RecordActualReplyInput, request),
                )
            if tool_name == "submit_generation_stage":
                return self._submit_generation_stage(
                    live,
                    cast(SubmitGenerationStageInput, request),
                    binding=exact_binding,
                )
            if tool_name == "get_generation_state":
                return self._get_generation_state(
                    live,
                    cast(GetGenerationStateInput, request),
                    binding=exact_binding,
                )
            if tool_name == "acknowledge_risk_observation":
                return self._acknowledge_risk_observation(
                    live,
                    cast(AcknowledgeRiskObservationInput, request),
                )
            if tool_name == "propose_archive":
                return self._propose_archive(
                    live,
                    cast(ProposeArchiveInput, request),
                )
            if tool_name == "preview_private_archive":
                return self._preview_private_archive(
                    live,
                    cast(PreviewPrivateArchiveInput, request),
                )
            if tool_name == "commit_private_archive":
                return self._commit_private_archive(
                    live,
                    cast(CommitPrivateArchiveInput, request),
                )
            if tool_name == "preview_profile_diff":
                return self._preview_profile_diff(
                    live,
                    cast(PreviewProfileDiffInput, request),
                )
            if tool_name == "commit_profile_update":
                return self._commit_profile_update(
                    live,
                    cast(CommitProfileUpdateInput, request),
                )
            if tool_name == "approve_case":
                return self._approve_case(
                    live,
                    cast(ApproveCaseInput, request),
                )
            if tool_name in {
                "rollback_version",
                "start_rebuild",
                "get_rebuild_status",
                "get_rebuild_report",
                "cancel_rebuild",
                "preview_rebuild",
                "preview_delete",
                "commit_delete",
            }:
                return self._invoke_lifecycle(
                    live,
                    tool_name,
                    request,
                    binding=exact_binding,
                )
            raise SessionRuntimeError("SESSION_TOOL_UNAVAILABLE")

    @staticmethod
    def _archive_approvals(live: _LiveSession) -> ApprovalService:
        approvals = live.archive_approvals
        if approvals is None:
            raise ChannelUnavailableError("CHANNEL_UNAVAILABLE")
        return approvals

    def _issue_archive_review(
        self,
        live: _LiveSession,
        *,
        descriptor: DraftDescriptor,
        diff_ref: VersionRef,
    ) -> dict[str, object]:
        approvals = self._archive_approvals(live)
        request = approvals.request(descriptor, diff_object_ref=diff_ref)
        return {
            "approval_request_id": request.request_id,
            "approval_operation_id": self._ids.object_id("archive_operation"),
            "approval_state": request.state,
            "approval_expires_at": request.expires_at,
            "approval_purpose": descriptor.purpose,
        }

    @staticmethod
    def _require_archive_descriptor(
        live: _LiveSession,
        *,
        approvals: ApprovalService,
        request_id: str,
        purpose: str,
    ) -> DraftDescriptor:
        descriptor = approvals.get(request_id).descriptor
        if (
            descriptor.purpose != purpose
            or descriptor.client_id != live.client_id
            or descriptor.session_id != live.session_id
        ):
            raise SessionRuntimeError("ARCHIVE_APPROVAL_BINDING_MISMATCH")
        return descriptor

    @staticmethod
    def _execute_approved_archive(
        live: _LiveSession,
        request: CommitPrivateArchiveRequest
        | CommitProfileUpdateRequest
        | StageSharedCaseOutboxRequest
        | CommitClientTombstoneRequest
        | RebuildClientDerivativesRequest
        | CommitClientRollbackRequest,
        *,
        descriptor: DraftDescriptor,
        operation_id: str,
        request_id: str,
        approval_service: ApprovalService | None = None,
    ) -> (
        CommitPrivateArchiveResponse
        | CommitProfileUpdateResponse
        | StageSharedCaseOutboxResponse
        | CommitClientTombstoneResponse
        | RebuildClientDerivativesResponse
        | CommitClientRollbackResponse
    ):
        approvals = (
            SessionRuntimeManager._archive_approvals(live)
            if approval_service is None
            else approval_service
        )
        recovering_committed = approvals.has_execution_binding(
            request_id,
            descriptor,
        )
        ticket = approvals.issue_for_execution(
            request_id,
            descriptor,
            operation_id=operation_id,
        )
        if recovering_committed:
            # A control-side binding does not prove the target transaction ran.
            # Probe the exact target first.  APPLIED is re-attested and never
            # replayed; sealed exact absence is the only state that permits the
            # original one-shot handler to run.
            recovered = live.worker.recover_applied_archive_operation(
                request,
                ticket=ticket,
                approval_service=approvals,
            )
            if recovered is None:
                response = live.worker.execute_approved_archive_operation(
                    request,
                    ticket=ticket,
                    approval_service=approvals,
                )
            else:
                response = recovered
        else:
            response = live.worker.execute_approved_archive_operation(
                request,
                ticket=ticket,
                approval_service=approvals,
            )
        if not isinstance(
            response,
            (
                CommitPrivateArchiveResponse,
                CommitProfileUpdateResponse,
                StageSharedCaseOutboxResponse,
                CommitClientTombstoneResponse,
                RebuildClientDerivativesResponse,
                CommitClientRollbackResponse,
            ),
        ):
            raise SessionRuntimeError("ARCHIVE_COMMIT_FAILED")
        return response

    def _preflight_approved_lifecycle(
        self,
        live: _LiveSession,
        *,
        lifecycle_kind: Literal["delete", "rebuild", "rollback"],
        plan_ref: ArchiveContentRef,
        plan_sha256: str,
        base_versions: tuple[WorkerBaseVersion, ...],
        approval_operation_id: str,
        approval_request_id: str,
        rebuild_action: Literal["START", "CANCEL"] | None = None,
        target_scope_hash: str | None = None,
    ) -> None:
        """Ask the private worker to validate its exact plan before issuance."""

        response = live.worker.call(
            PreflightClientLifecycleCommitRequest(
                request_id=self._request_id(),
                lifecycle_kind=lifecycle_kind,
                plan_ref=plan_ref,
                plan_sha256=plan_sha256,
                base_versions=base_versions,
                approval_operation_id=approval_operation_id,
                approval_request_id=approval_request_id,
                rebuild_action=rebuild_action,
                target_scope_hash=target_scope_hash,
            )
        )
        if type(response) is not PreflightClientLifecycleCommitResponse:
            raise SessionRuntimeError("LIFECYCLE_PLAN_MISMATCH")

    @staticmethod
    def _public_worker_response(response: StrictModel) -> dict[str, object]:
        return response.model_dump(
            mode="json",
            exclude={
                "request_id",
                "response_type",
                "success",
                "schema_version",
            },
        )

    def _approval_for_scope(self, scope_sha256: str) -> ApprovalService:
        factory = self._archive_approval_factory
        if factory is None:
            raise ChannelUnavailableError("CHANNEL_UNAVAILABLE")
        approvals = factory(scope_sha256)
        if (
            not isinstance(approvals, ApprovalService)
            or approvals.target_scope_hash != scope_sha256
        ):
            raise ChannelUnavailableError("CHANNEL_UNAVAILABLE")
        return approvals

    @staticmethod
    def _worker_base_versions(
        values: tuple[object, ...],
    ) -> tuple[WorkerBaseVersion, ...]:
        return tuple(
            WorkerBaseVersion.model_validate(value, from_attributes=True)
            for value in values
        )

    @staticmethod
    def _require_client_lifecycle_scope(
        live: _LiveSession,
        request: StrictModel,
    ) -> None:
        if (
            getattr(request, "database_scope", None) != "client"
            or getattr(request, "session_handle", None) != live.session_handle
            or getattr(request, "scope_sha256", None)
            != live.scope_marker_sha256
        ):
            raise SessionScopeDenied("SCOPE_DENIED")

    @staticmethod
    def _tombstone_base_version(
        base_versions: tuple[WorkerBaseVersion, ...],
        *,
        scope_sha256: str,
    ) -> int:
        matches = tuple(
            value
            for value in base_versions
            if value.authority_key == "tombstone_epoch"
            and value.scope_sha256 == scope_sha256
        )
        if len(base_versions) != 1 or len(matches) != 1:
            raise SessionRuntimeError("LIFECYCLE_BASE_VERSION_MISMATCH")
        return matches[0].version

    def _invoke_lifecycle(
        self,
        live: _LiveSession,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport,
    ) -> object:
        database_scope = getattr(request, "database_scope", None)
        if getattr(request, "session_handle", None) != live.session_handle:
            raise SessionScopeDenied("SCOPE_DENIED")
        if tool_name == "preview_delete":
            preview_values = cast(PreviewDeleteInput, request)
            if preview_values.target_type == "client":
                self._require_client_lifecycle_scope(live, request)
                if (
                    preview_values.target_id != "current-client"
                    or preview_values.target_version is not None
                    or preview_values.target_content_sha256 is not None
                ):
                    raise SessionScopeDenied("SCOPE_DENIED")
                whole_runtime = self._whole_client_lifecycle
                if whole_runtime is None:
                    raise SessionRuntimeError(
                        "WHOLE_CLIENT_LIFECYCLE_UNAVAILABLE"
                    )
                whole_preview = whole_runtime.preview(
                    bound_client_id=live.client_id,
                    reason_code=preview_values.reason_code,
                )
                return whole_preview.model_dump(mode="json")
        if tool_name == "commit_delete":
            commit_values = cast(CommitDeleteInput, request)
            if commit_values.deletion_subject == "current_client":
                self._require_client_lifecycle_scope(live, request)
                whole_runtime = self._whole_client_lifecycle
                if whole_runtime is None:
                    raise SessionRuntimeError(
                        "WHOLE_CLIENT_LIFECYCLE_UNAVAILABLE"
                    )
                whole_commit = whole_runtime.commit(
                    bound_client_id=live.client_id,
                    plan_ref=commit_values.plan_ref,
                    plan_sha256=commit_values.plan_sha256,
                    target_scope_hash=commit_values.target_scope_hash,
                    base_versions=tuple(
                        DeletionBaseVersion.model_validate(
                            value.model_dump(mode="json")
                        )
                        for value in commit_values.base_versions
                    ),
                    approval_operation_id=(
                        commit_values.approval_operation_id
                    ),
                    approval_request_id=commit_values.approval_request_id,
                )
                return {
                    "status": whole_commit.status,
                    **whole_commit.result.model_dump(mode="json"),
                    "client_scope_state": whole_commit.client_scope_state,
                    "physical_cleanup_state": whole_commit.physical_cleanup_state,
                }
        if database_scope == "global":
            global_runtime = self._global_lifecycle
            if global_runtime is None:
                raise SessionRuntimeError("GLOBAL_LIFECYCLE_UNAVAILABLE")
            return global_runtime.invoke(
                tool_name,
                request,
                binding=binding,
            )
        self._require_client_lifecycle_scope(live, request)

        if tool_name == "preview_delete":
            preview_values = cast(PreviewDeleteInput, request)
            if (
                preview_values.target_type != "session"
                or preview_values.target_id != live.session_id
                or preview_values.target_version is None
                or preview_values.target_content_sha256 is None
            ):
                raise SessionScopeDenied("SCOPE_DENIED")
            proposed_operation_id = self._ids.object_id("deletion_operation")
            response = live.worker.call(
                PreviewClientDeleteRequest(
                    request_id=self._request_id(),
                    target_type="session",
                    target_id=live.session_id,
                    target_version=preview_values.target_version,
                    target_content_sha256=preview_values.target_content_sha256,
                    reason_code=preview_values.reason_code,
                    proposed_operation_id=proposed_operation_id,
                    requested_at=self._clock.now(),
                )
            )
            if type(response) is not PreviewClientDeleteResponse:
                raise SessionRuntimeError("DELETION_PREVIEW_FAILED")
            descriptor = DraftDescriptor(
                purpose="delete",
                target_id=live.session_id,
                client_id=live.client_id,
                session_id=live.session_id,
                base_version=response.base_deletion_version,
                draft_sha256=response.plan_sha256,
            )
            approvals = self._approval_for_scope(response.target_scope_hash)
            approval = approvals.request(
                descriptor,
                diff_object_ref=response.plan_ref.version_ref,
            )
            return {
                **self._public_worker_response(response),
                "approval_request_id": approval.request_id,
                "approval_operation_id": proposed_operation_id,
                "approval_state": approval.state,
                "approval_expires_at": approval.expires_at,
            }

        if tool_name == "commit_delete":
            commit_delete_values = cast(CommitDeleteInput, request)
            approvals = self._approval_for_scope(
                commit_delete_values.target_scope_hash
            )
            descriptor = self._require_archive_descriptor(
                live,
                approvals=approvals,
                request_id=commit_delete_values.approval_request_id,
                purpose="delete",
            )
            if (
                descriptor.draft_sha256 != commit_delete_values.plan_sha256
                or approvals.get(
                    commit_delete_values.approval_request_id
                ).diff_object_ref
                != commit_delete_values.plan_ref.version_ref
            ):
                raise SessionRuntimeError("LIFECYCLE_APPROVAL_BINDING_MISMATCH")
            deletion_worker_request = CommitClientTombstoneRequest(
                request_id=self._request_id(),
                plan_ref=commit_delete_values.plan_ref,
                plan_sha256=commit_delete_values.plan_sha256,
                target_scope_hash=commit_delete_values.target_scope_hash,
                base_versions=self._worker_base_versions(
                    commit_delete_values.base_versions
                ),
                approval_operation_id=(
                    commit_delete_values.approval_operation_id
                ),
                approval_request_id=commit_delete_values.approval_request_id,
            )
            self._preflight_approved_lifecycle(
                live,
                lifecycle_kind="delete",
                plan_ref=deletion_worker_request.plan_ref,
                plan_sha256=deletion_worker_request.plan_sha256,
                base_versions=deletion_worker_request.base_versions,
                approval_operation_id=(
                    deletion_worker_request.approval_operation_id
                ),
                approval_request_id=(
                    deletion_worker_request.approval_request_id
                ),
                target_scope_hash=deletion_worker_request.target_scope_hash,
            )
            response = self._execute_approved_archive(
                live,
                deletion_worker_request,
                descriptor=descriptor,
                operation_id=commit_delete_values.approval_operation_id,
                request_id=commit_delete_values.approval_request_id,
                approval_service=approvals,
            )
            if type(response) is not CommitClientTombstoneResponse:
                raise SessionRuntimeError("DELETION_COMMIT_FAILED")
            return self._public_worker_response(response)

        if tool_name == "preview_rebuild":
            preview_rebuild = cast(PreviewRebuildInput, request)
            proposed_operation_id = self._ids.object_id("rebuild_operation")
            response = live.worker.call(
                PreviewClientRebuildRequest(
                    request_id=self._request_id(),
                    action=preview_rebuild.action,
                    purpose=preview_rebuild.purpose,
                    source_intent_id=preview_rebuild.source_intent_id,
                    job_id=preview_rebuild.job_id,
                    policy_sha256=preview_rebuild.policy_sha256,
                    model_descriptor_sha256=(
                        preview_rebuild.model_descriptor_sha256
                    ),
                    proposed_operation_id=proposed_operation_id,
                    requested_at=self._clock.now(),
                )
            )
            if type(response) is not PreviewClientRebuildResponse:
                raise SessionRuntimeError("REBUILD_PREVIEW_FAILED")
            base = self._tombstone_base_version(
                response.base_versions,
                scope_sha256=live.scope_marker_sha256,
            )
            target_id = (
                f"client_rebuild:{response.purpose}"
                if response.action == "start"
                else f"client_rebuild_cancel:{response.job_id}"
            )
            descriptor = DraftDescriptor(
                purpose="rebuild",
                target_id=target_id,
                client_id=live.client_id,
                session_id=live.session_id,
                base_version=base,
                draft_sha256=response.plan_sha256,
            )
            approvals = self._approval_for_scope(live.scope_marker_sha256)
            approval = approvals.request(
                descriptor,
                diff_object_ref=response.plan_ref.version_ref,
            )
            return {
                **self._public_worker_response(response),
                "approval_request_id": approval.request_id,
                "approval_operation_id": proposed_operation_id,
                "approval_state": approval.state,
                "approval_expires_at": approval.expires_at,
            }

        if tool_name in {"get_rebuild_status", "get_rebuild_report"}:
            status_values = cast(
                GetRebuildStatusInput | GetRebuildReportInput,
                request,
            )
            action: Literal["STATUS", "REPORT"] = (
                "REPORT" if tool_name == "get_rebuild_report" else "STATUS"
            )
            response = live.worker.call(
                RebuildClientDerivativesRequest(
                    request_id=self._request_id(),
                    action=action,
                    job_id=status_values.job_id,
                )
            )
            if type(response) is not RebuildClientDerivativesResponse:
                raise SessionRuntimeError("REBUILD_STATUS_FAILED")
            return self._public_worker_response(response)

        if tool_name == "start_rebuild":
            start_values = cast(StartRebuildInput, request)
            bases = self._worker_base_versions(start_values.base_versions)
            tombstone_epoch = self._tombstone_base_version(
                bases,
                scope_sha256=live.scope_marker_sha256,
            )
            approvals = self._approval_for_scope(live.scope_marker_sha256)
            descriptor = self._require_archive_descriptor(
                live,
                approvals=approvals,
                request_id=start_values.approval_request_id,
                purpose="rebuild",
            )
            if (
                approvals.get(start_values.approval_request_id).diff_object_ref
                != start_values.plan_ref.version_ref
                or descriptor
                != DraftDescriptor(
                purpose="rebuild",
                target_id="client_rebuild:all",
                client_id=live.client_id,
                session_id=live.session_id,
                base_version=tombstone_epoch,
                draft_sha256=start_values.plan_sha256,
                )
            ):
                raise SessionRuntimeError("LIFECYCLE_APPROVAL_BINDING_MISMATCH")
            start_worker_request = RebuildClientDerivativesRequest(
                request_id=self._request_id(),
                action="START",
                purpose="all",
                plan_sha256=start_values.plan_sha256,
                base_versions=bases,
                idempotency_key=start_values.idempotency_key,
                approval_operation_id=start_values.approval_operation_id,
                approval_request_id=start_values.approval_request_id,
                plan_ref=start_values.plan_ref,
            )
            self._preflight_approved_lifecycle(
                live,
                lifecycle_kind="rebuild",
                plan_ref=start_values.plan_ref,
                plan_sha256=start_values.plan_sha256,
                base_versions=bases,
                approval_operation_id=start_values.approval_operation_id,
                approval_request_id=start_values.approval_request_id,
                rebuild_action="START",
            )
            response = self._execute_approved_archive(
                live,
                start_worker_request,
                descriptor=descriptor,
                operation_id=start_values.approval_operation_id,
                request_id=start_values.approval_request_id,
                approval_service=approvals,
            )
            if type(response) is not RebuildClientDerivativesResponse:
                raise SessionRuntimeError("REBUILD_START_FAILED")
            return self._public_worker_response(response)

        if tool_name == "cancel_rebuild":
            cancel_values = cast(CancelRebuildInput, request)
            bases = self._worker_base_versions(cancel_values.base_versions)
            tombstone_epoch = self._tombstone_base_version(
                bases,
                scope_sha256=live.scope_marker_sha256,
            )
            approvals = self._approval_for_scope(live.scope_marker_sha256)
            descriptor = self._require_archive_descriptor(
                live,
                approvals=approvals,
                request_id=cancel_values.approval_request_id,
                purpose="rebuild",
            )
            prefix = "client_rebuild_cancel:"
            if not descriptor.target_id.startswith(prefix):
                raise SessionRuntimeError("LIFECYCLE_APPROVAL_BINDING_MISMATCH")
            job_id = descriptor.target_id[len(prefix) :]
            if (
                approvals.get(cancel_values.approval_request_id).diff_object_ref
                != cancel_values.plan_ref.version_ref
                or descriptor
                != DraftDescriptor(
                purpose="rebuild",
                target_id=f"client_rebuild_cancel:{job_id}",
                client_id=live.client_id,
                session_id=live.session_id,
                base_version=tombstone_epoch,
                draft_sha256=cancel_values.plan_sha256,
                )
            ):
                raise SessionRuntimeError("LIFECYCLE_APPROVAL_BINDING_MISMATCH")
            cancel_worker_request = RebuildClientDerivativesRequest(
                request_id=self._request_id(),
                action="CANCEL",
                job_id=job_id,
                plan_sha256=cancel_values.plan_sha256,
                base_versions=bases,
                approval_operation_id=cancel_values.approval_operation_id,
                approval_request_id=cancel_values.approval_request_id,
                plan_ref=cancel_values.plan_ref,
            )
            self._preflight_approved_lifecycle(
                live,
                lifecycle_kind="rebuild",
                plan_ref=cancel_values.plan_ref,
                plan_sha256=cancel_values.plan_sha256,
                base_versions=bases,
                approval_operation_id=cancel_values.approval_operation_id,
                approval_request_id=cancel_values.approval_request_id,
                rebuild_action="CANCEL",
            )
            response = self._execute_approved_archive(
                live,
                cancel_worker_request,
                descriptor=descriptor,
                operation_id=cancel_values.approval_operation_id,
                request_id=cancel_values.approval_request_id,
                approval_service=approvals,
            )
            if type(response) is not RebuildClientDerivativesResponse:
                raise SessionRuntimeError("REBUILD_CANCEL_FAILED")
            return self._public_worker_response(response)

        if tool_name == "rollback_version":
            rollback = cast(RollbackVersionInput, request)
            if rollback.action == "preview":
                if rollback.target_kind not in {"profile_fact", "artifact"}:
                    raise SessionScopeDenied("SCOPE_DENIED")
                assert rollback.target_id is not None
                assert rollback.current_version is not None
                assert rollback.restore_version is not None
                assert rollback.reason is not None
                response = live.worker.call(
                    PreviewClientRollbackRequest(
                        request_id=self._request_id(),
                        rollback_kind=rollback.target_kind,
                        target_id=rollback.target_id,
                        current_version=rollback.current_version,
                        restore_version=rollback.restore_version,
                        reason=rollback.reason,
                        source_plan_ref=rollback.source_plan_ref,
                    )
                )
                if type(response) is not PreviewClientRollbackResponse:
                    raise SessionRuntimeError("ROLLBACK_PREVIEW_FAILED")
                descriptor = DraftDescriptor(
                    purpose="rollback",
                    target_id=rollback.target_id,
                    client_id=live.client_id,
                    session_id=live.session_id,
                    base_version=rollback.current_version,
                    draft_sha256=response.plan_sha256,
                )
                approvals = self._approval_for_scope(
                    live.scope_marker_sha256
                )
                approval = approvals.request(
                    descriptor,
                    diff_object_ref=response.plan_ref.version_ref,
                )
                return {
                    **self._public_worker_response(response),
                    "approval_request_id": approval.request_id,
                    "approval_operation_id": (
                        response.proposed_operation_id
                    ),
                    "approval_state": approval.state,
                    "approval_expires_at": approval.expires_at,
                }

            plan_ref = rollback.plan_ref
            operation_id = rollback.approval_operation_id
            request_id = rollback.approval_request_id
            plan_sha256 = rollback.plan_sha256
            base_versions = rollback.base_versions
            assert plan_ref is not None
            assert operation_id is not None
            assert request_id is not None
            assert plan_sha256 is not None
            assert base_versions is not None
            approvals = self._approval_for_scope(live.scope_marker_sha256)
            descriptor = self._require_archive_descriptor(
                live,
                approvals=approvals,
                request_id=request_id,
                purpose="rollback",
            )
            client_fact_bases = tuple(
                value
                for value in base_versions
                if value.authority_key == "client_fact"
                and value.scope_sha256 == live.scope_marker_sha256
            )
            approval = approvals.get(request_id)
            if (
                descriptor.draft_sha256 != plan_sha256
                or approval.diff_object_ref != plan_ref.version_ref
                or len(client_fact_bases) != 1
                or client_fact_bases[0].version
                != descriptor.base_version
                or any(
                    value.scope_sha256 != live.scope_marker_sha256
                    for value in base_versions
                )
            ):
                raise SessionRuntimeError(
                    "LIFECYCLE_APPROVAL_BINDING_MISMATCH"
                )
            worker_request = CommitClientRollbackRequest(
                request_id=self._request_id(),
                plan_ref=plan_ref,
                plan_sha256=plan_sha256,
                base_versions=self._worker_base_versions(base_versions),
                approval_operation_id=operation_id,
                approval_request_id=request_id,
            )
            self._preflight_approved_lifecycle(
                live,
                lifecycle_kind="rollback",
                plan_ref=worker_request.plan_ref,
                plan_sha256=worker_request.plan_sha256,
                base_versions=worker_request.base_versions,
                approval_operation_id=worker_request.approval_operation_id,
                approval_request_id=worker_request.approval_request_id,
            )
            committed = self._execute_approved_archive(
                live,
                worker_request,
                descriptor=descriptor,
                operation_id=operation_id,
                request_id=request_id,
                approval_service=approvals,
            )
            if type(committed) is not CommitClientRollbackResponse:
                raise SessionRuntimeError("ROLLBACK_COMMIT_FAILED")
            return self._public_worker_response(committed)
        raise SessionRuntimeError("SESSION_TOOL_UNAVAILABLE")

    def _propose_archive(
        self,
        live: _LiveSession,
        request: ProposeArchiveInput,
    ) -> dict[str, object]:
        response = live.worker.call(
            BuildPrivateArchiveRequest(
                request_id=self._request_id(),
                session_handle=live.session_handle,
                analysis_ref=request.analysis_ref,
            )
        )
        if type(response) is not BuildPrivateArchiveResponse:
            raise SessionRuntimeError("ARCHIVE_PROPOSAL_FAILED")
        self._private_archive_previews[(live.session_id, response.bundle_id)] = response
        return {
            "status": "archive_proposed",
            "bundle_id": response.bundle_id,
            "actual_transcript_ref": response.actual_transcript_ref,
            "private_archive_draft_ref": response.draft_ref,
            "private_archive_review_diff_ref": response.review_diff_ref,
            "private_archive_base_version": response.base_version,
            "incomplete_evidence": response.incomplete_evidence,
            "purpose_states": (
                {
                    "purpose": "private_archive",
                    "state": response.private_archive_state,
                },
                {"purpose": "profile_diff", "state": "DRAFT"},
                {"purpose": "shared_case", "state": "DRAFT"},
            ),
        }

    def _preview_private_archive(
        self,
        live: _LiveSession,
        request: PreviewPrivateArchiveInput,
    ) -> dict[str, object]:
        built = self._private_archive_previews.get(
            (live.session_id, request.bundle_id)
        )
        if (
            built is None
            or built.draft_ref != request.draft_ref
            or built.review_diff_ref != request.review_diff_ref
            or built.base_version != request.base_version
        ):
            raise SessionRuntimeError("ARCHIVE_PREVIEW_BINDING_MISMATCH")
        descriptor = DraftDescriptor(
            purpose="private_archive_publish",
            target_id=request.draft_ref.object_id,
            client_id=live.client_id,
            base_version=request.base_version,
            draft_sha256=request.draft_ref.content_sha256,
            session_id=live.session_id,
        )
        review = self._issue_archive_review(
            live,
            descriptor=descriptor,
            diff_ref=request.review_diff_ref,
        )
        return {
            "status": "pending_local_review",
            "bundle_id": request.bundle_id,
            "draft_ref": request.draft_ref,
            "review_diff_ref": request.review_diff_ref,
            "section_boundary": (
                "actual_transcript",
                "model_analysis",
                "counselor_reflection",
            ),
            **review,
        }

    def _commit_private_archive(
        self,
        live: _LiveSession,
        request: CommitPrivateArchiveInput,
    ) -> dict[str, object]:
        approvals = self._archive_approvals(live)
        descriptor = self._require_archive_descriptor(
            live,
            approvals=approvals,
            request_id=request.approval_request_id,
            purpose="private_archive_publish",
        )
        if (
            descriptor.target_id != request.draft_ref.object_id
            or descriptor.base_version != request.base_version
            or descriptor.draft_sha256 != request.draft_ref.content_sha256
        ):
            raise SessionRuntimeError("ARCHIVE_APPROVAL_BINDING_MISMATCH")
        worker_request = CommitPrivateArchiveRequest(
            request_id=self._request_id(),
            session_handle=live.session_handle,
            bundle_id=request.bundle_id,
            draft_ref=request.draft_ref,
            base_version=request.base_version,
            approval_operation_id=request.approval_operation_id,
            approval_request_id=request.approval_request_id,
        )
        response = self._execute_approved_archive(
            live,
            worker_request,
            descriptor=descriptor,
            operation_id=request.approval_operation_id,
            request_id=request.approval_request_id,
        )
        if type(response) is not CommitPrivateArchiveResponse:
            raise SessionRuntimeError("PRIVATE_ARCHIVE_COMMIT_FAILED")
        return response.model_dump(mode="json", exclude={"request_id", "response_type", "success", "schema_version"})

    def _preview_profile_diff(
        self,
        live: _LiveSession,
        request: PreviewProfileDiffInput,
    ) -> dict[str, object]:
        response = live.worker.call(
            BuildProfileDiffRequest(
                request_id=self._request_id(),
                session_handle=live.session_handle,
                action=request.action,
                build_input_ref=request.build_input_ref,
                draft_ref=request.draft_ref,
                selected_operation_ids=request.selected_operation_ids,
                dismissed_indirect_review_fact_ids=(
                    request.dismissed_indirect_review_fact_ids
                ),
            )
        )
        if type(response) is not BuildProfileDiffResponse:
            raise SessionRuntimeError("PROFILE_DIFF_PREVIEW_FAILED")
        result = response.model_dump(
            mode="json",
            exclude={"request_id", "response_type", "success", "schema_version"},
        )
        result["action"] = request.action
        if request.action == "BUILD":
            result["status"] = "profile_diff_built"
            return result
        if (
            response.approval_draft_sha256 is None
            or response.approval_diff_ref is None
        ):
            raise SessionRuntimeError("PROFILE_DIFF_APPROVAL_PREVIEW_FAILED")
        descriptor = DraftDescriptor(
            purpose="profile_update",
            target_id=response.diff_id,
            client_id=live.client_id,
            base_version=response.base_client_commit_version,
            draft_sha256=response.approval_draft_sha256,
            session_id=live.session_id,
        )
        result.update(
            self._issue_archive_review(
                live,
                descriptor=descriptor,
                diff_ref=response.approval_diff_ref,
            )
        )
        result["status"] = "pending_local_review"
        return result

    def _commit_profile_update(
        self,
        live: _LiveSession,
        request: CommitProfileUpdateInput,
    ) -> dict[str, object]:
        approvals = self._archive_approvals(live)
        descriptor = self._require_archive_descriptor(
            live,
            approvals=approvals,
            request_id=request.approval_request_id,
            purpose="profile_update",
        )
        worker_request = CommitProfileUpdateRequest(
            request_id=self._request_id(),
            session_handle=live.session_handle,
            bundle_id=request.bundle_id,
            draft_ref=request.draft_ref,
            selected_operation_ids=request.selected_operation_ids,
            dismissed_indirect_review_fact_ids=(
                request.dismissed_indirect_review_fact_ids
            ),
            approval_operation_id=request.approval_operation_id,
            approval_request_id=request.approval_request_id,
            expected_runtime_epoch=request.expected_runtime_epoch,
            publication_timestamp=request.publication_timestamp,
        )
        response = self._execute_approved_archive(
            live,
            worker_request,
            descriptor=descriptor,
            operation_id=request.approval_operation_id,
            request_id=request.approval_request_id,
        )
        if type(response) is not CommitProfileUpdateResponse:
            raise SessionRuntimeError("PROFILE_UPDATE_COMMIT_FAILED")
        return response.model_dump(mode="json", exclude={"request_id", "response_type", "success", "schema_version"})

    def _approve_case(
        self,
        live: _LiveSession,
        request: ApproveCaseInput,
    ) -> dict[str, object]:
        if request.action == "PREPARE":
            response = live.worker.call(
                StageSharedCaseOutboxRequest(
                    request_id=self._request_id(),
                    session_handle=live.session_handle,
                    bundle_id=request.bundle_id,
                    action="PREPARE",
                    section_drafts=request.section_drafts,
                    decision=request.decision,
                    checked_categories=request.checked_categories,
                    residual_risk=request.residual_risk,
                    rare_combination_disposition=(
                        request.rare_combination_disposition
                    ),
                    reuse_authorized=request.reuse_authorized,
                    allowed_uses=request.allowed_uses,
                    authorization_expires_at=(
                        request.authorization_expires_at
                    ),
                )
            )
            if (
                type(response) is not StageSharedCaseOutboxResponse
                or response.action != "PREPARE"
                or response.candidate_ref is None
                or response.approval_draft_sha256 is None
                or response.approval_diff_ref is None
            ):
                raise SessionRuntimeError("CASE_APPROVAL_PREPARE_FAILED")
            descriptor = DraftDescriptor(
                purpose="case_publish",
                target_id=response.candidate_ref.object_id,
                client_id=live.client_id,
                base_version=response.candidate_ref.version,
                draft_sha256=response.approval_draft_sha256,
                session_id=live.session_id,
            )
            result = response.model_dump(
                mode="json",
                exclude={"request_id", "response_type", "success", "schema_version"},
            )
            result.update(
                self._issue_archive_review(
                    live,
                    descriptor=descriptor,
                    diff_ref=response.approval_diff_ref,
                )
            )
            result["status"] = "pending_local_review"
            return result

        if (
            request.candidate_ref is None
            or request.scan_ref is None
            or request.review_policy_draft_ref is None
            or request.approval_operation_id is None
            or request.approval_request_id is None
        ):
            raise SessionRuntimeError("CASE_APPROVAL_BINDING_MISMATCH")
        approvals = self._archive_approvals(live)
        descriptor = self._require_archive_descriptor(
            live,
            approvals=approvals,
            request_id=request.approval_request_id,
            purpose="case_publish",
        )
        if descriptor.target_id != request.candidate_ref.object_id:
            raise SessionRuntimeError("CASE_APPROVAL_BINDING_MISMATCH")
        worker_request = StageSharedCaseOutboxRequest(
            request_id=self._request_id(),
            session_handle=live.session_handle,
            bundle_id=request.bundle_id,
            action="COMMIT",
            decision=request.decision,
            checked_categories=request.checked_categories,
            residual_risk=request.residual_risk,
            rare_combination_disposition=(
                request.rare_combination_disposition
            ),
            reuse_authorized=request.reuse_authorized,
            allowed_uses=request.allowed_uses,
            authorization_expires_at=request.authorization_expires_at,
            candidate_ref=request.candidate_ref,
            scan_ref=request.scan_ref,
            review_policy_draft_ref=request.review_policy_draft_ref,
            approval_operation_id=request.approval_operation_id,
            approval_request_id=request.approval_request_id,
        )
        response = self._execute_approved_archive(
            live,
            worker_request,
            descriptor=descriptor,
            operation_id=request.approval_operation_id,
            request_id=request.approval_request_id,
        )
        if (
            type(response) is not StageSharedCaseOutboxResponse
            or response.action != "COMMIT"
        ):
            raise SessionRuntimeError("CASE_APPROVAL_COMMIT_FAILED")
        if response.event_id is not None:
            # The exact source event and its approval execution are durable at
            # this boundary.  A fault here must resume the outbox saga without
            # consuming or replaying the one-shot approval.
            self._fault("after_source_outbox")
        if response.event_id is not None and response.state != "PUBLISHED":
            try:
                acknowledged = self._drain_case_publications(
                    live,
                    event_id=response.event_id,
                )
                if acknowledged is not None:
                    response = response.model_copy(
                        update={
                            "state": acknowledged.state,
                            "attempt_count": acknowledged.attempt_count,
                            "published_global_version": (
                                acknowledged.published_global_version
                            ),
                        }
                    )
            except Exception:
                # The source P1 execution and PENDING/CLAIMED event are already
                # durable.  Publication is an idempotent recoverable saga and
                # must not require the counselor to re-consume an approval.
                pass
        return response.model_dump(mode="json", exclude={"request_id", "response_type", "success", "schema_version"})

    def _append(
        self,
        live: _LiveSession,
        request: AppendSessionTurnInput,
    ) -> AppendClientTurnResponse:
        risk_runtime = self._risk_evaluation
        if risk_runtime is None:
            raise SessionRuntimeError("RISK_EVALUATION_UNAVAILABLE")
        try:
            risk_authority = RiskEvaluationAuthorityBinding.model_validate(
                risk_runtime.current_authority(),
                strict=True,
            )
        except Exception:  # noqa: BLE001 - fail closed at authority seam
            raise SessionRuntimeError("RISK_EVALUATION_FAILED") from None
        response = live.worker.call(
            AppendClientTurnRequest(
                request_id=self._request_id(),
                session_id=live.session_id,
                turn_id=request.turn_id,
                client_message=request.client_message,
                risk_authority=risk_authority,
            )
        )
        if (
            type(response) is not AppendClientTurnResponse
            or response.session_id != live.session_id
            or response.turn_id != request.turn_id
            or response.client_message_ref.content_sha256
            != hashlib.sha256(request.client_message.encode("utf-8")).hexdigest()
        ):
            raise SessionRuntimeError("SESSION_APPEND_FAILED")
        try:
            observations = risk_runtime.evaluate_turn(
                session_id=live.session_id,
                turn_id=request.turn_id,
                content_ref=response.client_message_ref,
                text=request.client_message,
                approved_context_keys=frozenset(
                    {"client_turn_present", "synthetic_context_present"}
                ),
                authority=risk_authority,
            )
            if observations:
                self._assert_risk_observations_bound_to_turn(
                    observations,
                    session_id=live.session_id,
                    turn_id=request.turn_id,
                    content_ref=response.client_message_ref,
                    text=request.client_message,
                )
            persist_request = PersistRiskObservationsRequest(
                request_id=self._request_id(),
                session_id=live.session_id,
                turn_id=request.turn_id,
                risk_authority=risk_authority,
                observations=observations,
            )
            persisted = live.worker.call(persist_request)
            expected_set_sha256 = canonical_risk_observation_set_sha256(
                persist_request.observations
            )
            if (
                type(persisted) is not PersistRiskObservationsResponse
                or persisted.session_id != persist_request.session_id
                or persisted.turn_id != persist_request.turn_id
                or persisted.client_message_sha256
                != response.client_message_sha256
                or persisted.risk_authority != risk_authority
                or persisted.observation_set_sha256 != expected_set_sha256
                or persisted.observation_count != len(observations)
                or canonical_risk_observation_set_sha256(
                    persisted.observations
                )
                != expected_set_sha256
            ):
                raise SessionRuntimeError("RISK_PERSISTENCE_FAILED")
        except SessionRuntimeError:
            raise
        except Exception:  # noqa: BLE001 - fail closed at evaluator/worker seam
            raise SessionRuntimeError("RISK_EVALUATION_FAILED") from None
        return response

    def _ensure_current_turn_risk_evaluation(
        self,
        live: _LiveSession,
        *,
        turn_id: str,
        authority: RiskEvaluationAuthorityBinding,
    ) -> None:
        """Recover or complete the latest authority-bound turn evaluation."""

        risk_runtime = self._risk_evaluation
        if risk_runtime is None:
            raise SessionRuntimeError("RISK_EVALUATION_UNAVAILABLE")
        prepare_request = PrepareTurnRiskEvaluationRequest(
            request_id=self._request_id(),
            session_id=live.session_id,
            turn_id=turn_id,
            risk_authority=authority,
        )
        prepared = live.worker.call(prepare_request)
        if (
            type(prepared) is not PrepareTurnRiskEvaluationResponse
            or prepared.request_id != prepare_request.request_id
            or prepared.session_id != live.session_id
            or prepared.turn_id != turn_id
            or prepared.risk_authority != authority
            or prepared.client_message_ref.content_sha256
            != prepared.client_message_sha256
            or hashlib.sha256(prepared.client_message.encode("utf-8")).hexdigest()
            != prepared.client_message_sha256
        ):
            raise SessionRuntimeError("RISK_EVALUATION_RECOVERY_FAILED")
        if prepared.evaluation_status == "completed":
            return
        try:
            observations = risk_runtime.evaluate_turn(
                session_id=live.session_id,
                turn_id=turn_id,
                content_ref=prepared.client_message_ref,
                text=prepared.client_message,
                approved_context_keys=frozenset(
                    {"client_turn_present", "synthetic_context_present"}
                ),
                authority=authority,
            )
            if observations:
                self._assert_risk_observations_bound_to_turn(
                    observations,
                    session_id=live.session_id,
                    turn_id=turn_id,
                    content_ref=prepared.client_message_ref,
                    text=prepared.client_message,
                )
            persist_request = PersistRiskObservationsRequest(
                request_id=self._request_id(),
                session_id=live.session_id,
                turn_id=turn_id,
                risk_authority=authority,
                observations=observations,
            )
            persisted = live.worker.call(persist_request)
            expected_set_sha256 = canonical_risk_observation_set_sha256(
                observations
            )
            if (
                type(persisted) is not PersistRiskObservationsResponse
                or persisted.request_id != persist_request.request_id
                or persisted.session_id != live.session_id
                or persisted.turn_id != turn_id
                or persisted.client_message_sha256
                != prepared.client_message_sha256
                or persisted.risk_authority != authority
                or persisted.observation_set_sha256 != expected_set_sha256
                or persisted.observation_count != len(observations)
                or canonical_risk_observation_set_sha256(persisted.observations)
                != expected_set_sha256
            ):
                raise SessionRuntimeError("RISK_PERSISTENCE_FAILED")
        except SessionRuntimeError:
            raise
        except Exception:  # noqa: BLE001 - fail closed at evaluator/worker seam
            raise SessionRuntimeError("RISK_EVALUATION_FAILED") from None

    @staticmethod
    def _assert_risk_observations_bound_to_turn(
        observations: tuple[InternalRiskObservationRecord, ...],
        *,
        session_id: str,
        turn_id: str,
        content_ref: VersionRef,
        text: str,
    ) -> None:
        identifiers = tuple(
            item.observation.observation_id for item in observations
        )
        if identifiers != tuple(sorted(set(identifiers))):
            raise SessionRuntimeError("RISK_EVALUATION_FAILED")
        for record in observations:
            if (
                record.session_id != session_id
                or record.status != "open"
                or record.observation.trigger_turn_ids != (turn_id,)
            ):
                raise SessionRuntimeError("RISK_EVALUATION_FAILED")
            for span in record.trigger_spans:
                span_text = text[span.start_offset : span.end_offset]
                normalized_length, normalized_span_sha256 = (
                    normalized_sensitive_fingerprint(span_text)
                )
                if (
                    span.turn_id != turn_id
                    or span.content_ref != content_ref
                    or span.end_offset > len(text)
                    or hashlib.sha256(span_text.encode("utf-8")).hexdigest()
                    != span.span_sha256
                    or normalized_length != span.normalized_length
                    or normalized_span_sha256 != span.normalized_span_sha256
                ):
                    raise SessionRuntimeError("RISK_EVALUATION_FAILED")

    def _store_candidates(
        self,
        live: _LiveSession,
        request: StoreCandidateSetInput,
    ) -> StoreCandidateSetResponse:
        state = self.read_state(live)
        turn = next(
            (item for item in state.turns if item.turn_id == request.turn_id),
            None,
        )
        if turn is None:
            raise SessionRuntimeError("SESSION_TURN_UNAVAILABLE")
        if turn.state == "client_turn_received":
            live.worker.call(
                BeginGenerationRequest(
                    request_id=self._request_id(),
                    session_id=live.session_id,
                    turn_id=request.turn_id,
                    run_id=request.run_id,
                )
            )
        elif turn.state == "generation_in_progress" and turn.active_run_id != request.run_id:
            raise SessionRuntimeError("SESSION_RUN_CONFLICT")
        elif turn.state not in {"generation_in_progress", "awaiting_actual_reply"}:
            raise SessionRuntimeError("SESSION_TURN_STATE_INVALID")
        response = live.worker.call(
            StoreCandidateSetRequest(
                request_id=self._request_id(),
                session_id=live.session_id,
                turn_id=request.turn_id,
                run_id=request.run_id,
                idempotency_key=request.idempotency_key,
                candidates=tuple(
                    CandidateDraft(label=item.label, text=item.text)
                    for item in request.candidates
                ),
            )
        )
        if type(response) is not StoreCandidateSetResponse:
            raise SessionRuntimeError("SESSION_CANDIDATE_STORE_FAILED")
        return response

    def _append_temporary_fact(
        self,
        live: _LiveSession,
        request: AppendTemporaryFactInput,
    ) -> AppendTemporaryFactResponse:
        response = live.worker.call(
            AppendTemporaryFactRequest(
                request_id=self._request_id(),
                session_id=live.session_id,
                turn_id=request.turn_id,
                idempotency_key=request.idempotency_key,
                event_kind=request.event_kind,
                cognitive_type=request.cognitive_type,
                value=request.value,
                target_fact_id=request.target_fact_id,
                target_fact_version=request.target_fact_version,
            )
        )
        if type(response) is not AppendTemporaryFactResponse:
            raise SessionRuntimeError("SESSION_TEMPORARY_FACT_FAILED")
        return response

    def _record_actual(
        self,
        live: _LiveSession,
        request: RecordActualReplyInput,
    ) -> RecordActualReplyResponse:
        worker_request = RecordActualReplyRequest(
            request_id=self._request_id(),
            session_id=live.session_id,
            turn_id=request.turn_id,
            idempotency_key=request.idempotency_key,
            mode=request.mode,
            candidate_id=request.candidate_id,
            actual_text=request.actual_text,
            sent_at=request.sent_at,
            confirmed_at=request.confirmed_at,
        )
        response = live.worker.call(worker_request)
        if (
            type(response) is not RecordActualReplyResponse
            or not record_actual_reply_response_matches_request(
                worker_request,
                response,
            )
        ):
            raise SessionRuntimeError("SESSION_ACTUAL_REPLY_FAILED")
        return response

    def _submit_generation_stage(
        self,
        live: _LiveSession,
        request: SubmitGenerationStageInput,
        *,
        binding: BoundTransport,
    ) -> SubmitGenerationStageResponse:
        if not isinstance(request.payload, QueryPlan):
            self._assert_generation_binding_current(
                live,
                turn_id=request.payload.envelope.turn_id,
                run_id=request.payload.envelope.run_id,
                binding=binding,
            )
            submit_request = SubmitGenerationStageRequest(
                request_id=self._request_id(),
                session_id=live.session_id,
                idempotency_key=request.idempotency_key,
                stage_payload=request.payload,
                revision_reason=request.revision_reason,
            )
            response = live.worker.call(submit_request)
            if (
                type(response) is not SubmitGenerationStageResponse
                or not submit_generation_stage_response_matches_request(
                    submit_request,
                    response,
                )
            ):
                raise SessionRuntimeError("GENERATION_STAGE_SUBMIT_FAILED")
            envelope = request.payload.envelope
            self._assert_generation_binding_current(
                live,
                turn_id=envelope.turn_id,
                run_id=envelope.run_id,
                binding=binding,
            )
            return response

        plan = request.payload
        client_binding = self._generation_client_binding(
            live,
            turn_id=plan.envelope.turn_id,
        )
        global_binding = self._require_generation_runtime().generation_global_binding(
            binding=binding
        )
        risk_authority = self._current_risk_authority(
            global_runtime_epoch=global_binding.global_runtime_epoch,
        )
        self._assert_query_plan_binding(plan, client_binding, global_binding)
        self._ensure_current_turn_risk_evaluation(
            live,
            turn_id=plan.envelope.turn_id,
            authority=risk_authority,
        )
        if self._current_risk_authority(
            global_runtime_epoch=global_binding.global_runtime_epoch,
        ) != risk_authority:
            raise SessionRuntimeError("QUERY_PLAN_CORRECTION_REQUIRED")
        submit_request = SubmitGenerationStageRequest(
            request_id=self._request_id(),
            session_id=live.session_id,
            idempotency_key=request.idempotency_key,
            stage_payload=request.payload,
            revision_reason=request.revision_reason,
            risk_authority=risk_authority,
        )
        response = live.worker.call(submit_request)
        if (
            type(response) is not SubmitGenerationStageResponse
            or not submit_generation_stage_response_matches_request(
                submit_request,
                response,
            )
        ):
            raise SessionRuntimeError("GENERATION_STAGE_SUBMIT_FAILED")
        plan_sha256 = response.record.artifact.content_sha256
        recovered = self._generation_evidence_for_plan(
            live,
            turn_id=plan.envelope.turn_id,
            run_id=plan.envelope.run_id,
            query_plan_sha256=plan_sha256,
        )
        if recovered.ready:
            if recovered.evidence_pack is None:
                raise SessionRuntimeError("GENERATION_EVIDENCE_RECOVERY_FAILED")
            self._assert_evidence_pack_binding(
                plan,
                recovered.evidence_pack,
                client_binding,
                global_binding,
            )
            ready = SubmitGenerationStageResponse.model_validate(
                {
                    **response.model_dump(mode="python"),
                    "retrieval_status": "ready",
                    "evidence_pack_ref": recovered.evidence_pack_ref,
                    "evidence_pack_sha256": recovered.evidence_pack_sha256,
                    "evidence_pack": recovered.evidence_pack,
                    "evidence_context_ref": recovered.evidence_context_ref,
                    "evidence_context_sha256": recovered.evidence_context_sha256,
                    "evidence_context": recovered.evidence_context,
                    "retrieval_metadata": recovered.retrieval_metadata,
                },
                strict=True,
            )
            self._assert_generation_binding_current(
                live,
                turn_id=plan.envelope.turn_id,
                run_id=plan.envelope.run_id,
                binding=binding,
            )
            if self._current_risk_authority(
                global_runtime_epoch=global_binding.global_runtime_epoch,
            ) != risk_authority:
                raise SessionRuntimeError("QUERY_PLAN_CORRECTION_REQUIRED")
            return ready

        prepare_request = PrepareGenerationRetrievalRequest(
            request_id=self._request_id(),
            session_id=live.session_id,
            turn_id=plan.envelope.turn_id,
            run_id=plan.envelope.run_id,
            query_plan_sha256=plan_sha256,
            risk_authority=self._current_risk_authority(
                global_runtime_epoch=global_binding.global_runtime_epoch,
            ),
            query_categories=self._generation_query_categories(plan),
        )
        prepared = live.worker.call(prepare_request)
        if (
            type(prepared) is not PrepareGenerationRetrievalResponse
            or prepared.request_id != prepare_request.request_id
            or prepared.session_id != live.session_id
            or prepared.turn_id != plan.envelope.turn_id
            or prepared.run_id != plan.envelope.run_id
            or prepared.query_plan_sha256 != plan_sha256
            or prepared.risk_context_binding.turn_id != plan.envelope.turn_id
            or prepared.risk_context_binding.authority
            != prepare_request.risk_authority
        ):
            raise SessionRuntimeError("GENERATION_RETRIEVAL_PREPARE_FAILED")
        if prepared.binding != client_binding:
            raise SessionRuntimeError("GENERATION_BINDING_STALE")
        self._assert_c1_applicability_input_binding(
            plan,
            plan_sha256,
            prepared.binding,
            prepared.c1_applicability_input,
        )

        def revalidate_client_binding() -> GenerationClientBinding:
            return self._generation_client_binding(
                live,
                turn_id=plan.envelope.turn_id,
            )

        runtime = self._require_generation_runtime()
        outcome = runtime.retrieve_generation_plan(
            plan,
            prepared.binding,
            prepared.private_evidence,
            binding=binding,
            revalidate_binding=revalidate_client_binding,
            c1_applicability_input=prepared.c1_applicability_input,
            risk_context_binding=prepared.risk_context_binding,
        )
        self._assert_evidence_pack_binding(
            plan,
            outcome.evidence_pack,
            prepared.binding,
            global_binding,
        )
        current_global = runtime.generation_global_binding(binding=binding)
        if not self._same_global_binding(current_global, global_binding):
            raise SessionRuntimeError("GENERATION_BINDING_STALE")
        if self._current_risk_authority(
            global_runtime_epoch=global_binding.global_runtime_epoch,
        ) != prepare_request.risk_authority:
            raise SessionRuntimeError("QUERY_PLAN_CORRECTION_REQUIRED")
        store_request = StoreGenerationEvidencePackRequest(
            request_id=self._request_id(),
            session_id=live.session_id,
            turn_id=plan.envelope.turn_id,
            run_id=plan.envelope.run_id,
            query_plan_sha256=plan_sha256,
            evidence_pack=outcome.evidence_pack,
            evidence_context=outcome.evidence_context,
            run_objects=outcome.run_objects,
            retrieval_metadata=outcome.metadata,
        )
        stored = live.worker.call(store_request)
        if (
            type(stored) is not StoreGenerationEvidencePackResponse
            or stored.request_id != store_request.request_id
            or stored.session_id != live.session_id
            or stored.turn_id != plan.envelope.turn_id
            or stored.run_id != plan.envelope.run_id
            or stored.query_plan_sha256 != plan_sha256
        ):
            raise SessionRuntimeError("GENERATION_EVIDENCE_STORE_FAILED")
        if stored.evidence_pack_sha256 != outcome.evidence_pack_sha256:
            raise SessionRuntimeError("GENERATION_EVIDENCE_STORE_MISMATCH")
        if stored.evidence_pack != outcome.evidence_pack:
            raise SessionRuntimeError("GENERATION_EVIDENCE_STORE_MISMATCH")
        self._assert_evidence_pack_binding(
            plan,
            stored.evidence_pack,
            prepared.binding,
            global_binding,
        )
        if tuple(
            item
            for item in stored.evidence_context
            if item.context_kind == "retrieved_candidate"
        ) != outcome.evidence_context:
            raise SessionRuntimeError("GENERATION_EVIDENCE_STORE_MISMATCH")
        ready = SubmitGenerationStageResponse.model_validate(
            {
                **response.model_dump(mode="python"),
                "retrieval_status": "ready",
                "evidence_pack_ref": stored.evidence_pack_ref,
                "evidence_pack_sha256": stored.evidence_pack_sha256,
                "evidence_pack": stored.evidence_pack,
                "evidence_context_ref": stored.evidence_context_ref,
                "evidence_context_sha256": stored.evidence_context_sha256,
                "evidence_context": stored.evidence_context,
                "retrieval_metadata": stored.retrieval_metadata,
            },
            strict=True,
        )
        self._assert_generation_binding_current(
            live,
            turn_id=plan.envelope.turn_id,
            run_id=plan.envelope.run_id,
            binding=binding,
        )
        if self._current_risk_authority(
            global_runtime_epoch=global_binding.global_runtime_epoch,
        ) != prepare_request.risk_authority:
            raise SessionRuntimeError("QUERY_PLAN_CORRECTION_REQUIRED")
        return ready

    def _assert_generation_binding_current(
        self,
        live: _LiveSession,
        *,
        turn_id: str,
        run_id: str,
        binding: BoundTransport,
    ) -> None:
        state_request = GetGenerationStateRequest(
            request_id=self._request_id(),
            session_id=live.session_id,
            turn_id=turn_id,
            run_id=run_id,
        )
        state = live.worker.call(state_request)
        if (
            type(state) is not GetGenerationStateResponse
            or state.request_id != state_request.request_id
            or state.session_id != live.session_id
            or state.turn_id != turn_id
            or state.run_id != run_id
        ):
            raise SessionRuntimeError("GENERATION_STATE_READ_FAILED")
        plan_records = tuple(
            record
            for record in state.records
            if isinstance(record.payload, QueryPlan)
        )
        if len(plan_records) != 1:
            raise SessionRuntimeError("GENERATION_BINDING_INVALID")
        plan_record = plan_records[0]
        plan = cast(QueryPlan, plan_record.payload)
        evidence = self._generation_evidence_for_plan(
            live,
            turn_id=turn_id,
            run_id=run_id,
            query_plan_sha256=plan_record.artifact.content_sha256,
        )
        if (
            not evidence.ready
            or evidence.evidence_context is None
        ):
            raise SessionRuntimeError("GENERATION_BINDING_INVALID")
        frozen_temporary_refs = tuple(
            sorted(
                (
                    item.text_ref
                    for item in evidence.evidence_context
                    if item.context_kind == "temporary_fact"
                ),
                key=lambda item: (
                    item.object_id,
                    item.version,
                    item.content_sha256,
                ),
            )
        )
        if frozen_temporary_refs != state.client_binding.temporary_fact_refs:
            raise SessionRuntimeError("QUERY_PLAN_CORRECTION_REQUIRED")
        global_binding = self._require_generation_runtime().generation_global_binding(
            binding=binding
        )
        if evidence.evidence_pack is None:
            raise SessionRuntimeError("GENERATION_BINDING_INVALID")
        self._assert_evidence_pack_binding(
            plan,
            evidence.evidence_pack,
            state.client_binding,
            global_binding,
        )
        self._assert_query_plan_binding(
            plan,
            state.client_binding,
            global_binding,
        )

    def _require_generation_runtime(self) -> GenerationRetrievalRuntime:
        runtime = self._generation_retrieval
        if runtime is None:
            raise SessionRuntimeError("GENERATION_RETRIEVAL_UNAVAILABLE")
        return runtime

    def _current_risk_authority(
        self,
        *,
        global_runtime_epoch: int,
    ) -> RiskEvaluationAuthorityBinding:
        runtime = self._risk_evaluation
        if runtime is None:
            raise SessionRuntimeError("RISK_EVALUATION_UNAVAILABLE")
        try:
            authority = RiskEvaluationAuthorityBinding.model_validate(
                runtime.current_authority(),
                strict=True,
            )
        except Exception:  # noqa: BLE001 - fail closed at authority seam
            raise SessionRuntimeError("RISK_EVALUATION_FAILED") from None
        if authority.global_runtime_epoch != global_runtime_epoch:
            raise SessionRuntimeError("QUERY_PLAN_CORRECTION_REQUIRED")
        return authority

    def _generation_client_binding(
        self,
        live: _LiveSession,
        *,
        turn_id: str,
    ) -> GenerationClientBinding:
        binding_request = GetGenerationBindingRequest(
            request_id=self._request_id(),
            session_id=live.session_id,
            turn_id=turn_id,
        )
        response = live.worker.call(binding_request)
        if (
            type(response) is not GetGenerationBindingResponse
            or response.request_id != binding_request.request_id
            or response.session_id != live.session_id
            or response.turn_id != turn_id
        ):
            raise SessionRuntimeError("GENERATION_BINDING_READ_FAILED")
        return response.binding

    def _generation_evidence_for_plan(
        self,
        live: _LiveSession,
        *,
        turn_id: str,
        run_id: str,
        query_plan_sha256: str,
    ) -> GetGenerationEvidenceForPlanResponse:
        evidence_request = GetGenerationEvidenceForPlanRequest(
            request_id=self._request_id(),
            session_id=live.session_id,
            turn_id=turn_id,
            run_id=run_id,
            query_plan_sha256=query_plan_sha256,
        )
        response = live.worker.call(evidence_request)
        if (
            type(response) is not GetGenerationEvidenceForPlanResponse
            or response.request_id != evidence_request.request_id
            or response.session_id != live.session_id
            or response.turn_id != turn_id
            or response.run_id != run_id
            or response.query_plan_sha256 != query_plan_sha256
        ):
            raise SessionRuntimeError("GENERATION_EVIDENCE_RECOVERY_FAILED")
        return response

    @staticmethod
    def _same_global_binding(
        left: GenerationGlobalBinding,
        right: GenerationGlobalBinding,
    ) -> bool:
        return (
            left.global_runtime_epoch == right.global_runtime_epoch
            and left.global_tombstone_epoch == right.global_tombstone_epoch
            and left.authorization_epoch == right.authorization_epoch
            and left.authority_policy_ref == right.authority_policy_ref
            and left.roots == right.roots
            and left.available_routes == right.available_routes
        )

    @staticmethod
    def _assert_c1_applicability_input_binding(
        plan: QueryPlan,
        plan_sha256: str,
        client: GenerationClientBinding,
        applicability_input: C1ApplicabilityInput,
    ) -> None:
        try:
            exact = C1ApplicabilityInput.model_validate(
                applicability_input,
                strict=True,
            )
            exact.assert_plan_closure(plan)
        except (TypeError, ValueError):
            raise SessionRuntimeError(
                "QUERY_PLAN_CORRECTION_REQUIRED"
            ) from None
        if (
            exact.query_plan_sha256 != plan_sha256
            or exact.client_snapshot_ref != client.client_snapshot_ref
            or exact.client_runtime_epoch != client.client_runtime_epoch
            or exact.client_tombstone_count != client.client_tombstone_count
            or exact.temporary_fact_refs != client.temporary_fact_refs
        ):
            raise SessionRuntimeError("QUERY_PLAN_CORRECTION_REQUIRED")

    @staticmethod
    def _assert_evidence_pack_binding(
        plan: QueryPlan,
        pack: EvidencePack,
        client: GenerationClientBinding,
        global_binding: GenerationGlobalBinding,
    ) -> None:
        authority = pack.authority
        roots = global_binding.roots
        expected_tombstone = (
            global_binding.global_tombstone_epoch
            | client.client_tombstone_count
        )
        if (
            pack.run_id != plan.envelope.run_id
            or authority.run_id != plan.envelope.run_id
            or pack.client_snapshot_ref != plan.client_snapshot_ref
            or pack.client_snapshot_ref != client.client_snapshot_ref
            or pack.temporary_fact_refs != client.temporary_fact_refs
            or authority.global_runtime_epoch != plan.global_runtime_epoch
            or authority.global_runtime_epoch != global_binding.global_runtime_epoch
            or authority.client_runtime_epoch != plan.client_runtime_epoch
            or authority.client_runtime_epoch != client.client_runtime_epoch
            or authority.tombstone_epoch != plan.tombstone_epoch
            or authority.tombstone_epoch != expected_tombstone
            or authority.authorization_epoch != plan.authorization_epoch
            or authority.authorization_epoch != global_binding.authorization_epoch
            or authority.policy_ref != global_binding.authority_policy_ref
            or pack.wiki_manifest_ref != roots.wiki_manifest_ref
            or pack.lexical_manifest_ref != roots.lexical_manifest_ref
            or pack.vector_manifest_ref != roots.vector_manifest_ref
            or pack.graph_manifest_ref != roots.graph_manifest_ref
        ):
            raise SessionRuntimeError("QUERY_PLAN_CORRECTION_REQUIRED")

    @staticmethod
    def _assert_query_plan_binding(
        plan: QueryPlan,
        client: GenerationClientBinding,
        global_binding: GenerationGlobalBinding,
    ) -> None:
        expected_tombstone = (
            global_binding.global_tombstone_epoch
            | client.client_tombstone_count
        )
        used_routes = {
            route for subquery in plan.subqueries for route in subquery.routes
        }
        if (
            global_binding.global_tombstone_epoch & 0xFFFFFFFF
            or plan.client_snapshot_ref != client.client_snapshot_ref
            or plan.global_runtime_epoch != global_binding.global_runtime_epoch
            or plan.client_runtime_epoch != client.client_runtime_epoch
            or plan.tombstone_epoch != expected_tombstone
            or plan.authorization_epoch != global_binding.authorization_epoch
            or not used_routes <= set(global_binding.available_routes)
        ):
            raise SessionRuntimeError("QUERY_PLAN_CORRECTION_REQUIRED")

    @staticmethod
    def _generation_query_categories(
        plan: QueryPlan,
    ) -> tuple[ClientHistoryQueryCategory, ...]:
        categories: set[ClientHistoryQueryCategory] = set()
        for subquery in plan.subqueries:
            if "profile" in subquery.routes:
                categories.add("current_profile")
            if "client_history" in subquery.routes:
                categories.add(
                    "relationship_history"
                    if subquery.category
                    in {"emotion_needs_relationship", "historical_change"}
                    else "continuity"
                )
            if subquery.category == "historical_change":
                categories.add("continuity")
            if subquery.category == "internal_risk":
                categories.add("unresolved_items")
        if not categories:
            categories.add("continuity")
        return tuple(sorted(categories))

    def _get_generation_state(
        self,
        live: _LiveSession,
        request: GetGenerationStateInput,
        *,
        binding: BoundTransport,
    ) -> dict[str, object]:
        state_request = GetGenerationStateRequest(
            request_id=self._request_id(),
            session_id=live.session_id,
            turn_id=request.turn_id,
            run_id=request.run_id,
        )
        response = live.worker.call(state_request)
        if (
            type(response) is not GetGenerationStateResponse
            or response.request_id != state_request.request_id
            or response.session_id != live.session_id
            or response.turn_id != request.turn_id
            or response.run_id != request.run_id
        ):
            raise SessionRuntimeError("GENERATION_STATE_READ_FAILED")
        global_binding = self._require_generation_runtime().generation_global_binding(
            binding=binding
        )
        result: dict[str, object] = {
            **response.model_dump(mode="python"),
            "query_binding": self._query_binding(
                response.client_binding,
                global_binding,
            ),
        }
        plans = tuple(
            record
            for record in response.records
            if isinstance(record.payload, QueryPlan)
        )
        if len(plans) > 1:
            raise SessionRuntimeError("GENERATION_BINDING_INVALID")
        if plans:
            plan_record = plans[0]
            plan = cast(QueryPlan, plan_record.payload)
            self._assert_query_plan_binding(
                plan,
                response.client_binding,
                global_binding,
            )
            evidence = self._generation_evidence_for_plan(
                live,
                turn_id=request.turn_id,
                run_id=request.run_id,
                query_plan_sha256=plan_record.artifact.content_sha256,
            )
            if evidence.ready and evidence.evidence_context is not None:
                if evidence.evidence_pack is None:
                    raise SessionRuntimeError("GENERATION_EVIDENCE_RECOVERY_FAILED")
                self._assert_evidence_pack_binding(
                    plan,
                    evidence.evidence_pack,
                    response.client_binding,
                    global_binding,
                )
                frozen_temporary_refs = tuple(
                    sorted(
                        (
                            item.text_ref
                            for item in evidence.evidence_context
                            if item.context_kind == "temporary_fact"
                        ),
                        key=lambda item: (
                            item.object_id,
                            item.version,
                            item.content_sha256,
                        ),
                    )
                )
                if frozen_temporary_refs != response.client_binding.temporary_fact_refs:
                    raise SessionRuntimeError("QUERY_PLAN_CORRECTION_REQUIRED")
            result["generation_evidence"] = evidence.model_dump(
                mode="python",
                exclude={"request_id", "session_id", "turn_id", "run_id"},
            )
        return result

    def _query_binding(
        self,
        client_binding: GenerationClientBinding,
        global_binding: GenerationGlobalBinding,
    ) -> dict[str, object]:
        exact_client = GenerationClientBinding.model_validate(
            client_binding,
            strict=True,
        )
        if global_binding.global_tombstone_epoch & 0xFFFFFFFF:
            raise SessionRuntimeError("GENERATION_BINDING_INVALID")
        return {
            "client_snapshot_ref": exact_client.client_snapshot_ref,
            "global_runtime_epoch": global_binding.global_runtime_epoch,
            "client_runtime_epoch": exact_client.client_runtime_epoch,
            "tombstone_epoch": (
                global_binding.global_tombstone_epoch
                | exact_client.client_tombstone_count
            ),
            "authorization_epoch": global_binding.authorization_epoch,
            "temporary_fact_refs": exact_client.temporary_fact_refs,
            "authority_policy_ref": global_binding.authority_policy_ref,
            "roots": global_binding.roots,
            "available_routes": global_binding.available_routes,
            "created_at": global_binding.created_at,
        }

    def _acknowledge_risk_observation(
        self,
        live: _LiveSession,
        request: AcknowledgeRiskObservationInput,
    ) -> AcknowledgeRiskObservationResponse:
        worker_request = AcknowledgeRiskObservationRequest(
            request_id=self._request_id(),
            session_id=live.session_id,
            observation_id=request.observation_id,
            action=request.action,
            counselor_disposition=request.counselor_disposition,
            rejection_reason=request.rejection_reason,
            close_decision=request.close_decision,
            close_reason=request.close_reason,
        )
        response = live.worker.call(worker_request)
        if (
            type(response) is not AcknowledgeRiskObservationResponse
            or not risk_lifecycle_response_matches_request(
                worker_request,
                response,
            )
        ):
            raise SessionRuntimeError("RISK_ACKNOWLEDGEMENT_FAILED")
        return response

    def read_state(self, live: _LiveSession) -> ReadSessionStateResponse:
        response = live.worker.call(
            ReadSessionStateRequest(
                request_id=self._request_id(),
                session_id=live.session_id,
            )
        )
        if type(response) is not ReadSessionStateResponse:
            raise SessionRuntimeError("SESSION_STATE_FAILED")
        return response

    @staticmethod
    def _history_category(query: str) -> ClientHistoryQueryCategory:
        """Map free text to a closed worker category; raw text never crosses."""

        normalized = query.casefold()
        if any(token in normalized for token in ("未解决", "问题", "unresolved")):
            return "unresolved_items"
        if any(
            token in normalized
            for token in (
                "关系",
                "伴侣",
                "男友",
                "女友",
                "男朋友",
                "女朋友",
                "配偶",
                "丈夫",
                "妻子",
                "恋人",
                "对象",
                "前任",
                "relationship",
                "partner",
            )
        ):
            return "relationship_history"
        if any(token in normalized for token in ("资料", "当前", "profile", "current")):
            return "current_profile"
        return "continuity"

    def search_client_history(
        self,
        request: SearchClientHistoryInput,
        *,
        binding: BoundTransport | None,
    ) -> tuple[dict[str, object], ...]:
        with self._lock:
            live = self._require(binding)
            category = self._history_category(request.query)
            response = live.worker.call(
                QueryClientHistoryCandidatesRequest(
                    request_id=self._request_id(),
                    session_handle=live.session_handle,
                    query_category=category,
                    as_of=(self._clock.now() if request.as_of is None else request.as_of),
                )
            )
            if type(response) is not QueryClientHistoryCandidatesResponse:
                raise SessionRuntimeError("SESSION_HISTORY_FAILED")
            return tuple(
                {
                    "reference": item.reference.model_dump(mode="json"),
                    "content_ref": item.content_ref.model_dump(mode="json"),
                    "object_type": item.object_type,
                    "channel": item.channel,
                    "score": item.score,
                    "source_grade": item.metadata.source_grade,
                    "framework_priority": item.metadata.framework_priority,
                    "review_status": item.metadata.review_status,
                    "effective_from": item.metadata.effective_from,
                    "effective_to": item.metadata.effective_to,
                    "review_due_at": item.metadata.review_due_at,
                }
                for item in response.candidates[: request.limit]
            )

    def invoke_scoped_graph(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object:
        """Execute client graph operations only in the bound worker process."""

        with self._lock:
            live = self._require(binding)
            if tool_name == "query_client_graph":
                graph_values = cast(QueryClientGraphInput, request)
                response = live.worker.call(
                    SearchClientGraphRequest(
                        request_id=self._request_id(),
                        query=graph_values.query,
                        as_of=(
                            self._clock.now()
                            if graph_values.as_of is None
                            else graph_values.as_of
                        ),
                        max_depth=graph_values.max_depth,
                        limit=graph_values.limit,
                    )
                )
                if type(response) is not SearchClientGraphResponse:
                    raise SessionRuntimeError("SESSION_CLIENT_GRAPH_FAILED")
                return {
                    "status": "ok" if response.count else "no_matches",
                    "channel": "client_graph",
                    "graph_sha256": response.graph_sha256,
                    "source_client_commit_version": (
                        response.source_client_commit_version
                    ),
                    "runtime_epoch": response.runtime_epoch,
                    "query_mode": response.query_mode,
                    "node_count": response.node_count,
                    "edge_count": response.edge_count,
                    "count": response.count,
                    "items": tuple(
                        item.model_dump(mode="json") for item in response.items
                    ),
                    "truncated": response.truncated,
                }
            if tool_name == "weighted_path":
                path_values = cast(WeightedPathInput, request)
                response = live.worker.call(
                    QueryClientWeightedPathRequest(
                        request_id=self._request_id(),
                        source_ref=path_values.source_ref,
                        target_ref=path_values.target_ref,
                        as_of=(
                            self._clock.now()
                            if path_values.as_of is None
                            else path_values.as_of
                        ),
                        max_paths=path_values.max_paths,
                        max_hops=min(path_values.max_hops, 12),
                    )
                )
                if type(response) is not QueryClientWeightedPathResponse:
                    raise SessionRuntimeError("SESSION_CLIENT_PATH_FAILED")
                return {
                    "status": "ok" if response.count else "no_matches",
                    "channel": "client_graph_weighted_path",
                    "graph_sha256": response.graph_sha256,
                    "source_client_commit_version": (
                        response.source_client_commit_version
                    ),
                    "runtime_epoch": response.runtime_epoch,
                    "requested_max_hops": path_values.max_hops,
                    "effective_max_hops": min(path_values.max_hops, 12),
                    "count": response.count,
                    "items": tuple(
                        path.model_dump(mode="json") for path in response.paths
                    ),
                }
            if tool_name == "preview_dependency_impact":
                impact_values = cast(PreviewDependencyImpactInput, request)
                response = live.worker.call(
                    PreviewTargetDependencyImpactRequest(
                        request_id=self._request_id(),
                        target_ref=impact_values.target_ref,
                        action=impact_values.action,
                        as_of=(
                            self._clock.now()
                            if impact_values.as_of is None
                            else impact_values.as_of
                        ),
                    )
                )
                if type(response) is not PreviewTargetDependencyImpactResponse:
                    raise SessionRuntimeError("SESSION_DEPENDENCY_IMPACT_FAILED")
                return {
                    "status": "ok",
                    "channel": "client_dependency_impact",
                    "target_ref": response.target_ref.model_dump(mode="json"),
                    "action": response.action,
                    "as_of": response.as_of,
                    "proposal_sha256": response.proposal_sha256,
                    "direct_invalidation_count": len(
                        response.direct_invalidations
                    ),
                    "manual_review_count": len(response.manual_reviews),
                    "direct_invalidations": tuple(
                        item.model_dump(mode="json")
                        for item in response.direct_invalidations
                    ),
                    "manual_reviews": tuple(
                        item.model_dump(mode="json")
                        for item in response.manual_reviews
                    ),
                }
            raise SessionRuntimeError("SESSION_GRAPH_TOOL_UNAVAILABLE")

    def close(self) -> None:
        with self._lock:
            workers = tuple(
                {
                    id(item.worker): item.worker
                    for item in self._by_handle.values()
                }.values()
            )
            self._by_handle.clear()
            self._by_client.clear()
            self._private_archive_previews.clear()
        for worker in workers:
            worker.close()


__all__ = ["SessionRuntimeError", "SessionRuntimeManager", "SessionScopeDenied"]
