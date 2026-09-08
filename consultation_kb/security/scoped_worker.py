"""Control-plane broker for one capability-bound scoped worker process."""

from __future__ import annotations

import hmac
import hashlib
import multiprocessing
import re
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol, final

from consultation_kb.approvals.models import ApprovalExecutionTicket, descriptor_sha256
from consultation_kb.approvals.review_agent import VerifiedReviewDiff
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.archive.case_publisher import (
    CasePublication,
    CasePublishAuthoritySnapshot,
    CasePublishTransfer,
)
from consultation_kb.core.ids import IdFactory
from consultation_kb.core.errors import (
    ChannelUnavailableError,
    PreviousTurnNotClosedError,
    ScopedObjectAccessDeniedError,
    WorkflowOperationalError,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.retrieval.client_history import (
    ClientHistoryQuery,
    ClientHistoryResult,
)
from consultation_kb.security.capability import CapabilityService
from consultation_kb.security.scope_broker import ScopedSession
from consultation_kb.security.worker_main import (
    _READY_FRAME,
    _encode_bootstrap,
    worker_process_main,
)
from consultation_kb.security.windows_process_start import (
    start_process_with_isolated_standard_input,
)
from consultation_kb.security.worker_claim import (
    ApprovedCommitRequest,
    ApprovedCommitResponse,
    ApprovedCommitClaimPayload,
    AppliedCommitRecoveryPayload,
    CasePublishRpcPayload,
    CasePublishRpcResultPayload,
    LocalHmacApprovedCommitClaimSigner,
    LocalHmacAppliedCommitNotAppliedResult,
    LocalHmacAppliedCommitRecoverySigner,
    LocalHmacCasePublishRpc,
    MAX_INTERNAL_FRAME_BYTES,
    decode_approved_commit_result,
    decode_applied_not_applied_result,
    decode_case_publish_result,
    decode_review_diff_result,
    encode_approved_commit_claim,
    encode_applied_recovery_claim,
    encode_case_publish_rpc,
    encode_review_diff_read,
    is_applied_not_applied_result_frame,
    ReviewDiffReadRequest,
    approved_commit_request_sha256,
)
from consultation_kb.storage.outbox import CasePublishOutboxPayload, OutboxRecord
from consultation_kb.security.worker_protocol import (
    AcknowledgeRiskObservationRequest,
    AcknowledgeRiskObservationResponse,
    MAX_FRAME_BYTES,
    AppendScopedAuditRequest,
    AppendScopedAuditResponse,
    AppendClientTurnRequest,
    AppendClientTurnResponse,
    AppendTemporaryFactRequest,
    AppendTemporaryFactResponse,
    BeginGenerationRequest,
    BeginGenerationResponse,
    BeginSessionRequest,
    BeginSessionResponse,
    BuildPrivateArchiveRequest,
    BuildPrivateArchiveResponse,
    BuildProfileDiffRequest,
    BuildProfileDiffResponse,
    CommitClientTombstoneRequest,
    CommitClientTombstoneResponse,
    CommitClientRollbackRequest,
    CommitClientRollbackResponse,
    CommitFactMutationRequest,
    CommitFactMutationResponse,
    CommitPrivateArchiveRequest,
    CommitPrivateArchiveResponse,
    CommitProfileUpdateRequest,
    CommitProfileUpdateResponse,
    EmptyContextMetadataRequest,
    EmptyContextMetadataResponse,
    GetGenerationEvidenceForPlanRequest,
    GetGenerationEvidenceForPlanResponse,
    GetGenerationBindingRequest,
    GetGenerationBindingResponse,
    GetGenerationStateRequest,
    GetGenerationStateResponse,
    PingRequest,
    PingResponse,
    PersistRiskObservationsRequest,
    PersistRiskObservationsResponse,
    PreflightClientLifecycleCommitRequest,
    PreflightClientLifecycleCommitResponse,
    PreviewDependencyImpactRequest,
    PreviewDependencyImpactResponse,
    PreviewTargetDependencyImpactRequest,
    PreviewTargetDependencyImpactResponse,
    PreviewFactMutationRequest,
    PreviewFactMutationResponse,
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
    QueryClientGraphRequest,
    QueryClientGraphResponse,
    QueryClientWeightedPathRequest,
    QueryClientWeightedPathResponse,
    QueryClientHistoryCandidatesRequest,
    QueryClientHistoryCandidatesResponse,
    QueryFactSnapshotRequest,
    QueryFactSnapshotResponse,
    QueryProfileSnapshotRequest,
    QueryProfileSnapshotResponse,
    ReadSessionStateRequest,
    ReadSessionStateResponse,
    RecordActualReplyRequest,
    RecordActualReplyResponse,
    RebuildClientDerivativesRequest,
    RebuildClientDerivativesResponse,
    RecoverClientManifestsRequest,
    RecoverClientManifestsResponse,
    ResumeSessionRequest,
    ResumeSessionResponse,
    SearchClientGraphRequest,
    SearchClientGraphResponse,
    OperationalErrorResponse,
    ScopeDeniedResponse,
    StoreCandidateSetRequest,
    StoreCandidateSetResponse,
    StoreGenerationEvidencePackRequest,
    StoreGenerationEvidencePackResponse,
    StageSharedCaseOutboxRequest,
    StageSharedCaseOutboxResponse,
    SubmitGenerationStageRequest,
    SubmitGenerationStageResponse,
    VerifyClientIntegrityRequest,
    VerifyClientIntegrityResponse,
    WorkerPermission,
    WorkerRequest,
    WorkerResponse,
    decode_response,
    encode_message,
    record_actual_reply_response_matches_request,
    risk_lifecycle_response_matches_request,
    submit_generation_stage_response_matches_request,
    worker_request_binding,
)


_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_CLIENT_ID_RE = re.compile(r"client_[a-z0-9]{12}\Z")
_UUID7_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)


class ScopeDenied(ScopedObjectAccessDeniedError):
    """Uniform denial that reveals no scope, token, path, or existence detail."""

    def __init__(self) -> None:
        super().__init__("SCOPE_DENIED")


class CapabilityValidator(Protocol):
    """Adapter boundary for Task 5 epoch/expiry/revocation validation."""

    def assert_valid(
        self,
        capability_token: str,
        *,
        required_permission: WorkerPermission,
    ) -> None: ...


@final
class BoundCapabilityValidator:
    """Revalidate one exact control-plane session before every worker RPC."""

    __slots__ = ("_service", "_session")

    def __init__(
        self,
        capability_service: CapabilityService,
        session: ScopedSession,
    ) -> None:
        if (
            type(capability_service) is not CapabilityService
            or type(session) is not ScopedSession
        ):
            raise ScopeDenied
        self._service = capability_service
        self._session = session

    def __repr__(self) -> str:
        return "<BoundCapabilityValidator redacted>"

    def assert_valid(
        self,
        capability_token: str,
        *,
        required_permission: WorkerPermission,
    ) -> None:
        session = self._session
        try:
            binding = self._service.validate_binding(
                capability_token,
                session_id=session.session_scope.session_id,
                client_id=session.client_id,
                required_permissions=(required_permission,),
            )
            if (
                not hmac.compare_digest(
                    binding.capability_id,
                    session.capability_id,
                )
                or binding.capability_epoch != session.capability_epoch
                or not hmac.compare_digest(binding.client_id, session.client_id)
                or binding.session_scope.session_id
                != session.session_scope.session_id
            ):
                raise ScopeDenied
        except Exception:
            raise ScopeDenied from None


class _ByteConnection(Protocol):
    def send_bytes(self, buffer: bytes) -> None: ...

    def recv_bytes(self, maxlength: int | None = None) -> bytes: ...

    def poll(self, timeout: float = 0.0) -> bool: ...

    def close(self) -> None: ...


class _ProcessHandle(Protocol):
    def start(self) -> None: ...

    def is_alive(self) -> bool: ...

    def join(self, timeout: float | None = None) -> None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...


@final
@dataclass(frozen=True, slots=True, repr=False)
class WorkerScopeDescriptor:
    """Broker-verified current scope plus a non-path global descriptor."""

    scope_root: Path
    global_descriptor_sha256: str
    scope_marker_sha256: str
    session_id: str | None = None
    client_id: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.scope_root, Path)
            or not self.scope_root.is_absolute()
            or ".." in self.scope_root.parts
            or type(self.global_descriptor_sha256) is not str
            or _SHA256_RE.fullmatch(self.global_descriptor_sha256) is None
            or type(self.scope_marker_sha256) is not str
            or _SHA256_RE.fullmatch(self.scope_marker_sha256) is None
            or (
                self.session_id is not None
                and (
                    type(self.session_id) is not str
                    or _UUID7_RE.fullmatch(self.session_id) is None
                )
            )
            or (
                self.client_id is not None
                and (
                    type(self.client_id) is not str
                    or _CLIENT_ID_RE.fullmatch(self.client_id) is None
                )
            )
        ):
            raise ScopeDenied

    def __repr__(self) -> str:
        return "<WorkerScopeDescriptor redacted>"

    @classmethod
    def from_scoped_session(
        cls,
        session: ScopedSession,
    ) -> WorkerScopeDescriptor:
        if cls is not WorkerScopeDescriptor or type(session) is not ScopedSession:
            raise ScopeDenied
        return cls(
            scope_root=session.client_root,
            global_descriptor_sha256=session.global_descriptor_sha256,
            scope_marker_sha256=session.scope_marker_sha256,
            session_id=session.session_scope.session_id,
            client_id=session.client_id,
        )


@final
class ScopedWorkerBroker:
    """Spawn and serialize calls to a single current-client worker."""

    __slots__ = (
        "_call_timeout_seconds",
        "_capability_token",
        "_claim_secret",
        "_closed",
        "_connection",
        "_lock",
        "_process",
        "_scope",
        "_startup_timeout_seconds",
        "_target_attestor_id",
        "_target_attestor_secret",
        "_validator",
    )

    def __init__(
        self,
        *,
        scope: WorkerScopeDescriptor,
        capability_token: str,
        validator: CapabilityValidator,
        target_execution_attestor_secret: bytes | None = None,
        target_execution_attestor_id: str | None = None,
        startup_timeout_seconds: float = 10.0,
        call_timeout_seconds: float = 10.0,
    ) -> None:
        if (
            type(scope) is not WorkerScopeDescriptor
            or type(capability_token) is not str
            or not capability_token
            or len(capability_token) > 4096
            or not callable(getattr(validator, "assert_valid", None))
            or type(startup_timeout_seconds) is not float
            or not 0.0 < startup_timeout_seconds <= 60.0
            or type(call_timeout_seconds) is not float
            or not 0.0 < call_timeout_seconds <= 60.0
            or (target_execution_attestor_secret is None)
            != (target_execution_attestor_id is None)
            or (
                target_execution_attestor_secret is not None
                and (
                    type(target_execution_attestor_secret) is not bytes
                    or len(target_execution_attestor_secret) != 32
                    or type(target_execution_attestor_id) is not str
                    or not target_execution_attestor_id
                )
            )
        ):
            raise ScopeDenied
        self._scope: WorkerScopeDescriptor | None = scope
        self._capability_token: str | None = capability_token
        self._validator: CapabilityValidator | None = validator
        self._claim_secret: bytes | None = secrets.token_bytes(32)
        self._target_attestor_secret = target_execution_attestor_secret
        self._target_attestor_id = target_execution_attestor_id
        self._startup_timeout_seconds = startup_timeout_seconds
        self._call_timeout_seconds = call_timeout_seconds
        self._connection: _ByteConnection | None = None
        self._process: _ProcessHandle | None = None
        self._closed = False
        self._lock = threading.RLock()

    @classmethod
    def for_scoped_session(
        cls,
        *,
        session: ScopedSession,
        capability_token: str,
        capability_service: CapabilityService,
        target_execution_attestor_secret: bytes | None = None,
        target_execution_attestor_id: str | None = None,
        startup_timeout_seconds: float = 10.0,
        call_timeout_seconds: float = 10.0,
    ) -> ScopedWorkerBroker:
        if cls is not ScopedWorkerBroker:
            raise ScopeDenied
        return cls(
            scope=WorkerScopeDescriptor.from_scoped_session(session),
            capability_token=capability_token,
            validator=BoundCapabilityValidator(capability_service, session),
            target_execution_attestor_secret=target_execution_attestor_secret,
            target_execution_attestor_id=target_execution_attestor_id,
            startup_timeout_seconds=startup_timeout_seconds,
            call_timeout_seconds=call_timeout_seconds,
        )

    @property
    def is_alive(self) -> bool:
        with self._lock:
            return bool(
                not self._closed
                and self._process is not None
                and self._process.is_alive()
            )

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def _assert_capability(self, permission: WorkerPermission) -> None:
        token = self._capability_token
        validator = self._validator
        if token is None or validator is None:
            raise ScopeDenied
        try:
            validator.assert_valid(
                token,
                required_permission=permission,
            )
        except Exception:
            raise ScopeDenied from None

    def _assert_request_binding(self, request: WorkerRequest) -> None:
        """Reject cross-session targets before a frame reaches the worker."""

        session_id, session_handle = worker_request_binding(request)
        scope = self._scope
        capability_token = self._capability_token
        if session_id is not None and (
            scope is None
            or scope.session_id is None
            or not hmac.compare_digest(session_id, scope.session_id)
        ):
            raise ScopeDenied
        if session_handle is not None and (
            capability_token is None
            or not hmac.compare_digest(session_handle, capability_token)
        ):
            raise ScopeDenied

    def start(self) -> None:
        with self._lock:
            if self._closed or self._scope is None:
                raise ScopeDenied
            if self._process is not None:
                if self._process.is_alive():
                    return
                self._shutdown_locked()
                raise ScopeDenied
            try:
                self._assert_capability("client_read")
                capability_token = self._capability_token
                if capability_token is None:
                    raise ScopeDenied
                context = multiprocessing.get_context("spawn")
                parent_connection, child_connection = context.Pipe(duplex=True)
                process = context.Process(
                    target=worker_process_main,
                    args=(child_connection,),
                    daemon=True,
                    name="consultation-scoped-worker",
                )
                self._connection = parent_connection
                self._process = process
                start_process_with_isolated_standard_input(process)
                child_connection.close()
                parent_connection.send_bytes(
                    _encode_bootstrap(
                        self._scope.scope_root,
                        self._scope.global_descriptor_sha256,
                        self._scope.scope_marker_sha256,
                        session_id=self._scope.session_id,
                        capability_token_sha256=hashlib.sha256(
                            capability_token.encode("utf-8")
                        ).hexdigest(),
                        claim_verification_secret=self._claim_secret,
                        execution_attestor_secret=self._target_attestor_secret,
                        execution_attestor_id=self._target_attestor_id,
                        client_id=self._scope.client_id,
                    )
                )
                if not parent_connection.poll(self._startup_timeout_seconds):
                    raise ScopeDenied
                response = parent_connection.recv_bytes(MAX_FRAME_BYTES)
                if response != _READY_FRAME:
                    parsed = decode_response(response)
                    if type(parsed) is ScopeDeniedResponse:
                        raise ScopeDenied
                    raise ScopeDenied
            except ScopeDenied:
                self._shutdown_locked()
                raise ScopeDenied from None
            except Exception:
                self._shutdown_locked()
                raise ScopeDenied from None

    @staticmethod
    def _permission(request: WorkerRequest) -> WorkerPermission:
        if type(request) is StageSharedCaseOutboxRequest:
            return (
                "session_append"
                if request.action == "PREPARE"
                else "draft_write"
            )
        if type(request) is RebuildClientDerivativesRequest:
            return (
                "client_read"
                if request.action in {"STATUS", "REPORT"}
                else "formal_write"
            )
        if type(request) is RecoverClientManifestsRequest:
            return "client_read" if request.dry_run else "formal_write"
        if type(request) in (
            PingRequest,
            EmptyContextMetadataRequest,
            QueryFactSnapshotRequest,
            QueryProfileSnapshotRequest,
            QueryClientGraphRequest,
            SearchClientGraphRequest,
            QueryClientWeightedPathRequest,
            QueryClientHistoryCandidatesRequest,
            PreviewTargetDependencyImpactRequest,
            ReadSessionStateRequest,
            GetGenerationStateRequest,
            GetGenerationBindingRequest,
            PrepareGenerationRetrievalRequest,
            GetGenerationEvidenceForPlanRequest,
            VerifyClientIntegrityRequest,
        ):
            return "client_read"
        if type(request) in (
            AppendScopedAuditRequest,
            BeginSessionRequest,
            ResumeSessionRequest,
            AppendClientTurnRequest,
            AppendTemporaryFactRequest,
            BeginGenerationRequest,
            StoreCandidateSetRequest,
            RecordActualReplyRequest,
            SubmitGenerationStageRequest,
            AcknowledgeRiskObservationRequest,
            StoreGenerationEvidencePackRequest,
            PrepareTurnRiskEvaluationRequest,
            PersistRiskObservationsRequest,
            BuildPrivateArchiveRequest,
            BuildProfileDiffRequest,
        ):
            return "session_append"
        if type(request) in (
            PreviewFactMutationRequest,
            CommitFactMutationRequest,
            PreviewDependencyImpactRequest,
            CommitPrivateArchiveRequest,
            CommitProfileUpdateRequest,
            PreviewClientDeleteRequest,
            PreviewClientRebuildRequest,
            PreviewClientRollbackRequest,
        ):
            return "draft_write"
        if type(request) in (
            CommitClientTombstoneRequest,
            CommitClientRollbackRequest,
            PreflightClientLifecycleCommitRequest,
        ):
            return "formal_write"
        raise ScopeDenied

    @staticmethod
    def _response_matches(
        request: WorkerRequest,
        response: WorkerResponse,
    ) -> bool:
        if type(request) is PingRequest:
            return (
                type(response) is PingResponse
                and response.request_id == request.request_id
            )
        if type(request) is EmptyContextMetadataRequest:
            return (
                type(response) is EmptyContextMetadataResponse
                and response.request_id == request.request_id
            )
        if type(request) is AppendScopedAuditRequest:
            return (
                type(response) is AppendScopedAuditResponse
                and response.request_id == request.request_id
            )
        if type(request) is QueryFactSnapshotRequest:
            return (
                type(response) is QueryFactSnapshotResponse
                and response.request_id == request.request_id
            )
        if type(request) is PreviewFactMutationRequest:
            return (
                type(response) is PreviewFactMutationResponse
                and response.request_id == request.request_id
            )
        if type(request) is CommitFactMutationRequest:
            return (
                type(response) is CommitFactMutationResponse
                and response.request_id == request.request_id
            )
        if type(request) is BuildPrivateArchiveRequest:
            return (
                type(response) is BuildPrivateArchiveResponse
                and response.request_id == request.request_id
            )
        if type(request) is CommitPrivateArchiveRequest:
            return (
                type(response) is CommitPrivateArchiveResponse
                and response.request_id == request.request_id
                and response.bundle_id == request.bundle_id
                and response.approval_operation_id
                == request.approval_operation_id
            )
        if type(request) is BuildProfileDiffRequest:
            return (
                type(response) is BuildProfileDiffResponse
                and response.request_id == request.request_id
            )
        if type(request) is CommitProfileUpdateRequest:
            return (
                type(response) is CommitProfileUpdateResponse
                and response.request_id == request.request_id
                and response.bundle_id == request.bundle_id
                and response.approval_operation_id
                == request.approval_operation_id
            )
        if type(request) is StageSharedCaseOutboxRequest:
            return (
                type(response) is StageSharedCaseOutboxResponse
                and response.request_id == request.request_id
                and response.bundle_id == request.bundle_id
                and response.action == request.action
                and (
                    request.action == "PREPARE"
                    or response.approval_operation_id
                    == request.approval_operation_id
                )
            )
        if type(request) is QueryProfileSnapshotRequest:
            return (
                type(response) is QueryProfileSnapshotResponse
                and response.request_id == request.request_id
            )
        if type(request) is QueryClientGraphRequest:
            return (
                type(response) is QueryClientGraphResponse
                and response.request_id == request.request_id
            )
        if type(request) is SearchClientGraphRequest:
            return (
                type(response) is SearchClientGraphResponse
                and response.request_id == request.request_id
            )
        if type(request) is QueryClientWeightedPathRequest:
            return (
                type(response) is QueryClientWeightedPathResponse
                and response.request_id == request.request_id
            )
        if type(request) is QueryClientHistoryCandidatesRequest:
            return (
                type(response) is QueryClientHistoryCandidatesResponse
                and response.request_id == request.request_id
            )
        if type(request) is PreviewDependencyImpactRequest:
            return (
                type(response) is PreviewDependencyImpactResponse
                and response.request_id == request.request_id
            )
        if type(request) is PreviewTargetDependencyImpactRequest:
            return (
                type(response) is PreviewTargetDependencyImpactResponse
                and response.request_id == request.request_id
                and response.target_ref == request.target_ref
                and response.action == request.action
                and response.as_of == request.as_of
            )
        if type(request) is BeginSessionRequest:
            return (
                type(response) is BeginSessionResponse
                and response.request_id == request.request_id
                and response.session_id == request.session_id
            )
        if type(request) is ResumeSessionRequest:
            return (
                type(response) is ResumeSessionResponse
                and response.request_id == request.request_id
                and response.session_id == request.session_id
                and response.capability_epoch == request.capability_epoch
            )
        if type(request) is AppendClientTurnRequest:
            return (
                type(response) is AppendClientTurnResponse
                and response.request_id == request.request_id
                and response.session_id == request.session_id
                and response.turn_id == request.turn_id
            )
        if type(request) is AppendTemporaryFactRequest:
            return (
                type(response) is AppendTemporaryFactResponse
                and response.request_id == request.request_id
                and response.session_id == request.session_id
                and response.turn_id == request.turn_id
                and response.event_kind == request.event_kind
                and response.cognitive_type == request.cognitive_type
            )
        if type(request) is BeginGenerationRequest:
            return (
                type(response) is BeginGenerationResponse
                and response.request_id == request.request_id
                and response.session_id == request.session_id
                and response.turn_id == request.turn_id
                and response.run_id == request.run_id
            )
        if type(request) is StoreCandidateSetRequest:
            return (
                type(response) is StoreCandidateSetResponse
                and response.request_id == request.request_id
                and response.session_id == request.session_id
                and response.turn_id == request.turn_id
            )
        if type(request) is RecordActualReplyRequest:
            return (
                type(response) is RecordActualReplyResponse
                and record_actual_reply_response_matches_request(
                    request,
                    response,
                )
            )
        if type(request) is ReadSessionStateRequest:
            return (
                type(response) is ReadSessionStateResponse
                and response.request_id == request.request_id
                and response.session_id == request.session_id
            )
        if type(request) is GetGenerationBindingRequest:
            return (
                type(response) is GetGenerationBindingResponse
                and response.request_id == request.request_id
                and response.session_id == request.session_id
                and response.turn_id == request.turn_id
            )
        if type(request) is PrepareGenerationRetrievalRequest:
            return (
                type(response) is PrepareGenerationRetrievalResponse
                and response.request_id == request.request_id
                and response.session_id == request.session_id
                and response.turn_id == request.turn_id
                and response.run_id == request.run_id
                and response.query_plan_sha256 == request.query_plan_sha256
                and response.risk_context_binding.authority
                == request.risk_authority
            )
        if type(request) is StoreGenerationEvidencePackRequest:
            return (
                type(response) is StoreGenerationEvidencePackResponse
                and response.request_id == request.request_id
                and response.session_id == request.session_id
                and response.turn_id == request.turn_id
                and response.run_id == request.run_id
                and response.query_plan_sha256 == request.query_plan_sha256
            )
        if type(request) is GetGenerationEvidenceForPlanRequest:
            return (
                type(response) is GetGenerationEvidenceForPlanResponse
                and response.request_id == request.request_id
                and response.session_id == request.session_id
                and response.turn_id == request.turn_id
                and response.run_id == request.run_id
                and response.query_plan_sha256 == request.query_plan_sha256
            )
        if type(request) is SubmitGenerationStageRequest:
            return (
                type(response) is SubmitGenerationStageResponse
                and submit_generation_stage_response_matches_request(
                    request,
                    response,
                )
            )
        if type(request) is GetGenerationStateRequest:
            return (
                type(response) is GetGenerationStateResponse
                and response.request_id == request.request_id
                and response.session_id == request.session_id
                and response.turn_id == request.turn_id
                and response.run_id == request.run_id
            )
        if type(request) is AcknowledgeRiskObservationRequest:
            return (
                type(response) is AcknowledgeRiskObservationResponse
                and risk_lifecycle_response_matches_request(
                    request,
                    response,
                )
            )
        if type(request) is PersistRiskObservationsRequest:
            return (
                type(response) is PersistRiskObservationsResponse
                and response.request_id == request.request_id
                and response.session_id == request.session_id
                and response.turn_id == request.turn_id
                and response.risk_authority == request.risk_authority
                and tuple(
                    item.observation.observation_id
                    for item in response.observations
                )
                == tuple(
                    item.observation.observation_id
                    for item in request.observations
                )
            )
        if type(request) is PrepareTurnRiskEvaluationRequest:
            return (
                type(response) is PrepareTurnRiskEvaluationResponse
                and response.request_id == request.request_id
                and response.session_id == request.session_id
                and response.turn_id == request.turn_id
                and response.risk_authority == request.risk_authority
            )
        if type(request) is RecoverClientManifestsRequest:
            return (
                type(response) is RecoverClientManifestsResponse
                and response.request_id == request.request_id
                and response.dry_run == request.dry_run
            )
        if type(request) is PreflightClientLifecycleCommitRequest:
            return (
                type(response) is PreflightClientLifecycleCommitResponse
                and response.request_id == request.request_id
                and response.lifecycle_kind == request.lifecycle_kind
                and response.approval_operation_id
                == request.approval_operation_id
                and response.plan_sha256 == request.plan_sha256
            )
        if type(request) is PreviewClientDeleteRequest:
            return (
                type(response) is PreviewClientDeleteResponse
                and response.request_id == request.request_id
                and response.proposed_operation_id
                == request.proposed_operation_id
            )
        if type(request) is PreviewClientRebuildRequest:
            return (
                type(response) is PreviewClientRebuildResponse
                and response.request_id == request.request_id
                and response.action == request.action
                and response.proposed_operation_id
                == request.proposed_operation_id
            )
        if type(request) is CommitClientTombstoneRequest:
            return (
                type(response) is CommitClientTombstoneResponse
                and response.request_id == request.request_id
                and response.approval_operation_id
                == request.approval_operation_id
            )
        if type(request) is RebuildClientDerivativesRequest:
            return (
                type(response) is RebuildClientDerivativesResponse
                and response.request_id == request.request_id
                and response.action == request.action
                and (request.job_id is None or response.job_id == request.job_id)
                and (
                    request.plan_sha256 is None
                    or response.plan_sha256 == request.plan_sha256
                )
                and (
                    request.action in {"STATUS", "REPORT"}
                    or response.approval_operation_id
                    == request.approval_operation_id
                )
            )
        if type(request) is PreviewClientRollbackRequest:
            return (
                type(response) is PreviewClientRollbackResponse
                and response.request_id == request.request_id
                and response.rollback_kind == request.rollback_kind
                and response.current_version == request.current_version
                and response.restore_version == request.restore_version
            )
        if type(request) is CommitClientRollbackRequest:
            return (
                type(response) is CommitClientRollbackResponse
                and response.request_id == request.request_id
                and response.approval_operation_id
                == request.approval_operation_id
            )
        if type(request) is VerifyClientIntegrityRequest:
            return (
                type(response) is VerifyClientIntegrityResponse
                and response.request_id == request.request_id
            )
        return False

    def call(self, request: WorkerRequest) -> WorkerResponse:
        with self._lock:
            if (
                self._closed
                or self._connection is None
                or self._process is None
                or not self._process.is_alive()
            ):
                self._shutdown_locked()
                raise ChannelUnavailableError("CHANNEL_UNAVAILABLE")
            try:
                self._assert_request_binding(request)
                permission = self._permission(request)
                self._assert_capability(permission)
                frame = encode_message(request)
                self._connection.send_bytes(frame)
                if not self._connection.poll(self._call_timeout_seconds):
                    raise ChannelUnavailableError("CHANNEL_UNAVAILABLE")
                response = decode_response(
                    self._connection.recv_bytes(MAX_FRAME_BYTES)
                )
                if isinstance(response, ScopeDeniedResponse):
                    raise ScopeDenied
                if type(response) is OperationalErrorResponse:
                    if response.request_id != request.request_id:
                        raise ScopeDenied
                    if response.error_code == "PREVIOUS_TURN_NOT_CLOSED":
                        raise PreviousTurnNotClosedError(
                            "PREVIOUS_TURN_NOT_CLOSED"
                        )
                    if response.error_code == "CHANNEL_UNAVAILABLE":
                        raise ChannelUnavailableError("CHANNEL_UNAVAILABLE")
                    raise WorkflowOperationalError(response.error_code)
                if not self._response_matches(request, response):
                    raise ScopeDenied
                return response
            except PreviousTurnNotClosedError:
                raise
            except WorkflowOperationalError:
                raise
            except ChannelUnavailableError:
                self._shutdown_locked()
                raise
            except ScopeDenied:
                self._shutdown_locked()
                raise ScopeDenied from None
            except Exception:
                self._shutdown_locked()
                raise ScopeDenied from None

    def query_client_history(
        self,
        request: ClientHistoryQuery,
    ) -> ClientHistoryResult:
        """Adapt the scoped wire operation to the retrieval transport protocol."""

        if type(request) is not ClientHistoryQuery:
            raise ScopeDenied
        response = self.call(
            QueryClientHistoryCandidatesRequest(
                request_id=request.request_id,
                session_handle=request.session_handle,
                query_category=request.query_category,
                as_of=request.as_of,
            )
        )
        if type(response) is not QueryClientHistoryCandidatesResponse:
            raise ScopeDenied
        return ClientHistoryResult(
            request_id=response.request_id,
            candidates=response.candidates,
            runtime_epoch=response.runtime_epoch,
        )

    def _invoke_case_publish_rpc(
        self,
        payload: CasePublishRpcPayload,
    ) -> CasePublishRpcResultPayload:
        with self._lock:
            if (
                self._closed
                or self._connection is None
                or self._process is None
                or not self._process.is_alive()
                or self._claim_secret is None
            ):
                self._shutdown_locked()
                raise ScopeDenied
            try:
                self._assert_capability("draft_write")
                exact = CasePublishRpcPayload.model_validate(payload)
                codec = LocalHmacCasePublishRpc(self._claim_secret)
                self._connection.send_bytes(
                    encode_case_publish_rpc(codec.sign_request(exact))
                )
                if not self._connection.poll(self._call_timeout_seconds):
                    raise ScopeDenied
                result = codec.verify_result(
                    decode_case_publish_result(
                        self._connection.recv_bytes(MAX_INTERNAL_FRAME_BYTES)
                    )
                )
                if result.rpc_id != exact.rpc_id or result.action != exact.action:
                    raise ScopeDenied
                return result
            except ScopeDenied:
                self._shutdown_locked()
                raise ScopeDenied from None
            except Exception:
                self._shutdown_locked()
                raise ScopeDenied from None

    def export_pending_case_publish(
        self,
        *,
        event_id: str | None = None,
    ) -> tuple[OutboxRecord, CasePublishTransfer] | None:
        """Claim and export one exact source event over the sealed private pipe."""

        now = datetime.now(timezone.utc)
        result = self._invoke_case_publish_rpc(
            CasePublishRpcPayload(
                rpc_id=IdFactory().object_id("case_publish_rpc"),
                action="EXPORT",
                issued_at=now,
                expires_at=now + timedelta(seconds=10),
                event_id=event_id,
            )
        )
        if result.event is None and result.transfer is None:
            return None
        if result.event is None or result.transfer is None:
            raise ScopeDenied
        return result.event, result.transfer

    def resolve_case_publish_authority(
        self,
        *,
        payload: CasePublishOutboxPayload,
        as_of: datetime,
    ) -> CasePublishAuthoritySnapshot | None:
        """Resolve body-free live source authority for every publisher transition."""

        now = datetime.now(timezone.utc)
        result = self._invoke_case_publish_rpc(
            CasePublishRpcPayload(
                rpc_id=IdFactory().object_id("case_publish_rpc"),
                action="AUTHORITY",
                issued_at=now,
                expires_at=now + timedelta(seconds=10),
                payload=payload,
                as_of=as_of,
            )
        )
        return result.authority

    def acknowledge_case_publication(
        self,
        publication: CasePublication,
    ) -> OutboxRecord:
        """Mark the exact source event PUBLISHED after global ACTIVE succeeds."""

        exact = CasePublication.model_validate(publication)
        now = datetime.now(timezone.utc)
        result = self._invoke_case_publish_rpc(
            CasePublishRpcPayload(
                rpc_id=IdFactory().object_id("case_publish_rpc"),
                action="ACK",
                issued_at=now,
                expires_at=now + timedelta(seconds=10),
                event_id=exact.source_event_id,
                publication=exact,
            )
        )
        if (
            result.event is None
            or result.event.event_id != exact.source_event_id
            or result.event.state != "PUBLISHED"
            or result.event.published_global_version
            != exact.published_global_version
        ):
            raise ScopeDenied
        return result.event

    def execute_approved_fact_mutation(
        self,
        request: CommitFactMutationRequest,
        *,
        ticket: ApprovalExecutionTicket,
        approval_service: ApprovalService,
    ) -> CommitFactMutationResponse:
        """Use the private pipe only after global ticket verification.

        The approval ticket, receipt nonce, claim signature, and target proof
        never enter the public worker protocol or any model-facing schema.
        """

        with self._lock:
            if (
                self._closed
                or self._connection is None
                or self._process is None
                or not self._process.is_alive()
                or self._claim_secret is None
                or self._target_attestor_secret is None
                or self._target_attestor_id is None
            ):
                self._shutdown_locked()
                raise ScopeDenied
            try:
                self._assert_capability("draft_write")
                validated_ticket = ApprovalExecutionTicket.model_validate(ticket)
                if (
                    self._scope is None
                    or self._scope.client_id is None
                    or not hmac.compare_digest(
                        validated_ticket.target_scope_hash,
                        self._scope.scope_marker_sha256,
                    )
                    or request.approval_operation_id
                    != validated_ticket.operation_id
                    or request.preview_sha256
                    != validated_ticket.descriptor.draft_sha256
                    or request.base_commit_version
                    != validated_ticket.descriptor.base_version
                    or validated_ticket.descriptor.client_id
                    != self._scope.client_id
                ):
                    raise ScopeDenied
                approval_service.verify_ticket(
                    validated_ticket,
                    validated_ticket.descriptor,
                    allow_expired=False,
                )
                now = datetime.now(timezone.utc)
                claim_expiry = min(
                    now + timedelta(seconds=10),
                    validated_ticket.receipt.expires_at,
                )
                if claim_expiry <= now:
                    raise ScopeDenied
                payload = ApprovedCommitClaimPayload(
                    claim_id=IdFactory().object_id("worker_claim"),
                    claim_nonce=secrets.token_urlsafe(32),
                    issued_at=now,
                    expires_at=claim_expiry,
                    target_scope_hash=validated_ticket.target_scope_hash,
                    descriptor_sha256=descriptor_sha256(
                        validated_ticket.descriptor
                    ),
                    approval_nonce_sha256=hashlib.sha256(
                        validated_ticket.receipt.nonce.encode("ascii")
                    ).hexdigest(),
                    request=request,
                    descriptor=validated_ticket.descriptor,
                    ticket=validated_ticket,
                )
                frame = encode_approved_commit_claim(
                    LocalHmacApprovedCommitClaimSigner(
                        self._claim_secret
                    ).sign(payload)
                )
                self._connection.send_bytes(frame)
                if not self._connection.poll(self._call_timeout_seconds):
                    raise ScopeDenied
                result = decode_approved_commit_result(
                    self._connection.recv_bytes(MAX_INTERNAL_FRAME_BYTES)
                )
                if (
                    type(result.response) is not CommitFactMutationResponse
                    or result.response.request_id != request.request_id
                    or result.response.approval_operation_id
                    != request.approval_operation_id
                    or result.response.runtime_epoch
                    != request.expected_runtime_epoch
                    or result.draft_sha256 != request.preview_sha256
                ):
                    raise ScopeDenied
                acknowledged = approval_service.acknowledge(result.proof())
                if (
                    acknowledged.operation_id != request.approval_operation_id
                    or acknowledged.state != "acknowledged"
                ):
                    raise ScopeDenied
                return result.response
            except ScopeDenied:
                self._shutdown_locked()
                raise ScopeDenied from None

            except Exception:
                self._shutdown_locked()
                raise ScopeDenied from None

    def execute_approved_archive_operation(
        self,
        request: ApprovedCommitRequest,
        *,
        ticket: ApprovalExecutionTicket,
        approval_service: ApprovalService,
    ) -> ApprovedCommitResponse:
        """Execute one private/profile/case commit through the signed pipe.

        Public archive DTOs carry only the bound session handle, exact scoped
        references and approval IDs.  The complete ticket is verified by the
        control plane and then delivered only inside the broker-authenticated
        private claim frame.
        """

        with self._lock:
            if not isinstance(
                request,
                (
                    CommitPrivateArchiveRequest,
                    CommitProfileUpdateRequest,
                    StageSharedCaseOutboxRequest,
                    CommitClientTombstoneRequest,
                    RebuildClientDerivativesRequest,
                    CommitClientRollbackRequest,
                ),
            ):
                raise ScopeDenied
            if (
                (
                    isinstance(request, StageSharedCaseOutboxRequest)
                    and request.action != "COMMIT"
                )
                or self._closed
                or self._connection is None
                or self._process is None
                or not self._process.is_alive()
                or self._claim_secret is None
                or self._scope is None
                or self._scope.client_id is None
                or self._scope.session_id is None
            ):
                raise ScopeDenied
            try:
                self._assert_request_binding(request)
                self._assert_capability(
                    "formal_write"
                    if isinstance(
                        request,
                        (
                            CommitClientTombstoneRequest,
                            RebuildClientDerivativesRequest,
                            CommitClientRollbackRequest,
                        ),
                    )
                    else "draft_write"
                )
                validated_ticket = ApprovalExecutionTicket.model_validate(
                    ticket
                )
                operation_id = request.approval_operation_id
                approval_request_id = request.approval_request_id
                if (
                    operation_id is None
                    or approval_request_id is None
                    or operation_id != validated_ticket.operation_id
                    or approval_request_id != validated_ticket.request_id
                    or not hmac.compare_digest(
                        validated_ticket.target_scope_hash,
                        (
                            request.target_scope_hash
                            if type(request) is CommitClientTombstoneRequest
                            else self._scope.scope_marker_sha256
                        ),
                    )
                    or validated_ticket.descriptor.client_id
                    != self._scope.client_id
                    or validated_ticket.descriptor.session_id
                    != self._scope.session_id
                ):
                    raise ScopeDenied
                if type(request) is CommitPrivateArchiveRequest:
                    if (
                        validated_ticket.descriptor.purpose
                        != "private_archive_publish"
                        or validated_ticket.descriptor.target_id
                        != request.draft_ref.object_id
                        or validated_ticket.descriptor.draft_sha256
                        != request.draft_ref.content_sha256
                        or validated_ticket.descriptor.base_version
                        != request.base_version
                    ):
                        raise ScopeDenied
                elif type(request) is CommitProfileUpdateRequest:
                    if validated_ticket.descriptor.purpose != "profile_update":
                        raise ScopeDenied
                elif type(request) is StageSharedCaseOutboxRequest:
                    if (
                        request.candidate_ref is None
                        or request.review_policy_draft_ref is None
                        or validated_ticket.descriptor.purpose != "case_publish"
                        or validated_ticket.descriptor.target_id
                        != request.candidate_ref.object_id
                        or validated_ticket.descriptor.base_version
                        != request.candidate_ref.version
                        or validated_ticket.descriptor.draft_sha256
                        != request.review_policy_draft_ref.content_sha256
                    ):
                        raise ScopeDenied
                elif type(request) is CommitClientTombstoneRequest:
                    if (
                        validated_ticket.descriptor.purpose != "delete"
                        or validated_ticket.descriptor.draft_sha256
                        != request.plan_sha256
                        or validated_ticket.target_scope_hash
                        != request.target_scope_hash
                    ):
                        raise ScopeDenied
                elif type(request) is RebuildClientDerivativesRequest:
                    approval_request = approval_service.get(
                        validated_ticket.request_id
                    )
                    tombstone_bases = tuple(
                        value
                        for value in request.base_versions
                        if value.authority_key == "tombstone_epoch"
                        and value.scope_sha256
                        == self._scope.scope_marker_sha256
                    )
                    if request.action == "START":
                        valid = (
                            request.purpose is not None
                            and request.plan_sha256
                            == validated_ticket.descriptor.draft_sha256
                            and validated_ticket.descriptor.purpose == "rebuild"
                            and validated_ticket.descriptor.target_id
                            == f"client_rebuild:{request.purpose}"
                            and len(request.base_versions) == 1
                            and len(tombstone_bases) == 1
                            and tombstone_bases[0].version
                            == validated_ticket.descriptor.base_version
                        )
                    elif request.action == "CANCEL":
                        valid = (
                            request.job_id is not None
                            and request.plan_sha256
                            == validated_ticket.descriptor.draft_sha256
                            and validated_ticket.descriptor.purpose == "rebuild"
                            and validated_ticket.descriptor.target_id
                            == f"client_rebuild_cancel:{request.job_id}"
                            and len(request.base_versions) == 1
                            and len(tombstone_bases) == 1
                            and tombstone_bases[0].version
                            == validated_ticket.descriptor.base_version
                        )
                    else:
                        valid = False
                    if (
                        not valid
                        or request.plan_ref is None
                        or approval_request.diff_object_ref
                        != request.plan_ref.version_ref
                    ):
                        raise ScopeDenied
                elif type(request) is CommitClientRollbackRequest:
                    approval_request = approval_service.get(
                        validated_ticket.request_id
                    )
                    client_fact_bases = tuple(
                        value
                        for value in request.base_versions
                        if value.authority_key == "client_fact"
                        and value.scope_sha256
                        == self._scope.scope_marker_sha256
                    )
                    if (
                        validated_ticket.descriptor.purpose != "rollback"
                        or validated_ticket.descriptor.draft_sha256
                        != request.plan_sha256
                        or len(client_fact_bases) != 1
                        or client_fact_bases[0].version
                        != validated_ticket.descriptor.base_version
                        or any(
                            value.scope_sha256
                            != self._scope.scope_marker_sha256
                            for value in request.base_versions
                        )
                        or approval_request.diff_object_ref
                        != request.plan_ref.version_ref
                    ):
                        raise ScopeDenied
                approval_service.verify_ticket(
                    validated_ticket,
                    validated_ticket.descriptor,
                    allow_expired=False,
                )
                now = datetime.now(timezone.utc)
                claim_expiry = min(
                    now + timedelta(seconds=10),
                    validated_ticket.receipt.expires_at,
                )
                if claim_expiry <= now:
                    raise ScopeDenied
                payload = ApprovedCommitClaimPayload(
                    claim_id=IdFactory().object_id("worker_claim"),
                    claim_nonce=secrets.token_urlsafe(32),
                    issued_at=now,
                    expires_at=claim_expiry,
                    target_scope_hash=validated_ticket.target_scope_hash,
                    descriptor_sha256=descriptor_sha256(
                        validated_ticket.descriptor
                    ),
                    approval_nonce_sha256=hashlib.sha256(
                        validated_ticket.receipt.nonce.encode("ascii")
                    ).hexdigest(),
                    request=request,
                    descriptor=validated_ticket.descriptor,
                    ticket=validated_ticket,
                    approval_request=(
                        approval_service.get(validated_ticket.request_id)
                        if type(request) is CommitClientRollbackRequest
                        else None
                    ),
                )
                self._connection.send_bytes(
                    encode_approved_commit_claim(
                        LocalHmacApprovedCommitClaimSigner(
                            self._claim_secret
                        ).sign(payload)
                    )
                )
                if not self._connection.poll(self._call_timeout_seconds):
                    raise ScopeDenied
                result = decode_approved_commit_result(
                    self._connection.recv_bytes(MAX_INTERNAL_FRAME_BYTES)
                )
                if (
                    not self._response_matches(request, result.response)
                    or result.execution.operation_id != operation_id
                    or result.draft_sha256
                    != validated_ticket.descriptor.draft_sha256
                ):
                    raise ScopeDenied
                acknowledged = approval_service.acknowledge(result.proof())
                if (
                    acknowledged.operation_id != operation_id
                    or acknowledged.state != "acknowledged"
                ):
                    raise ScopeDenied
                return result.response
            except ScopeDenied:
                self._shutdown_locked()
                raise ScopeDenied from None
            except Exception:
                self._shutdown_locked()
                raise ScopeDenied from None

    def recover_applied_fact_mutation(
        self,
        request: CommitFactMutationRequest,
        *,
        ticket: ApprovalExecutionTicket,
        approval_service: ApprovalService,
    ) -> CommitFactMutationResponse:
        """Re-attest one exact APPLIED target row without executing writes."""

        with self._lock:
            if (
                self._closed
                or self._connection is None
                or self._process is None
                or not self._process.is_alive()
                or self._claim_secret is None
                or self._target_attestor_secret is None
                or self._target_attestor_id is None
                or self._scope is None
                or self._scope.client_id is None
            ):
                self._shutdown_locked()
                raise ScopeDenied
            try:
                self._assert_capability("draft_write")
                validated_ticket = ApprovalExecutionTicket.model_validate(ticket)
                if (
                    not hmac.compare_digest(
                        validated_ticket.target_scope_hash,
                        self._scope.scope_marker_sha256,
                    )
                    or validated_ticket.descriptor.client_id
                    != self._scope.client_id
                    or request.approval_operation_id
                    != validated_ticket.operation_id
                    or request.preview_sha256
                    != validated_ticket.descriptor.draft_sha256
                    or request.base_commit_version
                    != validated_ticket.descriptor.base_version
                ):
                    raise ScopeDenied
                approval_service.verify_ticket(
                    validated_ticket,
                    validated_ticket.descriptor,
                    allow_expired=True,
                )
                now = datetime.now(timezone.utc)
                payload = AppliedCommitRecoveryPayload(
                    claim_id=IdFactory().object_id("worker_recovery_claim"),
                    claim_nonce=secrets.token_urlsafe(32),
                    issued_at=now,
                    expires_at=now + timedelta(seconds=10),
                    target_scope_hash=validated_ticket.target_scope_hash,
                    descriptor_sha256=descriptor_sha256(
                        validated_ticket.descriptor
                    ),
                    approval_nonce_sha256=hashlib.sha256(
                        validated_ticket.receipt.nonce.encode("ascii")
                    ).hexdigest(),
                    request=request,
                    descriptor=validated_ticket.descriptor,
                    ticket=validated_ticket,
                )
                self._connection.send_bytes(
                    encode_applied_recovery_claim(
                        LocalHmacAppliedCommitRecoverySigner(
                            self._claim_secret
                        ).sign(payload)
                    )
                )
                if not self._connection.poll(self._call_timeout_seconds):
                    raise ScopeDenied
                result = decode_approved_commit_result(
                    self._connection.recv_bytes(MAX_INTERNAL_FRAME_BYTES)
                )
                if (
                    type(result.response) is not CommitFactMutationResponse
                    or result.response.request_id != request.request_id
                    or result.response.approval_operation_id
                    != request.approval_operation_id
                    or result.response.runtime_epoch
                    != request.expected_runtime_epoch
                    or result.draft_sha256 != request.preview_sha256
                ):
                    raise ScopeDenied
                acknowledged = approval_service.acknowledge(result.proof())
                if acknowledged.state != "acknowledged":
                    raise ScopeDenied
                return result.response
            except ScopeDenied:
                self._shutdown_locked()
                raise ScopeDenied from None
            except Exception:
                self._shutdown_locked()
                raise ScopeDenied from None

    def recover_applied_archive_operation(
        self,
        request: ApprovedCommitRequest,
        *,
        ticket: ApprovalExecutionTicket,
        approval_service: ApprovalService,
    ) -> ApprovedCommitResponse | None:
        """Re-attest exact APPLIED, or return sealed exact target absence."""

        with self._lock:
            if not isinstance(
                request,
                (
                    CommitPrivateArchiveRequest,
                    CommitProfileUpdateRequest,
                    StageSharedCaseOutboxRequest,
                    CommitClientTombstoneRequest,
                    RebuildClientDerivativesRequest,
                    CommitClientRollbackRequest,
                ),
            ):
                raise ScopeDenied
            if (
                (
                    isinstance(request, StageSharedCaseOutboxRequest)
                    and request.action != "COMMIT"
                )
                or self._closed
                or self._connection is None
                or self._process is None
                or not self._process.is_alive()
                or self._claim_secret is None
                or self._target_attestor_secret is None
                or self._target_attestor_id is None
                or self._scope is None
                or self._scope.client_id is None
                or self._scope.session_id is None
            ):
                self._shutdown_locked()
                raise ScopeDenied
            try:
                self._assert_request_binding(request)
                self._assert_capability(
                    "formal_write"
                    if isinstance(
                        request,
                        (
                            CommitClientTombstoneRequest,
                            RebuildClientDerivativesRequest,
                            CommitClientRollbackRequest,
                        ),
                    )
                    else "draft_write"
                )
                validated_ticket = ApprovalExecutionTicket.model_validate(ticket)
                operation_id = request.approval_operation_id
                approval_request_id = request.approval_request_id
                if (
                    operation_id is None
                    or approval_request_id is None
                    or operation_id != validated_ticket.operation_id
                    or approval_request_id != validated_ticket.request_id
                    or not hmac.compare_digest(
                        validated_ticket.target_scope_hash,
                        (
                            request.target_scope_hash
                            if type(request) is CommitClientTombstoneRequest
                            else self._scope.scope_marker_sha256
                        ),
                    )
                    or validated_ticket.descriptor.client_id
                    != self._scope.client_id
                    or validated_ticket.descriptor.session_id
                    != self._scope.session_id
                ):
                    raise ScopeDenied
                if type(request) is CommitPrivateArchiveRequest:
                    if (
                        validated_ticket.descriptor.purpose
                        != "private_archive_publish"
                        or validated_ticket.descriptor.target_id
                        != request.draft_ref.object_id
                        or validated_ticket.descriptor.draft_sha256
                        != request.draft_ref.content_sha256
                        or validated_ticket.descriptor.base_version
                        != request.base_version
                    ):
                        raise ScopeDenied
                elif type(request) is CommitProfileUpdateRequest:
                    if validated_ticket.descriptor.purpose != "profile_update":
                        raise ScopeDenied
                elif type(request) is StageSharedCaseOutboxRequest:
                    if (
                        request.candidate_ref is None
                        or request.review_policy_draft_ref is None
                        or validated_ticket.descriptor.purpose != "case_publish"
                        or validated_ticket.descriptor.target_id
                        != request.candidate_ref.object_id
                        or validated_ticket.descriptor.base_version
                        != request.candidate_ref.version
                        or validated_ticket.descriptor.draft_sha256
                        != request.review_policy_draft_ref.content_sha256
                    ):
                        raise ScopeDenied
                elif type(request) is CommitClientTombstoneRequest:
                    if (
                        validated_ticket.descriptor.purpose != "delete"
                        or validated_ticket.descriptor.draft_sha256
                        != request.plan_sha256
                        or validated_ticket.target_scope_hash
                        != request.target_scope_hash
                    ):
                        raise ScopeDenied
                elif type(request) is RebuildClientDerivativesRequest:
                    tombstone_bases = tuple(
                        value
                        for value in request.base_versions
                        if value.authority_key == "tombstone_epoch"
                        and value.scope_sha256
                        == self._scope.scope_marker_sha256
                    )
                    if request.action == "START":
                        valid = (
                            request.purpose is not None
                            and request.plan_sha256
                            == validated_ticket.descriptor.draft_sha256
                            and validated_ticket.descriptor.purpose == "rebuild"
                            and validated_ticket.descriptor.target_id
                            == f"client_rebuild:{request.purpose}"
                            and len(request.base_versions) == 1
                            and len(tombstone_bases) == 1
                            and tombstone_bases[0].version
                            == validated_ticket.descriptor.base_version
                        )
                    elif request.action == "CANCEL":
                        valid = (
                            request.job_id is not None
                            and request.plan_sha256
                            == validated_ticket.descriptor.draft_sha256
                            and validated_ticket.descriptor.purpose == "rebuild"
                            and validated_ticket.descriptor.target_id
                            == f"client_rebuild_cancel:{request.job_id}"
                            and len(request.base_versions) == 1
                            and len(tombstone_bases) == 1
                            and tombstone_bases[0].version
                            == validated_ticket.descriptor.base_version
                        )
                    else:
                        valid = False
                    if not valid:
                        raise ScopeDenied
                elif type(request) is CommitClientRollbackRequest:
                    approval_request = approval_service.get(
                        validated_ticket.request_id
                    )
                    client_fact_bases = tuple(
                        value
                        for value in request.base_versions
                        if value.authority_key == "client_fact"
                        and value.scope_sha256
                        == self._scope.scope_marker_sha256
                    )
                    if (
                        validated_ticket.descriptor.purpose != "rollback"
                        or validated_ticket.descriptor.draft_sha256
                        != request.plan_sha256
                        or len(client_fact_bases) != 1
                        or client_fact_bases[0].version
                        != validated_ticket.descriptor.base_version
                        or any(
                            value.scope_sha256
                            != self._scope.scope_marker_sha256
                            for value in request.base_versions
                        )
                        or approval_request.diff_object_ref
                        != request.plan_ref.version_ref
                    ):
                        raise ScopeDenied
                approval_service.verify_ticket(
                    validated_ticket,
                    validated_ticket.descriptor,
                    allow_expired=True,
                )
                now = datetime.now(timezone.utc)
                payload = AppliedCommitRecoveryPayload(
                    claim_id=IdFactory().object_id("worker_recovery_claim"),
                    claim_nonce=secrets.token_urlsafe(32),
                    issued_at=now,
                    expires_at=now + timedelta(seconds=10),
                    target_scope_hash=validated_ticket.target_scope_hash,
                    descriptor_sha256=descriptor_sha256(
                        validated_ticket.descriptor
                    ),
                    approval_nonce_sha256=hashlib.sha256(
                        validated_ticket.receipt.nonce.encode("ascii")
                    ).hexdigest(),
                    request=request,
                    descriptor=validated_ticket.descriptor,
                    ticket=validated_ticket,
                    approval_request=(
                        approval_service.get(validated_ticket.request_id)
                        if type(request) is CommitClientRollbackRequest
                        else None
                    ),
                )
                self._connection.send_bytes(
                    encode_applied_recovery_claim(
                        LocalHmacAppliedCommitRecoverySigner(
                            self._claim_secret
                        ).sign(payload)
                    )
                )
                if not self._connection.poll(self._call_timeout_seconds):
                    raise ScopeDenied
                response_frame = self._connection.recv_bytes(
                    MAX_INTERNAL_FRAME_BYTES
                )
                if is_applied_not_applied_result_frame(response_frame):
                    not_applied = LocalHmacAppliedCommitNotAppliedResult(
                        self._claim_secret
                    ).verify(
                        decode_applied_not_applied_result(response_frame)
                    )
                    if (
                        not_applied.claim_id != payload.claim_id
                        or not_applied.claim_nonce_sha256
                        != hashlib.sha256(
                            payload.claim_nonce.encode(
                                "utf-8",
                                errors="strict",
                            )
                        ).hexdigest()
                        or not_applied.worker_request_id != request.request_id
                        or not_applied.request_sha256
                        != approved_commit_request_sha256(request)
                        or not_applied.approval_request_id
                        != validated_ticket.request_id
                        or not_applied.operation_id
                        != validated_ticket.operation_id
                        or not_applied.descriptor_sha256
                        != validated_ticket.descriptor_sha256
                        or not_applied.draft_sha256
                        != validated_ticket.descriptor.draft_sha256
                        or not_applied.descriptor_base_version
                        != validated_ticket.descriptor.base_version
                        or not hmac.compare_digest(
                            not_applied.target_scope_hash,
                            validated_ticket.target_scope_hash,
                        )
                        or not hmac.compare_digest(
                            not_applied.approval_nonce_sha256,
                            payload.approval_nonce_sha256,
                        )
                    ):
                        raise ScopeDenied
                    return None
                result = decode_approved_commit_result(response_frame)
                if (
                    not self._response_matches(request, result.response)
                    or result.execution.operation_id != operation_id
                    or result.draft_sha256
                    != validated_ticket.descriptor.draft_sha256
                ):
                    raise ScopeDenied
                acknowledged = approval_service.acknowledge(result.proof())
                if (
                    acknowledged.operation_id != operation_id
                    or acknowledged.state != "acknowledged"
                ):
                    raise ScopeDenied
                return result.response
            except ScopeDenied:
                self._shutdown_locked()
                raise ScopeDenied from None
            except Exception:
                self._shutdown_locked()
                raise ScopeDenied from None

    def render_verified_review_diff(self, reference: VersionRef) -> VerifiedReviewDiff:
        """Resolve an immutable review object inside the scoped worker."""

        validated = VersionRef.model_validate(reference)
        with self._lock:
            if (
                self._closed
                or self._connection is None
                or self._process is None
                or not self._process.is_alive()
            ):
                self._shutdown_locked()
                raise ScopeDenied
            try:
                self._assert_capability("client_read")
                self._connection.send_bytes(
                    encode_review_diff_read(
                        ReviewDiffReadRequest(reference=validated)
                    )
                )
                if not self._connection.poll(self._call_timeout_seconds):
                    raise ScopeDenied
                result = decode_review_diff_result(
                    self._connection.recv_bytes(MAX_INTERNAL_FRAME_BYTES)
                )
                if result.reference != validated:
                    raise ScopeDenied
                return VerifiedReviewDiff(
                    reference=result.reference,
                    content=result.content(),
                )
            except ScopeDenied:
                self._shutdown_locked()
                raise ScopeDenied from None
            except Exception:
                self._shutdown_locked()
                raise ScopeDenied from None

    def close(self) -> None:
        with self._lock:
            self._shutdown_locked()

    def _shutdown_locked(self) -> None:
        connection = self._connection
        process = self._process
        self._connection = None
        self._process = None
        self._capability_token = None
        self._scope = None
        self._validator = None
        self._claim_secret = None
        self._target_attestor_secret = None
        self._target_attestor_id = None
        self._closed = True
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
        if process is not None:
            try:
                process.join(timeout=1.0)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=2.0)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=2.0)
            except Exception:
                try:
                    if process.is_alive():
                        process.kill()
                        process.join(timeout=2.0)
                except Exception:
                    pass


__all__ = [
    "BoundCapabilityValidator",
    "CapabilityValidator",
    "ScopeDenied",
    "ScopedWorkerBroker",
    "WorkerScopeDescriptor",
]
