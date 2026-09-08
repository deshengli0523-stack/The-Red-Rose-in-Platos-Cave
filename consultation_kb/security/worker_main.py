"""Spawn target for one minimal, path-confined consultation worker."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Callable, Literal, cast

from pydantic import ValidationError, model_validator

from consultation_kb.approvals.attestation import LocalHmacTargetExecutionAttestor
from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.models import (
    ApprovalExecutionTicket,
    ApprovalRequest,
    descriptor_sha256,
)
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.archive.bundles import ArchiveBundleService
from consultation_kb.archive.case_publisher import (
    CasePublishAuthoritySnapshot,
    CasePublishTransfer,
    case_release_decision_sha256,
    shared_candidate_bytes,
)
from consultation_kb.archive.publication_proof import (
    LocalHmacCasePublicationProofVerifier,
)
from consultation_kb.archive.deidentification import Deidentifier
from consultation_kb.archive.private_record import (
    ActualTranscriptReader,
    PrivateArchiveDraftBuilder,
)
from consultation_kb.archive.private_review import PrivateArchiveReviewService
from consultation_kb.archive.provenance import CaseContributorHasher
from consultation_kb.archive.profile_diff import (
    ProfileDiffBuildInput,
    ProfileDiffBuilder,
    ProfileDiffDraft,
)
from consultation_kb.archive.profile_publication import (
    AtomicProfilePublicationExecutor,
    AtomicProfilePublicationPlanner,
)
from consultation_kb.archive.profile_review import (
    PreparedProfileDiffApproval,
    ProfileDiffReviewService,
)
from consultation_kb.archive.release_policy import CaseReleasePolicy
from consultation_kb.archive.shared_candidate import SharedCaseCandidateBuilder
from consultation_kb.models.archive import PrivateArchiveAnalysis, PrivateArchiveDraft
from consultation_kb.models.cases import (
    CaseReuseAuthorization,
    CaseReleaseDecision,
    DeidentificationScan,
    DeidentificationHumanReview,
    DeidentificationTransform,
    PrivateActualCaseRecord,
    PrivateCaseSourceItem,
    ReviewCategory,
    SharedCaseHumanReviewDraft,
    SharedCaseCandidate,
    SharedCaseSectionProposal,
    case_reuse_authorization_payload,
    deidentification_human_review_payload,
    private_actual_case_record_payload,
)
from consultation_kb.client.bitemporal import BitemporalFactQuery, FactQuery
from consultation_kb.client.dependencies import DependencyImpactService, DependencyRepository
from consultation_kb.client.graph_query import TemporalGraphQuery
from consultation_kb.client.publication import (
    ClientPublicationExecutor,
    ClientPublicationPlan,
    ClientPublicationPlanner,
    result_event_count,
)
from consultation_kb.client.profile import ProfileMaterializer
from consultation_kb.client.temporal_graph import (
    TemporalGraphBuilder,
    TemporalGraphSnapshot,
)
from consultation_kb.core.clock import SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.lifecycle.publish import (
    RuntimeEpochRepository,
    publication_closure_sha256,
)
from consultation_kb.lifecycle.recovery import RecoveryCoordinator
from consultation_kb.lifecycle.sqlite_recovery import (
    SqliteRecoveryBackend,
    scoped_database_reference,
)
from consultation_kb.lifecycle.deletion import DeletionService
from consultation_kb.lifecycle.rebuild import (
    RebuildCoordinator,
    RebuildPlan,
    RebuildRequest,
)
from consultation_kb.lifecycle.rebuild_jobs import RebuildJob, RebuildJobRepository
from consultation_kb.lifecycle.rollback import (
    RollbackBaseVersion,
    RollbackError,
    SqliteRollbackWorkflow,
)
from consultation_kb.models.deletion import (
    DeletionObjectRef,
    DeletionPlan,
    DeletionPreviewRequest,
    DeletionTarget,
)
from consultation_kb.models.dependencies import DependencyEdge
from consultation_kb.models.facts import (
    FACT_MUTATION_ADAPTER,
    AddMutation,
    FactMutation,
    FactEvent,
    MergeMutation,
    SupersedeMutation,
    canonical_json,
)
from consultation_kb.models.common import (
    ClientId,
    Sha256Hex,
    StrictModel,
    Uuid7String,
    VersionRef,
)
from consultation_kb.knowledge._canonical import (
    canonical_json_bytes,
    canonical_sha256,
)
from consultation_kb.models.manifests import ApprovalExecution, DraftDescriptor
from consultation_kb.models.evidence import EvidencePack
from consultation_kb.models.session import CandidateDraft, StoredContentRef
from consultation_kb.generation.conceptualization import (
    ConceptualizationPolicyError,
    ConceptualizationValidator,
)
from consultation_kb.generation.c1_projection import (
    C1ContextProjectionError,
    build_c1_applicability_input,
)
from consultation_kb.generation.contracts import (
    Conceptualization,
    ConsistencyRiskReview,
    EvidenceAudit,
    FinalTurnBundle,
    QueryPlan,
    ReplyDraftSet,
    TheoryComparison,
)
from consultation_kb.generation.evidence_registry import (
    GenerationEvidenceBindingMismatch,
    GenerationEvidenceConflict,
    GenerationEvidenceContextItem,
    GenerationEvidencePackStore,
    GenerationRiskContextBinding,
    validate_generation_evidence_context,
    validate_generation_required_evidence_proofs,
)
from consultation_kb.generation.evidence_audit import EvidenceAuditor
from consultation_kb.generation.final_validation import (
    FinalBundleValidationError,
    FinalBundleValidator,
)
from consultation_kb.generation.consistency_validation import (
    GenerationConsistencyValidationError,
    GenerationConsistencyValidator,
)
from consultation_kb.generation.query_planning import QueryPlanValidationError
from consultation_kb.generation.reply_policy import (
    ReplyDraftValidator,
    ReplyPolicyError,
)
from consultation_kb.generation.stage_store import (
    GenerationBindingMismatch,
    GenerationStageConflict,
    GenerationStageIntegrityError,
    GenerationStageRecord,
    GenerationStageRevisionRequired,
    GenerationStageStore,
    GenerationTurnContext,
)
from consultation_kb.generation.state_machine import GenerationStateError
from consultation_kb.generation.theory_policy import (
    TheoryPolicyError,
    TheoryUsePolicy,
    derive_hard_constraint_evidence_ids,
)
from consultation_kb.retrieval.authority_snapshot import candidate_authority_membership
from consultation_kb.retrieval.client_history import (
    ClientHistoryQuery,
    ScopedClientHistoryService,
    client_history_derivation_rule_ref,
)
from consultation_kb.retrieval.contracts import CandidateRef
from consultation_kb.risk.output_guard import (
    ClientReplyLeakageError,
)
from consultation_kb.risk.repository import (
    InternalRiskObservationRepository,
    RiskLifecycleConflict,
    RiskRepositoryError,
    TurnRiskEvaluationRepository,
    canonical_risk_observation_set_sha256,
)
from consultation_kb.risk.text_normalization import normalized_sensitive_fingerprint
from consultation_kb.storage.client_ledger import FactEventRepository
from consultation_kb.storage.connection import connect_database, transaction
from consultation_kb.storage.integrity import (
    ActiveArtifact,
    ActiveIntegrityGate,
    ArtifactUnavailable,
    IntegrityStore,
)
from consultation_kb.storage.deletion_inventory import SqliteDeletionInventoryAdapter
from consultation_kb.storage.manifests import ArtifactManifest, ManifestRepository
from consultation_kb.storage.outbox import (
    CasePublishOutboxPayload,
    OutboxRecord,
    OutboxRepository,
    SourceCaseApproval,
    case_publish_payload_bytes,
    case_publish_payload_sha256,
)
from consultation_kb.vault.content_store import ContentStore, ContentStoreError
from consultation_kb.security.path_guard import PathGuard
from consultation_kb.security.worker_claim import (
    ApprovedCommitClaim,
    ApprovedCommitClaimPayload,
    ApprovedCommitResponse,
    ApprovedCommitResult,
    AppliedCommitNotAppliedPayload,
    AppliedCommitRecoveryClaim,
    CasePublishRpcPayload,
    CasePublishRpcResultPayload,
    LocalHmacApprovedCommitClaimVerifier,
    LocalHmacAppliedCommitNotAppliedResult,
    LocalHmacAppliedCommitRecoveryVerifier,
    LocalHmacCasePublishRpc,
    decode_approved_commit_claim,
    decode_applied_recovery_claim,
    decode_case_publish_rpc,
    decode_review_diff_read,
    encode_applied_not_applied_result,
    encode_approved_commit_result,
    encode_case_publish_result,
    encode_review_diff_result,
    is_approved_commit_claim_frame,
    is_applied_recovery_claim_frame,
    is_case_publish_rpc_frame,
    is_review_diff_read_frame,
    approved_commit_request_sha256,
)
from consultation_kb.security.worker_protocol import (
    ArchiveContentRef,
    AppendClientTurnRequest,
    AppendClientTurnResponse,
    AppendTemporaryFactRequest,
    AppendTemporaryFactResponse,
    AppendScopedAuditRequest,
    AppendScopedAuditResponse,
    BeginGenerationRequest,
    BeginGenerationResponse,
    BeginSessionRequest,
    BeginSessionResponse,
    BuildPrivateArchiveRequest,
    BuildPrivateArchiveResponse,
    BuildProfileDiffRequest,
    BuildProfileDiffResponse,
    CLIENT_ACTIVE_INTEGRITY_REBUILD_REQUIRED,
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
    ClientGraphEdgeView,
    ClientHistoryQueryCategory,
    ClientWeightedPathStepView,
    ClientWeightedPathView,
    DependencyImpactItemView,
    EmptyContextMetadataRequest,
    EmptyContextMetadataResponse,
    FinalCandidateBinding,
    GenerationClientBinding,
    GenerationStageWireRecord,
    GetGenerationEvidenceForPlanRequest,
    GetGenerationEvidenceForPlanResponse,
    GetGenerationBindingRequest,
    GetGenerationBindingResponse,
    GetGenerationStateRequest,
    GetGenerationStateResponse,
    MAX_FRAME_BYTES,
    OperationBinding,
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
    PreviewClientDeleteRequest,
    PreviewClientDeleteResponse,
    PreviewClientRebuildRequest,
    PreviewClientRebuildResponse,
    PreviewClientRollbackRequest,
    PreviewClientRollbackResponse,
    PrepareGenerationRetrievalRequest,
    PrepareGenerationRetrievalResponse,
    PrepareTurnRiskEvaluationRequest,
    PrepareTurnRiskEvaluationResponse,
    PrivateGenerationEvidence,
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
    RebuildClientDerivativesRequest,
    RebuildClientDerivativesResponse,
    RecoverClientManifestsRequest,
    RecoverClientManifestsResponse,
    RecoveredActualReply,
    RecoveredCandidate,
    RecoveredClientTurn,
    RecoveredTemporaryFact,
    RecordActualReplyRequest,
    RecordActualReplyResponse,
    ResumeSessionRequest,
    ResumeSessionResponse,
    SearchClientGraphRequest,
    SearchClientGraphResponse,
    SessionRecoveryPayload,
    SessionTurnState,
    ScopeDeniedResponse,
    StoreCandidateSetRequest,
    StoreCandidateSetResponse,
    StoreGenerationEvidencePackRequest,
    StoreGenerationEvidencePackResponse,
    StageSharedCaseOutboxRequest,
    StageSharedCaseOutboxResponse,
    SubmitGenerationStageRequest,
    SubmitGenerationStageResponse,
    AcknowledgeRiskObservationRequest,
    AcknowledgeRiskObservationResponse,
    WorkerOperationRegistry,
    WorkerOperationalError,
    WorkerProtocolError,
    WorkerRequest,
    WorkerResponse,
    VerifyClientIntegrityRequest,
    VerifyClientIntegrityResponse,
    WorkerBaseVersion,
    decode_request,
    encode_message,
    worker_request_binding,
)
from consultation_kb.session.actual_replies import ActualReplyService
from consultation_kb.session.candidate_sets import CandidateSetService
from consultation_kb.session.context import ClientContextBuilder, ClientContextSnapshot
from consultation_kb.session.repository import (
    PreviousTurnNotClosed,
    SessionNotFound,
    SessionRepository,
    TurnNotFound,
)
from consultation_kb.session.recovery import RecoveryState, SessionRecovery
from consultation_kb.session.temporary_ledger import TemporaryFactLedger
from consultation_kb.session.turns import TurnService


_CLIENT_DATABASE = "client.sqlite3"


class _ClientRebuildPlanEnvelope(StrictModel):
    schema_version: Literal["client_rebuild_plan.v1"] = (
        "client_rebuild_plan.v1"
    )
    action: Literal["start", "cancel"]
    operation_id: str
    client_id: ClientId
    session_id: Uuid7String
    plan: RebuildPlan | None = None
    job_id: str | None = None
    job_plan_sha256: Sha256Hex | None = None
    base_versions: tuple[WorkerBaseVersion, ...]
    plan_sha256: Sha256Hex
    descriptor: DraftDescriptor

    @model_validator(mode="after")
    def _exact_action(self) -> "_ClientRebuildPlanEnvelope":
        keys = tuple(
            (value.authority_key, value.scope_sha256)
            for value in self.base_versions
        )
        if keys != tuple(sorted(set(keys))) or len(keys) != 1:
            raise ValueError("CLIENT_REBUILD_BASE_INVALID")
        base = self.base_versions[0]
        if self.action == "start":
            if (
                self.plan is None
                or self.job_id is not None
                or self.job_plan_sha256 is not None
                or self.plan.database_scope != "client"
                or self.plan_sha256 != self.plan.plan_sha256
                or base.authority_key != "tombstone_epoch"
                or base.scope_sha256 != self.plan.scope_sha256
                or base.version != self.plan.tombstone_epoch
                or self.descriptor
                != DraftDescriptor(
                    purpose="rebuild",
                    target_id=f"client_rebuild:{self.plan.purpose}",
                    client_id=self.client_id,
                    session_id=self.session_id,
                    base_version=self.plan.tombstone_epoch,
                    draft_sha256=self.plan.plan_sha256,
                )
            ):
                raise ValueError("CLIENT_REBUILD_START_PLAN_INVALID")
            return self
        if (
            self.plan is not None
            or self.job_id is None
            or self.job_plan_sha256 is None
            or base.authority_key != "tombstone_epoch"
        ):
            raise ValueError("CLIENT_REBUILD_CANCEL_PLAN_INVALID")
        expected = canonical_sha256(
            {
                "domain": "consultation_kb.rebuild_cancel_plan.v1",
                "database_scope": "client",
                "job_id": self.job_id,
                "job_plan_sha256": self.job_plan_sha256,
                "base_versions": [
                    value.model_dump(mode="json")
                    for value in self.base_versions
                ],
            }
        )
        if self.plan_sha256 != expected or self.descriptor != DraftDescriptor(
            purpose="rebuild",
            target_id=f"client_rebuild_cancel:{self.job_id}",
            client_id=self.client_id,
            session_id=self.session_id,
            base_version=base.version,
            draft_sha256=expected,
        ):
            raise ValueError("CLIENT_REBUILD_CANCEL_PLAN_INVALID")
        return self
_SCOPE_MARKER = ".scope-id"
_AUDIT_STREAM = "audit/worker.jsonl"
_READY_FRAME = b'{"ready":true,"schema_version":"1.0"}'
_MAX_BOOTSTRAP_BYTES = 16_384


ArchiveApprovalResolver = Callable[[str, str], ApprovalExecutionTicket]
ClientRebuildResolver = Callable[
    [sqlite3.Connection, Path, str], RebuildCoordinator
]


def _production_client_rebuild_resolver(
    connection: sqlite3.Connection,
    client_root: Path,
    scope_marker_sha256: str,
) -> RebuildCoordinator:
    """Resolve the restart-stable production factory inside the spawned worker."""

    try:
        from consultation_kb.lifecycle.production_rebuild import (
            resolve_client_rebuild,
        )

        coordinator = resolve_client_rebuild(
            connection,
            client_root,
            scope_marker_sha256,
        )
    except WorkerOperationalError:
        raise
    except Exception:
        raise WorkerOperationalError(
            "REBUILD_PRODUCTION_BUILDERS_UNAVAILABLE"
        ) from None
    if not isinstance(coordinator, RebuildCoordinator):
        raise WorkerOperationalError(
            "REBUILD_PRODUCTION_BUILDERS_UNAVAILABLE"
        )
    return coordinator


def _client_recovery_coordinator(
    root: Path,
    scope_marker_sha256: str,
) -> RecoveryCoordinator:
    """Compose recovery for only the worker's already-bound client scope."""

    clock = SystemClock()
    return RecoveryCoordinator(
        backend=SqliteRecoveryBackend(
            database=(root / _CLIENT_DATABASE).resolve(strict=False),
            content_store=ContentStore(root / "cas"),
            database_scope="client",
            database_ref_sha256=scoped_database_reference(
                scope_marker_sha256
            ),
            clock=clock,
        ),
        clock=clock,
    )


def _start_client_rebuild_runner(
    *,
    root: Path,
    scope_marker_sha256: str,
    resolver: ClientRebuildResolver,
) -> None:
    """Drain durable jobs off the RPC thread using an independent DB handle."""

    def run() -> None:
        try:
            _drain_client_rebuilds(
                root=root,
                scope_marker_sha256=scope_marker_sha256,
                resolver=resolver,
            )
        except Exception:
            # Jobs claimed by the coordinator carry their own durable failure
            # state.  Resolver/configuration failures leave queued work intact
            # for a later process restart after configuration is repaired.
            return

    threading.Thread(
        target=run,
        daemon=True,
        name="consultation-client-rebuild",
    ).start()


def _drain_client_rebuilds(
    *,
    root: Path,
    scope_marker_sha256: str,
    resolver: ClientRebuildResolver,
) -> None:
    """Synchronously finish every durable job for startup recovery."""

    connection = connect_database(root / _CLIENT_DATABASE, "writer")
    try:
        coordinator = resolver(connection, root, scope_marker_sha256)
        while coordinator.run_next() is not None:
            pass
    finally:
        connection.close()


def _client_rebuild_pending(*, root: Path) -> bool:
    """Return whether startup must finish an interrupted durable rebuild."""

    connection = connect_database(root / _CLIENT_DATABASE, "reader")
    try:
        row = connection.execute(
            "SELECT 1 FROM rebuild_jobs WHERE state IN "
            "('queued', 'running', 'verifying', 'activating') LIMIT 1"
        ).fetchone()
        return row is not None
    finally:
        connection.close()


class _WorkerBootstrap(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    scope_root: str
    global_descriptor_sha256: Sha256Hex
    scope_marker_sha256: Sha256Hex
    session_id: Uuid7String | None = None
    capability_token_sha256: Sha256Hex
    claim_verification_secret_hex: Sha256Hex | None = None
    execution_attestor_secret_hex: Sha256Hex | None = None
    execution_attestor_id: str | None = None
    client_id: ClientId | None = None


def _unique_object(pairs: list[tuple[str, object]]) -> object:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise WorkerProtocolError
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise WorkerProtocolError


def _encode_bootstrap(
    scope_root: Path,
    global_descriptor_sha256: str,
    scope_marker_sha256: str,
    *,
    session_id: str | None,
    capability_token_sha256: str,
    claim_verification_secret: bytes | None = None,
    execution_attestor_secret: bytes | None = None,
    execution_attestor_id: str | None = None,
    client_id: str | None = None,
) -> bytes:
    try:
        bootstrap = _WorkerBootstrap(
            scope_root=str(scope_root),
            global_descriptor_sha256=global_descriptor_sha256,
            scope_marker_sha256=scope_marker_sha256,
            session_id=session_id,
            capability_token_sha256=capability_token_sha256,
            claim_verification_secret_hex=(
                None
                if claim_verification_secret is None
                else claim_verification_secret.hex()
            ),
            execution_attestor_secret_hex=(
                None
                if execution_attestor_secret is None
                else execution_attestor_secret.hex()
            ),
            execution_attestor_id=execution_attestor_id,
            client_id=client_id,
        )
        encoded = json.dumps(
            bootstrap.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (ValidationError, TypeError, ValueError, UnicodeError):
        raise WorkerProtocolError from None
    if not encoded or len(encoded) > _MAX_BOOTSTRAP_BYTES:
        raise WorkerProtocolError
    return encoded


def _decode_bootstrap(frame: bytes) -> _WorkerBootstrap:
    if type(frame) is not bytes or not frame or len(frame) > _MAX_BOOTSTRAP_BYTES:
        raise WorkerProtocolError
    try:
        raw = json.loads(
            frame.decode("ascii"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        bootstrap = _WorkerBootstrap.model_validate(raw, strict=True)
    except WorkerProtocolError:
        raise WorkerProtocolError from None
    except (ValidationError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        raise WorkerProtocolError from None
    if _encode_bootstrap(
        Path(bootstrap.scope_root),
        bootstrap.global_descriptor_sha256,
        bootstrap.scope_marker_sha256,
        session_id=bootstrap.session_id,
        capability_token_sha256=bootstrap.capability_token_sha256,
        claim_verification_secret=(
            None
            if bootstrap.claim_verification_secret_hex is None
            else bytes.fromhex(bootstrap.claim_verification_secret_hex)
        ),
        execution_attestor_secret=(
            None
            if bootstrap.execution_attestor_secret_hex is None
            else bytes.fromhex(bootstrap.execution_attestor_secret_hex)
        ),
        execution_attestor_id=bootstrap.execution_attestor_id,
        client_id=bootstrap.client_id,
    ) != frame:
        raise WorkerProtocolError
    root = Path(bootstrap.scope_root)
    if not root.is_absolute() or ".." in root.parts:
        raise WorkerProtocolError
    if (bootstrap.execution_attestor_secret_hex is None) != (
        bootstrap.execution_attestor_id is None
    ):
        raise WorkerProtocolError
    return bootstrap


def _verify_request_session_binding(
    request: WorkerRequest,
    bootstrap: _WorkerBootstrap,
) -> None:
    """Second-line verification after strict DTO decoding and before dispatch."""

    session_id, session_handle = worker_request_binding(request)
    if session_id is not None and (
        bootstrap.session_id is None
        or not hmac.compare_digest(session_id, bootstrap.session_id)
    ):
        raise WorkerProtocolError
    if session_handle is not None:
        try:
            presented_sha256 = hashlib.sha256(
                session_handle.encode("utf-8")
            ).hexdigest()
        except UnicodeError:
            raise WorkerProtocolError from None
        if not hmac.compare_digest(
            presented_sha256,
            bootstrap.capability_token_sha256,
        ):
            raise WorkerProtocolError


def _audit_line(request_id: str) -> bytes:
    return (
        json.dumps(
            {
                "event_code": "worker_rpc_completed",
                "request_id": request_id,
                "schema_version": "1.0",
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _utc_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _next_approval_execution_version(
    connection: sqlite3.Connection,
    operation_id: str | None = None,
) -> int:
    if operation_id is not None:
        existing = connection.execute(
            "SELECT applied_commit_version FROM approval_executions "
            "WHERE operation_id = ? AND state = 'APPLIED'",
            (operation_id,),
        ).fetchone()
        if existing is not None and type(existing[0]) is int and existing[0] > 0:
            return existing[0]
    row = connection.execute(
        "SELECT COALESCE(MAX(CAST(applied_commit_version AS INTEGER)), 0) + 1 "
        "FROM approval_executions"
    ).fetchone()
    if row is None or type(row[0]) is not int or row[0] <= 0:
        raise WorkerProtocolError
    return row[0]


def _load_bound_draft(
    connection: sqlite3.Connection,
    draft_event_id: str,
    *,
    expected_scope_hash: str,
    expected_client_id: str,
) -> tuple[FactMutation, str, str]:
    row = connection.execute(
        "SELECT event_json, session_fact_events.session_id, turn_id, event_kind, "
        "client_scope_hash FROM session_fact_events "
        "JOIN sessions USING(session_id) WHERE session_event_id = ?",
        (draft_event_id,),
    ).fetchone()
    if (
        row is None
        or any(type(value) is not str for value in row)
        or not hmac.compare_digest(str(row[4]), expected_scope_hash)
    ):
        raise WorkerProtocolError
    try:
        mutation = FACT_MUTATION_ADAPTER.validate_json(str(row[0]), strict=True)
    except (ValidationError, TypeError, ValueError):
        raise WorkerProtocolError from None
    if row[3] != mutation.operation:
        raise WorkerProtocolError
    supplied_events = (
        (mutation.new_fact,)
        if isinstance(mutation, AddMutation)
        else (mutation.replacement,)
        if isinstance(mutation, SupersedeMutation)
        else (mutation.canonical_projection,)
        if isinstance(mutation, MergeMutation)
        else ()
    )
    session_id = str(row[1])
    turn_id = str(row[2])
    for event in supplied_events:
        if event.client_id != expected_client_id:
            raise WorkerProtocolError
        if event.source_kind == "controlled_import" or (
            event.source_session_id != session_id
            or event.source_turn_id != turn_id
        ):
            raise WorkerProtocolError
    return mutation, session_id, turn_id


def _read_archive_bytes(
    root: Path,
    reference: ArchiveContentRef,
) -> bytes:
    store = ContentStore(root / "cas")
    try:
        content = store.read_verified(
            store.reference(
                content_sha256=reference.content_sha256,
                media_type=reference.media_type,
                size_bytes=reference.size_bytes,
            )
        )
        if hashlib.sha256(content).hexdigest() != reference.content_sha256:
            raise WorkerProtocolError
        return content
    except WorkerProtocolError:
        raise
    except Exception:
        raise WorkerProtocolError from None


def _read_archive_model(
    root: Path,
    reference: ArchiveContentRef,
    model: type[StrictModel],
) -> StrictModel:
    """Resolve one exact object from the pinned client CAS."""

    try:
        content = _read_archive_bytes(root, reference)
        return model.model_validate_json(content, strict=True)
    except WorkerProtocolError:
        raise
    except Exception:
        raise WorkerProtocolError from None


def _archive_content_ref(
    *,
    object_id: str,
    content_sha256: str,
    size_bytes: int,
    version: int = 1,
) -> ArchiveContentRef:
    return ArchiveContentRef(
        object_id=object_id,
        version=version,
        content_sha256=content_sha256,
        size_bytes=size_bytes,
    )


def _read_private_archive_draft(
    root: Path,
    reference: ArchiveContentRef,
) -> PrivateArchiveDraft:
    try:
        content = _read_archive_bytes(root, reference)
        payload = json.loads(content.decode("utf-8"))
        if type(payload) is not dict or set(payload) != {
            "actual",
            "analysis",
            "created_at",
        }:
            raise WorkerProtocolError
        return PrivateArchiveDraft.model_validate_json(
            json.dumps(
                {
                    "draft_ref": reference.version_ref.model_dump(mode="json"),
                    "actual_transcript": payload["actual"],
                    "analysis": payload["analysis"],
                    "created_at": payload["created_at"],
                },
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ),
            strict=True,
        )
    except WorkerProtocolError:
        raise
    except Exception:
        raise WorkerProtocolError from None


def _read_profile_diff_draft(
    root: Path,
    reference: ArchiveContentRef,
) -> ProfileDiffDraft:
    try:
        payload = json.loads(_read_archive_bytes(root, reference).decode("utf-8"))
        if type(payload) is not dict or "canonical_sha256" in payload:
            raise WorkerProtocolError
        payload["canonical_sha256"] = reference.content_sha256
        return ProfileDiffDraft.model_validate_json(
            json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ),
            strict=True,
        )
    except WorkerProtocolError:
        raise
    except Exception:
        raise WorkerProtocolError from None


def _read_shared_case_candidate(
    root: Path,
    reference: ArchiveContentRef,
) -> SharedCaseCandidate:
    try:
        payload = json.loads(_read_archive_bytes(root, reference).decode("utf-8"))
        if (
            type(payload) is not dict
            or payload.pop("candidate_id", None) != reference.object_id
            or payload.pop("version", None) != reference.version
        ):
            raise WorkerProtocolError
        payload["candidate_ref"] = reference.version_ref.model_dump(mode="json")
        payload["candidate_sha256"] = reference.content_sha256
        return SharedCaseCandidate.model_validate_json(
            json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ),
            strict=True,
        )
    except WorkerProtocolError:
        raise
    except Exception:
        raise WorkerProtocolError from None


class _CaseReviewPolicyDraft(StrictModel):
    schema_version: Literal["case_review_policy_draft.v1"] = (
        "case_review_policy_draft.v1"
    )
    candidate_ref: VersionRef
    scan_ref: VersionRef
    purpose: Literal["answer_support"] = "answer_support"
    required_review_categories: tuple[ReviewCategory, ...]
    human_review: SharedCaseHumanReviewDraft
    release_policy_ref: VersionRef
    created_at: datetime


_CASE_REVIEW_CATEGORIES: tuple[ReviewCategory, ...] = (
    "direct_identifiers",
    "third_party_people",
    "rare_attributes",
    "location_occupation_family_time",
    "section_boundaries",
    "no_verbatim_quotes",
)


def _derived_object_id(source_object_id: str, kind: str) -> str:
    suffix = source_object_id[-36:]
    return f"{kind}_{suffix}"


def _resolve_archive_ticket(
    resolver: ArchiveApprovalResolver | None,
    *,
    operation_id: str,
    receipt_id: str,
    purpose: Literal["private_archive_publish", "profile_update", "case_publish"],
    target_id: str,
    client_id: str,
    session_id: str,
    base_version: int,
    draft_sha256: str,
    scope_marker_sha256: str,
) -> ApprovalExecutionTicket:
    if resolver is None:
        raise WorkerProtocolError
    try:
        ticket = ApprovalExecutionTicket.model_validate(
            resolver(operation_id, receipt_id),
            strict=True,
        )
    except Exception:
        raise WorkerProtocolError from None
    descriptor = ticket.descriptor
    if (
        ticket.operation_id != operation_id
        or ticket.request_id != receipt_id
        or not hmac.compare_digest(ticket.target_scope_hash, scope_marker_sha256)
        or descriptor.purpose != purpose
        or descriptor.target_id != target_id
        or descriptor.client_id != client_id
        or descriptor.session_id != session_id
        or descriptor.base_version != base_version
        or not hmac.compare_digest(descriptor.draft_sha256, draft_sha256)
    ):
        raise WorkerProtocolError
    return ticket


class _ExactTicketVerifier:
    """Expose one already broker-verified ticket to a target transaction."""

    def __init__(self, ticket: ApprovalExecutionTicket) -> None:
        self._ticket = ApprovalExecutionTicket.model_validate(ticket)

    def verify_ticket(
        self,
        ticket: ApprovalExecutionTicket,
        descriptor: DraftDescriptor,
        *,
        allow_expired: bool,
    ) -> object:
        del allow_expired
        if ticket != self._ticket or descriptor != self._ticket.descriptor:
            raise WorkerProtocolError
        return self._ticket.receipt


def _build_registry(
    root: Path,
    *,
    scope_marker_sha256: str,
    client_id: str | None,
    bound_session_id: str | None = None,
    archive_approval_resolver: ArchiveApprovalResolver | None = None,
    rollback_approval_request: ApprovalRequest | None = None,
    execution_attestor_secret: bytes | None = None,
    execution_attestor_id: str | None = None,
    publication_plans: dict[str, ClientPublicationPlan] | None = None,
    review_diffs: dict[str, tuple[VersionRef, bytes]] | None = None,
    client_rebuild_resolver: ClientRebuildResolver | None = None,
) -> WorkerOperationRegistry:
    plans = publication_plans if publication_plans is not None else {}
    diffs = review_diffs if review_diffs is not None else {}
    rebuild_resolver = (
        _production_client_rebuild_resolver
        if client_rebuild_resolver is None
        else client_rebuild_resolver
    )

    def client_rollback_workflow(
        connection: sqlite3.Connection,
        *,
        approval_guard: ApprovalExecutionGuard | None = None,
    ) -> SqliteRollbackWorkflow:
        if client_id is None or bound_session_id is None:
            raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
        try:
            from consultation_kb.lifecycle.production_rebuild import (
                load_production_rebuild_config,
            )

            production = load_production_rebuild_config(
                root,
                database_scope="client",
                scope_sha256=scope_marker_sha256,
            )
            coordinator = rebuild_resolver(
                connection,
                root,
                scope_marker_sha256,
            )
            return SqliteRollbackWorkflow(
                connection,
                database_scope="client",
                scope_sha256=scope_marker_sha256,
                content_store=ContentStore(root / "cas"),
                approval_guard=approval_guard,
                rebuild_coordinator=coordinator,
                rebuild_policy_sha256=production.policy_sha256,
                rebuild_model_descriptor_sha256=(
                    production.model_descriptor_sha256
                ),
                bound_session_id=bound_session_id,
            )
        except WorkerOperationalError:
            raise
        except RollbackError:
            raise
        except Exception:
            raise WorkerOperationalError(
                "REBUILD_PRODUCTION_BUILDERS_UNAVAILABLE"
            ) from None
    def open_repository(
        mode: Literal["reader", "writer"] = "reader",
    ) -> tuple[sqlite3.Connection, FactEventRepository]:
        connection = connect_database(root / _CLIENT_DATABASE, mode)
        return connection, FactEventRepository(connection)

    def open_session_repository() -> tuple[sqlite3.Connection, SessionRepository]:
        connection = connect_database(root / _CLIENT_DATABASE, "writer")
        return connection, SessionRepository(
            connection,
            content_store=ContentStore(root / "cas"),
            clock=SystemClock(),
            id_factory=IdFactory(),
        )

    def assert_client_active_integrity(connection: sqlite3.Connection) -> int:
        """Fail closed on corrupt current client artifacts inside the worker.

        This helper is intentionally nested in the already scope-confined
        worker registry.  The MCP control process never receives a client
        database path or connection while private query entry points still
        share the same mandatory integrity contract as global retrieval.
        """

        try:
            epoch_rows = connection.execute(
                "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE' "
                "ORDER BY epoch"
            ).fetchall()
            if not epoch_rows:
                retained_rows = connection.execute(
                    "SELECT COUNT(*) FROM active_artifacts"
                ).fetchone()
                if (
                    retained_rows is None
                    or type(retained_rows[0]) is not int
                    or retained_rows[0] != 0
                ):
                    raise ArtifactUnavailable
                return 0
            if client_id is None:
                raise ArtifactUnavailable
            if len(epoch_rows) != 1 or type(epoch_rows[0][0]) is not int:
                raise ArtifactUnavailable
            epoch = int(epoch_rows[0][0])
            active_rows = connection.execute(
                "SELECT artifact_key, manifest_id FROM active_artifacts "
                "WHERE epoch = ? ORDER BY artifact_key",
                (epoch,),
            ).fetchall()
            if not active_rows:
                raise ArtifactUnavailable
            repository = ManifestRepository(connection)
            artifacts: list[ActiveArtifact] = []
            source_versions: set[int] = set()
            for row in active_rows:
                if type(row[0]) is not str or type(row[1]) is not str:
                    raise ArtifactUnavailable
                manifest = repository.get(str(row[1]))
                source_versions.add(manifest.source_version)
                artifacts.append(
                    ActiveArtifact(
                        artifact_key=str(row[0]),
                        manifest_ref=VersionRef(
                            object_id=manifest.manifest_id,
                            version=manifest.source_version,
                            content_sha256=manifest.manifest_sha256,
                        ),
                    )
                )
            if len(source_versions) != 1:
                raise ArtifactUnavailable
            tombstones = connection.execute(
                "SELECT COUNT(*) FROM tombstones"
            ).fetchone()
            if tombstones is None or type(tombstones[0]) is not int:
                raise ArtifactUnavailable
            ActiveIntegrityGate(
                IntegrityStore(
                    scope="client_private",
                    connection=connection,
                    content_store=ContentStore(root / "cas"),
                    client_id=client_id,
                )
            ).verify(
                epoch=epoch,
                artifacts=tuple(artifacts),
                source_version=next(iter(source_versions)),
                tombstone_epoch=int(tombstones[0]),
                authorization_epoch=None,
            )
            return epoch
        except ArtifactUnavailable:
            raise WorkerOperationalError(
                CLIENT_ACTIVE_INTEGRITY_REBUILD_REQUIRED
            ) from None
        except Exception:
            raise WorkerOperationalError(
                CLIENT_ACTIVE_INTEGRITY_REBUILD_REQUIRED
            ) from None

    def load_session_snapshot(
        repository: SessionRepository,
        session_id: str,
    ) -> ClientContextSnapshot:
        record = repository.get_session(session_id)
        try:
            snapshot = ClientContextSnapshot.model_validate_json(
                repository.read_snapshot(session_id)
            )
        except Exception:
            raise WorkerProtocolError from None
        if (
            snapshot.client_id != record.client_id
            or snapshot.profile_version != record.client_snapshot_version
            or snapshot.canonical_sha256
            != record.client_snapshot_canonical_sha256
        ):
            raise WorkerProtocolError
        return snapshot

    def generation_client_binding(
        repository: SessionRepository,
        *,
        session_id: str,
        turn_id: str,
    ) -> GenerationClientBinding:
        session = repository.get_session(session_id)
        turn = repository.get_turn(session_id, turn_id)
        if session.status != "OPEN" or turn.state == "turn_closed":
            raise WorkerProtocolError
        client_epoch = assert_client_active_integrity(repository.connection)
        tombstone_row = repository.connection.execute(
            "SELECT count(*) FROM tombstones"
        ).fetchone()
        if tombstone_row is None:
            raise WorkerProtocolError
        temporary = TemporaryFactLedger(repository).snapshot(
            session_id,
            turn_id=turn_id,
        )
        temporary_refs = tuple(
            sorted(
                (
                    VersionRef(
                        object_id=item.content.object_id,
                        version=1,
                        content_sha256=item.content.content_sha256,
                    )
                    for item in temporary
                ),
                key=lambda item: (
                    item.object_id,
                    item.version,
                    item.content_sha256,
                ),
            )
        )
        return GenerationClientBinding(
            client_snapshot_ref=VersionRef(
                object_id=session.client_snapshot.object_id,
                version=1,
                content_sha256=session.client_snapshot.content_sha256,
            ),
            client_runtime_epoch=client_epoch,
            client_tombstone_count=int(tombstone_row[0]),
            temporary_fact_refs=temporary_refs,
        )

    def private_generation_evidence(
        connection: sqlite3.Connection,
        *,
        session_handle: str,
        categories: tuple[ClientHistoryQueryCategory, ...],
    ) -> tuple[PrivateGenerationEvidence, ...]:
        if client_id is None:
            raise WorkerProtocolError
        service = ScopedClientHistoryService(
            connection,
            current_client_id=client_id,
            derivation_rule_ref=client_history_derivation_rule_ref(),
        )
        epoch = assert_client_active_integrity(connection)
        by_key: dict[
            tuple[str, int, str, str, int, str], CandidateRef
        ] = {}
        for category in categories:
            result = service.query(
                ClientHistoryQuery(
                    request_id=IdFactory().uuid7(),
                    session_handle=session_handle,
                    query_category=category,
                    limit=100,
                )
            )
            if result.runtime_epoch != epoch:
                raise WorkerProtocolError
            for candidate in result.candidates:
                key = (
                    candidate.reference.object_id,
                    candidate.reference.version,
                    candidate.reference.content_sha256,
                    candidate.content_ref.object_id,
                    candidate.content_ref.version,
                    candidate.content_ref.content_sha256,
                )
                existing = by_key.setdefault(key, candidate)
                if existing != candidate:
                    raise WorkerProtocolError
        store = ContentStore(root / "cas")
        rendered: list[PrivateGenerationEvidence] = []
        for key in sorted(by_key):
            candidate = by_key[key]
            membership = candidate_authority_membership(
                connection,
                schema="main",
                epoch=epoch,
                candidate=candidate,
            )
            if membership is None:
                raise WorkerProtocolError
            try:
                body = store.read_verified(
                    store.reference(
                        content_sha256=candidate.content_ref.content_sha256,
                        media_type=candidate.metadata.media_type,
                        size_bytes=candidate.metadata.size_bytes,
                    )
                ).decode("utf-8", errors="strict")
            except Exception:
                raise WorkerProtocolError from None
            rendered.append(
                PrivateGenerationEvidence(candidate=candidate, body=body)
            )
        return tuple(rendered)

    def session_recovery_payload(
        repository: SessionRepository,
        recovered: RecoveryState,
    ) -> SessionRecoveryPayload:
        """Hydrate only content already proven to belong to this session root."""

        try:
            turns = tuple(
                RecoveredClientTurn(
                    turn_id=turn.turn_id,
                    ordinal=turn.ordinal,
                    state=turn.state,
                    active_run_id=turn.active_run_id,
                    client_message=repository.read_content(
                        turn.client_message
                    ).decode("utf-8"),
                )
                for turn in recovered.turns
            )
            actuals = tuple(
                RecoveredActualReply(
                    actual_reply_id=actual.actual_reply_id,
                    turn_id=actual.turn_id,
                    source_type=actual.source_type,
                    candidate_id=actual.candidate_id,
                    actual_text=(
                        None
                        if actual.content is None
                        else repository.read_content(actual.content).decode("utf-8")
                    ),
                    sent_at=actual.sent_at,
                    confirmed_at=actual.confirmed_at,
                    evidence_gap=actual.evidence_gap,
                )
                for actual in recovered.actual_conversation
            )
            temporary_facts = tuple(
                RecoveredTemporaryFact(
                    event_id=event.event_id,
                    turn_id=event.turn_id,
                    event_kind=event.event_kind,
                    cognitive_type=event.cognitive_type,
                    value=json.loads(
                        repository.read_content(event.content).decode("utf-8")
                    ),
                    target_fact_id=event.target_fact_id,
                    target_fact_version=event.target_fact_version,
                )
                for event in recovered.temporary_facts
            )
            pending_candidates: tuple[RecoveredCandidate, ...] = ()
            if (
                recovered.active_turn is not None
                and recovered.active_turn.state == "awaiting_actual_reply"
            ):
                candidate_set = repository.get_candidate_set(
                    recovered.session.session_id,
                    recovered.active_turn.turn_id,
                )
                pending_candidates = tuple(
                    RecoveredCandidate(
                        candidate_id=candidate.candidate_id,
                        turn_id=candidate.turn_id,
                        run_id=candidate.run_id,
                        ordinal=candidate.ordinal,
                        label=candidate.label,
                        text=repository.read_content(candidate.content).decode("utf-8"),
                    )
                    for candidate in candidate_set.candidates
                )
            return SessionRecoveryPayload(
                pending_action=recovered.pending_action,
                incomplete_evidence=recovered.incomplete_evidence,
                turns=turns,
                actual_replies=actuals,
                temporary_facts=temporary_facts,
                pending_candidates=pending_candidates,
                discarded_stage_artifact_ids=(
                    recovered.discarded_stage_artifact_ids
                ),
            )
        except Exception:
            raise WorkerProtocolError from None

    def load_dependencies(connection: sqlite3.Connection) -> tuple[DependencyEdge, ...]:
        rows = connection.execute(
            "SELECT edge_id, dependent_fact_id, prerequisite_fact_id, "
            "dependency_type, confidence, source_event_id, reviewer_id "
            "FROM fact_dependencies ORDER BY edge_id"
        ).fetchall()
        return tuple(
            DependencyEdge.model_validate(
                {
                    "edge_id": row[0],
                    "dependent_fact_id": row[1],
                    "prerequisite_fact_id": row[2],
                    "dependency_type": row[3],
                    "confidence": row[4],
                    "source_event_id": row[5],
                    "reviewer_id": row[6],
                }
            )
            for row in rows
        )

    def assert_active_epoch(connection: sqlite3.Connection, fixed_epoch: int) -> None:
        highest_active = assert_client_active_integrity(connection)
        if fixed_epoch > highest_active:
            raise WorkerProtocolError

    def current_runtime_epoch(connection: sqlite3.Connection) -> int:
        return assert_client_active_integrity(connection)

    def temporal_graph_view(
        connection: sqlite3.Connection,
        repository: FactEventRepository,
        *,
        as_of: datetime,
    ) -> tuple[
        TemporalGraphSnapshot,
        tuple[tuple[str, str, str, dict[str, object]], ...],
        dict[str, FactEvent],
        int,
    ]:
        epoch = current_runtime_epoch(connection)
        snapshot = BitemporalFactQuery(repository).snapshot(
            FactQuery(
                effective_at=as_of,
                known_at=as_of,
                fixed_epoch=epoch,
            )
        )
        graph = TemporalGraphBuilder().build(
            snapshot,
            publication_operation_id="worker_query",
            runtime_epoch=max(1, epoch),
            dependencies=load_dependencies(connection),
        )
        edges = TemporalGraphQuery(graph.graph).edges_at(
            effective_at=as_of,
            known_at=as_of,
        )
        events = {event.fact_id: event for event in snapshot.events}
        return graph, edges, events, epoch

    def fact_reference(event: FactEvent) -> VersionRef:
        body = (canonical_json(event.model_dump(mode="json")) + "\n").encode(
            "utf-8"
        )
        return VersionRef(
            object_id=event.fact_id,
            version=event.event_version,
            content_sha256=hashlib.sha256(body).hexdigest(),
        )

    def edge_matches_query(query: str, attributes: dict[str, object]) -> bool:
        normalized = query.casefold().strip()
        searchable = " ".join(
            str(attributes.get(key, "")).casefold()
            for key in (
                "edge_id",
                "fact_id",
                "relation_type",
                "dependency_type",
                "epistemic_status",
            )
        )
        tokens = tuple(re.findall(r"[\w-]+", normalized, flags=re.UNICODE))
        if any(token in searchable for token in tokens):
            return True
        aliases = {
            "relationship": ("relationship", "partner", "关系", "伴侣", "男友", "女友"),
            "dependency": ("dependency", "impact", "依赖", "影响", "边效应"),
            "all": ("all", "overview", "全部", "概览", "所有"),
        }
        relation = str(attributes.get("relation_type", "")).casefold()
        dependency = str(attributes.get("dependency_type", "")).casefold()
        if any(alias in normalized for alias in aliases["all"]):
            return True
        if "relationship" in relation and any(
            alias in normalized for alias in aliases["relationship"]
        ):
            return True
        return dependency != "direct_deterministic" and any(
            alias in normalized for alias in aliases["dependency"]
        )

    def selected_graph_edges(
        edges: tuple[tuple[str, str, str, dict[str, object]], ...],
        *,
        query: str,
        max_depth: int,
    ) -> tuple[tuple[str, str, str, dict[str, object]], ...]:
        selected = {
            edge[2]: edge for edge in edges if edge_matches_query(query, edge[3])
        }
        if not selected:
            return ()
        frontier = {
            node for source, target, _key, _attributes in selected.values() for node in (source, target)
        }
        for _depth in range(1, max_depth):
            added = {
                key: edge
                for edge in edges
                for source, target, key, _attributes in (edge,)
                if key not in selected and (source in frontier or target in frontier)
            }
            if not added:
                break
            selected.update(added)
            frontier = {
                node
                for source, target, _key, _attributes in added.values()
                for node in (source, target)
            }
        return tuple(selected[key] for key in sorted(selected))

    def graph_edge_view(
        edge: tuple[str, str, str, dict[str, object]],
        events: dict[str, FactEvent],
    ) -> ClientGraphEdgeView | None:
        _source, _target, edge_id, attributes = edge
        event = events.get(str(attributes.get("fact_id", "")))
        if event is None:
            return None
        raw_sources = attributes.get("source_event_ids", ())
        source_event_ids = (
            tuple(str(value) for value in raw_sources)
            if isinstance(raw_sources, (tuple, list))
            else ()
        )
        raw_confidence = attributes.get("confidence", 0.0)
        confidence = (
            float(raw_confidence)
            if isinstance(raw_confidence, (str, int, float))
            and not isinstance(raw_confidence, bool)
            else 0.0
        )
        return ClientGraphEdgeView(
            edge_id=edge_id,
            fact_ref=fact_reference(event),
            relation_type=str(attributes.get("relation_type", "ABOUT_ENTITY")),
            dependency_type=str(
                attributes.get("dependency_type", "direct_deterministic")
            ),
            confidence=min(1.0, max(0.0, confidence)),
            source_event_ids=source_event_ids,
            effective_from=event.effective_from,
            effective_to=event.effective_to,
        )

    def ping(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not PingRequest:
            raise WorkerProtocolError
        return PingResponse(request_id=request.request_id)

    def empty_metadata(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not EmptyContextMetadataRequest:
            raise WorkerProtocolError
        return EmptyContextMetadataResponse(request_id=request.request_id)

    def append_audit(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not AppendScopedAuditRequest:
            raise WorkerProtocolError
        line = _audit_line(request.request_id)
        with PathGuard(root).open_scoped(_AUDIT_STREAM, mode="r+b") as stream:
            stream.seek(0, os.SEEK_END)
            if stream.write(line) != len(line):
                raise WorkerProtocolError
            stream.flush()
            os.fsync(stream.fileno())
        return AppendScopedAuditResponse(request_id=request.request_id)

    def query_facts(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not QueryFactSnapshotRequest:
            raise WorkerProtocolError
        connection, repository = open_repository()
        try:
            assert_active_epoch(connection, request.fixed_epoch)
            snapshot = BitemporalFactQuery(repository).snapshot(
                FactQuery(
                    effective_at=request.effective_at,
                    known_at=request.known_at,
                    fixed_epoch=request.fixed_epoch,
                )
            )
            snapshot = BitemporalFactQuery.snapshot_events(
                tuple(
                    event
                    for event in snapshot.events
                    if event.privacy_level == "private_client"
                    and event.allows_purpose("next_session_context")
                ),
                snapshot.query,
                client_commit_version=snapshot.client_commit_version,
            )
            return QueryFactSnapshotResponse(
                request_id=request.request_id,
                snapshot_sha256=snapshot.canonical_sha256,
                client_commit_version=snapshot.client_commit_version,
                event_count=len(snapshot.events),
            )
        finally:
            connection.close()

    def preview_mutation(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not PreviewFactMutationRequest:
            raise WorkerProtocolError
        connection, repository = open_repository("writer")
        try:
            if client_id is None:
                raise WorkerProtocolError
            if repository.current_commit_version() != request.base_commit_version:
                raise WorkerProtocolError
            mutation, session_id, _turn_id = _load_bound_draft(
                connection,
                request.draft_event_id,
                expected_scope_hash=scope_marker_sha256,
                expected_client_id=client_id,
            )
            current_epoch = RuntimeEpochRepository(connection).current()
            expected_runtime_epoch = (current_epoch.epoch if current_epoch else 0) + 1
            publication_timestamp = datetime.now(timezone.utc)
            plan = ClientPublicationPlanner(connection).prepare(
                mutation,
                draft_event_id=request.draft_event_id,
                operation_id=request.proposed_operation_id,
                expected_runtime_epoch=expected_runtime_epoch,
                publication_timestamp=publication_timestamp,
                draft_session_id=session_id,
            )
            if plan.mutation_preview.base_commit_version != request.base_commit_version:
                raise WorkerProtocolError
            fact_manifest = next(
                artifact
                for artifact in plan.artifacts
                if artifact.artifact_key == "client_fact_snapshot"
            )
            staged = ContentStore(root / "cas").stage_bytes(
                plan.mutation_diff_bytes,
                purpose="profile_update_review",
                manifest_id=fact_manifest.manifest_id,
                media_type="application/json",
            )
            finalized = ContentStore(root / "cas").finalize(staged)
            if finalized.content_sha256 != plan.diff_object_ref.content_sha256:
                raise WorkerProtocolError
            plans[request.draft_event_id] = plan
            diffs[plan.diff_object_ref.object_id] = (
                plan.diff_object_ref,
                plan.mutation_diff_bytes,
            )
            with transaction(connection):
                existing = connection.execute(
                    "SELECT version, content_sha256, size_bytes, media_type, "
                    "draft_event_id, operation_id, preview_sha256, "
                    "base_commit_version, expected_runtime_epoch, purpose "
                    "FROM review_diff_objects WHERE object_id = ?",
                    (plan.diff_object_ref.object_id,),
                ).fetchone()
                expected = (
                    plan.diff_object_ref.version,
                    plan.diff_object_ref.content_sha256,
                    finalized.size_bytes,
                    finalized.media_type,
                    request.draft_event_id,
                    request.proposed_operation_id,
                    plan.preview_sha256,
                    plan.mutation_preview.base_commit_version,
                    plan.runtime_epoch,
                    "profile_update_review",
                )
                if existing is None:
                    connection.execute(
                        "INSERT INTO review_diff_objects("
                        "object_id, version, content_sha256, size_bytes, media_type, "
                        "draft_event_id, operation_id, preview_sha256, "
                        "base_commit_version, expected_runtime_epoch, purpose, created_at"
                        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            plan.diff_object_ref.object_id,
                            *expected,
                            publication_timestamp.isoformat(
                                timespec="microseconds"
                            ).replace("+00:00", "Z"),
                        ),
                    )
                elif existing != expected:
                    raise WorkerProtocolError
            return PreviewFactMutationResponse(
                request_id=request.request_id,
                preview_sha256=plan.preview_sha256,
                base_commit_version=plan.mutation_preview.base_commit_version,
                publication_operation_id=plan.operation_id,
                expected_runtime_epoch=plan.runtime_epoch,
                publication_timestamp=plan.publication_timestamp,
                diff_object_ref=plan.diff_object_ref,
                duplicate_candidate_count=sum(
                    item.classification == "exact_duplicate"
                    for item in plan.mutation_preview.candidates
                ),
                conflict_candidate_count=sum(
                    item.classification == "conflict"
                    for item in plan.mutation_preview.candidates
                ),
                direct_invalidation_count=(
                    0
                    if plan.dependency_impact is None
                    else len(plan.dependency_impact.direct_invalidations)
                ),
                manual_review_count=(
                    0
                    if plan.dependency_impact is None
                    else len(plan.dependency_impact.manual_reviews)
                ),
            )
        finally:
            connection.close()

    def confirm_governed_commit(request: WorkerRequest) -> WorkerResponse:
        """Tool-facing commit cannot carry the private approval execution claim."""
        if type(request) is not CommitFactMutationRequest:
            raise WorkerProtocolError
        raise WorkerProtocolError

    def query_profile(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not QueryProfileSnapshotRequest:
            raise WorkerProtocolError
        connection, repository = open_repository()
        try:
            assert_active_epoch(connection, request.fixed_epoch)
            snapshot = BitemporalFactQuery(repository).snapshot(
                FactQuery(
                    effective_at=request.effective_at,
                    known_at=request.known_at,
                    fixed_epoch=request.fixed_epoch,
                )
            )
            profile = ProfileMaterializer().build(
                snapshot,
                merge_member_event_ids=repository.list_merge_member_ids(),
            )
            return QueryProfileSnapshotResponse(
                request_id=request.request_id,
                profile_sha256=profile.canonical_sha256,
                source_client_commit_version=profile.source_client_commit_version,
                item_count=len(profile.current_event_ids),
            )
        finally:
            connection.close()

    def query_graph(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not QueryClientGraphRequest:
            raise WorkerProtocolError
        connection, repository = open_repository()
        try:
            assert_active_epoch(connection, request.fixed_epoch)
            snapshot = BitemporalFactQuery(repository).snapshot(
                FactQuery(
                    effective_at=request.effective_at,
                    known_at=request.known_at,
                    fixed_epoch=request.fixed_epoch,
                )
            )
            graph = TemporalGraphBuilder().build(
                snapshot,
                publication_operation_id="worker_query",
                runtime_epoch=max(1, request.fixed_epoch),
                dependencies=load_dependencies(connection),
            )
            current_edges = TemporalGraphQuery(graph.graph).edges_at(
                effective_at=request.effective_at,
                known_at=request.known_at,
            )
            current_nodes = {
                node
                for source, target, _key, _attributes in current_edges
                for node in (source, target)
            }
            return QueryClientGraphResponse(
                request_id=request.request_id,
                graph_sha256=graph.canonical_sha256,
                source_client_commit_version=graph.source_client_commit_version,
                node_count=len(current_nodes),
                edge_count=len(current_edges),
            )
        finally:
            connection.close()

    def search_graph(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not SearchClientGraphRequest:
            raise WorkerProtocolError
        connection, repository = open_repository()
        try:
            graph, edges, events, epoch = temporal_graph_view(
                connection,
                repository,
                as_of=request.as_of,
            )
            selected = selected_graph_edges(
                edges,
                query=request.query,
                max_depth=request.max_depth,
            )
            safe_items = tuple(
                item
                for item in (graph_edge_view(edge, events) for edge in selected)
                if item is not None
            )
            items = safe_items[: request.limit]
            current_nodes = {
                node
                for source, target, _key, _attributes in edges
                for node in (source, target)
            }
            return SearchClientGraphResponse(
                request_id=request.request_id,
                graph_sha256=graph.canonical_sha256,
                source_client_commit_version=graph.source_client_commit_version,
                runtime_epoch=epoch,
                node_count=len(current_nodes),
                edge_count=len(edges),
                count=len(items),
                items=items,
                truncated=len(safe_items) > len(items),
            )
        finally:
            connection.close()

    def weighted_client_path(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not QueryClientWeightedPathRequest:
            raise WorkerProtocolError
        connection, repository = open_repository()
        try:
            graph, _edges, _events, epoch = temporal_graph_view(
                connection,
                repository,
                as_of=request.as_of,
            )
            paths = TemporalGraphQuery(graph.graph).weighted_paths(
                request.source_ref,
                request.target_ref,
                effective_at=request.as_of,
                known_at=request.as_of,
                max_hops=request.max_hops,
                top_k=request.max_paths,
                max_expansions=25_000,
            )
            rendered = tuple(
                ClientWeightedPathView(
                    total_cost=path.total_cost,
                    edge_ids=path.edge_ids,
                    steps=tuple(
                        ClientWeightedPathStepView(
                            edge_id=step.edge_id,
                            fact_id=step.fact_id,
                            source_event_ids=step.source_event_ids,
                            restrictions=step.restrictions,
                            cost=step.cost,
                        )
                        for step in path.steps
                    ),
                )
                for path in paths
            )
            return QueryClientWeightedPathResponse(
                request_id=request.request_id,
                graph_sha256=graph.canonical_sha256,
                source_client_commit_version=graph.source_client_commit_version,
                runtime_epoch=epoch,
                count=len(rendered),
                paths=rendered,
            )
        finally:
            connection.close()

    def query_client_history_candidates(
        request: WorkerRequest,
    ) -> WorkerResponse:
        if type(request) is not QueryClientHistoryCandidatesRequest:
            raise WorkerProtocolError
        if client_id is None:
            raise WorkerProtocolError
        connection, _repository = open_repository()
        try:
            active_epoch = assert_client_active_integrity(connection)
            result = ScopedClientHistoryService(
                connection,
                current_client_id=client_id,
                derivation_rule_ref=client_history_derivation_rule_ref(),
            ).query(
                ClientHistoryQuery(
                    request_id=request.request_id,
                    session_handle=request.session_handle,
                    query_category=request.query_category,
                    as_of=request.as_of,
                    limit=20,
                )
            )
            if result.runtime_epoch not in {0, active_epoch}:
                raise WorkerProtocolError
            return QueryClientHistoryCandidatesResponse(
                request_id=request.request_id,
                candidates=result.candidates,
                runtime_epoch=result.runtime_epoch,
            )
        finally:
            connection.close()

    def get_generation_binding(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not GetGenerationBindingRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            binding = generation_client_binding(
                repository,
                session_id=request.session_id,
                turn_id=request.turn_id,
            )
            return GetGenerationBindingResponse(
                request_id=request.request_id,
                session_id=request.session_id,
                turn_id=request.turn_id,
                binding=binding,
            )
        finally:
            connection.close()

    def prepare_generation_retrieval(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not PrepareGenerationRetrievalRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            turn = repository.get_turn(request.session_id, request.turn_id)
            risk_evaluations = TurnRiskEvaluationRepository(
                connection,
                database_scope="client",
                clock=SystemClock(),
            )
            try:
                risk_evaluation = risk_evaluations.require_completed(
                    request.session_id,
                    request.turn_id,
                    client_message_sha256=turn.client_message.content_sha256,
                    authority=request.risk_authority,
                )
            except (RiskLifecycleConflict, RiskRepositoryError):
                raise WorkerOperationalError(
                    "RISK_EVALUATION_INCOMPLETE"
                ) from None
            if turn.state == "generation_in_progress":
                if turn.active_run_id != request.run_id:
                    raise WorkerOperationalError("GENERATION_BINDING_MISMATCH")
            elif turn.state != "client_turn_received" or turn.active_run_id is not None:
                raise WorkerOperationalError("GENERATION_BINDING_MISMATCH")
            binding = generation_client_binding(
                repository,
                session_id=request.session_id,
                turn_id=request.turn_id,
            )
            context = GenerationTurnContext(
                session_id=request.session_id,
                turn_id=request.turn_id,
                run_id=request.run_id,
            )
            try:
                plan_record = GenerationStageStore(repository).get_latest(
                    context,
                    stage="query_plan",
                )
            except (KeyError, GenerationStageIntegrityError):
                raise WorkerOperationalError(
                    "GENERATION_BINDING_MISMATCH"
                ) from None
            if not isinstance(plan_record.payload, QueryPlan):
                raise WorkerOperationalError("GENERATION_BINDING_MISMATCH")
            plan = plan_record.payload
            if (
                plan_record.artifact.content_sha256
                != request.query_plan_sha256
                or plan.envelope.turn_id != request.turn_id
                or plan.envelope.run_id != request.run_id
                or plan.global_runtime_epoch
                != request.risk_authority.global_runtime_epoch
            ):
                raise WorkerOperationalError("GENERATION_BINDING_MISMATCH")
            snapshot = load_session_snapshot(repository, request.session_id)
            temporary_facts = TemporaryFactLedger(repository).snapshot(
                request.session_id,
                turn_id=request.turn_id,
            )
            try:
                temporary_values = {
                    event.content.object_id: json.loads(
                        repository.read_content(event.content).decode(
                            "utf-8",
                            errors="strict",
                        )
                    )
                    for event in temporary_facts
                }
                c1_applicability_input = build_c1_applicability_input(
                    plan,
                    binding,
                    snapshot,
                    temporary_facts,
                    temporary_values,
                )
            except (
                C1ContextProjectionError,
                TypeError,
                ValueError,
                UnicodeError,
            ):
                raise WorkerOperationalError(
                    "GENERATION_BINDING_MISMATCH"
                ) from None
            private = private_generation_evidence(
                connection,
                session_handle="scoped-generation-retrieval",
                categories=request.query_categories,
            )
            risk_repository = InternalRiskObservationRepository(
                connection,
                database_scope="client",
                clock=SystemClock(),
            )
            try:
                turn_risk = risk_evaluations.observations_for(risk_evaluation)
            except RiskRepositoryError:
                raise WorkerOperationalError(
                    "RISK_EVALUATION_INCOMPLETE"
                ) from None
            visible_risk = risk_repository.list_visible(request.session_id)
            if (
                risk_evaluation.observation_count is None
                or risk_evaluation.observation_set_sha256 is None
                or risk_evaluation.observation_count != len(turn_risk)
                or canonical_risk_observation_set_sha256(turn_risk)
                != risk_evaluation.observation_set_sha256
            ):
                raise WorkerOperationalError("RISK_EVALUATION_INCOMPLETE")
            risk_context_binding = GenerationRiskContextBinding(
                turn_id=request.turn_id,
                client_message_sha256=turn.client_message.content_sha256,
                authority=risk_evaluation.authority,
                evaluation_observation_ids=tuple(
                    record.observation.observation_id for record in turn_risk
                ),
                evaluation_set_sha256=risk_evaluation.observation_set_sha256,
                evaluation_count=risk_evaluation.observation_count,
                visible_observation_ids=tuple(
                    record.observation.observation_id for record in visible_risk
                ),
                visible_set_sha256=canonical_risk_observation_set_sha256(
                    visible_risk
                ),
                visible_count=len(visible_risk),
            )
            # Close the metadata/body race before returning any private text.
            if binding != generation_client_binding(
                repository,
                session_id=request.session_id,
                turn_id=request.turn_id,
            ):
                raise WorkerOperationalError("GENERATION_BINDING_MISMATCH")
            return PrepareGenerationRetrievalResponse(
                request_id=request.request_id,
                session_id=request.session_id,
                turn_id=request.turn_id,
                run_id=request.run_id,
                query_plan_sha256=plan_record.artifact.content_sha256,
                binding=binding,
                c1_applicability_input=c1_applicability_input,
                risk_context_binding=risk_context_binding,
                private_evidence=private,
            )
        finally:
            connection.close()

    def store_generation_evidence_pack(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not StoreGenerationEvidencePackRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            context = GenerationTurnContext(
                session_id=request.session_id,
                turn_id=request.turn_id,
                run_id=request.run_id,
            )
            stages = GenerationStageStore(repository)
            try:
                plan_record = stages.get_latest(context, stage="query_plan")
            except (KeyError, GenerationStageIntegrityError):
                raise WorkerOperationalError("GENERATION_BINDING_MISMATCH") from None
            if (
                plan_record.artifact.content_sha256 != request.query_plan_sha256
                or not isinstance(plan_record.payload, QueryPlan)
            ):
                raise WorkerOperationalError("GENERATION_BINDING_MISMATCH")
            plan = plan_record.payload
            binding = generation_client_binding(
                repository,
                session_id=request.session_id,
                turn_id=request.turn_id,
            )
            pack = request.evidence_pack
            authority = pack.authority
            if (
                plan.client_snapshot_ref != binding.client_snapshot_ref
                or plan.client_runtime_epoch != binding.client_runtime_epoch
                or plan.client_snapshot_ref != pack.client_snapshot_ref
                or plan.global_runtime_epoch != authority.global_runtime_epoch
                or plan.client_runtime_epoch != authority.client_runtime_epoch
                or plan.tombstone_epoch != authority.tombstone_epoch
                or plan.authorization_epoch != authority.authorization_epoch
                or plan.tombstone_epoch & 0xFFFFFFFF
                != binding.client_tombstone_count
                or pack.temporary_fact_refs != binding.temporary_fact_refs
            ):
                raise WorkerOperationalError("GENERATION_BINDING_MISMATCH")
            try:
                temporary_by_ref = {
                    (
                        item.content.object_id,
                        1,
                        item.content.content_sha256,
                    ): item
                    for item in TemporaryFactLedger(repository).snapshot(
                        request.session_id,
                        turn_id=request.turn_id,
                    )
                }
                temporary_context: list[GenerationEvidenceContextItem] = []
                for reference in pack.temporary_fact_refs:
                    event = temporary_by_ref.get(
                        (
                            reference.object_id,
                            reference.version,
                            reference.content_sha256,
                        )
                    )
                    if event is None:
                        raise GenerationEvidenceBindingMismatch
                    try:
                        body = repository.read_content(event.content).decode(
                            "utf-8",
                            errors="strict",
                        )
                    except (TypeError, ValueError, UnicodeError):
                        raise GenerationEvidenceBindingMismatch from None
                    temporary_context.append(
                        GenerationEvidenceContextItem(
                            evidence_id=reference.object_id,
                            context_kind="temporary_fact",
                            text_ref=reference,
                            body=body,
                        )
                    )
                evidence_context = validate_generation_evidence_context(
                    pack,
                    tuple(
                        sorted(
                            (*request.evidence_context, *temporary_context),
                            key=lambda item: item.evidence_id,
                        )
                    ),
                )
                turn = repository.get_turn(request.session_id, request.turn_id)
                risk_evaluations = TurnRiskEvaluationRepository(
                    connection,
                    database_scope="client",
                    clock=SystemClock(),
                )
                risk_evaluation = risk_evaluations.get(
                    request.session_id,
                    request.turn_id,
                )
                risk_repository = InternalRiskObservationRepository(
                    connection,
                    database_scope="client",
                    clock=SystemClock(),
                )
                try:
                    turn_risk = risk_evaluations.observations_for(risk_evaluation)
                except RiskRepositoryError:
                    raise GenerationEvidenceBindingMismatch from None
                visible_risk = risk_repository.list_visible(request.session_id)
                if (
                    risk_evaluation.status != "completed"
                    or risk_evaluation.client_message_sha256
                    != turn.client_message.content_sha256
                    or risk_evaluation.observation_count != len(turn_risk)
                    or risk_evaluation.observation_set_sha256 is None
                    or canonical_risk_observation_set_sha256(turn_risk)
                    != risk_evaluation.observation_set_sha256
                ):
                    raise GenerationEvidenceBindingMismatch
                risk_context_binding = GenerationRiskContextBinding(
                    turn_id=request.turn_id,
                    client_message_sha256=risk_evaluation.client_message_sha256,
                    authority=risk_evaluation.authority,
                    evaluation_observation_ids=tuple(
                        item.observation.observation_id for item in turn_risk
                    ),
                    evaluation_set_sha256=(
                        risk_evaluation.observation_set_sha256
                    ),
                    evaluation_count=len(turn_risk),
                    visible_observation_ids=tuple(
                        item.observation.observation_id for item in visible_risk
                    ),
                    visible_set_sha256=canonical_risk_observation_set_sha256(
                        visible_risk
                    ),
                    visible_count=len(visible_risk),
                )
                validate_generation_required_evidence_proofs(
                    plan,
                    pack,
                    evidence_context,
                    request.retrieval_metadata.evidence_type_proofs,
                    risk_context_binding=risk_context_binding,
                )
                record = GenerationEvidencePackStore(repository).register(
                    session_id=request.session_id,
                    turn_id=request.turn_id,
                    run_id=request.run_id,
                    query_plan_sha256=request.query_plan_sha256,
                    pack=pack,
                    evidence_context=evidence_context,
                    run_objects=request.run_objects,
                    metadata=request.retrieval_metadata,
                )
            except (GenerationEvidenceBindingMismatch, RiskRepositoryError):
                raise WorkerOperationalError("GENERATION_BINDING_MISMATCH") from None
            except GenerationEvidenceConflict:
                raise WorkerOperationalError("GENERATION_STAGE_CONFLICT") from None
            return StoreGenerationEvidencePackResponse(
                request_id=request.request_id,
                session_id=request.session_id,
                turn_id=request.turn_id,
                run_id=request.run_id,
                query_plan_sha256=request.query_plan_sha256,
                evidence_pack_ref=record.pack_ref,
                evidence_pack_sha256=record.pack_ref.content_sha256,
                evidence_pack=record.pack,
                evidence_context_ref=record.evidence_context_ref,
                evidence_context_sha256=(
                    record.evidence_context_ref.content_sha256
                ),
                evidence_context=record.evidence_context,
                retrieval_metadata=record.metadata,
            )
        finally:
            connection.close()

    def get_generation_evidence_for_plan(
        request: WorkerRequest,
    ) -> WorkerResponse:
        if type(request) is not GetGenerationEvidenceForPlanRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            context = GenerationTurnContext(
                session_id=request.session_id,
                turn_id=request.turn_id,
                run_id=request.run_id,
            )
            turn = repository.get_turn(request.session_id, request.turn_id)
            # The frozen pack remains part of the active run's read-only
            # closure after final synthesis and until the counselor records
            # the actual reply.  FinalTurnBundle atomically advances the turn
            # to ``awaiting_actual_reply`` before the control plane performs
            # its post-submit binding check, so refusing this state would make
            # every otherwise-successful final submission appear to fail.
            if (
                turn.state not in {
                    "generation_in_progress",
                    "awaiting_actual_reply",
                }
                or turn.active_run_id != request.run_id
            ):
                raise WorkerOperationalError("GENERATION_BINDING_MISMATCH")
            try:
                plan = GenerationStageStore(repository).get_latest(
                    context,
                    stage="query_plan",
                )
            except (KeyError, GenerationStageIntegrityError):
                raise WorkerOperationalError("GENERATION_BINDING_MISMATCH") from None
            if (
                plan.artifact.content_sha256 != request.query_plan_sha256
                or not isinstance(plan.payload, QueryPlan)
            ):
                raise WorkerOperationalError("GENERATION_BINDING_MISMATCH")
            try:
                record = GenerationEvidencePackStore(repository).get_for_plan(
                    session_id=request.session_id,
                    turn_id=request.turn_id,
                    run_id=request.run_id,
                    query_plan_sha256=request.query_plan_sha256,
                )
            except GenerationEvidenceBindingMismatch:
                return GetGenerationEvidenceForPlanResponse(
                    request_id=request.request_id,
                    session_id=request.session_id,
                    turn_id=request.turn_id,
                    run_id=request.run_id,
                    query_plan_sha256=request.query_plan_sha256,
                    ready=False,
                )
            return GetGenerationEvidenceForPlanResponse(
                request_id=request.request_id,
                session_id=request.session_id,
                turn_id=request.turn_id,
                run_id=request.run_id,
                query_plan_sha256=request.query_plan_sha256,
                ready=True,
                evidence_pack_ref=record.pack_ref,
                evidence_pack_sha256=record.pack_ref.content_sha256,
                evidence_pack=record.pack,
                evidence_context_ref=record.evidence_context_ref,
                evidence_context_sha256=(
                    record.evidence_context_ref.content_sha256
                ),
                evidence_context=record.evidence_context,
                retrieval_metadata=record.metadata,
            )
        finally:
            connection.close()

    def generation_wire_record(record: object) -> GenerationStageWireRecord:
        exact = GenerationStageRecord.model_validate(record, strict=True)
        return GenerationStageWireRecord(
            stage_revision_id=exact.stage_revision_id,
            revision=exact.revision,
            stage=exact.stage,
            artifact=exact.artifact,
            parent_sha256s=exact.parent_sha256s,
            payload=exact.payload,
            created_at=exact.created_at,
        )

    def submit_generation_stage(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not SubmitGenerationStageRequest:
            raise WorkerProtocolError
        payload = request.stage_payload
        context = GenerationTurnContext(
            session_id=request.session_id,
            turn_id=payload.envelope.turn_id,
            run_id=payload.envelope.run_id,
        )
        connection, repository = open_session_repository()
        try:
            store = GenerationStageStore(repository)
            visible_risk = InternalRiskObservationRepository(
                connection,
                database_scope="client",
                clock=SystemClock(),
            ).list_visible(request.session_id)
            if isinstance(payload, QueryPlan):
                if request.risk_authority is None:
                    raise WorkerProtocolError
                turn = repository.get_turn(
                    request.session_id,
                    payload.envelope.turn_id,
                )
                try:
                    TurnRiskEvaluationRepository(
                        connection,
                        database_scope="client",
                        clock=SystemClock(),
                    ).require_completed(
                        request.session_id,
                        payload.envelope.turn_id,
                        client_message_sha256=(
                            turn.client_message.content_sha256
                        ),
                        authority=request.risk_authority,
                    )
                except (RiskLifecycleConflict, RiskRepositoryError):
                    raise WorkerOperationalError(
                        "RISK_EVALUATION_INCOMPLETE"
                    ) from None
                binding = generation_client_binding(
                    repository,
                    session_id=request.session_id,
                    turn_id=payload.envelope.turn_id,
                )
                if (
                    payload.client_snapshot_ref != binding.client_snapshot_ref
                    or payload.client_runtime_epoch != binding.client_runtime_epoch
                    or payload.tombstone_epoch & 0xFFFFFFFF
                    != binding.client_tombstone_count
                ):
                    raise WorkerOperationalError("GENERATION_BINDING_MISMATCH")
                pack = None
            else:
                try:
                    pack_record = GenerationEvidencePackStore(repository).get_by_hash(
                        session_id=request.session_id,
                        turn_id=payload.envelope.turn_id,
                        run_id=payload.envelope.run_id,
                        pack_sha256=payload.evidence_pack_sha256,
                    )
                    plan_record = store.get_latest(context, stage="query_plan")
                except (GenerationEvidenceBindingMismatch, KeyError):
                    raise WorkerOperationalError("GENERATION_BINDING_MISMATCH") from None
                if pack_record.query_plan_sha256 != plan_record.artifact.content_sha256:
                    raise WorkerOperationalError("GENERATION_BINDING_MISMATCH")
                plan_payload = plan_record.payload
                if not isinstance(plan_payload, QueryPlan):
                    raise GenerationStageIntegrityError
                current_binding = generation_client_binding(
                    repository,
                    session_id=request.session_id,
                    turn_id=payload.envelope.turn_id,
                )
                if (
                    plan_payload.client_snapshot_ref
                    != current_binding.client_snapshot_ref
                    or plan_payload.client_runtime_epoch
                    != current_binding.client_runtime_epoch
                    or plan_payload.tombstone_epoch & 0xFFFFFFFF
                    != current_binding.client_tombstone_count
                    or pack_record.pack.temporary_fact_refs
                    != current_binding.temporary_fact_refs
                ):
                    raise WorkerOperationalError("GENERATION_BINDING_MISMATCH")
                pack = pack_record.pack
                active = store.list_records(context)
                previous_nonquery = next(
                    (
                        item
                        for item in reversed(active)
                        if not isinstance(item.payload, QueryPlan)
                    ),
                    None,
                )
                if not isinstance(payload, Conceptualization) and previous_nonquery is not None:
                    previous_payload = previous_nonquery.payload
                    if isinstance(previous_payload, QueryPlan):
                        raise GenerationStageIntegrityError
                    if (
                        previous_payload.evidence_pack_sha256
                        != payload.evidence_pack_sha256
                    ):
                        raise WorkerOperationalError("GENERATION_BINDING_MISMATCH")

                if isinstance(payload, Conceptualization):
                    ConceptualizationValidator().require_valid(payload, pack)
                elif isinstance(payload, TheoryComparison):
                    TheoryUsePolicy().require_valid(
                        payload,
                        pack,
                        hard_constraint_evidence_ids=(
                            derive_hard_constraint_evidence_ids(pack)
                        ),
                    )
                elif isinstance(payload, ReplyDraftSet):
                    try:
                        conceptualization = store.get_latest(
                            context,
                            stage="conceptualization",
                        ).payload
                    except KeyError:
                        raise WorkerOperationalError(
                            "GENERATION_STAGE_ORDER_INVALID"
                        ) from None
                    if not isinstance(conceptualization, Conceptualization):
                        raise WorkerOperationalError(
                            "GENERATION_STAGE_ORDER_INVALID"
                        )
                    ReplyDraftValidator().require_valid(
                        payload,
                        pack,
                        conceptualization,
                    )
                    theory_decision = TheoryUsePolicy().decide(
                        pack,
                        hard_constraint_evidence_ids=(
                            derive_hard_constraint_evidence_ids(pack)
                        ),
                    )
                    # The enforceable production boundary is currently the
                    # artifact's explicit ``suggestion`` claim type.  Do not
                    # infer advice from caller-authored prose; a broader gate
                    # requires a future typed professional-boundary proof.
                    if not theory_decision.specific_advice_allowed and any(
                        claim.claim_type == "suggestion"
                        for candidate in payload.candidates
                        for claim in candidate.claims
                    ):
                        raise GenerationStageConflict(
                            "GENERATION_STAGE_CONFLICT"
                        )
                elif isinstance(payload, EvidenceAudit):
                    conceptualization = store.get_latest(
                        context,
                        stage="conceptualization",
                    ).payload
                    replies = store.get_latest(
                        context,
                        stage="reply_drafts",
                    ).payload
                    if not (
                        isinstance(conceptualization, Conceptualization)
                        and isinstance(replies, ReplyDraftSet)
                    ):
                        raise GenerationStageIntegrityError
                    EvidenceAuditor().require_valid_artifact(
                        payload,
                        evidence_pack=pack,
                        evidence_context=pack_record.evidence_context,
                        conceptualization=conceptualization,
                        reply_drafts=replies,
                    )
                elif isinstance(payload, ConsistencyRiskReview):
                    audit = store.get_latest(
                        context,
                        stage="evidence_audit",
                    ).payload
                    if not isinstance(audit, EvidenceAudit) or audit.decision in {
                        "retrieve_more",
                        "rewrite",
                    }:
                        raise GenerationStageConflict("GENERATION_STAGE_CONFLICT")
                    expected_ids = tuple(
                        sorted(item.observation.observation_id for item in visible_risk)
                    )
                    if payload.risk_observation_ids != expected_ids:
                        raise GenerationStageConflict("GENERATION_STAGE_CONFLICT")
                    replies = store.get_latest(
                        context,
                        stage="reply_drafts",
                    ).payload
                    if not isinstance(replies, ReplyDraftSet):
                        raise GenerationStageIntegrityError
                    GenerationConsistencyValidator().require_valid(
                        payload,
                        reply_drafts=replies,
                        evidence_pack=pack,
                        evidence_context=pack_record.evidence_context,
                    )
                elif isinstance(payload, FinalTurnBundle):
                    conceptualization = store.get_latest(
                        context,
                        stage="conceptualization",
                    ).payload
                    theory = store.get_latest(
                        context,
                        stage="theory_comparison",
                    ).payload
                    replies = store.get_latest(context, stage="reply_drafts").payload
                    audit = store.get_latest(context, stage="evidence_audit").payload
                    consistency = store.get_latest(
                        context,
                        stage="consistency_risk_review",
                    ).payload
                    if not (
                        isinstance(conceptualization, Conceptualization)
                        and isinstance(theory, TheoryComparison)
                        and isinstance(replies, ReplyDraftSet)
                        and isinstance(audit, EvidenceAudit)
                        and isinstance(consistency, ConsistencyRiskReview)
                    ):
                        raise GenerationStageIntegrityError
                    FinalBundleValidator().require_valid(
                        payload,
                        conceptualization=conceptualization,
                        theory=theory,
                        replies=replies,
                        evidence_audit=audit,
                        consistency=consistency,
                        evidence_pack=pack,
                        visible_risk=visible_risk,
                    )
            try:
                record = store.submit(
                    context,
                    stage=payload.envelope.stage,
                    payload=payload,
                    idempotency_key=request.idempotency_key,
                    revision_reason=request.revision_reason,
                )
            except QueryPlanValidationError:
                raise WorkerOperationalError("QUERY_PLAN_CORRECTION_REQUIRED") from None
            except GenerationStageRevisionRequired:
                raise WorkerOperationalError(
                    "GENERATION_STAGE_REVISION_REASON_REQUIRED"
                ) from None
            except GenerationBindingMismatch:
                raise WorkerOperationalError("GENERATION_BINDING_MISMATCH") from None
            except GenerationStateError as error:
                code = str(error)
                if code not in {
                    "GENERATION_STAGE_ORDER_INVALID",
                    "GENERATION_PARENT_MISMATCH",
                    "QUALITY_RETRY_EXHAUSTED",
                }:
                    raise WorkerProtocolError from None
                raise WorkerOperationalError(code) from None  # type: ignore[arg-type]
            except GenerationStageConflict as error:
                code = str(error)
                mapped = {
                    "GENERATION_STAGE_IDEMPOTENCY_CONFLICT": code,
                    "GENERATION_STAGE_REVISION_CLOSED": code,
                }.get(code, "GENERATION_STAGE_CONFLICT")
                raise WorkerOperationalError(mapped) from None  # type: ignore[arg-type]
            if not isinstance(payload, QueryPlan):
                exact_plan = cast(QueryPlan, plan_payload)
                exact_pack = cast(EvidencePack, pack)
                latest_binding = generation_client_binding(
                    repository,
                    session_id=request.session_id,
                    turn_id=payload.envelope.turn_id,
                )
                if (
                    exact_plan.client_snapshot_ref
                    != latest_binding.client_snapshot_ref
                    or exact_plan.client_runtime_epoch
                    != latest_binding.client_runtime_epoch
                    or exact_plan.tombstone_epoch & 0xFFFFFFFF
                    != latest_binding.client_tombstone_count
                    or exact_pack.temporary_fact_refs
                    != latest_binding.temporary_fact_refs
                ):
                    raise WorkerOperationalError("GENERATION_BINDING_MISMATCH")
            turn = repository.get_turn(request.session_id, payload.envelope.turn_id)
            candidate_set_id = None
            candidate_ids: tuple[str, ...] = ()
            candidate_bindings: tuple[FinalCandidateBinding, ...] = ()
            if isinstance(payload, FinalTurnBundle):
                candidate_set = repository.get_candidate_set(
                    request.session_id,
                    payload.envelope.turn_id,
                )
                candidate_set_id = candidate_set.candidate_set_id
                candidate_ids = tuple(
                    item.candidate_id for item in candidate_set.candidates
                )
                candidate_bindings = tuple(
                    FinalCandidateBinding(
                        persistent_candidate_id=persisted.candidate_id,
                        ordinal=persisted.ordinal,
                        logical_candidate_id=logical.candidate_id,
                        label=persisted.label,
                        text_sha256=persisted.content.content_sha256,
                    )
                    for persisted, logical in zip(
                        candidate_set.candidates,
                        payload.client_reply_candidates,
                        strict=True,
                    )
                )
            return SubmitGenerationStageResponse(
                request_id=request.request_id,
                session_id=request.session_id,
                turn_id=payload.envelope.turn_id,
                run_id=payload.envelope.run_id,
                record=generation_wire_record(record),
                turn_state=turn.state,
                candidate_set_id=candidate_set_id,
                candidate_ids=candidate_ids,
                candidate_bindings=candidate_bindings,
                retrieval_status=(
                    "pending" if isinstance(payload, QueryPlan) else "not_applicable"
                ),
            )
        except (
            ConceptualizationPolicyError,
            TheoryPolicyError,
            ReplyPolicyError,
            GenerationConsistencyValidationError,
            FinalBundleValidationError,
            GenerationStageConflict,
        ):
            raise WorkerOperationalError("GENERATION_STAGE_CONFLICT") from None
        except ClientReplyLeakageError:
            raise WorkerOperationalError("CLIENT_REPLY_RISK_LEAKAGE") from None
        finally:
            connection.close()

    def get_generation_state(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not GetGenerationStateRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            context = GenerationTurnContext(
                session_id=request.session_id,
                turn_id=request.turn_id,
                run_id=request.run_id,
            )
            turn = repository.get_turn(request.session_id, request.turn_id)
            if turn.active_run_id not in {None, request.run_id}:
                raise WorkerOperationalError("GENERATION_BINDING_MISMATCH")
            records = GenerationStageStore(repository).list_records(context)
            risk = InternalRiskObservationRepository(
                connection,
                database_scope="client",
                clock=SystemClock(),
            ).list_visible(request.session_id)
            return GetGenerationStateResponse(
                request_id=request.request_id,
                session_id=request.session_id,
                turn_id=request.turn_id,
                run_id=request.run_id,
                turn_state=turn.state,
                records=tuple(generation_wire_record(item) for item in records),
                risk_observations=risk,
                client_binding=generation_client_binding(
                    repository,
                    session_id=request.session_id,
                    turn_id=request.turn_id,
                ),
            )
        finally:
            connection.close()

    def acknowledge_risk_observation(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not AcknowledgeRiskObservationRequest:
            raise WorkerProtocolError
        connection, _repository = open_session_repository()
        try:
            risks = InternalRiskObservationRepository(
                connection,
                database_scope="client",
                clock=SystemClock(),
            )
            try:
                current = risks.get(request.observation_id)
                if current.session_id != request.session_id:
                    raise WorkerOperationalError("RISK_OBSERVATION_UNAVAILABLE")
                if request.action == "acknowledge":
                    if current.status == "closed":
                        raise RiskLifecycleConflict(
                            "RISK_OBSERVATION_ALREADY_CLOSED"
                        )
                    updated = risks.acknowledge(
                        request.observation_id,
                        counselor_disposition=request.counselor_disposition,
                        rejection_reason=request.rejection_reason,
                    )
                elif current.status == "acknowledged":
                    assert request.close_decision is not None
                    assert request.close_reason is not None
                    updated = risks.close(
                        request.observation_id,
                        decision=request.close_decision,
                        reason=request.close_reason,
                    )
                elif (
                    current.status == "closed"
                    and current.close_decision == request.close_decision
                    and current.close_reason == request.close_reason
                ):
                    updated = current
                else:
                    raise RiskLifecycleConflict(
                        "RISK_CLOSE_REQUIRES_ACKNOWLEDGEMENT"
                    )
            except RiskLifecycleConflict:
                raise WorkerOperationalError("RISK_LIFECYCLE_CONFLICT") from None
            except RiskRepositoryError:
                raise WorkerOperationalError("RISK_OBSERVATION_UNAVAILABLE") from None
            return AcknowledgeRiskObservationResponse(
                request_id=request.request_id,
                session_id=request.session_id,
                action=request.action,
                observation=updated,
            )
        finally:
            connection.close()

    def persist_risk_observations(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not PersistRiskObservationsRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            turn = repository.get_turn(request.session_id, request.turn_id)
            if turn.state == "turn_closed":
                raise WorkerOperationalError("GENERATION_BINDING_MISMATCH")
            content_ref = VersionRef(
                object_id=turn.client_message.object_id,
                version=1,
                content_sha256=turn.client_message.content_sha256,
            )
            try:
                client_message = repository.read_content(
                    turn.client_message
                ).decode("utf-8")
            except (UnicodeError, ValueError):
                raise WorkerProtocolError from None
            for item in request.observations:
                for span in item.trigger_spans:
                    span_text = client_message[
                        span.start_offset : span.end_offset
                    ]
                    normalized_length, normalized_span_sha256 = (
                        normalized_sensitive_fingerprint(span_text)
                    )
                    if (
                        span.content_ref != content_ref
                        or span.end_offset > len(client_message)
                        or not hmac.compare_digest(
                            span.span_sha256,
                            hashlib.sha256(
                                span_text.encode("utf-8")
                            ).hexdigest(),
                        )
                        or normalized_length != span.normalized_length
                        or not hmac.compare_digest(
                            normalized_span_sha256,
                            span.normalized_span_sha256,
                        )
                    ):
                        raise WorkerProtocolError
            evaluation = TurnRiskEvaluationRepository(
                connection,
                database_scope="client",
                clock=SystemClock(),
            ).persist_completed(
                request.session_id,
                request.turn_id,
                client_message_sha256=turn.client_message.content_sha256,
                authority=request.risk_authority,
                observations=request.observations,
            )
            assert evaluation.observation_set_sha256 is not None
            assert evaluation.observation_count is not None
            return PersistRiskObservationsResponse(
                request_id=request.request_id,
                session_id=request.session_id,
                turn_id=request.turn_id,
                client_message_sha256=turn.client_message.content_sha256,
                risk_authority=evaluation.authority,
                observation_set_sha256=evaluation.observation_set_sha256,
                observation_count=evaluation.observation_count,
                observations=request.observations,
            )
        except RiskLifecycleConflict:
            raise WorkerOperationalError("RISK_LIFECYCLE_CONFLICT") from None
        except RiskRepositoryError:
            raise WorkerOperationalError("RISK_OBSERVATION_UNAVAILABLE") from None
        finally:
            connection.close()

    def prepare_turn_risk_evaluation(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not PrepareTurnRiskEvaluationRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            turn = repository.get_turn(request.session_id, request.turn_id)
            if turn.state == "turn_closed":
                raise WorkerOperationalError("GENERATION_BINDING_MISMATCH")
            content_ref = VersionRef(
                object_id=turn.client_message.object_id,
                version=1,
                content_sha256=turn.client_message.content_sha256,
            )
            try:
                client_message = repository.read_content(
                    turn.client_message
                ).decode("utf-8", errors="strict")
            except (UnicodeError, ValueError):
                raise WorkerProtocolError from None
            evaluation = TurnRiskEvaluationRepository(
                connection,
                database_scope="client",
                clock=SystemClock(),
            ).ensure_pending(
                request.session_id,
                request.turn_id,
                client_message_sha256=turn.client_message.content_sha256,
                authority=request.risk_authority,
            )
            return PrepareTurnRiskEvaluationResponse(
                request_id=request.request_id,
                session_id=request.session_id,
                turn_id=request.turn_id,
                client_message_ref=content_ref,
                client_message_sha256=turn.client_message.content_sha256,
                client_message=client_message,
                risk_authority=evaluation.authority,
                evaluation_revision=evaluation.evaluation_revision,
                evaluation_status=evaluation.status,
                observation_set_sha256=evaluation.observation_set_sha256,
                observation_count=evaluation.observation_count,
            )
        except RiskLifecycleConflict:
            raise WorkerOperationalError("RISK_LIFECYCLE_CONFLICT") from None
        except RiskRepositoryError:
            raise WorkerOperationalError("RISK_OBSERVATION_UNAVAILABLE") from None
        finally:
            connection.close()

    def preview_target_impact(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not PreviewTargetDependencyImpactRequest:
            raise WorkerProtocolError
        connection, repository = open_repository()
        try:
            _graph, _edges, events, _epoch = temporal_graph_view(
                connection,
                repository,
                as_of=request.as_of,
            )
            event = events.get(request.target_ref.object_id)
            if event is None or fact_reference(event) != request.target_ref:
                raise WorkerProtocolError
            visible_fact_ids = frozenset(events)
            visible_event_ids = frozenset(value.event_id for value in events.values())
            dependencies = tuple(
                edge
                for edge in load_dependencies(connection)
                if edge.prerequisite_fact_id in visible_fact_ids
                and edge.dependent_fact_id in visible_fact_ids
                and edge.source_event_id in visible_event_ids
            )
            proposal = DependencyImpactService(
                DependencyRepository(dependencies)
            ).preview(
                changed_fact_id=event.fact_id,
                old_value="current",
                new_value=f"action:{request.action}",
            )

            def item_view(item: object) -> DependencyImpactItemView:
                from consultation_kb.models.dependencies import ImpactItem

                validated = ImpactItem.model_validate(item)
                return DependencyImpactItemView(
                    fact_id=validated.fact_id,
                    path_edge_ids=validated.path_edge_ids,
                    path_confidence=validated.path_confidence,
                    classification=validated.classification,
                    recommended_operation=validated.recommended_mutation.operation,
                )

            direct = tuple(item_view(item) for item in proposal.direct_invalidations)
            reviews = tuple(item_view(item) for item in proposal.manual_reviews)
            proposal_sha256 = hashlib.sha256(
                (canonical_json(proposal.model_dump(mode="json")) + "\n").encode(
                    "utf-8"
                )
            ).hexdigest()
            return PreviewTargetDependencyImpactResponse(
                request_id=request.request_id,
                target_ref=request.target_ref,
                action=request.action,
                as_of=request.as_of,
                proposal_sha256=proposal_sha256,
                direct_invalidations=direct,
                manual_reviews=reviews,
            )
        finally:
            connection.close()

    def preview_impact(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not PreviewDependencyImpactRequest:
            raise WorkerProtocolError
        if client_id is None:
            raise WorkerProtocolError
        connection, _repository = open_repository()
        try:
            row = connection.execute(
                "SELECT object_id, version, content_sha256, base_commit_version, "
                "expected_runtime_epoch, operation_id, created_at "
                "FROM review_diff_objects WHERE draft_event_id = ? "
                "AND preview_sha256 = ? AND operation_id = ? "
                "AND object_id = ? AND version = ? AND content_sha256 = ? "
                "AND purpose = 'profile_update_review'",
                (
                    request.draft_event_id,
                    request.preview_sha256,
                    request.publication_operation_id,
                    request.diff_object_ref.object_id,
                    request.diff_object_ref.version,
                    request.diff_object_ref.content_sha256,
                ),
            ).fetchone()
            if row is None:
                raise WorkerProtocolError
            try:
                publication_timestamp = datetime.fromisoformat(
                    str(row[6]).replace("Z", "+00:00")
                )
            except ValueError:
                raise WorkerProtocolError from None
            mutation, session_id, _turn_id = _load_bound_draft(
                connection,
                request.draft_event_id,
                expected_scope_hash=scope_marker_sha256,
                expected_client_id=client_id,
            )
            plan = ClientPublicationPlanner(connection).prepare(
                mutation,
                draft_event_id=request.draft_event_id,
                operation_id=str(row[5]),
                expected_runtime_epoch=int(row[4]),
                publication_timestamp=publication_timestamp,
                draft_session_id=session_id,
            )
            if (
                plan.preview_sha256 != request.preview_sha256
                or plan.mutation_preview.base_commit_version != int(row[3])
                or plan.dependency_impact is None
                or plan.diff_object_ref
                != VersionRef(
                    object_id=str(row[0]),
                    version=int(row[1]),
                    content_sha256=str(row[2]),
                )
            ):
                raise WorkerProtocolError
            proposal = plan.dependency_impact
            proposal_hash = hashlib.sha256(
                (
                    canonical_json(proposal.model_dump(mode="json")) + "\n"
                ).encode("utf-8")
            ).hexdigest()
            return PreviewDependencyImpactResponse(
                request_id=request.request_id,
                proposal_sha256=proposal_hash,
                proposal_object_ref=plan.diff_object_ref,
                direct_invalidation_count=len(proposal.direct_invalidations),
                manual_review_count=len(proposal.manual_reviews),
            )
        finally:
            connection.close()

    def begin_session(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not BeginSessionRequest or client_id is None:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            assert_client_active_integrity(connection)
            try:
                existing = repository.get_session(request.session_id)
            except SessionNotFound:
                snapshot = ClientContextBuilder(
                    connection,
                    content_store=ContentStore(root / "cas"),
                    now=SystemClock().now,
                ).build(client_id)
                existing = repository.create_session(
                    session_id=request.session_id,
                    client_id=client_id,
                    client_scope_hash=scope_marker_sha256,
                    snapshot_version=snapshot.profile_version,
                    snapshot_canonical_sha256=snapshot.canonical_sha256,
                    snapshot_bytes=snapshot.canonical_bytes(),
                    capability_epoch=request.capability_epoch,
                )
            else:
                snapshot = load_session_snapshot(repository, request.session_id)
            if (
                existing.client_id != client_id
                or existing.client_scope_hash != scope_marker_sha256
                or existing.capability_epoch != request.capability_epoch
                or existing.status != "OPEN"
            ):
                raise WorkerProtocolError
            return BeginSessionResponse(
                request_id=request.request_id,
                session_id=request.session_id,
                capability_epoch=existing.capability_epoch,
                snapshot=snapshot,
            )
        finally:
            connection.close()

    def resume_session(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not ResumeSessionRequest or client_id is None:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            assert_client_active_integrity(connection)
            record = repository.get_session(request.session_id)
            if (
                record.client_id != client_id
                or record.client_scope_hash != scope_marker_sha256
                or record.status not in {"OPEN", "CLOSED"}
            ):
                raise WorkerProtocolError
            if record.status == "CLOSED":
                recoverable_case = connection.execute(
                    "SELECT 1 FROM outbox_events AS event "
                    "JOIN archive_bundles AS bundle "
                    "ON bundle.bundle_id = event.bundle_id "
                    "WHERE bundle.session_id = ? "
                    "AND event.event_type = 'shared_case_publish' "
                    "AND event.state IN ('PENDING', 'CLAIMED', 'FAILED') "
                    "LIMIT 1",
                    (request.session_id,),
                ).fetchone()
                if recoverable_case is None:
                    raise WorkerProtocolError
            # The capability was already validated by the parent broker.  It is
            # therefore the authority after a crash between global renewal and
            # this client-local CAS.  Reconcile any strictly lower client epoch;
            # equality is an idempotent retry and a higher epoch is anomalous.
            if record.capability_epoch < request.capability_epoch:
                record = repository.set_capability_epoch(
                    request.session_id,
                    expected_epoch=record.capability_epoch,
                    new_epoch=request.capability_epoch,
                )
            elif record.capability_epoch > request.capability_epoch:
                raise WorkerProtocolError
            recovered = SessionRecovery(repository).resume(request.session_id)
            return ResumeSessionResponse(
                request_id=request.request_id,
                session_id=request.session_id,
                capability_epoch=record.capability_epoch,
                snapshot=recovered.snapshot,
                recovery=session_recovery_payload(repository, recovered),
            )
        finally:
            connection.close()

    def append_client_turn(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not AppendClientTurnRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            try:
                turn = repository.get_turn(request.session_id, request.turn_id)
            except TurnNotFound:
                try:
                    turn = TurnService(repository).append(
                        request.session_id,
                        request.turn_id,
                        request.client_message,
                    )
                except PreviousTurnNotClosed:
                    raise WorkerOperationalError(
                        "PREVIOUS_TURN_NOT_CLOSED"
                    ) from None
            else:
                if (
                    turn.client_message.content_sha256
                    != hashlib.sha256(request.client_message.encode("utf-8")).hexdigest()
                    or turn.state == "turn_closed"
                ):
                    raise WorkerProtocolError
            TurnRiskEvaluationRepository(
                connection,
                database_scope="client",
                clock=SystemClock(),
            ).ensure_pending(
                turn.session_id,
                turn.turn_id,
                client_message_sha256=turn.client_message.content_sha256,
                authority=request.risk_authority,
            )
            return AppendClientTurnResponse(
                request_id=request.request_id,
                session_id=turn.session_id,
                turn_id=turn.turn_id,
                ordinal=turn.ordinal,
                state=turn.state,
                client_message_ref=VersionRef(
                    object_id=turn.client_message.object_id,
                    version=1,
                    content_sha256=turn.client_message.content_sha256,
                ),
                client_message_sha256=turn.client_message.content_sha256,
            )
        finally:
            connection.close()

    def append_temporary_fact(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not AppendTemporaryFactRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            event = TemporaryFactLedger(repository).propose(
                request.session_id,
                request.turn_id,
                event_kind=request.event_kind,
                cognitive_type=request.cognitive_type,
                value=request.value,
                target_fact_id=request.target_fact_id,
                target_fact_version=request.target_fact_version,
                idempotency_key=request.idempotency_key,
            )
            return AppendTemporaryFactResponse(
                request_id=request.request_id,
                session_id=event.session_id,
                turn_id=event.turn_id,
                event_id=event.event_id,
                event_kind=event.event_kind,
                cognitive_type=event.cognitive_type,
                content_sha256=event.content.content_sha256,
                target_fact_id=event.target_fact_id,
                target_fact_version=event.target_fact_version,
                recorded_at=event.recorded_at,
            )
        finally:
            connection.close()

    def begin_generation(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not BeginGenerationRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            turn = TurnService(repository).begin_generation(
                request.session_id,
                request.turn_id,
                run_id=request.run_id,
            )
            if turn.state != "generation_in_progress" or turn.active_run_id is None:
                raise WorkerProtocolError
            return BeginGenerationResponse(
                request_id=request.request_id,
                session_id=turn.session_id,
                turn_id=turn.turn_id,
                state="generation_in_progress",
                run_id=turn.active_run_id,
            )
        finally:
            connection.close()

    def store_candidate_set(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not StoreCandidateSetRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            candidate_set = CandidateSetService(repository).store_and_await(
                request.session_id,
                request.turn_id,
                tuple(CandidateDraft.model_validate(item) for item in request.candidates),
                run_id=request.run_id,
                idempotency_key=request.idempotency_key,
            )
            return StoreCandidateSetResponse(
                request_id=request.request_id,
                session_id=candidate_set.session_id,
                turn_id=candidate_set.turn_id,
                candidate_set_id=candidate_set.candidate_set_id,
                candidate_ids=tuple(
                    candidate.candidate_id for candidate in candidate_set.candidates
                ),
                state="awaiting_actual_reply",
            )
        finally:
            connection.close()

    def record_actual_reply(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not RecordActualReplyRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            service = ActualReplyService(repository)
            if request.mode == "adopted":
                if request.candidate_id is None or request.sent_at is None:
                    raise WorkerProtocolError
                actual = service.record_adopted(
                    request.session_id,
                    request.turn_id,
                    request.candidate_id,
                    sent_at=request.sent_at,
                    idempotency_key=request.idempotency_key,
                )
            elif request.mode == "edited":
                if (
                    request.candidate_id is None
                    or request.actual_text is None
                    or request.sent_at is None
                ):
                    raise WorkerProtocolError
                actual = service.record_edited(
                    request.session_id,
                    request.turn_id,
                    request.candidate_id,
                    request.actual_text,
                    sent_at=request.sent_at,
                    idempotency_key=request.idempotency_key,
                )
            else:
                if request.confirmed_at is None:
                    raise WorkerProtocolError
                actual = service.record_external_unknown(
                    request.session_id,
                    request.turn_id,
                    confirmed_at=request.confirmed_at,
                    idempotency_key=request.idempotency_key,
                )
            turn = repository.get_turn(request.session_id, request.turn_id)
            if turn.state != "turn_closed":
                raise WorkerProtocolError
            return RecordActualReplyResponse(
                request_id=request.request_id,
                session_id=actual.session_id,
                turn_id=actual.turn_id,
                actual_reply_id=actual.actual_reply_id,
                source_type=actual.source_type,
                state="turn_closed",
                evidence_gap=actual.evidence_gap,
                actual_reply=actual,
            )
        finally:
            connection.close()

    def read_session_state(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not ReadSessionStateRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            recovered = SessionRecovery(repository).inspect(request.session_id)
            session = recovered.session
            if client_id is None or session.client_id != client_id:
                raise WorkerProtocolError
            return ReadSessionStateResponse(
                request_id=request.request_id,
                session_id=session.session_id,
                status=session.status,
                capability_epoch=session.capability_epoch,
                snapshot_version=session.client_snapshot_version,
                snapshot_sha256=session.client_snapshot_canonical_sha256,
                turns=tuple(
                    SessionTurnState(
                        turn_id=turn.turn_id,
                        ordinal=turn.ordinal,
                        state=turn.state,
                        active_run_id=turn.active_run_id,
                    )
                    for turn in recovered.turns
                ),
                actual_reply_count=len(recovered.actual_conversation),
                temporary_fact_count=len(recovered.temporary_facts),
                recovery=session_recovery_payload(repository, recovered),
            )
        finally:
            connection.close()

    def require_archive_scope(repository: SessionRepository) -> tuple[str, str]:
        if client_id is None or bound_session_id is None:
            raise WorkerProtocolError
        session = repository.get_session(bound_session_id)
        if session.client_id != client_id:
            raise WorkerProtocolError
        return client_id, bound_session_id

    def build_private_archive(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not BuildPrivateArchiveRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            _bound_client, session_id = require_archive_scope(repository)
            analysis = PrivateArchiveAnalysis()
            if request.analysis_ref is not None:
                if not request.analysis_ref.object_id.startswith(
                    "private_archive_analysis_"
                ):
                    raise WorkerProtocolError
                analysis = cast(
                    PrivateArchiveAnalysis,
                    _read_archive_model(
                        root,
                        request.analysis_ref,
                        PrivateArchiveAnalysis,
                    ),
                )
            bundle = ArchiveBundleService(repository).propose(session_id)
            draft = PrivateArchiveDraftBuilder(repository).build(
                session_id,
                analysis=analysis,
            )
            preview = PrivateArchiveReviewService(repository).preview(draft)
            body = draft.canonical_text.encode("utf-8", errors="strict")
            private_state = bundle.state_for("private_archive").state
            if private_state not in {"DRAFT", "PREPARED", "ACTIVE", "REJECTED"}:
                raise WorkerProtocolError
            return BuildPrivateArchiveResponse(
                request_id=request.request_id,
                bundle_id=bundle.bundle_id,
                actual_transcript_ref=bundle.actual_transcript_ref,
                draft_ref=_archive_content_ref(
                    object_id=draft.draft_ref.object_id,
                    content_sha256=draft.draft_ref.content_sha256,
                    size_bytes=len(body),
                ),
                review_diff_ref=preview.diff_ref,
                base_version=preview.descriptor.base_version,
                incomplete_evidence=bundle.incomplete_evidence,
                private_archive_state=private_state,
            )
        finally:
            connection.close()

    def commit_private_archive(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not CommitPrivateArchiveRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            bound_client, session_id = require_archive_scope(repository)
            if not request.draft_ref.object_id.startswith("private_archive_draft_"):
                raise WorkerProtocolError
            draft = _read_private_archive_draft(root, request.draft_ref)
            if (
                draft.draft_ref != request.draft_ref.version_ref
                or draft.actual_transcript.session_id != session_id
                or request.base_version != 0
            ):
                raise WorkerProtocolError
            bundle = ArchiveBundleService(repository).get(request.bundle_id)
            if (
                bundle.session_id != session_id
                or bundle.actual_transcript_ref
                != draft.actual_transcript.actual_transcript_ref
            ):
                raise WorkerProtocolError
            review = PrivateArchiveReviewService(repository)
            preview = review.preview(draft)
            ticket = _resolve_archive_ticket(
                archive_approval_resolver,
                operation_id=request.approval_operation_id,
                receipt_id=request.approval_request_id,
                purpose="private_archive_publish",
                target_id=draft.draft_ref.object_id,
                client_id=bound_client,
                session_id=session_id,
                base_version=preview.descriptor.base_version,
                draft_sha256=draft.draft_ref.content_sha256,
                scope_marker_sha256=scope_marker_sha256,
            )
            if execution_attestor_secret is None or execution_attestor_id is None:
                raise WorkerProtocolError
            publication_refs: list[tuple[VersionRef, VersionRef]] = []

            def apply_private_archive(_connection: sqlite3.Connection) -> None:
                decision = review.approve_modified(
                    draft,
                    approval_ticket=ticket,
                )
                publication = review.commit(
                    decision,
                    approval_ticket=ticket,
                )
                publication_refs.append(
                    (publication.revision_ref, publication.manifest_ref)
                )

            proof = ApprovalExecutionGuard(
                connection,
                approval_service=cast(
                    ApprovalService,
                    _ExactTicketVerifier(ticket),
                ),
                execution_proof_signer=LocalHmacTargetExecutionAttestor(
                    secret=execution_attestor_secret,
                    attestor_id=execution_attestor_id,
                ),
                clock=SystemClock(),
                commit_version_allocator=lambda current: (
                    _next_approval_execution_version(
                        current,
                        request.approval_operation_id,
                    )
                ),
            ).apply_in_transaction(ticket, preview.descriptor, apply_private_archive)
            if not publication_refs:
                recovered = review.recover_committed(
                    draft,
                    approval_ticket=ticket,
                )
                publication_refs.append(
                    (recovered.revision_ref, recovered.manifest_ref)
                )
            if len(publication_refs) != 1:
                raise WorkerProtocolError
            revision_ref, manifest_ref = publication_refs[0]
            atomic_commit_version = proof.execution.applied_commit_version
            if atomic_commit_version is None:
                raise WorkerProtocolError
            return CommitPrivateArchiveResponse(
                request_id=request.request_id,
                bundle_id=request.bundle_id,
                approval_operation_id=request.approval_operation_id,
                applied_commit_version=atomic_commit_version,
                revision_ref=revision_ref,
                manifest_ref=manifest_ref,
            )
        finally:
            connection.close()

    def build_profile_diff(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not BuildProfileDiffRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            bound_client, session_id = require_archive_scope(repository)
            prepared: PreparedProfileDiffApproval | None = None
            approval_diff_ref: VersionRef | None = None
            if request.action == "BUILD":
                if request.build_input_ref is None or not (
                    request.build_input_ref.object_id.startswith(
                        "profile_diff_build_input_"
                    )
                ):
                    raise WorkerProtocolError
                build_input = cast(
                    ProfileDiffBuildInput,
                    _read_archive_model(
                        root,
                        request.build_input_ref,
                        ProfileDiffBuildInput,
                    ),
                )
                if (
                    build_input.client_id != bound_client
                    or build_input.session_actual.session_id != session_id
                ):
                    raise WorkerProtocolError
                bundle = ArchiveBundleService(repository).get(
                    build_input.archive_bundle_id
                )
                if (
                    bundle.session_id != session_id
                    or bundle.actual_transcript_ref
                    != build_input.session_actual.actual_transcript_ref
                    or tuple(repository.list_temporary_facts(session_id))
                    != build_input.temporary_ledger
                ):
                    raise WorkerProtocolError
                current_snapshot = BitemporalFactQuery(
                    FactEventRepository(connection)
                ).snapshot(
                    FactQuery(
                        effective_at=build_input.base_profile.effective_at,
                        known_at=build_input.base_profile.known_at,
                        fixed_epoch=build_input.base_profile.fixed_epoch,
                    )
                )
                current_profile = ProfileMaterializer().build(
                    current_snapshot,
                    merge_member_event_ids=FactEventRepository(
                        connection
                    ).list_merge_member_ids(),
                )
                if current_profile != build_input.base_profile:
                    raise WorkerProtocolError
                draft = ProfileDiffBuilder().build(build_input)
                body = (
                    json.dumps(
                        draft.model_dump(
                            mode="json",
                            exclude={"canonical_sha256"},
                        ),
                        ensure_ascii=False,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
                existing = connection.execute(
                    "SELECT draft_object_id, draft_sha256, draft_media_type, "
                    "draft_size_bytes, base_profile_version, base_profile_sha256 "
                    "FROM profile_diff_drafts WHERE draft_id = ?",
                    (draft.diff_id,),
                ).fetchone()
                if hashlib.sha256(body).hexdigest() != draft.canonical_sha256:
                    raise WorkerProtocolError
                if existing is None:
                    stored = repository.store_json(
                        body,
                        kind="profile_diff_draft",
                    )
                    if stored.content_sha256 != draft.canonical_sha256:
                        raise WorkerProtocolError
                    connection.execute(
                        "INSERT INTO profile_diff_drafts(draft_id, bundle_id, "
                        "revision, base_profile_version, base_profile_sha256, "
                        "draft_object_id, draft_sha256, draft_media_type, "
                        "draft_size_bytes, created_at) VALUES "
                        "(?, ?, 1, ?, ?, ?, ?, 'application/json', ?, ?)",
                        (
                            draft.diff_id,
                            bundle.bundle_id,
                            draft.base_client_commit_version,
                            draft.base_profile_sha256,
                            stored.object_id,
                            stored.content_sha256,
                            stored.size_bytes,
                            _utc_text(repository.clock.now()),
                        ),
                    )
                else:
                    expected_tail = (
                        draft.canonical_sha256,
                        "application/json",
                        len(body),
                        draft.base_client_commit_version,
                        draft.base_profile_sha256,
                    )
                    if (
                        type(existing[0]) is not str
                        or tuple(existing[1:]) != expected_tail
                    ):
                        raise WorkerProtocolError
                    stored = StoredContentRef(
                        object_id=existing[0],
                        content_sha256=existing[1],
                        media_type=existing[2],
                        size_bytes=existing[3],
                    )
                    if repository.read_content(stored) != body:
                        raise WorkerProtocolError
            else:
                if request.draft_ref is None or not (
                    request.draft_ref.object_id.startswith(
                        "profile_diff_draft_"
                    )
                ):
                    raise WorkerProtocolError
                draft = _read_profile_diff_draft(root, request.draft_ref)
                row = connection.execute(
                    "SELECT bundle_id, draft_object_id, draft_sha256, "
                    "draft_media_type, draft_size_bytes, base_profile_version, "
                    "base_profile_sha256 FROM profile_diff_drafts "
                    "WHERE draft_id = ?",
                    (draft.diff_id,),
                ).fetchone()
                if row is None or tuple(row[1:]) != (
                    request.draft_ref.object_id,
                    request.draft_ref.content_sha256,
                    request.draft_ref.media_type,
                    request.draft_ref.size_bytes,
                    draft.base_client_commit_version,
                    draft.base_profile_sha256,
                ):
                    raise WorkerProtocolError
                bundle = ArchiveBundleService(repository).get(str(row[0]))
                stored = StoredContentRef(
                    object_id=request.draft_ref.object_id,
                    content_sha256=request.draft_ref.content_sha256,
                    media_type=request.draft_ref.media_type,
                    size_bytes=request.draft_ref.size_bytes,
                )

            if (
                bundle.session_id != session_id
                or draft.client_id != bound_client
                or draft.session_id != session_id
                or bundle.actual_transcript_ref.content_sha256
                != draft.base_session_sha256
            ):
                raise WorkerProtocolError
            current_commit_version = FactEventRepository(
                connection
            ).current_commit_version()
            if current_commit_version != draft.base_client_commit_version:
                raise WorkerProtocolError
            preview = ProfileDiffReviewService().preview(
                draft,
                current_profile_sha256=draft.base_profile_sha256,
                current_session_sha256=(
                    bundle.actual_transcript_ref.content_sha256
                ),
                current_client_commit_version=current_commit_version,
            )
            if request.action == "PREPARE_APPROVAL":
                prepared = ProfileDiffReviewService().approve_partial(
                    preview,
                    approved_operation_ids=request.selected_operation_ids,
                    dismissed_indirect_review_fact_ids=(
                        request.dismissed_indirect_review_fact_ids
                    ),
                    current_profile_sha256=draft.base_profile_sha256,
                    current_session_sha256=(
                        bundle.actual_transcript_ref.content_sha256
                    ),
                    current_client_commit_version=current_commit_version,
                )
                if (
                    prepared.pending_indirect_review_fact_ids
                    or prepared.unapproved_direct_impact_fact_ids
                ):
                    raise WorkerProtocolError
                approval_body = canonical_json_bytes(
                    {
                        "diff_id": prepared.diff_id,
                        "dismissed_indirect_review_fact_ids": list(
                            prepared.dismissed_indirect_review_fact_ids
                        ),
                        "schema_version": "profile_diff_approval_review.v1",
                        "selected_operation_ids": [
                            item.operation_id
                            for item in prepared.selected_operations
                        ],
                        "selection_sha256": prepared.selection_sha256,
                        "source_diff_sha256": prepared.source_diff_sha256,
                    }
                )
                repository.store_json(
                    approval_body,
                    kind="profile_diff_approval_review",
                )
                approval_diff_ref = VersionRef(
                    object_id=_derived_object_id(
                        draft.diff_id,
                        "profile_diff_approval_review",
                    ),
                    version=1,
                    content_sha256=hashlib.sha256(approval_body).hexdigest(),
                )
            return BuildProfileDiffResponse(
                request_id=request.request_id,
                bundle_id=bundle.bundle_id,
                draft_ref=_archive_content_ref(
                    object_id=stored.object_id,
                    content_sha256=stored.content_sha256,
                    size_bytes=stored.size_bytes,
                ),
                diff_id=draft.diff_id,
                diff_sha256=draft.canonical_sha256,
                base_profile_sha256=draft.base_profile_sha256,
                base_session_sha256=draft.base_session_sha256,
                base_client_commit_version=draft.base_client_commit_version,
                operation_count=len(draft.operations),
                operation_ids=tuple(
                    item.operation_id for item in draft.operations
                ),
                indirect_review_fact_ids=tuple(
                    item.fact_id for item in draft.indirect_reviews
                ),
                direct_impact_fact_ids=tuple(
                    item.fact_id for item in draft.direct_impacts
                ),
                pending_indirect_review_count=(
                    len(draft.indirect_reviews)
                    if prepared is None
                    else len(prepared.pending_indirect_review_fact_ids)
                ),
                unapproved_direct_impact_count=(
                    len(draft.direct_impacts)
                    if prepared is None
                    else len(prepared.unapproved_direct_impact_fact_ids)
                ),
                approval_draft_sha256=(
                    None if prepared is None else prepared.selection_sha256
                ),
                approval_diff_ref=approval_diff_ref,
            )
        finally:
            connection.close()

    def commit_profile_update(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not CommitProfileUpdateRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            bound_client, session_id = require_archive_scope(repository)
            if not request.draft_ref.object_id.startswith(
                "profile_diff_draft_"
            ):
                raise WorkerProtocolError
            draft = _read_profile_diff_draft(root, request.draft_ref)
            row = connection.execute(
                "SELECT bundle_id, draft_object_id, draft_sha256, "
                "draft_media_type, draft_size_bytes, base_profile_version, "
                "base_profile_sha256 FROM profile_diff_drafts "
                "WHERE draft_id = ?",
                (draft.diff_id,),
            ).fetchone()
            if row is None or tuple(row) != (
                request.bundle_id,
                request.draft_ref.object_id,
                request.draft_ref.content_sha256,
                request.draft_ref.media_type,
                request.draft_ref.size_bytes,
                draft.base_client_commit_version,
                draft.base_profile_sha256,
            ):
                raise WorkerProtocolError
            bundle = ArchiveBundleService(repository).get(request.bundle_id)
            current_commit_version = FactEventRepository(
                connection
            ).current_commit_version()
            preview = ProfileDiffReviewService().preview(
                draft,
                current_profile_sha256=draft.base_profile_sha256,
                current_session_sha256=(
                    bundle.actual_transcript_ref.content_sha256
                ),
                current_client_commit_version=current_commit_version,
            )
            approval = ProfileDiffReviewService().approve_partial(
                preview,
                approved_operation_ids=request.selected_operation_ids,
                dismissed_indirect_review_fact_ids=(
                    request.dismissed_indirect_review_fact_ids
                ),
                current_profile_sha256=draft.base_profile_sha256,
                current_session_sha256=(
                    bundle.actual_transcript_ref.content_sha256
                ),
                current_client_commit_version=current_commit_version,
            )
            if (
                approval.client_id != bound_client
                or approval.session_id != session_id
                or bundle.session_id != session_id
                or approval.pending_indirect_review_fact_ids
                or approval.unapproved_direct_impact_fact_ids
            ):
                raise WorkerProtocolError
            plan = AtomicProfilePublicationPlanner(connection).prepare(
                approval,
                bundle_id=request.bundle_id,
                operation_id=request.approval_operation_id,
                expected_runtime_epoch=request.expected_runtime_epoch,
                publication_timestamp=request.publication_timestamp,
            )
            ticket = _resolve_archive_ticket(
                archive_approval_resolver,
                operation_id=request.approval_operation_id,
                receipt_id=request.approval_request_id,
                purpose="profile_update",
                target_id=approval.diff_id,
                client_id=bound_client,
                session_id=session_id,
                base_version=approval.base_client_commit_version,
                draft_sha256=approval.selection_sha256,
                scope_marker_sha256=scope_marker_sha256,
            )
            if execution_attestor_secret is None or execution_attestor_id is None:
                raise WorkerProtocolError
            result = AtomicProfilePublicationExecutor(
                connection,
                scope_root=root,
                execution_proof_signer=LocalHmacTargetExecutionAttestor(
                    secret=execution_attestor_secret,
                    attestor_id=execution_attestor_id,
                ),
            ).execute(plan, ticket)
            return CommitProfileUpdateResponse(
                request_id=request.request_id,
                bundle_id=request.bundle_id,
                approval_operation_id=request.approval_operation_id,
                new_commit_version=result.new_commit_version,
                runtime_epoch=result.runtime_epoch,
                event_count=result.event_count,
                manifest_ids=result.manifest_ids,
            )
        finally:
            connection.close()

    def stage_shared_case_outbox(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not StageSharedCaseOutboxRequest:
            raise WorkerProtocolError
        connection, repository = open_session_repository()
        try:
            bound_client, session_id = require_archive_scope(repository)
            bundle = ArchiveBundleService(repository).get(request.bundle_id)
            if bundle.session_id != session_id:
                raise WorkerProtocolError
            if execution_attestor_secret is None:
                raise WorkerProtocolError
            deidentifier = Deidentifier(
                span_hash_key=execution_attestor_secret,
                rule_version="case_deidentification_v1",
            )

            candidate_row = connection.execute(
                "SELECT candidate_id, version, candidate_object_id, "
                "candidate_sha256, candidate_media_type, candidate_size_bytes "
                "FROM shared_case_candidates WHERE bundle_id = ?",
                (request.bundle_id,),
            ).fetchone()
            if candidate_row is None:
                transcript = ActualTranscriptReader(repository).snapshot(
                    session_id
                )
                if (
                    transcript.actual_transcript_ref
                    != bundle.actual_transcript_ref
                ):
                    raise WorkerProtocolError
                contributor_hash = CaseContributorHasher(
                    hash_key=execution_attestor_secret
                ).hash_client_id(bound_client)
                source_items: list[PrivateCaseSourceItem] = []
                for turn in transcript.turns:
                    source_items.append(
                        PrivateCaseSourceItem(
                            source_ref=turn.client_message_ref,
                            source_kind="client_message",
                            content=turn.client_message_text,
                            actual_recorded=True,
                            selected_for_delivery=False,
                        )
                    )
                    if turn.reply_text is not None:
                        if turn.actual_reply_ref is None:
                            raise WorkerProtocolError
                        source_items.append(
                            PrivateCaseSourceItem(
                                source_ref=turn.actual_reply_ref,
                                source_kind="actual_reply",
                                content=turn.reply_text,
                                actual_recorded=True,
                                selected_for_delivery=True,
                            )
                        )
                record_id = _derived_object_id(
                    transcript.actual_transcript_ref.object_id,
                    "private_actual_record",
                )
                source_record = PrivateActualCaseRecord(
                    record_ref=VersionRef(
                        object_id=record_id,
                        version=1,
                        content_sha256=canonical_sha256(
                            private_actual_case_record_payload(
                                record_id=record_id,
                                version=1,
                                actual_transcript_ref=(
                                    transcript.actual_transcript_ref
                                ),
                                items=tuple(source_items),
                                incomplete_evidence=(
                                    transcript.incomplete_evidence
                                ),
                            )
                        ),
                    ),
                    actual_transcript_ref=transcript.actual_transcript_ref,
                    items=tuple(source_items),
                    incomplete_evidence=transcript.incomplete_evidence,
                )
                provenance_payload = {
                    "actual_transcript_sha256": (
                        bundle.actual_transcript_ref.content_sha256
                    ),
                    "contributor_client_hash": contributor_hash,
                    "schema_version": "case_candidate_provenance.v1",
                }
                provenance_ref = VersionRef(
                    object_id=_derived_object_id(
                        transcript.actual_transcript_ref.object_id,
                        "case_provenance",
                    ),
                    version=1,
                    content_sha256=canonical_sha256(provenance_payload),
                )
                derivation_payload = {
                    "no_verbatim_source": True,
                    "rule_version": deidentifier.rule_version,
                    "schema_version": "case_derivation_rule.v1",
                    "section_kinds": [
                        "factual_context",
                        "actual_response",
                    ],
                }
                derivation_ref = VersionRef(
                    object_id=_derived_object_id(
                        transcript.actual_transcript_ref.object_id,
                        "case_derivation_rule",
                    ),
                    version=1,
                    content_sha256=canonical_sha256(derivation_payload),
                )
                refs_by_section = {
                    "factual_context": tuple(
                        item.source_ref
                        for item in source_items
                        if item.source_kind == "client_message"
                    ),
                    "actual_response": tuple(
                        item.source_ref
                        for item in source_items
                        if item.source_kind == "actual_reply"
                    ),
                }
                proposals = tuple(
                    SharedCaseSectionProposal(
                        section_kind=draft.section_kind,
                        source_item_refs=refs_by_section[draft.section_kind],
                        abstracted_text=draft.abstracted_text,
                    )
                    for draft in request.section_drafts
                    if refs_by_section[draft.section_kind]
                )
                if len(proposals) != len(request.section_drafts):
                    raise WorkerProtocolError
                built_candidate = SharedCaseCandidateBuilder(
                    id_factory=repository.id_factory,
                    deidentifier=deidentifier,
                ).build(
                    source_record,
                    proposals,
                    contributor_client_hash=contributor_hash,
                    provenance_ref=provenance_ref,
                    derivation_rule_ref=derivation_ref,
                    requested_allowed_uses=frozenset({"answer_support"}),
                    created_at=bundle.created_at,
                    actual_transcript=transcript,
                )
                candidate = built_candidate.candidate
                scans = list(built_candidate.scans)
                transforms = list(built_candidate.transforms)
                candidate_id = candidate.candidate_ref.object_id
                candidate_sha256 = candidate.candidate_sha256
                source_record_sha256 = candidate.source_record_sha256
                candidate_body = shared_candidate_bytes(candidate)
                stored_candidate = repository.store_json(
                    candidate_body,
                    kind="shared_case_candidate",
                )
                if stored_candidate.content_sha256 != candidate_sha256:
                    raise WorkerProtocolError
                with transaction(connection):
                    connection.execute(
                        "INSERT INTO shared_case_candidates(candidate_id, "
                        "bundle_id, version, candidate_object_id, "
                        "candidate_sha256, candidate_media_type, "
                        "candidate_size_bytes, source_record_sha256, "
                        "incomplete_evidence, created_at) VALUES "
                        "(?, ?, 1, ?, ?, 'application/json', ?, ?, ?, ?)",
                        (
                            candidate_id,
                            request.bundle_id,
                            candidate_id,
                            candidate_sha256,
                            len(candidate_body),
                            source_record_sha256,
                            int(bundle.incomplete_evidence),
                            _utc_text(bundle.created_at),
                        ),
                    )
            else:
                candidate_ref = _archive_content_ref(
                    object_id=str(candidate_row[0]),
                    version=int(candidate_row[1]),
                    content_sha256=str(candidate_row[3]),
                    size_bytes=int(candidate_row[5]),
                )
                if (
                    candidate_row[2] != candidate_ref.object_id
                    or candidate_row[4] != candidate_ref.media_type
                ):
                    raise WorkerProtocolError
                candidate = _read_shared_case_candidate(root, candidate_ref)
                if request.action == "PREPARE":
                    if len(request.section_drafts) != len(candidate.sections):
                        raise WorkerProtocolError
                    scans = [
                        deidentifier.scan(item.abstracted_text)
                        for item in request.section_drafts
                    ]
                    transforms = [
                        deidentifier.transform(item.abstracted_text, scan)
                        for item, scan in zip(
                            request.section_drafts,
                            scans,
                            strict=True,
                        )
                    ]
                    if any(
                        draft.section_kind != section.section_kind
                        or transform.output_text != section.text
                        for draft, transform, section in zip(
                            request.section_drafts,
                            transforms,
                            candidate.sections,
                            strict=True,
                        )
                    ):
                        raise WorkerProtocolError
                else:
                    if request.scan_ref is None:
                        raise WorkerProtocolError
                    stored_scan_payload = json.loads(
                        _read_archive_bytes(root, request.scan_ref).decode("utf-8")
                    )
                    if (
                        type(stored_scan_payload) is not dict
                        or stored_scan_payload.get("candidate_sha256")
                        != candidate.candidate_sha256
                    ):
                        raise WorkerProtocolError
                    scans = [
                        DeidentificationScan.model_validate_json(
                            json.dumps(
                                item,
                                ensure_ascii=True,
                                separators=(",", ":"),
                            )
                        )
                        for item in stored_scan_payload.get("scans", ())
                    ]
                    transforms = [
                        DeidentificationTransform.model_validate_json(
                            json.dumps(
                                item,
                                ensure_ascii=True,
                                separators=(",", ":"),
                            )
                        )
                        for item in stored_scan_payload.get("transforms", ())
                    ]

            scan_body = canonical_json_bytes(
                {
                    "candidate_sha256": candidate.candidate_sha256,
                    "scans": [item.model_dump(mode="json") for item in scans],
                    "schema_version": "case_deidentification_scan_bundle.v1",
                    "transforms": [
                        item.model_dump(mode="json") for item in transforms
                    ],
                }
            )
            stored_scan = repository.store_json(
                scan_body,
                kind="case_deidentification_scan",
            )
            scan_ref = _archive_content_ref(
                object_id=_derived_object_id(
                    candidate.candidate_ref.object_id,
                    "case_deidentification_scan",
                ),
                content_sha256=stored_scan.content_sha256,
                size_bytes=stored_scan.size_bytes,
            )
            policy_body = canonical_json_bytes(
                {
                    "purpose": "answer_support",
                    "required_review_categories": list(
                        _CASE_REVIEW_CATEGORIES
                    ),
                    "schema_version": "case_release_policy.v1",
                }
            )
            stored_policy = repository.store_json(
                policy_body,
                kind="case_release_policy",
            )
            policy_ref = VersionRef(
                object_id=_derived_object_id(
                    candidate.candidate_ref.object_id,
                    "case_release_policy",
                ),
                version=1,
                content_sha256=stored_policy.content_sha256,
            )
            review_policy = _CaseReviewPolicyDraft(
                candidate_ref=candidate.candidate_ref,
                scan_ref=scan_ref.version_ref,
                required_review_categories=_CASE_REVIEW_CATEGORIES,
                human_review=SharedCaseHumanReviewDraft(
                    decision=request.decision,
                    checked_categories=request.checked_categories,
                    residual_risk=request.residual_risk,
                    rare_combination_disposition=(
                        request.rare_combination_disposition
                    ),
                    reuse_authorized=request.reuse_authorized,
                    allowed_uses=request.allowed_uses,
                    expires_at=request.authorization_expires_at,
                ),
                release_policy_ref=policy_ref,
                created_at=candidate.created_at,
            )
            review_policy_body = canonical_json_bytes(
                review_policy.model_dump(mode="json")
            )
            stored_review_policy = repository.store_json(
                review_policy_body,
                kind="case_review_policy_draft",
            )
            review_policy_ref = _archive_content_ref(
                object_id=_derived_object_id(
                    candidate.candidate_ref.object_id,
                    "case_review_policy_draft",
                ),
                content_sha256=stored_review_policy.content_sha256,
                size_bytes=stored_review_policy.size_bytes,
            )
            exact_candidate_ref = _archive_content_ref(
                object_id=candidate.candidate_ref.object_id,
                version=candidate.candidate_ref.version,
                content_sha256=candidate.candidate_sha256,
                size_bytes=len(shared_candidate_bytes(candidate)),
            )
            if request.action == "PREPARE":
                return StageSharedCaseOutboxResponse(
                    request_id=request.request_id,
                    bundle_id=request.bundle_id,
                    action="PREPARE",
                    candidate_ref=exact_candidate_ref,
                    scan_ref=scan_ref,
                    review_policy_draft_ref=review_policy_ref,
                    approval_draft_sha256=(
                        review_policy_ref.content_sha256
                    ),
                    approval_diff_ref=review_policy_ref.version_ref,
                    candidate_sections=candidate.sections,
                    deidentification_scans=tuple(scans),
                    state="PREPARED",
                )

            if (
                request.candidate_ref is None
                or request.scan_ref is None
                or request.review_policy_draft_ref is None
                or request.approval_operation_id is None
                or request.approval_request_id is None
                or request.candidate_ref != exact_candidate_ref
                or request.scan_ref != scan_ref
                or request.review_policy_draft_ref != review_policy_ref
                or _read_archive_bytes(root, request.scan_ref) != scan_body
            ):
                raise WorkerProtocolError
            parsed_review_policy = cast(
                _CaseReviewPolicyDraft,
                _read_archive_model(
                    root,
                    request.review_policy_draft_ref,
                    _CaseReviewPolicyDraft,
                ),
            )
            if parsed_review_policy != review_policy:
                raise WorkerProtocolError
            ticket = _resolve_archive_ticket(
                archive_approval_resolver,
                operation_id=request.approval_operation_id,
                receipt_id=request.approval_request_id,
                purpose="case_publish",
                target_id=candidate.candidate_ref.object_id,
                client_id=bound_client,
                session_id=session_id,
                base_version=candidate.candidate_ref.version,
                draft_sha256=review_policy_ref.content_sha256,
                scope_marker_sha256=scope_marker_sha256,
            )
            approved_at = ticket.receipt.approved_at
            contributor_hash = next(
                iter(candidate.provenance.contributor_client_hashes)
            )
            if not hmac.compare_digest(
                contributor_hash,
                CaseContributorHasher(
                    hash_key=execution_attestor_secret
                ).hash_client_id(bound_client),
            ):
                raise WorkerProtocolError
            authorization_id = _derived_object_id(
                candidate.candidate_ref.object_id,
                "case_authorization",
            )
            authorization_payload = case_reuse_authorization_payload(
                authorization_id=authorization_id,
                version=1,
                contributor_client_hash=contributor_hash,
                reuse_authorized=review_policy.human_review.reuse_authorized,
                allowed_uses=frozenset(review_policy.human_review.allowed_uses),
                valid_from=approved_at,
                expires_at=review_policy.human_review.expires_at,
                revoked_at=None,
                terms_sha256=review_policy_ref.content_sha256,
            )
            authorization = CaseReuseAuthorization(
                authorization_ref=VersionRef(
                    object_id=authorization_id,
                    version=1,
                    content_sha256=canonical_sha256(
                        authorization_payload
                    ),
                ),
                contributor_client_hash=contributor_hash,
                reuse_authorized=review_policy.human_review.reuse_authorized,
                allowed_uses=frozenset(review_policy.human_review.allowed_uses),
                valid_from=approved_at,
                expires_at=review_policy.human_review.expires_at,
                terms_sha256=review_policy_ref.content_sha256,
            )
            review_id = _derived_object_id(
                candidate.candidate_ref.object_id,
                "case_review",
            )
            reviewer_attestation_sha256 = hashlib.sha256(
                canonical_json_bytes(
                    {
                        "approval_request_id": ticket.request_id,
                        "candidate_sha256": candidate.candidate_sha256,
                        "provider_id": ticket.receipt.provider_id,
                        "schema_version": "case_human_review_attestation.v1",
                    }
                )
            ).hexdigest()
            review_payload = deidentification_human_review_payload(
                review_id=review_id,
                version=1,
                candidate_sha256=candidate.candidate_sha256,
                decision=review_policy.human_review.decision,
                checked_categories=frozenset(
                    review_policy.human_review.checked_categories
                ),
                residual_risk=review_policy.human_review.residual_risk,
                rare_combination_disposition=(
                    review_policy.human_review.rare_combination_disposition
                ),
                allowed_uses=frozenset(review_policy.human_review.allowed_uses),
                reviewed_at=approved_at,
                reviewer_attestation_sha256=(
                    reviewer_attestation_sha256
                ),
            )
            review = DeidentificationHumanReview(
                review_ref=VersionRef(
                    object_id=review_id,
                    version=1,
                    content_sha256=canonical_sha256(review_payload),
                ),
                candidate_sha256=candidate.candidate_sha256,
                decision=review_policy.human_review.decision,
                checked_categories=frozenset(
                    review_policy.human_review.checked_categories
                ),
                residual_risk=review_policy.human_review.residual_risk,
                rare_combination_disposition=(
                    review_policy.human_review.rare_combination_disposition
                ),
                allowed_uses=frozenset(review_policy.human_review.allowed_uses),
                reviewed_at=approved_at,
                reviewer_attestation_sha256=(
                    reviewer_attestation_sha256
                ),
            )
            release = CaseReleasePolicy(
                policy_ref=review_policy.release_policy_ref,
                required_review_categories=frozenset(
                    review_policy.required_review_categories
                ),
            ).evaluate(
                candidate,
                authorization,
                review,
                purpose="answer_support",
                at=approved_at,
            )
            if release.outcome != "eligible":
                if execution_attestor_id is None:
                    raise WorkerProtocolError
                reviewer_id_hash = hashlib.sha256(
                    ("case-publish\0" + ticket.receipt.provider_id).encode(
                        "utf-8"
                    )
                ).hexdigest()
                stored_decision = (
                    "REJECTED"
                    if review.decision in {"rejected", "quarantine"}
                    else "EDITED"
                )
                purpose_state = (
                    "REJECTED"
                    if review.decision == "rejected"
                    else "PRIVATE_ONLY"
                )

                def apply_nonpublish(current: sqlite3.Connection) -> None:
                    existing_review = current.execute(
                        "SELECT session_id, object_id, decision, "
                        "reviewer_id_hash, decided_at FROM review_decisions "
                        "WHERE decision_id = ?",
                        (ticket.request_id,),
                    ).fetchone()
                    expected_review = (
                        session_id,
                        candidate.candidate_ref.object_id,
                        stored_decision,
                        reviewer_id_hash,
                        _utc_text(ticket.receipt.approved_at),
                    )
                    if existing_review is None:
                        current.execute(
                            "INSERT INTO review_decisions(decision_id, "
                            "session_id, object_id, decision, reviewer_id_hash, "
                            "decided_at) VALUES (?, ?, ?, ?, ?, ?)",
                            (ticket.request_id, *expected_review),
                        )
                    elif tuple(existing_review) != expected_review:
                        raise WorkerProtocolError
                    current.execute(
                        "UPDATE archive_purpose_states SET state = ?, "
                        "manifest_id = NULL, review_decision_id = ?, "
                        "updated_at = ? WHERE bundle_id = ? "
                        "AND purpose = 'shared_case'",
                        (
                            purpose_state,
                            ticket.request_id,
                            _utc_text(ticket.receipt.approved_at),
                            request.bundle_id,
                        ),
                    )
                    if current.execute("SELECT changes()").fetchone() != (1,):
                        raise WorkerProtocolError

                proof = ApprovalExecutionGuard(
                    connection,
                    approval_service=cast(
                        ApprovalService,
                        _ExactTicketVerifier(ticket),
                    ),
                    execution_proof_signer=LocalHmacTargetExecutionAttestor(
                        secret=execution_attestor_secret,
                        attestor_id=execution_attestor_id,
                    ),
                    clock=SystemClock(),
                    commit_version_allocator=lambda current: (
                        _next_approval_execution_version(
                            current,
                            ticket.operation_id,
                        )
                    ),
                ).apply_in_transaction(
                    ticket,
                    ticket.descriptor,
                    apply_nonpublish,
                )
                applied_version = proof.execution.applied_commit_version
                if applied_version is None:
                    raise WorkerProtocolError
                return StageSharedCaseOutboxResponse(
                    request_id=request.request_id,
                    bundle_id=request.bundle_id,
                    action="COMMIT",
                    approval_operation_id=ticket.operation_id,
                    applied_commit_version=applied_version,
                    release_outcome=release.outcome,
                    state=(
                        "REJECTED"
                        if review.decision == "rejected"
                        else (
                            "QUARANTINED"
                            if review.decision == "quarantine"
                            else "PRIVATE_ONLY"
                        )
                    ),
                )
            if (
                release.outcome != "eligible"
                or release.reasons
                or release.authorization_ref != authorization.authorization_ref
                or release.review_ref != review.review_ref
                or "answer_support" not in release.allowed_uses
                or "answer_support" not in candidate.requested_allowed_uses
                or review.candidate_sha256 != candidate.candidate_sha256
                or not authorization.reuse_authorized
                or authorization.contributor_client_hash
                not in candidate.provenance.contributor_client_hashes
                or release.evaluated_at < review.reviewed_at
                or release.evaluated_at < authorization.valid_from
                or (
                    authorization.expires_at is not None
                    and release.evaluated_at >= authorization.expires_at
                )
                or (
                    authorization.revoked_at is not None
                    and release.evaluated_at >= authorization.revoked_at
                )
            ):
                raise WorkerProtocolError
            candidate_body = shared_candidate_bytes(candidate)
            source_candidate_row = connection.execute(
                "SELECT b.session_id, c.candidate_sha256, c.candidate_size_bytes "
                "FROM shared_case_candidates AS c JOIN archive_bundles AS b "
                "ON b.bundle_id = c.bundle_id WHERE c.bundle_id = ? "
                "AND c.candidate_id = ? AND c.candidate_object_id = ?",
                (
                    request.bundle_id,
                    candidate.candidate_ref.object_id,
                    candidate.candidate_ref.object_id,
                ),
            ).fetchone()
            if source_candidate_row != (
                session_id,
                candidate.candidate_sha256,
                len(candidate_body),
            ):
                raise WorkerProtocolError
            payload = CasePublishOutboxPayload(
                candidate_ref=candidate.candidate_ref,
                candidate_sha256=candidate.candidate_sha256,
                candidate_size_bytes=len(candidate_body),
                authorization_ref=authorization.authorization_ref,
                review_ref=review.review_ref,
                release_policy_ref=release.policy_ref,
                release_decision_sha256=case_release_decision_sha256(release),
                provenance_ref=candidate.provenance.provenance_ref,
                purpose="answer_support",
                approval_operation_id=ticket.operation_id,
                approval_request_id=ticket.request_id,
                approval_descriptor_sha256=ticket.descriptor_sha256,
                approval_draft_sha256=ticket.descriptor.draft_sha256,
                approval_target_scope_hash=ticket.target_scope_hash,
                source_review_decision_id=request.approval_request_id,
                idempotency_key=(
                    f"case-publish:{request.bundle_id}:"
                    f"{request.approval_operation_id}"
                ),
            )
            payload_bytes = case_publish_payload_bytes(payload)
            transfer = CasePublishTransfer(
                outbox_payload=payload,
                candidate=candidate,
                authorization=authorization,
                review=review,
                release_decision=release,
            )
            if transfer.outbox_payload != payload:
                raise WorkerProtocolError
            governed_bodies = (
                (
                    authorization.authorization_ref.content_sha256,
                    canonical_json_bytes(authorization_payload),
                    "case_reuse_authorization",
                ),
                (
                    review.review_ref.content_sha256,
                    canonical_json_bytes(review_payload),
                    "case_deidentification_review",
                ),
                (
                    payload.release_decision_sha256,
                    canonical_json_bytes(release.model_dump(mode="json")),
                    "case_release_decision",
                ),
            )
            for expected_sha256, body, kind in governed_bodies:
                stored_governed = repository.store_json(body, kind=kind)
                if stored_governed.content_sha256 != expected_sha256:
                    raise WorkerProtocolError
            source_approval = SourceCaseApproval(
                operation_id=ticket.operation_id,
                decision_id=ticket.request_id,
                descriptor_sha256=ticket.descriptor_sha256,
                draft_sha256=ticket.descriptor.draft_sha256,
                target_scope_hash=ticket.target_scope_hash,
                session_id=session_id,
                candidate_id=candidate.candidate_ref.object_id,
                candidate_sha256=candidate.candidate_sha256,
                reviewer_id_hash=hashlib.sha256(
                    ("case-publish\0" + ticket.receipt.provider_id).encode(
                        "utf-8"
                    )
                ).hexdigest(),
                decided_at=ticket.receipt.approved_at,
            )
            existing = connection.execute(
                "SELECT event_id FROM outbox_events WHERE idempotency_key = ?",
                (payload.idempotency_key,),
            ).fetchone()
            if existing is not None:
                record = OutboxRepository(connection).get(str(existing[0]))
                if (
                    record.payload.content_sha256
                    != case_publish_payload_sha256(payload)
                    or record.payload.size_bytes != len(payload_bytes)
                    or repository.read_content(record.payload) != payload_bytes
                ):
                    raise WorkerProtocolError
                record = OutboxRepository(connection).enqueue(
                    event_id=record.event_id,
                    bundle_id=request.bundle_id,
                    approval=source_approval,
                    payload=payload,
                    payload_ref=record.payload,
                    created_at=ticket.receipt.approved_at,
                )
                applied_commit_version = _next_approval_execution_version(
                    connection,
                    request.approval_operation_id,
                )
                return StageSharedCaseOutboxResponse(
                    request_id=request.request_id,
                    bundle_id=request.bundle_id,
                    action="COMMIT",
                    event_id=record.event_id,
                    payload_ref=_archive_content_ref(
                        object_id=record.payload.object_id,
                        content_sha256=record.payload.content_sha256,
                        size_bytes=record.payload.size_bytes,
                    ),
                    approval_operation_id=request.approval_operation_id,
                    applied_commit_version=applied_commit_version,
                    release_outcome="eligible",
                    state=record.state,
                    attempt_count=record.attempt_count,
                    published_global_version=(
                        record.published_global_version
                    ),
                )
            stored = repository.store_json(
                payload_bytes,
                kind="case_outbox_payload",
            )
            if execution_attestor_id is None:
                raise WorkerProtocolError
            event_id = repository.id_factory.object_id("case_outbox_event")
            records: list[OutboxRecord] = []

            def apply_case_outbox(current: sqlite3.Connection) -> None:
                expected_review = (
                    source_approval.session_id,
                    source_approval.candidate_id,
                    "APPROVED",
                    source_approval.reviewer_id_hash,
                    _utc_text(source_approval.decided_at),
                )
                existing_review = current.execute(
                    "SELECT session_id, object_id, decision, reviewer_id_hash, "
                    "decided_at FROM review_decisions WHERE decision_id = ?",
                    (source_approval.decision_id,),
                ).fetchone()
                if existing_review is None:
                    current.execute(
                        "INSERT INTO review_decisions(decision_id, session_id, "
                        "object_id, decision, reviewer_id_hash, decided_at) "
                        "VALUES (?, ?, ?, 'APPROVED', ?, ?)",
                        (
                            source_approval.decision_id,
                            source_approval.session_id,
                            source_approval.candidate_id,
                            source_approval.reviewer_id_hash,
                            _utc_text(source_approval.decided_at),
                        ),
                    )
                elif tuple(existing_review) != expected_review:
                    raise WorkerProtocolError
                records.append(
                    OutboxRepository(current).enqueue_in_transaction(
                        event_id=event_id,
                        bundle_id=request.bundle_id,
                        approval=source_approval,
                        payload=payload,
                        payload_ref=stored,
                        created_at=ticket.receipt.approved_at,
                    )
                )

            proof = ApprovalExecutionGuard(
                connection,
                approval_service=cast(
                    ApprovalService,
                    _ExactTicketVerifier(ticket),
                ),
                execution_proof_signer=LocalHmacTargetExecutionAttestor(
                    secret=execution_attestor_secret,
                    attestor_id=execution_attestor_id,
                ),
                clock=SystemClock(),
                commit_version_allocator=lambda current: (
                    _next_approval_execution_version(
                        current,
                        request.approval_operation_id,
                    )
                ),
            ).apply_in_transaction(
                ticket,
                ticket.descriptor,
                apply_case_outbox,
            )
            if len(records) != 1:
                raise WorkerProtocolError
            record = records[0]
            case_commit_version = proof.execution.applied_commit_version
            if case_commit_version is None:
                raise WorkerProtocolError
            return StageSharedCaseOutboxResponse(
                request_id=request.request_id,
                bundle_id=request.bundle_id,
                action="COMMIT",
                event_id=record.event_id,
                payload_ref=_archive_content_ref(
                    object_id=record.payload.object_id,
                    content_sha256=record.payload.content_sha256,
                    size_bytes=record.payload.size_bytes,
                ),
                approval_operation_id=request.approval_operation_id,
                applied_commit_version=case_commit_version,
                release_outcome="eligible",
                state=record.state,
                attempt_count=record.attempt_count,
                published_global_version=record.published_global_version,
            )
        finally:
            connection.close()

    def recover_client_manifests(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not RecoverClientManifestsRequest:
            raise WorkerProtocolError
        try:
            coordinator = _client_recovery_coordinator(
                root,
                scope_marker_sha256,
            )
            if request.dry_run:
                scan = coordinator.scan()
                receipt_result_sha256: tuple[str, ...] = ()
            else:
                recovery = coordinator.recover()
                scan = recovery.scan
                receipt_result_sha256 = tuple(
                    receipt.durable_result_sha256
                    for receipt in recovery.receipts
                )
            report_sha256 = canonical_sha256(
                {
                    "domain": "consultation_kb.client_recovery_report.v2",
                    "dry_run": request.dry_run,
                    "scan_sha256": scan.scan_sha256,
                    "inventory_count": scan.inventory_count,
                    "decision_sha256": [
                        decision.decision_sha256
                        for decision in scan.decisions
                    ],
                    "receipt_result_sha256": receipt_result_sha256,
                    "startup_health": scan.startup_health,
                }
            )
            return RecoverClientManifestsResponse(
                request_id=request.request_id,
                dry_run=request.dry_run,
                scanned_count=scan.inventory_count,
                applied_count=len(receipt_result_sha256),
                startup_health=scan.startup_health,
                report_sha256=report_sha256,
            )
        except WorkerOperationalError:
            raise
        except Exception:
            raise WorkerOperationalError("LIFECYCLE_RECOVERY_FAILED") from None

    def lifecycle_operation_applied(
        connection: sqlite3.Connection,
        *,
        operation_id: str,
        request_id: str,
        descriptor: DraftDescriptor,
        target_scope_hash: str,
    ) -> bool:
        row = connection.execute(
            "SELECT request_id, descriptor_sha256, draft_sha256, "
            "descriptor_base_version, target_scope_hash, state "
            "FROM approval_executions WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if row is None:
            return False
        if tuple(row) != (
            request_id,
            descriptor_sha256(descriptor),
            descriptor.draft_sha256,
            descriptor.base_version,
            target_scope_hash,
            "APPLIED",
        ):
            raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
        return True

    def load_client_deletion_plan(
        connection: sqlite3.Connection,
        *,
        plan_ref: ArchiveContentRef,
        plan_sha256: str,
        target_scope_hash: str,
        base_versions: tuple[WorkerBaseVersion, ...],
        approval_operation_id: str,
        approval_request_id: str,
    ) -> DeletionPlan:
        if client_id is None or bound_session_id is None:
            raise WorkerProtocolError
        row = connection.execute(
            "SELECT version, content_sha256, size_bytes, media_type, "
            "purpose, operation_id, plan_sha256, base_version, "
            "target_scope_hash FROM lifecycle_plan_objects "
            "WHERE object_id = ?",
            (plan_ref.object_id,),
        ).fetchone()
        if row is None or tuple(row[:7]) != (
            plan_ref.version,
            plan_ref.content_sha256,
            plan_ref.size_bytes,
            plan_ref.media_type,
            "delete",
            approval_operation_id,
            plan_sha256,
        ):
            raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
        try:
            plan = DeletionPlan.model_validate_json(
                _read_archive_bytes(root, plan_ref),
                strict=True,
            )
        except (ValueError, OSError):
            raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH") from None
        expected_bases = tuple(
            WorkerBaseVersion.model_validate(value.model_dump(mode="json"))
            for value in plan.base_versions
        )
        if (
            plan.plan_sha256 != plan_sha256
            or plan.target_scope_hash != target_scope_hash
            or expected_bases != base_versions
            or plan.target.client_id != client_id
            or plan.target.session_id != bound_session_id
            or plan.base_deletion_version != int(row[7])
            or plan.target_scope_hash != str(row[8])
        ):
            raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
        if not lifecycle_operation_applied(
            connection,
            operation_id=approval_operation_id,
            request_id=approval_request_id,
            descriptor=plan.descriptor,
            target_scope_hash=target_scope_hash,
        ):
            DeletionService.for_preview(
                connection,
                inventory_adapter=SqliteDeletionInventoryAdapter(
                    connection,
                    authority_scope="client",
                    client_id=client_id,
                ),
            ).preflight(plan)
        return plan

    def load_client_rebuild_envelope(
        connection: sqlite3.Connection,
        *,
        plan_ref: ArchiveContentRef,
        plan_sha256: str,
        base_versions: tuple[WorkerBaseVersion, ...],
        approval_operation_id: str,
        approval_request_id: str,
        action: Literal["START", "CANCEL"],
    ) -> _ClientRebuildPlanEnvelope:
        if client_id is None or bound_session_id is None:
            raise WorkerProtocolError
        plan_row = connection.execute(
            "SELECT version, content_sha256, size_bytes, media_type, "
            "purpose, operation_id, plan_sha256, base_version, "
            "target_scope_hash FROM lifecycle_plan_objects "
            "WHERE object_id = ?",
            (plan_ref.object_id,),
        ).fetchone()
        if plan_row is None or tuple(plan_row[:7]) != (
            plan_ref.version,
            plan_ref.content_sha256,
            plan_ref.size_bytes,
            plan_ref.media_type,
            "rebuild",
            approval_operation_id,
            plan_sha256,
        ):
            raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
        try:
            envelope = _ClientRebuildPlanEnvelope.model_validate_json(
                _read_archive_bytes(root, plan_ref),
                strict=True,
            )
        except (ValueError, OSError):
            raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH") from None
        if (
            envelope.operation_id != approval_operation_id
            or envelope.plan_sha256 != plan_sha256
            or envelope.base_versions != base_versions
            or envelope.client_id != client_id
            or envelope.session_id != bound_session_id
            or envelope.base_versions[0].version != int(plan_row[7])
            or str(plan_row[8]) != scope_marker_sha256
            or (action == "START" and envelope.action != "start")
            or (action == "CANCEL" and envelope.action != "cancel")
        ):
            raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
        if lifecycle_operation_applied(
            connection,
            operation_id=approval_operation_id,
            request_id=approval_request_id,
            descriptor=envelope.descriptor,
            target_scope_hash=scope_marker_sha256,
        ):
            return envelope

        jobs = RebuildJobRepository(connection, database_scope="client")
        if action == "CANCEL":
            if envelope.job_id is None or envelope.job_plan_sha256 is None:
                raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
            try:
                current = jobs.get(envelope.job_id)
            except Exception as exc:
                if getattr(exc, "code", None) == "REBUILD_JOB_NOT_FOUND":
                    raise WorkerOperationalError("REBUILD_JOB_NOT_FOUND") from None
                raise
            tombstone_bases = tuple(
                value
                for value in base_versions
                if value.authority_key == "tombstone_epoch"
                and value.scope_sha256 == scope_marker_sha256
            )
            authority_state = connection.execute(
                "SELECT tombstone_epoch FROM deletion_authority_state "
                "WHERE singleton = 1"
            ).fetchone()
            if (
                current.scope_sha256 != scope_marker_sha256
                or current.plan_sha256 != envelope.job_plan_sha256
                or len(base_versions) != 1
                or len(tombstone_bases) != 1
                or authority_state != (tombstone_bases[0].version,)
            ):
                raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
            if current.source_intent_id is not None:
                raise WorkerOperationalError(
                    "REBUILD_SOURCE_INTENT_CANCEL_FORBIDDEN"
                )
            if current.state in {"activating", "succeeded"}:
                raise WorkerOperationalError(
                    "REBUILD_CANCELLATION_AFTER_ACTIVATION"
                )
            if current.state not in {
                "queued",
                "running",
                "verifying",
                "failed",
            }:
                raise WorkerOperationalError("REBUILD_JOB_STATE_CONFLICT")
            return envelope

        plan = envelope.plan
        if plan is None or plan.purpose != "all":
            raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
        coordinator = rebuild_resolver(
            connection,
            root,
            scope_marker_sha256,
        )
        current_plan = coordinator.plan(
            RebuildRequest(
                database_scope="client",
                source_intent_id=plan.source_intent_id,
                scope_sha256=scope_marker_sha256,
                purpose=plan.purpose,
                policy_sha256=plan.policy_sha256,
                model_descriptor_sha256=plan.model_descriptor_sha256,
            )
        )
        coordinator.assert_executable(current_plan)
        tombstone_bases = tuple(
            value
            for value in base_versions
            if value.authority_key == "tombstone_epoch"
            and value.scope_sha256 == scope_marker_sha256
        )
        if (
            current_plan != plan
            or len(base_versions) != 1
            or len(tombstone_bases) != 1
            or tombstone_bases[0].version != plan.tombstone_epoch
        ):
            raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
        return envelope

    def preflight_client_lifecycle_commit(
        request: WorkerRequest,
    ) -> WorkerResponse:
        if (
            type(request) is not PreflightClientLifecycleCommitRequest
            or client_id is None
            or bound_session_id is None
        ):
            raise WorkerProtocolError
        connection = connect_database(root / _CLIENT_DATABASE, "reader")
        try:
            if request.lifecycle_kind == "delete":
                if request.target_scope_hash is None:
                    raise WorkerProtocolError
                load_client_deletion_plan(
                    connection,
                    plan_ref=request.plan_ref,
                    plan_sha256=request.plan_sha256,
                    target_scope_hash=request.target_scope_hash,
                    base_versions=request.base_versions,
                    approval_operation_id=request.approval_operation_id,
                    approval_request_id=request.approval_request_id,
                )
            elif request.lifecycle_kind == "rebuild":
                if request.rebuild_action is None:
                    raise WorkerProtocolError
                load_client_rebuild_envelope(
                    connection,
                    plan_ref=request.plan_ref,
                    plan_sha256=request.plan_sha256,
                    base_versions=request.base_versions,
                    approval_operation_id=request.approval_operation_id,
                    approval_request_id=request.approval_request_id,
                    action=request.rebuild_action,
                )
            else:
                workflow = client_rollback_workflow(connection)
                try:
                    workflow.preflight_plan_binding(
                        plan_ref=request.plan_ref,
                        plan_sha256=request.plan_sha256,
                        base_versions=tuple(
                            RollbackBaseVersion.model_validate(
                                value.model_dump(mode="json")
                            )
                            for value in request.base_versions
                        ),
                        approval_operation_id=request.approval_operation_id,
                        approval_request_id=request.approval_request_id,
                    )
                except (ContentStoreError, RollbackError):
                    raise WorkerOperationalError(
                        "LIFECYCLE_PLAN_MISMATCH"
                    ) from None
            return PreflightClientLifecycleCommitResponse(
                request_id=request.request_id,
                lifecycle_kind=request.lifecycle_kind,
                approval_operation_id=request.approval_operation_id,
                plan_sha256=request.plan_sha256,
            )
        finally:
            connection.close()

    def preview_client_delete(request: WorkerRequest) -> WorkerResponse:
        if (
            type(request) is not PreviewClientDeleteRequest
            or client_id is None
            or bound_session_id is None
            or request.target_id != bound_session_id
        ):
            raise WorkerProtocolError
        connection = connect_database(root / _CLIENT_DATABASE, "writer")
        try:
            adapter = SqliteDeletionInventoryAdapter(
                connection,
                authority_scope="client",
                client_id=client_id,
            )
            target = DeletionTarget(
                target_type="session",
                object_ref=DeletionObjectRef(
                    object_type="session",
                    object_id=request.target_id,
                    version=request.target_version,
                    content_sha256=request.target_content_sha256,
                    authority_scope="client",
                ),
                client_id=client_id,
                session_id=request.target_id,
            )
            plan = DeletionService.for_preview(
                connection,
                inventory_adapter=adapter,
            ).preview(
                DeletionPreviewRequest(
                    request_id=IdFactory().object_id("deletion_request"),
                    target=target,
                    reason_code=request.reason_code,
                    requested_at=request.requested_at,
                )
            )
            plan_bytes = canonical_json_bytes(plan.model_dump(mode="json"))
            plan_object_id = IdFactory().object_id("lifecycle_plan")
            stored = ContentStore(root / "cas").finalize(
                ContentStore(root / "cas").stage_bytes(
                    plan_bytes,
                    purpose="delete",
                    manifest_id=plan_object_id,
                    media_type="application/json",
                )
            )
            created_at = request.requested_at.isoformat(
                timespec="microseconds"
            ).replace("+00:00", "Z")
            with transaction(connection):
                existing = connection.execute(
                    "SELECT object_id, version, content_sha256, size_bytes, "
                    "media_type, purpose, plan_sha256, base_version, "
                    "target_scope_hash FROM lifecycle_plan_objects "
                    "WHERE operation_id = ?",
                    (request.proposed_operation_id,),
                ).fetchone()
                expected_tail = (
                    stored.content_sha256,
                    stored.size_bytes,
                    stored.media_type,
                    "delete",
                    plan.plan_sha256,
                    plan.base_deletion_version,
                    plan.target_scope_hash,
                )
                if existing is None:
                    connection.execute(
                        "INSERT INTO lifecycle_plan_objects("
                        "object_id, version, content_sha256, size_bytes, "
                        "media_type, purpose, operation_id, plan_sha256, "
                        "base_version, target_scope_hash, created_at"
                        ") VALUES (?, 1, ?, ?, ?, 'delete', ?, ?, ?, ?, ?)",
                        (
                            plan_object_id,
                            stored.content_sha256,
                            stored.size_bytes,
                            stored.media_type,
                            request.proposed_operation_id,
                            plan.plan_sha256,
                            plan.base_deletion_version,
                            plan.target_scope_hash,
                            created_at,
                        ),
                    )
                elif tuple(existing[2:]) != expected_tail:
                    raise WorkerProtocolError
                else:
                    plan_object_id = str(existing[0])
            return PreviewClientDeleteResponse(
                request_id=request.request_id,
                plan_ref=_archive_content_ref(
                    object_id=plan_object_id,
                    content_sha256=stored.content_sha256,
                    size_bytes=stored.size_bytes,
                ),
                plan_sha256=plan.plan_sha256,
                target_scope_hash=plan.target_scope_hash,
                proposed_operation_id=request.proposed_operation_id,
                base_deletion_version=plan.base_deletion_version,
                base_versions=tuple(
                    WorkerBaseVersion.model_validate(value.model_dump(mode="json"))
                    for value in plan.base_versions
                ),
                action_count=len(plan.actions),
                retained_audit_count=len(plan.retained_audit_refs),
            )
        finally:
            connection.close()

    def commit_client_tombstone(request: WorkerRequest) -> WorkerResponse:
        if (
            type(request) is not CommitClientTombstoneRequest
            or client_id is None
            or bound_session_id is None
            or archive_approval_resolver is None
            or execution_attestor_secret is None
            or execution_attestor_id is None
        ):
            raise WorkerOperationalError("LIFECYCLE_APPROVAL_REQUIRED")
        connection = connect_database(root / _CLIENT_DATABASE, "writer")
        try:
            plan = load_client_deletion_plan(
                connection,
                plan_ref=request.plan_ref,
                plan_sha256=request.plan_sha256,
                target_scope_hash=request.target_scope_hash,
                base_versions=request.base_versions,
                approval_operation_id=request.approval_operation_id,
                approval_request_id=request.approval_request_id,
            )
            ticket = archive_approval_resolver(
                request.approval_operation_id,
                request.approval_request_id,
            )
            if ticket.descriptor != plan.descriptor:
                raise WorkerOperationalError("LIFECYCLE_APPROVAL_REQUIRED")
            guard = ApprovalExecutionGuard(
                connection,
                approval_service=cast(ApprovalService, _ExactTicketVerifier(ticket)),
                execution_proof_signer=LocalHmacTargetExecutionAttestor(
                    secret=execution_attestor_secret,
                    attestor_id=execution_attestor_id,
                ),
                clock=SystemClock(),
                commit_version_allocator=lambda _connection: (
                    plan.next_deletion_version
                ),
            )
            result = DeletionService(
                connection,
                approval_guard=guard,
                inventory_adapter=SqliteDeletionInventoryAdapter(
                    connection,
                    authority_scope="client",
                    client_id=client_id,
                ),
            ).commit_tombstone(plan, ticket)
            queue_count = connection.execute(
                "SELECT COUNT(*) FROM deletion_queue_intents WHERE request_id = ?",
                (plan.request_id,),
            ).fetchone()
            if queue_count is None or type(queue_count[0]) is not int:
                raise WorkerProtocolError
            return CommitClientTombstoneResponse(
                request_id=request.request_id,
                approval_operation_id=request.approval_operation_id,
                deletion_version=result.deletion_version,
                tombstone_epoch=result.tombstone_epoch,
                queue_intent_count=int(queue_count[0]),
            )
        finally:
            connection.close()

    def rebuild_job_response(
        request: RebuildClientDerivativesRequest,
        jobs: RebuildJobRepository,
        job: RebuildJob,
        *,
        applied_commit_version: int | None = None,
    ) -> RebuildClientDerivativesResponse:
        journal = jobs.journal(job.job_id)
        return RebuildClientDerivativesResponse(
            request_id=request.request_id,
            action=request.action,
            approval_operation_id=(
                request.approval_operation_id
                if request.action in {"START", "CANCEL"}
                else None
            ),
            applied_commit_version=applied_commit_version,
            job_id=job.job_id,
            plan_sha256=job.plan_sha256,
            state=job.state,
            attempt_count=job.attempt_count,
            output_manifest_set_sha256=job.output_manifest_set_sha256,
            equivalence_report_sha256=job.equivalence_report_sha256,
            last_error_code=job.last_error_code,
            report_sha256=canonical_sha256(
                {
                    "domain": "consultation_kb.client_rebuild_report.v1",
                    "job": job.model_dump(mode="json"),
                    "journal": [
                        value.model_dump(mode="json") for value in journal
                    ],
                }
            ),
        )

    def preview_client_rebuild(request: WorkerRequest) -> WorkerResponse:
        if (
            type(request) is not PreviewClientRebuildRequest
            or client_id is None
            or bound_session_id is None
        ):
            raise WorkerProtocolError
        connection = connect_database(root / _CLIENT_DATABASE, "writer")
        try:
            jobs = RebuildJobRepository(connection, database_scope="client")
            if request.action == "start":
                try:
                    from consultation_kb.lifecycle.production_rebuild import (
                        load_production_rebuild_config,
                    )

                    production = load_production_rebuild_config(
                        root,
                        database_scope="client",
                        scope_sha256=scope_marker_sha256,
                    )
                except Exception:
                    raise WorkerOperationalError(
                        "REBUILD_PRODUCTION_BUILDERS_UNAVAILABLE"
                    ) from None
                if (
                    request.purpose != "all"
                    or (
                        request.policy_sha256 is not None
                        and request.policy_sha256 != production.policy_sha256
                    )
                    or (
                        request.model_descriptor_sha256 is not None
                        and request.model_descriptor_sha256
                        != production.model_descriptor_sha256
                    )
                ):
                    raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
                coordinator = rebuild_resolver(
                    connection,
                    root,
                    scope_marker_sha256,
                )
                plan = coordinator.plan(
                    RebuildRequest(
                        database_scope="client",
                        source_intent_id=request.source_intent_id,
                        scope_sha256=scope_marker_sha256,
                        purpose="all",
                        policy_sha256=production.policy_sha256,
                        model_descriptor_sha256=(
                            production.model_descriptor_sha256
                        ),
                    )
                )
                base_versions = (
                    WorkerBaseVersion(
                        authority_key="tombstone_epoch",
                        scope_sha256=scope_marker_sha256,
                        version=plan.tombstone_epoch,
                    ),
                )
                descriptor = DraftDescriptor(
                    purpose="rebuild",
                    target_id="client_rebuild:all",
                    client_id=client_id,
                    session_id=bound_session_id,
                    base_version=plan.tombstone_epoch,
                    draft_sha256=plan.plan_sha256,
                )
                envelope = _ClientRebuildPlanEnvelope(
                    action="start",
                    operation_id=request.proposed_operation_id,
                    client_id=client_id,
                    session_id=bound_session_id,
                    plan=plan,
                    base_versions=base_versions,
                    plan_sha256=plan.plan_sha256,
                    descriptor=descriptor,
                )
            else:
                assert request.job_id is not None
                try:
                    job = jobs.get(request.job_id)
                except Exception as exc:
                    if getattr(exc, "code", None) == "REBUILD_JOB_NOT_FOUND":
                        raise WorkerOperationalError(
                            "REBUILD_JOB_NOT_FOUND"
                        ) from None
                    raise
                if job.scope_sha256 != scope_marker_sha256:
                    raise WorkerOperationalError("REBUILD_JOB_NOT_FOUND")
                if job.source_intent_id is not None:
                    raise WorkerOperationalError(
                        "REBUILD_SOURCE_INTENT_CANCEL_FORBIDDEN"
                    )
                if job.state in {"activating", "succeeded"}:
                    raise WorkerOperationalError(
                        "REBUILD_CANCELLATION_AFTER_ACTIVATION"
                    )
                state = connection.execute(
                    "SELECT tombstone_epoch FROM deletion_authority_state "
                    "WHERE singleton = 1"
                ).fetchone()
                if state is None or type(state[0]) is not int:
                    raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
                base_versions = (
                    WorkerBaseVersion(
                        authority_key="tombstone_epoch",
                        scope_sha256=scope_marker_sha256,
                        version=int(state[0]),
                    ),
                )
                plan_sha256 = canonical_sha256(
                    {
                        "domain": "consultation_kb.rebuild_cancel_plan.v1",
                        "database_scope": "client",
                        "job_id": job.job_id,
                        "job_plan_sha256": job.plan_sha256,
                        "base_versions": [
                            value.model_dump(mode="json")
                            for value in base_versions
                        ],
                    }
                )
                descriptor = DraftDescriptor(
                    purpose="rebuild",
                    target_id=f"client_rebuild_cancel:{job.job_id}",
                    client_id=client_id,
                    session_id=bound_session_id,
                    base_version=int(state[0]),
                    draft_sha256=plan_sha256,
                )
                envelope = _ClientRebuildPlanEnvelope(
                    action="cancel",
                    operation_id=request.proposed_operation_id,
                    client_id=client_id,
                    session_id=bound_session_id,
                    job_id=job.job_id,
                    job_plan_sha256=job.plan_sha256,
                    base_versions=base_versions,
                    plan_sha256=plan_sha256,
                    descriptor=descriptor,
                )
            payload = canonical_json_bytes(envelope.model_dump(mode="json"))
            object_id = IdFactory().object_id("lifecycle_plan")
            store = ContentStore(root / "cas")
            stored = store.finalize(
                store.stage_bytes(
                    payload,
                    purpose="rebuild",
                    manifest_id=object_id,
                    media_type="application/json",
                )
            )
            created_at = request.requested_at.isoformat(
                timespec="microseconds"
            ).replace("+00:00", "Z")
            with transaction(connection):
                connection.execute(
                    "INSERT INTO lifecycle_plan_objects("
                    "object_id, version, content_sha256, size_bytes, media_type, "
                    "purpose, operation_id, plan_sha256, base_version, "
                    "target_scope_hash, created_at) "
                    "VALUES (?, 1, ?, ?, ?, 'rebuild', ?, ?, ?, ?, ?)",
                    (
                        object_id,
                        stored.content_sha256,
                        stored.size_bytes,
                        stored.media_type,
                        request.proposed_operation_id,
                        envelope.plan_sha256,
                        envelope.base_versions[0].version,
                        scope_marker_sha256,
                        created_at,
                    ),
                )
            return PreviewClientRebuildResponse(
                request_id=request.request_id,
                action=envelope.action,
                plan_ref=_archive_content_ref(
                    object_id=object_id,
                    content_sha256=stored.content_sha256,
                    size_bytes=stored.size_bytes,
                ),
                plan_sha256=envelope.plan_sha256,
                proposed_operation_id=request.proposed_operation_id,
                base_versions=envelope.base_versions,
                purpose=None if envelope.plan is None else envelope.plan.purpose,
                source_intent_id=(
                    None
                    if envelope.plan is None
                    else envelope.plan.source_intent_id
                ),
                job_id=envelope.job_id,
            )
        finally:
            connection.close()

    def rebuild_client_derivatives(request: WorkerRequest) -> WorkerResponse:
        if (
            type(request) is not RebuildClientDerivativesRequest
            or client_id is None
            or bound_session_id is None
        ):
            raise WorkerProtocolError
        writer = request.action in {"START", "CANCEL"}
        connection = connect_database(
            root / _CLIENT_DATABASE,
            "writer" if writer else "reader",
        )
        try:
            jobs = RebuildJobRepository(connection, database_scope="client")
            if request.action in {"STATUS", "REPORT"}:
                if request.job_id is None:
                    raise WorkerProtocolError
                try:
                    job = jobs.get(request.job_id)
                except Exception as exc:
                    if getattr(exc, "code", None) == "REBUILD_JOB_NOT_FOUND":
                        raise WorkerOperationalError("REBUILD_JOB_NOT_FOUND") from None
                    raise
                if job.scope_sha256 != scope_marker_sha256:
                    raise WorkerOperationalError("REBUILD_JOB_NOT_FOUND")
                return rebuild_job_response(request, jobs, job)

            if (
                archive_approval_resolver is None
                or execution_attestor_secret is None
                or execution_attestor_id is None
                or request.approval_operation_id is None
                or request.approval_request_id is None
                or request.plan_sha256 is None
                or request.plan_ref is None
            ):
                raise WorkerOperationalError("LIFECYCLE_APPROVAL_REQUIRED")
            plan_ref = request.plan_ref
            lifecycle_action = cast(
                Literal["START", "CANCEL"],
                request.action,
            )
            envelope = load_client_rebuild_envelope(
                connection,
                plan_ref=plan_ref,
                plan_sha256=request.plan_sha256,
                base_versions=request.base_versions,
                approval_operation_id=request.approval_operation_id,
                approval_request_id=request.approval_request_id,
                action=lifecycle_action,
            )

            if request.action == "CANCEL":
                if envelope.job_id is None or envelope.job_plan_sha256 is None:
                    raise WorkerProtocolError
                try:
                    current = jobs.get(envelope.job_id)
                except Exception as exc:
                    if getattr(exc, "code", None) == "REBUILD_JOB_NOT_FOUND":
                        raise WorkerOperationalError("REBUILD_JOB_NOT_FOUND") from None
                    raise
                tombstone_bases = tuple(
                    value
                    for value in request.base_versions
                    if value.authority_key == "tombstone_epoch"
                    and value.scope_sha256 == scope_marker_sha256
                )
                authority_state = connection.execute(
                    "SELECT tombstone_epoch FROM deletion_authority_state "
                    "WHERE singleton = 1"
                ).fetchone()
                if (
                    current.scope_sha256 != scope_marker_sha256
                    or current.plan_sha256 != envelope.job_plan_sha256
                    or len(request.base_versions) != 1
                    or len(tombstone_bases) != 1
                    or authority_state != (tombstone_bases[0].version,)
                ):
                    raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
                if current.source_intent_id is not None:
                    raise WorkerOperationalError(
                        "REBUILD_SOURCE_INTENT_CANCEL_FORBIDDEN"
                    )
                if current.state in {"activating", "succeeded"}:
                    raise WorkerOperationalError(
                        "REBUILD_CANCELLATION_AFTER_ACTIVATION"
                    )
                if current.state not in {
                    "queued",
                    "running",
                    "verifying",
                    "failed",
                }:
                    raise WorkerOperationalError("REBUILD_JOB_STATE_CONFLICT")
                ticket = archive_approval_resolver(
                    request.approval_operation_id,
                    request.approval_request_id,
                )
                if (
                    ticket.descriptor != envelope.descriptor
                    or ticket.target_scope_hash != scope_marker_sha256
                ):
                    raise WorkerOperationalError("LIFECYCLE_APPROVAL_REQUIRED")

                def cancel_job(target: sqlite3.Connection) -> None:
                    exact = jobs.get(current.job_id)
                    if (
                        target is not connection
                        or not target.in_transaction
                        or exact.source_intent_id is not None
                        or exact.state not in {
                            "queued",
                            "running",
                            "verifying",
                            "failed",
                        }
                    ):
                        raise WorkerOperationalError(
                            "REBUILD_JOB_STATE_CONFLICT"
                        )
                    target.execute(
                        "INSERT INTO lifecycle_approval_attestations("
                        "operation_id, request_id, descriptor_sha256, "
                        "plan_object_id, plan_version, plan_content_sha256, "
                        "plan_size_bytes, plan_media_type, purpose, "
                        "base_version, target_scope_hash, attested_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'rebuild', ?, ?, ?)",
                        (
                            ticket.operation_id,
                            ticket.request_id,
                            ticket.descriptor_sha256,
                            plan_ref.object_id,
                            plan_ref.version,
                            plan_ref.content_sha256,
                            plan_ref.size_bytes,
                            plan_ref.media_type,
                            ticket.descriptor.base_version,
                            ticket.target_scope_hash,
                            _utc_text(SystemClock().now()),
                        ),
                    )
                    now = _utc_text(SystemClock().now())
                    changed = target.execute(
                        "UPDATE rebuild_jobs SET state = 'cancelled', "
                        "updated_at = ?, finished_at = ?, cancelled_at = ?, "
                        "last_error_code = NULL WHERE job_id = ? AND state = ?",
                        (now, now, now, exact.job_id, exact.state),
                    ).rowcount
                    if changed != 1:
                        raise WorkerOperationalError(
                            "REBUILD_JOB_STATE_CONFLICT"
                        )
                    jobs._append_journal(  # noqa: SLF001
                        job_id=exact.job_id,
                        state="cancelled",
                    )

                proof = ApprovalExecutionGuard(
                    connection,
                    approval_service=cast(
                        ApprovalService,
                        _ExactTicketVerifier(ticket),
                    ),
                    execution_proof_signer=LocalHmacTargetExecutionAttestor(
                        secret=execution_attestor_secret,
                        attestor_id=execution_attestor_id,
                    ),
                    clock=SystemClock(),
                ).apply_in_transaction(ticket, envelope.descriptor, cancel_job)
                return rebuild_job_response(
                    request,
                    jobs,
                    jobs.get(current.job_id),
                    applied_commit_version=proof.applied_commit_version,
                )

            if envelope.plan is None or request.idempotency_key is None:
                raise WorkerOperationalError(
                    "REBUILD_PRODUCTION_BUILDERS_UNAVAILABLE"
                )
            plan = envelope.plan
            if plan.purpose != "all":
                raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
            idempotency_key = request.idempotency_key
            coordinator = rebuild_resolver(
                connection,
                root,
                scope_marker_sha256,
            )
            if not isinstance(coordinator, RebuildCoordinator):
                raise WorkerOperationalError(
                    "REBUILD_PRODUCTION_BUILDERS_UNAVAILABLE"
                )
            current_plan = coordinator.plan(
                RebuildRequest(
                    database_scope="client",
                    source_intent_id=plan.source_intent_id,
                    scope_sha256=scope_marker_sha256,
                    purpose=plan.purpose,
                    policy_sha256=plan.policy_sha256,
                    model_descriptor_sha256=plan.model_descriptor_sha256,
                )
            )
            coordinator.assert_executable(current_plan)
            tombstone_bases = tuple(
                value
                for value in request.base_versions
                if value.authority_key == "tombstone_epoch"
                and value.scope_sha256 == scope_marker_sha256
            )
            if (
                current_plan != plan
                or len(request.base_versions) != 1
                or len(tombstone_bases) != 1
                or tombstone_bases[0].version != plan.tombstone_epoch
            ):
                raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
            ticket = archive_approval_resolver(
                request.approval_operation_id,
                request.approval_request_id,
            )
            if (
                ticket.descriptor != envelope.descriptor
                or ticket.target_scope_hash != scope_marker_sha256
            ):
                raise WorkerOperationalError("LIFECYCLE_APPROVAL_REQUIRED")
            queued: list[RebuildJob] = []

            def enqueue(_connection: sqlite3.Connection) -> None:
                if coordinator.plan(
                    RebuildRequest(
                        database_scope="client",
                        source_intent_id=plan.source_intent_id,
                        scope_sha256=scope_marker_sha256,
                        purpose=plan.purpose,
                        policy_sha256=plan.policy_sha256,
                        model_descriptor_sha256=plan.model_descriptor_sha256,
                    )
                ) != plan:
                    raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
                _connection.execute(
                    "INSERT INTO lifecycle_approval_attestations("
                    "operation_id, request_id, descriptor_sha256, "
                    "plan_object_id, plan_version, plan_content_sha256, "
                    "plan_size_bytes, plan_media_type, purpose, "
                    "base_version, target_scope_hash, attested_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'rebuild', ?, ?, ?)",
                    (
                        ticket.operation_id,
                        ticket.request_id,
                        ticket.descriptor_sha256,
                        plan_ref.object_id,
                        plan_ref.version,
                        plan_ref.content_sha256,
                        plan_ref.size_bytes,
                        plan_ref.media_type,
                        ticket.descriptor.base_version,
                        ticket.target_scope_hash,
                        _utc_text(SystemClock().now()),
                    ),
                )
                queued.append(
                    coordinator.start_in_transaction(
                        plan,
                        idempotency_key=idempotency_key,
                        approval_operation_id=request.approval_operation_id,
                        approval_request_id=request.approval_request_id,
                    )
                )

            proof = ApprovalExecutionGuard(
                connection,
                approval_service=cast(
                    ApprovalService,
                    _ExactTicketVerifier(ticket),
                ),
                execution_proof_signer=LocalHmacTargetExecutionAttestor(
                    secret=execution_attestor_secret,
                    attestor_id=execution_attestor_id,
                ),
                clock=SystemClock(),
            ).apply_in_transaction(ticket, envelope.descriptor, enqueue)
            if queued:
                job = queued[0]
            else:
                row = connection.execute(
                    "SELECT job_id FROM rebuild_jobs "
                    "WHERE approval_operation_id = ?",
                    (request.approval_operation_id,),
                ).fetchone()
                if row is None:
                    raise WorkerProtocolError
                job = jobs.get(str(row[0]))
            result = rebuild_job_response(
                request,
                jobs,
                job,
                applied_commit_version=proof.applied_commit_version,
            )
            _start_client_rebuild_runner(
                root=root,
                scope_marker_sha256=scope_marker_sha256,
                resolver=rebuild_resolver,
            )
            return result
        finally:
            connection.close()

    def preview_client_rollback(request: WorkerRequest) -> WorkerResponse:
        if (
            type(request) is not PreviewClientRollbackRequest
            or client_id is None
            or bound_session_id is None
        ):
            raise WorkerProtocolError
        connection = connect_database(root / _CLIENT_DATABASE, "writer")
        try:
            workflow = client_rollback_workflow(connection)
            try:
                if request.rollback_kind == "profile_fact":
                    preview = workflow.preview_profile_fact(
                        fact_id=request.target_id,
                        current_version=request.current_version,
                        restore_version=request.restore_version,
                        reason=request.reason,
                    )
                else:
                    assert request.source_plan_ref is not None
                    preview = workflow.preview_artifact(
                        artifact_key=request.target_id,
                        current_version=request.current_version,
                        restore_version=request.restore_version,
                        reason=request.reason,
                        source_plan_ref=request.source_plan_ref,
                    )
            except RollbackError as error:
                raise WorkerOperationalError(
                    "LIFECYCLE_APPROVAL_REQUIRED"
                    if error.code == "ROLLBACK_APPROVAL_REQUIRED"
                    else "LIFECYCLE_PLAN_MISMATCH"
                ) from None
            if (
                preview.descriptor.client_id != client_id
                or preview.descriptor.session_id != bound_session_id
                or preview.rollback_kind != request.rollback_kind
            ):
                raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
            return PreviewClientRollbackResponse(
                request_id=request.request_id,
                rollback_kind=request.rollback_kind,
                plan_ref=preview.plan_ref,
                plan_sha256=preview.plan_sha256,
                proposed_operation_id=preview.proposed_operation_id,
                base_versions=tuple(
                    WorkerBaseVersion.model_validate(
                        value.model_dump(mode="json")
                    )
                    for value in preview.base_versions
                ),
                current_version=preview.current_version,
                restore_version=preview.restore_version,
            )
        finally:
            connection.close()

    def commit_client_rollback(request: WorkerRequest) -> WorkerResponse:
        if (
            type(request) is not CommitClientRollbackRequest
            or client_id is None
            or bound_session_id is None
            or archive_approval_resolver is None
            or rollback_approval_request is None
            or execution_attestor_secret is None
            or execution_attestor_id is None
        ):
            raise WorkerOperationalError("LIFECYCLE_APPROVAL_REQUIRED")
        connection = connect_database(root / _CLIENT_DATABASE, "writer")
        try:
            ticket = archive_approval_resolver(
                request.approval_operation_id,
                request.approval_request_id,
            )
            guard = ApprovalExecutionGuard(
                connection,
                approval_service=cast(
                    ApprovalService,
                    _ExactTicketVerifier(ticket),
                ),
                execution_proof_signer=LocalHmacTargetExecutionAttestor(
                    secret=execution_attestor_secret,
                    attestor_id=execution_attestor_id,
                ),
                clock=SystemClock(),
            )
            workflow = client_rollback_workflow(
                connection,
                approval_guard=guard,
            )
            try:
                result = workflow.commit(
                    plan_ref=request.plan_ref,
                    plan_sha256=request.plan_sha256,
                    base_versions=tuple(
                        RollbackBaseVersion.model_validate(
                            value.model_dump(mode="json")
                        )
                        for value in request.base_versions
                    ),
                    ticket=ticket,
                    approval_request=rollback_approval_request,
                )
            except RollbackError as error:
                raise WorkerOperationalError(
                    "LIFECYCLE_APPROVAL_REQUIRED"
                    if error.code
                    in {
                        "ROLLBACK_APPROVAL_REQUIRED",
                        "ROLLBACK_APPROVAL_BINDING_MISMATCH",
                    }
                    else "LIFECYCLE_PLAN_MISMATCH"
                ) from None
            summary = result.summary
            if (
                summary.rollback_kind not in {"profile_fact", "artifact"}
                or summary.rebuild_job_id is None
                or summary.requires_combined_publication
            ):
                raise WorkerOperationalError("LIFECYCLE_PLAN_MISMATCH")
            response = CommitClientRollbackResponse(
                request_id=request.request_id,
                approval_operation_id=request.approval_operation_id,
                applied_commit_version=summary.applied_commit_version,
                rollback_kind=summary.rollback_kind,
                successor_ref=summary.successor_ref,
                rebuild_job_id=summary.rebuild_job_id,
            )
            _start_client_rebuild_runner(
                root=root,
                scope_marker_sha256=scope_marker_sha256,
                resolver=_production_client_rebuild_resolver,
            )
            return response
        finally:
            connection.close()

    def verify_client_integrity(request: WorkerRequest) -> WorkerResponse:
        if type(request) is not VerifyClientIntegrityRequest:
            raise WorkerProtocolError
        connection = connect_database(root / _CLIENT_DATABASE, "reader")
        try:
            try:
                epoch = assert_client_active_integrity(connection)
            except ArtifactUnavailable:
                raise WorkerOperationalError(
                    CLIENT_ACTIVE_INTEGRITY_REBUILD_REQUIRED
                ) from None
            rows = connection.execute(
                "SELECT artifact_key, manifest_id FROM active_artifacts "
                "WHERE epoch = ? ORDER BY artifact_key",
                (epoch,),
            ).fetchall()
            return VerifyClientIntegrityResponse(
                request_id=request.request_id,
                active_epoch=epoch,
                artifact_count=len(rows),
                verification_sha256=canonical_sha256(
                    {
                        "domain": "consultation_kb.client_integrity_result.v1",
                        "active_epoch": epoch,
                        "active_artifacts": [
                            {"artifact_key": row[0], "manifest_id": row[1]}
                            for row in rows
                        ],
                    }
                ),
            )
        finally:
            connection.close()

    return WorkerOperationRegistry(
        (
            OperationBinding(
                schema_version="1.0",
                operation="ping",
                request_model=PingRequest,
                response_model=PingResponse,
                required_permission="client_read",
                handler=ping,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="get_empty_context_metadata",
                request_model=EmptyContextMetadataRequest,
                response_model=EmptyContextMetadataResponse,
                required_permission="client_read",
                handler=empty_metadata,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="append_scoped_audit",
                request_model=AppendScopedAuditRequest,
                response_model=AppendScopedAuditResponse,
                required_permission="session_append",
                handler=append_audit,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="query_fact_snapshot",
                request_model=QueryFactSnapshotRequest,
                response_model=QueryFactSnapshotResponse,
                required_permission="client_read",
                handler=query_facts,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="preview_fact_mutation",
                request_model=PreviewFactMutationRequest,
                response_model=PreviewFactMutationResponse,
                required_permission="draft_write",
                handler=preview_mutation,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="commit_fact_mutation",
                request_model=CommitFactMutationRequest,
                response_model=CommitFactMutationResponse,
                required_permission="draft_write",
                handler=confirm_governed_commit,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="query_profile_snapshot",
                request_model=QueryProfileSnapshotRequest,
                response_model=QueryProfileSnapshotResponse,
                required_permission="client_read",
                handler=query_profile,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="query_client_graph",
                request_model=QueryClientGraphRequest,
                response_model=QueryClientGraphResponse,
                required_permission="client_read",
                handler=query_graph,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="search_client_graph",
                request_model=SearchClientGraphRequest,
                response_model=SearchClientGraphResponse,
                required_permission="client_read",
                handler=search_graph,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="query_client_weighted_path",
                request_model=QueryClientWeightedPathRequest,
                response_model=QueryClientWeightedPathResponse,
                required_permission="client_read",
                handler=weighted_client_path,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="query_client_history_candidates",
                request_model=QueryClientHistoryCandidatesRequest,
                response_model=QueryClientHistoryCandidatesResponse,
                required_permission="client_read",
                handler=query_client_history_candidates,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="preview_dependency_impact",
                request_model=PreviewDependencyImpactRequest,
                response_model=PreviewDependencyImpactResponse,
                required_permission="draft_write",
                handler=preview_impact,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="preview_target_dependency_impact",
                request_model=PreviewTargetDependencyImpactRequest,
                response_model=PreviewTargetDependencyImpactResponse,
                required_permission="client_read",
                handler=preview_target_impact,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="begin_session",
                request_model=BeginSessionRequest,
                response_model=BeginSessionResponse,
                required_permission="session_append",
                handler=begin_session,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="resume_session",
                request_model=ResumeSessionRequest,
                response_model=ResumeSessionResponse,
                required_permission="session_append",
                handler=resume_session,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="append_client_turn",
                request_model=AppendClientTurnRequest,
                response_model=AppendClientTurnResponse,
                required_permission="session_append",
                handler=append_client_turn,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="append_temporary_fact",
                request_model=AppendTemporaryFactRequest,
                response_model=AppendTemporaryFactResponse,
                required_permission="session_append",
                handler=append_temporary_fact,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="begin_generation",
                request_model=BeginGenerationRequest,
                response_model=BeginGenerationResponse,
                required_permission="session_append",
                handler=begin_generation,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="store_candidate_set",
                request_model=StoreCandidateSetRequest,
                response_model=StoreCandidateSetResponse,
                required_permission="session_append",
                handler=store_candidate_set,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="record_actual_reply",
                request_model=RecordActualReplyRequest,
                response_model=RecordActualReplyResponse,
                required_permission="session_append",
                handler=record_actual_reply,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="read_session_state",
                request_model=ReadSessionStateRequest,
                response_model=ReadSessionStateResponse,
                required_permission="client_read",
                handler=read_session_state,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="get_generation_binding",
                request_model=GetGenerationBindingRequest,
                response_model=GetGenerationBindingResponse,
                required_permission="client_read",
                handler=get_generation_binding,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="prepare_generation_retrieval",
                request_model=PrepareGenerationRetrievalRequest,
                response_model=PrepareGenerationRetrievalResponse,
                required_permission="client_read",
                handler=prepare_generation_retrieval,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="get_generation_evidence_for_plan",
                request_model=GetGenerationEvidenceForPlanRequest,
                response_model=GetGenerationEvidenceForPlanResponse,
                required_permission="client_read",
                handler=get_generation_evidence_for_plan,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="store_generation_evidence_pack",
                request_model=StoreGenerationEvidencePackRequest,
                response_model=StoreGenerationEvidencePackResponse,
                required_permission="session_append",
                handler=store_generation_evidence_pack,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="submit_generation_stage",
                request_model=SubmitGenerationStageRequest,
                response_model=SubmitGenerationStageResponse,
                required_permission="session_append",
                handler=submit_generation_stage,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="get_generation_state",
                request_model=GetGenerationStateRequest,
                response_model=GetGenerationStateResponse,
                required_permission="client_read",
                handler=get_generation_state,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="prepare_turn_risk_evaluation",
                request_model=PrepareTurnRiskEvaluationRequest,
                response_model=PrepareTurnRiskEvaluationResponse,
                required_permission="session_append",
                handler=prepare_turn_risk_evaluation,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="persist_risk_observations",
                request_model=PersistRiskObservationsRequest,
                response_model=PersistRiskObservationsResponse,
                required_permission="session_append",
                handler=persist_risk_observations,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="acknowledge_risk_observation",
                request_model=AcknowledgeRiskObservationRequest,
                response_model=AcknowledgeRiskObservationResponse,
                required_permission="session_append",
                handler=acknowledge_risk_observation,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="build_private_archive",
                request_model=BuildPrivateArchiveRequest,
                response_model=BuildPrivateArchiveResponse,
                required_permission="session_append",
                handler=build_private_archive,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="commit_private_archive",
                request_model=CommitPrivateArchiveRequest,
                response_model=CommitPrivateArchiveResponse,
                required_permission="draft_write",
                handler=commit_private_archive,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="build_profile_diff",
                request_model=BuildProfileDiffRequest,
                response_model=BuildProfileDiffResponse,
                required_permission="session_append",
                handler=build_profile_diff,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="commit_profile_update",
                request_model=CommitProfileUpdateRequest,
                response_model=CommitProfileUpdateResponse,
                required_permission="draft_write",
                handler=commit_profile_update,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="stage_shared_case_outbox",
                request_model=StageSharedCaseOutboxRequest,
                response_model=StageSharedCaseOutboxResponse,
                required_permission="draft_write",
                handler=stage_shared_case_outbox,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="recover_client_manifests",
                request_model=RecoverClientManifestsRequest,
                response_model=RecoverClientManifestsResponse,
                required_permission="formal_write",
                handler=recover_client_manifests,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="preflight_client_lifecycle_commit",
                request_model=PreflightClientLifecycleCommitRequest,
                response_model=PreflightClientLifecycleCommitResponse,
                required_permission="formal_write",
                handler=preflight_client_lifecycle_commit,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="preview_client_delete",
                request_model=PreviewClientDeleteRequest,
                response_model=PreviewClientDeleteResponse,
                required_permission="draft_write",
                handler=preview_client_delete,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="commit_client_tombstone",
                request_model=CommitClientTombstoneRequest,
                response_model=CommitClientTombstoneResponse,
                required_permission="formal_write",
                handler=commit_client_tombstone,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="preview_client_rebuild",
                request_model=PreviewClientRebuildRequest,
                response_model=PreviewClientRebuildResponse,
                required_permission="draft_write",
                handler=preview_client_rebuild,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="rebuild_client_derivatives",
                request_model=RebuildClientDerivativesRequest,
                response_model=RebuildClientDerivativesResponse,
                required_permission="formal_write",
                handler=rebuild_client_derivatives,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="preview_client_rollback",
                request_model=PreviewClientRollbackRequest,
                response_model=PreviewClientRollbackResponse,
                required_permission="draft_write",
                handler=preview_client_rollback,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="commit_client_rollback",
                request_model=CommitClientRollbackRequest,
                response_model=CommitClientRollbackResponse,
                required_permission="formal_write",
                handler=commit_client_rollback,
            ),
            OperationBinding(
                schema_version="1.0",
                operation="verify_client_integrity",
                request_model=VerifyClientIntegrityRequest,
                response_model=VerifyClientIntegrityResponse,
                required_permission="client_read",
                handler=verify_client_integrity,
            ),
        )
    )


def _verify_current_scope(
    guard: PathGuard,
    bootstrap: _WorkerBootstrap,
) -> None:
    """Revalidate the marker and database while the caller pins the root."""

    with guard.open_scoped(_SCOPE_MARKER, mode="rb") as marker:
        marker_bytes = marker.read(4097)
    if (
        not marker_bytes
        or len(marker_bytes) > 4096
        or hashlib.sha256(marker_bytes).hexdigest()
        != bootstrap.scope_marker_sha256
    ):
        raise WorkerProtocolError
    with guard.open_scoped(_CLIENT_DATABASE, mode="rb") as database:
        database.read(0)


def _send_denied(connection: Connection) -> None:
    try:
        connection.send_bytes(encode_message(ScopeDeniedResponse()))
    except (EOFError, OSError, WorkerProtocolError):
        pass


def _archive_response_commit_version(response: WorkerResponse) -> int:
    if isinstance(response, CommitProfileUpdateResponse):
        return response.new_commit_version
    if isinstance(
        response,
        (CommitPrivateArchiveResponse, StageSharedCaseOutboxResponse),
    ):
        value = response.applied_commit_version
        if value is None:
            raise WorkerProtocolError
        return value
    if isinstance(response, CommitClientTombstoneResponse):
        return response.deletion_version
    if isinstance(response, RebuildClientDerivativesResponse):
        value = response.applied_commit_version
        if value is None or response.action not in {"START", "CANCEL"}:
            raise WorkerProtocolError
        return value
    if isinstance(response, CommitClientRollbackResponse):
        return response.applied_commit_version
    raise WorkerProtocolError


def _require_archive_execution(
    connection: sqlite3.Connection,
    *,
    ticket: ApprovalExecutionTicket,
    applied_commit_version: int,
) -> ApprovalExecution:
    nonce_sha256 = hashlib.sha256(
        ticket.receipt.nonce.encode("ascii", errors="strict")
    ).hexdigest()
    expected = (
        ticket.request_id,
        ticket.descriptor_sha256,
        ticket.descriptor.draft_sha256,
        ticket.descriptor.base_version,
        ticket.target_scope_hash,
        nonce_sha256,
        "APPLIED",
        applied_commit_version,
    )
    row = connection.execute(
        "SELECT request_id, descriptor_sha256, draft_sha256, "
        "descriptor_base_version, target_scope_hash, nonce_sha256, "
        "state, applied_commit_version FROM approval_executions "
        "WHERE operation_id = ?",
        (ticket.operation_id,),
    ).fetchone()
    if row is None or tuple(row) != expected:
        raise WorkerProtocolError
    return ApprovalExecution(
        operation_id=ticket.operation_id,
        request_id=ticket.request_id,
        descriptor_sha256=ticket.descriptor_sha256,
        target_scope_hash=ticket.target_scope_hash,
        state="applied",
        applied_commit_version=applied_commit_version,
    )


def _execute_approved_archive_commit(
    root: Path,
    bootstrap: _WorkerBootstrap,
    payload: ApprovedCommitClaimPayload,
) -> ApprovedCommitResult:
    if (
        bootstrap.client_id is None
        or bootstrap.session_id is None
        or bootstrap.execution_attestor_secret_hex is None
        or bootstrap.execution_attestor_id is None
        or type(payload.request) not in {
            CommitPrivateArchiveRequest,
            CommitProfileUpdateRequest,
            StageSharedCaseOutboxRequest,
            CommitClientTombstoneRequest,
            RebuildClientDerivativesRequest,
            CommitClientRollbackRequest,
        }
    ):
        raise WorkerProtocolError
    request = payload.request
    _verify_request_session_binding(request, bootstrap)

    def resolve_ticket(
        operation_id: str,
        receipt_id: str,
    ) -> ApprovalExecutionTicket:
        if (
            operation_id != payload.ticket.operation_id
            or receipt_id != payload.ticket.request_id
        ):
            raise WorkerProtocolError
        return payload.ticket

    registry = _build_registry(
        root,
        scope_marker_sha256=bootstrap.scope_marker_sha256,
        client_id=bootstrap.client_id,
        bound_session_id=bootstrap.session_id,
        archive_approval_resolver=resolve_ticket,
        rollback_approval_request=payload.approval_request,
        execution_attestor_secret=bytes.fromhex(
            bootstrap.execution_attestor_secret_hex
        ),
        execution_attestor_id=bootstrap.execution_attestor_id,
    )
    response = registry.resolve(request).handler(request)
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
        raise WorkerProtocolError
    archive_response = cast(ApprovedCommitResponse, response)
    applied_commit_version = _archive_response_commit_version(
        archive_response
    )
    database = connect_database(root / _CLIENT_DATABASE, "writer")
    try:
        execution = _require_archive_execution(
            database,
            ticket=payload.ticket,
            applied_commit_version=applied_commit_version,
        )
    finally:
        database.close()
    nonce_sha256 = hashlib.sha256(
        payload.ticket.receipt.nonce.encode("ascii", errors="strict")
    ).hexdigest()
    proof = LocalHmacTargetExecutionAttestor(
        secret=bytes.fromhex(bootstrap.execution_attestor_secret_hex),
        attestor_id=bootstrap.execution_attestor_id,
    ).attest(
        execution=execution,
        draft_sha256=payload.ticket.descriptor.draft_sha256,
        nonce_sha256=nonce_sha256,
        issuance_signature=payload.ticket.issuance_signature,
    )
    return ApprovedCommitResult(
        response=archive_response,
        execution=proof.execution,
        attestor_id=proof.attestor_id,
        draft_sha256=proof.draft_sha256,
        nonce_sha256=proof.nonce_sha256,
        issuance_signature=proof.issuance_signature,
        proof_signature=proof.signature,
    )


def _execute_approved_commit(
    root: Path,
    bootstrap: _WorkerBootstrap,
    claim: ApprovedCommitClaim,
) -> ApprovedCommitResult:
    if (
        bootstrap.claim_verification_secret_hex is None
        or bootstrap.execution_attestor_secret_hex is None
        or bootstrap.execution_attestor_id is None
    ):
        raise WorkerProtocolError
    now = datetime.now(timezone.utc)
    payload = LocalHmacApprovedCommitClaimVerifier(
        bytes.fromhex(bootstrap.claim_verification_secret_hex)
    ).verify(claim, now=now)
    expected_scope_hash = (
        payload.request.target_scope_hash
        if type(payload.request) is CommitClientTombstoneRequest
        else bootstrap.scope_marker_sha256
    )
    if (
        bootstrap.client_id is None
        or not hmac.compare_digest(
            payload.target_scope_hash,
            expected_scope_hash,
        )
        or payload.descriptor.client_id != bootstrap.client_id
    ):
        raise WorkerProtocolError
    if type(payload.request) is not CommitFactMutationRequest:
        return _execute_approved_archive_commit(root, bootstrap, payload)
    request = payload.request
    connection = connect_database(root / _CLIENT_DATABASE, "writer")
    try:
        preview_row = connection.execute(
            "SELECT preview_sha256, base_commit_version, expected_runtime_epoch, "
            "created_at FROM review_diff_objects "
            "WHERE draft_event_id = ? AND operation_id = ? "
            "AND purpose = 'profile_update_review'",
            (request.draft_event_id, request.approval_operation_id),
        ).fetchone()
        if preview_row is None or preview_row[:3] != (
            request.preview_sha256,
            request.base_commit_version,
            request.expected_runtime_epoch,
        ):
            raise WorkerProtocolError
        try:
            registered_timestamp = datetime.fromisoformat(
                str(preview_row[3]).replace("Z", "+00:00")
            )
        except ValueError:
            raise WorkerProtocolError from None
        if registered_timestamp != request.publication_timestamp:
            raise WorkerProtocolError
        mutation, session_id, _turn_id = _load_bound_draft(
            connection,
            request.draft_event_id,
            expected_scope_hash=bootstrap.scope_marker_sha256,
            expected_client_id=bootstrap.client_id,
        )
        plan = ClientPublicationPlanner(connection).prepare(
            mutation,
            draft_event_id=request.draft_event_id,
            operation_id=request.approval_operation_id,
            expected_runtime_epoch=request.expected_runtime_epoch,
            publication_timestamp=registered_timestamp,
            draft_session_id=session_id,
        )
        if (
            plan.preview_sha256 != request.preview_sha256
            or plan.mutation_preview.base_commit_version
            != request.base_commit_version
            or plan.descriptor != payload.descriptor
            or payload.ticket.descriptor != plan.descriptor
        ):
            raise WorkerProtocolError
        proof = ClientPublicationExecutor(
            connection,
            scope_root=root,
            execution_proof_signer=LocalHmacTargetExecutionAttestor(
                secret=bytes.fromhex(bootstrap.execution_attestor_secret_hex),
                attestor_id=bootstrap.execution_attestor_id,
            ),
        ).execute(plan, payload.ticket)
        response = CommitFactMutationResponse(
            request_id=request.request_id,
            approval_operation_id=request.approval_operation_id,
            new_commit_version=plan.authority_version,
            runtime_epoch=plan.runtime_epoch,
            event_count=result_event_count(plan),
        )
        return ApprovedCommitResult(
            response=response,
            execution=proof.execution,
            attestor_id=proof.attestor_id,
            draft_sha256=proof.draft_sha256,
            nonce_sha256=proof.nonce_sha256,
            issuance_signature=proof.issuance_signature,
            proof_signature=proof.signature,
        )
    finally:
        connection.close()


def _read_registered_review_diff(root: Path, reference: VersionRef) -> bytes:
    connection = connect_database(root / _CLIENT_DATABASE, "reader")
    try:
        row = connection.execute(
            "SELECT version, content_sha256, size_bytes, media_type "
            "FROM review_diff_objects WHERE object_id = ?",
            (reference.object_id,),
        ).fetchone()
        if row is None or row[0] != reference.version or row[1] != (
            reference.content_sha256
        ):
            raise WorkerProtocolError
        content_reference = ContentStore(root / "cas").reference(
            content_sha256=str(row[1]),
            media_type=str(row[3]),
            size_bytes=int(row[2]),
        )
        content = ContentStore(root / "cas").read_verified(content_reference)
        if hashlib.sha256(content).hexdigest() != reference.content_sha256:
            raise WorkerProtocolError
        return content
    finally:
        connection.close()


def _recover_applied_fact_commit(
    root: Path,
    bootstrap: _WorkerBootstrap,
    claim: AppliedCommitRecoveryClaim,
) -> ApprovedCommitResult:
    if (
        bootstrap.claim_verification_secret_hex is None
        or bootstrap.execution_attestor_secret_hex is None
        or bootstrap.execution_attestor_id is None
        or bootstrap.client_id is None
    ):
        raise WorkerProtocolError
    payload = LocalHmacAppliedCommitRecoveryVerifier(
        bytes.fromhex(bootstrap.claim_verification_secret_hex)
    ).verify(claim, now=datetime.now(timezone.utc))
    if (
        not hmac.compare_digest(
            payload.target_scope_hash,
            bootstrap.scope_marker_sha256,
        )
        or payload.descriptor.client_id != bootstrap.client_id
    ):
        raise WorkerProtocolError
    request = payload.request
    if type(request) is not CommitFactMutationRequest:
        raise WorkerProtocolError
    ticket = payload.ticket
    connection = connect_database(root / _CLIENT_DATABASE, "reader")
    try:
        preview = connection.execute(
            "SELECT preview_sha256, base_commit_version, expected_runtime_epoch, "
            "created_at FROM review_diff_objects "
            "WHERE draft_event_id = ? AND operation_id = ? "
            "AND purpose = 'profile_update_review'",
            (request.draft_event_id, request.approval_operation_id),
        ).fetchone()
        if preview is None or preview[:3] != (
            request.preview_sha256,
            request.base_commit_version,
            request.expected_runtime_epoch,
        ) or str(preview[3]) != request.publication_timestamp.isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z"):
            raise WorkerProtocolError
        expected_nonce_sha256 = hashlib.sha256(
            ticket.receipt.nonce.encode("ascii")
        ).hexdigest()
        execution_row = connection.execute(
            "SELECT request_id, descriptor_sha256, draft_sha256, "
            "descriptor_base_version, target_scope_hash, nonce_sha256, state, "
            "applied_commit_version FROM approval_executions "
            "WHERE operation_id = ?",
            (ticket.operation_id,),
        ).fetchone()
        expected_execution = (
            ticket.request_id,
            ticket.descriptor_sha256,
            ticket.descriptor.draft_sha256,
            ticket.descriptor.base_version,
            ticket.target_scope_hash,
            expected_nonce_sha256,
            "APPLIED",
            request.base_commit_version + 1,
        )
        if execution_row != expected_execution:
            raise WorkerProtocolError
        expected_current_epoch = (
            None
            if request.expected_runtime_epoch == 1
            else request.expected_runtime_epoch - 1
        )
        publication_row = connection.execute(
            "SELECT purpose, authority_base_version, approval_request_id, "
            "descriptor_sha256, state, expected_current_epoch, runtime_epoch "
            "FROM publication_operations WHERE operation_id = ?",
            (ticket.operation_id,),
        ).fetchone()
        if publication_row != (
            "profile_update",
            request.base_commit_version + 1,
            ticket.request_id,
            ticket.descriptor_sha256,
            "ACTIVE",
            expected_current_epoch,
            request.expected_runtime_epoch,
        ):
            raise WorkerProtocolError
        manifests = ManifestRepository(connection).list_for_operation(
            ticket.operation_id
        )
        if publication_closure_sha256(
            purpose="profile_update",
            authority_base_version=request.base_commit_version + 1,
            expected_current_epoch=expected_current_epoch,
            artifacts=manifests,
        ) != request.preview_sha256:
            raise WorkerProtocolError
        if connection.execute(
            "SELECT artifact_key FROM active_artifacts WHERE epoch = ? "
            "ORDER BY artifact_key",
            (request.expected_runtime_epoch,),
        ).fetchall() != [
            ("client_fact_snapshot",),
            ("client_graph",),
            ("client_profile",),
        ]:
            raise WorkerProtocolError
        fact_row = connection.execute(
            "SELECT COUNT(*), MIN(commit_version), MAX(commit_version), "
            "MIN(visible_runtime_epoch), MAX(visible_runtime_epoch) "
            "FROM fact_events WHERE publication_operation_id = ?",
            (ticket.operation_id,),
        ).fetchone()
        if (
            fact_row is None
            or int(fact_row[0]) <= 0
            or fact_row[1:] != (
                request.base_commit_version + 1,
                request.base_commit_version + 1,
                request.expected_runtime_epoch,
                request.expected_runtime_epoch,
            )
        ):
            raise WorkerProtocolError
        if connection.execute(
            "SELECT source_commit_version, visible_runtime_epoch "
            "FROM profile_revisions WHERE publication_operation_id = ?",
            (ticket.operation_id,),
        ).fetchone() != (
            request.base_commit_version + 1,
            request.expected_runtime_epoch,
        ):
            raise WorkerProtocolError
        store = ContentStore(root / "cas")
        for manifest in manifests:
            for member in manifest.members:
                store.read_verified(
                    store.reference(
                        content_sha256=member.object_sha256,
                        media_type=member.media_type,
                        size_bytes=member.size_bytes,
                    )
                )
        execution = ApprovalExecution(
            operation_id=ticket.operation_id,
            request_id=ticket.request_id,
            descriptor_sha256=ticket.descriptor_sha256,
            target_scope_hash=ticket.target_scope_hash,
            state="applied",
            applied_commit_version=request.base_commit_version + 1,
        )
        proof = LocalHmacTargetExecutionAttestor(
            secret=bytes.fromhex(bootstrap.execution_attestor_secret_hex),
            attestor_id=bootstrap.execution_attestor_id,
        ).attest(
            execution=execution,
            draft_sha256=ticket.descriptor.draft_sha256,
            nonce_sha256=expected_nonce_sha256,
            issuance_signature=ticket.issuance_signature,
        )
        return ApprovedCommitResult(
            response=CommitFactMutationResponse(
                request_id=request.request_id,
                approval_operation_id=request.approval_operation_id,
                new_commit_version=request.base_commit_version + 1,
                runtime_epoch=request.expected_runtime_epoch,
                event_count=int(fact_row[0]),
            ),
            execution=proof.execution,
            attestor_id=proof.attestor_id,
            draft_sha256=proof.draft_sha256,
            nonce_sha256=proof.nonce_sha256,
            issuance_signature=proof.issuance_signature,
            proof_signature=proof.signature,
        )
    finally:
        connection.close()


def _read_applied_archive_execution(
    connection: sqlite3.Connection,
    ticket: ApprovalExecutionTicket,
) -> ApprovalExecution:
    row = connection.execute(
        "SELECT applied_commit_version FROM approval_executions "
        "WHERE operation_id = ?",
        (ticket.operation_id,),
    ).fetchone()
    if row is None or type(row[0]) is not int or row[0] <= 0:
        raise WorkerProtocolError
    return _require_archive_execution(
        connection,
        ticket=ticket,
        applied_commit_version=int(row[0]),
    )


def _probe_applied_archive_execution(
    connection: sqlite3.Connection,
    ticket: ApprovalExecutionTicket,
) -> ApprovalExecution | None:
    """Return exact APPLIED or exact absence; reject every ambiguous target row."""

    row = connection.execute(
        "SELECT applied_commit_version FROM approval_executions "
        "WHERE operation_id = ?",
        (ticket.operation_id,),
    ).fetchone()
    if row is not None:
        if type(row[0]) is not int or row[0] <= 0:
            raise WorkerProtocolError
        return _require_archive_execution(
            connection,
            ticket=ticket,
            applied_commit_version=int(row[0]),
        )
    nonce_sha256 = hashlib.sha256(
        ticket.receipt.nonce.encode("ascii", errors="strict")
    ).hexdigest()
    conflict = connection.execute(
        "SELECT operation_id FROM approval_executions "
        "WHERE request_id = ? OR nonce_sha256 = ? LIMIT 1",
        (ticket.request_id, nonce_sha256),
    ).fetchone()
    if conflict is not None:
        raise WorkerProtocolError
    return None


def _verify_active_manifest_cas(
    root: Path,
    manifests: tuple[ArtifactManifest, ...],
) -> None:
    store = ContentStore(root / "cas")
    try:
        for manifest in manifests:
            if (
                manifest.state != "ACTIVE"
                or not manifest.verified
                or not manifest.members
            ):
                raise WorkerProtocolError
            for member in manifest.members:
                content = store.read_verified(
                    store.reference(
                        content_sha256=member.object_sha256,
                        media_type=member.media_type,
                        size_bytes=member.size_bytes,
                    )
                )
                if (
                    len(content) != member.size_bytes
                    or hashlib.sha256(content).hexdigest()
                    != member.object_sha256
                ):
                    raise WorkerProtocolError
    except WorkerProtocolError:
        raise
    except Exception:
        raise WorkerProtocolError from None


def _verify_publication_closure_attestation(
    connection: sqlite3.Connection,
    *,
    publication_operation_id: str,
    ticket: ApprovalExecutionTicket,
    purpose: str,
    authority_base_version: int,
    expected_current_epoch: int | None,
    manifests: tuple[ArtifactManifest, ...],
) -> None:
    """Bind the approved draft to the independently derived artifact closure."""

    row = connection.execute(
        "SELECT approval_draft_sha256, closure_sha256 "
        "FROM publication_closure_attestations WHERE operation_id = ?",
        (publication_operation_id,),
    ).fetchone()
    actual_closure_sha256 = publication_closure_sha256(
        purpose=purpose,
        authority_base_version=authority_base_version,
        expected_current_epoch=expected_current_epoch,
        artifacts=manifests,
    )
    if row != (
        ticket.descriptor.draft_sha256,
        actual_closure_sha256,
    ):
        raise WorkerProtocolError


def _archive_recovery_result(
    bootstrap: _WorkerBootstrap,
    *,
    ticket: ApprovalExecutionTicket,
    execution: ApprovalExecution,
    response: ApprovedCommitResponse,
) -> ApprovedCommitResult:
    if (
        bootstrap.execution_attestor_secret_hex is None
        or bootstrap.execution_attestor_id is None
    ):
        raise WorkerProtocolError
    nonce_sha256 = hashlib.sha256(
        ticket.receipt.nonce.encode("ascii", errors="strict")
    ).hexdigest()
    proof = LocalHmacTargetExecutionAttestor(
        secret=bytes.fromhex(bootstrap.execution_attestor_secret_hex),
        attestor_id=bootstrap.execution_attestor_id,
    ).attest(
        execution=execution,
        draft_sha256=ticket.descriptor.draft_sha256,
        nonce_sha256=nonce_sha256,
        issuance_signature=ticket.issuance_signature,
    )
    return ApprovedCommitResult(
        response=response,
        execution=proof.execution,
        attestor_id=proof.attestor_id,
        draft_sha256=proof.draft_sha256,
        nonce_sha256=proof.nonce_sha256,
        issuance_signature=proof.issuance_signature,
        proof_signature=proof.signature,
    )


def _recover_private_archive_commit(
    root: Path,
    bootstrap: _WorkerBootstrap,
    *,
    request: CommitPrivateArchiveRequest,
    ticket: ApprovalExecutionTicket,
) -> ApprovedCommitResult:
    if bootstrap.session_id is None or bootstrap.client_id is None:
        raise WorkerProtocolError
    draft = _read_private_archive_draft(root, request.draft_ref)
    if (
        draft.draft_ref != request.draft_ref.version_ref
        or draft.actual_transcript.session_id != bootstrap.session_id
    ):
        raise WorkerProtocolError
    connection = connect_database(root / _CLIENT_DATABASE, "reader")
    try:
        execution = _read_applied_archive_execution(connection, ticket)
        bundle = connection.execute(
            "SELECT session_id, actual_transcript_object_id, "
            "actual_transcript_version, actual_transcript_sha256, "
            "actual_transcript_media_type, actual_transcript_size_bytes "
            "FROM archive_bundles WHERE bundle_id = ?",
            (request.bundle_id,),
        ).fetchone()
        actual = draft.actual_transcript.actual_transcript_ref
        if bundle != (
            bootstrap.session_id,
            actual.object_id,
            actual.version,
            actual.content_sha256,
            "application/json",
            len(draft.actual_transcript.canonical_text.encode("utf-8")),
        ):
            raise WorkerProtocolError
        revision = connection.execute(
            "SELECT revision_id, revision, draft_object_id, draft_sha256, "
            "draft_media_type, draft_size_bytes, actual_transcript_object_id, "
            "actual_transcript_sha256, review_decision_id, manifest_id, state "
            "FROM private_archive_revisions WHERE bundle_id = ? "
            "AND draft_object_id = ? AND draft_sha256 = ?",
            (
                request.bundle_id,
                request.draft_ref.object_id,
                request.draft_ref.content_sha256,
            ),
        ).fetchone()
        if (
            revision is None
            or type(revision[0]) is not str
            or revision[1] != request.base_version + 1
            or revision[2:6]
            != (
                request.draft_ref.object_id,
                request.draft_ref.content_sha256,
                request.draft_ref.media_type,
                request.draft_ref.size_bytes,
            )
            or revision[6:8] != (actual.object_id, actual.content_sha256)
            or type(revision[8]) is not str
            or type(revision[9]) is not str
            or revision[10] != "ACTIVE"
        ):
            raise WorkerProtocolError
        decision_id = str(revision[8])
        manifest_id = str(revision[9])
        if connection.execute(
            "SELECT state, manifest_id, review_decision_id "
            "FROM archive_purpose_states WHERE bundle_id = ? "
            "AND purpose = 'private_archive'",
            (request.bundle_id,),
        ).fetchone() != ("ACTIVE", manifest_id, decision_id):
            raise WorkerProtocolError
        reviewer_hash = hashlib.sha256(
            ticket.receipt.provider_id.encode("utf-8")
        ).hexdigest()
        decision = connection.execute(
            "SELECT session_id, object_id, decision, reviewer_id_hash, decided_at "
            "FROM review_decisions WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()
        if (
            decision is None
            or decision[:4]
            != (
                bootstrap.session_id,
                request.draft_ref.object_id,
                "EDITED",
                reviewer_hash,
            )
            or type(decision[4]) is not str
        ):
            raise WorkerProtocolError
        manifest = ManifestRepository(connection).get(manifest_id)
        if (
            manifest.artifact_key != "private_archive"
            or manifest.artifact_kind != "private_archive"
            or manifest.source_version != request.base_version + 1
            or len(manifest.members) != 1
        ):
            raise WorkerProtocolError
        member = manifest.members[0]
        if (
            member.object_type != "private_archive_draft"
            or member.object_id != request.draft_ref.object_id
            or member.object_sha256 != request.draft_ref.content_sha256
            or member.source_version != request.base_version + 1
            or member.media_type != request.draft_ref.media_type
            or member.size_bytes != request.draft_ref.size_bytes
            or member.source_lineage_hashes != (actual.content_sha256,)
        ):
            raise WorkerProtocolError
        required = json.dumps([manifest_id], separators=(",", ":"))
        if connection.execute(
            "SELECT purpose, authority_base_version, approval_request_id, "
            "descriptor_sha256, state, required_manifests_json, "
            "required_manifest_count, verified_manifest_count, "
            "expected_current_epoch, runtime_epoch "
            "FROM publication_operations WHERE operation_id = ?",
            (manifest.operation_id,),
        ).fetchone() != (
            "private_archive_publish",
            request.base_version + 1,
            ticket.request_id,
            ticket.descriptor_sha256,
            "ACTIVE",
            required,
            1,
            1,
            None,
            None,
        ):
            raise WorkerProtocolError
        _verify_active_manifest_cas(root, (manifest,))
        _verify_publication_closure_attestation(
            connection,
            publication_operation_id=manifest.operation_id,
            ticket=ticket,
            purpose="private_archive_publish",
            authority_base_version=request.base_version + 1,
            expected_current_epoch=None,
            manifests=(manifest,),
        )
        store = ContentStore(root / "cas")
        store.read_verified(
            store.reference(
                content_sha256=actual.content_sha256,
                media_type="application/json",
                size_bytes=int(bundle[5]),
            )
        )
        response = CommitPrivateArchiveResponse(
            request_id=request.request_id,
            bundle_id=request.bundle_id,
            approval_operation_id=request.approval_operation_id,
            applied_commit_version=cast(int, execution.applied_commit_version),
            revision_ref=VersionRef(
                object_id=str(revision[0]),
                version=int(revision[1]),
                content_sha256=str(revision[3]),
            ),
            manifest_ref=VersionRef(
                object_id=manifest.manifest_id,
                version=manifest.source_version,
                content_sha256=manifest.manifest_sha256,
            ),
        )
        return _archive_recovery_result(
            bootstrap,
            ticket=ticket,
            execution=execution,
            response=response,
        )
    finally:
        connection.close()


def _recover_profile_archive_commit(
    root: Path,
    bootstrap: _WorkerBootstrap,
    *,
    request: CommitProfileUpdateRequest,
    ticket: ApprovalExecutionTicket,
) -> ApprovedCommitResult:
    if bootstrap.session_id is None or bootstrap.client_id is None:
        raise WorkerProtocolError
    draft = _read_profile_diff_draft(root, request.draft_ref)
    connection = connect_database(root / _CLIENT_DATABASE, "reader")
    try:
        execution = _read_applied_archive_execution(connection, ticket)
        bundle = connection.execute(
            "SELECT session_id, actual_transcript_sha256 FROM archive_bundles "
            "WHERE bundle_id = ?",
            (request.bundle_id,),
        ).fetchone()
        if bundle != (bootstrap.session_id, draft.base_session_sha256):
            raise WorkerProtocolError
        stored = connection.execute(
            "SELECT bundle_id, draft_object_id, draft_sha256, draft_media_type, "
            "draft_size_bytes, base_profile_version, base_profile_sha256 "
            "FROM profile_diff_drafts WHERE draft_id = ?",
            (draft.diff_id,),
        ).fetchone()
        if stored != (
            request.bundle_id,
            request.draft_ref.object_id,
            request.draft_ref.content_sha256,
            request.draft_ref.media_type,
            request.draft_ref.size_bytes,
            draft.base_client_commit_version,
            draft.base_profile_sha256,
        ):
            raise WorkerProtocolError
        preview = ProfileDiffReviewService().preview(
            draft,
            current_profile_sha256=draft.base_profile_sha256,
            current_session_sha256=draft.base_session_sha256,
            current_client_commit_version=draft.base_client_commit_version,
        )
        approved = ProfileDiffReviewService().approve_partial(
            preview,
            approved_operation_ids=request.selected_operation_ids,
            dismissed_indirect_review_fact_ids=(
                request.dismissed_indirect_review_fact_ids
            ),
            current_profile_sha256=draft.base_profile_sha256,
            current_session_sha256=draft.base_session_sha256,
            current_client_commit_version=draft.base_client_commit_version,
        )
        if (
            approved.client_id != bootstrap.client_id
            or approved.session_id != bootstrap.session_id
            or approved.descriptor != ticket.descriptor
            or approved.pending_indirect_review_fact_ids
            or approved.unapproved_direct_impact_fact_ids
        ):
            raise WorkerProtocolError
        authority_version = ticket.descriptor.base_version + 1
        # Profile publication deliberately uses the client authority version as
        # its approval execution commit version.  Unlike private archive and
        # source outbox commits (whose values are approval-execution sequence
        # numbers), this value is independently recoverable from the approved
        # descriptor and every published profile artifact below.
        if execution.applied_commit_version != authority_version:
            raise WorkerProtocolError
        expected_current_epoch = (
            None
            if request.expected_runtime_epoch == 1
            else request.expected_runtime_epoch - 1
        )
        operation = connection.execute(
            "SELECT purpose, authority_base_version, approval_request_id, "
            "descriptor_sha256, state, required_manifests_json, "
            "required_manifest_count, verified_manifest_count, "
            "expected_current_epoch, runtime_epoch FROM publication_operations "
            "WHERE operation_id = ?",
            (ticket.operation_id,),
        ).fetchone()
        if (
            operation is None
            or operation[:5]
            != (
                "profile_update",
                authority_version,
                ticket.request_id,
                ticket.descriptor_sha256,
                "ACTIVE",
            )
            or operation[6:] != (
                3,
                3,
                expected_current_epoch,
                request.expected_runtime_epoch,
            )
        ):
            raise WorkerProtocolError
        manifests = ManifestRepository(connection).list_for_operation(
            ticket.operation_id
        )
        if (
            len(manifests) != 3
            or tuple(sorted(item.artifact_key for item in manifests))
            != ("client_fact_snapshot", "client_graph", "client_profile")
            or any(item.source_version != authority_version for item in manifests)
        ):
            raise WorkerProtocolError
        manifest_ids = tuple(sorted(item.manifest_id for item in manifests))
        try:
            required_manifest_ids = tuple(json.loads(str(operation[5])))
        except (TypeError, ValueError, json.JSONDecodeError):
            raise WorkerProtocolError from None
        if required_manifest_ids != manifest_ids:
            raise WorkerProtocolError
        if connection.execute(
            "SELECT state, operation_id FROM runtime_epochs WHERE epoch = ?",
            (request.expected_runtime_epoch,),
        ).fetchone() not in {
            ("ACTIVE", ticket.operation_id),
            ("RETIRED", ticket.operation_id),
        }:
            raise WorkerProtocolError
        active_rows = connection.execute(
            "SELECT artifact_key, manifest_id FROM active_artifacts "
            "WHERE epoch = ? ORDER BY artifact_key",
            (request.expected_runtime_epoch,),
        ).fetchall()
        expected_active = sorted(
            (item.artifact_key, item.manifest_id) for item in manifests
        )
        if active_rows != expected_active:
            raise WorkerProtocolError
        if connection.execute(
            "SELECT state, manifest_id, review_decision_id "
            "FROM archive_purpose_states WHERE bundle_id = ? "
            "AND purpose = 'profile_diff'",
            (request.bundle_id,),
        ).fetchone() != (
            "ACTIVE",
            next(
                item.manifest_id
                for item in manifests
                if item.artifact_key == "client_profile"
            ),
            ticket.request_id,
        ):
            raise WorkerProtocolError
        reviewer_hash = hashlib.sha256(
            ("profile-update\0" + ticket.receipt.provider_id).encode("utf-8")
        ).hexdigest()
        if connection.execute(
            "SELECT session_id, object_id, decision, reviewer_id_hash, decided_at "
            "FROM review_decisions WHERE decision_id = ?",
            (ticket.request_id,),
        ).fetchone() != (
            bootstrap.session_id,
            ticket.descriptor.target_id,
            "APPROVED",
            reviewer_hash,
            _utc_text(ticket.receipt.approved_at),
        ):
            raise WorkerProtocolError
        fact_row = connection.execute(
            "SELECT COUNT(*), MIN(commit_version), MAX(commit_version), "
            "MIN(visible_runtime_epoch), MAX(visible_runtime_epoch) "
            "FROM fact_events WHERE publication_operation_id = ?",
            (ticket.operation_id,),
        ).fetchone()
        if (
            fact_row is None
            or int(fact_row[0]) <= 0
            or fact_row[1:] != (
                authority_version,
                authority_version,
                request.expected_runtime_epoch,
                request.expected_runtime_epoch,
            )
        ):
            raise WorkerProtocolError
        profile_revision = connection.execute(
            "SELECT source_commit_version, visible_runtime_epoch, "
            "json_object_id, markdown_object_id, created_at "
            "FROM profile_revisions WHERE publication_operation_id = ?",
            (ticket.operation_id,),
        ).fetchone()
        if (
            profile_revision is None
            or profile_revision[:2]
            != (authority_version, request.expected_runtime_epoch)
            or profile_revision[4] != _utc_text(request.publication_timestamp)
        ):
            raise WorkerProtocolError
        profile_manifest = next(
            item for item in manifests if item.artifact_key == "client_profile"
        )
        profile_ids = {
            member.object_type: member.object_id
            for member in profile_manifest.members
        }
        if profile_ids != {
            "profile_json": profile_revision[2],
            "profile_markdown": profile_revision[3],
        }:
            raise WorkerProtocolError
        fact_manifest = next(
            item for item in manifests if item.artifact_key == "client_fact_snapshot"
        )
        commitments = tuple(
            member
            for member in fact_manifest.members
            if member.object_type == "profile_diff_review_commitment"
        )
        if len(commitments) != 1:
            raise WorkerProtocolError
        commitment_body = ContentStore(root / "cas").read_hash_verified(
            commitments[0].object_sha256
        )
        try:
            commitment = json.loads(commitment_body.decode("utf-8"))
        except (UnicodeError, ValueError, json.JSONDecodeError):
            raise WorkerProtocolError from None
        if commitment != {
            "schema_version": "profile_diff_review_commitment.v1",
            "selection_sha256": ticket.descriptor.draft_sha256,
            "source_diff_sha256": draft.canonical_sha256,
        }:
            raise WorkerProtocolError
        _verify_active_manifest_cas(root, manifests)
        _verify_publication_closure_attestation(
            connection,
            publication_operation_id=ticket.operation_id,
            ticket=ticket,
            purpose="profile_update",
            authority_base_version=authority_version,
            expected_current_epoch=expected_current_epoch,
            manifests=manifests,
        )
        response = CommitProfileUpdateResponse(
            request_id=request.request_id,
            bundle_id=request.bundle_id,
            approval_operation_id=request.approval_operation_id,
            new_commit_version=authority_version,
            runtime_epoch=request.expected_runtime_epoch,
            event_count=int(fact_row[0]),
            manifest_ids=manifest_ids,
        )
        return _archive_recovery_result(
            bootstrap,
            ticket=ticket,
            execution=execution,
            response=response,
        )
    finally:
        connection.close()


def _recover_shared_case_commit(
    root: Path,
    bootstrap: _WorkerBootstrap,
    *,
    request: StageSharedCaseOutboxRequest,
    ticket: ApprovalExecutionTicket,
) -> ApprovedCommitResult:
    if (
        bootstrap.session_id is None
        or bootstrap.client_id is None
        or bootstrap.execution_attestor_secret_hex is None
        or bootstrap.execution_attestor_id is None
        or request.action != "COMMIT"
        or request.candidate_ref is None
        or request.scan_ref is None
        or request.review_policy_draft_ref is None
    ):
        raise WorkerProtocolError
    candidate = _read_shared_case_candidate(root, request.candidate_ref)
    review_policy = cast(
        _CaseReviewPolicyDraft,
        _read_archive_model(
            root,
            request.review_policy_draft_ref,
            _CaseReviewPolicyDraft,
        ),
    )
    expected_review = SharedCaseHumanReviewDraft(
        decision=request.decision,
        checked_categories=request.checked_categories,
        residual_risk=request.residual_risk,
        rare_combination_disposition=request.rare_combination_disposition,
        reuse_authorized=request.reuse_authorized,
        allowed_uses=request.allowed_uses,
        expires_at=request.authorization_expires_at,
    )
    if (
        review_policy.candidate_ref != request.candidate_ref.version_ref
        or review_policy.scan_ref != request.scan_ref.version_ref
        or review_policy.human_review != expected_review
        or candidate.candidate_ref != request.candidate_ref.version_ref
        or candidate.candidate_sha256 != request.candidate_ref.content_sha256
    ):
        raise WorkerProtocolError
    _read_archive_bytes(root, request.scan_ref)
    connection = connect_database(root / _CLIENT_DATABASE, "reader")
    try:
        execution = _read_applied_archive_execution(connection, ticket)
        if connection.execute(
            "SELECT b.session_id, c.version, c.candidate_object_id, "
            "c.candidate_sha256, c.candidate_media_type, c.candidate_size_bytes "
            "FROM shared_case_candidates AS c JOIN archive_bundles AS b "
            "ON b.bundle_id = c.bundle_id WHERE c.bundle_id = ? "
            "AND c.candidate_id = ?",
            (request.bundle_id, request.candidate_ref.object_id),
        ).fetchone() != (
            bootstrap.session_id,
            request.candidate_ref.version,
            request.candidate_ref.object_id,
            request.candidate_ref.content_sha256,
            request.candidate_ref.media_type,
            request.candidate_ref.size_bytes,
        ):
            raise WorkerProtocolError
        idempotency_key = (
            f"case-publish:{request.bundle_id}:{request.approval_operation_id}"
        )
        event_rows = connection.execute(
            "SELECT event_id FROM outbox_events WHERE bundle_id = ?",
            (request.bundle_id,),
        ).fetchall()
        if len(event_rows) != 1:
            raise WorkerProtocolError
        outbox = OutboxRepository(connection)
        record = outbox.get(str(event_rows[0][0]))
        if (
            record.idempotency_key != idempotency_key
            or record.state not in {"PENDING", "CLAIMED", "PUBLISHED"}
        ):
            raise WorkerProtocolError
        payload = _case_publish_event_payload(root, record)
        if (
            payload.approval_operation_id != ticket.operation_id
            or payload.approval_request_id != ticket.request_id
            or payload.approval_descriptor_sha256 != ticket.descriptor_sha256
            or payload.approval_draft_sha256
            != ticket.descriptor.draft_sha256
            or not hmac.compare_digest(
                payload.approval_target_scope_hash,
                ticket.target_scope_hash,
            )
            or payload.candidate_ref != request.candidate_ref.version_ref
            or payload.candidate_sha256 != request.candidate_ref.content_sha256
            or payload.candidate_size_bytes != request.candidate_ref.size_bytes
            or payload.idempotency_key != idempotency_key
            or payload.source_review_decision_id != ticket.request_id
        ):
            raise WorkerProtocolError
        transfer, authority = _case_publish_authority(
            connection,
            root,
            bootstrap,
            record=record,
            payload=payload,
            as_of=ticket.receipt.approved_at,
        )
        applied_commit_version = execution.applied_commit_version
        if (
            applied_commit_version is None
            or authority.state != "active"
            or authority.approval_operation_id != ticket.operation_id
            or authority.approval_request_id != ticket.request_id
            or authority.approval_descriptor_sha256
            != ticket.descriptor_sha256
            or authority.approval_draft_sha256
            != ticket.descriptor.draft_sha256
            or authority.approval_descriptor_base_version
            != ticket.descriptor.base_version
            or authority.approval_applied_commit_version
            != applied_commit_version
            or not hmac.compare_digest(
                authority.approval_target_scope_hash,
                ticket.target_scope_hash,
            )
            or authority.authority_epoch != applied_commit_version
            or transfer.candidate != candidate
            or transfer.review.decision != request.decision
            or transfer.review.checked_categories
            != request.checked_categories
            or transfer.review.residual_risk != request.residual_risk
            or transfer.review.rare_combination_disposition
            != request.rare_combination_disposition
            or transfer.authorization.reuse_authorized
            != request.reuse_authorized
            or transfer.authorization.allowed_uses != request.allowed_uses
            or transfer.authorization.expires_at
            != request.authorization_expires_at
            or transfer.release_decision.outcome != "eligible"
        ):
            raise WorkerProtocolError
        publication_proof = outbox.publication_proof(record.event_id)
        if (record.state == "PUBLISHED") != (publication_proof is not None):
            raise WorkerProtocolError
        if publication_proof is not None:
            proof_payload = publication_proof.payload
            if (
                not LocalHmacCasePublicationProofVerifier(
                    secret=bytes.fromhex(
                        bootstrap.execution_attestor_secret_hex
                    ),
                    attestor_id=bootstrap.execution_attestor_id,
                ).verify(publication_proof)
                or proof_payload.source_event_id != record.event_id
                or proof_payload.approval_operation_id != ticket.operation_id
                or proof_payload.approval_request_id != ticket.request_id
                or proof_payload.approval_descriptor_sha256
                != ticket.descriptor_sha256
                or proof_payload.approval_draft_sha256
                != ticket.descriptor.draft_sha256
                or proof_payload.approval_descriptor_base_version
                != ticket.descriptor.base_version
                or proof_payload.approval_applied_commit_version
                != applied_commit_version
                or not hmac.compare_digest(
                    proof_payload.approval_target_scope_hash,
                    ticket.target_scope_hash,
                )
                or proof_payload.published_global_version
                != record.published_global_version
                or proof_payload.authority_epoch != authority.authority_epoch
            ):
                raise WorkerProtocolError
        response = StageSharedCaseOutboxResponse(
            request_id=request.request_id,
            bundle_id=request.bundle_id,
            action="COMMIT",
            event_id=record.event_id,
            payload_ref=_archive_content_ref(
                object_id=record.payload.object_id,
                content_sha256=record.payload.content_sha256,
                size_bytes=record.payload.size_bytes,
            ),
            approval_operation_id=request.approval_operation_id,
            applied_commit_version=applied_commit_version,
            release_outcome="eligible",
            state=record.state,
            attempt_count=record.attempt_count,
            published_global_version=record.published_global_version,
        )
        return _archive_recovery_result(
            bootstrap,
            ticket=ticket,
            execution=execution,
            response=response,
        )
    finally:
        connection.close()


def _recover_client_tombstone_commit(
    root: Path,
    bootstrap: _WorkerBootstrap,
    *,
    request: CommitClientTombstoneRequest,
    ticket: ApprovalExecutionTicket,
    execution: ApprovalExecution,
) -> ApprovedCommitResult:
    connection = connect_database(root / _CLIENT_DATABASE, "reader")
    try:
        plan_row = connection.execute(
            "SELECT version, content_sha256, size_bytes, media_type, purpose, "
            "operation_id, plan_sha256, target_scope_hash "
            "FROM lifecycle_plan_objects WHERE object_id = ?",
            (request.plan_ref.object_id,),
        ).fetchone()
        if plan_row != (
            request.plan_ref.version,
            request.plan_ref.content_sha256,
            request.plan_ref.size_bytes,
            request.plan_ref.media_type,
            "delete",
            request.approval_operation_id,
            request.plan_sha256,
            request.target_scope_hash,
        ):
            raise WorkerProtocolError
        deletion = connection.execute(
            "SELECT plan_sha256, committed_deletion_version, tombstone_epoch, "
            "approval_request_id, approval_target_scope_hash, state "
            "FROM deletion_requests WHERE operation_id = ?",
            (request.approval_operation_id,),
        ).fetchone()
        if (
            deletion is None
            or tuple(deletion[:5])
            != (
                request.plan_sha256,
                execution.applied_commit_version,
                execution.applied_commit_version,
                request.approval_request_id,
                request.target_scope_hash,
            )
            or str(deletion[5])
            not in {"TOMBSTONED", "PHYSICAL_CLEANUP_COMPLETE"}
        ):
            raise WorkerProtocolError
        queue = connection.execute(
            "SELECT COUNT(*) FROM deletion_queue_intents WHERE request_id = ("
            "SELECT request_id FROM deletion_requests WHERE operation_id = ?)",
            (request.approval_operation_id,),
        ).fetchone()
        if queue is None or type(queue[0]) is not int:
            raise WorkerProtocolError
        return _archive_recovery_result(
            bootstrap,
            ticket=ticket,
            execution=execution,
            response=CommitClientTombstoneResponse(
                request_id=request.request_id,
                approval_operation_id=request.approval_operation_id,
                deletion_version=int(deletion[1]),
                tombstone_epoch=int(deletion[2]),
                queue_intent_count=int(queue[0]),
            ),
        )
    finally:
        connection.close()


def _recover_client_rebuild_commit(
    root: Path,
    bootstrap: _WorkerBootstrap,
    *,
    request: RebuildClientDerivativesRequest,
    ticket: ApprovalExecutionTicket,
    execution: ApprovalExecution,
) -> ApprovedCommitResult:
    connection = connect_database(root / _CLIENT_DATABASE, "reader")
    try:
        jobs = RebuildJobRepository(connection, database_scope="client")
        if request.action == "START":
            row = connection.execute(
                "SELECT job_id FROM rebuild_jobs WHERE approval_operation_id = ?",
                (request.approval_operation_id,),
            ).fetchone()
            if row is None:
                raise WorkerProtocolError
            job = jobs.get(str(row[0]))
        elif request.action == "CANCEL" and request.job_id is not None:
            job = jobs.get(request.job_id)
            if job.state != "cancelled" or job.source_intent_id is not None:
                raise WorkerProtocolError
        else:
            raise WorkerProtocolError
        if (
            job.scope_sha256 != bootstrap.scope_marker_sha256
            or request.plan_sha256 != job.plan_sha256
        ):
            raise WorkerProtocolError
        journal = jobs.journal(job.job_id)
        response = RebuildClientDerivativesResponse(
            request_id=request.request_id,
            action=request.action,
            approval_operation_id=request.approval_operation_id,
            applied_commit_version=execution.applied_commit_version,
            job_id=job.job_id,
            plan_sha256=job.plan_sha256,
            state=job.state,
            attempt_count=job.attempt_count,
            output_manifest_set_sha256=job.output_manifest_set_sha256,
            equivalence_report_sha256=job.equivalence_report_sha256,
            last_error_code=job.last_error_code,
            report_sha256=canonical_sha256(
                {
                    "domain": "consultation_kb.client_rebuild_report.v1",
                    "job": job.model_dump(mode="json"),
                    "journal": [
                        value.model_dump(mode="json") for value in journal
                    ],
                }
            ),
        )
        return _archive_recovery_result(
            bootstrap,
            ticket=ticket,
            execution=execution,
            response=response,
        )
    finally:
        connection.close()


def _recover_client_rollback_commit(
    root: Path,
    bootstrap: _WorkerBootstrap,
    *,
    request: CommitClientRollbackRequest,
    ticket: ApprovalExecutionTicket,
    approval_request: ApprovalRequest,
    execution: ApprovalExecution,
) -> ApprovedCommitResult:
    if (
        bootstrap.client_id is None
        or bootstrap.session_id is None
        or bootstrap.execution_attestor_secret_hex is None
        or bootstrap.execution_attestor_id is None
    ):
        raise WorkerProtocolError

    def resolve_ticket(
        operation_id: str,
        receipt_id: str,
    ) -> ApprovalExecutionTicket:
        if operation_id != ticket.operation_id or receipt_id != ticket.request_id:
            raise WorkerProtocolError
        return ticket

    registry = _build_registry(
        root,
        scope_marker_sha256=bootstrap.scope_marker_sha256,
        client_id=bootstrap.client_id,
        bound_session_id=bootstrap.session_id,
        archive_approval_resolver=resolve_ticket,
        rollback_approval_request=approval_request,
        execution_attestor_secret=bytes.fromhex(
            bootstrap.execution_attestor_secret_hex
        ),
        execution_attestor_id=bootstrap.execution_attestor_id,
    )
    response = registry.resolve(request).handler(request)
    if (
        type(response) is not CommitClientRollbackResponse
        or response.applied_commit_version
        != execution.applied_commit_version
    ):
        raise WorkerProtocolError
    return _archive_recovery_result(
        bootstrap,
        ticket=ticket,
        execution=execution,
        response=response,
    )


def _recover_applied_commit(
    root: Path,
    bootstrap: _WorkerBootstrap,
    claim: AppliedCommitRecoveryClaim,
) -> ApprovedCommitResult | AppliedCommitNotAppliedPayload:
    if (
        bootstrap.claim_verification_secret_hex is None
        or bootstrap.execution_attestor_secret_hex is None
        or bootstrap.execution_attestor_id is None
        or bootstrap.client_id is None
    ):
        raise WorkerProtocolError
    payload = LocalHmacAppliedCommitRecoveryVerifier(
        bytes.fromhex(bootstrap.claim_verification_secret_hex)
    ).verify(claim, now=datetime.now(timezone.utc))
    expected_scope_hash = (
        payload.request.target_scope_hash
        if type(payload.request) is CommitClientTombstoneRequest
        else bootstrap.scope_marker_sha256
    )
    if (
        not hmac.compare_digest(
            payload.target_scope_hash,
            expected_scope_hash,
        )
        or payload.descriptor.client_id != bootstrap.client_id
        or payload.ticket.descriptor != payload.descriptor
    ):
        raise WorkerProtocolError
    request = payload.request
    if type(request) is CommitFactMutationRequest:
        return _recover_applied_fact_commit(root, bootstrap, claim)
    _verify_request_session_binding(request, bootstrap)
    probe_connection = connect_database(root / _CLIENT_DATABASE, "reader")
    try:
        execution = _probe_applied_archive_execution(
            probe_connection,
            payload.ticket,
        )
    finally:
        probe_connection.close()
    if execution is None:
        return AppliedCommitNotAppliedPayload(
            claim_id=payload.claim_id,
            claim_nonce_sha256=hashlib.sha256(
                payload.claim_nonce.encode("utf-8", errors="strict")
            ).hexdigest(),
            worker_request_id=request.request_id,
            request_sha256=approved_commit_request_sha256(request),
            approval_request_id=payload.ticket.request_id,
            operation_id=payload.ticket.operation_id,
            descriptor_sha256=payload.ticket.descriptor_sha256,
            draft_sha256=payload.ticket.descriptor.draft_sha256,
            descriptor_base_version=payload.ticket.descriptor.base_version,
            target_scope_hash=payload.ticket.target_scope_hash,
            approval_nonce_sha256=payload.approval_nonce_sha256,
        )
    if type(request) is CommitPrivateArchiveRequest:
        return _recover_private_archive_commit(
            root,
            bootstrap,
            request=request,
            ticket=payload.ticket,
        )
    if type(request) is CommitProfileUpdateRequest:
        return _recover_profile_archive_commit(
            root,
            bootstrap,
            request=request,
            ticket=payload.ticket,
        )
    if type(request) is StageSharedCaseOutboxRequest:
        return _recover_shared_case_commit(
            root,
            bootstrap,
            request=request,
            ticket=payload.ticket,
        )
    if type(request) is CommitClientTombstoneRequest:
        return _recover_client_tombstone_commit(
            root,
            bootstrap,
            request=request,
            ticket=payload.ticket,
            execution=execution,
        )
    if type(request) is RebuildClientDerivativesRequest:
        return _recover_client_rebuild_commit(
            root,
            bootstrap,
            request=request,
            ticket=payload.ticket,
            execution=execution,
        )
    if type(request) is CommitClientRollbackRequest:
        approval_request = payload.approval_request
        if approval_request is None:
            raise WorkerProtocolError
        return _recover_client_rollback_commit(
            root,
            bootstrap,
            request=request,
            ticket=payload.ticket,
            approval_request=approval_request,
            execution=execution,
        )
    raise WorkerProtocolError


def _case_publish_event_payload(
    root: Path,
    record: OutboxRecord,
) -> CasePublishOutboxPayload:
    try:
        body = ContentStore(root / "cas").read_hash_verified(
            record.payload.content_sha256
        )
        payload = CasePublishOutboxPayload.model_validate_json(body, strict=True)
    except Exception:
        raise WorkerProtocolError from None
    if (
        record.payload.media_type != "application/json"
        or len(body) != record.payload.size_bytes
        or case_publish_payload_bytes(payload) != body
        or case_publish_payload_sha256(payload)
        != record.payload.content_sha256
        or record.idempotency_key != payload.idempotency_key
    ):
        raise WorkerProtocolError
    return payload


def _case_publish_transfer(
    root: Path,
    payload: CasePublishOutboxPayload,
) -> CasePublishTransfer:
    store = ContentStore(root / "cas")
    try:
        candidate = _read_shared_case_candidate(
            root,
            _archive_content_ref(
                object_id=payload.candidate_ref.object_id,
                version=payload.candidate_ref.version,
                content_sha256=payload.candidate_sha256,
                size_bytes=payload.candidate_size_bytes,
            ),
        )
        authorization_payload = json.loads(
            store.read_hash_verified(
                payload.authorization_ref.content_sha256
            ).decode("utf-8")
        )
        if (
            type(authorization_payload) is not dict
            or authorization_payload.pop("authorization_id", None)
            != payload.authorization_ref.object_id
            or authorization_payload.pop("version", None)
            != payload.authorization_ref.version
        ):
            raise WorkerProtocolError
        authorization_payload["authorization_ref"] = (
            payload.authorization_ref.model_dump(mode="json")
        )
        authorization = CaseReuseAuthorization.model_validate_json(
            json.dumps(
                authorization_payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ),
            strict=True,
        )
        review_payload = json.loads(
            store.read_hash_verified(payload.review_ref.content_sha256).decode(
                "utf-8"
            )
        )
        if (
            type(review_payload) is not dict
            or review_payload.pop("review_id", None)
            != payload.review_ref.object_id
            or review_payload.pop("version", None) != payload.review_ref.version
        ):
            raise WorkerProtocolError
        review_payload["review_ref"] = payload.review_ref.model_dump(mode="json")
        review = DeidentificationHumanReview.model_validate_json(
            json.dumps(
                review_payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ),
            strict=True,
        )
        release = CaseReleaseDecision.model_validate_json(
            store.read_hash_verified(payload.release_decision_sha256),
            strict=True,
        )
        return CasePublishTransfer(
            outbox_payload=payload,
            candidate=candidate,
            authorization=authorization,
            review=review,
            release_decision=release,
        )
    except Exception:
        raise WorkerProtocolError from None


def _case_publish_authority(
    connection: sqlite3.Connection,
    root: Path,
    bootstrap: _WorkerBootstrap,
    *,
    record: OutboxRecord,
    payload: CasePublishOutboxPayload,
    as_of: datetime,
) -> tuple[CasePublishTransfer, CasePublishAuthoritySnapshot]:
    if bootstrap.client_id is None or bootstrap.session_id is None:
        raise WorkerProtocolError
    source = connection.execute(
        "SELECT b.session_id, s.client_id, s.client_scope_hash, ps.state, "
        "ps.review_decision_id FROM outbox_events AS o "
        "JOIN archive_bundles AS b ON b.bundle_id = o.bundle_id "
        "JOIN sessions AS s ON s.session_id = b.session_id "
        "JOIN archive_purpose_states AS ps ON ps.bundle_id = b.bundle_id "
        "AND ps.purpose = 'shared_case' WHERE o.event_id = ?",
        (record.event_id,),
    ).fetchone()
    if (
        source is None
        or source[0] != bootstrap.session_id
        or source[1] != bootstrap.client_id
        or not hmac.compare_digest(str(source[2]), bootstrap.scope_marker_sha256)
    ):
        raise WorkerProtocolError
    transfer = _case_publish_transfer(root, payload)
    descriptor = DraftDescriptor(
        purpose="case_publish",
        target_id=payload.candidate_ref.object_id,
        client_id=bootstrap.client_id,
        base_version=payload.candidate_ref.version,
        draft_sha256=payload.approval_draft_sha256,
        session_id=bootstrap.session_id,
    )
    execution = connection.execute(
        "SELECT request_id, descriptor_sha256, draft_sha256, "
        "descriptor_base_version, target_scope_hash, state, "
        "applied_commit_version FROM approval_executions WHERE operation_id = ?",
        (payload.approval_operation_id,),
    ).fetchone()
    review_row = connection.execute(
        "SELECT session_id, object_id, decision, decided_at "
        "FROM review_decisions WHERE decision_id = ?",
        (payload.approval_request_id,),
    ).fetchone()
    expected_execution = (
        payload.approval_request_id,
        payload.approval_descriptor_sha256,
        payload.approval_draft_sha256,
        payload.candidate_ref.version,
        payload.approval_target_scope_hash,
        "APPLIED",
    )
    exact_execution = (
        execution is not None
        and tuple(execution[:6]) == expected_execution
        and type(execution[6]) is int
        and execution[6] > 0
        and descriptor_sha256(descriptor) == payload.approval_descriptor_sha256
        and hmac.compare_digest(
            payload.approval_target_scope_hash,
            bootstrap.scope_marker_sha256,
        )
    )
    exact_review = review_row == (
        bootstrap.session_id,
        payload.candidate_ref.object_id,
        "APPROVED",
        _utc_text(transfer.review.reviewed_at),
    ) and source[4] == payload.approval_request_id
    state: Literal["active", "revoked", "expired", "superseded"] = "active"
    authorization = transfer.authorization
    if (
        not exact_execution
        or not exact_review
        or source[3] != "PREPARED"
        or not authorization.reuse_authorized
        or payload.purpose not in authorization.allowed_uses
        or as_of < authorization.valid_from
    ):
        state = "revoked"
    elif authorization.revoked_at is not None and as_of >= authorization.revoked_at:
        state = "revoked"
    elif authorization.expires_at is not None and as_of >= authorization.expires_at:
        state = "expired"
    authority_epoch = 0 if execution is None or type(execution[6]) is not int else int(execution[6])
    return transfer, CasePublishAuthoritySnapshot(
        candidate_ref=payload.candidate_ref,
        authorization_ref=payload.authorization_ref,
        review_ref=payload.review_ref,
        release_policy_ref=payload.release_policy_ref,
        release_decision_sha256=payload.release_decision_sha256,
        provenance_ref=payload.provenance_ref,
        purpose=payload.purpose,
        approval_operation_id=payload.approval_operation_id,
        approval_request_id=payload.approval_request_id,
        approval_descriptor_sha256=payload.approval_descriptor_sha256,
        approval_draft_sha256=payload.approval_draft_sha256,
        approval_descriptor_base_version=payload.candidate_ref.version,
        approval_applied_commit_version=authority_epoch,
        approval_target_scope_hash=payload.approval_target_scope_hash,
        authority_epoch=authority_epoch,
        state=state,
    )


def _execute_case_publish_rpc(
    root: Path,
    bootstrap: _WorkerBootstrap,
    payload: CasePublishRpcPayload,
) -> CasePublishRpcResultPayload:
    if bootstrap.session_id is None:
        raise WorkerProtocolError
    now = datetime.now(timezone.utc)
    connection = connect_database(root / _CLIENT_DATABASE, "writer")
    try:
        repository = OutboxRepository(connection)
        if payload.action == "EXPORT":
            candidates = repository.pending(limit=100)
            selected: OutboxRecord | None = None
            for candidate in candidates:
                if payload.event_id is not None and candidate.event_id != payload.event_id:
                    continue
                session_row = connection.execute(
                    "SELECT b.session_id FROM outbox_events AS o "
                    "JOIN archive_bundles AS b ON b.bundle_id = o.bundle_id "
                    "WHERE o.event_id = ?",
                    (candidate.event_id,),
                ).fetchone()
                if session_row == (bootstrap.session_id,):
                    selected = candidate
                    break
            if selected is None:
                return CasePublishRpcResultPayload(
                    rpc_id=payload.rpc_id,
                    action=payload.action,
                )
            if selected.state in {"PENDING", "FAILED"}:
                selected = repository.claim(selected.event_id, claimed_at=now)
            if selected.state != "CLAIMED":
                raise WorkerProtocolError
            envelope = _case_publish_event_payload(root, selected)
            transfer, authority = _case_publish_authority(
                connection,
                root,
                bootstrap,
                record=selected,
                payload=envelope,
                as_of=now,
            )
            if authority.state != "active":
                raise WorkerProtocolError
            return CasePublishRpcResultPayload(
                rpc_id=payload.rpc_id,
                action=payload.action,
                event=selected,
                transfer=transfer,
                authority=authority,
            )
        if payload.action == "AUTHORITY":
            if payload.payload is None or payload.as_of is None:
                raise WorkerProtocolError
            row = connection.execute(
                "SELECT event_id FROM outbox_events WHERE idempotency_key = ?",
                (payload.payload.idempotency_key,),
            ).fetchone()
            resolved_authority: CasePublishAuthoritySnapshot | None = None
            if row is not None:
                record = repository.get(str(row[0]))
                current_payload = _case_publish_event_payload(root, record)
                if current_payload == payload.payload:
                    _transfer, resolved_authority = _case_publish_authority(
                        connection,
                        root,
                        bootstrap,
                        record=record,
                        payload=current_payload,
                        as_of=payload.as_of,
                    )
            return CasePublishRpcResultPayload(
                rpc_id=payload.rpc_id,
                action=payload.action,
                authority=resolved_authority,
            )
        if (
            payload.event_id is None
            or payload.publication is None
            or bootstrap.execution_attestor_secret_hex is None
            or bootstrap.execution_attestor_id is None
        ):
            raise WorkerProtocolError
        record = repository.get(payload.event_id)
        current_payload = _case_publish_event_payload(root, record)
        _transfer, authority = _case_publish_authority(
            connection,
            root,
            bootstrap,
            record=record,
            payload=current_payload,
            as_of=now,
        )
        publication_proof = payload.publication.proof
        proof_payload = publication_proof.payload
        if (
            not LocalHmacCasePublicationProofVerifier(
                secret=bytes.fromhex(
                    bootstrap.execution_attestor_secret_hex
                ),
                attestor_id=bootstrap.execution_attestor_id,
            ).verify(publication_proof)
            or proof_payload.source_event_id != record.event_id
            or proof_payload.approval_operation_id
            != current_payload.approval_operation_id
            or proof_payload.approval_request_id
            != current_payload.approval_request_id
            or proof_payload.approval_descriptor_sha256
            != current_payload.approval_descriptor_sha256
            or proof_payload.approval_draft_sha256
            != current_payload.approval_draft_sha256
            or proof_payload.approval_descriptor_base_version
            != authority.approval_descriptor_base_version
            or proof_payload.approval_applied_commit_version
            != authority.approval_applied_commit_version
            or not hmac.compare_digest(
                proof_payload.approval_target_scope_hash,
                current_payload.approval_target_scope_hash,
            )
            or proof_payload.authority_epoch != authority.authority_epoch
            or authority.state != "active"
            or payload.publication.source_event_id != record.event_id
            or payload.publication.published_global_version
            != payload.publication.case_ref.version
        ):
            raise WorkerProtocolError
        published = repository.mark_published(
            record.event_id,
            global_version=payload.publication.published_global_version,
            published_at=now,
            publication_proof=publication_proof,
        )
        return CasePublishRpcResultPayload(
            rpc_id=payload.rpc_id,
            action=payload.action,
            event=published,
        )
    finally:
        connection.close()


def worker_process_main(connection: Connection) -> None:
    """Run one scope until EOF, malformed input, or a denied operation."""

    try:
        bootstrap = _decode_bootstrap(connection.recv_bytes(_MAX_BOOTSTRAP_BYTES))
        root = Path(bootstrap.scope_root)
        # Bootstrap verifies the fixed scope marker and current database through
        # their same final handles. The global descriptor is a hash, not a path.
        guard = PathGuard(root)
        lifecycle_bound = (
            bootstrap.client_id is not None and bootstrap.session_id is not None
        )
        with guard.pin_root():
            _verify_current_scope(guard, bootstrap)
            # Recovery intentionally gates query readiness on the active
            # closure.  Finish any durable rebuild first so a process restart
            # after a rollback commit can repair that closure before the gate
            # is evaluated.
            if lifecycle_bound:
                if _client_rebuild_pending(root=root):
                    _drain_client_rebuilds(
                        root=root,
                        scope_marker_sha256=bootstrap.scope_marker_sha256,
                        resolver=_production_client_rebuild_resolver,
                    )
                startup_recovery = _client_recovery_coordinator(
                    root=root,
                    scope_marker_sha256=bootstrap.scope_marker_sha256,
                )
                startup_report = startup_recovery.recover()
                startup_recovery.require_query_ready(startup_report.scan)
        publication_plans: dict[str, ClientPublicationPlan] = {}
        review_diffs: dict[str, tuple[VersionRef, bytes]] = {}
        registry = _build_registry(
            root,
            scope_marker_sha256=bootstrap.scope_marker_sha256,
            client_id=bootstrap.client_id,
            bound_session_id=bootstrap.session_id,
            execution_attestor_secret=(
                None
                if bootstrap.execution_attestor_secret_hex is None
                else bytes.fromhex(bootstrap.execution_attestor_secret_hex)
            ),
            execution_attestor_id=bootstrap.execution_attestor_id,
            publication_plans=publication_plans,
            review_diffs=review_diffs,
        )
        connection.send_bytes(_READY_FRAME)
        if lifecycle_bound:
            _start_client_rebuild_runner(
                root=root,
                scope_marker_sha256=bootstrap.scope_marker_sha256,
                resolver=_production_client_rebuild_resolver,
            )
        while True:
            try:
                request_frame = connection.recv_bytes(MAX_FRAME_BYTES)
            except EOFError:
                return
            # The root is re-pinned and its marker revalidated for every RPC.
            # A path-level A/B swap between calls is therefore rejected before
            # any fixed relative write can target the replacement directory.
            with guard.pin_root():
                _verify_current_scope(guard, bootstrap)
                if is_approved_commit_claim_frame(request_frame):
                    claim = decode_approved_commit_claim(request_frame)
                    result = _execute_approved_commit(root, bootstrap, claim)
                    connection.send_bytes(encode_approved_commit_result(result))
                    continue
                if is_applied_recovery_claim_frame(request_frame):
                    recovery = decode_applied_recovery_claim(request_frame)
                    recovered = _recover_applied_commit(
                        root,
                        bootstrap,
                        recovery,
                    )
                    if isinstance(recovered, AppliedCommitNotAppliedPayload):
                        if bootstrap.claim_verification_secret_hex is None:
                            raise WorkerProtocolError
                        connection.send_bytes(
                            encode_applied_not_applied_result(
                                LocalHmacAppliedCommitNotAppliedResult(
                                    bytes.fromhex(
                                        bootstrap.claim_verification_secret_hex
                                    )
                                ).sign(recovered)
                            )
                        )
                    else:
                        connection.send_bytes(
                            encode_approved_commit_result(recovered)
                        )
                    continue
                if is_review_diff_read_frame(request_frame):
                    review_request = decode_review_diff_read(request_frame)
                    connection.send_bytes(
                        encode_review_diff_result(
                            review_request.reference,
                            _read_registered_review_diff(
                                root,
                                review_request.reference,
                            ),
                        )
                    )
                    continue
                if is_case_publish_rpc_frame(request_frame):
                    if bootstrap.claim_verification_secret_hex is None:
                        raise WorkerProtocolError
                    rpc_codec = LocalHmacCasePublishRpc(
                        bytes.fromhex(bootstrap.claim_verification_secret_hex)
                    )
                    rpc_request = decode_case_publish_rpc(request_frame)
                    rpc_payload = rpc_codec.verify_request(
                        rpc_request,
                        now=datetime.now(timezone.utc),
                    )
                    rpc_result = _execute_case_publish_rpc(
                        root,
                        bootstrap,
                        rpc_payload,
                    )
                    connection.send_bytes(
                        encode_case_publish_result(
                            rpc_codec.sign_result(rpc_result)
                        )
                    )
                    continue
                request = decode_request(request_frame)
                _verify_request_session_binding(request, bootstrap)
                response = registry.dispatch(request)
                connection.send_bytes(encode_message(response))
    except Exception:
        _send_denied(connection)
    finally:
        try:
            connection.close()
        except OSError:
            pass


__all__ = ["worker_process_main"]
