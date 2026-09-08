"""Strict, versioned protocol for one already-scoped consultation worker.

The wire may carry consultation text only after the process has been bound to
one client root. It never accepts a client identity, filesystem path, SQL, or
generic payload field, and every frame remains explicitly size bounded.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Callable, Final, Literal, TypeAlias, cast

from pydantic import (
    Field,
    JsonValue,
    TypeAdapter,
    ValidationError,
    field_serializer,
    field_validator,
    model_validator,
)

from consultation_kb.generation.c1_context import C1ApplicabilityInput
from consultation_kb.generation.contracts import (
    FinalTurnBundle,
    GenerationStagePayload,
    QueryPlan,
)
from consultation_kb.generation.evidence_registry import (
    GenerationEvidenceBindingMismatch,
    GenerationEvidenceContextItem,
    GenerationRetrievalMetadata,
    GenerationRunObject,
    GenerationRiskContextBinding,
    evidence_pack_sha256,
    generation_evidence_context_bytes,
    validate_generation_evidence_context,
    validate_retrieved_generation_evidence_context,
)
from consultation_kb.models.common import (
    NonNegativeInt,
    NonEmptyStr,
    ObjectId,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    Uuid7String,
    VersionRef,
)
from consultation_kb.models.cases import (
    DeidentificationScan,
    ReviewCategory,
    SharedCaseSection,
    SharedCaseSectionDraft,
)
from consultation_kb.models.facts import CognitiveType
from consultation_kb.models.evidence import EvidencePack
from consultation_kb.models.generation import GenerationStageName
from consultation_kb.models.session import (
    ActualReply,
    ActualReplySource,
    CandidateDraft,
    TemporaryFactKind,
    TurnState,
    StoredContentRef,
)
from consultation_kb.retrieval.contracts import CandidateRef
from consultation_kb.session.context import ClientContextSnapshot
from consultation_kb.risk.repository import (
    InternalRiskObservationRecord,
    RiskEvaluationAuthorityBinding,
    canonical_risk_observation_set_sha256,
)


PROTOCOL_VERSION: Final = "1.0"
MAX_FRAME_BYTES: Final = 4_194_304
CLIENT_ACTIVE_INTEGRITY_REBUILD_REQUIRED: Final = (
    "CLIENT_ACTIVE_INTEGRITY_REBUILD_REQUIRED"
)
WorkerOperation: TypeAlias = Literal[
    "ping",
    "get_empty_context_metadata",
    "append_scoped_audit",
    "query_fact_snapshot",
    "preview_fact_mutation",
    "commit_fact_mutation",
    "query_profile_snapshot",
    "query_client_graph",
    "search_client_graph",
    "query_client_weighted_path",
    "query_client_history_candidates",
    "preview_dependency_impact",
    "preview_target_dependency_impact",
    "begin_session",
    "resume_session",
    "append_client_turn",
    "append_temporary_fact",
    "begin_generation",
    "store_candidate_set",
    "record_actual_reply",
    "read_session_state",
    "submit_generation_stage",
    "get_generation_state",
    "acknowledge_risk_observation",
    "get_generation_binding",
    "prepare_generation_retrieval",
    "get_generation_evidence_for_plan",
    "store_generation_evidence_pack",
    "prepare_turn_risk_evaluation",
    "persist_risk_observations",
    "build_private_archive",
    "commit_private_archive",
    "build_profile_diff",
    "commit_profile_update",
    "stage_shared_case_outbox",
    "recover_client_manifests",
    "preflight_client_lifecycle_commit",
    "preview_client_delete",
    "commit_client_tombstone",
    "preview_client_rebuild",
    "rebuild_client_derivatives",
    "preview_client_rollback",
    "commit_client_rollback",
    "verify_client_integrity",
]
ClientHistoryQueryCategory: TypeAlias = Literal[
    "continuity",
    "current_profile",
    "relationship_history",
    "unresolved_items",
]
WorkerPermission: TypeAlias = Literal[
    "client_read",
    "session_append",
    "draft_write",
    "formal_write",
]
OperationalErrorCode: TypeAlias = Literal[
    "PREVIOUS_TURN_NOT_CLOSED",
    "CHANNEL_UNAVAILABLE",
    "QUERY_PLAN_CORRECTION_REQUIRED",
    "GENERATION_STAGE_ORDER_INVALID",
    "GENERATION_PARENT_MISMATCH",
    "QUALITY_RETRY_EXHAUSTED",
    "GENERATION_BINDING_MISMATCH",
    "GENERATION_STAGE_CONFLICT",
    "GENERATION_STAGE_IDEMPOTENCY_CONFLICT",
    "GENERATION_STAGE_REVISION_REASON_REQUIRED",
    "GENERATION_STAGE_REVISION_CLOSED",
    "CLIENT_REPLY_RISK_LEAKAGE",
    "RISK_OBSERVATION_UNAVAILABLE",
    "RISK_LIFECYCLE_CONFLICT",
    "RISK_EVALUATION_INCOMPLETE",
    "CLIENT_ACTIVE_INTEGRITY_REBUILD_REQUIRED",
    "REBUILD_PRODUCTION_BUILDERS_UNAVAILABLE",
    "REBUILD_JOB_NOT_FOUND",
    "REBUILD_JOB_STATE_CONFLICT",
    "REBUILD_CANCELLATION_AFTER_ACTIVATION",
    "REBUILD_SOURCE_INTENT_CANCEL_FORBIDDEN",
    "LIFECYCLE_APPROVAL_REQUIRED",
    "LIFECYCLE_PLAN_MISMATCH",
    "LIFECYCLE_RECOVERY_FAILED",
]


class WorkerProtocolError(RuntimeError):
    """Fixed protocol rejection with no reflected input."""

    def __init__(self) -> None:
        super().__init__("WORKER_PROTOCOL_INVALID")


class WorkerOperationalError(RuntimeError):
    """One closed, caller-content-free operational failure."""

    def __init__(self, code: OperationalErrorCode) -> None:
        self.code = code
        super().__init__(code)


def _generation_context_sha256(
    context: tuple[GenerationEvidenceContextItem, ...],
) -> str:
    try:
        return hashlib.sha256(generation_evidence_context_bytes(context)).hexdigest()
    except GenerationEvidenceBindingMismatch:
        raise ValueError("generation evidence context is not canonical") from None


class _RequestBase(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    request_id: Uuid7String


class PingRequest(_RequestBase):
    operation: Literal["ping"] = "ping"


class EmptyContextMetadataRequest(_RequestBase):
    operation: Literal["get_empty_context_metadata"] = "get_empty_context_metadata"


class AppendScopedAuditRequest(_RequestBase):
    operation: Literal["append_scoped_audit"] = "append_scoped_audit"


class QueryFactSnapshotRequest(_RequestBase):
    operation: Literal["query_fact_snapshot"] = "query_fact_snapshot"
    effective_at: UtcDateTime
    known_at: UtcDateTime
    fixed_epoch: NonNegativeInt


class PreviewFactMutationRequest(_RequestBase):
    operation: Literal["preview_fact_mutation"] = "preview_fact_mutation"
    draft_event_id: ObjectId
    base_commit_version: NonNegativeInt
    proposed_operation_id: ObjectId


class CommitFactMutationRequest(_RequestBase):
    operation: Literal["commit_fact_mutation"] = "commit_fact_mutation"
    draft_event_id: ObjectId
    approval_operation_id: ObjectId
    preview_sha256: Sha256Hex
    base_commit_version: NonNegativeInt
    expected_runtime_epoch: PositiveInt
    publication_timestamp: UtcDateTime


class ArchiveContentRef(StrictModel):
    """Exact scoped-CAS reference accepted by archive operations.

    The reference deliberately carries no client identity or filesystem path.
    The worker must resolve it inside its already-pinned client root and verify
    all bytes before parsing the requested governed object.
    """

    object_id: ObjectId
    version: PositiveInt
    content_sha256: Sha256Hex
    media_type: Literal["application/json"] = "application/json"
    size_bytes: PositiveInt

    @property
    def version_ref(self) -> VersionRef:
        return VersionRef(
            object_id=self.object_id,
            version=self.version,
            content_sha256=self.content_sha256,
        )


class WorkerBaseVersion(StrictModel):
    authority_key: SafePolicyKey
    scope_sha256: Sha256Hex
    version: NonNegativeInt


class RecoverClientManifestsRequest(_RequestBase):
    operation: Literal["recover_client_manifests"] = "recover_client_manifests"
    dry_run: bool = True


class PreviewClientDeleteRequest(_RequestBase):
    operation: Literal["preview_client_delete"] = "preview_client_delete"
    target_type: Literal["session"]
    target_id: Uuid7String
    target_version: NonNegativeInt
    target_content_sha256: Sha256Hex
    reason_code: SafePolicyKey
    proposed_operation_id: ObjectId
    requested_at: UtcDateTime


class PreflightClientLifecycleCommitRequest(_RequestBase):
    """Body-free exact-plan check before a one-shot receipt is bound."""

    operation: Literal["preflight_client_lifecycle_commit"] = (
        "preflight_client_lifecycle_commit"
    )
    lifecycle_kind: Literal["delete", "rebuild", "rollback"]
    plan_ref: ArchiveContentRef
    plan_sha256: Sha256Hex
    base_versions: tuple[WorkerBaseVersion, ...]
    approval_operation_id: ObjectId
    approval_request_id: ObjectId
    rebuild_action: Literal["START", "CANCEL"] | None = None
    target_scope_hash: Sha256Hex | None = None

    @model_validator(mode="after")
    def _exact_kind_shape(self) -> "PreflightClientLifecycleCommitRequest":
        keys = tuple(
            (value.authority_key, value.scope_sha256)
            for value in self.base_versions
        )
        valid_shape = (
            (
                self.lifecycle_kind == "delete"
                and self.target_scope_hash is not None
                and self.rebuild_action is None
            )
            or (
                self.lifecycle_kind == "rebuild"
                and self.rebuild_action in {"START", "CANCEL"}
                and self.target_scope_hash is None
            )
            or (
                self.lifecycle_kind == "rollback"
                and self.rebuild_action is None
                and self.target_scope_hash is None
            )
        )
        if not keys or keys != tuple(sorted(set(keys))) or not valid_shape:
            raise ValueError("client lifecycle preflight payload is not exact")
        return self


class CommitClientTombstoneRequest(_RequestBase):
    operation: Literal["commit_client_tombstone"] = "commit_client_tombstone"
    plan_ref: ArchiveContentRef
    plan_sha256: Sha256Hex
    target_scope_hash: Sha256Hex
    base_versions: tuple[WorkerBaseVersion, ...]
    approval_operation_id: ObjectId
    approval_request_id: ObjectId

    @model_validator(mode="after")
    def _canonical_versions(self) -> "CommitClientTombstoneRequest":
        keys = tuple(
            (value.authority_key, value.scope_sha256)
            for value in self.base_versions
        )
        if not keys or keys != tuple(sorted(set(keys))):
            raise ValueError("client deletion base versions are not canonical")
        return self


class PreviewClientRebuildRequest(_RequestBase):
    operation: Literal["preview_client_rebuild"] = "preview_client_rebuild"
    action: Literal["start", "cancel"]
    purpose: SafePolicyKey | None = None
    source_intent_id: ObjectId | None = None
    job_id: ObjectId | None = None
    policy_sha256: Sha256Hex | None = None
    model_descriptor_sha256: Sha256Hex | None = None
    proposed_operation_id: ObjectId
    requested_at: UtcDateTime

    @model_validator(mode="after")
    def _exact_action(self) -> "PreviewClientRebuildRequest":
        if self.action == "start":
            if self.purpose != "all" or self.job_id is not None:
                raise ValueError("client full-closure rebuild preview required")
        elif (
            self.job_id is None
            or self.purpose is not None
            or self.source_intent_id is not None
            or self.policy_sha256 is not None
            or self.model_descriptor_sha256 is not None
        ):
            raise ValueError("client cancel rebuild preview is not exact")
        return self


class RebuildClientDerivativesRequest(_RequestBase):
    operation: Literal["rebuild_client_derivatives"] = (
        "rebuild_client_derivatives"
    )
    action: Literal["START", "STATUS", "REPORT", "CANCEL"]
    job_id: ObjectId | None = None
    purpose: SafePolicyKey | None = None
    plan_sha256: Sha256Hex | None = None
    base_versions: tuple[WorkerBaseVersion, ...] = ()
    policy_sha256: Sha256Hex | None = None
    model_descriptor_sha256: Sha256Hex | None = None
    idempotency_key: NonEmptyStr | None = None
    approval_operation_id: ObjectId | None = None
    approval_request_id: ObjectId | None = None
    plan_ref: ArchiveContentRef | None = None

    @model_validator(mode="after")
    def _exact_action_shape(self) -> "RebuildClientDerivativesRequest":
        keys = tuple(
            (value.authority_key, value.scope_sha256)
            for value in self.base_versions
        )
        if keys != tuple(sorted(set(keys))):
            raise ValueError("client rebuild base versions are not canonical")
        if self.action in {"START", "CANCEL"} and (
            len(self.base_versions) != 1
            or self.base_versions[0].authority_key != "tombstone_epoch"
        ):
            raise ValueError("single tombstone epoch base version required")
        if self.action == "START":
            valid = (
                self.job_id is None
                and self.purpose is not None
                and self.plan_sha256 is not None
                and bool(self.base_versions)
                and self.idempotency_key is not None
                and self.approval_operation_id is not None
                and self.approval_request_id is not None
                and self.plan_ref is not None
                and self.policy_sha256 is None
                and self.model_descriptor_sha256 is None
            )
        elif self.action in {"STATUS", "REPORT"}:
            valid = (
                self.job_id is not None
                and self.purpose is None
                and self.plan_sha256 is None
                and not self.base_versions
                and self.policy_sha256 is None
                and self.model_descriptor_sha256 is None
                and self.idempotency_key is None
                and self.approval_operation_id is None
                and self.approval_request_id is None
                and self.plan_ref is None
            )
        else:
            valid = (
                self.job_id is not None
                and self.purpose is None
                and self.plan_sha256 is not None
                and bool(self.base_versions)
                and self.policy_sha256 is None
                and self.model_descriptor_sha256 is None
                and self.idempotency_key is None
                and self.approval_operation_id is not None
                and self.approval_request_id is not None
                and self.plan_ref is not None
            )
        if not valid:
            raise ValueError("client rebuild payload does not match action")
        return self


class PreviewClientRollbackRequest(_RequestBase):
    """Body-free rollback preview inside one already pinned client scope."""

    operation: Literal["preview_client_rollback"] = "preview_client_rollback"
    rollback_kind: Literal["profile_fact", "artifact"]
    target_id: NonEmptyStr
    current_version: PositiveInt
    restore_version: PositiveInt
    reason: NonEmptyStr
    source_plan_ref: ArchiveContentRef | None = None

    @model_validator(mode="after")
    def _exact_kind_shape(self) -> "PreviewClientRollbackRequest":
        if (
            self.restore_version >= self.current_version
            or (self.rollback_kind == "artifact")
            != (self.source_plan_ref is not None)
        ):
            raise ValueError("client rollback preview payload is not exact")
        return self


class CommitClientRollbackRequest(_RequestBase):
    """Exact reviewed rollback plan; target identity cannot be resubmitted."""

    operation: Literal["commit_client_rollback"] = "commit_client_rollback"
    plan_ref: ArchiveContentRef
    plan_sha256: Sha256Hex
    base_versions: tuple[WorkerBaseVersion, ...]
    approval_operation_id: ObjectId
    approval_request_id: ObjectId

    @model_validator(mode="after")
    def _canonical_versions(self) -> "CommitClientRollbackRequest":
        keys = tuple(
            (value.authority_key, value.scope_sha256)
            for value in self.base_versions
        )
        if not keys or keys != tuple(sorted(set(keys))):
            raise ValueError("client rollback base versions are not canonical")
        return self


class VerifyClientIntegrityRequest(_RequestBase):
    operation: Literal["verify_client_integrity"] = "verify_client_integrity"


class BuildPrivateArchiveRequest(_RequestBase):
    operation: Literal["build_private_archive"] = "build_private_archive"
    session_handle: NonEmptyStr
    analysis_ref: ArchiveContentRef | None = None


class CommitPrivateArchiveRequest(_RequestBase):
    operation: Literal["commit_private_archive"] = "commit_private_archive"
    session_handle: NonEmptyStr
    bundle_id: ObjectId
    draft_ref: ArchiveContentRef
    base_version: NonNegativeInt
    approval_operation_id: ObjectId
    approval_request_id: ObjectId


class BuildProfileDiffRequest(_RequestBase):
    operation: Literal["build_profile_diff"] = "build_profile_diff"
    session_handle: NonEmptyStr
    action: Literal["BUILD", "PREPARE_APPROVAL"] = "BUILD"
    build_input_ref: ArchiveContentRef | None = None
    draft_ref: ArchiveContentRef | None = None
    selected_operation_ids: tuple[NonEmptyStr, ...] = ()
    dismissed_indirect_review_fact_ids: tuple[NonEmptyStr, ...] = ()

    @model_validator(mode="after")
    def _exact_profile_action(self) -> "BuildProfileDiffRequest":
        if self.action == "BUILD":
            if (
                self.build_input_ref is None
                or self.draft_ref is not None
                or self.selected_operation_ids
                or self.dismissed_indirect_review_fact_ids
            ):
                raise ValueError("profile build action is malformed")
        elif (
            self.build_input_ref is not None
            or self.draft_ref is None
            or not self.selected_operation_ids
            or len(self.selected_operation_ids)
            != len(set(self.selected_operation_ids))
            or len(self.dismissed_indirect_review_fact_ids)
            != len(set(self.dismissed_indirect_review_fact_ids))
        ):
            raise ValueError("profile approval preparation is malformed")
        return self


class CommitProfileUpdateRequest(_RequestBase):
    operation: Literal["commit_profile_update"] = "commit_profile_update"
    session_handle: NonEmptyStr
    bundle_id: ObjectId
    draft_ref: ArchiveContentRef
    selected_operation_ids: tuple[NonEmptyStr, ...]
    dismissed_indirect_review_fact_ids: tuple[NonEmptyStr, ...] = ()
    approval_operation_id: ObjectId
    approval_request_id: ObjectId
    expected_runtime_epoch: PositiveInt
    publication_timestamp: UtcDateTime

    @model_validator(mode="after")
    def _canonical_profile_selection(self) -> "CommitProfileUpdateRequest":
        if (
            not self.selected_operation_ids
            or len(self.selected_operation_ids)
            != len(set(self.selected_operation_ids))
            or len(self.dismissed_indirect_review_fact_ids)
            != len(set(self.dismissed_indirect_review_fact_ids))
        ):
            raise ValueError("profile commit selection is invalid")
        return self


class StageSharedCaseOutboxRequest(_RequestBase):
    operation: Literal["stage_shared_case_outbox"] = "stage_shared_case_outbox"
    session_handle: NonEmptyStr
    bundle_id: ObjectId
    action: Literal["PREPARE", "COMMIT"]
    section_drafts: tuple[SharedCaseSectionDraft, ...] = ()
    decision: Literal["approved", "rejected", "quarantine"]
    checked_categories: frozenset[ReviewCategory]
    residual_risk: Literal["low", "medium", "high"]
    rare_combination_disposition: Literal[
        "not_present", "mitigated", "unresolved"
    ]
    reuse_authorized: bool
    allowed_uses: frozenset[SafePolicyKey]
    authorization_expires_at: UtcDateTime | None = None
    candidate_ref: ArchiveContentRef | None = None
    scan_ref: ArchiveContentRef | None = None
    review_policy_draft_ref: ArchiveContentRef | None = None
    approval_operation_id: ObjectId | None = None
    approval_request_id: ObjectId | None = None

    @field_validator("section_drafts", mode="before")
    @classmethod
    def _json_sections(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value

    @field_validator("checked_categories", "allowed_uses", mode="before")
    @classmethod
    def _json_case_sets(cls, value: object) -> object:
        return frozenset(value) if type(value) is list else value

    @field_serializer("checked_categories", "allowed_uses")
    def _canonical_case_sets(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @model_validator(mode="after")
    def _exact_case_action(self) -> "StageSharedCaseOutboxRequest":
        commit_fields = (
            self.candidate_ref,
            self.scan_ref,
            self.review_policy_draft_ref,
            self.approval_operation_id,
            self.approval_request_id,
        )
        if self.action == "PREPARE":
            malformed = not self.section_drafts or any(
                value is not None for value in commit_fields
            )
            if malformed:
                raise ValueError("case prepare action is malformed")
        elif self.section_drafts or any(value is None for value in commit_fields):
            raise ValueError("case commit action is malformed")
        if self.reuse_authorized:
            if (
                self.decision != "approved"
                or not self.allowed_uses
                or self.authorization_expires_at is None
            ):
                raise ValueError("case reuse authorization is incomplete")
        elif self.allowed_uses or self.authorization_expires_at is not None:
            raise ValueError("case reuse denial cannot grant authority")
        return self


class QueryProfileSnapshotRequest(_RequestBase):
    operation: Literal["query_profile_snapshot"] = "query_profile_snapshot"
    effective_at: UtcDateTime
    known_at: UtcDateTime
    fixed_epoch: NonNegativeInt


class QueryClientGraphRequest(_RequestBase):
    operation: Literal["query_client_graph"] = "query_client_graph"
    effective_at: UtcDateTime
    known_at: UtcDateTime
    fixed_epoch: NonNegativeInt


class SearchClientGraphRequest(_RequestBase):
    """Search the current scoped temporal graph without exposing its subject."""

    operation: Literal["search_client_graph"] = "search_client_graph"
    query: NonEmptyStr
    as_of: UtcDateTime
    max_depth: PositiveInt = 2
    limit: PositiveInt = 10

    @model_validator(mode="after")
    def _bounded_search(self) -> "SearchClientGraphRequest":
        if self.max_depth > 8 or self.limit > 100:
            raise ValueError("client graph search exceeds its fixed bound")
        return self


class QueryClientWeightedPathRequest(_RequestBase):
    operation: Literal["query_client_weighted_path"] = "query_client_weighted_path"
    source_ref: ObjectId
    target_ref: ObjectId
    as_of: UtcDateTime
    max_paths: PositiveInt = 3
    max_hops: PositiveInt = 8

    @model_validator(mode="after")
    def _bounded_path(self) -> "QueryClientWeightedPathRequest":
        if self.source_ref == self.target_ref:
            raise ValueError("client graph path endpoints must differ")
        if self.max_paths > 10 or self.max_hops > 12:
            raise ValueError("client graph path exceeds its fixed bound")
        return self


class QueryClientHistoryCandidatesRequest(_RequestBase):
    """Scope-preserving request with no client, path, SQL, or generic payload."""

    operation: Literal["query_client_history_candidates"] = (
        "query_client_history_candidates"
    )
    session_handle: NonEmptyStr
    query_category: ClientHistoryQueryCategory
    as_of: UtcDateTime | None = None


class PreviewDependencyImpactRequest(_RequestBase):
    operation: Literal["preview_dependency_impact"] = "preview_dependency_impact"
    draft_event_id: ObjectId
    preview_sha256: Sha256Hex
    publication_operation_id: ObjectId
    diff_object_ref: VersionRef


class PreviewTargetDependencyImpactRequest(_RequestBase):
    operation: Literal["preview_target_dependency_impact"] = (
        "preview_target_dependency_impact"
    )
    target_ref: VersionRef
    action: Literal["supersede", "invalidate", "resolve", "revoke"]
    as_of: UtcDateTime


class BeginSessionRequest(_RequestBase):
    operation: Literal["begin_session"] = "begin_session"
    session_id: Uuid7String
    capability_epoch: PositiveInt


class ResumeSessionRequest(_RequestBase):
    operation: Literal["resume_session"] = "resume_session"
    session_id: Uuid7String
    previous_capability_epoch: PositiveInt
    capability_epoch: PositiveInt

    @model_validator(mode="after")
    def _increases_epoch(self) -> "ResumeSessionRequest":
        if self.capability_epoch <= self.previous_capability_epoch:
            raise ValueError("resume must increase capability epoch")
        return self


class AppendClientTurnRequest(_RequestBase):
    operation: Literal["append_client_turn"] = "append_client_turn"
    session_id: Uuid7String
    turn_id: Uuid7String
    client_message: NonEmptyStr
    risk_authority: RiskEvaluationAuthorityBinding


class AppendTemporaryFactRequest(_RequestBase):
    operation: Literal["append_temporary_fact"] = "append_temporary_fact"
    session_id: Uuid7String
    turn_id: Uuid7String
    idempotency_key: NonEmptyStr
    event_kind: TemporaryFactKind
    cognitive_type: CognitiveType
    value: JsonValue
    target_fact_id: NonEmptyStr | None = None
    target_fact_version: PositiveInt | None = None

    @model_validator(mode="after")
    def _target_shape(self) -> "AppendTemporaryFactRequest":
        requires_target = self.event_kind in {
            "CORRECT",
            "SUPERSEDE",
            "RESOLVE",
            "POSSIBLY_INVALID",
            "CONFLICT",
        }
        if requires_target != (self.target_fact_id is not None):
            raise ValueError("temporary event target does not match event kind")
        if (self.target_fact_id is None) != (self.target_fact_version is None):
            raise ValueError("temporary target fact fields must be paired")
        return self


class BeginGenerationRequest(_RequestBase):
    operation: Literal["begin_generation"] = "begin_generation"
    session_id: Uuid7String
    turn_id: Uuid7String
    run_id: Uuid7String


class StoreCandidateSetRequest(_RequestBase):
    operation: Literal["store_candidate_set"] = "store_candidate_set"
    session_id: Uuid7String
    turn_id: Uuid7String
    run_id: Uuid7String
    idempotency_key: NonEmptyStr
    candidates: tuple[CandidateDraft, ...]

    @model_validator(mode="after")
    def _bounded_candidates(self) -> "StoreCandidateSetRequest":
        if not 2 <= len(self.candidates) <= 3:
            raise ValueError("candidate count must be between two and three")
        labels = tuple(candidate.label for candidate in self.candidates)
        if len(labels) != len(set(labels)):
            raise ValueError("candidate labels must be unique")
        return self


class RecordActualReplyRequest(_RequestBase):
    operation: Literal["record_actual_reply"] = "record_actual_reply"
    session_id: Uuid7String
    turn_id: Uuid7String
    idempotency_key: NonEmptyStr
    mode: Literal["adopted", "edited", "external_unknown"]
    candidate_id: ObjectId | None = None
    actual_text: NonEmptyStr | None = None
    sent_at: UtcDateTime | None = None
    confirmed_at: UtcDateTime | None = None

    @model_validator(mode="after")
    def _valid_mode_payload(self) -> "RecordActualReplyRequest":
        if self.mode == "adopted":
            valid = (
                self.candidate_id is not None
                and self.actual_text is None
                and self.sent_at is not None
                and self.confirmed_at is None
            )
        elif self.mode == "edited":
            valid = (
                self.candidate_id is not None
                and self.actual_text is not None
                and self.sent_at is not None
                and self.confirmed_at is None
            )
        else:
            valid = (
                self.candidate_id is None
                and self.actual_text is None
                and self.sent_at is None
                and self.confirmed_at is not None
            )
        if not valid:
            raise ValueError("actual reply payload does not match mode")
        return self


class ReadSessionStateRequest(_RequestBase):
    operation: Literal["read_session_state"] = "read_session_state"
    session_id: Uuid7String


class SubmitGenerationStageRequest(_RequestBase):
    operation: Literal["submit_generation_stage"] = "submit_generation_stage"
    session_id: Uuid7String
    idempotency_key: NonEmptyStr
    stage_payload: GenerationStagePayload
    revision_reason: NonEmptyStr | None = None
    risk_authority: RiskEvaluationAuthorityBinding | None = None

    @model_validator(mode="after")
    def _query_plan_risk_authority(self) -> "SubmitGenerationStageRequest":
        if isinstance(self.stage_payload, QueryPlan) != (
            self.risk_authority is not None
        ):
            raise ValueError("query plan requires one exact risk authority")
        if (
            isinstance(self.stage_payload, QueryPlan)
            and self.risk_authority is not None
            and self.risk_authority.global_runtime_epoch
            != self.stage_payload.global_runtime_epoch
        ):
            raise ValueError("query plan and risk authority epochs differ")
        return self


class GetGenerationStateRequest(_RequestBase):
    operation: Literal["get_generation_state"] = "get_generation_state"
    session_id: Uuid7String
    turn_id: Uuid7String
    run_id: Uuid7String


class AcknowledgeRiskObservationRequest(_RequestBase):
    operation: Literal["acknowledge_risk_observation"] = (
        "acknowledge_risk_observation"
    )
    session_id: Uuid7String
    observation_id: ObjectId
    action: Literal["acknowledge", "close"]
    counselor_disposition: NonEmptyStr | None = None
    rejection_reason: NonEmptyStr | None = None
    close_decision: SafePolicyKey | None = None
    close_reason: NonEmptyStr | None = None

    @model_validator(mode="after")
    def _manual_decision(self) -> "AcknowledgeRiskObservationRequest":
        acknowledgement = (self.counselor_disposition, self.rejection_reason)
        closure = (self.close_decision, self.close_reason)
        if self.action == "acknowledge":
            if not any(value is not None for value in acknowledgement):
                raise ValueError("risk acknowledgement requires a manual decision")
            if any(value is not None for value in closure):
                raise ValueError("risk acknowledgement cannot contain close fields")
        elif any(value is not None for value in acknowledgement):
            raise ValueError("risk close cannot contain acknowledgement fields")
        elif any(value is None for value in closure):
            raise ValueError("risk close requires an exact decision and reason")
        return self


class GetGenerationBindingRequest(_RequestBase):
    """Read only the opaque client-local half of a generation binding."""

    operation: Literal["get_generation_binding"] = "get_generation_binding"
    session_id: Uuid7String
    turn_id: Uuid7String


class PrepareGenerationRetrievalRequest(_RequestBase):
    """Resolve bounded private evidence inside the already-scoped worker."""

    operation: Literal["prepare_generation_retrieval"] = (
        "prepare_generation_retrieval"
    )
    session_id: Uuid7String
    turn_id: Uuid7String
    run_id: Uuid7String
    query_plan_sha256: Sha256Hex
    risk_authority: RiskEvaluationAuthorityBinding
    query_categories: tuple[ClientHistoryQueryCategory, ...]

    @model_validator(mode="after")
    def _categories(self) -> "PrepareGenerationRetrievalRequest":
        if (
            not self.query_categories
            or len(self.query_categories) != len(set(self.query_categories))
            or self.query_categories != tuple(sorted(self.query_categories))
        ):
            raise ValueError("generation retrieval categories must be canonical")
        return self


class StoreGenerationEvidencePackRequest(_RequestBase):
    """Internal-only registration of one real retrieval result."""

    operation: Literal["store_generation_evidence_pack"] = (
        "store_generation_evidence_pack"
    )
    session_id: Uuid7String
    turn_id: Uuid7String
    run_id: Uuid7String
    query_plan_sha256: Sha256Hex
    evidence_pack: EvidencePack
    evidence_context: tuple[GenerationEvidenceContextItem, ...]
    run_objects: tuple[GenerationRunObject, ...]
    retrieval_metadata: GenerationRetrievalMetadata

    @model_validator(mode="after")
    def _pack_scope(self) -> "StoreGenerationEvidencePackRequest":
        if self.evidence_pack.run_id != self.run_id:
            raise ValueError("EvidencePack is bound to a different run")
        try:
            validate_retrieved_generation_evidence_context(
                self.evidence_pack,
                self.evidence_context,
            )
        except GenerationEvidenceBindingMismatch:
            raise ValueError("generation evidence context mismatch") from None
        keys = tuple(
            (item.object_type, item.reference.object_id)
            for item in self.run_objects
        )
        if keys != tuple(sorted(set(keys))):
            raise ValueError("generation run objects must be canonical")
        return self


class GetGenerationEvidenceForPlanRequest(_RequestBase):
    """Recover the immutable pack already registered for one exact plan."""

    operation: Literal["get_generation_evidence_for_plan"] = (
        "get_generation_evidence_for_plan"
    )
    session_id: Uuid7String
    turn_id: Uuid7String
    run_id: Uuid7String
    query_plan_sha256: Sha256Hex


class PersistRiskObservationsRequest(_RequestBase):
    """Internal-only persistence of deterministic, authority-checked findings."""

    operation: Literal["persist_risk_observations"] = "persist_risk_observations"
    session_id: Uuid7String
    turn_id: Uuid7String
    risk_authority: RiskEvaluationAuthorityBinding
    observations: tuple[InternalRiskObservationRecord, ...]

    @model_validator(mode="after")
    def _turn_authority_closure(self) -> "PersistRiskObservationsRequest":
        identifiers = tuple(
            item.observation.observation_id for item in self.observations
        )
        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("risk observations must be canonical")
        for item in self.observations:
            source_kinds = {source.source_kind for source in item.sources}
            if (
                item.session_id != self.session_id
                or item.status != "open"
                or not source_kinds
                or not source_kinds.issubset(
                    {"deterministic_rule", "model_observation"}
                )
                or (
                    "deterministic_rule" in source_kinds
                    and item.confidence != 1.0
                )
                or set(item.observation.trigger_turn_ids) != {self.turn_id}
                or (
                    "model_observation" in source_kinds
                    and (
                        self.risk_authority.model_mode != "approved_model"
                        or self.risk_authority.approved_model_ref is None
                        or any(
                            source.source_ref
                            != self.risk_authority.approved_model_ref
                            for source in item.sources
                            if source.source_kind == "model_observation"
                        )
                    )
                )
            ):
                raise ValueError("risk observations are not authority-bound findings")
        return self


class PrepareTurnRiskEvaluationRequest(_RequestBase):
    """Internal-only recovery of one exact turn for authority-bound evaluation."""

    operation: Literal["prepare_turn_risk_evaluation"] = (
        "prepare_turn_risk_evaluation"
    )
    session_id: Uuid7String
    turn_id: Uuid7String
    risk_authority: RiskEvaluationAuthorityBinding


class _SuccessResponseBase(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    success: Literal[True] = True
    request_id: Uuid7String


class PingResponse(_SuccessResponseBase):
    response_type: Literal["ping"] = "ping"
    status: Literal["ok"] = "ok"


class EmptyContextMetadataResponse(_SuccessResponseBase):
    response_type: Literal["get_empty_context_metadata"] = (
        "get_empty_context_metadata"
    )
    session_count: Literal[0] = 0
    fact_count: Literal[0] = 0
    object_count: Literal[0] = 0


class AppendScopedAuditResponse(_SuccessResponseBase):
    response_type: Literal["append_scoped_audit"] = "append_scoped_audit"
    appended: Literal[True] = True


class QueryFactSnapshotResponse(_SuccessResponseBase):
    response_type: Literal["query_fact_snapshot"] = "query_fact_snapshot"
    snapshot_sha256: Sha256Hex
    client_commit_version: NonNegativeInt
    event_count: NonNegativeInt


class PreviewFactMutationResponse(_SuccessResponseBase):
    response_type: Literal["preview_fact_mutation"] = "preview_fact_mutation"
    preview_sha256: Sha256Hex
    base_commit_version: NonNegativeInt
    publication_operation_id: ObjectId
    expected_runtime_epoch: PositiveInt
    publication_timestamp: UtcDateTime
    diff_object_ref: VersionRef
    duplicate_candidate_count: NonNegativeInt
    conflict_candidate_count: NonNegativeInt
    direct_invalidation_count: NonNegativeInt
    manual_review_count: NonNegativeInt


class CommitFactMutationResponse(_SuccessResponseBase):
    response_type: Literal["commit_fact_mutation"] = "commit_fact_mutation"
    approval_operation_id: ObjectId
    new_commit_version: PositiveInt
    runtime_epoch: PositiveInt
    event_count: PositiveInt


class BuildPrivateArchiveResponse(_SuccessResponseBase):
    response_type: Literal["build_private_archive"] = "build_private_archive"
    bundle_id: ObjectId
    actual_transcript_ref: VersionRef
    draft_ref: ArchiveContentRef
    review_diff_ref: VersionRef
    base_version: NonNegativeInt
    incomplete_evidence: bool
    private_archive_state: Literal["DRAFT", "PREPARED", "ACTIVE", "REJECTED"]


class CommitPrivateArchiveResponse(_SuccessResponseBase):
    response_type: Literal["commit_private_archive"] = "commit_private_archive"
    bundle_id: ObjectId
    approval_operation_id: ObjectId
    applied_commit_version: PositiveInt
    revision_ref: VersionRef
    manifest_ref: VersionRef
    state: Literal["ACTIVE"] = "ACTIVE"


class BuildProfileDiffResponse(_SuccessResponseBase):
    response_type: Literal["build_profile_diff"] = "build_profile_diff"
    bundle_id: ObjectId
    draft_ref: ArchiveContentRef
    diff_id: ObjectId
    diff_sha256: Sha256Hex
    base_profile_sha256: Sha256Hex
    base_session_sha256: Sha256Hex
    base_client_commit_version: NonNegativeInt
    operation_count: NonNegativeInt
    operation_ids: tuple[NonEmptyStr, ...]
    indirect_review_fact_ids: tuple[NonEmptyStr, ...]
    direct_impact_fact_ids: tuple[NonEmptyStr, ...]
    pending_indirect_review_count: NonNegativeInt
    unapproved_direct_impact_count: NonNegativeInt
    approval_draft_sha256: Sha256Hex | None = None
    approval_diff_ref: VersionRef | None = None

    @model_validator(mode="after")
    def _approval_preview_pair(self) -> "BuildProfileDiffResponse":
        if (self.approval_draft_sha256 is None) != (
            self.approval_diff_ref is None
        ):
            raise ValueError("profile approval preview is incomplete")
        if self.operation_count != len(self.operation_ids):
            raise ValueError("profile operation count mismatch")
        return self


class CommitProfileUpdateResponse(_SuccessResponseBase):
    response_type: Literal["commit_profile_update"] = "commit_profile_update"
    bundle_id: ObjectId
    approval_operation_id: ObjectId
    new_commit_version: PositiveInt
    runtime_epoch: PositiveInt
    event_count: PositiveInt
    manifest_ids: tuple[ObjectId, ...]
    state: Literal["ACTIVE"] = "ACTIVE"

    @field_validator("manifest_ids")
    @classmethod
    def _canonical_manifest_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or value != tuple(sorted(set(value))):
            raise ValueError("profile publication manifests must be canonical")
        return value


class RecoverClientManifestsResponse(_SuccessResponseBase):
    response_type: Literal["recover_client_manifests"] = (
        "recover_client_manifests"
    )
    dry_run: bool
    scanned_count: NonNegativeInt
    applied_count: NonNegativeInt
    startup_health: Literal["HEALTHY", "DEGRADED"]
    report_sha256: Sha256Hex

    @model_validator(mode="after")
    def _dry_run_does_not_apply(self) -> "RecoverClientManifestsResponse":
        if self.dry_run and self.applied_count != 0:
            raise ValueError("dry-run recovery cannot apply decisions")
        return self


class PreflightClientLifecycleCommitResponse(_SuccessResponseBase):
    response_type: Literal["preflight_client_lifecycle_commit"] = (
        "preflight_client_lifecycle_commit"
    )
    lifecycle_kind: Literal["delete", "rebuild", "rollback"]
    approval_operation_id: ObjectId
    plan_sha256: Sha256Hex


class PreviewClientDeleteResponse(_SuccessResponseBase):
    response_type: Literal["preview_client_delete"] = "preview_client_delete"
    plan_ref: ArchiveContentRef
    plan_sha256: Sha256Hex
    target_scope_hash: Sha256Hex
    proposed_operation_id: ObjectId
    base_deletion_version: NonNegativeInt
    base_versions: tuple[WorkerBaseVersion, ...]
    action_count: NonNegativeInt
    retained_audit_count: NonNegativeInt

class CommitClientTombstoneResponse(_SuccessResponseBase):
    response_type: Literal["commit_client_tombstone"] = (
        "commit_client_tombstone"
    )
    approval_operation_id: ObjectId
    deletion_version: PositiveInt
    tombstone_epoch: PositiveInt
    queue_intent_count: NonNegativeInt
    state: Literal["TOMBSTONED"] = "TOMBSTONED"


class PreviewClientRebuildResponse(_SuccessResponseBase):
    response_type: Literal["preview_client_rebuild"] = (
        "preview_client_rebuild"
    )
    action: Literal["start", "cancel"]
    plan_ref: ArchiveContentRef
    plan_sha256: Sha256Hex
    proposed_operation_id: ObjectId
    base_versions: tuple[WorkerBaseVersion, ...]
    purpose: SafePolicyKey | None = None
    source_intent_id: ObjectId | None = None
    job_id: ObjectId | None = None


class RebuildClientDerivativesResponse(_SuccessResponseBase):
    response_type: Literal["rebuild_client_derivatives"] = (
        "rebuild_client_derivatives"
    )
    action: Literal["START", "STATUS", "REPORT", "CANCEL"]
    approval_operation_id: ObjectId | None = None
    applied_commit_version: PositiveInt | None = None
    job_id: ObjectId
    plan_sha256: Sha256Hex
    state: Literal[
        "queued",
        "running",
        "verifying",
        "activating",
        "succeeded",
        "failed",
        "cancelled",
    ]
    attempt_count: NonNegativeInt
    output_manifest_set_sha256: Sha256Hex | None = None
    equivalence_report_sha256: Sha256Hex | None = None
    last_error_code: NonEmptyStr | None = None
    report_sha256: Sha256Hex

    @model_validator(mode="after")
    def _approval_shape(self) -> "RebuildClientDerivativesResponse":
        approved = self.action in {"START", "CANCEL"}
        if approved != (
            self.approval_operation_id is not None
            and self.applied_commit_version is not None
        ):
            raise ValueError("client rebuild approval result shape is invalid")
        return self


class PreviewClientRollbackResponse(_SuccessResponseBase):
    response_type: Literal["preview_client_rollback"] = (
        "preview_client_rollback"
    )
    rollback_kind: Literal["profile_fact", "artifact"]
    plan_ref: ArchiveContentRef
    plan_sha256: Sha256Hex
    proposed_operation_id: ObjectId
    base_versions: tuple[WorkerBaseVersion, ...]
    current_version: PositiveInt
    restore_version: PositiveInt


class CommitClientRollbackResponse(_SuccessResponseBase):
    response_type: Literal["commit_client_rollback"] = (
        "commit_client_rollback"
    )
    approval_operation_id: ObjectId
    applied_commit_version: PositiveInt
    rollback_kind: Literal["profile_fact", "artifact"]
    successor_ref: VersionRef
    rebuild_job_id: ObjectId
    requires_combined_publication: Literal[False] = False


class VerifyClientIntegrityResponse(_SuccessResponseBase):
    response_type: Literal["verify_client_integrity"] = "verify_client_integrity"
    status: Literal["valid"] = "valid"
    active_epoch: NonNegativeInt
    artifact_count: NonNegativeInt
    verification_sha256: Sha256Hex


class StageSharedCaseOutboxResponse(_SuccessResponseBase):
    response_type: Literal["stage_shared_case_outbox"] = (
        "stage_shared_case_outbox"
    )
    bundle_id: ObjectId
    action: Literal["PREPARE", "COMMIT"]
    candidate_ref: ArchiveContentRef | None = None
    scan_ref: ArchiveContentRef | None = None
    review_policy_draft_ref: ArchiveContentRef | None = None
    approval_draft_sha256: Sha256Hex | None = None
    approval_diff_ref: VersionRef | None = None
    candidate_sections: tuple[SharedCaseSection, ...] = ()
    deidentification_scans: tuple[DeidentificationScan, ...] = ()
    event_id: ObjectId | None = None
    payload_ref: ArchiveContentRef | None = None
    approval_operation_id: ObjectId | None = None
    applied_commit_version: PositiveInt | None = None
    release_outcome: Literal["eligible", "private_only", "quarantine"] | None = None
    state: Literal[
        "PREPARED",
        "PENDING",
        "CLAIMED",
        "PUBLISHED",
        "FAILED",
        "REJECTED",
        "QUARANTINED",
        "PRIVATE_ONLY",
    ]
    attempt_count: NonNegativeInt = 0
    published_global_version: PositiveInt | None = None

    @field_validator("candidate_sections", mode="before")
    @classmethod
    def _json_candidate_sections(cls, value: object) -> object:
        if type(value) is not list:
            return value
        normalized: list[object] = []
        for item in value:
            if type(item) is dict:
                section = dict(item)
                hashes = section.get("source_item_hmacs")
                if type(hashes) is list:
                    section["source_item_hmacs"] = tuple(hashes)
                normalized.append(section)
            else:
                normalized.append(item)
        return tuple(normalized)

    @field_validator("deidentification_scans", mode="before")
    @classmethod
    def _json_deidentification_scans(cls, value: object) -> object:
        if type(value) is not list:
            return value
        normalized: list[object] = []
        for item in value:
            if type(item) is not dict:
                normalized.append(item)
                continue
            scan = dict(item)
            for field in ("findings", "rare_combinations"):
                entries = scan.get(field)
                if type(entries) is list:
                    if field == "rare_combinations":
                        entries = [
                            {
                                **entry,
                                "categories": frozenset(entry["categories"]),
                            }
                            if type(entry) is dict
                            and type(entry.get("categories")) is list
                            else entry
                            for entry in entries
                        ]
                    scan[field] = tuple(entries)
            categories = scan.get("scanned_categories")
            if type(categories) is list:
                scan["scanned_categories"] = frozenset(categories)
            normalized.append(scan)
        return tuple(normalized)

    @model_validator(mode="after")
    def _exact_case_result(self) -> "StageSharedCaseOutboxResponse":
        prepared = (
            self.candidate_ref,
            self.scan_ref,
            self.review_policy_draft_ref,
            self.approval_draft_sha256,
            self.approval_diff_ref,
        )
        committed = (
            self.event_id,
            self.payload_ref,
            self.approval_operation_id,
            self.applied_commit_version,
        )
        if self.action == "PREPARE":
            if (
                self.state != "PREPARED"
                or any(value is None for value in prepared)
                or any(value is not None for value in committed)
                or not self.candidate_sections
                or len(self.candidate_sections) != len(self.deidentification_scans)
                or self.release_outcome is not None
                or self.attempt_count != 0
                or self.published_global_version is not None
            ):
                raise ValueError("case prepare result is malformed")
        else:
            unpublished = self.state in {
                "REJECTED",
                "QUARANTINED",
                "PRIVATE_ONLY",
            }
            if (
                self.state == "PREPARED"
                or any(value is not None for value in prepared)
                or self.candidate_sections
                or self.deidentification_scans
                or self.release_outcome is None
                or (
                    unpublished
                    and (
                        self.event_id is not None
                        or self.payload_ref is not None
                        or self.approval_operation_id is None
                        or self.applied_commit_version is None
                    )
                )
                or (not unpublished and any(value is None for value in committed))
                or (
                    self.state == "PUBLISHED"
                    and self.published_global_version is None
                )
                or (
                    self.state != "PUBLISHED"
                    and self.published_global_version is not None
                )
            ):
                raise ValueError("case commit result is malformed")
        return self


class QueryProfileSnapshotResponse(_SuccessResponseBase):
    response_type: Literal["query_profile_snapshot"] = "query_profile_snapshot"
    profile_sha256: Sha256Hex
    source_client_commit_version: NonNegativeInt
    item_count: NonNegativeInt


class QueryClientGraphResponse(_SuccessResponseBase):
    response_type: Literal["query_client_graph"] = "query_client_graph"
    graph_sha256: Sha256Hex
    source_client_commit_version: NonNegativeInt
    node_count: NonNegativeInt
    edge_count: NonNegativeInt


class ClientGraphEdgeView(StrictModel):
    edge_id: NonEmptyStr
    fact_ref: VersionRef
    relation_type: NonEmptyStr
    dependency_type: NonEmptyStr
    confidence: float = Field(strict=True, ge=0.0, le=1.0)
    source_event_ids: tuple[NonEmptyStr, ...]
    effective_from: UtcDateTime
    effective_to: UtcDateTime | None


class SearchClientGraphResponse(_SuccessResponseBase):
    response_type: Literal["search_client_graph"] = "search_client_graph"
    graph_sha256: Sha256Hex
    source_client_commit_version: NonNegativeInt
    runtime_epoch: NonNegativeInt
    query_mode: Literal["deterministic_metadata"] = "deterministic_metadata"
    node_count: NonNegativeInt
    edge_count: NonNegativeInt
    count: NonNegativeInt
    items: tuple[ClientGraphEdgeView, ...]
    truncated: bool


class ClientWeightedPathStepView(StrictModel):
    edge_id: NonEmptyStr
    fact_id: NonEmptyStr
    source_event_ids: tuple[NonEmptyStr, ...]
    restrictions: tuple[NonEmptyStr, ...]
    cost: float = Field(strict=True, ge=0.0)


class ClientWeightedPathView(StrictModel):
    total_cost: float = Field(strict=True, ge=0.0)
    edge_ids: tuple[NonEmptyStr, ...]
    steps: tuple[ClientWeightedPathStepView, ...]


class QueryClientWeightedPathResponse(_SuccessResponseBase):
    response_type: Literal["query_client_weighted_path"] = (
        "query_client_weighted_path"
    )
    graph_sha256: Sha256Hex
    source_client_commit_version: NonNegativeInt
    runtime_epoch: NonNegativeInt
    count: NonNegativeInt
    paths: tuple[ClientWeightedPathView, ...]


class QueryClientHistoryCandidatesResponse(_SuccessResponseBase):
    response_type: Literal["query_client_history_candidates"] = (
        "query_client_history_candidates"
    )
    candidates: tuple[CandidateRef, ...]
    runtime_epoch: NonNegativeInt


class PreviewDependencyImpactResponse(_SuccessResponseBase):
    response_type: Literal["preview_dependency_impact"] = "preview_dependency_impact"
    proposal_sha256: Sha256Hex
    proposal_object_ref: VersionRef
    direct_invalidation_count: NonNegativeInt
    manual_review_count: NonNegativeInt


class DependencyImpactItemView(StrictModel):
    fact_id: NonEmptyStr
    path_edge_ids: tuple[NonEmptyStr, ...]
    path_confidence: float = Field(strict=True, ge=0.0, le=1.0)
    classification: Literal["direct_invalidation", "manual_review"]
    recommended_operation: Literal["SUPERSEDE", "CORRECT", "REVIEW"]


class PreviewTargetDependencyImpactResponse(_SuccessResponseBase):
    response_type: Literal["preview_target_dependency_impact"] = (
        "preview_target_dependency_impact"
    )
    target_ref: VersionRef
    action: Literal["supersede", "invalidate", "resolve", "revoke"]
    as_of: UtcDateTime
    proposal_sha256: Sha256Hex
    direct_invalidations: tuple[DependencyImpactItemView, ...]
    manual_reviews: tuple[DependencyImpactItemView, ...]


class BeginSessionResponse(_SuccessResponseBase):
    response_type: Literal["begin_session"] = "begin_session"
    session_id: Uuid7String
    capability_epoch: PositiveInt
    snapshot: ClientContextSnapshot


class SessionTurnState(StrictModel):
    turn_id: Uuid7String
    ordinal: PositiveInt
    state: TurnState
    active_run_id: Uuid7String | None


class RecoveredClientTurn(StrictModel):
    turn_id: Uuid7String
    ordinal: PositiveInt
    state: TurnState
    active_run_id: Uuid7String | None
    client_message: NonEmptyStr


class RecoveredActualReply(StrictModel):
    actual_reply_id: ObjectId
    turn_id: Uuid7String
    source_type: ActualReplySource
    candidate_id: ObjectId | None
    actual_text: NonEmptyStr | None
    sent_at: UtcDateTime | None
    confirmed_at: UtcDateTime | None
    evidence_gap: bool

    @model_validator(mode="after")
    def _source_shape(self) -> "RecoveredActualReply":
        if self.source_type == "external_unknown":
            valid = (
                self.candidate_id is None
                and self.actual_text is None
                and self.sent_at is None
                and self.confirmed_at is not None
                and self.evidence_gap
            )
        else:
            valid = (
                self.candidate_id is not None
                and self.actual_text is not None
                and self.sent_at is not None
                and self.confirmed_at is None
                and not self.evidence_gap
            )
        if not valid:
            raise ValueError("recovered actual reply has an invalid source shape")
        return self


class RecoveredTemporaryFact(StrictModel):
    event_id: ObjectId
    turn_id: Uuid7String
    event_kind: TemporaryFactKind
    cognitive_type: CognitiveType
    value: JsonValue
    target_fact_id: NonEmptyStr | None
    target_fact_version: PositiveInt | None


class RecoveredCandidate(StrictModel):
    candidate_id: ObjectId
    turn_id: Uuid7String
    run_id: Uuid7String
    ordinal: PositiveInt
    label: NonEmptyStr
    text: NonEmptyStr


class SessionRecoveryPayload(StrictModel):
    pending_action: Literal[
        "begin_generation",
        "regenerate",
        "record_actual_reply",
        "ready_for_next_turn",
        "session_closed",
    ]
    incomplete_evidence: bool
    turns: tuple[RecoveredClientTurn, ...]
    actual_replies: tuple[RecoveredActualReply, ...]
    temporary_facts: tuple[RecoveredTemporaryFact, ...]
    pending_candidates: tuple[RecoveredCandidate, ...]
    discarded_stage_artifact_ids: tuple[ObjectId, ...]


class ResumeSessionResponse(_SuccessResponseBase):
    response_type: Literal["resume_session"] = "resume_session"
    session_id: Uuid7String
    capability_epoch: PositiveInt
    snapshot: ClientContextSnapshot
    recovery: SessionRecoveryPayload


class AppendClientTurnResponse(_SuccessResponseBase):
    response_type: Literal["append_client_turn"] = "append_client_turn"
    session_id: Uuid7String
    turn_id: Uuid7String
    ordinal: PositiveInt
    state: TurnState
    client_message_ref: VersionRef
    client_message_sha256: Sha256Hex

    @model_validator(mode="after")
    def _message_binding(self) -> "AppendClientTurnResponse":
        if self.client_message_ref.content_sha256 != self.client_message_sha256:
            raise ValueError("client turn response content binding mismatch")
        return self


class AppendTemporaryFactResponse(_SuccessResponseBase):
    response_type: Literal["append_temporary_fact"] = "append_temporary_fact"
    session_id: Uuid7String
    turn_id: Uuid7String
    event_id: ObjectId
    event_kind: TemporaryFactKind
    cognitive_type: CognitiveType
    content_sha256: Sha256Hex
    target_fact_id: NonEmptyStr | None
    target_fact_version: PositiveInt | None
    recorded_at: UtcDateTime


class BeginGenerationResponse(_SuccessResponseBase):
    response_type: Literal["begin_generation"] = "begin_generation"
    session_id: Uuid7String
    turn_id: Uuid7String
    state: Literal["generation_in_progress"]
    run_id: Uuid7String


class StoreCandidateSetResponse(_SuccessResponseBase):
    response_type: Literal["store_candidate_set"] = "store_candidate_set"
    session_id: Uuid7String
    turn_id: Uuid7String
    candidate_set_id: ObjectId
    candidate_ids: tuple[ObjectId, ...]
    state: Literal["awaiting_actual_reply"]


class RecordActualReplyResponse(_SuccessResponseBase):
    response_type: Literal["record_actual_reply"] = "record_actual_reply"
    session_id: Uuid7String
    turn_id: Uuid7String
    actual_reply_id: ObjectId
    source_type: Literal["adopted", "edited", "external_unknown"]
    state: Literal["turn_closed"]
    evidence_gap: bool
    actual_reply: ActualReply

    @model_validator(mode="after")
    def _actual_reply_closure(self) -> "RecordActualReplyResponse":
        actual = self.actual_reply
        if (
            actual.actual_reply_id != self.actual_reply_id
            or actual.session_id != self.session_id
            or actual.turn_id != self.turn_id
            or actual.source_type != self.source_type
            or actual.evidence_gap != self.evidence_gap
        ):
            raise ValueError("actual reply response closure mismatch")
        return self


class ReadSessionStateResponse(_SuccessResponseBase):
    response_type: Literal["read_session_state"] = "read_session_state"
    session_id: Uuid7String
    status: Literal["OPEN", "CLOSED", "ARCHIVED"]
    capability_epoch: PositiveInt
    snapshot_version: NonNegativeInt
    snapshot_sha256: Sha256Hex
    turns: tuple[SessionTurnState, ...]
    actual_reply_count: NonNegativeInt
    temporary_fact_count: NonNegativeInt
    recovery: SessionRecoveryPayload


class GenerationClientBinding(StrictModel):
    client_snapshot_ref: VersionRef
    client_runtime_epoch: NonNegativeInt
    client_tombstone_count: NonNegativeInt
    temporary_fact_refs: tuple[VersionRef, ...]

    @model_validator(mode="after")
    def _bounded_tombstone_epoch(self) -> "GenerationClientBinding":
        if self.client_tombstone_count >= 2**32:
            raise ValueError("client tombstone epoch is exhausted")
        keys = tuple(
            (item.object_id, item.version, item.content_sha256)
            for item in self.temporary_fact_refs
        )
        if keys != tuple(sorted(set(keys))):
            raise ValueError("temporary fact refs must be canonical")
        return self


class GenerationStageWireRecord(StrictModel):
    stage_revision_id: ObjectId
    revision: PositiveInt
    stage: GenerationStageName
    artifact: StoredContentRef
    parent_sha256s: tuple[Sha256Hex, ...]
    payload: GenerationStagePayload
    created_at: UtcDateTime

    @model_validator(mode="after")
    def _stage_closure(self) -> "GenerationStageWireRecord":
        if (
            self.payload.envelope.stage != self.stage
            or self.payload.envelope.parent_sha256s != self.parent_sha256s
            or self.payload.envelope.created_at != self.created_at
        ):
            raise ValueError("generation wire record closure mismatch")
        return self


class FinalCandidateBinding(StrictModel):
    """One ordered logical-to-persistent candidate identity closure."""

    persistent_candidate_id: ObjectId
    ordinal: Annotated[int, Field(strict=True, ge=1, le=4)]
    logical_candidate_id: SafePolicyKey
    label: Annotated[NonEmptyStr, Field(max_length=120)]
    text_sha256: Sha256Hex


def _final_candidate_bindings_match_payload(
    payload: GenerationStagePayload,
    candidate_ids: tuple[ObjectId, ...],
    bindings: tuple[FinalCandidateBinding, ...],
) -> bool:
    if not isinstance(payload, FinalTurnBundle):
        return not candidate_ids and not bindings
    logical = payload.client_reply_candidates
    if (
        len(bindings) != len(logical)
        or candidate_ids
        != tuple(item.persistent_candidate_id for item in bindings)
        or len(candidate_ids) != len(set(candidate_ids))
    ):
        return False
    return all(
        binding.ordinal == ordinal
        and binding.logical_candidate_id == candidate.candidate_id
        and binding.label == candidate.label
        and binding.text_sha256
        == hashlib.sha256(candidate.text.encode("utf-8")).hexdigest()
        for ordinal, (binding, candidate) in enumerate(
            zip(bindings, logical, strict=True),
            start=1,
        )
    )


class SubmitGenerationStageResponse(_SuccessResponseBase):
    response_type: Literal["submit_generation_stage"] = "submit_generation_stage"
    session_id: Uuid7String
    turn_id: Uuid7String
    run_id: Uuid7String
    record: GenerationStageWireRecord
    turn_state: TurnState
    candidate_set_id: ObjectId | None = None
    candidate_ids: tuple[ObjectId, ...] = ()
    candidate_bindings: tuple[FinalCandidateBinding, ...] = ()
    retrieval_status: Literal["not_applicable", "pending", "ready"] = (
        "not_applicable"
    )
    evidence_pack_ref: StoredContentRef | None = None
    evidence_pack_sha256: Sha256Hex | None = None
    evidence_pack: EvidencePack | None = None
    evidence_context_ref: StoredContentRef | None = None
    evidence_context_sha256: Sha256Hex | None = None
    evidence_context: tuple[GenerationEvidenceContextItem, ...] | None = None
    retrieval_metadata: GenerationRetrievalMetadata | None = None

    @model_validator(mode="after")
    def _result_closure(self) -> "SubmitGenerationStageResponse":
        envelope = self.record.payload.envelope
        if envelope.turn_id != self.turn_id or envelope.run_id != self.run_id:
            raise ValueError("generation response is bound to a different turn")
        final = self.record.stage == "final_bundle"
        if final != (
            self.candidate_set_id is not None
            and bool(self.candidate_ids)
            and bool(self.candidate_bindings)
        ):
            raise ValueError("only a final bundle may return stored candidates")
        if not _final_candidate_bindings_match_payload(
            self.record.payload,
            self.candidate_ids,
            self.candidate_bindings,
        ):
            raise ValueError("final candidate binding closure mismatch")
        if final != (self.turn_state == "awaiting_actual_reply"):
            raise ValueError("final bundle and turn state are inconsistent")
        if not final and self.turn_state != "generation_in_progress":
            raise ValueError("non-final generation stage requires active generation")
        is_plan = self.record.stage == "query_plan"
        retrieval_complete = (
            self.evidence_pack_ref is not None
            and self.evidence_pack_sha256 is not None
            and self.evidence_pack is not None
            and self.evidence_context_ref is not None
            and self.evidence_context_sha256 is not None
            and self.evidence_context is not None
            and self.retrieval_metadata is not None
        )
        retrieval_fields = (
            self.evidence_pack_ref,
            self.evidence_pack_sha256,
            self.evidence_pack,
            self.evidence_context_ref,
            self.evidence_context_sha256,
            self.evidence_context,
            self.retrieval_metadata,
        )
        if any(item is not None for item in retrieval_fields) != all(
            item is not None for item in retrieval_fields
        ):
            raise ValueError("query plan retrieval result is partial")
        if is_plan:
            if self.retrieval_status not in {"pending", "ready"}:
                raise ValueError("query plan retrieval status is invalid")
            if (self.retrieval_status == "ready") != retrieval_complete:
                raise ValueError("query plan retrieval result is incomplete")
            if retrieval_complete and (
                self.evidence_pack_ref is None
                or self.evidence_pack_ref.content_sha256
                != self.evidence_pack_sha256
                or self.evidence_pack is None
                or evidence_pack_sha256(self.evidence_pack)
                != self.evidence_pack_sha256
                or self.evidence_context_ref is None
                or self.evidence_context_sha256 is None
                or self.evidence_context is None
                or self.evidence_context_ref.content_sha256
                != self.evidence_context_sha256
                or _generation_context_sha256(self.evidence_context)
                != self.evidence_context_sha256
                or self.evidence_pack.run_id != self.run_id
            ):
                raise ValueError("query plan retrieval hash mismatch")
            if retrieval_complete:
                plan = self.record.payload
                if not isinstance(plan, QueryPlan) or (
                    self.evidence_pack is None
                    or self.evidence_pack.client_snapshot_ref
                    != plan.client_snapshot_ref
                    or self.evidence_pack.authority.global_runtime_epoch
                    != plan.global_runtime_epoch
                    or self.evidence_pack.authority.client_runtime_epoch
                    != plan.client_runtime_epoch
                    or self.evidence_pack.authority.tombstone_epoch
                    != plan.tombstone_epoch
                    or self.evidence_pack.authority.authorization_epoch
                    != plan.authorization_epoch
                ):
                    raise ValueError("query plan retrieval binding mismatch")
            if retrieval_complete:
                try:
                    validate_generation_evidence_context(
                        self.evidence_pack,
                        self.evidence_context,
                    )
                except GenerationEvidenceBindingMismatch:
                    raise ValueError("query plan evidence context mismatch") from None
        elif self.retrieval_status != "not_applicable" or retrieval_complete:
            raise ValueError("only a query plan may return retrieval output")
        return self


def submit_generation_stage_response_matches_request(
    request: SubmitGenerationStageRequest,
    response: SubmitGenerationStageResponse,
) -> bool:
    """Recheck response scope and final-candidate closure without trusting parsing."""

    envelope = request.stage_payload.envelope
    final = isinstance(request.stage_payload, FinalTurnBundle)
    return (
        response.request_id == request.request_id
        and response.session_id == request.session_id
        and response.turn_id == envelope.turn_id
        and response.run_id == envelope.run_id
        and response.record.stage == envelope.stage
        and response.record.payload == request.stage_payload
        and response.record.parent_sha256s == envelope.parent_sha256s
        and response.record.created_at == envelope.created_at
        and _final_candidate_bindings_match_payload(
            response.record.payload,
            response.candidate_ids,
            response.candidate_bindings,
        )
        and (
            final == (response.candidate_set_id is not None)
        )
        and response.turn_state
        == ("awaiting_actual_reply" if final else "generation_in_progress")
    )


class GetGenerationStateResponse(_SuccessResponseBase):
    response_type: Literal["get_generation_state"] = "get_generation_state"
    session_id: Uuid7String
    turn_id: Uuid7String
    run_id: Uuid7String
    turn_state: TurnState
    records: tuple[GenerationStageWireRecord, ...]
    risk_observations: tuple[InternalRiskObservationRecord, ...]
    client_binding: GenerationClientBinding

    @model_validator(mode="after")
    def _scope_closure(self) -> "GetGenerationStateResponse":
        if any(
            record.payload.envelope.turn_id != self.turn_id
            or record.payload.envelope.run_id != self.run_id
            for record in self.records
        ):
            raise ValueError("generation state contains a foreign turn or run")
        if any(
            item.session_id != self.session_id
            for item in self.risk_observations
        ):
            raise ValueError("generation state contains a foreign risk observation")
        return self


class AcknowledgeRiskObservationResponse(_SuccessResponseBase):
    response_type: Literal["acknowledge_risk_observation"] = (
        "acknowledge_risk_observation"
    )
    session_id: Uuid7String
    action: Literal["acknowledge", "close"]
    observation: InternalRiskObservationRecord

    @model_validator(mode="after")
    def _acknowledged(self) -> "AcknowledgeRiskObservationResponse":
        expected_status = (
            "acknowledged" if self.action == "acknowledge" else "closed"
        )
        if self.observation.session_id != self.session_id:
            raise ValueError("risk lifecycle response contains a foreign session")
        if self.observation.status != expected_status:
            raise ValueError("risk lifecycle response does not match its action")
        return self


def risk_lifecycle_response_matches_request(
    request: AcknowledgeRiskObservationRequest,
    response: AcknowledgeRiskObservationResponse,
) -> bool:
    """Bind a manual lifecycle result to the exact counselor decision."""

    observation = response.observation
    base = (
        response.request_id == request.request_id
        and response.session_id == request.session_id
        and response.action == request.action
        and observation.session_id == request.session_id
        and observation.observation.observation_id == request.observation_id
    )
    if not base:
        return False
    if request.action == "acknowledge":
        return (
            observation.status == "acknowledged"
            and observation.counselor_disposition
            == request.counselor_disposition
            and observation.rejection_reason == request.rejection_reason
        )
    return (
        observation.status == "closed"
        and observation.close_decision == request.close_decision
        and observation.close_reason == request.close_reason
    )


def _actual_reply_operation_sha256(
    request: RecordActualReplyRequest,
    actual: ActualReply,
) -> str | None:
    if request.mode == "adopted":
        if actual.content is None or request.sent_at is None:
            return None
        payload: dict[str, object] = {
            "candidate_id": request.candidate_id,
            "reply_sha256": actual.content.content_sha256,
            "sent_at": _wire_utc_text(request.sent_at),
            "source_type": "adopted",
        }
    elif request.mode == "edited":
        if (
            actual.content is None
            or actual.diff is None
            or request.actual_text is None
            or request.sent_at is None
            or actual.content.content_sha256
            != hashlib.sha256(request.actual_text.encode("utf-8")).hexdigest()
        ):
            return None
        payload = {
            "candidate_id": request.candidate_id,
            "diff_sha256": actual.diff.content_sha256,
            "reply_sha256": actual.content.content_sha256,
            "sent_at": _wire_utc_text(request.sent_at),
            "source_type": "edited",
        }
    else:
        if request.confirmed_at is None:
            return None
        payload = {
            "confirmed_at": _wire_utc_text(request.confirmed_at),
            "source_type": "external_unknown",
        }
    return hashlib.sha256(
        (
            json.dumps(
                payload,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
    ).hexdigest()


def _wire_utc_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def record_actual_reply_response_matches_request(
    request: RecordActualReplyRequest,
    response: RecordActualReplyResponse,
) -> bool:
    """Validate the body-free ActualReply closure against the exact request."""

    actual = response.actual_reply
    expected_operation = _actual_reply_operation_sha256(request, actual)
    return (
        response.request_id == request.request_id
        and response.session_id == request.session_id
        and response.turn_id == request.turn_id
        and response.source_type == request.mode
        and response.state == "turn_closed"
        and response.actual_reply_id == actual.actual_reply_id
        and response.evidence_gap == actual.evidence_gap
        and actual.session_id == request.session_id
        and actual.turn_id == request.turn_id
        and actual.source_type == request.mode
        and actual.idempotency_key == request.idempotency_key
        and actual.candidate_id == request.candidate_id
        and actual.sent_at == request.sent_at
        and actual.confirmed_at == request.confirmed_at
        and expected_operation is not None
        and actual.operation_sha256 == expected_operation
    )


class PrivateGenerationEvidence(StrictModel):
    candidate: CandidateRef
    body: Annotated[NonEmptyStr, Field(max_length=500_000)]

    @model_validator(mode="after")
    def _private_exact_body(self) -> "PrivateGenerationEvidence":
        if (
            self.candidate.filter_binding is not None
            or self.candidate.provenance.provenance_scope != "client_private"
            or self.candidate.channel not in {"profile", "client_history"}
            or hashlib.sha256(self.body.encode("utf-8")).hexdigest()
            != self.candidate.content_ref.content_sha256
        ):
            raise ValueError("private generation evidence closure mismatch")
        return self


class GetGenerationBindingResponse(_SuccessResponseBase):
    response_type: Literal["get_generation_binding"] = "get_generation_binding"
    session_id: Uuid7String
    turn_id: Uuid7String
    binding: GenerationClientBinding


class PrepareGenerationRetrievalResponse(_SuccessResponseBase):
    response_type: Literal["prepare_generation_retrieval"] = (
        "prepare_generation_retrieval"
    )
    session_id: Uuid7String
    turn_id: Uuid7String
    run_id: Uuid7String
    query_plan_sha256: Sha256Hex
    binding: GenerationClientBinding
    c1_applicability_input: C1ApplicabilityInput
    risk_context_binding: GenerationRiskContextBinding
    private_evidence: tuple[PrivateGenerationEvidence, ...]

    @model_validator(mode="after")
    def _turn_risk_binding(self) -> "PrepareGenerationRetrievalResponse":
        if self.risk_context_binding.turn_id != self.turn_id:
            raise ValueError("risk context binding belongs to a different turn")
        return self

    @model_validator(mode="after")
    def _unique_private_evidence(self) -> "PrepareGenerationRetrievalResponse":
        applicability = self.c1_applicability_input
        if (
            applicability.query_plan_sha256 != self.query_plan_sha256
            or applicability.client_snapshot_ref != self.binding.client_snapshot_ref
            or applicability.client_runtime_epoch
            != self.binding.client_runtime_epoch
            or applicability.client_tombstone_count
            != self.binding.client_tombstone_count
            or applicability.temporary_fact_refs
            != self.binding.temporary_fact_refs
        ):
            raise ValueError("C1 applicability input binding mismatch")
        keys = tuple(
            (
                item.candidate.reference.object_id,
                item.candidate.reference.version,
                item.candidate.reference.content_sha256,
                item.candidate.channel,
            )
            for item in self.private_evidence
        )
        if len(keys) != len(set(keys)):
            raise ValueError("private generation evidence must be unique")
        return self


class StoreGenerationEvidencePackResponse(_SuccessResponseBase):
    response_type: Literal["store_generation_evidence_pack"] = (
        "store_generation_evidence_pack"
    )
    session_id: Uuid7String
    turn_id: Uuid7String
    run_id: Uuid7String
    query_plan_sha256: Sha256Hex
    evidence_pack_ref: StoredContentRef
    evidence_pack_sha256: Sha256Hex
    evidence_pack: EvidencePack
    evidence_context_ref: StoredContentRef
    evidence_context_sha256: Sha256Hex
    evidence_context: tuple[GenerationEvidenceContextItem, ...]
    retrieval_metadata: GenerationRetrievalMetadata

    @model_validator(mode="after")
    def _hash_closure(self) -> "StoreGenerationEvidencePackResponse":
        if (
            self.evidence_pack_ref.content_sha256 != self.evidence_pack_sha256
            or evidence_pack_sha256(self.evidence_pack)
            != self.evidence_pack_sha256
            or self.evidence_pack.run_id != self.run_id
        ):
            raise ValueError("stored EvidencePack hash mismatch")
        if (
            self.evidence_context_ref.content_sha256
            != self.evidence_context_sha256
            or _generation_context_sha256(self.evidence_context)
            != self.evidence_context_sha256
        ):
            raise ValueError("stored generation evidence context hash mismatch")
        try:
            validate_generation_evidence_context(
                self.evidence_pack,
                self.evidence_context,
            )
        except GenerationEvidenceBindingMismatch:
            raise ValueError("stored generation evidence context mismatch") from None
        return self


class GetGenerationEvidenceForPlanResponse(_SuccessResponseBase):
    response_type: Literal["get_generation_evidence_for_plan"] = (
        "get_generation_evidence_for_plan"
    )
    session_id: Uuid7String
    turn_id: Uuid7String
    run_id: Uuid7String
    query_plan_sha256: Sha256Hex
    ready: bool
    evidence_pack_ref: StoredContentRef | None = None
    evidence_pack_sha256: Sha256Hex | None = None
    evidence_pack: EvidencePack | None = None
    evidence_context_ref: StoredContentRef | None = None
    evidence_context_sha256: Sha256Hex | None = None
    evidence_context: tuple[GenerationEvidenceContextItem, ...] | None = None
    retrieval_metadata: GenerationRetrievalMetadata | None = None

    @model_validator(mode="after")
    def _ready_closure(self) -> "GetGenerationEvidenceForPlanResponse":
        complete = (
            self.evidence_pack_ref is not None
            and self.evidence_pack_sha256 is not None
            and self.evidence_pack is not None
            and self.evidence_context_ref is not None
            and self.evidence_context_sha256 is not None
            and self.evidence_context is not None
            and self.retrieval_metadata is not None
        )
        fields = (
            self.evidence_pack_ref,
            self.evidence_pack_sha256,
            self.evidence_pack,
            self.evidence_context_ref,
            self.evidence_context_sha256,
            self.evidence_context,
            self.retrieval_metadata,
        )
        if any(item is not None for item in fields) != all(
            item is not None for item in fields
        ):
            raise ValueError("generation evidence recovery is partial")
        if self.ready != complete:
            raise ValueError("generation evidence readiness is inconsistent")
        if complete and (
            self.evidence_pack_ref is None
            or self.evidence_pack_ref.content_sha256
            != self.evidence_pack_sha256
            or self.evidence_pack is None
            or evidence_pack_sha256(self.evidence_pack)
            != self.evidence_pack_sha256
            or self.evidence_context_ref is None
            or self.evidence_context_sha256 is None
            or self.evidence_context is None
            or self.evidence_context_ref.content_sha256
            != self.evidence_context_sha256
            or _generation_context_sha256(self.evidence_context)
            != self.evidence_context_sha256
            or self.evidence_pack.run_id != self.run_id
        ):
            raise ValueError("generation evidence recovery hash mismatch")
        if complete:
            try:
                validate_generation_evidence_context(
                    self.evidence_pack,
                    self.evidence_context,
                )
            except GenerationEvidenceBindingMismatch:
                raise ValueError("generation evidence recovery mismatch") from None
        return self


class PersistRiskObservationsResponse(_SuccessResponseBase):
    response_type: Literal["persist_risk_observations"] = (
        "persist_risk_observations"
    )
    session_id: Uuid7String
    turn_id: Uuid7String
    client_message_sha256: Sha256Hex
    risk_authority: RiskEvaluationAuthorityBinding
    observation_set_sha256: Sha256Hex
    observation_count: NonNegativeInt
    observations: tuple[InternalRiskObservationRecord, ...]

    @model_validator(mode="after")
    def _scope_closure(self) -> "PersistRiskObservationsResponse":
        if self.observation_count != len(self.observations) or any(
            item.session_id != self.session_id
            or set(item.observation.trigger_turn_ids) != {self.turn_id}
            for item in self.observations
        ):
            raise ValueError("persisted risk result contains foreign scope")
        if (
            canonical_risk_observation_set_sha256(self.observations)
            != self.observation_set_sha256
        ):
            raise ValueError("persisted risk result hash mismatch")
        return self


class PrepareTurnRiskEvaluationResponse(_SuccessResponseBase):
    response_type: Literal["prepare_turn_risk_evaluation"] = (
        "prepare_turn_risk_evaluation"
    )
    session_id: Uuid7String
    turn_id: Uuid7String
    client_message_ref: VersionRef
    client_message_sha256: Sha256Hex
    client_message: NonEmptyStr
    risk_authority: RiskEvaluationAuthorityBinding
    evaluation_revision: PositiveInt
    evaluation_status: Literal["pending", "completed"]
    observation_set_sha256: Sha256Hex | None = None
    observation_count: NonNegativeInt | None = None

    @model_validator(mode="after")
    def _evaluation_closure(self) -> "PrepareTurnRiskEvaluationResponse":
        if (
            self.client_message_ref.content_sha256
            != self.client_message_sha256
            or hashlib.sha256(self.client_message.encode("utf-8")).hexdigest()
            != self.client_message_sha256
        ):
            raise ValueError("risk evaluation turn content binding mismatch")
        completed = (
            self.observation_set_sha256 is not None
            and self.observation_count is not None
        )
        if (self.evaluation_status == "completed") != completed:
            raise ValueError("risk evaluation recovery state is inconsistent")
        return self


class ScopeDeniedResponse(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    response_type: Literal["scope_denied"] = "scope_denied"
    success: Literal[False] = False
    error_code: Literal["SCOPE_DENIED"] = "SCOPE_DENIED"


class OperationalErrorResponse(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    response_type: Literal["operational_error"] = "operational_error"
    success: Literal[False] = False
    request_id: Uuid7String
    error_code: OperationalErrorCode


WorkerRequest: TypeAlias = (
    PingRequest
    | EmptyContextMetadataRequest
    | AppendScopedAuditRequest
    | QueryFactSnapshotRequest
    | PreviewFactMutationRequest
    | CommitFactMutationRequest
    | QueryProfileSnapshotRequest
    | QueryClientGraphRequest
    | SearchClientGraphRequest
    | QueryClientWeightedPathRequest
    | QueryClientHistoryCandidatesRequest
    | PreviewDependencyImpactRequest
    | PreviewTargetDependencyImpactRequest
    | BeginSessionRequest
    | ResumeSessionRequest
    | AppendClientTurnRequest
    | AppendTemporaryFactRequest
    | BeginGenerationRequest
    | StoreCandidateSetRequest
    | RecordActualReplyRequest
    | ReadSessionStateRequest
    | SubmitGenerationStageRequest
    | GetGenerationStateRequest
    | AcknowledgeRiskObservationRequest
    | GetGenerationBindingRequest
    | PrepareGenerationRetrievalRequest
    | GetGenerationEvidenceForPlanRequest
    | StoreGenerationEvidencePackRequest
    | PrepareTurnRiskEvaluationRequest
    | PersistRiskObservationsRequest
    | BuildPrivateArchiveRequest
    | CommitPrivateArchiveRequest
    | BuildProfileDiffRequest
    | CommitProfileUpdateRequest
    | StageSharedCaseOutboxRequest
    | RecoverClientManifestsRequest
    | PreflightClientLifecycleCommitRequest
    | PreviewClientDeleteRequest
    | CommitClientTombstoneRequest
    | PreviewClientRebuildRequest
    | RebuildClientDerivativesRequest
    | PreviewClientRollbackRequest
    | CommitClientRollbackRequest
    | VerifyClientIntegrityRequest
)
SessionBoundWorkerRequest: TypeAlias = (
    BeginSessionRequest
    | ResumeSessionRequest
    | AppendClientTurnRequest
    | AppendTemporaryFactRequest
    | BeginGenerationRequest
    | StoreCandidateSetRequest
    | RecordActualReplyRequest
    | ReadSessionStateRequest
    | SubmitGenerationStageRequest
    | GetGenerationStateRequest
    | AcknowledgeRiskObservationRequest
    | GetGenerationBindingRequest
    | PrepareGenerationRetrievalRequest
    | GetGenerationEvidenceForPlanRequest
    | StoreGenerationEvidencePackRequest
    | PrepareTurnRiskEvaluationRequest
    | PersistRiskObservationsRequest
)
_SESSION_BOUND_REQUEST_TYPES: Final = (
    BeginSessionRequest,
    ResumeSessionRequest,
    AppendClientTurnRequest,
    AppendTemporaryFactRequest,
    BeginGenerationRequest,
    StoreCandidateSetRequest,
    RecordActualReplyRequest,
    ReadSessionStateRequest,
    SubmitGenerationStageRequest,
    GetGenerationStateRequest,
    AcknowledgeRiskObservationRequest,
    GetGenerationBindingRequest,
    PrepareGenerationRetrievalRequest,
    GetGenerationEvidenceForPlanRequest,
    StoreGenerationEvidencePackRequest,
    PrepareTurnRiskEvaluationRequest,
    PersistRiskObservationsRequest,
)
_HANDLE_BOUND_REQUEST_TYPES: Final = (
    QueryClientHistoryCandidatesRequest,
    BuildPrivateArchiveRequest,
    CommitPrivateArchiveRequest,
    BuildProfileDiffRequest,
    CommitProfileUpdateRequest,
    StageSharedCaseOutboxRequest,
)


def worker_request_binding(
    request: WorkerRequest,
) -> tuple[str | None, str | None]:
    """Return the closed session-id/handle target carried by one request."""

    if type(request) in _SESSION_BOUND_REQUEST_TYPES:
        return cast(SessionBoundWorkerRequest, request).session_id, None
    if type(request) in _HANDLE_BOUND_REQUEST_TYPES:
        return None, cast(
            QueryClientHistoryCandidatesRequest
            | BuildPrivateArchiveRequest
            | CommitPrivateArchiveRequest
            | BuildProfileDiffRequest
            | CommitProfileUpdateRequest
            | StageSharedCaseOutboxRequest,
            request,
        ).session_handle
    return None, None


WorkerResponse: TypeAlias = (
    PingResponse
    | EmptyContextMetadataResponse
    | AppendScopedAuditResponse
    | QueryFactSnapshotResponse
    | PreviewFactMutationResponse
    | CommitFactMutationResponse
    | QueryProfileSnapshotResponse
    | QueryClientGraphResponse
    | SearchClientGraphResponse
    | QueryClientWeightedPathResponse
    | QueryClientHistoryCandidatesResponse
    | PreviewDependencyImpactResponse
    | PreviewTargetDependencyImpactResponse
    | BeginSessionResponse
    | ResumeSessionResponse
    | AppendClientTurnResponse
    | AppendTemporaryFactResponse
    | BeginGenerationResponse
    | StoreCandidateSetResponse
    | RecordActualReplyResponse
    | ReadSessionStateResponse
    | SubmitGenerationStageResponse
    | GetGenerationStateResponse
    | AcknowledgeRiskObservationResponse
    | GetGenerationBindingResponse
    | PrepareGenerationRetrievalResponse
    | GetGenerationEvidenceForPlanResponse
    | StoreGenerationEvidencePackResponse
    | PrepareTurnRiskEvaluationResponse
    | PersistRiskObservationsResponse
    | BuildPrivateArchiveResponse
    | CommitPrivateArchiveResponse
    | BuildProfileDiffResponse
    | CommitProfileUpdateResponse
    | StageSharedCaseOutboxResponse
    | RecoverClientManifestsResponse
    | PreflightClientLifecycleCommitResponse
    | PreviewClientDeleteResponse
    | CommitClientTombstoneResponse
    | PreviewClientRebuildResponse
    | RebuildClientDerivativesResponse
    | PreviewClientRollbackResponse
    | CommitClientRollbackResponse
    | VerifyClientIntegrityResponse
    | ScopeDeniedResponse
    | OperationalErrorResponse
)
_DiscriminatedRequest: TypeAlias = Annotated[
    WorkerRequest,
    Field(discriminator="operation"),
]
_DiscriminatedResponse: TypeAlias = Annotated[
    WorkerResponse,
    Field(discriminator="response_type"),
]
_REQUEST_ADAPTER: TypeAdapter[WorkerRequest] = TypeAdapter(_DiscriminatedRequest)
_RESPONSE_ADAPTER: TypeAdapter[WorkerResponse] = TypeAdapter(_DiscriminatedResponse)

_REQUEST_MODELS: Final = {
    "ping": PingRequest,
    "get_empty_context_metadata": EmptyContextMetadataRequest,
    "append_scoped_audit": AppendScopedAuditRequest,
    "query_fact_snapshot": QueryFactSnapshotRequest,
    "preview_fact_mutation": PreviewFactMutationRequest,
    "commit_fact_mutation": CommitFactMutationRequest,
    "query_profile_snapshot": QueryProfileSnapshotRequest,
    "query_client_graph": QueryClientGraphRequest,
    "search_client_graph": SearchClientGraphRequest,
    "query_client_weighted_path": QueryClientWeightedPathRequest,
    "query_client_history_candidates": QueryClientHistoryCandidatesRequest,
    "preview_dependency_impact": PreviewDependencyImpactRequest,
    "preview_target_dependency_impact": PreviewTargetDependencyImpactRequest,
    "begin_session": BeginSessionRequest,
    "resume_session": ResumeSessionRequest,
    "append_client_turn": AppendClientTurnRequest,
    "append_temporary_fact": AppendTemporaryFactRequest,
    "begin_generation": BeginGenerationRequest,
    "store_candidate_set": StoreCandidateSetRequest,
    "record_actual_reply": RecordActualReplyRequest,
    "read_session_state": ReadSessionStateRequest,
    "submit_generation_stage": SubmitGenerationStageRequest,
    "get_generation_state": GetGenerationStateRequest,
    "acknowledge_risk_observation": AcknowledgeRiskObservationRequest,
    "get_generation_binding": GetGenerationBindingRequest,
    "prepare_generation_retrieval": PrepareGenerationRetrievalRequest,
    "get_generation_evidence_for_plan": GetGenerationEvidenceForPlanRequest,
    "store_generation_evidence_pack": StoreGenerationEvidencePackRequest,
    "prepare_turn_risk_evaluation": PrepareTurnRiskEvaluationRequest,
    "persist_risk_observations": PersistRiskObservationsRequest,
    "build_private_archive": BuildPrivateArchiveRequest,
    "commit_private_archive": CommitPrivateArchiveRequest,
    "build_profile_diff": BuildProfileDiffRequest,
    "commit_profile_update": CommitProfileUpdateRequest,
    "stage_shared_case_outbox": StageSharedCaseOutboxRequest,
    "recover_client_manifests": RecoverClientManifestsRequest,
    "preflight_client_lifecycle_commit": PreflightClientLifecycleCommitRequest,
    "preview_client_delete": PreviewClientDeleteRequest,
    "commit_client_tombstone": CommitClientTombstoneRequest,
    "preview_client_rebuild": PreviewClientRebuildRequest,
    "rebuild_client_derivatives": RebuildClientDerivativesRequest,
    "preview_client_rollback": PreviewClientRollbackRequest,
    "commit_client_rollback": CommitClientRollbackRequest,
    "verify_client_integrity": VerifyClientIntegrityRequest,
}
_RESPONSE_MODELS: Final = {
    "ping": PingResponse,
    "get_empty_context_metadata": EmptyContextMetadataResponse,
    "append_scoped_audit": AppendScopedAuditResponse,
    "query_fact_snapshot": QueryFactSnapshotResponse,
    "preview_fact_mutation": PreviewFactMutationResponse,
    "commit_fact_mutation": CommitFactMutationResponse,
    "query_profile_snapshot": QueryProfileSnapshotResponse,
    "query_client_graph": QueryClientGraphResponse,
    "search_client_graph": SearchClientGraphResponse,
    "query_client_weighted_path": QueryClientWeightedPathResponse,
    "query_client_history_candidates": QueryClientHistoryCandidatesResponse,
    "preview_dependency_impact": PreviewDependencyImpactResponse,
    "preview_target_dependency_impact": PreviewTargetDependencyImpactResponse,
    "begin_session": BeginSessionResponse,
    "resume_session": ResumeSessionResponse,
    "append_client_turn": AppendClientTurnResponse,
    "append_temporary_fact": AppendTemporaryFactResponse,
    "begin_generation": BeginGenerationResponse,
    "store_candidate_set": StoreCandidateSetResponse,
    "record_actual_reply": RecordActualReplyResponse,
    "read_session_state": ReadSessionStateResponse,
    "submit_generation_stage": SubmitGenerationStageResponse,
    "get_generation_state": GetGenerationStateResponse,
    "acknowledge_risk_observation": AcknowledgeRiskObservationResponse,
    "get_generation_binding": GetGenerationBindingResponse,
    "prepare_generation_retrieval": PrepareGenerationRetrievalResponse,
    "get_generation_evidence_for_plan": GetGenerationEvidenceForPlanResponse,
    "store_generation_evidence_pack": StoreGenerationEvidencePackResponse,
    "prepare_turn_risk_evaluation": PrepareTurnRiskEvaluationResponse,
    "persist_risk_observations": PersistRiskObservationsResponse,
    "build_private_archive": BuildPrivateArchiveResponse,
    "commit_private_archive": CommitPrivateArchiveResponse,
    "build_profile_diff": BuildProfileDiffResponse,
    "commit_profile_update": CommitProfileUpdateResponse,
    "stage_shared_case_outbox": StageSharedCaseOutboxResponse,
    "recover_client_manifests": RecoverClientManifestsResponse,
    "preflight_client_lifecycle_commit": PreflightClientLifecycleCommitResponse,
    "preview_client_delete": PreviewClientDeleteResponse,
    "commit_client_tombstone": CommitClientTombstoneResponse,
    "preview_client_rebuild": PreviewClientRebuildResponse,
    "rebuild_client_derivatives": RebuildClientDerivativesResponse,
    "preview_client_rollback": PreviewClientRollbackResponse,
    "commit_client_rollback": CommitClientRollbackResponse,
    "verify_client_integrity": VerifyClientIntegrityResponse,
}
_PERMISSIONS: Final = {
    "ping": "client_read",
    "get_empty_context_metadata": "client_read",
    "append_scoped_audit": "session_append",
    "query_fact_snapshot": "client_read",
    "preview_fact_mutation": "draft_write",
    "commit_fact_mutation": "draft_write",
    "query_profile_snapshot": "client_read",
    "query_client_graph": "client_read",
    "search_client_graph": "client_read",
    "query_client_weighted_path": "client_read",
    "query_client_history_candidates": "client_read",
    "preview_dependency_impact": "draft_write",
    "preview_target_dependency_impact": "client_read",
    "begin_session": "session_append",
    "resume_session": "session_append",
    "append_client_turn": "session_append",
    "append_temporary_fact": "session_append",
    "begin_generation": "session_append",
    "store_candidate_set": "session_append",
    "record_actual_reply": "session_append",
    "read_session_state": "client_read",
    "submit_generation_stage": "session_append",
    "get_generation_state": "client_read",
    "acknowledge_risk_observation": "session_append",
    "get_generation_binding": "client_read",
    "prepare_generation_retrieval": "client_read",
    "get_generation_evidence_for_plan": "client_read",
    "store_generation_evidence_pack": "session_append",
    "prepare_turn_risk_evaluation": "session_append",
    "persist_risk_observations": "session_append",
    "build_private_archive": "session_append",
    "commit_private_archive": "draft_write",
    "build_profile_diff": "session_append",
    "commit_profile_update": "draft_write",
    "stage_shared_case_outbox": "draft_write",
    "recover_client_manifests": "formal_write",
    "preflight_client_lifecycle_commit": "formal_write",
    "preview_client_delete": "draft_write",
    "commit_client_tombstone": "formal_write",
    "preview_client_rebuild": "draft_write",
    "rebuild_client_derivatives": "formal_write",
    "preview_client_rollback": "draft_write",
    "commit_client_rollback": "formal_write",
    "verify_client_integrity": "client_read",
}
_MESSAGE_TYPES: Final = frozenset(
    {
        PingRequest,
        EmptyContextMetadataRequest,
        AppendScopedAuditRequest,
        QueryFactSnapshotRequest,
        PreviewFactMutationRequest,
        CommitFactMutationRequest,
        QueryProfileSnapshotRequest,
        QueryClientGraphRequest,
        SearchClientGraphRequest,
        QueryClientWeightedPathRequest,
        QueryClientHistoryCandidatesRequest,
        PreviewDependencyImpactRequest,
        PreviewTargetDependencyImpactRequest,
        PingResponse,
        EmptyContextMetadataResponse,
        AppendScopedAuditResponse,
        QueryFactSnapshotResponse,
        PreviewFactMutationResponse,
        CommitFactMutationResponse,
        QueryProfileSnapshotResponse,
        QueryClientGraphResponse,
        SearchClientGraphResponse,
        QueryClientWeightedPathResponse,
        QueryClientHistoryCandidatesResponse,
        PreviewDependencyImpactResponse,
        PreviewTargetDependencyImpactResponse,
        BeginSessionRequest,
        BeginSessionResponse,
        ResumeSessionRequest,
        ResumeSessionResponse,
        AppendClientTurnRequest,
        AppendClientTurnResponse,
        AppendTemporaryFactRequest,
        AppendTemporaryFactResponse,
        BeginGenerationRequest,
        BeginGenerationResponse,
        StoreCandidateSetRequest,
        StoreCandidateSetResponse,
        RecordActualReplyRequest,
        RecordActualReplyResponse,
        ReadSessionStateRequest,
        ReadSessionStateResponse,
        SubmitGenerationStageRequest,
        SubmitGenerationStageResponse,
        GetGenerationStateRequest,
        GetGenerationStateResponse,
        AcknowledgeRiskObservationRequest,
        AcknowledgeRiskObservationResponse,
        GetGenerationBindingRequest,
        GetGenerationBindingResponse,
        PrepareGenerationRetrievalRequest,
        PrepareGenerationRetrievalResponse,
        GetGenerationEvidenceForPlanRequest,
        GetGenerationEvidenceForPlanResponse,
        StoreGenerationEvidencePackRequest,
        StoreGenerationEvidencePackResponse,
        PrepareTurnRiskEvaluationRequest,
        PrepareTurnRiskEvaluationResponse,
        PersistRiskObservationsRequest,
        PersistRiskObservationsResponse,
        BuildPrivateArchiveRequest,
        BuildPrivateArchiveResponse,
        CommitPrivateArchiveRequest,
        CommitPrivateArchiveResponse,
        BuildProfileDiffRequest,
        BuildProfileDiffResponse,
        CommitProfileUpdateRequest,
        CommitProfileUpdateResponse,
        StageSharedCaseOutboxRequest,
        StageSharedCaseOutboxResponse,
        RecoverClientManifestsRequest,
        RecoverClientManifestsResponse,
        PreflightClientLifecycleCommitRequest,
        PreflightClientLifecycleCommitResponse,
        PreviewClientDeleteRequest,
        PreviewClientDeleteResponse,
        PreviewClientRebuildRequest,
        PreviewClientRebuildResponse,
        CommitClientTombstoneRequest,
        CommitClientTombstoneResponse,
        RebuildClientDerivativesRequest,
        RebuildClientDerivativesResponse,
        PreviewClientRollbackRequest,
        PreviewClientRollbackResponse,
        CommitClientRollbackRequest,
        CommitClientRollbackResponse,
        VerifyClientIntegrityRequest,
        VerifyClientIntegrityResponse,
        ScopeDeniedResponse,
        OperationalErrorResponse,
    }
)


def _reject_constant(_value: str) -> None:
    raise WorkerProtocolError


def _unique_object(pairs: list[tuple[str, object]]) -> object:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise WorkerProtocolError
        result[key] = value
    return result


def _load_object(frame: object) -> object:
    if type(frame) is not bytes or not frame or len(frame) > MAX_FRAME_BYTES:
        raise WorkerProtocolError
    try:
        text = frame.decode("ascii")
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except WorkerProtocolError:
        raise WorkerProtocolError from None
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        raise WorkerProtocolError from None


def encode_message(message: object) -> bytes:
    if type(message) not in _MESSAGE_TYPES:
        raise WorkerProtocolError
    validated_message = cast(StrictModel, message)
    try:
        encoded = json.dumps(
            validated_message.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (AttributeError, TypeError, ValueError):
        raise WorkerProtocolError from None
    if not encoded or len(encoded) > MAX_FRAME_BYTES:
        raise WorkerProtocolError
    return encoded


def decode_request(frame: bytes) -> WorkerRequest:
    _load_object(frame)
    try:
        request: WorkerRequest = _REQUEST_ADAPTER.validate_json(frame, strict=True)
    except (ValidationError, TypeError, ValueError):
        raise WorkerProtocolError from None
    if encode_message(request) != frame:
        raise WorkerProtocolError
    return request


def decode_response(frame: bytes) -> WorkerResponse:
    _load_object(frame)
    try:
        response: WorkerResponse = _RESPONSE_ADAPTER.validate_json(frame, strict=True)
    except (ValidationError, TypeError, ValueError):
        raise WorkerProtocolError from None
    if encode_message(response) != frame:
        raise WorkerProtocolError
    return response


WorkerHandler: TypeAlias = Callable[[WorkerRequest], WorkerResponse]


@dataclass(frozen=True, slots=True)
class OperationBinding:
    """One explicit version/operation/model/permission/handler binding."""

    schema_version: str
    operation: str
    request_model: type[StrictModel]
    response_model: type[StrictModel]
    required_permission: str
    handler: WorkerHandler

    def __post_init__(self) -> None:
        expected_request = _REQUEST_MODELS.get(self.operation)
        expected_response = _RESPONSE_MODELS.get(self.operation)
        expected_permission = _PERMISSIONS.get(self.operation)
        if (
            type(self.schema_version) is not str
            or self.schema_version != PROTOCOL_VERSION
            or expected_request is None
            or self.request_model is not expected_request
            or self.response_model is not expected_response
            or self.required_permission != expected_permission
            or not callable(self.handler)
        ):
            raise WorkerProtocolError


class WorkerOperationRegistry:
    """Frozen operation registry with no string or dynamic-module dispatch."""

    __slots__ = ("_bindings",)

    def __init__(self, bindings: tuple[OperationBinding, ...]) -> None:
        if type(bindings) is not tuple or not bindings:
            raise WorkerProtocolError
        checked: dict[tuple[str, str], OperationBinding] = {}
        for binding in bindings:
            if type(binding) is not OperationBinding:
                raise WorkerProtocolError
            key = (binding.schema_version, binding.operation)
            if key in checked:
                raise WorkerProtocolError
            checked[key] = binding
        self._bindings = checked

    @property
    def operations(self) -> tuple[str, ...]:
        return tuple(sorted(operation for _version, operation in self._bindings))

    def resolve(self, request: WorkerRequest) -> OperationBinding:
        if type(request) not in _REQUEST_MODELS.values():
            raise WorkerProtocolError
        key = (request.schema_version, request.operation)
        binding = self._bindings.get(key)
        if binding is None or type(request) is not binding.request_model:
            raise WorkerProtocolError
        return binding

    def dispatch(self, request: WorkerRequest) -> WorkerResponse:
        binding = self.resolve(request)
        try:
            response = binding.handler(request)
        except WorkerOperationalError as error:
            return OperationalErrorResponse(
                request_id=request.request_id,
                error_code=error.code,
            )
        except WorkerProtocolError:
            raise WorkerProtocolError from None
        except Exception:
            raise WorkerProtocolError from None
        if type(response) is OperationalErrorResponse:
            if response.request_id != request.request_id:
                raise WorkerProtocolError
            return response
        if (
            type(response) is not binding.response_model
            or not hasattr(response, "request_id")
            or response.request_id != request.request_id
        ):
            raise WorkerProtocolError
        return response


__all__ = [
    "AcknowledgeRiskObservationRequest",
    "AcknowledgeRiskObservationResponse",
    "ArchiveContentRef",
    "AppendClientTurnRequest",
    "AppendClientTurnResponse",
    "AppendTemporaryFactRequest",
    "AppendTemporaryFactResponse",
    "AppendScopedAuditRequest",
    "AppendScopedAuditResponse",
    "BeginGenerationRequest",
    "BeginGenerationResponse",
    "BeginSessionRequest",
    "BeginSessionResponse",
    "BuildPrivateArchiveRequest",
    "BuildPrivateArchiveResponse",
    "BuildProfileDiffRequest",
    "BuildProfileDiffResponse",
    "CLIENT_ACTIVE_INTEGRITY_REBUILD_REQUIRED",
    "CommitFactMutationRequest",
    "CommitFactMutationResponse",
    "CommitPrivateArchiveRequest",
    "CommitPrivateArchiveResponse",
    "CommitProfileUpdateRequest",
    "CommitProfileUpdateResponse",
    "CommitClientTombstoneRequest",
    "CommitClientTombstoneResponse",
    "CommitClientRollbackRequest",
    "CommitClientRollbackResponse",
    "ClientGraphEdgeView",
    "ClientWeightedPathStepView",
    "ClientWeightedPathView",
    "DependencyImpactItemView",
    "EmptyContextMetadataRequest",
    "EmptyContextMetadataResponse",
    "FinalCandidateBinding",
    "GenerationStageWireRecord",
    "GenerationClientBinding",
    "GetGenerationStateRequest",
    "GetGenerationStateResponse",
    "GetGenerationEvidenceForPlanRequest",
    "GetGenerationEvidenceForPlanResponse",
    "GetGenerationBindingRequest",
    "GetGenerationBindingResponse",
    "MAX_FRAME_BYTES",
    "OperationBinding",
    "OperationalErrorCode",
    "OperationalErrorResponse",
    "PROTOCOL_VERSION",
    "PingRequest",
    "PingResponse",
    "PreflightClientLifecycleCommitRequest",
    "PreflightClientLifecycleCommitResponse",
    "PreviewDependencyImpactRequest",
    "PreviewDependencyImpactResponse",
    "PreviewTargetDependencyImpactRequest",
    "PreviewTargetDependencyImpactResponse",
    "PreviewFactMutationRequest",
    "PreviewFactMutationResponse",
    "PersistRiskObservationsRequest",
    "PersistRiskObservationsResponse",
    "PrepareGenerationRetrievalRequest",
    "PrepareGenerationRetrievalResponse",
    "PrepareTurnRiskEvaluationRequest",
    "PrepareTurnRiskEvaluationResponse",
    "PreviewClientDeleteRequest",
    "PreviewClientDeleteResponse",
    "PreviewClientRebuildRequest",
    "PreviewClientRebuildResponse",
    "PreviewClientRollbackRequest",
    "PreviewClientRollbackResponse",
    "PrivateGenerationEvidence",
    "QueryClientGraphRequest",
    "QueryClientGraphResponse",
    "QueryClientWeightedPathRequest",
    "QueryClientWeightedPathResponse",
    "QueryClientHistoryCandidatesRequest",
    "QueryClientHistoryCandidatesResponse",
    "QueryFactSnapshotRequest",
    "QueryFactSnapshotResponse",
    "QueryProfileSnapshotRequest",
    "QueryProfileSnapshotResponse",
    "ReadSessionStateRequest",
    "ReadSessionStateResponse",
    "RecoveredActualReply",
    "RecoveredCandidate",
    "RecoveredClientTurn",
    "RecoveredTemporaryFact",
    "RecordActualReplyRequest",
    "RecordActualReplyResponse",
    "RebuildClientDerivativesRequest",
    "RebuildClientDerivativesResponse",
    "RecoverClientManifestsRequest",
    "RecoverClientManifestsResponse",
    "ResumeSessionRequest",
    "ResumeSessionResponse",
    "SearchClientGraphRequest",
    "SearchClientGraphResponse",
    "SessionRecoveryPayload",
    "SessionTurnState",
    "ScopeDeniedResponse",
    "StoreCandidateSetRequest",
    "StoreCandidateSetResponse",
    "StoreGenerationEvidencePackRequest",
    "StoreGenerationEvidencePackResponse",
    "StageSharedCaseOutboxRequest",
    "StageSharedCaseOutboxResponse",
    "SubmitGenerationStageRequest",
    "SubmitGenerationStageResponse",
    "WorkerOperation",
    "WorkerOperationRegistry",
    "WorkerBaseVersion",
    "WorkerOperationalError",
    "WorkerPermission",
    "WorkerProtocolError",
    "WorkerRequest",
    "WorkerResponse",
    "VerifyClientIntegrityRequest",
    "VerifyClientIntegrityResponse",
    "decode_request",
    "decode_response",
    "encode_message",
    "record_actual_reply_response_matches_request",
    "risk_lifecycle_response_matches_request",
    "submit_generation_stage_response_matches_request",
    "worker_request_binding",
]
