"""Strict, path-free schemas for the local consultation MCP boundary.

The models in this module are deliberately transport DTOs.  They do not
mirror repository rows and they never accept a filesystem path, SQL text, or
an independently supplied client identity after the initial context load.
"""

from __future__ import annotations

import json
import math
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal, TypeAlias

from pydantic import Field, JsonValue, StringConstraints, field_validator, model_validator

from consultation_kb.core.errors import ToolError
from consultation_kb.generation.contracts import (
    GENERATION_STAGE_ADAPTER,
    GenerationStagePayload,
)
from consultation_kb.evaluation.variants import (
    ALL_SYSTEM_VARIANTS,
    SystemVariantName,
)
from consultation_kb.evaluation.work_queue import (
    EvaluationFairnessContract,
    EvaluationStageResult,
)
from consultation_kb.models.common import (
    ClientId,
    FiniteFloat,
    NonEmptyStr,
    NonNegativeInt,
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
    ReviewCategory,
    SharedCaseSectionDraft,
)
from consultation_kb.models.evidence import EmpiricalSupport, SourceGrade
from consultation_kb.models.facts import CognitiveType as FactCognitiveType
from consultation_kb.models.knowledge import (
    ClaimApplicability,
    ClaimEvidenceRef,
    CognitiveType,
    DocumentType,
)
from consultation_kb.models.session import TemporaryFactKind
from consultation_kb.models.theory import TheoryRevisionDraft
from consultation_kb.models.wiki import WikiRevisionDraft
from consultation_kb.security.worker_protocol import ArchiveContentRef


OpaqueHandle: TypeAlias = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=16,
        max_length=512,
        pattern=r"^[^\x00-\x20\x7f/\\]+$",
    ),
]
LifecycleTargetId: TypeAlias = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
QueryText: TypeAlias = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=16_384),
]
ReplyText: TypeAlias = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=131_072),
]
IdempotencyKey: TypeAlias = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=16,
        max_length=256,
        pattern=r"^[A-Za-z0-9._:-]+$",
    ),
]
ClientAlias: TypeAlias = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[^\x00-\x1f\x7f]+$",
    ),
]


def _json_utc_datetime(value: object) -> object:
    """Restore strict JSON datetime semantics after raw MCP passthrough."""

    if type(value) is not str:
        return value
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value


class ToolEnvelope(StrictModel):
    """Uniform success/error envelope returned by every pure handler."""

    ok: bool
    result: JsonValue | None = None
    error: ToolError | None = None

    @model_validator(mode="after")
    def _closed_state(self) -> "ToolEnvelope":
        if self.ok and self.error is not None:
            raise ValueError("successful tool envelopes cannot contain an error")
        if not self.ok and (self.error is None or self.result is not None):
            raise ValueError("failed tool envelopes require only an error")
        return self


class LoadClientContextInput(StrictModel):
    """The sole MCP input model allowed to contain a client identity."""

    client_id: ClientId
    resume_session_id: Uuid7String | None = None


class _BoundQueryInput(StrictModel):
    session_handle: OpaqueHandle
    query: QueryText
    limit: PositiveInt = 10

    @field_validator("limit")
    @classmethod
    def _bounded_limit(cls, value: int) -> int:
        if value > 100:
            raise ValueError("limit must not exceed 100")
        return value


class SearchClientHistoryInput(_BoundQueryInput):
    as_of: UtcDateTime | None = None

    _accept_json_as_of = field_validator("as_of", mode="before")(
        _json_utc_datetime
    )


class SearchWikiInput(_BoundQueryInput):
    pass


class SearchLexicalInput(_BoundQueryInput):
    pass


class SearchVectorInput(_BoundQueryInput):
    pass


class SearchCasesInput(_BoundQueryInput):
    pass


class QueryGlobalGraphInput(_BoundQueryInput):
    max_depth: PositiveInt = 2

    @field_validator("max_depth")
    @classmethod
    def _bounded_depth(cls, value: int) -> int:
        if value > 8:
            raise ValueError("max_depth must not exceed 8")
        return value


class QueryClientGraphInput(_BoundQueryInput):
    as_of: UtcDateTime | None = None
    max_depth: PositiveInt = 2

    _accept_json_as_of = field_validator("as_of", mode="before")(
        _json_utc_datetime
    )

    @field_validator("max_depth")
    @classmethod
    def _bounded_depth(cls, value: int) -> int:
        if value > 8:
            raise ValueError("max_depth must not exceed 8")
        return value


class WeightedPathInput(StrictModel):
    session_handle: OpaqueHandle
    graph_scope: Literal["global", "client"]
    source_ref: ObjectId
    target_ref: ObjectId
    as_of: UtcDateTime | None = None
    max_paths: PositiveInt = 3
    max_hops: PositiveInt = 8

    _accept_json_as_of = field_validator("as_of", mode="before")(
        _json_utc_datetime
    )

    @model_validator(mode="after")
    def _bounded_search(self) -> "WeightedPathInput":
        if self.source_ref == self.target_ref:
            raise ValueError("weighted path endpoints must differ")
        if self.max_paths > 10 or self.max_hops > 16:
            raise ValueError("weighted path search exceeds its fixed bound")
        return self


class PreviewDependencyImpactInput(StrictModel):
    session_handle: OpaqueHandle
    target_ref: VersionRef
    action: Literal["supersede", "invalidate", "resolve", "revoke"]
    as_of: UtcDateTime | None = None

    _accept_json_as_of = field_validator("as_of", mode="before")(
        _json_utc_datetime
    )


class AppendSessionTurnInput(StrictModel):
    session_handle: OpaqueHandle
    turn_id: Uuid7String
    client_message: ReplyText


class AppendTemporaryFactInput(StrictModel):
    """Append one session-local fact; the value never enters the global store."""

    session_handle: OpaqueHandle
    turn_id: Uuid7String
    idempotency_key: IdempotencyKey
    event_kind: TemporaryFactKind
    cognitive_type: FactCognitiveType
    value: JsonValue
    target_fact_id: NonEmptyStr | None = None
    target_fact_version: PositiveInt | None = None

    @model_validator(mode="after")
    def _target_shape(self) -> "AppendTemporaryFactInput":
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


class CandidateSubmission(StrictModel):
    label: NonEmptyStr
    text: ReplyText


class StoreCandidateSetInput(StrictModel):
    session_handle: OpaqueHandle
    turn_id: Uuid7String
    run_id: Uuid7String
    idempotency_key: IdempotencyKey
    candidates: tuple[CandidateSubmission, ...]

    @field_validator("candidates", mode="before")
    @classmethod
    def _accept_json_candidates(cls, value: object) -> object:
        """Canonical JSON arrays become the immutable domain tuple."""

        return tuple(value) if type(value) is list else value

    @field_validator("candidates")
    @classmethod
    def _bounded_candidates(
        cls, value: tuple[CandidateSubmission, ...]
    ) -> tuple[CandidateSubmission, ...]:
        if not 2 <= len(value) <= 3:
            raise ValueError("candidate set must contain two or three entries")
        labels = [item.label for item in value]
        if len(labels) != len(set(labels)):
            raise ValueError("candidate labels must be unique")
        return value


RevisionReason: TypeAlias = Annotated[NonEmptyStr, Field(max_length=1_000)]
CounselorDisposition: TypeAlias = Annotated[NonEmptyStr, Field(max_length=2_000)]


class SubmitGenerationStageInput(StrictModel):
    """Submit one private, structured stage for the bound consultation turn."""

    session_handle: OpaqueHandle
    idempotency_key: IdempotencyKey
    payload: GenerationStagePayload
    revision_reason: RevisionReason | None = None

    @field_validator("payload", mode="before")
    @classmethod
    def _accept_json_payload(cls, value: object) -> object:
        # The raw MCP boundary hands Python dictionaries to strict models.
        # Re-validate through JSON semantics so UTC timestamps are decoded
        # without weakening any strict scalar or discriminated-union rule.
        if type(value) is dict:
            return GENERATION_STAGE_ADAPTER.validate_json(
                json.dumps(
                    value,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        return value


class GetGenerationStateInput(StrictModel):
    session_handle: OpaqueHandle
    turn_id: Uuid7String
    run_id: Uuid7String


class AcknowledgeRiskObservationInput(StrictModel):
    session_handle: OpaqueHandle
    observation_id: ObjectId
    action: Literal["acknowledge", "close"]
    counselor_disposition: CounselorDisposition | None = None
    rejection_reason: CounselorDisposition | None = None
    close_decision: SafePolicyKey | None = None
    close_reason: CounselorDisposition | None = None

    @model_validator(mode="after")
    def _manual_decision(self) -> "AcknowledgeRiskObservationInput":
        acknowledgement = (self.counselor_disposition, self.rejection_reason)
        closure = (self.close_decision, self.close_reason)
        if self.action == "acknowledge":
            if not any(value is not None for value in acknowledgement):
                raise ValueError(
                    "risk acknowledgement requires a disposition or rejection reason"
                )
            if any(value is not None for value in closure):
                raise ValueError("risk acknowledgement cannot contain close fields")
        elif any(value is not None for value in acknowledgement):
            raise ValueError("risk close cannot contain acknowledgement fields")
        elif any(value is None for value in closure):
            raise ValueError("risk close requires an exact decision and reason")
        return self


class RecordActualReplyInput(StrictModel):
    session_handle: OpaqueHandle
    turn_id: Uuid7String
    idempotency_key: IdempotencyKey
    mode: Literal["adopted", "edited", "external_unknown"]
    candidate_id: ObjectId | None = None
    actual_text: ReplyText | None = None
    sent_at: UtcDateTime | None = None
    confirmed_at: UtcDateTime | None = None

    _accept_json_times = field_validator(
        "sent_at",
        "confirmed_at",
        mode="before",
    )(_json_utc_datetime)

    @model_validator(mode="after")
    def _mode_payload(self) -> "RecordActualReplyInput":
        if self.mode == "adopted":
            if (
                self.candidate_id is None
                or self.actual_text is not None
                or self.sent_at is None
                or self.confirmed_at is not None
            ):
                raise ValueError("adopted replies require candidate and sent time")
        elif self.mode == "edited":
            if (
                self.candidate_id is None
                or self.actual_text is None
                or self.sent_at is None
                or self.confirmed_at is not None
            ):
                raise ValueError("edited replies require candidate, text and sent time")
        elif (
            any(
                value is not None
                for value in (self.candidate_id, self.actual_text, self.sent_at)
            )
            or self.confirmed_at is None
        ):
            raise ValueError("external unknown replies require only confirmation time")
        return self


class ProposeArchiveInput(StrictModel):
    """Create one archive bundle inside the already-bound client worker.

    The model-facing boundary deliberately accepts neither archive bodies nor
    a client selector.  A trusted analysis producer may first persist an exact
    scoped-CAS object and pass only its immutable reference.
    """

    session_handle: OpaqueHandle
    analysis_ref: ArchiveContentRef | None = None


class PreviewPrivateArchiveInput(StrictModel):
    """Request review of the exact private draft returned by proposal."""

    session_handle: OpaqueHandle
    bundle_id: ObjectId
    draft_ref: ArchiveContentRef
    review_diff_ref: VersionRef
    base_version: NonNegativeInt


class CommitPrivateArchiveInput(StrictModel):
    """Apply an exact private draft using its one-shot approval binding."""

    session_handle: OpaqueHandle
    bundle_id: ObjectId
    draft_ref: ArchiveContentRef
    base_version: NonNegativeInt
    approval_operation_id: ObjectId
    approval_request_id: ObjectId


class PreviewProfileDiffInput(StrictModel):
    """Build and review one exact profile-diff selection.

    BUILD accepts only a trusted scoped-CAS input reference.  A later
    PREPARE_APPROVAL call carries only the returned draft reference and exact
    review selections; the worker reconstructs private operation bodies.
    """

    session_handle: OpaqueHandle
    action: Literal["BUILD", "PREPARE_APPROVAL"] = "BUILD"
    build_input_ref: ArchiveContentRef | None = None
    draft_ref: ArchiveContentRef | None = None
    selected_operation_ids: tuple[NonEmptyStr, ...] = ()
    dismissed_indirect_review_fact_ids: tuple[NonEmptyStr, ...] = ()

    @field_validator(
        "selected_operation_ids",
        "dismissed_indirect_review_fact_ids",
        mode="before",
    )
    @classmethod
    def _accept_json_id_lists(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value

    @model_validator(mode="after")
    def _exact_action(self) -> "PreviewProfileDiffInput":
        if self.action == "BUILD":
            valid = (
                self.build_input_ref is not None
                and self.draft_ref is None
                and not self.selected_operation_ids
                and not self.dismissed_indirect_review_fact_ids
            )
        else:
            valid = (
                self.build_input_ref is None
                and self.draft_ref is not None
                and bool(self.selected_operation_ids)
                and len(self.selected_operation_ids)
                == len(set(self.selected_operation_ids))
                and len(self.dismissed_indirect_review_fact_ids)
                == len(set(self.dismissed_indirect_review_fact_ids))
            )
        if not valid:
            raise ValueError("profile preview payload does not match action")
        return self


class CommitProfileUpdateInput(StrictModel):
    """Apply the exact prepared selection using its independent approval."""

    session_handle: OpaqueHandle
    bundle_id: ObjectId
    draft_ref: ArchiveContentRef
    selected_operation_ids: tuple[NonEmptyStr, ...]
    dismissed_indirect_review_fact_ids: tuple[NonEmptyStr, ...] = ()
    approval_operation_id: ObjectId
    approval_request_id: ObjectId
    expected_runtime_epoch: PositiveInt
    publication_timestamp: UtcDateTime

    @field_validator(
        "selected_operation_ids",
        "dismissed_indirect_review_fact_ids",
        mode="before",
    )
    @classmethod
    def _accept_json_id_lists(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value

    _accept_json_time = field_validator(
        "publication_timestamp",
        mode="before",
    )(_json_utc_datetime)

    @model_validator(mode="after")
    def _canonical_selection(self) -> "CommitProfileUpdateInput":
        if (
            not self.selected_operation_ids
            or len(self.selected_operation_ids)
            != len(set(self.selected_operation_ids))
            or len(self.dismissed_indirect_review_fact_ids)
            != len(set(self.dismissed_indirect_review_fact_ids))
        ):
            raise ValueError("profile commit selection is invalid")
        return self


class ApproveCaseInput(StrictModel):
    """Prepare or commit a shared case using a third independent approval."""

    session_handle: OpaqueHandle
    action: Literal["PREPARE", "COMMIT"]
    bundle_id: ObjectId
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
    def _accept_json_sections(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value

    @field_validator("checked_categories", "allowed_uses", mode="before")
    @classmethod
    def _accept_json_sets(cls, value: object) -> object:
        return frozenset(value) if type(value) is list else value

    _accept_json_expiry = field_validator(
        "authorization_expires_at",
        mode="before",
    )(_json_utc_datetime)

    @model_validator(mode="after")
    def _exact_action(self) -> "ApproveCaseInput":
        commit_fields = (
            self.candidate_ref,
            self.scan_ref,
            self.review_policy_draft_ref,
            self.approval_operation_id,
            self.approval_request_id,
        )
        if self.action == "PREPARE":
            valid = bool(self.section_drafts) and all(
                value is None for value in commit_fields
            )
        else:
            valid = not self.section_drafts and all(
                value is not None for value in commit_fields
            )
        if self.reuse_authorized:
            valid = valid and (
                self.decision == "approved"
                and bool(self.allowed_uses)
                and self.authorization_expires_at is not None
            )
        else:
            valid = valid and (
                not self.allowed_uses
                and self.authorization_expires_at is None
            )
        if not valid:
            raise ValueError("case approval payload does not match action")
        return self


class ListSourceInboxInput(StrictModel):
    pass


class SourceMetadataInput(StrictModel):
    license: NonEmptyStr
    domain: NonEmptyStr
    language: NonEmptyStr
    sensitivity: NonEmptyStr
    source_grade: SourceGrade
    document_type: DocumentType
    author: NonEmptyStr | None = None
    observed_at: UtcDateTime | None = None
    review_due_at: UtcDateTime | None = None

    _accept_json_times = field_validator(
        "observed_at",
        "review_due_at",
        mode="before",
    )(_json_utc_datetime)


class RegisterSourceDraftInput(StrictModel):
    source_handle: OpaqueHandle
    metadata: SourceMetadataInput


class ExtractPassagesInput(StrictModel):
    source_ref: VersionRef
    extractor_version: NonEmptyStr


class ClaimDraftInput(StrictModel):
    """Claim proposal without caller-controlled provenance or C1 authority."""

    text: ReplyText
    cognitive_type: CognitiveType
    source_grade: SourceGrade
    empirical_support: EmpiricalSupport
    model_confidence: FiniteFloat | None = None
    applicability: ClaimApplicability
    allowed_uses: frozenset[SafePolicyKey]
    evidence: tuple[ClaimEvidenceRef, ...]

    @field_validator("allowed_uses", mode="before")
    @classmethod
    def _accept_json_allowed_uses(cls, value: object) -> object:
        return frozenset(value) if type(value) is list else value

    @field_validator("evidence", mode="before")
    @classmethod
    def _accept_json_evidence(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value

    @field_validator("applicability", mode="before")
    @classmethod
    def _accept_json_applicability(cls, value: object) -> object:
        if type(value) is not dict:
            return value
        converted = dict(value)
        for field in (
            "domains",
            "populations",
            "contexts",
            "required_conditions",
            "exclusions",
            "contraindications",
        ):
            item = converted.get(field)
            if type(item) is list:
                converted[field] = frozenset(item)
        return converted

    @model_validator(mode="after")
    def _safe_proposal(self) -> "ClaimDraftInput":
        if self.source_grade == "C1":
            raise ValueError("C1 authority can only be proposed as a theory revision")
        if self.model_confidence is not None and not math.isfinite(
            self.model_confidence
        ):
            raise ValueError("model confidence must be finite")
        if self.model_confidence is not None and not 0 <= self.model_confidence <= 1:
            raise ValueError("model confidence must be within zero and one")
        if not self.allowed_uses or not self.evidence:
            raise ValueError("claim proposals require use and evidence")
        return self


class ProposeClaimsInput(StrictModel):
    claims: tuple[ClaimDraftInput, ...]

    @field_validator("claims", mode="before")
    @classmethod
    def _accept_json_claims(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value

    @field_validator("claims")
    @classmethod
    def _bounded_claims(
        cls, value: tuple[ClaimDraftInput, ...]
    ) -> tuple[ClaimDraftInput, ...]:
        if not 1 <= len(value) <= 100:
            raise ValueError("claim proposal batch must contain one to 100 claims")
        return value


class PreviewClaimReviewInput(StrictModel):
    proposal_id: ObjectId


class ProposeWikiUpdateInput(StrictModel):
    """Governed Wiki proposal payload; formal authority still needs approval."""

    draft: WikiRevisionDraft

    @field_validator("draft", mode="before")
    @classmethod
    def _accept_json_draft(cls, value: object) -> object:
        if type(value) is not dict:
            return value
        converted = dict(value)
        due_at = converted.get("review_due_at")
        if type(due_at) is str:
            try:
                converted["review_due_at"] = _json_utc_datetime(due_at)
            except ValueError:
                pass
        for field in (
            "sections",
            "theory_revision_refs",
            "relationships",
            "graph_relations",
            "unresolved_questions",
        ):
            item = converted.get(field)
            if type(item) is list:
                converted[field] = tuple(item)

        sections = converted.get("sections")
        if type(sections) is tuple:
            normalized_sections: list[object] = []
            for item in sections:
                if type(item) is not dict:
                    normalized_sections.append(item)
                    continue
                section = dict(item)
                for field in ("claim_refs", "passage_refs"):
                    references = section.get(field)
                    if type(references) is list:
                        section[field] = tuple(references)
                normalized_sections.append(section)
            converted["sections"] = tuple(normalized_sections)

        relationships = converted.get("relationships")
        if type(relationships) is tuple:
            normalized_relationships: list[object] = []
            for item in relationships:
                if type(item) is not dict:
                    normalized_relationships.append(item)
                    continue
                relationship = dict(item)
                for field in ("scope", "source_refs"):
                    entries = relationship.get(field)
                    if type(entries) is list:
                        relationship[field] = tuple(entries)
                normalized_relationships.append(relationship)
            converted["relationships"] = tuple(normalized_relationships)

        graph_relations = converted.get("graph_relations")
        if type(graph_relations) is tuple:
            normalized_graph_relations: list[object] = []
            for item in graph_relations:
                if type(item) is not dict:
                    normalized_graph_relations.append(item)
                    continue
                relation = dict(item)
                scope = relation.get("scope")
                if type(scope) is list:
                    relation["scope"] = tuple(scope)
                for field in ("effective_from", "effective_to"):
                    instant = relation.get(field)
                    if type(instant) is str:
                        try:
                            relation[field] = _json_utc_datetime(instant)
                        except ValueError:
                            pass
                normalized_graph_relations.append(relation)
            converted["graph_relations"] = tuple(normalized_graph_relations)
        return converted


class PreviewWikiUpdateInput(StrictModel):
    wiki_draft_id: ObjectId


class KnowledgeLintInput(StrictModel):
    catalog_version: NonNegativeInt | None = None


class ProposeTheoryRevisionInput(StrictModel):
    draft: TheoryRevisionDraft

    @field_validator("draft", mode="before")
    @classmethod
    def _accept_json_draft(cls, value: object) -> object:
        if type(value) is not dict:
            return value
        converted = dict(value)
        for field in ("effective_from", "effective_to"):
            item = converted.get(field)
            if type(item) is str:
                converted[field] = _json_utc_datetime(item)
        for field in (
            "core_claims",
            "methods",
            "contraindications",
            "counterexamples",
            "passage_refs",
            "citation_refs",
        ):
            item = converted.get(field)
            if type(item) is list:
                converted[field] = tuple(item)
        scope = converted.get("scope")
        if type(scope) is dict:
            converted_scope = dict(scope)
            for field in (
                "domains",
                "populations",
                "contexts",
                "required_conditions",
                "exclusions",
                "contraindications",
            ):
                item = converted_scope.get(field)
                if type(item) is list:
                    converted_scope[field] = frozenset(item)
            converted["scope"] = converted_scope
        return converted


class ApprovalExecutionInput(StrictModel):
    """Only the opaque request is accepted; its descriptor binds every target."""

    approval_request_id: ObjectId


class CreateClientInput(StrictModel):
    """Two-phase client creation: preview an alias, then commit an approval."""

    action: Literal["preview", "commit"]
    alias: ClientAlias | None = None
    idempotency_key: IdempotencyKey | None = None
    approval_request_id: ObjectId | None = None

    @model_validator(mode="after")
    def _phase_payload(self) -> "CreateClientInput":
        if self.action == "preview":
            valid = (
                self.alias is not None
                and self.idempotency_key is not None
                and self.approval_request_id is None
            )
            if self.alias is not None and self.alias.strip() != self.alias:
                valid = False
        else:
            valid = (
                self.alias is None
                and self.idempotency_key is None
                and self.approval_request_id is not None
            )
        if not valid:
            raise ValueError("create client payload does not match action")
        return self


class ApprovePassageInput(ApprovalExecutionInput):
    pass


class ApproveClaimInput(ApprovalExecutionInput):
    pass


class RevokeClaimInput(ApprovalExecutionInput):
    pass


class PublishWikiInput(ApprovalExecutionInput):
    pass


class ApproveTheoryRevisionInput(ApprovalExecutionInput):
    pass


class RevokeTheoryRevisionInput(ApprovalExecutionInput):
    pass


class LifecycleBaseVersion(StrictModel):
    """Exact body-free authority version bound into an operator plan."""

    authority_key: SafePolicyKey
    scope_sha256: Sha256Hex
    version: NonNegativeInt


class _LifecycleScopedInput(StrictModel):
    session_handle: OpaqueHandle
    database_scope: Literal["global", "client"]
    scope_sha256: Sha256Hex


class _LifecycleApprovedInput(_LifecycleScopedInput):
    approval_operation_id: ObjectId
    approval_request_id: ObjectId
    plan_sha256: Sha256Hex
    base_versions: tuple[LifecycleBaseVersion, ...]

    @field_validator("base_versions", mode="before")
    @classmethod
    def _accept_json_base_versions(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value

    @model_validator(mode="after")
    def _canonical_base_versions(self) -> "_LifecycleApprovedInput":
        keys = tuple(
            (value.authority_key, value.scope_sha256)
            for value in self.base_versions
        )
        if not keys or keys != tuple(sorted(set(keys))):
            raise ValueError("lifecycle base versions must be non-empty and canonical")
        return self


class RollbackVersionInput(_LifecycleScopedInput):
    """Two-phase exact rollback surface without caller-supplied bodies.

    Preview identifies authoritative versions and produces the immutable plan.
    Commit accepts only that plan reference plus the exact P1 approval binding;
    target identity, versions, reason, paths, SQL, and replacement content cannot
    be resubmitted after review.
    """

    action: Literal["preview", "commit"]
    target_kind: Literal["profile_fact", "wiki", "theory", "artifact"] | None = (
        None
    )
    target_id: LifecycleTargetId | None = None
    current_version: PositiveInt | None = None
    restore_version: PositiveInt | None = None
    reason: NonEmptyStr | None = None
    source_plan_ref: ArchiveContentRef | None = None
    plan_ref: ArchiveContentRef | None = None
    approval_operation_id: ObjectId | None = None
    approval_request_id: ObjectId | None = None
    plan_sha256: Sha256Hex | None = None
    base_versions: tuple[LifecycleBaseVersion, ...] | None = None

    @field_validator("base_versions", mode="before")
    @classmethod
    def _accept_json_base_versions(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value

    @model_validator(mode="after")
    def _exact_phase_payload(self) -> "RollbackVersionInput":
        if self.action == "preview":
            valid = (
                self.target_kind is not None
                and self.target_id is not None
                and self.current_version is not None
                and self.restore_version is not None
                and self.restore_version < self.current_version
                and self.reason is not None
                and (
                    (self.target_kind == "artifact")
                    == (self.source_plan_ref is not None)
                )
                and self.plan_ref is None
                and self.approval_operation_id is None
                and self.approval_request_id is None
                and self.plan_sha256 is None
                and self.base_versions is None
            )
            if not valid:
                raise ValueError("rollback preview payload is not exact")
            return self

        values = self.base_versions
        keys = (
            ()
            if values is None
            else tuple(
                (value.authority_key, value.scope_sha256) for value in values
            )
        )
        valid = (
            self.target_kind is None
            and self.target_id is None
            and self.current_version is None
            and self.restore_version is None
            and self.reason is None
            and self.source_plan_ref is None
            and self.plan_ref is not None
            and self.approval_operation_id is not None
            and self.approval_request_id is not None
            and self.plan_sha256 is not None
            and values is not None
            and bool(keys)
            and keys == tuple(sorted(set(keys)))
        )
        if not valid:
            raise ValueError("rollback commit payload is not exact")
        return self


class PreviewRebuildInput(_LifecycleScopedInput):
    action: Literal["start", "cancel"]
    purpose: SafePolicyKey | None = None
    source_intent_id: ObjectId | None = None
    job_id: ObjectId | None = None
    policy_sha256: Sha256Hex | None = None
    model_descriptor_sha256: Sha256Hex | None = None

    @model_validator(mode="after")
    def _one_action(self) -> "PreviewRebuildInput":
        if self.action == "start":
            if self.purpose != "all" or self.job_id is not None:
                raise ValueError("full-closure rebuild preview required")
        elif (
            self.job_id is None
            or self.purpose is not None
            or self.source_intent_id is not None
            or self.policy_sha256 is not None
            or self.model_descriptor_sha256 is not None
        ):
            raise ValueError("cancel rebuild preview is not exact")
        return self


class StartRebuildInput(_LifecycleApprovedInput):
    plan_ref: ArchiveContentRef
    idempotency_key: IdempotencyKey

    @model_validator(mode="after")
    def _single_tombstone_base(self) -> "StartRebuildInput":
        if (
            len(self.base_versions) != 1
            or self.base_versions[0].authority_key != "tombstone_epoch"
        ):
            raise ValueError("single tombstone epoch base version required")
        return self


class GetRebuildStatusInput(_LifecycleScopedInput):
    job_id: ObjectId


class GetRebuildReportInput(GetRebuildStatusInput):
    pass


class CancelRebuildInput(_LifecycleApprovedInput):
    plan_ref: ArchiveContentRef

    @model_validator(mode="after")
    def _single_tombstone_base(self) -> "CancelRebuildInput":
        if (
            len(self.base_versions) != 1
            or self.base_versions[0].authority_key != "tombstone_epoch"
        ):
            raise ValueError("single tombstone epoch base version required")
        return self


class PreviewDeleteInput(_LifecycleScopedInput):
    target_type: Literal[
        "client",
        "session",
        "case",
        "case_authorization",
        "passage",
        "claim",
    ]
    target_id: LifecycleTargetId | None = None
    target_version: NonNegativeInt | None = None
    target_content_sha256: Sha256Hex | None = None
    reason_code: SafePolicyKey

    @model_validator(mode="after")
    def _current_client_or_exact_target(self) -> "PreviewDeleteInput":
        if self.target_type == "client":
            if (
                self.database_scope != "client"
                or self.target_id != "current-client"
                or self.target_version is not None
                or self.target_content_sha256 is not None
            ):
                raise ValueError("bound current-client deletion required")
            return self
        if (
            self.target_id is None
            or self.target_version is None
            or self.target_content_sha256 is None
        ):
            raise ValueError("exact deletion target authority required")
        return self


class CommitDeleteInput(_LifecycleApprovedInput):
    plan_ref: ArchiveContentRef
    target_scope_hash: Sha256Hex
    deletion_subject: Literal["planned_target", "current_client"] = (
        "planned_target"
    )

    @model_validator(mode="after")
    def _bound_current_client_scope(self) -> "CommitDeleteInput":
        if (
            self.deletion_subject == "current_client"
            and self.database_scope != "client"
        ):
            raise ValueError("current-client commit requires client scope")
        return self


class EvaluationRoutePolicyInput(StrictModel):
    variant_name: SystemVariantName
    route_policy_ref: VersionRef


class PrepareEvaluationInput(StrictModel):
    """Freeze one repository-controlled synthetic paired evaluation queue."""

    evaluation_run_id: Uuid7String
    fairness: EvaluationFairnessContract
    route_policies: tuple[EvaluationRoutePolicyInput, ...]
    variants: tuple[SystemVariantName, ...] = tuple(
        variant.name for variant in ALL_SYSTEM_VARIANTS
    )
    repetition_count: Annotated[int, Field(strict=True, ge=2, le=100)] = 2
    case_ids: tuple[SafePolicyKey, ...] = ()
    include_canary: bool = False

    @field_validator("fairness", mode="before")
    @classmethod
    def _accept_json_fairness(cls, value: object) -> object:
        if type(value) is dict:
            return EvaluationFairnessContract.model_validate_json(
                json.dumps(
                    value,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                strict=True,
            )
        return value

    @field_validator("route_policies", "variants", "case_ids", mode="before")
    @classmethod
    def _accept_json_arrays(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value

    @model_validator(mode="after")
    def _closed_selection(self) -> "PrepareEvaluationInput":
        names = tuple(item.variant_name for item in self.route_policies)
        if len(names) != len(set(names)) or set(names) != set(self.variants):
            raise ValueError("route policies must exactly cover selected variants")
        if len(self.variants) != len(set(self.variants)):
            raise ValueError("evaluation variants must be unique")
        canonical = tuple(
            item.name for item in ALL_SYSTEM_VARIANTS if item.name in self.variants
        )
        if self.variants != canonical or names != canonical:
            raise ValueError("evaluation variants must use canonical registry order")
        if len(self.case_ids) != len(set(self.case_ids)):
            raise ValueError("evaluation case IDs must be unique")
        if self.case_ids != tuple(sorted(self.case_ids)):
            raise ValueError("evaluation case IDs must use canonical order")
        return self


class GetNextEvaluationCaseInput(StrictModel):
    evaluation_handle: Sha256Hex


class SubmitEvaluationResultInput(StrictModel):
    """Submit one exact result bound to every frozen experiment hash."""

    evaluation_handle: Sha256Hex
    work_item_id: Sha256Hex
    case_payload_sha256: Sha256Hex
    variant_sha256: Sha256Hex
    client_snapshot_ref: VersionRef
    evidence_catalog_sha256: Sha256Hex
    evidence_pack_sha256: Sha256Hex
    result: EvaluationStageResult

    @field_validator("result", mode="before")
    @classmethod
    def _accept_json_result(cls, value: object) -> object:
        if type(value) is dict:
            return EvaluationStageResult.model_validate_json(
                json.dumps(
                    value,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                strict=True,
            )
        return value


class MissingEvaluationReasonInput(StrictModel):
    work_item_id: Sha256Hex
    reason_code: SafePolicyKey


class FinalizeEvaluationInput(StrictModel):
    evaluation_handle: Sha256Hex
    missing_reasons: tuple[MissingEvaluationReasonInput, ...] = ()

    @field_validator("missing_reasons", mode="before")
    @classmethod
    def _accept_json_missing(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value

    @field_validator("missing_reasons")
    @classmethod
    def _canonical_missing(
        cls,
        value: tuple[MissingEvaluationReasonInput, ...],
    ) -> tuple[MissingEvaluationReasonInput, ...]:
        identifiers = tuple(item.work_item_id for item in value)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("missing evaluation reasons must be unique")
        if identifiers != tuple(sorted(identifiers)):
            raise ValueError("missing evaluation reasons must use canonical order")
        return value


LIFECYCLE_TOOL_INPUT_MODELS: dict[str, type[StrictModel]] = {
    "rollback_version": RollbackVersionInput,
    "start_rebuild": StartRebuildInput,
    "get_rebuild_status": GetRebuildStatusInput,
    "get_rebuild_report": GetRebuildReportInput,
    "cancel_rebuild": CancelRebuildInput,
    "preview_rebuild": PreviewRebuildInput,
    "preview_delete": PreviewDeleteInput,
    "commit_delete": CommitDeleteInput,
}


EVALUATION_TOOL_INPUT_MODELS: dict[str, type[StrictModel]] = {
    "prepare_evaluation": PrepareEvaluationInput,
    "get_next_evaluation_case": GetNextEvaluationCaseInput,
    "submit_evaluation_result": SubmitEvaluationResultInput,
    "finalize_evaluation": FinalizeEvaluationInput,
}


class ToolAccess(str, Enum):
    READ = "read"
    DRAFT_WRITE = "draft_write"
    FORMAL_WRITE = "formal_write"


class ToolAnnotations(StrictModel):
    access: ToolAccess
    read_only: bool
    destructive: bool
    approval_required: bool

    @model_validator(mode="after")
    def _consistent(self) -> "ToolAnnotations":
        expected = {
            ToolAccess.READ: (True, False, False),
            ToolAccess.DRAFT_WRITE: (False, False, False),
            ToolAccess.FORMAL_WRITE: (False, True, True),
        }[self.access]
        if (self.read_only, self.destructive, self.approval_required) != expected:
            raise ValueError("tool annotations do not match access class")
        return self


READ_ANNOTATIONS = ToolAnnotations(
    access=ToolAccess.READ,
    read_only=True,
    destructive=False,
    approval_required=False,
)
DRAFT_WRITE_ANNOTATIONS = ToolAnnotations(
    access=ToolAccess.DRAFT_WRITE,
    read_only=False,
    destructive=False,
    approval_required=False,
)
FORMAL_WRITE_ANNOTATIONS = ToolAnnotations(
    access=ToolAccess.FORMAL_WRITE,
    read_only=False,
    destructive=True,
    approval_required=True,
)


TOOL_INPUT_MODELS: dict[str, type[StrictModel]] = {
    "load_client_context": LoadClientContextInput,
    "search_client_history": SearchClientHistoryInput,
    "search_wiki": SearchWikiInput,
    "search_lexical": SearchLexicalInput,
    "search_vector": SearchVectorInput,
    "search_cases": SearchCasesInput,
    "query_global_graph": QueryGlobalGraphInput,
    "query_client_graph": QueryClientGraphInput,
    "weighted_path": WeightedPathInput,
    "preview_dependency_impact": PreviewDependencyImpactInput,
    "append_session_turn": AppendSessionTurnInput,
    "append_temporary_fact": AppendTemporaryFactInput,
    "store_candidate_set": StoreCandidateSetInput,
    "record_actual_reply": RecordActualReplyInput,
    "submit_generation_stage": SubmitGenerationStageInput,
    "get_generation_state": GetGenerationStateInput,
    "acknowledge_risk_observation": AcknowledgeRiskObservationInput,
    "list_source_inbox": ListSourceInboxInput,
    "register_source_draft": RegisterSourceDraftInput,
    "extract_passages": ExtractPassagesInput,
    "propose_claims": ProposeClaimsInput,
    "preview_claim_review": PreviewClaimReviewInput,
    "propose_wiki_update": ProposeWikiUpdateInput,
    "preview_wiki_update": PreviewWikiUpdateInput,
    "knowledge_lint": KnowledgeLintInput,
    "propose_theory_revision": ProposeTheoryRevisionInput,
    "create_client": CreateClientInput,
    "approve_passage": ApprovePassageInput,
    "approve_claim": ApproveClaimInput,
    "revoke_claim": RevokeClaimInput,
    "publish_wiki": PublishWikiInput,
    "approve_theory_revision": ApproveTheoryRevisionInput,
    "revoke_theory_revision": RevokeTheoryRevisionInput,
    "propose_archive": ProposeArchiveInput,
    "preview_private_archive": PreviewPrivateArchiveInput,
    "commit_private_archive": CommitPrivateArchiveInput,
    "preview_profile_diff": PreviewProfileDiffInput,
    "commit_profile_update": CommitProfileUpdateInput,
    "approve_case": ApproveCaseInput,
    **LIFECYCLE_TOOL_INPUT_MODELS,
    **EVALUATION_TOOL_INPUT_MODELS,
}


__all__ = [
    "AcknowledgeRiskObservationInput",
    "ApproveCaseInput",
    "AppendSessionTurnInput",
    "AppendTemporaryFactInput",
    "ApprovalExecutionInput",
    "ApproveClaimInput",
    "ApprovePassageInput",
    "ApproveTheoryRevisionInput",
    "CandidateSubmission",
    "CreateClientInput",
    "CommitPrivateArchiveInput",
    "CommitProfileUpdateInput",
    "CancelRebuildInput",
    "DRAFT_WRITE_ANNOTATIONS",
    "EVALUATION_TOOL_INPUT_MODELS",
    "EvaluationRoutePolicyInput",
    "ExtractPassagesInput",
    "FinalizeEvaluationInput",
    "FORMAL_WRITE_ANNOTATIONS",
    "GetGenerationStateInput",
    "GetNextEvaluationCaseInput",
    "GetRebuildReportInput",
    "GetRebuildStatusInput",
    "KnowledgeLintInput",
    "ListSourceInboxInput",
    "LoadClientContextInput",
    "LifecycleBaseVersion",
    "LIFECYCLE_TOOL_INPUT_MODELS",
    "PreviewClaimReviewInput",
    "PreviewDependencyImpactInput",
    "PreviewPrivateArchiveInput",
    "PreviewProfileDiffInput",
    "PreviewDeleteInput",
    "PreviewRebuildInput",
    "PreviewWikiUpdateInput",
    "ProposeClaimsInput",
    "ProposeArchiveInput",
    "ProposeTheoryRevisionInput",
    "ProposeWikiUpdateInput",
    "PrepareEvaluationInput",
    "PublishWikiInput",
    "QueryClientGraphInput",
    "QueryGlobalGraphInput",
    "READ_ANNOTATIONS",
    "RecordActualReplyInput",
    "RegisterSourceDraftInput",
    "RollbackVersionInput",
    "ReplyText",
    "RevokeClaimInput",
    "RevokeTheoryRevisionInput",
    "SearchCasesInput",
    "SearchClientHistoryInput",
    "SearchLexicalInput",
    "SearchVectorInput",
    "SearchWikiInput",
    "SourceMetadataInput",
    "StoreCandidateSetInput",
    "StartRebuildInput",
    "CommitDeleteInput",
    "SubmitGenerationStageInput",
    "SubmitEvaluationResultInput",
    "TOOL_INPUT_MODELS",
    "ToolAccess",
    "ToolAnnotations",
    "ToolEnvelope",
    "WeightedPathInput",
]
