"""Frozen consultation-session records and governed content references."""

from __future__ import annotations

from typing import Literal, TypeAlias

from pydantic import Field, model_validator

from consultation_kb.models.common import (
    ClientId,
    NonEmptyStr,
    ObjectId,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    Uuid7String,
)
from consultation_kb.models.facts import CognitiveType


SessionStatus: TypeAlias = Literal["OPEN", "CLOSED", "ARCHIVED"]
ArchiveState: TypeAlias = Literal[
    "NOT_STARTED", "DRAFT", "INCOMPLETE", "READY", "ARCHIVED"
]
TurnState: TypeAlias = Literal[
    "client_turn_received",
    "generation_in_progress",
    "candidates_generated",
    "awaiting_actual_reply",
    "actual_reply_recorded",
    "external_reply_unknown",
    "turn_closed",
]
ActualReplySource: TypeAlias = Literal["adopted", "edited", "external_unknown"]
TemporaryFactKind: TypeAlias = Literal[
    "ADD",
    "CONFIRM",
    "CORRECT",
    "SUPERSEDE",
    "RESOLVE",
    "MERGE",
    "POSSIBLY_INVALID",
    "GOAL",
    "ISSUE",
    "PREFERENCE",
    "CONSTRAINT",
    "HYPOTHESIS",
    "CONFLICT",
]


class StoredContentRef(StrictModel):
    object_id: ObjectId
    content_sha256: Sha256Hex
    media_type: NonEmptyStr
    size_bytes: int = Field(strict=True, gt=0)


class SessionRecord(StrictModel):
    session_id: Uuid7String
    client_id: ClientId
    client_scope_hash: Sha256Hex
    client_snapshot_version: int = Field(strict=True, ge=0)
    client_snapshot_canonical_sha256: Sha256Hex
    client_snapshot: StoredContentRef
    status: SessionStatus
    capability_epoch: int = Field(strict=True, gt=0)
    last_closed_turn_ordinal: int = Field(strict=True, ge=0)
    archive_state: ArchiveState
    started_at: UtcDateTime
    updated_at: UtcDateTime
    closed_at: UtcDateTime | None

    @model_validator(mode="after")
    def _closed_shape(self) -> "SessionRecord":
        if (self.status == "OPEN") == (self.closed_at is not None):
            raise ValueError("open sessions cannot have closed_at and closed sessions require it")
        return self


class TurnRecord(StrictModel):
    session_id: Uuid7String
    turn_id: Uuid7String
    ordinal: int = Field(strict=True, gt=0)
    client_message: StoredContentRef
    state: TurnState
    active_run_id: Uuid7String | None
    received_at: UtcDateTime
    updated_at: UtcDateTime
    closed_at: UtcDateTime | None

    @model_validator(mode="after")
    def _closed_shape(self) -> "TurnRecord":
        if (self.state == "turn_closed") != (self.closed_at is not None):
            raise ValueError("turn_closed and closed_at must change together")
        return self


class CandidateDraft(StrictModel):
    label: NonEmptyStr
    text: NonEmptyStr


class CandidateReply(StrictModel):
    candidate_id: ObjectId
    candidate_set_id: ObjectId
    session_id: Uuid7String
    turn_id: Uuid7String
    ordinal: int = Field(strict=True, ge=1, le=4)
    label: NonEmptyStr
    content: StoredContentRef
    run_id: Uuid7String
    created_at: UtcDateTime


class CandidateSet(StrictModel):
    candidate_set_id: ObjectId
    session_id: Uuid7String
    turn_id: Uuid7String
    run_id: Uuid7String
    idempotency_key: NonEmptyStr
    set_sha256: Sha256Hex
    candidates: tuple[CandidateReply, ...]
    created_at: UtcDateTime

    @model_validator(mode="after")
    def _candidate_membership(self) -> "CandidateSet":
        if not 2 <= len(self.candidates) <= 4:
            raise ValueError("candidate sets require between two and four candidates")
        if tuple(item.ordinal for item in self.candidates) != tuple(
            range(1, len(self.candidates) + 1)
        ):
            raise ValueError("candidate ordinals must be contiguous")
        if any(
            item.candidate_set_id != self.candidate_set_id
            or item.session_id != self.session_id
            or item.turn_id != self.turn_id
            or item.run_id != self.run_id
            for item in self.candidates
        ):
            raise ValueError("candidate set membership mismatch")
        return self


class ActualReply(StrictModel):
    actual_reply_id: ObjectId
    session_id: Uuid7String
    turn_id: Uuid7String
    idempotency_key: NonEmptyStr
    operation_sha256: Sha256Hex
    source_type: ActualReplySource
    candidate_id: ObjectId | None
    content: StoredContentRef | None
    diff: StoredContentRef | None
    sent_at: UtcDateTime | None
    confirmed_at: UtcDateTime | None
    evidence_gap: bool
    created_at: UtcDateTime

    @model_validator(mode="after")
    def _source_shape(self) -> "ActualReply":
        if self.source_type == "external_unknown":
            valid = (
                self.candidate_id is None
                and self.content is None
                and self.diff is None
                and self.sent_at is None
                and self.confirmed_at is not None
                and self.evidence_gap
            )
        elif self.source_type == "adopted":
            valid = (
                self.candidate_id is not None
                and self.content is not None
                and self.diff is None
                and self.sent_at is not None
                and self.confirmed_at is None
                and not self.evidence_gap
            )
        else:
            valid = (
                self.candidate_id is not None
                and self.content is not None
                and self.diff is not None
                and self.sent_at is not None
                and self.confirmed_at is None
                and not self.evidence_gap
            )
        if not valid:
            raise ValueError("actual reply fields do not match source_type")
        return self


class TemporaryFactEvent(StrictModel):
    event_id: ObjectId
    session_id: Uuid7String
    turn_id: Uuid7String
    event_kind: TemporaryFactKind
    cognitive_type: CognitiveType
    content: StoredContentRef
    target_fact_id: NonEmptyStr | None
    target_fact_version: int | None = Field(default=None, strict=True, gt=0)
    recorded_at: UtcDateTime

    @model_validator(mode="after")
    def _target_shape(self) -> "TemporaryFactEvent":
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
            raise ValueError("temporary target fact ID and version must be paired")
        return self


__all__ = [
    "ActualReply",
    "ActualReplySource",
    "ArchiveState",
    "CandidateDraft",
    "CandidateReply",
    "CandidateSet",
    "SessionRecord",
    "SessionStatus",
    "StoredContentRef",
    "TemporaryFactEvent",
    "TemporaryFactKind",
    "TurnRecord",
    "TurnState",
]
