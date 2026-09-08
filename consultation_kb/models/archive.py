"""Strict client-local contracts for consultation archive boundaries."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Literal, TypeAlias

from pydantic import Field, field_validator, model_validator

from consultation_kb.models.common import (
    NonEmptyStr,
    ObjectId,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    Uuid7String,
    VersionRef,
)
from consultation_kb.models.session import ActualReplySource
from consultation_kb.models.manifests import DraftDescriptor


ArchivePurpose: TypeAlias = Literal["private_archive", "profile_diff", "shared_case"]
ArchivePurposeState: TypeAlias = Literal[
    "DRAFT",
    "PREPARED",
    "ACTIVE",
    "REJECTED",
    "NO_CHANGE",
    "PRIVATE_ONLY",
]

ARCHIVE_PURPOSE_ORDER: tuple[ArchivePurpose, ...] = (
    "private_archive",
    "profile_diff",
    "shared_case",
)
LEGAL_PURPOSE_STATES: dict[ArchivePurpose, frozenset[ArchivePurposeState]] = {
    "private_archive": frozenset({"DRAFT", "PREPARED", "ACTIVE", "REJECTED"}),
    "profile_diff": frozenset(
        {"DRAFT", "PREPARED", "ACTIVE", "REJECTED", "NO_CHANGE"}
    ),
    "shared_case": frozenset(
        {"DRAFT", "PREPARED", "ACTIVE", "REJECTED", "PRIVATE_ONLY"}
    ),
}


def _canonical_json_text(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="strict")).hexdigest()


class ArchivePurposeStatus(StrictModel):
    purpose: ArchivePurpose
    state: ArchivePurposeState
    manifest_id: ObjectId | None = None
    review_decision_id: ObjectId | None = None

    @model_validator(mode="after")
    def _validate_purpose_state(self) -> "ArchivePurposeStatus":
        if self.state not in LEGAL_PURPOSE_STATES[self.purpose]:
            raise ValueError("purpose state is not legal for archive purpose")
        if self.state == "DRAFT":
            valid_refs = self.manifest_id is None and self.review_decision_id is None
        elif self.state == "PREPARED":
            valid_refs = self.manifest_id is None and self.review_decision_id is not None
        elif self.state == "ACTIVE":
            valid_refs = self.manifest_id is not None and self.review_decision_id is not None
        else:
            valid_refs = self.manifest_id is None and self.review_decision_id is not None
        if not valid_refs:
            raise ValueError("purpose state references do not match lifecycle state")
        return self


class ActualTranscriptTurn(StrictModel):
    ordinal: int = Field(strict=True, gt=0)
    turn_id: Uuid7String
    client_message_ref: VersionRef
    client_message_text: NonEmptyStr
    actual_reply_ref: VersionRef | None
    reply_text: NonEmptyStr | None
    reply_source_type: ActualReplySource
    evidence_gap: bool

    @property
    def source_type(self) -> ActualReplySource:
        return self.reply_source_type

    @model_validator(mode="after")
    def _validate_actual_boundary(self) -> "ActualTranscriptTurn":
        if self.reply_source_type == "external_unknown":
            valid = (
                self.actual_reply_ref is not None
                and self.reply_text is None
                and self.evidence_gap
            )
        else:
            valid = (
                self.actual_reply_ref is not None
                and self.reply_text is not None
                and not self.evidence_gap
            )
        if not valid:
            raise ValueError("actual transcript turn does not match reply evidence")
        return self


def actual_transcript_payload(
    *,
    session_id: str,
    turns: tuple[ActualTranscriptTurn, ...],
    incomplete_evidence: bool,
    captured_at: datetime,
) -> dict[str, object]:
    return {
        "captured_at": captured_at.isoformat(),
        "incomplete_evidence": incomplete_evidence,
        "session_id": session_id,
        "turns": [item.model_dump(mode="json") for item in turns],
    }


class ActualTranscript(StrictModel):
    actual_transcript_ref: VersionRef
    session_id: Uuid7String
    turns: tuple[ActualTranscriptTurn, ...]
    incomplete_evidence: bool
    captured_at: UtcDateTime

    @field_validator("turns")
    @classmethod
    def _ordered_turns(
        cls,
        value: tuple[ActualTranscriptTurn, ...],
    ) -> tuple[ActualTranscriptTurn, ...]:
        if not value or tuple(item.ordinal for item in value) != tuple(
            range(1, len(value) + 1)
        ):
            raise ValueError("actual transcript turns must be contiguous and ordered")
        return value

    @property
    def transcript_ref(self) -> VersionRef:
        return self.actual_transcript_ref

    @property
    def canonical_text(self) -> str:
        return _canonical_json_text(
            actual_transcript_payload(
                session_id=self.session_id,
                turns=self.turns,
                incomplete_evidence=self.incomplete_evidence,
                captured_at=self.captured_at,
            )
        )

    @model_validator(mode="after")
    def _validate_transcript_ref(self) -> "ActualTranscript":
        if not self.actual_transcript_ref.object_id.startswith("actual_transcript_"):
            raise ValueError("actual transcript requires a governed transcript reference")
        if _text_sha256(self.canonical_text) != self.actual_transcript_ref.content_sha256:
            raise ValueError("actual transcript reference hash mismatch")
        if self.incomplete_evidence != any(item.evidence_gap for item in self.turns):
            raise ValueError("actual transcript incomplete flag does not match its turns")
        return self


class TheoryEvidenceLimitation(StrictModel):
    theory: NonEmptyStr
    evidence_refs: tuple[VersionRef, ...] = ()
    limitations: tuple[NonEmptyStr, ...] = ()


class PrivateArchiveAnalysis(StrictModel):
    emotion_change_refs: tuple[VersionRef, ...] = ()
    goal_change_refs: tuple[VersionRef, ...] = ()
    key_events: tuple[NonEmptyStr, ...] = ()
    actual_interventions: tuple[NonEmptyStr, ...] = ()
    client_responses: tuple[NonEmptyStr, ...] = ()
    theory_evidence_limitations: tuple[TheoryEvidenceLimitation, ...] = ()
    model_analysis: tuple[NonEmptyStr, ...] = ()
    counselor_reflection: tuple[NonEmptyStr, ...] = ()


def private_archive_draft_payload(
    *,
    actual_transcript: ActualTranscript,
    analysis: PrivateArchiveAnalysis,
    created_at: datetime,
) -> dict[str, object]:
    return {
        "actual": actual_transcript.model_dump(mode="json"),
        "analysis": analysis.model_dump(mode="json"),
        "created_at": created_at.isoformat(),
    }


class PrivateArchiveDraft(StrictModel):
    draft_ref: VersionRef
    actual_transcript: ActualTranscript
    analysis: PrivateArchiveAnalysis
    created_at: UtcDateTime

    @property
    def turns(self) -> tuple[ActualTranscriptTurn, ...]:
        return self.actual_transcript.turns

    @property
    def incomplete_evidence(self) -> bool:
        return self.actual_transcript.incomplete_evidence

    @property
    def canonical_text(self) -> str:
        return _canonical_json_text(
            private_archive_draft_payload(
                actual_transcript=self.actual_transcript,
                analysis=self.analysis,
                created_at=self.created_at,
            )
        )

    @model_validator(mode="after")
    def _validate_draft_ref(self) -> "PrivateArchiveDraft":
        if not self.draft_ref.object_id.startswith("private_archive_draft_"):
            raise ValueError("private archive draft requires a governed draft reference")
        if _text_sha256(self.canonical_text) != self.draft_ref.content_sha256:
            raise ValueError("private archive draft reference hash mismatch")
        return self


class ArchiveBundle(StrictModel):
    bundle_id: ObjectId
    session_id: Uuid7String
    actual_transcript_ref: VersionRef
    incomplete_evidence: bool
    purpose_states: tuple[ArchivePurposeStatus, ...]
    created_at: UtcDateTime

    @field_validator("purpose_states")
    @classmethod
    def _all_purposes(
        cls,
        value: tuple[ArchivePurposeStatus, ...],
    ) -> tuple[ArchivePurposeStatus, ...]:
        if tuple(item.purpose for item in value) != ARCHIVE_PURPOSE_ORDER:
            raise ValueError("archive bundle must contain each purpose in canonical order")
        return value

    def state_for(self, purpose: ArchivePurpose) -> ArchivePurposeStatus:
        return next(item for item in self.purpose_states if item.purpose == purpose)


class PrivateArchiveReviewPreview(StrictModel):
    actual_transcript: ActualTranscript
    analysis: PrivateArchiveAnalysis
    section_boundary: tuple[
        Literal["actual_transcript"],
        Literal["model_analysis"],
        Literal["counselor_reflection"],
    ] = ("actual_transcript", "model_analysis", "counselor_reflection")
    diff_ref: VersionRef
    descriptor: DraftDescriptor

    @model_validator(mode="after")
    def _validate_preview_binding(self) -> "PrivateArchiveReviewPreview":
        if self.descriptor.purpose != "private_archive_publish":
            raise ValueError("private archive preview requires its own approval purpose")
        if self.descriptor.session_id != self.actual_transcript.session_id:
            raise ValueError("private archive preview session mismatch")
        return self


PrivateArchiveReviewAction: TypeAlias = Literal["APPROVE_MODIFIED", "REJECT"]


class PrivateArchiveReviewDecision(StrictModel):
    decision_id: ObjectId
    bundle_id: ObjectId
    draft: PrivateArchiveDraft
    action: PrivateArchiveReviewAction
    descriptor: DraftDescriptor
    diff_ref: VersionRef
    reviewer_id_hash: Sha256Hex
    reviewed_at: UtcDateTime

    @model_validator(mode="after")
    def _validate_decision_binding(self) -> "PrivateArchiveReviewDecision":
        if self.descriptor.purpose != "private_archive_publish":
            raise ValueError("private archive decision requires its own approval purpose")
        if self.descriptor.target_id != self.draft.draft_ref.object_id:
            raise ValueError("private archive decision target mismatch")
        if self.descriptor.draft_sha256 != self.draft.draft_ref.content_sha256:
            raise ValueError("private archive decision draft hash mismatch")
        if self.descriptor.session_id != self.draft.actual_transcript.session_id:
            raise ValueError("private archive decision session mismatch")
        return self


class PrivateArchivePublication(StrictModel):
    revision_ref: VersionRef
    manifest_ref: VersionRef
    purpose_state: ArchivePurposeStatus
    draft: PrivateArchiveDraft
    published_at: UtcDateTime

    @model_validator(mode="after")
    def _validate_publication(self) -> "PrivateArchivePublication":
        if (
            self.purpose_state.purpose != "private_archive"
            or self.purpose_state.state != "ACTIVE"
            or self.purpose_state.manifest_id != self.manifest_ref.object_id
        ):
            raise ValueError("private archive publication must be the active private purpose")
        if self.revision_ref.content_sha256 != self.draft.draft_ref.content_sha256:
            raise ValueError("private archive publication revision hash mismatch")
        return self


def legal_archive_purpose(value: str) -> ArchivePurpose:
    if value not in ARCHIVE_PURPOSE_ORDER:
        raise ValueError("unknown archive purpose")
    return value


__all__ = [
    "ARCHIVE_PURPOSE_ORDER",
    "LEGAL_PURPOSE_STATES",
    "ActualTranscript",
    "ActualTranscriptTurn",
    "ArchiveBundle",
    "ArchivePurpose",
    "ArchivePurposeState",
    "ArchivePurposeStatus",
    "PrivateArchiveAnalysis",
    "PrivateArchiveDraft",
    "PrivateArchivePublication",
    "PrivateArchiveReviewAction",
    "PrivateArchiveReviewDecision",
    "PrivateArchiveReviewPreview",
    "TheoryEvidenceLimitation",
    "actual_transcript_payload",
    "legal_archive_purpose",
    "private_archive_draft_payload",
]
