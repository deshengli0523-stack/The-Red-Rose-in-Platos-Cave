"""Structured current-profile models derived from approved client facts."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import Field, model_validator

from consultation_kb.models.common import NonEmptyStr, StrictModel, UtcDateTime
from consultation_kb.models.facts import (
    CognitiveType,
    EpistemicStatus,
    ResolutionStatus,
    ReviewStatus,
    ValidityStatus,
)


ProfileSectionName = Literal[
    "goals",
    "unresolved_issues",
    "relationships",
    "preferences",
    "constraints",
    "active_facts",
    "uncertainty_disputes",
    "pending_review",
]


class ProfileItem(StrictModel):
    fact_id: NonEmptyStr
    event_id: NonEmptyStr
    subject: NonEmptyStr
    predicate: NonEmptyStr
    object_json: NonEmptyStr
    cognitive_type: CognitiveType
    review_status: ReviewStatus
    validity_status: ValidityStatus
    resolution_status: ResolutionStatus
    epistemic_status: EpistemicStatus
    fact_confidence: float = Field(strict=True, ge=0.0, le=1.0)
    effective_from: UtcDateTime
    effective_to: UtcDateTime | None
    recorded_at: UtcDateTime
    approved_at: UtcDateTime
    source_session_id: NonEmptyStr | None
    source_turn_id: NonEmptyStr | None
    source_event_ids: tuple[NonEmptyStr, ...]


class ProfileSection(StrictModel):
    name: ProfileSectionName
    items: tuple[ProfileItem, ...]


class ProfileSnapshot(StrictModel):
    schema_version: Literal["client_profile.v1"] = "client_profile.v1"
    source_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_client_commit_version: int = Field(strict=True, ge=0)
    effective_at: UtcDateTime
    known_at: UtcDateTime
    fixed_epoch: int = Field(strict=True, ge=0)
    sections: tuple[ProfileSection, ...]
    current_event_ids: tuple[NonEmptyStr, ...]
    canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _hash_matches(self) -> "ProfileSnapshot":
        expected = profile_sha256(self.model_dump(mode="json", exclude={"canonical_sha256"}))
        if expected != self.canonical_sha256:
            raise ValueError("profile snapshot hash mismatch")
        flattened = tuple(
            item.event_id for section in self.sections for item in section.items
        )
        if flattened != self.current_event_ids:
            raise ValueError("profile current event IDs do not match sections")
        return self


def profile_sha256(payload: object) -> str:
    encoded = (
        json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "ProfileItem",
    "ProfileSection",
    "ProfileSectionName",
    "ProfileSnapshot",
    "profile_sha256",
]
