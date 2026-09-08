"""Structured consistency and explainable conclusion-change contracts.

The models in this module deliberately encode *what* changed, not a hidden
reasoning trace.  They are small enough to compare deterministically across
reply candidates, turns, and the latest client profile.
"""

from __future__ import annotations

from typing import Annotated, Literal, TypeAlias

from pydantic import Field, field_validator, model_validator

from .common import NonEmptyStr, ObjectId, SafePolicyKey, StrictModel


FactState: TypeAlias = Literal["affirmed", "denied", "uncertain", "superseded"]
PositionStance: TypeAlias = Literal["support", "oppose", "uncertain"]
ActionDisposition: TypeAlias = Literal["pursue", "avoid", "explore", "defer"]


def _unique_sorted_strings(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must not contain duplicates")
    return tuple(sorted(values))


class FactPosition(StrictModel):
    """A stable fact key and the state asserted by one comparison source."""

    fact_key: SafePolicyKey
    state: FactState
    evidence_ids: Annotated[
        tuple[ObjectId, ...], Field(json_schema_extra={"uniqueItems": True})
    ]

    @field_validator("evidence_ids")
    @classmethod
    def _canonical_evidence_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted_strings(value, "fact evidence IDs")


class CorePosition(StrictModel):
    """A normalized conclusion axis used across reply candidates."""

    position_key: SafePolicyKey
    stance: PositionStance


class ActionDirection(StrictModel):
    """A normalized action axis used across reply candidates."""

    action_key: SafePolicyKey
    disposition: ActionDisposition


class ConsistencySnapshot(StrictModel):
    """One current candidate or historical/profile comparison view."""

    snapshot_key: SafePolicyKey
    source: Literal["current_candidate", "session_earlier", "client_profile"]
    facts: tuple[FactPosition, ...]
    core_positions: tuple[CorePosition, ...]
    action_directions: tuple[ActionDirection, ...]
    conclusion: NonEmptyStr
    conclusion_evidence_ids: Annotated[
        tuple[ObjectId, ...], Field(json_schema_extra={"uniqueItems": True})
    ]

    @field_validator("conclusion_evidence_ids")
    @classmethod
    def _canonical_conclusion_evidence_ids(
        cls, value: tuple[str, ...]
    ) -> tuple[str, ...]:
        return _unique_sorted_strings(value, "conclusion evidence IDs")

    @model_validator(mode="after")
    def _require_unique_axes(self) -> "ConsistencySnapshot":
        for label, values in (
            ("fact", tuple(item.fact_key for item in self.facts)),
            ("core position", tuple(item.position_key for item in self.core_positions)),
            ("action", tuple(item.action_key for item in self.action_directions)),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{label} keys must not contain duplicates")
        return self


class ConclusionChangeRecord(StrictModel):
    """Required audit record when new information changes prior advice."""

    subject_key: SafePolicyKey
    old_conclusion: NonEmptyStr
    new_information: NonEmptyStr
    change_reason: NonEmptyStr
    impact_on_advice: NonEmptyStr
    impact_on_profile: NonEmptyStr
    follow_up: NonEmptyStr
    previous_evidence_ids: Annotated[
        tuple[ObjectId, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    current_evidence_ids: Annotated[
        tuple[ObjectId, ...], Field(json_schema_extra={"uniqueItems": True})
    ]

    @field_validator("previous_evidence_ids", "current_evidence_ids")
    @classmethod
    def _canonical_evidence_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted_strings(value, "conclusion-change evidence IDs")

    @model_validator(mode="after")
    def _require_auditable_change(self) -> "ConclusionChangeRecord":
        if not self.previous_evidence_ids:
            raise ValueError("a conclusion change requires previous evidence")
        if not self.current_evidence_ids:
            raise ValueError("a conclusion change requires current evidence")
        return self


ConsistencySeverity: TypeAlias = Literal["info", "warning", "blocking"]


class ConsistencyFinding(StrictModel):
    code: Literal[
        "candidate_fact_conflict",
        "candidate_core_position_conflict",
        "candidate_action_conflict",
        "historical_fact_conflict",
        "unexplained_conclusion_change",
    ]
    severity: ConsistencySeverity
    subject_key: SafePolicyKey
    source_snapshot_keys: Annotated[
        tuple[SafePolicyKey, ...], Field(min_length=1, json_schema_extra={"uniqueItems": True})
    ]
    correction: NonEmptyStr

    @field_validator("source_snapshot_keys")
    @classmethod
    def _canonical_sources(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted_strings(value, "finding source snapshots")


class ConsistencyReviewResult(StrictModel):
    findings: tuple[ConsistencyFinding, ...]
    conclusion_changes: tuple[ConclusionChangeRecord, ...]
    decision: Literal["pass", "rewrite", "needs_counselor_judgment"]
    retry_count: Annotated[int, Field(strict=True, ge=0, le=2)]

    @model_validator(mode="after")
    def _decision_matches_findings(self) -> "ConsistencyReviewResult":
        blocking = any(item.severity == "blocking" for item in self.findings)
        if not blocking and self.decision != "pass":
            raise ValueError("a non-blocking review must pass")
        if blocking and self.retry_count < 2 and self.decision != "rewrite":
            raise ValueError("a retryable blocking review must request rewrite")
        if (
            blocking
            and self.retry_count == 2
            and self.decision != "needs_counselor_judgment"
        ):
            raise ValueError("exhausted blocking review requires counselor judgment")
        return self


__all__ = [
    "ActionDirection",
    "ActionDisposition",
    "ConclusionChangeRecord",
    "ConsistencyFinding",
    "ConsistencyReviewResult",
    "ConsistencySeverity",
    "ConsistencySnapshot",
    "CorePosition",
    "FactPosition",
    "FactState",
    "PositionStance",
]
