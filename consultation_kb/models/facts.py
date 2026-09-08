"""Immutable client fact events and six governed mutation contracts."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Literal, TypeAlias

from pydantic import Field, TypeAdapter, field_validator, model_validator

from consultation_kb.models.common import ClientId, NonEmptyStr, StrictModel, UtcDateTime
from consultation_kb.models.dependencies import DependencyEdge


ReviewStatus: TypeAlias = Literal["proposed", "reviewed", "approved", "rejected"]
ValidityStatus: TypeAlias = Literal["active", "superseded", "invalidated", "historical"]
ResolutionStatus: TypeAlias = Literal["open", "resolved", "not_applicable"]
EpistemicStatus: TypeAlias = Literal["asserted", "uncertain", "disputed"]
CognitiveType: TypeAlias = Literal[
    "external_fact",
    "client_statement",
    "consultant_observation",
    "interpretation",
    "hypothesis",
    "recommendation",
]
SourceKind: TypeAlias = Literal[
    "controlled_import",
    "session_statement",
    "session_observation",
    "session_derived",
]
MutationType: TypeAlias = Literal[
    "ADD", "CONFIRM", "CORRECT", "SUPERSEDE", "RESOLVE", "MERGE"
]
RelationType: TypeAlias = Literal[
    "ABOUT_ENTITY",
    "DEPENDS_ON",
    "DERIVED_FROM",
    "SUPPORTS",
    "CONTRADICTS",
    "SUPERSEDES",
    "RESOLVED_BY",
    "CURRENT_RELATIONSHIP",
    "HISTORICAL_RELATIONSHIP",
]


def canonical_json(value: object) -> str:
    """Return deterministic, UTF-8 friendly JSON with no non-finite values."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _utc_text(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


class FactEvidence(StrictModel):
    evidence_id: NonEmptyStr
    source_kind: SourceKind
    source_ref: NonEmptyStr
    supports: bool = True
    evidence_confidence: float = Field(strict=True, ge=0.0, le=1.0)


class FactEvent(StrictModel):
    """One immutable event in the per-client bitemporal ledger."""

    event_id: NonEmptyStr
    fact_id: NonEmptyStr
    client_id: ClientId
    event_version: int = Field(strict=True, gt=0)
    mutation_type: MutationType
    canonical_key: NonEmptyStr
    subject: NonEmptyStr
    predicate: NonEmptyStr
    object_json: NonEmptyStr
    cognitive_type: CognitiveType
    source_kind: SourceKind
    source_session_id: NonEmptyStr | None
    source_turn_id: NonEmptyStr | None
    source_ref: NonEmptyStr | None
    effective_from: UtcDateTime
    effective_to: UtcDateTime | None
    time_precision: Literal["instant", "minute", "hour", "day", "month", "year", "unknown"]
    timezone_name: NonEmptyStr
    recorded_at: UtcDateTime
    approved_at: UtcDateTime
    reported_at: UtcDateTime | None
    observed_at: UtcDateTime | None
    transaction_id: NonEmptyStr
    commit_version: int = Field(strict=True, gt=0)
    publication_operation_id: NonEmptyStr
    visible_runtime_epoch: int = Field(strict=True, gt=0)
    review_status: ReviewStatus
    validity_status: ValidityStatus
    resolution_status: ResolutionStatus
    epistemic_status: EpistemicStatus
    fact_confidence: float = Field(strict=True, ge=0.0, le=1.0)
    model_confidence: float | None = Field(default=None, strict=True, ge=0.0, le=1.0)
    reviewer_id: NonEmptyStr
    review_reason: NonEmptyStr
    review_source: NonEmptyStr
    privacy_level: Literal["private_client", "private_session"]
    allowed_purposes_json: NonEmptyStr
    applicability_json: NonEmptyStr
    source_anchor_json: NonEmptyStr
    supersedes_event_id: NonEmptyStr | None
    previous_event_id: NonEmptyStr | None
    replacement_event_id: NonEmptyStr | None
    source_event_ids: tuple[NonEmptyStr, ...] = ()
    relation_type: RelationType | None = None

    @field_validator(
        "object_json",
        "allowed_purposes_json",
        "applicability_json",
        "source_anchor_json",
    )
    @classmethod
    def _canonical_json_fields(cls, value: str) -> str:
        try:
            decoded = json.loads(value)
            rendered = canonical_json(decoded)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise ValueError("field must contain canonical JSON") from error
        if rendered != value:
            raise ValueError("field must contain canonical JSON")
        return value

    @field_validator("allowed_purposes_json")
    @classmethod
    def _allowed_purposes_contract(cls, value: str) -> str:
        decoded = json.loads(value)
        if (
            not isinstance(decoded, list)
            or not decoded
            or any(type(item) is not str or not item.strip() for item in decoded)
            or len(decoded) != len(set(decoded))
        ):
            raise ValueError("allowed_purposes_json must be a nonempty unique string list")
        return value

    @field_validator("source_event_ids")
    @classmethod
    def _source_ids_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("source_event_ids must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def _validate_event(self) -> "FactEvent":
        if self.effective_to is not None and self.effective_to <= self.effective_from:
            raise ValueError("effective_to must be later than effective_from")
        if self.approved_at < self.recorded_at:
            raise ValueError("approved_at must not precede recorded_at")
        session_fields = (self.source_session_id, self.source_turn_id)
        if self.source_kind == "controlled_import":
            if self.source_ref is None:
                raise ValueError("controlled import requires source_ref")
            if any(value is not None for value in session_fields):
                raise ValueError("controlled import cannot carry session anchors")
            if self.reported_at is not None or self.observed_at is not None:
                raise ValueError("controlled import cannot carry session observation times")
            if self.cognitive_type == "client_statement":
                raise ValueError("client_statement must use session_statement")
            if self.cognitive_type == "consultant_observation":
                raise ValueError("consultant_observation must use session_observation")
        else:
            if self.source_ref is not None:
                raise ValueError("session sources cannot carry an external source_ref")
            if any(value is None for value in session_fields):
                raise ValueError("session source requires source_session_id/source_turn_id")
            if self.source_kind == "session_statement":
                if self.cognitive_type != "client_statement" or self.reported_at is None:
                    raise ValueError("session_statement requires client_statement and reported_at")
                if self.observed_at is not None:
                    raise ValueError("session_statement cannot carry observed_at")
            elif self.source_kind == "session_observation":
                if self.cognitive_type != "consultant_observation" or self.observed_at is None:
                    raise ValueError(
                        "session_observation requires consultant_observation and observed_at"
                    )
                if self.reported_at is not None:
                    raise ValueError("session_observation cannot carry reported_at")
            else:
                if self.cognitive_type in {"client_statement", "consultant_observation"}:
                    raise ValueError("session_derived requires a derived cognitive type")
                if (self.reported_at is None) == (self.observed_at is None):
                    raise ValueError(
                        "session_derived requires exactly one of reported_at/observed_at"
                    )
        if self.replacement_event_id == self.event_id:
            raise ValueError("event cannot replace itself")
        return self

    @property
    def object_value(self) -> object:
        return json.loads(self.object_json)

    def allows_purpose(self, purpose: str) -> bool:
        if type(purpose) is not str or not purpose:
            raise ValueError("purpose must be nonempty")
        return purpose in json.loads(self.allowed_purposes_json)

    def to_record(self) -> dict[str, object]:
        """Return the exact v0002 SQLite row representation."""

        dumped = self.model_dump(mode="python")
        for field in (
            "effective_from",
            "effective_to",
            "recorded_at",
            "approved_at",
            "reported_at",
            "observed_at",
        ):
            dumped[field] = _utc_text(dumped[field])
        relation_type = dumped.pop("relation_type")
        dumped["source_event_ids_json"] = canonical_json(dumped.pop("source_event_ids"))
        dumped["relation_type"] = relation_type
        return dumped

    @classmethod
    def from_record(cls, row: dict[str, object]) -> "FactEvent":
        values = dict(row)
        raw_source_ids = values.pop("source_event_ids_json")
        if not isinstance(raw_source_ids, str):
            raise ValueError("source_event_ids_json is invalid")
        values["source_event_ids"] = tuple(json.loads(raw_source_ids))
        for field in (
            "effective_from",
            "effective_to",
            "recorded_at",
            "approved_at",
            "reported_at",
            "observed_at",
        ):
            raw_timestamp = values[field]
            if raw_timestamp is not None:
                if not isinstance(raw_timestamp, str):
                    raise ValueError(f"{field} is invalid")
                values[field] = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
        return cls.model_validate(values)


class AddMutation(StrictModel):
    operation: Literal["ADD"] = "ADD"
    new_fact: FactEvent
    dependency_edges: tuple[DependencyEdge, ...] = ()

    @model_validator(mode="after")
    def _fresh_fact(self) -> "AddMutation":
        if self.new_fact.event_version != 1 or any(
            value is not None
            for value in (
                self.new_fact.previous_event_id,
                self.new_fact.supersedes_event_id,
                self.new_fact.replacement_event_id,
            )
        ):
            raise ValueError("ADD requires a fresh version with no version links")
        if (
            self.new_fact.review_status != "approved"
            or self.new_fact.validity_status != "active"
            or self.new_fact.resolution_status != "open"
        ):
            raise ValueError("ADD requires an approved active open fact")
        self._validate_dependency_edges(
            self.dependency_edges,
            event_id=self.new_fact.event_id,
            fact_id=self.new_fact.fact_id,
        )
        return self

    @staticmethod
    def _validate_dependency_edges(
        edges: tuple[DependencyEdge, ...],
        *,
        event_id: str,
        fact_id: str,
    ) -> None:
        if len({edge.edge_id for edge in edges}) != len(edges):
            raise ValueError("dependency edge IDs must be unique")
        if any(
            edge.source_event_id != event_id
            or fact_id not in {edge.dependent_fact_id, edge.prerequisite_fact_id}
            for edge in edges
        ):
            raise ValueError("dependency edges must be anchored to the new fact event")


class ConfirmMutation(StrictModel):
    operation: Literal["CONFIRM"] = "CONFIRM"
    target_event_id: NonEmptyStr
    evidence: tuple[FactEvidence, ...]
    calibrated_confidence: float = Field(strict=True, ge=0.0, le=1.0)
    reason: NonEmptyStr

    @model_validator(mode="after")
    def _require_evidence(self) -> "ConfirmMutation":
        if not self.evidence or not any(item.supports for item in self.evidence):
            raise ValueError("CONFIRM requires at least one supporting evidence item")
        return self


class CorrectMutation(StrictModel):
    operation: Literal["CORRECT"] = "CORRECT"
    target_event_id: NonEmptyStr
    correction_kind: Literal["value", "time", "validity"]
    previous_value_json: NonEmptyStr
    reason: NonEmptyStr
    effective_at: UtcDateTime
    new_value_json: NonEmptyStr | None = None
    new_effective_from: UtcDateTime | None = None
    new_effective_to: UtcDateTime | None = None
    previous_validity_status: ValidityStatus | None = None
    new_validity_status: Literal["invalidated"] | None = None

    @field_validator("previous_value_json", "new_value_json")
    @classmethod
    def _mutation_json(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if canonical_json(json.loads(value)) != value:
            raise ValueError("correction values must be canonical JSON")
        return value

    @model_validator(mode="after")
    def _kind_fields(self) -> "CorrectMutation":
        supplied = {
            "value": self.new_value_json is not None,
            "time": self.new_effective_from is not None,
            "validity": self.new_validity_status is not None,
        }
        if not supplied[self.correction_kind] or sum(supplied.values()) != 1:
            raise ValueError("CORRECT fields must match correction_kind exactly")
        if self.new_effective_to is not None and self.correction_kind != "time":
            raise ValueError("new_effective_to is only valid for a time correction")
        if (self.previous_validity_status is not None) != (
            self.correction_kind == "validity"
        ):
            raise ValueError(
                "previous_validity_status is required only for validity correction"
            )
        if (
            self.new_effective_from is not None
            and self.new_effective_to is not None
            and self.new_effective_to <= self.new_effective_from
        ):
            raise ValueError("corrected effective window is inverted")
        if (
            self.correction_kind == "value"
            and self.new_value_json == self.previous_value_json
        ):
            raise ValueError("value correction must change the value")
        return self


class SupersedeMutation(StrictModel):
    operation: Literal["SUPERSEDE"] = "SUPERSEDE"
    target_event_id: NonEmptyStr
    replacement: FactEvent
    effective_at: UtcDateTime
    reason: NonEmptyStr
    dependency_edges: tuple[DependencyEdge, ...] = ()

    @model_validator(mode="after")
    def _not_self(self) -> "SupersedeMutation":
        if self.target_event_id == self.replacement.event_id:
            raise ValueError("fact cannot supersede itself")
        if self.replacement.effective_from < self.effective_at:
            raise ValueError("replacement cannot begin before supersede effective time")
        if self.replacement.event_version != 1 or any(
            value is not None
            for value in (
                self.replacement.previous_event_id,
                self.replacement.supersedes_event_id,
                self.replacement.replacement_event_id,
            )
        ):
            raise ValueError("SUPERSEDE replacement must be a fresh unlinked version")
        if (
            self.replacement.review_status != "approved"
            or self.replacement.validity_status != "active"
            or self.replacement.resolution_status != "open"
        ):
            raise ValueError("SUPERSEDE replacement must be approved active and open")
        AddMutation._validate_dependency_edges(
            self.dependency_edges,
            event_id=self.replacement.event_id,
            fact_id=self.replacement.fact_id,
        )
        return self


class ResolveMutation(StrictModel):
    operation: Literal["RESOLVE"] = "RESOLVE"
    target_event_id: NonEmptyStr
    resolved_at: UtcDateTime
    reason: NonEmptyStr


class MergeMutation(StrictModel):
    operation: Literal["MERGE"] = "MERGE"
    member_event_ids: tuple[NonEmptyStr, ...]
    canonical_projection: FactEvent
    no_conflict_proof: NonEmptyStr
    reason: NonEmptyStr
    dependency_edges: tuple[DependencyEdge, ...] = ()

    @model_validator(mode="after")
    def _members(self) -> "MergeMutation":
        if len(self.member_event_ids) < 2 or len(set(self.member_event_ids)) != len(
            self.member_event_ids
        ):
            raise ValueError("MERGE requires at least two unique members")
        if self.canonical_projection.event_id in self.member_event_ids:
            raise ValueError("MERGE projection cannot be one of its members")
        if self.canonical_projection.event_version != 1 or any(
            value is not None
            for value in (
                self.canonical_projection.previous_event_id,
                self.canonical_projection.supersedes_event_id,
                self.canonical_projection.replacement_event_id,
            )
        ):
            raise ValueError("MERGE projection must be a fresh unlinked version")
        if (
            self.canonical_projection.review_status != "approved"
            or self.canonical_projection.validity_status != "active"
            or self.canonical_projection.resolution_status != "open"
        ):
            raise ValueError("MERGE projection must be approved active and open")
        if set(self.canonical_projection.source_event_ids) != set(
            self.member_event_ids
        ):
            raise ValueError("MERGE projection lineage must equal its members")
        AddMutation._validate_dependency_edges(
            self.dependency_edges,
            event_id=self.canonical_projection.event_id,
            fact_id=self.canonical_projection.fact_id,
        )
        return self


FactMutation: TypeAlias = Annotated[
    AddMutation
    | ConfirmMutation
    | CorrectMutation
    | SupersedeMutation
    | ResolveMutation
    | MergeMutation,
    Field(discriminator="operation"),
]
FACT_MUTATION_ADAPTER: TypeAdapter[FactMutation] = TypeAdapter(FactMutation)


__all__ = [
    "AddMutation",
    "CognitiveType",
    "ConfirmMutation",
    "CorrectMutation",
    "EpistemicStatus",
    "FACT_MUTATION_ADAPTER",
    "FactEvent",
    "FactEvidence",
    "FactMutation",
    "MergeMutation",
    "MutationType",
    "RelationType",
    "ResolutionStatus",
    "ResolveMutation",
    "ReviewStatus",
    "SourceKind",
    "SupersedeMutation",
    "ValidityStatus",
    "canonical_json",
]
