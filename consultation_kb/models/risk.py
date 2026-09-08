"""Counselor-only minimal risk observation root."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, field_validator

from .common import (
    NonEmptyStr,
    ObjectId,
    SafePolicyKey,
    StrictModel,
    UtcDateTime,
    Uuid7String,
    VersionRef,
)


class InternalRiskObservation(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    observation_id: ObjectId
    category: SafePolicyKey
    level: Literal["general", "high"]
    trigger_turn_ids: Annotated[
        tuple[Uuid7String, ...],
        Field(min_length=1, json_schema_extra={"uniqueItems": True}),
    ]
    rule_ref: VersionRef
    detected_at: UtcDateTime
    suggested_questions: Annotated[
        tuple[NonEmptyStr, ...],
        Field(min_length=1, json_schema_extra={"uniqueItems": True}),
    ]
    client_facing_visibility: Literal["never"] = "never"

    @field_validator("trigger_turn_ids")
    @classmethod
    def _canonical_trigger_turns(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("risk observation requires at least one trigger turn")
        if len(value) != len(set(value)):
            raise ValueError("trigger turns must not contain duplicates")
        return tuple(sorted(value))

    @field_validator("suggested_questions")
    @classmethod
    def _validate_questions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("risk observation requires at least one suggested question")
        if len(value) != len(set(value)):
            raise ValueError("suggested questions must not contain duplicates")
        return value
