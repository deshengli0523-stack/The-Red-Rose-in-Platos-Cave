"""Minimal frozen generation and client-reply roots."""

from __future__ import annotations

from typing import Annotated, Literal, TypeAlias

from pydantic import Field, field_validator

from .common import NonEmptyStr, Sha256Hex, StrictModel, UtcDateTime, Uuid7String


GenerationStageName: TypeAlias = Literal[
    "query_plan",
    "conceptualization",
    "theory_comparison",
    "reply_drafts",
    "evidence_audit",
    "consistency_risk_review",
    "final_bundle",
]


class GenerationStageEnvelope(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    stage: GenerationStageName
    turn_id: Uuid7String
    run_id: Uuid7String
    parent_sha256s: Annotated[
        tuple[Sha256Hex, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    created_at: UtcDateTime

    @field_validator("parent_sha256s")
    @classmethod
    def _canonical_parent_hashes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("parent hashes must not contain duplicates")
        return tuple(sorted(value))


class ClientReplyOutput(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    text: NonEmptyStr
