"""Versioned authority contracts for deterministic C1 scope policies."""

from __future__ import annotations

from typing import Literal

from pydantic import field_serializer, model_validator

from .common import (
    ObjectId,
    PositiveInt,
    SafeLocatorText,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    VersionRef,
)


class ScopePolicyFieldValueMembers(StrictModel):
    """Closed value vocabulary for one approved context field."""

    context_field: SafePolicyKey
    value_members: frozenset[SafePolicyKey]

    @model_validator(mode="after")
    def _require_values(self) -> "ScopePolicyFieldValueMembers":
        if not self.value_members:
            raise ValueError("scope policy field vocabulary must not be empty")
        return self

    @field_serializer("value_members")
    def _serialize_values(self, value: frozenset[str]) -> list[str]:
        return sorted(value)


class ScopePolicyDocument(StrictModel):
    """Canonical semantic body stored only in the global scope CAS."""

    policy_id: ObjectId
    version: PositiveInt
    evaluator_id: SafePolicyKey
    evaluator_version: PositiveInt
    rule_members: frozenset[SafePolicyKey]
    context_fields: frozenset[SafePolicyKey]
    field_value_members: tuple[ScopePolicyFieldValueMembers, ...]
    missing_field_semantics: Literal["insufficient_context"] = "insufficient_context"
    known_empty_semantics: Literal["present_empty"] = "present_empty"

    @model_validator(mode="after")
    def _require_closed_vocabulary(self) -> "ScopePolicyDocument":
        if not self.policy_id.startswith("scope_policy_"):
            raise ValueError("scope policy ID must use scope_policy kind")
        if not self.rule_members or not self.context_fields:
            raise ValueError("scope policy requires rules and context fields")
        ordered_fields = tuple(item.context_field for item in self.field_value_members)
        if len(set(ordered_fields)) != len(ordered_fields):
            raise ValueError("scope policy field vocabulary contains duplicates")
        if frozenset(ordered_fields) != self.context_fields:
            raise ValueError("scope policy field vocabulary must close context fields")
        if ordered_fields != tuple(sorted(ordered_fields)):
            raise ValueError("scope policy field vocabulary must use canonical order")
        return self

    @field_serializer("rule_members", "context_fields")
    def _serialize_sets(self, value: frozenset[str]) -> list[str]:
        return sorted(value)


ScopePolicyStatus = Literal["PREPARED", "APPROVED", "REVOKED", "SUPERSEDED"]


class ScopePolicyRecord(StrictModel):
    """Hash-only control-plane record for one scope-policy version."""

    semantic_ref: VersionRef
    cas_object_ref: SafeLocatorText
    cas_object_sha256: Sha256Hex
    cas_object_size_bytes: PositiveInt
    cas_object_media_type: Literal["application/json"] = "application/json"
    status: ScopePolicyStatus
    approval_request_id: ObjectId | None = None
    approved_at: UtcDateTime | None = None
    revocation_approval_request_id: ObjectId | None = None
    revoked_at: UtcDateTime | None = None
    effective_from: UtcDateTime
    effective_to: UtcDateTime | None = None
    supersedes_ref: VersionRef | None = None
    created_at: UtcDateTime
    updated_at: UtcDateTime

    @model_validator(mode="after")
    def _validate_authority_record(self) -> "ScopePolicyRecord":
        if not self.semantic_ref.object_id.startswith("scope_policy_"):
            raise ValueError("scope policy semantic ref has the wrong kind")
        if self.cas_object_ref != f"sha256:{self.cas_object_sha256}":
            raise ValueError("scope policy CAS reference is not hash-bound")
        if self.cas_object_sha256 != self.semantic_ref.content_sha256:
            raise ValueError("scope policy semantic and CAS hashes differ")
        if self.effective_to is not None and self.effective_to <= self.effective_from:
            raise ValueError("scope policy effective interval must be increasing")
        if self.updated_at < self.created_at:
            raise ValueError("scope policy update precedes creation")
        if self.approved_at is not None and self.approved_at < self.created_at:
            raise ValueError("scope policy approval precedes creation")
        if self.revoked_at is not None and (
            self.approved_at is None or self.revoked_at < self.approved_at
        ):
            raise ValueError("scope policy revocation precedes approval")
        lifecycle_times = tuple(
            value for value in (self.approved_at, self.revoked_at) if value is not None
        )
        if any(self.updated_at < value for value in lifecycle_times):
            raise ValueError("scope policy update precedes lifecycle transition")
        if self.semantic_ref.version == 1:
            if self.supersedes_ref is not None:
                raise ValueError(
                    "initial scope policy cannot supersede another version"
                )
        elif (
            self.supersedes_ref is None
            or self.supersedes_ref.object_id != self.semantic_ref.object_id
            or self.supersedes_ref.version != self.semantic_ref.version - 1
        ):
            raise ValueError(
                "scope policy successor must bind its immediate predecessor"
            )

        approved = self.status != "PREPARED"
        approval_complete = (
            self.approval_request_id is not None and self.approved_at is not None
        )
        approval_absent = self.approval_request_id is None and self.approved_at is None
        if (approved and not approval_complete) or (
            not approved and not approval_absent
        ):
            raise ValueError("scope policy approval metadata does not match state")
        revoked = self.status == "REVOKED"
        revocation_complete = (
            self.revocation_approval_request_id is not None
            and self.revoked_at is not None
        )
        revocation_absent = (
            self.revocation_approval_request_id is None and self.revoked_at is None
        )
        if (revoked and not revocation_complete) or (
            not revoked and not revocation_absent
        ):
            raise ValueError("scope policy revocation metadata does not match state")
        return self


__all__ = [
    "ScopePolicyDocument",
    "ScopePolicyFieldValueMembers",
    "ScopePolicyRecord",
    "ScopePolicyStatus",
]
