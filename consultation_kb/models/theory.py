"""Consultant-authored C1 theory contracts."""

from __future__ import annotations

from typing import Literal

from pydantic import field_serializer, model_validator

from .common import (
    NonEmptyStr,
    ObjectId,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    VersionRef,
)
from .evidence import EmpiricalSupport


class TheoryScope(StrictModel):
    domains: frozenset[SafePolicyKey]
    populations: frozenset[SafePolicyKey]
    contexts: frozenset[SafePolicyKey]
    required_conditions: frozenset[SafePolicyKey]
    exclusions: frozenset[SafePolicyKey]
    contraindications: frozenset[SafePolicyKey]

    @model_validator(mode="after")
    def _require_domain_and_population(self) -> "TheoryScope":
        if not self.domains or not self.populations:
            raise ValueError("C1 scope requires domain and population")
        return self

    @field_serializer(
        "domains",
        "populations",
        "contexts",
        "required_conditions",
        "exclusions",
        "contraindications",
    )
    def _serialize_sets(self, value: frozenset[str]) -> list[str]:
        return sorted(value)


class TheoryRevisionDraft(StrictModel):
    theory_id: ObjectId
    source_ref: VersionRef
    document_sha256: Sha256Hex
    author: NonEmptyStr
    declared_version: NonEmptyStr
    effective_from: UtcDateTime
    effective_to: UtcDateTime | None
    scope: TheoryScope
    core_claims: tuple[NonEmptyStr, ...]
    methods: tuple[NonEmptyStr, ...]
    contraindications: tuple[NonEmptyStr, ...]
    counterexamples: tuple[NonEmptyStr, ...]
    passage_refs: tuple[VersionRef, ...]
    citation_refs: tuple[VersionRef, ...]
    empirical_support: EmpiricalSupport
    scope_policy_ref: VersionRef
    supersedes_ref: VersionRef | None = None
    revokes_ref: VersionRef | None = None

    @model_validator(mode="after")
    def _validate_complete_c1(self) -> "TheoryRevisionDraft":
        if self.document_sha256 != self.source_ref.content_sha256:
            raise ValueError("formal C1 document hash must match source version")
        if self.effective_to is not None and self.effective_to <= self.effective_from:
            raise ValueError("C1 effective interval must be increasing")
        required_collections = (
            self.core_claims,
            self.methods,
            self.contraindications,
            self.counterexamples,
            self.passage_refs,
            self.citation_refs,
        )
        if any(not values for values in required_collections):
            raise ValueError("C1 revision is missing required governed content")
        if self.supersedes_ref is not None and self.revokes_ref is not None:
            raise ValueError("one C1 revision cannot supersede and revoke simultaneously")
        return self


class TheoryProposal(StrictModel):
    request_id: ObjectId
    draft: TheoryRevisionDraft
    draft_sha256: Sha256Hex
    actor: NonEmptyStr
    created_at: UtcDateTime


TheoryStatus = Literal[
    "draft", "prepared", "active", "superseded", "revoked", "expired"
]


class TheoryRevision(StrictModel):
    theory_id: ObjectId
    revision: PositiveInt
    source_ref: VersionRef
    document_sha256: Sha256Hex
    author: NonEmptyStr
    declared_version: NonEmptyStr
    source_grade: Literal["C1"] = "C1"
    empirical_support: EmpiricalSupport
    status: TheoryStatus
    approval_request_id: ObjectId | None = None
    approved_at: UtcDateTime | None = None
    effective_from: UtcDateTime
    effective_to: UtcDateTime | None
    scope: TheoryScope
    core_claims: tuple[NonEmptyStr, ...]
    methods: tuple[NonEmptyStr, ...]
    contraindications: tuple[NonEmptyStr, ...]
    counterexamples: tuple[NonEmptyStr, ...]
    passage_refs: tuple[VersionRef, ...]
    claim_refs: tuple[VersionRef, ...]
    citation_refs: tuple[VersionRef, ...]
    scope_policy_ref: VersionRef
    supersedes_ref: VersionRef | None = None
    revokes_ref: VersionRef | None = None
    created_at: UtcDateTime

    @model_validator(mode="after")
    def _validate_governance(self) -> "TheoryRevision":
        if self.status != "draft" and (
            self.approval_request_id is None or self.approved_at is None
        ):
            raise ValueError("non-draft C1 revision requires primary approval")
        if self.status == "draft" and (
            self.approval_request_id is not None or self.approved_at is not None
        ):
            raise ValueError("draft C1 revision cannot contain an approval")
        if self.document_sha256 != self.source_ref.content_sha256:
            raise ValueError("formal C1 document hash must match source version")
        if self.effective_to is not None and self.effective_to <= self.effective_from:
            raise ValueError("C1 effective interval must be increasing")
        if self.status != "draft" and not self.claim_refs:
            raise ValueError("approved C1 revision requires associated Claim revisions")
        return self


__all__ = [
    "TheoryProposal",
    "TheoryRevision",
    "TheoryRevisionDraft",
    "TheoryScope",
    "TheoryStatus",
]
