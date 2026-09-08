"""Strict governed-knowledge contracts.

These models separate source authority, empirical support, model confidence,
human review and runtime applicability.  In particular, no stored field can
claim the runtime-only ``highest`` framework priority.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, TypeAlias

from pydantic import field_serializer, model_validator

from .common import (
    FiniteFloat,
    NonEmptyStr,
    ObjectId,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    VersionRef,
)
from .evidence import EmpiricalSupport, EvidenceLocator, Provenance, SourceGrade


DocumentType: TypeAlias = Literal["txt", "md", "pdf", "docx", "xlsx", "csv"]
ReviewStatus: TypeAlias = Literal[
    "draft", "reviewed", "approved", "rejected", "revoked"
]
CognitiveType: TypeAlias = Literal[
    "explicit",
    "paraphrase",
    "counselor_judgment",
    "model_inference",
    "cross_theory_analogy",
]
FrameworkEligibility: TypeAlias = Literal["eligible", "ineligible", "conditional"]
PrivacyScope: TypeAlias = Literal["global", "private", "case", "mixed"]


class ClaimApplicability(StrictModel):
    """Deeply immutable, policy-key-only applicability metadata."""

    domains: frozenset[SafePolicyKey]
    populations: frozenset[SafePolicyKey]
    contexts: frozenset[SafePolicyKey]
    required_conditions: frozenset[SafePolicyKey]
    exclusions: frozenset[SafePolicyKey]
    contraindications: frozenset[SafePolicyKey]

    @model_validator(mode="after")
    def _require_scope(self) -> "ClaimApplicability":
        if not self.domains:
            raise ValueError("claim applicability requires a domain")
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


class SourceMetadata(StrictModel):
    license: NonEmptyStr
    domain: NonEmptyStr
    language: NonEmptyStr
    sensitivity: NonEmptyStr
    source_grade: SourceGrade
    document_type: DocumentType
    author: NonEmptyStr | None = None
    observed_at: UtcDateTime | None = None
    review_due_at: UtcDateTime | None = None


class SourceRecord(StrictModel):
    source_id: ObjectId
    version: PositiveInt
    logical_path: NonEmptyStr
    content_sha256: Sha256Hex
    content_object_ref: NonEmptyStr
    size_bytes: int
    metadata: SourceMetadata
    status: ReviewStatus = "draft"
    imported_at: UtcDateTime

    @model_validator(mode="after")
    def _validate_size(self) -> "SourceRecord":
        if type(self.size_bytes) is not int or self.size_bytes < 0:
            raise ValueError("source size must be a non-negative exact integer")
        return self


class PassageRecord(StrictModel):
    passage_id: ObjectId
    version: PositiveInt
    source_ref: VersionRef
    document_type: DocumentType
    structural_path: NonEmptyStr
    locator: EvidenceLocator
    normalized_text_sha256: Sha256Hex
    raw_content_ref: NonEmptyStr
    retrieval_content_ref: NonEmptyStr
    context_before_ref: NonEmptyStr | None = None
    context_after_ref: NonEmptyStr | None = None
    extractor_version: NonEmptyStr
    privacy_scope: Literal["global", "private", "case"]
    provenance: Provenance
    review_status: ReviewStatus = "draft"
    created_at: UtcDateTime

    @model_validator(mode="after")
    def _validate_provenance_scope(self) -> "PassageRecord":
        expected = {
            "global": "global_source",
            "private": "client_private",
            "case": "case_derived",
        }[self.privacy_scope]
        if self.provenance.provenance_scope != expected:
            raise ValueError("passage privacy scope must equal its provenance scope")
        if self.passage_id not in self.provenance.passage_ids:
            raise ValueError("passage provenance must contain its own stable ID")
        if self.privacy_scope == "global" and self.provenance.source_ids != frozenset(
            {self.source_ref.object_id}
        ):
            raise ValueError("global passage provenance must bind its source")
        return self


class ClaimEvidenceRef(StrictModel):
    passage_ref: VersionRef
    relation: Literal["supports", "contradicts"]
    evidence_role: Literal["primary", "corroborating", "counterevidence"]


class ClaimDraft(StrictModel):
    text: NonEmptyStr
    cognitive_type: CognitiveType
    source_grade: SourceGrade
    empirical_support: EmpiricalSupport
    model_confidence: FiniteFloat | None = None
    applicability: ClaimApplicability
    privacy_scope: PrivacyScope
    allowed_uses: frozenset[NonEmptyStr]
    evidence: tuple[ClaimEvidenceRef, ...]
    provenance: Provenance
    theory_revision_ref: VersionRef | None = None

    @model_validator(mode="after")
    def _validate_draft(self) -> "ClaimDraft":
        if self.model_confidence is not None and not 0 <= self.model_confidence <= 1:
            raise ValueError("model confidence must be within zero and one")
        if not self.evidence:
            raise ValueError("claim requires at least one Passage evidence reference")
        if not self.allowed_uses:
            raise ValueError("claim requires at least one allowed use")
        if self.source_grade == "C1" and self.theory_revision_ref is None:
            raise ValueError("C1 claim requires a theory revision")
        if self.source_grade != "C1" and self.theory_revision_ref is not None:
            raise ValueError("only a C1 claim may bind a theory revision")
        expected_provenance = {
            "global": "global_source",
            "private": "client_private",
            "case": "case_derived",
            "mixed": "mixed",
        }[self.privacy_scope]
        if self.provenance.provenance_scope != expected_provenance:
            raise ValueError("claim privacy scope must equal its provenance scope")
        evidence_keys = [
            (
                item.passage_ref.object_id,
                item.passage_ref.version,
                item.relation,
            )
            for item in self.evidence
        ]
        if len(evidence_keys) != len(set(evidence_keys)):
            raise ValueError("claim evidence entries must be unique")
        if any(
            not item.passage_ref.object_id.startswith("passage_")
            for item in self.evidence
        ):
            raise ValueError("claim evidence must reference a Passage")
        evidence_passages = frozenset(item.passage_ref.object_id for item in self.evidence)
        if evidence_passages != self.provenance.passage_ids:
            raise ValueError("claim evidence and provenance Passage IDs must match")
        return self

    @field_serializer("allowed_uses")
    def _serialize_uses(self, value: frozenset[str]) -> list[str]:
        return sorted(value)


class ClaimRecord(StrictModel):
    claim_id: ObjectId
    version: PositiveInt
    text: NonEmptyStr
    text_sha256: Sha256Hex
    cognitive_type: CognitiveType
    source_grade: SourceGrade
    framework_eligibility: FrameworkEligibility
    empirical_support: EmpiricalSupport
    model_confidence: FiniteFloat | None = None
    review_status: ReviewStatus
    effective_from: UtcDateTime | None = None
    effective_to: UtcDateTime | None = None
    review_due_at: UtcDateTime | None = None
    applicability: ClaimApplicability
    privacy_scope: PrivacyScope
    allowed_uses: frozenset[NonEmptyStr]
    passage_refs: tuple[VersionRef, ...]
    provenance: Provenance
    theory_revision_ref: VersionRef | None = None
    created_at: UtcDateTime

    @model_validator(mode="after")
    def _validate_record(self) -> "ClaimRecord":
        if self.model_confidence is not None and not 0 <= self.model_confidence <= 1:
            raise ValueError("model confidence must be within zero and one")
        if self.effective_from is not None and self.effective_to is not None:
            if self.effective_to <= self.effective_from:
                raise ValueError("claim effective interval must be increasing")
        if not self.passage_refs:
            raise ValueError("approved-capable claim requires Passage references")
        if self.source_grade == "C1" and self.theory_revision_ref is None:
            raise ValueError("C1 claim requires a theory revision")
        if self.source_grade != "C1" and self.theory_revision_ref is not None:
            raise ValueError("only C1 may reference a theory revision")
        expected_provenance = {
            "global": "global_source",
            "private": "client_private",
            "case": "case_derived",
            "mixed": "mixed",
        }[self.privacy_scope]
        if self.provenance.provenance_scope != expected_provenance:
            raise ValueError("claim privacy scope must equal its provenance scope")
        if any(not reference.object_id.startswith("passage_") for reference in self.passage_refs):
            raise ValueError("claim evidence must reference a Passage")
        if self.review_status == "approved" and not self.allowed_uses:
            raise ValueError("approved claim requires an allowed use")
        passages = frozenset(ref.object_id for ref in self.passage_refs)
        if passages != self.provenance.passage_ids:
            raise ValueError("claim Passage refs must equal provenance Passage IDs")
        return self

    @field_serializer("allowed_uses")
    def _serialize_uses(self, value: frozenset[str]) -> list[str]:
        return sorted(value)


def claim_is_current(record: ClaimRecord, *, at: datetime) -> bool:
    """Return whether an approved claim is temporally usable (not applicability)."""

    if record.review_status != "approved":
        return False
    if record.effective_from is not None and at < record.effective_from:
        return False
    return record.effective_to is None or at < record.effective_to


__all__ = [
    "ClaimDraft",
    "ClaimApplicability",
    "ClaimEvidenceRef",
    "ClaimRecord",
    "CognitiveType",
    "DocumentType",
    "FrameworkEligibility",
    "PassageRecord",
    "PrivacyScope",
    "ReviewStatus",
    "SourceMetadata",
    "SourceRecord",
    "claim_is_current",
]
