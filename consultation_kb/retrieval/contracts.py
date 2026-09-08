"""Body-free retrieval contracts and fixed-code filtering outcomes.

Retrievers exchange immutable references and governance metadata only.  Text
is intentionally absent from every type in this module; it becomes available
only through :mod:`consultation_kb.retrieval.resolver` after a successful
filter decision has been bound to one live authority snapshot.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal, Protocol, TypeAlias

from pydantic import field_serializer, field_validator, model_validator

from consultation_kb.models.common import (
    ClientId,
    FiniteFloat,
    NonEmptyStr,
    NonNegativeInt,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    Uuid7String,
    VersionRef,
)
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    EmpiricalSupport,
    EvidenceChannel,
    EvidenceFreshnessSnapshot,
    EvidenceLocator,
    Provenance,
    SourceGrade,
)


ReviewStatus: TypeAlias = Literal[
    "draft", "reviewed", "approved", "rejected", "revoked"
]
ContributorIdentityScheme: TypeAlias = Literal["direct_v1", "hmac_alias_v1"]
DeniedReason: TypeAlias = Literal[
    "not_authorized",
    "tombstoned",
    "scope_denied",
    "use_denied",
    "review_not_approved",
    "not_yet_effective",
    "expired",
    "review_overdue",
    "sensitivity_denied",
    "source_client_excluded",
    "leave_one_out_ineligible",
]

DENIED_REASON_ORDER: tuple[DeniedReason, ...] = (
    "not_authorized",
    "tombstoned",
    "scope_denied",
    "use_denied",
    "review_not_approved",
    "not_yet_effective",
    "expired",
    "review_overdue",
    "sensitivity_denied",
    "source_client_excluded",
    "leave_one_out_ineligible",
)


def canonical_json_bytes(value: object) -> bytes:
    """Return the single canonical JSON representation used for hashes."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class ScoreComponent(StrictModel):
    """One deterministic channel contribution; raw text is never included."""

    channel: SafePolicyKey
    rank: PositiveInt | None = None
    score: FiniteFloat


class FilterCapabilityBinding(StrictModel):
    """Non-secret, single-decision epoch binding checked again by the resolver."""

    run_id: Uuid7String
    global_runtime_epoch: NonNegativeInt
    client_runtime_epoch: NonNegativeInt
    tombstone_epoch: NonNegativeInt
    authorization_epoch: NonNegativeInt
    policy_ref: VersionRef
    decision_sha256: Sha256Hex


class LeaveOneOutVariant(StrictModel):
    """Pre-approved case-derived replacement that excludes one contributor."""

    reference: VersionRef
    content_ref: VersionRef
    object_type: SafePolicyKey
    manifest_ref: VersionRef
    review_status: ReviewStatus
    allowed_uses: frozenset[NonEmptyStr]
    approved_at: UtcDateTime
    effective_from: UtcDateTime | None = None
    effective_to: UtcDateTime | None = None
    review_due_at: UtcDateTime | None = None
    sensitivity: NonNegativeInt
    source_grade: SourceGrade
    framework_priority: Literal["highest", "normal", "not_applicable"] = (
        "not_applicable"
    )
    empirical_support: EmpiricalSupport = "unassessed"
    source_count: PositiveInt
    provenance: Provenance
    location: EvidenceLocator
    freshness: EvidenceFreshnessSnapshot
    source_lineage_hashes: tuple[Sha256Hex, ...] = ()
    media_type: NonEmptyStr
    size_bytes: NonNegativeInt

    @field_serializer("allowed_uses")
    def _serialize_allowed_uses(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @field_validator("source_lineage_hashes")
    @classmethod
    def _canonical_lineage(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("source lineage hashes must be unique")
        return tuple(sorted(value))


class CandidateMetadata(StrictModel):
    """Governance metadata required before any body can be read."""

    manifest_ref: VersionRef
    review_status: ReviewStatus
    allowed_uses: frozenset[NonEmptyStr]
    approved_at: UtcDateTime
    effective_from: UtcDateTime | None = None
    effective_to: UtcDateTime | None = None
    review_due_at: UtcDateTime | None = None
    sensitivity: NonNegativeInt
    source_grade: SourceGrade
    framework_priority: Literal["highest", "normal", "not_applicable"] = (
        "not_applicable"
    )
    empirical_support: EmpiricalSupport = "unassessed"
    source_count: PositiveInt
    minimum_leave_one_out_sources: PositiveInt = 1
    contributor_identity_scheme: ContributorIdentityScheme = "direct_v1"
    source_lineage_hashes: tuple[Sha256Hex, ...] = ()
    media_type: NonEmptyStr
    size_bytes: NonNegativeInt
    leave_one_out: LeaveOneOutVariant | None = None

    @field_serializer("allowed_uses")
    def _serialize_allowed_uses(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @field_validator("source_lineage_hashes")
    @classmethod
    def _canonical_lineage(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("source lineage hashes must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def _validate_windows(self) -> "CandidateMetadata":
        if (
            self.effective_from is not None
            and self.effective_to is not None
            and self.effective_to <= self.effective_from
        ):
            raise ValueError("candidate effective window is inverted")
        return self


class CandidateRef(StrictModel):
    """Exact, body-free retrieval candidate.

    ``reference`` identifies the evidence object while ``content_ref`` points
    at the immutable body that may be opened only after filtering.  They are
    distinct because a Claim can resolve to a governed Passage body.
    """

    reference: VersionRef
    content_ref: VersionRef
    object_type: SafePolicyKey
    channel: EvidenceChannel
    metadata: CandidateMetadata
    provenance: Provenance
    location: EvidenceLocator
    freshness: EvidenceFreshnessSnapshot
    score: FiniteFloat
    score_components: tuple[ScoreComponent, ...] = ()
    filter_binding: FilterCapabilityBinding | None = None

    @field_validator("score_components")
    @classmethod
    def _canonical_components(
        cls, value: tuple[ScoreComponent, ...]
    ) -> tuple[ScoreComponent, ...]:
        channels = [component.channel for component in value]
        if len(channels) != len(set(channels)):
            raise ValueError("score components must use unique channels")
        return tuple(sorted(value, key=lambda item: item.channel))


class ExclusionProof(StrictModel):
    """Safe aggregate proof; it cannot expose candidate or client identifiers."""

    run_id: Uuid7String
    policy_ref: VersionRef
    input_count: NonNegativeInt
    allowed_count: NonNegativeInt
    denied_count: NonNegativeInt
    candidate_ids_sha256: Sha256Hex
    reasons: dict[DeniedReason, NonNegativeInt]

    @field_validator("reasons")
    @classmethod
    def _canonical_reasons(
        cls, value: dict[DeniedReason, int]
    ) -> dict[DeniedReason, int]:
        unknown = set(value) - set(DENIED_REASON_ORDER)
        if unknown or any(type(count) is not int or count < 0 for count in value.values()):
            raise ValueError("exclusion reasons are invalid")
        return {
            reason: value[reason]
            for reason in DENIED_REASON_ORDER
            if value.get(reason, 0) > 0
        }

    @model_validator(mode="after")
    def _validate_counts(self) -> "ExclusionProof":
        if self.allowed_count + self.denied_count != self.input_count:
            raise ValueError("exclusion counts do not close")
        if sum(self.reasons.values()) != self.denied_count:
            raise ValueError("denied reason counts do not close")
        return self


class FilterDecision(StrictModel):
    allowed: tuple[CandidateRef, ...]
    proof: ExclusionProof
    exclusion_proof_ref: VersionRef | None = None

    @model_validator(mode="after")
    def _validate_binding(self) -> "FilterDecision":
        if len(self.allowed) != self.proof.allowed_count:
            raise ValueError("allowed candidates do not match proof")
        if any(candidate.filter_binding is None for candidate in self.allowed):
            raise ValueError("allowed candidates must be filter-bound")
        return self


class ResolvedEvidence(StrictModel):
    """A filtered candidate paired with its verified immutable body."""

    candidate: CandidateRef
    body: bytes


class Retriever(Protocol):
    def search(
        self,
        query: str,
        scope: object,
        authority_snapshot: AuthoritativeFilterSnapshot,
        *,
        limit: int,
    ) -> tuple[CandidateRef, ...]: ...


class ExclusionProofPublisher(Protocol):
    def publish(self, proof: ExclusionProof) -> VersionRef: ...


def candidate_set_sha256(candidates: tuple[CandidateRef, ...]) -> str:
    identities = sorted(
        (
            candidate.reference.object_id,
            candidate.reference.version,
            candidate.reference.content_sha256,
            candidate.content_ref.object_id,
            candidate.content_ref.version,
            candidate.content_ref.content_sha256,
        )
        for candidate in candidates
    )
    return hashlib.sha256(canonical_json_bytes(identities)).hexdigest()


def candidate_capability_payload(candidate: CandidateRef) -> dict[str, object]:
    """Bind every authority-sensitive field while permitting later score updates."""

    return {
        "channel": candidate.channel,
        "content_ref": candidate.content_ref.model_dump(mode="json"),
        "freshness": candidate.freshness.model_dump(mode="json"),
        "location": candidate.location.model_dump(mode="json"),
        "metadata": candidate.metadata.model_dump(mode="json"),
        "object_type": candidate.object_type,
        "provenance": candidate.provenance.model_dump(mode="json"),
        "reference": candidate.reference.model_dump(mode="json"),
    }


def canonical_candidate_capability_payloads(
    candidates: tuple[CandidateRef, ...],
) -> list[dict[str, object]]:
    ordered = sorted(
        candidates,
        key=lambda candidate: (
            candidate.reference.object_id,
            candidate.reference.version,
            candidate.reference.content_sha256,
            candidate.content_ref.object_id,
            candidate.content_ref.version,
            candidate.content_ref.content_sha256,
        ),
    )
    return [candidate_capability_payload(candidate) for candidate in ordered]


def capability_sha256(
    snapshot: AuthoritativeFilterSnapshot,
    allowed: tuple[CandidateRef, ...],
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "allowed": canonical_candidate_capability_payloads(allowed),
                "authorization_epoch": snapshot.authorization_epoch,
                "client_runtime_epoch": snapshot.client_runtime_epoch,
                "global_runtime_epoch": snapshot.global_runtime_epoch,
                "policy_ref": snapshot.policy_ref.model_dump(mode="json"),
                "run_id": snapshot.run_id,
                "tombstone_epoch": snapshot.tombstone_epoch,
            }
        )
    ).hexdigest()


def private_owner(provenance: Provenance) -> ClientId | None:
    """Typed spelling used by filters without serializing the owner."""

    return provenance.private_owner_client_id


__all__ = [
    "CandidateMetadata",
    "CandidateRef",
    "ContributorIdentityScheme",
    "DENIED_REASON_ORDER",
    "DeniedReason",
    "ExclusionProof",
    "ExclusionProofPublisher",
    "FilterCapabilityBinding",
    "FilterDecision",
    "LeaveOneOutVariant",
    "ResolvedEvidence",
    "Retriever",
    "ReviewStatus",
    "ScoreComponent",
    "candidate_set_sha256",
    "candidate_capability_payload",
    "canonical_candidate_capability_payloads",
    "canonical_json_bytes",
    "capability_sha256",
]
