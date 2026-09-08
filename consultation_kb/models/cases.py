"""Strict contracts for deidentified shared cases and governed case lineage.

The models in this module deliberately split private source material from
shared artifacts.  Private source models may carry consultation text while
every model whose name starts with ``Shared`` or ``CaseProvenance`` is safe to
serialize outside the client vault: contributor identities are represented by
keyed hashes and source-session identifiers are represented by content hashes.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime
from typing import Literal, TypeAlias

from pydantic import field_serializer, field_validator, model_validator

from consultation_kb.knowledge._canonical import canonical_sha256, text_sha256
from consultation_kb.models.common import (
    NonEmptyStr,
    NonNegativeInt,
    ObjectId,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    VersionRef,
)
from consultation_kb.models.evidence import SourceGrade


PrivateCaseSourceKind: TypeAlias = Literal[
    "client_message",
    "actual_reply",
    "model_analysis",
    "counselor_reflection",
]
CaseSectionKind: TypeAlias = Literal[
    "factual_context",
    "actual_response",
    "model_analysis",
    "counselor_reflection",
]
DeidentificationCategory: TypeAlias = Literal[
    "internal_identifier",
    "person_name",
    "phone",
    "email",
    "national_id",
    "exact_address",
    "organization",
    "exact_date",
    "third_party_person",
    "rare_location",
    "occupation",
    "family_structure",
]
ReviewCategory: TypeAlias = Literal[
    "direct_identifiers",
    "third_party_people",
    "rare_attributes",
    "location_occupation_family_time",
    "section_boundaries",
    "no_verbatim_quotes",
]
CaseArtifactKind: TypeAlias = Literal[
    "case",
    "case_pattern",
    "claim",
    "wiki_section",
    "graph_edge",
    "lexical_row",
    "vector_row",
]
CaseProvenanceScope: TypeAlias = Literal[
    "global_source", "case_derived", "mixed"
]
ReleaseOutcome: TypeAlias = Literal["eligible", "private_only", "quarantine"]
ReleaseReason: TypeAlias = Literal[
    "reuse_not_authorized",
    "authorization_subject_mismatch",
    "authorization_not_yet_effective",
    "authorization_expired",
    "authorization_revoked",
    "purpose_not_authorized",
    "human_review_missing",
    "human_review_quarantined",
    "human_review_rejected",
    "human_review_candidate_mismatch",
    "human_review_not_yet_effective",
    "review_categories_incomplete",
    "residual_risk_too_high",
    "rare_combination_unresolved",
    "deidentification_incomplete",
    "section_boundary_incomplete",
    "incomplete_evidence",
]
LeaveOneOutIneligibility: TypeAlias = Literal[
    "no_remaining_evidence",
    "insufficient_independent_sources",
    "grade_below_policy",
]


_CLIENT_ID_RE = re.compile(r"client_[a-z0-9]{12}")
_UUID_RE = re.compile(
    r"(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![0-9a-f])",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
_MOBILE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
_NATIONAL_ID_RE = re.compile(r"(?<!\d)\d{17}[0-9Xx](?!\d)")
_EXACT_DATE_RE = re.compile(
    r"(?<!\d)(?:19|20)\d{2}(?:[-/.年])(?:0?[1-9]|1[0-2])"
    r"(?:[-/.月])(?:0?[1-9]|[12]\d|3[01])日?(?!\d)"
)
_QUOTE_RE = re.compile(r"[\"'“”‘’「」『』]")


def version_ref_key(value: VersionRef) -> tuple[str, int, str]:
    return value.object_id, value.version, value.content_sha256


def stable_version_ref_key(value: VersionRef) -> tuple[str, int]:
    """Return the immutable object/version identity, excluding its digest."""

    return value.object_id, value.version


def assert_no_direct_identifiers(value: str) -> str:
    """Reject mechanically detectable direct or internal identifiers."""

    if any(unicodedata.category(character) == "Cf" for character in value):
        raise ValueError("shared text contains Unicode format controls")
    normalized = unicodedata.normalize("NFKC", value).casefold()
    patterns = (
        _CLIENT_ID_RE,
        _UUID_RE,
        _EMAIL_RE,
        _MOBILE_RE,
        _NATIONAL_ID_RE,
        _EXACT_DATE_RE,
    )
    if any(pattern.search(normalized) is not None for pattern in patterns):
        raise ValueError("shared text contains a direct or internal identifier")
    return value


def assert_shared_text_safe(value: str) -> str:
    """Apply the shared-body mechanical privacy boundary.

    Human review remains mandatory for semantic re-identification risk.  This
    guard prevents the most damaging structural mistakes, including copying
    quoted source speech into an allegedly abstracted section.
    """

    assert_no_direct_identifiers(value)
    normalized = unicodedata.normalize("NFKC", value).casefold()
    if _QUOTE_RE.search(normalized) is not None:
        raise ValueError("shared case sections must not contain verbatim quotation marks")
    return value


class PrivateCaseSourceItem(StrictModel):
    """One client-vault source item; never a shared artifact."""

    source_ref: VersionRef
    source_kind: PrivateCaseSourceKind
    content: NonEmptyStr
    actual_recorded: bool
    selected_for_delivery: bool

    @model_validator(mode="after")
    def _validate_source_boundary(self) -> "PrivateCaseSourceItem":
        if text_sha256(self.content) != self.source_ref.content_sha256:
            raise ValueError("private source content does not match its exact reference")
        is_actual = self.source_kind in {"client_message", "actual_reply"}
        if self.actual_recorded != is_actual:
            raise ValueError("only actual messages and replies may be marked actual")
        if self.selected_for_delivery != (self.source_kind == "actual_reply"):
            raise ValueError("only an actual adopted or edited reply is selected for delivery")
        if self.source_kind == "actual_reply" and not self.source_ref.object_id.startswith(
            "actual_reply_"
        ):
            raise ValueError("actual reply source must bind an ActualReply reference")
        expected_prefix = {
            "client_message": "client_turn_",
            "actual_reply": "actual_reply_",
            "model_analysis": "model_analysis_",
            "counselor_reflection": "counselor_reflection_",
        }[self.source_kind]
        if not self.source_ref.object_id.startswith(expected_prefix):
            raise ValueError("private source kind does not match its governed reference")
        return self


def private_actual_case_record_payload(
    *,
    record_id: str,
    version: int,
    actual_transcript_ref: VersionRef,
    items: tuple[PrivateCaseSourceItem, ...],
    incomplete_evidence: bool,
) -> dict[str, object]:
    """Return the exact private-record descriptor bound by ``record_ref``."""

    return {
        "actual_transcript_ref": actual_transcript_ref.model_dump(mode="json"),
        "incomplete_evidence": incomplete_evidence,
        "items": [item.model_dump(mode="json") for item in items],
        "record_id": record_id,
        "version": version,
    }


class PrivateActualCaseRecord(StrictModel):
    """Private source record from which a shared candidate may be derived."""

    record_ref: VersionRef
    actual_transcript_ref: VersionRef
    items: tuple[PrivateCaseSourceItem, ...]
    incomplete_evidence: bool

    @field_validator("items")
    @classmethod
    def _canonical_items(
        cls, value: tuple[PrivateCaseSourceItem, ...]
    ) -> tuple[PrivateCaseSourceItem, ...]:
        if not value:
            raise ValueError("private case source requires at least one item")
        keys = [version_ref_key(item.source_ref) for item in value]
        if len(keys) != len(set(keys)):
            raise ValueError("private case source references must be unique")
        stable_keys = [stable_version_ref_key(item.source_ref) for item in value]
        if len(stable_keys) != len(set(stable_keys)):
            raise ValueError("private case source has a stable version conflict")
        return value

    @model_validator(mode="after")
    def _validate_actual_record(self) -> "PrivateActualCaseRecord":
        if not self.record_ref.object_id.startswith("private_actual_record_"):
            raise ValueError("private actual record requires a governed record reference")
        if not self.actual_transcript_ref.object_id.startswith("actual_transcript_"):
            raise ValueError("private actual record requires an ActualTranscript reference")
        kinds = {item.source_kind for item in self.items}
        if "client_message" not in kinds:
            raise ValueError("private actual record requires a client message")
        if "actual_reply" not in kinds and not self.incomplete_evidence:
            raise ValueError("a record without an actual reply must be incomplete evidence")
        expected = canonical_sha256(
            private_actual_case_record_payload(
                record_id=self.record_ref.object_id,
                version=self.record_ref.version,
                actual_transcript_ref=self.actual_transcript_ref,
                items=self.items,
                incomplete_evidence=self.incomplete_evidence,
            )
        )
        if self.record_ref.content_sha256 != expected:
            raise ValueError("private actual record canonical hash mismatch")
        return self


class SharedCaseSectionProposal(StrictModel):
    """Counselor-reviewable abstraction proposed from exact private sources."""

    section_kind: CaseSectionKind
    source_item_refs: tuple[VersionRef, ...]
    abstracted_text: NonEmptyStr

    @field_validator("source_item_refs")
    @classmethod
    def _canonical_sources(cls, value: tuple[VersionRef, ...]) -> tuple[VersionRef, ...]:
        keys = [version_ref_key(item) for item in value]
        if not value or len(keys) != len(set(keys)):
            raise ValueError("section source references must be non-empty and unique")
        stable_keys = [stable_version_ref_key(item) for item in value]
        if len(stable_keys) != len(set(stable_keys)):
            raise ValueError("section source references contain a stable version conflict")
        return tuple(sorted(value, key=version_ref_key))


class SharedCaseSectionDraft(StrictModel):
    """Counselor-authored abstraction before private source refs are attached."""

    section_kind: Literal["factual_context", "actual_response"]
    abstracted_text: NonEmptyStr


class SharedCaseHumanReviewDraft(StrictModel):
    """Every human choice that must be covered by the case approval hash."""

    decision: Literal["approved", "rejected", "quarantine"]
    checked_categories: frozenset[ReviewCategory]
    residual_risk: Literal["low", "medium", "high"]
    rare_combination_disposition: Literal[
        "not_present", "mitigated", "unresolved"
    ]
    reuse_authorized: bool
    allowed_uses: frozenset[SafePolicyKey]
    expires_at: UtcDateTime | None = None

    @field_serializer("checked_categories", "allowed_uses")
    def _serialize_review_sets(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @model_validator(mode="after")
    def _authorization_shape(self) -> "SharedCaseHumanReviewDraft":
        if self.reuse_authorized:
            if (
                self.decision != "approved"
                or not self.allowed_uses
                or self.expires_at is None
            ):
                raise ValueError(
                    "authorized reuse requires approval, allowed uses and explicit expiry"
                )
        elif self.allowed_uses or self.expires_at is not None:
            raise ValueError("denied reuse cannot grant uses or an expiry")
        return self


class DeidentificationFinding(StrictModel):
    """Body-free finding; the matched span is represented only by keyed HMAC."""

    rule: SafePolicyKey
    category: DeidentificationCategory
    span_hmac_sha256: Sha256Hex
    start: NonNegativeInt
    end: PositiveInt
    replacement_category: SafePolicyKey
    automatic_action: Literal["replace", "review"]

    @model_validator(mode="after")
    def _validate_span(self) -> "DeidentificationFinding":
        if self.end <= self.start:
            raise ValueError("deidentification finding span must be increasing")
        return self


class RareCombinationFinding(StrictModel):
    categories: frozenset[DeidentificationCategory]
    combination_hmac_sha256: Sha256Hex
    severity: Literal["high"] = "high"

    @field_serializer("categories")
    def _serialize_categories(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @model_validator(mode="after")
    def _validate_combination(self) -> "RareCombinationFinding":
        if len(self.categories) < 3:
            raise ValueError("rare combination requires at least three quasi-identifiers")
        return self


class DeidentificationScan(StrictModel):
    input_sha256: Sha256Hex
    rule_version: SafePolicyKey
    findings: tuple[DeidentificationFinding, ...]
    rare_combinations: tuple[RareCombinationFinding, ...]
    scanned_categories: frozenset[DeidentificationCategory]
    complete: Literal[True] = True

    @field_serializer("scanned_categories")
    def _serialize_scanned(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @model_validator(mode="after")
    def _validate_scan(self) -> "DeidentificationScan":
        ordered = tuple(sorted(self.findings, key=lambda item: (item.start, item.end, item.rule)))
        if self.findings != ordered:
            raise ValueError("deidentification findings must use canonical span order")
        for previous, current in zip(self.findings, self.findings[1:], strict=False):
            if current.start < previous.end:
                raise ValueError("deidentification findings must not overlap")
        return self


class DeidentificationTransform(StrictModel):
    input_sha256: Sha256Hex
    output_sha256: Sha256Hex
    rule_version: SafePolicyKey
    output_text: NonEmptyStr
    applied_finding_hashes: tuple[Sha256Hex, ...]
    unresolved_rare_combination_hashes: tuple[Sha256Hex, ...]
    requires_human_review: Literal[True] = True

    @field_validator(
        "applied_finding_hashes", "unresolved_rare_combination_hashes"
    )
    @classmethod
    def _canonical_hashes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("deidentification hash lists must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def _validate_output(self) -> "DeidentificationTransform":
        if text_sha256(self.output_text) != self.output_sha256:
            raise ValueError("deidentified output hash mismatch")
        assert_no_direct_identifiers(self.output_text)
        return self


class DeidentificationSummary(StrictModel):
    report_sha256: Sha256Hex
    scanned_section_count: PositiveInt
    transformed_section_count: PositiveInt
    finding_count: NonNegativeInt
    unresolved_rare_combination_count: NonNegativeInt
    automatic_scan_complete: bool
    human_review_required: Literal[True] = True

    @model_validator(mode="after")
    def _validate_counts(self) -> "DeidentificationSummary":
        if self.transformed_section_count != self.scanned_section_count:
            raise ValueError("every scanned shared section must be transformed")
        return self


class SharedCaseSection(StrictModel):
    section_id: ObjectId
    section_kind: CaseSectionKind
    text: NonEmptyStr
    text_sha256: Sha256Hex
    source_item_hmacs: tuple[Sha256Hex, ...]
    deidentification_output_sha256: Sha256Hex
    content_form: Literal["abstracted_summary"] = "abstracted_summary"
    no_verbatim_source: Literal[True] = True

    @field_validator("source_item_hmacs")
    @classmethod
    def _canonical_source_hashes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("shared section source hashes must be non-empty and unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def _validate_shared_text(self) -> "SharedCaseSection":
        if text_sha256(self.text) != self.text_sha256:
            raise ValueError("shared case section text hash mismatch")
        if self.text_sha256 != self.deidentification_output_sha256:
            raise ValueError("shared section must be the deidentified output")
        assert_shared_text_safe(self.text)
        return self


class CandidateProvenanceSummary(StrictModel):
    provenance_ref: VersionRef
    contributor_client_hashes: frozenset[Sha256Hex]
    independent_source_count: NonNegativeInt
    derivation_rule_ref: VersionRef

    @field_serializer("contributor_client_hashes")
    def _serialize_contributors(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @model_validator(mode="after")
    def _validate_candidate_provenance(self) -> "CandidateProvenanceSummary":
        if len(self.contributor_client_hashes) != 1:
            raise ValueError("a K1 shared case candidate requires exactly one contributor")
        if self.independent_source_count != 0:
            raise ValueError("a K1 shared case candidate cannot claim independent sources")
        return self


def shared_case_candidate_payload(
    *,
    candidate_id: str,
    version: int,
    source_record_sha256: str,
    actual_transcript_sha256: str,
    sections: tuple[SharedCaseSection, ...],
    deidentification: DeidentificationSummary,
    provenance: CandidateProvenanceSummary,
    requested_allowed_uses: frozenset[str],
    incomplete_evidence: bool,
    created_at: datetime,
) -> dict[str, object]:
    return {
        "actual_transcript_sha256": actual_transcript_sha256,
        "candidate_id": candidate_id,
        "created_at": created_at.isoformat(),
        "deidentification": deidentification.model_dump(mode="json"),
        "incomplete_evidence": incomplete_evidence,
        "privacy_scope": "case",
        "provenance": provenance.model_dump(mode="json"),
        "requested_allowed_uses": sorted(requested_allowed_uses),
        "sections": [item.model_dump(mode="json") for item in sections],
        "source_grade": "K1",
        "source_record_sha256": source_record_sha256,
        "version": version,
    }


class SharedCaseCandidate(StrictModel):
    """Client-vault candidate containing no source client/session identifier."""

    candidate_ref: VersionRef
    source_record_sha256: Sha256Hex
    actual_transcript_sha256: Sha256Hex
    sections: tuple[SharedCaseSection, ...]
    deidentification: DeidentificationSummary
    provenance: CandidateProvenanceSummary
    requested_allowed_uses: frozenset[SafePolicyKey]
    source_grade: Literal["K1"] = "K1"
    privacy_scope: Literal["case"] = "case"
    incomplete_evidence: bool
    candidate_sha256: Sha256Hex
    created_at: UtcDateTime

    @field_serializer("requested_allowed_uses")
    def _serialize_uses(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @model_validator(mode="after")
    def _validate_candidate(self) -> "SharedCaseCandidate":
        if not self.sections:
            raise ValueError("shared case candidate requires at least one section")
        section_ids = [item.section_id for item in self.sections]
        if len(section_ids) != len(set(section_ids)):
            raise ValueError("shared case section IDs must be unique")
        if not self.requested_allowed_uses:
            raise ValueError("shared case candidate requires a requested use")
        expected = canonical_sha256(
            shared_case_candidate_payload(
                candidate_id=self.candidate_ref.object_id,
                version=self.candidate_ref.version,
                source_record_sha256=self.source_record_sha256,
                actual_transcript_sha256=self.actual_transcript_sha256,
                sections=self.sections,
                deidentification=self.deidentification,
                provenance=self.provenance,
                requested_allowed_uses=frozenset(self.requested_allowed_uses),
                incomplete_evidence=self.incomplete_evidence,
                created_at=self.created_at,
            )
        )
        if self.candidate_sha256 != expected:
            raise ValueError("shared case candidate canonical hash mismatch")
        if self.candidate_ref.content_sha256 != self.candidate_sha256:
            raise ValueError("shared case candidate reference hash mismatch")
        return self


def case_reuse_authorization_payload(
    *,
    authorization_id: str,
    version: int,
    contributor_client_hash: str,
    reuse_authorized: bool,
    allowed_uses: frozenset[str],
    valid_from: datetime,
    expires_at: datetime | None,
    revoked_at: datetime | None,
    terms_sha256: str,
) -> dict[str, object]:
    """Return every authorization field covered by its exact version hash."""

    return {
        "allowed_uses": sorted(allowed_uses),
        "authorization_id": authorization_id,
        "contributor_client_hash": contributor_client_hash,
        "expires_at": expires_at.isoformat() if expires_at is not None else None,
        "reuse_authorized": reuse_authorized,
        "revoked_at": revoked_at.isoformat() if revoked_at is not None else None,
        "terms_sha256": terms_sha256,
        "valid_from": valid_from.isoformat(),
        "version": version,
    }


class CaseReuseAuthorization(StrictModel):
    authorization_ref: VersionRef
    contributor_client_hash: Sha256Hex
    reuse_authorized: bool
    allowed_uses: frozenset[SafePolicyKey]
    valid_from: UtcDateTime
    expires_at: UtcDateTime | None = None
    revoked_at: UtcDateTime | None = None
    terms_sha256: Sha256Hex

    @field_serializer("allowed_uses")
    def _serialize_allowed_uses(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @model_validator(mode="after")
    def _validate_authorization(self) -> "CaseReuseAuthorization":
        if self.reuse_authorized and not self.allowed_uses:
            raise ValueError("reuse authorization requires at least one allowed use")
        if not self.reuse_authorized and self.allowed_uses:
            raise ValueError("denied reuse authorization cannot grant allowed uses")
        if self.expires_at is not None and self.expires_at <= self.valid_from:
            raise ValueError("authorization expiry must follow validity start")
        if self.revoked_at is not None and self.revoked_at < self.valid_from:
            raise ValueError("authorization revocation cannot precede validity")
        expected = canonical_sha256(
            case_reuse_authorization_payload(
                authorization_id=self.authorization_ref.object_id,
                version=self.authorization_ref.version,
                contributor_client_hash=self.contributor_client_hash,
                reuse_authorized=self.reuse_authorized,
                allowed_uses=frozenset(self.allowed_uses),
                valid_from=self.valid_from,
                expires_at=self.expires_at,
                revoked_at=self.revoked_at,
                terms_sha256=self.terms_sha256,
            )
        )
        if self.authorization_ref.content_sha256 != expected:
            raise ValueError("authorization canonical hash mismatch")
        return self


def deidentification_human_review_payload(
    *,
    review_id: str,
    version: int,
    candidate_sha256: str,
    decision: Literal["approved", "rejected", "quarantine"],
    checked_categories: frozenset[ReviewCategory],
    residual_risk: Literal["low", "medium", "high"],
    rare_combination_disposition: Literal[
        "not_present", "mitigated", "unresolved"
    ],
    allowed_uses: frozenset[str],
    reviewed_at: datetime,
    reviewer_attestation_sha256: str,
) -> dict[str, object]:
    """Return every human-review field covered by its exact version hash."""

    return {
        "allowed_uses": sorted(allowed_uses),
        "candidate_sha256": candidate_sha256,
        "checked_categories": sorted(checked_categories),
        "decision": decision,
        "rare_combination_disposition": rare_combination_disposition,
        "residual_risk": residual_risk,
        "review_id": review_id,
        "reviewed_at": reviewed_at.isoformat(),
        "reviewer_attestation_sha256": reviewer_attestation_sha256,
        "version": version,
    }


class DeidentificationHumanReview(StrictModel):
    review_ref: VersionRef
    candidate_sha256: Sha256Hex
    decision: Literal["approved", "rejected", "quarantine"]
    checked_categories: frozenset[ReviewCategory]
    residual_risk: Literal["low", "medium", "high"]
    rare_combination_disposition: Literal[
        "not_present", "mitigated", "unresolved"
    ]
    allowed_uses: frozenset[SafePolicyKey]
    reviewed_at: UtcDateTime
    reviewer_attestation_sha256: Sha256Hex

    @field_serializer("checked_categories", "allowed_uses")
    def _serialize_sets(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @model_validator(mode="after")
    def _validate_review_ref(self) -> "DeidentificationHumanReview":
        expected = canonical_sha256(
            deidentification_human_review_payload(
                review_id=self.review_ref.object_id,
                version=self.review_ref.version,
                candidate_sha256=self.candidate_sha256,
                decision=self.decision,
                checked_categories=frozenset(self.checked_categories),
                residual_risk=self.residual_risk,
                rare_combination_disposition=self.rare_combination_disposition,
                allowed_uses=frozenset(self.allowed_uses),
                reviewed_at=self.reviewed_at,
                reviewer_attestation_sha256=self.reviewer_attestation_sha256,
            )
        )
        if self.review_ref.content_sha256 != expected:
            raise ValueError("review canonical hash mismatch")
        return self


_RELEASE_REASON_ORDER: tuple[ReleaseReason, ...] = (
    "reuse_not_authorized",
    "authorization_subject_mismatch",
    "authorization_not_yet_effective",
    "authorization_expired",
    "authorization_revoked",
    "purpose_not_authorized",
    "human_review_missing",
    "human_review_quarantined",
    "human_review_rejected",
    "human_review_candidate_mismatch",
    "human_review_not_yet_effective",
    "review_categories_incomplete",
    "residual_risk_too_high",
    "rare_combination_unresolved",
    "deidentification_incomplete",
    "section_boundary_incomplete",
    "incomplete_evidence",
)


class CaseReleaseDecision(StrictModel):
    candidate_sha256: Sha256Hex
    outcome: ReleaseOutcome
    reasons: tuple[ReleaseReason, ...]
    authorization_ref: VersionRef | None
    review_ref: VersionRef | None
    policy_ref: VersionRef
    allowed_uses: frozenset[SafePolicyKey]
    evaluated_at: UtcDateTime

    @field_serializer("allowed_uses")
    def _serialize_decision_uses(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @field_validator("reasons")
    @classmethod
    def _canonical_reasons(
        cls, value: tuple[ReleaseReason, ...]
    ) -> tuple[ReleaseReason, ...]:
        if len(value) != len(set(value)):
            raise ValueError("release reasons must be unique")
        order = {reason: index for index, reason in enumerate(_RELEASE_REASON_ORDER)}
        return tuple(sorted(value, key=lambda item: order[item]))

    @model_validator(mode="after")
    def _validate_outcome(self) -> "CaseReleaseDecision":
        if self.outcome == "eligible":
            if self.reasons or not self.allowed_uses:
                raise ValueError("eligible release must be reason-free with allowed uses")
        elif not self.reasons or self.allowed_uses:
            raise ValueError("non-eligible release requires reasons and no allowed uses")
        return self


class CaseContribution(StrictModel):
    case_ref: VersionRef
    source_provenance_ref: VersionRef
    contributor_client_hashes: frozenset[Sha256Hex]
    authorization_ref: VersionRef
    allowed_uses: frozenset[SafePolicyKey]
    effective_to: UtcDateTime | None = None
    source_grade: Literal["K1", "K2", "K4"]
    source_lineage_sha256: Sha256Hex

    @field_serializer("contributor_client_hashes", "allowed_uses")
    def _serialize_sets(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @model_validator(mode="after")
    def _validate_contribution(self) -> "CaseContribution":
        if len(self.contributor_client_hashes) != 1 or not self.allowed_uses:
            raise ValueError("a direct case contribution requires one contributor and allowed uses")
        return self


class IndependentEvidence(StrictModel):
    evidence_ref: VersionRef
    source_provenance_ref: VersionRef
    source_grade: SourceGrade
    allowed_uses: frozenset[SafePolicyKey]
    effective_to: UtcDateTime | None = None
    source_lineage_sha256: Sha256Hex

    @field_serializer("allowed_uses")
    def _serialize_uses(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @model_validator(mode="after")
    def _validate_independent(self) -> "IndependentEvidence":
        if self.source_grade.startswith("K"):
            raise ValueError("case evidence must be represented as a case contribution")
        if not self.allowed_uses:
            raise ValueError("independent evidence requires an allowed use")
        return self


def _lineage_allowed_uses(
    cases: tuple[CaseContribution, ...],
    independent: tuple[IndependentEvidence, ...],
) -> frozenset[str]:
    values: list[frozenset[str]] = [item.allowed_uses for item in cases]
    values.extend(item.allowed_uses for item in independent)
    if not values:
        return frozenset()
    allowed = set(values[0])
    for current in values[1:]:
        allowed.intersection_update(current)
    return frozenset(allowed)


def _lineage_effective_to(
    cases: tuple[CaseContribution, ...],
    independent: tuple[IndependentEvidence, ...],
) -> datetime | None:
    values = [item.effective_to for item in cases if item.effective_to is not None]
    values.extend(
        item.effective_to
        for item in independent
        if item.effective_to is not None
    )
    return min(values) if values else None


_CASE_GRADE_PRIORITY: tuple[SourceGrade, ...] = (
    "C1",
    "T1",
    "C2",
    "T2",
    "T3",
    "C3",
    "T4",
    "C4",
    "C5",
    "C6",
    "L1",
    "L2",
    "L3",
    "L4",
    "K3",
    "K2",
    "K1",
    "K4",
)
_CASE_GRADE_RANK = {
    grade: rank for rank, grade in enumerate(_CASE_GRADE_PRIORITY)
}


def recompute_case_source_grade(
    case_contributions: tuple[CaseContribution, ...],
    independent_evidence: tuple[IndependentEvidence, ...],
) -> SourceGrade:
    """Conservatively recompute grade after every provenance derivation."""

    if independent_evidence:
        return min(
            (item.source_grade for item in independent_evidence),
            key=_CASE_GRADE_RANK.__getitem__,
        )
    contributors = {
        value
        for item in case_contributions
        for value in item.contributor_client_hashes
    }
    if len(case_contributions) >= 2 and len(contributors) >= 2:
        return "K3"
    if len(case_contributions) == 1:
        return case_contributions[0].source_grade
    return "K1"


def case_provenance_payload(
    *,
    provenance_id: str,
    version: int,
    artifact_ref: VersionRef,
    artifact_kind: CaseArtifactKind,
    parent_provenance_refs: tuple[VersionRef, ...],
    ancestor_artifact_refs: tuple[VersionRef, ...],
    case_contributions: tuple[CaseContribution, ...],
    independent_evidence: tuple[IndependentEvidence, ...],
    contributor_client_hashes: frozenset[str],
    derivation_rule_ref: VersionRef,
    policy_manifest_ref: VersionRef,
    source_grade: SourceGrade,
    provenance_scope: CaseProvenanceScope,
    allowed_uses: frozenset[str],
    effective_to: datetime | None,
) -> dict[str, object]:
    return {
        "allowed_uses": sorted(allowed_uses),
        "ancestor_artifact_refs": [
            item.model_dump(mode="json") for item in ancestor_artifact_refs
        ],
        "artifact_kind": artifact_kind,
        "artifact_ref": artifact_ref.model_dump(mode="json"),
        "case_contributions": [item.model_dump(mode="json") for item in case_contributions],
        "contributor_client_hashes": sorted(contributor_client_hashes),
        "derivation_rule_ref": derivation_rule_ref.model_dump(mode="json"),
        "effective_to": effective_to.isoformat() if effective_to is not None else None,
        "independent_evidence": [item.model_dump(mode="json") for item in independent_evidence],
        "parent_provenance_refs": [
            item.model_dump(mode="json") for item in parent_provenance_refs
        ],
        "provenance_id": provenance_id,
        "policy_manifest_ref": policy_manifest_ref.model_dump(mode="json"),
        "provenance_scope": provenance_scope,
        "source_grade": source_grade,
        "version": version,
    }


class CaseProvenanceRecord(StrictModel):
    """Transitive, body-free lineage safe for shared artifacts."""

    provenance_ref: VersionRef
    artifact_ref: VersionRef
    artifact_kind: CaseArtifactKind
    parent_provenance_refs: tuple[VersionRef, ...]
    ancestor_artifact_refs: tuple[VersionRef, ...]
    case_contributions: tuple[CaseContribution, ...]
    independent_evidence: tuple[IndependentEvidence, ...]
    contributor_client_hashes: frozenset[Sha256Hex]
    derivation_rule_ref: VersionRef
    policy_manifest_ref: VersionRef
    source_grade: SourceGrade
    provenance_scope: CaseProvenanceScope
    allowed_uses: frozenset[SafePolicyKey]
    effective_to: UtcDateTime | None = None
    closure_sha256: Sha256Hex

    @field_serializer("contributor_client_hashes", "allowed_uses")
    def _serialize_sets(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @field_validator("parent_provenance_refs", "ancestor_artifact_refs")
    @classmethod
    def _canonical_refs(cls, value: tuple[VersionRef, ...]) -> tuple[VersionRef, ...]:
        keys = [version_ref_key(item) for item in value]
        if len(keys) != len(set(keys)):
            raise ValueError("lineage reference lists must be unique")
        stable_keys = [stable_version_ref_key(item) for item in value]
        if len(stable_keys) != len(set(stable_keys)):
            raise ValueError("lineage reference lists contain a stable version conflict")
        return tuple(sorted(value, key=version_ref_key))

    @field_validator("case_contributions")
    @classmethod
    def _canonical_cases(
        cls, value: tuple[CaseContribution, ...]
    ) -> tuple[CaseContribution, ...]:
        keys = [version_ref_key(item.case_ref) for item in value]
        if len(keys) != len(set(keys)):
            raise ValueError("case contributions must be unique by exact case version")
        stable_keys = [stable_version_ref_key(item.case_ref) for item in value]
        if len(stable_keys) != len(set(stable_keys)):
            raise ValueError("case contributions contain a stable version conflict")
        return tuple(sorted(value, key=lambda item: version_ref_key(item.case_ref)))

    @field_validator("independent_evidence")
    @classmethod
    def _canonical_independent(
        cls, value: tuple[IndependentEvidence, ...]
    ) -> tuple[IndependentEvidence, ...]:
        keys = [version_ref_key(item.evidence_ref) for item in value]
        if len(keys) != len(set(keys)):
            raise ValueError("independent evidence must be unique by exact version")
        stable_keys = [stable_version_ref_key(item.evidence_ref) for item in value]
        if len(stable_keys) != len(set(stable_keys)):
            raise ValueError("independent evidence contains a stable version conflict")
        return tuple(sorted(value, key=lambda item: version_ref_key(item.evidence_ref)))

    @model_validator(mode="after")
    def _validate_closure(self) -> "CaseProvenanceRecord":
        if not self.case_contributions and not self.independent_evidence:
            raise ValueError("case provenance requires at least one source")
        contributors = frozenset().union(
            *(item.contributor_client_hashes for item in self.case_contributions)
        ) if self.case_contributions else frozenset()
        if contributors != self.contributor_client_hashes:
            raise ValueError("case contributor hash closure mismatch")
        expected_scope: CaseProvenanceScope
        if self.case_contributions and self.independent_evidence:
            expected_scope = "mixed"
        elif self.case_contributions:
            expected_scope = "case_derived"
        else:
            expected_scope = "global_source"
        if self.provenance_scope != expected_scope:
            raise ValueError("case provenance scope does not match its sources")
        if self.allowed_uses != _lineage_allowed_uses(
            self.case_contributions, self.independent_evidence
        ):
            raise ValueError("derived allowed uses must be the source intersection")
        if not self.allowed_uses:
            raise ValueError("derived case artifact has no common allowed use")
        if self.effective_to != _lineage_effective_to(
            self.case_contributions, self.independent_evidence
        ):
            raise ValueError("derived expiry must be the earliest source expiry")
        ancestor_keys = {version_ref_key(item) for item in self.ancestor_artifact_refs}
        if version_ref_key(self.artifact_ref) in ancestor_keys:
            raise ValueError("case provenance cycle detected")
        if self.artifact_kind == "case":
            if (
                self.parent_provenance_refs
                or len(self.case_contributions) != 1
                or self.independent_evidence
            ):
                raise ValueError("case root requires exactly one direct contribution")
            if self.case_contributions[0].case_ref != self.artifact_ref:
                raise ValueError("case root contribution must reference itself")
        elif not self.parent_provenance_refs:
            raise ValueError("derived case artifact requires parent provenance")
        if self.source_grade != recompute_case_source_grade(
            self.case_contributions, self.independent_evidence
        ):
            raise ValueError("case provenance evidence grade was not recomputed")
        expected = canonical_sha256(
            case_provenance_payload(
                provenance_id=self.provenance_ref.object_id,
                version=self.provenance_ref.version,
                artifact_ref=self.artifact_ref,
                artifact_kind=self.artifact_kind,
                parent_provenance_refs=self.parent_provenance_refs,
                ancestor_artifact_refs=self.ancestor_artifact_refs,
                case_contributions=self.case_contributions,
                independent_evidence=self.independent_evidence,
                contributor_client_hashes=frozenset(self.contributor_client_hashes),
                derivation_rule_ref=self.derivation_rule_ref,
                policy_manifest_ref=self.policy_manifest_ref,
                source_grade=self.source_grade,
                provenance_scope=self.provenance_scope,
                allowed_uses=frozenset(self.allowed_uses),
                effective_to=self.effective_to,
            )
        )
        if self.closure_sha256 != expected:
            raise ValueError("case provenance closure hash mismatch")
        if self.provenance_ref.content_sha256 != self.closure_sha256:
            raise ValueError("case provenance exact reference hash mismatch")
        return self


class RegeneratedCaseArtifact(StrictModel):
    """Output of the trusted LOO regenerator, bound to its exact execution proof."""

    parent_ref: VersionRef
    variant_ref: VersionRef
    content_ref: VersionRef
    regeneration_rule_ref: VersionRef
    input_case_refs: tuple[VersionRef, ...]
    input_independent_source_refs: tuple[VersionRef, ...]
    rendered_text: NonEmptyStr
    rendered_text_sha256: Sha256Hex
    regeneration_request_sha256: Sha256Hex
    regeneration_proof_ref: VersionRef

    @field_validator("input_case_refs", "input_independent_source_refs")
    @classmethod
    def _canonical_inputs(cls, value: tuple[VersionRef, ...]) -> tuple[VersionRef, ...]:
        keys = [version_ref_key(item) for item in value]
        if len(keys) != len(set(keys)):
            raise ValueError("LOO regeneration inputs must be unique")
        stable_keys = [stable_version_ref_key(item) for item in value]
        if len(stable_keys) != len(set(stable_keys)):
            raise ValueError("LOO regeneration inputs contain a stable version conflict")
        return tuple(sorted(value, key=version_ref_key))

    @model_validator(mode="after")
    def _validate_regeneration(self) -> "RegeneratedCaseArtifact":
        if not self.input_case_refs and not self.input_independent_source_refs:
            raise ValueError("LOO regeneration requires remaining evidence")
        if self.parent_ref == self.variant_ref:
            raise ValueError("LOO variant must be a new exact object version")
        if self.variant_ref == self.content_ref:
            raise ValueError("LOO variant and content records must be distinct")
        if text_sha256(self.rendered_text) != self.rendered_text_sha256:
            raise ValueError("LOO regenerated body hash mismatch")
        if self.parent_ref.content_sha256 == self.rendered_text_sha256:
            raise ValueError("LOO regeneration must not republish parent-identical bytes")
        if (
            self.variant_ref.content_sha256 != self.rendered_text_sha256
            or self.content_ref.content_sha256 != self.rendered_text_sha256
        ):
            raise ValueError("LOO variant and content refs must bind regenerated bytes")
        expected_request_sha256 = canonical_sha256(
            regenerated_case_request_payload(
                parent_ref=self.parent_ref,
                variant_ref=self.variant_ref,
                content_ref=self.content_ref,
                regeneration_rule_ref=self.regeneration_rule_ref,
                input_case_refs=self.input_case_refs,
                input_independent_source_refs=self.input_independent_source_refs,
                rendered_text_sha256=self.rendered_text_sha256,
            )
        )
        if self.regeneration_request_sha256 != expected_request_sha256:
            raise ValueError("LOO regeneration request hash mismatch")
        if (
            not self.regeneration_proof_ref.object_id.startswith(
                "case_regeneration_proof_"
            )
            or self.regeneration_proof_ref.content_sha256
            != self.regeneration_request_sha256
        ):
            raise ValueError("LOO regeneration proof does not bind the exact request")
        assert_shared_text_safe(self.rendered_text)
        return self


def regenerated_case_request_payload(
    *,
    parent_ref: VersionRef,
    variant_ref: VersionRef,
    content_ref: VersionRef,
    regeneration_rule_ref: VersionRef,
    input_case_refs: tuple[VersionRef, ...],
    input_independent_source_refs: tuple[VersionRef, ...],
    rendered_text_sha256: str,
) -> dict[str, object]:
    return {
        "content_ref": content_ref.model_dump(mode="json"),
        "input_case_refs": [item.model_dump(mode="json") for item in input_case_refs],
        "input_independent_source_refs": [
            item.model_dump(mode="json")
            for item in input_independent_source_refs
        ],
        "parent_ref": parent_ref.model_dump(mode="json"),
        "regeneration_rule_ref": regeneration_rule_ref.model_dump(mode="json"),
        "rendered_text_sha256": rendered_text_sha256,
        "schema_version": "case_regeneration_request.v1",
        "variant_ref": variant_ref.model_dump(mode="json"),
    }


def leave_one_out_draft_payload(
    *,
    draft_id: str,
    version: int,
    artifact_kind: CaseArtifactKind,
    parent_ref: VersionRef,
    parent_provenance_ref: VersionRef,
    excluded_client_hash: str,
    variant_ref: VersionRef,
    variant_provenance_ref: VersionRef,
    content_ref: VersionRef,
    regeneration_rule_ref: VersionRef,
    regeneration_request_sha256: str,
    regeneration_proof_ref: VersionRef,
    remaining_case_count: int,
    remaining_contributor_count: int,
    remaining_independent_evidence_count: int,
    remaining_independent_source_count: int,
    minimum_independent_source_count: int,
    source_grade: SourceGrade,
    provenance_scope: CaseProvenanceScope,
    eligible_for_approval: bool,
    ineligibility_reason: LeaveOneOutIneligibility | None,
) -> dict[str, object]:
    return {
        "artifact_kind": artifact_kind,
        "content_ref": content_ref.model_dump(mode="json"),
        "draft_id": draft_id,
        "eligible_for_approval": eligible_for_approval,
        "excluded_client_hash": excluded_client_hash,
        "ineligibility_reason": ineligibility_reason,
        "minimum_independent_source_count": minimum_independent_source_count,
        "parent_provenance_ref": parent_provenance_ref.model_dump(mode="json"),
        "parent_ref": parent_ref.model_dump(mode="json"),
        "provenance_scope": provenance_scope,
        "regeneration_rule_ref": regeneration_rule_ref.model_dump(mode="json"),
        "regeneration_request_sha256": regeneration_request_sha256,
        "regeneration_proof_ref": regeneration_proof_ref.model_dump(mode="json"),
        "remaining_case_count": remaining_case_count,
        "remaining_contributor_count": remaining_contributor_count,
        "remaining_independent_evidence_count": remaining_independent_evidence_count,
        "remaining_independent_source_count": remaining_independent_source_count,
        "source_grade": source_grade,
        "variant_provenance_ref": variant_provenance_ref.model_dump(mode="json"),
        "variant_ref": variant_ref.model_dump(mode="json"),
        "version": version,
    }


class LeaveOneOutDraft(StrictModel):
    draft_ref: VersionRef
    artifact_kind: CaseArtifactKind
    parent_ref: VersionRef
    parent_provenance_ref: VersionRef
    excluded_client_hash: Sha256Hex
    variant_ref: VersionRef
    variant_provenance_ref: VersionRef
    content_ref: VersionRef
    regeneration_rule_ref: VersionRef
    regeneration_request_sha256: Sha256Hex
    regeneration_proof_ref: VersionRef
    remaining_case_count: NonNegativeInt
    remaining_contributor_count: NonNegativeInt
    remaining_independent_evidence_count: NonNegativeInt
    remaining_independent_source_count: NonNegativeInt
    minimum_independent_source_count: PositiveInt
    source_grade: SourceGrade
    provenance_scope: CaseProvenanceScope
    eligible_for_approval: bool
    ineligibility_reason: LeaveOneOutIneligibility | None
    draft_sha256: Sha256Hex

    @model_validator(mode="after")
    def _validate_draft(self) -> "LeaveOneOutDraft":
        if self.eligible_for_approval == (self.ineligibility_reason is not None):
            raise ValueError("LOO eligibility and reason are inconsistent")
        if (
            self.regeneration_proof_ref.content_sha256
            != self.regeneration_request_sha256
        ):
            raise ValueError("LOO draft regeneration proof binding mismatch")
        expected = canonical_sha256(
            leave_one_out_draft_payload(
                draft_id=self.draft_ref.object_id,
                version=self.draft_ref.version,
                artifact_kind=self.artifact_kind,
                parent_ref=self.parent_ref,
                parent_provenance_ref=self.parent_provenance_ref,
                excluded_client_hash=self.excluded_client_hash,
                variant_ref=self.variant_ref,
                variant_provenance_ref=self.variant_provenance_ref,
                content_ref=self.content_ref,
                regeneration_rule_ref=self.regeneration_rule_ref,
                regeneration_request_sha256=self.regeneration_request_sha256,
                regeneration_proof_ref=self.regeneration_proof_ref,
                remaining_case_count=self.remaining_case_count,
                remaining_contributor_count=self.remaining_contributor_count,
                remaining_independent_evidence_count=self.remaining_independent_evidence_count,
                remaining_independent_source_count=self.remaining_independent_source_count,
                minimum_independent_source_count=self.minimum_independent_source_count,
                source_grade=self.source_grade,
                provenance_scope=self.provenance_scope,
                eligible_for_approval=self.eligible_for_approval,
                ineligibility_reason=self.ineligibility_reason,
            )
        )
        if expected != self.draft_sha256:
            raise ValueError("LOO draft canonical hash mismatch")
        if self.draft_ref.content_sha256 != self.draft_sha256:
            raise ValueError("LOO draft reference hash mismatch")
        return self


class LeaveOneOutBuildResult(StrictModel):
    draft: LeaveOneOutDraft
    parent_provenance: CaseProvenanceRecord
    variant_provenance: CaseProvenanceRecord
    regeneration: RegeneratedCaseArtifact

    @model_validator(mode="after")
    def _validate_binding(self) -> "LeaveOneOutBuildResult":
        parent = self.parent_provenance
        provenance = self.variant_provenance
        regeneration = self.regeneration
        draft = self.draft
        if (
            draft.parent_ref != parent.artifact_ref
            or draft.parent_provenance_ref != parent.provenance_ref
            or regeneration.parent_ref != parent.artifact_ref
        ):
            raise ValueError("LOO draft parent binding mismatch")
        if draft.excluded_client_hash not in parent.contributor_client_hashes:
            raise ValueError("LOO excluded contributor parent binding mismatch")

        remaining_cases = tuple(
            item
            for item in parent.case_contributions
            if draft.excluded_client_hash not in item.contributor_client_hashes
        )
        remaining_independent = parent.independent_evidence
        if not remaining_cases and not remaining_independent:
            raise ValueError("LOO build result requires remaining evidence")
        remaining_contributors = frozenset(
            contributor
            for item in remaining_cases
            for contributor in item.contributor_client_hashes
        )
        independent_source_count = len(remaining_contributors) + len(
            {item.source_lineage_sha256 for item in remaining_independent}
        )

        if (
            provenance.case_contributions != remaining_cases
            or provenance.independent_evidence != remaining_independent
            or draft.excluded_client_hash in provenance.contributor_client_hashes
        ):
            raise ValueError("LOO variant provenance source binding mismatch")
        if (
            provenance.artifact_ref != draft.variant_ref
            or provenance.artifact_kind != draft.artifact_kind
            or provenance.artifact_kind != parent.artifact_kind
            or provenance.derivation_rule_ref != draft.regeneration_rule_ref
            or provenance.derivation_rule_ref != parent.derivation_rule_ref
            or provenance.policy_manifest_ref != parent.policy_manifest_ref
        ):
            raise ValueError("LOO variant provenance binding mismatch")
        source_provenance_refs = tuple(
            item.source_provenance_ref for item in remaining_cases
        ) + tuple(
            item.source_provenance_ref for item in remaining_independent
        )
        expected_parent_refs = tuple(
            sorted(
                {
                    version_ref_key(reference): reference
                    for reference in source_provenance_refs
                }.values(),
                key=version_ref_key,
            )
        )
        expected_ancestor_refs = tuple(
            sorted(
                (
                    *(item.case_ref for item in remaining_cases),
                    *(item.evidence_ref for item in remaining_independent),
                ),
                key=version_ref_key,
            )
        )
        if (
            provenance.parent_provenance_refs != expected_parent_refs
            or provenance.ancestor_artifact_refs != expected_ancestor_refs
        ):
            raise ValueError("LOO variant provenance closure binding mismatch")
        if (
            regeneration.regeneration_rule_ref != draft.regeneration_rule_ref
            or regeneration.input_case_refs
            != tuple(item.case_ref for item in remaining_cases)
            or regeneration.input_independent_source_refs
            != tuple(item.evidence_ref for item in remaining_independent)
        ):
            raise ValueError("LOO regeneration input binding mismatch")
        if self.draft.variant_provenance_ref != self.variant_provenance.provenance_ref:
            raise ValueError("LOO draft must bind the exact variant provenance")
        if self.draft.variant_ref != self.regeneration.variant_ref:
            raise ValueError("LOO draft must bind the exact regenerated variant")
        if self.draft.content_ref != self.regeneration.content_ref:
            raise ValueError("LOO draft must bind the exact regenerated content")
        if (
            self.draft.regeneration_request_sha256
            != self.regeneration.regeneration_request_sha256
            or self.draft.regeneration_proof_ref
            != self.regeneration.regeneration_proof_ref
        ):
            raise ValueError("LOO draft must bind the exact regeneration proof")

        if (
            draft.remaining_case_count != len(remaining_cases)
            or draft.remaining_contributor_count != len(remaining_contributors)
            or draft.remaining_independent_evidence_count
            != len(remaining_independent)
            or draft.remaining_independent_source_count != independent_source_count
        ):
            raise ValueError("LOO draft source count binding mismatch")
        if (
            draft.source_grade != provenance.source_grade
            or draft.provenance_scope != provenance.provenance_scope
        ):
            raise ValueError("LOO draft provenance policy binding mismatch")

        ineligibility: LeaveOneOutIneligibility | None = None
        if independent_source_count < draft.minimum_independent_source_count:
            ineligibility = "insufficient_independent_sources"
        elif parent.artifact_kind == "case_pattern" and (
            provenance.source_grade != "K3"
            or len(remaining_cases) < 2
            or len(remaining_contributors) < 2
        ):
            ineligibility = "grade_below_policy"
        elif (
            parent.source_grade == "K3"
            and provenance.source_grade.startswith("K")
            and provenance.source_grade != "K3"
        ):
            ineligibility = "grade_below_policy"
        if (
            draft.eligible_for_approval != (ineligibility is None)
            or draft.ineligibility_reason != ineligibility
        ):
            raise ValueError("LOO draft eligibility binding mismatch")
        return self


def leave_one_out_authority_payload(
    *,
    mapping_id: str,
    version: int,
    parent_ref: VersionRef,
    excluded_client_hash: str,
    variant_ref: VersionRef,
    content_ref: VersionRef,
    authority_manifest_ref: VersionRef,
    provenance_ref: VersionRef,
    approval_ref: VersionRef,
    approval_version: int,
    approval_descriptor_sha256: str,
    draft_ref: VersionRef,
    regeneration_rule_ref: VersionRef,
    regeneration_request_sha256: str,
    regeneration_proof_ref: VersionRef,
    allowed_uses: frozenset[str],
    approved_at: datetime,
    effective_to: datetime | None,
    source_grade: SourceGrade,
    remaining_independent_source_count: int,
    minimum_independent_source_count: int,
) -> dict[str, object]:
    return {
        "allowed_uses": sorted(allowed_uses),
        "approval_ref": approval_ref.model_dump(mode="json"),
        "approval_version": approval_version,
        "approval_descriptor_sha256": approval_descriptor_sha256,
        "approved_at": approved_at.isoformat(),
        "authority_manifest_ref": authority_manifest_ref.model_dump(mode="json"),
        "content_ref": content_ref.model_dump(mode="json"),
        "draft_ref": draft_ref.model_dump(mode="json"),
        "effective_to": effective_to.isoformat() if effective_to is not None else None,
        "excluded_client_hash": excluded_client_hash,
        "mapping_id": mapping_id,
        "minimum_independent_source_count": minimum_independent_source_count,
        "parent_ref": parent_ref.model_dump(mode="json"),
        "provenance_ref": provenance_ref.model_dump(mode="json"),
        "regeneration_rule_ref": regeneration_rule_ref.model_dump(mode="json"),
        "regeneration_request_sha256": regeneration_request_sha256,
        "regeneration_proof_ref": regeneration_proof_ref.model_dump(mode="json"),
        "remaining_independent_source_count": remaining_independent_source_count,
        "review_status": "approved",
        "source_grade": source_grade,
        "variant_ref": variant_ref.model_dump(mode="json"),
        "version": version,
    }


class LeaveOneOutVariantAuthority(StrictModel):
    """Exact authoritative mapping consumed by pre-retrieval client exclusion."""

    mapping_ref: VersionRef
    parent_ref: VersionRef
    excluded_client_hash: Sha256Hex
    variant_ref: VersionRef
    content_ref: VersionRef
    authority_manifest_ref: VersionRef
    provenance_ref: VersionRef
    approval_ref: VersionRef
    approval_version: PositiveInt
    approval_descriptor_sha256: Sha256Hex
    draft_ref: VersionRef
    regeneration_rule_ref: VersionRef
    regeneration_request_sha256: Sha256Hex
    regeneration_proof_ref: VersionRef
    allowed_uses: frozenset[SafePolicyKey]
    approved_at: UtcDateTime
    effective_to: UtcDateTime | None = None
    review_status: Literal["approved"] = "approved"
    source_grade: SourceGrade
    remaining_independent_source_count: PositiveInt
    minimum_independent_source_count: PositiveInt
    mapping_sha256: Sha256Hex

    @field_serializer("allowed_uses")
    def _serialize_authority_uses(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @model_validator(mode="after")
    def _validate_authority(self) -> "LeaveOneOutVariantAuthority":
        if self.approval_version != self.approval_ref.version:
            raise ValueError("LOO approval version must bind the exact approval ref")
        if (
            self.regeneration_proof_ref.content_sha256
            != self.regeneration_request_sha256
        ):
            raise ValueError("LOO authority regeneration proof binding mismatch")
        if self.remaining_independent_source_count < self.minimum_independent_source_count:
            raise ValueError("approved LOO variant lacks independent sources")
        if not self.allowed_uses:
            raise ValueError("approved LOO variant requires allowed uses")
        if self.effective_to is not None and self.effective_to <= self.approved_at:
            raise ValueError("LOO authority expiry must follow approval")
        expected = canonical_sha256(
            leave_one_out_authority_payload(
                mapping_id=self.mapping_ref.object_id,
                version=self.mapping_ref.version,
                parent_ref=self.parent_ref,
                excluded_client_hash=self.excluded_client_hash,
                variant_ref=self.variant_ref,
                content_ref=self.content_ref,
                authority_manifest_ref=self.authority_manifest_ref,
                provenance_ref=self.provenance_ref,
                approval_ref=self.approval_ref,
                approval_version=self.approval_version,
                approval_descriptor_sha256=self.approval_descriptor_sha256,
                draft_ref=self.draft_ref,
                regeneration_rule_ref=self.regeneration_rule_ref,
                regeneration_request_sha256=self.regeneration_request_sha256,
                regeneration_proof_ref=self.regeneration_proof_ref,
                allowed_uses=frozenset(self.allowed_uses),
                approved_at=self.approved_at,
                effective_to=self.effective_to,
                source_grade=self.source_grade,
                remaining_independent_source_count=self.remaining_independent_source_count,
                minimum_independent_source_count=self.minimum_independent_source_count,
            )
        )
        if expected != self.mapping_sha256:
            raise ValueError("LOO authority canonical hash mismatch")
        if self.mapping_ref.content_sha256 != self.mapping_sha256:
            raise ValueError("LOO authority exact reference hash mismatch")
        return self


__all__ = [
    "CandidateProvenanceSummary",
    "CaseArtifactKind",
    "CaseContribution",
    "CaseProvenanceRecord",
    "CaseProvenanceScope",
    "CaseReleaseDecision",
    "CaseReuseAuthorization",
    "CaseSectionKind",
    "DeidentificationCategory",
    "DeidentificationFinding",
    "DeidentificationHumanReview",
    "DeidentificationScan",
    "DeidentificationSummary",
    "DeidentificationTransform",
    "IndependentEvidence",
    "LeaveOneOutBuildResult",
    "LeaveOneOutDraft",
    "LeaveOneOutIneligibility",
    "LeaveOneOutVariantAuthority",
    "PrivateActualCaseRecord",
    "PrivateCaseSourceItem",
    "RareCombinationFinding",
    "RegeneratedCaseArtifact",
    "ReleaseOutcome",
    "ReleaseReason",
    "ReviewCategory",
    "SharedCaseCandidate",
    "SharedCaseHumanReviewDraft",
    "SharedCaseSection",
    "SharedCaseSectionDraft",
    "SharedCaseSectionProposal",
    "assert_no_direct_identifiers",
    "assert_shared_text_safe",
    "case_reuse_authorization_payload",
    "case_provenance_payload",
    "deidentification_human_review_payload",
    "leave_one_out_authority_payload",
    "leave_one_out_draft_payload",
    "private_actual_case_record_payload",
    "regenerated_case_request_payload",
    "recompute_case_source_grade",
    "shared_case_candidate_payload",
    "stable_version_ref_key",
    "version_ref_key",
]
