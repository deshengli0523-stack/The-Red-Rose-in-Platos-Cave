"""Fail-closed release matrix for deidentified shared case candidates."""

from __future__ import annotations

from datetime import datetime

from pydantic import TypeAdapter

from consultation_kb.models.cases import (
    CaseReleaseDecision,
    CaseReuseAuthorization,
    DeidentificationHumanReview,
    ReleaseOutcome,
    ReleaseReason,
    ReviewCategory,
    SharedCaseCandidate,
)
from consultation_kb.models.common import SafePolicyKey, UtcDateTime, VersionRef


_SAFE_POLICY_ADAPTER = TypeAdapter(SafePolicyKey)
_UTC_ADAPTER: TypeAdapter[datetime] = TypeAdapter(UtcDateTime)
_DEFAULT_REQUIRED_REVIEW_CATEGORIES: frozenset[ReviewCategory] = frozenset(
    {
        "direct_identifiers",
        "third_party_people",
        "rare_attributes",
        "location_occupation_family_time",
        "section_boundaries",
        "no_verbatim_quotes",
    }
)


class CaseReleasePolicy:
    """Evaluate authorization and review without reading or logging case bodies."""

    def __init__(
        self,
        *,
        policy_ref: VersionRef,
        required_review_categories: frozenset[ReviewCategory] = (
            _DEFAULT_REQUIRED_REVIEW_CATEGORIES
        ),
    ) -> None:
        self._policy_ref = VersionRef.model_validate(policy_ref)
        if not required_review_categories:
            raise ValueError("case release policy requires review categories")
        self._required_review_categories = frozenset(required_review_categories)

    def evaluate(
        self,
        candidate: SharedCaseCandidate,
        authorization: CaseReuseAuthorization,
        review: DeidentificationHumanReview | None,
        *,
        purpose: str,
        at: UtcDateTime,
    ) -> CaseReleaseDecision:
        value = SharedCaseCandidate.model_validate(candidate)
        grant = CaseReuseAuthorization.model_validate(authorization)
        checked_purpose = _SAFE_POLICY_ADAPTER.validate_python(purpose)
        checked_at = _UTC_ADAPTER.validate_python(at)
        checked_review = (
            None
            if review is None
            else DeidentificationHumanReview.model_validate(review)
        )

        private_reasons: list[ReleaseReason] = []
        quarantine_reasons: list[ReleaseReason] = []
        if not grant.reuse_authorized:
            private_reasons.append("reuse_not_authorized")
        if grant.contributor_client_hash not in value.provenance.contributor_client_hashes:
            private_reasons.append("authorization_subject_mismatch")
        if checked_at < grant.valid_from:
            private_reasons.append("authorization_not_yet_effective")
        if grant.expires_at is not None and checked_at >= grant.expires_at:
            private_reasons.append("authorization_expired")
        if grant.revoked_at is not None and checked_at >= grant.revoked_at:
            private_reasons.append("authorization_revoked")
        if (
            checked_purpose not in grant.allowed_uses
            or checked_purpose not in value.requested_allowed_uses
        ):
            private_reasons.append("purpose_not_authorized")

        if checked_review is None:
            quarantine_reasons.append("human_review_missing")
        else:
            if checked_review.decision == "rejected":
                private_reasons.append("human_review_rejected")
            elif checked_review.decision == "quarantine":
                quarantine_reasons.append("human_review_quarantined")
            if (
                checked_review.candidate_sha256 != value.candidate_sha256
                or checked_review.reviewed_at < value.created_at
            ):
                quarantine_reasons.append("human_review_candidate_mismatch")
            if checked_review.reviewed_at > checked_at:
                quarantine_reasons.append("human_review_not_yet_effective")
            if not self._required_review_categories.issubset(
                checked_review.checked_categories
            ):
                quarantine_reasons.append("review_categories_incomplete")
            if checked_review.residual_risk == "high":
                quarantine_reasons.append("residual_risk_too_high")
            if value.deidentification.unresolved_rare_combination_count:
                if checked_review.rare_combination_disposition != "mitigated":
                    quarantine_reasons.append("rare_combination_unresolved")
            elif checked_review.rare_combination_disposition == "unresolved":
                quarantine_reasons.append("rare_combination_unresolved")
            if checked_purpose not in checked_review.allowed_uses:
                private_reasons.append("purpose_not_authorized")

        if not value.deidentification.automatic_scan_complete:
            quarantine_reasons.append("deidentification_incomplete")
        section_kinds = frozenset(item.section_kind for item in value.sections)
        if not {"factual_context", "actual_response"}.issubset(section_kinds):
            quarantine_reasons.append("section_boundary_incomplete")
        if value.incomplete_evidence:
            quarantine_reasons.append("incomplete_evidence")

        private_reasons = list(dict.fromkeys(private_reasons))
        quarantine_reasons = list(dict.fromkeys(quarantine_reasons))
        outcome: ReleaseOutcome
        if private_reasons:
            outcome = "private_only"
            reasons = tuple((*private_reasons, *quarantine_reasons))
            allowed_uses: frozenset[str] = frozenset()
        elif quarantine_reasons:
            outcome = "quarantine"
            reasons = tuple(quarantine_reasons)
            allowed_uses = frozenset()
        else:
            if checked_review is None:
                raise AssertionError("eligible release must have a human review")
            outcome = "eligible"
            reasons = ()
            allowed_uses = frozenset(
                value.requested_allowed_uses
                & grant.allowed_uses
                & checked_review.allowed_uses
            )
            if checked_purpose not in allowed_uses:
                raise AssertionError("eligible release lost its evaluated purpose")

        return CaseReleaseDecision(
            candidate_sha256=value.candidate_sha256,
            outcome=outcome,
            reasons=reasons,
            authorization_ref=grant.authorization_ref,
            review_ref=(checked_review.review_ref if checked_review is not None else None),
            policy_ref=self._policy_ref,
            allowed_uses=allowed_uses,
            evaluated_at=checked_at,
        )


__all__ = ["CaseReleasePolicy"]
