from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal

import pytest

from consultation_kb.archive.release_policy import CaseReleasePolicy
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import canonical_sha256, text_sha256
from consultation_kb.models.cases import (
    CandidateProvenanceSummary,
    CaseReuseAuthorization,
    DeidentificationHumanReview,
    DeidentificationSummary,
    ReviewCategory,
    SharedCaseCandidate,
    SharedCaseSection,
    case_reuse_authorization_payload,
    deidentification_human_review_payload,
    shared_case_candidate_payload,
)
from consultation_kb.models.common import VersionRef


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
REQUIRED_REVIEW_CATEGORIES: frozenset[ReviewCategory] = frozenset(
    {
        "direct_identifiers",
        "third_party_people",
        "rare_attributes",
        "location_occupation_family_time",
        "section_boundaries",
        "no_verbatim_quotes",
    }
)


def _ids() -> IdFactory:
    counter = iter(range(6000, 9000))
    return IdFactory(FixedClock(NOW), lambda: next(counter))


def _ref(ids: IdFactory, kind: str, digest: str) -> VersionRef:
    return VersionRef(
        object_id=ids.object_id(kind), version=1, content_sha256=digest
    )


def _candidate(
    ids: IdFactory,
    *,
    rare_count: int = 0,
    incomplete: bool = False,
    automatic_scan_complete: bool = True,
) -> SharedCaseCandidate:
    context = "亲密关系冲突呈周期性变化"
    response = "咨询师先澄清目标并帮助梳理边界"
    sections = (
        SharedCaseSection(
            section_id=ids.object_id("shared_case_section"),
            section_kind="factual_context",
            text=context,
            text_sha256=text_sha256(context),
            source_item_hmacs=("1" * 64,),
            deidentification_output_sha256=text_sha256(context),
        ),
        SharedCaseSection(
            section_id=ids.object_id("shared_case_section"),
            section_kind="actual_response",
            text=response,
            text_sha256=text_sha256(response),
            source_item_hmacs=("2" * 64,),
            deidentification_output_sha256=text_sha256(response),
        ),
    )
    deidentification = DeidentificationSummary(
        report_sha256="3" * 64,
        scanned_section_count=2,
        transformed_section_count=2,
        finding_count=0,
        unresolved_rare_combination_count=rare_count,
        automatic_scan_complete=automatic_scan_complete,
    )
    provenance = CandidateProvenanceSummary(
        provenance_ref=_ref(ids, "case_provenance", "4" * 64),
        contributor_client_hashes=frozenset({"a" * 64}),
        independent_source_count=0,
        derivation_rule_ref=_ref(ids, "policy", "5" * 64),
    )
    candidate_id = ids.object_id("shared_case_candidate")
    digest = canonical_sha256(
        shared_case_candidate_payload(
            candidate_id=candidate_id,
            version=1,
            source_record_sha256="6" * 64,
            actual_transcript_sha256="7" * 64,
            sections=sections,
            deidentification=deidentification,
            provenance=provenance,
            requested_allowed_uses=frozenset({"answer_support"}),
            incomplete_evidence=incomplete,
            created_at=NOW,
        )
    )
    return SharedCaseCandidate(
        candidate_ref=VersionRef(
            object_id=candidate_id, version=1, content_sha256=digest
        ),
        source_record_sha256="6" * 64,
        actual_transcript_sha256="7" * 64,
        sections=sections,
        deidentification=deidentification,
        provenance=provenance,
        requested_allowed_uses=frozenset({"answer_support"}),
        incomplete_evidence=incomplete,
        candidate_sha256=digest,
        created_at=NOW,
    )


def _authorization(
    ids: IdFactory,
    *,
    reuse: bool = True,
    expires_at: datetime | None = None,
    revoked_at: datetime | None = None,
    contributor_client_hash: str = "a" * 64,
) -> CaseReuseAuthorization:
    authorization_id = ids.object_id("case_authorization")
    allowed_uses = frozenset({"answer_support"}) if reuse else frozenset()
    valid_from = NOW - timedelta(days=1)
    terms_sha256 = "9" * 64
    payload = case_reuse_authorization_payload(
        authorization_id=authorization_id,
        version=1,
        contributor_client_hash=contributor_client_hash,
        reuse_authorized=reuse,
        allowed_uses=allowed_uses,
        valid_from=valid_from,
        expires_at=expires_at,
        revoked_at=revoked_at,
        terms_sha256=terms_sha256,
    )
    return CaseReuseAuthorization(
        authorization_ref=VersionRef(
            object_id=authorization_id,
            version=1,
            content_sha256=canonical_sha256(payload),
        ),
        contributor_client_hash=contributor_client_hash,
        reuse_authorized=reuse,
        allowed_uses=allowed_uses,
        valid_from=valid_from,
        expires_at=expires_at,
        revoked_at=revoked_at,
        terms_sha256=terms_sha256,
    )


def _review(
    ids: IdFactory,
    candidate: SharedCaseCandidate,
    *,
    decision: Literal["approved", "rejected", "quarantine"] = "approved",
    rare_disposition: Literal["not_present", "mitigated", "unresolved"] = (
        "not_present"
    ),
    candidate_sha256: str | None = None,
    reviewed_at: datetime | None = None,
) -> DeidentificationHumanReview:
    review_id = ids.object_id("case_review")
    bound_candidate_sha256 = (
        candidate.candidate_sha256
        if candidate_sha256 is None
        else candidate_sha256
    )
    checked_categories = REQUIRED_REVIEW_CATEGORIES
    residual_risk = "low"
    allowed_uses = frozenset({"answer_support"})
    exact_reviewed_at = reviewed_at or NOW + timedelta(minutes=1)
    reviewer_attestation_sha256 = "c" * 64
    payload = deidentification_human_review_payload(
        review_id=review_id,
        version=1,
        candidate_sha256=bound_candidate_sha256,
        decision=decision,
        checked_categories=checked_categories,
        residual_risk=residual_risk,
        rare_combination_disposition=rare_disposition,
        allowed_uses=allowed_uses,
        reviewed_at=exact_reviewed_at,
        reviewer_attestation_sha256=reviewer_attestation_sha256,
    )
    return DeidentificationHumanReview(
        review_ref=VersionRef(
            object_id=review_id,
            version=1,
            content_sha256=canonical_sha256(payload),
        ),
        candidate_sha256=bound_candidate_sha256,
        decision=decision,
        checked_categories=checked_categories,
        residual_risk=residual_risk,
        rare_combination_disposition=rare_disposition,
        allowed_uses=allowed_uses,
        reviewed_at=exact_reviewed_at,
        reviewer_attestation_sha256=reviewer_attestation_sha256,
    )


def _policy(ids: IdFactory) -> CaseReleasePolicy:
    return CaseReleasePolicy(
        policy_ref=_ref(ids, "case_release_policy", "d" * 64)
    )


def test_release_requires_valid_authorization_and_completed_human_review() -> None:
    ids = _ids()
    candidate = _candidate(ids)

    decision = _policy(ids).evaluate(
        candidate,
        _authorization(ids),
        _review(ids, candidate),
        purpose="answer_support",
        at=NOW + timedelta(minutes=2),
    )

    assert decision.outcome == "eligible"
    assert decision.reasons == ()
    assert decision.allowed_uses == frozenset({"answer_support"})
    assert candidate.sections[0].text not in decision.model_dump_json()


@pytest.mark.parametrize(
    ("reuse", "expires_at", "revoked_at", "reason"),
    [
        (False, None, None, "reuse_not_authorized"),
        (True, NOW, None, "authorization_expired"),
        (True, None, NOW, "authorization_revoked"),
    ],
)
def test_false_expired_or_revoked_authorization_is_private_only(
    reuse: bool,
    expires_at: datetime | None,
    revoked_at: datetime | None,
    reason: str,
) -> None:
    ids = _ids()
    candidate = _candidate(ids)

    decision = _policy(ids).evaluate(
        candidate,
        _authorization(
            ids,
            reuse=reuse,
            expires_at=expires_at,
            revoked_at=revoked_at,
        ),
        _review(ids, candidate),
        purpose="answer_support",
        at=NOW + timedelta(minutes=2),
    )

    assert decision.outcome == "private_only"
    assert reason in decision.reasons
    assert decision.allowed_uses == frozenset()


def test_automatic_scan_never_substitutes_for_human_review() -> None:
    ids = _ids()
    candidate = _candidate(ids)

    decision = _policy(ids).evaluate(
        candidate,
        _authorization(ids),
        None,
        purpose="answer_support",
        at=NOW + timedelta(minutes=2),
    )

    assert decision.outcome == "quarantine"
    assert decision.reasons == ("human_review_missing",)


def test_rare_combination_must_be_explicitly_mitigated() -> None:
    ids = _ids()
    candidate = _candidate(ids, rare_count=1)
    policy = _policy(ids)
    authorization = _authorization(ids)

    unresolved = policy.evaluate(
        candidate,
        authorization,
        _review(ids, candidate, rare_disposition="unresolved"),
        purpose="answer_support",
        at=NOW + timedelta(minutes=2),
    )
    mitigated = policy.evaluate(
        candidate,
        authorization,
        _review(ids, candidate, rare_disposition="mitigated"),
        purpose="answer_support",
        at=NOW + timedelta(minutes=2),
    )

    assert unresolved.outcome == "quarantine"
    assert "rare_combination_unresolved" in unresolved.reasons
    assert mitigated.outcome == "eligible"


def test_incomplete_actual_evidence_remains_quarantined() -> None:
    ids = _ids()
    candidate = _candidate(ids, incomplete=True)

    decision = _policy(ids).evaluate(
        candidate,
        _authorization(ids),
        _review(ids, candidate),
        purpose="answer_support",
        at=NOW + timedelta(minutes=2),
    )

    assert decision.outcome == "quarantine"
    assert "incomplete_evidence" in decision.reasons


def test_review_is_bound_to_exact_candidate_hash() -> None:
    ids = _ids()
    candidate = _candidate(ids)

    decision = _policy(ids).evaluate(
        candidate,
        _authorization(ids),
        _review(ids, candidate, candidate_sha256="f" * 64),
        purpose="answer_support",
        at=NOW + timedelta(minutes=2),
    )

    assert decision.outcome == "quarantine"
    assert "human_review_candidate_mismatch" in decision.reasons


def test_authorization_cannot_be_reused_for_another_source_client() -> None:
    ids = _ids()
    candidate = _candidate(ids)

    decision = _policy(ids).evaluate(
        candidate,
        _authorization(ids, contributor_client_hash="e" * 64),
        _review(ids, candidate),
        purpose="answer_support",
        at=NOW + timedelta(minutes=2),
    )

    assert decision.outcome == "private_only"
    assert decision.reasons == ("authorization_subject_mismatch",)
    assert decision.allowed_uses == frozenset()


def test_k1_candidate_provenance_cannot_claim_unverified_independent_sources() -> None:
    ids = _ids()
    candidate = _candidate(ids)

    with pytest.raises(ValueError, match="cannot claim independent sources"):
        candidate.model_copy(
            update={
                "provenance": candidate.provenance.model_copy(
                    update={"independent_source_count": 1}
                )
            }
        )


@pytest.mark.parametrize(
    "update",
    [
        {"contributor_client_hash": "e" * 64},
        {"reuse_authorized": False, "allowed_uses": frozenset()},
        {"allowed_uses": frozenset({"pattern_derivation"})},
        {"valid_from": NOW - timedelta(days=2)},
        {"expires_at": NOW + timedelta(days=30)},
        {"revoked_at": NOW},
        {"terms_sha256": "f" * 64},
    ],
)
def test_authorization_ref_binds_every_semantic_field(
    update: dict[str, object],
) -> None:
    authorization = _authorization(_ids())

    with pytest.raises(ValueError, match="authorization canonical hash mismatch"):
        authorization.model_copy(update=update)


@pytest.mark.parametrize(
    "update",
    [
        {"candidate_sha256": "e" * 64},
        {"decision": "rejected"},
        {"checked_categories": frozenset({"direct_identifiers"})},
        {"residual_risk": "medium"},
        {"rare_combination_disposition": "unresolved"},
        {"allowed_uses": frozenset({"pattern_derivation"})},
        {"reviewed_at": NOW + timedelta(minutes=2)},
        {"reviewer_attestation_sha256": "f" * 64},
    ],
)
def test_review_ref_binds_every_semantic_field(update: dict[str, object]) -> None:
    ids = _ids()
    review = _review(ids, _candidate(ids))

    with pytest.raises(ValueError, match="review canonical hash mismatch"):
        review.model_copy(update=update)


def test_review_from_the_future_is_quarantined() -> None:
    ids = _ids()
    candidate = _candidate(ids)

    decision = _policy(ids).evaluate(
        candidate,
        _authorization(ids),
        _review(
            ids,
            candidate,
            reviewed_at=NOW + timedelta(minutes=3),
        ),
        purpose="answer_support",
        at=NOW + timedelta(minutes=2),
    )

    assert decision.outcome == "quarantine"
    assert "human_review_not_yet_effective" in decision.reasons
