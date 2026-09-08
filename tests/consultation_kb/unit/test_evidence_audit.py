from __future__ import annotations

import pytest
from pydantic import ValidationError

from consultation_kb.generation.contracts import (
    AuditFinding,
    EvidenceAudit,
    EvidenceSemanticAssessment,
    ReplyClaim,
)
from consultation_kb.generation.evidence_audit import AuditableClaim, EvidenceAuditor
from consultation_kb.generation.evidence_registry import GenerationEvidenceContextItem
from consultation_kb.knowledge._canonical import text_sha256
from consultation_kb.knowledge._canonical import canonical_sha256

from tests.consultation_kb.unit.p6_quality_support import (
    candidate,
    envelope,
    object_id,
    pack,
    ref,
)
from tests.consultation_kb.unit.test_conceptualization import _artifact, _valid_items
from tests.consultation_kb.unit.test_reply_drafts import _drafts


def _claim(
    *,
    claim_id: str = "core_conclusion",
    claim_type: str = "important_conclusion",
    evidence_ids: tuple[str, ...],
    contradicting: tuple[str, ...] = (),
    fidelity: str = "faithful",
) -> AuditableClaim:
    return AuditableClaim(
        claim_id=claim_id,
        claim_type=claim_type,
        statement="现有信息支持先澄清变化，再决定行动。",
        evidence_ids=evidence_ids,
        contradicting_evidence_ids=contradicting,
        evidence_fidelity=fidelity,
    )


def _assessments(
    *,
    analysis: tuple[AuditableClaim | ReplyClaim, ...] = (),
    reply: tuple[AuditableClaim | ReplyClaim, ...] = (),
    status_by_pair: dict[tuple[str, str, str, str], str] | None = None,
) -> tuple[EvidenceSemanticAssessment, ...]:
    excerpt = "source excerpt"
    statuses = status_by_pair or {}
    pairs: dict[tuple[str, str, str, str], EvidenceSemanticAssessment] = {}
    for scope, claims in (("analysis", analysis), ("reply", reply)):
        for claim in claims:
            for role, evidence_ids in (
                ("support", claim.evidence_ids),
                ("contradict", claim.contradicting_evidence_ids),
            ):
                for evidence_id in evidence_ids:
                    key = (scope, claim.claim_id, evidence_id, role)
                    status = statuses.get(
                        key,
                        "supports" if role == "support" else "contradicts",
                    )
                    pairs[key] = EvidenceSemanticAssessment(
                        claim_scope=scope,
                        claim_id=claim.claim_id,
                        assessed_claim_type=claim.claim_type,
                        evidence_id=evidence_id,
                        role=role,
                        text_start_char=0,
                        text_end_char=len(excerpt),
                        exact_excerpt=excerpt,
                        excerpt_sha256=text_sha256(excerpt),
                        semantic_status=status,
                    )
    return tuple(pairs[key] for key in sorted(pairs))


def _pack_with_context():
    body = "source excerpt"
    evidence_pack = pack()
    candidates = tuple(
        item.model_copy(
            update={
                "text_ref": item.text_ref.model_copy(
                    update={"content_sha256": text_sha256(body)}
                )
            }
        )
        for item in evidence_pack.supporting
    )
    evidence_pack = evidence_pack.model_copy(update={"supporting": candidates})
    context = tuple(
        GenerationEvidenceContextItem(
            evidence_id=item.evidence_id,
            context_kind="retrieved_candidate",
            text_ref=item.text_ref,
            body=body,
        )
        for item in candidates
    )
    return evidence_pack, context


def test_important_claim_with_faithful_pack_reference_passes() -> None:
    evidence_pack = pack()
    claim = _claim(evidence_ids=(evidence_pack.supporting[0].evidence_id,))

    auditor = EvidenceAuditor()
    result = auditor.audit(
        evidence_pack=evidence_pack,
        analysis_claims=(claim,),
        reply_claims=(claim,),
        assessments=_assessments(analysis=(claim,), reply=(claim,)),
    )

    assert result.decision == "pass"
    assert not result.findings


def test_identical_shared_claim_ids_across_candidates_are_deduplicated() -> None:
    evidence_pack = pack()
    claim = _claim(evidence_ids=(evidence_pack.supporting[0].evidence_id,))

    auditor = EvidenceAuditor()
    result = auditor.audit(
        evidence_pack=evidence_pack,
        analysis_claims=(),
        reply_claims=(claim, claim, claim),
        assessments=_assessments(reply=(claim,)),
    )

    assert result.decision == "pass"


def test_frozen_conceptualization_and_reply_contracts_adapt_directly() -> None:
    evidence_pack = pack()
    evidence_id = evidence_pack.supporting[0].evidence_id

    conceptualization = _artifact(evidence_pack, _valid_items(evidence_id))
    replies = _drafts(evidence_pack)
    analysis_claims = tuple(
        AuditableClaim.from_conceptualization_item(item)
        for item in conceptualization.items
    )
    reply_claims = tuple(
        claim for candidate in replies.candidates for claim in candidate.claims
    )
    result = EvidenceAuditor().audit_artifacts(
        evidence_pack=evidence_pack,
        conceptualization=conceptualization,
        reply_drafts=replies,
        assessments=_assessments(analysis=analysis_claims, reply=reply_claims),
    )

    assert result.decision == "pass"


def test_current_turn_temporary_fact_is_auditable_support() -> None:
    current_report = ref("temporary_fact", 43)
    evidence_pack = pack(
        supporting=(),
        temporary_fact_refs=(current_report,),
        c1_status="unavailable",
        effective_status="none",
    )
    claim = _claim(evidence_ids=(current_report.object_id,))

    result = EvidenceAuditor().audit(
        evidence_pack=evidence_pack,
        analysis_claims=(claim,),
        reply_claims=(claim,),
        assessments=_assessments(analysis=(claim,), reply=(claim,)),
    )

    assert result.decision == "pass"
    assert result.findings == ()


def test_assessment_pairs_must_have_no_missing_or_extra_entries() -> None:
    evidence_pack = pack()
    claim = _claim(evidence_ids=(evidence_pack.supporting[0].evidence_id,))
    valid = _assessments(analysis=(claim,))

    with pytest.raises(ValueError, match="ASSESSMENT_PAIR_MISMATCH"):
        EvidenceAuditor().audit(
            evidence_pack=evidence_pack,
            analysis_claims=(claim,),
            reply_claims=(),
            assessments=(),
        )
    with pytest.raises(ValueError, match="ASSESSMENT_PAIR_MISMATCH"):
        EvidenceAuditor().audit(
            evidence_pack=evidence_pack,
            analysis_claims=(claim,),
            reply_claims=(),
            assessments=(
                *valid,
                valid[0].model_copy(update={"claim_scope": "reply"}),
            ),
        )


def test_assessment_contract_closes_hash_and_canonical_order() -> None:
    evidence_pack = pack()
    claim = _claim(evidence_ids=(evidence_pack.supporting[0].evidence_id,))
    assessments = _assessments(analysis=(claim,), reply=(claim,))

    with pytest.raises(ValidationError, match="excerpt hash mismatch"):
        assessments[0].model_copy(update={"excerpt_sha256": "0" * 64})
    with pytest.raises(ValidationError, match="unique and canonical"):
        EvidenceAudit(
            envelope=envelope("evidence_audit"),
            evidence_pack_sha256=canonical_sha256(
                evidence_pack.model_dump(mode="json")
            ),
            assessments=tuple(reversed(assessments)),
            findings=(),
            decision="pass",
            rationale_summary="The assessment order is intentionally forged.",
        )


def test_unicode_source_span_closes_against_frozen_body() -> None:
    body = "甲🙂乙"
    evidence_pack = pack()
    candidate = evidence_pack.supporting[0]
    candidate = candidate.model_copy(
        update={
            "text_ref": candidate.text_ref.model_copy(
                update={"content_sha256": text_sha256(body)}
            )
        }
    )
    evidence_pack = evidence_pack.model_copy(update={"supporting": (candidate,)})
    context = (
        GenerationEvidenceContextItem(
            evidence_id=candidate.evidence_id,
            context_kind="retrieved_candidate",
            text_ref=candidate.text_ref,
            body=body,
        ),
    )
    assessment = EvidenceSemanticAssessment(
        claim_scope="analysis",
        claim_id="unicode_claim",
        assessed_claim_type="fact",
        evidence_id=candidate.evidence_id,
        role="support",
        text_start_char=1,
        text_end_char=3,
        exact_excerpt="🙂乙",
        excerpt_sha256=text_sha256("🙂乙"),
        semantic_status="supports",
    )

    EvidenceAuditor.require_exact_source_spans(
        evidence_pack=evidence_pack,
        evidence_context=context,
        assessments=(assessment,),
    )
    forged = assessment.model_copy(
        update={"text_start_char": 0, "text_end_char": 2}
    )
    with pytest.raises(ValueError, match="ASSESSMENT_SOURCE_MISMATCH"):
        EvidenceAuditor.require_exact_source_spans(
            evidence_pack=evidence_pack,
            evidence_context=context,
            assessments=(forged,),
        )


def test_submitted_audit_decision_fields_must_equal_deterministic_recomputation() -> None:
    evidence_pack, evidence_context = _pack_with_context()
    evidence_id = evidence_pack.supporting[0].evidence_id
    conceptualization = _artifact(evidence_pack, _valid_items(evidence_id))
    replies = _drafts(evidence_pack)
    auditor = EvidenceAuditor()
    result = auditor.audit_artifacts(
        evidence_pack=evidence_pack,
        conceptualization=conceptualization,
        reply_drafts=replies,
        assessments=_assessments(
            analysis=tuple(
                AuditableClaim.from_conceptualization_item(item)
                for item in conceptualization.items
            ),
            reply=tuple(
                claim
                for candidate in replies.candidates
                for claim in candidate.claims
            ),
        ),
    )
    submitted = EvidenceAudit(
        envelope=envelope("evidence_audit"),
        evidence_pack_sha256=canonical_sha256(
            evidence_pack.model_dump(mode="json")
        ),
        assessments=_assessments(
            analysis=tuple(
                AuditableClaim.from_conceptualization_item(item)
                for item in conceptualization.items
            ),
            reply=tuple(
                claim
                for candidate in replies.candidates
                for claim in candidate.claims
            ),
        ),
        findings=tuple(
            auditor._contract_finding(item) for item in result.findings
        ),
        decision=result.decision,
        retry_count=result.retry_count,
        unresolved_reasons=result.unresolved_reasons,
        rationale_summary="Deterministic fields were copied without alteration.",
    )

    auditor.require_valid_artifact(
        submitted,
        evidence_pack=evidence_pack,
        evidence_context=evidence_context,
        conceptualization=conceptualization,
        reply_drafts=replies,
    )
    forged = submitted.model_copy(
        update={
            "findings": (
                AuditFinding(
                    claim_id="invented_finding",
                    evidence_ids=(evidence_id,),
                    fidelity="faithful",
                    severity="info",
                ),
            )
        }
    )
    with pytest.raises(ValueError, match="RECOMPUTATION_MISMATCH"):
        auditor.require_valid_artifact(
            forged,
            evidence_pack=evidence_pack,
            evidence_context=evidence_context,
            conceptualization=conceptualization,
            reply_drafts=replies,
        )


def test_conflicting_copies_of_same_claim_id_fail_closed() -> None:
    evidence_pack = pack()
    evidence_id = evidence_pack.supporting[0].evidence_id
    left = _claim(evidence_ids=(evidence_id,))
    right = left.model_copy(update={"statement": "同一 ID 却是另一个结论。"})

    with pytest.raises(ValueError, match="copies must be identical"):
        EvidenceAuditor().audit(
            evidence_pack=evidence_pack,
            analysis_claims=(),
            reply_claims=(left, right),
            assessments=_assessments(reply=(left,)),
        )


def test_nonexistent_evidence_requests_retrieval() -> None:
    evidence_pack = pack()
    claim = _claim(evidence_ids=(object_id("evidence", 99),))

    result = EvidenceAuditor().audit(
        evidence_pack=evidence_pack,
        analysis_claims=(),
        reply_claims=(claim,),
        assessments=_assessments(reply=(claim,)),
    )

    assert result.decision == "retrieve_more"
    assert result.unresolved_reasons == ("insufficient_evidence",)
    assert {item.code for item in result.findings} == {"unknown_evidence"}


def test_stale_or_tombstoned_reference_is_blocking() -> None:
    stale = candidate(1, freshness="stale")
    evidence_pack = pack(supporting=(stale,))
    claim = _claim(evidence_ids=(stale.evidence_id,))

    stale_result = EvidenceAuditor().audit(
        evidence_pack=evidence_pack,
        analysis_claims=(),
        reply_claims=(claim,),
        assessments=_assessments(reply=(claim,)),
    )
    current_pack = pack()
    current_claim = _claim(
        evidence_ids=(current_pack.supporting[0].evidence_id,)
    )
    tombstone_result = EvidenceAuditor().audit(
        evidence_pack=current_pack,
        analysis_claims=(),
        reply_claims=(current_claim,),
        assessments=_assessments(reply=(current_claim,)),
        tombstoned_evidence_ids=(current_pack.supporting[0].evidence_id,),
    )

    assert stale_result.findings[0].code == "stale_or_tombstoned_evidence"
    assert tombstone_result.findings[0].code == "stale_or_tombstoned_evidence"


def test_counterevidence_must_be_explicitly_associated() -> None:
    counter_id = object_id("evidence", 2)
    support = candidate(1, contradicts=(counter_id,))
    counter = candidate(2)
    evidence_pack = pack(supporting=(support,), contradicting=(counter,))
    omitted = _claim(evidence_ids=(support.evidence_id,))
    covered = _claim(
        evidence_ids=(support.evidence_id,),
        contradicting=(counter.evidence_id,),
    )

    rejected = EvidenceAuditor().audit(
        evidence_pack=evidence_pack,
        analysis_claims=(),
        reply_claims=(omitted,),
        assessments=_assessments(reply=(omitted,)),
    )
    accepted = EvidenceAuditor().audit(
        evidence_pack=evidence_pack,
        analysis_claims=(),
        reply_claims=(covered,),
        assessments=_assessments(reply=(covered,)),
    )

    assert rejected.decision == "rewrite"
    assert "counterevidence_omitted" in {item.code for item in rejected.findings}
    assert accepted.decision == "pass"


def test_hypothesis_cannot_be_promoted_to_fact_under_same_claim_id() -> None:
    evidence_pack = pack()
    evidence_id = evidence_pack.supporting[0].evidence_id
    hypothesis = _claim(
        claim_id="partner_intent",
        claim_type="hypothesis",
        evidence_ids=(evidence_id,),
        fidelity="interpretation",
    )
    promoted = _claim(
        claim_id="partner_intent",
        claim_type="fact",
        evidence_ids=(evidence_id,),
        fidelity="faithful",
    )

    result = EvidenceAuditor().audit(
        evidence_pack=evidence_pack,
        analysis_claims=(hypothesis,),
        reply_claims=(promoted,),
        assessments=_assessments(
            analysis=(hypothesis,),
            reply=(promoted,),
        ),
    )

    assert result.decision == "rewrite"
    assert "hypothesis_promoted_to_fact" in {
        item.code for item in result.findings
    }


def test_self_reported_fidelity_and_semantic_assessment_are_both_required() -> None:
    evidence_pack = pack()
    interpretation = _claim(
        claim_type="fact",
        evidence_ids=(evidence_pack.supporting[0].evidence_id,),
        fidelity="interpretation",
    )
    faithful = interpretation.model_copy(update={"evidence_fidelity": "faithful"})
    pair = ("analysis", faithful.claim_id, faithful.evidence_ids[0], "support")
    self_report_failure = EvidenceAuditor().audit(
        evidence_pack=evidence_pack,
        analysis_claims=(interpretation,),
        reply_claims=(),
        assessments=_assessments(analysis=(interpretation,)),
    )
    semantic_failure = EvidenceAuditor().audit(
        evidence_pack=evidence_pack,
        analysis_claims=(faithful,),
        reply_claims=(),
        assessments=_assessments(
            analysis=(faithful,),
            status_by_pair={pair: "irrelevant"},
        ),
    )

    assert self_report_failure.decision == "rewrite"
    assert self_report_failure.findings[0].code == "unfaithful_paraphrase"
    assert semantic_failure.decision == "rewrite"
    assert semantic_failure.findings[0].code == "semantic_evidence_unfaithful"


def test_independent_assessed_claim_type_blocks_suggestion_mislabeled_as_fact() -> None:
    evidence_pack = pack()
    mislabeled = _claim(
        claim_type="important_conclusion",
        evidence_ids=(evidence_pack.supporting[0].evidence_id,),
    )
    independent_assessments = tuple(
        item.model_copy(update={"assessed_claim_type": "suggestion"})
        for item in _assessments(reply=(mislabeled,))
    )

    auditor = EvidenceAuditor()
    result = auditor.audit(
        evidence_pack=evidence_pack,
        analysis_claims=(),
        reply_claims=(mislabeled,),
        assessments=independent_assessments,
    )

    assert result.decision == "rewrite"
    assert result.unresolved_reasons == ("unresolved_conflict",)
    assert "semantic_claim_type_mismatch" in {
        finding.code for finding in result.findings
    }
    EvidenceAudit(
        envelope=envelope("evidence_audit"),
        evidence_pack_sha256=canonical_sha256(
            evidence_pack.model_dump(mode="json")
        ),
        assessments=independent_assessments,
        findings=tuple(auditor._contract_finding(item) for item in result.findings),
        decision=result.decision,
        retry_count=result.retry_count,
        unresolved_reasons=result.unresolved_reasons,
        rationale_summary="The independent critic classified the claim as advice.",
    )


def test_unsupported_important_claim_is_rejected_at_contract_boundary() -> None:
    with pytest.raises(ValidationError):
        _claim(evidence_ids=())


def test_retry_is_bounded_to_two_then_requires_counselor_judgment() -> None:
    evidence_pack = pack()
    unknown = _claim(evidence_ids=(object_id("evidence", 99),))

    exhausted = EvidenceAuditor().audit(
        evidence_pack=evidence_pack,
        analysis_claims=(),
        reply_claims=(unknown,),
        assessments=_assessments(reply=(unknown,)),
        retry_count=2,
    )

    assert exhausted.decision == "needs_counselor_judgment"
    assert set(exhausted.unresolved_reasons) == {
        "insufficient_evidence",
        "needs_counselor_judgment",
    }
    with pytest.raises(ValueError, match="between zero and two"):
        EvidenceAuditor().audit(
            evidence_pack=evidence_pack,
            analysis_claims=(),
            reply_claims=(unknown,),
            assessments=_assessments(reply=(unknown,)),
            retry_count=3,
        )
