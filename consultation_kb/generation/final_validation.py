"""Deterministic closure checks for the final generation projection."""

from __future__ import annotations

from consultation_kb.generation.contracts import (
    Conceptualization,
    ConsistencyRiskReview,
    EvidenceAudit,
    FinalTurnBundle,
    ReplyDraftSet,
    TheoryComparison,
)
from consultation_kb.generation.evidence_scope import bound_evidence_ids
from consultation_kb.models.evidence import EvidencePack
from consultation_kb.risk.output_guard import ClientReplyOutputGuard
from consultation_kb.risk.repository import InternalRiskObservationRecord


class FinalBundleValidationError(ValueError):
    """The final bundle is not an exact projection of reviewed artifacts."""


def _deduplicated(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


class FinalBundleValidator:
    """Reject free-form final fields that diverge from reviewed stage state."""

    def require_valid(
        self,
        value: FinalTurnBundle,
        *,
        conceptualization: Conceptualization,
        theory: TheoryComparison,
        replies: ReplyDraftSet,
        evidence_audit: EvidenceAudit,
        consistency: ConsistencyRiskReview,
        evidence_pack: EvidencePack,
        visible_risk: tuple[InternalRiskObservationRecord, ...],
    ) -> FinalTurnBundle:
        final = FinalTurnBundle.model_validate(value, strict=True)
        concept = Conceptualization.model_validate(conceptualization, strict=True)
        theory_value = TheoryComparison.model_validate(theory, strict=True)
        reply_value = ReplyDraftSet.model_validate(replies, strict=True)
        audit = EvidenceAudit.model_validate(evidence_audit, strict=True)
        review = ConsistencyRiskReview.model_validate(consistency, strict=True)
        pack = EvidencePack.model_validate(evidence_pack, strict=True)

        reply_by_id = {item.candidate_id: item for item in reply_value.candidates}
        if not 2 <= len(final.client_reply_candidates) <= 3:
            raise FinalBundleValidationError("FINAL_REPLY_COUNT_MISMATCH")
        for candidate in final.client_reply_candidates:
            draft = reply_by_id.get(candidate.candidate_id)
            if draft is None or (
                candidate.strategy != draft.strategy
                or candidate.text != draft.text
                or candidate.core_positions != draft.core_positions
                or candidate.action_directions != draft.action_directions
            ):
                raise FinalBundleValidationError("FINAL_REPLY_PROJECTION_MISMATCH")

        if audit.decision in {"retrieve_more", "rewrite"} or review.decision in {
            "retrieve_more",
            "rewrite",
        }:
            raise FinalBundleValidationError("FINAL_REVIEW_NOT_READY")

        fact_ids = tuple(
            sorted(
                item.item_id
                for item in concept.items
                if item.cognitive_type
                in {"client_fact", "client_reported", "counselor_observation"}
            )
        )
        hypotheses = tuple(
            item.statement
            for item in concept.items
            if item.cognitive_type in {"hypothesis", "counselor_observation"}
        )
        conflicts = _deduplicated(
            theory_value.conflicts
            + tuple(
                finding.description
                for finding in review.consistency_findings
                if finding.severity != "allowed"
            )
        )
        uncertainty = _deduplicated(
            concept.limitations
            + tuple(
                item.clarification_question
                for item in concept.items
                if item.clarification_question is not None
            )
            + theory_value.clarification_questions
        )
        used_evidence = _deduplicated(
            tuple(
                evidence_id
                for item in concept.items
                for evidence_id in (
                    item.supporting_evidence_ids + item.contradicting_evidence_ids
                )
            )
            + tuple(
                evidence_id
                for selection in (
                    (() if theory_value.primary_framework is None else (theory_value.primary_framework,))
                    + theory_value.comparisons
                )
                for evidence_id in selection.evidence_ids
            )
            + tuple(
                evidence_id
                for candidate in reply_value.candidates
                for claim in candidate.claims
                for evidence_id in (
                    claim.evidence_ids + claim.contradicting_evidence_ids
                )
            )
        )
        internal = final.counselor_internal
        if (
            internal.summary != concept.rationale_summary
            or internal.key_fact_ids != fact_ids
            or internal.hypotheses != hypotheses
            or internal.conflicts != conflicts
            or internal.uncertainty != uncertainty
            or internal.evidence_ids != used_evidence
        ):
            raise FinalBundleValidationError("FINAL_INTERNAL_PROJECTION_MISMATCH")

        expected_risk = {
            item.observation.observation_id: item.observation for item in visible_risk
        }
        actual_risk = {
            item.observation_id: item for item in internal.risk_observations
        }
        if expected_risk != actual_risk:
            raise FinalBundleValidationError("FINAL_RISK_PROJECTION_MISMATCH")

        unresolved = _deduplicated(
            audit.unresolved_reasons + review.unresolved_reasons
        )
        needs_judgment = (
            audit.decision == "needs_counselor_judgment"
            or review.decision == "needs_counselor_judgment"
        )
        has_conflict = bool(pack.unresolved_conflict_refs) or any(
            finding.fidelity == "conflicted" for finding in audit.findings
        ) or any(
            finding.severity in {"warning", "blocking"}
            for finding in review.consistency_findings
        )
        has_support = bool(pack.supporting or pack.temporary_fact_refs)
        if needs_judgment:
            expected_status = "needs_counselor_judgment"
            if not unresolved:
                unresolved = ("needs_counselor_judgment",)
        elif has_conflict:
            expected_status = "conflicted"
            if not unresolved:
                unresolved = ("evidence_conflict_present",)
        elif not has_support:
            expected_status = "limited"
            if not unresolved:
                unresolved = ("supporting_evidence_limited",)
        else:
            expected_status = "sufficient"

        quality = final.evidence_quality
        if (
            quality.status != expected_status
            or quality.evidence_ids != tuple(sorted(bound_evidence_ids(pack)))
            or quality.unresolved_reasons != unresolved
            or quality.retry_count != max(audit.retry_count, review.retry_count)
        ):
            raise FinalBundleValidationError("FINAL_EVIDENCE_QUALITY_MISMATCH")

        canaries = tuple(
            dict.fromkeys(
                canary
                for item in visible_risk
                for canary in (
                    item.observation.observation_id,
                    item.observation.category,
                    item.observation.rule_ref.object_id,
                    item.observation.rule_ref.content_sha256,
                    *item.observation.suggested_questions,
                    *(
                        value
                        for source in item.sources
                        for value in (
                            source.source_kind,
                            source.source_ref.object_id,
                            source.source_ref.content_sha256,
                        )
                    ),
                    *(
                        value
                        for span in item.trigger_spans
                        for value in (
                            span.turn_id,
                            span.content_ref.object_id,
                            span.content_ref.content_sha256,
                            span.span_sha256,
                            span.normalized_span_sha256,
                        )
                    ),
                )
            )
        )
        levels = tuple(sorted({item.observation.level for item in visible_risk}))
        trigger_fingerprints = tuple(
            sorted(
                {
                    (span.normalized_length, span.normalized_span_sha256)
                    for item in visible_risk
                    for span in item.trigger_spans
                }
            )
        )
        ClientReplyOutputGuard(
            internal_canaries=canaries,
            internal_levels=levels,
            internal_span_fingerprints=trigger_fingerprints,
        ).validate_many(final.client_reply_candidates)
        return final


__all__ = ["FinalBundleValidationError", "FinalBundleValidator"]
