from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import cast

import pytest
from pydantic import ValidationError

from consultation_kb.generation.contracts import (
    AuditFinding,
    ClientReplyCandidate,
    Conceptualization,
    ConceptualizationItem,
    ConsistencyRiskReview,
    CounselorInternalAnalysis,
    EvidenceAudit,
    EvidenceQualitySummary,
    FinalTurnBundle,
    FollowUpGuidance,
    QueryGuardrails,
    QueryPlan,
    ReplyClaim,
    ReplyDraft,
    ReplyDraftSet,
    RouteOmission,
    Subquery,
    TheoryComparison,
    validate_generation_payload,
)
from consultation_kb.generation.stage_store import generation_payload_sha256
from consultation_kb.knowledge._canonical import text_sha256
from consultation_kb.generation.state_machine import (
    GenerationParentMismatch,
    GenerationStageOrderError,
    GenerationStateMachine,
    QualityRetryExhausted,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.consistency import (
    ActionDirection,
    ConsistencySnapshot,
    CorePosition,
    FactPosition,
)
from consultation_kb.models.generation import GenerationStageEnvelope, GenerationStageName
from tests.consultation_kb.unit.p6_quality_support import (
    current_consistency_assessments,
)


TURN_ID = "018f0000-0000-7000-8000-000000000011"
RUN_ID = "018f0000-0000-7000-8000-000000000012"
EVIDENCE_ID = "evidence_018f0000-0000-7000-8000-000000000013"
PACK_HASH = "f" * 64
NOW = datetime(2026, 7, 19, 7, 0, tzinfo=timezone.utc)


def _envelope(stage: str, *parents: str) -> GenerationStageEnvelope:
    return GenerationStageEnvelope(
        stage=cast(GenerationStageName, stage),
        turn_id=TURN_ID,
        run_id=RUN_ID,
        parent_sha256s=tuple(sorted(parents)),
        created_at=NOW,
    )


def _query() -> QueryPlan:
    return QueryPlan(
        envelope=_envelope("query_plan"),
        intent="simple_empathic_clarification",
        client_snapshot_ref=VersionRef(
            object_id="client_snapshot_018f0000-0000-7000-8000-000000000014",
            version=1,
            content_sha256="a" * 64,
        ),
        global_runtime_epoch=1,
        client_runtime_epoch=2,
        tombstone_epoch=3,
        authorization_epoch=4,
        guardrails=QueryGuardrails(),
        subqueries=(
            Subquery(
                subquery_id="emotion",
                category="emotion_needs_relationship",
                question="What feeling should be clarified?",
                routes=("profile",),
                required_evidence_types=(),
                scope="client_private",
            ),
        ),
        route_omissions=tuple(
            RouteOmission(route=route, reason="not needed for this clarification")
            for route in (
                "client_history",
                "wiki",
                "lexical",
                "vector",
                "global_graph",
                "case",
            )
        ),
        rationale_summary="Start with the smallest sufficient private context.",
    )


def _conceptualization(previous_hash: str) -> Conceptualization:
    return Conceptualization(
        envelope=_envelope("conceptualization", previous_hash, PACK_HASH),
        evidence_pack_sha256=PACK_HASH,
        items=(
            ConceptualizationItem(
                item_id="reported_need",
                cognitive_type="client_reported",
                statement="The client reports needing clarity.",
                supporting_evidence_ids=(EVIDENCE_ID,),
                uncertainty="low",
            ),
            ConceptualizationItem(
                item_id="clarify_first",
                cognitive_type="suggestion",
                statement="Clarify the immediate need before choosing an action.",
                supporting_evidence_ids=(EVIDENCE_ID,),
                supporting_item_ids=("reported_need",),
                uncertainty="medium",
            ),
        ),
        key_emotions=("uncertainty",),
        key_needs=("clarity",),
        alternative_explanations=("The uncertainty may concern timing rather than direction.",),
        limitations=("Only one current report is available.",),
        rationale_summary="Separate the report from the tentative interpretation.",
    )


def _theory(previous_hash: str) -> TheoryComparison:
    return TheoryComparison(
        envelope=_envelope("theory_comparison", previous_hash, PACK_HASH),
        evidence_pack_sha256=PACK_HASH,
        primary_framework=None,
        comparisons=(),
        conflicts=(),
        clarification_questions=("What outcome matters most right now?",),
        rationale_summary="No theory is needed before the goal is clarified.",
    )


def _reply(previous_hash: str) -> ReplyDraftSet:
    return ReplyDraftSet(
        envelope=_envelope("reply_drafts", previous_hash, PACK_HASH),
        evidence_pack_sha256=PACK_HASH,
        candidates=tuple(
            ReplyDraft(
                candidate_id=candidate_id,
                strategy=strategy,
                text=text,
                core_positions=("clarify_before_deciding",),
                current_fact_ids=("reported_need",),
                action_directions=("ask_one_clarifying_question",),
                evidence_ids=(EVIDENCE_ID,),
                claims=(
                    ReplyClaim(
                        claim_id=f"{candidate_id}_body",
                        claim_type="important_conclusion",
                        statement=text,
                        evidence_ids=(EVIDENCE_ID,),
                        evidence_fidelity="interpretation",
                        text_start_char=0,
                        text_end_char=len(text),
                        text_sha256=text_sha256(text),
                    ),
                ),
            )
            for candidate_id, strategy, text in (
                ("gentle", "gentle_empathy", "We can first slow down and name what feels hardest."),
                ("direct", "direct_clarification", "Which single question needs an answer first?"),
            )
        ),
        shared_core_positions=("clarify_before_deciding",),
        shared_action_directions=("ask_one_clarifying_question",),
        rationale_summary="Keep the conclusion stable while varying the tone.",
    )


def _audit(previous_hash: str) -> EvidenceAudit:
    return EvidenceAudit(
        envelope=_envelope("evidence_audit", previous_hash, PACK_HASH),
        evidence_pack_sha256=PACK_HASH,
        assessments=(),
        findings=(
            AuditFinding(
                claim_id="need_clarity",
                evidence_ids=(EVIDENCE_ID,),
                fidelity="faithful",
                severity="info",
            ),
        ),
        decision="pass",
        rationale_summary="All important claims resolve to the frozen pack.",
    )


def _review(previous_hash: str) -> ConsistencyRiskReview:
    replies = _reply("d" * 64)
    snapshots = tuple(
        ConsistencySnapshot(
            snapshot_key=item.candidate_id,
            source="current_candidate",
            facts=tuple(
                FactPosition(
                    fact_key=fact_id,
                    state="affirmed",
                    evidence_ids=item.evidence_ids,
                )
                for fact_id in item.current_fact_ids
            ),
            core_positions=tuple(
                CorePosition(position_key=key, stance="support")
                for key in item.core_positions
            ),
            action_directions=tuple(
                ActionDirection(action_key=key, disposition="pursue")
                for key in item.action_directions
            ),
            conclusion=item.text,
            conclusion_evidence_ids=item.evidence_ids,
        )
        for item in replies.candidates
    )
    return ConsistencyRiskReview(
        envelope=_envelope("consistency_risk_review", previous_hash, PACK_HASH),
        evidence_pack_sha256=PACK_HASH,
        current_candidate_snapshots=snapshots,
        semantic_assessments=current_consistency_assessments(replies, snapshots),
        consistency_findings=(),
        risk_observation_ids=(),
        decision="pass",
        rationale_summary="The candidates preserve the same conclusion and action direction.",
    )


def _final(previous_hash: str) -> FinalTurnBundle:
    candidates = tuple(
        ClientReplyCandidate(
            candidate_id=item.candidate_id,
            label=item.candidate_id,
            strategy=item.strategy,
            text=item.text,
            core_positions=item.core_positions,
            action_directions=item.action_directions,
        )
        for item in _reply("d" * 64).candidates
    )
    return FinalTurnBundle(
        envelope=_envelope("final_bundle", previous_hash, PACK_HASH),
        evidence_pack_sha256=PACK_HASH,
        counselor_internal=CounselorInternalAnalysis(
            summary="Clarify the client's immediate need before choosing a direction.",
            key_fact_ids=("reported_need",),
            hypotheses=("The uncertainty may concern timing.",),
            conflicts=(),
            uncertainty=("The desired outcome remains unclear.",),
            evidence_ids=(EVIDENCE_ID,),
        ),
        client_reply_candidates=candidates,
        follow_up_guidance=FollowUpGuidance(
            suggested_questions=("Which answer would help most today?",),
            optional_actions=("Write down the one decision that feels most urgent.",),
            observation_focus=("Notice whether urgency changes after clarification.",),
            next_steps=("Choose one question to explore next.",),
        ),
        evidence_quality=EvidenceQualitySummary(
            status="sufficient",
            evidence_ids=(EVIDENCE_ID,),
            unresolved_reasons=(),
        ),
    )


def _all_stages() -> tuple[object, ...]:
    query = _query()
    query_hash = generation_payload_sha256(query)
    conceptualization = _conceptualization(query_hash)
    theory = _theory(generation_payload_sha256(conceptualization))
    reply = _reply(generation_payload_sha256(theory))
    audit = _audit(generation_payload_sha256(reply))
    review = _review(generation_payload_sha256(audit))
    final = _final(generation_payload_sha256(review))
    return query, conceptualization, theory, reply, audit, review, final


def test_all_seven_stage_payloads_form_one_strict_tagged_union() -> None:
    payloads = _all_stages()

    assert tuple(validate_generation_payload(item).envelope.stage for item in payloads) == (
        "query_plan",
        "conceptualization",
        "theory_comparison",
        "reply_drafts",
        "evidence_audit",
        "consistency_risk_review",
        "final_bundle",
    )


@pytest.mark.parametrize("forbidden", ["reasoning", "chain_of_thought", "scratchpad"])
def test_contracts_reject_hidden_reasoning_fields(forbidden: str) -> None:
    payload = _query().model_dump(mode="json")
    payload[forbidden] = "private free-form reasoning"

    with pytest.raises(ValidationError):
        validate_generation_payload(payload)

    nested = _conceptualization("a" * 64).model_dump(mode="json")
    nested["items"][0][forbidden] = "hidden"
    with pytest.raises(ValidationError):
        validate_generation_payload(nested)


def test_rationale_summary_is_bounded_and_parent_alias_is_forbidden() -> None:
    payload = _query().model_dump(mode="json")
    payload["rationale_summary"] = "x" * 801
    with pytest.raises(ValidationError):
        QueryPlan.model_validate(payload)

    envelope = _envelope("query_plan").model_dump(mode="json")
    envelope["parent_hashes"] = envelope.pop("parent_sha256s")
    with pytest.raises(ValidationError):
        GenerationStageEnvelope.model_validate(envelope)
    assert "parent_hashes" not in json.dumps(GenerationStageEnvelope.model_json_schema())


def test_generation_stages_require_order_and_evidence_pack_parent_hash() -> None:
    query = _query()
    reply = _reply("b" * 64)
    with pytest.raises(GenerationStageOrderError):
        GenerationStateMachine.validate_next({}, reply)

    query_hash = generation_payload_sha256(query)
    GenerationStateMachine.validate_next({}, query)
    wrong = _conceptualization("0" * 64)
    with pytest.raises(GenerationParentMismatch):
        GenerationStateMachine.validate_next({"query_plan": query_hash}, wrong)

    correct = _conceptualization(query_hash)
    transition = GenerationStateMachine.validate_next(
        {"query_plan": query_hash}, correct
    )
    assert transition.required_parent_sha256s == tuple(sorted((query_hash, PACK_HASH)))


def test_third_quality_retry_fails_closed() -> None:
    audit = EvidenceAudit(
        envelope=_envelope("evidence_audit", "d" * 64, PACK_HASH),
        evidence_pack_sha256=PACK_HASH,
        assessments=(),
        findings=(
            AuditFinding(
                claim_id="unsupported_claim",
                evidence_ids=(),
                fidelity="unsupported",
                severity="blocking",
                correction="Retrieve support or rewrite as uncertainty.",
            ),
        ),
        decision="rewrite",
        retry_count=2,
        unresolved_reasons=("The important conclusion remains unsupported.",),
        rationale_summary="Two correction attempts did not resolve the evidence gap.",
    )

    with pytest.raises(QualityRetryExhausted, match="QUALITY_RETRY_EXHAUSTED"):
        GenerationStateMachine.validate_next(
            {
                "query_plan": "a" * 64,
                "conceptualization": "b" * 64,
                "theory_comparison": "c" * 64,
                "reply_drafts": "d" * 64,
            },
            audit,
        )


def test_client_reply_candidate_physically_rejects_internal_risk_objects() -> None:
    payload = _final("e" * 64).client_reply_candidates[0].model_dump(mode="json")
    payload["risk_observations"] = []
    payload["category"] = "self_harm"

    with pytest.raises(ValidationError):
        ClientReplyCandidate.model_validate(payload)
