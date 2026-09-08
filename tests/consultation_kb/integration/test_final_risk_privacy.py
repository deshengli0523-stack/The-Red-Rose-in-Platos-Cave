from __future__ import annotations

import hashlib

import pytest

from consultation_kb.generation.contracts import EvidenceAudit, ReplyDraftSet
from consultation_kb.generation.evidence_scope import bound_evidence_ids
from consultation_kb.generation.final_validation import FinalBundleValidator
from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.risk import InternalRiskObservation
from consultation_kb.risk.output_guard import ClientReplyLeakageError
from consultation_kb.risk.repository import (
    InternalRiskObservationRecord,
    RiskObservationSource,
    RiskTriggerSpan,
)
from consultation_kb.risk.text_normalization import normalized_sensitive_fingerprint
from tests.consultation_kb.integration.test_generation_pipeline import (
    _conceptualization,
    _consistency_review,
    _envelope,
    _final_bundle,
    _reply_drafts,
    _theory_comparison,
)
from tests.consultation_kb.unit.p6_quality_support import (
    NOW,
    object_id,
    pack,
    ref,
    sha,
    uuid7,
)


_TRIGGER = "I want to kill myself"
_INTERNAL_QUESTION = "Confirm current intent, plan, means, and timeframe."
_TRIGGER_SHA256 = hashlib.sha256(_TRIGGER.encode("utf-8")).hexdigest()
_BOUND_TURN_ID = uuid7(9_500)


def _replace_first_reply_text(replies: ReplyDraftSet, text: str) -> ReplyDraftSet:
    original = replies.candidates[0]
    claim = original.claims[0].model_copy(
        update={
            "statement": text,
            "text_start_char": 0,
            "text_end_char": len(text),
            "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        }
    )
    replacement = original.model_copy(update={"text": text, "claims": (claim,)})
    return replies.model_copy(
        update={"candidates": (replacement, *replies.candidates[1:])}
    )


@pytest.mark.integration
@pytest.mark.parametrize(
    ("leaking_text", "expected_code"),
    [
        ("suicide_intent", "CLIENT_REPLY_INTERNAL_CANARY"),
        ("suicide-intent", "CLIENT_REPLY_INTERNAL_CANARY"),
        ("suicide intent", "CLIENT_REPLY_INTERNAL_CANARY"),
        ("suicide/intent", "CLIENT_REPLY_INTERNAL_CANARY"),
        (_TRIGGER, "CLIENT_REPLY_TRIGGER_QUOTE"),
        (_TRIGGER.upper(), "CLIENT_REPLY_TRIGGER_QUOTE"),
        ("Ｉ　ｗａｎｔ　ｔｏ　ｋｉｌｌ　ｍｙｓｅｌｆ", "CLIENT_REPLY_TRIGGER_QUOTE"),
        ("I\u200b want to kill myself", "CLIENT_REPLY_TRIGGER_QUOTE"),
        (_INTERNAL_QUESTION, "CLIENT_REPLY_INTERNAL_CANARY"),
        (
            "Confirm/current:intent.plan/means:and timeframe",
            "CLIENT_REPLY_INTERNAL_CANARY",
        ),
        ("deterministic/rule", "CLIENT_REPLY_INTERNAL_CANARY"),
        (_BOUND_TURN_ID.replace("-", ":"), "CLIENT_REPLY_INTERNAL_CANARY"),
        (
            "-".join(
                _TRIGGER_SHA256[index : index + 8]
                for index in range(0, len(_TRIGGER_SHA256), 8)
            ),
            "CLIENT_REPLY_INTERNAL_CANARY",
        ),
        ("Ordinary values 0 and 21 remain safe to mention.", None),
    ],
)
def test_nonempty_risk_final_bundle_enforces_private_values_without_numeric_canaries(
    leaking_text: str,
    expected_code: str | None,
) -> None:
    evidence_pack = pack()
    pack_sha256 = canonical_sha256(evidence_pack.model_dump(mode="json"))
    evidence_id = evidence_pack.supporting[0].evidence_id
    turn_id = _BOUND_TURN_ID
    run_id = uuid7(9_501)

    concept = _conceptualization(
        turn_id=turn_id,
        run_id=run_id,
        parent_sha256s=(sha(9_510),),
        evidence_pack_sha256=pack_sha256,
        evidence_id=evidence_id,
    )
    theory = _theory_comparison(
        turn_id=turn_id,
        run_id=run_id,
        parent_sha256s=(sha(9_511),),
        evidence_pack_sha256=pack_sha256,
        evidence_id=evidence_id,
        pack=evidence_pack,
    )
    replies = _replace_first_reply_text(
        _reply_drafts(
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=(sha(9_512),),
            evidence_pack_sha256=pack_sha256,
            evidence_id=evidence_id,
        ),
        leaking_text,
    )
    audit = EvidenceAudit(
        envelope=_envelope(
            "evidence_audit",
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=(sha(9_513),),
        ),
        evidence_pack_sha256=pack_sha256,
        assessments=(),
        findings=(),
        decision="pass",
        retry_count=0,
        unresolved_reasons=(),
        rationale_summary="Synthetic final privacy boundary audit fixture.",
    )

    rule_ref = ref("risk_rule", 9_520)
    observation = InternalRiskObservation(
        observation_id=object_id("risk_observation", 9_520),
        category="suicide_intent",
        level="high",
        trigger_turn_ids=(turn_id,),
        rule_ref=rule_ref,
        detected_at=NOW,
        suggested_questions=(_INTERNAL_QUESTION,),
    )
    normalized_length, normalized_span_sha256 = normalized_sensitive_fingerprint(
        _TRIGGER
    )
    visible_risk = (
        InternalRiskObservationRecord(
            session_id=uuid7(9_530),
            observation=observation,
            trigger_spans=(
                RiskTriggerSpan(
                    turn_id=turn_id,
                    content_ref=ref("client_message", 9_521),
                    start_offset=0,
                    end_offset=len(_TRIGGER),
                    span_sha256=_TRIGGER_SHA256,
                    normalized_length=normalized_length,
                    normalized_span_sha256=normalized_span_sha256,
                ),
            ),
            sources=(
                RiskObservationSource(
                    source_kind="deterministic_rule",
                    source_ref=rule_ref,
                ),
            ),
            confidence=1.0,
        ),
    )
    consistency = _consistency_review(
        turn_id=turn_id,
        run_id=run_id,
        parent_sha256s=(sha(9_514),),
        evidence_pack_sha256=pack_sha256,
        evidence_id=evidence_id,
        replies=replies,
    ).model_copy(update={"risk_observation_ids": (observation.observation_id,)})
    final = _final_bundle(
        turn_id=turn_id,
        run_id=run_id,
        parent_sha256s=(sha(9_515),),
        evidence_pack_sha256=pack_sha256,
        evidence_id=evidence_id,
        replies=replies,
        quality_evidence_ids=tuple(sorted(bound_evidence_ids(evidence_pack))),
    )
    final = final.model_copy(
        update={
            "counselor_internal": final.counselor_internal.model_copy(
                update={"risk_observations": (observation,)}
            )
        }
    )

    if expected_code is None:
        assert FinalBundleValidator().require_valid(
            final,
            conceptualization=concept,
            theory=theory,
            replies=replies,
            evidence_audit=audit,
            consistency=consistency,
            evidence_pack=evidence_pack,
            visible_risk=visible_risk,
        ) == final
    else:
        with pytest.raises(ClientReplyLeakageError, match=expected_code):
            FinalBundleValidator().require_valid(
                final,
                conceptualization=concept,
                theory=theory,
                replies=replies,
                evidence_audit=audit,
                consistency=consistency,
                evidence_pack=evidence_pack,
                visible_risk=visible_risk,
            )
