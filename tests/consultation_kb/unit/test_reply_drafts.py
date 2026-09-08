from __future__ import annotations

import pytest
from pydantic import ValidationError

from consultation_kb.generation.contracts import (
    Conceptualization,
    ConceptualizationItem,
    ReplyClaim,
    ReplyDraft,
    ReplyDraftSet,
)
from consultation_kb.generation.reply_policy import (
    BUILT_IN_REPLY_STRATEGIES,
    ReplyDraftValidator,
)
from consultation_kb.knowledge._canonical import canonical_sha256, text_sha256
from consultation_kb.models.evidence import EvidencePack

from tests.consultation_kb.unit.p6_quality_support import envelope, object_id, pack, ref


def _claim(
    evidence_id: str,
    *,
    statement: str,
    claim_id: str = "shared_conclusion",
) -> ReplyClaim:
    return ReplyClaim(
        claim_id=claim_id,
        claim_type="important_conclusion",
        statement=statement,
        evidence_ids=(evidence_id,),
        evidence_fidelity="faithful",
        text_start_char=0,
        text_end_char=len(statement),
        text_sha256=text_sha256(statement),
    )


def _candidate(
    strategy: str,
    evidence_id: str,
    *,
    text: str,
    fact_ids: tuple[str, ...] = ("current_relationship_change",),
    claims: tuple[ReplyClaim, ...] | None = None,
) -> ReplyDraft:
    return ReplyDraft(
        candidate_id=f"candidate_{strategy}",
        strategy=strategy,
        text=text,
        core_positions=("clarify_before_deciding",),
        current_fact_ids=fact_ids,
        action_directions=("gather_timeline",),
        evidence_ids=(evidence_id,),
        claims=claims
        or (
            _claim(
                evidence_id,
                statement=text,
                claim_id=f"{strategy}_body",
            ),
        ),
    )


def _drafts(
    evidence_pack: EvidencePack,
    *,
    candidates: tuple[ReplyDraft, ...] | None = None,
) -> ReplyDraftSet:
    return ReplyDraftSet(
        envelope=envelope("reply_drafts"),
        evidence_pack_sha256=canonical_sha256(evidence_pack.model_dump(mode="json")),
        candidates=candidates
        or (
            _candidate(
                "gentle_empathy",
                evidence_pack.supporting[0].evidence_id,
                text="这份不确定感很难受。我们可以先一起看看变化从何时开始。",
            ),
            _candidate(
                "direct_clarification",
                evidence_pack.supporting[0].evidence_id,
                text="目前最关键的是联系减少的时间线，以及你们如何谈过这件事。",
            ),
            _candidate(
                "exploratory_guidance",
                evidence_pack.supporting[0].evidence_id,
                text="如果先不急着下结论，你最想澄清哪一个变化？",
            ),
        ),
        shared_core_positions=("clarify_before_deciding",),
        shared_action_directions=("gather_timeline",),
        rationale_summary="三个版本语气不同，事实、核心判断与行动方向一致。",
    )


def _conceptualization(
    evidence_pack: EvidencePack,
    *,
    items: tuple[ConceptualizationItem, ...] | None = None,
) -> Conceptualization:
    evidence_id = (
        evidence_pack.supporting[0].evidence_id
        if evidence_pack.supporting
        else evidence_pack.temporary_fact_refs[0].object_id
    )
    return Conceptualization(
        envelope=envelope("conceptualization"),
        evidence_pack_sha256=canonical_sha256(evidence_pack.model_dump(mode="json")),
        items=items
        or (
            ConceptualizationItem(
                item_id="current_relationship_change",
                cognitive_type="client_reported",
                statement="The client reports a current relationship change.",
                supporting_evidence_ids=(evidence_id,),
                uncertainty="low",
            ),
        ),
        key_emotions=("uncertainty",),
        key_needs=("clarity",),
        alternative_explanations=("The meaning of the change is not established.",),
        limitations=("Only the current report is available.",),
        rationale_summary="Separate fact-like statements from hypotheses and suggestions.",
    )


def _validate(
    artifact: ReplyDraftSet,
    evidence_pack: EvidencePack,
    conceptualization: Conceptualization | None = None,
):
    return ReplyDraftValidator().validate(
        artifact,
        evidence_pack,
        conceptualization or _conceptualization(evidence_pack),
    )


def test_three_configurable_strategies_preserve_core_and_actions() -> None:
    evidence_pack = pack()
    result = _validate(_drafts(evidence_pack), evidence_pack)

    assert result.accepted
    assert not result.findings
    assert BUILT_IN_REPLY_STRATEGIES == {
        "gentle_empathy",
        "direct_clarification",
        "exploratory_guidance",
    }


def test_two_distinct_strategy_candidates_are_allowed() -> None:
    evidence_pack = pack()
    evidence_id = evidence_pack.supporting[0].evidence_id
    candidates = (
        _candidate("gentle_empathy", evidence_id, text="先照顾感受，再澄清事实。"),
        _candidate("direct_clarification", evidence_id, text="先澄清事实，再考虑行动。"),
    )
    result = _validate(
        _drafts(evidence_pack, candidates=candidates),
        evidence_pack,
    )

    assert result.accepted is True


@pytest.mark.parametrize("field", ["core_positions", "action_directions"])
def test_consistency_axes_cannot_be_empty(field: str) -> None:
    evidence_pack = pack()
    candidate = _candidate(
        "gentle_empathy",
        evidence_pack.supporting[0].evidence_id,
        text="Clarify the current report before deciding.",
    ).model_dump(mode="python")
    candidate[field] = ()

    with pytest.raises(ValidationError, match="at least 1 item"):
        ReplyDraft.model_validate(candidate)


def test_candidates_without_strategy_variation_are_rejected() -> None:
    evidence_pack = pack()
    evidence_id = evidence_pack.supporting[0].evidence_id
    first = _candidate("gentle_empathy", evidence_id, text="先照顾感受，再澄清。")
    second = _candidate(
        "gentle_empathy",
        evidence_id,
        text="我们慢慢澄清。",
    ).model_copy(
        update={"candidate_id": "candidate_gentle_alternative"}
    )
    result = _validate(
        _drafts(evidence_pack, candidates=(first, second)),
        evidence_pack,
    )

    assert result.accepted is False
    assert "strategy_variation_missing" in {item.code for item in result.findings}


def test_all_candidates_must_use_same_current_facts() -> None:
    evidence_pack = pack()
    evidence_id = evidence_pack.supporting[0].evidence_id
    candidates = (
        _candidate("gentle_empathy", evidence_id, text="先澄清。"),
        _candidate(
            "direct_clarification",
            evidence_id,
            text="先核对。",
            fact_ids=("different_fact",),
        ),
        _candidate("exploratory_guidance", evidence_id, text="先探索。"),
    )

    result = _validate(
        _drafts(evidence_pack, candidates=candidates), evidence_pack
    )

    assert "current_fact_conflict" in {item.code for item in result.findings}


def test_each_candidate_current_facts_equal_all_fact_like_concept_items() -> None:
    evidence_pack = pack()
    evidence_id = evidence_pack.supporting[0].evidence_id
    conceptualization = _conceptualization(
        evidence_pack,
        items=(
            ConceptualizationItem(
                item_id="client_fact_item",
                cognitive_type="client_fact",
                statement="A client fact.",
                supporting_evidence_ids=(evidence_id,),
                uncertainty="low",
            ),
            ConceptualizationItem(
                item_id="reported_item",
                cognitive_type="client_reported",
                statement="A client report.",
                supporting_evidence_ids=(evidence_id,),
                uncertainty="low",
            ),
            ConceptualizationItem(
                item_id="observed_item",
                cognitive_type="counselor_observation",
                statement="A counselor observation.",
                supporting_evidence_ids=(evidence_id,),
                uncertainty="medium",
            ),
            ConceptualizationItem(
                item_id="possible_meaning",
                cognitive_type="hypothesis",
                statement="A possible meaning.",
                supporting_evidence_ids=(evidence_id,),
                uncertainty="high",
                clarification_question="What would distinguish this possibility?",
            ),
        ),
    )
    exact_ids = ("client_fact_item", "observed_item", "reported_item")
    candidates = (
        _candidate("gentle_empathy", evidence_id, text="First response.", fact_ids=exact_ids),
        _candidate(
            "direct_clarification",
            evidence_id,
            text="Second response.",
            fact_ids=exact_ids,
        ),
    )

    result = _validate(
        _drafts(evidence_pack, candidates=candidates),
        evidence_pack,
        conceptualization,
    )

    assert result.accepted is True


@pytest.mark.parametrize(
    "candidate_fact_ids",
    [
        ("client_fact_item",),
        ("client_fact_item", "forged_fact_item", "reported_item"),
        ("same_but_wrong_fact",),
    ],
    ids=["missing", "forged", "candidates-consistent-but-wrong"],
)
def test_current_facts_reject_missing_forged_or_consistently_wrong_items(
    candidate_fact_ids: tuple[str, ...],
) -> None:
    evidence_pack = pack()
    evidence_id = evidence_pack.supporting[0].evidence_id
    conceptualization = _conceptualization(
        evidence_pack,
        items=(
            ConceptualizationItem(
                item_id="client_fact_item",
                cognitive_type="client_fact",
                statement="A client fact.",
                supporting_evidence_ids=(evidence_id,),
                uncertainty="low",
            ),
            ConceptualizationItem(
                item_id="reported_item",
                cognitive_type="client_reported",
                statement="A client report.",
                supporting_evidence_ids=(evidence_id,),
                uncertainty="low",
            ),
        ),
    )
    candidates = (
        _candidate(
            "gentle_empathy",
            evidence_id,
            text="First response.",
            fact_ids=candidate_fact_ids,
        ),
        _candidate(
            "direct_clarification",
            evidence_id,
            text="Second response.",
            fact_ids=candidate_fact_ids,
        ),
    )

    result = _validate(
        _drafts(evidence_pack, candidates=candidates),
        evidence_pack,
        conceptualization,
    )

    mismatches = [
        finding
        for finding in result.findings
        if finding.code == "current_fact_conceptualization_mismatch"
    ]
    assert result.accepted is False
    assert {finding.candidate_id for finding in mismatches} == {
        "candidate_gentle_empathy",
        "candidate_direct_clarification",
    }


def test_evidence_free_expression_must_be_open_or_explicitly_uncertain() -> None:
    evidence_pack = pack()
    evidence_id = evidence_pack.supporting[0].evidence_id
    def unsupported(text: str, claim_id: str) -> ReplyClaim:
        return ReplyClaim(
            claim_id=claim_id,
            claim_type="hypothesis",
            statement=text,
            evidence_ids=(),
            evidence_fidelity="interpretation",
            text_start_char=0,
            text_end_char=len(text),
            text_sha256=text_sha256(text),
        )

    gentle_text = "我们可以先核对这个猜测。"
    direct_text = "先核对这个猜测。"
    exploratory_text = "你会怎样核对这个猜测？"
    candidates = (
        _candidate(
            "gentle_empathy",
            evidence_id,
            text=gentle_text,
            claims=(unsupported(gentle_text, "unsupported_gentle"),),
        ),
        _candidate(
            "direct_clarification",
            evidence_id,
            text=direct_text,
            claims=(unsupported(direct_text, "unsupported_direct"),),
        ),
        _candidate(
            "exploratory_guidance",
            evidence_id,
            text=exploratory_text,
            claims=(unsupported(exploratory_text, "unsupported_exploratory"),),
        ),
    )

    result = _validate(
        _drafts(evidence_pack, candidates=candidates), evidence_pack
    )

    assert {
        item.code for item in result.findings
    } >= {"unsupported_expression"}


@pytest.mark.parametrize(
    ("text", "expected_code"),
    [
        ("你就是人格障碍。", "automatic_diagnosis"),
        ("你应该立即停药。", "dangerous_advice"),
        ("被伤害都是因为你。", "victim_blaming"),
        ("易经可以治疗抑郁症。", "guoxue_medicalization"),
        ("这个案例证明所有人都应该分手。", "single_case_universalization"),
        ("你必须立即照我说的做。", "client_agency_overridden"),
    ],
)
def test_professional_boundary_policy_findings(text: str, expected_code: str) -> None:
    evidence_pack = pack()
    evidence_id = evidence_pack.supporting[0].evidence_id
    candidates = (
        _candidate("gentle_empathy", evidence_id, text=text),
        _candidate("direct_clarification", evidence_id, text="先核对事实。"),
        _candidate("exploratory_guidance", evidence_id, text="你想先探索什么？"),
    )

    result = _validate(
        _drafts(evidence_pack, candidates=candidates), evidence_pack
    )

    assert expected_code in {item.code for item in result.findings}


def test_internal_citations_and_labels_are_not_client_text() -> None:
    evidence_pack = pack()
    evidence_id = evidence_pack.supporting[0].evidence_id
    candidates = (
        _candidate(
            "gentle_empathy",
            evidence_id,
            text="根据 EvidencePack [1]，先澄清。",
        ),
        _candidate("direct_clarification", evidence_id, text="先澄清事实。"),
        _candidate("exploratory_guidance", evidence_id, text="你想先问什么？"),
    )

    result = _validate(
        _drafts(evidence_pack, candidates=candidates), evidence_pack
    )

    assert "internal_jargon_or_citation" in {
        item.code for item in result.findings
    }


def test_opposite_relationship_actions_fail_despite_style_difference() -> None:
    evidence_pack = pack()
    evidence_id = evidence_pack.supporting[0].evidence_id
    candidates = (
        _candidate("gentle_empathy", evidence_id, text="我理解你，建议立即分手。"),
        _candidate("direct_clarification", evidence_id, text="关系无需改变。"),
        _candidate("exploratory_guidance", evidence_id, text="先探索你的选择。"),
    )

    result = _validate(
        _drafts(evidence_pack, candidates=candidates), evidence_pack
    )

    assert "candidate_semantic_conflict" in {
        item.code for item in result.findings
    }


def test_unknown_evidence_is_rejected_even_when_claim_has_a_citation_field() -> None:
    evidence_pack = pack()
    valid_id = evidence_pack.supporting[0].evidence_id
    unknown_id = object_id("evidence", 99)
    bad_text = "先澄清事实。"
    bad_claim = _claim(
        unknown_id,
        statement=bad_text,
        claim_id="invented_support",
    )
    bad = _candidate(
        "gentle_empathy",
        valid_id,
        text=bad_text,
        claims=(bad_claim,),
    )
    candidates = (
        bad,
        _candidate("direct_clarification", valid_id, text="先核对事实。"),
        _candidate("exploratory_guidance", valid_id, text="你想先问什么？"),
    )

    result = _validate(
        _drafts(evidence_pack, candidates=candidates), evidence_pack
    )

    codes = {item.code for item in result.findings}
    assert {"unknown_evidence", "candidate_evidence_closure"} <= codes


def test_reply_may_use_hash_bound_current_turn_temporary_fact() -> None:
    current_report = ref("temporary_fact", 42)
    evidence_pack = pack(
        supporting=(),
        temporary_fact_refs=(current_report,),
        c1_status="unavailable",
        effective_status="none",
    )
    candidates = (
        _candidate(
            "gentle_empathy",
            current_report.object_id,
            text="听起来，这份不确定感最近一直让你很难受。",
        ),
        _candidate(
            "direct_clarification",
            current_report.object_id,
            text="我们可以先澄清，这份不确定感通常在什么情境下出现。",
        ),
    )

    result = _validate(
        _drafts(evidence_pack, candidates=candidates),
        evidence_pack,
    )

    assert result.accepted is True
    assert result.findings == ()


def test_unclaimed_client_assertion_cannot_hide_behind_unrelated_question() -> None:
    evidence_id = pack().supporting[0].evidence_id
    question = "What detail would you like to clarify first?"
    prefix = "Your partner is certainly cheating on you. "
    payload = _candidate(
        "direct_clarification",
        evidence_id,
        text=question,
    ).model_dump(mode="python")
    payload["text"] = prefix + question
    payload["claims"] = (
        {
            "claim_id": "unrelated_question",
            "claim_type": "open_question",
            "statement": question,
            "evidence_ids": (),
            "contradicting_evidence_ids": (),
            "evidence_fidelity": "not_applicable",
            "text_start_char": len(prefix),
            "text_end_char": len(prefix + question),
            "text_sha256": text_sha256(question),
            "safe_template_id": "clarify_detail_en",
        },
    )

    with pytest.raises(ValidationError, match="without gaps or overlaps"):
        ReplyDraft.model_validate(payload)


def test_reply_claim_span_hash_and_exact_statement_are_fail_closed() -> None:
    evidence_id = pack().supporting[0].evidence_id
    body = "We can clarify the timeline before deciding."
    payload = _candidate(
        "direct_clarification",
        evidence_id,
        text=body,
    ).model_dump(mode="python")
    payload["claims"][0]["text_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="text hash"):
        ReplyDraft.model_validate(payload)


def test_declarative_assertion_cannot_be_labeled_as_an_open_question() -> None:
    body = "Your partner is certainly cheating on you."

    with pytest.raises(ValidationError, match="approved safe template"):
        ReplyClaim(
            claim_id="misclassified_assertion",
            claim_type="open_question",
            statement=body,
            evidence_ids=(),
            evidence_fidelity="not_applicable",
            text_start_char=0,
            text_end_char=len(body),
            text_sha256=text_sha256(body),
        )


def test_assertion_and_question_cannot_share_one_evidence_free_claim() -> None:
    body = (
        "Your partner is certainly cheating on you. "
        "What detail would you like to clarify first?"
    )

    with pytest.raises(ValidationError, match="approved safe template"):
        ReplyClaim(
            claim_id="assertion_hidden_in_question",
            claim_type="open_question",
            statement=body,
            evidence_ids=(),
            evidence_fidelity="not_applicable",
            text_start_char=0,
            text_end_char=len(body),
            text_sha256=text_sha256(body),
        )


@pytest.mark.parametrize(
    "body",
    [
        "Do you agree, your partner is certainly cheating on you?",
        "What makes you accept that your partner is certainly cheating on you?",
    ],
)
def test_loaded_question_cannot_impersonate_an_approved_safe_template(
    body: str,
) -> None:
    with pytest.raises(ValidationError, match="approved safe template"):
        ReplyClaim(
            claim_id="loaded_question",
            claim_type="open_question",
            statement=body,
            evidence_ids=(),
            evidence_fidelity="not_applicable",
            text_start_char=0,
            text_end_char=len(body),
            text_sha256=text_sha256(body),
            safe_template_id="clarify_detail_en",
        )
