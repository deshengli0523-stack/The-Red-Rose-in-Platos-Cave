from __future__ import annotations

import pytest
from pydantic import ValidationError

from consultation_kb.generation.conceptualization import ConceptualizationValidator
from consultation_kb.generation.contracts import Conceptualization, ConceptualizationItem
from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.evidence import EvidencePack

from tests.consultation_kb.unit.p6_quality_support import envelope, object_id, pack, ref


def _artifact(
    evidence_pack: EvidencePack,
    items: tuple[ConceptualizationItem, ...],
) -> Conceptualization:
    return Conceptualization(
        envelope=envelope("conceptualization"),
        evidence_pack_sha256=canonical_sha256(evidence_pack.model_dump(mode="json")),
        items=items,
        key_emotions=("焦虑",),
        key_needs=("澄清与自主决定",),
        alternative_explanations=("也可能是近期沟通压力造成。",),
        limitations=("尚未听到对方视角。",),
        rationale_summary="区分事实、报告、观察、假设与建议。",
    )


def _valid_items(evidence_id: str) -> tuple[ConceptualizationItem, ...]:
    return (
        ConceptualizationItem(
            item_id="reported_change",
            cognitive_type="client_reported",
            statement="来访者报告伴侣近期减少联系。",
            supporting_evidence_ids=(evidence_id,),
            uncertainty="low",
        ),
        ConceptualizationItem(
            item_id="possible_withdrawal",
            cognitive_type="hypothesis",
            statement="这可能与关系中的回避互动有关。",
            supporting_evidence_ids=(evidence_id,),
            uncertainty="high",
            clarification_question="这种减少联系从什么时候开始？",
        ),
        ConceptualizationItem(
            item_id="clarify_timeline",
            cognitive_type="suggestion",
            statement="先澄清变化的时间线，再讨论行动选择。",
            supporting_evidence_ids=(evidence_id,),
            supporting_item_ids=("reported_change", "possible_withdrawal"),
            uncertainty="medium",
        ),
    )


def test_conceptualization_keeps_fact_hypothesis_and_suggestion_distinct() -> None:
    evidence_pack = pack()
    artifact = _artifact(
        evidence_pack,
        _valid_items(evidence_pack.supporting[0].evidence_id),
    )

    result = ConceptualizationValidator().validate(artifact, evidence_pack)

    assert result.accepted is True
    assert not result.findings
    assert [item.cognitive_type for item in artifact.items] == [
        "client_reported",
        "hypothesis",
        "suggestion",
    ]


def test_hypothesis_requires_support_uncertainty_and_clarification() -> None:
    with pytest.raises(ValidationError):
        ConceptualizationItem(
            item_id="unsupported_hypothesis",
            cognitive_type="hypothesis",
            statement="这是一个没有依据的猜测。",
            supporting_evidence_ids=(),
            uncertainty="high",
            clarification_question=None,
        )


def test_suggestion_must_link_to_fact_or_hypothesis_item() -> None:
    evidence_pack = pack()
    evidence_id = evidence_pack.supporting[0].evidence_id
    with pytest.raises(ValidationError):
        _artifact(
            evidence_pack,
            (
                ConceptualizationItem(
                    item_id="unsupported_suggestion",
                    cognitive_type="suggestion",
                    statement="建议马上作出决定。",
                    supporting_evidence_ids=(evidence_id,),
                    supporting_item_ids=("missing_fact",),
                    uncertainty="medium",
                ),
            ),
        )


def test_validator_rejects_unknown_evidence_and_automatic_diagnosis() -> None:
    evidence_pack = pack()
    artifact = _artifact(
        evidence_pack,
        (
            ConceptualizationItem(
                item_id="diagnosis_claim",
                cognitive_type="counselor_observation",
                statement="你就是人格障碍。",
                supporting_evidence_ids=(object_id("evidence", 99),),
                uncertainty="low",
            ),
        ),
    )

    result = ConceptualizationValidator().validate(artifact, evidence_pack)

    assert result.accepted is False
    assert {item.code for item in result.findings} == {
        "automatic_diagnosis",
        "unknown_evidence",
    }


def test_client_reported_prior_clinical_diagnosis_is_not_auto_diagnosis() -> None:
    evidence_pack = pack()
    evidence_id = evidence_pack.supporting[0].evidence_id
    artifact = _artifact(
        evidence_pack,
        (
            ConceptualizationItem(
                item_id="reported_history",
                cognitive_type="client_reported",
                statement="来访者报告医生曾诊断为焦虑症。",
                supporting_evidence_ids=(evidence_id,),
                uncertainty="low",
            ),
        ),
    )

    assert ConceptualizationValidator().validate(artifact, evidence_pack).accepted


def test_current_turn_temporary_fact_is_valid_client_report_evidence() -> None:
    current_report = ref("temporary_fact", 41)
    evidence_pack = pack(
        supporting=(),
        temporary_fact_refs=(current_report,),
        c1_status="unavailable",
        effective_status="none",
    )
    artifact = _artifact(
        evidence_pack,
        (
            ConceptualizationItem(
                item_id="current_turn_report",
                cognitive_type="client_reported",
                statement="来访者本轮报告最近常感到关系中的不确定。",
                supporting_evidence_ids=(current_report.object_id,),
                uncertainty="low",
            ),
        ),
    )

    result = ConceptualizationValidator().validate(artifact, evidence_pack)

    assert result.accepted is True
    assert result.findings == ()
