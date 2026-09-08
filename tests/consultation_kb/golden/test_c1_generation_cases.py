from __future__ import annotations

from consultation_kb.generation.theory_policy import TheoryUsePolicy

from tests.consultation_kb.unit.p6_quality_support import candidate, pack
from tests.consultation_kb.unit.test_generation_theory_policy import (
    _comparison,
    _primary,
)


def test_applicable_c1_is_highest_framework_but_hard_facts_gate_advice() -> None:
    evidence_pack = pack(empirical_support="case_supported")
    hard_fact_id = evidence_pack.supporting[0].evidence_id
    policy = TheoryUsePolicy()

    decision = policy.decide(
        evidence_pack,
        hard_constraint_evidence_ids=(hard_fact_id,),
    )

    assert decision.use_c1 is True
    assert decision.framework_priority == "highest"
    assert decision.c1_source_grade == "C1"
    assert decision.empirical_support == "case_supported"
    assert decision.specific_advice_allowed is False
    assert decision.inapplicability_reasons == ("hard_constraint_conflict",)

    omitted = policy.validate(
        _comparison(evidence_pack, primary=_primary(evidence_pack)),
        evidence_pack,
        hard_constraint_evidence_ids=(hard_fact_id,),
    )
    assert omitted.accepted is False
    assert "hard_constraint_not_respected" in {
        finding.code for finding in omitted.findings
    }

    disclosed = policy.validate(
        _comparison(
            evidence_pack,
            primary=_primary(evidence_pack),
            conflicts=("当前事实构成硬约束，C1 只保留为解释框架，不生成具体建议。",),
        ),
        evidence_pack,
        hard_constraint_evidence_ids=(hard_fact_id,),
    )
    assert disclosed.accepted is True
    assert disclosed.decision.framework_priority == "highest"
    assert disclosed.decision.specific_advice_allowed is False


def test_out_of_scope_c1_is_not_forced_into_generation() -> None:
    evidence_pack = pack(c1_status="not_applicable")

    result = TheoryUsePolicy().validate(
        _comparison(evidence_pack, primary=None),
        evidence_pack,
    )

    assert result.accepted is True
    assert result.decision.use_c1 is False
    assert result.decision.mode == "use_domain_sources"
    assert result.decision.framework_priority == "not_applicable"
    assert result.decision.inapplicability_reasons == ("scope_not_applicable",)


def test_insufficient_c1_context_requires_clarification_not_advice() -> None:
    evidence_pack = pack(
        c1_status="insufficient_context",
        missing_context_fields=("relationship_status",),
    )
    policy = TheoryUsePolicy()

    rejected = policy.validate(
        _comparison(evidence_pack, primary=None),
        evidence_pack,
    )
    accepted = policy.validate(
        _comparison(
            evidence_pack,
            primary=None,
            clarification_questions=("你们目前如何定义这段关系？",),
        ),
        evidence_pack,
    )

    assert "clarification_missing" in {
        finding.code for finding in rejected.findings
    }
    assert accepted.accepted is True
    assert accepted.decision.use_c1 is False
    assert accepted.decision.mode == "clarify_first"
    assert accepted.decision.clarification_fields == ("relationship_status",)
    assert accepted.decision.specific_advice_allowed is False


def test_expired_c1_revision_is_not_used() -> None:
    evidence_pack = pack(c1_status="unavailable", effective_status="expired")

    result = TheoryUsePolicy().validate(
        _comparison(evidence_pack, primary=None),
        evidence_pack,
    )

    assert result.accepted is True
    assert result.decision.use_c1 is False
    assert result.decision.mode == "use_domain_sources"
    assert result.decision.inapplicability_reasons == ("c1_expired",)


def test_c1_c2_conflict_keeps_framework_and_empirical_axes_separate() -> None:
    support = candidate(31)
    c2_counterevidence = candidate(
        32,
        contradicts=(support.evidence_id,),
    ).model_copy(
        update={
            "source_grade": "C2",
            "empirical_support": "conflicting",
        }
    )
    evidence_pack = pack(
        supporting=(support,),
        contradicting=(c2_counterevidence,),
        c1_conflicts=(c2_counterevidence.evidence_id,),
        empirical_support="conflicting",
    )
    artifact = _comparison(
        evidence_pack,
        primary=_primary(evidence_pack),
        conflicts=("C1 与 C2 实证材料冲突；保留 C2 的冲突状态。",),
    )

    result = TheoryUsePolicy().validate(artifact, evidence_pack)

    assert result.accepted is True
    assert result.decision.framework_priority == "highest"
    assert result.decision.c1_source_grade == "C1"
    assert result.decision.empirical_support == "conflicting"
    assert result.decision.conflict_evidence_ids == (
        c2_counterevidence.evidence_id,
    )
    assert evidence_pack.contradicting[0].source_grade == "C2"
    assert evidence_pack.contradicting[0].empirical_support == "conflicting"

    omitted = TheoryUsePolicy().validate(
        _comparison(evidence_pack, primary=_primary(evidence_pack)),
        evidence_pack,
    )
    assert omitted.accepted is False
    assert "c1_conflict_omitted" in {finding.code for finding in omitted.findings}
