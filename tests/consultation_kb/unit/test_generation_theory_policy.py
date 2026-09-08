from __future__ import annotations

from consultation_kb.generation.contracts import TheoryComparison, TheorySelection
from consultation_kb.generation.theory_policy import (
    TheoryUsePolicy,
    derive_hard_constraint_evidence_ids,
)
from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.evidence import EvidencePack

from tests.consultation_kb.unit.p6_quality_support import (
    candidate,
    envelope,
    pack,
    ref,
)


def _comparison(
    evidence_pack: EvidencePack,
    *,
    primary: TheorySelection | None,
    conflicts: tuple[str, ...] = (),
    clarification_questions: tuple[str, ...] = (),
) -> TheoryComparison:
    return TheoryComparison(
        envelope=envelope("theory_comparison"),
        evidence_pack_sha256=canonical_sha256(evidence_pack.model_dump(mode="json")),
        primary_framework=primary,
        comparisons=(),
        conflicts=conflicts,
        clarification_questions=clarification_questions,
        rationale_summary="按适用性、来源等级和实证状态分别比较。",
    )


def _primary(
    evidence_pack: EvidencePack,
    *,
    empirical_support: str | None = None,
) -> TheorySelection:
    decision = evidence_pack.c1_applicability
    assert decision.revision is not None
    return TheorySelection(
        theory_ref=decision.revision,
        role="primary_framework",
        source_grade="C1",
        empirical_support=empirical_support or decision.empirical_support,
        applicability="applicable",
        boundaries=("仅在已确认的关系语境内使用。",),
        evidence_ids=tuple(
            sorted(
                {
                    evidence_pack.supporting[0].evidence_id,
                    *decision.conflict_evidence_ids,
                }
            )
        ),
    )


def _domain_primary(evidence_pack: EvidencePack) -> TheorySelection:
    return TheorySelection(
        theory_ref=ref("theory_revision", 200),
        role="primary_framework",
        source_grade="T1",
        empirical_support="empirically_supported",
        applicability="applicable",
        boundaries=("仅用于当前问题的领域解释，不冒充 C1。",),
        evidence_ids=(evidence_pack.supporting[0].evidence_id,),
    )


def test_applicable_active_c1_is_primary_with_separate_empirical_axis() -> None:
    evidence_pack = pack(empirical_support="case_supported")
    artifact = _comparison(evidence_pack, primary=_primary(evidence_pack))

    result = TheoryUsePolicy().validate(artifact, evidence_pack)

    assert result.accepted is True
    assert result.decision.use_c1 is True
    assert result.decision.framework_priority == "highest"
    assert result.decision.c1_source_grade == "C1"
    assert result.decision.empirical_support == "case_supported"


def test_c1_empirical_conflict_is_retained_without_demoting_framework() -> None:
    support = candidate(1)
    counter = candidate(2, contradicts=(support.evidence_id,))
    evidence_pack = pack(
        supporting=(support,),
        contradicting=(counter,),
        c1_conflicts=(counter.evidence_id,),
        empirical_support="conflicting",
    )
    artifact = _comparison(
        evidence_pack,
        primary=_primary(evidence_pack),
        conflicts=("C1 与外部经验性材料存在冲突，保留冲突。",),
    )

    result = TheoryUsePolicy().validate(artifact, evidence_pack)

    assert result.accepted
    assert result.decision.framework_priority == "highest"
    assert result.decision.empirical_support == "conflicting"
    assert result.decision.conflict_evidence_ids == (counter.evidence_id,)

    omitted = TheoryUsePolicy().validate(
        _comparison(evidence_pack, primary=_primary(evidence_pack)),
        evidence_pack,
    )
    assert omitted.accepted is False
    assert "c1_conflict_omitted" in {item.code for item in omitted.findings}


def test_no_applicable_c1_does_not_fabricate_primary_framework() -> None:
    evidence_pack = pack(c1_status="not_applicable")
    artifact = _comparison(evidence_pack, primary=None)

    result = TheoryUsePolicy().validate(artifact, evidence_pack)

    assert result.accepted
    assert result.decision.use_c1 is False
    assert result.decision.mode == "use_domain_sources"
    assert result.decision.framework_priority == "not_applicable"


def test_no_applicable_c1_allows_an_applicable_non_c1_domain_framework() -> None:
    evidence_pack = pack(c1_status="not_applicable")
    artifact = _comparison(
        evidence_pack,
        primary=_domain_primary(evidence_pack),
    )

    result = TheoryUsePolicy().validate(artifact, evidence_pack)

    assert result.accepted
    assert result.decision.use_c1 is False
    assert result.decision.mode == "use_domain_sources"


def test_stage_cannot_self_report_non_applicable_c1_as_applicable_alternative() -> None:
    evidence_pack = pack(c1_status="not_applicable")
    decision = evidence_pack.c1_applicability
    assert decision.revision is not None
    fabricated = TheorySelection(
        theory_ref=decision.revision,
        role="alternative",
        source_grade="C1",
        empirical_support=decision.empirical_support,
        applicability="applicable",
        boundaries=("伪造的适用性。",),
        evidence_ids=(evidence_pack.supporting[0].evidence_id,),
    )
    artifact = _comparison(evidence_pack, primary=None).model_copy(
        update={"comparisons": (fabricated,)}
    )

    result = TheoryUsePolicy().validate(artifact, evidence_pack)

    assert result.accepted is False
    assert "c1_axis_mismatch" in {item.code for item in result.findings}


def test_insufficient_context_requires_clarification_before_c1() -> None:
    evidence_pack = pack(
        c1_status="insufficient_context",
        missing_context_fields=("relationship_status",),
    )
    missing = _comparison(evidence_pack, primary=None)
    clarified = _comparison(
        evidence_pack,
        primary=None,
        clarification_questions=("你们目前如何定义这段关系？",),
    )

    rejected = TheoryUsePolicy().validate(missing, evidence_pack)
    accepted = TheoryUsePolicy().validate(clarified, evidence_pack)

    assert "clarification_missing" in {item.code for item in rejected.findings}
    assert accepted.accepted
    assert accepted.decision.mode == "clarify_first"
    assert accepted.decision.specific_advice_allowed is False


def test_expired_c1_revision_is_never_used() -> None:
    evidence_pack = pack(c1_status="unavailable", effective_status="expired")
    result = TheoryUsePolicy().validate(
        _comparison(evidence_pack, primary=None),
        evidence_pack,
    )

    assert result.accepted
    assert result.decision.use_c1 is False
    assert result.decision.inapplicability_reasons == ("c1_expired",)


def test_hard_fact_or_legal_constraint_disables_specific_advice() -> None:
    evidence_pack = pack()
    blocker = evidence_pack.supporting[0].evidence_id
    policy = TheoryUsePolicy()
    decision = policy.decide(
        evidence_pack,
        hard_constraint_evidence_ids=(blocker,),
    )
    artifact = _comparison(
        evidence_pack,
        primary=_primary(evidence_pack),
        conflicts=("客户事实或硬约束与具体建议冲突，禁用该建议。",),
    )

    result = policy.validate(
        artifact,
        evidence_pack,
        hard_constraint_evidence_ids=(blocker,),
    )

    assert decision.use_c1 is True
    assert decision.specific_advice_allowed is False
    assert decision.inapplicability_reasons == ("hard_constraint_conflict",)
    assert result.accepted


def test_production_hard_constraints_are_derived_only_from_frozen_pack_roles() -> None:
    support = candidate(61)
    contradiction = candidate(62)
    evidence_pack = pack(
        supporting=(support,),
        contradicting=(contradiction,),
        c1_conflicts=(support.evidence_id,),
    )

    derived = derive_hard_constraint_evidence_ids(evidence_pack)

    assert derived == tuple(
        sorted((support.evidence_id, contradiction.evidence_id))
    )
    assert not TheoryUsePolicy().decide(
        evidence_pack,
        hard_constraint_evidence_ids=derived,
    ).specific_advice_allowed


def test_stage_cannot_substitute_another_revision_for_frozen_c1() -> None:
    evidence_pack = pack()
    wrong = _primary(evidence_pack).model_copy(
        update={"theory_ref": ref("theory_revision", 999)}
    )

    result = TheoryUsePolicy().validate(
        _comparison(evidence_pack, primary=wrong),
        evidence_pack,
    )

    assert result.accepted is False
    assert "c1_revision_mismatch" in {item.code for item in result.findings}
