"""Deterministic C1 dual-axis selection and applicability policy."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from consultation_kb.generation.contracts import TheoryComparison
from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.common import (
    NonEmptyStr,
    ObjectId,
    SafePolicyKey,
    StrictModel,
    VersionRef,
)
from consultation_kb.models.evidence import EmpiricalSupport, EvidencePack


def _unique_sorted(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must not contain duplicates")
    return tuple(sorted(values))


class TheoryUseDecision(StrictModel):
    mode: Literal["primary_framework", "use_domain_sources", "clarify_first"]
    use_c1: bool
    c1_revision: VersionRef | None
    c1_source_grade: Literal["C1"] | None
    empirical_support: EmpiricalSupport
    framework_priority: Literal["highest", "normal", "not_applicable"]
    clarification_fields: Annotated[
        tuple[SafePolicyKey, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    conflict_evidence_ids: Annotated[
        tuple[ObjectId, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    specific_advice_allowed: bool
    inapplicability_reasons: Annotated[
        tuple[SafePolicyKey, ...], Field(json_schema_extra={"uniqueItems": True})
    ]

    @field_validator(
        "clarification_fields", "conflict_evidence_ids", "inapplicability_reasons"
    )
    @classmethod
    def _canonical_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted(value, "theory decision values")

    @model_validator(mode="after")
    def _state_matrix(self) -> "TheoryUseDecision":
        if self.use_c1:
            if (
                self.mode != "primary_framework"
                or self.c1_revision is None
                or self.c1_source_grade != "C1"
                or self.framework_priority != "highest"
                or self.clarification_fields
            ):
                raise ValueError("active C1 primary-framework decision is inconsistent")
        elif self.mode == "clarify_first":
            if not self.clarification_fields or self.framework_priority != "normal":
                raise ValueError("clarify-first decision requires missing context")
        elif self.framework_priority == "highest":
            raise ValueError("unused C1 cannot have highest framework priority")
        if not self.specific_advice_allowed and not self.inapplicability_reasons:
            raise ValueError("blocked specific advice requires an auditable reason")
        return self


class TheoryPolicyFinding(StrictModel):
    code: Literal[
        "evidence_pack_hash_mismatch",
        "c1_primary_missing",
        "c1_primary_forbidden",
        "c1_revision_mismatch",
        "c1_axis_mismatch",
        "unfrozen_c1_selection",
        "c1_conflict_omitted",
        "clarification_missing",
        "unknown_evidence",
        "hard_constraint_not_respected",
    ]
    severity: Literal["blocking"] = "blocking"
    evidence_ids: tuple[ObjectId, ...]
    correction: NonEmptyStr


class TheoryPolicyValidationResult(StrictModel):
    accepted: bool
    decision: TheoryUseDecision
    findings: tuple[TheoryPolicyFinding, ...]

    @model_validator(mode="after")
    def _accepted_matches_findings(self) -> "TheoryPolicyValidationResult":
        if self.accepted == bool(self.findings):
            raise ValueError("accepted must be the inverse of blocking findings")
        return self


class TheoryPolicyError(RuntimeError):
    def __init__(self, result: TheoryPolicyValidationResult) -> None:
        self.result = result
        super().__init__("THEORY_POLICY_REJECTED")


def derive_hard_constraint_evidence_ids(
    evidence_pack: EvidencePack,
) -> tuple[ObjectId, ...]:
    """Derive the minimum trusted hard-constraint closure from a frozen pack.

    QueryPlan prose and generation-stage self-reports are deliberately excluded:
    neither is an authority proof.  Until legal and professional boundaries have
    their own typed, worker-verified proof objects, the conservative production
    minimum is the union of the frozen C1 decision's conflict evidence and every
    candidate assigned the pack's contradicting role.
    """

    pack = EvidencePack.model_validate(evidence_pack)
    return tuple(
        sorted(
            {
                *pack.c1_applicability.conflict_evidence_ids,
                *(item.evidence_id for item in pack.contradicting),
            }
        )
    )


class TheoryUsePolicy:
    """Read only the frozen pack decision; never trust a stage's C1 claim."""

    def decide(
        self,
        evidence_pack: EvidencePack,
        *,
        hard_constraint_evidence_ids: tuple[ObjectId, ...] = (),
    ) -> TheoryUseDecision:
        pack = EvidencePack.model_validate(evidence_pack)
        decision = pack.c1_applicability
        available = {
            item.evidence_id for item in pack.supporting + pack.contradicting
        }
        blockers = _unique_sorted(
            hard_constraint_evidence_ids, "hard-constraint evidence IDs"
        )
        if not set(blockers) <= available:
            raise ValueError("hard-constraint evidence must resolve inside EvidencePack")

        blocked_reasons: tuple[str, ...] = (
            ("hard_constraint_conflict",) if blockers else ()
        )
        if decision.status == "applicable" and decision.effective_status == "active":
            return TheoryUseDecision(
                mode="primary_framework",
                use_c1=True,
                c1_revision=decision.revision,
                c1_source_grade="C1",
                empirical_support=decision.empirical_support,
                framework_priority="highest",
                clarification_fields=(),
                conflict_evidence_ids=decision.conflict_evidence_ids,
                specific_advice_allowed=not blockers,
                inapplicability_reasons=blocked_reasons,
            )
        if decision.status == "insufficient_context":
            return TheoryUseDecision(
                mode="clarify_first",
                use_c1=False,
                c1_revision=decision.revision,
                c1_source_grade="C1",
                empirical_support=decision.empirical_support,
                framework_priority="normal",
                clarification_fields=decision.missing_context_fields,
                conflict_evidence_ids=decision.conflict_evidence_ids,
                specific_advice_allowed=False,
                inapplicability_reasons=("insufficient_context",),
            )

        reason = (
            "scope_not_applicable"
            if decision.status == "not_applicable"
            else f"c1_{decision.effective_status}"
        )
        return TheoryUseDecision(
            mode="use_domain_sources",
            use_c1=False,
            c1_revision=decision.revision,
            c1_source_grade="C1" if decision.revision is not None else None,
            empirical_support=decision.empirical_support,
            framework_priority=(
                "not_applicable" if decision.status == "not_applicable" else "normal"
            ),
            clarification_fields=(),
            conflict_evidence_ids=decision.conflict_evidence_ids,
            specific_advice_allowed=not blockers,
            inapplicability_reasons=tuple(sorted({reason, *blocked_reasons})),
        )

    def validate(
        self,
        artifact: TheoryComparison,
        evidence_pack: EvidencePack,
        *,
        hard_constraint_evidence_ids: tuple[ObjectId, ...] = (),
    ) -> TheoryPolicyValidationResult:
        value = TheoryComparison.model_validate(artifact)
        pack = EvidencePack.model_validate(evidence_pack)
        policy = self.decide(
            pack,
            hard_constraint_evidence_ids=hard_constraint_evidence_ids,
        )
        findings: list[TheoryPolicyFinding] = []
        available = {
            item.evidence_id for item in pack.supporting + pack.contradicting
        }

        if value.evidence_pack_sha256 != canonical_sha256(
            pack.model_dump(mode="json")
        ):
            findings.append(
                TheoryPolicyFinding(
                    code="evidence_pack_hash_mismatch",
                    evidence_ids=(),
                    correction="Bind the comparison to the retrieved EvidencePack.",
                )
            )

        selections = (
            (() if value.primary_framework is None else (value.primary_framework,))
            + value.comparisons
        )
        unknown = tuple(
            sorted(
                {
                    evidence_id
                    for selection in selections
                    for evidence_id in selection.evidence_ids
                }
                - available
            )
        )
        if unknown:
            findings.append(
                TheoryPolicyFinding(
                    code="unknown_evidence",
                    evidence_ids=unknown,
                    correction="Use only evidence identifiers from the bound EvidencePack.",
                )
            )

        frozen_c1 = pack.c1_applicability
        for selection in selections:
            is_frozen_revision = selection.theory_ref == frozen_c1.revision
            if selection.source_grade == "C1" and not is_frozen_revision:
                findings.append(
                    TheoryPolicyFinding(
                        code="unfrozen_c1_selection",
                        evidence_ids=selection.evidence_ids,
                        correction="Use only the exact C1 revision frozen in EvidencePack.",
                    )
                )
            elif is_frozen_revision and (
                selection.source_grade != "C1"
                or selection.applicability != frozen_c1.status
                or selection.empirical_support != frozen_c1.empirical_support
            ):
                findings.append(
                    TheoryPolicyFinding(
                        code="c1_axis_mismatch",
                        evidence_ids=selection.evidence_ids,
                        correction="Preserve frozen C1 source, applicability, and empirical axes.",
                    )
                )

        primary = value.primary_framework
        if policy.use_c1:
            if primary is None:
                findings.append(
                    TheoryPolicyFinding(
                        code="c1_primary_missing",
                        evidence_ids=policy.conflict_evidence_ids,
                        correction="Use the applicable active C1 revision as primary framework.",
                    )
                )
            else:
                if primary.theory_ref != policy.c1_revision:
                    findings.append(
                        TheoryPolicyFinding(
                            code="c1_revision_mismatch",
                            evidence_ids=primary.evidence_ids,
                            correction="Use the exact C1 revision frozen in EvidencePack.",
                        )
                    )
                if (
                    primary.source_grade != policy.c1_source_grade
                    or primary.empirical_support != policy.empirical_support
                    or primary.applicability != "applicable"
                ):
                    findings.append(
                        TheoryPolicyFinding(
                            code="c1_axis_mismatch",
                            evidence_ids=primary.evidence_ids,
                            correction="Keep source grade and empirical support as separate frozen axes.",
                        )
                    )
                if not set(policy.conflict_evidence_ids) <= set(primary.evidence_ids):
                    findings.append(
                        TheoryPolicyFinding(
                            code="c1_conflict_omitted",
                            evidence_ids=policy.conflict_evidence_ids,
                            correction="Retain C1 counterevidence and empirical conflict in the comparison.",
                        )
                    )
        elif primary is not None and primary.source_grade == "C1":
            # A non-C1 domain framework remains available when the frozen C1
            # decision is out of scope, unavailable, or needs clarification.
            # Only C1 itself is forbidden from being forced into the primary
            # slot in those states.
            findings.append(
                TheoryPolicyFinding(
                    code="c1_primary_forbidden",
                    evidence_ids=primary.evidence_ids,
                    correction="Do not force C1 when it is outside scope, inactive, or unclear.",
                )
            )

        if policy.conflict_evidence_ids and not value.conflicts:
            findings.append(
                TheoryPolicyFinding(
                    code="c1_conflict_omitted",
                    evidence_ids=policy.conflict_evidence_ids,
                    correction="Describe the retained C1 counterevidence/conflict for internal audit.",
                )
            )

        if policy.mode == "clarify_first" and not value.clarification_questions:
            findings.append(
                TheoryPolicyFinding(
                    code="clarification_missing",
                    evidence_ids=(),
                    correction="Ask for the missing applicability context before using C1.",
                )
            )
        if hard_constraint_evidence_ids and not value.conflicts:
            findings.append(
                TheoryPolicyFinding(
                    code="hard_constraint_not_respected",
                    evidence_ids=hard_constraint_evidence_ids,
                    correction="Record the hard-constraint conflict and disable specific advice.",
                )
            )

        return TheoryPolicyValidationResult(
            accepted=not findings,
            decision=policy,
            findings=tuple(findings),
        )

    def require_valid(
        self,
        artifact: TheoryComparison,
        evidence_pack: EvidencePack,
        *,
        hard_constraint_evidence_ids: tuple[ObjectId, ...] = (),
    ) -> TheoryComparison:
        value = TheoryComparison.model_validate(artifact)
        result = self.validate(
            value,
            evidence_pack,
            hard_constraint_evidence_ids=hard_constraint_evidence_ids,
        )
        if not result.accepted:
            raise TheoryPolicyError(result)
        return value


__all__ = [
    "derive_hard_constraint_evidence_ids",
    "TheoryPolicyError",
    "TheoryPolicyFinding",
    "TheoryPolicyValidationResult",
    "TheoryUseDecision",
    "TheoryUsePolicy",
]
