"""Deterministic C1 scope gate over an approved policy vocabulary."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from pydantic import field_serializer, model_validator

from consultation_kb.models.common import ObjectId, SafePolicyKey, StrictModel, VersionRef
from consultation_kb.models.evidence import C1ApplicabilityDecision, EmpiricalSupport
from consultation_kb.models.theory import TheoryScope


class ApplicabilityPolicyError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ScopePolicyManifest(StrictModel):
    policy_ref: VersionRef
    rule_members: frozenset[SafePolicyKey]
    context_fields: frozenset[SafePolicyKey]

    @model_validator(mode="after")
    def _require_vocabulary(self) -> "ScopePolicyManifest":
        if not self.rule_members or not self.context_fields:
            raise ValueError("scope policy requires rules and context fields")
        return self

    @field_serializer("rule_members", "context_fields")
    def _serialize_sets(self, value: frozenset[str]) -> list[str]:
        return sorted(value)


def _as_key_set(value: object) -> frozenset[str]:
    if value is None:
        return frozenset()
    if type(value) is str:
        return frozenset({value})
    if isinstance(value, (set, frozenset, tuple, list)) and all(
        type(item) is str for item in value
    ):
        return frozenset(value)
    raise ApplicabilityPolicyError("CONTEXT_VALUE_INVALID")


class ApplicabilityGate:
    def __init__(self, manifest: ScopePolicyManifest) -> None:
        self._manifest = ScopePolicyManifest.model_validate(manifest)

    def _rule(self, *candidates: str) -> str:
        for value in candidates:
            if value in self._manifest.rule_members:
                return value
        raise ApplicabilityPolicyError("POLICY_RULE_NOT_APPROVED")

    def evaluate(
        self,
        *,
        revision: VersionRef,
        scope: TheoryScope,
        context: Mapping[str, object],
        effective_status: Literal[
            "active", "expired", "superseded", "revoked"
        ] = "active",
        empirical_support: EmpiricalSupport = "unassessed",
        conflict_evidence_ids: tuple[ObjectId, ...] = (),
    ) -> C1ApplicabilityDecision:
        revision_ref = VersionRef.model_validate(revision)
        theory_scope = TheoryScope.model_validate(scope)
        unknown = set(context).difference(self._manifest.context_fields)
        if unknown:
            raise ApplicabilityPolicyError("POLICY_KEY_NOT_APPROVED")
        if effective_status != "active":
            return C1ApplicabilityDecision(
                status="unavailable",
                revision=revision_ref,
                scope_policy_ref=self._manifest.policy_ref,
                matched_rule_ids=(),
                missing_context_fields=(),
                effective_status=effective_status,
                empirical_support=empirical_support,
                conflict_evidence_ids=conflict_evidence_ids,
            )

        required_fields: list[str] = []
        if theory_scope.domains:
            required_fields.append("domain")
        if theory_scope.populations:
            required_fields.append("population")
        if theory_scope.contexts:
            required_fields.append("context")
        if theory_scope.required_conditions:
            required_fields.append("conditions")
        if theory_scope.exclusions:
            required_fields.append("exclusions")
        if theory_scope.contraindications:
            required_fields.append("contraindications")
        missing = tuple(sorted(field for field in required_fields if field not in context))
        unapproved_missing = set(missing).difference(self._manifest.context_fields)
        if unapproved_missing:
            raise ApplicabilityPolicyError("POLICY_CONTEXT_FIELD_NOT_APPROVED")
        if missing:
            return C1ApplicabilityDecision(
                status="insufficient_context",
                revision=revision_ref,
                scope_policy_ref=self._manifest.policy_ref,
                matched_rule_ids=(),
                missing_context_fields=missing,
                effective_status="active",
                empirical_support=empirical_support,
                conflict_evidence_ids=conflict_evidence_ids,
            )

        matched: list[str] = []
        domain = _as_key_set(context.get("domain"))
        if not domain.intersection(theory_scope.domains):
            matched.append(self._rule("domain_mismatch", "domain_match"))
            decision: Literal["applicable", "not_applicable"] = "not_applicable"
        else:
            matched.append(self._rule("domain_match"))
            decision = "applicable"

        population = _as_key_set(context.get("population"))
        if decision == "applicable" and not population.intersection(
            theory_scope.populations
        ):
            matched.append(self._rule("population_mismatch", "population_match"))
            decision = "not_applicable"
        elif decision == "applicable":
            population_value = min(population, default="population")
            matched.append(
                self._rule(f"{population_value}_population", "population_match")
            )

        context_values = _as_key_set(context.get("context"))
        if decision == "applicable" and theory_scope.contexts:
            if not context_values.intersection(theory_scope.contexts):
                matched.append(self._rule("context_mismatch", "context_match"))
                decision = "not_applicable"
            else:
                matched.append(self._rule("context_match"))

        conditions = _as_key_set(context.get("conditions"))
        if decision == "applicable" and not theory_scope.required_conditions.issubset(
            conditions
        ):
            matched.append(
                self._rule("required_condition_missing", "required_conditions_met")
            )
            decision = "not_applicable"
        elif decision == "applicable" and theory_scope.required_conditions:
            matched.append(self._rule("required_conditions_met"))

        exclusions = _as_key_set(context.get("exclusions"))
        contraindications = _as_key_set(context.get("contraindications"))
        if theory_scope.exclusions.intersection(exclusions):
            matched.append(self._rule("exclusion_match"))
            decision = "not_applicable"
        if theory_scope.contraindications.intersection(contraindications):
            matched.append(self._rule("contraindication_match"))
            decision = "not_applicable"

        return C1ApplicabilityDecision(
            status=decision,
            revision=revision_ref,
            scope_policy_ref=self._manifest.policy_ref,
            matched_rule_ids=tuple(sorted(set(matched))),
            missing_context_fields=(),
            effective_status="active",
            empirical_support=empirical_support,
            conflict_evidence_ids=conflict_evidence_ids,
        )


def derive_framework_priority(
    decision: C1ApplicabilityDecision,
) -> Literal["highest", "normal", "not_applicable"]:
    """Derive, never store, the runtime framework priority."""

    value = C1ApplicabilityDecision.model_validate(decision)
    if value.status == "applicable" and value.effective_status == "active":
        return "highest"
    if value.status == "not_applicable":
        return "not_applicable"
    return "normal"


__all__ = [
    "ApplicabilityGate",
    "ApplicabilityPolicyError",
    "ScopePolicyManifest",
    "derive_framework_priority",
]
