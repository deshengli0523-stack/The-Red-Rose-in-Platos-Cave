"""Client fact-dependency and impact-proposal contracts."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from consultation_kb.models.common import NonEmptyStr, StrictModel


DependencyType = Literal[
    "direct_deterministic", "direct_conditional", "indirect_inferred"
]


class DependencyEdge(StrictModel):
    edge_id: NonEmptyStr
    dependent_fact_id: NonEmptyStr
    prerequisite_fact_id: NonEmptyStr
    dependency_type: DependencyType
    confidence: float = Field(strict=True, ge=0.0, le=1.0)
    source_event_id: NonEmptyStr
    reviewer_id: NonEmptyStr

    @model_validator(mode="after")
    def _not_self(self) -> "DependencyEdge":
        if self.dependent_fact_id == self.prerequisite_fact_id:
            raise ValueError("a dependency edge cannot depend on itself")
        return self


class ImpactItem(StrictModel):
    fact_id: NonEmptyStr
    path_edge_ids: tuple[NonEmptyStr, ...]
    path_confidence: float = Field(strict=True, ge=0.0, le=1.0)
    classification: Literal["direct_invalidation", "manual_review"]
    recommended_mutation: "RecommendedImpactMutation"
    reason: NonEmptyStr
    policy_version: Literal["dependency-impact.v1"] = "dependency-impact.v1"


class RecommendedImpactMutation(StrictModel):
    operation: Literal["SUPERSEDE", "CORRECT", "REVIEW"]
    correction_kind: Literal["validity"] | None = None
    new_validity_status: Literal["invalidated"] | None = None

    @model_validator(mode="after")
    def _six_operation_contract(self) -> "RecommendedImpactMutation":
        correction = self.operation == "CORRECT"
        if correction != (
            self.correction_kind == "validity"
            and self.new_validity_status == "invalidated"
        ):
            raise ValueError("validity invalidation must use CORRECT")
        return self


class ImpactProposal(StrictModel):
    changed_fact_id: NonEmptyStr
    old_value: NonEmptyStr
    new_value: NonEmptyStr
    direct_invalidations: tuple[ImpactItem, ...]
    manual_reviews: tuple[ImpactItem, ...]
    applied_mutations: tuple[()] = ()
    policy_version: Literal["dependency-impact.v1"] = "dependency-impact.v1"


__all__ = [
    "DependencyEdge",
    "DependencyType",
    "ImpactItem",
    "ImpactProposal",
    "RecommendedImpactMutation",
]
