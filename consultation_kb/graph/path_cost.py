"""Versioned, explainable cost policy for governed global graph edges."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Mapping

from consultation_kb.models.common import VersionRef, require_utc
from consultation_kb.models.evidence import C1ApplicabilityDecision


@dataclass(frozen=True, slots=True)
class PathCostContext:
    effective_at: datetime
    required_use: str
    c1_applicability: C1ApplicabilityDecision | None = None
    applicable_edge_ids: frozenset[str] = frozenset()
    excluded_edge_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        require_utc(self.effective_at)
        if not self.required_use:
            raise ValueError("required_use must be nonempty")


@dataclass(frozen=True, slots=True)
class EdgeCostBreakdown:
    policy_version: str
    components: Mapping[str, float]
    total: float


@dataclass(frozen=True, slots=True)
class PathCostAssessment:
    cost: EdgeCostBreakdown | None
    impassable_reason: str | None


class PathCostPolicy:
    """Fail closed on authority gates; score only already-governed edges."""

    VERSION = "global-path-cost.v1"
    MINIMUM_EDGE_COST = 0.05

    _INFERENCE_PENALTIES = {
        "explicit": 0.0,
        "paraphrase": 0.1,
        "counselor_judgment": 0.2,
        "model_inference": 0.75,
        "cross_theory_analogy": 0.9,
    }
    _GRADE_PENALTIES = {
        "T1": 0.0,
        "T2": 0.1,
        "T3": 0.25,
        "T4": 0.55,
        "C1": 0.0,
        "C2": 0.05,
        "C3": 0.1,
        "C4": 0.25,
        "C5": 0.45,
        "C6": 0.75,
        "K1": 0.05,
        "K2": 0.15,
        "K3": 0.25,
        "K4": 0.5,
        "L1": 0.0,
        "L2": 0.15,
        "L3": 0.3,
        "L4": 0.55,
    }

    def assess(
        self,
        attributes: Mapping[str, object],
        context: PathCostContext,
    ) -> PathCostAssessment:
        reason = self._impassable_reason(attributes, context)
        if reason is not None:
            return PathCostAssessment(None, reason)

        confidence = attributes["confidence"]
        assert isinstance(confidence, int | float) and not isinstance(confidence, bool)
        cognitive_type = str(attributes["cognitive_type"])
        source_grade = str(attributes["source_grade"])
        relation = str(attributes["relation"])
        independent_sources = attributes["independent_source_count"]
        assert isinstance(independent_sources, int) and not isinstance(
            independent_sources, bool
        )
        edge_id = str(attributes["edge_id"])

        stale_penalty = 0.0
        review_due_at = attributes.get("review_due_at")
        if isinstance(review_due_at, datetime) and review_due_at <= context.effective_at:
            stale_penalty = 0.45
        analogy_penalty = 0.6 if relation == "ANALOGOUS_TO" else 0.0
        applicability_penalty = (
            0.0 if edge_id in context.applicable_edge_ids else 0.15
        )
        c1_adjustment = self._c1_adjustment(attributes, context)
        source_adjustment = -min(0.3, max(0, independent_sources - 1) * 0.1)
        components: dict[str, float] = {
            "base_cost": 0.8,
            "confidence_penalty": round((1.0 - float(confidence)) * 0.8, 12),
            "inference_penalty": self._INFERENCE_PENALTIES[cognitive_type],
            "source_grade_penalty": self._GRADE_PENALTIES[source_grade],
            "stale_review_penalty": stale_penalty,
            "analogy_penalty": analogy_penalty,
            "applicability_penalty": applicability_penalty,
            "source_diversity_adjustment": source_adjustment,
            "c1_framework_adjustment": c1_adjustment,
            "floor_adjustment": 0.0,
        }
        raw_total = sum(components.values())
        if raw_total < self.MINIMUM_EDGE_COST:
            components["floor_adjustment"] = self.MINIMUM_EDGE_COST - raw_total
        total = round(sum(components.values()), 12)
        return PathCostAssessment(
            EdgeCostBreakdown(
                policy_version=self.VERSION,
                components=MappingProxyType(
                    {key: round(value, 12) for key, value in components.items()}
                ),
                total=total,
            ),
            None,
        )

    def evaluate(
        self,
        attributes: Mapping[str, object],
        context: PathCostContext,
    ) -> EdgeCostBreakdown | None:
        return self.assess(attributes, context).cost

    def _impassable_reason(
        self,
        attributes: Mapping[str, object],
        context: PathCostContext,
    ) -> str | None:
        if attributes.get("review_status") != "approved":
            return "review_not_approved"
        if attributes.get("passage_review_status") != "approved":
            return "passage_not_approved"
        if attributes.get("authorized") is not True:
            return "not_authorized"
        if attributes.get("tombstoned") is not False:
            return "tombstoned"

        edge_id = attributes.get("edge_id")
        relation_ref = attributes.get("relation_ref")
        claim_ref = attributes.get("claim_ref")
        passages = attributes.get("passage_refs")
        if (
            not isinstance(edge_id, str)
            or not isinstance(relation_ref, VersionRef)
            or relation_ref.object_id != edge_id
            or not isinstance(claim_ref, VersionRef)
            or not isinstance(passages, tuple)
            or not passages
            or any(not isinstance(value, VersionRef) for value in passages)
        ):
            return "evidence_closure_invalid"
        if edge_id in context.excluded_edge_ids:
            return "scope_excluded"
        allowed_uses = attributes.get("allowed_uses")
        if not isinstance(allowed_uses, tuple | list | set | frozenset) or (
            context.required_use not in allowed_uses
        ):
            return "use_not_allowed"

        effective_from = attributes.get("effective_from")
        effective_to = attributes.get("effective_to")
        if effective_from is not None and not isinstance(effective_from, datetime):
            return "effective_interval_invalid"
        if effective_to is not None and not isinstance(effective_to, datetime):
            return "effective_interval_invalid"
        if (
            isinstance(effective_from, datetime)
            and effective_from > context.effective_at
        ) or (
            isinstance(effective_to, datetime)
            and context.effective_at >= effective_to
        ):
            return "not_effective"

        confidence = attributes.get("confidence")
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, int | float)
            or not 0 <= float(confidence) <= 1
        ):
            return "confidence_invalid"
        cognitive_type = attributes.get("cognitive_type")
        if cognitive_type not in self._INFERENCE_PENALTIES:
            return "cognitive_type_invalid"
        source_grade = attributes.get("source_grade")
        if source_grade not in self._GRADE_PENALTIES:
            return "source_grade_invalid"
        source_count = attributes.get("independent_source_count")
        if (
            isinstance(source_count, bool)
            or not isinstance(source_count, int)
            or source_count < 1
        ):
            return "source_count_invalid"
        if source_grade == "C1":
            if (
                not isinstance(attributes.get("theory_ref"), VersionRef)
                or attributes.get("theory_status") != "active"
            ):
                return "c1_not_active"
        return None

    @staticmethod
    def _c1_adjustment(
        attributes: Mapping[str, object],
        context: PathCostContext,
    ) -> float:
        decision = context.c1_applicability
        if (
            attributes.get("source_grade") != "C1"
            or decision is None
            or decision.status != "applicable"
            or decision.effective_status != "active"
            or decision.revision is None
            or attributes.get("theory_ref") != decision.revision
        ):
            return 0.0
        return -0.7


__all__ = [
    "EdgeCostBreakdown",
    "PathCostAssessment",
    "PathCostContext",
    "PathCostPolicy",
]
