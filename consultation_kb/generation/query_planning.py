"""Deterministic validation for Codex-authored retrieval plans."""

from __future__ import annotations

from typing import Final

from pydantic import Field

from consultation_kb.generation.contracts import QueryPlan, Subquery
from consultation_kb.models.common import NonEmptyStr, SafePolicyKey, StrictModel
from consultation_kb.models.evidence import EvidenceChannel


ALL_RETRIEVAL_ROUTES: Final[tuple[EvidenceChannel, ...]] = (
    "profile",
    "client_history",
    "wiki",
    "lexical",
    "vector",
    "global_graph",
    "case",
)
_KNOWLEDGE_ROUTES: Final[frozenset[EvidenceChannel]] = frozenset(
    {"wiki", "lexical", "vector", "global_graph"}
)


class RequiredRouteRule(StrictModel):
    required_routes: frozenset[EvidenceChannel] = frozenset()
    any_routes: frozenset[EvidenceChannel] = frozenset()
    required_evidence_types: frozenset[SafePolicyKey] = frozenset()


REQUIRED_ROUTE_POLICY: Final[dict[str, RequiredRouteRule]] = {
    "current_client_facts": RequiredRouteRule(required_routes=frozenset({"profile"})),
    "emotion_needs_relationship": RequiredRouteRule(),
    "historical_change": RequiredRouteRule(
        required_routes=frozenset({"client_history"}),
        required_evidence_types=frozenset({"temporal_graph_edge"}),
    ),
    "theory_method_boundary": RequiredRouteRule(
        any_routes=_KNOWLEDGE_ROUTES,
        required_evidence_types=frozenset(
            {"theory_applicability", "theory_boundary"}
        ),
    ),
    "case_analogy": RequiredRouteRule(
        required_routes=frozenset({"case"}),
        required_evidence_types=frozenset({"case_provenance"}),
    ),
    "counterevidence_conflict": RequiredRouteRule(
        any_routes=_KNOWLEDGE_ROUTES
        | frozenset[EvidenceChannel]({"client_history", "case"}),
        required_evidence_types=frozenset({"contradicting_evidence"}),
    ),
    "internal_risk": RequiredRouteRule(
        required_evidence_types=frozenset({"risk_context"})
    ),
}


class QueryPlanCorrectionRequest(StrictModel):
    code: str = Field(default="QUERY_PLAN_CORRECTION_REQUIRED", pattern="^QUERY_PLAN_CORRECTION_REQUIRED$")
    issues: tuple[SafePolicyKey, ...]
    corrections: tuple[NonEmptyStr, ...]


class QueryPlanValidationError(RuntimeError):
    def __init__(self, request: QueryPlanCorrectionRequest) -> None:
        self.correction_request = request
        super().__init__("QUERY_PLAN_INVALID")


class QueryPlanValidator:
    """Validate routes and evidence requirements without rewriting the query."""

    @classmethod
    def validate(cls, plan: QueryPlan | object) -> QueryPlan:
        values = QueryPlan.model_validate(plan, strict=True)
        findings: dict[str, str] = {}

        used_routes = {
            route for subquery in values.subqueries for route in subquery.routes
        }
        omitted_routes = {omission.route for omission in values.route_omissions}
        all_routes = set(ALL_RETRIEVAL_ROUTES)
        if used_routes & omitted_routes:
            findings["route_both_used_and_omitted"] = (
                "Remove every used route from route_omissions."
            )
        if used_routes | omitted_routes != all_routes:
            findings["route_omission_reason_missing"] = (
                "List every unused retrieval route once with a concrete omission reason."
            )

        for subquery in values.subqueries:
            cls._validate_subquery(subquery, findings)

        categories = {subquery.category for subquery in values.subqueries}
        if values.intent == "fact_change" and "historical_change" not in categories:
            findings["fact_change_history_missing"] = (
                "Add a historical_change subquery using client_history and temporal_graph_edge."
            )
        if values.intent == "theory_guidance" and "theory_method_boundary" not in categories:
            findings["theory_boundary_query_missing"] = (
                "Add a theory_method_boundary subquery with applicability and boundary evidence."
            )
        if values.intent == "case_comparison" and "case_analogy" not in categories:
            findings["case_provenance_query_missing"] = (
                "Add a case_analogy subquery using the case route and case_provenance evidence."
            )
        if values.intent == "simple_empathic_clarification" and used_routes & {
            "global_graph",
            "case",
        }:
            findings["simple_plan_not_minimal"] = (
                "Omit case and global_graph for simple empathic clarification unless the intent changes."
            )

        if findings:
            ordered = sorted(findings.items())
            raise QueryPlanValidationError(
                QueryPlanCorrectionRequest(
                    issues=tuple(key for key, _ in ordered),
                    corrections=tuple(message for _, message in ordered),
                )
            )
        return values

    @staticmethod
    def _validate_subquery(
        subquery: Subquery,
        findings: dict[str, str],
    ) -> None:
        rule = REQUIRED_ROUTE_POLICY[subquery.category]
        routes = set(subquery.routes)
        evidence_types = set(subquery.required_evidence_types)
        prefix = subquery.subquery_id
        if not set(rule.required_routes) <= routes:
            findings[f"{prefix}_required_route_missing"] = (
                f"Add required routes for {subquery.category}: "
                + ", ".join(sorted(rule.required_routes))
                + "."
            )
        if rule.any_routes and not routes & set(rule.any_routes):
            findings[f"{prefix}_knowledge_route_missing"] = (
                f"Select at least one permitted route for {subquery.category}."
            )
        if not set(rule.required_evidence_types) <= evidence_types:
            findings[f"{prefix}_evidence_type_missing"] = (
                f"Request required evidence types for {subquery.category}: "
                + ", ".join(sorted(rule.required_evidence_types))
                + "."
            )
        unexpected_evidence_types = evidence_types - set(
            rule.required_evidence_types
        )
        if unexpected_evidence_types:
            findings[f"{prefix}_evidence_type_not_permitted"] = (
                f"Remove evidence types not permitted for {subquery.category}: "
                + ", ".join(sorted(unexpected_evidence_types))
                + "."
            )
        if subquery.category == "internal_risk" and subquery.scope != "internal_only":
            findings[f"{prefix}_risk_scope_invalid"] = (
                "Use internal_only scope for internal risk observation."
            )
        if subquery.category == "case_analogy" and subquery.scope == "client_private":
            findings[f"{prefix}_case_scope_invalid"] = (
                "Use global_knowledge or both scope for a governed case analogy."
            )


__all__ = [
    "ALL_RETRIEVAL_ROUTES",
    "QueryPlanCorrectionRequest",
    "QueryPlanValidationError",
    "QueryPlanValidator",
    "REQUIRED_ROUTE_POLICY",
    "RequiredRouteRule",
    "Subquery",
]
