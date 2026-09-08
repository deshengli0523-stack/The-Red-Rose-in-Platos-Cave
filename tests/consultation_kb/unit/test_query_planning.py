from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from consultation_kb.generation.contracts import (
    QueryGuardrails,
    QueryPlan,
    RouteOmission,
    Subquery,
)
from consultation_kb.generation.query_planning import (
    ALL_RETRIEVAL_ROUTES,
    QueryPlanValidationError,
    QueryPlanValidator,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.generation import GenerationStageEnvelope


TURN_ID = "018f0000-0000-7000-8000-000000000001"
RUN_ID = "018f0000-0000-7000-8000-000000000002"


def _query_plan(*, intent: str, subqueries: tuple[Subquery, ...]) -> QueryPlan:
    used = {route for subquery in subqueries for route in subquery.routes}
    omissions = tuple(
        RouteOmission(route=route, reason=f"not needed for {intent}")
        for route in ALL_RETRIEVAL_ROUTES
        if route not in used
    )
    return QueryPlan.model_validate(
        {
            "envelope": GenerationStageEnvelope(
                stage="query_plan",
                turn_id=TURN_ID,
                run_id=RUN_ID,
                parent_sha256s=(),
                created_at=datetime(2026, 7, 19, 6, 0, tzinfo=timezone.utc),
            ),
            "intent": intent,
            "client_snapshot_ref": VersionRef(
                object_id="client_snapshot_018f0000-0000-7000-8000-000000000003",
                version=1,
                content_sha256="a" * 64,
            ),
            "global_runtime_epoch": 3,
            "client_runtime_epoch": 4,
            "tombstone_epoch": 5,
            "authorization_epoch": 6,
            "guardrails": QueryGuardrails(),
            "subqueries": subqueries,
            "route_omissions": omissions,
            "rationale_summary": "Use only routes that can change this answer.",
        }
    )


def test_query_plan_goldens_cover_required_routes_and_minimality() -> None:
    path = Path(__file__).parents[1] / "golden" / "query_plan_cases.jsonl"
    cases = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    for case in cases:
        subqueries = tuple(
            Subquery.model_validate_json(json.dumps(item))
            for item in case["subqueries"]
        )
        plan = _query_plan(intent=case["intent"], subqueries=subqueries)
        if case["valid"]:
            assert QueryPlanValidator.validate(plan) == plan, case["name"]
        else:
            with pytest.raises(QueryPlanValidationError) as caught:
                QueryPlanValidator.validate(plan)
            assert case["expected_issue"] in caught.value.correction_request.issues


def test_all_unused_routes_require_an_explicit_omission_reason() -> None:
    plan = _query_plan(
        intent="simple_empathic_clarification",
        subqueries=(
            Subquery(
                subquery_id="empathy",
                category="emotion_needs_relationship",
                question="What needs clarification?",
                routes=("profile",),
                required_evidence_types=(),
                scope="client_private",
            ),
        ),
    )
    incomplete = plan.model_copy(update={"route_omissions": plan.route_omissions[:-1]})

    with pytest.raises(QueryPlanValidationError) as caught:
        QueryPlanValidator.validate(incomplete)

    assert caught.value.correction_request.code == "QUERY_PLAN_CORRECTION_REQUIRED"
    assert "route_omission_reason_missing" in caught.value.correction_request.issues


def test_validator_returns_corrections_and_never_rewrites_the_query() -> None:
    plan = _query_plan(
        intent="theory_guidance",
        subqueries=(
            Subquery(
                subquery_id="theory",
                category="theory_method_boundary",
                question="Use a theory.",
                routes=("wiki",),
                required_evidence_types=("theory_applicability",),
                scope="global_knowledge",
            ),
        ),
    )
    original = plan.model_dump(mode="json")

    with pytest.raises(QueryPlanValidationError) as caught:
        QueryPlanValidator.validate(plan)

    assert plan.model_dump(mode="json") == original
    assert "theory_evidence_type_missing" in caught.value.correction_request.issues
    assert any("theory_boundary" in item for item in caught.value.correction_request.corrections)


def test_query_plan_has_all_three_unconditional_filter_guards() -> None:
    schema = QueryPlan.model_json_schema()
    serialized = json.dumps(schema, sort_keys=True)

    assert "current_client_snapshot_validation" in serialized
    assert "provenance_source_client_filter" in serialized
    assert "tombstone_version_check" in serialized


def test_unknown_required_evidence_type_is_rejected_by_closed_contract() -> None:
    with pytest.raises(ValidationError):
        Subquery.model_validate(
            {
                "subquery_id": "unknown_evidence",
                "category": "emotion_needs_relationship",
                "question": "Can the caller invent a proof label?",
                "routes": ("profile",),
                "required_evidence_types": ("caller_asserted_type",),
                "scope": "client_private",
            },
            strict=True,
        )


def test_known_evidence_type_cannot_be_attached_to_wrong_category() -> None:
    plan = _query_plan(
        intent="simple_empathic_clarification",
        subqueries=(
            Subquery(
                subquery_id="wrong_known_type",
                category="emotion_needs_relationship",
                question="Can a valid label be used without its source policy?",
                routes=("profile",),
                required_evidence_types=("risk_context",),
                scope="client_private",
            ),
        ),
    )

    with pytest.raises(QueryPlanValidationError) as caught:
        QueryPlanValidator.validate(plan)

    assert (
        "wrong_known_type_evidence_type_not_permitted"
        in caught.value.correction_request.issues
    )
