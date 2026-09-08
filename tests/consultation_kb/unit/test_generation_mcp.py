from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.generation.contracts import QueryPlan
from consultation_kb.mcp import (
    HandlerServices,
    McpHandlerContext,
    P9_TOOL_NAMES,
    TransportBindingRegistry,
    build_handler_registry,
)
from consultation_kb.mcp.context import BoundTransport
from consultation_kb.mcp.schemas import (
    AcknowledgeRiskObservationInput,
    SubmitGenerationStageInput,
)
from consultation_kb.models.common import StrictModel, VersionRef
from consultation_kb.models.generation import GenerationStageEnvelope


NOW = datetime(2026, 7, 20, 8, 0, tzinfo=timezone.utc)
CLIENT_ID = "client_" + "a1b2c3d4e5f6"
HANDLE = "opaque-session-handle-p6-0001"


def _ids() -> IdFactory:
    return IdFactory(FixedClock(NOW), lambda: 81)


def _query_plan() -> QueryPlan:
    ids = _ids()
    return QueryPlan(
        envelope=GenerationStageEnvelope(
            stage="query_plan",
            turn_id=ids.uuid7(),
            run_id=ids.uuid7(),
            parent_sha256s=(),
            created_at=NOW,
        ),
        intent="simple_empathic_clarification",
        client_snapshot_ref=VersionRef(
            object_id=ids.object_id("profile_snapshot"),
            version=1,
            content_sha256="a" * 64,
        ),
        global_runtime_epoch=1,
        client_runtime_epoch=1,
        tombstone_epoch=0,
        authorization_epoch=1,
        guardrails={
            "current_client_snapshot_validation": True,
            "provenance_source_client_filter": True,
            "tombstone_version_check": True,
        },
        subqueries=(
            {
                "subquery_id": "current_feeling",
                "category": "emotion_needs_relationship",
                "question": "澄清此刻最想被理解的感受。",
                "routes": ("profile",),
                "required_evidence_types": (),
                "scope": "client_private",
            },
        ),
        route_omissions=(
            {"route": "case", "reason": "简单澄清无需案例类比。"},
        ),
        rationale_summary="只检索与当前澄清直接相关的最小证据。",
    )


class _Service:
    def __init__(self) -> None:
        self.calls: list[tuple[str, StrictModel, BoundTransport | None]] = []

    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object | Awaitable[object]:
        self.calls.append((tool_name, request, binding))
        if tool_name == "load_client_context":
            return {"session_handle": HANDLE, "snapshot_version": 1}
        return {"status": "ok", "tool": tool_name}


def _registry() -> tuple[_Service, object]:
    service = _Service()
    services = HandlerServices(
        read=service,
        graph=service,
        session=service,
        knowledge=service,
        write=service,
    )
    return service, build_handler_registry(
        McpHandlerContext(
            transport_session_id="stdio-p6-generation",
            bindings=TransportBindingRegistry(),
            services=services,
        )
    )


def test_generation_tool_set_is_exact_and_annotations_match_effects() -> None:
    _service, registry = _registry()
    assert tuple(registry) == P9_TOOL_NAMES  # type: ignore[arg-type]
    assert not registry["submit_generation_stage"].annotations.read_only  # type: ignore[index]
    assert registry["get_generation_state"].annotations.read_only  # type: ignore[index]
    assert not registry["acknowledge_risk_observation"].annotations.read_only  # type: ignore[index]


def test_submit_stage_accepts_strict_json_and_rejects_hidden_reasoning_fields() -> None:
    plan = _query_plan()
    payload = {
        "session_handle": HANDLE,
        "idempotency_key": "generation-stage:query-plan:0001",
        "payload": plan.model_dump(mode="json"),
    }
    request = SubmitGenerationStageInput.model_validate(payload)
    assert request.payload == plan

    payload["payload"] = {
        **plan.model_dump(mode="json"),
        "chain_of_thought": "must never be persisted",
    }
    with pytest.raises(ValidationError):
        SubmitGenerationStageInput.model_validate(payload)


def test_generation_handlers_require_the_exact_bound_session() -> None:
    service, registry = _registry()
    plan = _query_plan()
    unbound = asyncio.run(
        registry["submit_generation_stage"](  # type: ignore[index]
            {
                "session_handle": HANDLE,
                "idempotency_key": "generation-stage:query-plan:0002",
                "payload": plan.model_dump(mode="json"),
            }
        )
    )
    assert not unbound.ok
    assert unbound.error is not None
    assert unbound.error.code == "SCOPE_DENIED"
    assert not service.calls

    loaded = asyncio.run(
        registry["load_client_context"]({"client_id": CLIENT_ID})  # type: ignore[index]
    )
    assert loaded.ok
    submitted = asyncio.run(
        registry["submit_generation_stage"](  # type: ignore[index]
            {
                "session_handle": HANDLE,
                "idempotency_key": "generation-stage:query-plan:0002",
                "payload": plan.model_dump(mode="json"),
            }
        )
    )
    assert submitted.ok
    assert service.calls[-1][2] == BoundTransport(
        "stdio-p6-generation", HANDLE
    )


def test_risk_acknowledgement_is_manual_and_has_no_scope_selectors() -> None:
    ids = _ids()
    payload = {
        "session_handle": HANDLE,
        "observation_id": ids.object_id("risk_observation"),
    }
    with pytest.raises(ValidationError):
        AcknowledgeRiskObservationInput.model_validate(payload)
    request = AcknowledgeRiskObservationInput.model_validate(
        {
            **payload,
            "action": "acknowledge",
            "counselor_disposition": "继续观察并在下一轮核对。",
        }
    )
    schema = request.model_json_schema()
    rendered = str(schema)
    assert "client_id" not in rendered
    assert "path" not in rendered
    assert "sql" not in rendered


def test_risk_lifecycle_action_fields_are_strictly_disjoint() -> None:
    ids = _ids()
    base = {
        "session_handle": HANDLE,
        "observation_id": ids.object_id("risk_observation"),
    }
    closed = AcknowledgeRiskObservationInput.model_validate(
        {
            **base,
            "action": "close",
            "close_decision": "counselor_confirmed_closed",
            "close_reason": "咨询师已复核当前轮次和后续情况。",
        }
    )
    assert closed.close_decision == "counselor_confirmed_closed"

    invalid_payloads = (
        {**base, "action": "acknowledge"},
        {
            **base,
            "action": "acknowledge",
            "counselor_disposition": "继续观察。",
            "close_decision": "counselor_confirmed_closed",
            "close_reason": "不得混合。",
        },
        {**base, "action": "close"},
        {
            **base,
            "action": "close",
            "counselor_disposition": "不得混合。",
            "close_decision": "counselor_confirmed_closed",
            "close_reason": "不得混合。",
        },
        {
            **base,
            "action": "close",
            "close_decision": "not a safe policy key",
            "close_reason": "无效决定。",
        },
    )
    for invalid in invalid_payloads:
        with pytest.raises(ValidationError):
            AcknowledgeRiskObservationInput.model_validate(invalid)
