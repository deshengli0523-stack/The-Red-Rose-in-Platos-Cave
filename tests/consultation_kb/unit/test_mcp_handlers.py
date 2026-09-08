from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from datetime import datetime, timezone

import pytest

from consultation_kb.core.errors import (
    ChannelUnavailableError,
    PreviousTurnNotClosedError,
)
from consultation_kb.mcp import (
    HandlerServices,
    McpHandlerContext,
    P9_TOOL_NAMES,
    TransportBindingRegistry,
    build_handler_registry,
)
from consultation_kb.mcp.context import BoundTransport
from consultation_kb.models.common import StrictModel


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
CLIENT_A = "client_" + "a1b2" + "c3d4" + "e5f6"
CLIENT_B = "client_" + "b1c2" + "d3e4" + "f5a6"
HANDLE = "opaque-session-handle-0001"
APPROVAL_REQUEST_ID = "approval_request_01800000-0000-7000-8000-000000000001"


class FakeService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, StrictModel, BoundTransport | None]] = []
        self.failure: BaseException | None = None
        self.results: dict[str, object] = {}

    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object | Awaitable[object]:
        self.calls.append((tool_name, request, binding))
        if self.failure is not None:
            raise self.failure
        if tool_name in self.results:
            return self.results[tool_name]
        if tool_name == "load_client_context":
            return {"session_handle": HANDLE, "snapshot_version": 1}
        return {"tool": tool_name, "count": 0}


def _registry() -> tuple[FakeService, object]:
    service = FakeService()
    services = HandlerServices(
        read=service,
        graph=service,
        session=service,
        knowledge=service,
        write=service,
    )
    context = McpHandlerContext(
        transport_session_id="stdio-transport-1",
        bindings=TransportBindingRegistry(),
        services=services,
    )
    return service, build_handler_registry(context)


def test_registry_is_exact_and_carries_registration_metadata() -> None:
    _service, registry_object = _registry()
    registry = registry_object
    assert tuple(registry) == P9_TOOL_NAMES  # type: ignore[arg-type]
    assert registry["search_wiki"].annotations.read_only  # type: ignore[index]
    assert not registry["append_session_turn"].annotations.read_only  # type: ignore[index]
    assert registry["approve_claim"].annotations.destructive  # type: ignore[index]
    assert registry["approve_claim"].annotations.approval_required  # type: ignore[index]
    with pytest.raises(TypeError):
        registry["future_tool"] = registry["search_wiki"]  # type: ignore[index]


def test_create_client_handler_preserves_the_two_phase_contract() -> None:
    service, registry_object = _registry()
    registry = registry_object
    service.results["create_client"] = {
        "status": "approval_required",
        "client_id": CLIENT_A,
        "approval_request_id": APPROVAL_REQUEST_ID,
    }
    preview = asyncio.run(
        registry["create_client"](  # type: ignore[index]
            {
                "action": "preview",
                "alias": "来访者代号",
                "idempotency_key": "create-client:handler-0001",
            }
        )
    )
    assert preview.ok
    assert service.calls[-1][0] == "create_client"
    assert service.calls[-1][1].model_dump() == {
        "action": "preview",
        "alias": "来访者代号",
        "idempotency_key": "create-client:handler-0001",
        "approval_request_id": None,
    }
    before = len(service.calls)

    invalid = asyncio.run(
        registry["create_client"](  # type: ignore[index]
            {"action": "commit", "alias": "must-not-cross-phases"}
        )
    )
    assert not invalid.ok
    assert invalid.error is not None
    assert invalid.error.code == "INVALID_ARGUMENTS"
    assert len(service.calls) == before


@pytest.mark.parametrize(
    "unsafe_result",
    (
        {
            "status": "approval_required",
            "client_id": CLIENT_A,
            "approval_request_id": APPROVAL_REQUEST_ID,
            "alias": "private alias",
        },
        {
            "status": "active",
            "client_id": CLIENT_A,
            "path": "C:\\private\\client",
        },
        {"status": "active", "client_id": CLIENT_A, "nested": {"client_id": CLIENT_B}},
    ),
)
def test_create_client_handler_rejects_any_field_outside_exact_safe_shape(
    unsafe_result: object,
) -> None:
    service, registry_object = _registry()
    registry = registry_object
    service.results["create_client"] = unsafe_result

    result = asyncio.run(
        registry["create_client"](  # type: ignore[index]
            {
                "action": "preview",
                "alias": "safe alias",
                "idempotency_key": "create-client:shape-0001",
            }
        )
    )

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "INTERNAL_ERROR"
    rendered = result.model_dump_json()
    assert "private alias" not in rendered
    assert "private\\\\client" not in rendered
    assert CLIENT_B not in rendered


def test_transport_is_permanently_bound_and_handle_checked_before_service() -> None:
    service, registry_object = _registry()
    registry = registry_object
    loaded = asyncio.run(
        registry["load_client_context"]({"client_id": CLIENT_A})  # type: ignore[index]
    )
    assert loaded.ok
    assert loaded.result == {"session_handle": HANDLE, "snapshot_version": 1}

    searched = asyncio.run(
        registry["search_wiki"](  # type: ignore[index]
            {"session_handle": HANDLE, "query": "关系变化", "limit": 3}
        )
    )
    assert searched.ok
    assert service.calls[-1][2] == BoundTransport("stdio-transport-1", HANDLE)

    temporary = asyncio.run(
        registry["append_temporary_fact"](  # type: ignore[index]
            {
                "session_handle": HANDLE,
                "turn_id": "017f22e2-79b0-7cc3-98c4-dc0c0c07398f",
                "idempotency_key": "temporary-fact:0001",
                "event_kind": "GOAL",
                "cognitive_type": "client_statement",
                "value": {"goal": "clarify next step"},
            }
        )
    )
    assert temporary.ok
    assert service.calls[-1][0] == "append_temporary_fact"
    assert service.calls[-1][2] == BoundTransport("stdio-transport-1", HANDLE)

    before = len(service.calls)
    wrong_handle = asyncio.run(
        registry["search_wiki"](  # type: ignore[index]
            {"session_handle": "wrong-session-handle-0000", "query": "test"}
        )
    )
    assert not wrong_handle.ok
    assert wrong_handle.error is not None
    assert wrong_handle.error.code == "SCOPE_DENIED"
    assert len(service.calls) == before

    other_client = asyncio.run(
        registry["load_client_context"]({"client_id": CLIENT_B})  # type: ignore[index]
    )
    assert not other_client.ok
    assert other_client.error is not None
    assert other_client.error.code == "TASK_SCOPE_ALREADY_BOUND"
    assert len(service.calls) == before


def test_handler_maps_validation_and_internal_errors_without_echo() -> None:
    service, registry_object = _registry()
    registry = registry_object
    invalid = asyncio.run(
        registry["load_client_context"](  # type: ignore[index]
            {"client_id": CLIENT_A, "path": "secret"}
        )
    )
    assert not invalid.ok
    assert invalid.error is not None
    assert invalid.error.code == "INVALID_ARGUMENTS"
    assert "path" not in invalid.error.message.lower()
    assert service.calls == []

    service.failure = RuntimeError(f"secret {CLIENT_A} C:\\private\\transcript.txt")
    failed = asyncio.run(
        registry["load_client_context"]({"client_id": CLIENT_A})  # type: ignore[index]
    )
    assert not failed.ok
    assert failed.error is not None
    rendered = failed.model_dump_json()
    assert failed.error.code == "INTERNAL_ERROR"
    assert CLIENT_A not in rendered
    assert "transcript" not in rendered.lower()


@pytest.mark.parametrize(
    ("failure", "expected_code"),
    [
        (
            PreviousTurnNotClosedError("private turn body"),
            "PREVIOUS_TURN_NOT_CLOSED",
        ),
        (ChannelUnavailableError("private runtime path"), "CHANNEL_UNAVAILABLE"),
    ],
)
def test_handler_maps_closed_operational_errors_without_echo(
    failure: BaseException,
    expected_code: str,
) -> None:
    service, registry_object = _registry()
    registry = registry_object
    asyncio.run(
        registry["load_client_context"]({"client_id": CLIENT_A})  # type: ignore[index]
    )
    service.failure = failure
    result = asyncio.run(
        registry["search_wiki"](  # type: ignore[index]
            {"session_handle": HANDLE, "query": "safe query"}
        )
    )
    assert not result.ok
    assert result.error is not None
    assert result.error.code == expected_code
    rendered = result.model_dump_json()
    assert "private turn body" not in rendered
    assert "private runtime path" not in rendered


def test_same_client_can_retry_after_failed_load() -> None:
    service, registry_object = _registry()
    registry = registry_object
    service.failure = RuntimeError("unavailable")
    first = asyncio.run(
        registry["load_client_context"]({"client_id": CLIENT_A})  # type: ignore[index]
    )
    assert not first.ok
    service.failure = None
    second = asyncio.run(
        registry["load_client_context"]({"client_id": CLIENT_A})  # type: ignore[index]
    )
    assert second.ok


def test_same_client_can_retry_after_cancelled_async_load() -> None:
    service, registry_object = _registry()
    registry = registry_object

    async def scenario() -> None:
        started = asyncio.Event()

        async def blocked_load() -> object:
            started.set()
            await asyncio.Future()
            raise AssertionError("unreachable")

        service.results["load_client_context"] = blocked_load()
        task = asyncio.create_task(
            registry["load_client_context"]({"client_id": CLIENT_A})  # type: ignore[index]
        )
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        service.results["load_client_context"] = {
            "session_handle": HANDLE,
            "snapshot_version": 1,
        }
        retry = await registry["load_client_context"](  # type: ignore[index]
            {"client_id": CLIENT_A}
        )
        assert retry.ok

    asyncio.run(scenario())


def test_bound_handler_rejects_client_identity_even_when_handle_is_valid() -> None:
    service, registry_object = _registry()
    registry = registry_object
    asyncio.run(
        registry["load_client_context"]({"client_id": CLIENT_A})  # type: ignore[index]
    )
    before = len(service.calls)
    result = asyncio.run(
        registry["search_cases"](  # type: ignore[index]
            {
                "session_handle": HANDLE,
                "query": "相似案例",
                "client_id": CLIENT_A,
            }
        )
    )
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "INVALID_ARGUMENTS"
    assert len(service.calls) == before


def test_outward_search_result_cannot_expose_provenance_client_identity() -> None:
    service, registry_object = _registry()
    registry = registry_object
    asyncio.run(
        registry["load_client_context"]({"client_id": CLIENT_A})  # type: ignore[index]
    )
    service.results["search_cases"] = {
        "items": [{"source_client_id": CLIENT_B, "summary": "must not escape"}]
    }
    result = asyncio.run(
        registry["search_cases"](  # type: ignore[index]
            {"session_handle": HANDLE, "query": "相似案例"}
        )
    )
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "INTERNAL_ERROR"
    assert CLIENT_B not in result.model_dump_json()


def test_outward_result_cannot_hide_client_identity_in_dynamic_mapping_key() -> None:
    service, registry_object = _registry()
    registry = registry_object
    asyncio.run(
        registry["load_client_context"]({"client_id": CLIENT_A})  # type: ignore[index]
    )
    service.results["search_cases"] = {
        "facets": {f"case-owner:{CLIENT_B}": {"count": 1}}
    }

    result = asyncio.run(
        registry["search_cases"](  # type: ignore[index]
            {"session_handle": HANDLE, "query": "相似案例"}
        )
    )

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "INTERNAL_ERROR"
    assert CLIENT_B not in result.model_dump_json()
