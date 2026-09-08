from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from datetime import datetime, timezone

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.mcp import (
    HandlerServices,
    McpHandlerContext,
    TransportBindingRegistry,
    build_handler_registry,
)
from consultation_kb.mcp.context import BoundTransport
from consultation_kb.models.common import StrictModel


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)


class KnowledgeService:
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
        return {"accepted": True}


def _registry() -> tuple[KnowledgeService, object]:
    service = KnowledgeService()
    services = HandlerServices(
        read=service,
        graph=service,
        session=service,
        knowledge=service,
        write=service,
    )
    context = McpHandlerContext(
        transport_session_id="knowledge-transport-1",
        bindings=TransportBindingRegistry(),
        services=services,
    )
    return service, build_handler_registry(context)


def test_knowledge_drafts_use_fixed_inbox_handles_not_caller_paths() -> None:
    service, registry_object = _registry()
    registry = registry_object
    accepted = asyncio.run(
        registry["register_source_draft"](  # type: ignore[index]
            {
                "source_handle": "source-handle-00000001",
                "metadata": {
                    "license": "internal",
                    "domain": "emotion_consultation",
                    "language": "zh-CN",
                    "sensitivity": "ordinary",
                    "source_grade": "C2",
                    "document_type": "md",
                },
            }
        )
    )
    assert accepted.ok
    assert service.calls[-1][2] is None
    before = len(service.calls)
    rejected = asyncio.run(
        registry["register_source_draft"](  # type: ignore[index]
            {
                "source_handle": "source-handle-00000001",
                "path": "C:\\incoming\\source.md",
                "metadata": {
                    "license": "internal",
                    "domain": "emotion_consultation",
                    "language": "zh-CN",
                    "sensitivity": "ordinary",
                    "source_grade": "C2",
                    "document_type": "md",
                },
            }
        )
    )
    assert not rejected.ok
    assert rejected.error is not None
    assert rejected.error.code == "INVALID_ARGUMENTS"
    assert len(service.calls) == before


def test_formal_knowledge_writes_forward_only_approval_request_id() -> None:
    service, registry_object = _registry()
    registry = registry_object
    request_id = IdFactory(FixedClock(NOW), lambda: 4).object_id("approval_request")
    result = asyncio.run(
        registry["approve_claim"](  # type: ignore[index]
            {"approval_request_id": request_id}
        )
    )
    assert result.ok
    name, request, binding = service.calls[-1]
    assert name == "approve_claim"
    assert request.model_dump() == {"approval_request_id": request_id}
    assert binding is None
    assert registry["approve_claim"].annotations.approval_required  # type: ignore[index]


def test_p8_lifecycle_handlers_are_exposed_only_through_session_runtime() -> None:
    _service, registry_object = _registry()
    registry = registry_object
    assert {
        "start_rebuild",
        "rollback_version",
        "preview_rebuild",
        "preview_delete",
        "commit_delete",
    } <= set(registry)  # type: ignore[arg-type]
    assert "delete_client" not in registry  # type: ignore[operator]
    for name in (
        "start_rebuild",
        "rollback_version",
        "preview_rebuild",
        "preview_delete",
        "commit_delete",
    ):
        assert registry[name].service_slot == "session"  # type: ignore[index]
