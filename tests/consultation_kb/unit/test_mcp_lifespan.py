from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from typing import Any, cast

import pytest

from consultation_kb.lifecycle.fault_points import FAULT_ENV, FaultConfigurationError
from consultation_kb.mcp import lifespan as lifespan_module
from consultation_kb.mcp.context import BoundTransport, HandlerServices, ToolService
from consultation_kb.models.common import StrictModel


class _Service:
    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object | Awaitable[object]:
        del tool_name, request, binding
        return {}


def _services() -> HandlerServices:
    service: ToolService = _Service()
    return HandlerServices(
        read=service,
        graph=service,
        session=service,
        knowledge=service,
        write=service,
        evaluation=service,
    )


class _Runtime:
    def __init__(self) -> None:
        self.handler_services = _services()
        self.close_count = 0

    def close(self) -> None:
        self.close_count += 1


def _fail_graph_install(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = lifespan_module._DeferredToolService.install

    def install(
        service: lifespan_module._DeferredToolService,
        delegate: ToolService,
    ) -> None:
        if service._slot == "graph":
            raise RuntimeError("synthetic partial install failure")
        original(service, delegate)

    monkeypatch.setattr(lifespan_module._DeferredToolService, "install", install)


def test_deferred_install_rolls_back_every_slot_after_partial_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deferred = lifespan_module.DeferredHandlerServices()
    _fail_graph_install(monkeypatch)

    with pytest.raises(RuntimeError, match="synthetic partial install failure"):
        deferred.install(_services())

    with pytest.raises(RuntimeError, match="MCP_RUNTIME_NOT_READY"):
        deferred.handler_services.read.invoke(
            "probe",
            cast(StrictModel, object()),
            binding=None,
        )


def test_lifespan_closes_runtime_when_deferred_install_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deferred = lifespan_module.DeferredHandlerServices()
    runtime = _Runtime()
    _fail_graph_install(monkeypatch)
    monkeypatch.setattr(lifespan_module, "build_production_runtime", lambda: runtime)

    async def enter_lifespan() -> None:
        manager = lifespan_module.consultation_lifespan(deferred)
        async with manager(cast(Any, None)):
            pytest.fail("a partially installed runtime must not enter the lifespan")

    with pytest.raises(RuntimeError, match="synthetic partial install failure"):
        asyncio.run(enter_lifespan())

    assert runtime.close_count == 1
    with pytest.raises(RuntimeError, match="MCP_RUNTIME_NOT_READY"):
        deferred.handler_services.read.invoke(
            "probe",
            cast(StrictModel, object()),
            binding=None,
        )


def test_production_startup_rejects_the_fault_injection_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(FAULT_ENV, "after_stage_write")

    with pytest.raises(FaultConfigurationError, match="^FAULT_ENV_FORBIDDEN$"):
        lifespan_module.build_production_runtime()
