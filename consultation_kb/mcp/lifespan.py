"""Lazy, fail-closed service composition for the consultation MCP process."""

from __future__ import annotations

import inspect
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import Protocol, final

from mcp.server.fastmcp import FastMCP

from consultation_kb.models.common import StrictModel

from .context import BoundTransport, HandlerServices, ToolService


class RuntimeServices(Protocol):
    """Owned production services installed for exactly one server lifespan."""

    @property
    def handler_services(self) -> HandlerServices: ...

    def close(self) -> None | Awaitable[None]: ...


class _RuntimeNotReady(RuntimeError):
    def __init__(self) -> None:
        super().__init__("MCP_RUNTIME_NOT_READY")


@final
class _DeferredToolService:
    def __init__(self, slot: str) -> None:
        self._slot = slot
        self._delegate: ToolService | None = None

    def install(self, delegate: ToolService) -> None:
        if self._delegate is not None:
            raise RuntimeError("MCP_RUNTIME_ALREADY_INSTALLED")
        self._delegate = delegate

    def uninstall(self) -> None:
        self._delegate = None

    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object | Awaitable[object]:
        delegate = self._delegate
        if delegate is None:
            raise _RuntimeNotReady
        return delegate.invoke(tool_name, request, binding=binding)


@final
class DeferredHandlerServices:
    """Stable handler references whose delegates exist only during lifespan."""

    def __init__(self) -> None:
        self._read = _DeferredToolService("read")
        self._graph = _DeferredToolService("graph")
        self._session = _DeferredToolService("session")
        self._knowledge = _DeferredToolService("knowledge")
        self._write = _DeferredToolService("write")
        self._evaluation = _DeferredToolService("evaluation")
        self._installed = False

    @property
    def handler_services(self) -> HandlerServices:
        return HandlerServices(
            read=self._read,
            graph=self._graph,
            session=self._session,
            knowledge=self._knowledge,
            write=self._write,
            evaluation=self._evaluation,
        )

    def install(self, services: HandlerServices) -> None:
        if self._installed:
            raise RuntimeError("MCP_RUNTIME_ALREADY_INSTALLED")
        try:
            self._read.install(services.read)
            self._graph.install(services.graph)
            self._session.install(services.session)
            self._knowledge.install(services.knowledge)
            self._write.install(services.write)
            if services.evaluation is None:
                raise RuntimeError("MCP_EVALUATION_RUNTIME_UNAVAILABLE")
            self._evaluation.install(services.evaluation)
        except BaseException:
            # Installation is one transaction.  No previously installed
            # delegate may survive a later-slot failure.
            self.uninstall()
            raise
        else:
            self._installed = True

    def uninstall(self) -> None:
        self._read.uninstall()
        self._graph.uninstall()
        self._session.uninstall()
        self._knowledge.uninstall()
        self._write.uninstall()
        self._evaluation.uninstall()
        self._installed = False


@dataclass(frozen=True, slots=True)
class McpLifespanState:
    runtime: RuntimeServices


def build_production_runtime() -> RuntimeServices:
    """Build the local-vault runtime without importing it during tool listing."""

    from consultation_kb.lifecycle.fault_points import (
        reject_fault_environment_in_production,
    )

    from .runtime import ProductionRuntime

    reject_fault_environment_in_production()
    return ProductionRuntime.open()


def consultation_lifespan(
    deferred: DeferredHandlerServices,
) -> Callable[
    [FastMCP[object]],
    AbstractAsyncContextManager[McpLifespanState],
]:
    @asynccontextmanager
    async def lifespan(_server: FastMCP[object]) -> AsyncIterator[McpLifespanState]:
        runtime = build_production_runtime()
        try:
            deferred.install(runtime.handler_services)
            yield McpLifespanState(runtime=runtime)
        finally:
            deferred.uninstall()
            result = runtime.close()
            if inspect.isawaitable(result):
                await result

    return lifespan


__all__ = [
    "DeferredHandlerServices",
    "McpLifespanState",
    "RuntimeServices",
    "build_production_runtime",
    "consultation_lifespan",
]
