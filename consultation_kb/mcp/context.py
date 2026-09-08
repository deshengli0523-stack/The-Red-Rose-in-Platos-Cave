"""Pure handler composition and permanent per-transport client binding."""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import re
import threading
from collections.abc import Awaitable, Mapping
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Literal, Protocol, cast, final

from pydantic import BaseModel, JsonValue, TypeAdapter, ValidationError

from consultation_kb.core.errors import (
    ScopedObjectAccessDeniedError,
    ToolError,
    map_exception_to_client_error,
)
from consultation_kb.models.common import ObjectId, StrictModel

from .schemas import (
    LoadClientContextInput,
    ToolAnnotations,
    ToolEnvelope,
)


ServiceSlot = Literal[
    "read",
    "graph",
    "session",
    "knowledge",
    "write",
    "evaluation",
]
_CLIENT_ID_RE = re.compile(r"client_[a-z0-9]{12}")
_CLIENT_ID_KEYS = frozenset(
    {
        "case_contributor_client_ids",
        "client_id",
        "client_ids",
        "private_owner_client_id",
        "source_client_id",
        "source_client_ids",
    }
)
_OBJECT_ID_ADAPTER = TypeAdapter(ObjectId)


@dataclass(frozen=True, slots=True)
class BoundTransport:
    """Non-sensitive invocation binding passed to a service adapter."""

    transport_session_id: str
    session_handle: str


class ToolService(Protocol):
    """Adapter boundary between transport handlers and domain services."""

    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object | Awaitable[object]: ...


@dataclass(frozen=True, slots=True)
class HandlerServices:
    read: ToolService
    graph: ToolService
    session: ToolService
    knowledge: ToolService
    write: ToolService
    evaluation: ToolService | None = None

    def for_slot(self, slot: ServiceSlot) -> ToolService:
        if slot == "read":
            return self.read
        if slot == "graph":
            return self.graph
        if slot == "session":
            return self.session
        if slot == "knowledge":
            return self.knowledge
        if slot == "write":
            return self.write
        if self.evaluation is None:
            raise RuntimeError("EVALUATION_RUNTIME_NOT_READY")
        return self.evaluation


class TaskScopeAlreadyBound(ScopedObjectAccessDeniedError):
    """A transport attempted to select a second client identity."""


class TransportLoadInProgress(ScopedObjectAccessDeniedError):
    """Concurrent context selection is rejected instead of racing."""


class SessionBindingUnavailable(ScopedObjectAccessDeniedError):
    """A bound client tool was called without its exact live handle."""


@dataclass(slots=True)
class _TransportState:
    client_binding_sha256: str
    session_handle: str | None
    load_in_progress: bool


@dataclass(frozen=True, slots=True)
class _LoadLease:
    transport_session_id: str
    client_binding_sha256: str
    previous_session_handle: str | None


@final
class TransportBindingRegistry:
    """Permanently bind one MCP transport to one opaque client digest.

    A failed first load releases its reservation.  Once a load succeeds, no
    method can remove or replace the client digest; a same-client resume may
    only rotate the opaque session handle.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._states: dict[str, _TransportState] = {}

    @staticmethod
    def _client_digest(client_id: str) -> str:
        return hashlib.sha256(
            b"consultation-mcp-client-binding\x00" + client_id.encode("ascii")
        ).hexdigest()

    @staticmethod
    def _transport_id(value: str) -> str:
        if (
            type(value) is not str
            or not value
            or any(ord(char) < 0x20 for char in value)
        ):
            raise SessionBindingUnavailable
        return value

    def begin_load(self, transport_session_id: str, client_id: str) -> _LoadLease:
        transport = self._transport_id(transport_session_id)
        digest = self._client_digest(client_id)
        with self._lock:
            state = self._states.get(transport)
            if state is None:
                self._states[transport] = _TransportState(
                    client_binding_sha256=digest,
                    session_handle=None,
                    load_in_progress=True,
                )
                return _LoadLease(transport, digest, None)
            if not hmac.compare_digest(state.client_binding_sha256, digest):
                raise TaskScopeAlreadyBound
            if state.load_in_progress:
                raise TransportLoadInProgress
            previous = state.session_handle
            state.load_in_progress = True
            return _LoadLease(transport, digest, previous)

    def complete_load(self, lease: _LoadLease, session_handle: str) -> BoundTransport:
        if type(session_handle) is not str or not session_handle:
            raise SessionBindingUnavailable
        with self._lock:
            state = self._states.get(lease.transport_session_id)
            if (
                state is None
                or not state.load_in_progress
                or not hmac.compare_digest(
                    state.client_binding_sha256,
                    lease.client_binding_sha256,
                )
            ):
                raise SessionBindingUnavailable
            state.session_handle = session_handle
            state.load_in_progress = False
        return BoundTransport(lease.transport_session_id, session_handle)

    def abort_load(self, lease: _LoadLease) -> None:
        with self._lock:
            state = self._states.get(lease.transport_session_id)
            if state is None or not hmac.compare_digest(
                state.client_binding_sha256,
                lease.client_binding_sha256,
            ):
                return
            state.load_in_progress = False
            state.session_handle = lease.previous_session_handle
            if lease.previous_session_handle is None:
                del self._states[lease.transport_session_id]

    def require_session(
        self,
        transport_session_id: str,
        session_handle: str,
    ) -> BoundTransport:
        transport = self._transport_id(transport_session_id)
        if type(session_handle) is not str or not session_handle:
            raise SessionBindingUnavailable
        with self._lock:
            state = self._states.get(transport)
            if (
                state is None
                or state.load_in_progress
                or state.session_handle is None
                or not hmac.compare_digest(state.session_handle, session_handle)
            ):
                raise SessionBindingUnavailable
        return BoundTransport(transport, session_handle)


@dataclass(frozen=True, slots=True)
class McpHandlerContext:
    transport_session_id: str
    bindings: TransportBindingRegistry
    services: HandlerServices

    def __post_init__(self) -> None:
        TransportBindingRegistry._transport_id(self.transport_session_id)
        if not isinstance(self.bindings, TransportBindingRegistry):
            raise TypeError("MCP context requires a transport binding registry")


def _normalise_json(value: object) -> JsonValue:
    if isinstance(value, BaseModel):
        return _normalise_json(value.model_dump(mode="json"))
    if is_dataclass(value) and not isinstance(value, type):
        return _normalise_json(asdict(value))
    if value is None or type(value) in (str, int, bool):
        return cast(JsonValue, value)
    if type(value) is float:
        if value != value or value in (float("inf"), float("-inf")):
            raise TypeError("non-finite tool results are forbidden")
        return cast(JsonValue, value)
    if isinstance(value, datetime):
        return cast(JsonValue, value.isoformat().replace("+00:00", "Z"))
    if isinstance(value, Enum):
        return _normalise_json(value.value)
    if isinstance(value, Mapping):
        rendered: dict[str, JsonValue] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("tool result mappings require string keys")
            rendered[key] = _normalise_json(item)
        return cast(JsonValue, rendered)
    if isinstance(value, (tuple, list)):
        return cast(JsonValue, [_normalise_json(item) for item in value])
    if isinstance(value, (set, frozenset)):
        rendered_items = [_normalise_json(item) for item in value]
        rendered_items.sort(
            key=lambda item: json.dumps(
                item,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return cast(JsonValue, rendered_items)
    raise TypeError("tool service returned a non-serializable value")


def _fixed_error(code: str, message: str) -> ToolEnvelope:
    return ToolEnvelope(
        ok=False,
        error=ToolError(code=code, message=message),
    )


def _error_envelope(error: BaseException) -> ToolEnvelope:
    if isinstance(error, ValidationError):
        return _fixed_error("INVALID_ARGUMENTS", "The tool arguments are invalid.")
    if isinstance(error, TaskScopeAlreadyBound):
        return _fixed_error(
            "TASK_SCOPE_ALREADY_BOUND",
            "This task is already bound to a different client scope.",
        )
    if isinstance(error, TransportLoadInProgress):
        return _fixed_error(
            "CONTEXT_LOAD_IN_PROGRESS",
            "A client context load is already in progress.",
        )
    mapped = map_exception_to_client_error(error)
    return ToolEnvelope(ok=False, error=mapped)


def _assert_no_client_identity(value: JsonValue) -> None:
    """Reject service DTOs that accidentally expose provenance identities."""

    if isinstance(value, str):
        if _CLIENT_ID_RE.search(value):
            raise TypeError("client identities are forbidden in MCP results")
        return
    if isinstance(value, list):
        for item in value:
            _assert_no_client_identity(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            # JSON object member names are outward data too.  Facet/grouping
            # DTOs commonly use dynamic keys, so scanning values alone leaves
            # a provenance-identity exfiltration channel.
            _assert_no_client_identity(key)
            if key in _CLIENT_ID_KEYS:
                raise TypeError("client identity fields are forbidden in MCP results")
            _assert_no_client_identity(item)


def _assert_create_client_result(value: JsonValue) -> None:
    """Allow exactly one intentional opaque client ID and nothing else."""

    if type(value) is not dict:
        raise TypeError("create client returned an invalid result")
    status = value.get("status")
    if status == "approval_required":
        expected = {"status", "client_id", "approval_request_id"}
    elif status == "active":
        expected = {"status", "client_id"}
    else:
        raise TypeError("create client returned an invalid result")
    if set(value) != expected:
        raise TypeError("create client returned an invalid result")
    client_id = value.get("client_id")
    if type(client_id) is not str or _CLIENT_ID_RE.fullmatch(client_id) is None:
        raise TypeError("create client returned an invalid result")
    if status == "approval_required":
        request_id = value.get("approval_request_id")
        try:
            validated = _OBJECT_ID_ADAPTER.validate_python(request_id, strict=True)
        except ValidationError:
            raise TypeError("create client returned an invalid result") from None
        if not validated.startswith("approval_request_"):
            raise TypeError("create client returned an invalid result")


def _session_handle_from_result(value: object) -> str:
    candidate: object
    if isinstance(value, BaseModel):
        candidate = value.model_dump(mode="python").get("session_handle")
    elif isinstance(value, Mapping):
        candidate = value.get("session_handle")
    else:
        candidate = getattr(value, "session_handle", None)
    if type(candidate) is not str or not candidate:
        raise SessionBindingUnavailable
    return candidate


@dataclass(frozen=True, slots=True)
class ToolHandler:
    """Callable pure-Python handler plus schema and registration annotations."""

    name: str
    input_model: type[StrictModel]
    annotations: ToolAnnotations
    context: McpHandlerContext
    service_slot: ServiceSlot
    requires_session_binding: bool = False
    loads_client_context: bool = False

    async def __call__(self, arguments: object) -> ToolEnvelope:
        lease: _LoadLease | None = None
        try:
            request = self.input_model.model_validate(arguments)
            binding: BoundTransport | None = None
            if self.loads_client_context:
                if not isinstance(request, LoadClientContextInput):
                    raise TypeError("client loader has the wrong input model")
                lease = self.context.bindings.begin_load(
                    self.context.transport_session_id,
                    request.client_id,
                )
            elif self.requires_session_binding:
                handle = getattr(request, "session_handle", None)
                if type(handle) is not str:
                    raise SessionBindingUnavailable
                binding = self.context.bindings.require_session(
                    self.context.transport_session_id,
                    handle,
                )
            service = self.context.services.for_slot(self.service_slot)
            value = service.invoke(self.name, request, binding=binding)
            if inspect.isawaitable(value):
                value = await value
            if lease is not None:
                handle = _session_handle_from_result(value)
                self.context.bindings.complete_load(lease, handle)
                lease = None
            result = _normalise_json(value)
            # ``create_client`` intentionally returns one opaque identity, but
            # it is not exempt from result validation or future leak checks.
            if self.name == "create_client":
                _assert_create_client_result(result)
            else:
                _assert_no_client_identity(result)
            return ToolEnvelope(ok=True, result=result)
        except Exception as error:
            return _error_envelope(error)
        finally:
            # asyncio cancellation inherits BaseException, not Exception.  A
            # context-selection lease must therefore be released on every
            # non-successful exit while allowing cancellation to propagate.
            if lease is not None:
                self.context.bindings.abort_load(lease)


def make_handler(
    *,
    name: str,
    input_model: type[StrictModel],
    annotations: ToolAnnotations,
    context: McpHandlerContext,
    service_slot: ServiceSlot,
    requires_session_binding: bool = False,
    loads_client_context: bool = False,
) -> ToolHandler:
    if requires_session_binding and loads_client_context:
        raise ValueError("a tool cannot load and require a context simultaneously")
    return ToolHandler(
        name=name,
        input_model=input_model,
        annotations=annotations,
        context=context,
        service_slot=service_slot,
        requires_session_binding=requires_session_binding,
        loads_client_context=loads_client_context,
    )


__all__ = [
    "BoundTransport",
    "HandlerServices",
    "McpHandlerContext",
    "ServiceSlot",
    "SessionBindingUnavailable",
    "TaskScopeAlreadyBound",
    "ToolHandler",
    "ToolService",
    "TransportBindingRegistry",
    "make_handler",
]
