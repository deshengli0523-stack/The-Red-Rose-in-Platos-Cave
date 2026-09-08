"""Single-process STDIO MCP transport for the consultation knowledge base."""

from __future__ import annotations

import inspect
import logging
import secrets
import sys
from collections.abc import Callable, Mapping
from typing import Any, cast

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.utilities.func_metadata import ArgModelBase
from mcp.types import ToolAnnotations as SdkToolAnnotations
from pydantic import ConfigDict
from pydantic.fields import FieldInfo

from consultation_kb.models.common import StrictModel

from . import (
    HandlerServices,
    McpHandlerContext,
    ToolEnvelope,
    ToolHandler,
    TransportBindingRegistry,
    build_handler_registry,
)
from .lifespan import DeferredHandlerServices, consultation_lifespan


_SERVER_NAME = "consultation-kb"
_SERVER_INSTRUCTIONS = (
    "Local, single-counselor consultation knowledge service. Load one client "
    "context before using client-bound tools; never infer or substitute scope."
)


class _RawToolArguments(ArgModelBase):
    """Preserve raw MCP arguments until our fixed-error strict handler.

    FastMCP otherwise validates the dynamic function signature first and
    includes Pydantic ``input_value`` text in protocol errors.  This model has
    no declared fields, accepts the JSON object verbatim, and deliberately
    forwards every key to ``_make_sdk_tool``.  The advertised schema remains
    the exact strict DTO and the handler performs the only domain validation.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    def model_dump_one_level(self) -> dict[str, Any]:
        return dict(self.__pydantic_extra__ or {})


def _field_annotation(field: FieldInfo) -> object:
    """Preserve Pydantic constraints when exposing one model field to FastMCP."""

    return field.rebuild_annotation()


def _tool_signature(handler: ToolHandler) -> inspect.Signature:
    parameters: list[inspect.Parameter] = []
    for name, field in handler.input_model.model_fields.items():
        default = inspect.Parameter.empty if field.is_required() else field.default
        parameters.append(
            inspect.Parameter(
                name,
                inspect.Parameter.KEYWORD_ONLY,
                default=default,
                annotation=_field_annotation(field),
            )
        )
    parameters.append(
        inspect.Parameter(
            "ctx",
            inspect.Parameter.KEYWORD_ONLY,
            annotation=Context,
        )
    )
    return inspect.Signature(parameters, return_annotation=ToolEnvelope)


def _sdk_annotations(handler: ToolHandler) -> SdkToolAnnotations:
    annotations = handler.annotations
    return SdkToolAnnotations(
        title=handler.name,
        readOnlyHint=annotations.read_only,
        destructiveHint=annotations.destructive,
        idempotentHint=annotations.read_only,
        openWorldHint=False,
    )


def _transport_identity(ctx: Context[Any, Any, Any]) -> str:
    """Return a stable, process-local identity for the active MCP session."""

    return f"stdio-session-{id(ctx.session):x}"


def _make_sdk_tool(
    handler_name: str,
    *,
    input_model: type[StrictModel],
    registry_for_transport: Callable[[str], Mapping[str, ToolHandler]],
) -> Callable[..., Any]:
    async def invoke(**arguments: object) -> ToolEnvelope:
        raw_context = arguments.pop("ctx", None)
        if not isinstance(raw_context, Context):
            raise RuntimeError("MCP_CONTEXT_UNAVAILABLE")
        registry = registry_for_transport(_transport_identity(raw_context))
        handler = registry[handler_name]
        return await handler(arguments)

    invoke.__name__ = handler_name
    invoke.__qualname__ = handler_name
    invoke.__doc__ = (
        f"Invoke the strict local {handler_name} consultation operation."
    )
    annotations: dict[str, object] = {
        name: _field_annotation(field)
        for name, field in input_model.model_fields.items()
    }
    annotations["ctx"] = Context
    annotations["return"] = ToolEnvelope
    invoke.__annotations__ = annotations
    return cast(Callable[..., Any], invoke)


def create_mcp(
    *,
    services: HandlerServices | DeferredHandlerServices | None = None,
    bindings: TransportBindingRegistry | None = None,
) -> FastMCP[Any]:
    """Build the exact current P9 tool registry without starting a transport."""

    if services is None:
        deferred = DeferredHandlerServices()
        handler_services = deferred.handler_services
        lifespan = consultation_lifespan(deferred)
    elif isinstance(services, DeferredHandlerServices):
        deferred = services
        handler_services = deferred.handler_services
        lifespan = None
    else:
        deferred = None
        handler_services = services
        lifespan = None
    binding_registry = bindings or TransportBindingRegistry()
    registries: dict[str, Mapping[str, ToolHandler]] = {}

    def registry_for_transport(
        transport_session_id: str,
    ) -> Mapping[str, ToolHandler]:
        registry = registries.get(transport_session_id)
        if registry is None:
            registry = build_handler_registry(
                McpHandlerContext(
                    transport_session_id=transport_session_id,
                    bindings=binding_registry,
                    services=handler_services,
                )
            )
            registries[transport_session_id] = registry
        return registry

    # One synthetic registry supplies the schemas and annotations. No client is
    # selected and no domain service is invoked during registration.
    schema_registry = registry_for_transport(
        f"schema-{secrets.token_hex(16)}"
    )
    server = FastMCP(
        _SERVER_NAME,
        instructions=_SERVER_INSTRUCTIONS,
        log_level="ERROR",
        lifespan=lifespan,
    )
    for name, handler in schema_registry.items():
        tool = _make_sdk_tool(
            name,
            input_model=handler.input_model,
            registry_for_transport=registry_for_transport,
        )
        tool.__signature__ = _tool_signature(handler)  # type: ignore[attr-defined]
        server.tool(
            name=name,
            description=tool.__doc__,
            annotations=_sdk_annotations(handler),
            structured_output=True,
        )(tool)
        # FastMCP builds a permissive synthetic argument model from the dynamic
        # function signature.  Runtime validation is already strict, but the
        # advertised MCP contract must be equally strict so clients never infer
        # that unknown scope selectors are accepted.  The SDK has no public
        # input-schema override in v1, so bind the exact Pydantic transport DTO
        # to its registered Tool under the pinned SDK version.
        registered = server._tool_manager.get_tool(name)  # noqa: SLF001
        if registered is None:
            raise RuntimeError("MCP_TOOL_REGISTRATION_FAILED")
        # SDK-side validation errors reflect raw ``input_value`` content into
        # CallToolResult.  Route every raw argument through our strict handler,
        # whose fixed envelope never reflects input, while keeping the public
        # schema closed below.
        registered.fn_metadata.arg_model = _RawToolArguments
        registered.parameters = handler.input_model.model_json_schema(
            by_alias=True
        )
    return server


def _configure_stderr_logging() -> None:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    root.addHandler(handler)
    root.setLevel(logging.ERROR)


def main() -> None:
    """Run the required STDIO endpoint; stdout remains SDK-owned."""

    _configure_stderr_logging()
    create_mcp().run("stdio")


if __name__ == "__main__":
    main()


__all__ = ["create_mcp", "main"]
