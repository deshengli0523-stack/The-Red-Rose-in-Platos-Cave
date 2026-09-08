"""Governed global/client graph handler registrations."""

from __future__ import annotations

from .context import McpHandlerContext, ToolHandler, make_handler
from .schemas import (
    PreviewDependencyImpactInput,
    QueryClientGraphInput,
    QueryGlobalGraphInput,
    READ_ANNOTATIONS,
    WeightedPathInput,
)


def build_graph_handlers(context: McpHandlerContext) -> tuple[ToolHandler, ...]:
    inputs = (
        ("query_global_graph", QueryGlobalGraphInput),
        ("query_client_graph", QueryClientGraphInput),
        ("weighted_path", WeightedPathInput),
        ("preview_dependency_impact", PreviewDependencyImpactInput),
    )
    return tuple(
        make_handler(
            name=name,
            input_model=input_model,
            annotations=READ_ANNOTATIONS,
            context=context,
            service_slot="graph",
            requires_session_binding=True,
        )
        for name, input_model in inputs
    )


__all__ = ["build_graph_handlers"]
