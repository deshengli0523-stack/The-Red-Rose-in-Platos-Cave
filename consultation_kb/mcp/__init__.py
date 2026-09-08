"""Pure MCP boundary exported for FastMCP registration by the server layer."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from .context import (
    BoundTransport,
    HandlerServices,
    McpHandlerContext,
    ToolHandler,
    ToolService,
    TransportBindingRegistry,
)
from .archive_tools import build_archive_handlers
from .evaluation_tools import build_evaluation_handlers
from .graph_tools import build_graph_handlers
from .generation_tools import build_generation_handlers
from .knowledge_tools import build_knowledge_handlers
from .lifecycle_tools import build_lifecycle_handlers
from .read_tools import build_read_handlers
from .schemas import TOOL_INPUT_MODELS, ToolEnvelope
from .session_tools import build_session_handlers
from .write_tools import build_write_handlers


P5_TOOL_NAMES: tuple[str, ...] = (
    "load_client_context",
    "search_client_history",
    "search_wiki",
    "search_lexical",
    "search_vector",
    "search_cases",
    "query_global_graph",
    "query_client_graph",
    "weighted_path",
    "preview_dependency_impact",
    "append_session_turn",
    "append_temporary_fact",
    "store_candidate_set",
    "record_actual_reply",
    "list_source_inbox",
    "register_source_draft",
    "extract_passages",
    "propose_claims",
    "preview_claim_review",
    "propose_wiki_update",
    "preview_wiki_update",
    "knowledge_lint",
    "propose_theory_revision",
    "create_client",
    "approve_passage",
    "approve_claim",
    "revoke_claim",
    "publish_wiki",
    "approve_theory_revision",
    "revoke_theory_revision",
)

P6_TOOL_NAMES: tuple[str, ...] = (
    *P5_TOOL_NAMES[:14],
    "submit_generation_stage",
    "get_generation_state",
    "acknowledge_risk_observation",
    *P5_TOOL_NAMES[14:],
)

P7_TOOL_NAMES: tuple[str, ...] = (
    *P6_TOOL_NAMES,
    "propose_archive",
    "preview_private_archive",
    "commit_private_archive",
    "preview_profile_diff",
    "commit_profile_update",
    "approve_case",
)

P8_TOOL_NAMES: tuple[str, ...] = (
    *P7_TOOL_NAMES,
    "rollback_version",
    "start_rebuild",
    "get_rebuild_status",
    "get_rebuild_report",
    "cancel_rebuild",
    "preview_rebuild",
    "preview_delete",
    "commit_delete",
)

P9_TOOL_NAMES: tuple[str, ...] = (
    *P8_TOOL_NAMES,
    "prepare_evaluation",
    "get_next_evaluation_case",
    "submit_evaluation_result",
    "finalize_evaluation",
)


def build_handler_registry(
    context: McpHandlerContext,
) -> Mapping[str, ToolHandler]:
    """Return the exact current P9 registry without binding to a transport SDK."""

    handlers = (
        *build_read_handlers(context),
        *build_graph_handlers(context),
        *build_session_handlers(context),
        *build_generation_handlers(context),
        *build_knowledge_handlers(context),
        *build_write_handlers(context),
        *build_archive_handlers(context),
        *build_lifecycle_handlers(context),
        *build_evaluation_handlers(context),
    )
    registry = {handler.name: handler for handler in handlers}
    if len(registry) != len(handlers):
        raise RuntimeError("duplicate MCP handler registration")
    if tuple(registry) != P9_TOOL_NAMES or set(registry) != set(TOOL_INPUT_MODELS):
        raise RuntimeError("P9 MCP handler registry does not match its schema set")
    return MappingProxyType(registry)


__all__ = [
    "BoundTransport",
    "HandlerServices",
    "McpHandlerContext",
    "P5_TOOL_NAMES",
    "P6_TOOL_NAMES",
    "P7_TOOL_NAMES",
    "P8_TOOL_NAMES",
    "P9_TOOL_NAMES",
    "ToolEnvelope",
    "ToolHandler",
    "ToolService",
    "TransportBindingRegistry",
    "build_handler_registry",
]
