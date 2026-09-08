"""Read and retrieval handler registrations."""

from __future__ import annotations

from .context import McpHandlerContext, ToolHandler, make_handler
from .schemas import (
    LoadClientContextInput,
    READ_ANNOTATIONS,
    SearchCasesInput,
    SearchClientHistoryInput,
    SearchLexicalInput,
    SearchVectorInput,
    SearchWikiInput,
)


def build_read_handlers(context: McpHandlerContext) -> tuple[ToolHandler, ...]:
    return (
        make_handler(
            name="load_client_context",
            input_model=LoadClientContextInput,
            annotations=READ_ANNOTATIONS,
            context=context,
            service_slot="session",
            loads_client_context=True,
        ),
        make_handler(
            name="search_client_history",
            input_model=SearchClientHistoryInput,
            annotations=READ_ANNOTATIONS,
            context=context,
            service_slot="read",
            requires_session_binding=True,
        ),
        make_handler(
            name="search_wiki",
            input_model=SearchWikiInput,
            annotations=READ_ANNOTATIONS,
            context=context,
            service_slot="read",
            requires_session_binding=True,
        ),
        make_handler(
            name="search_lexical",
            input_model=SearchLexicalInput,
            annotations=READ_ANNOTATIONS,
            context=context,
            service_slot="read",
            requires_session_binding=True,
        ),
        make_handler(
            name="search_vector",
            input_model=SearchVectorInput,
            annotations=READ_ANNOTATIONS,
            context=context,
            service_slot="read",
            requires_session_binding=True,
        ),
        make_handler(
            name="search_cases",
            input_model=SearchCasesInput,
            annotations=READ_ANNOTATIONS,
            context=context,
            service_slot="read",
            requires_session_binding=True,
        ),
    )


__all__ = ["build_read_handlers"]
