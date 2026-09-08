"""Session draft and actual-reply handler registrations."""

from __future__ import annotations

from .context import McpHandlerContext, ToolHandler, make_handler
from .schemas import (
    AppendSessionTurnInput,
    AppendTemporaryFactInput,
    DRAFT_WRITE_ANNOTATIONS,
    RecordActualReplyInput,
    StoreCandidateSetInput,
)


def build_session_handlers(context: McpHandlerContext) -> tuple[ToolHandler, ...]:
    inputs = (
        ("append_session_turn", AppendSessionTurnInput),
        ("append_temporary_fact", AppendTemporaryFactInput),
        ("store_candidate_set", StoreCandidateSetInput),
        ("record_actual_reply", RecordActualReplyInput),
    )
    return tuple(
        make_handler(
            name=name,
            input_model=input_model,
            annotations=DRAFT_WRITE_ANNOTATIONS,
            context=context,
            service_slot="session",
            requires_session_binding=True,
        )
        for name, input_model in inputs
    )


__all__ = ["build_session_handlers"]
