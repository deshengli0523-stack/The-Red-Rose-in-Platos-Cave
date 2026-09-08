"""Approval-bound formal write handler registrations."""

from __future__ import annotations

from .context import McpHandlerContext, ToolHandler, make_handler
from .schemas import (
    ApproveClaimInput,
    ApprovePassageInput,
    ApproveTheoryRevisionInput,
    CreateClientInput,
    FORMAL_WRITE_ANNOTATIONS,
    PublishWikiInput,
    RevokeClaimInput,
    RevokeTheoryRevisionInput,
)


def build_write_handlers(context: McpHandlerContext) -> tuple[ToolHandler, ...]:
    inputs = (
        ("create_client", CreateClientInput),
        ("approve_passage", ApprovePassageInput),
        ("approve_claim", ApproveClaimInput),
        ("revoke_claim", RevokeClaimInput),
        ("publish_wiki", PublishWikiInput),
        ("approve_theory_revision", ApproveTheoryRevisionInput),
        ("revoke_theory_revision", RevokeTheoryRevisionInput),
    )
    return tuple(
        make_handler(
            name=name,
            input_model=input_model,
            annotations=FORMAL_WRITE_ANNOTATIONS,
            context=context,
            service_slot="write",
        )
        for name, input_model in inputs
    )


__all__ = ["build_write_handlers"]
