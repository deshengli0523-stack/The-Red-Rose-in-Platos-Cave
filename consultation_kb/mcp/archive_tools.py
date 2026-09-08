"""Archive workflow registrations for the client-scoped session service."""

from __future__ import annotations

from .context import McpHandlerContext, ToolHandler, make_handler
from .schemas import (
    ApproveCaseInput,
    CommitPrivateArchiveInput,
    CommitProfileUpdateInput,
    DRAFT_WRITE_ANNOTATIONS,
    FORMAL_WRITE_ANNOTATIONS,
    PreviewPrivateArchiveInput,
    PreviewProfileDiffInput,
    ProposeArchiveInput,
)


def build_archive_handlers(
    context: McpHandlerContext,
) -> tuple[ToolHandler, ...]:
    """Bind all P7 archive operations to the already-scoped worker runtime."""

    draft_handlers = tuple(
        make_handler(
            name=name,
            input_model=input_model,
            annotations=DRAFT_WRITE_ANNOTATIONS,
            context=context,
            service_slot="session",
            requires_session_binding=True,
        )
        for name, input_model in (
            ("propose_archive", ProposeArchiveInput),
            ("preview_private_archive", PreviewPrivateArchiveInput),
            ("preview_profile_diff", PreviewProfileDiffInput),
        )
    )
    formal_handlers = tuple(
        make_handler(
            name=name,
            input_model=input_model,
            annotations=FORMAL_WRITE_ANNOTATIONS,
            context=context,
            service_slot="session",
            requires_session_binding=True,
        )
        for name, input_model in (
            ("commit_private_archive", CommitPrivateArchiveInput),
            ("commit_profile_update", CommitProfileUpdateInput),
            ("approve_case", ApproveCaseInput),
        )
    )
    return (
        draft_handlers[0],
        draft_handlers[1],
        formal_handlers[0],
        draft_handlers[2],
        formal_handlers[1],
        formal_handlers[2],
    )


__all__ = ["build_archive_handlers"]
