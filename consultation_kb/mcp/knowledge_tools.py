"""Global source, Claim, Wiki, lint, and C1 proposal handlers."""

from __future__ import annotations

from .context import McpHandlerContext, ToolHandler, make_handler
from .schemas import (
    DRAFT_WRITE_ANNOTATIONS,
    ExtractPassagesInput,
    KnowledgeLintInput,
    ListSourceInboxInput,
    PreviewClaimReviewInput,
    PreviewWikiUpdateInput,
    ProposeClaimsInput,
    ProposeTheoryRevisionInput,
    ProposeWikiUpdateInput,
    RegisterSourceDraftInput,
)


def build_knowledge_handlers(context: McpHandlerContext) -> tuple[ToolHandler, ...]:
    inputs = (
        ("list_source_inbox", ListSourceInboxInput),
        ("register_source_draft", RegisterSourceDraftInput),
        ("extract_passages", ExtractPassagesInput),
        ("propose_claims", ProposeClaimsInput),
        ("preview_claim_review", PreviewClaimReviewInput),
        ("propose_wiki_update", ProposeWikiUpdateInput),
        ("preview_wiki_update", PreviewWikiUpdateInput),
        ("knowledge_lint", KnowledgeLintInput),
        ("propose_theory_revision", ProposeTheoryRevisionInput),
    )
    return tuple(
        make_handler(
            name=name,
            input_model=input_model,
            annotations=DRAFT_WRITE_ANNOTATIONS,
            context=context,
            service_slot="knowledge",
        )
        for name, input_model in inputs
    )


__all__ = ["build_knowledge_handlers"]
