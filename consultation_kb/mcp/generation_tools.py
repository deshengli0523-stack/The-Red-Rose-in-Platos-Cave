"""Generation-stage and counselor-only risk handler registrations."""

from __future__ import annotations

from .context import McpHandlerContext, ToolHandler, make_handler
from .schemas import (
    AcknowledgeRiskObservationInput,
    DRAFT_WRITE_ANNOTATIONS,
    GetGenerationStateInput,
    READ_ANNOTATIONS,
    SubmitGenerationStageInput,
)


def build_generation_handlers(
    context: McpHandlerContext,
) -> tuple[ToolHandler, ...]:
    """Bind all P6 operations to the existing client-scoped session service."""

    return (
        make_handler(
            name="submit_generation_stage",
            input_model=SubmitGenerationStageInput,
            annotations=DRAFT_WRITE_ANNOTATIONS,
            context=context,
            service_slot="session",
            requires_session_binding=True,
        ),
        make_handler(
            name="get_generation_state",
            input_model=GetGenerationStateInput,
            annotations=READ_ANNOTATIONS,
            context=context,
            service_slot="session",
            requires_session_binding=True,
        ),
        make_handler(
            name="acknowledge_risk_observation",
            input_model=AcknowledgeRiskObservationInput,
            annotations=DRAFT_WRITE_ANNOTATIONS,
            context=context,
            service_slot="session",
            requires_session_binding=True,
        ),
    )


__all__ = ["build_generation_handlers"]
