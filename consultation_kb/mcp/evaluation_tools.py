"""MCP registrations and adapter for the controlled evaluation runtime."""

from __future__ import annotations

from typing import final

from consultation_kb.evaluation.runtime import EvaluationRuntime
from consultation_kb.models.common import StrictModel

from .context import BoundTransport, McpHandlerContext, ToolHandler, make_handler
from .schemas import (
    DRAFT_WRITE_ANNOTATIONS,
    FinalizeEvaluationInput,
    GetNextEvaluationCaseInput,
    PrepareEvaluationInput,
    READ_ANNOTATIONS,
    SubmitEvaluationResultInput,
)


@final
class EvaluationToolRuntime:
    """Path-free ToolService adapter over one offline local runtime."""

    def __init__(self, runtime: EvaluationRuntime) -> None:
        if type(runtime) is not EvaluationRuntime:
            raise TypeError("evaluation tool runtime requires EvaluationRuntime")
        self._runtime = runtime

    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object:
        if binding is not None:
            raise RuntimeError("EVALUATION_CLIENT_BINDING_FORBIDDEN")
        if tool_name == "prepare_evaluation":
            if not isinstance(request, PrepareEvaluationInput):
                raise TypeError("prepare_evaluation received the wrong request")
            return self._runtime.prepare(
                evaluation_run_id=request.evaluation_run_id,
                fairness=request.fairness,
                route_policy_refs={
                    item.variant_name: item.route_policy_ref
                    for item in request.route_policies
                },
                variants=request.variants,
                repetition_count=request.repetition_count,
                case_ids=request.case_ids,
                include_canary=request.include_canary,
            )
        if tool_name == "get_next_evaluation_case":
            if not isinstance(request, GetNextEvaluationCaseInput):
                raise TypeError("get_next_evaluation_case received the wrong request")
            return self._runtime.get_next(request.evaluation_handle)
        if tool_name == "submit_evaluation_result":
            if not isinstance(request, SubmitEvaluationResultInput):
                raise TypeError("submit_evaluation_result received the wrong request")
            return self._runtime.submit(
                evaluation_handle=request.evaluation_handle,
                work_item_id=request.work_item_id,
                case_payload_sha256=request.case_payload_sha256,
                variant_sha256=request.variant_sha256,
                client_snapshot_ref=request.client_snapshot_ref,
                evidence_catalog_sha256=request.evidence_catalog_sha256,
                evidence_pack_sha256=request.evidence_pack_sha256,
                result=request.result,
            )
        if tool_name == "finalize_evaluation":
            if not isinstance(request, FinalizeEvaluationInput):
                raise TypeError("finalize_evaluation received the wrong request")
            return self._runtime.finalize(
                request.evaluation_handle,
                missing_reasons={
                    item.work_item_id: item.reason_code
                    for item in request.missing_reasons
                },
            )
        raise RuntimeError("EVALUATION_TOOL_UNAVAILABLE")


def build_evaluation_handlers(
    context: McpHandlerContext,
) -> tuple[ToolHandler, ...]:
    """Bind the four unscoped synthetic-evaluation operations."""

    definitions = (
        (
            "prepare_evaluation",
            PrepareEvaluationInput,
            DRAFT_WRITE_ANNOTATIONS,
        ),
        (
            "get_next_evaluation_case",
            GetNextEvaluationCaseInput,
            READ_ANNOTATIONS,
        ),
        (
            "submit_evaluation_result",
            SubmitEvaluationResultInput,
            DRAFT_WRITE_ANNOTATIONS,
        ),
        (
            "finalize_evaluation",
            FinalizeEvaluationInput,
            DRAFT_WRITE_ANNOTATIONS,
        ),
    )
    return tuple(
        make_handler(
            name=name,
            input_model=input_model,
            annotations=annotations,
            context=context,
            service_slot="evaluation",
        )
        for name, input_model, annotations in definitions
    )


__all__ = ["EvaluationToolRuntime", "build_evaluation_handlers"]
