"""Pure ordering, parent-closure, and bounded-retry validation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from consultation_kb.generation.contracts import (
    ConsistencyRiskReview,
    EvidenceAudit,
    GenerationStagePayload,
    QueryPlan,
)
from consultation_kb.models.generation import GenerationStageName


GENERATION_STAGE_ORDER: tuple[GenerationStageName, ...] = (
    "query_plan",
    "conceptualization",
    "theory_comparison",
    "reply_drafts",
    "evidence_audit",
    "consistency_risk_review",
    "final_bundle",
)


class GenerationStateError(RuntimeError):
    """Base class whose messages are stable machine error codes."""


class GenerationStageOrderError(GenerationStateError):
    def __init__(self) -> None:
        super().__init__("GENERATION_STAGE_ORDER_INVALID")


class GenerationParentMismatch(GenerationStateError):
    def __init__(self) -> None:
        super().__init__("GENERATION_PARENT_MISMATCH")


class QualityRetryExhausted(GenerationStateError):
    def __init__(self) -> None:
        super().__init__("QUALITY_RETRY_EXHAUSTED")


class GenerationRetrySequenceError(GenerationStateError):
    def __init__(self) -> None:
        super().__init__("QUALITY_RETRY_SEQUENCE_INVALID")


@dataclass(frozen=True, slots=True)
class GenerationTransition:
    stage: GenerationStageName
    previous_stage: GenerationStageName | None
    revising: bool
    required_parent_sha256s: tuple[str, ...]


class GenerationStateMachine:
    """Validate one proposed stage against immutable active-stage hashes."""

    @staticmethod
    def validate_next(
        existing_stage_sha256s: Mapping[GenerationStageName, str],
        payload: GenerationStagePayload,
    ) -> GenerationTransition:
        existing = dict(existing_stage_sha256s)
        if set(existing) - set(GENERATION_STAGE_ORDER):
            raise GenerationStageOrderError
        present = [stage for stage in GENERATION_STAGE_ORDER if stage in existing]
        if present != list(GENERATION_STAGE_ORDER[: len(present)]):
            raise GenerationStageOrderError

        stage = payload.envelope.stage
        stage_index = GENERATION_STAGE_ORDER.index(stage)
        next_index = len(present)
        revising = stage_index < next_index
        if stage_index > next_index:
            raise GenerationStageOrderError

        previous_stage = (
            None if stage_index == 0 else GENERATION_STAGE_ORDER[stage_index - 1]
        )
        if isinstance(payload, QueryPlan):
            required_parents: tuple[str, ...] = ()
        else:
            if previous_stage is None or previous_stage not in existing:
                raise GenerationStageOrderError
            required_parents = tuple(
                sorted(
                    {
                        existing[previous_stage],
                        payload.evidence_pack_sha256,
                    }
                )
            )
        if payload.envelope.parent_sha256s != required_parents:
            raise GenerationParentMismatch

        if isinstance(payload, (EvidenceAudit, ConsistencyRiskReview)) and (
            payload.decision in {"retrieve_more", "rewrite"}
            and payload.retry_count >= 2
        ):
            raise QualityRetryExhausted

        return GenerationTransition(
            stage=stage,
            previous_stage=previous_stage,
            revising=revising,
            required_parent_sha256s=required_parents,
        )

    @staticmethod
    def validate_retry_sequence(
        previous: GenerationStagePayload | None,
        current: GenerationStagePayload,
    ) -> None:
        if not isinstance(current, (EvidenceAudit, ConsistencyRiskReview)):
            return
        if previous is None:
            if current.retry_count != 0:
                raise GenerationRetrySequenceError
            return
        if type(previous) is not type(current):
            raise GenerationRetrySequenceError
        if previous.retry_count + 1 != current.retry_count:
            raise GenerationRetrySequenceError


__all__ = [
    "GENERATION_STAGE_ORDER",
    "GenerationParentMismatch",
    "GenerationRetrySequenceError",
    "GenerationStageOrderError",
    "GenerationStateError",
    "GenerationStateMachine",
    "GenerationTransition",
    "QualityRetryExhausted",
]
