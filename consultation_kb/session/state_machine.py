"""Pure frozen turn-state transition contract."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import TypeAdapter, ValidationError

from consultation_kb.models.common import Sha256Hex
from consultation_kb.models.session import TurnState


_STATE_ADAPTER: TypeAdapter[TurnState] = TypeAdapter(TurnState)
_HASH_ADAPTER: TypeAdapter[str] = TypeAdapter(Sha256Hex)
_ALLOWED: frozenset[tuple[TurnState, TurnState]] = frozenset(
    {
        ("client_turn_received", "generation_in_progress"),
        ("generation_in_progress", "candidates_generated"),
        ("candidates_generated", "awaiting_actual_reply"),
        ("awaiting_actual_reply", "actual_reply_recorded"),
        ("awaiting_actual_reply", "external_reply_unknown"),
        ("actual_reply_recorded", "turn_closed"),
        ("external_reply_unknown", "turn_closed"),
    }
)


class InvalidTurnTransition(RuntimeError):
    def __init__(self) -> None:
        super().__init__("TURN_STATE_TRANSITION_INVALID")


@dataclass(frozen=True, slots=True)
class TurnTransition:
    current: TurnState
    target: TurnState
    payload_sha256: str


class TurnStateMachine:
    @staticmethod
    def transition(
        *,
        current: str,
        target: str,
        payload_sha256: str,
    ) -> TurnTransition:
        try:
            validated_current = _STATE_ADAPTER.validate_python(current, strict=True)
            validated_target = _STATE_ADAPTER.validate_python(target, strict=True)
            validated_payload = _HASH_ADAPTER.validate_python(
                payload_sha256,
                strict=True,
            )
        except ValidationError:
            raise InvalidTurnTransition from None
        if (validated_current, validated_target) not in _ALLOWED:
            raise InvalidTurnTransition
        return TurnTransition(
            current=validated_current,
            target=validated_target,
            payload_sha256=validated_payload,
        )


__all__ = ["InvalidTurnTransition", "TurnStateMachine", "TurnTransition"]
