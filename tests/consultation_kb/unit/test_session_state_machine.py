from __future__ import annotations

import pytest

from consultation_kb.session.state_machine import (
    InvalidTurnTransition,
    TurnStateMachine,
)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        ("client_turn_received", "generation_in_progress"),
        ("generation_in_progress", "candidates_generated"),
        ("candidates_generated", "awaiting_actual_reply"),
        ("awaiting_actual_reply", "actual_reply_recorded"),
        ("awaiting_actual_reply", "external_reply_unknown"),
        ("actual_reply_recorded", "turn_closed"),
        ("external_reply_unknown", "turn_closed"),
    ],
)
def test_only_frozen_turn_transitions_are_allowed(current: str, target: str) -> None:
    transition = TurnStateMachine.transition(
        current=current,
        target=target,
        payload_sha256="a" * 64,
    )

    assert transition.current == current
    assert transition.target == target
    assert transition.payload_sha256 == "a" * 64


@pytest.mark.parametrize(
    ("current", "target"),
    [
        ("client_turn_received", "awaiting_actual_reply"),
        ("generation_in_progress", "turn_closed"),
        ("awaiting_actual_reply", "turn_closed"),
        ("turn_closed", "client_turn_received"),
        ("awaiting_actual_reply", "awaiting_actual_reply"),
    ],
)
def test_transition_rejects_skips_terminal_reopen_and_duplicates(
    current: str,
    target: str,
) -> None:
    with pytest.raises(InvalidTurnTransition, match="TURN_STATE_TRANSITION_INVALID"):
        TurnStateMachine.transition(
            current=current,
            target=target,
            payload_sha256="b" * 64,
        )
