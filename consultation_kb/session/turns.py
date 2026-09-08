"""High-level append and generation-start operations for one turn."""

from __future__ import annotations

import hashlib
import json

from consultation_kb.models.session import TurnRecord
from consultation_kb.session.repository import SessionRepository


def _operation_hash(value: object) -> str:
    encoded = (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


class TurnService:
    def __init__(self, repository: SessionRepository) -> None:
        self._repository = repository

    def append(self, session_id: str, turn_id: str, message: str) -> TurnRecord:
        return self._repository.append_client_turn(session_id, turn_id, message)

    def begin_generation(
        self,
        session_id: str,
        turn_id: str,
        *,
        run_id: str,
    ) -> TurnRecord:
        return self._repository.transition_turn(
            session_id,
            turn_id,
            target="generation_in_progress",
            payload_sha256=_operation_hash(
                {"operation": "begin_generation", "run_id": run_id}
            ),
            active_run_id=run_id,
        )


__all__ = ["TurnService"]
