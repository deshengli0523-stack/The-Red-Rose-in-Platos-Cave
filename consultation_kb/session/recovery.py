"""Rebuild a consultation solely from committed client-scope records."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import Field

from consultation_kb.models.common import ObjectId, StrictModel
from consultation_kb.models.session import (
    ActualReply,
    SessionRecord,
    TemporaryFactEvent,
    TurnRecord,
)
from consultation_kb.session.context import ClientContextSnapshot
from consultation_kb.session.repository import (
    SessionConflict,
    SessionRepository,
    TurnStateConflict,
)
from consultation_kb.storage.connection import transaction


RecoveryAction = Literal[
    "begin_generation",
    "regenerate",
    "record_actual_reply",
    "ready_for_next_turn",
    "session_closed",
]


class RecoveryState(StrictModel):
    session: SessionRecord
    snapshot: ClientContextSnapshot
    turns: tuple[TurnRecord, ...]
    actual_conversation: tuple[ActualReply, ...]
    temporary_facts: tuple[TemporaryFactEvent, ...]
    active_turn: TurnRecord | None
    pending_action: RecoveryAction
    incomplete_evidence: bool
    discarded_stage_artifact_ids: tuple[ObjectId, ...] = Field(
        json_schema_extra={"uniqueItems": True}
    )


def _hash(value: object) -> str:
    return hashlib.sha256(
        (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
    ).hexdigest()


class SessionRecovery:
    def __init__(self, repository: SessionRepository) -> None:
        self._repository = repository

    def _discard_interrupted_generation(
        self,
        session_id: str,
        active: TurnRecord,
    ) -> tuple[ObjectId, ...]:
        """Atomically retire persisted work from one interrupted generation run."""

        if active.state != "generation_in_progress" or active.active_run_id is None:
            raise SessionConflict("SESSION_RECOVERY_RUN_INVALID")
        from consultation_kb.session.repository import _utc_text

        with transaction(self._repository.connection):
            current = self._repository.get_turn(session_id, active.turn_id)
            if (
                current.state != "generation_in_progress"
                or current.active_run_id != active.active_run_id
            ):
                raise TurnStateConflict
            rows = self._repository.connection.execute(
                """
                SELECT stage_artifact_id
                  FROM generation_stage_artifacts
                 WHERE session_id = ? AND turn_id = ? AND run_id = ?
                   AND status = 'ACTIVE'
                 ORDER BY created_at, stage_artifact_id
                """,
                (session_id, active.turn_id, active.active_run_id),
            ).fetchall()
            discarded = tuple(str(row[0]) for row in rows)
            latest_checkpoint = self._repository.connection.execute(
                """
                SELECT event_kind
                  FROM session_checkpoints
                 WHERE session_id = ? AND turn_id = ?
                 ORDER BY checkpoint_sequence DESC
                 LIMIT 1
                """,
                (session_id, active.turn_id),
            ).fetchone()
            if not discarded and latest_checkpoint == ("generation_run_restarted",):
                return ()
            new_run_id = self._repository.id_factory.uuid7()
            now = self._repository.clock.now()
            if discarded:
                changed = self._repository.connection.execute(
                    """
                    UPDATE generation_stage_artifacts
                       SET status = 'DISCARDED', discarded_at = ?
                     WHERE session_id = ? AND turn_id = ? AND run_id = ?
                       AND status = 'ACTIVE'
                    """,
                    (
                        _utc_text(now),
                        session_id,
                        active.turn_id,
                        active.active_run_id,
                    ),
                ).rowcount
                if changed != len(discarded):
                    raise SessionConflict("SESSION_RECOVERY_STAGE_CONFLICT")
            changed = self._repository.connection.execute(
                """
                UPDATE turns
                   SET active_run_id = ?, updated_at = ?
                 WHERE session_id = ? AND turn_id = ?
                   AND state = 'generation_in_progress' AND active_run_id = ?
                """,
                (
                    new_run_id,
                    _utc_text(now),
                    session_id,
                    active.turn_id,
                    active.active_run_id,
                ),
            ).rowcount
            if changed != 1:
                raise TurnStateConflict
            self._repository.connection.execute(
                "UPDATE sessions SET updated_at = ? WHERE session_id = ?",
                (_utc_text(now), session_id),
            )
            self._repository._insert_checkpoint(
                session_id=session_id,
                turn_id=active.turn_id,
                current="generation_in_progress",
                target="generation_in_progress",
                payload_sha256=_hash(
                    {
                        "discarded_stage_artifact_ids": discarded,
                        "new_run_id": new_run_id,
                        "old_run_id": active.active_run_id,
                    }
                ),
                event_kind="generation_run_restarted",
                created_at=now,
            )
        return discarded

    def _build(self, session_id: str, *, recover: bool) -> RecoveryState:
        session = self._repository.get_session(session_id)
        try:
            snapshot = ClientContextSnapshot.model_validate_json(
                self._repository.read_snapshot(session_id)
            )
        except Exception:
            raise SessionConflict("SESSION_SNAPSHOT_INVALID") from None
        if (
            snapshot.client_id != session.client_id
            or snapshot.profile_version != session.client_snapshot_version
            or snapshot.canonical_sha256
            != session.client_snapshot_canonical_sha256
        ):
            raise SessionConflict("SESSION_SNAPSHOT_INVALID")

        turns = self._repository.list_turns(session_id)
        active = next((turn for turn in reversed(turns) if turn.state != "turn_closed"), None)
        if recover and active is not None and active.state == "generation_in_progress":
            self._discard_interrupted_generation(session_id, active)
        elif recover and active is not None and active.state == "candidates_generated":
            candidate_set = self._repository.get_candidate_set(session_id, active.turn_id)
            self._repository.transition_turn(
                session_id,
                active.turn_id,
                target="awaiting_actual_reply",
                payload_sha256=_hash(
                    {
                        "candidate_set_sha256": candidate_set.set_sha256,
                        "recovery": "awaiting_actual_reply",
                    }
                ),
                active_run_id=active.active_run_id,
            )
        elif recover and active is not None and active.state in {
            "actual_reply_recorded",
            "external_reply_unknown",
        }:
            actual = self._repository.connection.execute(
                "SELECT operation_sha256 FROM actual_replies "
                "WHERE session_id = ? AND turn_id = ?",
                (session_id, active.turn_id),
            ).fetchone()
            if actual is None:
                raise SessionConflict("SESSION_RECOVERY_ACTUAL_REPLY_MISSING")
            self._repository.transition_turn(
                session_id,
                active.turn_id,
                target="turn_closed",
                payload_sha256=_hash(
                    {"actual_reply_sha256": actual[0], "recovery": "turn_closed"}
                ),
            )

        turns = self._repository.list_turns(session_id)
        active = next((turn for turn in reversed(turns) if turn.state != "turn_closed"), None)
        if session.status != "OPEN":
            action: RecoveryAction = "session_closed"
        elif active is None:
            action = "ready_for_next_turn"
        elif active.state == "client_turn_received":
            action = "begin_generation"
        elif active.state == "generation_in_progress":
            action = "regenerate"
        elif active.state == "awaiting_actual_reply":
            action = "record_actual_reply"
        else:
            raise SessionConflict("SESSION_RECOVERY_STATE_INVALID")

        discarded = tuple(
            str(row[0])
            for row in self._repository.connection.execute(
                "SELECT stage_artifact_id FROM generation_stage_artifacts "
                "WHERE session_id = ? AND status = 'DISCARDED' "
                "ORDER BY discarded_at, stage_artifact_id",
                (session_id,),
            ).fetchall()
        )
        actuals = self._repository.list_actual_replies(session_id)
        return RecoveryState(
            session=self._repository.get_session(session_id),
            snapshot=snapshot,
            turns=turns,
            actual_conversation=actuals,
            temporary_facts=self._repository.list_temporary_facts(session_id),
            active_turn=active,
            pending_action=action,
            incomplete_evidence=any(reply.evidence_gap for reply in actuals),
            discarded_stage_artifact_ids=discarded,
        )

    def inspect(self, session_id: str) -> RecoveryState:
        """Read committed recovery state without advancing or rotating it."""

        return self._build(session_id, recover=False)

    def resume(self, session_id: str) -> RecoveryState:
        """Repair committed intermediate states and return the resumable state."""

        return self._build(session_id, recover=True)


__all__ = ["RecoveryAction", "RecoveryState", "SessionRecovery"]
