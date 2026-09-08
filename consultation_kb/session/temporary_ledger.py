"""Append-only session-local facts that never become approved long-term facts."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from pydantic import ValidationError

from consultation_kb.models.facts import CognitiveType
from consultation_kb.models.session import (
    TemporaryFactEvent,
    TemporaryFactKind,
)
from consultation_kb.session.repository import SessionClosed, SessionRepository
from consultation_kb.storage.connection import transaction


class TemporaryLedgerError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("TEMPORARY_LEDGER_INVALID")


class TemporaryLedgerConflict(TemporaryLedgerError):
    def __init__(self, code: str = "TEMPORARY_FACT_IDEMPOTENCY_CONFLICT") -> None:
        RuntimeError.__init__(self, code)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_hash(value: object) -> str:
    return _sha256(
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
    )


def _idempotency_hash(value: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError("idempotency_key must be nonblank")
    return _sha256(b"session-temporary-fact\x00" + value.encode("utf-8"))


def temporary_fact_from_row(row: tuple[object, ...]) -> TemporaryFactEvent:
    if len(row) != 12:
        raise TemporaryLedgerError
    try:
        from consultation_kb.session.repository import _parse_utc

        return TemporaryFactEvent.model_validate(
            {
                "event_id": row[0],
                "session_id": row[1],
                "turn_id": row[2],
                "event_kind": row[3],
                "cognitive_type": row[4],
                "content": {
                    "object_id": row[5],
                    "content_sha256": row[6],
                    "media_type": row[7],
                    "size_bytes": row[8],
                },
                "target_fact_id": row[9],
                "target_fact_version": row[10],
                "recorded_at": _parse_utc(row[11]),
            }
        )
    except (TypeError, ValueError, ValidationError):
        raise TemporaryLedgerError from None


class TemporaryFactLedger:
    def __init__(self, repository: SessionRepository) -> None:
        self._repository = repository

    def _existing(
        self,
        session_id: str,
        *,
        idempotency_key_sha256: str,
        operation_sha256: str,
    ) -> TemporaryFactEvent | None:
        row = self._repository.connection.execute(
            """
            SELECT session_event_id, operation_sha256
              FROM session_fact_events
             WHERE session_id = ? AND idempotency_key_sha256 = ?
            """,
            (session_id, idempotency_key_sha256),
        ).fetchone()
        if row is None:
            return None
        if row[1] != operation_sha256:
            raise TemporaryLedgerConflict
        event_row = self._repository.connection.execute(
            """
            SELECT session_event_id, session_id, turn_id, event_kind,
                   cognitive_type, content_object_id, content_sha256,
                   content_media_type, content_size_bytes, target_fact_id,
                   target_fact_version, recorded_at
              FROM session_fact_events WHERE session_event_id = ?
            """,
            (row[0],),
        ).fetchone()
        if event_row is None:
            raise TemporaryLedgerConflict("TEMPORARY_FACT_INTEGRITY_ERROR")
        return temporary_fact_from_row(tuple(event_row))

    def propose(
        self,
        session_id: str,
        turn_id: str,
        *,
        event_kind: TemporaryFactKind,
        cognitive_type: CognitiveType,
        value: Any,
        target_fact_id: str | None = None,
        target_fact_version: int | None = None,
        idempotency_key: str,
    ) -> TemporaryFactEvent:
        try:
            body = (
                json.dumps(
                    value,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError):
            raise ValueError("temporary fact value must be finite JSON") from None
        idempotency_key_sha256 = _idempotency_hash(idempotency_key)
        operation_sha256 = _canonical_hash(
            {
                "body_sha256": _sha256(body),
                "cognitive_type": cognitive_type,
                "event_kind": event_kind,
                "target_fact_id": target_fact_id,
                "target_fact_version": target_fact_version,
                "turn_id": turn_id,
            }
        )
        existing = self._existing(
            session_id,
            idempotency_key_sha256=idempotency_key_sha256,
            operation_sha256=operation_sha256,
        )
        if existing is not None:
            return existing

        session = self._repository.get_session(session_id)
        turn = self._repository.get_turn(session_id, turn_id)
        if session.status != "OPEN" or turn.state == "turn_closed":
            raise SessionClosed
        content = self._repository.store_json(body, kind="session_fact")
        recorded_at = self._repository.clock.now()
        event = TemporaryFactEvent(
            event_id=self._repository.id_factory.object_id("session_fact"),
            session_id=session_id,
            turn_id=turn_id,
            event_kind=event_kind,
            cognitive_type=cognitive_type,
            content=content,
            target_fact_id=target_fact_id,
            target_fact_version=target_fact_version,
            recorded_at=recorded_at,
        )
        metadata = json.dumps(
            {
                "content_sha256": content.content_sha256,
                "schema_version": "session_fact_event.v1",
            },
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        from consultation_kb.session.repository import _utc_text

        try:
            with transaction(self._repository.connection):
                self._repository.connection.execute(
                    """
                    INSERT INTO session_fact_events(
                        session_event_id, session_id, turn_id, event_kind,
                        event_json, recorded_at, cognitive_type,
                        content_object_id, content_sha256, content_media_type,
                        content_size_bytes, target_fact_id, target_fact_version,
                        idempotency_key_sha256, operation_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id,
                        event.session_id,
                        event.turn_id,
                        event.event_kind,
                        metadata,
                        _utc_text(event.recorded_at),
                        event.cognitive_type,
                        event.content.object_id,
                        event.content.content_sha256,
                        event.content.media_type,
                        event.content.size_bytes,
                        event.target_fact_id,
                        event.target_fact_version,
                        idempotency_key_sha256,
                        operation_sha256,
                    ),
                )
        except sqlite3.IntegrityError:
            existing = self._existing(
                session_id,
                idempotency_key_sha256=idempotency_key_sha256,
                operation_sha256=operation_sha256,
            )
            if existing is not None:
                return existing
            raise TemporaryLedgerConflict("TEMPORARY_FACT_WRITE_CONFLICT") from None
        return event

    def correct(
        self,
        session_id: str,
        turn_id: str,
        *,
        target_fact_id: str,
        target_fact_version: int,
        value: Any,
        idempotency_key: str,
    ) -> TemporaryFactEvent:
        return self.propose(
            session_id,
            turn_id,
            event_kind="CORRECT",
            cognitive_type="client_statement",
            value=value,
            target_fact_id=target_fact_id,
            target_fact_version=target_fact_version,
            idempotency_key=idempotency_key,
        )

    def conflict(
        self,
        session_id: str,
        turn_id: str,
        *,
        target_fact_id: str,
        target_fact_version: int,
        value: Any,
        idempotency_key: str,
    ) -> TemporaryFactEvent:
        return self.propose(
            session_id,
            turn_id,
            event_kind="CONFLICT",
            cognitive_type="interpretation",
            value=value,
            target_fact_id=target_fact_id,
            target_fact_version=target_fact_version,
            idempotency_key=idempotency_key,
        )

    def snapshot(
        self,
        session_id: str,
        *,
        turn_id: str | None = None,
    ) -> tuple[TemporaryFactEvent, ...]:
        events = self._repository.list_temporary_facts(session_id)
        if turn_id is None:
            return events
        return tuple(event for event in events if event.turn_id == turn_id)


__all__ = [
    "TemporaryFactLedger",
    "TemporaryLedgerConflict",
    "TemporaryLedgerError",
    "temporary_fact_from_row",
]
