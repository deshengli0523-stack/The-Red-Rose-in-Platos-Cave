"""Append-only repository for one physically scoped client session database."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta
from typing import cast

from pydantic import TypeAdapter, ValidationError

from consultation_kb.core.clock import Clock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import ClientId, Sha256Hex, Uuid7String
from consultation_kb.models.session import (
    ActualReply,
    CandidateReply,
    CandidateSet,
    SessionRecord,
    StoredContentRef,
    TemporaryFactEvent,
    TurnRecord,
    TurnState,
)
from consultation_kb.session.state_machine import InvalidTurnTransition, TurnStateMachine
from consultation_kb.storage.connection import transaction
from consultation_kb.vault.content_store import ContentStore


_UUID_ADAPTER = TypeAdapter(Uuid7String)
_CLIENT_ADAPTER = TypeAdapter(ClientId)
_HASH_ADAPTER = TypeAdapter(Sha256Hex)


class SessionRepositoryError(RuntimeError):
    """Base fixed-code session repository error."""


class SessionNotFound(SessionRepositoryError):
    def __init__(self) -> None:
        super().__init__("SESSION_NOT_FOUND")


class SessionClosed(SessionRepositoryError):
    def __init__(self) -> None:
        super().__init__("SESSION_CLOSED")


class SessionConflict(SessionRepositoryError):
    pass


class PreviousTurnNotClosed(SessionRepositoryError):
    def __init__(self) -> None:
        super().__init__("PREVIOUS_TURN_NOT_CLOSED")


class TurnNotFound(SessionRepositoryError):
    def __init__(self) -> None:
        super().__init__("TURN_NOT_FOUND")


class TurnStateConflict(SessionRepositoryError):
    def __init__(self) -> None:
        super().__init__("TURN_STATE_CONFLICT")


class SessionIntegrityError(SessionRepositoryError):
    def __init__(self) -> None:
        super().__init__("SESSION_INTEGRITY_ERROR")


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be timezone-aware UTC")
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise SessionIntegrityError
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise SessionIntegrityError from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise SessionIntegrityError
    return parsed


def _optional_utc(value: object) -> datetime | None:
    return None if value is None else _parse_utc(value)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_hash(value: object) -> str:
    encoded = (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    return _sha256(encoded)


class SessionRepository:
    """One client-scope repository; bodies live only in its matching CAS."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        content_store: ContentStore,
        clock: Clock,
        id_factory: IdFactory,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SessionRepository requires sqlite3.Connection")
        if not isinstance(content_store, ContentStore):
            raise TypeError("SessionRepository requires ContentStore")
        if not isinstance(id_factory, IdFactory):
            raise TypeError("SessionRepository requires IdFactory")
        self.connection = connection
        self.content_store = content_store
        self.clock = clock
        self.id_factory = id_factory

    def _store_content(
        self,
        data: bytes,
        *,
        kind: str,
        media_type: str,
    ) -> StoredContentRef:
        if type(data) is not bytes or not data:
            raise ValueError("content must be nonempty bytes")
        staged = self.content_store.stage_bytes(
            data,
            purpose="session_content",
            manifest_id=self.id_factory.object_id("session_manifest"),
            media_type=media_type,
        )
        stored = self.content_store.finalize(staged)
        return StoredContentRef(
            object_id=self.id_factory.object_id(kind),
            content_sha256=stored.content_sha256,
            media_type=stored.media_type,
            size_bytes=stored.size_bytes,
        )

    def store_text(self, text: str, *, kind: str) -> StoredContentRef:
        if type(text) is not str or not text.strip():
            raise ValueError("text must be nonblank")
        return self._store_content(text.encode("utf-8"), kind=kind, media_type="text/plain")

    def store_json(self, data: bytes, *, kind: str) -> StoredContentRef:
        return self._store_content(data, kind=kind, media_type="application/json")

    def read_content(self, reference: StoredContentRef) -> bytes:
        validated = StoredContentRef.model_validate(reference)
        opaque = self.content_store.reference(
            content_sha256=validated.content_sha256,
            media_type=validated.media_type,
            size_bytes=validated.size_bytes,
        )
        return self.content_store.read_verified(opaque)

    def create_session(
        self,
        *,
        session_id: str,
        client_id: str,
        client_scope_hash: str,
        snapshot_version: int,
        snapshot_canonical_sha256: str,
        snapshot_bytes: bytes,
        capability_epoch: int = 1,
    ) -> SessionRecord:
        try:
            validated_session = _UUID_ADAPTER.validate_python(session_id, strict=True)
            validated_client = _CLIENT_ADAPTER.validate_python(client_id, strict=True)
            validated_scope_hash = _HASH_ADAPTER.validate_python(
                client_scope_hash,
                strict=True,
            )
            validated_snapshot_hash = _HASH_ADAPTER.validate_python(
                snapshot_canonical_sha256,
                strict=True,
            )
        except ValidationError as error:
            raise ValueError("invalid session binding") from error
        if type(snapshot_version) is not int or snapshot_version < 0:
            raise ValueError("snapshot_version must be a non-negative integer")
        if type(capability_epoch) is not int or capability_epoch <= 0:
            raise ValueError("capability_epoch must be positive")
        if type(snapshot_bytes) is not bytes or not snapshot_bytes:
            raise ValueError("snapshot_bytes must be nonempty bytes")
        snapshot_bytes_sha256 = _sha256(snapshot_bytes)
        existing = self._session_row(validated_session)
        if existing is not None:
            record = self._session_from_row(existing)
            if (
                record.client_id != validated_client
                or record.client_scope_hash != validated_scope_hash
                or record.client_snapshot_version != snapshot_version
                or record.client_snapshot_canonical_sha256 != validated_snapshot_hash
                or record.client_snapshot.content_sha256 != snapshot_bytes_sha256
            ):
                raise SessionConflict("SESSION_BINDING_CONFLICT")
            return record

        snapshot_ref = self.store_json(snapshot_bytes, kind="session_context")
        now = self.clock.now()
        record = SessionRecord(
            session_id=validated_session,
            client_id=validated_client,
            client_scope_hash=validated_scope_hash,
            client_snapshot_version=snapshot_version,
            client_snapshot_canonical_sha256=validated_snapshot_hash,
            client_snapshot=snapshot_ref,
            status="OPEN",
            capability_epoch=capability_epoch,
            last_closed_turn_ordinal=0,
            archive_state="NOT_STARTED",
            started_at=now,
            updated_at=now,
            closed_at=None,
        )
        try:
            with transaction(self.connection):
                self.connection.execute(
                    """
                    INSERT INTO sessions(
                        session_id, client_scope_hash, state, started_at, closed_at,
                        client_id, client_snapshot_version,
                        client_snapshot_canonical_sha256,
                        client_snapshot_object_id, client_snapshot_sha256,
                        client_snapshot_media_type, client_snapshot_size_bytes,
                        capability_epoch, last_closed_turn_ordinal,
                        archive_state, updated_at
                    ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                    """,
                    (
                        record.session_id,
                        record.client_scope_hash,
                        record.status,
                        _utc_text(record.started_at),
                        record.client_id,
                        record.client_snapshot_version,
                        record.client_snapshot_canonical_sha256,
                        record.client_snapshot.object_id,
                        record.client_snapshot.content_sha256,
                        record.client_snapshot.media_type,
                        record.client_snapshot.size_bytes,
                        record.capability_epoch,
                        record.archive_state,
                        _utc_text(record.updated_at),
                    ),
                )
                self._insert_checkpoint(
                    session_id=record.session_id,
                    turn_id=None,
                    current=None,
                    target="session_open",
                    payload_sha256=record.client_snapshot.content_sha256,
                    event_kind="session_started",
                    created_at=now,
                )
        except sqlite3.IntegrityError:
            raise SessionConflict("SESSION_BINDING_CONFLICT") from None
        return record

    def _session_row(self, session_id: str) -> tuple[object, ...] | None:
        return cast(
            tuple[object, ...] | None,
            self.connection.execute(
            """
            SELECT session_id, client_id, client_scope_hash,
                   client_snapshot_version, client_snapshot_canonical_sha256,
                   client_snapshot_object_id, client_snapshot_sha256,
                   client_snapshot_media_type, client_snapshot_size_bytes,
                   state, capability_epoch, last_closed_turn_ordinal,
                   archive_state, started_at, updated_at, closed_at
              FROM sessions WHERE session_id = ?
            """,
            (session_id,),
            ).fetchone(),
        )

    @staticmethod
    def _session_from_row(row: tuple[object, ...]) -> SessionRecord:
        if len(row) != 16:
            raise SessionIntegrityError
        try:
            return SessionRecord.model_validate(
                {
                    "session_id": row[0],
                    "client_id": row[1],
                    "client_scope_hash": row[2],
                    "client_snapshot_version": row[3],
                    "client_snapshot_canonical_sha256": row[4],
                    "client_snapshot": {
                        "object_id": row[5],
                        "content_sha256": row[6],
                        "media_type": row[7],
                        "size_bytes": row[8],
                    },
                    "status": row[9],
                    "capability_epoch": row[10],
                    "last_closed_turn_ordinal": row[11],
                    "archive_state": row[12],
                    "started_at": _parse_utc(row[13]),
                    "updated_at": _parse_utc(row[14]),
                    "closed_at": _optional_utc(row[15]),
                }
            )
        except (ValidationError, ValueError, TypeError):
            raise SessionIntegrityError from None

    def get_session(self, session_id: str) -> SessionRecord:
        row = self._session_row(session_id)
        if row is None:
            raise SessionNotFound
        return self._session_from_row(row)

    def read_snapshot(self, session_id: str) -> bytes:
        return self.read_content(self.get_session(session_id).client_snapshot)

    def set_capability_epoch(
        self,
        session_id: str,
        *,
        expected_epoch: int,
        new_epoch: int,
    ) -> SessionRecord:
        if (
            type(expected_epoch) is not int
            or type(new_epoch) is not int
            or expected_epoch <= 0
            or new_epoch <= expected_epoch
        ):
            raise ValueError("capability epoch must increase")
        now = self.clock.now()
        with transaction(self.connection):
            changed = self.connection.execute(
                "UPDATE sessions SET capability_epoch = ?, updated_at = ? "
                "WHERE session_id = ? AND capability_epoch = ?",
                (new_epoch, _utc_text(now), session_id, expected_epoch),
            ).rowcount
            if changed != 1:
                raise SessionConflict("SESSION_CAPABILITY_EPOCH_CONFLICT")
            self._insert_checkpoint(
                session_id=session_id,
                turn_id=None,
                current=str(expected_epoch),
                target=str(new_epoch),
                payload_sha256=_canonical_hash(
                    {"capability_epoch": new_epoch}
                ),
                event_kind="capability_epoch_changed",
                created_at=now,
            )
        return self.get_session(session_id)

    def close_session(self, session_id: str) -> SessionRecord:
        record = self.get_session(session_id)
        if record.status != "OPEN":
            return record
        open_count = int(
            self.connection.execute(
                "SELECT count(*) FROM turns WHERE session_id = ? AND state != 'turn_closed'",
                (session_id,),
            ).fetchone()[0]
        )
        if open_count:
            raise PreviousTurnNotClosed
        now = self.clock.now()
        with transaction(self.connection):
            changed = self.connection.execute(
                "UPDATE sessions SET state = 'CLOSED', closed_at = ?, updated_at = ? "
                "WHERE session_id = ? AND state = 'OPEN'",
                (_utc_text(now), _utc_text(now), session_id),
            ).rowcount
            if changed != 1:
                raise SessionConflict("SESSION_STATE_CONFLICT")
            self._insert_checkpoint(
                session_id=session_id,
                turn_id=None,
                current="OPEN",
                target="CLOSED",
                payload_sha256=_canonical_hash({"status": "CLOSED"}),
                event_kind="session_closed",
                created_at=now,
            )
        return self.get_session(session_id)

    def append_client_turn(
        self,
        session_id: str,
        turn_id: str,
        message: str,
    ) -> TurnRecord:
        try:
            validated_session = _UUID_ADAPTER.validate_python(session_id, strict=True)
            validated_turn = _UUID_ADAPTER.validate_python(turn_id, strict=True)
        except ValidationError as error:
            raise ValueError("invalid session or turn ID") from error
        if type(message) is not str or not message.strip():
            raise ValueError("message must be nonblank")
        message_bytes = message.encode("utf-8")
        digest = _sha256(message_bytes)
        existing = self._turn_row(validated_session, validated_turn)
        if existing is not None:
            record = self._turn_from_row(existing)
            if record.client_message.content_sha256 != digest:
                raise SessionConflict("TURN_CONTENT_CONFLICT")
            return record
        session = self.get_session(validated_session)
        if session.status != "OPEN":
            raise SessionClosed
        pending = self.connection.execute(
            "SELECT 1 FROM turns WHERE session_id = ? AND state != 'turn_closed' LIMIT 1",
            (validated_session,),
        ).fetchone()
        if pending is not None:
            raise PreviousTurnNotClosed
        ordinal = int(
            self.connection.execute(
                "SELECT COALESCE(MAX(ordinal), 0) + 1 FROM turns WHERE session_id = ?",
                (validated_session,),
            ).fetchone()[0]
        )
        content = self._store_content(
            message_bytes,
            kind="client_turn",
            media_type="text/plain",
        )
        now = self.clock.now()
        try:
            with transaction(self.connection):
                self.connection.execute(
                    """
                    INSERT INTO turns(
                        session_id, turn_id, ordinal, client_message_object_id,
                        client_message_sha256, client_message_media_type,
                        client_message_size_bytes, state, active_run_id,
                        received_at, updated_at, closed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'client_turn_received', NULL,
                              ?, ?, NULL)
                    """,
                    (
                        validated_session,
                        validated_turn,
                        ordinal,
                        content.object_id,
                        content.content_sha256,
                        content.media_type,
                        content.size_bytes,
                        _utc_text(now),
                        _utc_text(now),
                    ),
                )
                self._insert_checkpoint(
                    session_id=validated_session,
                    turn_id=validated_turn,
                    current=None,
                    target="client_turn_received",
                    payload_sha256=digest,
                    event_kind="client_turn_appended",
                    created_at=now,
                )
        except sqlite3.IntegrityError as error:
            raise SessionConflict("TURN_APPEND_CONFLICT") from error
        return self.get_turn(validated_session, validated_turn)

    def _turn_row(self, session_id: str, turn_id: str) -> tuple[object, ...] | None:
        return cast(
            tuple[object, ...] | None,
            self.connection.execute(
            """
            SELECT session_id, turn_id, ordinal, client_message_object_id,
                   client_message_sha256, client_message_media_type,
                   client_message_size_bytes, state, active_run_id,
                   received_at, updated_at, closed_at
              FROM turns WHERE session_id = ? AND turn_id = ?
            """,
            (session_id, turn_id),
            ).fetchone(),
        )

    @staticmethod
    def _turn_from_row(row: tuple[object, ...]) -> TurnRecord:
        if len(row) != 12:
            raise SessionIntegrityError
        try:
            return TurnRecord.model_validate(
                {
                    "session_id": row[0],
                    "turn_id": row[1],
                    "ordinal": row[2],
                    "client_message": {
                        "object_id": row[3],
                        "content_sha256": row[4],
                        "media_type": row[5],
                        "size_bytes": row[6],
                    },
                    "state": row[7],
                    "active_run_id": row[8],
                    "received_at": _parse_utc(row[9]),
                    "updated_at": _parse_utc(row[10]),
                    "closed_at": _optional_utc(row[11]),
                }
            )
        except (ValidationError, ValueError, TypeError):
            raise SessionIntegrityError from None

    def get_turn(self, session_id: str, turn_id: str) -> TurnRecord:
        row = self._turn_row(session_id, turn_id)
        if row is None:
            raise TurnNotFound
        return self._turn_from_row(row)

    def list_turns(self, session_id: str) -> tuple[TurnRecord, ...]:
        rows = self.connection.execute(
            """
            SELECT session_id, turn_id, ordinal, client_message_object_id,
                   client_message_sha256, client_message_media_type,
                   client_message_size_bytes, state, active_run_id,
                   received_at, updated_at, closed_at
              FROM turns WHERE session_id = ? ORDER BY ordinal
            """,
            (session_id,),
        ).fetchall()
        return tuple(self._turn_from_row(row) for row in rows)

    def count_turns(self, session_id: str) -> int:
        return int(
            self.connection.execute(
                "SELECT count(*) FROM turns WHERE session_id = ?",
                (session_id,),
            ).fetchone()[0]
        )

    def transition_turn(
        self,
        session_id: str,
        turn_id: str,
        *,
        target: TurnState,
        payload_sha256: str,
        active_run_id: str | None = None,
    ) -> TurnRecord:
        with transaction(self.connection):
            self.transition_turn_in_transaction(
                session_id,
                turn_id,
                target=target,
                payload_sha256=payload_sha256,
                active_run_id=active_run_id,
            )
        return self.get_turn(session_id, turn_id)

    def transition_turn_in_transaction(
        self,
        session_id: str,
        turn_id: str,
        *,
        target: TurnState,
        payload_sha256: str,
        active_run_id: str | None = None,
    ) -> None:
        if not self.connection.in_transaction:
            raise SessionIntegrityError
        current = self.get_turn(session_id, turn_id)
        if current.state == target:
            row = self.connection.execute(
                "SELECT payload_sha256 FROM session_checkpoints "
                "WHERE session_id = ? AND turn_id = ? AND to_state = ? "
                "ORDER BY checkpoint_sequence DESC LIMIT 1",
                (session_id, turn_id, target),
            ).fetchone()
            if row == (payload_sha256,):
                return
            raise SessionConflict("TURN_TRANSITION_PAYLOAD_CONFLICT")
        try:
            transition = TurnStateMachine.transition(
                current=current.state,
                target=target,
                payload_sha256=payload_sha256,
            )
        except InvalidTurnTransition:
            raise TurnStateConflict from None
        if active_run_id is not None:
            try:
                active_run_id = _UUID_ADAPTER.validate_python(active_run_id, strict=True)
            except ValidationError as error:
                raise ValueError("active_run_id must be UUIDv7") from error
            if current.active_run_id not in {None, active_run_id}:
                raise SessionConflict("TURN_RUN_CONFLICT")
        now = self.clock.now()
        closed_at = _utc_text(now) if target == "turn_closed" else None
        changed = self.connection.execute(
            """
            UPDATE turns
               SET state = ?, active_run_id = COALESCE(?, active_run_id),
                   updated_at = ?, closed_at = ?
             WHERE session_id = ? AND turn_id = ? AND state = ?
            """,
            (
                target,
                active_run_id,
                _utc_text(now),
                closed_at,
                session_id,
                turn_id,
                current.state,
            ),
        ).rowcount
        if changed != 1:
            raise TurnStateConflict
        self._insert_checkpoint(
            session_id=session_id,
            turn_id=turn_id,
            current=transition.current,
            target=transition.target,
            payload_sha256=transition.payload_sha256,
            event_kind="turn_state_transition",
            created_at=now,
        )
        if target == "turn_closed":
            self.connection.execute(
                "UPDATE sessions SET last_closed_turn_ordinal = ?, updated_at = ? "
                "WHERE session_id = ? AND last_closed_turn_ordinal < ?",
                (current.ordinal, _utc_text(now), session_id, current.ordinal),
            )

    def _insert_checkpoint(
        self,
        *,
        session_id: str,
        turn_id: str | None,
        current: str | None,
        target: str,
        payload_sha256: str,
        event_kind: str,
        created_at: datetime,
    ) -> None:
        if not self.connection.in_transaction:
            raise SessionIntegrityError
        sequence = int(
            self.connection.execute(
                "SELECT COALESCE(MAX(checkpoint_sequence), 0) + 1 "
                "FROM session_checkpoints WHERE session_id = ?",
                (session_id,),
            ).fetchone()[0]
        )
        self.connection.execute(
            """
            INSERT INTO session_checkpoints(
                checkpoint_id, session_id, checkpoint_sequence, turn_id,
                from_state, to_state, payload_sha256, event_kind, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self.id_factory.object_id("session_checkpoint"),
                session_id,
                sequence,
                turn_id,
                current,
                target,
                payload_sha256,
                event_kind,
                _utc_text(created_at),
            ),
        )

    # The following read methods are completed by the specialized P5 services.
    def list_actual_replies(self, session_id: str) -> tuple[ActualReply, ...]:
        from consultation_kb.session.actual_replies import actual_reply_from_row

        rows = self.connection.execute(
            "SELECT * FROM actual_replies WHERE session_id = ? ORDER BY created_at, actual_reply_id",
            (session_id,),
        ).fetchall()
        return tuple(actual_reply_from_row(tuple(row)) for row in rows)

    def list_temporary_facts(self, session_id: str) -> tuple[TemporaryFactEvent, ...]:
        from consultation_kb.session.temporary_ledger import temporary_fact_from_row

        rows = self.connection.execute(
            """
            SELECT session_event_id, session_id, turn_id, event_kind,
                   cognitive_type, content_object_id, content_sha256,
                   content_media_type, content_size_bytes, target_fact_id,
                   target_fact_version, recorded_at
              FROM session_fact_events WHERE session_id = ?
             ORDER BY recorded_at, session_event_id
            """,
            (session_id,),
        ).fetchall()
        return tuple(temporary_fact_from_row(tuple(row)) for row in rows)

    def get_candidate(self, candidate_id: str) -> CandidateReply:
        from consultation_kb.session.candidate_sets import candidate_from_row

        row = self.connection.execute(
            """
            SELECT cr.candidate_id, cr.candidate_set_id, cr.session_id, cr.turn_id,
                   cr.ordinal, cr.label, cr.candidate_object_id,
                   cr.candidate_sha256, cr.candidate_media_type,
                   cr.candidate_size_bytes, cs.run_id, cr.created_at
              FROM candidate_replies cr
              JOIN candidate_sets cs USING(candidate_set_id)
             WHERE cr.candidate_id = ?
            """,
            (candidate_id,),
        ).fetchone()
        if row is None:
            raise KeyError(candidate_id)
        return candidate_from_row(tuple(row))

    def get_candidate_set(self, session_id: str, turn_id: str) -> CandidateSet:
        from consultation_kb.session.candidate_sets import candidate_set_from_database

        return candidate_set_from_database(self.connection, session_id, turn_id)


__all__ = [
    "PreviousTurnNotClosed",
    "SessionClosed",
    "SessionConflict",
    "SessionIntegrityError",
    "SessionNotFound",
    "SessionRepository",
    "SessionRepositoryError",
    "TurnNotFound",
    "TurnStateConflict",
]
