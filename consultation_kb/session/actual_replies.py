"""Only actually sent, edited, or explicitly unknown replies close a turn."""

from __future__ import annotations

import difflib
import hashlib
import json
import sqlite3
from datetime import datetime

from pydantic import ValidationError

from consultation_kb.models.session import ActualReply, TurnState
from consultation_kb.session.repository import SessionRepository, TurnStateConflict
from consultation_kb.storage.connection import transaction


class ActualReplyError(RuntimeError):
    """Base fixed-code actual-reply error."""


class ActualReplyConflict(ActualReplyError):
    pass


def _canonical_hash(value: object) -> str:
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


def actual_reply_from_row(row: tuple[object, ...]) -> ActualReply:
    if len(row) != 19:
        raise ActualReplyConflict("ACTUAL_REPLY_INTEGRITY_ERROR")
    try:
        from consultation_kb.session.repository import _optional_utc, _parse_utc

        content = None if row[7] is None else {
            "object_id": row[7],
            "content_sha256": row[8],
            "media_type": row[9],
            "size_bytes": row[10],
        }
        diff = None if row[11] is None else {
            "object_id": row[11],
            "content_sha256": row[12],
            "media_type": row[13],
            "size_bytes": row[14],
        }
        return ActualReply.model_validate(
            {
                "actual_reply_id": row[0],
                "session_id": row[1],
                "turn_id": row[2],
                "idempotency_key": row[3],
                "operation_sha256": row[4],
                "source_type": row[5],
                "candidate_id": row[6],
                "content": content,
                "diff": diff,
                "sent_at": _optional_utc(row[15]),
                "confirmed_at": _optional_utc(row[16]),
                "evidence_gap": bool(row[17]),
                "created_at": _parse_utc(row[18]),
            }
        )
    except (TypeError, ValueError, ValidationError):
        raise ActualReplyConflict("ACTUAL_REPLY_INTEGRITY_ERROR") from None


class ActualReplyService:
    def __init__(self, repository: SessionRepository) -> None:
        self._repository = repository

    def _existing(
        self,
        session_id: str,
        idempotency_key: str,
        *,
        turn_id: str,
        operation_sha256: str,
    ) -> ActualReply | None:
        row = self._repository.connection.execute(
            "SELECT * FROM actual_replies WHERE session_id = ? AND idempotency_key = ?",
            (session_id, idempotency_key),
        ).fetchone()
        if row is None:
            return None
        actual = actual_reply_from_row(tuple(row))
        if actual.turn_id != turn_id or actual.operation_sha256 != operation_sha256:
            raise ActualReplyConflict("ACTUAL_REPLY_IDEMPOTENCY_CONFLICT")
        return actual

    def _record(self, actual: ActualReply) -> ActualReply:
        from consultation_kb.session.repository import _utc_text

        target: TurnState = (
            "external_reply_unknown"
            if actual.source_type == "external_unknown"
            else "actual_reply_recorded"
        )
        try:
            with transaction(self._repository.connection):
                if self._repository.get_turn(actual.session_id, actual.turn_id).state != "awaiting_actual_reply":
                    raise TurnStateConflict
                self._repository.connection.execute(
                    """
                    INSERT INTO actual_replies(
                        actual_reply_id, session_id, turn_id, idempotency_key,
                        operation_sha256, source_type, candidate_id,
                        reply_object_id, reply_sha256, reply_media_type,
                        reply_size_bytes, diff_object_id, diff_sha256,
                        diff_media_type, diff_size_bytes, sent_at, confirmed_at,
                        evidence_gap, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        actual.actual_reply_id,
                        actual.session_id,
                        actual.turn_id,
                        actual.idempotency_key,
                        actual.operation_sha256,
                        actual.source_type,
                        actual.candidate_id,
                        None if actual.content is None else actual.content.object_id,
                        None if actual.content is None else actual.content.content_sha256,
                        None if actual.content is None else actual.content.media_type,
                        None if actual.content is None else actual.content.size_bytes,
                        None if actual.diff is None else actual.diff.object_id,
                        None if actual.diff is None else actual.diff.content_sha256,
                        None if actual.diff is None else actual.diff.media_type,
                        None if actual.diff is None else actual.diff.size_bytes,
                        None if actual.sent_at is None else _utc_text(actual.sent_at),
                        None
                        if actual.confirmed_at is None
                        else _utc_text(actual.confirmed_at),
                        int(actual.evidence_gap),
                        _utc_text(actual.created_at),
                    ),
                )
                self._repository.transition_turn_in_transaction(
                    actual.session_id,
                    actual.turn_id,
                    target=target,
                    payload_sha256=actual.operation_sha256,
                )
                self._repository.transition_turn_in_transaction(
                    actual.session_id,
                    actual.turn_id,
                    target="turn_closed",
                    payload_sha256=_canonical_hash(
                        {
                            "actual_reply_sha256": actual.operation_sha256,
                            "state": "turn_closed",
                        }
                    ),
                )
        except sqlite3.IntegrityError:
            raise ActualReplyConflict("ACTUAL_REPLY_WRITE_CONFLICT") from None
        return actual

    def record_adopted(
        self,
        session_id: str,
        turn_id: str,
        candidate_id: str,
        *,
        sent_at: datetime,
        idempotency_key: str,
    ) -> ActualReply:
        from consultation_kb.session.repository import _utc_text

        candidate = self._repository.get_candidate(candidate_id)
        if candidate.session_id != session_id or candidate.turn_id != turn_id:
            raise ActualReplyConflict("ACTUAL_REPLY_CANDIDATE_MISMATCH")
        operation_sha256 = _canonical_hash(
            {
                "candidate_id": candidate_id,
                "reply_sha256": candidate.content.content_sha256,
                "sent_at": _utc_text(sent_at),
                "source_type": "adopted",
            }
        )
        existing = self._existing(
            session_id,
            idempotency_key,
            turn_id=turn_id,
            operation_sha256=operation_sha256,
        )
        if existing is not None:
            return existing
        now = self._repository.clock.now()
        return self._record(
            ActualReply(
                actual_reply_id=self._repository.id_factory.object_id("actual_reply"),
                session_id=session_id,
                turn_id=turn_id,
                idempotency_key=idempotency_key,
                operation_sha256=operation_sha256,
                source_type="adopted",
                candidate_id=candidate_id,
                content=candidate.content,
                diff=None,
                sent_at=sent_at,
                confirmed_at=None,
                evidence_gap=False,
                created_at=now,
            )
        )

    def record_edited(
        self,
        session_id: str,
        turn_id: str,
        candidate_id: str,
        text: str,
        *,
        sent_at: datetime,
        idempotency_key: str,
    ) -> ActualReply:
        from consultation_kb.session.repository import _utc_text

        candidate = self._repository.get_candidate(candidate_id)
        if candidate.session_id != session_id or candidate.turn_id != turn_id:
            raise ActualReplyConflict("ACTUAL_REPLY_CANDIDATE_MISMATCH")
        if type(text) is not str or not text.strip():
            raise ValueError("edited reply must be nonblank")
        original = self._repository.read_content(candidate.content).decode("utf-8")
        if text == original:
            raise ValueError("edited reply must differ from candidate")
        text_bytes = text.encode("utf-8")
        diff_bytes = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                text.splitlines(keepends=True),
                fromfile="candidate",
                tofile="actual",
            )
        ).encode("utf-8")
        reply_sha256 = hashlib.sha256(text_bytes).hexdigest()
        diff_sha256 = hashlib.sha256(diff_bytes).hexdigest()
        operation_sha256 = _canonical_hash(
            {
                "candidate_id": candidate_id,
                "diff_sha256": diff_sha256,
                "reply_sha256": reply_sha256,
                "sent_at": _utc_text(sent_at),
                "source_type": "edited",
            }
        )
        existing = self._existing(
            session_id,
            idempotency_key,
            turn_id=turn_id,
            operation_sha256=operation_sha256,
        )
        if existing is not None:
            return existing
        content = self._repository.store_text(text, kind="actual_reply")
        diff = self._repository._store_content(
            diff_bytes,
            kind="reply_diff",
            media_type="text/x-diff",
        )
        return self._record(
            ActualReply(
                actual_reply_id=self._repository.id_factory.object_id("actual_reply"),
                session_id=session_id,
                turn_id=turn_id,
                idempotency_key=idempotency_key,
                operation_sha256=operation_sha256,
                source_type="edited",
                candidate_id=candidate_id,
                content=content,
                diff=diff,
                sent_at=sent_at,
                confirmed_at=None,
                evidence_gap=False,
                created_at=self._repository.clock.now(),
            )
        )

    def record_external_unknown(
        self,
        session_id: str,
        turn_id: str,
        *,
        confirmed_at: datetime,
        idempotency_key: str,
    ) -> ActualReply:
        from consultation_kb.session.repository import _utc_text

        operation_sha256 = _canonical_hash(
            {
                "confirmed_at": _utc_text(confirmed_at),
                "source_type": "external_unknown",
            }
        )
        existing = self._existing(
            session_id,
            idempotency_key,
            turn_id=turn_id,
            operation_sha256=operation_sha256,
        )
        if existing is not None:
            return existing
        return self._record(
            ActualReply(
                actual_reply_id=self._repository.id_factory.object_id("actual_reply"),
                session_id=session_id,
                turn_id=turn_id,
                idempotency_key=idempotency_key,
                operation_sha256=operation_sha256,
                source_type="external_unknown",
                candidate_id=None,
                content=None,
                diff=None,
                sent_at=None,
                confirmed_at=confirmed_at,
                evidence_gap=True,
                created_at=self._repository.clock.now(),
            )
        )


__all__ = [
    "ActualReplyConflict",
    "ActualReplyError",
    "ActualReplyService",
    "actual_reply_from_row",
]
