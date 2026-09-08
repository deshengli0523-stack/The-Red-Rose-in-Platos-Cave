"""Atomic candidate registration followed by mandatory actual-reply waiting."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Sequence

from pydantic import ValidationError

from consultation_kb.models.session import (
    CandidateDraft,
    CandidateReply,
    CandidateSet,
)
from consultation_kb.session.repository import SessionRepository, TurnStateConflict
from consultation_kb.storage.connection import transaction


class CandidateSetError(RuntimeError):
    """Base fixed-code candidate registration error."""


class CandidateSetConflict(CandidateSetError):
    pass


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    ).hexdigest()


def candidate_from_row(row: tuple[object, ...]) -> CandidateReply:
    if len(row) != 12:
        raise CandidateSetConflict("CANDIDATE_SET_INTEGRITY_ERROR")
    try:
        from consultation_kb.session.repository import _parse_utc

        return CandidateReply.model_validate(
            {
                "candidate_id": row[0],
                "candidate_set_id": row[1],
                "session_id": row[2],
                "turn_id": row[3],
                "ordinal": row[4],
                "label": row[5],
                "content": {
                    "object_id": row[6],
                    "content_sha256": row[7],
                    "media_type": row[8],
                    "size_bytes": row[9],
                },
                "run_id": row[10],
                "created_at": _parse_utc(row[11]),
            }
        )
    except (TypeError, ValueError, ValidationError):
        raise CandidateSetConflict("CANDIDATE_SET_INTEGRITY_ERROR") from None


def candidate_set_from_database(
    connection: sqlite3.Connection,
    session_id: str,
    turn_id: str,
) -> CandidateSet:
    row = connection.execute(
        """
        SELECT candidate_set_id, session_id, turn_id, run_id,
               idempotency_key, set_sha256, created_at
          FROM candidate_sets WHERE session_id = ? AND turn_id = ?
        """,
        (session_id, turn_id),
    ).fetchone()
    if row is None:
        raise KeyError((session_id, turn_id))
    candidate_rows = connection.execute(
        """
        SELECT cr.candidate_id, cr.candidate_set_id, cr.session_id, cr.turn_id,
               cr.ordinal, cr.label, cr.candidate_object_id,
               cr.candidate_sha256, cr.candidate_media_type,
               cr.candidate_size_bytes, cs.run_id, cr.created_at
          FROM candidate_replies cr
          JOIN candidate_sets cs USING(candidate_set_id)
         WHERE cr.candidate_set_id = ? ORDER BY cr.ordinal
        """,
        (row[0],),
    ).fetchall()
    try:
        from consultation_kb.session.repository import _parse_utc

        return CandidateSet.model_validate(
            {
                "candidate_set_id": row[0],
                "session_id": row[1],
                "turn_id": row[2],
                "run_id": row[3],
                "idempotency_key": row[4],
                "set_sha256": row[5],
                "candidates": tuple(
                    candidate_from_row(tuple(item)) for item in candidate_rows
                ),
                "created_at": _parse_utc(row[6]),
            }
        )
    except (TypeError, ValueError, ValidationError):
        raise CandidateSetConflict("CANDIDATE_SET_INTEGRITY_ERROR") from None


class CandidateSetService:
    def __init__(self, repository: SessionRepository) -> None:
        self._repository = repository

    @staticmethod
    def _drafts(
        candidates: Sequence[CandidateDraft | str],
    ) -> tuple[CandidateDraft, ...]:
        if isinstance(candidates, (str, bytes)):
            raise ValueError("candidates must be a sequence")
        normalized = tuple(
            item
            if isinstance(item, CandidateDraft)
            else CandidateDraft(label=f"candidate_{index}", text=item)
            for index, item in enumerate(candidates, start=1)
        )
        if not 2 <= len(normalized) <= 4:
            raise ValueError("candidate sets require between two and four candidates")
        if len({item.label for item in normalized}) != len(normalized) or len(
            {item.text for item in normalized}
        ) != len(normalized):
            raise ValueError("candidate labels and texts must be unique")
        return normalized

    def store_and_await(
        self,
        session_id: str,
        turn_id: str,
        candidates: Sequence[CandidateDraft | str],
        *,
        run_id: str,
        idempotency_key: str,
    ) -> CandidateSet:
        if type(idempotency_key) is not str or not idempotency_key:
            raise ValueError("idempotency_key must be nonempty")
        drafts = self._drafts(candidates)
        candidate_hashes = tuple(
            hashlib.sha256(item.text.encode("utf-8")).hexdigest() for item in drafts
        )
        set_sha256 = _canonical_hash(
            {
                "candidates": [
                    {"label": item.label, "sha256": digest}
                    for item, digest in zip(drafts, candidate_hashes, strict=True)
                ],
                "run_id": run_id,
            }
        )
        existing = self._repository.connection.execute(
            "SELECT turn_id, set_sha256 FROM candidate_sets "
            "WHERE session_id = ? AND idempotency_key = ?",
            (session_id, idempotency_key),
        ).fetchone()
        if existing is not None:
            if existing != (turn_id, set_sha256):
                raise CandidateSetConflict("CANDIDATE_SET_IDEMPOTENCY_CONFLICT")
            return self._repository.get_candidate_set(session_id, turn_id)

        turn = self._repository.get_turn(session_id, turn_id)
        if turn.state != "generation_in_progress" or turn.active_run_id != run_id:
            raise TurnStateConflict
        stored = tuple(
            self._repository.store_text(item.text, kind="candidate_reply")
            for item in drafts
        )
        now = self._repository.clock.now()
        candidate_set_id = self._repository.id_factory.object_id("candidate_set")
        replies = tuple(
            CandidateReply(
                candidate_id=self._repository.id_factory.object_id("candidate_reply"),
                candidate_set_id=candidate_set_id,
                session_id=session_id,
                turn_id=turn_id,
                ordinal=index,
                label=draft.label,
                content=content,
                run_id=run_id,
                created_at=now,
            )
            for index, (draft, content) in enumerate(
                zip(drafts, stored, strict=True),
                start=1,
            )
        )
        candidate_set = CandidateSet(
            candidate_set_id=candidate_set_id,
            session_id=session_id,
            turn_id=turn_id,
            run_id=run_id,
            idempotency_key=idempotency_key,
            set_sha256=set_sha256,
            candidates=replies,
            created_at=now,
        )
        from consultation_kb.session.repository import _utc_text

        try:
            with transaction(self._repository.connection):
                current = self._repository.get_turn(session_id, turn_id)
                if current.state != "generation_in_progress" or current.active_run_id != run_id:
                    raise TurnStateConflict
                self._repository.connection.execute(
                    """
                    INSERT INTO candidate_sets(
                        candidate_set_id, session_id, turn_id, run_id,
                        idempotency_key, set_sha256, candidate_count, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        candidate_set.candidate_set_id,
                        session_id,
                        turn_id,
                        run_id,
                        idempotency_key,
                        set_sha256,
                        len(replies),
                        _utc_text(now),
                    ),
                )
                for reply in replies:
                    self._repository.connection.execute(
                        """
                        INSERT INTO candidate_replies(
                            candidate_id, candidate_set_id, session_id, turn_id,
                            ordinal, label, candidate_object_id,
                            candidate_sha256, candidate_media_type,
                            candidate_size_bytes, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            reply.candidate_id,
                            reply.candidate_set_id,
                            reply.session_id,
                            reply.turn_id,
                            reply.ordinal,
                            reply.label,
                            reply.content.object_id,
                            reply.content.content_sha256,
                            reply.content.media_type,
                            reply.content.size_bytes,
                            _utc_text(reply.created_at),
                        ),
                    )
                self._repository.transition_turn_in_transaction(
                    session_id,
                    turn_id,
                    target="candidates_generated",
                    payload_sha256=set_sha256,
                    active_run_id=run_id,
                )
                self._repository.transition_turn_in_transaction(
                    session_id,
                    turn_id,
                    target="awaiting_actual_reply",
                    payload_sha256=_canonical_hash(
                        {"candidate_set_sha256": set_sha256, "state": "awaiting"}
                    ),
                    active_run_id=run_id,
                )
        except sqlite3.IntegrityError:
            raise CandidateSetConflict("CANDIDATE_SET_WRITE_CONFLICT") from None
        return candidate_set


__all__ = [
    "CandidateSetConflict",
    "CandidateSetError",
    "CandidateSetService",
    "candidate_from_row",
    "candidate_set_from_database",
]
