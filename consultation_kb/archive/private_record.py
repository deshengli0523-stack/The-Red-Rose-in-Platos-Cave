"""Build exact private transcripts without reading unselected model candidates."""

from __future__ import annotations

import hashlib

from consultation_kb.models.archive import (
    ActualTranscript,
    ActualTranscriptTurn,
    PrivateArchiveAnalysis,
    PrivateArchiveDraft,
    actual_transcript_payload,
    private_archive_draft_payload,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.session import StoredContentRef
from consultation_kb.session.repository import SessionRepository


class PrivateArchiveRecordError(RuntimeError):
    """A session cannot be represented as an exact actual transcript."""


def _canonical_bytes(payload: object) -> bytes:
    import json

    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")


class ActualTranscriptReader:
    """Read only actual client messages and recorded counselor replies."""

    def __init__(self, repository: SessionRepository) -> None:
        self._repository = repository

    def snapshot(self, session_id: str) -> ActualTranscript:
        self._repository.get_session(session_id)
        turns = self._repository.list_turns(session_id)
        if not turns:
            raise PrivateArchiveRecordError("ACTUAL_TRANSCRIPT_EMPTY")
        if any(item.state != "turn_closed" for item in turns):
            raise PrivateArchiveRecordError("ACTUAL_TRANSCRIPT_OPEN_TURN")

        replies = self._repository.list_actual_replies(session_id)
        replies_by_turn = {item.turn_id: item for item in replies}
        if len(replies_by_turn) != len(replies) or set(replies_by_turn) != {
            item.turn_id for item in turns
        }:
            raise PrivateArchiveRecordError("ACTUAL_TRANSCRIPT_REPLY_MISMATCH")

        actual_turns: list[ActualTranscriptTurn] = []
        for turn in turns:
            reply = replies_by_turn[turn.turn_id]
            client_text = self._repository.read_content(turn.client_message).decode(
                "utf-8",
                errors="strict",
            )
            reply_text = (
                None
                if reply.content is None
                else self._repository.read_content(reply.content).decode(
                    "utf-8",
                    errors="strict",
                )
            )
            actual_turns.append(
                ActualTranscriptTurn(
                    ordinal=turn.ordinal,
                    turn_id=turn.turn_id,
                    client_message_ref=VersionRef(
                        object_id=turn.client_message.object_id,
                        version=1,
                        content_sha256=turn.client_message.content_sha256,
                    ),
                    client_message_text=client_text,
                    actual_reply_ref=VersionRef(
                        object_id=reply.actual_reply_id,
                        version=1,
                        content_sha256=(
                            reply.operation_sha256
                            if reply.content is None
                            else reply.content.content_sha256
                        ),
                    ),
                    reply_text=reply_text,
                    reply_source_type=reply.source_type,
                    evidence_gap=reply.evidence_gap,
                )
            )

        closed_turn_times = tuple(item.closed_at for item in turns)
        if any(item is None for item in closed_turn_times):
            raise PrivateArchiveRecordError("ACTUAL_TRANSCRIPT_OPEN_TURN")
        captured_at = max(item for item in closed_turn_times if item is not None)
        members = tuple(actual_turns)
        incomplete = any(item.evidence_gap for item in members)
        body = _canonical_bytes(
            actual_transcript_payload(
                session_id=session_id,
                turns=members,
                incomplete_evidence=incomplete,
                captured_at=captured_at,
            )
        )
        body_sha256 = hashlib.sha256(body).hexdigest()
        archived = self._repository.connection.execute(
            """
            SELECT actual_transcript_object_id, actual_transcript_version,
                   actual_transcript_sha256, actual_transcript_media_type,
                   actual_transcript_size_bytes
              FROM archive_bundles WHERE session_id = ?
            """,
            (session_id,),
        ).fetchone()
        if archived is None:
            stored = self._repository.store_json(body, kind="actual_transcript")
            transcript_ref = VersionRef(
                object_id=stored.object_id,
                version=1,
                content_sha256=stored.content_sha256,
            )
        else:
            if (
                len(archived) != 5
                or type(archived[0]) is not str
                or type(archived[1]) is not int
                or type(archived[2]) is not str
                or archived[2] != body_sha256
                or archived[3] != "application/json"
                or type(archived[4]) is not int
                or archived[4] != len(body)
            ):
                raise PrivateArchiveRecordError("ACTUAL_TRANSCRIPT_BUNDLE_MISMATCH")
            archived_content = StoredContentRef(
                object_id=archived[0],
                content_sha256=archived[2],
                media_type=archived[3],
                size_bytes=archived[4],
            )
            if self._repository.read_content(archived_content) != body:
                raise PrivateArchiveRecordError("ACTUAL_TRANSCRIPT_BUNDLE_MISMATCH")
            transcript_ref = VersionRef(
                object_id=archived[0],
                version=archived[1],
                content_sha256=archived[2],
            )
        return ActualTranscript(
            actual_transcript_ref=transcript_ref,
            session_id=session_id,
            turns=members,
            incomplete_evidence=incomplete,
            captured_at=captured_at,
        )


class PrivateArchiveDraftBuilder:
    """Keep exact evidence and interpretive analysis in explicit sections."""

    def __init__(self, repository: SessionRepository) -> None:
        self._repository = repository

    def build(
        self,
        session_id: str,
        *,
        analysis: PrivateArchiveAnalysis | None = None,
    ) -> PrivateArchiveDraft:
        transcript = ActualTranscriptReader(self._repository).snapshot(session_id)
        selected_analysis = (
            PrivateArchiveAnalysis()
            if analysis is None
            else PrivateArchiveAnalysis.model_validate(analysis)
        )
        created_at = self._repository.clock.now()
        body = _canonical_bytes(
            private_archive_draft_payload(
                actual_transcript=transcript,
                analysis=selected_analysis,
                created_at=created_at,
            )
        )
        stored = self._repository.store_json(body, kind="private_archive_draft")
        return PrivateArchiveDraft(
            draft_ref=VersionRef(
                object_id=stored.object_id,
                version=1,
                content_sha256=stored.content_sha256,
            ),
            actual_transcript=transcript,
            analysis=selected_analysis,
            created_at=created_at,
        )


__all__ = [
    "ActualTranscriptReader",
    "PrivateArchiveDraftBuilder",
    "PrivateArchiveRecordError",
]
