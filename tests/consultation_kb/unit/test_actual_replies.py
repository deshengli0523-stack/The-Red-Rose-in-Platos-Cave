from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.session.actual_replies import ActualReplyConflict, ActualReplyService
from consultation_kb.session.candidate_sets import CandidateSetService
from consultation_kb.session.repository import SessionRepository
from consultation_kb.session.turns import TurnService
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore


def _awaiting(tmp_path: Path, suffix: int = 1) -> tuple[sqlite3.Connection, SessionRepository, str, str, str]:
    connection = connect_database(tmp_path / f"client-{suffix}.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "client").apply()
    clock = FixedClock(datetime(2026, 7, 19, 6, suffix, tzinfo=timezone.utc))
    values = iter(range(900 + suffix * 100, 1200 + suffix * 100))
    repository = SessionRepository(
        connection,
        content_store=ContentStore(tmp_path / f"scope-{suffix}"),
        clock=clock,
        id_factory=IdFactory(clock=clock, random_source=lambda: next(values)),
    )
    session_id = f"018f0000-0000-7000-8000-{suffix:012d}"
    turn_id = f"018f0000-0000-7001-8000-{suffix:012d}"
    run_id = f"018f0000-0000-7002-8000-{suffix:012d}"
    repository.create_session(
        session_id=session_id,
        client_id="client_" + "aaaaaaaaaaaa",
        client_scope_hash="a" * 64,
        snapshot_version=0,
        snapshot_canonical_sha256="b" * 64,
        snapshot_bytes=b'{"empty":true}\n',
    )
    turns = TurnService(repository)
    turns.append(session_id, turn_id, "来访者消息")
    turns.begin_generation(session_id, turn_id, run_id=run_id)
    candidates = CandidateSetService(repository).store_and_await(
        session_id,
        turn_id,
        ("候选一原文", "候选二原文"),
        run_id=run_id,
        idempotency_key=f"set-{suffix}",
    )
    return connection, repository, session_id, turn_id, candidates.candidates[0].candidate_id


def test_adopted_reply_reuses_exact_candidate_and_is_idempotent(tmp_path: Path) -> None:
    connection, repository, session_id, turn_id, candidate_id = _awaiting(tmp_path)
    service = ActualReplyService(repository)
    sent_at = datetime(2026, 7, 19, 6, 10, tzinfo=timezone.utc)
    try:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="adopted reply must exactly match candidate",
        ):
            connection.execute(
                """
                INSERT INTO actual_replies(
                    actual_reply_id, session_id, turn_id, idempotency_key,
                    operation_sha256, source_type, candidate_id,
                    reply_object_id, reply_sha256, reply_media_type,
                    reply_size_bytes, diff_object_id, diff_sha256,
                    diff_media_type, diff_size_bytes, sent_at, confirmed_at,
                    evidence_gap, created_at
                ) VALUES (?, ?, ?, 'direct-mismatch', ?, 'adopted', ?,
                          'actual_reply_direct_mismatch', ?, 'text/plain',
                          1, NULL, NULL, NULL, NULL, ?, NULL, 0, ?)
                """,
                (
                    "actual_reply_direct_mismatch",
                    session_id,
                    turn_id,
                    "a" * 64,
                    candidate_id,
                    "b" * 64,
                    sent_at.isoformat().replace("+00:00", "Z"),
                    sent_at.isoformat().replace("+00:00", "Z"),
                ),
            )
        first = service.record_adopted(
            session_id,
            turn_id,
            candidate_id,
            sent_at=sent_at,
            idempotency_key="actual-1",
        )
        second = service.record_adopted(
            session_id,
            turn_id,
            candidate_id,
            sent_at=sent_at,
            idempotency_key="actual-1",
        )
        candidate = repository.get_candidate(candidate_id)

        assert second == first
        assert first.content == candidate.content
        assert repository.get_turn(session_id, turn_id).state == "turn_closed"
        with pytest.raises(ActualReplyConflict, match="ACTUAL_REPLY_IDEMPOTENCY_CONFLICT"):
            service.record_adopted(
                session_id,
                turn_id,
                candidate_id,
                sent_at=sent_at + timedelta(seconds=1),
                idempotency_key="actual-1",
            )
    finally:
        connection.close()


def test_edited_and_external_unknown_preserve_exact_evidence_boundary(tmp_path: Path) -> None:
    edited_conn, edited_repo, session_id, turn_id, candidate_id = _awaiting(tmp_path, 2)
    unknown_conn, unknown_repo, unknown_session, unknown_turn, _ = _awaiting(tmp_path, 3)
    sent_at = datetime(2026, 7, 19, 6, 20, tzinfo=timezone.utc)
    try:
        edited = ActualReplyService(edited_repo).record_edited(
            session_id,
            turn_id,
            candidate_id,
            "咨询师实际修改后的完整回复",
            sent_at=sent_at,
            idempotency_key="edited-1",
        )
        unknown = ActualReplyService(unknown_repo).record_external_unknown(
            unknown_session,
            unknown_turn,
            confirmed_at=sent_at,
            idempotency_key="unknown-1",
        )

        assert edited.diff is not None
        assert edited_repo.read_content(edited.content).decode() == "咨询师实际修改后的完整回复"
        assert unknown.content is None
        assert unknown.evidence_gap is True
        assert unknown.confirmed_at == sent_at
    finally:
        edited_conn.close()
        unknown_conn.close()
