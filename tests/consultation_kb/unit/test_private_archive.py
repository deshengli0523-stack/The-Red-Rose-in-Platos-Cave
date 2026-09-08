from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from consultation_kb.archive.bundles import ArchiveBundleError, ArchiveBundleService
from consultation_kb.archive.private_record import (
    ActualTranscriptReader,
    PrivateArchiveDraftBuilder,
)
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.session.actual_replies import ActualReplyService
from consultation_kb.session.candidate_sets import CandidateSetService
from consultation_kb.session.repository import SessionRepository
from consultation_kb.session.turns import TurnService
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore


def _repository(
    tmp_path: Path,
    *,
    suffix: int,
) -> tuple[sqlite3.Connection, SessionRepository, str]:
    connection = connect_database(tmp_path / f"archive-{suffix}.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "client").apply()
    clock = FixedClock(datetime(2026, 7, 19, 8, suffix, tzinfo=timezone.utc))
    values = iter(range(10_000 + suffix * 100, 20_000 + suffix * 100))
    repository = SessionRepository(
        connection,
        content_store=ContentStore(tmp_path / f"archive-scope-{suffix}"),
        clock=clock,
        id_factory=IdFactory(clock=clock, random_source=lambda: next(values)),
    )
    session_id = f"018f0000-0000-7100-8000-{suffix:012d}"
    repository.create_session(
        session_id=session_id,
        client_id="client_" + "aaaaaaaaaaaa",
        client_scope_hash="a" * 64,
        snapshot_version=0,
        snapshot_canonical_sha256="b" * 64,
        snapshot_bytes=b'{"empty":true}\n',
    )
    return connection, repository, session_id


def _awaiting_actual(
    repository: SessionRepository,
    session_id: str,
    *,
    suffix: int,
) -> tuple[str, str, str, str]:
    turn_id = f"018f0000-0000-7101-8000-{suffix:012d}"
    run_id = f"018f0000-0000-7102-8000-{suffix:012d}"
    TurnService(repository).append(session_id, turn_id, "来访者实际输入")
    TurnService(repository).begin_generation(session_id, turn_id, run_id=run_id)
    candidates = CandidateSetService(repository).store_and_await(
        session_id,
        turn_id,
        ("最终采用的回复", "绝不能进入实际会谈记录的候选回复"),
        run_id=run_id,
        idempotency_key=f"candidate-set-{suffix}",
    )
    return (
        turn_id,
        candidates.candidates[0].candidate_id,
        candidates.candidates[0].content.content_sha256,
        candidates.candidates[1].content.content_sha256,
    )


def test_private_archive_contains_only_actual_replies(tmp_path: Path) -> None:
    connection, repository, session_id = _repository(tmp_path, suffix=1)
    turn_id, selected_id, selected_sha256, rejected_sha256 = _awaiting_actual(
        repository,
        session_id,
        suffix=1,
    )
    try:
        actual = ActualReplyService(repository).record_adopted(
            session_id,
            turn_id,
            selected_id,
            sent_at=datetime(2026, 7, 19, 8, 10, tzinfo=timezone.utc),
            idempotency_key="actual-1",
        )

        transcript = ActualTranscriptReader(repository).snapshot(session_id)
        draft = PrivateArchiveDraftBuilder(repository).build(session_id)

        assert [item.reply_text for item in draft.turns] == ["最终采用的回复"]
        assert draft.turns[0].actual_reply_ref is not None
        assert draft.turns[0].actual_reply_ref.object_id == actual.actual_reply_id
        assert draft.turns[0].actual_reply_ref.content_sha256 == selected_sha256
        assert rejected_sha256 not in draft.canonical_text
        assert "绝不能进入实际会谈记录的候选回复" not in draft.canonical_text
        assert transcript.canonical_text == draft.actual_transcript.canonical_text
    finally:
        connection.close()


def test_actual_reply_cannot_be_deleted_after_it_was_recorded(
    tmp_path: Path,
) -> None:
    connection, repository, session_id = _repository(tmp_path, suffix=11)
    turn_id, selected_id, _, _ = _awaiting_actual(
        repository,
        session_id,
        suffix=11,
    )
    try:
        actual = ActualReplyService(repository).record_adopted(
            session_id,
            turn_id,
            selected_id,
            sent_at=datetime(2026, 7, 19, 8, 10, tzinfo=timezone.utc),
            idempotency_key="actual-11",
        )

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM actual_replies WHERE actual_reply_id = ?",
                (actual.actual_reply_id,),
            )

        assert ActualTranscriptReader(repository).snapshot(session_id).turns[0].reply_text == (
            "最终采用的回复"
        )
    finally:
        connection.close()


def test_open_turn_cannot_propose_archive_bundle(tmp_path: Path) -> None:
    connection, repository, session_id = _repository(tmp_path, suffix=2)
    turn_id = "018f0000-0000-7101-8000-000000000002"
    TurnService(repository).append(session_id, turn_id, "尚未完成的来访者输入")
    try:
        with pytest.raises(ArchiveBundleError, match="ARCHIVE_OPEN_TURN"):
            ArchiveBundleService(repository).propose(session_id)
        assert repository.get_session(session_id).status == "OPEN"
    finally:
        connection.close()


def test_empty_session_archive_proposal_does_not_close_session(tmp_path: Path) -> None:
    connection, repository, session_id = _repository(tmp_path, suffix=10)
    try:
        with pytest.raises(ArchiveBundleError, match="ARCHIVE_EMPTY_SESSION"):
            ArchiveBundleService(repository).propose(session_id)

        assert repository.get_session(session_id).status == "OPEN"
        assert connection.execute(
            "SELECT count(*) FROM archive_bundles WHERE session_id = ?",
            (session_id,),
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_external_reply_unknown_is_archivable_but_incomplete(tmp_path: Path) -> None:
    connection, repository, session_id = _repository(tmp_path, suffix=3)
    turn_id, _, _, _ = _awaiting_actual(repository, session_id, suffix=3)
    try:
        ActualReplyService(repository).record_external_unknown(
            session_id,
            turn_id,
            confirmed_at=datetime(2026, 7, 19, 8, 30, tzinfo=timezone.utc),
            idempotency_key="external-unknown-3",
        )

        bundle = ArchiveBundleService(repository).propose(session_id)
        transcript = ActualTranscriptReader(repository).snapshot(session_id)

        assert bundle.incomplete_evidence is True
        assert transcript.incomplete_evidence is True
        assert transcript.turns[0].reply_text is None
        assert transcript.turns[0].evidence_gap is True
        assert repository.get_session(session_id).status == "CLOSED"
    finally:
        connection.close()


def test_actual_transcript_hash_is_stable_when_only_reader_clock_advances(
    tmp_path: Path,
) -> None:
    connection, repository, session_id = _repository(tmp_path, suffix=9)
    turn_id, selected_id, _, _ = _awaiting_actual(repository, session_id, suffix=9)
    try:
        ActualReplyService(repository).record_adopted(
            session_id,
            turn_id,
            selected_id,
            sent_at=repository.clock.now(),
            idempotency_key="actual-9",
        )
        first = ActualTranscriptReader(repository).snapshot(session_id)
        repository.clock = FixedClock(repository.clock.now() + timedelta(hours=1))
        second = ActualTranscriptReader(repository).snapshot(session_id)
        bundle = ArchiveBundleService(repository).propose(session_id)

        assert second.canonical_text == first.canonical_text
        assert second.actual_transcript_ref.content_sha256 == (
            first.actual_transcript_ref.content_sha256
        )
        assert bundle.actual_transcript_ref.content_sha256 == (
            first.actual_transcript_ref.content_sha256
        )
    finally:
        connection.close()
