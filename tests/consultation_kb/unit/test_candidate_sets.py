from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.session import CandidateDraft
from consultation_kb.session.candidate_sets import CandidateSetConflict, CandidateSetService
from consultation_kb.session.repository import PreviousTurnNotClosed, SessionRepository
from consultation_kb.session.turns import TurnService
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore


def _active_generation(tmp_path: Path) -> tuple[sqlite3.Connection, SessionRepository, str, str, str]:
    connection = connect_database(tmp_path / "client.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "client").apply()
    clock = FixedClock(datetime(2026, 7, 19, 4, 0, tzinfo=timezone.utc))
    values = iter(range(100, 500))
    repository = SessionRepository(
        connection,
        content_store=ContentStore(tmp_path / "scope"),
        clock=clock,
        id_factory=IdFactory(clock=clock, random_source=lambda: next(values)),
    )
    session_id = "018f0000-0000-7000-8000-000000000101"
    turn_id = "018f0000-0000-7000-8000-000000000102"
    run_id = "018f0000-0000-7000-8000-000000000103"
    repository.create_session(
        session_id=session_id,
        client_id="client_" + "aaaaaaaaaaaa",
        client_scope_hash="a" * 64,
        snapshot_version=0,
        snapshot_canonical_sha256="b" * 64,
        snapshot_bytes=b'{"empty":true}\n',
    )
    turns = TurnService(repository)
    turns.append(session_id, turn_id, "我不知道接下来怎么办")
    turns.begin_generation(session_id, turn_id, run_id=run_id)
    return connection, repository, session_id, turn_id, run_id


def test_candidate_set_is_atomic_idempotent_and_not_actual_reply(tmp_path: Path) -> None:
    connection, repository, session_id, turn_id, run_id = _active_generation(tmp_path)
    service = CandidateSetService(repository)
    try:
        drafts = (
            CandidateDraft(label="温和共情", text="先陪你看清最在意的部分。"),
            CandidateDraft(label="探索引导", text="如果只选一个问题，你想先谈哪个？"),
        )
        first = service.store_and_await(
            session_id,
            turn_id,
            drafts,
            run_id=run_id,
            idempotency_key="candidate-set-1",
        )
        second = service.store_and_await(
            session_id,
            turn_id,
            drafts,
            run_id=run_id,
            idempotency_key="candidate-set-1",
        )

        assert second == first
        assert repository.get_turn(session_id, turn_id).state == "awaiting_actual_reply"
        assert repository.list_actual_replies(session_id) == ()
        assert tuple(repository.read_content(item.content).decode() for item in first.candidates) == tuple(
            item.text for item in drafts
        )
        with pytest.raises(PreviousTurnNotClosed, match="PREVIOUS_TURN_NOT_CLOSED"):
            repository.append_client_turn(
                session_id,
                "018f0000-0000-7000-8000-000000000104",
                "下一条消息",
            )
    finally:
        connection.close()


def test_candidate_idempotency_key_rejects_changed_content(tmp_path: Path) -> None:
    connection, repository, session_id, turn_id, run_id = _active_generation(tmp_path)
    service = CandidateSetService(repository)
    try:
        service.store_and_await(
            session_id,
            turn_id,
            ("候选一", "候选二"),
            run_id=run_id,
            idempotency_key="candidate-set-1",
        )
        with pytest.raises(CandidateSetConflict, match="CANDIDATE_SET_IDEMPOTENCY_CONFLICT"):
            service.store_and_await(
                session_id,
                turn_id,
                ("候选一", "被替换的候选"),
                run_id=run_id,
                idempotency_key="candidate-set-1",
            )
    finally:
        connection.close()
