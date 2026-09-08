from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.session.actual_replies import ActualReplyService
from consultation_kb.session.candidate_sets import CandidateSetService
from consultation_kb.session.repository import PreviousTurnNotClosed, SessionRepository
from consultation_kb.session.turns import TurnService
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore


@pytest.mark.acceptance_id("TURN-01")
def test_candidate_is_never_assumed_sent_before_next_client_turn(tmp_path: Path) -> None:
    connection = connect_database(tmp_path / "client.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "client").apply()
    now = datetime(2026, 7, 19, 7, 0, tzinfo=timezone.utc)
    clock = FixedClock(now)
    values = iter(range(1500, 1900))
    repository = SessionRepository(
        connection,
        content_store=ContentStore(tmp_path / "scope"),
        clock=clock,
        id_factory=IdFactory(clock=clock, random_source=lambda: next(values)),
    )
    session_id = "018f0000-0000-7000-8000-000000000301"
    first_turn = "018f0000-0000-7000-8000-000000000302"
    second_turn = "018f0000-0000-7000-8000-000000000303"
    run_id = "018f0000-0000-7000-8000-000000000304"
    try:
        repository.create_session(
            session_id=session_id,
            client_id="client_" + "aaaaaaaaaaaa",
            client_scope_hash="a" * 64,
            snapshot_version=0,
            snapshot_canonical_sha256="b" * 64,
            snapshot_bytes=b'{"empty":true}\n',
        )
        turns = TurnService(repository)
        turns.append(session_id, first_turn, "第一条消息")
        turns.begin_generation(session_id, first_turn, run_id=run_id)
        CandidateSetService(repository).store_and_await(
            session_id,
            first_turn,
            ("候选一", "候选二"),
            run_id=run_id,
            idempotency_key="set-1",
        )

        with pytest.raises(PreviousTurnNotClosed, match="PREVIOUS_TURN_NOT_CLOSED"):
            turns.append(session_id, second_turn, "第二条消息")
        assert repository.list_actual_replies(session_id) == ()

        ActualReplyService(repository).record_external_unknown(
            session_id,
            first_turn,
            confirmed_at=now,
            idempotency_key="actual-unknown",
        )
        appended = turns.append(session_id, second_turn, "第二条消息")
        assert appended.ordinal == 2
    finally:
        connection.close()
