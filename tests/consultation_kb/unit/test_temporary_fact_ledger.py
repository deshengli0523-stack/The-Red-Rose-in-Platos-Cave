from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.session.repository import SessionRepository
from consultation_kb.session.temporary_ledger import (
    TemporaryFactLedger,
    TemporaryLedgerConflict,
)
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore


def _repository(tmp_path: Path) -> tuple[sqlite3.Connection, SessionRepository]:
    connection = connect_database(tmp_path / "client.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "client").apply()
    clock = FixedClock(datetime(2026, 7, 19, 5, 0, tzinfo=timezone.utc))
    values = iter(range(500, 900))
    return connection, SessionRepository(
        connection,
        content_store=ContentStore(tmp_path / "scope"),
        clock=clock,
        id_factory=IdFactory(clock=clock, random_source=lambda: next(values)),
    )


def test_temporary_facts_are_session_scoped_append_only_and_not_approved_facts(
    tmp_path: Path,
) -> None:
    connection, repository = _repository(tmp_path)
    session_a = "018f0000-0000-7000-8000-000000000201"
    session_b = "018f0000-0000-7000-8000-000000000202"
    turn_a = "018f0000-0000-7000-8000-000000000203"
    turn_b = "018f0000-0000-7000-8000-000000000204"
    try:
        for session_id, turn_id in ((session_a, turn_a), (session_b, turn_b)):
            repository.create_session(
                session_id=session_id,
                client_id="client_" + "aaaaaaaaaaaa",
                client_scope_hash="a" * 64,
                snapshot_version=0,
                snapshot_canonical_sha256="b" * 64,
                snapshot_bytes=b'{"empty":true}\n',
            )
            repository.append_client_turn(session_id, turn_id, "本轮陈述")
        ledger = TemporaryFactLedger(repository)
        added = ledger.propose(
            session_a,
            turn_a,
            event_kind="GOAL",
            cognitive_type="client_statement",
            value={"goal": "先稳定情绪"},
            idempotency_key="goal-1",
        )
        repeated = ledger.propose(
            session_a,
            turn_a,
            event_kind="GOAL",
            cognitive_type="client_statement",
            value={"goal": "先稳定情绪"},
            idempotency_key="goal-1",
        )
        corrected = ledger.correct(
            session_a,
            turn_a,
            target_fact_id="fact-partner",
            target_fact_version=2,
            value={"correction": "已经更换伴侣"},
            idempotency_key="correction-1",
        )

        assert repeated == added
        assert ledger.snapshot(session_a) == (added, corrected)
        assert ledger.snapshot(session_b) == ()
        assert repository.read_content(added.content).decode().endswith("\n")
        assert connection.execute("SELECT count(*) FROM fact_events").fetchone() == (0,)
        metadata = connection.execute(
            "SELECT event_json FROM session_fact_events WHERE session_event_id = ?",
            (added.event_id,),
        ).fetchone()[0]
        assert "先稳定情绪" not in metadata
        assert "approved" not in metadata
        stored_key = connection.execute(
            "SELECT idempotency_key_sha256 FROM session_fact_events "
            "WHERE session_event_id = ?",
            (added.event_id,),
        ).fetchone()[0]
        assert stored_key != "goal-1"

        with pytest.raises(
            TemporaryLedgerConflict,
            match="TEMPORARY_FACT_IDEMPOTENCY_CONFLICT",
        ):
            ledger.propose(
                session_a,
                turn_a,
                event_kind="GOAL",
                cognitive_type="client_statement",
                value={"goal": "被替换的内容"},
                idempotency_key="goal-1",
            )
    finally:
        connection.close()
