from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.session.repository import (
    SessionClosed,
    SessionConflict,
    SessionRepository,
)
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore


def _repository(tmp_path: Path) -> tuple[sqlite3.Connection, SessionRepository]:
    connection = connect_database(tmp_path / "client.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "client").apply()
    values = iter(range(1, 100))
    clock = FixedClock(datetime(2026, 7, 19, 1, 2, 3, tzinfo=timezone.utc))
    repository = SessionRepository(
        connection,
        content_store=ContentStore(tmp_path / "client-scope"),
        clock=clock,
        id_factory=IdFactory(clock=clock, random_source=lambda: next(values)),
    )
    return connection, repository


def _create(repository: SessionRepository, *, session_id: str) -> None:
    repository.create_session(
        session_id=session_id,
        client_id="client_" + "aaaaaaaaaaaa",
        client_scope_hash="a" * 64,
        snapshot_version=1,
        snapshot_canonical_sha256="b" * 64,
        snapshot_bytes=b'{"profile_version":1}\n',
    )


def test_turn_id_is_idempotent_and_changed_content_conflicts(tmp_path: Path) -> None:
    connection, repository = _repository(tmp_path)
    session_id = "018f0000-0000-7000-8000-000000000001"
    turn_id = "018f0000-0000-7000-8000-000000000002"
    try:
        _create(repository, session_id=session_id)

        first = repository.append_client_turn(session_id, turn_id, "第一条消息")
        second = repository.append_client_turn(session_id, turn_id, "第一条消息")

        assert second == first
        assert repository.count_turns(session_id) == 1
        assert repository.read_content(first.client_message) == "第一条消息".encode()
        with pytest.raises(SessionConflict, match="TURN_CONTENT_CONFLICT"):
            repository.append_client_turn(session_id, turn_id, "被替换的消息")
    finally:
        connection.close()


def test_session_snapshot_binding_is_immutable_and_closed_session_rejects_append(
    tmp_path: Path,
) -> None:
    connection, repository = _repository(tmp_path)
    session_id = "018f0000-0000-7000-8000-000000000010"
    try:
        created = repository.create_session(
            session_id=session_id,
            client_id="client_" + "aaaaaaaaaaaa",
            client_scope_hash="a" * 64,
            snapshot_version=1,
            snapshot_canonical_sha256="b" * 64,
            snapshot_bytes=b'{"profile_version":1}\n',
        )
        same = repository.create_session(
            session_id=session_id,
            client_id="client_" + "aaaaaaaaaaaa",
            client_scope_hash="a" * 64,
            snapshot_version=1,
            snapshot_canonical_sha256="b" * 64,
            snapshot_bytes=b'{"profile_version":1}\n',
        )
        assert same == created

        with pytest.raises(SessionConflict, match="SESSION_BINDING_CONFLICT"):
            repository.create_session(
                session_id=session_id,
                client_id="client_" + "aaaaaaaaaaaa",
                client_scope_hash="a" * 64,
                snapshot_version=2,
                snapshot_canonical_sha256="c" * 64,
                snapshot_bytes=b'{"profile_version":2}\n',
            )

        repository.close_session(session_id)
        with pytest.raises(SessionClosed, match="SESSION_CLOSED"):
            repository.append_client_turn(
                session_id,
                "018f0000-0000-7000-8000-000000000011",
                "不能追加",
            )
    finally:
        connection.close()


def test_checkpoint_rows_contain_only_refs_hashes_and_state_metadata(
    tmp_path: Path,
) -> None:
    connection, repository = _repository(tmp_path)
    session_id = "018f0000-0000-7000-8000-000000000020"
    turn_id = "018f0000-0000-7000-8000-000000000021"
    try:
        _create(repository, session_id=session_id)
        repository.append_client_turn(session_id, turn_id, "敏感正文不应复制到审计")

        row = connection.execute(
            "SELECT event_kind, from_state, to_state, payload_sha256 "
            "FROM session_checkpoints WHERE turn_id = ?",
            (turn_id,),
        ).fetchone()
        assert row == (
            "client_turn_appended",
            None,
            "client_turn_received",
            repository.get_turn(session_id, turn_id).client_message.content_sha256,
        )
        assert "敏感正文" not in repr(row)
    finally:
        connection.close()
