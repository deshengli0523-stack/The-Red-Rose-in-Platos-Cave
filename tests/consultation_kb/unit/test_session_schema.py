from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner, load_migrations


def test_client_migrations_register_complete_session_schema(tmp_path: Path) -> None:
    connection = connect_database(tmp_path / "client.sqlite3", mode="writer")
    try:
        migrations = load_migrations("client")
        MigrationRunner(connection, migrations).apply()

        assert [migration.version for migration in migrations] == [
            1,
            2,
            3,
            4,
            5,
            6,
            7,
        ]
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert {
            "sessions",
            "turns",
            "candidate_sets",
            "candidate_replies",
            "actual_replies",
            "session_fact_events",
            "generation_stage_artifacts",
            "risk_observations",
            "session_checkpoints",
            "turn_risk_evaluations",
            "archive_bundles",
            "archive_purpose_states",
            "private_archive_revisions",
            "profile_diff_drafts",
            "shared_case_candidates",
            "outbox_events",
        } <= tables

        for table in (
            "turns",
            "candidate_replies",
            "actual_replies",
            "generation_stage_artifacts",
            "session_checkpoints",
            "turn_risk_evaluations",
            "archive_bundles",
            "private_archive_revisions",
            "profile_diff_drafts",
            "shared_case_candidates",
            "outbox_events",
        ):
            columns = {
                str(row[1])
                for row in connection.execute(f"PRAGMA table_info({table})")
            }
            assert not ({"body", "text", "content", "transcript"} & columns)

        checkpoint_columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(session_checkpoints)")
        }
        assert "checkpoint_sequence" in checkpoint_columns
    finally:
        connection.close()


def test_database_rejects_turn_state_skip_and_session_snapshot_rebinding(
    tmp_path: Path,
) -> None:
    connection = connect_database(tmp_path / "client.sqlite3", mode="writer")
    try:
        MigrationRunner.for_scope(connection, "client").apply()
        connection.execute(
            """
            INSERT INTO sessions(
                session_id, client_scope_hash, state, started_at, client_id,
                client_snapshot_version, client_snapshot_canonical_sha256,
                client_snapshot_object_id, client_snapshot_sha256,
                client_snapshot_media_type, client_snapshot_size_bytes,
                capability_epoch, archive_state, last_closed_turn_ordinal,
                updated_at
            ) VALUES (?, ?, 'OPEN', ?, ?, 1, ?, ?, ?, 'application/json', 2,
                      1, 'NOT_STARTED', 0, ?)
            """,
            (
                "018f0000-0000-7000-8000-000000000001",
                "a" * 64,
                "2026-07-19T00:00:00.000000Z",
                "client_" + "aaaaaaaaaaaa",
                "b" * 64,
                "session_context_018f0000-0000-7000-8000-000000000002",
                "c" * 64,
                "2026-07-19T00:00:00.000000Z",
            ),
        )
        connection.execute(
            """
            INSERT INTO turns(
                session_id, turn_id, ordinal, client_message_object_id,
                client_message_sha256, client_message_media_type,
                client_message_size_bytes, state, received_at, updated_at
            ) VALUES (?, ?, 1, ?, ?, 'text/plain', 2,
                      'client_turn_received', ?, ?)
            """,
            (
                "018f0000-0000-7000-8000-000000000001",
                "018f0000-0000-7000-8000-000000000003",
                "client_turn_018f0000-0000-7000-8000-000000000004",
                "d" * 64,
                "2026-07-19T00:00:00.000000Z",
                "2026-07-19T00:00:00.000000Z",
            ),
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE turns SET state = 'awaiting_actual_reply' WHERE ordinal = 1"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE sessions SET client_snapshot_version = 2 WHERE state = 'OPEN'"
            )
    finally:
        connection.close()
