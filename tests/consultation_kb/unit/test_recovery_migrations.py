from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.storage.migrations.client import v0007_recovery_journal


NOW = "2026-07-22T12:00:00.000000Z"


@pytest.mark.parametrize(("scope", "latest"), [("global", 9), ("client", 7)])
def test_fresh_recovery_schema_is_body_free_and_closed(
    tmp_path: Path,
    scope: str,
    latest: int,
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", "writer")
    try:
        MigrationRunner.for_scope(connection, scope).apply()  # type: ignore[arg-type]
        assert connection.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone() == (latest,)
        expected = {
            "recovery_operation_authority_bindings",
            "recovery_epoch_retention_windows",
            "recovery_decision_journal",
            "recovery_prepared_retirements",
            "recovery_required_actions",
        }
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert expected.issubset(tables)
        forbidden = {
            "body",
            "payload",
            "path",
            "client_id",
            "session_id",
            "transcript",
        }
        for table in expected:
            columns = {
                str(row[1])
                for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            }
            assert columns.isdisjoint(forbidden)
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ["global", "client"])
def test_live_authority_binding_and_retention_window_are_immutable(
    tmp_path: Path,
    scope: str,
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", "writer")
    try:
        MigrationRunner.for_scope(connection, scope).apply()  # type: ignore[arg-type]
        if scope == "global":
            connection.execute(
                "UPDATE knowledge_catalog_state SET catalog_version = 1 "
                "WHERE singleton = 1"
            )
            connection.execute(
                "UPDATE knowledge_catalog_state SET authorization_epoch = 1 "
                "WHERE singleton = 1"
            )
            expected = (1, 1, 0, "LIVE")
        else:
            connection.execute(
                "UPDATE client_fact_authority SET commit_version = 4 "
                "WHERE singleton = 1"
            )
            expected = (4, 0, 0, "LIVE")
        operation_id = "operation_019f79d1-7d00-7000-8000-000000000001"
        connection.execute(
            "INSERT INTO publication_operations("
            "operation_id, purpose, authority_base_version, approval_request_id, "
            "descriptor_sha256, state, required_manifests_json, "
            "required_manifest_count, verified_manifest_count, "
            "expected_current_epoch, runtime_epoch, created_at, activated_at"
            ") VALUES (?, 'recovery_test', 4, ?, ?, 'PREPARED', '[]', "
            "0, 0, NULL, NULL, ?, NULL)",
            (
                operation_id,
                "approval_request_019f79d1-7d00-7000-8000-000000000002",
                "a" * 64,
                NOW,
            ),
        )
        assert connection.execute(
            "SELECT authority_version, permission_epoch, tombstone_epoch, "
            "binding_origin FROM recovery_operation_authority_bindings "
            "WHERE operation_id = ?",
            (operation_id,),
        ).fetchone() == expected
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE recovery_operation_authority_bindings "
                "SET authority_version = authority_version + 1 "
                "WHERE operation_id = ?",
                (operation_id,),
            )

        connection.execute(
            "INSERT INTO runtime_epochs("
            "epoch, operation_id, state, created_at, activated_at"
            ") VALUES (1, ?, 'ACTIVE', ?, ?)",
            (operation_id, NOW, NOW),
        )
        connection.execute(
            "UPDATE runtime_epochs SET state = 'RETIRED' WHERE epoch = 1"
        )
        assert connection.execute(
            "SELECT retention_required, binding_origin "
            "FROM recovery_epoch_retention_windows WHERE epoch = 1"
        ).fetchone() == (0, "DEFAULT")
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE recovery_epoch_retention_windows "
                "SET retention_required = 1 WHERE epoch = 1"
            )
    finally:
        connection.close()


def test_client_recovery_migration_has_no_global_authority_dependency() -> None:
    source = "\n".join(v0007_recovery_journal._STATEMENTS)
    assert "knowledge_catalog_state" not in source
    assert "client_fact_authority" in source
    assert "recovery_outbox_authority_bindings" in source
