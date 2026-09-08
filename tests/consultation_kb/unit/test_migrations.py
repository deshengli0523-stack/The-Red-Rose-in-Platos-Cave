from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Callable

import pytest

from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import (
    MigrationChecksumError,
    MigrationHistoryError,
    MigrationPendingError,
    MigrationRunner,
    load_migrations,
)


@dataclass(frozen=True)
class FakeMigration:
    version: int
    name: str
    sha256: str
    upgrade: Callable[[sqlite3.Connection], None]


def _sha256(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _create_item(connection: sqlite3.Connection) -> None:
    connection.execute("CREATE TABLE item(id INTEGER PRIMARY KEY)")


def test_apply_records_migration_and_is_idempotent(tmp_path: Path) -> None:
    connection = connect_database(tmp_path / "db.sqlite3", mode="writer")
    migration = FakeMigration(1, "create_item", _sha256("v1"), _create_item)
    runner = MigrationRunner(connection, (migration,))
    try:
        runner.apply()
        runner.apply()
        runner.check()

        rows = connection.execute(
            "SELECT version, name, sha256 FROM schema_migrations"
        ).fetchall()
        assert rows == [(1, "create_item", migration.sha256)]
        assert connection.execute("SELECT count(*) FROM item").fetchone()[0] == 0
    finally:
        connection.close()


def test_check_rejects_changed_applied_checksum(tmp_path: Path) -> None:
    connection = connect_database(tmp_path / "db.sqlite3", mode="writer")
    first = FakeMigration(1, "create_item", _sha256("v1"), _create_item)
    try:
        MigrationRunner(connection, (first,)).apply()
        changed = FakeMigration(1, "create_item", _sha256("changed"), _create_item)

        with pytest.raises(MigrationChecksumError):
            MigrationRunner(connection, (changed,)).check()
    finally:
        connection.close()


def test_failed_migration_rolls_back_schema_and_record(tmp_path: Path) -> None:
    def fail_after_create(connection: sqlite3.Connection) -> None:
        connection.execute("CREATE TABLE half_written(id INTEGER PRIMARY KEY)")
        raise RuntimeError("injected migration failure")

    connection = connect_database(tmp_path / "db.sqlite3", mode="writer")
    migration = FakeMigration(1, "broken", _sha256("broken"), fail_after_create)
    try:
        with pytest.raises(RuntimeError, match="injected migration failure"):
            MigrationRunner(connection, (migration,)).apply()

        assert (
            connection.execute(
                "SELECT count(*) FROM sqlite_master WHERE name = 'half_written'"
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute("SELECT count(*) FROM schema_migrations").fetchone()[0]
            == 0
        )
        assert not connection.in_transaction
    finally:
        connection.close()


def test_migration_cannot_escape_runner_transaction_with_executescript(
    tmp_path: Path,
) -> None:
    def attempt_implicit_commit(connection: sqlite3.Connection) -> None:
        connection.executescript(
            "CREATE TABLE escaped(id INTEGER PRIMARY KEY);"
            "INSERT INTO escaped(id) VALUES (1);"
        )

    connection = connect_database(tmp_path / "db.sqlite3", mode="writer")
    migration = FakeMigration(
        1,
        "escape_attempt",
        _sha256("escape"),
        attempt_implicit_commit,
    )
    try:
        with pytest.raises(sqlite3.DatabaseError):
            MigrationRunner(connection, (migration,)).apply()

        assert (
            connection.execute(
                "SELECT count(*) FROM sqlite_master WHERE name = 'escaped'"
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute("SELECT count(*) FROM schema_migrations").fetchone()[0]
            == 0
        )
    finally:
        connection.close()


def test_check_is_read_only_when_bootstrap_table_is_missing(tmp_path: Path) -> None:
    database = tmp_path / "db.sqlite3"
    writer = connect_database(database, mode="writer")
    writer.close()
    before = database.stat().st_size

    reader = connect_database(database, mode="reader")
    try:
        with pytest.raises(MigrationPendingError):
            MigrationRunner(reader, load_migrations("global")).check()
    finally:
        reader.close()

    assert database.stat().st_size == before
    verify = connect_database(database, mode="reader")
    try:
        assert (
            verify.execute(
                "SELECT count(*) FROM sqlite_master WHERE name = 'schema_migrations'"
            ).fetchone()[0]
            == 0
        )
    finally:
        verify.close()


def test_history_with_gap_fails_closed(tmp_path: Path) -> None:
    connection = connect_database(tmp_path / "db.sqlite3", mode="writer")
    first = FakeMigration(1, "one", _sha256("one"), lambda conn: None)
    second = FakeMigration(2, "two", _sha256("two"), lambda conn: None)
    try:
        runner = MigrationRunner(connection, (first, second))
        runner.ensure_migration_table()
        connection.execute(
            "INSERT INTO schema_migrations(version, name, sha256, applied_at) "
            "VALUES (2, ?, ?, '2026-07-18T00:00:00Z')",
            (second.name, second.sha256),
        )

        with pytest.raises(MigrationHistoryError):
            runner.apply()
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("scope", "expected_tables"),
    [
        (
            "global",
            {
                "clients",
                "capabilities",
                "approval_requests",
                "approval_receipts",
                "approval_executions",
                "publication_operations",
                "runtime_epochs",
                "artifact_manifests",
                "artifact_members",
                "active_artifacts",
                "tombstones",
                "audit_events",
            },
        ),
        (
            "client",
            {
                "sessions",
                "review_decisions",
                "approval_executions",
                "publication_operations",
                "runtime_epochs",
                "artifact_manifests",
                "artifact_members",
                "active_artifacts",
                "tombstones",
            },
        ),
    ],
)
def test_v0001_creates_required_scope_tables(
    tmp_path: Path,
    scope: str,
    expected_tables: set[str],
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        migrations = load_migrations(scope)  # type: ignore[arg-type]
        MigrationRunner(connection, migrations).apply()
        MigrationRunner(connection, migrations).check()
        actual = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert expected_tables <= actual
    finally:
        connection.close()


def test_resource_migration_checksum_is_source_bytes() -> None:
    migration = load_migrations("global")[0]
    source = (
        resources.files("consultation_kb.storage.migrations.global")
        .joinpath("v0001_initial.py")
        .read_bytes()
    )

    assert migration.sha256 == hashlib.sha256(source).hexdigest()


def test_global_approval_request_binds_exact_scope_hash_and_integer_version(
    tmp_path: Path,
) -> None:
    connection = connect_database(tmp_path / "global.sqlite3", mode="writer")
    try:
        MigrationRunner.for_scope(connection, "global").apply()
        columns = {
            row[1]: row[2]
            for row in connection.execute("PRAGMA table_info(approval_requests)")
        }

        assert "target_scope" not in columns
        assert columns["target_scope_hash"] == "TEXT"
        assert columns["base_version"] == "INTEGER"
        assert "diff_object_id" not in columns
        assert columns["diff_object_ref_json"] == "TEXT"
    finally:
        connection.close()


def test_global_capability_schema_binds_token_session_client_and_epoch(
    tmp_path: Path,
) -> None:
    connection = connect_database(tmp_path / "global.sqlite3", mode="writer")
    try:
        MigrationRunner.for_scope(connection, "global").apply()
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(capabilities)")
        }

        assert {
            "capability_id",
            "token_sha256",
            "session_id",
            "client_id",
            "permissions_json",
            "issued_at",
            "expires_at",
            "revoked_at",
            "state",
            "capability_epoch",
        } <= columns
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ["global", "client"])
def test_approval_execution_supports_claim_before_apply(
    tmp_path: Path,
    scope: str,
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        MigrationRunner.for_scope(connection, scope).apply()  # type: ignore[arg-type]
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(approval_executions)")
        }
        assert "acknowledged_at" not in columns
        assert "draft_sha256" in columns
        assert "descriptor_base_version" in columns
        connection.execute(
            """
            INSERT INTO approval_executions(
                operation_id, request_id, descriptor_sha256, draft_sha256,
                descriptor_base_version, target_scope_hash,
                nonce_sha256, state, applied_commit_version, applied_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'CLAIMED', NULL, NULL)
            """,
            (
                "operation",
                "request",
                "a" * 64,
                "d" * 64,
                0,
                "b" * 64,
                "c" * 64,
            ),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO approval_executions(
                    operation_id, request_id, descriptor_sha256, draft_sha256,
                    descriptor_base_version, target_scope_hash,
                    nonce_sha256, state,
                    applied_commit_version, applied_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'APPLIED', NULL, NULL)
                """,
                (
                    "operation-2",
                    "request-2",
                    "d" * 64,
                    "a" * 64,
                    0,
                    "e" * 64,
                    "f" * 64,
                ),
            )
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ["global", "client"])
def test_publication_operation_binds_descriptor_hash(
    tmp_path: Path,
    scope: str,
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        MigrationRunner.for_scope(connection, scope).apply()  # type: ignore[arg-type]
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(publication_operations)")
        }
        assert "descriptor_sha256" in columns
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ["global", "client"])
def test_artifact_member_requires_source_lineage_json(
    tmp_path: Path,
    scope: str,
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        MigrationRunner.for_scope(connection, scope).apply()  # type: ignore[arg-type]
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(artifact_members)")
        }
        assert "source_lineage_json" in columns
        assert "object_type" in columns
    finally:
        connection.close()
