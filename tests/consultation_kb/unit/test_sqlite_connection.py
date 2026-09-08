from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from consultation_kb.storage.connection import (
    NestedTransactionError,
    connect_database,
    connect_database_snapshot,
    transaction,
)


def test_writer_connection_uses_required_pragmas(tmp_path: Path) -> None:
    connection = connect_database(tmp_path / "client.sqlite3", mode="writer")
    try:
        assert connection.isolation_level is None
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    finally:
        connection.close()


def test_reader_connection_is_read_only_and_does_not_create_missing_file(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing.sqlite3"

    with pytest.raises(sqlite3.OperationalError):
        connect_database(missing, mode="reader")

    assert not missing.exists()

    writer = connect_database(tmp_path / "existing.sqlite3", mode="writer")
    writer.execute("CREATE TABLE item(id INTEGER PRIMARY KEY)")
    writer.close()
    reader = connect_database(tmp_path / "existing.sqlite3", mode="reader")
    try:
        assert reader.isolation_level is None
        assert reader.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert reader.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
        assert reader.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            reader.execute("INSERT INTO item(id) VALUES (1)")
    finally:
        reader.close()


def test_reader_sees_committed_wal_snapshot_while_writer_remains_open(
    tmp_path: Path,
) -> None:
    database = tmp_path / "active.sqlite3"
    writer = connect_database(database, mode="writer")
    try:
        writer.execute("CREATE TABLE item(id INTEGER PRIMARY KEY)")
        writer.execute("INSERT INTO item(id) VALUES (1)")
        reader = connect_database(database, mode="reader")
        try:
            assert reader.execute("SELECT count(*) FROM item").fetchone()[0] == 1
        finally:
            reader.close()
    finally:
        writer.close()


def test_offline_snapshot_reader_is_zero_write_and_refuses_wal(
    tmp_path: Path,
) -> None:
    database = tmp_path / "active.sqlite3"
    writer = connect_database(database, mode="writer")
    try:
        writer.execute("CREATE TABLE item(id INTEGER PRIMARY KEY)")
        writer.execute("INSERT INTO item(id) VALUES (1)")
        assert database.with_name(f"{database.name}-wal").exists()

        with pytest.raises(sqlite3.OperationalError, match="DATABASE_SNAPSHOT_UNSAFE"):
            connect_database_snapshot(database)
    finally:
        writer.close()

    files_before = {path.name for path in tmp_path.iterdir()}
    snapshot = connect_database_snapshot(database)
    try:
        assert snapshot.execute("SELECT count(*) FROM item").fetchone()[0] == 1
    finally:
        snapshot.close()
    assert {path.name for path in tmp_path.iterdir()} == files_before


def test_transaction_rolls_back_all_rows(tmp_path: Path) -> None:
    connection = connect_database(tmp_path / "x.sqlite3", mode="writer")
    try:
        connection.execute("CREATE TABLE item(id INTEGER PRIMARY KEY)")
        with pytest.raises(RuntimeError, match="inject"):
            with transaction(connection):
                connection.execute("INSERT INTO item(id) VALUES (1)")
                raise RuntimeError("inject")

        assert connection.execute("SELECT count(*) FROM item").fetchone()[0] == 0
        assert not connection.in_transaction
    finally:
        connection.close()


def test_transaction_commits_and_rejects_nesting(tmp_path: Path) -> None:
    connection = connect_database(tmp_path / "x.sqlite3", mode="writer")
    try:
        connection.execute("CREATE TABLE item(id INTEGER PRIMARY KEY)")
        with transaction(connection, immediate=False):
            connection.execute("INSERT INTO item(id) VALUES (1)")
            with pytest.raises(NestedTransactionError):
                with transaction(connection):
                    pass

        assert connection.execute("SELECT count(*) FROM item").fetchone()[0] == 1
        assert not connection.in_transaction
    finally:
        connection.close()


def test_connection_rejects_unknown_mode_without_creating_file(tmp_path: Path) -> None:
    database = tmp_path / "unknown.sqlite3"

    with pytest.raises(ValueError, match="DATABASE_MODE_INVALID"):
        connect_database(database, mode="invalid")  # type: ignore[arg-type]

    assert not database.exists()
