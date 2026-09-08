from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

import consultation_kb.lifecycle.sqlite_cleanup as sqlite_cleanup_module
from consultation_kb.lifecycle.sqlite_cleanup import (
    SYNTHETIC_VAULT_MARKER,
    SYNTHETIC_VAULT_MARKER_BYTES,
    CleanupScopeError,
    SqliteCleanupRequest,
    SqliteSanitizer,
    SyntheticCleanupScope,
)


CANARY = b"PHYSICAL_CLEANUP_CANARY_" + (b"X" * 3500)


def _scope(tmp_path: Path) -> tuple[SyntheticCleanupScope, Path]:
    vault = tmp_path / "synthetic-vault"
    vault.mkdir(parents=True)
    (vault / SYNTHETIC_VAULT_MARKER).write_bytes(SYNTHETIC_VAULT_MARKER_BYTES)
    return SyntheticCleanupScope.open(vault, allowed_parent=tmp_path), vault


def _file_contains(path: Path, needle: bytes) -> bool:
    return path.is_file() and needle in path.read_bytes()


def test_secure_delete_checkpoint_and_clean_rebuild_remove_sqlite_residue(
    tmp_path: Path,
) -> None:
    scope, vault = _scope(tmp_path)
    database = vault / "client.sqlite3"
    connection = sqlite3.connect(database, isolation_level=None)
    try:
        assert connection.execute("PRAGMA journal_mode = WAL").fetchone() == ("wal",)
        connection.execute("PRAGMA secure_delete = OFF")
        connection.execute(
            "CREATE TABLE private_rows(id INTEGER PRIMARY KEY, body BLOB)"
        )
        connection.execute("CREATE VIRTUAL TABLE private_fts USING fts5(body)")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("INSERT INTO private_rows(body) VALUES (?)", (CANARY,))
        connection.execute(
            "INSERT INTO private_fts(rowid, body) VALUES (1, ?)",
            (CANARY.decode("ascii"),),
        )
        connection.execute("COMMIT")
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()
    assert _file_contains(database, CANARY)

    def delete_private_rows(active: sqlite3.Connection) -> int:
        active.execute("DELETE FROM private_fts WHERE rowid = 1")
        return active.execute("DELETE FROM private_rows WHERE id = 1").rowcount

    result = SqliteSanitizer(scope).sanitize(
        SqliteCleanupRequest(
            database_path=database,
            delete_callback=delete_private_rows,
            fts_tables=("private_fts",),
            forbidden_needles=(
                CANARY,
                hashlib.sha256(CANARY).hexdigest().encode("ascii"),
            ),
        )
    )

    assert result.deleted_row_count == 1
    assert result.secure_delete_enabled
    assert result.wal_checkpoint_truncated
    assert result.strategy == "vacuum_into_atomic_replace"
    assert result.fts_cleanup_mode == "fts5_secure_delete"
    for suffix in ("", "-wal", "-shm", "-journal"):
        assert not _file_contains(Path(f"{database}{suffix}"), CANARY)
    verify = sqlite3.connect(database)
    try:
        assert verify.execute("SELECT count(*) FROM private_rows").fetchone() == (0,)
        assert verify.execute("SELECT count(*) FROM private_fts").fetchone() == (0,)
        assert verify.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        verify.close()


def test_ordinary_delete_without_sanitizer_leaves_demonstrable_residue(
    tmp_path: Path,
) -> None:
    _scope_value, vault = _scope(tmp_path)
    database = vault / "ordinary-delete.sqlite3"
    connection = sqlite3.connect(database, isolation_level=None)
    try:
        connection.execute("PRAGMA secure_delete = OFF")
        connection.execute(
            "CREATE TABLE private_rows(id INTEGER PRIMARY KEY, body BLOB)"
        )
        connection.execute("INSERT INTO private_rows(body) VALUES (?)", (CANARY,))
        connection.execute("DELETE FROM private_rows")
    finally:
        connection.close()

    assert _file_contains(database, CANARY)


def test_pre_342_fts_branch_uses_clean_rebuild_and_atomic_switch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, vault = _scope(tmp_path)
    database = vault / "legacy-fts.sqlite3"
    connection = sqlite3.connect(database, isolation_level=None)
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA secure_delete = OFF")
        connection.execute("CREATE VIRTUAL TABLE private_fts USING fts5(body)")
        connection.execute(
            "INSERT INTO private_fts(rowid, body) VALUES (1, ?)",
            (CANARY.decode("ascii"),),
        )
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()
    monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 41, 2))

    result = SqliteSanitizer(scope).sanitize(
        SqliteCleanupRequest(
            database_path=database,
            delete_callback=lambda active: (
                active.execute("DELETE FROM private_fts WHERE rowid = 1").rowcount
            ),
            fts_tables=("private_fts",),
            forbidden_needles=(CANARY,),
        )
    )

    assert result.fts_cleanup_mode == "clean_rebuild"
    assert result.strategy == "vacuum_into_atomic_replace"
    assert not any(
        _file_contains(Path(f"{database}{suffix}"), CANARY)
        for suffix in ("", "-wal", "-shm", "-journal")
    )


def test_runtime_without_fts_secure_delete_command_uses_clean_rebuild(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, vault = _scope(tmp_path)
    database = vault / "capability-fallback.sqlite3"
    connection = sqlite3.connect(database, isolation_level=None)
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA secure_delete = OFF")
        connection.execute("CREATE VIRTUAL TABLE private_fts USING fts5(body)")
        connection.execute(
            "INSERT INTO private_fts(rowid, body) VALUES (1, ?)",
            (CANARY.decode("ascii"),),
        )
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()

    def unavailable(
        _connection: sqlite3.Connection,
        _tables: tuple[str, ...],
    ) -> None:
        raise sqlite3.OperationalError("unknown FTS5 special command: secure-delete")

    monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 99, 0))
    monkeypatch.setattr(sqlite_cleanup_module, "_set_fts_secure_delete", unavailable)

    result = SqliteSanitizer(scope).sanitize(
        SqliteCleanupRequest(
            database_path=database,
            delete_callback=lambda active: (
                active.execute("DELETE FROM private_fts WHERE rowid = 1").rowcount
            ),
            fts_tables=("private_fts",),
            forbidden_needles=(CANARY,),
        )
    )

    assert result.fts_cleanup_mode == "clean_rebuild"
    assert result.strategy == "vacuum_into_atomic_replace"
    assert not any(
        _file_contains(Path(f"{database}{suffix}"), CANARY)
        for suffix in ("", "-wal", "-shm", "-journal")
    )


def test_sqlite_sanitizer_refuses_unmarked_or_out_of_scope_database(
    tmp_path: Path,
) -> None:
    vault = tmp_path / "unmarked"
    vault.mkdir()
    database = vault / "unsafe.sqlite3"
    sqlite3.connect(database).close()

    with pytest.raises(CleanupScopeError, match="CLEANUP_SYNTHETIC_SCOPE_REQUIRED"):
        SyntheticCleanupScope.open(vault, allowed_parent=tmp_path)

    safe_scope, _safe_vault = _scope(tmp_path / "safe-parent")
    with pytest.raises(CleanupScopeError, match="CLEANUP_PATH_OUT_OF_SCOPE"):
        SqliteSanitizer(safe_scope).sanitize(
            SqliteCleanupRequest(
                database_path=database,
                delete_callback=lambda _connection: 0,
            )
        )
