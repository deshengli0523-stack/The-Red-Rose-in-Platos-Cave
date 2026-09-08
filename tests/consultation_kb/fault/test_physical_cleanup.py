from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from consultation_kb.lifecycle.backup_queue import (
    BACKUP_QUEUE_SCHEMA,
    BackupDestructionQueue,
)
from consultation_kb.lifecycle.physical_cleanup import (
    CLEANUP_ARTIFACT_KINDS,
    CleanupWorkItem,
    PhysicalCleanupError,
    PhysicalCleanupWorker,
)
from consultation_kb.lifecycle.sqlite_cleanup import (
    SYNTHETIC_VAULT_MARKER,
    SYNTHETIC_VAULT_MARKER_BYTES,
    SyntheticCleanupScope,
)
from consultation_kb.storage.tombstones import target_hash


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
CANARY = b"LOCKED_VECTOR_CANARY"
TARGET_HASH = target_hash("vector_shard", "synthetic-vector")


def _scope(tmp_path: Path) -> tuple[SyntheticCleanupScope, Path]:
    vault = tmp_path / "synthetic-vault"
    vault.mkdir(parents=True)
    (vault / SYNTHETIC_VAULT_MARKER).write_bytes(SYNTHETIC_VAULT_MARKER_BYTES)
    return SyntheticCleanupScope.open(vault, allowed_parent=tmp_path), vault


def _queue_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.executescript(
        """
        CREATE TABLE tombstones(
            target_type TEXT NOT NULL,
            target_id_hash TEXT NOT NULL
        );
        CREATE TABLE deletion_queue_intents(
            intent_id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            action_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            object_type TEXT NOT NULL,
            target_id_hash TEXT NOT NULL,
            state TEXT NOT NULL,
            attempt_count INTEGER NOT NULL,
            last_error_code TEXT,
            claimed_at TEXT,
            finished_at TEXT
        );
        """
    )
    connection.execute(
        "INSERT INTO tombstones(target_type, target_id_hash) VALUES (?, ?)",
        ("vector_shard", TARGET_HASH),
    )
    connection.execute(
        """
        INSERT INTO deletion_queue_intents(
            intent_id, request_id, action_id, action_type, object_type,
            target_id_hash, state, attempt_count
        ) VALUES ('intent', 'request', 'action', 'physical_delete',
                  'vector_shard', ?, 'PENDING', 0)
        """,
        (TARGET_HASH,),
    )
    return connection


class _LockOnceRemover:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, path: Path) -> None:
        self.calls += 1
        if self.calls == 1:
            raise PermissionError("synthetic Windows sharing violation")
        path.unlink()


def test_windows_file_lock_enters_retry_without_removing_tombstone(
    tmp_path: Path,
) -> None:
    scope, vault = _scope(tmp_path)
    shard = vault / "vector" / "old.npy"
    shard.parent.mkdir()
    shard.write_bytes(CANARY)
    connection = _queue_connection()
    remover = _LockOnceRemover()
    worker = PhysicalCleanupWorker(connection, scope=scope, file_remover=remover)
    work = CleanupWorkItem(
        intent_id="intent",
        artifact_kind="vector_shard",
        object_type="vector_shard",
        target_id_hash=TARGET_HASH,
        relative_path=Path("vector/old.npy"),
        expected_file_sha256=hashlib.sha256(CANARY).hexdigest(),
    )
    try:
        first = worker.process(work)

        assert first.state == "retry_pending"
        assert shard.exists()
        assert connection.execute(
            "SELECT state, attempt_count, last_error_code FROM deletion_queue_intents"
        ).fetchone() == ("FAILED", 1, "FILE_LOCK_RETRY")
        assert connection.execute("SELECT count(*) FROM tombstones").fetchone() == (1,)

        second = worker.process(work)

        assert second.state == "succeeded"
        assert not shard.exists()
        assert connection.execute(
            "SELECT state, attempt_count FROM deletion_queue_intents"
        ).fetchone() == ("SUCCEEDED", 2)
        assert connection.execute("SELECT count(*) FROM tombstones").fetchone() == (1,)
    finally:
        connection.close()


def test_backup_queue_remains_pending_until_operator_proof() -> None:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    for statement in BACKUP_QUEUE_SCHEMA:
        connection.execute(statement)
    queue = BackupDestructionQueue(connection)
    try:
        record = queue.enqueue(
            backup_id="backup-1",
            request_id="request-1",
            object_sha256s=("a" * 64, "b" * 64),
            location_class="offline_media",
            due_at=NOW + timedelta(days=30),
            created_at=NOW,
        )
        assert record.state == "pending"
        assert record.operator_proof_sha256 is None
        assert queue.pending() == (record,)

        completed = queue.complete(
            "backup-1",
            operator_proof_sha256="c" * 64,
            finished_at=NOW + timedelta(days=1),
        )

        assert completed.state == "succeeded"
        assert completed.operator_proof_sha256 == "c" * 64
        assert queue.pending() == ()
        rendered = repr(completed)
        assert "consultation" not in rendered.lower()
    finally:
        connection.close()


def test_cleanup_refuses_to_run_without_governing_tombstone(tmp_path: Path) -> None:
    scope, vault = _scope(tmp_path)
    artifact = vault / "cache" / "derived.bin"
    artifact.parent.mkdir()
    artifact.write_bytes(CANARY)
    connection = _queue_connection()
    connection.execute("DELETE FROM tombstones")
    worker = PhysicalCleanupWorker(connection, scope=scope)
    work = CleanupWorkItem(
        intent_id="intent",
        artifact_kind="cache",
        object_type="vector_shard",
        target_id_hash=TARGET_HASH,
        relative_path=Path("cache/derived.bin"),
        expected_file_sha256=hashlib.sha256(CANARY).hexdigest(),
    )
    try:
        with pytest.raises(
            PhysicalCleanupError,
            match="PHYSICAL_CLEANUP_TOMBSTONE_REQUIRED",
        ):
            worker.process(work)

        assert artifact.read_bytes() == CANARY
        assert connection.execute(
            "SELECT state, attempt_count FROM deletion_queue_intents"
        ).fetchone() == ("PENDING", 0)
    finally:
        connection.close()


def test_cleanup_registry_covers_every_physical_surface() -> None:
    assert set(CLEANUP_ARTIFACT_KINDS) == {
        "primary_file",
        "session_copy",
        "global_case_copy",
        "case_contribution",
        "graph",
        "fts",
        "vector_shard",
        "wiki_render",
        "cache",
        "export",
        "temporary_file",
        "evaluation_sample",
        "old_content_object",
        "sqlite_wal",
        "sqlite_shm",
        "backup",
    }
