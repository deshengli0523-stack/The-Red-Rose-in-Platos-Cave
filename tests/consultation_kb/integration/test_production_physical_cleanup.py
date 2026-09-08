from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from consultation_kb.lifecycle.backup_queue import (
    BackupDestructionQueue,
    BackupDestructionRecord,
    BackupDestructionWorker,
    BackupQueueError,
)
from consultation_kb.lifecycle.physical_cleanup import AuthorizedPhysicalCleanupWorker
from consultation_kb.lifecycle.sqlite_cleanup import (
    SYNTHETIC_VAULT_MARKER,
    SYNTHETIC_VAULT_MARKER_BYTES,
    SyntheticCleanupScope,
)
from consultation_kb.models.deletion import deletion_intent_authority_sha256
from consultation_kb.storage.deletion_inventory import session_authority_sha256
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.storage.tombstones import lineage_hash, target_hash
from consultation_kb.vault.content_store import ContentStore


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=UTC)
STAMP = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
SCOPE_HASH = "1" * 64
PLAN_SHA256 = "2" * 64
DESCRIPTOR_SHA256 = "3" * 64
NONCE_SHA256 = "4" * 64


def _vault(tmp_path: Path, scope_name: str) -> tuple[SyntheticCleanupScope, Path, Path]:
    root = tmp_path / scope_name
    root.mkdir(parents=True)
    (root / SYNTHETIC_VAULT_MARKER).write_bytes(SYNTHETIC_VAULT_MARKER_BYTES)
    database = root / "authority.sqlite3"
    connection = sqlite3.connect(database, isolation_level=None)
    try:
        MigrationRunner.for_scope(connection, scope_name).apply()
    finally:
        connection.close()
    cas_root = root / "cas"
    cas_root.mkdir()
    return SyntheticCleanupScope.open(root, allowed_parent=tmp_path), database, cas_root


def _connect(database: Path) -> sqlite3.Connection:
    return sqlite3.connect(database, isolation_level=None, timeout=5.0)


def _seed_request(
    connection: sqlite3.Connection,
    *,
    root_type: str,
    root_id: str,
    target_type: str,
    target_id: str,
    target_version: int,
    target_sha256: str,
    authority_scope: str,
    include_backup: bool = False,
    include_proof: bool = True,
) -> tuple[str, str | None]:
    request_id = "deletion-request"
    operation_id = "deletion-operation"
    approval_request_id = "approval-request"
    connection.execute(
        """
        INSERT INTO approval_executions(
            operation_id, request_id, descriptor_sha256, draft_sha256,
            descriptor_base_version, target_scope_hash, nonce_sha256, state
        ) VALUES (?, ?, ?, ?, 0, ?, ?, 'CLAIMED')
        """,
        (
            operation_id,
            approval_request_id,
            DESCRIPTOR_SHA256,
            PLAN_SHA256,
            SCOPE_HASH,
            NONCE_SHA256,
        ),
    )
    connection.execute(
        """
        UPDATE approval_executions
           SET state = 'APPLIED', applied_commit_version = 1, applied_at = ?
         WHERE operation_id = ?
        """,
        (STAMP, operation_id),
    )
    connection.execute(
        """
        INSERT INTO deletion_requests(
            request_id, operation_id, plan_sha256, target_type,
            target_id_hash, target_scope_hash, base_deletion_version,
            committed_deletion_version, tombstone_epoch,
            approval_request_id, approval_descriptor_sha256,
            approval_target_scope_hash, state, queue_state, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 0, 1, 1, ?, ?, ?,
                  'TOMBSTONED', 'PENDING', ?)
        """,
        (
            request_id,
            operation_id,
            PLAN_SHA256,
            root_type,
            target_hash(root_type, root_id),
            SCOPE_HASH,
            approval_request_id,
            DESCRIPTOR_SHA256,
            SCOPE_HASH,
            STAMP,
        ),
    )
    root_lineage = lineage_hash(root_type, root_id)
    connection.execute(
        """
        INSERT INTO tombstones(
            tombstone_id, target_type, target_id_hash,
            source_lineage_hash, reason_code, created_at
        ) VALUES ('root-tombstone', ?, ?, ?, 'REQUESTED', ?)
        """,
        (root_type, target_hash(root_type, root_id), root_lineage, STAMP),
    )
    if target_type != root_type or target_id != root_id:
        connection.execute(
            """
            INSERT INTO tombstones(
                tombstone_id, target_type, target_id_hash,
                source_lineage_hash, reason_code, created_at
            ) VALUES ('target-tombstone', ?, ?, ?, 'REQUESTED', ?)
            """,
            (
                target_type,
                target_hash(target_type, target_id),
                root_lineage,
                STAMP,
            ),
        )
    connection.execute(
        "UPDATE deletion_authority_state "
        "SET deletion_version = 1, tombstone_epoch = 1 WHERE singleton = 1"
    )
    physical_intent = "physical-intent"
    _insert_intent(
        connection,
        intent_id=physical_intent,
        request_id=request_id,
        action_id="physical-action",
        action_type="physical_delete",
        object_type=target_type,
        object_id=target_id,
        target_version=target_version,
        target_sha256=target_sha256,
        authority_scope=authority_scope,
        root_type=root_type,
        root_id=root_id,
        root_lineage=root_lineage,
        include_proof=include_proof,
    )
    backup_intent = None
    if include_backup:
        backup_intent = "backup-intent"
        _insert_intent(
            connection,
            intent_id=backup_intent,
            request_id=request_id,
            action_id="backup-action",
            action_type="backup_expiry",
            object_type="backup_set",
            object_id="backup-set",
            target_version=1,
            target_sha256="5" * 64,
            authority_scope=authority_scope,
            root_type=root_type,
            root_id=root_id,
            root_lineage=root_lineage,
            include_proof=True,
        )
    return physical_intent, backup_intent


def _insert_intent(
    connection: sqlite3.Connection,
    *,
    intent_id: str,
    request_id: str,
    action_id: str,
    action_type: str,
    object_type: str,
    object_id: str,
    target_version: int,
    target_sha256: str,
    authority_scope: str,
    root_type: str,
    root_id: str,
    root_lineage: str,
    include_proof: bool,
) -> None:
    target_id_sha256 = target_hash(object_type, object_id)
    connection.execute(
        """
        INSERT INTO deletion_queue_intents(
            intent_id, request_id, action_id, action_type, object_type,
            target_id_hash, target_version, target_content_sha256,
            authority_scope, state, attempt_count, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', 0, ?)
        """,
        (
            intent_id,
            request_id,
            action_id,
            action_type,
            object_type,
            target_id_sha256,
            target_version,
            target_sha256,
            authority_scope,
            STAMP,
        ),
    )
    if not include_proof:
        return
    root_id_sha256 = target_hash(root_type, root_id)
    descriptor = deletion_intent_authority_sha256(
        intent_id=intent_id,
        request_id=request_id,
        action_id=action_id,
        action_type=action_type,  # type: ignore[arg-type]
        object_type=object_type,
        target_id_hash=target_id_sha256,
        target_version=target_version,
        target_content_sha256=target_sha256,
        authority_scope=authority_scope,  # type: ignore[arg-type]
        deletion_plan_sha256=PLAN_SHA256,
        root_object_type=root_type,
        root_target_id_hash=root_id_sha256,
        root_lineage_hash=root_lineage,
    )
    connection.execute(
        """
        INSERT INTO deletion_intent_authority_proofs(
            intent_id, request_id, action_id, deletion_plan_sha256,
            root_object_type, root_target_id_hash, root_lineage_hash,
            action_descriptor_sha256, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            intent_id,
            request_id,
            action_id,
            PLAN_SHA256,
            root_type,
            root_id_sha256,
            root_lineage,
            descriptor,
            STAMP,
        ),
    )


def _store_bytes(cas_root: Path, payload: bytes) -> str:
    store = ContentStore(cas_root)
    staged = store.stage_bytes(
        payload,
        purpose="cleanup",
        manifest_id="cleanup_019f55c5-5e2c-7e20-bfe3-65480ce3bb0d",
        media_type="application/octet-stream",
    )
    return store.finalize(staged).content_sha256


def _worker(
    database: Path,
    scope: SyntheticCleanupScope,
    cas_root: Path,
    scope_name: str,
    **kwargs: object,
) -> AuthorizedPhysicalCleanupWorker:
    return AuthorizedPhysicalCleanupWorker(
        lambda: _connect(database),
        authority_scope=scope_name,  # type: ignore[arg-type]
        scope=scope,
        database_path=database,
        cas_root=cas_root,
        **kwargs,  # type: ignore[arg-type]
    )


def test_real_v6_authority_resolves_cas_and_controlled_vector_copy(
    tmp_path: Path,
) -> None:
    scope, database, cas_root = _vault(tmp_path, "global")
    payload = b"PRODUCTION_CAS_AND_VECTOR_CANARY"
    digest = _store_bytes(cas_root, payload)
    vector = scope.root / "indexes" / "vector" / "old.npy"
    vector.parent.mkdir(parents=True)
    vector.write_bytes(payload)
    connection = _connect(database)
    try:
        intent_id, _backup = _seed_request(
            connection,
            root_type="case",
            root_id="case-one",
            target_type="case",
            target_id="case-one",
            target_version=1,
            target_sha256=digest,
            authority_scope="global",
        )
    finally:
        connection.close()

    worker = _worker(database, scope, cas_root, "global")
    result = worker.process(intent_id)
    replay = worker.process(intent_id)

    assert result.state == "succeeded"
    assert result.deleted_file_count == 2
    assert replay.state == "succeeded"
    assert replay.deleted_file_count == 0
    assert replay.attempt_count == 1
    assert not vector.exists()
    connection = _connect(database)
    try:
        assert connection.execute(
            "SELECT state, attempt_count FROM deletion_queue_intents"
        ).fetchone() == ("SUCCEEDED", 1)
        assert connection.execute(
            "SELECT state, queue_state FROM deletion_requests"
        ).fetchone() == ("PHYSICAL_CLEANUP_COMPLETE", "SUCCEEDED")
        assert connection.execute("SELECT count(*) FROM tombstones").fetchone() == (
            1,
        )
    finally:
        connection.close()


def test_cancelled_sibling_never_counts_as_cleanup_closure(
    tmp_path: Path,
) -> None:
    scope, database, cas_root = _vault(tmp_path, "global")
    digest = _store_bytes(cas_root, b"CANCELLED_SIBLING_CLOSURE_CANARY")
    connection = _connect(database)
    try:
        physical_intent, backup_intent = _seed_request(
            connection,
            root_type="case",
            root_id="case-one",
            target_type="case",
            target_id="case-one",
            target_version=1,
            target_sha256=digest,
            authority_scope="global",
            include_backup=True,
        )
        assert backup_intent is not None
        connection.execute(
            "UPDATE deletion_queue_intents SET state = 'CANCELLED', "
            "finished_at = ? WHERE intent_id = ?",
            (STAMP, backup_intent),
        )
    finally:
        connection.close()

    result = _worker(database, scope, cas_root, "global").process(physical_intent)

    assert result.state == "succeeded"
    connection = _connect(database)
    try:
        assert connection.execute(
            "SELECT state FROM deletion_queue_intents ORDER BY intent_id"
        ).fetchall() == [("CANCELLED",), ("SUCCEEDED",)]
        assert connection.execute(
            "SELECT state, queue_state FROM deletion_requests"
        ).fetchone() == ("TOMBSTONED", "PARTIAL")
    finally:
        connection.close()


def test_missing_exact_authority_proof_fails_closed_without_claim_or_delete(
    tmp_path: Path,
) -> None:
    scope, database, cas_root = _vault(tmp_path, "global")
    digest = _store_bytes(cas_root, b"UNAUTHORIZED_DELETE_CANARY")
    connection = _connect(database)
    try:
        intent_id, _backup = _seed_request(
            connection,
            root_type="case",
            root_id="case-one",
            target_type="case",
            target_id="case-one",
            target_version=1,
            target_sha256=digest,
            authority_scope="global",
            include_proof=False,
        )
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="CLEANUP_AUTHORITY_INVALID"):
        _worker(database, scope, cas_root, "global").process(intent_id)

    assert ContentStore(cas_root).read_hash_verified(digest) == b"UNAUTHORIZED_DELETE_CANARY"
    connection = _connect(database)
    try:
        assert connection.execute(
            "SELECT state, attempt_count FROM deletion_queue_intents"
        ).fetchone() == ("PENDING", 0)
    finally:
        connection.close()


def _activate_reference(connection: sqlite3.Connection, digest: str) -> None:
    connection.execute(
        """
        INSERT INTO publication_operations(
            operation_id, purpose, authority_base_version,
            approval_request_id, descriptor_sha256, state,
            required_manifests_json, required_manifest_count,
            verified_manifest_count, expected_current_epoch,
            runtime_epoch, created_at, activated_at
        ) VALUES ('active-operation', 'test', 1, 'active-approval', ?,
                  'ACTIVE', '["active-manifest"]', 1, 1, NULL, 1, ?, ?)
        """,
        ("6" * 64, STAMP, STAMP),
    )
    connection.execute(
        "INSERT INTO runtime_epochs VALUES (1, 'active-operation', 'ACTIVE', ?, ?)",
        (STAMP, STAMP),
    )
    connection.execute(
        """
        INSERT INTO artifact_manifests(
            manifest_id, operation_id, artifact_key, artifact_kind,
            source_version, manifest_sha256, state, verified,
            created_at, verified_at
        ) VALUES ('active-manifest', 'active-operation', 'vector', 'vector',
                  '1', ?, 'ACTIVE', 1, ?, ?)
        """,
        ("7" * 64, STAMP, STAMP),
    )
    connection.execute(
        """
        INSERT INTO artifact_members(
            manifest_id, ordinal, object_type, object_id, object_sha256,
            source_version, source_lineage_json, media_type, size_bytes
        ) VALUES ('active-manifest', 0, 'unrelated', 'other-object', ?,
                  '1', '[]', 'application/octet-stream', 1)
        """,
        (digest,),
    )
    connection.execute(
        "INSERT INTO active_artifacts VALUES (1, 'vector', 'active-manifest', ?)",
        (STAMP,),
    )


def test_active_manifest_reference_blocks_cas_reclamation_for_rollback(
    tmp_path: Path,
) -> None:
    scope, database, cas_root = _vault(tmp_path, "global")
    payload = b"SHARED_ACTIVE_VECTOR_CANARY"
    digest = _store_bytes(cas_root, payload)
    connection = _connect(database)
    try:
        intent_id, _backup = _seed_request(
            connection,
            root_type="case",
            root_id="case-one",
            target_type="case",
            target_id="case-one",
            target_version=1,
            target_sha256=digest,
            authority_scope="global",
        )
        _activate_reference(connection, digest)
    finally:
        connection.close()

    result = _worker(database, scope, cas_root, "global").process(intent_id)

    assert result.state == "retry_pending"
    assert result.active_reference_count == 1
    assert ContentStore(cas_root).read_hash_verified(digest) == payload
    connection = _connect(database)
    try:
        assert connection.execute(
            "SELECT state, last_error_code FROM deletion_queue_intents"
        ).fetchone() == ("FAILED", "CAS_REFERENCES_REMAIN")
        assert connection.execute("SELECT count(*) FROM tombstones").fetchone() == (
            1,
        )
    finally:
        connection.close()


def test_pending_backup_destruction_blocks_cas_reclamation(
    tmp_path: Path,
) -> None:
    scope, database, cas_root = _vault(tmp_path, "global")
    payload = b"CAS_PENDING_BACKUP_CANARY"
    digest = _store_bytes(cas_root, payload)
    connection = _connect(database)
    try:
        intent_id, backup_intent = _seed_request(
            connection,
            root_type="case",
            root_id="case-one",
            target_type="case",
            target_id="case-one",
            target_version=1,
            target_sha256=digest,
            authority_scope="global",
            include_backup=True,
        )
        assert backup_intent is not None
        BackupDestructionQueue(connection).enqueue_authorized(
            intent_id=backup_intent,
            backup_id="backup-one",
            object_sha256s=(digest,),
            location_class="offline_media",
            due_at=NOW,
            created_at=NOW,
            authority_scope="global",
        )
    finally:
        connection.close()

    result = _worker(database, scope, cas_root, "global").process(intent_id)

    assert result.state == "retry_pending"
    assert result.pending_backup_count == 1
    assert ContentStore(cas_root).read_hash_verified(digest) == payload
    connection = _connect(database)
    try:
        assert connection.execute(
            "SELECT state, last_error_code FROM deletion_queue_intents "
            "WHERE intent_id = ?",
            (intent_id,),
        ).fetchone() == ("FAILED", "BACKUP_DESTRUCTION_PENDING")
        assert connection.execute("SELECT count(*) FROM tombstones").fetchone() == (
            1,
        )
    finally:
        connection.close()


def test_exact_hash_removes_cache_temp_and_evaluation_old_versions_only(
    tmp_path: Path,
) -> None:
    scope, database, cas_root = _vault(tmp_path, "global")
    payload = b"CONTROLLED_OLD_VERSION_CANARY"
    digest = hashlib.sha256(payload).hexdigest()
    controlled = tuple(
        scope.root / relative
        for relative in (
            Path("cache") / "old.cache",
            Path("temp") / "old.tmp",
            Path("evaluation") / "old.json",
        )
    )
    for path in controlled:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    neighbor = scope.root / "cache" / "current.cache"
    neighbor.write_bytes(b"CURRENT_VERSION_MUST_SURVIVE")
    connection = _connect(database)
    try:
        intent_id, _backup = _seed_request(
            connection,
            root_type="case",
            root_id="case-one",
            target_type="case",
            target_id="case-one",
            target_version=1,
            target_sha256=digest,
            authority_scope="global",
        )
    finally:
        connection.close()

    result = _worker(database, scope, cas_root, "global").process(intent_id)

    assert result.state == "succeeded"
    assert result.deleted_file_count == len(controlled)
    assert all(not path.exists() for path in controlled)
    assert neighbor.read_bytes() == b"CURRENT_VERSION_MUST_SURVIVE"


def test_post_delete_pre_ack_retry_is_idempotent(tmp_path: Path) -> None:
    scope, database, cas_root = _vault(tmp_path, "global")
    payload = b"POST_DELETE_PRE_ACK_CANARY"
    digest = hashlib.sha256(payload).hexdigest()
    vector = scope.root / "indexes" / "vector" / "old.npy"
    vector.parent.mkdir(parents=True)
    vector.write_bytes(payload)
    connection = _connect(database)
    try:
        intent_id, _backup = _seed_request(
            connection,
            root_type="case",
            root_id="case-one",
            target_type="case",
            target_id="case-one",
            target_version=1,
            target_sha256=digest,
            authority_scope="global",
        )
    finally:
        connection.close()
    worker = _worker(database, scope, cas_root, "global")
    original_ack = worker._mark_succeeded  # noqa: SLF001
    calls = 0

    def fail_after_first_delete(exact_intent_id: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("synthetic crash after unlink before durable ACK")
        original_ack(exact_intent_id)

    worker._mark_succeeded = fail_after_first_delete  # type: ignore[method-assign]  # noqa: SLF001

    first = worker.process(intent_id)
    second = worker.process(intent_id)

    assert first.state == "retry_pending"
    assert not vector.exists()
    assert second.state == "succeeded"
    assert second.deleted_file_count == 0
    assert second.attempt_count == 2
    connection = _connect(database)
    try:
        assert connection.execute(
            "SELECT state, attempt_count FROM deletion_queue_intents"
        ).fetchone() == ("SUCCEEDED", 2)
        assert connection.execute("SELECT count(*) FROM tombstones").fetchone() == (
            1,
        )
    finally:
        connection.close()


def test_succeeded_intent_rejects_reappeared_file(tmp_path: Path) -> None:
    scope, database, cas_root = _vault(tmp_path, "global")
    payload = b"RESTORED_AFTER_SUCCESS_CANARY"
    digest = hashlib.sha256(payload).hexdigest()
    cache = scope.root / "cache" / "old.cache"
    cache.parent.mkdir(parents=True)
    cache.write_bytes(payload)
    connection = _connect(database)
    try:
        intent_id, _backup = _seed_request(
            connection,
            root_type="case",
            root_id="case-one",
            target_type="case",
            target_id="case-one",
            target_version=1,
            target_sha256=digest,
            authority_scope="global",
        )
    finally:
        connection.close()
    worker = _worker(database, scope, cas_root, "global")
    assert worker.process(intent_id).state == "succeeded"

    cache.write_bytes(payload)

    with pytest.raises(
        RuntimeError,
        match="PHYSICAL_CLEANUP_FILE_STILL_PRESENT",
    ):
        worker.process(intent_id)
    connection = _connect(database)
    try:
        assert connection.execute(
            "SELECT state, attempt_count FROM deletion_queue_intents"
        ).fetchone() == ("SUCCEEDED", 1)
        assert connection.execute("SELECT count(*) FROM tombstones").fetchone() == (
            1,
        )
    finally:
        connection.close()


class _LockOnce:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, path: Path) -> None:
        self.calls += 1
        if self.calls == 1:
            raise PermissionError("synthetic Windows mmap sharing violation")
        path.unlink()


def test_production_vector_mmap_lock_retries_without_restoring_tombstone(
    tmp_path: Path,
) -> None:
    scope, database, cas_root = _vault(tmp_path, "global")
    payload = b"MMAP_VECTOR_LOCK_CANARY"
    digest = hashlib.sha256(payload).hexdigest()
    vector = scope.root / "indexes" / "vector" / "old.npy"
    vector.parent.mkdir(parents=True)
    vector.write_bytes(payload)
    connection = _connect(database)
    try:
        intent_id, _backup = _seed_request(
            connection,
            root_type="case",
            root_id="case-one",
            target_type="case",
            target_id="case-one",
            target_version=1,
            target_sha256=digest,
            authority_scope="global",
        )
    finally:
        connection.close()
    remover = _LockOnce()
    worker = _worker(
        database,
        scope,
        cas_root,
        "global",
        file_remover=remover,
    )

    first = worker.process(intent_id)
    second = worker.process(intent_id)

    assert first.state == "retry_pending"
    assert second.state == "succeeded"
    assert second.attempt_count == 2
    assert not vector.exists()
    connection = _connect(database)
    try:
        assert connection.execute("SELECT count(*) FROM tombstones").fetchone() == (
            1,
        )
    finally:
        connection.close()


def test_session_inline_immutable_body_uses_authorized_clean_rebuild(
    tmp_path: Path,
) -> None:
    scope, database, cas_root = _vault(tmp_path, "client")
    session_id = "session-one"
    client_id = "client" + "_abcdefghijkl"
    connection = _connect(database)
    try:
        connection.execute(
            """
            INSERT INTO sessions(
                session_id, client_scope_hash, state, started_at, client_id,
                client_snapshot_version, client_snapshot_canonical_sha256,
                last_closed_turn_ordinal, updated_at
            ) VALUES (?, ?, 'CLOSED', ?, ?, 0, NULL, 0, ?)
            """,
            (session_id, SCOPE_HASH, STAMP, client_id, STAMP),
        )
        canary = "PRIVATE_INLINE_SESSION_CANARY"
        connection.execute(
            """
            INSERT INTO internal_risk_observations(
                observation_id, session_id, immutable_record_json, status
            ) VALUES ('risk-one', ?, ?, 'open')
            """,
            (session_id, json.dumps({"private": canary})),
        )
        authority_sha = session_authority_sha256(
            session_id=session_id,
            client_id=client_id,
            client_scope_hash=SCOPE_HASH,
            client_snapshot_version=0,
            client_snapshot_canonical_sha256=None,
            started_at=STAMP,
        )
        intent_id, _backup = _seed_request(
            connection,
            root_type="session",
            root_id=session_id,
            target_type="session",
            target_id=session_id,
            target_version=0,
            target_sha256=authority_sha,
            authority_scope="client",
        )
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()

    result = _worker(database, scope, cas_root, "client").process(intent_id)

    assert result.state == "succeeded"
    assert result.sanitized_row_count == 1
    for path in (database, Path(f"{database}-wal"), Path(f"{database}-shm")):
        if path.is_file():
            assert canary.encode() not in path.read_bytes()
    connection = _connect(database)
    try:
        assert connection.execute(
            "SELECT count(*) FROM internal_risk_observations"
        ).fetchone() == (0,)
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("SELECT count(*) FROM tombstones").fetchone() == (
            1,
        )
    finally:
        connection.close()


@dataclass
class _OfflineThenProof:
    proof: str | None = None

    def destroy(self, record: BackupDestructionRecord) -> str | None:
        assert record.location_class == "offline_media"
        return self.proof


def test_offline_backup_stays_pending_until_exact_operator_proof(
    tmp_path: Path,
) -> None:
    _scope, database, _cas_root = _vault(tmp_path, "global")
    payload_sha256 = "8" * 64
    connection = _connect(database)
    try:
        physical_intent, backup_intent = _seed_request(
            connection,
            root_type="case",
            root_id="case-one",
            target_type="case",
            target_id="case-one",
            target_version=1,
            target_sha256=payload_sha256,
            authority_scope="global",
            include_backup=True,
        )
        assert backup_intent is not None
        queue = BackupDestructionQueue(connection)
        with pytest.raises(
            BackupQueueError,
            match="BACKUP_QUEUE_OBJECT_CLOSURE_MISMATCH",
        ):
            queue.enqueue_authorized(
                intent_id=backup_intent,
                backup_id="backup-one",
                object_sha256s=(payload_sha256, "9" * 64),
                location_class="offline_media",
                due_at=NOW,
                created_at=NOW,
                authority_scope="global",
            )
        record = queue.enqueue_authorized(
            intent_id=backup_intent,
            backup_id="backup-one",
            object_sha256s=(payload_sha256,),
            location_class="offline_media",
            due_at=NOW,
            created_at=NOW,
            authority_scope="global",
        )
        assert record.state == "pending"
        adapter = _OfflineThenProof()
        worker = BackupDestructionWorker(
            connection,
            authority_scope="global",
            adapter=adapter,
            clock=lambda: NOW + timedelta(days=1),
        )

        pending = worker.process(backup_id="backup-one", intent_id=backup_intent)
        adapter.proof = "a" * 64
        completed = worker.process(backup_id="backup-one", intent_id=backup_intent)

        assert pending.state == "pending_operator"
        assert queue.get("backup-one").state == "succeeded"
        assert completed.state == "succeeded"
        assert completed.operator_proof_sha256 == "a" * 64
        assert connection.execute(
            "SELECT state FROM deletion_queue_intents WHERE intent_id = ?",
            (backup_intent,),
        ).fetchone() == ("SUCCEEDED",)
        assert connection.execute(
            "SELECT state FROM deletion_queue_intents WHERE intent_id = ?",
            (physical_intent,),
        ).fetchone() == ("PENDING",)
    finally:
        connection.close()
