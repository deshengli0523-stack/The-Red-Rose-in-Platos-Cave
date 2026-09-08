"""Hash-only durable destruction queue for local and external backups."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol, TypeAlias

from consultation_kb.lifecycle.cleanup_authority import (
    CleanupAuthorityResolver,
    CleanupAuthorityScope,
)
from consultation_kb.storage.cleanup_inventory import SqlitePhysicalCleanupInventory
from consultation_kb.storage.connection import transaction


_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
BackupLocationClass: TypeAlias = Literal[
    "local_snapshot", "offline_media", "cloud_managed", "external_managed"
]
BackupQueueState: TypeAlias = Literal["pending", "failed", "succeeded"]
BackupProcessState: TypeAlias = Literal[
    "pending_retention", "pending_operator", "retry_pending", "succeeded"
]


BACKUP_QUEUE_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS backup_destruction_queue(
        backup_id TEXT PRIMARY KEY CHECK(length(backup_id) > 0),
        request_id TEXT NOT NULL CHECK(length(request_id) > 0),
        location_class TEXT NOT NULL CHECK(
            location_class IN (
                'local_snapshot', 'offline_media',
                'cloud_managed', 'external_managed'
            )
        ),
        object_set_sha256 TEXT NOT NULL CHECK(
            length(object_set_sha256) = 64
            AND object_set_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        due_at TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('pending', 'failed', 'succeeded')),
        attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
        last_error_code TEXT,
        finished_at TEXT,
        operator_proof_sha256 TEXT CHECK(
            operator_proof_sha256 IS NULL OR (
                length(operator_proof_sha256) = 64
                AND operator_proof_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        CHECK(updated_at >= created_at),
        CHECK(
            (state = 'succeeded'
             AND finished_at IS NOT NULL
             AND operator_proof_sha256 IS NOT NULL)
            OR
            (state != 'succeeded'
             AND finished_at IS NULL
             AND operator_proof_sha256 IS NULL)
        )
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS backup_destruction_objects(
        backup_id TEXT NOT NULL
            REFERENCES backup_destruction_queue(backup_id) ON DELETE RESTRICT,
        object_sha256 TEXT NOT NULL CHECK(
            length(object_sha256) = 64
            AND object_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        PRIMARY KEY(backup_id, object_sha256)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_backup_destruction_pending
    ON backup_destruction_queue(state, due_at, backup_id)
    """,
)


class BackupQueueError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("BACKUP_QUEUE_TIME_NOT_UTC")
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise BackupQueueError("BACKUP_QUEUE_ROW_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise BackupQueueError("BACKUP_QUEUE_ROW_INVALID") from None
    if parsed.utcoffset() != timedelta(0):
        raise BackupQueueError("BACKUP_QUEUE_ROW_INVALID")
    return parsed


def _sha256(value: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ValueError("BACKUP_QUEUE_HASH_INVALID")
    return value


def _object_set_sha256(values: tuple[str, ...]) -> str:
    return hashlib.sha256(
        b"consultation-kb-backup-object-set-v1\0"
        + b"\0".join(value.encode("ascii") for value in values)
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class BackupDestructionRecord:
    backup_id: str
    request_id: str
    object_sha256s: tuple[str, ...]
    object_set_sha256: str
    location_class: BackupLocationClass
    due_at: datetime
    state: BackupQueueState
    attempt_count: int
    last_error_code: str | None
    finished_at: datetime | None
    operator_proof_sha256: str | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class BackupProcessResult:
    backup_id: str
    intent_id: str
    state: BackupProcessState
    attempt_count: int
    object_set_sha256: str
    operator_proof_sha256: str | None


class BackupDestructionAdapter(Protocol):
    """External/local adapter returns proof only after verified destruction."""

    def destroy(self, record: BackupDestructionRecord) -> str | None: ...


class BackupDestructionQueue:
    """Persist proof-oriented backup destruction without copying a body."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("BACKUP_QUEUE_SQLITE_REQUIRED")
        self._connection = connection

    def enqueue(
        self,
        *,
        backup_id: str,
        request_id: str,
        object_sha256s: tuple[str, ...],
        location_class: BackupLocationClass,
        due_at: datetime,
        created_at: datetime,
    ) -> BackupDestructionRecord:
        objects = tuple(sorted(_sha256(value) for value in object_sha256s))
        if not objects or len(objects) != len(set(objects)):
            raise ValueError("BACKUP_QUEUE_OBJECT_SET_INVALID")
        if location_class not in {
            "local_snapshot",
            "offline_media",
            "cloud_managed",
            "external_managed",
        }:
            raise ValueError("BACKUP_QUEUE_LOCATION_INVALID")
        if not backup_id or not request_id:
            raise ValueError("BACKUP_QUEUE_ID_INVALID")
        due_text = _utc_text(due_at)
        created_text = _utc_text(created_at)
        if due_at < created_at:
            raise ValueError("BACKUP_QUEUE_DUE_TIME_INVALID")
        set_hash = _object_set_sha256(objects)
        with transaction(self._connection):
            existing = self._find(backup_id)
            if existing is not None:
                if (
                    existing.request_id == request_id
                    and existing.object_sha256s == objects
                    and existing.location_class == location_class
                    and existing.due_at == due_at
                ):
                    return existing
                raise BackupQueueError("BACKUP_QUEUE_IDEMPOTENCY_CONFLICT")
            self._connection.execute(
                """
                INSERT INTO backup_destruction_queue(
                    backup_id, request_id, location_class, object_set_sha256,
                    due_at, state, attempt_count, last_error_code,
                    finished_at, operator_proof_sha256, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', 0, NULL, NULL, NULL, ?, ?)
                """,
                (
                    backup_id,
                    request_id,
                    location_class,
                    set_hash,
                    due_text,
                    created_text,
                    created_text,
                ),
            )
            self._connection.executemany(
                "INSERT INTO backup_destruction_objects(backup_id, object_sha256) "
                "VALUES (?, ?)",
                [(backup_id, value) for value in objects],
            )
        return self.get(backup_id)

    def enqueue_authorized(
        self,
        *,
        intent_id: str,
        backup_id: str,
        object_sha256s: tuple[str, ...],
        location_class: BackupLocationClass,
        due_at: datetime,
        created_at: datetime,
        authority_scope: CleanupAuthorityScope,
    ) -> BackupDestructionRecord:
        """Enqueue only the exact object closure resolved from an approved plan."""

        authority = CleanupAuthorityResolver(
            self._connection,
            authority_scope=authority_scope,
        ).resolve(intent_id, expected_action_type="backup_expiry")
        physical_rows = self._connection.execute(
            """
            SELECT intent_id FROM deletion_queue_intents
             WHERE request_id = ? AND action_type = 'physical_delete'
             ORDER BY intent_id
            """,
            (authority.request_id,),
        ).fetchall()
        if not physical_rows:
            raise BackupQueueError("BACKUP_QUEUE_PHYSICAL_CLOSURE_MISSING")
        expected: set[str] = set()
        for row in physical_rows:
            physical = CleanupAuthorityResolver(
                self._connection,
                authority_scope=authority_scope,
            ).resolve(str(row[0]), expected_action_type="physical_delete")
            inventory = SqlitePhysicalCleanupInventory(
                self._connection,
                authority_scope=authority_scope,
            ).resolve(physical)
            expected.update(inventory.content_sha256s)
        objects = tuple(sorted(_sha256(value) for value in object_sha256s))
        if objects != tuple(sorted(expected)):
            raise BackupQueueError("BACKUP_QUEUE_OBJECT_CLOSURE_MISMATCH")
        return self.enqueue(
            backup_id=backup_id,
            request_id=authority.request_id,
            object_sha256s=objects,
            location_class=location_class,
            due_at=due_at,
            created_at=created_at,
        )

    def get(self, backup_id: str) -> BackupDestructionRecord:
        record = self._find(backup_id)
        if record is None:
            raise BackupQueueError("BACKUP_QUEUE_NOT_FOUND")
        return record

    def pending(self) -> tuple[BackupDestructionRecord, ...]:
        ids = self._connection.execute(
            "SELECT backup_id FROM backup_destruction_queue "
            "WHERE state IN ('pending', 'failed') ORDER BY due_at, backup_id"
        ).fetchall()
        return tuple(self.get(str(row[0])) for row in ids)

    def mark_failed(
        self,
        backup_id: str,
        *,
        error_code: str,
        failed_at: datetime,
    ) -> BackupDestructionRecord:
        if (
            type(error_code) is not str
            or not 1 <= len(error_code) <= 64
            or re.fullmatch(r"[A-Z0-9_]+", error_code) is None
        ):
            raise ValueError("BACKUP_QUEUE_ERROR_CODE_INVALID")
        with transaction(self._connection):
            current = self.get(backup_id)
            if current.state == "succeeded":
                return current
            if failed_at < current.updated_at:
                raise BackupQueueError("BACKUP_QUEUE_TIME_REGRESSION")
            self._connection.execute(
                """
                UPDATE backup_destruction_queue
                   SET state = 'failed', attempt_count = attempt_count + 1,
                       last_error_code = ?, updated_at = ?
                 WHERE backup_id = ?
                """,
                (error_code, _utc_text(failed_at), backup_id),
            )
        return self.get(backup_id)

    def complete(
        self,
        backup_id: str,
        *,
        operator_proof_sha256: str,
        finished_at: datetime,
    ) -> BackupDestructionRecord:
        proof = _sha256(operator_proof_sha256)
        with transaction(self._connection):
            current = self.get(backup_id)
            if current.state == "succeeded":
                if current.operator_proof_sha256 != proof:
                    raise BackupQueueError("BACKUP_QUEUE_PROOF_CONFLICT")
                return current
            if finished_at < current.updated_at:
                raise BackupQueueError("BACKUP_QUEUE_TIME_REGRESSION")
            finished_text = _utc_text(finished_at)
            self._connection.execute(
                """
                UPDATE backup_destruction_queue
                   SET state = 'succeeded', attempt_count = attempt_count + 1,
                       last_error_code = NULL, finished_at = ?,
                       operator_proof_sha256 = ?, updated_at = ?
                 WHERE backup_id = ?
                """,
                (finished_text, proof, finished_text, backup_id),
            )
        return self.get(backup_id)

    def _find(self, backup_id: str) -> BackupDestructionRecord | None:
        row = self._connection.execute(
            """
            SELECT backup_id, request_id, location_class, object_set_sha256,
                   due_at, state, attempt_count, last_error_code, finished_at,
                   operator_proof_sha256, created_at, updated_at
              FROM backup_destruction_queue WHERE backup_id = ?
            """,
            (backup_id,),
        ).fetchone()
        if row is None:
            return None
        objects = tuple(
            str(item[0])
            for item in self._connection.execute(
                "SELECT object_sha256 FROM backup_destruction_objects "
                "WHERE backup_id = ? ORDER BY object_sha256",
                (backup_id,),
            ).fetchall()
        )
        if (
            not objects
            or _object_set_sha256(objects) != row[3]
            or any(_SHA256_RE.fullmatch(value) is None for value in objects)
        ):
            raise BackupQueueError("BACKUP_QUEUE_ROW_INVALID")
        return BackupDestructionRecord(
            backup_id=str(row[0]),
            request_id=str(row[1]),
            location_class=row[2],
            object_sha256s=objects,
            object_set_sha256=str(row[3]),
            due_at=_parse_utc(row[4]),
            state=row[5],
            attempt_count=int(row[6]),
            last_error_code=None if row[7] is None else str(row[7]),
            finished_at=None if row[8] is None else _parse_utc(row[8]),
            operator_proof_sha256=None if row[9] is None else str(row[9]),
            created_at=_parse_utc(row[10]),
            updated_at=_parse_utc(row[11]),
        )


class BackupDestructionWorker:
    """Process a backup expiry without claiming inaccessible media as deleted."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        authority_scope: CleanupAuthorityScope,
        adapter: BackupDestructionAdapter,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("BACKUP_WORKER_SQLITE_REQUIRED")
        if authority_scope not in {"global", "client"}:
            raise ValueError("BACKUP_WORKER_SCOPE_INVALID")
        if not callable(getattr(adapter, "destroy", None)):
            raise TypeError("BACKUP_WORKER_ADAPTER_REQUIRED")
        self._connection = connection
        self._scope = authority_scope
        self._adapter = adapter
        self._clock = clock or (lambda: datetime.now(UTC))
        self._queue = BackupDestructionQueue(connection)

    def process(self, *, backup_id: str, intent_id: str) -> BackupProcessResult:
        authority = CleanupAuthorityResolver(
            self._connection,
            authority_scope=self._scope,
        ).resolve(intent_id, expected_action_type="backup_expiry")
        record = self._queue.get(backup_id)
        if record.request_id != authority.request_id:
            raise BackupQueueError("BACKUP_QUEUE_AUTHORITY_MISMATCH")
        if record.state == "succeeded":
            self._ack_intent(authority.intent_id, authority.request_id)
            return self._result(record, authority.intent_id, "succeeded")
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ValueError("BACKUP_QUEUE_TIME_NOT_UTC")
        if now < record.due_at:
            return self._result(record, authority.intent_id, "pending_retention")
        try:
            proof = self._adapter.destroy(record)
        except OSError:
            failed = self._queue.mark_failed(
                backup_id,
                error_code="BACKUP_ACCESS_RETRY",
                failed_at=now,
            )
            return self._result(failed, authority.intent_id, "retry_pending")
        if proof is None:
            # Offline/external media remains pending until an operator supplies
            # a verifiable proof.  Inaccessibility is not success or failure.
            return self._result(record, authority.intent_id, "pending_operator")
        completed = self._queue.complete(
            backup_id,
            operator_proof_sha256=_sha256(proof),
            finished_at=now,
        )
        self._ack_intent(authority.intent_id, authority.request_id)
        return self._result(completed, authority.intent_id, "succeeded")

    def _ack_intent(self, intent_id: str, request_id: str) -> None:
        now = _utc_text(self._clock())
        with transaction(self._connection):
            state = self._connection.execute(
                "SELECT state FROM deletion_queue_intents WHERE intent_id = ?",
                (intent_id,),
            ).fetchone()
            if state is None:
                raise BackupQueueError("BACKUP_QUEUE_INTENT_NOT_FOUND")
            if state == ("SUCCEEDED",):
                return
            if state[0] in {"PENDING", "FAILED", "CLAIMED"}:
                self._connection.execute(
                    """
                    UPDATE deletion_queue_intents
                       SET state = 'CLAIMED', attempt_count = attempt_count + 1,
                           claimed_at = ?, finished_at = NULL,
                           last_error_code = NULL
                     WHERE intent_id = ?
                    """,
                    (now, intent_id),
                )
            changed = self._connection.execute(
                """
                UPDATE deletion_queue_intents
                   SET state = 'SUCCEEDED', finished_at = ?,
                       last_error_code = NULL
                 WHERE intent_id = ? AND state = 'CLAIMED'
                """,
                (now, intent_id),
            ).rowcount
            if changed != 1:
                raise BackupQueueError("BACKUP_QUEUE_INTENT_ACK_FAILED")
            remaining = int(
                self._connection.execute(
                    "SELECT count(*) FROM deletion_queue_intents "
                    "WHERE request_id = ? AND state != 'SUCCEEDED'",
                    (request_id,),
                ).fetchone()[0]
            )
            pending = int(
                self._connection.execute(
                    "SELECT count(*) FROM backup_destruction_queue "
                    "WHERE request_id = ? AND state != 'succeeded'",
                    (request_id,),
                ).fetchone()[0]
            )
            if remaining == 0 and pending == 0:
                current = self._connection.execute(
                    "SELECT queue_state FROM deletion_requests WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                if current is None:
                    raise BackupQueueError("BACKUP_QUEUE_REQUEST_NOT_FOUND")
                if current[0] == "FAILED":
                    self._connection.execute(
                        "UPDATE deletion_requests SET queue_state = 'RUNNING' "
                        "WHERE request_id = ?",
                        (request_id,),
                    )
                self._connection.execute(
                    "UPDATE deletion_requests SET queue_state = 'SUCCEEDED', "
                    "state = 'PHYSICAL_CLEANUP_COMPLETE' WHERE request_id = ?",
                    (request_id,),
                )

    @staticmethod
    def _result(
        record: BackupDestructionRecord,
        intent_id: str,
        state: BackupProcessState,
    ) -> BackupProcessResult:
        return BackupProcessResult(
            backup_id=record.backup_id,
            intent_id=intent_id,
            state=state,
            attempt_count=record.attempt_count,
            object_set_sha256=record.object_set_sha256,
            operator_proof_sha256=record.operator_proof_sha256,
        )


__all__ = [
    "BACKUP_QUEUE_SCHEMA",
    "BackupDestructionQueue",
    "BackupDestructionRecord",
    "BackupDestructionAdapter",
    "BackupDestructionWorker",
    "BackupLocationClass",
    "BackupProcessResult",
    "BackupProcessState",
    "BackupQueueError",
    "BackupQueueState",
]
