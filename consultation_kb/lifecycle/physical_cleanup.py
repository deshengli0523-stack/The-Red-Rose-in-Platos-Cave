"""Tombstone-gated physical cleanup for scoped vault artifacts."""

from __future__ import annotations

import errno
import hashlib
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, TypeAlias

from consultation_kb.lifecycle.cleanup_authority import (
    CleanupAuthorityResolver,
    CleanupAuthorityScope,
    CleanupIntentAuthority,
)

from consultation_kb.lifecycle.sqlite_cleanup import (
    CleanupError,
    CleanupFileScope,
    CleanupScopeError,
    SqliteCleanupRequest,
    SqliteSanitizer,
    SyntheticCleanupScope,
    VaultCleanupScope,
)
from consultation_kb.storage.connection import transaction
from consultation_kb.storage.cleanup_inventory import (
    CleanupInventoryError,
    PhysicalCleanupInventory,
    SqlitePhysicalCleanupInventory,
)

CleanupArtifactKind = Literal[
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
]

CLEANUP_ARTIFACT_KINDS: tuple[CleanupArtifactKind, ...] = (
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
)

CleanupProcessState = Literal["succeeded", "retry_pending"]


class PhysicalCleanupError(CleanupError):
    """Raised when a physical cleanup invariant cannot be satisfied."""


@dataclass(frozen=True, slots=True)
class CleanupWorkItem:
    """A path-bearing in-memory work item derived from a hash-only intent."""

    intent_id: str
    artifact_kind: CleanupArtifactKind
    object_type: str
    target_id_hash: str
    relative_path: Path
    expected_file_sha256: str

    def __post_init__(self) -> None:
        if not self.intent_id.strip():
            raise ValueError("intent_id must not be empty")
        if self.artifact_kind not in CLEANUP_ARTIFACT_KINDS:
            raise ValueError("unsupported cleanup artifact kind")
        if not self.object_type.strip():
            raise ValueError("object_type must not be empty")
        _require_sha256(self.target_id_hash, field="target_id_hash")
        _require_sha256(self.expected_file_sha256, field="expected_file_sha256")
        if self.relative_path.is_absolute() or self.relative_path == Path("."):
            raise ValueError("relative_path must be a non-empty relative path")


@dataclass(frozen=True, slots=True)
class CleanupProcessResult:
    """Outcome of one cleanup attempt."""

    intent_id: str
    state: CleanupProcessState
    artifact_kind: CleanupArtifactKind
    attempt_count: int
    target_id_hash: str
    evidence_sha256: str
    tombstone_active: bool


class PhysicalCleanupWorker:
    """Delete scoped files while retaining the governing tombstone.

    File-lock failures are recorded as retryable queue failures. This is the
    expected path for Windows mmap and open-handle contention.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        scope: CleanupFileScope,
        file_remover: Callable[[Path], None] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._connection = connection
        self._scope = scope
        self._file_remover = file_remover or _remove_file
        self._clock = clock or _utc_now

    def process(self, work: CleanupWorkItem) -> CleanupProcessResult:
        """Run one attempt, returning ``retry_pending`` for locked files."""

        queue_row = self._load_and_validate_intent(work)
        attempt_count = int(queue_row[1])
        state = str(queue_row[0])
        self._require_tombstone(work)

        if state == "SUCCEEDED":
            if self._resolve_work_path(work).exists():
                raise PhysicalCleanupError("PHYSICAL_CLEANUP_FILE_STILL_PRESENT")
            return self._result(work, "succeeded", attempt_count)
        if state not in {"PENDING", "FAILED", "CLAIMED"}:
            raise PhysicalCleanupError(f"PHYSICAL_CLEANUP_BAD_INTENT_STATE:{state}")

        attempt_count = self._claim(work.intent_id)
        try:
            candidate = self._resolve_work_path(work)
            if candidate.exists():
                actual_sha256 = _file_sha256(candidate)
                if actual_sha256 != work.expected_file_sha256:
                    raise PhysicalCleanupError("PHYSICAL_CLEANUP_CONTENT_HASH_MISMATCH")
                self._file_remover(candidate)
                if candidate.exists():
                    raise PhysicalCleanupError("PHYSICAL_CLEANUP_FILE_STILL_PRESENT")
        except OSError as error:
            error_code = (
                "FILE_LOCK_RETRY"
                if _is_windows_lock_or_busy(error)
                else "PHYSICAL_CLEANUP_IO_RETRY"
            )
            self._mark_failed(work.intent_id, error_code)
            return self._result(work, "retry_pending", attempt_count)
        except (CleanupScopeError, PhysicalCleanupError):
            self._mark_failed(work.intent_id, "PHYSICAL_CLEANUP_VERIFICATION_FAILED")
            raise

        self._mark_succeeded(work.intent_id)
        return self._result(work, "succeeded", attempt_count)

    def _resolve_work_path(self, work: CleanupWorkItem) -> Path:
        untrusted_candidate = self._scope.root / work.relative_path
        return self._scope.resolve_file(
            untrusted_candidate,
            must_exist=untrusted_candidate.exists(),
        )

    def _load_and_validate_intent(self, work: CleanupWorkItem) -> tuple[str, int]:
        row = self._connection.execute(
            """
            SELECT state, attempt_count, action_type, object_type, target_id_hash
            FROM deletion_queue_intents
            WHERE intent_id = ?
            """,
            (work.intent_id,),
        ).fetchone()
        if row is None:
            raise PhysicalCleanupError("PHYSICAL_CLEANUP_INTENT_NOT_FOUND")
        if row[2] != "physical_delete":
            raise PhysicalCleanupError("PHYSICAL_CLEANUP_ACTION_MISMATCH")
        if row[3] != work.object_type or row[4] != work.target_id_hash:
            raise PhysicalCleanupError("PHYSICAL_CLEANUP_TARGET_MISMATCH")
        return str(row[0]), int(row[1])

    def _require_tombstone(self, work: CleanupWorkItem) -> None:
        row = self._connection.execute(
            """
            SELECT 1
            FROM tombstones
            WHERE target_type = ? AND target_id_hash = ?
            LIMIT 1
            """,
            (work.object_type, work.target_id_hash),
        ).fetchone()
        if row is None:
            raise PhysicalCleanupError("PHYSICAL_CLEANUP_TOMBSTONE_REQUIRED")

    def _claim(self, intent_id: str) -> int:
        claimed_at = _format_utc(self._clock())
        with transaction(self._connection):
            cursor = self._connection.execute(
                """
                UPDATE deletion_queue_intents
                SET state = 'CLAIMED',
                    attempt_count = attempt_count + 1,
                    claimed_at = ?,
                    finished_at = NULL,
                    last_error_code = NULL
                WHERE intent_id = ?
                  AND state IN ('PENDING', 'FAILED', 'CLAIMED')
                """,
                (claimed_at, intent_id),
            )
            if cursor.rowcount != 1:
                raise PhysicalCleanupError("PHYSICAL_CLEANUP_CLAIM_FAILED")
            row = self._connection.execute(
                "SELECT attempt_count FROM deletion_queue_intents WHERE intent_id = ?",
                (intent_id,),
            ).fetchone()
            if row is None:
                raise PhysicalCleanupError("PHYSICAL_CLEANUP_INTENT_NOT_FOUND")
            return int(row[0])

    def _mark_failed(self, intent_id: str, error_code: str) -> None:
        with transaction(self._connection):
            self._connection.execute(
                """
                UPDATE deletion_queue_intents
                SET state = 'FAILED', last_error_code = ?, finished_at = NULL
                WHERE intent_id = ?
                """,
                (error_code, intent_id),
            )

    def _mark_succeeded(self, intent_id: str) -> None:
        with transaction(self._connection):
            self._connection.execute(
                """
                UPDATE deletion_queue_intents
                SET state = 'SUCCEEDED',
                    finished_at = ?,
                    last_error_code = NULL
                WHERE intent_id = ?
                """,
                (_format_utc(self._clock()), intent_id),
            )

    def _result(
        self,
        work: CleanupWorkItem,
        state: CleanupProcessState,
        attempt_count: int,
    ) -> CleanupProcessResult:
        self._require_tombstone(work)
        evidence = "\x1f".join(
            (
                work.intent_id,
                work.artifact_kind,
                work.target_id_hash,
                state,
                str(attempt_count),
            )
        ).encode("utf-8")
        return CleanupProcessResult(
            intent_id=work.intent_id,
            state=state,
            artifact_kind=work.artifact_kind,
            attempt_count=attempt_count,
            target_id_hash=work.target_id_hash,
            evidence_sha256=hashlib.sha256(evidence).hexdigest(),
            tombstone_active=True,
        )


ConnectionFactory: TypeAlias = Callable[[], sqlite3.Connection]


@dataclass(frozen=True, slots=True)
class AuthorizedCleanupResult:
    """Body-free outcome of one production cleanup intent attempt."""

    intent_id: str
    request_id: str
    state: CleanupProcessState
    attempt_count: int
    deleted_file_count: int
    sanitized_row_count: int
    active_reference_count: int
    pending_backup_count: int
    evidence_sha256: str
    tombstone_active: Literal[True] = True


class ScopedCleanupResolver:
    """Resolve exact CAS and controlled-copy paths inside one vault boundary."""

    _DEFAULT_COPY_ROOTS: tuple[Path, ...] = (
        Path("graph"),
        Path("indexes"),
        Path("wiki"),
        Path("cache"),
        Path("exports"),
        Path("temp"),
        Path("evaluation"),
        Path("sessions"),
        Path("cases"),
    )

    def __init__(
        self,
        *,
        scope: CleanupFileScope,
        cas_root: Path,
        copy_roots: tuple[Path, ...] | None = None,
    ) -> None:
        if not isinstance(scope, (SyntheticCleanupScope, VaultCleanupScope)):
            raise TypeError("CLEANUP_SCOPE_REQUIRED")
        self._scope = scope
        self._cas_root = self._resolve_directory(cas_root, required=True)
        roots = self._DEFAULT_COPY_ROOTS if copy_roots is None else copy_roots
        if len(roots) != len(set(roots)):
            raise ValueError("CLEANUP_COPY_ROOT_DUPLICATE")
        resolved_roots: list[Path] = []
        for root in roots:
            if not isinstance(root, Path) or root.is_absolute() or ".." in root.parts:
                raise ValueError("CLEANUP_COPY_ROOT_INVALID")
            candidate = scope.root / root
            if candidate.exists():
                resolved_roots.append(self._resolve_directory(candidate, required=True))
        self._copy_roots = tuple(resolved_roots)

    def resolve(
        self,
        inventory: PhysicalCleanupInventory,
    ) -> tuple[CleanupWorkItem, ...]:
        digests = frozenset(inventory.content_sha256s)
        found: dict[Path, CleanupWorkItem] = {}
        for digest in digests:
            _require_sha256(digest, field="content_sha256")
            payload = (
                self._cas_root
                / "objects"
                / "sha256"
                / digest[:2]
                / digest
                / "payload"
            )
            if payload.exists():
                resolved = self._scope.resolve_file(payload, must_exist=True)
                found[resolved] = CleanupWorkItem(
                    intent_id="resolved",
                    artifact_kind="old_content_object",
                    object_type="cas_object",
                    target_id_hash=digest,
                    relative_path=resolved.relative_to(self._scope.root),
                    expected_file_sha256=digest,
                )
        for root in self._copy_roots:
            for candidate in root.rglob("*"):
                if candidate.is_symlink():
                    raise CleanupScopeError("CLEANUP_PATH_OUT_OF_SCOPE")
                if not candidate.is_file():
                    continue
                resolved = self._scope.resolve_file(candidate, must_exist=True)
                digest = _file_sha256(resolved)
                if digest not in digests:
                    continue
                found.setdefault(
                    resolved,
                    CleanupWorkItem(
                        intent_id="resolved",
                        artifact_kind=self._artifact_kind(root, resolved),
                        object_type="controlled_copy",
                        target_id_hash=digest,
                        relative_path=resolved.relative_to(self._scope.root),
                        expected_file_sha256=digest,
                    ),
                )
        return tuple(found[path] for path in sorted(found, key=str))

    def _resolve_directory(self, path: Path, *, required: bool) -> Path:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self._scope.root / candidate
        try:
            resolved = candidate.resolve(strict=required)
            if (
                resolved == self._scope.root
                or not resolved.is_relative_to(self._scope.root)
                or not resolved.is_dir()
            ):
                raise CleanupScopeError("CLEANUP_PATH_OUT_OF_SCOPE")
            cursor = self._scope.root
            for part in resolved.relative_to(self._scope.root).parts:
                cursor /= part
                if cursor.is_symlink():
                    raise CleanupScopeError("CLEANUP_PATH_OUT_OF_SCOPE")
            return resolved
        except CleanupScopeError:
            raise
        except (OSError, RuntimeError, ValueError):
            raise CleanupScopeError("CLEANUP_PATH_OUT_OF_SCOPE") from None

    @staticmethod
    def _artifact_kind(root: Path, candidate: Path) -> CleanupArtifactKind:
        name = root.name.lower()
        candidate_parts = {part.lower() for part in candidate.parts}
        if name == "indexes" and (
            "fts" in candidate_parts
            or candidate.suffix.lower() in {".db", ".sqlite", ".sqlite3"}
        ):
            return "fts"
        if "vector" in name or name == "indexes":
            return "vector_shard"
        if "graph" in name:
            return "graph"
        if "wiki" in name:
            return "wiki_render"
        if "evaluation" in name:
            return "evaluation_sample"
        if name in {"exports", "export"}:
            return "export"
        if name in {"temp", "tmp"}:
            return "temporary_file"
        if name == "cache":
            return "cache"
        if name == "cases":
            return "global_case_copy"
        return "session_copy"


class AuthorizedPhysicalCleanupWorker:
    """Production worker for one exact, approval-bound lifecycle intent.

    The worker owns short-lived SQLite handles so an authorized clean rebuild
    can atomically replace the database on Windows.  A failed cleanup only
    moves the durable queue row to ``FAILED``; it never removes a tombstone.
    """

    def __init__(
        self,
        connection_factory: ConnectionFactory,
        *,
        authority_scope: CleanupAuthorityScope,
        scope: CleanupFileScope,
        database_path: Path,
        cas_root: Path,
        copy_roots: tuple[Path, ...] | None = None,
        file_remover: Callable[[Path], None] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not callable(connection_factory):
            raise TypeError("CLEANUP_CONNECTION_FACTORY_REQUIRED")
        if authority_scope not in {"global", "client"}:
            raise ValueError("CLEANUP_AUTHORITY_SCOPE_INVALID")
        if not isinstance(scope, (SyntheticCleanupScope, VaultCleanupScope)):
            raise TypeError("CLEANUP_SCOPE_REQUIRED")
        self._connection_factory = connection_factory
        self._authority_scope = authority_scope
        self._scope = scope
        self._database_path = scope.resolve_file(database_path, must_exist=True)
        self._resolver = ScopedCleanupResolver(
            scope=scope,
            cas_root=cas_root,
            copy_roots=copy_roots,
        )
        self._file_remover = file_remover or _remove_file
        self._clock = clock or _utc_now

    def process(self, intent_id: str) -> AuthorizedCleanupResult:
        authority, inventory = self._load_claim_and_inventory(intent_id)
        if authority.state == "SUCCEEDED":
            if self._resolver.resolve(inventory):
                raise PhysicalCleanupError("PHYSICAL_CLEANUP_FILE_STILL_PRESENT")
            return self._authorized_result(
                authority,
                state="succeeded",
                deleted_file_count=0,
                sanitized_row_count=0,
                active_reference_count=0,
                pending_backup_count=0,
            )
        sanitized_rows = 0
        try:
            if inventory.sqlite_cleanup_required:
                sanitized_rows = self._sanitize_sqlite(authority, inventory)
            connection = self._open_connection()
            try:
                current = CleanupAuthorityResolver(
                    connection,
                    authority_scope=self._authority_scope,
                ).resolve(intent_id, expected_action_type="physical_delete")
                if current.state != "CLAIMED":
                    raise PhysicalCleanupError("PHYSICAL_CLEANUP_CLAIM_LOST")
                gate_inventory = SqlitePhysicalCleanupInventory(
                    connection,
                    authority_scope=self._authority_scope,
                )
                gates = tuple(
                    gate_inventory.cas_gate(current, digest)
                    for digest in inventory.content_sha256s
                )
            finally:
                connection.close()
            active_references = sum(gate.active_reference_count for gate in gates)
            pending_backups = sum(gate.pending_backup_count for gate in gates)
            if active_references:
                self._mark_failed(intent_id, "CAS_REFERENCES_REMAIN")
                return self._authorized_result(
                    current,
                    state="retry_pending",
                    deleted_file_count=0,
                    sanitized_row_count=sanitized_rows,
                    active_reference_count=active_references,
                    pending_backup_count=pending_backups,
                )
            if pending_backups:
                self._mark_failed(intent_id, "BACKUP_DESTRUCTION_PENDING")
                return self._authorized_result(
                    current,
                    state="retry_pending",
                    deleted_file_count=0,
                    sanitized_row_count=sanitized_rows,
                    active_reference_count=0,
                    pending_backup_count=pending_backups,
                )
            if not all(gate.allowed for gate in gates):
                raise PhysicalCleanupError("PHYSICAL_CLEANUP_POLICY_DENIED")
            work_items = self._resolver.resolve(inventory)
            resolved_paths: list[Path] = []
            for work in work_items:
                candidate = self._scope.resolve_file(
                    self._scope.root / work.relative_path,
                    must_exist=True,
                )
                if _file_sha256(candidate) != work.expected_file_sha256:
                    raise PhysicalCleanupError(
                        "PHYSICAL_CLEANUP_CONTENT_HASH_MISMATCH"
                    )
                resolved_paths.append(candidate)
            deleted = 0
            for candidate in resolved_paths:
                self._file_remover(candidate)
                if candidate.exists():
                    raise PhysicalCleanupError("PHYSICAL_CLEANUP_FILE_STILL_PRESENT")
                deleted += 1
            self._mark_succeeded(intent_id)
            completed = self._resolve_authority(intent_id)
            return self._authorized_result(
                completed,
                state="succeeded",
                deleted_file_count=deleted,
                sanitized_row_count=sanitized_rows,
                active_reference_count=0,
                pending_backup_count=0,
            )
        except OSError as error:
            code = (
                "FILE_LOCK_RETRY"
                if _is_windows_lock_or_busy(error)
                else "PHYSICAL_CLEANUP_IO_RETRY"
            )
            self._mark_failed(intent_id, code)
            failed = self._resolve_authority(intent_id)
            return self._authorized_result(
                failed,
                state="retry_pending",
                deleted_file_count=0,
                sanitized_row_count=sanitized_rows,
                active_reference_count=0,
                pending_backup_count=0,
            )
        except (CleanupError, CleanupInventoryError, CleanupScopeError):
            self._mark_failed_if_claimed(
                intent_id,
                "PHYSICAL_CLEANUP_VERIFICATION_FAILED",
            )
            raise

    def _load_claim_and_inventory(
        self,
        intent_id: str,
    ) -> tuple[CleanupIntentAuthority, PhysicalCleanupInventory]:
        connection = self._open_connection()
        try:
            authority = CleanupAuthorityResolver(
                connection,
                authority_scope=self._authority_scope,
            ).resolve(intent_id, expected_action_type="physical_delete")
            if authority.state == "SUCCEEDED":
                inventory = SqlitePhysicalCleanupInventory(
                    connection,
                    authority_scope=self._authority_scope,
                ).resolve(authority)
                return authority, inventory
            if authority.state not in {"PENDING", "FAILED", "CLAIMED"}:
                raise PhysicalCleanupError(
                    f"PHYSICAL_CLEANUP_BAD_INTENT_STATE:{authority.state}"
                )
            attempt = self._claim(connection, authority)
            claimed = CleanupAuthorityResolver(
                connection,
                authority_scope=self._authority_scope,
            ).resolve(intent_id, expected_action_type="physical_delete")
            if claimed.state != "CLAIMED" or claimed.attempt_count != attempt:
                raise PhysicalCleanupError("PHYSICAL_CLEANUP_CLAIM_FAILED")
            inventory = SqlitePhysicalCleanupInventory(
                connection,
                authority_scope=self._authority_scope,
            ).resolve(claimed)
            return claimed, inventory
        finally:
            connection.close()

    def _sanitize_sqlite(
        self,
        authority: CleanupIntentAuthority,
        inventory: PhysicalCleanupInventory,
    ) -> int:
        def delete_rows(connection: sqlite3.Connection) -> int:
            return SqlitePhysicalCleanupInventory(
                connection,
                authority_scope=self._authority_scope,
            ).delete_authorized_inline_rows(connection, authority)

        result = SqliteSanitizer(self._scope).sanitize(
            SqliteCleanupRequest(
                database_path=self._database_path,
                delete_callback=delete_rows,
                fts_tables=inventory.fts_tables,
                forbidden_needles=inventory.forbidden_needles,
                bypass_immutability_triggers=True,
            )
        )
        return result.deleted_row_count

    def _open_connection(self) -> sqlite3.Connection:
        connection = self._connection_factory()
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("CLEANUP_CONNECTION_FACTORY_INVALID")
        rows = connection.execute("PRAGMA database_list").fetchall()
        main = tuple(row for row in rows if str(row[1]) == "main")
        try:
            actual = Path(str(main[0][2])).resolve(strict=True)
        except (IndexError, OSError, RuntimeError, ValueError):
            connection.close()
            raise PhysicalCleanupError("PHYSICAL_CLEANUP_DATABASE_SCOPE_MISMATCH") from None
        if len(main) != 1 or actual != self._database_path:
            connection.close()
            raise PhysicalCleanupError("PHYSICAL_CLEANUP_DATABASE_SCOPE_MISMATCH")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _resolve_authority(self, intent_id: str) -> CleanupIntentAuthority:
        connection = self._open_connection()
        try:
            return CleanupAuthorityResolver(
                connection,
                authority_scope=self._authority_scope,
            ).resolve(intent_id, expected_action_type="physical_delete")
        finally:
            connection.close()

    def _claim(
        self,
        connection: sqlite3.Connection,
        authority: CleanupIntentAuthority,
    ) -> int:
        claimed_at = _format_utc(self._clock())
        with transaction(connection):
            changed = connection.execute(
                """
                UPDATE deletion_queue_intents
                   SET state = 'CLAIMED', attempt_count = attempt_count + 1,
                       claimed_at = ?, finished_at = NULL,
                       last_error_code = NULL
                 WHERE intent_id = ? AND state IN ('PENDING', 'FAILED', 'CLAIMED')
                """,
                (claimed_at, authority.intent_id),
            ).rowcount
            if changed != 1:
                raise PhysicalCleanupError("PHYSICAL_CLEANUP_CLAIM_FAILED")
            request = connection.execute(
                "SELECT queue_state FROM deletion_requests WHERE request_id = ?",
                (authority.request_id,),
            ).fetchone()
            if request is None:
                raise PhysicalCleanupError("PHYSICAL_CLEANUP_REQUEST_NOT_FOUND")
            if str(request[0]) != "RUNNING":
                connection.execute(
                    "UPDATE deletion_requests SET queue_state = 'RUNNING' "
                    "WHERE request_id = ?",
                    (authority.request_id,),
                )
            row = connection.execute(
                "SELECT attempt_count FROM deletion_queue_intents WHERE intent_id = ?",
                (authority.intent_id,),
            ).fetchone()
            if row is None:
                raise PhysicalCleanupError("PHYSICAL_CLEANUP_INTENT_NOT_FOUND")
            return int(row[0])

    def _mark_failed(self, intent_id: str, error_code: str) -> None:
        connection = self._open_connection()
        try:
            with transaction(connection):
                row = connection.execute(
                    "SELECT request_id, state FROM deletion_queue_intents "
                    "WHERE intent_id = ?",
                    (intent_id,),
                ).fetchone()
                if row is None:
                    raise PhysicalCleanupError("PHYSICAL_CLEANUP_INTENT_NOT_FOUND")
                if row[1] == "FAILED":
                    return
                if row[1] != "CLAIMED":
                    raise PhysicalCleanupError("PHYSICAL_CLEANUP_CLAIM_LOST")
                connection.execute(
                    "UPDATE deletion_queue_intents SET state = 'FAILED', "
                    "last_error_code = ?, finished_at = NULL WHERE intent_id = ?",
                    (error_code, intent_id),
                )
                connection.execute(
                    "UPDATE deletion_requests SET queue_state = 'FAILED' "
                    "WHERE request_id = ? AND queue_state = 'RUNNING'",
                    (str(row[0]),),
                )
        finally:
            connection.close()

    def _mark_failed_if_claimed(self, intent_id: str, error_code: str) -> None:
        try:
            self._mark_failed(intent_id, error_code)
        except (CleanupError, sqlite3.Error):
            pass

    def _mark_succeeded(self, intent_id: str) -> None:
        connection = self._open_connection()
        try:
            with transaction(connection):
                row = connection.execute(
                    "SELECT request_id FROM deletion_queue_intents "
                    "WHERE intent_id = ? AND state = 'CLAIMED'",
                    (intent_id,),
                ).fetchone()
                if row is None:
                    raise PhysicalCleanupError("PHYSICAL_CLEANUP_CLAIM_LOST")
                request_id = str(row[0])
                changed = connection.execute(
                    "UPDATE deletion_queue_intents SET state = 'SUCCEEDED', "
                    "finished_at = ?, last_error_code = NULL WHERE intent_id = ? "
                    "AND state = 'CLAIMED'",
                    (_format_utc(self._clock()), intent_id),
                ).rowcount
                if changed != 1:
                    raise PhysicalCleanupError("PHYSICAL_CLEANUP_ACK_FAILED")
                remaining = int(
                    connection.execute(
                        "SELECT count(*) FROM deletion_queue_intents "
                        "WHERE request_id = ? AND state != 'SUCCEEDED'",
                        (request_id,),
                    ).fetchone()[0]
                )
                backup_pending = int(
                    connection.execute(
                        "SELECT count(*) FROM backup_destruction_queue "
                        "WHERE request_id = ? AND state != 'succeeded'",
                        (request_id,),
                    ).fetchone()[0]
                )
                if remaining == 0 and backup_pending == 0:
                    connection.execute(
                        "UPDATE deletion_requests SET queue_state = 'SUCCEEDED', "
                        "state = 'PHYSICAL_CLEANUP_COMPLETE' WHERE request_id = ?",
                        (request_id,),
                    )
                else:
                    connection.execute(
                        "UPDATE deletion_requests SET queue_state = 'PARTIAL' "
                        "WHERE request_id = ? AND queue_state = 'RUNNING'",
                        (request_id,),
                    )
        finally:
            connection.close()

    @staticmethod
    def _authorized_result(
        authority: CleanupIntentAuthority,
        *,
        state: CleanupProcessState,
        deleted_file_count: int,
        sanitized_row_count: int,
        active_reference_count: int,
        pending_backup_count: int,
    ) -> AuthorizedCleanupResult:
        evidence = "\x1f".join(
            (
                authority.intent_id,
                authority.request_id,
                authority.action_descriptor_sha256,
                state,
                str(authority.attempt_count),
                str(deleted_file_count),
                str(sanitized_row_count),
                str(active_reference_count),
                str(pending_backup_count),
            )
        ).encode("ascii")
        return AuthorizedCleanupResult(
            intent_id=authority.intent_id,
            request_id=authority.request_id,
            state=state,
            attempt_count=authority.attempt_count,
            deleted_file_count=deleted_file_count,
            sanitized_row_count=sanitized_row_count,
            active_reference_count=active_reference_count,
            pending_backup_count=pending_backup_count,
            evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        )


def _remove_file(path: Path) -> None:
    path.unlink()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_windows_lock_or_busy(error: OSError) -> bool:
    winerror = getattr(error, "winerror", None)
    return bool(
        isinstance(error, PermissionError)
        or winerror in {32, 33}
        or error.errno in {errno.EACCES, errno.EBUSY}
    )


def _require_sha256(value: str, *, field: str) -> None:
    if len(value) != 64:
        raise ValueError(f"{field} must be a lowercase SHA-256 hex digest")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{field} must be a lowercase SHA-256 hex digest") from error
    if len(decoded) != 32 or value != value.lower():
        raise ValueError(f"{field} must be a lowercase SHA-256 hex digest")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _format_utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("clock must return a timezone-aware datetime")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


__all__ = [
    "AuthorizedCleanupResult",
    "AuthorizedPhysicalCleanupWorker",
    "CLEANUP_ARTIFACT_KINDS",
    "CleanupArtifactKind",
    "CleanupProcessResult",
    "CleanupProcessState",
    "CleanupWorkItem",
    "PhysicalCleanupError",
    "PhysicalCleanupWorker",
    "ScopedCleanupResolver",
]
