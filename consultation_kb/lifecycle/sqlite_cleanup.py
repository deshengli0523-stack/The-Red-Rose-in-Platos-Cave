"""Scoped SQLite sanitization with atomic rebuild and residue verification."""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TypeAlias


SYNTHETIC_VAULT_MARKER = ".consultation-kb-synthetic-vault"
SYNTHETIC_VAULT_MARKER_BYTES = b"consultation-kb synthetic destructive test vault v1\n"
_IDENTIFIER_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_SCHEMA_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")


class CleanupError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CleanupScopeError(CleanupError):
    pass


class CleanupVerificationError(CleanupError):
    pass


@dataclass(frozen=True, slots=True)
class SyntheticCleanupScope:
    """Destructive authority restricted to one marked temporary descendant."""

    root: Path
    allowed_parent: Path

    @classmethod
    def open(cls, root: Path, *, allowed_parent: Path) -> "SyntheticCleanupScope":
        try:
            parent_input = Path(allowed_parent)
            root_input = Path(root)
            if parent_input.is_symlink() or root_input.is_symlink():
                raise CleanupScopeError("CLEANUP_SYNTHETIC_SCOPE_REQUIRED")
            resolved_parent = parent_input.resolve(strict=True)
            resolved_root = root_input.resolve(strict=True)
            if (
                resolved_root == resolved_parent
                or not resolved_root.is_relative_to(resolved_parent)
                or (resolved_root / ".git").exists()
            ):
                raise CleanupScopeError("CLEANUP_SYNTHETIC_SCOPE_REQUIRED")
            marker = resolved_root / SYNTHETIC_VAULT_MARKER
            if (
                not marker.is_file()
                or marker.is_symlink()
                or marker.stat().st_nlink != 1
                or marker.read_bytes() != SYNTHETIC_VAULT_MARKER_BYTES
            ):
                raise CleanupScopeError("CLEANUP_SYNTHETIC_SCOPE_REQUIRED")
        except CleanupScopeError:
            raise
        except (OSError, RuntimeError, ValueError):
            raise CleanupScopeError("CLEANUP_SYNTHETIC_SCOPE_REQUIRED") from None
        return cls(root=resolved_root, allowed_parent=resolved_parent)

    def resolve_file(self, path: Path, *, must_exist: bool) -> Path:
        return _resolve_scoped_file(self.root, path, must_exist=must_exist)

    def unlink_if_present(self, path: Path) -> None:
        _unlink_scoped_file(self, path)


@dataclass(frozen=True, slots=True)
class VaultCleanupScope:
    """Production filesystem boundary opened from an already-approved vault root.

    Unlike :class:`SyntheticCleanupScope`, this scope has no test marker.  Its
    caller must supply both the exact vault root and its configured parent; the
    scope still rejects repositories, reparse points, hard links and escapes.
    """

    root: Path
    allowed_parent: Path

    @classmethod
    def open(cls, root: Path, *, allowed_parent: Path) -> "VaultCleanupScope":
        try:
            parent_input = Path(allowed_parent)
            root_input = Path(root)
            if parent_input.is_symlink() or root_input.is_symlink():
                raise CleanupScopeError("CLEANUP_VAULT_SCOPE_REQUIRED")
            resolved_parent = parent_input.resolve(strict=True)
            resolved_root = root_input.resolve(strict=True)
            if (
                resolved_root == resolved_parent
                or not resolved_root.is_relative_to(resolved_parent)
                or (resolved_root / ".git").exists()
            ):
                raise CleanupScopeError("CLEANUP_VAULT_SCOPE_REQUIRED")
        except CleanupScopeError:
            raise
        except (OSError, RuntimeError, ValueError):
            raise CleanupScopeError("CLEANUP_VAULT_SCOPE_REQUIRED") from None
        return cls(root=resolved_root, allowed_parent=resolved_parent)

    def resolve_file(self, path: Path, *, must_exist: bool) -> Path:
        return _resolve_scoped_file(self.root, path, must_exist=must_exist)

    def unlink_if_present(self, path: Path) -> None:
        _unlink_scoped_file(self, path)


CleanupFileScope: TypeAlias = SyntheticCleanupScope | VaultCleanupScope


def _resolve_scoped_file(
    root: Path,
    path: Path,
    *,
    must_exist: bool,
) -> Path:
    candidate = Path(path)
    if ".." in candidate.parts:
        raise CleanupScopeError("CLEANUP_PATH_OUT_OF_SCOPE")
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        if candidate == root or not candidate.is_relative_to(root):
            raise CleanupScopeError("CLEANUP_PATH_OUT_OF_SCOPE")
        relative = candidate.relative_to(root)
        cursor = root
        for part in relative.parts:
            cursor /= part
            if cursor.is_symlink():
                raise CleanupScopeError("CLEANUP_PATH_OUT_OF_SCOPE")
        if must_exist:
            resolved = candidate.resolve(strict=True)
        else:
            parent = candidate.parent.resolve(strict=True)
            resolved = parent / candidate.name
        if resolved == root or not resolved.is_relative_to(root):
            raise CleanupScopeError("CLEANUP_PATH_OUT_OF_SCOPE")
        if must_exist:
            status = resolved.lstat()
            if (
                not resolved.is_file()
                or resolved.is_symlink()
                or status.st_nlink != 1
            ):
                raise CleanupScopeError("CLEANUP_PATH_OUT_OF_SCOPE")
        elif resolved.exists() or resolved.is_symlink():
            raise CleanupScopeError("CLEANUP_PATH_OUT_OF_SCOPE")
        return resolved
    except CleanupScopeError:
        raise
    except (OSError, RuntimeError, ValueError):
        raise CleanupScopeError("CLEANUP_PATH_OUT_OF_SCOPE") from None


def _unlink_scoped_file(scope: CleanupFileScope, path: Path) -> None:
    candidate = Path(path)
    if not candidate.exists() and not candidate.is_symlink():
        scope.resolve_file(candidate, must_exist=False)
        return
    resolved = scope.resolve_file(candidate, must_exist=True)
    try:
        resolved.unlink()
    except OSError:
        raise CleanupError("CLEANUP_FILE_REMOVE_FAILED") from None


DeleteCallback = Callable[[sqlite3.Connection], int]


@dataclass(frozen=True, slots=True)
class SqliteCleanupRequest:
    database_path: Path
    delete_callback: DeleteCallback
    fts_tables: tuple[str, ...] = ()
    forbidden_needles: tuple[bytes, ...] = ()
    bypass_immutability_triggers: bool = False

    def __post_init__(self) -> None:
        if not callable(self.delete_callback):
            raise TypeError("SQLITE_DELETE_CALLBACK_REQUIRED")
        if len(self.fts_tables) != len(set(self.fts_tables)) or any(
            _IDENTIFIER_RE.fullmatch(value) is None for value in self.fts_tables
        ):
            raise ValueError("SQLITE_FTS_TABLE_INVALID")
        if any(
            type(value) is not bytes or not value for value in self.forbidden_needles
        ):
            raise ValueError("SQLITE_FORBIDDEN_NEEDLE_INVALID")
        if type(self.bypass_immutability_triggers) is not bool:
            raise ValueError("SQLITE_TRIGGER_BYPASS_INVALID")


@dataclass(frozen=True, slots=True)
class SqliteCleanupResult:
    database_sha256: str
    deleted_row_count: int
    secure_delete_enabled: bool
    wal_checkpoint_truncated: bool
    strategy: Literal["vacuum_into_atomic_replace"]
    fts_cleanup_mode: Literal["none", "fts5_secure_delete", "clean_rebuild"]
    sqlite_version: str


def _quoted_identifier(value: str) -> str:
    if _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError("SQLITE_IDENTIFIER_INVALID")
    return f'"{value}"'


def _quoted_schema_identifier(value: str) -> str:
    if _SCHEMA_IDENTIFIER_RE.fullmatch(value) is None:
        raise CleanupVerificationError("SQLITE_TRIGGER_NAME_INVALID")
    return f'"{value}"'


def _checkpoint_truncate(connection: sqlite3.Connection) -> None:
    row = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    if row is None or len(row) != 3 or int(row[0]) != 0:
        raise CleanupVerificationError("SQLITE_WAL_CHECKPOINT_FAILED")


def _set_secure_delete(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA secure_delete = ON")
    row = connection.execute("PRAGMA secure_delete").fetchone()
    if row != (1,):
        raise CleanupVerificationError("SQLITE_SECURE_DELETE_UNAVAILABLE")


def _set_fts_secure_delete(
    connection: sqlite3.Connection, tables: tuple[str, ...]
) -> None:
    for table in tables:
        quoted = _quoted_identifier(table)
        connection.execute(
            f"INSERT INTO {quoted}({quoted}, rank) VALUES('secure-delete', 1)"
        )


def _enable_fts_secure_delete(
    connection: sqlite3.Connection,
    tables: tuple[str, ...],
) -> bool:
    """Probe the command, falling back only for an unavailable FTS command.

    SQLite version strings alone are not a capability guarantee: vendors can
    backport, omit, or alter FTS5.  ``SQLITE_ERROR`` is the error class used by
    FTS5 for an unknown special command.  Storage, locking, and corruption
    errors still fail closed.
    """

    if sqlite3.sqlite_version_info < (3, 42, 0):
        return False
    try:
        _set_fts_secure_delete(connection, tables)
    except sqlite3.OperationalError as error:
        error_code = getattr(error, "sqlite_errorcode", None)
        if error_code not in {None, sqlite3.SQLITE_ERROR}:
            raise
        return False
    return True


def _optimize_fts(connection: sqlite3.Connection, tables: tuple[str, ...]) -> None:
    for table in tables:
        quoted = _quoted_identifier(table)
        connection.execute(f"INSERT INTO {quoted}({quoted}) VALUES('optimize')")


def _rebuild_fts(connection: sqlite3.Connection, tables: tuple[str, ...]) -> None:
    for table in tables:
        quoted = _quoted_identifier(table)
        connection.execute(f"INSERT INTO {quoted}({quoted}) VALUES('rebuild')")


def _sidecars(database: Path) -> tuple[Path, ...]:
    return tuple(Path(f"{database}{suffix}") for suffix in ("-wal", "-shm", "-journal"))


class SqliteSanitizer:
    """Delete governed rows, clean-rebuild, switch atomically, then scan."""

    def __init__(self, scope: CleanupFileScope) -> None:
        if not isinstance(scope, (SyntheticCleanupScope, VaultCleanupScope)):
            raise TypeError("CLEANUP_SCOPE_REQUIRED")
        self._scope = scope

    def sanitize(self, request: SqliteCleanupRequest) -> SqliteCleanupResult:
        exact = request if isinstance(request, SqliteCleanupRequest) else None
        if exact is None:
            raise TypeError("SQLITE_CLEANUP_REQUEST_REQUIRED")
        database = self._scope.resolve_file(exact.database_path, must_exist=True)
        temporary = self._scope.resolve_file(
            database.with_name(f".{database.name}.clean-{uuid.uuid4().hex}.sqlite3"),
            must_exist=False,
        )
        source: sqlite3.Connection | None = None
        working: sqlite3.Connection | None = None
        deleted_count = 0
        fts_mode: Literal["none", "fts5_secure_delete", "clean_rebuild"] = "none"
        try:
            source = sqlite3.connect(database, isolation_level=None, timeout=5.0)
            source.execute("PRAGMA foreign_keys = ON")
            source.execute("PRAGMA busy_timeout = 5000")
            journal = source.execute("PRAGMA journal_mode = WAL").fetchone()
            if journal is None or str(journal[0]).lower() != "wal":
                raise CleanupVerificationError("SQLITE_WAL_REQUIRED")
            _set_secure_delete(source)
            _checkpoint_truncate(source)
            source.execute("VACUUM INTO ?", (str(temporary),))
            source.close()
            source = None

            working = sqlite3.connect(
                temporary,
                isolation_level=None,
                timeout=5.0,
            )
            working.execute("PRAGMA busy_timeout = 5000")
            working.execute("PRAGMA foreign_keys = OFF")
            journal = working.execute("PRAGMA journal_mode = WAL").fetchone()
            if journal is None or str(journal[0]).lower() != "wal":
                raise CleanupVerificationError("SQLITE_WAL_REQUIRED")
            _set_secure_delete(working)
            trigger_definitions: tuple[tuple[str, str], ...] = ()
            if exact.bypass_immutability_triggers:
                trigger_definitions = tuple(
                    (str(row[0]), str(row[1]))
                    for row in working.execute(
                        "SELECT name, sql FROM sqlite_schema "
                        "WHERE type = 'trigger' AND sql IS NOT NULL ORDER BY name"
                    ).fetchall()
                )
                for trigger_name, _sql in trigger_definitions:
                    working.execute(
                        f"DROP TRIGGER {_quoted_schema_identifier(trigger_name)}"
                    )
            if exact.fts_tables:
                if _enable_fts_secure_delete(working, exact.fts_tables):
                    fts_mode = "fts5_secure_delete"
                else:
                    fts_mode = "clean_rebuild"
            working.execute("BEGIN IMMEDIATE")
            try:
                deleted_count = exact.delete_callback(working)
                if type(deleted_count) is not int or deleted_count < 0:
                    raise CleanupError("SQLITE_DELETE_COUNT_INVALID")
                if fts_mode == "clean_rebuild":
                    _rebuild_fts(working, exact.fts_tables)
                _optimize_fts(working, exact.fts_tables)
                working.execute("COMMIT")
            except BaseException:
                if working.in_transaction:
                    working.execute("ROLLBACK")
                raise
            for _trigger_name, trigger_sql in trigger_definitions:
                working.execute(trigger_sql)
            working.execute("PRAGMA foreign_keys = ON")
            if working.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise CleanupVerificationError("SQLITE_FOREIGN_KEY_INVALID")
            _checkpoint_truncate(working)
            working.execute("VACUUM")
            _checkpoint_truncate(working)
            if working.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise CleanupVerificationError("SQLITE_CLEAN_REBUILD_INVALID")
            _set_secure_delete(working)
            working.close()
            working = None
            for sidecar in _sidecars(temporary):
                self._scope.unlink_if_present(sidecar)
            self._assert_needles_absent(temporary, exact.forbidden_needles)
            with temporary.open("r+b") as stream:
                stream.flush()
                os.fsync(stream.fileno())
            for sidecar in _sidecars(database):
                self._scope.unlink_if_present(sidecar)
            os.replace(temporary, database)

            finalized = sqlite3.connect(database, isolation_level=None, timeout=5.0)
            try:
                finalized.execute("PRAGMA foreign_keys = ON")
                journal = finalized.execute("PRAGMA journal_mode = WAL").fetchone()
                if journal is None or str(journal[0]).lower() != "wal":
                    raise CleanupVerificationError("SQLITE_WAL_REQUIRED")
                _set_secure_delete(finalized)
                _checkpoint_truncate(finalized)
                if finalized.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                    raise CleanupVerificationError("SQLITE_FINAL_INTEGRITY_INVALID")
            finally:
                finalized.close()
            for sidecar in _sidecars(database):
                self._scope.unlink_if_present(sidecar)
            self._assert_needles_absent(database, exact.forbidden_needles)
            database_sha256 = hashlib.sha256(database.read_bytes()).hexdigest()
            return SqliteCleanupResult(
                database_sha256=database_sha256,
                deleted_row_count=deleted_count,
                secure_delete_enabled=True,
                wal_checkpoint_truncated=True,
                strategy="vacuum_into_atomic_replace",
                fts_cleanup_mode=fts_mode,
                sqlite_version=sqlite3.sqlite_version,
            )
        except (CleanupError, sqlite3.Error, OSError):
            raise
        finally:
            if source is not None:
                source.close()
            if working is not None:
                working.close()
            for sidecar in _sidecars(temporary):
                self._scope.unlink_if_present(sidecar)
            self._scope.unlink_if_present(temporary)

    @staticmethod
    def _assert_needles_absent(database: Path, needles: tuple[bytes, ...]) -> None:
        for path in (database, *_sidecars(database)):
            if not path.is_file():
                continue
            payload = path.read_bytes()
            if any(needle in payload for needle in needles):
                raise CleanupVerificationError("SQLITE_RESIDUE_DETECTED")


__all__ = [
    "SYNTHETIC_VAULT_MARKER",
    "SYNTHETIC_VAULT_MARKER_BYTES",
    "CleanupError",
    "CleanupFileScope",
    "CleanupScopeError",
    "CleanupVerificationError",
    "SqliteCleanupRequest",
    "SqliteCleanupResult",
    "SqliteSanitizer",
    "SyntheticCleanupScope",
    "VaultCleanupScope",
]
