"""Checksum-bound SQLite schema migrations."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from importlib import import_module, resources
from typing import Literal, Protocol, TypeAlias, cast

from consultation_kb.storage.connection import transaction


MigrationScope: TypeAlias = Literal["global", "client"]


class Migration(Protocol):
    @property
    def version(self) -> int: ...

    @property
    def name(self) -> str: ...

    @property
    def sha256(self) -> str: ...

    def upgrade(self, connection: sqlite3.Connection) -> None: ...


class MigrationError(RuntimeError):
    """Base migration failure."""

    code: str

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class MigrationChecksumError(MigrationError):
    """An applied migration no longer matches its source checksum."""

    def __init__(self) -> None:
        super().__init__("MIGRATION_CHECKSUM_MISMATCH")


class MigrationHistoryError(MigrationError):
    """Applied migration history is not a valid expected prefix."""

    def __init__(self) -> None:
        super().__init__("MIGRATION_HISTORY_INVALID")


class MigrationPendingError(MigrationError):
    """The database is missing one or more expected migrations."""

    def __init__(self) -> None:
        super().__init__("MIGRATION_PENDING")


class MigrationDefinitionError(MigrationError):
    """A packaged migration does not satisfy the closed migration contract."""

    def __init__(self) -> None:
        super().__init__("MIGRATION_DEFINITION_INVALID")


@dataclass(frozen=True)
class _ResourceMigration:
    version: int
    name: str
    sha256: str
    upgrade: Callable[[sqlite3.Connection], None]


_MIGRATION_MODULES: dict[MigrationScope, tuple[str, ...]] = {
    "global": (
        "v0001_initial",
        "v0002_knowledge",
        "v0003_knowledge_proposals",
        "v0004_scope_policy",
        "v0005_cases",
        "v0006_lifecycle",
        "v0007_case_index_serialization",
        "v0008_recovery_journal",
        "v0009_rollback",
    ),
    "client": (
        "v0001_initial",
        "v0002_fact_ledger",
        "v0003_sessions",
        "v0004_generation_risk",
        "v0005_archive",
        "v0006_lifecycle",
        "v0007_recovery_journal",
    ),
}
_BOOTSTRAP_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY CHECK(version > 0),
    name TEXT NOT NULL UNIQUE CHECK(length(name) > 0),
    sha256 TEXT NOT NULL CHECK(
        length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    applied_at TEXT NOT NULL CHECK(
        applied_at GLOB '????-??-??T??:??:??*Z'
        OR applied_at GLOB '????-??-??T??:??:??*+00:00'
    )
)
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _valid_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_migrations(
    migrations: Iterable[Migration],
) -> tuple[Migration, ...]:
    try:
        ordered = tuple(sorted(migrations, key=lambda migration: migration.version))
    except Exception as error:
        raise MigrationDefinitionError from error
    versions: set[int] = set()
    names: set[str] = set()
    for migration in ordered:
        if (
            type(migration.version) is not int
            or migration.version <= 0
            or type(migration.name) is not str
            or not migration.name
            or migration.name in names
            or migration.version in versions
            or not _valid_sha256(migration.sha256)
            or not callable(migration.upgrade)
        ):
            raise MigrationDefinitionError
        versions.add(migration.version)
        names.add(migration.name)
    return ordered


def _deny_nested_transaction_control(
    action_code: int,
    first_argument: str | None,
    second_argument: str | None,
    database_name: str | None,
    trigger_name: str | None,
) -> int:
    del first_argument, second_argument, database_name, trigger_name
    if action_code in {sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_SAVEPOINT}:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


@contextmanager
def _migration_upgrade_guard(
    connection: sqlite3.Connection,
) -> Iterator[None]:
    """Prevent a migration callback from committing outside the runner."""

    connection.set_authorizer(_deny_nested_transaction_control)
    try:
        yield
    finally:
        connection.set_authorizer(None)


def load_migrations(scope: MigrationScope) -> tuple[Migration, ...]:
    """Load a closed scope's migrations and hash their exact source bytes."""

    if scope not in _MIGRATION_MODULES:
        raise MigrationDefinitionError
    package = f"consultation_kb.storage.migrations.{scope}"
    loaded: list[Migration] = []
    for module_name in _MIGRATION_MODULES[scope]:
        try:
            source = resources.files(package).joinpath(f"{module_name}.py").read_bytes()
            module = import_module(f"{package}.{module_name}")
            version = getattr(module, "VERSION")
            name = getattr(module, "NAME")
            upgrade = cast(
                Callable[[sqlite3.Connection], None],
                getattr(module, "upgrade"),
            )
        except Exception as error:
            raise MigrationDefinitionError from error
        loaded.append(
            _ResourceMigration(
                version=version,
                name=name,
                sha256=sha256(source).hexdigest(),
                upgrade=upgrade,
            )
        )
    return _validate_migrations(loaded)


class MigrationRunner:
    def __init__(
        self,
        connection: sqlite3.Connection,
        migrations: Iterable[Migration],
    ) -> None:
        self._connection = connection
        self._migrations = _validate_migrations(migrations)

    @classmethod
    def for_scope(
        cls,
        connection: sqlite3.Connection,
        scope: MigrationScope,
    ) -> MigrationRunner:
        return cls(connection, load_migrations(scope))

    def ensure_migration_table(self) -> None:
        with transaction(self._connection):
            self._connection.execute(_BOOTSTRAP_SCHEMA)

    def apply(self) -> None:
        self.ensure_migration_table()
        while True:
            with transaction(self._connection):
                applied = self._read_applied()
                self._verify_history(applied, require_complete=False)
                if len(applied) == len(self._migrations):
                    return
                migration = self._migrations[len(applied)]
                with _migration_upgrade_guard(self._connection):
                    migration.upgrade(self._connection)
                self._connection.execute(
                    "INSERT INTO schema_migrations"
                    "(version, name, sha256, applied_at) VALUES (?, ?, ?, ?)",
                    (
                        migration.version,
                        migration.name,
                        migration.sha256,
                        _utc_now(),
                    ),
                )

    def check(self) -> None:
        row = self._connection.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type = 'table' AND name = 'schema_migrations'"
        ).fetchone()
        if row is None:
            raise MigrationPendingError
        applied = self._read_applied()
        self._verify_history(applied, require_complete=True)

    def _read_applied(self) -> tuple[tuple[int, str, str], ...]:
        try:
            rows = self._connection.execute(
                "SELECT version, name, sha256 "
                "FROM schema_migrations ORDER BY version"
            ).fetchall()
        except sqlite3.DatabaseError as error:
            raise MigrationHistoryError from error
        if any(
            len(row) != 3
            or type(row[0]) is not int
            or type(row[1]) is not str
            or type(row[2]) is not str
            for row in rows
        ):
            raise MigrationHistoryError
        return tuple((row[0], row[1], row[2]) for row in rows)

    def _verify_history(
        self,
        applied: tuple[tuple[int, str, str], ...],
        *,
        require_complete: bool,
    ) -> None:
        if len(applied) > len(self._migrations):
            raise MigrationHistoryError
        for index, (version, name, checksum) in enumerate(applied):
            expected = self._migrations[index]
            if version != expected.version or name != expected.name:
                raise MigrationHistoryError
            if checksum != expected.sha256:
                raise MigrationChecksumError
        if require_complete and len(applied) != len(self._migrations):
            raise MigrationPendingError
