"""Explicit SQLite connection and transaction boundaries."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from os import PathLike
from pathlib import Path
from typing import Literal, TypeAlias


DatabaseMode: TypeAlias = Literal["writer", "reader"]


class NestedTransactionError(RuntimeError):
    """Raised when code tries to open a nested transaction."""

    def __init__(self) -> None:
        super().__init__("DATABASE_TRANSACTION_NESTED")


def connect_database(
    path: str | PathLike[str],
    mode: DatabaseMode,
) -> sqlite3.Connection:
    """Open a SQLite database without Python's implicit transaction behavior."""

    if mode not in {"writer", "reader"}:
        raise ValueError("DATABASE_MODE_INVALID")

    database_path = Path(path).resolve(strict=False)
    if mode == "reader":
        connection = sqlite3.connect(
            f"{database_path.as_uri()}?mode=ro",
            uri=True,
            isolation_level=None,
            timeout=5.0,
        )
    else:
        connection = sqlite3.connect(
            database_path,
            isolation_level=None,
            timeout=5.0,
        )

    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        if mode == "writer":
            journal_mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if journal_mode is None or str(journal_mode[0]).lower() != "wal":
                raise sqlite3.OperationalError("DATABASE_WAL_REQUIRED")
            connection.execute("PRAGMA synchronous = FULL")
        else:
            connection.execute("PRAGMA query_only = ON")
        return connection
    except BaseException:
        connection.close()
        raise


def connect_database_snapshot(
    path: str | PathLike[str],
) -> sqlite3.Connection:
    """Open an offline immutable snapshot without creating SQLite sidecars."""

    database_path = Path(path).resolve(strict=False)
    sidecars = tuple(
        database_path.with_name(f"{database_path.name}{suffix}")
        for suffix in ("-wal", "-shm", "-journal")
    )
    if any(sidecar.exists() for sidecar in sidecars):
        raise sqlite3.OperationalError("DATABASE_SNAPSHOT_UNSAFE")
    connection = sqlite3.connect(
        f"{database_path.as_uri()}?mode=ro&immutable=1",
        uri=True,
        isolation_level=None,
        timeout=5.0,
    )
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA query_only = ON")
        return connection
    except BaseException:
        connection.close()
        raise


@contextmanager
def transaction(
    connection: sqlite3.Connection,
    *,
    immediate: bool = True,
) -> Iterator[sqlite3.Connection]:
    """Run one explicit transaction and roll it back on every exceptional exit."""

    if connection.in_transaction:
        raise NestedTransactionError
    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield connection
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    else:
        try:
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
