"""SQLite storage primitives for the consultation knowledge base."""

from consultation_kb.storage.connection import (
    DatabaseMode,
    NestedTransactionError,
    connect_database,
    connect_database_snapshot,
    transaction,
)
from consultation_kb.storage.migrate import (
    Migration,
    MigrationChecksumError,
    MigrationDefinitionError,
    MigrationError,
    MigrationHistoryError,
    MigrationPendingError,
    MigrationRunner,
    MigrationScope,
    load_migrations,
)

__all__ = [
    "DatabaseMode",
    "Migration",
    "MigrationChecksumError",
    "MigrationDefinitionError",
    "MigrationError",
    "MigrationHistoryError",
    "MigrationPendingError",
    "MigrationRunner",
    "MigrationScope",
    "NestedTransactionError",
    "connect_database",
    "connect_database_snapshot",
    "load_migrations",
    "transaction",
]
