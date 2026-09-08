"""Immutable global rollback plans and exact approval attestations."""

from __future__ import annotations

import sqlite3


VERSION = 9
NAME = "global_rollback"


_STATEMENTS = (
    """
    CREATE TABLE lifecycle_plan_objects (
        object_id TEXT PRIMARY KEY CHECK(length(object_id) > 0),
        version INTEGER NOT NULL CHECK(version > 0),
        content_sha256 TEXT NOT NULL CHECK(
            length(content_sha256) = 64
            AND content_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        size_bytes INTEGER NOT NULL CHECK(size_bytes > 0),
        media_type TEXT NOT NULL CHECK(media_type = 'application/json'),
        purpose TEXT NOT NULL CHECK(purpose IN ('delete', 'rollback', 'rebuild')),
        operation_id TEXT NOT NULL UNIQUE CHECK(length(operation_id) > 0),
        plan_sha256 TEXT NOT NULL CHECK(
            length(plan_sha256) = 64
            AND plan_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        base_version INTEGER NOT NULL CHECK(base_version >= 0),
        target_scope_hash TEXT NOT NULL CHECK(
            length(target_scope_hash) = 64
            AND target_scope_hash NOT GLOB '*[^0-9a-f]*'
        ),
        created_at TEXT NOT NULL CHECK(
            created_at GLOB '????-??-??T??:??:??*Z'
            OR created_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        CHECK(julianday(created_at) IS NOT NULL)
    )
    """,
    """
    CREATE TRIGGER lifecycle_plan_objects_no_update
    BEFORE UPDATE ON lifecycle_plan_objects BEGIN
        SELECT RAISE(ABORT, 'lifecycle plan object is immutable');
    END
    """,
    """
    CREATE TRIGGER lifecycle_plan_objects_no_delete
    BEFORE DELETE ON lifecycle_plan_objects BEGIN
        SELECT RAISE(ABORT, 'lifecycle plan object is immutable');
    END
    """,
    """
    CREATE TRIGGER lifecycle_plan_objects_no_replace
    BEFORE INSERT ON lifecycle_plan_objects
    WHEN EXISTS(
        SELECT 1 FROM lifecycle_plan_objects
         WHERE object_id = NEW.object_id OR operation_id = NEW.operation_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'lifecycle plan object is immutable');
    END
    """,
    """
    CREATE TABLE lifecycle_approval_attestations (
        operation_id TEXT PRIMARY KEY
            REFERENCES approval_executions(operation_id) ON DELETE RESTRICT,
        request_id TEXT NOT NULL UNIQUE CHECK(length(request_id) > 0),
        descriptor_sha256 TEXT NOT NULL CHECK(
            length(descriptor_sha256) = 64
            AND descriptor_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        plan_object_id TEXT NOT NULL UNIQUE
            REFERENCES lifecycle_plan_objects(object_id) ON DELETE RESTRICT,
        plan_version INTEGER NOT NULL CHECK(plan_version > 0),
        plan_content_sha256 TEXT NOT NULL CHECK(
            length(plan_content_sha256) = 64
            AND plan_content_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        plan_size_bytes INTEGER NOT NULL CHECK(plan_size_bytes > 0),
        plan_media_type TEXT NOT NULL CHECK(plan_media_type = 'application/json'),
        purpose TEXT NOT NULL CHECK(purpose IN ('delete', 'rollback', 'rebuild')),
        base_version INTEGER NOT NULL CHECK(base_version >= 0),
        target_scope_hash TEXT NOT NULL CHECK(
            length(target_scope_hash) = 64
            AND target_scope_hash NOT GLOB '*[^0-9a-f]*'
        ),
        attested_at TEXT NOT NULL CHECK(
            attested_at GLOB '????-??-??T??:??:??*Z'
            OR attested_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        CHECK(julianday(attested_at) IS NOT NULL)
    )
    """,
    """
    CREATE TRIGGER lifecycle_approval_attestations_no_update
    BEFORE UPDATE ON lifecycle_approval_attestations BEGIN
        SELECT RAISE(ABORT, 'lifecycle approval attestation is immutable');
    END
    """,
    """
    CREATE TRIGGER lifecycle_approval_attestations_no_delete
    BEFORE DELETE ON lifecycle_approval_attestations BEGIN
        SELECT RAISE(ABORT, 'lifecycle approval attestation is immutable');
    END
    """,
    """
    CREATE TRIGGER lifecycle_approval_attestations_no_replace
    BEFORE INSERT ON lifecycle_approval_attestations
    WHEN EXISTS(
        SELECT 1 FROM lifecycle_approval_attestations
         WHERE operation_id = NEW.operation_id
            OR request_id = NEW.request_id
            OR plan_object_id = NEW.plan_object_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'lifecycle approval attestation is immutable');
    END
    """,
)


def upgrade(connection: sqlite3.Connection) -> None:
    """Install global rollback authority in the migration transaction."""

    for statement in _STATEMENTS:
        connection.execute(statement)
