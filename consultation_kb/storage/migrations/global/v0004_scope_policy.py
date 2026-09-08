"""Hash-only authority records for versioned C1 scope policies."""

from __future__ import annotations

import sqlite3


VERSION = 4
NAME = "scope_policy_authority"


_STATEMENTS = (
    """
    CREATE TABLE scope_policy_versions (
        policy_id TEXT NOT NULL CHECK(length(policy_id) > 0),
        version INTEGER NOT NULL CHECK(version > 0),
        semantic_sha256 TEXT NOT NULL CHECK(
            length(semantic_sha256) = 64
            AND semantic_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        cas_object_ref TEXT NOT NULL CHECK(
            cas_object_ref = 'sha256:' || cas_object_sha256
        ),
        cas_object_sha256 TEXT NOT NULL CHECK(
            length(cas_object_sha256) = 64
            AND cas_object_sha256 NOT GLOB '*[^0-9a-f]*'
            AND cas_object_sha256 = semantic_sha256
        ),
        cas_object_size_bytes INTEGER NOT NULL CHECK(cas_object_size_bytes > 0),
        cas_object_media_type TEXT NOT NULL CHECK(
            cas_object_media_type = 'application/json'
        ),
        status TEXT NOT NULL CHECK(
            status IN ('PREPARED', 'APPROVED', 'REVOKED', 'SUPERSEDED')
        ),
        approval_request_id TEXT UNIQUE,
        approved_at TEXT CHECK(
            approved_at IS NULL
            OR approved_at GLOB '????-??-??T??:??:??*Z'
            OR approved_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        revocation_approval_request_id TEXT UNIQUE,
        revoked_at TEXT CHECK(
            revoked_at IS NULL
            OR revoked_at GLOB '????-??-??T??:??:??*Z'
            OR revoked_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        effective_from TEXT NOT NULL CHECK(
            effective_from GLOB '????-??-??T??:??:??*Z'
            OR effective_from GLOB '????-??-??T??:??:??*+00:00'
        ),
        effective_to TEXT CHECK(
            effective_to IS NULL
            OR effective_to GLOB '????-??-??T??:??:??*Z'
            OR effective_to GLOB '????-??-??T??:??:??*+00:00'
        ),
        supersedes_policy_id TEXT,
        supersedes_version INTEGER CHECK(
            supersedes_version IS NULL OR supersedes_version > 0
        ),
        supersedes_sha256 TEXT CHECK(
            supersedes_sha256 IS NULL
            OR (
                length(supersedes_sha256) = 64
                AND supersedes_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        created_at TEXT NOT NULL CHECK(
            created_at GLOB '????-??-??T??:??:??*Z'
            OR created_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        updated_at TEXT NOT NULL CHECK(
            updated_at GLOB '????-??-??T??:??:??*Z'
            OR updated_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        PRIMARY KEY(policy_id, version),
        UNIQUE(policy_id, semantic_sha256),
        FOREIGN KEY(supersedes_policy_id, supersedes_version)
            REFERENCES scope_policy_versions(policy_id, version)
            ON DELETE RESTRICT,
        CHECK(effective_to IS NULL OR effective_to > effective_from),
        CHECK(updated_at >= created_at),
        CHECK(approved_at IS NULL OR approved_at >= created_at),
        CHECK(revoked_at IS NULL OR revoked_at >= approved_at),
        CHECK(approved_at IS NULL OR updated_at >= approved_at),
        CHECK(revoked_at IS NULL OR updated_at >= revoked_at),
        CHECK(
            (version = 1
             AND supersedes_policy_id IS NULL
             AND supersedes_version IS NULL
             AND supersedes_sha256 IS NULL)
            OR
            (version > 1
             AND supersedes_policy_id = policy_id
             AND supersedes_version = version - 1
             AND supersedes_sha256 IS NOT NULL)
        ),
        CHECK(
            (status = 'PREPARED'
             AND approval_request_id IS NULL
             AND approved_at IS NULL)
            OR
            (status IN ('APPROVED', 'REVOKED', 'SUPERSEDED')
             AND approval_request_id IS NOT NULL
             AND approved_at IS NOT NULL)
        ),
        CHECK(
            (status = 'REVOKED'
             AND revocation_approval_request_id IS NOT NULL
             AND revoked_at IS NOT NULL)
            OR
            (status != 'REVOKED'
             AND revocation_approval_request_id IS NULL
             AND revoked_at IS NULL)
        )
    )
    """,
    """
    CREATE UNIQUE INDEX idx_scope_policy_one_approved
    ON scope_policy_versions(policy_id) WHERE status = 'APPROVED'
    """,
    """
    CREATE INDEX idx_scope_policy_status_effective
    ON scope_policy_versions(status, effective_from, effective_to)
    """,
    """
    CREATE TABLE scope_policy_approval_bindings (
        approval_request_id TEXT PRIMARY KEY CHECK(length(approval_request_id) > 0),
        policy_id TEXT NOT NULL,
        version INTEGER NOT NULL CHECK(version > 0),
        action TEXT NOT NULL CHECK(action IN ('APPROVE', 'REVOKE')),
        bound_at TEXT NOT NULL CHECK(
            bound_at GLOB '????-??-??T??:??:??*Z'
            OR bound_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        UNIQUE(policy_id, version, action),
        FOREIGN KEY(policy_id, version)
            REFERENCES scope_policy_versions(policy_id, version)
            ON DELETE RESTRICT
    )
    """,
)


def upgrade(connection: sqlite3.Connection) -> None:
    for statement in _STATEMENTS:
        connection.execute(statement)
