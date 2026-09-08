"""Durable, hash-bound global knowledge proposal operations.

Proposal bodies are immutable global-scope CAS objects.  SQLite deliberately
stores only opaque identifiers, hashes, sizes, media types, and approval /
execution bindings; no source path or knowledge body is copied into the
control plane.
"""

from __future__ import annotations

import sqlite3


VERSION = 3
NAME = "knowledge_proposal_operations"


_STATEMENTS = (
    """
    CREATE TABLE knowledge_proposal_operations (
        operation_id TEXT PRIMARY KEY CHECK(length(operation_id) > 0),
        operation_sha256 TEXT NOT NULL UNIQUE CHECK(
            length(operation_sha256) = 64
            AND operation_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        proposal_kind TEXT NOT NULL CHECK(
            proposal_kind IN ('CLAIM', 'WIKI', 'THEORY')
        ),
        proposal_id TEXT NOT NULL UNIQUE CHECK(length(proposal_id) > 0),
        target_id TEXT NOT NULL CHECK(length(target_id) > 0),
        base_version INTEGER NOT NULL CHECK(base_version >= 0),
        draft_sha256 TEXT NOT NULL CHECK(
            length(draft_sha256) = 64
            AND draft_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        proposal_object_ref TEXT NOT NULL CHECK(
            proposal_object_ref = 'sha256:' || proposal_object_sha256
        ),
        proposal_object_sha256 TEXT NOT NULL CHECK(
            length(proposal_object_sha256) = 64
            AND proposal_object_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        proposal_object_size_bytes INTEGER NOT NULL CHECK(
            proposal_object_size_bytes > 0
        ),
        proposal_object_media_type TEXT NOT NULL CHECK(
            proposal_object_media_type = 'application/json'
        ),
        approval_request_id TEXT UNIQUE
            REFERENCES approval_requests(request_id) ON DELETE RESTRICT,
        approval_descriptor_sha256 TEXT CHECK(
            approval_descriptor_sha256 IS NULL
            OR (
                length(approval_descriptor_sha256) = 64
                AND approval_descriptor_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        approval_expires_at TEXT CHECK(
            approval_expires_at IS NULL
            OR approval_expires_at GLOB '????-??-??T??:??:??*Z'
            OR approval_expires_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        execution_operation_id TEXT UNIQUE,
        execution_sha256 TEXT CHECK(
            execution_sha256 IS NULL
            OR (
                length(execution_sha256) = 64
                AND execution_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        state TEXT NOT NULL CHECK(
            state IN ('PROPOSED', 'REVIEW_PENDING', 'EXPIRED', 'APPLIED')
        ),
        created_at TEXT NOT NULL CHECK(
            created_at GLOB '????-??-??T??:??:??*Z'
            OR created_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        updated_at TEXT NOT NULL CHECK(
            updated_at GLOB '????-??-??T??:??:??*Z'
            OR updated_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        CHECK(
            (approval_request_id IS NULL
             AND approval_descriptor_sha256 IS NULL
             AND approval_expires_at IS NULL
             AND state = 'PROPOSED')
            OR
            (approval_request_id IS NOT NULL
             AND approval_descriptor_sha256 IS NOT NULL
             AND approval_expires_at IS NOT NULL
             AND state IN ('REVIEW_PENDING', 'EXPIRED', 'APPLIED'))
        ),
        CHECK(
            (state = 'APPLIED'
             AND execution_operation_id IS NOT NULL
             AND execution_sha256 IS NOT NULL)
            OR
            (state != 'APPLIED'
             AND execution_operation_id IS NULL
             AND execution_sha256 IS NULL)
        )
    )
    """,
    """
    CREATE INDEX idx_knowledge_proposals_approval
    ON knowledge_proposal_operations(approval_request_id, proposal_kind, state)
    """,
    """
    CREATE INDEX idx_knowledge_proposals_target
    ON knowledge_proposal_operations(proposal_kind, target_id, base_version)
    """,
)


def upgrade(connection: sqlite3.Connection) -> None:
    for statement in _STATEMENTS:
        connection.execute(statement)
