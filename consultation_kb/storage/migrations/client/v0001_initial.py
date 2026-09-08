"""Initial client-isolated schema."""

from __future__ import annotations

import sqlite3


VERSION = 1
NAME = "initial_client_scope"


_STATEMENTS = (
    """
    CREATE TABLE sessions (
        session_id TEXT PRIMARY KEY CHECK(length(session_id) > 0),
        client_scope_hash TEXT NOT NULL CHECK(
            length(client_scope_hash) = 64
            AND client_scope_hash NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK(state IN ('OPEN', 'CLOSED', 'ARCHIVED')),
        started_at TEXT NOT NULL CHECK(
            started_at GLOB '????-??-??T??:??:??*Z'
            OR started_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        closed_at TEXT CHECK(
            closed_at IS NULL
            OR closed_at GLOB '????-??-??T??:??:??*Z'
            OR closed_at GLOB '????-??-??T??:??:??*+00:00'
        )
    )
    """,
    "CREATE INDEX idx_sessions_state ON sessions(state)",
    """
    CREATE TABLE review_decisions (
        decision_id TEXT PRIMARY KEY CHECK(length(decision_id) > 0),
        session_id TEXT NOT NULL
            REFERENCES sessions(session_id) ON DELETE RESTRICT,
        object_id TEXT NOT NULL CHECK(length(object_id) > 0),
        decision TEXT NOT NULL CHECK(decision IN ('APPROVED', 'REJECTED', 'EDITED')),
        reviewer_id_hash TEXT NOT NULL CHECK(
            length(reviewer_id_hash) = 64
            AND reviewer_id_hash NOT GLOB '*[^0-9a-f]*'
        ),
        decided_at TEXT NOT NULL CHECK(
            decided_at GLOB '????-??-??T??:??:??*Z'
            OR decided_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        UNIQUE(session_id, object_id)
    )
    """,
    "CREATE INDEX idx_review_decisions_decision ON review_decisions(decision)",
    """
    CREATE TABLE approval_executions (
        operation_id TEXT PRIMARY KEY CHECK(length(operation_id) > 0),
        request_id TEXT NOT NULL UNIQUE CHECK(length(request_id) > 0),
        descriptor_sha256 TEXT NOT NULL CHECK(
            length(descriptor_sha256) = 64
            AND descriptor_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        draft_sha256 TEXT NOT NULL CHECK(
            length(draft_sha256) = 64
            AND draft_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        descriptor_base_version INTEGER NOT NULL CHECK(descriptor_base_version >= 0),
        target_scope_hash TEXT NOT NULL CHECK(
            length(target_scope_hash) = 64
            AND target_scope_hash NOT GLOB '*[^0-9a-f]*'
        ),
        nonce_sha256 TEXT NOT NULL UNIQUE CHECK(
            length(nonce_sha256) = 64
            AND nonce_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK(state IN ('CLAIMED', 'APPLIED')),
        applied_commit_version INTEGER CHECK(applied_commit_version > 0),
        applied_at TEXT CHECK(
            applied_at IS NULL
            OR applied_at GLOB '????-??-??T??:??:??*Z'
            OR applied_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        CHECK(
            (state = 'CLAIMED' AND applied_commit_version IS NULL AND applied_at IS NULL)
            OR (
                state = 'APPLIED'
                AND applied_commit_version IS NOT NULL
                AND applied_at IS NOT NULL
            )
        )
    )
    """,
    "CREATE INDEX idx_approval_executions_state ON approval_executions(state)",
    """
    CREATE TABLE publication_operations (
        operation_id TEXT PRIMARY KEY CHECK(length(operation_id) > 0),
        purpose TEXT NOT NULL CHECK(length(purpose) > 0),
        authority_base_version INTEGER NOT NULL CHECK(authority_base_version > 0),
        approval_request_id TEXT NOT NULL CHECK(length(approval_request_id) > 0),
        descriptor_sha256 TEXT NOT NULL CHECK(
            length(descriptor_sha256) = 64
            AND descriptor_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK(
            state IN ('PREPARED', 'VERIFIED', 'ACTIVE', 'FAILED')
        ),
        required_manifests_json TEXT NOT NULL CHECK(
            length(required_manifests_json) > 0
        ),
        required_manifest_count INTEGER NOT NULL CHECK(required_manifest_count >= 0),
        verified_manifest_count INTEGER NOT NULL DEFAULT 0 CHECK(
            verified_manifest_count >= 0
            AND verified_manifest_count <= required_manifest_count
        ),
        expected_current_epoch INTEGER CHECK(
            expected_current_epoch IS NULL OR expected_current_epoch >= 1
        ),
        runtime_epoch INTEGER CHECK(runtime_epoch IS NULL OR runtime_epoch > 0),
        created_at TEXT NOT NULL CHECK(
            created_at GLOB '????-??-??T??:??:??*Z'
            OR created_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        activated_at TEXT CHECK(
            activated_at IS NULL
            OR activated_at GLOB '????-??-??T??:??:??*Z'
            OR activated_at GLOB '????-??-??T??:??:??*+00:00'
        )
    )
    """,
    "CREATE INDEX idx_publication_operations_state ON publication_operations(state)",
    """
    CREATE TABLE runtime_epochs (
        epoch INTEGER PRIMARY KEY CHECK(epoch > 0),
        operation_id TEXT NOT NULL UNIQUE
            REFERENCES publication_operations(operation_id) ON DELETE RESTRICT,
        state TEXT NOT NULL CHECK(state IN ('PREPARED', 'ACTIVE', 'RETIRED')),
        created_at TEXT NOT NULL CHECK(
            created_at GLOB '????-??-??T??:??:??*Z'
            OR created_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        activated_at TEXT CHECK(
            activated_at IS NULL
            OR activated_at GLOB '????-??-??T??:??:??*Z'
            OR activated_at GLOB '????-??-??T??:??:??*+00:00'
        )
    )
    """,
    """
    CREATE UNIQUE INDEX idx_runtime_epochs_one_active
    ON runtime_epochs(state) WHERE state = 'ACTIVE'
    """,
    """
    CREATE TABLE artifact_manifests (
        manifest_id TEXT PRIMARY KEY CHECK(length(manifest_id) > 0),
        operation_id TEXT NOT NULL
            REFERENCES publication_operations(operation_id) ON DELETE RESTRICT,
        artifact_key TEXT NOT NULL CHECK(length(artifact_key) > 0),
        artifact_kind TEXT NOT NULL CHECK(length(artifact_kind) > 0),
        source_version TEXT NOT NULL CHECK(length(source_version) > 0),
        manifest_sha256 TEXT NOT NULL UNIQUE CHECK(
            length(manifest_sha256) = 64
            AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK(state IN ('PREPARED', 'VERIFIED', 'ACTIVE')),
        verified INTEGER NOT NULL DEFAULT 0 CHECK(verified IN (0, 1)),
        created_at TEXT NOT NULL CHECK(
            created_at GLOB '????-??-??T??:??:??*Z'
            OR created_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        verified_at TEXT CHECK(
            verified_at IS NULL
            OR verified_at GLOB '????-??-??T??:??:??*Z'
            OR verified_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        UNIQUE(operation_id, artifact_key)
    )
    """,
    "CREATE INDEX idx_artifact_manifests_state ON artifact_manifests(state)",
    """
    CREATE INDEX idx_artifact_manifests_artifact
    ON artifact_manifests(artifact_kind, artifact_key, source_version)
    """,
    """
    CREATE TABLE artifact_members (
        manifest_id TEXT NOT NULL
            REFERENCES artifact_manifests(manifest_id) ON DELETE CASCADE,
        ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
        object_type TEXT NOT NULL CHECK(length(object_type) > 0),
        object_id TEXT NOT NULL CHECK(length(object_id) > 0),
        object_sha256 TEXT NOT NULL CHECK(
            length(object_sha256) = 64
            AND object_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        source_version TEXT NOT NULL CHECK(length(source_version) > 0),
        source_lineage_json TEXT NOT NULL CHECK(length(source_lineage_json) > 0),
        media_type TEXT NOT NULL CHECK(length(media_type) > 0),
        size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
        PRIMARY KEY(manifest_id, ordinal),
        UNIQUE(manifest_id, object_id)
    )
    """,
    "CREATE INDEX idx_artifact_members_hash ON artifact_members(object_sha256)",
    """
    CREATE TABLE active_artifacts (
        epoch INTEGER NOT NULL
            REFERENCES runtime_epochs(epoch) ON DELETE RESTRICT,
        artifact_key TEXT NOT NULL CHECK(length(artifact_key) > 0),
        manifest_id TEXT NOT NULL
            REFERENCES artifact_manifests(manifest_id) ON DELETE RESTRICT,
        activated_at TEXT NOT NULL CHECK(
            activated_at GLOB '????-??-??T??:??:??*Z'
            OR activated_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        PRIMARY KEY(epoch, artifact_key),
        UNIQUE(epoch, manifest_id)
    )
    """,
    "CREATE INDEX idx_active_artifacts_manifest ON active_artifacts(manifest_id)",
    """
    CREATE TABLE tombstones (
        tombstone_id TEXT PRIMARY KEY CHECK(length(tombstone_id) > 0),
        target_type TEXT NOT NULL CHECK(length(target_type) > 0),
        target_id_hash TEXT NOT NULL CHECK(
            length(target_id_hash) = 64
            AND target_id_hash NOT GLOB '*[^0-9a-f]*'
        ),
        source_lineage_hash TEXT NOT NULL DEFAULT '' CHECK(
            source_lineage_hash = ''
            OR (
                length(source_lineage_hash) = 64
                AND source_lineage_hash NOT GLOB '*[^0-9a-f]*'
            )
        ),
        reason_code TEXT NOT NULL CHECK(length(reason_code) > 0),
        created_at TEXT NOT NULL CHECK(
            created_at GLOB '????-??-??T??:??:??*Z'
            OR created_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        UNIQUE(target_type, target_id_hash, source_lineage_hash)
    )
    """,
    "CREATE INDEX idx_tombstones_target ON tombstones(target_type, target_id_hash)",
    "CREATE INDEX idx_tombstones_lineage ON tombstones(source_lineage_hash)",
)


def upgrade(connection: sqlite3.Connection) -> None:
    """Create the complete initial client schema inside the runner transaction."""

    for statement in _STATEMENTS:
        connection.execute(statement)
