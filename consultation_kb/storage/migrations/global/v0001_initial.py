"""Initial global control-plane schema."""

from __future__ import annotations

import sqlite3


VERSION = 1
NAME = "initial_global_control_plane"


_STATEMENTS = (
    """
    CREATE TABLE clients (
        client_id TEXT PRIMARY KEY CHECK(length(client_id) > 0),
        directory_object_id TEXT NOT NULL UNIQUE CHECK(length(directory_object_id) > 0),
        alias_lookup_sha256 TEXT NOT NULL UNIQUE CHECK(
            length(alias_lookup_sha256) = 64
            AND alias_lookup_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
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
    "CREATE INDEX idx_clients_state ON clients(state)",
    """
    CREATE TABLE capabilities (
        capability_id TEXT PRIMARY KEY CHECK(length(capability_id) > 0),
        token_sha256 TEXT NOT NULL UNIQUE CHECK(
            length(token_sha256) = 64
            AND token_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        session_id TEXT NOT NULL UNIQUE CHECK(length(session_id) > 0),
        client_id TEXT NOT NULL
            REFERENCES clients(client_id) ON DELETE RESTRICT,
        permissions_json TEXT NOT NULL CHECK(length(permissions_json) > 0),
        issued_at TEXT NOT NULL CHECK(
            length(issued_at) = 27
            AND issued_at GLOB '????-??-??T??:??:??.??????Z'
        ),
        expires_at TEXT NOT NULL CHECK(
            length(expires_at) = 27
            AND expires_at GLOB '????-??-??T??:??:??.??????Z'
            AND expires_at > issued_at
        ),
        revoked_at TEXT CHECK(
            revoked_at IS NULL
            OR (
                length(revoked_at) = 27
                AND revoked_at GLOB '????-??-??T??:??:??.??????Z'
                AND revoked_at >= issued_at
            )
        ),
        state TEXT NOT NULL CHECK(state IN ('ACTIVE', 'REVOKED')),
        capability_epoch INTEGER NOT NULL DEFAULT 1 CHECK(capability_epoch > 0),
        CHECK(
            (state = 'ACTIVE' AND revoked_at IS NULL)
            OR (state = 'REVOKED' AND revoked_at IS NOT NULL)
        )
    )
    """,
    "CREATE INDEX idx_capabilities_client ON capabilities(client_id)",
    "CREATE INDEX idx_capabilities_state ON capabilities(state)",
    "CREATE INDEX idx_capabilities_expiry ON capabilities(expires_at)",
    """
    CREATE TABLE approval_requests (
        request_id TEXT PRIMARY KEY CHECK(length(request_id) > 0),
        descriptor_sha256 TEXT NOT NULL CHECK(
            length(descriptor_sha256) = 64
            AND descriptor_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        descriptor_json TEXT NOT NULL CHECK(length(descriptor_json) > 0),
        diff_object_ref_json TEXT NOT NULL CHECK(length(diff_object_ref_json) > 0),
        purpose TEXT NOT NULL CHECK(length(purpose) > 0),
        target_scope_hash TEXT NOT NULL CHECK(
            length(target_scope_hash) = 64
            AND target_scope_hash NOT GLOB '*[^0-9a-f]*'
        ),
        session_id TEXT,
        base_version INTEGER NOT NULL CHECK(base_version >= 0),
        created_at TEXT NOT NULL CHECK(
            created_at GLOB '????-??-??T??:??:??*Z'
            OR created_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        expires_at TEXT NOT NULL CHECK(
            expires_at GLOB '????-??-??T??:??:??*Z'
            OR expires_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        nonce_sha256 TEXT NOT NULL UNIQUE CHECK(
            length(nonce_sha256) = 64
            AND nonce_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        nonce_ciphertext BLOB NOT NULL CHECK(length(nonce_ciphertext) > 0),
        state TEXT NOT NULL CHECK(
            state IN (
                'PENDING', 'CONFIRMED', 'REJECTED', 'ISSUED', 'ACKNOWLEDGED'
            )
        ),
        provider_event_sha256 TEXT CHECK(
            provider_event_sha256 IS NULL
            OR (
                length(provider_event_sha256) = 64
                AND provider_event_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        confirmed_at TEXT CHECK(
            confirmed_at IS NULL
            OR confirmed_at GLOB '????-??-??T??:??:??*Z'
            OR confirmed_at GLOB '????-??-??T??:??:??*+00:00'
        )
    )
    """,
    "CREATE INDEX idx_approval_requests_state ON approval_requests(state)",
    "CREATE INDEX idx_approval_requests_expires ON approval_requests(expires_at)",
    """
    CREATE TABLE approval_receipts (
        request_id TEXT PRIMARY KEY
            REFERENCES approval_requests(request_id) ON DELETE RESTRICT,
        receipt_json TEXT NOT NULL CHECK(length(receipt_json) > 0),
        operation_id TEXT UNIQUE,
        confirmed_at TEXT NOT NULL CHECK(
            confirmed_at GLOB '????-??-??T??:??:??*Z'
            OR confirmed_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        acknowledged_at TEXT CHECK(
            acknowledged_at IS NULL
            OR acknowledged_at GLOB '????-??-??T??:??:??*Z'
            OR acknowledged_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        state TEXT NOT NULL CHECK(state IN ('ISSUED', 'ACKNOWLEDGED'))
    )
    """,
    "CREATE INDEX idx_approval_receipts_state ON approval_receipts(state)",
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
    """
    CREATE TABLE audit_events (
        event_id TEXT PRIMARY KEY CHECK(length(event_id) > 0),
        event_type TEXT NOT NULL CHECK(length(event_type) > 0),
        component TEXT NOT NULL CHECK(length(component) > 0),
        outcome TEXT NOT NULL CHECK(length(outcome) > 0),
        error_code TEXT,
        scope_hash TEXT NOT NULL CHECK(
            length(scope_hash) = 64 AND scope_hash NOT GLOB '*[^0-9a-f]*'
        ),
        safe_counts_json TEXT NOT NULL CHECK(length(safe_counts_json) > 0),
        versions_json TEXT NOT NULL CHECK(length(versions_json) > 0),
        occurred_at TEXT NOT NULL CHECK(
            occurred_at GLOB '????-??-??T??:??:??*Z'
            OR occurred_at GLOB '????-??-??T??:??:??*+00:00'
        )
    )
    """,
    "CREATE INDEX idx_audit_events_type_time ON audit_events(event_type, occurred_at)",
)


def upgrade(connection: sqlite3.Connection) -> None:
    """Create the complete initial global schema inside the runner transaction."""

    for statement in _STATEMENTS:
        connection.execute(statement)
