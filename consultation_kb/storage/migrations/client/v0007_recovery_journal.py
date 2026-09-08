"""Body-free client recovery journal and authority bindings."""

from __future__ import annotations

import sqlite3


VERSION = 7
NAME = "recovery_journal"


_STATEMENTS = (
    """
    CREATE TABLE recovery_operation_authority_bindings (
        operation_id TEXT PRIMARY KEY
            REFERENCES publication_operations(operation_id) ON DELETE RESTRICT,
        authority_version INTEGER NOT NULL CHECK(authority_version >= 0),
        permission_epoch INTEGER NOT NULL CHECK(permission_epoch >= 0),
        tombstone_epoch INTEGER NOT NULL CHECK(tombstone_epoch >= 0),
        binding_origin TEXT NOT NULL CHECK(
            binding_origin IN ('LIVE', 'LEGACY_UNTRUSTED')
        ),
        bound_at TEXT NOT NULL CHECK(julianday(bound_at) IS NOT NULL)
    )
    """,
    """
    INSERT INTO recovery_operation_authority_bindings(
        operation_id, authority_version, permission_epoch,
        tombstone_epoch, binding_origin, bound_at
    )
    SELECT operation.operation_id, authority.commit_version, 0,
           (SELECT COUNT(*) FROM tombstones), 'LEGACY_UNTRUSTED',
           operation.created_at
      FROM publication_operations AS operation
      JOIN client_fact_authority AS authority ON authority.singleton = 1
    """,
    """
    CREATE TRIGGER recovery_operation_authority_binding_insert
    AFTER INSERT ON publication_operations BEGIN
        INSERT INTO recovery_operation_authority_bindings(
            operation_id, authority_version, permission_epoch,
            tombstone_epoch, binding_origin, bound_at
        )
        SELECT NEW.operation_id, authority.commit_version, 0,
               (SELECT COUNT(*) FROM tombstones), 'LIVE', NEW.created_at
          FROM client_fact_authority AS authority
         WHERE authority.singleton = 1;
    END
    """,
    """
    CREATE TRIGGER recovery_operation_authority_bindings_no_update
    BEFORE UPDATE ON recovery_operation_authority_bindings BEGIN
        SELECT RAISE(ABORT, 'recovery operation authority binding is immutable');
    END
    """,
    """
    CREATE TRIGGER recovery_operation_authority_bindings_no_delete
    BEFORE DELETE ON recovery_operation_authority_bindings BEGIN
        SELECT RAISE(ABORT, 'recovery operation authority binding is immutable');
    END
    """,
    """
    CREATE TABLE recovery_outbox_authority_bindings (
        event_id TEXT PRIMARY KEY
            REFERENCES outbox_events(event_id) ON DELETE RESTRICT,
        tombstone_epoch INTEGER NOT NULL CHECK(tombstone_epoch >= 0),
        binding_origin TEXT NOT NULL CHECK(
            binding_origin IN ('LIVE', 'LEGACY_UNTRUSTED')
        ),
        bound_at TEXT NOT NULL CHECK(julianday(bound_at) IS NOT NULL)
    )
    """,
    """
    INSERT INTO recovery_outbox_authority_bindings(
        event_id, tombstone_epoch, binding_origin, bound_at
    )
    SELECT event_id, (SELECT COUNT(*) FROM tombstones),
           'LEGACY_UNTRUSTED', created_at
      FROM outbox_events
    """,
    """
    CREATE TRIGGER recovery_outbox_authority_binding_insert
    AFTER INSERT ON outbox_events BEGIN
        INSERT INTO recovery_outbox_authority_bindings(
            event_id, tombstone_epoch, binding_origin, bound_at
        ) VALUES (
            NEW.event_id, (SELECT COUNT(*) FROM tombstones),
            'LIVE', NEW.created_at
        );
    END
    """,
    """
    CREATE TRIGGER recovery_outbox_authority_bindings_no_update
    BEFORE UPDATE ON recovery_outbox_authority_bindings BEGIN
        SELECT RAISE(ABORT, 'recovery outbox authority binding is immutable');
    END
    """,
    """
    CREATE TRIGGER recovery_outbox_authority_bindings_no_delete
    BEFORE DELETE ON recovery_outbox_authority_bindings BEGIN
        SELECT RAISE(ABORT, 'recovery outbox authority binding is immutable');
    END
    """,
    """
    CREATE TABLE recovery_epoch_retention_windows (
        epoch INTEGER PRIMARY KEY
            REFERENCES runtime_epochs(epoch) ON DELETE RESTRICT,
        rollback_expires_at TEXT NOT NULL CHECK(
            julianday(rollback_expires_at) IS NOT NULL
        ),
        retention_required INTEGER NOT NULL CHECK(retention_required IN (0, 1)),
        binding_origin TEXT NOT NULL CHECK(
            binding_origin IN ('DEFAULT', 'EXPLICIT', 'LEGACY_UNTRUSTED')
        ),
        bound_at TEXT NOT NULL CHECK(julianday(bound_at) IS NOT NULL)
    )
    """,
    """
    INSERT INTO recovery_epoch_retention_windows(
        epoch, rollback_expires_at, retention_required, binding_origin, bound_at
    )
    SELECT epoch,
           strftime('%Y-%m-%dT%H:%M:%fZ',
                    COALESCE(activated_at, created_at), '+7 days'),
           1, 'LEGACY_UNTRUSTED', COALESCE(activated_at, created_at)
      FROM runtime_epochs
     WHERE state = 'RETIRED'
    """,
    """
    CREATE TRIGGER recovery_epoch_retention_on_retire
    AFTER UPDATE OF state ON runtime_epochs
    WHEN OLD.state = 'ACTIVE' AND NEW.state = 'RETIRED' BEGIN
        INSERT OR IGNORE INTO recovery_epoch_retention_windows(
            epoch, rollback_expires_at, retention_required,
            binding_origin, bound_at
        ) VALUES (
            NEW.epoch,
            strftime('%Y-%m-%dT%H:%M:%fZ',
                     COALESCE(NEW.activated_at, NEW.created_at), '+7 days'),
            0, 'DEFAULT', COALESCE(NEW.activated_at, NEW.created_at)
        );
    END
    """,
    """
    CREATE TRIGGER recovery_epoch_retention_no_update
    BEFORE UPDATE ON recovery_epoch_retention_windows BEGIN
        SELECT RAISE(ABORT, 'recovery epoch retention is immutable');
    END
    """,
    """
    CREATE TRIGGER recovery_epoch_retention_no_delete
    BEFORE DELETE ON recovery_epoch_retention_windows BEGIN
        SELECT RAISE(ABORT, 'recovery epoch retention is immutable');
    END
    """,
    """
    CREATE TABLE recovery_decision_journal (
        decision_sha256 TEXT PRIMARY KEY CHECK(
            length(decision_sha256) = 64
            AND decision_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        evidence_sha256 TEXT NOT NULL CHECK(
            length(evidence_sha256) = 64
            AND evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        database_ref_sha256 TEXT NOT NULL CHECK(
            length(database_ref_sha256) = 64
            AND database_ref_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        database_scope TEXT NOT NULL CHECK(database_scope IN ('global', 'client')),
        purpose TEXT NOT NULL CHECK(
            purpose IN (
                'private_record', 'profile', 'wiki', 'graph', 'lex',
                'vector', 'case', 'index', 'outbox'
            )
        ),
        manifest_id TEXT NOT NULL CHECK(length(manifest_id) > 0),
        manifest_sha256 TEXT NOT NULL CHECK(
            length(manifest_sha256) = 64
            AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        before_state TEXT NOT NULL CHECK(
            before_state IN ('DRAFT', 'PREPARED', 'ACTIVE', 'RETIRED')
        ),
        after_state TEXT NOT NULL CHECK(
            after_state IN ('DRAFT', 'PREPARED', 'ACTIVE', 'RETIRED')
        ),
        action TEXT NOT NULL CHECK(
            action IN (
                'CLEAN_STAGING', 'VERIFY_AND_ACTIVATE',
                'TOMBSTONE_PREPARED', 'ACK_SOURCE',
                'ENQUEUE_REBUILD', 'QUEUE_CLEANUP'
            )
        ),
        verification_result TEXT NOT NULL CHECK(length(verification_result) > 0),
        reason_codes_json TEXT NOT NULL CHECK(
            json_valid(reason_codes_json) AND json_type(reason_codes_json) = 'array'
        ),
        durable_result_sha256 TEXT NOT NULL CHECK(
            length(durable_result_sha256) = 64
            AND durable_result_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        applied_at TEXT NOT NULL CHECK(julianday(applied_at) IS NOT NULL),
        UNIQUE(database_ref_sha256, purpose, manifest_id, evidence_sha256)
    )
    """,
    """
    CREATE TRIGGER recovery_decision_journal_no_update
    BEFORE UPDATE ON recovery_decision_journal BEGIN
        SELECT RAISE(ABORT, 'recovery decision journal is append only');
    END
    """,
    """
    CREATE TRIGGER recovery_decision_journal_no_delete
    BEFORE DELETE ON recovery_decision_journal BEGIN
        SELECT RAISE(ABORT, 'recovery decision journal is append only');
    END
    """,
    """
    CREATE TRIGGER recovery_decision_journal_no_replace
    BEFORE INSERT ON recovery_decision_journal
    WHEN EXISTS(
        SELECT 1 FROM recovery_decision_journal
         WHERE decision_sha256 = NEW.decision_sha256
    ) BEGIN
        SELECT RAISE(ABORT, 'recovery decision journal is append only');
    END
    """,
    """
    CREATE TABLE recovery_prepared_retirements (
        manifest_id TEXT PRIMARY KEY
            REFERENCES artifact_manifests(manifest_id) ON DELETE RESTRICT,
        operation_id TEXT NOT NULL
            REFERENCES publication_operations(operation_id) ON DELETE RESTRICT,
        decision_sha256 TEXT NOT NULL UNIQUE
            REFERENCES recovery_decision_journal(decision_sha256) ON DELETE RESTRICT,
        manifest_sha256 TEXT NOT NULL CHECK(
            length(manifest_sha256) = 64
            AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        evidence_sha256 TEXT NOT NULL CHECK(
            length(evidence_sha256) = 64
            AND evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        retired_at TEXT NOT NULL CHECK(julianday(retired_at) IS NOT NULL)
    )
    """,
    """
    CREATE TRIGGER recovery_prepared_retirements_no_update
    BEFORE UPDATE ON recovery_prepared_retirements BEGIN
        SELECT RAISE(ABORT, 'prepared recovery retirement is append only');
    END
    """,
    """
    CREATE TRIGGER recovery_prepared_retirements_no_delete
    BEFORE DELETE ON recovery_prepared_retirements BEGIN
        SELECT RAISE(ABORT, 'prepared recovery retirement is append only');
    END
    """,
    """
    CREATE TABLE recovery_required_actions (
        decision_sha256 TEXT PRIMARY KEY
            REFERENCES recovery_decision_journal(decision_sha256) ON DELETE RESTRICT,
        action_type TEXT NOT NULL CHECK(action_type IN ('rebuild', 'cleanup')),
        database_ref_sha256 TEXT NOT NULL CHECK(
            length(database_ref_sha256) = 64
            AND database_ref_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        purpose TEXT NOT NULL CHECK(length(purpose) > 0),
        manifest_id TEXT NOT NULL CHECK(length(manifest_id) > 0),
        manifest_sha256 TEXT NOT NULL CHECK(
            length(manifest_sha256) = 64
            AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        evidence_sha256 TEXT NOT NULL CHECK(
            length(evidence_sha256) = 64
            AND evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK(
            state IN ('PENDING', 'CLAIMED', 'SUCCEEDED', 'FAILED')
        ),
        attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
        last_error_code TEXT CHECK(
            last_error_code IS NULL OR (
                length(last_error_code) BETWEEN 1 AND 64
                AND last_error_code NOT GLOB '*[^A-Z0-9_]*'
            )
        ),
        created_at TEXT NOT NULL CHECK(julianday(created_at) IS NOT NULL),
        updated_at TEXT NOT NULL CHECK(julianday(updated_at) IS NOT NULL),
        CHECK(updated_at >= created_at),
        CHECK(
            (state = 'PENDING' AND attempt_count = 0 AND last_error_code IS NULL)
            OR (state = 'CLAIMED' AND attempt_count > 0 AND last_error_code IS NULL)
            OR (state = 'SUCCEEDED' AND attempt_count > 0 AND last_error_code IS NULL)
            OR (state = 'FAILED' AND attempt_count > 0 AND last_error_code IS NOT NULL)
        )
    )
    """,
    """
    CREATE INDEX idx_recovery_required_actions_pending
    ON recovery_required_actions(state, action_type, purpose, created_at)
    """,
    """
    CREATE TRIGGER recovery_required_actions_update_guard
    BEFORE UPDATE ON recovery_required_actions BEGIN
        SELECT CASE WHEN
            NEW.decision_sha256 != OLD.decision_sha256
            OR NEW.action_type != OLD.action_type
            OR NEW.database_ref_sha256 != OLD.database_ref_sha256
            OR NEW.purpose != OLD.purpose
            OR NEW.manifest_id != OLD.manifest_id
            OR NEW.manifest_sha256 != OLD.manifest_sha256
            OR NEW.evidence_sha256 != OLD.evidence_sha256
            OR NEW.created_at != OLD.created_at
            OR NEW.updated_at < OLD.updated_at
            OR NOT (
                (OLD.state IN ('PENDING', 'FAILED')
                 AND NEW.state = 'CLAIMED'
                 AND NEW.attempt_count = OLD.attempt_count + 1
                 AND NEW.last_error_code IS NULL)
                OR (OLD.state = 'CLAIMED'
                    AND NEW.state = 'SUCCEEDED'
                    AND NEW.attempt_count = OLD.attempt_count
                    AND NEW.last_error_code IS NULL)
                OR (OLD.state = 'CLAIMED'
                    AND NEW.state = 'FAILED'
                    AND NEW.attempt_count = OLD.attempt_count
                    AND NEW.last_error_code IS NOT NULL)
            )
        THEN RAISE(ABORT, 'recovery required action transition invalid') END;
    END
    """,
    """
    CREATE TRIGGER recovery_required_actions_no_delete
    BEFORE DELETE ON recovery_required_actions BEGIN
        SELECT RAISE(ABORT, 'recovery required actions cannot be deleted');
    END
    """,
)


def upgrade(connection: sqlite3.Connection) -> None:
    for statement in _STATEMENTS:
        connection.execute(statement)
