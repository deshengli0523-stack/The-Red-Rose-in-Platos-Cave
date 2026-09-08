"""Global deletion lifecycle and durable rebuild-control schema."""

from __future__ import annotations

import sqlite3


VERSION = 6
NAME = "global_lifecycle"


_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS rebuild_structured_artifacts (
        manifest_id TEXT PRIMARY KEY
            REFERENCES artifact_manifests(manifest_id) ON DELETE RESTRICT,
        artifact_key TEXT NOT NULL CHECK(length(artifact_key) > 0),
        artifact_kind TEXT NOT NULL CHECK(length(artifact_kind) > 0),
        source_version INTEGER NOT NULL CHECK(source_version > 0),
        semantic_basis_sha256 TEXT NOT NULL CHECK(
            length(semantic_basis_sha256) = 64
            AND semantic_basis_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        member_comparisons_json TEXT NOT NULL CHECK(
            json_valid(member_comparisons_json)
        ),
        envelope_sha256 TEXT NOT NULL CHECK(
            length(envelope_sha256) = 64
            AND envelope_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    )
    """,
    """
    CREATE TRIGGER IF NOT EXISTS rebuild_structured_artifacts_no_update
    BEFORE UPDATE ON rebuild_structured_artifacts BEGIN
        SELECT RAISE(ABORT, 'structured rebuild artifacts are immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS rebuild_structured_artifacts_no_delete
    BEFORE DELETE ON rebuild_structured_artifacts BEGIN
        SELECT RAISE(ABORT, 'structured rebuild artifacts are immutable');
    END
    """,
    """
    CREATE TABLE IF NOT EXISTS deletion_authority_state (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        deletion_version INTEGER NOT NULL CHECK(deletion_version >= 0),
        tombstone_epoch INTEGER NOT NULL CHECK(tombstone_epoch >= 0)
    )
    """,
    """
    INSERT INTO deletion_authority_state(
        singleton, deletion_version, tombstone_epoch
    )
    SELECT 1, 0, tombstone_epoch
      FROM knowledge_catalog_state
     WHERE singleton = 1
       AND NOT EXISTS(
           SELECT 1 FROM deletion_authority_state WHERE singleton = 1
       )
    """,
    """
    CREATE TABLE IF NOT EXISTS deletion_base_versions (
        authority_key TEXT NOT NULL CHECK(
            length(authority_key) BETWEEN 1 AND 64
            AND authority_key NOT GLOB '*[^a-z0-9_]*'
        ),
        scope_sha256 TEXT NOT NULL CHECK(
            length(scope_sha256) = 64
            AND scope_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        version INTEGER NOT NULL CHECK(version >= 0),
        PRIMARY KEY(authority_key, scope_sha256)
    )
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_base_versions_update_guard
    BEFORE UPDATE ON deletion_base_versions
    WHEN NEW.authority_key != OLD.authority_key
         OR NEW.scope_sha256 != OLD.scope_sha256
         OR NEW.version NOT IN (OLD.version, OLD.version + 1)
    BEGIN
        SELECT RAISE(ABORT, 'deletion base version transition invalid');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_base_versions_no_delete
    BEFORE DELETE ON deletion_base_versions BEGIN
        SELECT RAISE(ABORT, 'deletion base version cannot be deleted');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_base_versions_no_replace
    BEFORE INSERT ON deletion_base_versions
    WHEN EXISTS(
        SELECT 1 FROM deletion_base_versions
         WHERE authority_key = NEW.authority_key
           AND scope_sha256 = NEW.scope_sha256
    )
    BEGIN
        SELECT RAISE(ABORT, 'deletion base version cannot be replaced');
    END
    """,
    """
    CREATE TABLE IF NOT EXISTS publication_closure_attestations (
        operation_id TEXT PRIMARY KEY
            REFERENCES publication_operations(operation_id) ON DELETE RESTRICT,
        approval_draft_sha256 TEXT NOT NULL CHECK(
            length(approval_draft_sha256) = 64
            AND approval_draft_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        closure_sha256 TEXT NOT NULL CHECK(
            length(closure_sha256) = 64
            AND closure_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        created_at TEXT NOT NULL CHECK(
            created_at GLOB '????-??-??T??:??:??*Z'
            OR created_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        CHECK(julianday(created_at) IS NOT NULL)
    )
    """,
    """
    CREATE TRIGGER IF NOT EXISTS publication_closure_attestations_no_update
    BEFORE UPDATE ON publication_closure_attestations BEGIN
        SELECT RAISE(ABORT, 'publication closure attestation is immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS publication_closure_attestations_no_replace
    BEFORE INSERT ON publication_closure_attestations
    WHEN EXISTS(
        SELECT 1 FROM publication_closure_attestations
         WHERE operation_id = NEW.operation_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'publication closure attestation is immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS publication_closure_attestations_no_delete
    BEFORE DELETE ON publication_closure_attestations BEGIN
        SELECT RAISE(ABORT, 'publication closure attestation is immutable');
    END
    """,
    """
    CREATE TABLE IF NOT EXISTS deletion_requests (
        request_id TEXT PRIMARY KEY CHECK(length(request_id) > 0),
        operation_id TEXT NOT NULL UNIQUE
            REFERENCES approval_executions(operation_id) ON DELETE RESTRICT,
        plan_sha256 TEXT NOT NULL UNIQUE CHECK(
            length(plan_sha256) = 64
            AND plan_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        target_type TEXT NOT NULL CHECK(
            target_type IN (
                'client', 'session', 'case', 'case_authorization',
                'passage', 'claim'
            )
        ),
        target_id_hash TEXT NOT NULL CHECK(
            length(target_id_hash) = 64
            AND target_id_hash NOT GLOB '*[^0-9a-f]*'
        ),
        target_scope_hash TEXT NOT NULL CHECK(
            length(target_scope_hash) = 64
            AND target_scope_hash NOT GLOB '*[^0-9a-f]*'
        ),
        base_deletion_version INTEGER NOT NULL CHECK(base_deletion_version >= 0),
        committed_deletion_version INTEGER NOT NULL CHECK(
            committed_deletion_version = base_deletion_version + 1
        ),
        tombstone_epoch INTEGER NOT NULL CHECK(tombstone_epoch > 0),
        approval_request_id TEXT NOT NULL CHECK(length(approval_request_id) > 0),
        approval_descriptor_sha256 TEXT NOT NULL CHECK(
            length(approval_descriptor_sha256) = 64
            AND approval_descriptor_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        approval_target_scope_hash TEXT NOT NULL CHECK(
            length(approval_target_scope_hash) = 64
            AND approval_target_scope_hash NOT GLOB '*[^0-9a-f]*'
            AND approval_target_scope_hash = target_scope_hash
        ),
        state TEXT NOT NULL CHECK(
            state IN ('TOMBSTONED', 'PHYSICAL_CLEANUP_COMPLETE')
        ),
        queue_state TEXT NOT NULL CHECK(
            queue_state IN ('PENDING', 'RUNNING', 'PARTIAL', 'SUCCEEDED', 'FAILED')
        ),
        created_at TEXT NOT NULL CHECK(
            created_at GLOB '????-??-??T??:??:??*Z'
            OR created_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        CHECK(
            (state = 'TOMBSTONED' AND queue_state != 'SUCCEEDED')
            OR
            (state = 'PHYSICAL_CLEANUP_COMPLETE'
             AND queue_state = 'SUCCEEDED')
        )
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_deletion_requests_state
    ON deletion_requests(state, queue_state, tombstone_epoch)
    """,
    """
    CREATE TABLE IF NOT EXISTS deletion_revocations (
        request_id TEXT NOT NULL
            REFERENCES deletion_requests(request_id) ON DELETE RESTRICT,
        action_id TEXT NOT NULL CHECK(length(action_id) > 0),
        effect TEXT NOT NULL CHECK(
            effect IN ('revoke_case', 'revoke_authorization')
        ),
        object_type TEXT NOT NULL CHECK(
            length(object_type) BETWEEN 1 AND 64
            AND object_type NOT GLOB '*[^a-z0-9_]*'
        ),
        target_id_hash TEXT NOT NULL CHECK(
            length(target_id_hash) = 64
            AND target_id_hash NOT GLOB '*[^0-9a-f]*'
        ),
        object_version INTEGER NOT NULL CHECK(object_version >= 0),
        created_at TEXT NOT NULL CHECK(
            created_at GLOB '????-??-??T??:??:??*Z'
            OR created_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        PRIMARY KEY(request_id, action_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_deletion_revocations_target
    ON deletion_revocations(effect, object_type, target_id_hash)
    """,
    """
    CREATE TABLE IF NOT EXISTS deletion_queue_intents (
        intent_id TEXT PRIMARY KEY CHECK(length(intent_id) > 0),
        request_id TEXT NOT NULL
            REFERENCES deletion_requests(request_id) ON DELETE RESTRICT,
        action_id TEXT NOT NULL UNIQUE CHECK(length(action_id) > 0),
        action_type TEXT NOT NULL CHECK(
            action_type IN ('physical_delete', 'rebuild', 'backup_expiry')
        ),
        object_type TEXT NOT NULL CHECK(
            length(object_type) BETWEEN 1 AND 64
            AND object_type NOT GLOB '*[^a-z0-9_]*'
        ),
        target_id_hash TEXT NOT NULL CHECK(
            length(target_id_hash) = 64
            AND target_id_hash NOT GLOB '*[^0-9a-f]*'
        ),
        target_version INTEGER NOT NULL CHECK(target_version >= 0),
        target_content_sha256 TEXT NOT NULL CHECK(
            length(target_content_sha256) = 64
            AND target_content_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        authority_scope TEXT NOT NULL CHECK(authority_scope IN ('global', 'client')),
        state TEXT NOT NULL CHECK(
            state IN ('PENDING', 'CLAIMED', 'SUCCEEDED', 'FAILED', 'CANCELLED')
        ),
        attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
        last_error_code TEXT CHECK(
            last_error_code IS NULL OR (
                length(last_error_code) BETWEEN 1 AND 64
                AND last_error_code NOT GLOB '*[^A-Z0-9_]*'
            )
        ),
        claimed_at TEXT CHECK(
            claimed_at IS NULL
            OR claimed_at GLOB '????-??-??T??:??:??*Z'
            OR claimed_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        finished_at TEXT CHECK(
            finished_at IS NULL
            OR finished_at GLOB '????-??-??T??:??:??*Z'
            OR finished_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        created_at TEXT NOT NULL CHECK(
            created_at GLOB '????-??-??T??:??:??*Z'
            OR created_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        CHECK(julianday(created_at) IS NOT NULL),
        CHECK(claimed_at IS NULL OR julianday(claimed_at) IS NOT NULL),
        CHECK(finished_at IS NULL OR julianday(finished_at) IS NOT NULL),
        CHECK(
            (state = 'PENDING'
             AND attempt_count = 0
             AND last_error_code IS NULL
             AND claimed_at IS NULL
             AND finished_at IS NULL)
            OR
            (state = 'CLAIMED'
             AND attempt_count > 0
             AND last_error_code IS NULL
             AND claimed_at IS NOT NULL
             AND finished_at IS NULL)
            OR
            (state = 'FAILED'
             AND attempt_count > 0
             AND last_error_code IS NOT NULL
             AND claimed_at IS NOT NULL
             AND finished_at IS NULL)
            OR
            (state = 'SUCCEEDED'
             AND attempt_count > 0
             AND last_error_code IS NULL
             AND claimed_at IS NOT NULL
             AND finished_at IS NOT NULL
             AND julianday(finished_at) >= julianday(claimed_at))
            OR
            (state = 'CANCELLED'
             AND last_error_code IS NULL
             AND finished_at IS NOT NULL
             AND julianday(finished_at)
                 >= julianday(COALESCE(claimed_at, created_at))
             AND ((attempt_count = 0 AND claimed_at IS NULL)
                  OR (attempt_count > 0 AND claimed_at IS NOT NULL)))
        )
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_deletion_queue_pending
    ON deletion_queue_intents(state, action_type, created_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS deletion_intent_authority_proofs (
        intent_id TEXT PRIMARY KEY
            REFERENCES deletion_queue_intents(intent_id) ON DELETE RESTRICT,
        request_id TEXT NOT NULL
            REFERENCES deletion_requests(request_id) ON DELETE RESTRICT,
        action_id TEXT NOT NULL UNIQUE CHECK(length(action_id) > 0),
        deletion_plan_sha256 TEXT NOT NULL CHECK(
            length(deletion_plan_sha256) = 64
            AND deletion_plan_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        root_object_type TEXT NOT NULL CHECK(
            length(root_object_type) BETWEEN 1 AND 64
            AND root_object_type NOT GLOB '*[^a-z0-9_]*'
        ),
        root_target_id_hash TEXT NOT NULL CHECK(
            length(root_target_id_hash) = 64
            AND root_target_id_hash NOT GLOB '*[^0-9a-f]*'
        ),
        root_lineage_hash TEXT NOT NULL CHECK(
            length(root_lineage_hash) = 64
            AND root_lineage_hash NOT GLOB '*[^0-9a-f]*'
        ),
        action_descriptor_sha256 TEXT NOT NULL CHECK(
            length(action_descriptor_sha256) = 64
            AND action_descriptor_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        created_at TEXT NOT NULL CHECK(
            created_at GLOB '????-??-??T??:??:??*Z'
            OR created_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        UNIQUE(request_id, action_id),
        CHECK(julianday(created_at) IS NOT NULL)
    )
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_intent_authority_proofs_no_update
    BEFORE UPDATE ON deletion_intent_authority_proofs BEGIN
        SELECT RAISE(ABORT, 'deletion intent authority proof is immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_intent_authority_proofs_no_replace
    BEFORE INSERT ON deletion_intent_authority_proofs
    WHEN EXISTS(
        SELECT 1 FROM deletion_intent_authority_proofs
         WHERE intent_id = NEW.intent_id
            OR action_id = NEW.action_id
            OR (request_id = NEW.request_id AND action_id = NEW.action_id)
    )
    BEGIN
        SELECT RAISE(ABORT, 'deletion intent authority proof is immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_intent_authority_proofs_no_delete
    BEFORE DELETE ON deletion_intent_authority_proofs BEGIN
        SELECT RAISE(ABORT, 'deletion intent authority proof is immutable');
    END
    """,
    """
    CREATE TABLE IF NOT EXISTS backup_destruction_queue (
        backup_id TEXT PRIMARY KEY CHECK(length(backup_id) > 0),
        request_id TEXT NOT NULL
            REFERENCES deletion_requests(request_id) ON DELETE RESTRICT,
        location_class TEXT NOT NULL CHECK(
            location_class IN (
                'local_snapshot', 'offline_media',
                'cloud_managed', 'external_managed'
            )
        ),
        object_set_sha256 TEXT NOT NULL CHECK(
            length(object_set_sha256) = 64
            AND object_set_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        due_at TEXT NOT NULL CHECK(
            due_at GLOB '????-??-??T??:??:??*Z'
            OR due_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        state TEXT NOT NULL CHECK(state IN ('pending', 'failed', 'succeeded')),
        attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
        last_error_code TEXT CHECK(
            last_error_code IS NULL OR (
                length(last_error_code) BETWEEN 1 AND 64
                AND last_error_code NOT GLOB '*[^A-Z0-9_]*'
            )
        ),
        finished_at TEXT CHECK(
            finished_at IS NULL
            OR finished_at GLOB '????-??-??T??:??:??*Z'
            OR finished_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        operator_proof_sha256 TEXT CHECK(
            operator_proof_sha256 IS NULL OR (
                length(operator_proof_sha256) = 64
                AND operator_proof_sha256 NOT GLOB '*[^0-9a-f]*'
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
        CHECK(julianday(due_at) IS NOT NULL),
        CHECK(julianday(created_at) IS NOT NULL),
        CHECK(julianday(updated_at) IS NOT NULL),
        CHECK(finished_at IS NULL OR julianday(finished_at) IS NOT NULL),
        CHECK(julianday(due_at) >= julianday(created_at)),
        CHECK(julianday(updated_at) >= julianday(created_at)),
        CHECK(
            (state = 'pending'
             AND finished_at IS NULL
             AND operator_proof_sha256 IS NULL)
            OR
            (state = 'failed'
             AND attempt_count > 0
             AND last_error_code IS NOT NULL
             AND finished_at IS NULL
             AND operator_proof_sha256 IS NULL)
            OR
            (state = 'succeeded'
             AND attempt_count > 0
             AND last_error_code IS NULL
             AND finished_at IS NOT NULL
             AND finished_at = updated_at
             AND operator_proof_sha256 IS NOT NULL)
        )
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS backup_destruction_objects (
        backup_id TEXT NOT NULL
            REFERENCES backup_destruction_queue(backup_id) ON DELETE RESTRICT,
        object_sha256 TEXT NOT NULL CHECK(
            length(object_sha256) = 64
            AND object_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        PRIMARY KEY(backup_id, object_sha256)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_backup_destruction_pending
    ON backup_destruction_queue(state, due_at, backup_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS rebuild_jobs (
        job_id TEXT PRIMARY KEY CHECK(length(job_id) > 0),
        source_intent_id TEXT UNIQUE,
        approval_operation_id TEXT NOT NULL UNIQUE
            REFERENCES approval_executions(operation_id) ON DELETE RESTRICT,
        approval_request_id TEXT NOT NULL CHECK(length(approval_request_id) > 0),
        plan_sha256 TEXT NOT NULL CHECK(
            length(plan_sha256) = 64
            AND plan_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        idempotency_key_sha256 TEXT NOT NULL UNIQUE CHECK(
            length(idempotency_key_sha256) = 64
            AND idempotency_key_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        scope_sha256 TEXT NOT NULL CHECK(
            length(scope_sha256) = 64
            AND scope_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        purpose TEXT NOT NULL CHECK(
            length(purpose) BETWEEN 1 AND 64
            AND purpose NOT GLOB '*[^a-z0-9_]*'
        ),
        builder_dag_sha256 TEXT NOT NULL CHECK(
            length(builder_dag_sha256) = 64
            AND builder_dag_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        input_authority_versions_sha256 TEXT NOT NULL CHECK(
            length(input_authority_versions_sha256) = 64
            AND input_authority_versions_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        policy_sha256 TEXT CHECK(
            policy_sha256 IS NULL OR (
                length(policy_sha256) = 64
                AND policy_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        model_descriptor_sha256 TEXT CHECK(
            model_descriptor_sha256 IS NULL OR (
                length(model_descriptor_sha256) = 64
                AND model_descriptor_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        tombstone_epoch INTEGER NOT NULL CHECK(tombstone_epoch >= 0),
        state TEXT NOT NULL CHECK(
            state IN (
                'queued', 'running', 'verifying', 'activating',
                'succeeded', 'failed', 'cancelled'
            )
        ),
        attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
        output_manifest_set_sha256 TEXT CHECK(
            output_manifest_set_sha256 IS NULL OR (
                length(output_manifest_set_sha256) = 64
                AND output_manifest_set_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        equivalence_report_sha256 TEXT CHECK(
            equivalence_report_sha256 IS NULL OR (
                length(equivalence_report_sha256) = 64
                AND equivalence_report_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        last_error_code TEXT CHECK(
            last_error_code IS NULL OR (
                length(last_error_code) BETWEEN 1 AND 64
                AND last_error_code NOT GLOB '*[^A-Z0-9_]*'
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
        started_at TEXT CHECK(
            started_at IS NULL
            OR started_at GLOB '????-??-??T??:??:??*Z'
            OR started_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        finished_at TEXT CHECK(
            finished_at IS NULL
            OR finished_at GLOB '????-??-??T??:??:??*Z'
            OR finished_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        cancelled_at TEXT CHECK(
            cancelled_at IS NULL
            OR cancelled_at GLOB '????-??-??T??:??:??*Z'
            OR cancelled_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        CHECK(julianday(created_at) IS NOT NULL),
        CHECK(julianday(updated_at) IS NOT NULL),
        CHECK(started_at IS NULL OR julianday(started_at) IS NOT NULL),
        CHECK(finished_at IS NULL OR julianday(finished_at) IS NOT NULL),
        CHECK(cancelled_at IS NULL OR julianday(cancelled_at) IS NOT NULL),
        CHECK(julianday(updated_at) >= julianday(created_at)),
        CHECK(started_at IS NULL OR julianday(started_at) >= julianday(created_at)),
        CHECK(finished_at IS NULL OR julianday(finished_at) >= julianday(created_at)),
        CHECK(cancelled_at IS NULL OR julianday(cancelled_at) >= julianday(created_at)),
        CHECK(
            (state = 'queued'
             AND finished_at IS NULL
             AND cancelled_at IS NULL
             AND output_manifest_set_sha256 IS NULL
             AND equivalence_report_sha256 IS NULL
             AND ((attempt_count = 0
                   AND started_at IS NULL
                   AND last_error_code IS NULL)
                  OR (attempt_count > 0
                      AND started_at IS NOT NULL
                      AND (last_error_code IS NULL
                           OR last_error_code = 'REBUILD_PROCESS_INTERRUPTED'))))
            OR
            (state IN ('running', 'verifying')
             AND attempt_count > 0
             AND started_at IS NOT NULL
             AND finished_at IS NULL
             AND cancelled_at IS NULL
             AND output_manifest_set_sha256 IS NULL
             AND equivalence_report_sha256 IS NULL
             AND last_error_code IS NULL)
            OR
            (state = 'activating'
             AND attempt_count > 0
             AND started_at IS NOT NULL
             AND finished_at IS NULL
             AND cancelled_at IS NULL
             AND output_manifest_set_sha256 IS NOT NULL
             AND equivalence_report_sha256 IS NOT NULL
             AND last_error_code IS NULL)
            OR
            (state = 'succeeded'
             AND attempt_count > 0
             AND started_at IS NOT NULL
             AND finished_at IS NOT NULL
             AND finished_at = updated_at
             AND cancelled_at IS NULL
             AND output_manifest_set_sha256 IS NOT NULL
             AND equivalence_report_sha256 IS NOT NULL
             AND last_error_code IS NULL)
            OR
            (state = 'failed'
             AND ((attempt_count = 0 AND started_at IS NULL)
                  OR (attempt_count > 0 AND started_at IS NOT NULL))
             AND finished_at IS NOT NULL
             AND finished_at = updated_at
             AND cancelled_at IS NULL
             AND output_manifest_set_sha256 IS NULL
             AND equivalence_report_sha256 IS NULL
             AND last_error_code IS NOT NULL)
            OR
            (state = 'cancelled'
             AND ((attempt_count = 0 AND started_at IS NULL)
                  OR (attempt_count > 0 AND started_at IS NOT NULL))
             AND finished_at IS NOT NULL
             AND finished_at = updated_at
             AND cancelled_at = finished_at
             AND output_manifest_set_sha256 IS NULL
             AND equivalence_report_sha256 IS NULL
             AND last_error_code IS NULL)
        )
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS rebuild_source_intents (
        intent_id TEXT PRIMARY KEY CHECK(length(intent_id) > 0),
        intent_kind TEXT NOT NULL CHECK(intent_kind IN ('rollback')),
        created_at TEXT NOT NULL CHECK(
            created_at GLOB '????-??-??T??:??:??*Z'
            OR created_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        CHECK(julianday(created_at) IS NOT NULL)
    )
    """,
    """
    CREATE TRIGGER IF NOT EXISTS rebuild_source_intents_no_update
    BEFORE UPDATE ON rebuild_source_intents BEGIN
        SELECT RAISE(ABORT, 'rebuild source intent is immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS rebuild_source_intents_no_delete
    BEFORE DELETE ON rebuild_source_intents BEGIN
        SELECT RAISE(ABORT, 'rebuild source intent is immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS rebuild_jobs_source_intent_guard
    BEFORE INSERT ON rebuild_jobs
    WHEN NEW.source_intent_id IS NOT NULL
         AND NOT EXISTS(
             SELECT 1 FROM deletion_queue_intents
              WHERE intent_id = NEW.source_intent_id
         )
         AND NOT EXISTS(
             SELECT 1 FROM rebuild_source_intents
              WHERE intent_id = NEW.source_intent_id
         )
    BEGIN
        SELECT RAISE(ABORT, 'rebuild source intent is not authoritative');
    END
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_rebuild_jobs_worker
    ON rebuild_jobs(state, updated_at, job_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS rebuild_stage_bindings (
        operation_id TEXT PRIMARY KEY
            REFERENCES publication_operations(operation_id) ON DELETE RESTRICT,
        job_id TEXT NOT NULL
            REFERENCES rebuild_jobs(job_id) ON DELETE RESTRICT,
        attempt_count INTEGER NOT NULL CHECK(attempt_count > 0),
        approval_request_id TEXT NOT NULL CHECK(length(approval_request_id) > 0),
        plan_sha256 TEXT NOT NULL CHECK(
            length(plan_sha256) = 64
            AND plan_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        scope_sha256 TEXT NOT NULL CHECK(
            length(scope_sha256) = 64
            AND scope_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        tombstone_epoch INTEGER NOT NULL CHECK(tombstone_epoch >= 0),
        created_at TEXT NOT NULL CHECK(
            created_at GLOB '????-??-??T??:??:??*Z'
            OR created_at GLOB '????-??-??T??:??:??*+00:00'
        ),
        UNIQUE(job_id, attempt_count),
        CHECK(julianday(created_at) IS NOT NULL)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_rebuild_stage_bindings_job
    ON rebuild_stage_bindings(job_id, attempt_count)
    """,
    """
    CREATE TRIGGER IF NOT EXISTS rebuild_stage_bindings_no_update
    BEFORE UPDATE ON rebuild_stage_bindings BEGIN
        SELECT RAISE(ABORT, 'rebuild stage binding is immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS rebuild_stage_bindings_no_replace
    BEFORE INSERT ON rebuild_stage_bindings
    WHEN EXISTS(
        SELECT 1 FROM rebuild_stage_bindings
         WHERE operation_id = NEW.operation_id
            OR (job_id = NEW.job_id AND attempt_count = NEW.attempt_count)
    )
    BEGIN
        SELECT RAISE(ABORT, 'rebuild stage binding is immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS rebuild_stage_bindings_no_delete
    BEFORE DELETE ON rebuild_stage_bindings BEGIN
        SELECT RAISE(ABORT, 'rebuild stage binding is immutable');
    END
    """,
    """
    CREATE TABLE IF NOT EXISTS rebuild_job_journal (
        journal_id TEXT PRIMARY KEY CHECK(length(journal_id) > 0),
        job_id TEXT NOT NULL REFERENCES rebuild_jobs(job_id) ON DELETE RESTRICT,
        sequence INTEGER NOT NULL CHECK(sequence > 0),
        state TEXT NOT NULL CHECK(
            state IN (
                'queued', 'running', 'verifying', 'activating',
                'succeeded', 'failed', 'cancelled'
            )
        ),
        evidence_sha256 TEXT NOT NULL CHECK(
            length(evidence_sha256) = 64
            AND evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        occurred_at TEXT NOT NULL CHECK(
            occurred_at GLOB '????-??-??T??:??:??*Z'
            OR occurred_at GLOB '????-??-??T??:??:??*+00:00'
        ) CHECK(julianday(occurred_at) IS NOT NULL),
        UNIQUE(job_id, sequence)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_rebuild_journal_job
    ON rebuild_job_journal(job_id, sequence)
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_authority_state_update_guard
    BEFORE UPDATE ON deletion_authority_state
    WHEN NEW.singleton != OLD.singleton
         OR NOT (
             (NEW.deletion_version = OLD.deletion_version
              AND NEW.tombstone_epoch = OLD.tombstone_epoch)
             OR
             (NEW.deletion_version = OLD.deletion_version
              AND NEW.tombstone_epoch = OLD.tombstone_epoch + 1)
             OR
             (NEW.deletion_version = OLD.deletion_version + 1
              AND NEW.tombstone_epoch = OLD.tombstone_epoch + 1)
         )
    BEGIN
        SELECT RAISE(ABORT, 'deletion authority CAS transition invalid');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_authority_state_no_delete
    BEFORE DELETE ON deletion_authority_state BEGIN
        SELECT RAISE(ABORT, 'deletion authority cannot be deleted');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_authority_state_no_replace
    BEFORE INSERT ON deletion_authority_state
    WHEN EXISTS(
        SELECT 1 FROM deletion_authority_state
         WHERE singleton = NEW.singleton
    )
    BEGIN
        SELECT RAISE(ABORT, 'deletion authority cannot be replaced');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_epoch_to_knowledge_catalog
    AFTER UPDATE OF tombstone_epoch ON deletion_authority_state
    WHEN (SELECT tombstone_epoch FROM knowledge_catalog_state WHERE singleton = 1)
         != NEW.tombstone_epoch
    BEGIN
        UPDATE knowledge_catalog_state
           SET tombstone_epoch = NEW.tombstone_epoch
         WHERE singleton = 1;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS knowledge_catalog_to_deletion_epoch
    AFTER UPDATE OF tombstone_epoch ON knowledge_catalog_state
    WHEN (SELECT tombstone_epoch FROM deletion_authority_state WHERE singleton = 1)
         != NEW.tombstone_epoch
    BEGIN
        UPDATE deletion_authority_state
           SET tombstone_epoch = NEW.tombstone_epoch
         WHERE singleton = 1;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS rebuild_jobs_insert_guard
    BEFORE INSERT ON rebuild_jobs
    WHEN EXISTS(
             SELECT 1 FROM rebuild_jobs
              WHERE job_id = NEW.job_id
                 OR idempotency_key_sha256 = NEW.idempotency_key_sha256
                 OR (NEW.source_intent_id IS NOT NULL
                     AND source_intent_id = NEW.source_intent_id)
         )
         OR NEW.state != 'queued'
         OR NEW.attempt_count != 0
         OR NEW.created_at != NEW.updated_at
         OR NEW.output_manifest_set_sha256 IS NOT NULL
         OR NEW.equivalence_report_sha256 IS NOT NULL
         OR NEW.last_error_code IS NOT NULL
         OR NEW.started_at IS NOT NULL
         OR NEW.finished_at IS NOT NULL
         OR NEW.cancelled_at IS NOT NULL
    BEGIN
        SELECT RAISE(ABORT, 'rebuild job must start queued');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS rebuild_jobs_transition_guard
    BEFORE UPDATE ON rebuild_jobs BEGIN
        SELECT CASE WHEN
            NEW.job_id != OLD.job_id
            OR NEW.source_intent_id IS NOT OLD.source_intent_id
            OR NEW.approval_operation_id IS NOT OLD.approval_operation_id
            OR NEW.approval_request_id IS NOT OLD.approval_request_id
            OR NEW.plan_sha256 != OLD.plan_sha256
            OR NEW.idempotency_key_sha256 != OLD.idempotency_key_sha256
            OR NEW.scope_sha256 != OLD.scope_sha256
            OR NEW.purpose != OLD.purpose
            OR NEW.builder_dag_sha256 != OLD.builder_dag_sha256
            OR NEW.input_authority_versions_sha256
               != OLD.input_authority_versions_sha256
            OR NEW.policy_sha256 IS NOT OLD.policy_sha256
            OR NEW.model_descriptor_sha256 IS NOT OLD.model_descriptor_sha256
            OR NEW.tombstone_epoch != OLD.tombstone_epoch
            OR NEW.created_at != OLD.created_at
            OR NOT (
                (NEW.state = OLD.state
                 AND NEW.attempt_count = OLD.attempt_count
                 AND NEW.output_manifest_set_sha256
                     IS OLD.output_manifest_set_sha256
                 AND NEW.equivalence_report_sha256
                     IS OLD.equivalence_report_sha256
                 AND NEW.last_error_code IS OLD.last_error_code
                 AND NEW.updated_at = OLD.updated_at
                 AND NEW.started_at IS OLD.started_at
                 AND NEW.finished_at IS OLD.finished_at
                 AND NEW.cancelled_at IS OLD.cancelled_at)
                OR
                (OLD.state = 'queued' AND NEW.state = 'running'
                 AND NEW.attempt_count = OLD.attempt_count + 1
                 AND NEW.output_manifest_set_sha256
                     IS OLD.output_manifest_set_sha256
                 AND NEW.equivalence_report_sha256
                     IS OLD.equivalence_report_sha256
                 AND NEW.last_error_code IS NULL
                 AND julianday(NEW.updated_at) >= julianday(OLD.updated_at)
                 AND NEW.started_at IS COALESCE(OLD.started_at, NEW.updated_at)
                 AND NEW.finished_at IS NULL
                 AND NEW.cancelled_at IS NULL)
                OR
                (OLD.state = 'running' AND NEW.state = 'verifying'
                 AND NEW.attempt_count = OLD.attempt_count
                 AND NEW.output_manifest_set_sha256
                     IS OLD.output_manifest_set_sha256
                 AND NEW.equivalence_report_sha256
                     IS OLD.equivalence_report_sha256
                 AND NEW.last_error_code IS NULL
                 AND julianday(NEW.updated_at) >= julianday(OLD.updated_at)
                 AND NEW.started_at IS OLD.started_at
                 AND NEW.finished_at IS NULL
                 AND NEW.cancelled_at IS NULL)
                OR
                (OLD.state = 'verifying' AND NEW.state = 'activating'
                 AND NEW.attempt_count = OLD.attempt_count
                 AND OLD.output_manifest_set_sha256 IS NULL
                 AND NEW.output_manifest_set_sha256 IS NOT NULL
                 AND OLD.equivalence_report_sha256 IS NULL
                 AND NEW.equivalence_report_sha256 IS NOT NULL
                 AND NEW.last_error_code IS NULL
                 AND julianday(NEW.updated_at) >= julianday(OLD.updated_at)
                 AND NEW.started_at IS OLD.started_at
                 AND NEW.finished_at IS NULL
                 AND NEW.cancelled_at IS NULL)
                OR
                (OLD.state = 'activating' AND NEW.state = 'succeeded'
                 AND NEW.attempt_count = OLD.attempt_count
                 AND NEW.output_manifest_set_sha256
                     = OLD.output_manifest_set_sha256
                 AND NEW.equivalence_report_sha256
                     = OLD.equivalence_report_sha256
                 AND NEW.last_error_code IS NULL
                 AND julianday(NEW.updated_at) >= julianday(OLD.updated_at)
                 AND NEW.started_at IS OLD.started_at
                 AND NEW.finished_at = NEW.updated_at
                 AND NEW.cancelled_at IS NULL)
                OR
                (OLD.state IN ('queued', 'running', 'verifying')
                 AND NEW.state = 'failed'
                 AND NEW.attempt_count = OLD.attempt_count
                 AND NEW.output_manifest_set_sha256
                     IS OLD.output_manifest_set_sha256
                 AND NEW.equivalence_report_sha256
                     IS OLD.equivalence_report_sha256
                 AND NEW.last_error_code IS NOT NULL
                 AND julianday(NEW.updated_at) >= julianday(OLD.updated_at)
                 AND NEW.started_at IS OLD.started_at
                 AND NEW.finished_at = NEW.updated_at
                 AND NEW.cancelled_at IS NULL)
                OR
                (OLD.state = 'failed' AND NEW.state = 'queued'
                 AND NEW.attempt_count = OLD.attempt_count
                 AND NEW.output_manifest_set_sha256 IS NULL
                 AND NEW.equivalence_report_sha256 IS NULL
                 AND NEW.last_error_code IS NULL
                 AND julianday(NEW.updated_at) >= julianday(OLD.updated_at)
                 AND NEW.started_at IS OLD.started_at
                 AND NEW.finished_at IS NULL
                 AND NEW.cancelled_at IS NULL)
                OR
                (OLD.state IN ('running', 'verifying')
                 AND NEW.state = 'queued'
                 AND NEW.attempt_count = OLD.attempt_count
                 AND NEW.output_manifest_set_sha256
                     IS OLD.output_manifest_set_sha256
                 AND NEW.equivalence_report_sha256
                     IS OLD.equivalence_report_sha256
                 AND NEW.last_error_code = 'REBUILD_PROCESS_INTERRUPTED'
                 AND julianday(NEW.updated_at) >= julianday(OLD.updated_at)
                 AND NEW.started_at IS OLD.started_at
                 AND NEW.finished_at IS NULL
                 AND NEW.cancelled_at IS NULL)
                OR
                (OLD.state IN ('queued', 'running', 'verifying', 'failed')
                 AND NEW.state = 'cancelled'
                 AND NEW.attempt_count = OLD.attempt_count
                 AND OLD.output_manifest_set_sha256 IS NULL
                 AND NEW.output_manifest_set_sha256 IS NULL
                 AND OLD.equivalence_report_sha256 IS NULL
                 AND NEW.equivalence_report_sha256 IS NULL
                 AND NEW.last_error_code IS NULL
                 AND julianday(NEW.updated_at) >= julianday(OLD.updated_at)
                 AND NEW.started_at IS OLD.started_at
                 AND NEW.finished_at = NEW.updated_at
                 AND NEW.cancelled_at = NEW.updated_at)
            )
        THEN RAISE(ABORT, 'rebuild job transition invalid') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS rebuild_jobs_no_delete
    BEFORE DELETE ON rebuild_jobs BEGIN
        SELECT RAISE(ABORT, 'rebuild job audit cannot be deleted');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_queue_intents_insert_guard
    BEFORE INSERT ON deletion_queue_intents
    WHEN EXISTS(
             SELECT 1 FROM deletion_queue_intents
              WHERE intent_id = NEW.intent_id OR action_id = NEW.action_id
         )
         OR NEW.state != 'PENDING'
         OR NEW.attempt_count != 0
         OR NEW.last_error_code IS NOT NULL
         OR NEW.claimed_at IS NOT NULL
         OR NEW.finished_at IS NOT NULL
    BEGIN
        SELECT RAISE(ABORT, 'deletion queue intent must start pending');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_queue_intents_update_guard
    BEFORE UPDATE ON deletion_queue_intents BEGIN
        SELECT CASE WHEN
            NEW.intent_id != OLD.intent_id
            OR NEW.request_id != OLD.request_id
            OR NEW.action_id != OLD.action_id
            OR NEW.action_type != OLD.action_type
            OR NEW.object_type != OLD.object_type
            OR NEW.target_id_hash != OLD.target_id_hash
            OR NEW.target_version != OLD.target_version
            OR NEW.target_content_sha256 != OLD.target_content_sha256
            OR NEW.authority_scope != OLD.authority_scope
            OR NEW.created_at != OLD.created_at
            OR NOT (
                (NEW.state = OLD.state
                 AND NEW.attempt_count = OLD.attempt_count
                 AND NEW.last_error_code IS OLD.last_error_code
                 AND NEW.claimed_at IS OLD.claimed_at
                 AND NEW.finished_at IS OLD.finished_at)
                OR
                (OLD.state IN ('PENDING', 'CLAIMED', 'FAILED')
                 AND NEW.state = 'CLAIMED'
                 AND NEW.attempt_count = OLD.attempt_count + 1
                 AND NEW.last_error_code IS NULL
                 AND NEW.claimed_at IS NOT NULL
                 AND julianday(NEW.claimed_at)
                     >= julianday(COALESCE(OLD.claimed_at, OLD.created_at))
                 AND NEW.finished_at IS NULL)
                OR
                (OLD.state = 'CLAIMED' AND NEW.state = 'FAILED'
                 AND NEW.attempt_count = OLD.attempt_count
                 AND NEW.last_error_code IS NOT NULL
                 AND NEW.claimed_at IS OLD.claimed_at
                 AND NEW.finished_at IS NULL)
                OR
                (OLD.state = 'CLAIMED' AND NEW.state = 'SUCCEEDED'
                 AND NEW.attempt_count = OLD.attempt_count
                 AND NEW.last_error_code IS NULL
                 AND NEW.claimed_at IS OLD.claimed_at
                 AND NEW.finished_at IS NOT NULL
                 AND julianday(NEW.finished_at) >= julianday(NEW.claimed_at))
                OR
                (OLD.state IN ('PENDING', 'CLAIMED', 'FAILED')
                 AND NEW.state = 'CANCELLED'
                 AND NEW.attempt_count = OLD.attempt_count
                 AND NEW.last_error_code IS NULL
                 AND NEW.claimed_at IS OLD.claimed_at
                 AND NEW.finished_at IS NOT NULL
                 AND julianday(NEW.finished_at)
                     >= julianday(COALESCE(OLD.claimed_at, OLD.created_at)))
            )
        THEN RAISE(ABORT, 'deletion queue intent transition invalid') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_queue_intents_no_delete
    BEFORE DELETE ON deletion_queue_intents BEGIN
        SELECT RAISE(ABORT, 'deletion queue intent cannot be deleted');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS backup_destruction_queue_insert_guard
    BEFORE INSERT ON backup_destruction_queue
    WHEN EXISTS(
             SELECT 1 FROM backup_destruction_queue
              WHERE backup_id = NEW.backup_id
         )
         OR NEW.state != 'pending'
         OR NEW.attempt_count != 0
         OR NEW.last_error_code IS NOT NULL
         OR NEW.finished_at IS NOT NULL
         OR NEW.operator_proof_sha256 IS NOT NULL
         OR NEW.created_at != NEW.updated_at
    BEGIN
        SELECT RAISE(ABORT, 'backup destruction must start pending');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS backup_destruction_queue_update_guard
    BEFORE UPDATE ON backup_destruction_queue BEGIN
        SELECT CASE WHEN
            NEW.backup_id != OLD.backup_id
            OR NEW.request_id != OLD.request_id
            OR NEW.location_class != OLD.location_class
            OR NEW.object_set_sha256 != OLD.object_set_sha256
            OR NEW.due_at != OLD.due_at
            OR NEW.created_at != OLD.created_at
            OR NOT (
                (NEW.state = OLD.state
                 AND NEW.attempt_count = OLD.attempt_count
                 AND NEW.last_error_code IS OLD.last_error_code
                 AND NEW.finished_at IS OLD.finished_at
                 AND NEW.operator_proof_sha256 IS OLD.operator_proof_sha256
                 AND NEW.updated_at = OLD.updated_at)
                OR
                (OLD.state IN ('pending', 'failed') AND NEW.state = 'failed'
                 AND NEW.attempt_count = OLD.attempt_count + 1
                 AND NEW.last_error_code IS NOT NULL
                 AND NEW.finished_at IS NULL
                 AND NEW.operator_proof_sha256 IS NULL
                 AND julianday(NEW.updated_at) >= julianday(OLD.updated_at))
                OR
                (OLD.state IN ('pending', 'failed') AND NEW.state = 'succeeded'
                 AND NEW.attempt_count = OLD.attempt_count + 1
                 AND NEW.last_error_code IS NULL
                 AND NEW.finished_at = NEW.updated_at
                 AND NEW.operator_proof_sha256 IS NOT NULL
                 AND julianday(NEW.updated_at) >= julianday(OLD.updated_at))
            )
        THEN RAISE(ABORT, 'backup destruction transition invalid') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS backup_destruction_queue_no_delete
    BEFORE DELETE ON backup_destruction_queue BEGIN
        SELECT RAISE(ABORT, 'backup destruction audit cannot be deleted');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS backup_destruction_objects_no_update
    BEFORE UPDATE ON backup_destruction_objects BEGIN
        SELECT RAISE(ABORT, 'backup destruction objects are append only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS backup_destruction_objects_no_replace
    BEFORE INSERT ON backup_destruction_objects
    WHEN EXISTS(
        SELECT 1 FROM backup_destruction_objects
         WHERE backup_id = NEW.backup_id
           AND object_sha256 = NEW.object_sha256
    )
    BEGIN
        SELECT RAISE(ABORT, 'backup destruction objects are append only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS backup_destruction_objects_no_delete
    BEFORE DELETE ON backup_destruction_objects BEGIN
        SELECT RAISE(ABORT, 'backup destruction objects are append only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_requests_no_delete
    BEFORE DELETE ON deletion_requests BEGIN
        SELECT RAISE(ABORT, 'deletion request audit cannot be deleted');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_requests_initial_state_guard
    BEFORE INSERT ON deletion_requests
    WHEN NEW.state != 'TOMBSTONED' OR NEW.queue_state != 'PENDING'
    BEGIN
        SELECT RAISE(ABORT, 'deletion request initial state invalid');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_requests_no_replace
    BEFORE INSERT ON deletion_requests
    WHEN EXISTS(
        SELECT 1 FROM deletion_requests
         WHERE request_id = NEW.request_id
            OR operation_id = NEW.operation_id
            OR plan_sha256 = NEW.plan_sha256
    )
    BEGIN
        SELECT RAISE(ABORT, 'deletion request audit cannot be replaced');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_requests_update_guard
    BEFORE UPDATE ON deletion_requests BEGIN
        SELECT CASE WHEN NOT (
            (NEW.state = 'TOMBSTONED' AND NEW.queue_state != 'SUCCEEDED')
            OR
            (NEW.state = 'PHYSICAL_CLEANUP_COMPLETE'
             AND NEW.queue_state = 'SUCCEEDED')
        ) THEN RAISE(ABORT, 'deletion request state queue mismatch') END;
        SELECT CASE WHEN
            NEW.state = 'PHYSICAL_CLEANUP_COMPLETE'
            AND NEW.queue_state = 'SUCCEEDED'
            AND (
                NOT EXISTS(
                    SELECT 1 FROM deletion_queue_intents AS intent
                     WHERE intent.request_id = NEW.request_id
                )
                OR EXISTS(
                    SELECT 1 FROM deletion_queue_intents AS intent
                     WHERE intent.request_id = NEW.request_id
                       AND intent.state != 'SUCCEEDED'
                )
                OR EXISTS(
                    SELECT 1 FROM backup_destruction_queue AS backup
                     WHERE backup.request_id = NEW.request_id
                       AND backup.state != 'succeeded'
                )
            )
        THEN RAISE(ABORT, 'deletion request child closure incomplete') END;
        SELECT CASE WHEN
            NEW.request_id != OLD.request_id
            OR NEW.operation_id != OLD.operation_id
            OR NEW.plan_sha256 != OLD.plan_sha256
            OR NEW.target_type != OLD.target_type
            OR NEW.target_id_hash != OLD.target_id_hash
            OR NEW.target_scope_hash != OLD.target_scope_hash
            OR NEW.base_deletion_version != OLD.base_deletion_version
            OR NEW.committed_deletion_version != OLD.committed_deletion_version
            OR NEW.tombstone_epoch != OLD.tombstone_epoch
            OR NEW.approval_request_id != OLD.approval_request_id
            OR NEW.approval_descriptor_sha256 != OLD.approval_descriptor_sha256
            OR NEW.approval_target_scope_hash != OLD.approval_target_scope_hash
            OR NEW.created_at != OLD.created_at
            OR NOT (
                NEW.state = OLD.state
                OR (OLD.state = 'TOMBSTONED'
                    AND NEW.state = 'PHYSICAL_CLEANUP_COMPLETE'
                    AND NEW.queue_state = 'SUCCEEDED')
            )
            OR NOT (
                NEW.queue_state = OLD.queue_state
                OR (OLD.queue_state = 'PENDING'
                    AND NEW.queue_state IN ('RUNNING', 'SUCCEEDED', 'FAILED'))
                OR (OLD.queue_state = 'RUNNING'
                    AND NEW.queue_state IN ('PARTIAL', 'SUCCEEDED', 'FAILED'))
                OR (OLD.queue_state = 'PARTIAL'
                    AND NEW.queue_state IN ('RUNNING', 'SUCCEEDED', 'FAILED'))
                OR (OLD.queue_state = 'FAILED'
                    AND NEW.queue_state IN ('PENDING', 'RUNNING'))
            )
        THEN RAISE(ABORT, 'deletion request transition invalid') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_revocations_no_delete
    BEFORE DELETE ON deletion_revocations BEGIN
        SELECT RAISE(ABORT, 'deletion revocation audit cannot be deleted');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_revocations_no_update
    BEFORE UPDATE ON deletion_revocations BEGIN
        SELECT RAISE(ABORT, 'deletion revocation audit is append only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS deletion_revocations_no_replace
    BEFORE INSERT ON deletion_revocations
    WHEN EXISTS(
        SELECT 1 FROM deletion_revocations
         WHERE request_id = NEW.request_id AND action_id = NEW.action_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'deletion revocation audit is append only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS rebuild_journal_no_update
    BEFORE UPDATE ON rebuild_job_journal BEGIN
        SELECT RAISE(ABORT, 'rebuild journal is append only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS rebuild_journal_no_replace
    BEFORE INSERT ON rebuild_job_journal
    WHEN EXISTS(
        SELECT 1 FROM rebuild_job_journal
         WHERE journal_id = NEW.journal_id
            OR (job_id = NEW.job_id AND sequence = NEW.sequence)
    )
    BEGIN
        SELECT RAISE(ABORT, 'rebuild journal is append only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS rebuild_journal_no_delete
    BEFORE DELETE ON rebuild_job_journal BEGIN
        SELECT RAISE(ABORT, 'rebuild journal is append only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS lifecycle_tombstones_no_update
    BEFORE UPDATE ON tombstones BEGIN
        SELECT RAISE(ABORT, 'tombstones are append only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS lifecycle_tombstones_no_delete
    BEFORE DELETE ON tombstones BEGIN
        SELECT RAISE(ABORT, 'tombstones are append only');
    END
    """,
)


def upgrade(connection: sqlite3.Connection) -> None:
    """Install hash-only global lifecycle control tables in the runner transaction."""

    for statement in _STATEMENTS:
        connection.execute(statement)
