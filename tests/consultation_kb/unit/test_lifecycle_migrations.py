from __future__ import annotations

import hashlib
import sqlite3
from importlib import import_module, resources
from pathlib import Path
from types import ModuleType
from typing import Literal

import pytest

from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner, load_migrations


client_v6 = import_module(
    "consultation_kb.storage.migrations.client.v0006_lifecycle"
)
global_v6 = import_module(
    "consultation_kb.storage.migrations.global.v0006_lifecycle"
)


Scope = Literal["global", "client"]
LIFECYCLE_TABLES = {
    "deletion_authority_state",
    "deletion_base_versions",
    "deletion_requests",
    "deletion_revocations",
    "deletion_queue_intents",
    "deletion_intent_authority_proofs",
    "backup_destruction_queue",
    "backup_destruction_objects",
    "publication_closure_attestations",
    "rebuild_jobs",
    "rebuild_stage_bindings",
    "rebuild_job_journal",
}
CLIENT_LIFECYCLE_TABLES = {"case_publication_proofs"}
HASH = "a" * 64
OTHER_HASH = "b" * 64
THIRD_HASH = "c" * 64
FOURTH_HASH = "d" * 64
NOW = "2026-07-19T08:00:00.000000Z"
LATER = "2026-07-19T08:01:00.000000Z"
FINAL = "2026-07-19T08:02:00.000000Z"


def _module(scope: Scope) -> ModuleType:
    return global_v6 if scope == "global" else client_v6


def _apply_v6(connection: sqlite3.Connection, scope: Scope) -> MigrationRunner:
    migrations = tuple(
        migration for migration in load_migrations(scope) if migration.version <= 6
    )
    if scope == "global":
        MigrationRunner(connection, migrations[:-1]).apply()
        connection.execute(
            "UPDATE knowledge_catalog_state SET tombstone_epoch = 7 "
            "WHERE singleton = 1"
        )
    runner = MigrationRunner(connection, migrations)
    runner.apply()
    runner.apply()
    runner.check()
    return runner


@pytest.mark.parametrize("scope", ("global", "client"))
def test_v0006_is_in_the_closed_migration_set_and_hashes_owned_backup_sql(
    scope: Scope,
) -> None:
    migration = next(
        migration for migration in load_migrations(scope) if migration.version == 6
    )
    source = (
        resources.files(f"consultation_kb.storage.migrations.{scope}")
        .joinpath("v0006_lifecycle.py")
        .read_bytes()
    )

    assert migration.version == 6
    assert migration.name == _module(scope).NAME
    assert migration.sha256 == hashlib.sha256(source).hexdigest()
    assert b"CREATE TABLE IF NOT EXISTS backup_destruction_queue" in source
    assert b"CREATE TABLE IF NOT EXISTS backup_destruction_objects" in source
    assert b"consultation_kb.lifecycle.backup_queue" not in source


@pytest.mark.parametrize("scope", ("global", "client"))
def test_v0006_upgrade_is_runner_idempotent_and_creates_lifecycle_tables(
    tmp_path: Path, scope: Scope
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        _apply_v6(connection, scope)

        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        expected_tables = LIFECYCLE_TABLES | (
            CLIENT_LIFECYCLE_TABLES if scope == "client" else set()
        )
        assert expected_tables <= tables
        expected_epoch = 7 if scope == "global" else 0
        assert connection.execute(
            "SELECT deletion_version, tombstone_epoch "
            "FROM deletion_authority_state WHERE singleton = 1"
        ).fetchone() == (0, expected_epoch)
        assert connection.execute(
            "SELECT version, name FROM schema_migrations ORDER BY version DESC LIMIT 1"
        ).fetchone() == (6, _module(scope).NAME)
    finally:
        connection.close()


def test_global_lifecycle_epoch_stays_atomic_with_query_authority(
    tmp_path: Path,
) -> None:
    connection = connect_database(tmp_path / "global.sqlite3", mode="writer")
    try:
        _apply_v6(connection, "global")

        connection.execute(
            "UPDATE deletion_authority_state SET tombstone_epoch = 8 "
            "WHERE singleton = 1 AND tombstone_epoch = 7"
        )
        assert connection.execute(
            "SELECT tombstone_epoch FROM knowledge_catalog_state WHERE singleton = 1"
        ).fetchone() == (8,)

        connection.execute(
            "UPDATE knowledge_catalog_state SET tombstone_epoch = 9 "
            "WHERE singleton = 1"
        )
        assert connection.execute(
            "SELECT tombstone_epoch FROM deletion_authority_state WHERE singleton = 1"
        ).fetchone() == (9,)
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ("global", "client"))
def test_deletion_authority_is_monotonic_single_step_and_cannot_be_deleted(
    tmp_path: Path, scope: Scope
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        _apply_v6(connection, scope)
        before = connection.execute(
            "SELECT deletion_version, tombstone_epoch "
            "FROM deletion_authority_state WHERE singleton = 1"
        ).fetchone()
        assert before is not None
        connection.execute(
            "UPDATE deletion_authority_state "
            "SET deletion_version = ?, tombstone_epoch = ? "
            "WHERE singleton = 1 AND deletion_version = ? AND tombstone_epoch = ?",
            (before[0] + 1, before[1] + 1, before[0], before[1]),
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE deletion_authority_state "
                "SET deletion_version = deletion_version + 2, "
                "tombstone_epoch = tombstone_epoch + 2 WHERE singleton = 1"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE deletion_authority_state "
                "SET deletion_version = deletion_version - 1, "
                "tombstone_epoch = tombstone_epoch - 1 WHERE singleton = 1"
            )
        if scope == "client":
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE deletion_authority_state "
                    "SET tombstone_epoch = tombstone_epoch + 1 WHERE singleton = 1"
                )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM deletion_authority_state WHERE singleton = 1"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT OR REPLACE INTO deletion_authority_state("
                "singleton, deletion_version, tombstone_epoch) VALUES (1, 99, 99)"
            )
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ("global", "client"))
def test_deletion_base_versions_are_single_step_cas_records(
    tmp_path: Path, scope: Scope
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        _apply_v6(connection, scope)
        connection.execute(
            "INSERT INTO deletion_base_versions(authority_key, scope_sha256, version) "
            "VALUES ('catalog', ?, 5)",
            (HASH,),
        )
        connection.execute(
            "UPDATE deletion_base_versions SET version = 6 "
            "WHERE authority_key = 'catalog' AND scope_sha256 = ? AND version = 5",
            (HASH,),
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE deletion_base_versions SET version = 8 "
                "WHERE authority_key = 'catalog' AND scope_sha256 = ?",
                (HASH,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE deletion_base_versions SET version = 5 "
                "WHERE authority_key = 'catalog' AND scope_sha256 = ?",
                (HASH,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE deletion_base_versions SET authority_key = 'other' "
                "WHERE authority_key = 'catalog' AND scope_sha256 = ?",
                (HASH,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT OR REPLACE INTO deletion_base_versions("
                "authority_key, scope_sha256, version) VALUES ('catalog', ?, 99)",
                (HASH,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM deletion_base_versions "
                "WHERE authority_key = 'catalog' AND scope_sha256 = ?",
                (HASH,),
            )
    finally:
        connection.close()


def _insert_claimed_approval(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        INSERT INTO approval_executions(
            operation_id, request_id, descriptor_sha256, draft_sha256,
            descriptor_base_version, target_scope_hash, nonce_sha256,
            state, applied_commit_version, applied_at
        ) VALUES ('operation', 'approval-request', ?, ?, 0, ?, ?,
                  'CLAIMED', NULL, NULL)
        """,
        (HASH, OTHER_HASH, HASH, OTHER_HASH),
    )


def _insert_rebuild_approval(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        INSERT INTO approval_executions(
            operation_id, request_id, descriptor_sha256, draft_sha256,
            descriptor_base_version, target_scope_hash, nonce_sha256,
            state, applied_commit_version, applied_at
        ) VALUES ('rebuild-operation', 'rebuild-approval-request', ?, ?, 0, ?, ?,
                  'CLAIMED', NULL, NULL)
        """,
        (HASH, THIRD_HASH, OTHER_HASH, FOURTH_HASH),
    )


def _insert_deletion_request(connection: sqlite3.Connection) -> None:
    _insert_claimed_approval(connection)
    connection.execute(
        """
        INSERT INTO deletion_requests(
            request_id, operation_id, plan_sha256, target_type,
            target_id_hash, target_scope_hash, base_deletion_version,
            committed_deletion_version, tombstone_epoch,
            approval_request_id, approval_descriptor_sha256,
            approval_target_scope_hash, state, queue_state, created_at
        ) VALUES ('deletion-request', 'operation', ?, 'case', ?, ?,
                  0, 1, 1, 'approval-request', ?, ?,
                  'TOMBSTONED', 'PENDING', ?)
        """,
        (HASH, OTHER_HASH, HASH, HASH, HASH, NOW),
    )


def _insert_publication_operation(
    connection: sqlite3.Connection,
    *,
    operation_id: str,
    approval_request_id: str,
    purpose: str = "lifecycle",
) -> None:
    connection.execute(
        """
        INSERT INTO publication_operations(
            operation_id, purpose, authority_base_version,
            approval_request_id, descriptor_sha256, state,
            required_manifests_json, required_manifest_count,
            verified_manifest_count, expected_current_epoch,
            runtime_epoch, created_at, activated_at
        ) VALUES (?, ?, 1, ?, ?, 'PREPARED', '[]', 0, 0,
                  NULL, NULL, ?, NULL)
        """,
        (operation_id, purpose, approval_request_id, HASH, NOW),
    )


def _insert_queue_intent(
    connection: sqlite3.Connection,
    *,
    intent_id: str = "intent",
    action_id: str = "action",
    action_type: str = "physical_delete",
    scope: Scope = "client",
) -> None:
    connection.execute(
        """
        INSERT INTO deletion_queue_intents(
            intent_id, request_id, action_id, action_type, object_type,
            target_id_hash, target_version, target_content_sha256,
            authority_scope, state, attempt_count, created_at
        ) VALUES (?, 'deletion-request', ?, ?, 'artifact_manifest',
                  ?, 4, ?, ?, 'PENDING', 0, ?)
        """,
        (intent_id, action_id, action_type, HASH, OTHER_HASH, scope, NOW),
    )


def _mark_queue_intent_succeeded(
    connection: sqlite3.Connection,
    *,
    intent_id: str = "intent",
) -> None:
    connection.execute(
        "UPDATE deletion_queue_intents SET state = 'CLAIMED', "
        "attempt_count = attempt_count + 1, claimed_at = ?, "
        "last_error_code = NULL, finished_at = NULL WHERE intent_id = ?",
        (NOW, intent_id),
    )
    connection.execute(
        "UPDATE deletion_queue_intents SET state = 'SUCCEEDED', "
        "last_error_code = NULL, finished_at = ? WHERE intent_id = ?",
        (LATER, intent_id),
    )


def _insert_pending_backup(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        INSERT INTO backup_destruction_queue(
            backup_id, request_id, location_class, object_set_sha256,
            due_at, state, attempt_count, created_at, updated_at
        ) VALUES ('backup', 'deletion-request', 'local_snapshot', ?, ?,
                  'pending', 0, ?, ?)
        """,
        (THIRD_HASH, FINAL, NOW, NOW),
    )


def _insert_rebuild_job(
    connection: sqlite3.Connection,
    *,
    job_id: str = "job",
    source_intent_id: str | None = None,
) -> None:
    _insert_rebuild_approval(connection)
    connection.execute(
        """
        INSERT INTO rebuild_jobs(
            job_id, source_intent_id, approval_operation_id,
            approval_request_id, plan_sha256, idempotency_key_sha256,
            scope_sha256, purpose, builder_dag_sha256,
            input_authority_versions_sha256, tombstone_epoch,
            state, attempt_count, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'client_graph', ?, ?, 0,
                  'queued', 0, ?, ?)
        """,
        (
            job_id,
            source_intent_id,
            "rebuild-operation",
            "rebuild-approval-request",
            THIRD_HASH,
            HASH,
            OTHER_HASH,
            HASH,
            OTHER_HASH,
            NOW,
            NOW,
        ),
    )


@pytest.mark.parametrize("scope", ("global", "client"))
def test_deletion_and_rebuild_rows_are_hash_only_durable_and_idempotent(
    tmp_path: Path, scope: Scope
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        _apply_v6(connection, scope)
        _insert_claimed_approval(connection)
        connection.execute(
            """
            INSERT INTO deletion_requests(
                request_id, operation_id, plan_sha256, target_type,
                target_id_hash, target_scope_hash, base_deletion_version,
                committed_deletion_version, tombstone_epoch,
                approval_request_id, approval_descriptor_sha256,
                approval_target_scope_hash, state, queue_state, created_at
            ) VALUES ('deletion-request', 'operation', ?, 'case', ?, ?,
                      0, 1, 1, 'approval-request', ?, ?,
                      'TOMBSTONED', 'PENDING', ?)
            """,
            (HASH, OTHER_HASH, HASH, HASH, HASH, NOW),
        )
        connection.execute(
            """
            INSERT INTO deletion_queue_intents(
                intent_id, request_id, action_id, action_type, object_type,
                target_id_hash, target_version, target_content_sha256,
                authority_scope, state, attempt_count, created_at
            ) VALUES ('intent', 'deletion-request', 'action', 'rebuild',
                      'artifact_manifest', ?, 4, ?, ?, 'PENDING', 0, ?)
            """,
            (HASH, OTHER_HASH, scope, NOW),
        )
        _insert_rebuild_approval(connection)
        connection.execute(
            """
            INSERT INTO rebuild_jobs(
                job_id, source_intent_id, approval_operation_id,
                approval_request_id, plan_sha256, idempotency_key_sha256,
                scope_sha256, purpose, builder_dag_sha256,
                input_authority_versions_sha256, tombstone_epoch,
                state, attempt_count, created_at, updated_at
            ) VALUES ('job-1', 'intent', 'rebuild-operation',
                      'rebuild-approval-request', ?, ?, ?, 'global_graph', ?, ?, 1,
                      'queued', 0, ?, ?)
            """,
            (THIRD_HASH, HASH, OTHER_HASH, HASH, OTHER_HASH, NOW, NOW),
        )
        connection.execute(
            """
            INSERT INTO rebuild_job_journal(
                journal_id, job_id, sequence, state, evidence_sha256,
                occurred_at
            ) VALUES ('journal-1', 'job-1', 1, 'queued', ?, ?)
            """,
            (HASH, NOW),
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO rebuild_jobs(
                    job_id, idempotency_key_sha256, scope_sha256, purpose,
                    builder_dag_sha256, input_authority_versions_sha256,
                    tombstone_epoch, state, attempt_count, created_at, updated_at
                ) VALUES ('job-2', ?, ?, 'global_graph', ?, ?, 1,
                          'queued', 0, ?, ?)
                """,
                (HASH, OTHER_HASH, HASH, OTHER_HASH, NOW, NOW),
            )
        assert connection.execute(
            "SELECT state FROM deletion_queue_intents WHERE intent_id = 'intent'"
        ).fetchone() == ("PENDING",)
        assert connection.execute(
            "SELECT state FROM rebuild_jobs WHERE job_id = 'job-1'"
        ).fetchone() == ("queued",)
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ("global", "client"))
def test_deletion_queue_enforces_claim_retry_terminal_and_identity_rules(
    tmp_path: Path, scope: Scope
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        _apply_v6(connection, scope)
        _insert_deletion_request(connection)
        _insert_queue_intent(connection, scope=scope)

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO deletion_queue_intents(
                    intent_id, request_id, action_id, action_type, object_type,
                    target_id_hash, target_version, target_content_sha256,
                    authority_scope, state, attempt_count,
                    claimed_at, finished_at, created_at
                ) VALUES ('evil', 'deletion-request', 'evil-action',
                          'physical_delete', 'artifact_manifest', ?, 4, ?, ?,
                          'SUCCEEDED', 1, ?, ?, ?)
                """,
                (HASH, OTHER_HASH, scope, NOW, LATER, NOW),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE deletion_queue_intents SET attempt_count = 9 "
                "WHERE intent_id = 'intent'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT OR REPLACE INTO deletion_queue_intents "
                "SELECT * FROM deletion_queue_intents WHERE intent_id = 'intent'"
            )

        connection.execute(
            "UPDATE deletion_queue_intents "
            "SET state = 'CLAIMED', attempt_count = attempt_count + 1, "
            "claimed_at = ?, last_error_code = NULL, finished_at = NULL "
            "WHERE intent_id = 'intent'",
            (NOW,),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE deletion_queue_intents SET target_version = 99 "
                "WHERE intent_id = 'intent'"
            )
        connection.execute(
            "UPDATE deletion_queue_intents "
            "SET state = 'FAILED', last_error_code = 'WINDOWS_FILE_BUSY' "
            "WHERE intent_id = 'intent'"
        )
        connection.execute(
            "UPDATE deletion_queue_intents "
            "SET state = 'CLAIMED', attempt_count = attempt_count + 1, "
            "claimed_at = ?, last_error_code = NULL, finished_at = NULL "
            "WHERE intent_id = 'intent'",
            (LATER,),
        )
        connection.execute(
            "UPDATE deletion_queue_intents "
            "SET state = 'SUCCEEDED', last_error_code = NULL, finished_at = ? "
            "WHERE intent_id = 'intent'",
            (FINAL,),
        )
        assert connection.execute(
            "SELECT state, attempt_count, claimed_at, finished_at "
            "FROM deletion_queue_intents WHERE intent_id = 'intent'"
        ).fetchone() == ("SUCCEEDED", 2, LATER, FINAL)

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE deletion_queue_intents SET state = 'FAILED', "
                "last_error_code = 'TAMPERED', finished_at = NULL "
                "WHERE intent_id = 'intent'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM deletion_queue_intents WHERE intent_id = 'intent'"
            )

        _insert_queue_intent(
            connection,
            intent_id="cancel-intent",
            action_id="cancel-action",
            scope=scope,
        )
        connection.execute(
            "UPDATE deletion_queue_intents "
            "SET state = 'CANCELLED', finished_at = ? "
            "WHERE intent_id = 'cancel-intent'",
            (LATER,),
        )
        assert connection.execute(
            "SELECT state, attempt_count FROM deletion_queue_intents "
            "WHERE intent_id = 'cancel-intent'"
        ).fetchone() == ("CANCELLED", 0)
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ("global", "client"))
@pytest.mark.parametrize("intent_state", ("PENDING", "CANCELLED"))
def test_deletion_request_completion_requires_every_intent_to_succeed(
    tmp_path: Path,
    scope: Scope,
    intent_state: str,
) -> None:
    connection = connect_database(
        tmp_path / f"{scope}-{intent_state}.sqlite3",
        mode="writer",
    )
    try:
        _apply_v6(connection, scope)
        _insert_deletion_request(connection)
        _insert_queue_intent(connection, scope=scope)
        if intent_state == "CANCELLED":
            connection.execute(
                "UPDATE deletion_queue_intents SET state = 'CANCELLED', "
                "finished_at = ? WHERE intent_id = 'intent'",
                (LATER,),
            )

        with pytest.raises(
            sqlite3.IntegrityError,
            match="deletion request child closure incomplete",
        ):
            connection.execute(
                "UPDATE deletion_requests SET state = "
                "'PHYSICAL_CLEANUP_COMPLETE', queue_state = 'SUCCEEDED' "
                "WHERE request_id = 'deletion-request'"
            )

        assert connection.execute(
            "SELECT state, queue_state FROM deletion_requests "
            "WHERE request_id = 'deletion-request'"
        ).fetchone() == ("TOMBSTONED", "PENDING")
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ("global", "client"))
def test_deletion_request_completion_requires_at_least_one_intent(
    tmp_path: Path,
    scope: Scope,
) -> None:
    connection = connect_database(
        tmp_path / f"{scope}-empty-closure.sqlite3",
        mode="writer",
    )
    try:
        _apply_v6(connection, scope)
        _insert_deletion_request(connection)

        with pytest.raises(
            sqlite3.IntegrityError,
            match="deletion request child closure incomplete",
        ):
            connection.execute(
                "UPDATE deletion_requests SET state = "
                "'PHYSICAL_CLEANUP_COMPLETE', queue_state = 'SUCCEEDED' "
                "WHERE request_id = 'deletion-request'"
            )
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ("global", "client"))
def test_deletion_request_completion_requires_every_backup_to_succeed(
    tmp_path: Path,
    scope: Scope,
) -> None:
    connection = connect_database(
        tmp_path / f"{scope}-backup.sqlite3",
        mode="writer",
    )
    try:
        _apply_v6(connection, scope)
        _insert_deletion_request(connection)
        _insert_queue_intent(connection, scope=scope)
        _mark_queue_intent_succeeded(connection)
        _insert_pending_backup(connection)

        with pytest.raises(
            sqlite3.IntegrityError,
            match="deletion request child closure incomplete",
        ):
            connection.execute(
                "UPDATE deletion_requests SET state = "
                "'PHYSICAL_CLEANUP_COMPLETE', queue_state = 'SUCCEEDED' "
                "WHERE request_id = 'deletion-request'"
            )

        connection.execute(
            "UPDATE backup_destruction_queue SET state = 'succeeded', "
            "attempt_count = attempt_count + 1, last_error_code = NULL, "
            "finished_at = ?, operator_proof_sha256 = ?, updated_at = ? "
            "WHERE backup_id = 'backup'",
            (FINAL, FOURTH_HASH, FINAL),
        )
        connection.execute(
            "UPDATE deletion_requests SET state = "
            "'PHYSICAL_CLEANUP_COMPLETE', queue_state = 'SUCCEEDED' "
            "WHERE request_id = 'deletion-request'"
        )
        assert connection.execute(
            "SELECT state, queue_state FROM deletion_requests "
            "WHERE request_id = 'deletion-request'"
        ).fetchone() == ("PHYSICAL_CLEANUP_COMPLETE", "SUCCEEDED")
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ("global", "client"))
def test_deletion_request_state_and_queue_state_are_locked(
    tmp_path: Path,
    scope: Scope,
) -> None:
    connection = connect_database(
        tmp_path / f"{scope}-request-pair.sqlite3",
        mode="writer",
    )
    try:
        _apply_v6(connection, scope)
        _insert_claimed_approval(connection)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="deletion request initial state invalid",
        ):
            connection.execute(
                """
                INSERT INTO deletion_requests(
                    request_id, operation_id, plan_sha256, target_type,
                    target_id_hash, target_scope_hash, base_deletion_version,
                    committed_deletion_version, tombstone_epoch,
                    approval_request_id, approval_descriptor_sha256,
                    approval_target_scope_hash, state, queue_state, created_at
                ) VALUES ('deletion-request', 'operation', ?, 'case', ?, ?,
                          0, 1, 1, 'approval-request', ?, ?,
                          'PHYSICAL_CLEANUP_COMPLETE', 'SUCCEEDED', ?)
                """,
                (HASH, OTHER_HASH, HASH, HASH, HASH, NOW),
            )
        connection.execute(
            """
            INSERT INTO deletion_requests(
                request_id, operation_id, plan_sha256, target_type,
                target_id_hash, target_scope_hash, base_deletion_version,
                committed_deletion_version, tombstone_epoch,
                approval_request_id, approval_descriptor_sha256,
                approval_target_scope_hash, state, queue_state, created_at
            ) VALUES ('deletion-request', 'operation', ?, 'case', ?, ?,
                      0, 1, 1, 'approval-request', ?, ?,
                      'TOMBSTONED', 'PENDING', ?)
            """,
            (HASH, OTHER_HASH, HASH, HASH, HASH, NOW),
        )

        with pytest.raises(
            sqlite3.IntegrityError,
            match="deletion request state queue mismatch",
        ):
            connection.execute(
                "UPDATE deletion_requests SET queue_state = 'SUCCEEDED' "
                "WHERE request_id = 'deletion-request'"
            )
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ("global", "client"))
def test_lifecycle_schema_has_no_body_or_location_columns(
    tmp_path: Path, scope: Scope
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        _apply_v6(connection, scope)

        forbidden = {
            "body",
            "content",
            "payload",
            "path",
            "client_id",
            "session_id",
            "transcript",
            "raw_text",
        }
        tables = LIFECYCLE_TABLES | (
            CLIENT_LIFECYCLE_TABLES if scope == "client" else set()
        )
        for table in sorted(tables):
            columns = {
                str(row[1])
                for row in connection.execute(f"PRAGMA table_info({table})")
            }
            assert forbidden.isdisjoint(columns)
            assert all(
                not column.endswith(("_body", "_content", "_path", "_payload"))
                for column in columns
            )
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ("global", "client"))
def test_rebuild_job_enforces_attempt_recovery_cancel_and_immutable_inputs(
    tmp_path: Path, scope: Scope
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        _apply_v6(connection, scope)
        _insert_rebuild_job(connection)

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO rebuild_jobs(
                    job_id, idempotency_key_sha256, scope_sha256, purpose,
                    builder_dag_sha256, input_authority_versions_sha256,
                    tombstone_epoch, state, attempt_count,
                    created_at, updated_at, started_at
                ) VALUES ('evil', ?, ?, 'client_graph', ?, ?, 0,
                          'running', 1, ?, ?, ?)
                """,
                (THIRD_HASH, FOURTH_HASH, THIRD_HASH, FOURTH_HASH, NOW, NOW, NOW),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE rebuild_jobs SET state = 'running', attempt_count = 9, "
                "started_at = ?, updated_at = ? WHERE job_id = 'job'",
                (LATER, LATER),
            )

        connection.execute(
            "UPDATE rebuild_jobs SET state = 'running', "
            "attempt_count = attempt_count + 1, started_at = ?, updated_at = ? "
            "WHERE job_id = 'job'",
            (LATER, LATER),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE rebuild_jobs SET purpose = 'tampered' WHERE job_id = 'job'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE rebuild_jobs SET plan_sha256 = ? WHERE job_id = 'job'",
                (FOURTH_HASH,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE rebuild_jobs SET approval_request_id = 'tampered' "
                "WHERE job_id = 'job'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE rebuild_jobs SET attempt_count = attempt_count + 1 "
                "WHERE job_id = 'job'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT OR REPLACE INTO rebuild_jobs "
                "SELECT * FROM rebuild_jobs WHERE job_id = 'job'"
            )

        connection.execute(
            "UPDATE rebuild_jobs SET state = 'queued', "
            "last_error_code = 'REBUILD_PROCESS_INTERRUPTED', updated_at = ? "
            "WHERE job_id = 'job'",
            (LATER,),
        )
        connection.execute(
            "UPDATE rebuild_jobs SET state = 'running', "
            "attempt_count = attempt_count + 1, "
            "started_at = COALESCE(started_at, ?), "
            "last_error_code = NULL, updated_at = ? WHERE job_id = 'job'",
            (FINAL, FINAL),
        )
        connection.execute(
            "UPDATE rebuild_jobs SET state = 'failed', "
            "last_error_code = 'REBUILD_WORKER_FAILED', "
            "finished_at = ?, updated_at = ? WHERE job_id = 'job'",
            (FINAL, FINAL),
        )
        connection.execute(
            "UPDATE rebuild_jobs SET state = 'queued', last_error_code = NULL, "
            "finished_at = NULL, updated_at = ? WHERE job_id = 'job'",
            (FINAL,),
        )
        connection.execute(
            "UPDATE rebuild_jobs SET state = 'cancelled', "
            "finished_at = ?, cancelled_at = ?, updated_at = ? "
            "WHERE job_id = 'job'",
            (FINAL, FINAL, FINAL),
        )
        assert connection.execute(
            "SELECT state, attempt_count, started_at, finished_at, cancelled_at "
            "FROM rebuild_jobs WHERE job_id = 'job'"
        ).fetchone() == ("cancelled", 2, LATER, FINAL, FINAL)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM rebuild_jobs WHERE job_id = 'job'")
    finally:
        connection.close()


def test_rebuild_cannot_be_cancelled_after_activation_begins(
    tmp_path: Path,
) -> None:
    connection = connect_database(tmp_path / "client.sqlite3", mode="writer")
    try:
        _apply_v6(connection, "client")
        _insert_rebuild_job(connection)
        connection.execute(
            "UPDATE rebuild_jobs SET state = 'running', attempt_count = 1, "
            "started_at = ?, updated_at = ? "
            "WHERE job_id = 'job'",
            (LATER, LATER),
        )
        connection.execute(
            "UPDATE rebuild_jobs SET state = 'verifying', updated_at = ? "
            "WHERE job_id = 'job'",
            (LATER,),
        )
        connection.execute(
            "UPDATE rebuild_jobs SET state = 'activating', "
            "output_manifest_set_sha256 = ?, equivalence_report_sha256 = ?, "
            "updated_at = ? "
            "WHERE job_id = 'job'",
            (HASH, OTHER_HASH, LATER),
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE rebuild_jobs SET state = 'cancelled', finished_at = ?, "
                "cancelled_at = ?, updated_at = ? "
                "WHERE job_id = 'job'",
                (FINAL, FINAL, FINAL),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE rebuild_jobs SET output_manifest_set_sha256 = ? "
                "WHERE job_id = 'job'",
                (THIRD_HASH,),
            )
        connection.execute(
            "UPDATE rebuild_jobs SET state = 'succeeded', finished_at = ?, "
            "updated_at = ? WHERE job_id = 'job'",
            (FINAL, FINAL),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE rebuild_jobs SET last_error_code = 'TAMPERED' "
                "WHERE job_id = 'job'"
            )
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ("global", "client"))
def test_rebuild_journal_is_append_only(tmp_path: Path, scope: Scope) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        _apply_v6(connection, scope)
        _insert_rebuild_job(connection)
        connection.execute(
            """
            INSERT INTO rebuild_job_journal(
                journal_id, job_id, sequence, state, evidence_sha256, occurred_at
            ) VALUES ('journal', 'job', 1, 'queued', ?, ?)
            """,
            (HASH, NOW),
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE rebuild_job_journal SET evidence_sha256 = ? "
                "WHERE journal_id = 'journal'",
                (OTHER_HASH,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM rebuild_job_journal WHERE journal_id = 'journal'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT OR REPLACE INTO rebuild_job_journal "
                "SELECT * FROM rebuild_job_journal WHERE journal_id = 'journal'"
            )
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ("global", "client"))
def test_publication_closure_attestations_are_append_only(
    tmp_path: Path, scope: Scope
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        _apply_v6(connection, scope)
        _insert_publication_operation(
            connection,
            operation_id="publication",
            approval_request_id="approval",
        )
        connection.execute(
            "INSERT INTO publication_closure_attestations("
            "operation_id, approval_draft_sha256, closure_sha256, created_at) "
            "VALUES ('publication', ?, ?, ?)",
            (HASH, OTHER_HASH, NOW),
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE publication_closure_attestations "
                "SET closure_sha256 = ? WHERE operation_id = 'publication'",
                (THIRD_HASH,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM publication_closure_attestations "
                "WHERE operation_id = 'publication'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT OR REPLACE INTO publication_closure_attestations "
                "SELECT * FROM publication_closure_attestations "
                "WHERE operation_id = 'publication'"
            )
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ("global", "client"))
def test_deletion_intent_authority_proofs_are_append_only(
    tmp_path: Path, scope: Scope
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        _apply_v6(connection, scope)
        _insert_deletion_request(connection)
        _insert_queue_intent(connection, scope=scope)
        connection.execute(
            """
            INSERT INTO deletion_intent_authority_proofs(
                intent_id, request_id, action_id, deletion_plan_sha256,
                root_object_type, root_target_id_hash, root_lineage_hash,
                action_descriptor_sha256, created_at
            ) VALUES ('intent', 'deletion-request', 'action', ?, 'case',
                      ?, ?, ?, ?)
            """,
            (HASH, OTHER_HASH, THIRD_HASH, FOURTH_HASH, NOW),
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE deletion_intent_authority_proofs "
                "SET root_lineage_hash = ? WHERE intent_id = 'intent'",
                (HASH,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM deletion_intent_authority_proofs "
                "WHERE intent_id = 'intent'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT OR REPLACE INTO deletion_intent_authority_proofs "
                "SELECT * FROM deletion_intent_authority_proofs "
                "WHERE intent_id = 'intent'"
            )
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ("global", "client"))
def test_rebuild_stage_bindings_are_append_only_and_attempt_unique(
    tmp_path: Path, scope: Scope
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        _apply_v6(connection, scope)
        _insert_rebuild_job(connection)
        _insert_publication_operation(
            connection,
            operation_id="stage-operation",
            approval_request_id="rebuild-approval-request",
            purpose="rebuild",
        )
        connection.execute(
            """
            INSERT INTO rebuild_stage_bindings(
                operation_id, job_id, attempt_count, approval_request_id,
                plan_sha256, scope_sha256, tombstone_epoch, created_at
            ) VALUES ('stage-operation', 'job', 1, 'rebuild-approval-request',
                      ?, ?, 0, ?)
            """,
            (THIRD_HASH, OTHER_HASH, NOW),
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE rebuild_stage_bindings SET plan_sha256 = ? "
                "WHERE operation_id = 'stage-operation'",
                (FOURTH_HASH,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM rebuild_stage_bindings "
                "WHERE operation_id = 'stage-operation'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT OR REPLACE INTO rebuild_stage_bindings "
                "SELECT * FROM rebuild_stage_bindings "
                "WHERE operation_id = 'stage-operation'"
            )
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ("global", "client"))
def test_backup_destruction_schema_is_durable_and_transition_guarded(
    tmp_path: Path, scope: Scope
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        _apply_v6(connection, scope)
        _insert_deletion_request(connection)
        connection.execute(
            """
            INSERT INTO backup_destruction_queue(
                backup_id, request_id, location_class, object_set_sha256,
                due_at, state, attempt_count, created_at, updated_at
            ) VALUES ('backup', 'deletion-request', 'offline_media', ?, ?,
                      'pending', 0, ?, ?)
            """,
            (HASH, LATER, NOW, NOW),
        )
        connection.execute(
            "INSERT INTO backup_destruction_objects(backup_id, object_sha256) "
            "VALUES ('backup', ?)",
            (OTHER_HASH,),
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO backup_destruction_queue(
                    backup_id, request_id, location_class, object_set_sha256,
                    due_at, state, attempt_count, finished_at,
                    operator_proof_sha256, created_at, updated_at
                ) VALUES ('evil-backup', 'deletion-request', 'offline_media', ?, ?,
                          'succeeded', 1, ?, ?, ?, ?)
                """,
                (THIRD_HASH, LATER, FINAL, FOURTH_HASH, NOW, FINAL),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE backup_destruction_queue SET due_at = ? "
                "WHERE backup_id = 'backup'",
                (FINAL,),
            )

        connection.execute(
            "UPDATE backup_destruction_queue SET state = 'failed', "
            "attempt_count = attempt_count + 1, "
            "last_error_code = 'OFFLINE_MEDIA_UNAVAILABLE', updated_at = ? "
            "WHERE backup_id = 'backup'",
            (LATER,),
        )
        connection.execute(
            "UPDATE backup_destruction_queue SET state = 'succeeded', "
            "attempt_count = attempt_count + 1, last_error_code = NULL, "
            "finished_at = ?, operator_proof_sha256 = ?, updated_at = ? "
            "WHERE backup_id = 'backup'",
            (FINAL, FOURTH_HASH, FINAL),
        )
        assert connection.execute(
            "SELECT state, attempt_count, finished_at, operator_proof_sha256 "
            "FROM backup_destruction_queue WHERE backup_id = 'backup'"
        ).fetchone() == ("succeeded", 2, FINAL, FOURTH_HASH)

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE backup_destruction_objects SET object_sha256 = ? "
                "WHERE backup_id = 'backup'",
                (THIRD_HASH,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM backup_destruction_objects WHERE backup_id = 'backup'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT OR REPLACE INTO backup_destruction_objects "
                "SELECT * FROM backup_destruction_objects WHERE backup_id = 'backup'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM backup_destruction_queue WHERE backup_id = 'backup'"
            )
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ("global", "client"))
def test_deletion_revocations_are_append_only(tmp_path: Path, scope: Scope) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        _apply_v6(connection, scope)
        _insert_deletion_request(connection)
        connection.execute(
            """
            INSERT INTO deletion_revocations(
                request_id, action_id, effect, object_type,
                target_id_hash, object_version, created_at
            ) VALUES ('deletion-request', 'revoke', 'revoke_case',
                      'case', ?, 3, ?)
            """,
            (HASH, NOW),
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE deletion_revocations SET object_version = 4 "
                "WHERE action_id = 'revoke'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM deletion_revocations WHERE action_id = 'revoke'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT OR REPLACE INTO deletion_revocations "
                "SELECT * FROM deletion_revocations WHERE action_id = 'revoke'"
            )
    finally:
        connection.close()


@pytest.mark.parametrize("scope", ("global", "client"))
def test_deletion_authority_and_tombstones_are_append_only(
    tmp_path: Path, scope: Scope
) -> None:
    connection = connect_database(tmp_path / f"{scope}.sqlite3", mode="writer")
    try:
        _apply_v6(connection, scope)
        _insert_claimed_approval(connection)
        connection.execute(
            """
            INSERT INTO deletion_requests(
                request_id, operation_id, plan_sha256, target_type,
                target_id_hash, target_scope_hash, base_deletion_version,
                committed_deletion_version, tombstone_epoch,
                approval_request_id, approval_descriptor_sha256,
                approval_target_scope_hash, state, queue_state, created_at
            ) VALUES ('deletion-request', 'operation', ?, 'claim', ?, ?,
                      0, 1, 1, 'approval-request', ?, ?,
                      'TOMBSTONED', 'PENDING', ?)
            """,
            (HASH, OTHER_HASH, HASH, HASH, HASH, NOW),
        )
        connection.execute(
            """
            INSERT INTO tombstones(
                tombstone_id, target_type, target_id_hash,
                source_lineage_hash, reason_code, created_at
            ) VALUES ('tombstone', 'claim', ?, ?, 'approved_deletion', ?)
            """,
            (HASH, OTHER_HASH, NOW),
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE deletion_requests SET target_id_hash = ? "
                "WHERE request_id = 'deletion-request'",
                (HASH,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE tombstones SET reason_code = 'changed' "
                "WHERE tombstone_id = 'tombstone'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM tombstones WHERE tombstone_id = 'tombstone'"
            )
    finally:
        connection.close()
