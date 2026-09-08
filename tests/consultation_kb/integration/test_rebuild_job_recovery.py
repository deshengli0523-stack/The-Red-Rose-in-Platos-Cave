from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from importlib import import_module
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.lifecycle.rebuild_jobs import (
    RebuildCancellationRejected,
    RebuildJobCreate,
    RebuildJobRepository,
)
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner, load_migrations


NOW = datetime(2026, 7, 19, 9, 0, tzinfo=timezone.utc)
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64
HASH_PLAN = "e" * 64


def _approval_ids() -> tuple[str, str]:
    factory = _id_factory()
    return (
        factory.object_id("approval_operation"),
        factory.object_id("approval_request"),
    )


def _connection(tmp_path: Path) -> sqlite3.Connection:
    connection = connect_database(tmp_path / "global.sqlite3", mode="writer")
    MigrationRunner(connection, load_migrations("global")).apply()
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'rebuild_jobs'"
    ).fetchone()
    if exists is None:
        import_module(
            "consultation_kb.storage.migrations.global.v0006_lifecycle"
        ).upgrade(connection)
    operation_id, request_id = _approval_ids()
    connection.execute(
        """
        INSERT INTO approval_executions(
            operation_id, request_id, descriptor_sha256, draft_sha256,
            descriptor_base_version, target_scope_hash, nonce_sha256,
            state, applied_commit_version, applied_at
        ) VALUES (?, ?, ?, ?, 7, ?, ?, 'CLAIMED', NULL, NULL)
        """,
        (operation_id, request_id, HASH_A, HASH_PLAN, HASH_A, HASH_B),
    )
    connection.execute(
        """
        UPDATE approval_executions
           SET state = 'APPLIED', applied_commit_version = 8,
               applied_at = '2026-07-19T09:00:00.000000Z'
         WHERE operation_id = ? AND state = 'CLAIMED'
        """,
        (operation_id,),
    )
    return connection


def _id_factory() -> IdFactory:
    counter = iter(range(1, 1000))
    return IdFactory(
        clock=FixedClock(NOW),
        random_source=lambda: next(counter),
    )


def _repository(
    connection: sqlite3.Connection,
    *,
    id_factory: IdFactory | None = None,
) -> RebuildJobRepository:
    return RebuildJobRepository(
        connection,
        database_scope="global",
        clock=FixedClock(NOW),
        id_factory=id_factory or _id_factory(),
    )


def _request() -> RebuildJobCreate:
    operation_id, request_id = _approval_ids()
    return RebuildJobCreate(
        database_scope="global",
        source_intent_id=None,
        approval_operation_id=operation_id,
        approval_request_id=request_id,
        plan_sha256=HASH_PLAN,
        scope_sha256=HASH_A,
        purpose="all",
        builder_dag_sha256=HASH_B,
        input_authority_versions_sha256=HASH_C,
        policy_sha256=HASH_D,
        model_descriptor_sha256=HASH_A,
        tombstone_epoch=7,
    )


def test_enqueue_is_fast_durable_and_idempotent_without_storing_the_raw_key(
    tmp_path: Path,
) -> None:
    connection = _connection(tmp_path)
    try:
        repository = _repository(connection)

        first = repository.enqueue(_request(), idempotency_key="operator-secret-key")
        second = repository.enqueue(_request(), idempotency_key="operator-secret-key")

        assert first == second
        assert first.state == "queued"
        assert first.attempt_count == 0
        assert connection.execute("SELECT count(*) FROM rebuild_jobs").fetchone() == (
            1,
        )
        assert tuple(entry.state for entry in repository.journal(first.job_id)) == (
            "queued",
        )
        raw_rows = "\n".join(
            "|".join("" if value is None else str(value) for value in row)
            for table in ("rebuild_jobs", "rebuild_job_journal")
            for row in connection.execute(f"SELECT * FROM {table}").fetchall()
        )
        assert "operator-secret-key" not in raw_rows
    finally:
        connection.close()


@pytest.mark.parametrize("interrupted_state", ("running", "verifying"))
def test_process_restart_requeues_interrupted_work_and_preserves_attempt_history(
    tmp_path: Path,
    interrupted_state: str,
) -> None:
    connection = _connection(tmp_path)
    try:
        ids = _id_factory()
        first_process = _repository(connection, id_factory=ids)
        queued = first_process.enqueue(_request(), idempotency_key="restartable")
        running = first_process.claim_next()
        assert running is not None
        assert running.job_id == queued.job_id
        assert running.state == "running"
        assert running.attempt_count == 1
        if interrupted_state == "verifying":
            first_process.mark_verifying(running.job_id)

        restarted_process = _repository(connection, id_factory=ids)
        recovered = restarted_process.recover_interrupted()
        resumed = restarted_process.claim_next()

        assert recovered == (queued.job_id,)
        assert resumed is not None
        assert resumed.job_id == queued.job_id
        assert resumed.state == "running"
        assert resumed.attempt_count == 2
        assert tuple(
            entry.state for entry in restarted_process.journal(queued.job_id)
        ) == (
            "queued",
            "running",
            *(("verifying",) if interrupted_state == "verifying" else ()),
            "queued",
            "running",
        )
    finally:
        connection.close()


def test_verified_output_is_durable_before_activation_and_cannot_be_cancelled(
    tmp_path: Path,
) -> None:
    connection = _connection(tmp_path)
    try:
        repository = _repository(connection)
        queued = repository.enqueue(_request(), idempotency_key="activate-once")
        running = repository.claim_next()
        assert running is not None
        repository.mark_verifying(running.job_id)

        activating = repository.mark_activating(
            running.job_id,
            output_manifest_set_sha256=HASH_B,
            equivalence_report_sha256=HASH_C,
        )

        assert activating.state == "activating"
        assert activating.output_manifest_set_sha256 == HASH_B
        assert activating.equivalence_report_sha256 == HASH_C
        assert repository.recover_interrupted() == ()
        with pytest.raises(
            RebuildCancellationRejected,
            match="REBUILD_CANCELLATION_AFTER_ACTIVATION",
        ):
            repository.cancel_before_activation(queued.job_id)

        succeeded = repository.mark_succeeded(queued.job_id)
        assert succeeded.state == "succeeded"
        assert succeeded.finished_at == NOW
        assert tuple(entry.state for entry in repository.journal(queued.job_id)) == (
            "queued",
            "running",
            "verifying",
            "activating",
            "succeeded",
        )
    finally:
        connection.close()


def test_cancellation_is_durable_only_before_activation(tmp_path: Path) -> None:
    connection = _connection(tmp_path)
    try:
        repository = _repository(connection)
        queued = repository.enqueue(_request(), idempotency_key="cancel-me")

        cancelled = repository.cancel_before_activation(queued.job_id)

        assert cancelled.state == "cancelled"
        assert cancelled.cancelled_at == NOW
        assert cancelled.finished_at == NOW
        assert repository.claim_next() is None
    finally:
        connection.close()


def test_two_connections_never_claim_overlapping_rebuilds_for_one_database(
    tmp_path: Path,
) -> None:
    first_connection = _connection(tmp_path)
    second_connection = connect_database(
        tmp_path / "global.sqlite3",
        mode="writer",
    )
    try:
        first = _repository(first_connection)
        second = _repository(second_connection)
        extra_ids = IdFactory(
            clock=FixedClock(NOW),
            random_source=iter(range(5000, 6000)).__next__,
        )
        second_operation_id = extra_ids.object_id("approval_operation")
        second_request_id = extra_ids.object_id("approval_request")
        first_connection.execute(
            """
            INSERT INTO approval_executions(
                operation_id, request_id, descriptor_sha256, draft_sha256,
                descriptor_base_version, target_scope_hash, nonce_sha256,
                state, applied_commit_version, applied_at
            ) VALUES (?, ?, ?, ?, 7, ?, ?, 'CLAIMED', NULL, NULL)
            """,
            (
                second_operation_id,
                second_request_id,
                HASH_A,
                HASH_PLAN,
                HASH_A,
                HASH_C,
            ),
        )
        first_connection.execute(
            "UPDATE approval_executions SET state = 'APPLIED', "
            "applied_commit_version = 9, "
            "applied_at = '2026-07-19T09:00:00.000000Z' "
            "WHERE operation_id = ?",
            (second_operation_id,),
        )
        second_job_request = _request().model_copy(
            update={
                "approval_operation_id": second_operation_id,
                "approval_request_id": second_request_id,
            }
        )
        queued = (
            first.enqueue(_request(), idempotency_key="serialized-first"),
            first.enqueue(
                second_job_request,
                idempotency_key="serialized-second",
            ),
        )

        running = first.claim_next()
        assert running is not None
        assert second.claim_next() is None

        first.mark_failed(running.job_id, error_code="REBUILD_TEST_FAILURE")
        next_running = second.claim_next()
        assert next_running is not None
        assert next_running.job_id == next(
            value.job_id for value in queued if value.job_id != running.job_id
        )
    finally:
        second_connection.close()
        first_connection.close()
