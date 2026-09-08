"""Durable SQLite rebuild queue and append-only state journal."""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime
from typing import Literal, TypeAlias

from pydantic import field_validator, model_validator

from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.lifecycle.rebuild_registry import DatabaseScope
from consultation_kb.models.common import (
    NonEmptyStr,
    NonNegativeInt,
    ObjectId,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
)
from consultation_kb.storage.connection import transaction


RebuildJobState: TypeAlias = Literal[
    "queued",
    "running",
    "verifying",
    "activating",
    "succeeded",
    "failed",
    "cancelled",
]
_ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_JOB_COLUMNS = """
    job_id, source_intent_id, approval_operation_id, approval_request_id,
    plan_sha256, idempotency_key_sha256, scope_sha256, purpose,
    builder_dag_sha256, input_authority_versions_sha256, policy_sha256,
    model_descriptor_sha256, tombstone_epoch, state, attempt_count,
    output_manifest_set_sha256, equivalence_report_sha256, last_error_code,
    created_at, updated_at, started_at, finished_at, cancelled_at
"""


class RebuildJobError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RebuildJobNotFound(RebuildJobError):
    def __init__(self) -> None:
        super().__init__("REBUILD_JOB_NOT_FOUND")


class RebuildJobConflict(RebuildJobError):
    def __init__(self, code: str = "REBUILD_IDEMPOTENCY_CONFLICT") -> None:
        super().__init__(code)


class RebuildJobStateConflict(RebuildJobError):
    def __init__(self) -> None:
        super().__init__("REBUILD_JOB_STATE_CONFLICT")


class RebuildCancellationRejected(RebuildJobError):
    def __init__(self) -> None:
        super().__init__("REBUILD_CANCELLATION_AFTER_ACTIVATION")


class RebuildJobCreate(StrictModel):
    """Body-free immutable inputs persisted with a queued rebuild job."""

    database_scope: DatabaseScope
    source_intent_id: NonEmptyStr | None
    approval_operation_id: ObjectId | None
    approval_request_id: ObjectId | None
    plan_sha256: Sha256Hex
    scope_sha256: Sha256Hex
    purpose: SafePolicyKey
    builder_dag_sha256: Sha256Hex
    input_authority_versions_sha256: Sha256Hex
    policy_sha256: Sha256Hex | None
    model_descriptor_sha256: Sha256Hex | None
    tombstone_epoch: NonNegativeInt

    @model_validator(mode="after")
    def _validate_authority_route(self) -> "RebuildJobCreate":
        direct = (
            self.approval_operation_id is not None
            and self.approval_request_id is not None
        )
        partial = (self.approval_operation_id is None) != (
            self.approval_request_id is None
        )
        if partial or not direct:
            raise ValueError(
                "rebuild requires one complete plan approval binding"
            )
        return self


class RebuildJob(StrictModel):
    """Persisted rebuild state; it contains hashes and versions, never bodies."""

    database_scope: DatabaseScope
    job_id: ObjectId
    source_intent_id: NonEmptyStr | None
    approval_operation_id: ObjectId | None
    approval_request_id: ObjectId | None
    plan_sha256: Sha256Hex
    idempotency_key_sha256: Sha256Hex
    scope_sha256: Sha256Hex
    purpose: SafePolicyKey
    builder_dag_sha256: Sha256Hex
    input_authority_versions_sha256: Sha256Hex
    policy_sha256: Sha256Hex | None
    model_descriptor_sha256: Sha256Hex | None
    tombstone_epoch: NonNegativeInt
    state: RebuildJobState
    attempt_count: NonNegativeInt
    output_manifest_set_sha256: Sha256Hex | None
    equivalence_report_sha256: Sha256Hex | None
    last_error_code: NonEmptyStr | None
    created_at: UtcDateTime
    updated_at: UtcDateTime
    started_at: UtcDateTime | None
    finished_at: UtcDateTime | None
    cancelled_at: UtcDateTime | None

    @field_validator("last_error_code")
    @classmethod
    def _validate_error_code(cls, value: str | None) -> str | None:
        if value is not None and _ERROR_CODE.fullmatch(value) is None:
            raise ValueError("rebuild error code must be fixed uppercase snake case")
        return value

    @model_validator(mode="after")
    def _validate_state_shape(self) -> "RebuildJob":
        direct = (
            self.approval_operation_id is not None
            and self.approval_request_id is not None
        )
        partial = (self.approval_operation_id is None) != (
            self.approval_request_id is None
        )
        if partial or not direct:
            raise ValueError("persisted rebuild authority route is invalid")
        if self.updated_at < self.created_at:
            raise ValueError("rebuild update cannot predate creation")
        if self.state == "queued":
            if self.finished_at is not None or self.cancelled_at is not None:
                raise ValueError("queued rebuild must not be terminal")
        if self.state in {"running", "verifying", "activating", "succeeded"}:
            if self.started_at is None:
                raise ValueError("started rebuild state requires started_at")
        if self.state in {"activating", "succeeded"}:
            if (
                self.output_manifest_set_sha256 is None
                or self.equivalence_report_sha256 is None
            ):
                raise ValueError("activation requires verified output hashes")
        elif (
            self.output_manifest_set_sha256 is not None
            or self.equivalence_report_sha256 is not None
        ):
            raise ValueError("unverified rebuild state cannot expose output hashes")
        if self.state in {"succeeded", "failed", "cancelled"}:
            if self.finished_at is None:
                raise ValueError("terminal rebuild state requires finished_at")
        elif self.finished_at is not None:
            raise ValueError("non-terminal rebuild state cannot have finished_at")
        if (self.state == "cancelled") != (self.cancelled_at is not None):
            raise ValueError("cancelled_at must exactly match cancelled state")
        if self.state == "failed" and self.last_error_code is None:
            raise ValueError("failed rebuild requires an error code")
        return self


class RebuildJournalEntry(StrictModel):
    journal_id: ObjectId
    job_id: ObjectId
    sequence: PositiveInt
    state: RebuildJobState
    evidence_sha256: Sha256Hex
    occurred_at: UtcDateTime


def _utc_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime | None:
    if value is None:
        return None
    if type(value) is not str:
        raise RebuildJobError("REBUILD_JOB_TIMESTAMP_INVALID")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _parse_required_utc(value: object) -> datetime:
    parsed = _parse_utc(value)
    if parsed is None:
        raise RebuildJobError("REBUILD_JOB_TIMESTAMP_INVALID")
    return parsed


def _idempotency_sha256(
    *, database_scope: DatabaseScope, scope_sha256: str, key: str
) -> str:
    if type(key) is not str or not key.strip():
        raise RebuildJobError("REBUILD_IDEMPOTENCY_KEY_INVALID")
    return canonical_sha256(
        {
            "domain": "consultation_kb.rebuild_job.v1",
            "database_scope": database_scope,
            "scope_sha256": scope_sha256,
            "key": key,
        }
    )


class RebuildJobRepository:
    """Single-database durable rebuild queue.

    The caller binds one repository to either the global database or one
    already-scoped client worker database.  No database discovery occurs here.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        database_scope: DatabaseScope,
        clock: Clock | None = None,
        id_factory: IdFactory | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("REBUILD_SQLITE_CONNECTION_REQUIRED")
        if database_scope not in {"global", "client"}:
            raise ValueError("REBUILD_DATABASE_SCOPE_INVALID")
        self._connection = connection
        self._database_scope = database_scope
        self._clock = clock if clock is not None else SystemClock()
        self._ids = id_factory if id_factory is not None else IdFactory(self._clock)

    def enqueue(
        self,
        request: RebuildJobCreate,
        *,
        idempotency_key: str,
    ) -> RebuildJob:
        with transaction(self._connection):
            return self.enqueue_in_transaction(
                request,
                idempotency_key=idempotency_key,
            )

    def enqueue_in_transaction(
        self,
        request: RebuildJobCreate,
        *,
        idempotency_key: str,
    ) -> RebuildJob:
        """Enqueue under the caller's target approval transaction."""

        if not self._connection.in_transaction:
            raise RebuildJobError("REBUILD_TARGET_TRANSACTION_REQUIRED")
        exact = RebuildJobCreate.model_validate(request)
        if exact.database_scope != self._database_scope:
            raise RebuildJobConflict("REBUILD_DATABASE_SCOPE_MISMATCH")
        key_sha256 = _idempotency_sha256(
            database_scope=self._database_scope,
            scope_sha256=exact.scope_sha256,
            key=idempotency_key,
        )
        now = _utc_text(self._clock.now())
        existing = self._select_by_idempotency(key_sha256)
        if existing is not None:
            self._assert_same_request(existing, exact)
            return existing
        job_id = self._ids.object_id("rebuild_job")
        try:
            self._connection.execute(
                    f"""
                    INSERT INTO rebuild_jobs({_JOB_COLUMNS})
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                            'queued', 0, NULL, NULL, NULL, ?, ?, NULL, NULL, NULL)
                    """,
                    (
                        job_id,
                        exact.source_intent_id,
                        exact.approval_operation_id,
                        exact.approval_request_id,
                        exact.plan_sha256,
                        key_sha256,
                        exact.scope_sha256,
                        exact.purpose,
                        exact.builder_dag_sha256,
                        exact.input_authority_versions_sha256,
                        exact.policy_sha256,
                        exact.model_descriptor_sha256,
                        exact.tombstone_epoch,
                        now,
                        now,
                    ),
            )
        except sqlite3.IntegrityError as exc:
            raise RebuildJobConflict("REBUILD_JOB_INSERT_CONFLICT") from exc
        self._append_journal(job_id=job_id, state="queued")
        return self._require(job_id)

    def get(self, job_id: str) -> RebuildJob:
        return self._require(job_id)

    def journal(self, job_id: str) -> tuple[RebuildJournalEntry, ...]:
        self._require(job_id)
        rows = self._connection.execute(
            """
            SELECT journal_id, job_id, sequence, state,
                   evidence_sha256, occurred_at
              FROM rebuild_job_journal
             WHERE job_id = ? ORDER BY sequence
            """,
            (job_id,),
        ).fetchall()
        return tuple(
            RebuildJournalEntry.model_validate(
                {
                    "journal_id": row[0],
                    "job_id": row[1],
                    "sequence": row[2],
                    "state": row[3],
                    "evidence_sha256": row[4],
                    "occurred_at": _parse_required_utc(row[5]),
                }
            )
            for row in rows
        )

    def claim_next(self) -> RebuildJob | None:
        """Return an activation-resume first, otherwise atomically claim queued work."""

        with transaction(self._connection):
            activating = self._connection.execute(
                f"""
                SELECT {_JOB_COLUMNS} FROM rebuild_jobs
                 WHERE state = 'activating'
                 ORDER BY updated_at, job_id LIMIT 1
                """
            ).fetchone()
            if activating is not None:
                return self._row_to_job(activating)
            busy = self._connection.execute(
                """
                SELECT 1 FROM rebuild_jobs
                 WHERE state IN ('running', 'verifying')
                 LIMIT 1
                """
            ).fetchone()
            if busy is not None:
                return None
            row = self._connection.execute(
                """
                SELECT job_id FROM rebuild_jobs
                 WHERE state = 'queued'
                 ORDER BY updated_at, job_id LIMIT 1
                """
            ).fetchone()
            if row is None:
                return None
            job_id = str(row[0])
            now = _utc_text(self._clock.now())
            changed = self._connection.execute(
                """
                UPDATE rebuild_jobs
                   SET state = 'running', attempt_count = attempt_count + 1,
                       started_at = COALESCE(started_at, ?), updated_at = ?,
                       finished_at = NULL, last_error_code = NULL
                 WHERE job_id = ? AND state = 'queued'
                """,
                (now, now, job_id),
            ).rowcount
            if changed != 1:
                raise RebuildJobStateConflict
            self._claim_source_intent(job_id=job_id, claimed_at=now)
            self._append_journal(job_id=job_id, state="running")
            return self._require(job_id)

    def _claim_source_intent(self, *, job_id: str, claimed_at: str) -> None:
        source_kind = self._source_intent_kind(job_id)
        if source_kind is None:
            return
        if source_kind == "rollback":
            # Rollback intent authority is immutable. Claiming the durable job
            # is its only state transition; deletion queues remain untouched.
            return
        row = self._connection.execute(
            """
            SELECT j.source_intent_id, i.request_id, i.action_type,
                   i.authority_scope, i.state
              FROM rebuild_jobs AS j
              LEFT JOIN deletion_queue_intents AS i
                ON i.intent_id = j.source_intent_id
             WHERE j.job_id = ?
            """,
            (job_id,),
        ).fetchone()
        if row is None:
            raise RebuildJobStateConflict
        source_intent_id = None if row[0] is None else str(row[0])
        if source_intent_id is None:
            raise RebuildJobStateConflict
        if (
            row[1] is None
            or str(row[2]) != "rebuild"
            or str(row[3]) != self._database_scope
            or str(row[4]) not in {"PENDING", "CLAIMED", "FAILED"}
        ):
            raise RebuildJobStateConflict
        request_id = str(row[1])
        changed = self._connection.execute(
            """
            UPDATE deletion_queue_intents
               SET state = 'CLAIMED', attempt_count = attempt_count + 1,
                   last_error_code = NULL, claimed_at = ?, finished_at = NULL
             WHERE intent_id = ? AND action_type = 'rebuild'
               AND authority_scope = ?
               AND state IN ('PENDING', 'CLAIMED', 'FAILED')
            """,
            (claimed_at, source_intent_id, self._database_scope),
        ).rowcount
        if changed != 1:
            raise RebuildJobStateConflict
        self._connection.execute(
            """
            UPDATE deletion_requests SET queue_state = 'RUNNING'
             WHERE request_id = ? AND state = 'TOMBSTONED'
               AND queue_state IN ('PENDING', 'PARTIAL', 'FAILED')
            """,
            (request_id,),
        )
        request = self._connection.execute(
            "SELECT state, queue_state FROM deletion_requests WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if request != ("TOMBSTONED", "RUNNING"):
            raise RebuildJobStateConflict

    def mark_verifying(self, job_id: str) -> RebuildJob:
        return self._simple_transition(
            job_id=job_id,
            expected="running",
            target="verifying",
        )

    def mark_activating(
        self,
        job_id: str,
        *,
        output_manifest_set_sha256: Sha256Hex,
        equivalence_report_sha256: Sha256Hex,
    ) -> RebuildJob:
        with transaction(self._connection):
            current = self._require(job_id)
            if current.state == "activating":
                if (
                    current.output_manifest_set_sha256
                    != output_manifest_set_sha256
                    or current.equivalence_report_sha256
                    != equivalence_report_sha256
                ):
                    raise RebuildJobStateConflict
                return current
            if current.state != "verifying":
                raise RebuildJobStateConflict
            now = _utc_text(self._clock.now())
            changed = self._connection.execute(
                """
                UPDATE rebuild_jobs
                   SET state = 'activating', output_manifest_set_sha256 = ?,
                       equivalence_report_sha256 = ?, updated_at = ?
                 WHERE job_id = ? AND state = 'verifying'
                   AND output_manifest_set_sha256 IS NULL
                   AND equivalence_report_sha256 IS NULL
                """,
                (
                    output_manifest_set_sha256,
                    equivalence_report_sha256,
                    now,
                    job_id,
                ),
            ).rowcount
            if changed != 1:
                raise RebuildJobStateConflict
            self._append_journal(job_id=job_id, state="activating")
            return self._require(job_id)

    def mark_succeeded(self, job_id: str) -> RebuildJob:
        with transaction(self._connection):
            current = self._require(job_id)
            if current.state == "succeeded":
                return current
            if current.state != "activating":
                raise RebuildJobStateConflict
            if current.source_intent_id is not None:
                source_kind = self._source_intent_kind(job_id)
                if source_kind == "deletion":
                    source = self._connection.execute(
                        "SELECT state FROM deletion_queue_intents "
                        "WHERE intent_id = ? AND action_type = 'rebuild' "
                        "AND authority_scope = ?",
                        (current.source_intent_id, self._database_scope),
                    ).fetchone()
                    if source != ("SUCCEEDED",):
                        raise RebuildJobStateConflict
                elif source_kind != "rollback":
                    raise RebuildJobStateConflict
            now = _utc_text(self._clock.now())
            changed = self._connection.execute(
                """
                UPDATE rebuild_jobs
                   SET state = 'succeeded', updated_at = ?, finished_at = ?,
                       last_error_code = NULL
                 WHERE job_id = ? AND state = 'activating'
                """,
                (now, now, job_id),
            ).rowcount
            if changed != 1:
                raise RebuildJobStateConflict
            self._append_journal(job_id=job_id, state="succeeded")
            return self._require(job_id)

    def mark_failed(self, job_id: str, *, error_code: str) -> RebuildJob:
        if type(error_code) is not str or _ERROR_CODE.fullmatch(error_code) is None:
            raise RebuildJobError("REBUILD_ERROR_CODE_INVALID")
        with transaction(self._connection):
            current = self._require(job_id)
            if current.state == "failed":
                if current.last_error_code != error_code:
                    raise RebuildJobStateConflict
                return current
            if current.state not in {"queued", "running", "verifying"}:
                raise RebuildJobStateConflict
            now = _utc_text(self._clock.now())
            changed = self._connection.execute(
                """
                UPDATE rebuild_jobs
                   SET state = 'failed', last_error_code = ?, updated_at = ?,
                       finished_at = ?
                 WHERE job_id = ? AND state = ?
                """,
                (error_code, now, now, job_id, current.state),
            ).rowcount
            if changed != 1:
                raise RebuildJobStateConflict
            self._fail_source_intent(
                job_id=job_id,
                failed_at=now,
                error_code=error_code,
            )
            self._append_journal(job_id=job_id, state="failed")
            return self._require(job_id)

    def requeue_failed(self, job_id: str) -> RebuildJob:
        with transaction(self._connection):
            current = self._require(job_id)
            if current.state != "failed":
                raise RebuildJobStateConflict
            now = _utc_text(self._clock.now())
            changed = self._connection.execute(
                """
                UPDATE rebuild_jobs
                   SET state = 'queued', last_error_code = NULL,
                       finished_at = NULL, updated_at = ?
                 WHERE job_id = ? AND state = 'failed'
                """,
                (now, job_id),
            ).rowcount
            if changed != 1:
                raise RebuildJobStateConflict
            self._append_journal(job_id=job_id, state="queued")
            return self._require(job_id)

    def cancel_before_activation(self, job_id: str) -> RebuildJob:
        with transaction(self._connection):
            return self.cancel_before_activation_in_transaction(job_id)

    def cancel_before_activation_in_transaction(self, job_id: str) -> RebuildJob:
        """Cancel inside an existing P1 target transaction."""

        current = self._require(job_id)
        if current.state == "cancelled":
            return current
        if current.source_intent_id is not None:
            self._source_intent_kind(job_id)
            raise RebuildCancellationRejected
        if current.state in {"activating", "succeeded"}:
            raise RebuildCancellationRejected
        if current.state not in {"queued", "running", "verifying", "failed"}:
            raise RebuildJobStateConflict
        now = _utc_text(self._clock.now())
        changed = self._connection.execute(
            """
            UPDATE rebuild_jobs
               SET state = 'cancelled', updated_at = ?, finished_at = ?,
                   cancelled_at = ?, last_error_code = NULL
             WHERE job_id = ? AND state = ?
            """,
            (now, now, now, job_id, current.state),
        ).rowcount
        if changed != 1:
            raise RebuildJobStateConflict
        self._append_journal(job_id=job_id, state="cancelled")
        return self._require(job_id)

    def _fail_source_intent(
        self,
        *,
        job_id: str,
        failed_at: str,
        error_code: str,
    ) -> None:
        source_kind = self._source_intent_kind(job_id)
        if source_kind is None or source_kind == "rollback":
            return
        row = self._connection.execute(
            """
            SELECT j.source_intent_id, i.request_id, i.state
              FROM rebuild_jobs AS j
              LEFT JOIN deletion_queue_intents AS i
                ON i.intent_id = j.source_intent_id
             WHERE j.job_id = ?
            """,
            (job_id,),
        ).fetchone()
        if row is None:
            raise RebuildJobStateConflict
        source_intent_id = None if row[0] is None else str(row[0])
        if source_intent_id is None:
            raise RebuildJobStateConflict
        if row[1] is None or str(row[2]) not in {"PENDING", "CLAIMED", "FAILED"}:
            raise RebuildJobStateConflict
        request_id = str(row[1])
        state = str(row[2])
        if state != "CLAIMED":
            claimed = self._connection.execute(
                """
                UPDATE deletion_queue_intents
                   SET state = 'CLAIMED', attempt_count = attempt_count + 1,
                       last_error_code = NULL, claimed_at = ?, finished_at = NULL
                 WHERE intent_id = ? AND action_type = 'rebuild'
                   AND authority_scope = ? AND state IN ('PENDING', 'FAILED')
                """,
                (failed_at, source_intent_id, self._database_scope),
            ).rowcount
            if claimed != 1:
                raise RebuildJobStateConflict
        failed = self._connection.execute(
            """
            UPDATE deletion_queue_intents
               SET state = 'FAILED', last_error_code = ?, finished_at = NULL
             WHERE intent_id = ? AND action_type = 'rebuild'
               AND authority_scope = ? AND state = 'CLAIMED'
            """,
            (error_code, source_intent_id, self._database_scope),
        ).rowcount
        if failed != 1:
            raise RebuildJobStateConflict
        self._connection.execute(
            """
            UPDATE deletion_requests SET queue_state = 'RUNNING'
             WHERE request_id = ? AND state = 'TOMBSTONED'
               AND queue_state IN ('PENDING', 'PARTIAL')
            """,
            (request_id,),
        )
        self._connection.execute(
            """
            UPDATE deletion_requests SET queue_state = 'FAILED'
             WHERE request_id = ? AND state = 'TOMBSTONED'
               AND queue_state = 'RUNNING'
            """,
            (request_id,),
        )
        request = self._connection.execute(
            "SELECT state, queue_state FROM deletion_requests WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if request != ("TOMBSTONED", "FAILED"):
            raise RebuildJobStateConflict

    def recover_interrupted(self) -> tuple[str, ...]:
        """Requeue pre-activation work; activation itself is resumed in place."""

        with transaction(self._connection):
            rows = self._connection.execute(
                """
                SELECT job_id, state FROM rebuild_jobs
                 WHERE state IN ('running', 'verifying')
                 ORDER BY updated_at, job_id
                """
            ).fetchall()
            recovered: list[str] = []
            now = _utc_text(self._clock.now())
            for job_id_value, state_value in rows:
                job_id = str(job_id_value)
                state = str(state_value)
                self._source_intent_kind(job_id)
                changed = self._connection.execute(
                    """
                    UPDATE rebuild_jobs
                       SET state = 'queued', updated_at = ?, finished_at = NULL,
                           last_error_code = 'REBUILD_PROCESS_INTERRUPTED'
                     WHERE job_id = ? AND state = ?
                    """,
                    (now, job_id, state),
                ).rowcount
                if changed != 1:
                    raise RebuildJobStateConflict
                self._append_journal(job_id=job_id, state="queued")
                recovered.append(job_id)
            return tuple(recovered)

    def _source_intent_kind(
        self,
        job_id: str,
    ) -> Literal["deletion", "rollback"] | None:
        """Classify one closed source authority without cross-queue fallback."""

        row = self._connection.execute(
            "SELECT j.source_intent_id, r.intent_kind, d.action_type, "
            "d.authority_scope FROM rebuild_jobs AS j "
            "LEFT JOIN rebuild_source_intents AS r "
            "ON r.intent_id = j.source_intent_id "
            "LEFT JOIN deletion_queue_intents AS d "
            "ON d.intent_id = j.source_intent_id WHERE j.job_id = ?",
            (job_id,),
        ).fetchone()
        if row is None:
            raise RebuildJobStateConflict
        if row[0] is None:
            if any(value is not None for value in row[1:]):
                raise RebuildJobStateConflict
            return None
        rollback = row[1] == "rollback"
        deletion = (
            row[2] == "rebuild" and row[3] == self._database_scope
        )
        if rollback == deletion:
            raise RebuildJobStateConflict
        return "rollback" if rollback else "deletion"

    def _simple_transition(
        self,
        *,
        job_id: str,
        expected: RebuildJobState,
        target: RebuildJobState,
    ) -> RebuildJob:
        with transaction(self._connection):
            current = self._require(job_id)
            if current.state == target:
                return current
            if current.state != expected:
                raise RebuildJobStateConflict
            now = _utc_text(self._clock.now())
            changed = self._connection.execute(
                "UPDATE rebuild_jobs SET state = ?, updated_at = ? "
                "WHERE job_id = ? AND state = ?",
                (target, now, job_id, expected),
            ).rowcount
            if changed != 1:
                raise RebuildJobStateConflict
            self._append_journal(job_id=job_id, state=target)
            return self._require(job_id)

    def _append_journal(self, *, job_id: str, state: RebuildJobState) -> None:
        row = self._connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) + 1 "
            "FROM rebuild_job_journal WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        if row is None or type(row[0]) is not int:
            raise RebuildJobError("REBUILD_JOURNAL_SEQUENCE_INVALID")
        sequence = row[0]
        occurred_at = _utc_text(self._clock.now())
        evidence_sha256 = canonical_sha256(
            {
                "domain": "consultation_kb.rebuild_job_journal.v1",
                "job_id": job_id,
                "sequence": sequence,
                "state": state,
                "occurred_at": occurred_at,
            }
        )
        self._connection.execute(
            """
            INSERT INTO rebuild_job_journal(
                journal_id, job_id, sequence, state,
                evidence_sha256, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                self._ids.object_id("rebuild_journal"),
                job_id,
                sequence,
                state,
                evidence_sha256,
                occurred_at,
            ),
        )

    def _select_by_idempotency(self, value: str) -> RebuildJob | None:
        row = self._connection.execute(
            f"SELECT {_JOB_COLUMNS} FROM rebuild_jobs "
            "WHERE idempotency_key_sha256 = ?",
            (value,),
        ).fetchone()
        return None if row is None else self._row_to_job(row)

    def _require(self, job_id: str) -> RebuildJob:
        row = self._connection.execute(
            f"SELECT {_JOB_COLUMNS} FROM rebuild_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        if row is None:
            raise RebuildJobNotFound
        return self._row_to_job(row)

    def _row_to_job(self, row: tuple[object, ...]) -> RebuildJob:
        return RebuildJob.model_validate(
            {
                "database_scope": self._database_scope,
                "job_id": row[0],
                "source_intent_id": row[1],
                "approval_operation_id": row[2],
                "approval_request_id": row[3],
                "plan_sha256": row[4],
                "idempotency_key_sha256": row[5],
                "scope_sha256": row[6],
                "purpose": row[7],
                "builder_dag_sha256": row[8],
                "input_authority_versions_sha256": row[9],
                "policy_sha256": row[10],
                "model_descriptor_sha256": row[11],
                "tombstone_epoch": row[12],
                "state": row[13],
                "attempt_count": row[14],
                "output_manifest_set_sha256": row[15],
                "equivalence_report_sha256": row[16],
                "last_error_code": row[17],
                "created_at": _parse_required_utc(row[18]),
                "updated_at": _parse_required_utc(row[19]),
                "started_at": _parse_utc(row[20]),
                "finished_at": _parse_utc(row[21]),
                "cancelled_at": _parse_utc(row[22]),
            }
        )

    @staticmethod
    def _assert_same_request(
        existing: RebuildJob, requested: RebuildJobCreate
    ) -> None:
        if (
            existing.database_scope != requested.database_scope
            or existing.source_intent_id != requested.source_intent_id
            or existing.approval_operation_id != requested.approval_operation_id
            or existing.approval_request_id != requested.approval_request_id
            or existing.plan_sha256 != requested.plan_sha256
            or existing.scope_sha256 != requested.scope_sha256
            or existing.purpose != requested.purpose
            or existing.builder_dag_sha256 != requested.builder_dag_sha256
            or existing.input_authority_versions_sha256
            != requested.input_authority_versions_sha256
            or existing.policy_sha256 != requested.policy_sha256
            or existing.model_descriptor_sha256
            != requested.model_descriptor_sha256
            or existing.tombstone_epoch != requested.tombstone_epoch
        ):
            raise RebuildJobConflict


__all__ = [
    "RebuildCancellationRejected",
    "RebuildJob",
    "RebuildJobConflict",
    "RebuildJobCreate",
    "RebuildJobError",
    "RebuildJobNotFound",
    "RebuildJobRepository",
    "RebuildJobState",
    "RebuildJobStateConflict",
    "RebuildJournalEntry",
]
