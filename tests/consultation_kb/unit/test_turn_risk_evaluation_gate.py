from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import VersionRef
from consultation_kb.models.risk import InternalRiskObservation
from consultation_kb.risk.repository import (
    InternalRiskObservationRecord,
    InternalRiskObservationRepository,
    RiskLifecycleConflict,
    RiskEvaluationAuthorityBinding,
    RiskObservationSource,
    RiskRepositoryError,
    RiskTriggerSpan,
    TurnRiskEvaluationRepository,
    canonical_risk_observation_set_sha256,
)
from consultation_kb.risk.text_normalization import normalized_sensitive_fingerprint
from consultation_kb.session.repository import SessionRepository
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore


NOW = datetime(2026, 7, 19, 15, 0, tzinfo=timezone.utc)
SESSION_ID = "018f0000-0000-7000-8000-000000000901"
TURN_ID = "018f0000-0000-7000-8000-000000000902"
MESSAGE = "A durable risk evaluation must close before generation."
AUTHORITY = RiskEvaluationAuthorityBinding(
    global_runtime_epoch=7,
    risk_policy_manifest_ref=VersionRef(
        object_id="risk_policy_manifest_018f0000-0000-7000-8000-000000000900",
        version=3,
        content_sha256="9" * 64,
    ),
    model_mode="deterministic_only",
)
STALE_AUTHORITY = AUTHORITY.model_copy(
    update={
        "risk_policy_manifest_ref": AUTHORITY.risk_policy_manifest_ref.model_copy(
            update={"content_sha256": "8" * 64}
        )
    }
)
MODEL_AUTHORITY = RiskEvaluationAuthorityBinding(
    global_runtime_epoch=7,
    risk_policy_manifest_ref=AUTHORITY.risk_policy_manifest_ref,
    model_mode="approved_model",
    risk_model_manifest_ref=VersionRef(
        object_id="risk_model_manifest_018f0000-0000-7000-8000-000000000903",
        version=1,
        content_sha256="7" * 64,
    ),
    approved_model_ref=VersionRef(
        object_id="risk_model_018f0000-0000-7000-8000-000000000904",
        version=1,
        content_sha256="6" * 64,
    ),
)
UPDATED_MODEL_AUTHORITY = MODEL_AUTHORITY.model_copy(
    update={
        "approved_model_ref": MODEL_AUTHORITY.approved_model_ref.model_copy(
            update={"version": 2, "content_sha256": "5" * 64}
        )
        if MODEL_AUTHORITY.approved_model_ref is not None
        else None,
    }
)


def _repositories(
    tmp_path: Path,
) -> tuple[sqlite3.Connection, SessionRepository, TurnRiskEvaluationRepository]:
    connection = connect_database(tmp_path / "client.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "client").apply()
    clock = FixedClock(NOW)
    values = iter(range(1, 100))
    cas_root = tmp_path / "scope" / "cas"
    cas_root.parent.mkdir(parents=True)
    sessions = SessionRepository(
        connection,
        content_store=ContentStore(cas_root),
        clock=clock,
        id_factory=IdFactory(clock, lambda: next(values)),
    )
    sessions.create_session(
        session_id=SESSION_ID,
        client_id="client_" + "aaaaaaaaaaaa",
        client_scope_hash="a" * 64,
        snapshot_version=1,
        snapshot_canonical_sha256="b" * 64,
        snapshot_bytes=b'{"profile_version":1}\n',
    )
    sessions.append_client_turn(SESSION_ID, TURN_ID, MESSAGE)
    return (
        connection,
        sessions,
        TurnRiskEvaluationRepository(
            connection,
            database_scope="client",
            clock=clock,
        ),
    )


def _record(
    sessions: SessionRepository,
    *,
    suffix: int,
    category: str,
    detected_at: datetime = NOW,
) -> InternalRiskObservationRecord:
    turn = sessions.get_turn(SESSION_ID, TURN_ID)
    rule_ref = VersionRef(
        object_id=f"risk_rule_018f0000-0000-7000-8000-{suffix:012x}",
        version=1,
        content_sha256=f"{suffix % 16:x}" * 64,
    )
    trigger = MESSAGE[:7]
    normalized_length, normalized_span_sha256 = normalized_sensitive_fingerprint(
        trigger
    )
    return InternalRiskObservationRecord(
        session_id=SESSION_ID,
        observation=InternalRiskObservation(
            observation_id=(
                "risk_observation_018f0000-0000-7000-8000-"
                f"{suffix:012x}"
            ),
            category=category,
            level="general",
            trigger_turn_ids=(TURN_ID,),
            rule_ref=rule_ref,
            detected_at=detected_at,
            suggested_questions=("SYNTH-QUESTION-GENERAL-VERIFY",),
        ),
        trigger_spans=(
            RiskTriggerSpan(
                turn_id=TURN_ID,
                content_ref=VersionRef(
                    object_id=turn.client_message.object_id,
                    version=1,
                    content_sha256=turn.client_message.content_sha256,
                ),
                start_offset=0,
                end_offset=len(trigger),
                span_sha256=hashlib.sha256(trigger.encode("utf-8")).hexdigest(),
                normalized_length=normalized_length,
                normalized_span_sha256=normalized_span_sha256,
            ),
        ),
        sources=(
            RiskObservationSource(
                source_kind="deterministic_rule",
                source_ref=rule_ref,
            ),
        ),
        confidence=1.0,
    )


def test_pending_and_missing_block_until_empty_result_is_durably_completed(
    tmp_path: Path,
) -> None:
    connection, sessions, evaluations = _repositories(tmp_path)
    message_sha256 = sessions.get_turn(
        SESSION_ID, TURN_ID
    ).client_message.content_sha256
    try:
        with pytest.raises(RiskRepositoryError, match="TURN_RISK_EVALUATION_MISSING"):
            evaluations.require_completed(
                SESSION_ID,
                TURN_ID,
                client_message_sha256=message_sha256,
                authority=AUTHORITY,
            )

        first = evaluations.ensure_pending(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=AUTHORITY,
        )
        assert evaluations.ensure_pending(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=AUTHORITY,
        ) == first
        with pytest.raises(RiskLifecycleConflict, match="PENDING"):
            evaluations.require_completed(
                SESSION_ID,
                TURN_ID,
                client_message_sha256=message_sha256,
                authority=AUTHORITY,
            )

        completed = evaluations.persist_completed(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=AUTHORITY,
            observations=(),
        )
        assert completed.status == "completed"
        assert completed.observation_count == 0
        assert completed.observation_set_sha256 == (
            canonical_risk_observation_set_sha256(())
        )
        assert evaluations.persist_completed(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=AUTHORITY,
            observations=(),
        ) == completed
        assert evaluations.require_completed(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=AUTHORITY,
        ) == completed

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE turn_risk_evaluations SET observation_count = 1 "
                "WHERE session_id = ? AND turn_id = ?",
                (SESSION_ID, TURN_ID),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM turn_risk_evaluations "
                "WHERE session_id = ? AND turn_id = ?",
                (SESSION_ID, TURN_ID),
            )

        with pytest.raises(RiskLifecycleConflict, match="EVALUATION_CONFLICT"):
            evaluations.persist_completed(
                SESSION_ID,
                TURN_ID,
                client_message_sha256=message_sha256,
                authority=AUTHORITY,
                observations=(_record(sessions, suffix=0x911, category="new_result"),),
            )

        columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(turn_risk_evaluations)"
            )
        }
        assert not ({"body", "text", "content", "transcript"} & columns)
    finally:
        connection.close()


def test_failed_batch_rolls_back_observations_and_pending_can_be_retried(
    tmp_path: Path,
) -> None:
    connection, sessions, evaluations = _repositories(tmp_path)
    message_sha256 = sessions.get_turn(
        SESSION_ID, TURN_ID
    ).client_message.content_sha256
    try:
        evaluations.ensure_pending(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=AUTHORITY,
        )
        conflicts = InternalRiskObservationRepository(
            connection,
            database_scope="client",
            clock=FixedClock(NOW),
        )
        conflicts.add(_record(sessions, suffix=0x922, category="saved_identity"))
        proposed = (
            _record(sessions, suffix=0x921, category="would_be_rolled_back"),
            _record(sessions, suffix=0x922, category="conflicting_identity"),
        )

        with pytest.raises(RiskLifecycleConflict, match="ID_CONFLICT"):
            evaluations.persist_completed(
                SESSION_ID,
                TURN_ID,
                client_message_sha256=message_sha256,
                authority=AUTHORITY,
                observations=proposed,
            )
        assert evaluations.get(SESSION_ID, TURN_ID).status == "pending"
        assert connection.execute(
            "SELECT count(*) FROM internal_risk_observations "
            "WHERE observation_id = ?",
            (proposed[0].observation.observation_id,),
        ).fetchone() == (0,)

        recovered = TurnRiskEvaluationRepository(
            connection,
            database_scope="client",
            clock=FixedClock(NOW + timedelta(seconds=1)),
        ).persist_completed(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=AUTHORITY,
            observations=(),
        )
        assert recovered.status == "completed"
    finally:
        connection.close()


def test_pending_observation_is_not_visible_until_membership_completes(
    tmp_path: Path,
) -> None:
    connection, sessions, evaluations = _repositories(tmp_path)
    message_sha256 = sessions.get_turn(
        SESSION_ID, TURN_ID
    ).client_message.content_sha256
    observation = _record(sessions, suffix=0x929, category="pending_result")
    lifecycle = InternalRiskObservationRepository(
        connection,
        database_scope="client",
        clock=FixedClock(NOW),
    )
    try:
        evaluations.ensure_pending(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=AUTHORITY,
        )
        lifecycle.add(observation)

        assert lifecycle.list_visible(SESSION_ID) == ()

        evaluations.persist_completed(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=AUTHORITY,
            observations=(observation,),
        )
        assert lifecycle.list_visible(SESSION_ID) == (observation,)
    finally:
        connection.close()


def test_retry_identity_hash_is_stable_across_detection_clock_only(
    tmp_path: Path,
) -> None:
    # The first persisted detection time remains authoritative; a crash retry
    # with the same deterministic finding must still bind to the same result.
    connection, sessions, _evaluations = _repositories(tmp_path)
    try:
        first = _record(sessions, suffix=0x931, category="same_result")
        retry = _record(
            sessions,
            suffix=0x931,
            category="same_result",
            detected_at=NOW + timedelta(seconds=1),
        )
        assert canonical_risk_observation_set_sha256((first,)) == (
            canonical_risk_observation_set_sha256((retry,))
        )
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("completed_authority", "live_authority"),
    (
        (AUTHORITY, STALE_AUTHORITY),
        (
            AUTHORITY,
            AUTHORITY.model_copy(update={"global_runtime_epoch": 8}),
        ),
        (MODEL_AUTHORITY, UPDATED_MODEL_AUTHORITY),
    ),
)
def test_completed_evaluation_never_satisfies_a_different_live_authority(
    tmp_path: Path,
    completed_authority: RiskEvaluationAuthorityBinding,
    live_authority: RiskEvaluationAuthorityBinding,
) -> None:
    connection, sessions, evaluations = _repositories(tmp_path)
    message_sha256 = sessions.get_turn(
        SESSION_ID, TURN_ID
    ).client_message.content_sha256
    try:
        evaluations.ensure_pending(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=completed_authority,
        )
        evaluations.persist_completed(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=completed_authority,
            observations=(),
        )
        with pytest.raises(RiskLifecycleConflict, match="AUTHORITY_BINDING_STALE"):
            evaluations.require_completed(
                SESSION_ID,
                TURN_ID,
                client_message_sha256=message_sha256,
                authority=live_authority,
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE turn_risk_evaluations "
                "SET risk_policy_manifest_sha256 = ? "
                "WHERE session_id = ? AND turn_id = ?",
                ("4" * 64, SESSION_ID, TURN_ID),
            )
    finally:
        connection.close()


def test_new_authority_supersedes_old_pending_revision_without_rewriting_it(
    tmp_path: Path,
) -> None:
    connection, sessions, evaluations = _repositories(tmp_path)
    message_sha256 = sessions.get_turn(
        SESSION_ID, TURN_ID
    ).client_message.content_sha256
    try:
        old_pending = evaluations.ensure_pending(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=AUTHORITY,
        )
        current_pending = evaluations.ensure_pending(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=STALE_AUTHORITY,
        )
        assert old_pending.evaluation_revision == 1
        assert current_pending.evaluation_revision == 2
        assert old_pending.status == current_pending.status == "pending"

        with pytest.raises(RiskLifecycleConflict, match="AUTHORITY_BINDING_STALE"):
            evaluations.persist_completed(
                SESSION_ID,
                TURN_ID,
                client_message_sha256=message_sha256,
                authority=AUTHORITY,
                observations=(),
            )
        completed = evaluations.persist_completed(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=STALE_AUTHORITY,
            observations=(),
        )

        assert completed.evaluation_revision == 2
        assert completed.status == "completed"
        assert evaluations.get(
            SESSION_ID,
            TURN_ID,
            authority=AUTHORITY,
        ).status == "pending"
        assert evaluations.get(SESSION_ID, TURN_ID) == completed
    finally:
        connection.close()


def test_new_authority_can_expand_provenance_for_one_stable_semantic_observation(
    tmp_path: Path,
) -> None:
    connection, sessions, evaluations = _repositories(tmp_path)
    message_sha256 = sessions.get_turn(
        SESSION_ID, TURN_ID
    ).client_message.content_sha256
    deterministic = _record(
        sessions,
        suffix=0x941,
        category="stable_semantic_result",
    ).model_copy(update={"confidence": 0.8})
    assert MODEL_AUTHORITY.approved_model_ref is not None
    expanded = deterministic.model_copy(
        update={
            "sources": (
                *deterministic.sources,
                RiskObservationSource(
                    source_kind="model_observation",
                    source_ref=MODEL_AUTHORITY.approved_model_ref,
                ),
            ),
            "confidence": 0.95,
        }
    )
    try:
        first_pending = evaluations.ensure_pending(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=AUTHORITY,
        )
        first = evaluations.persist_completed(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=AUTHORITY,
            observations=(deterministic,),
        )
        second_pending = evaluations.ensure_pending(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=MODEL_AUTHORITY,
        )
        second = evaluations.persist_completed(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=MODEL_AUTHORITY,
            observations=(expanded,),
        )

        assert first_pending.evaluation_revision == first.evaluation_revision == 1
        assert second_pending.evaluation_revision == second.evaluation_revision == 2
        assert deterministic.observation.observation_id == (
            expanded.observation.observation_id
        )
        assert evaluations.observations_for(first) == (deterministic,)
        assert evaluations.observations_for(second) == (expanded,)
        visible = InternalRiskObservationRepository(
            connection,
            database_scope="client",
            clock=FixedClock(NOW),
        ).list_visible(SESSION_ID)
        assert visible == (expanded,)
        assert connection.execute(
            "SELECT count(*) FROM internal_risk_observations "
            "WHERE observation_id = ?",
            (expanded.observation.observation_id,),
        ).fetchone() == (1,)

        replay = expanded.model_copy(
            update={
                "observation": expanded.observation.model_copy(
                    update={"detected_at": NOW + timedelta(seconds=1)}
                )
            }
        )
        assert evaluations.persist_completed(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=MODEL_AUTHORITY,
            observations=(replay,),
        ) == second
        assert connection.execute(
            "SELECT count(*) FROM turn_risk_evaluation_observations "
            "WHERE session_id = ? AND turn_id = ? AND evaluation_revision = 2",
            (SESSION_ID, TURN_ID),
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_member_insert_guard_rejects_wrong_turn_object_and_hash(
    tmp_path: Path,
) -> None:
    connection, sessions, evaluations = _repositories(tmp_path)
    message_sha256 = sessions.get_turn(
        SESSION_ID, TURN_ID
    ).client_message.content_sha256
    valid = _record(sessions, suffix=0x951, category="scope_bound_result")
    lifecycle = InternalRiskObservationRepository(
        connection,
        database_scope="client",
        clock=FixedClock(NOW),
    )
    lifecycle.add(valid)
    pending = evaluations.ensure_pending(
        SESSION_ID,
        TURN_ID,
        client_message_sha256=message_sha256,
        authority=AUTHORITY,
    )
    span = valid.trigger_spans[0]
    invalid_records = (
        valid.model_copy(
            update={
                "observation": valid.observation.model_copy(
                    update={
                        "trigger_turn_ids": (
                            "018f0000-0000-7000-8000-0000000009f1",
                        )
                    }
                ),
                "trigger_spans": (
                    span.model_copy(
                        update={
                            "turn_id": "018f0000-0000-7000-8000-0000000009f1"
                        }
                    ),
                ),
            }
        ),
        valid.model_copy(
            update={
                "trigger_spans": (
                    span.model_copy(
                        update={
                            "content_ref": span.content_ref.model_copy(
                                update={
                                    "object_id": (
                                        "private_span_018f0000-0000-7000-8000-"
                                        "0000000009f2"
                                    )
                                }
                            )
                        }
                    ),
                )
            }
        ),
        valid.model_copy(
            update={
                "trigger_spans": (
                    span.model_copy(
                        update={
                            "content_ref": span.content_ref.model_copy(
                                update={"content_sha256": "f" * 64}
                            )
                        }
                    ),
                )
            }
        ),
    )
    try:
        for invalid in invalid_records:
            snapshot = lifecycle._immutable_json(invalid)
            with pytest.raises(
                sqlite3.IntegrityError,
                match="member snapshot invalid|member invalid",
            ):
                connection.execute(
                    """
                    INSERT INTO turn_risk_evaluation_observations(
                        session_id, turn_id, evaluation_revision,
                        observation_id, ordinal, record_snapshot_json,
                        record_snapshot_sha256
                    ) VALUES (?, ?, ?, ?, 0, ?, ?)
                    """,
                    (
                        SESSION_ID,
                        TURN_ID,
                        pending.evaluation_revision,
                        valid.observation.observation_id,
                        snapshot,
                        hashlib.sha256(
                            (snapshot + "\n").encode("ascii")
                        ).hexdigest(),
                    ),
                )
        valid_snapshot = lifecycle._immutable_json(valid)
        duplicate_key_snapshot = (
            valid_snapshot[:-1]
            + ',"session_id":"018f0000-0000-7000-8000-0000000009f4"}'
        )
        with pytest.raises(sqlite3.IntegrityError, match="member snapshot invalid"):
            connection.execute(
                """
                INSERT INTO turn_risk_evaluation_observations(
                    session_id, turn_id, evaluation_revision,
                    observation_id, ordinal, record_snapshot_json,
                    record_snapshot_sha256
                ) VALUES (?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    SESSION_ID,
                    TURN_ID,
                    pending.evaluation_revision,
                    valid.observation.observation_id,
                    duplicate_key_snapshot,
                    hashlib.sha256(
                        (duplicate_key_snapshot + "\n").encode("ascii")
                    ).hexdigest(),
                ),
            )
    finally:
        connection.close()


def test_observations_for_rejects_cross_turn_member_if_db_guard_is_bypassed(
    tmp_path: Path,
) -> None:
    connection, sessions, evaluations = _repositories(tmp_path)
    message_sha256 = sessions.get_turn(
        SESSION_ID, TURN_ID
    ).client_message.content_sha256
    foreign_turn_id = "018f0000-0000-7000-8000-0000000009f3"
    foreign = _record(
        sessions,
        suffix=0x953,
        category="forged_cross_turn_result",
    )
    foreign = foreign.model_copy(
        update={
            "observation": foreign.observation.model_copy(
                update={"trigger_turn_ids": (foreign_turn_id,)}
            ),
            "trigger_spans": (
                foreign.trigger_spans[0].model_copy(
                    update={"turn_id": foreign_turn_id}
                ),
            ),
        }
    )
    lifecycle = InternalRiskObservationRepository(
        connection,
        database_scope="client",
        clock=FixedClock(NOW),
    )
    lifecycle.add(foreign)
    pending = evaluations.ensure_pending(
        SESSION_ID,
        TURN_ID,
        client_message_sha256=message_sha256,
        authority=AUTHORITY,
    )
    snapshot = lifecycle._immutable_json(foreign)
    snapshot_sha256 = hashlib.sha256(
        (snapshot + "\n").encode("ascii")
    ).hexdigest()
    try:
        with pytest.raises(sqlite3.IntegrityError, match="member snapshot invalid"):
            connection.execute(
                """
                INSERT INTO turn_risk_evaluation_observations(
                    session_id, turn_id, evaluation_revision,
                    observation_id, ordinal, record_snapshot_json,
                    record_snapshot_sha256
                ) VALUES (?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    SESSION_ID,
                    TURN_ID,
                    pending.evaluation_revision,
                    foreign.observation.observation_id,
                    snapshot,
                    snapshot_sha256,
                ),
            )

        connection.execute(
            "DROP TRIGGER turn_risk_evaluation_observations_insert_guard"
        )
        connection.execute(
            """
            INSERT INTO turn_risk_evaluation_observations(
                session_id, turn_id, evaluation_revision,
                observation_id, ordinal, record_snapshot_json,
                record_snapshot_sha256
            ) VALUES (?, ?, ?, ?, 0, ?, ?)
            """,
            (
                SESSION_ID,
                TURN_ID,
                pending.evaluation_revision,
                foreign.observation.observation_id,
                snapshot,
                snapshot_sha256,
            ),
        )
        connection.execute(
            """
            UPDATE turn_risk_evaluations
               SET status = 'completed', observation_set_sha256 = ?,
                   observation_count = 1, completed_at = ?
             WHERE session_id = ? AND turn_id = ? AND evaluation_revision = ?
            """,
            (
                canonical_risk_observation_set_sha256((foreign,)),
                NOW.isoformat().replace("+00:00", "Z"),
                SESSION_ID,
                TURN_ID,
                pending.evaluation_revision,
            ),
        )
        completed = evaluations.get(SESSION_ID, TURN_ID)
        with pytest.raises(
            RiskRepositoryError,
            match="TURN_RISK_EVALUATION_MEMBERSHIP_CORRUPT",
        ):
            evaluations.observations_for(completed)
    finally:
        connection.close()


def test_acknowledge_and_close_do_not_change_completed_snapshot_hash(
    tmp_path: Path,
) -> None:
    connection, sessions, evaluations = _repositories(tmp_path)
    message_sha256 = sessions.get_turn(
        SESSION_ID, TURN_ID
    ).client_message.content_sha256
    record = _record(sessions, suffix=0x961, category="lifecycle_hash_result")
    try:
        evaluations.ensure_pending(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=AUTHORITY,
        )
        completed = evaluations.persist_completed(
            SESSION_ID,
            TURN_ID,
            client_message_sha256=message_sha256,
            authority=AUTHORITY,
            observations=(record,),
        )
        assert completed.observation_set_sha256 is not None

        acknowledged = InternalRiskObservationRepository(
            connection,
            database_scope="client",
            clock=FixedClock(NOW + timedelta(minutes=1)),
        ).acknowledge(
            record.observation.observation_id,
            counselor_disposition="continue observing",
        )
        after_ack = evaluations.observations_for(completed)
        assert after_ack[0].status == acknowledged.status == "acknowledged"
        assert canonical_risk_observation_set_sha256(after_ack) == (
            completed.observation_set_sha256
        )

        closed = InternalRiskObservationRepository(
            connection,
            database_scope="client",
            clock=FixedClock(NOW + timedelta(minutes=2)),
        ).close(
            record.observation.observation_id,
            decision="resolved",
            reason="manual review completed",
        )
        after_close = evaluations.observations_for(completed)
        assert after_close[0].status == closed.status == "closed"
        assert canonical_risk_observation_set_sha256(after_close) == (
            completed.observation_set_sha256
        )
        assert InternalRiskObservationRepository(
            connection,
            database_scope="client",
            clock=FixedClock(NOW + timedelta(minutes=2)),
        ).list_visible(SESSION_ID) == ()
    finally:
        connection.close()
