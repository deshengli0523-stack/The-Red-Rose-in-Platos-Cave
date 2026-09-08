from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.session.actual_replies import ActualReplyService
from consultation_kb.session.candidate_sets import CandidateSetService
from consultation_kb.session.context import ClientContextSnapshot, client_context_sha256
from consultation_kb.session.recovery import SessionRecovery
from consultation_kb.session.repository import SessionRepository
from consultation_kb.session.temporary_ledger import TemporaryFactLedger
from consultation_kb.session.turns import TurnService
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore


def _empty_context(now: datetime) -> ClientContextSnapshot:
    payload = {
        "schema_version": "client_context.v1",
        "client_id": "client_" + "aaaaaaaaaaaa",
        "profile_revision_id": None,
        "profile_version": 0,
        "profile_sha256": None,
        "fixed_epoch": 0,
        "profile": None,
        "recent_session_summary_refs": (),
        "unresolved_items": (),
        "goals": (),
        "preferences": (),
        "constraints": (),
        "key_facts": (),
        "review_items": (),
        "created_at": now,
    }
    return ClientContextSnapshot(
        **payload,
        canonical_sha256=client_context_sha256(payload),
    )


def test_recovery_preserves_snapshot_actuals_and_temp_facts_but_regenerates_stage(
    tmp_path: Path,
) -> None:
    connection = connect_database(tmp_path / "client.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "client").apply()
    now = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
    clock = FixedClock(now)
    values = iter(range(2000, 2600))
    repository = SessionRepository(
        connection,
        content_store=ContentStore(tmp_path / "scope"),
        clock=clock,
        id_factory=IdFactory(clock=clock, random_source=lambda: next(values)),
    )
    session_id = "018f0000-0000-7000-8000-000000000401"
    turn_id = "018f0000-0000-7000-8000-000000000402"
    run_id = "018f0000-0000-7000-8000-000000000403"
    context = _empty_context(now)
    try:
        repository.create_session(
            session_id=session_id,
            client_id=context.client_id,
            client_scope_hash="a" * 64,
            snapshot_version=context.profile_version,
            snapshot_canonical_sha256=context.canonical_sha256,
            snapshot_bytes=context.canonical_bytes(),
        )
        turns = TurnService(repository)
        turns.append(session_id, turn_id, "需要恢复的消息")
        TemporaryFactLedger(repository).propose(
            session_id,
            turn_id,
            event_kind="HYPOTHESIS",
            cognitive_type="hypothesis",
            value={"hypothesis": "可能担心被拒绝"},
            idempotency_key="hypothesis-recovery-1",
        )
        turns.begin_generation(session_id, turn_id, run_id=run_id)
        partial = repository.store_json(
            b'{"partial":"analysis"}\n',
            kind="generation_stage",
        )
        partial_id = repository.id_factory.object_id("generation_stage")
        connection.execute(
            """
            INSERT INTO generation_stage_artifacts(
                stage_artifact_id, session_id, turn_id, run_id, stage,
                artifact_object_id, artifact_sha256, artifact_media_type,
                artifact_size_bytes, parent_sha256s_json, created_at
            ) VALUES (?, ?, ?, ?, 'conceptualization', ?, ?, ?, ?, '[]', ?)
            """,
            (
                partial_id,
                session_id,
                turn_id,
                run_id,
                partial.object_id,
                partial.content_sha256,
                partial.media_type,
                partial.size_bytes,
                now.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            ),
        )

        recovered = SessionRecovery(repository).resume(session_id)
        assert recovered.pending_action == "regenerate"
        assert recovered.snapshot == context
        assert len(recovered.temporary_facts) == 1
        assert recovered.actual_conversation == ()
        assert recovered.discarded_stage_artifact_ids == (partial_id,)
        assert recovered.active_turn is not None
        recovered_run_id = recovered.active_turn.active_run_id
        assert recovered_run_id is not None
        assert recovered_run_id != run_id
        assert connection.execute(
            "SELECT status, discarded_at FROM generation_stage_artifacts "
            "WHERE stage_artifact_id = ?",
            (partial_id,),
        ).fetchone()[0] == "DISCARDED"
        repeated_recovery = SessionRecovery(repository).resume(session_id)
        assert repeated_recovery.active_turn is not None
        assert repeated_recovery.active_turn.active_run_id == recovered_run_id

        candidates = CandidateSetService(repository).store_and_await(
            session_id,
            turn_id,
            ("候选一", "候选二"),
            run_id=recovered_run_id,
            idempotency_key="set-recovery",
        )
        awaiting = SessionRecovery(repository).resume(session_id)
        assert awaiting.pending_action == "record_actual_reply"
        assert awaiting.active_turn is not None

        ActualReplyService(repository).record_external_unknown(
            session_id,
            turn_id,
            confirmed_at=now,
            idempotency_key="unknown-recovery",
        )
        closed = SessionRecovery(repository).resume(session_id)
        assert closed.pending_action == "ready_for_next_turn"
        assert closed.incomplete_evidence is True
        assert len(closed.actual_conversation) == 1
        assert all(
            actual.candidate_id not in {item.candidate_id for item in candidates.candidates}
            for actual in closed.actual_conversation
        )
    finally:
        connection.close()


def test_recovery_rotates_generation_run_without_stage_artifacts_once(
    tmp_path: Path,
) -> None:
    connection = connect_database(tmp_path / "client.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "client").apply()
    now = datetime(2026, 7, 19, 9, 0, tzinfo=timezone.utc)
    clock = FixedClock(now)
    # UUIDv7's random field is not a commit-order sequence.  Deliberately make
    # later IDs sort before earlier IDs so recovery cannot accidentally rely on
    # checkpoint_id lexical order when timestamps are identical.
    values = iter(range(3600, 3000, -1))
    repository = SessionRepository(
        connection,
        content_store=ContentStore(tmp_path / "scope"),
        clock=clock,
        id_factory=IdFactory(clock=clock, random_source=lambda: next(values)),
    )
    session_id = "018f0000-0000-7000-8000-000000000411"
    turn_id = "018f0000-0000-7000-8000-000000000412"
    interrupted_run_id = "018f0000-0000-7000-8000-000000000413"
    context = _empty_context(now)
    try:
        repository.create_session(
            session_id=session_id,
            client_id=context.client_id,
            client_scope_hash="b" * 64,
            snapshot_version=context.profile_version,
            snapshot_canonical_sha256=context.canonical_sha256,
            snapshot_bytes=context.canonical_bytes(),
        )
        turns = TurnService(repository)
        turns.append(session_id, turn_id, "A message interrupted before any stage persisted")
        turns.begin_generation(session_id, turn_id, run_id=interrupted_run_id)

        first = SessionRecovery(repository).resume(session_id)
        assert first.pending_action == "regenerate"
        assert first.discarded_stage_artifact_ids == ()
        assert first.active_turn is not None
        replacement_run_id = first.active_turn.active_run_id
        assert replacement_run_id is not None
        assert replacement_run_id != interrupted_run_id

        repeated = SessionRecovery(repository).resume(session_id)
        assert repeated.active_turn is not None
        assert repeated.active_turn.active_run_id == replacement_run_id
        restart_count = connection.execute(
            "SELECT COUNT(*) FROM session_checkpoints "
            "WHERE session_id = ? AND turn_id = ? "
            "AND event_kind = 'generation_run_restarted'",
            (session_id, turn_id),
        ).fetchone()[0]
        assert restart_count == 1
        sequences = [
            int(row[0])
            for row in connection.execute(
                "SELECT checkpoint_sequence FROM session_checkpoints "
                "WHERE session_id = ? ORDER BY checkpoint_sequence",
                (session_id,),
            ).fetchall()
        ]
        assert sequences == list(range(1, len(sequences) + 1))
    finally:
        connection.close()
