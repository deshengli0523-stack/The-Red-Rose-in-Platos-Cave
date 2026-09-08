from __future__ import annotations

import itertools
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import BaseModel

from consultation_kb.core.errors import PreviousTurnNotClosedError
from consultation_kb.core.client_ids import ClientIdFactory
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.session import CandidateDraft
from consultation_kb.security.capability import CapabilityService
from consultation_kb.security.scope_broker import ScopeBroker, ScopedSession
from consultation_kb.security.scoped_worker import ScopeDenied, ScopedWorkerBroker
from consultation_kb.security.worker_protocol import (
    AppendClientTurnRequest,
    AppendClientTurnResponse,
    AppendTemporaryFactRequest,
    AppendTemporaryFactResponse,
    BeginGenerationRequest,
    BeginGenerationResponse,
    BeginSessionRequest,
    BeginSessionResponse,
    QueryClientHistoryCandidatesRequest,
    ReadSessionStateRequest,
    ReadSessionStateResponse,
    RecordActualReplyRequest,
    RecordActualReplyResponse,
    ResumeSessionRequest,
    ResumeSessionResponse,
    StoreCandidateSetRequest,
    StoreCandidateSetResponse,
    WorkerRequest,
)
from consultation_kb.storage.catalog import ClientCatalog
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from tests.consultation_kb.risk_support import deterministic_risk_authority


pytestmark = [
    pytest.mark.integration,
    pytest.mark.acceptance_id("TURN-01"),
    pytest.mark.skipif(sys.platform != "win32", reason="Windows scoped subprocess"),
]
RISK_AUTHORITY = deterministic_risk_authority(epoch=1, suffix=915_000)


class _FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 7, 19, 4, 0, tzinfo=timezone.utc)


@dataclass(slots=True)
class _Harness:
    global_connection: sqlite3.Connection
    capability_service: CapabilityService
    clients_root: Path
    client_a: str
    client_b: str
    client_a_root: Path
    client_b_root: Path
    session_id: str
    token: str
    scope: ScopedSession
    ids: IdFactory

    def worker(self) -> ScopedWorkerBroker:
        return ScopedWorkerBroker.for_scoped_session(
            session=self.scope,
            capability_token=self.token,
            capability_service=self.capability_service,
            startup_timeout_seconds=10.0,
            call_timeout_seconds=10.0,
        )

    def close(self) -> None:
        self.global_connection.close()


def _build_harness(tmp_path: Path) -> _Harness:
    vault = tmp_path / "vault"
    clients_root = vault / "clients"
    clients_root.mkdir(parents=True)
    global_database = vault / "global" / "catalog.sqlite3"
    global_database.parent.mkdir()
    global_connection = connect_database(global_database, mode="writer")
    MigrationRunner.for_scope(global_connection, "global").apply()

    clock = _FixedClock()
    ids = IdFactory(clock, itertools.count(1).__next__)
    suffixes = iter(("a1b2c3d4e5f6", "b1b2c3d4e5f6"))
    client_ids = ClientIdFactory(suffix_source=suffixes.__next__)
    client_a = client_ids.new()
    client_b = client_ids.new()
    catalog = ClientCatalog(global_connection)
    roots: dict[str, Path] = {}
    for index, client_id in enumerate((client_a, client_b), start=1):
        record = catalog.prepare(
            client_id=client_id,
            directory_object_id=ids.object_id("client_directory"),
            alias_lookup_sha256=f"{index}" * 64,
            created_at=clock.now(),
        )
        catalog.activate(client_id, activated_at=clock.now())
        root = clients_root / client_id
        root.mkdir()
        roots[client_id] = root
        (root / ".scope-id").write_bytes(
            f"{record.directory_object_id}\n".encode("ascii")
        )
        connection = connect_database(root / "client.sqlite3", mode="writer")
        try:
            MigrationRunner.for_scope(connection, "client").apply()
        finally:
            connection.close()

    b_canary = b"SESSION-WORKER-B-PRIVATE-CANARY"
    (roots[client_b] / "private-canary.bin").write_bytes(b_canary)
    capability_tokens = iter((b"w" * 32, b"x" * 32, b"y" * 32))
    capability_service = CapabilityService(
        global_connection,
        catalog=catalog,
        clock=clock,
        id_factory=ids,
        token_source=lambda _size: next(capability_tokens),
    )
    session_id = ids.uuid7()
    token = capability_service.issue(
        client_id=client_a,
        session_id=session_id,
        permissions=frozenset({"client_read", "session_append"}),
    )
    scope = ScopeBroker(
        capability_service=capability_service,
        catalog=catalog,
        clients_root=clients_root,
        global_database=global_database,
    ).authorize(
        token,
        session_id=session_id,
        client_id=client_a,
        required_permissions=frozenset({"client_read", "session_append"}),
    )
    return _Harness(
        global_connection=global_connection,
        capability_service=capability_service,
        clients_root=clients_root,
        client_a=client_a,
        client_b=client_b,
        client_a_root=roots[client_a],
        client_b_root=roots[client_b],
        session_id=session_id,
        token=token,
        scope=scope,
        ids=ids,
    )


def _request_id(harness: _Harness) -> str:
    return harness.ids.uuid7()


def _append_generate_and_store(
    harness: _Harness,
    worker: ScopedWorkerBroker,
    *,
    turn_id: str,
    message: str,
    key: str,
) -> tuple[str, str]:
    appended = worker.call(
        AppendClientTurnRequest(
            request_id=_request_id(harness),
            session_id=harness.session_id,
            turn_id=turn_id,
            client_message=message,
            risk_authority=RISK_AUTHORITY,
        )
    )
    assert isinstance(appended, AppendClientTurnResponse)
    assert appended.state == "client_turn_received"
    run_id = harness.ids.uuid7()
    generating = worker.call(
        BeginGenerationRequest(
            request_id=_request_id(harness),
            session_id=harness.session_id,
            turn_id=turn_id,
            run_id=run_id,
        )
    )
    assert isinstance(generating, BeginGenerationResponse)
    assert generating.state == "generation_in_progress"
    stored = worker.call(
        StoreCandidateSetRequest(
            request_id=_request_id(harness),
            session_id=harness.session_id,
            turn_id=turn_id,
            run_id=run_id,
            idempotency_key=f"candidate-set-{key}",
            candidates=(
                CandidateDraft(label="共情", text=f"{message}：先理解感受。"),
                CandidateDraft(label="行动", text=f"{message}：再澄清下一步。"),
            ),
        )
    )
    assert isinstance(stored, StoreCandidateSetResponse)
    assert stored.state == "awaiting_actual_reply"
    assert len(stored.candidate_ids) == 2
    return stored.candidate_ids


def _all_file_bytes(root: Path) -> bytes:
    chunks: list[bytes] = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            chunks.append(path.read_bytes())
    return b"\n".join(chunks)


def _property_names(schema: object) -> set[str]:
    names: set[str] = set()
    if isinstance(schema, dict):
        properties = schema.get("properties")
        if isinstance(properties, dict):
            names.update(str(key) for key in properties)
        for value in schema.values():
            names.update(_property_names(value))
    elif isinstance(schema, list):
        for value in schema:
            names.update(_property_names(value))
    return names


def test_session_worker_requests_expose_no_scope_selector_fields() -> None:
    request_models: tuple[type[BaseModel], ...] = (
        BeginSessionRequest,
        ResumeSessionRequest,
        AppendClientTurnRequest,
        AppendTemporaryFactRequest,
        BeginGenerationRequest,
        StoreCandidateSetRequest,
        RecordActualReplyRequest,
        ReadSessionStateRequest,
    )
    forbidden = {"client", "client_id", "path", "root", "sql", "payload"}
    for model in request_models:
        assert _property_names(model.model_json_schema()).isdisjoint(forbidden)


def test_worker_rejects_every_cross_session_target_before_dispatch(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    other_session_id = harness.ids.uuid7()
    turn_id = harness.ids.uuid7()
    run_id = harness.ids.uuid7()
    requests: tuple[WorkerRequest, ...] = (
        BeginSessionRequest(
            request_id=_request_id(harness),
            session_id=other_session_id,
            capability_epoch=1,
        ),
        ResumeSessionRequest(
            request_id=_request_id(harness),
            session_id=other_session_id,
            previous_capability_epoch=1,
            capability_epoch=2,
        ),
        ReadSessionStateRequest(
            request_id=_request_id(harness),
            session_id=other_session_id,
        ),
        AppendClientTurnRequest(
            request_id=_request_id(harness),
            session_id=other_session_id,
            turn_id=turn_id,
            client_message="cross-session message must be rejected",
            risk_authority=RISK_AUTHORITY,
        ),
        AppendTemporaryFactRequest(
            request_id=_request_id(harness),
            session_id=other_session_id,
            turn_id=turn_id,
            idempotency_key="cross-session-temporary-fact",
            event_kind="GOAL",
            cognitive_type="client_statement",
            value={"goal": "must not be written"},
        ),
        BeginGenerationRequest(
            request_id=_request_id(harness),
            session_id=other_session_id,
            turn_id=turn_id,
            run_id=run_id,
        ),
        StoreCandidateSetRequest(
            request_id=_request_id(harness),
            session_id=other_session_id,
            turn_id=turn_id,
            run_id=run_id,
            idempotency_key="cross-session-candidate-set",
            candidates=(
                CandidateDraft(label="first", text="first rejected candidate"),
                CandidateDraft(label="second", text="second rejected candidate"),
            ),
        ),
        RecordActualReplyRequest(
            request_id=_request_id(harness),
            session_id=other_session_id,
            turn_id=turn_id,
            idempotency_key="cross-session-actual-reply",
            mode="external_unknown",
            confirmed_at=datetime(2026, 7, 19, 4, 5, tzinfo=timezone.utc),
        ),
        QueryClientHistoryCandidatesRequest(
            request_id=_request_id(harness),
            session_handle="foreign-session-handle",
            query_category="relationship_history",
        ),
    )
    try:
        for request in requests:
            worker = harness.worker()
            worker.start()
            with pytest.raises(ScopeDenied, match="SCOPE_DENIED"):
                worker.call(request)
            assert worker.closed

        connection = connect_database(
            harness.client_a_root / "client.sqlite3",
            mode="reader",
        )
        try:
            row = connection.execute(
                "SELECT COUNT(*) FROM sessions WHERE session_id = ?",
                (other_session_id,),
            ).fetchone()
        finally:
            connection.close()
        assert row == (0,)
    finally:
        harness.close()


def test_resume_hydrates_actual_conversation_and_temporary_facts(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    first_worker = harness.worker()
    resumed_worker: ScopedWorkerBroker | None = None
    try:
        first_worker.start()
        started = first_worker.call(
            BeginSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                capability_epoch=1,
            )
        )
        assert isinstance(started, BeginSessionResponse)
        turn_id = harness.ids.uuid7()
        first_worker.call(
            AppendClientTurnRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                client_message="visitor message to recover",
                risk_authority=RISK_AUTHORITY,
            )
        )

        temporary = first_worker.call(
            AppendTemporaryFactRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                event_kind="GOAL",
                cognitive_type="client_statement",
                value={"goal": "recover this temporary fact"},
                idempotency_key="resume-temp-fact-1",
            )
        )
        assert isinstance(temporary, AppendTemporaryFactResponse)
        repeated_temporary = first_worker.call(
            AppendTemporaryFactRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                event_kind="GOAL",
                cognitive_type="client_statement",
                value={"goal": "recover this temporary fact"},
                idempotency_key="resume-temp-fact-1",
            )
        )
        assert isinstance(repeated_temporary, AppendTemporaryFactResponse)
        assert repeated_temporary.event_id == temporary.event_id
        assert repeated_temporary.content_sha256 == temporary.content_sha256

        run_id = harness.ids.uuid7()
        first_worker.call(
            BeginGenerationRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                run_id=run_id,
            )
        )
        candidates = first_worker.call(
            StoreCandidateSetRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                run_id=run_id,
                idempotency_key="resume-candidates-1",
                candidates=(
                    CandidateDraft(label="first", text="candidate one"),
                    CandidateDraft(label="second", text="candidate two"),
                ),
            )
        )
        assert isinstance(candidates, StoreCandidateSetResponse)
        first_worker.call(
            RecordActualReplyRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                idempotency_key="resume-actual-1",
                mode="edited",
                candidate_id=candidates.candidate_ids[0],
                actual_text="the exact edited reply that was sent",
                sent_at=datetime(2026, 7, 19, 4, 5, tzinfo=timezone.utc),
            )
        )
        first_worker.close()

        orphaned_token = harness.capability_service.renew(
            client_id=harness.client_a,
            session_id=harness.session_id,
            previous_epoch=1,
        )
        assert harness.capability_service.revoke(orphaned_token) == 3
        renewed_token = harness.capability_service.renew(
            client_id=harness.client_a,
            session_id=harness.session_id,
            previous_epoch=3,
        )
        binding = harness.capability_service.validate_binding(
            renewed_token,
            session_id=harness.session_id,
            client_id=harness.client_a,
            required_permissions=frozenset({"client_read", "session_append"}),
        )
        renewed_scope = ScopedSession(
            session_scope=binding.session_scope,
            client_id=harness.scope.client_id,
            client_root=harness.scope.client_root,
            client_database=harness.scope.client_database,
            global_database=harness.scope.global_database,
            scope_marker_sha256=harness.scope.scope_marker_sha256,
            global_descriptor_sha256=harness.scope.global_descriptor_sha256,
            capability_id=binding.capability_id,
            capability_epoch=binding.capability_epoch,
        )
        resumed_worker = ScopedWorkerBroker.for_scoped_session(
            session=renewed_scope,
            capability_token=renewed_token,
            capability_service=harness.capability_service,
            startup_timeout_seconds=10.0,
            call_timeout_seconds=10.0,
        )
        resumed_worker.start()
        resumed = resumed_worker.call(
            ResumeSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                previous_capability_epoch=3,
                capability_epoch=4,
            )
        )
        assert isinstance(resumed, ResumeSessionResponse)
        assert resumed.capability_epoch == 4
        assert resumed.recovery.pending_action == "ready_for_next_turn"
        assert [item.client_message for item in resumed.recovery.turns] == [
            "visitor message to recover"
        ]
        assert [item.actual_text for item in resumed.recovery.actual_replies] == [
            "the exact edited reply that was sent"
        ]
        assert [item.value for item in resumed.recovery.temporary_facts] == [
            {"goal": "recover this temporary fact"}
        ]
        recovery_json = resumed.recovery.model_dump_json()
        assert harness.client_a not in recovery_json
        assert str(harness.client_a_root) not in recovery_json
    finally:
        first_worker.close()
        if resumed_worker is not None:
            resumed_worker.close()
        harness.close()


def test_real_scoped_worker_persists_all_actual_reply_modes_and_fails_closed(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    first_worker = harness.worker()
    second_worker: ScopedWorkerBroker | None = None
    responses: list[str] = []
    b_canary = (harness.client_b_root / "private-canary.bin").read_bytes()
    try:
        first_worker.start()
        started = first_worker.call(
            BeginSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                capability_epoch=1,
            )
        )
        assert isinstance(started, BeginSessionResponse)
        assert started.snapshot.client_id == harness.client_a
        assert started.snapshot.profile is None
        responses.append(started.model_dump_json())

        turn_edited = harness.ids.uuid7()
        first_worker.call(
            AppendClientTurnRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_edited,
                client_message="第一轮来访者消息",
                risk_authority=RISK_AUTHORITY,
            )
        )
        run_edited = harness.ids.uuid7()
        first_worker.call(
            BeginGenerationRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_edited,
                run_id=run_edited,
            )
        )
        edited_candidate_set = first_worker.call(
            StoreCandidateSetRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_edited,
                run_id=run_edited,
                idempotency_key="candidate-set-edited",
                candidates=(
                    CandidateDraft(label="共情", text="候选一"),
                    CandidateDraft(label="行动", text="候选二"),
                ),
            )
        )
        assert isinstance(edited_candidate_set, StoreCandidateSetResponse)
        edited_candidate_ids = edited_candidate_set.candidate_ids
        awaiting_state = first_worker.call(
            ReadSessionStateRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
            )
        )
        assert isinstance(awaiting_state, ReadSessionStateResponse)
        assert [
            item.candidate_id
            for item in awaiting_state.recovery.pending_candidates
        ] == list(edited_candidate_ids)
        assert all(
            item.text for item in awaiting_state.recovery.pending_candidates
        )
        with pytest.raises(PreviousTurnNotClosedError) as denied:
            first_worker.call(
                AppendClientTurnRequest(
                    request_id=_request_id(harness),
                    session_id=harness.session_id,
                    turn_id=harness.ids.uuid7(),
                    client_message="上一轮未关闭时不可进入下一轮",
                    risk_authority=RISK_AUTHORITY,
                )
            )
        assert str(denied.value) == "PREVIOUS_TURN_NOT_CLOSED"
        assert not first_worker.closed
        assert first_worker.is_alive

        second_worker = first_worker
        edited = second_worker.call(
            RecordActualReplyRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_edited,
                idempotency_key="actual-edited",
                mode="edited",
                candidate_id=edited_candidate_ids[0],
                actual_text="咨询师实际发送的编辑版回复",
                sent_at=datetime(2026, 7, 19, 4, 1, tzinfo=timezone.utc),
            )
        )
        assert isinstance(edited, RecordActualReplyResponse)
        assert edited.source_type == "edited"
        assert not edited.evidence_gap
        responses.append(edited.model_dump_json())

        turn_adopted = harness.ids.uuid7()
        adopted_candidates = _append_generate_and_store(
            harness,
            second_worker,
            turn_id=turn_adopted,
            message="第二轮来访者消息",
            key="adopted",
        )
        adopted = second_worker.call(
            RecordActualReplyRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_adopted,
                idempotency_key="actual-adopted",
                mode="adopted",
                candidate_id=adopted_candidates[1],
                sent_at=datetime(2026, 7, 19, 4, 2, tzinfo=timezone.utc),
            )
        )
        assert isinstance(adopted, RecordActualReplyResponse)
        assert adopted.source_type == "adopted"
        assert not adopted.evidence_gap
        responses.append(adopted.model_dump_json())

        turn_unknown = harness.ids.uuid7()
        _append_generate_and_store(
            harness,
            second_worker,
            turn_id=turn_unknown,
            message="第三轮来访者消息",
            key="unknown",
        )
        unknown = second_worker.call(
            RecordActualReplyRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_unknown,
                idempotency_key="actual-unknown",
                mode="external_unknown",
                confirmed_at=datetime(2026, 7, 19, 4, 3, tzinfo=timezone.utc),
            )
        )
        assert isinstance(unknown, RecordActualReplyResponse)
        assert unknown.source_type == "external_unknown"
        assert unknown.evidence_gap
        responses.append(unknown.model_dump_json())

        state = second_worker.call(
            ReadSessionStateRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
            )
        )
        assert isinstance(state, ReadSessionStateResponse)
        assert [turn.state for turn in state.turns] == ["turn_closed"] * 3
        assert [turn.ordinal for turn in state.turns] == [1, 2, 3]
        assert state.actual_reply_count == 3
        assert state.temporary_fact_count == 0
        assert len(state.recovery.turns) == 3
        assert all(item.client_message for item in state.recovery.turns)
        assert [item.source_type for item in state.recovery.actual_replies] == [
            "edited",
            "adopted",
            "external_unknown",
        ]
        assert state.recovery.actual_replies[0].actual_text is not None
        assert state.recovery.actual_replies[1].actual_text is not None
        assert state.recovery.actual_replies[2].actual_text is None
        assert state.recovery.pending_candidates == ()
        responses.append(state.model_dump_json())

        client_b_connection = connect_database(
            harness.client_b_root / "client.sqlite3", mode="reader"
        )
        try:
            assert client_b_connection.execute(
                "SELECT COUNT(*) FROM sessions"
            ).fetchone() == (0,)
        finally:
            client_b_connection.close()
        assert b_canary not in _all_file_bytes(harness.client_a_root)
        disclosure_surface = "\n".join(responses).encode("utf-8")
        assert b_canary not in disclosure_surface
        assert harness.client_b.encode("ascii") not in disclosure_surface

        assert harness.capability_service.revoke(harness.token) == 2
        with pytest.raises(ScopeDenied) as revoked:
            second_worker.call(
                ReadSessionStateRequest(
                    request_id=_request_id(harness),
                    session_id=harness.session_id,
                )
            )
        assert str(revoked.value) == "SCOPE_DENIED"
        assert second_worker.closed
        assert not second_worker.is_alive
    finally:
        first_worker.close()
        if second_worker is not None:
            second_worker.close()
        harness.close()
