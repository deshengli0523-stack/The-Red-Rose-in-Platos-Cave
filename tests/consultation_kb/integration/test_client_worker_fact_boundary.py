from __future__ import annotations

import hashlib
import inspect
import os
import sys
from io import StringIO
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from consultation_kb.security import scoped_worker
from consultation_kb.security.scoped_worker import (
    ScopeDenied,
    ScopedWorkerBroker,
    WorkerScopeDescriptor,
)
from consultation_kb.security.worker_protocol import (
    CommitFactMutationRequest,
    PreviewDependencyImpactRequest,
    PreviewFactMutationRequest,
    PreviewFactMutationResponse,
    QueryClientGraphRequest,
    QueryClientGraphResponse,
    QueryFactSnapshotRequest,
    QueryFactSnapshotResponse,
    QueryProfileSnapshotRequest,
    QueryProfileSnapshotResponse,
)
from consultation_kb.approvals.review_agent import ReviewAgent
from consultation_kb.models.facts import AddMutation, canonical_json
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.common import VersionRef
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from tests.consultation_kb.approval_support import build_approval_harness
from tests.consultation_kb.unit.test_fact_schema import CLIENT_ID, _event


pytestmark = [pytest.mark.integration, pytest.mark.skipif(sys.platform != "win32", reason="Windows scoped worker")]
UTC = timezone.utc
REQUEST_ID = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
REQUEST_ID_2 = "017f22e2-79b0-7cc3-98c4-dc0c0c073990"
REQUEST_ID_3 = "017f22e2-79b0-7cc3-98c4-dc0c0c073991"


@dataclass
class _Validator:
    calls: list[str] = field(default_factory=list)

    def assert_valid(self, _token: str, *, required_permission: str) -> None:
        self.calls.append(required_permission)


def _scope(tmp_path: Path) -> Path:
    root = tmp_path / "client-scope"
    (root / "audit").mkdir(parents=True)
    marker = b"p2-synthetic-scope\n"
    (root / ".scope-id").write_bytes(marker)
    (root / "audit" / "worker.jsonl").write_bytes(b"")
    connection = connect_database(root / "client.sqlite3", "writer")
    try:
        MigrationRunner.for_scope(connection, "client").apply()
    finally:
        connection.close()
    return root


def test_p2_protocol_models_are_frozen_and_contain_no_scope_or_execution_fields() -> None:
    request_models = (
        QueryFactSnapshotRequest,
        PreviewFactMutationRequest,
        CommitFactMutationRequest,
        QueryProfileSnapshotRequest,
        QueryClientGraphRequest,
        PreviewDependencyImpactRequest,
    )
    forbidden = {
        "client_id",
        "path",
        "payload",
        "receipt",
        "secret",
        "shell",
        "sql",
        "ticket",
    }
    for model in request_models:
        assert forbidden.isdisjoint(model.model_fields)
        assert model.model_config["frozen"] is True


def test_empty_p2_queries_execute_only_in_the_spawned_scoped_worker(tmp_path: Path) -> None:
    root = _scope(tmp_path)
    marker_sha = hashlib.sha256((root / ".scope-id").read_bytes()).hexdigest()
    validator = _Validator()
    broker = ScopedWorkerBroker(
        scope=WorkerScopeDescriptor(
            scope_root=root,
            global_descriptor_sha256="a" * 64,
            scope_marker_sha256=marker_sha,
        ),
        capability_token="opaque-p2-token",
        validator=validator,
    )
    broker.start()
    try:
        process = broker._process
        assert process is not None and process.pid != os.getpid()
        when = datetime(2026, 7, 17, tzinfo=UTC)
        facts = broker.call(
            QueryFactSnapshotRequest(
                request_id=REQUEST_ID,
                effective_at=when,
                known_at=when,
                fixed_epoch=0,
            )
        )
        profile = broker.call(
            QueryProfileSnapshotRequest(
                request_id=REQUEST_ID_2,
                effective_at=when,
                known_at=when,
                fixed_epoch=0,
            )
        )
        graph = broker.call(
            QueryClientGraphRequest(
                request_id=REQUEST_ID_3,
                effective_at=when,
                known_at=when,
                fixed_epoch=0,
            )
        )
        assert isinstance(facts, QueryFactSnapshotResponse)
        assert facts.event_count == 0 and facts.client_commit_version == 0
        assert isinstance(profile, QueryProfileSnapshotResponse)
        assert profile.item_count == 0
        assert isinstance(graph, QueryClientGraphResponse)
        assert graph.node_count == 0 and graph.edge_count == 0
    finally:
        broker.close()
    assert validator.calls == [
        "client_read",  # worker bootstrap
        "client_read",
        "client_read",
        "client_read",
    ]


def test_control_plane_does_not_construct_client_repository_or_connection() -> None:
    source = inspect.getsource(scoped_worker)
    assert "FactEventRepository" not in source
    assert "connect_database" not in source


class _TTY(StringIO):
    def isatty(self) -> bool:
        return True


def test_real_review_and_approval_commit_run_through_private_subprocess_pipe(
    tmp_path: Path,
) -> None:
    root = tmp_path / "approved-client-scope"
    (root / "audit").mkdir(parents=True)
    marker = b"p2-approved-scope\n"
    (root / ".scope-id").write_bytes(marker)
    (root / "audit" / "worker.jsonl").write_bytes(b"")
    marker_sha = hashlib.sha256(marker).hexdigest()
    harness = build_approval_harness(root, target_scope_hash=marker_sha)
    harness.clock.value = datetime.now(UTC)
    operation_id = harness.operation_id()
    draft_event_id = harness.ids.object_id("fact_draft")
    session_id = harness.ids.uuid7()
    mutation = AddMutation(
        new_fact=_event(
            event_id=harness.ids.object_id("fact_event"),
            fact_id=harness.ids.object_id("fact"),
            source_session_id=session_id,
            source_turn_id="turn-1",
        )
    )
    now_text = harness.clock.now().isoformat().replace("+00:00", "Z")
    harness.target_connection.execute(
        "INSERT INTO sessions(session_id, client_scope_hash, state, started_at) "
        "VALUES (?, ?, 'OPEN', ?)",
        (session_id, marker_sha, now_text),
    )
    harness.target_connection.execute(
        "INSERT INTO session_fact_events("
        "session_event_id, session_id, turn_id, event_kind, event_json, recorded_at"
        ") VALUES (?, ?, ?, 'ADD', ?, ?)",
        (
            draft_event_id,
            session_id,
            "turn-1",
            canonical_json(mutation.model_dump(mode="json")),
            now_text,
        ),
    )
    validator = _Validator()
    broker = ScopedWorkerBroker(
        scope=WorkerScopeDescriptor(
            scope_root=root,
            global_descriptor_sha256="a" * 64,
            scope_marker_sha256=marker_sha,
            client_id=CLIENT_ID,
        ),
        capability_token="opaque-approved-token",
        validator=validator,
        target_execution_attestor_secret=b"t" * 32,
        target_execution_attestor_id="test-target-writer",
    )
    broker.start()
    try:
        preview = broker.call(
            PreviewFactMutationRequest(
                request_id=REQUEST_ID,
                draft_event_id=draft_event_id,
                base_commit_version=0,
                proposed_operation_id=operation_id,
            )
        )
        assert isinstance(preview, PreviewFactMutationResponse)
        broker.close()
        broker = ScopedWorkerBroker(
            scope=WorkerScopeDescriptor(
                scope_root=root,
                global_descriptor_sha256="a" * 64,
                scope_marker_sha256=marker_sha,
                client_id=CLIENT_ID,
            ),
            capability_token="opaque-approved-token-restarted",
            validator=validator,
            target_execution_attestor_secret=b"t" * 32,
            target_execution_attestor_id="test-target-writer",
        )
        broker.start()
        with pytest.raises(ScopeDenied, match="SCOPE_DENIED"):
            broker.render_verified_review_diff(
                VersionRef(
                    object_id=harness.ids.object_id("mutation_diff"),
                    version=preview.diff_object_ref.version,
                    content_sha256=preview.diff_object_ref.content_sha256,
                )
            )
        broker = ScopedWorkerBroker(
            scope=WorkerScopeDescriptor(
                scope_root=root,
                global_descriptor_sha256="a" * 64,
                scope_marker_sha256=marker_sha,
                client_id=CLIENT_ID,
            ),
            capability_token="opaque-approved-token-review",
            validator=validator,
            target_execution_attestor_secret=b"t" * 32,
            target_execution_attestor_id="test-target-writer",
        )
        broker.start()
        descriptor = DraftDescriptor(
            purpose="profile_update",
            target_id=draft_event_id,
            client_id=CLIENT_ID,
            base_version=preview.base_commit_version,
            draft_sha256=preview.preview_sha256,
            session_id=session_id,
        )
        approval_request = harness.service.request(
            descriptor,
            diff_object_ref=preview.diff_object_ref,
        )
        phrase = f"APPROVE {approval_request.descriptor_sha256[:16]}\n"
        ReviewAgent(
            service=harness.service,
            signer=harness.signer,
            render_verified_diff=broker.render_verified_review_diff,
        ).review(
            approval_request.request_id,
            stdin=_TTY(phrase),
            stdout=StringIO(),
        )
        ticket = harness.service.issue_for_execution(
            approval_request.request_id,
            descriptor,
            operation_id=operation_id,
        )
        result = broker.execute_approved_fact_mutation(
            CommitFactMutationRequest(
                request_id=REQUEST_ID_2,
                draft_event_id=draft_event_id,
                approval_operation_id=operation_id,
                preview_sha256=preview.preview_sha256,
                base_commit_version=preview.base_commit_version,
                expected_runtime_epoch=preview.expected_runtime_epoch,
                publication_timestamp=preview.publication_timestamp,
            ),
            ticket=ticket,
            approval_service=harness.service,
        )
        assert result.new_commit_version == 1
        assert result.runtime_epoch == 1
        assert harness.global_connection.execute(
            "SELECT state FROM approval_receipts WHERE request_id = ?",
            (approval_request.request_id,),
        ).fetchone() == ("ACKNOWLEDGED",)
        assert harness.target_connection.execute(
            "SELECT epoch, state FROM runtime_epochs"
        ).fetchone() == (1, "ACTIVE")
        assert harness.target_connection.execute(
            "SELECT count(*) FROM fact_events"
        ).fetchone() == (1,)
    finally:
        broker.close()
        harness.close()


class _LostAckService:
    def __init__(self, service) -> None:
        self._service = service

    def verify_ticket(self, *args, **kwargs):
        return self._service.verify_ticket(*args, **kwargs)

    def acknowledge(self, _proof):
        raise RuntimeError("simulated lost ACK")


def test_expired_ticket_recovers_only_an_existing_applied_publication(
    tmp_path: Path,
) -> None:
    root = tmp_path / "recovery-client-scope"
    (root / "audit").mkdir(parents=True)
    marker = b"p2-recovery-scope\n"
    (root / ".scope-id").write_bytes(marker)
    (root / "audit" / "worker.jsonl").write_bytes(b"")
    marker_sha = hashlib.sha256(marker).hexdigest()
    harness = build_approval_harness(root, target_scope_hash=marker_sha)
    harness.clock.value = datetime.now(UTC)
    operation_id = harness.operation_id()
    draft_event_id = harness.ids.object_id("fact_draft")
    session_id = harness.ids.uuid7()
    mutation = AddMutation(
        new_fact=_event(
            event_id=harness.ids.object_id("fact_event"),
            fact_id=harness.ids.object_id("fact"),
            source_session_id=session_id,
            source_turn_id="turn-1",
        )
    )
    now_text = harness.clock.now().isoformat().replace("+00:00", "Z")
    harness.target_connection.execute(
        "INSERT INTO sessions(session_id, client_scope_hash, state, started_at) "
        "VALUES (?, ?, 'OPEN', ?)",
        (session_id, marker_sha, now_text),
    )
    harness.target_connection.execute(
        "INSERT INTO session_fact_events("
        "session_event_id, session_id, turn_id, event_kind, event_json, recorded_at"
        ") VALUES (?, ?, 'turn-1', 'ADD', ?, ?)",
        (
            draft_event_id,
            session_id,
            canonical_json(mutation.model_dump(mode="json")),
            now_text,
        ),
    )
    scope = WorkerScopeDescriptor(
        scope_root=root,
        global_descriptor_sha256="a" * 64,
        scope_marker_sha256=marker_sha,
        client_id=CLIENT_ID,
    )

    def new_broker() -> ScopedWorkerBroker:
        worker = ScopedWorkerBroker(
            scope=scope,
            capability_token="opaque-recovery-token",
            validator=_Validator(),
            target_execution_attestor_secret=b"t" * 32,
            target_execution_attestor_id="test-target-writer",
        )
        worker.start()
        return worker

    first = new_broker()
    try:
        preview = first.call(
            PreviewFactMutationRequest(
                request_id=REQUEST_ID,
                draft_event_id=draft_event_id,
                base_commit_version=0,
                proposed_operation_id=operation_id,
            )
        )
        assert isinstance(preview, PreviewFactMutationResponse)
        descriptor = DraftDescriptor(
            purpose="profile_update",
            target_id=draft_event_id,
            client_id=CLIENT_ID,
            base_version=0,
            draft_sha256=preview.preview_sha256,
            session_id=session_id,
        )
        approval_request = harness.service.request(
            descriptor,
            diff_object_ref=preview.diff_object_ref,
        )
        ReviewAgent(
            service=harness.service,
            signer=harness.signer,
            render_verified_diff=first.render_verified_review_diff,
        ).review(
            approval_request.request_id,
            stdin=_TTY(
                f"APPROVE {approval_request.descriptor_sha256[:16]}\n"
            ),
            stdout=StringIO(),
        )
        ticket = harness.service.issue_for_execution(
            approval_request.request_id,
            descriptor,
            operation_id=operation_id,
        )
        commit_request = CommitFactMutationRequest(
            request_id=REQUEST_ID_2,
            draft_event_id=draft_event_id,
            approval_operation_id=operation_id,
            preview_sha256=preview.preview_sha256,
            base_commit_version=0,
            expected_runtime_epoch=preview.expected_runtime_epoch,
            publication_timestamp=preview.publication_timestamp,
        )
        live_clock = harness.clock.value
        harness.clock.value = ticket.receipt.expires_at + timedelta(seconds=1)
        premature_recovery = new_broker()
        try:
            with pytest.raises(ScopeDenied, match="SCOPE_DENIED"):
                premature_recovery.recover_applied_fact_mutation(
                    commit_request,
                    ticket=ticket,
                    approval_service=harness.service,
                )
        finally:
            premature_recovery.close()
            harness.clock.value = live_clock
        with pytest.raises(ScopeDenied, match="SCOPE_DENIED"):
            first.execute_approved_fact_mutation(
                commit_request,
                ticket=ticket,
                approval_service=_LostAckService(harness.service),  # type: ignore[arg-type]
            )
    finally:
        first.close()

    assert harness.target_connection.execute(
        "SELECT state, applied_commit_version FROM approval_executions"
    ).fetchone() == ("APPLIED", 1)
    assert harness.global_connection.execute(
        "SELECT state FROM approval_receipts WHERE request_id = ?",
        (ticket.request_id,),
    ).fetchone() == ("ISSUED",)
    before = (
        harness.target_connection.execute("SELECT count(*) FROM fact_events").fetchone(),
        harness.target_connection.execute("SELECT count(*) FROM runtime_epochs").fetchone(),
    )
    harness.clock.value = ticket.receipt.expires_at + timedelta(seconds=1)
    recovered_worker = new_broker()
    try:
        recovered = recovered_worker.recover_applied_fact_mutation(
            commit_request,
            ticket=ticket,
            approval_service=harness.service,
        )
        assert recovered.new_commit_version == 1
        after = (
            harness.target_connection.execute(
                "SELECT count(*) FROM fact_events"
            ).fetchone(),
            harness.target_connection.execute(
                "SELECT count(*) FROM runtime_epochs"
            ).fetchone(),
        )
        assert after == before
    finally:
        recovered_worker.close()
        harness.close()
