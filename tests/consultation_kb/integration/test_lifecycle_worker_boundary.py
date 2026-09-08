from __future__ import annotations

import hashlib
import itertools
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Literal

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.errors import WorkflowOperationalError
from consultation_kb.core.ids import IdFactory
from consultation_kb.lifecycle.production_rebuild import (
    CONFIG_FILENAME,
    ProductionRebuildConfig,
)
from consultation_kb.models.facts import FactEvent, canonical_json
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.security.scoped_worker import (
    ScopeDenied,
    ScopedWorkerBroker,
    WorkerScopeDescriptor,
)
from consultation_kb.security.worker_main import _client_recovery_coordinator
from consultation_kb.security.worker_protocol import (
    ArchiveContentRef,
    BeginSessionRequest,
    BeginSessionResponse,
    CommitClientTombstoneRequest,
    CommitClientTombstoneResponse,
    CommitClientRollbackRequest,
    CommitClientRollbackResponse,
    PreflightClientLifecycleCommitRequest,
    PreflightClientLifecycleCommitResponse,
    PreviewClientDeleteRequest,
    PreviewClientDeleteResponse,
    PreviewClientRebuildRequest,
    PreviewClientRebuildResponse,
    PreviewClientRollbackRequest,
    PreviewClientRollbackResponse,
    RebuildClientDerivativesRequest,
    RebuildClientDerivativesResponse,
    RecoverClientManifestsRequest,
    RecoverClientManifestsResponse,
    VerifyClientIntegrityRequest,
    VerifyClientIntegrityResponse,
    WorkerBaseVersion,
    encode_message,
)
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.client_ledger import FactEventRepository
from consultation_kb.storage.deletion_inventory import session_authority_sha256
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.approval_support import (
    ApprovalHarness,
    build_approval_harness,
)
from tests.consultation_kb.integration.test_sqlite_recovery import (
    _artifacts as _recovery_artifacts,
    _prepare as _prepare_recovery,
)
from tests.consultation_kb.unit.test_rollback import (
    _fact as _rollback_fact,
    _seed_closure as _seed_rollback_closure,
)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows scoped subprocess"),
]
NOW = datetime(2026, 7, 19, 8, 0, tzinfo=UTC)
CLIENT_ID = "client" + "_aaaaaaaaaaaa"


@dataclass(slots=True)
class _Validator:
    calls: list[str] = field(default_factory=list)

    def assert_valid(
        self,
        _capability_token: str,
        *,
        required_permission: str,
    ) -> None:
        self.calls.append(required_permission)


@dataclass(slots=True)
class _Harness:
    root: Path
    marker_sha256: str
    session_id: str
    ids: IdFactory
    validator: _Validator

    def broker(self) -> ScopedWorkerBroker:
        return ScopedWorkerBroker(
            scope=WorkerScopeDescriptor(
                scope_root=self.root,
                global_descriptor_sha256="f" * 64,
                scope_marker_sha256=self.marker_sha256,
                session_id=self.session_id,
                client_id=CLIENT_ID,
            ),
            capability_token="opaque-lifecycle-capability",
            validator=self.validator,
            target_execution_attestor_secret=b"t" * 32,
            target_execution_attestor_id="test-target-writer",
            startup_timeout_seconds=10.0,
            call_timeout_seconds=10.0,
        )


def _harness(tmp_path: Path) -> _Harness:
    root = tmp_path / "clients" / "opaque-client-root"
    root.mkdir(parents=True)
    (root / "cas").mkdir()
    marker = b"synthetic-lifecycle-scope\n"
    (root / ".scope-id").write_bytes(marker)
    connection = connect_database(root / "client.sqlite3", "writer")
    try:
        MigrationRunner.for_scope(connection, "client").apply()
    finally:
        connection.close()
    ids = IdFactory(FixedClock(NOW), itertools.count(1).__next__)
    return _Harness(
        root=root,
        marker_sha256=hashlib.sha256(marker).hexdigest(),
        session_id=ids.uuid7(),
        ids=ids,
        validator=_Validator(),
    )


def _request_id(harness: _Harness) -> str:
    return harness.ids.uuid7()


def _assert_preflight_preserves_unbound_approval(
    *,
    broker: ScopedWorkerBroker,
    harness: _Harness,
    approval: ApprovalHarness,
    lifecycle_kind: Literal["delete", "rebuild", "rollback"],
    plan_ref: ArchiveContentRef,
    plan_sha256: str,
    base_versions: tuple[WorkerBaseVersion, ...],
    operation_id: str,
    request_id: str,
    rebuild_action: Literal["START", "CANCEL"] | None = None,
    target_scope_hash: str | None = None,
) -> None:
    exact = PreflightClientLifecycleCommitRequest.model_validate(
        {
            "request_id": _request_id(harness),
            "lifecycle_kind": lifecycle_kind,
            "plan_ref": plan_ref,
            "plan_sha256": plan_sha256,
            "base_versions": base_versions,
            "approval_operation_id": operation_id,
            "approval_request_id": request_id,
            "rebuild_action": rebuild_action,
            "target_scope_hash": target_scope_hash,
        }
    )
    assert all(
        value not in encode_message(exact)
        for value in (b"client_id", b"path", b"sql", b"ticket", b"nonce")
    )
    wrong_operation = exact.model_copy(
        update={
            "approval_operation_id": harness.ids.object_id(
                "lifecycle_operation"
            )
        }
    )
    wrong_reference = exact.model_copy(
        update={
            "plan_ref": exact.plan_ref.model_copy(
                update={"size_bytes": exact.plan_ref.size_bytes + 1}
            )
        }
    )
    for invalid in (wrong_operation, wrong_reference):
        with pytest.raises(
            WorkflowOperationalError,
            match="LIFECYCLE_PLAN_MISMATCH",
        ):
            broker.call(invalid)
        assert approval.global_connection.execute(
            "SELECT operation_id FROM approval_receipts WHERE request_id = ?",
            (request_id,),
        ).fetchone() == (None,)

    response = broker.call(exact)
    assert isinstance(response, PreflightClientLifecycleCommitResponse)
    assert response.lifecycle_kind == lifecycle_kind
    assert response.approval_operation_id == operation_id


def _seed_client_fact_authority(harness: _Harness) -> None:
    connection = connect_database(harness.root / "client.sqlite3", "writer")
    try:
        event = FactEvent(
            event_id=harness.ids.object_id("fact_event"),
            fact_id=harness.ids.object_id("fact"),
            client_id=CLIENT_ID,
            event_version=1,
            mutation_type="ADD",
            canonical_key="client|goal|stable_relationship",
            subject="client",
            predicate="goal",
            object_json=canonical_json(
                {"goal": "build_a_stable_relationship"}
            ),
            cognitive_type="external_fact",
            source_kind="controlled_import",
            source_session_id=None,
            source_turn_id=None,
            source_ref="controlled-import",
            effective_from=NOW,
            effective_to=None,
            time_precision="instant",
            timezone_name="Asia/Shanghai",
            recorded_at=NOW,
            approved_at=NOW,
            reported_at=None,
            observed_at=None,
            transaction_id=harness.ids.object_id("transaction"),
            commit_version=1,
            publication_operation_id=harness.ids.object_id(
                "publication_operation"
            ),
            visible_runtime_epoch=1,
            review_status="approved",
            validity_status="active",
            resolution_status="open",
            epistemic_status="asserted",
            fact_confidence=1.0,
            model_confidence=None,
            reviewer_id="primary-counselor",
            review_reason="approved controlled import",
            review_source="primary_counselor",
            privacy_level="private_client",
            allowed_purposes_json=canonical_json(
                ["client_history", "next_session_context"]
            ),
            applicability_json=canonical_json(
                {"scope": "client_private"}
            ),
            source_anchor_json=canonical_json(
                {"source": "controlled-import"}
            ),
            supersedes_event_id=None,
            previous_event_id=None,
            replacement_event_id=None,
            source_event_ids=(),
            relation_type=None,
        )
        FactEventRepository(connection).append(event)
        revision_id = harness.ids.object_id("profile_revision")
        created_at = NOW.isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        )
        connection.execute(
            "INSERT INTO profile_revisions("
            "revision_id, publication_operation_id, source_commit_version, "
            "visible_runtime_epoch, profile_sha256, json_object_id, "
            "markdown_object_id, created_at) VALUES (?, ?, 1, 1, ?, ?, ?, ?)",
            (
                revision_id,
                event.publication_operation_id,
                "a" * 64,
                harness.ids.object_id("profile_json"),
                harness.ids.object_id("profile_markdown"),
                created_at,
            ),
        )
        connection.execute(
            "INSERT INTO profile_members("
            "revision_id, ordinal, section, fact_id, event_id) "
            "VALUES (?, 0, 'goals', ?, ?)",
            (revision_id, event.fact_id, event.event_id),
        )
    finally:
        connection.close()


def _session_authority(harness: _Harness) -> tuple[int, str]:
    connection = connect_database(harness.root / "client.sqlite3", "reader")
    try:
        row = connection.execute(
            "SELECT client_id, client_scope_hash, client_snapshot_version, "
            "client_snapshot_canonical_sha256, started_at, "
            "last_closed_turn_ordinal FROM sessions WHERE session_id = ?",
            (harness.session_id,),
        ).fetchone()
    finally:
        connection.close()
    assert row is not None
    version = int(row[5])
    return version, session_authority_sha256(
        session_id=harness.session_id,
        client_id=str(row[0]),
        client_scope_hash=str(row[1]),
        client_snapshot_version=int(row[2]),
        client_snapshot_canonical_sha256=(
            None if row[3] is None else str(row[3])
        ),
        started_at=str(row[4]),
    )


def test_real_scoped_worker_recovery_delete_rebuild_status_and_integrity(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path)
    broker = harness.broker()
    broker.start()
    try:
        started = broker.call(
            BeginSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                capability_epoch=1,
            )
        )
        assert isinstance(started, BeginSessionResponse)
        recovery_connection = connect_database(
            harness.root / "client.sqlite3",
            "writer",
        )
        try:
            recovery_connection.execute(
                "UPDATE client_fact_authority SET commit_version = 1, "
                "client_id = ? WHERE singleton = 1",
                (CLIENT_ID,),
            )
            _prepare_recovery(
                recovery_connection,
                harness.root / "cas",
                operation_suffix=900,
                version=1,
                expected_epoch=None,
                artifacts=_recovery_artifacts(
                    version=1,
                    suffix_base=900,
                    kinds=("profile",),
                ),
                purpose="profile_update",
            )
        finally:
            recovery_connection.close()
        recovery = broker.call(
            RecoverClientManifestsRequest(
                request_id=_request_id(harness),
                dry_run=True,
            )
        )
        assert isinstance(recovery, RecoverClientManifestsResponse)
        assert recovery.applied_count == 0
        assert recovery.scanned_count == 1
        applied_recovery = broker.call(
            RecoverClientManifestsRequest(
                request_id=_request_id(harness),
                dry_run=False,
            )
        )
        assert isinstance(applied_recovery, RecoverClientManifestsResponse)
        assert applied_recovery.applied_count == 1
        replayed_recovery = broker.call(
            RecoverClientManifestsRequest(
                request_id=_request_id(harness),
                dry_run=False,
            )
        )
        assert isinstance(replayed_recovery, RecoverClientManifestsResponse)
        assert replayed_recovery.applied_count == 0
        integrity = broker.call(
            VerifyClientIntegrityRequest(request_id=_request_id(harness))
        )
        assert isinstance(integrity, VerifyClientIntegrityResponse)
        assert integrity.active_epoch == 1
    finally:
        broker.close()

    target_version, target_sha256 = _session_authority(harness)
    broker = harness.broker()
    broker.start()
    approval = None
    try:
        operation_id = harness.ids.object_id("deletion_operation")
        preview = broker.call(
            PreviewClientDeleteRequest(
                request_id=_request_id(harness),
                target_type="session",
                target_id=harness.session_id,
                target_version=target_version,
                target_content_sha256=target_sha256,
                reason_code="client_request",
                proposed_operation_id=operation_id,
                requested_at=NOW,
            )
        )
        assert isinstance(preview, PreviewClientDeleteResponse)
        approval_root = tmp_path / "approval"
        approval_root.mkdir()
        approval = build_approval_harness(
            approval_root,
            target_scope_hash=preview.target_scope_hash,
        )
        approval.clock.value = datetime.now(UTC)
        descriptor = DraftDescriptor(
            purpose="delete",
            target_id=harness.session_id,
            client_id=CLIENT_ID,
            session_id=harness.session_id,
            base_version=preview.base_deletion_version,
            draft_sha256=preview.plan_sha256,
        )
        requested = approval.service.request(
            descriptor,
            diff_object_ref=preview.plan_ref.version_ref,
        )
        approval.service.confirm(
            approval.signer.confirm(
                approval.service.challenge_for_review(requested.request_id)
            )
        )
        _assert_preflight_preserves_unbound_approval(
            broker=broker,
            harness=harness,
            approval=approval,
            lifecycle_kind="delete",
            plan_ref=preview.plan_ref,
            plan_sha256=preview.plan_sha256,
            base_versions=preview.base_versions,
            operation_id=operation_id,
            request_id=requested.request_id,
            target_scope_hash=preview.target_scope_hash,
        )
        ticket = approval.service.issue_for_execution(
            requested.request_id,
            descriptor,
            operation_id=operation_id,
        )
        commit_request = CommitClientTombstoneRequest(
            request_id=_request_id(harness),
            plan_ref=preview.plan_ref,
            plan_sha256=preview.plan_sha256,
            target_scope_hash=preview.target_scope_hash,
            base_versions=preview.base_versions,
            approval_operation_id=ticket.operation_id,
            approval_request_id=ticket.request_id,
        )
        frame = encode_message(commit_request)
        assert all(
            value not in frame
            for value in (b"client_id", b"path", b"sql", b"ticket", b"nonce")
        )
        with pytest.raises(
            WorkflowOperationalError,
            match="LIFECYCLE_APPROVAL_REQUIRED",
        ):
            broker.call(commit_request)
        committed = broker.execute_approved_archive_operation(
            commit_request,
            ticket=ticket,
            approval_service=approval.service,
        )
        assert isinstance(committed, CommitClientTombstoneResponse)
        assert committed.state == "TOMBSTONED"

        with pytest.raises(
            WorkflowOperationalError,
            match="REBUILD_JOB_NOT_FOUND",
        ):
            broker.call(
                RebuildClientDerivativesRequest(
                    request_id=_request_id(harness),
                    action="STATUS",
                    job_id=harness.ids.object_id("rebuild_job"),
                )
            )
    finally:
        broker.close()
        if approval is not None:
            approval.close()

    assert {"client_read", "session_append", "draft_write", "formal_write"}.issubset(
        set(harness.validator.calls)
    )


def test_real_scoped_worker_runs_signed_production_rebuild_to_success(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path)
    _seed_client_fact_authority(harness)
    config = ProductionRebuildConfig.create_client(
        scope_sha256=harness.marker_sha256
    )
    (harness.root / CONFIG_FILENAME).write_bytes(config.canonical_bytes)
    broker = harness.broker()
    approval = None
    broker.start()
    try:
        started = broker.call(
            BeginSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                capability_epoch=1,
            )
        )
        assert isinstance(started, BeginSessionResponse)

        operation_id = harness.ids.object_id("rebuild_operation")
        preview = broker.call(
            PreviewClientRebuildRequest(
                request_id=_request_id(harness),
                action="start",
                purpose="all",
                proposed_operation_id=operation_id,
                requested_at=NOW,
            )
        )
        assert isinstance(preview, PreviewClientRebuildResponse)

        approval_root = tmp_path / "rebuild-approval"
        approval_root.mkdir()
        approval = build_approval_harness(
            approval_root,
            target_scope_hash=harness.marker_sha256,
        )
        approval.clock.value = datetime.now(UTC)
        descriptor = DraftDescriptor(
            purpose="rebuild",
            target_id="client_rebuild:all",
            client_id=CLIENT_ID,
            session_id=harness.session_id,
            base_version=preview.base_versions[0].version,
            draft_sha256=preview.plan_sha256,
        )
        wrong_approval_root = tmp_path / "wrong-rebuild-approval"
        wrong_approval_root.mkdir()
        wrong_approval = build_approval_harness(
            wrong_approval_root,
            target_scope_hash=harness.marker_sha256,
        )
        try:
            wrong_approval.clock.value = datetime.now(UTC)
            wrong_request = wrong_approval.service.request(
                descriptor,
                diff_object_ref=wrong_approval.diff_object_ref(),
            )
            wrong_approval.service.confirm(
                wrong_approval.signer.confirm(
                    wrong_approval.service.challenge_for_review(
                        wrong_request.request_id
                    )
                )
            )
            wrong_ticket = wrong_approval.service.issue_for_execution(
                wrong_request.request_id,
                descriptor,
                operation_id=operation_id,
            )
            wrong_start = RebuildClientDerivativesRequest(
                request_id=_request_id(harness),
                action="START",
                purpose="all",
                plan_sha256=preview.plan_sha256,
                base_versions=preview.base_versions,
                idempotency_key="worker-rebuild-wrong-diff",
                approval_operation_id=wrong_ticket.operation_id,
                approval_request_id=wrong_ticket.request_id,
                plan_ref=preview.plan_ref,
            )
            with pytest.raises(ScopeDenied):
                broker.execute_approved_archive_operation(
                    wrong_start,
                    ticket=wrong_ticket,
                    approval_service=wrong_approval.service,
                )
        finally:
            wrong_approval.close()
        broker.close()
        broker = harness.broker()
        broker.start()

        requested = approval.service.request(
            descriptor,
            diff_object_ref=preview.plan_ref.version_ref,
        )
        approval.service.confirm(
            approval.signer.confirm(
                approval.service.challenge_for_review(requested.request_id)
            )
        )
        _assert_preflight_preserves_unbound_approval(
            broker=broker,
            harness=harness,
            approval=approval,
            lifecycle_kind="rebuild",
            plan_ref=preview.plan_ref,
            plan_sha256=preview.plan_sha256,
            base_versions=preview.base_versions,
            operation_id=operation_id,
            request_id=requested.request_id,
            rebuild_action="START",
        )
        ticket = approval.service.issue_for_execution(
            requested.request_id,
            descriptor,
            operation_id=operation_id,
        )
        request = RebuildClientDerivativesRequest(
            request_id=_request_id(harness),
            action="START",
            purpose="all",
            plan_sha256=preview.plan_sha256,
            base_versions=preview.base_versions,
            idempotency_key="worker-production-rebuild-all-v1",
            approval_operation_id=ticket.operation_id,
            approval_request_id=ticket.request_id,
            plan_ref=preview.plan_ref,
        )
        frame = encode_message(request)
        assert all(
            value not in frame
            for value in (b"client_id", b"path", b"sql", b"ticket", b"nonce")
        )
        with pytest.raises(
            WorkflowOperationalError,
            match="LIFECYCLE_APPROVAL_REQUIRED",
        ):
            broker.call(request)
        queued = broker.execute_approved_archive_operation(
            request,
            ticket=ticket,
            approval_service=approval.service,
        )
        assert isinstance(queued, RebuildClientDerivativesResponse)
        assert queued.state == "queued"

        deadline = time.monotonic() + 10.0
        status = queued
        while status.state not in {"succeeded", "failed", "cancelled"}:
            if time.monotonic() >= deadline:
                pytest.fail("production rebuild did not reach a terminal state")
            time.sleep(0.02)
            response = broker.call(
                RebuildClientDerivativesRequest(
                    request_id=_request_id(harness),
                    action="STATUS",
                    job_id=queued.job_id,
                )
            )
            assert isinstance(response, RebuildClientDerivativesResponse)
            status = response

        assert status.state == "succeeded", status.last_error_code
        assert status.output_manifest_set_sha256 is not None
        assert status.equivalence_report_sha256 is not None
        assert status.report_sha256 is not None
        integrity = broker.call(
            VerifyClientIntegrityRequest(request_id=_request_id(harness))
        )
        assert isinstance(integrity, VerifyClientIntegrityResponse)
        assert integrity.active_epoch == preview.base_versions[0].version + 1
        assert integrity.artifact_count == 4
        connection = connect_database(
            harness.root / "client.sqlite3",
            "reader",
        )
        try:
            assert connection.execute(
                "SELECT request_id, plan_object_id, plan_content_sha256 "
                "FROM lifecycle_approval_attestations "
                "WHERE operation_id = ?",
                (operation_id,),
            ).fetchone() == (
                ticket.request_id,
                preview.plan_ref.object_id,
                preview.plan_ref.content_sha256,
            )
        finally:
            connection.close()
    finally:
        broker.close()
        if approval is not None:
            approval.close()


def test_real_scoped_worker_artifact_rollback_is_exact_and_restart_safe(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path)
    connection = connect_database(harness.root / "client.sqlite3", "writer")
    try:
        seed = SimpleNamespace(ids=harness.ids, target_connection=connection)
        restore = _rollback_fact(
            seed,  # type: ignore[arg-type]
            version=1,
            value="partner-a",
            previous=None,
        )
        current = _rollback_fact(
            seed,  # type: ignore[arg-type]
            version=2,
            value="partner-b",
            previous=restore,
        )
        facts = FactEventRepository(connection)
        facts.append(restore)
        facts.append(current)
        store = ContentStore(harness.root / "cas")
        _seed_rollback_closure(
            seed,  # type: ignore[arg-type]
            store,
            source_version=1,
            epoch=1,
            state="RETIRED",
            fact_events=(restore,),
        )
        connection.execute(
            "INSERT INTO recovery_epoch_retention_windows("
            "epoch, rollback_expires_at, retention_required, "
            "binding_origin, bound_at) "
            "VALUES (1, '2099-01-01T00:00:00.000000Z', 1, "
            "'EXPLICIT', ?)",
            (NOW.isoformat(),),
        )
        _seed_rollback_closure(
            seed,  # type: ignore[arg-type]
            store,
            source_version=2,
            epoch=2,
            state="ACTIVE",
            fact_events=(restore, current),
        )
    finally:
        connection.close()
    config = ProductionRebuildConfig.create_client(
        scope_sha256=harness.marker_sha256
    )
    (harness.root / CONFIG_FILENAME).write_bytes(config.canonical_bytes)
    recovery = _client_recovery_coordinator(
        harness.root,
        harness.marker_sha256,
    )
    recovery_report = recovery.recover()
    assert recovery_report.scan.query_ready, recovery_report.scan.model_dump_json()

    broker = harness.broker()
    approval = None
    reason = "restore the reviewed source and rebuild the complete closure"
    broker.start()
    try:
        source = broker.call(
            PreviewClientRollbackRequest(
                request_id=_request_id(harness),
                rollback_kind="profile_fact",
                target_id=current.fact_id,
                current_version=2,
                restore_version=1,
                reason=reason,
            )
        )
        assert isinstance(source, PreviewClientRollbackResponse)
        artifact = broker.call(
            PreviewClientRollbackRequest(
                request_id=_request_id(harness),
                rollback_kind="artifact",
                target_id="client_profile",
                current_version=2,
                restore_version=1,
                reason=reason,
                source_plan_ref=source.plan_ref,
            )
        )
        assert isinstance(artifact, PreviewClientRollbackResponse)
        assert artifact.rollback_kind == "artifact"

        approval_root = tmp_path / "rollback-approval"
        approval_root.mkdir()
        approval = build_approval_harness(
            approval_root,
            target_scope_hash=harness.marker_sha256,
        )
        approval.clock.value = datetime.now(UTC)
        descriptor = DraftDescriptor(
            purpose="rollback",
            target_id="client_profile",
            client_id=CLIENT_ID,
            session_id=harness.session_id,
            base_version=2,
            draft_sha256=artifact.plan_sha256,
        )
        requested = approval.service.request(
            descriptor,
            diff_object_ref=artifact.plan_ref.version_ref,
        )
        approval.service.confirm(
            approval.signer.confirm(
                approval.service.challenge_for_review(requested.request_id)
            )
        )
        _assert_preflight_preserves_unbound_approval(
            broker=broker,
            harness=harness,
            approval=approval,
            lifecycle_kind="rollback",
            plan_ref=artifact.plan_ref,
            plan_sha256=artifact.plan_sha256,
            base_versions=artifact.base_versions,
            operation_id=artifact.proposed_operation_id,
            request_id=requested.request_id,
        )
        ticket = approval.service.issue_for_execution(
            requested.request_id,
            descriptor,
            operation_id=artifact.proposed_operation_id,
        )
        commit_request = CommitClientRollbackRequest(
            request_id=_request_id(harness),
            plan_ref=artifact.plan_ref,
            plan_sha256=artifact.plan_sha256,
            base_versions=artifact.base_versions,
            approval_operation_id=ticket.operation_id,
            approval_request_id=ticket.request_id,
        )
        frame = encode_message(commit_request)
        assert all(
            value not in frame
            for value in (b"client_id", b"path", b"sql", b"ticket", b"nonce")
        )
        with pytest.raises(
            WorkflowOperationalError,
            match="LIFECYCLE_APPROVAL_REQUIRED",
        ):
            broker.call(commit_request)
        committed = broker.execute_approved_archive_operation(
            commit_request,
            ticket=ticket,
            approval_service=approval.service,
        )
        assert isinstance(committed, CommitClientRollbackResponse)
        assert committed.rollback_kind == "artifact"
        assert committed.requires_combined_publication is False
        assert committed.rebuild_job_id is not None

        deadline = time.monotonic() + 10.0
        while True:
            status = broker.call(
                RebuildClientDerivativesRequest(
                    request_id=_request_id(harness),
                    action="STATUS",
                    job_id=committed.rebuild_job_id,
                )
            )
            assert isinstance(status, RebuildClientDerivativesResponse)
            if status.state in {"succeeded", "failed", "cancelled"}:
                break
            if time.monotonic() >= deadline:
                pytest.fail(
                    "rollback rebuild did not reach a terminal state: "
                    f"{status.state}/{status.last_error_code}"
                )
            time.sleep(0.05)
        assert status.state == "succeeded", status.last_error_code

        broker.close()
        broker = harness.broker()
        broker.start()
        replay = broker.recover_applied_archive_operation(
            commit_request,
            ticket=ticket,
            approval_service=approval.service,
        )
        assert replay == committed
    finally:
        broker.close()
        if approval is not None:
            approval.close()

    connection = connect_database(harness.root / "client.sqlite3", "reader")
    try:
        latest = FactEventRepository(connection).get_latest_event(current.fact_id)
        assert latest.object_json == restore.object_json
        assert connection.execute(
            "SELECT count(*) FROM fact_events"
        ).fetchone() == (3,)
        assert connection.execute(
            "SELECT count(*) FROM rebuild_jobs WHERE purpose = 'all'"
        ).fetchone() == (1,)
    finally:
        connection.close()

    assert {"client_read", "draft_write", "formal_write"}.issubset(
        set(harness.validator.calls)
    )
