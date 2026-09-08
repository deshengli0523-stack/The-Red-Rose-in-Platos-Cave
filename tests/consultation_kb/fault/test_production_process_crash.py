from __future__ import annotations

import json
import os
import pickle
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from consultation_kb.client.publication import ClientPublicationPlanner
from consultation_kb.lifecycle.fault_points import (
    APPROVAL_EXECUTION_FAULT_POINTS,
    MANIFEST_PUBLICATION_FAULT_POINTS,
    OUTBOX_SAGA_FAULT_POINTS,
)
from consultation_kb.models.facts import AddMutation
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.approval_support import build_approval_harness
from tests.consultation_kb.fault.test_manifest_process_crash import (
    _FAULT_ENV,
    _arm,
    _python,
    _repo_root,
)
from tests.consultation_kb.integration.test_case_publish_saga import _package
from tests.consultation_kb.unit.test_fact_schema import _event


pytestmark = [
    pytest.mark.fault,
    pytest.mark.acceptance_id("TX-01"),
]


@dataclass(frozen=True, slots=True)
class _ProcessResult:
    returncode: int
    stdout: str
    stderr: str


def _worker() -> Path:
    return Path(__file__).with_name("production_fault_worker.py").resolve()


def _run(
    *,
    scenario: str,
    vault: Path,
    control: Path,
    fault_point: str | None,
) -> _ProcessResult:
    environment = os.environ.copy()
    environment.pop(_FAULT_ENV, None)
    if fault_point is not None:
        environment[_FAULT_ENV] = fault_point
    process = subprocess.Popen(
        [
            str(_python()),
            str(_worker()),
            "--scenario",
            scenario,
            "--vault",
            str(vault),
            "--control",
            str(control),
            "--test-mode",
        ],
        cwd=_repo_root(),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = process.communicate(timeout=45)
    return _ProcessResult(process.returncode, stdout, stderr)


def _dump_config(vault: Path, value: object) -> None:
    with (vault / "production-fault.pkl").open("wb") as handle:
        pickle.dump(value, handle, protocol=pickle.HIGHEST_PROTOCOL)


def _assert_database_closed(path: Path) -> None:
    assert not path.with_name(path.name + "-wal").exists()
    assert not path.with_name(path.name + "-shm").exists()


def _client_fixture(vault: Path) -> None:
    _arm(vault)
    harness = build_approval_harness(vault)
    try:
        plan = ClientPublicationPlanner(harness.target_connection).prepare(
            AddMutation(
                new_fact=_event(
                    event_id=harness.ids.object_id("fact_event"),
                    fact_id=harness.ids.object_id("fact"),
                )
            ),
            draft_event_id=harness.ids.object_id("fact_draft"),
            operation_id=harness.operation_id(),
            expected_runtime_epoch=1,
            publication_timestamp=harness.clock.now(),
        )
        request = harness.service.request(
            plan.descriptor,
            diff_object_ref=harness.diff_object_ref(),
        )
        harness.service.confirm(
            harness.signer.confirm(
                harness.service.challenge_for_review(request.request_id)
            )
        )
        ticket = harness.service.issue_for_execution(
            request.request_id,
            plan.descriptor,
            operation_id=plan.operation_id,
        )
        _dump_config(
            vault,
            {"plan": plan, "ticket": ticket, "now": harness.clock.now()},
        )
    finally:
        harness.close()


def _case_fixture(vault: Path) -> None:
    _arm(vault)
    event, transfer, now = _package()
    event = event.model_copy(
        update={"state": "PENDING", "attempt_count": 0}
    )
    source = connect_database(vault / "source.sqlite3", mode="writer")
    global_connection = connect_database(vault / "global.sqlite3", mode="writer")
    try:
        MigrationRunner.for_scope(source, "client").apply()
        MigrationRunner.for_scope(global_connection, "global").apply()
        session_id = "production-fault-session"
        timestamp = now.isoformat(timespec="microseconds").replace("+00:00", "Z")
        source.execute(
            "INSERT INTO sessions(session_id, client_scope_hash, state, started_at) "
            "VALUES (?, ?, 'ARCHIVED', ?)",
            (session_id, "a" * 64, timestamp),
        )
        source.execute(
            "INSERT INTO archive_bundles("
            "bundle_id, session_id, actual_transcript_object_id, "
            "actual_transcript_sha256, actual_transcript_media_type, "
            "actual_transcript_size_bytes, incomplete_evidence, created_at"
            ") VALUES (?, ?, ?, ?, 'application/json', 1, 0, ?)",
            (
                event.bundle_id,
                session_id,
                "production-fault-transcript",
                "b" * 64,
                timestamp,
            ),
        )
        payload = transfer.outbox_payload
        source.execute(
            "INSERT INTO approval_executions("
            "operation_id, request_id, descriptor_sha256, draft_sha256, "
            "descriptor_base_version, target_scope_hash, nonce_sha256, "
            "state, applied_commit_version, applied_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, 'CLAIMED', NULL, NULL)",
            (
                payload.approval_operation_id,
                payload.approval_request_id,
                payload.approval_descriptor_sha256,
                payload.approval_draft_sha256,
                payload.candidate_ref.version,
                payload.approval_target_scope_hash,
                "c" * 64,
            ),
        )
        source.execute(
            "UPDATE approval_executions SET state = 'APPLIED', "
            "applied_commit_version = 1, applied_at = ? "
            "WHERE operation_id = ? AND state = 'CLAIMED'",
            (timestamp, payload.approval_operation_id),
        )
        source.execute(
            "INSERT INTO outbox_events("
            "event_id, bundle_id, event_type, idempotency_key, "
            "payload_object_id, payload_sha256, payload_media_type, "
            "payload_size_bytes, state, attempt_count, published_global_version, "
            "last_error_code, created_at, updated_at"
            ") VALUES (?, ?, 'shared_case_publish', ?, ?, ?, ?, ?, "
            "'PENDING', 0, NULL, NULL, ?, ?)",
            (
                event.event_id,
                event.bundle_id,
                event.idempotency_key,
                event.payload.object_id,
                event.payload.content_sha256,
                event.payload.media_type,
                event.payload.size_bytes,
                timestamp,
                timestamp,
            ),
        )
        _dump_config(vault, {"event": event, "transfer": transfer, "now": now})
    finally:
        global_connection.close()
        source.close()


@pytest.mark.parametrize(
    "fault_point",
    (*APPROVAL_EXECUTION_FAULT_POINTS, *MANIFEST_PUBLICATION_FAULT_POINTS),
)
def test_real_client_executor_crash_recovers_exact_closure_once(
    tmp_path: Path,
    fault_point: str,
) -> None:
    vault = tmp_path / f"production-client-{fault_point}"
    control = tmp_path / f"production-client-{fault_point}.json"
    _client_fixture(vault)

    crashed = _run(
        scenario="client",
        vault=vault,
        control=control,
        fault_point=fault_point,
    )
    assert crashed.returncode == 137, crashed.stderr
    assert crashed.stdout == ""

    crashed_connection = sqlite3.connect(vault / "client.sqlite3")
    try:
        approval_count = crashed_connection.execute(
            "SELECT count(*) FROM approval_executions"
        ).fetchone()[0]
        fact_count = crashed_connection.execute(
            "SELECT count(*) FROM fact_events"
        ).fetchone()[0]
        operation_state = crashed_connection.execute(
            "SELECT state FROM publication_operations"
        ).fetchone()
        active_epoch = crashed_connection.execute(
            "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
        ).fetchone()
        if fault_point in {
            "after_stage_write",
            "after_file_fsync",
            "after_approval_claim",
            "before_target_commit",
            "before_prepared_tx",
            "after_prepared_tx",
        }:
            assert (approval_count, fact_count, operation_state, active_epoch) == (
                0,
                0,
                None,
                None,
            )
        elif fault_point == "after_target_commit_before_ack":
            assert (approval_count, fact_count, operation_state, active_epoch) == (
                1,
                1,
                ("PREPARED",),
                None,
            )
        elif fault_point in {"after_verify", "before_active_tx"}:
            assert (approval_count, fact_count, operation_state, active_epoch) == (
                1,
                1,
                ("VERIFIED",),
                None,
            )
        else:
            assert (approval_count, fact_count, operation_state, active_epoch) == (
                1,
                1,
                ("ACTIVE",),
                (1,),
            )
    finally:
        crashed_connection.close()

    results: list[dict[str, object]] = []
    for _ in range(3):
        recovered = _run(
            scenario="client",
            vault=vault,
            control=control,
            fault_point=None,
        )
        assert recovered.returncode == 0, recovered.stderr
        assert recovered.stdout == ""
        results.append(json.loads(control.read_text(encoding="ascii")))
    assert results[0] == results[1] == results[2]
    assert results[0] == {
        "active_artifacts": 3,
        "approval_rows": 1,
        "approval_states": ["APPLIED"],
        "fact_events": 1,
        "manifests": 3,
        "profile_revisions": 1,
        "publication_rows": 1,
        "publication_states": ["ACTIVE"],
        "runtime_epochs": [[1, "ACTIVE"]],
    }
    connection = sqlite3.connect(vault / "client.sqlite3")
    try:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute(
            "SELECT count(DISTINCT epoch) FROM active_artifacts"
        ).fetchone() == (1,)
        store = ContentStore(vault / "cas")
        for digest, media_type, size_bytes in connection.execute(
            "SELECT object_sha256, media_type, size_bytes FROM artifact_members"
        ).fetchall():
            reference = store.reference(
                content_sha256=str(digest),
                media_type=str(media_type),
                size_bytes=int(size_bytes),
            )
            assert store.read_verified(reference)
    finally:
        connection.close()
    _assert_database_closed(vault / "client.sqlite3")


@pytest.mark.parametrize("fault_point", OUTBOX_SAGA_FAULT_POINTS)
def test_real_case_outbox_and_global_publisher_recover_without_duplicate_writes(
    tmp_path: Path,
    fault_point: str,
) -> None:
    vault = tmp_path / f"production-case-{fault_point}"
    control = tmp_path / f"production-case-{fault_point}.json"
    _case_fixture(vault)

    crashed = _run(
        scenario="case",
        vault=vault,
        control=control,
        fault_point=fault_point,
    )
    assert crashed.returncode == 137, crashed.stderr
    assert crashed.stdout == ""

    source = sqlite3.connect(vault / "source.sqlite3")
    global_connection = sqlite3.connect(vault / "global.sqlite3")
    try:
        source_state = source.execute(
            "SELECT state, attempt_count FROM outbox_events"
        ).fetchone()
        saga_state = global_connection.execute(
            "SELECT state FROM global_publish_sagas"
        ).fetchone()
        before_recovery = (
            global_connection.execute("SELECT count(*) FROM cases").fetchone()[0],
            global_connection.execute("SELECT count(*) FROM case_versions").fetchone()[0],
            global_connection.execute(
                "SELECT count(*) FROM global_publish_sagas"
            ).fetchone()[0],
        )
        if fault_point == "after_source_outbox":
            assert source_state == ("PENDING", 0)
            assert saga_state is None
            assert before_recovery == (0, 0, 0)
        elif fault_point == "after_global_copy":
            assert source_state == ("CLAIMED", 1)
            assert saga_state == ("COPIED",)
            assert before_recovery == (0, 0, 1)
        elif fault_point == "after_global_prepare":
            assert source_state == ("CLAIMED", 1)
            assert saga_state == ("PREPARED",)
            assert before_recovery == (1, 1, 1)
            assert global_connection.execute(
                "SELECT count(*) FROM case_versions WHERE state = 'ACTIVE'"
            ).fetchone() == (0,)
            assert global_connection.execute(
                "SELECT count(*) FROM runtime_epochs WHERE state = 'ACTIVE'"
            ).fetchone() == (0,)
        else:
            assert source_state == ("CLAIMED", 1)
            assert saga_state == ("ACTIVE",)
            assert before_recovery == (1, 1, 1)
    finally:
        global_connection.close()
        source.close()

    results: list[dict[str, object]] = []
    for _ in range(3):
        recovered = _run(
            scenario="case",
            vault=vault,
            control=control,
            fault_point=None,
        )
        assert recovered.returncode == 0, recovered.stderr
        assert recovered.stdout == ""
        results.append(json.loads(control.read_text(encoding="ascii")))
    assert results[0] == results[1] == results[2]
    assert results[0] == {
        "active_artifacts": 0,
        "active_case_versions": 1,
        "case_versions": 1,
        "cases": 1,
        "runtime_epochs": [],
        "sagas": [["ACTIVE"]],
        "source": [["PUBLISHED", 1, 1]],
    }
    if fault_point in {"after_global_activate", "before_source_ack"}:
        assert before_recovery == (1, 1, 1)

    source = sqlite3.connect(vault / "source.sqlite3")
    global_connection = sqlite3.connect(vault / "global.sqlite3")
    try:
        assert source.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert source.execute("PRAGMA foreign_key_check").fetchall() == []
        assert global_connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert global_connection.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        global_connection.close()
        source.close()
    _assert_database_closed(vault / "source.sqlite3")
    _assert_database_closed(vault / "global.sqlite3")
