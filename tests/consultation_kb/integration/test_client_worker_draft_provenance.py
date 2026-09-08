from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import pytest

from consultation_kb.models.facts import (
    AddMutation,
    MergeMutation,
    SupersedeMutation,
    canonical_json,
)
from consultation_kb.security.scoped_worker import (
    ScopeDenied,
    ScopedWorkerBroker,
    WorkerScopeDescriptor,
)
from consultation_kb.security.worker_protocol import PreviewFactMutationRequest
from consultation_kb.storage.client_ledger import FactEventRepository
from tests.consultation_kb.approval_support import build_approval_harness
from tests.consultation_kb.unit.test_fact_schema import CLIENT_ID, _event


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows scoped worker"),
]
UTC = timezone.utc


@dataclass
class _Validator:
    calls: list[str] = field(default_factory=list)

    def assert_valid(self, _token: str, *, required_permission: str) -> None:
        self.calls.append(required_permission)


@pytest.mark.parametrize("attack", ["forged_session", "forged_import", "cross_client"])
def test_worker_rejects_unbound_draft_provenance_without_writes(
    tmp_path: Path,
    attack: str,
) -> None:
    root = tmp_path / attack
    (root / "audit").mkdir(parents=True)
    marker = f"{attack}\n".encode()
    (root / ".scope-id").write_bytes(marker)
    (root / "audit" / "worker.jsonl").write_bytes(b"")
    marker_sha = hashlib.sha256(marker).hexdigest()
    harness = build_approval_harness(root, target_scope_hash=marker_sha)
    harness.clock.value = datetime.now(UTC)
    session_id = harness.ids.uuid7()
    turn_id = "turn-1"
    harness.target_connection.execute(
        "INSERT INTO sessions(session_id, client_scope_hash, state, started_at) "
        "VALUES (?, ?, 'OPEN', ?)",
        (
            session_id,
            marker_sha,
            harness.clock.now().isoformat().replace("+00:00", "Z"),
        ),
    )
    changes: dict[str, object] = {
        "event_id": harness.ids.object_id("fact_event"),
        "fact_id": harness.ids.object_id("fact"),
        "source_session_id": session_id,
        "source_turn_id": turn_id,
    }
    if attack == "forged_session":
        changes["source_session_id"] = harness.ids.uuid7()
    elif attack == "forged_import":
        changes.update(
            {
                "cognitive_type": "external_fact",
                "source_kind": "controlled_import",
                "source_session_id": None,
                "source_turn_id": None,
                "source_ref": "forged-unregistered-source",
                "reported_at": None,
                "observed_at": None,
            }
        )
    else:
        changes["client_id"] = "client_" + "b" * 12
    mutation = AddMutation(new_fact=_event(**changes))
    draft_event_id = harness.ids.object_id("fact_draft")
    harness.target_connection.execute(
        "INSERT INTO session_fact_events("
        "session_event_id, session_id, turn_id, event_kind, event_json, recorded_at"
        ") VALUES (?, ?, ?, 'ADD', ?, ?)",
        (
            draft_event_id,
            session_id,
            turn_id,
            canonical_json(mutation.model_dump(mode="json")),
            harness.clock.now().isoformat().replace("+00:00", "Z"),
        ),
    )
    broker = ScopedWorkerBroker(
        scope=WorkerScopeDescriptor(
            scope_root=root,
            global_descriptor_sha256="a" * 64,
            scope_marker_sha256=marker_sha,
            client_id=CLIENT_ID,
        ),
        capability_token="provenance-attack-token",
        validator=_Validator(),
        target_execution_attestor_secret=b"t" * 32,
        target_execution_attestor_id="test-target-writer",
    )
    broker.start()
    try:
        with pytest.raises(ScopeDenied, match="SCOPE_DENIED"):
            broker.call(
                PreviewFactMutationRequest(
                    request_id=harness.ids.uuid7(),
                    draft_event_id=draft_event_id,
                    base_commit_version=0,
                    proposed_operation_id=harness.operation_id(),
                )
            )
        assert harness.target_connection.execute(
            "SELECT count(*) FROM review_diff_objects"
        ).fetchone() == (0,)
        assert harness.target_connection.execute(
            "SELECT count(*) FROM fact_events"
        ).fetchone() == (0,)
        assert harness.target_connection.execute(
            "SELECT commit_version, client_id FROM client_fact_authority"
        ).fetchone() == (0, None)
    finally:
        broker.close()
        harness.close()


@pytest.mark.parametrize("operation", ["SUPERSEDE", "MERGE"])
def test_worker_rejects_cross_client_composite_mutation_without_writes(
    tmp_path: Path,
    operation: str,
) -> None:
    root = tmp_path / operation.lower()
    (root / "audit").mkdir(parents=True)
    marker = f"{operation}\n".encode()
    (root / ".scope-id").write_bytes(marker)
    (root / "audit" / "worker.jsonl").write_bytes(b"")
    marker_sha = hashlib.sha256(marker).hexdigest()
    harness = build_approval_harness(root, target_scope_hash=marker_sha)
    harness.clock.value = datetime.now(UTC)
    session_id = harness.ids.uuid7()
    turn_id = "turn-1"
    harness.target_connection.execute(
        "INSERT INTO sessions(session_id, client_scope_hash, state, started_at) "
        "VALUES (?, ?, 'OPEN', ?)",
        (
            session_id,
            marker_sha,
            harness.clock.now().isoformat().replace("+00:00", "Z"),
        ),
    )
    first = _event(
        event_id=harness.ids.object_id("fact_event"),
        fact_id=harness.ids.object_id("fact"),
        source_session_id=session_id,
        source_turn_id=turn_id,
    )
    existing = (first,)
    if operation == "MERGE":
        second = _event(
            event_id=harness.ids.object_id("fact_event"),
            fact_id=harness.ids.object_id("fact"),
            canonical_key="second",
            source_session_id=session_id,
            source_turn_id=turn_id,
        )
        existing = (first, second)
        mutation = MergeMutation(
            member_event_ids=(first.event_id, second.event_id),
            canonical_projection=_event(
                event_id=harness.ids.object_id("fact_event"),
                fact_id=harness.ids.object_id("fact"),
                client_id="client_" + "b" * 12,
                canonical_key="cross-client-merge",
                source_session_id=session_id,
                source_turn_id=turn_id,
                source_event_ids=(first.event_id, second.event_id),
            ),
            no_conflict_proof="forged cross-client projection",
            reason="must fail at worker boundary",
        )
    else:
        mutation = SupersedeMutation(
            target_event_id=first.event_id,
            replacement=_event(
                event_id=harness.ids.object_id("fact_event"),
                fact_id=harness.ids.object_id("fact"),
                client_id="client_" + "b" * 12,
                canonical_key="cross-client-replacement",
                source_session_id=session_id,
                source_turn_id=turn_id,
            ),
            effective_at=first.effective_from,
            reason="must fail at worker boundary",
        )
    repository = FactEventRepository(harness.target_connection)
    repository.append_batch(base_commit_version=0, events=existing)
    draft_event_id = harness.ids.object_id("fact_draft")
    harness.target_connection.execute(
        "INSERT INTO session_fact_events("
        "session_event_id, session_id, turn_id, event_kind, event_json, recorded_at"
        ") VALUES (?, ?, ?, ?, ?, ?)",
        (
            draft_event_id,
            session_id,
            turn_id,
            operation,
            canonical_json(mutation.model_dump(mode="json")),
            harness.clock.now().isoformat().replace("+00:00", "Z"),
        ),
    )
    broker = ScopedWorkerBroker(
        scope=WorkerScopeDescriptor(
            scope_root=root,
            global_descriptor_sha256="a" * 64,
            scope_marker_sha256=marker_sha,
            client_id=CLIENT_ID,
        ),
        capability_token="cross-client-composite-token",
        validator=_Validator(),
        target_execution_attestor_secret=b"t" * 32,
        target_execution_attestor_id="test-target-writer",
    )
    broker.start()
    try:
        with pytest.raises(ScopeDenied, match="SCOPE_DENIED"):
            broker.call(
                PreviewFactMutationRequest(
                    request_id=harness.ids.uuid7(),
                    draft_event_id=draft_event_id,
                    base_commit_version=1,
                    proposed_operation_id=harness.operation_id(),
                )
            )
        assert harness.target_connection.execute(
            "SELECT count(*) FROM review_diff_objects"
        ).fetchone() == (0,)
        assert repository.current_commit_version() == 1
        assert len(repository.list_events()) == len(existing)
    finally:
        broker.close()
        harness.close()
