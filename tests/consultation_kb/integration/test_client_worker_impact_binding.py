from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest

from consultation_kb.models.facts import SupersedeMutation, canonical_json
from consultation_kb.security.scoped_worker import (
    ScopeDenied,
    ScopedWorkerBroker,
    WorkerScopeDescriptor,
)
from consultation_kb.security.worker_protocol import (
    PreviewDependencyImpactRequest,
    PreviewDependencyImpactResponse,
    PreviewFactMutationRequest,
    PreviewFactMutationResponse,
)
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
    def assert_valid(self, _token: str, *, required_permission: str) -> None:
        assert required_permission in {"client_read", "draft_write"}


def test_impact_lookup_is_bound_to_exact_operation_and_diff_reference(
    tmp_path: Path,
) -> None:
    root = tmp_path / "impact-binding"
    (root / "audit").mkdir(parents=True)
    marker = b"impact-binding\n"
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
    original = _event(
        event_id=harness.ids.object_id("fact_event"),
        fact_id=harness.ids.object_id("fact"),
        source_session_id=session_id,
        source_turn_id=turn_id,
    )
    FactEventRepository(harness.target_connection).append_batch(
        base_commit_version=0,
        events=(original,),
    )
    replacement = _event(
        event_id=harness.ids.object_id("fact_event"),
        fact_id=harness.ids.object_id("fact"),
        canonical_key="replacement",
        object_json='"replacement"',
        source_session_id=session_id,
        source_turn_id=turn_id,
        commit_version=2,
    )
    mutation = SupersedeMutation(
        target_event_id=original.event_id,
        replacement=replacement,
        effective_at=original.effective_from,
        reason="exact impact binding",
    )
    draft_event_id = harness.ids.object_id("fact_draft")
    harness.target_connection.execute(
        "INSERT INTO session_fact_events("
        "session_event_id, session_id, turn_id, event_kind, event_json, recorded_at"
        ") VALUES (?, ?, ?, 'SUPERSEDE', ?, ?)",
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
        capability_token="impact-binding-token",
        validator=_Validator(),
        target_execution_attestor_secret=b"t" * 32,
        target_execution_attestor_id="test-target-writer",
    )
    broker.start()
    try:
        previews: list[PreviewFactMutationResponse] = []
        for _index in range(2):
            response = broker.call(
                PreviewFactMutationRequest(
                    request_id=harness.ids.uuid7(),
                    draft_event_id=draft_event_id,
                    base_commit_version=1,
                    proposed_operation_id=harness.operation_id(),
                )
            )
            assert isinstance(response, PreviewFactMutationResponse)
            previews.append(response)
        exact = broker.call(
            PreviewDependencyImpactRequest(
                request_id=harness.ids.uuid7(),
                draft_event_id=draft_event_id,
                preview_sha256=previews[0].preview_sha256,
                publication_operation_id=previews[0].publication_operation_id,
                diff_object_ref=previews[0].diff_object_ref,
            )
        )
        assert isinstance(exact, PreviewDependencyImpactResponse)
        with pytest.raises(ScopeDenied, match="SCOPE_DENIED"):
            broker.call(
                PreviewDependencyImpactRequest(
                    request_id=harness.ids.uuid7(),
                    draft_event_id=draft_event_id,
                    preview_sha256=previews[0].preview_sha256,
                    publication_operation_id=previews[1].publication_operation_id,
                    diff_object_ref=previews[0].diff_object_ref,
                )
            )
        assert harness.target_connection.execute(
            "SELECT count(*) FROM review_diff_objects"
        ).fetchone() == (2,)
        assert harness.target_connection.execute(
            "SELECT commit_version FROM client_fact_authority"
        ).fetchone() == (1,)
    finally:
        broker.close()
        harness.close()
