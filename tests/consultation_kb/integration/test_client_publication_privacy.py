from __future__ import annotations

from pathlib import Path

import pytest

from consultation_kb.client.publication import ClientPublicationPlanner
from consultation_kb.models.facts import AddMutation
from tests.consultation_kb.approval_support import build_approval_harness
from tests.consultation_kb.unit.test_fact_schema import _event


pytestmark = pytest.mark.integration


def test_private_session_content_never_enters_next_session_artifacts(
    tmp_path: Path,
) -> None:
    harness = build_approval_harness(tmp_path)
    try:
        secret = "private-session-secret-marker"
        plan = ClientPublicationPlanner(harness.target_connection).prepare(
            AddMutation(
                new_fact=_event(
                    event_id=harness.ids.object_id("fact_event"),
                    fact_id=harness.ids.object_id("fact"),
                    object_json=f'"{secret}"',
                    privacy_level="private_session",
                )
            ),
            draft_event_id=harness.ids.object_id("fact_draft"),
            operation_id=harness.operation_id(),
            expected_runtime_epoch=1,
            publication_timestamp=harness.clock.now(),
        )
        active_payload = b"".join(
            member.data
            for artifact in plan.artifacts
            for member in artifact.members
        )
        assert secret.encode() not in active_payload
        assert secret.encode() in plan.mutation_diff_bytes
        assert plan.snapshot.events == ()
        assert plan.profile.current_event_ids == ()
        assert plan.graph.graph.number_of_edges() == 0
    finally:
        harness.close()
