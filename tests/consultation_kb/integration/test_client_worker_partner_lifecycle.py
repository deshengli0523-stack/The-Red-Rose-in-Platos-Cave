from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

import pytest

from consultation_kb.approvals.review_agent import ReviewAgent
from consultation_kb.client.bitemporal import BitemporalFactQuery, FactQuery
from consultation_kb.models.dependencies import DependencyEdge
from consultation_kb.models.facts import (
    AddMutation,
    FactMutation,
    SupersedeMutation,
    canonical_json,
)
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.security.scoped_worker import (
    ScopedWorkerBroker,
    WorkerScopeDescriptor,
)
from consultation_kb.security.worker_protocol import (
    CommitFactMutationRequest,
    PreviewDependencyImpactRequest,
    PreviewDependencyImpactResponse,
    PreviewTargetDependencyImpactRequest,
    PreviewTargetDependencyImpactResponse,
    PreviewFactMutationRequest,
    PreviewFactMutationResponse,
    QueryClientGraphRequest,
    QueryClientGraphResponse,
    QueryClientWeightedPathRequest,
    QueryClientWeightedPathResponse,
    QueryFactSnapshotRequest,
    QueryFactSnapshotResponse,
    QueryProfileSnapshotRequest,
    QueryProfileSnapshotResponse,
    SearchClientGraphRequest,
    SearchClientGraphResponse,
)
from consultation_kb.storage.client_ledger import FactEventRepository
from tests.consultation_kb.approval_support import ApprovalHarness, build_approval_harness
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


class _TTY(StringIO):
    def isatty(self) -> bool:
        return True


def _approve_and_commit(
    harness: ApprovalHarness,
    broker: ScopedWorkerBroker,
    *,
    session_id: str,
    turn_id: str,
    mutation: FactMutation,
) -> tuple[PreviewFactMutationResponse, dict[str, object]]:
    operation_id = harness.operation_id()
    draft_event_id = harness.ids.object_id("fact_draft")
    now_text = harness.clock.now().isoformat().replace("+00:00", "Z")
    harness.target_connection.execute(
        "INSERT INTO session_fact_events("
        "session_event_id, session_id, turn_id, event_kind, event_json, recorded_at"
        ") VALUES (?, ?, ?, ?, ?, ?)",
        (
            draft_event_id,
            session_id,
            turn_id,
            mutation.operation,
            canonical_json(mutation.model_dump(mode="json")),
            now_text,
        ),
    )
    preview = broker.call(
        PreviewFactMutationRequest(
            request_id=harness.ids.uuid7(),
            draft_event_id=draft_event_id,
            base_commit_version=FactEventRepository(
                harness.target_connection
            ).current_commit_version(),
            proposed_operation_id=operation_id,
        )
    )
    assert isinstance(preview, PreviewFactMutationResponse)
    diff = json.loads(
        broker.render_verified_review_diff(preview.diff_object_ref).content
    )
    impact_response: PreviewDependencyImpactResponse | None = None
    if preview.direct_invalidation_count or preview.manual_review_count:
        candidate = broker.call(
            PreviewDependencyImpactRequest(
                request_id=harness.ids.uuid7(),
                draft_event_id=draft_event_id,
                preview_sha256=preview.preview_sha256,
                publication_operation_id=preview.publication_operation_id,
                diff_object_ref=preview.diff_object_ref,
            )
        )
        assert isinstance(candidate, PreviewDependencyImpactResponse)
        impact_response = candidate
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
    ReviewAgent(
        service=harness.service,
        signer=harness.signer,
        render_verified_diff=broker.render_verified_review_diff,
    ).review(
        approval_request.request_id,
        stdin=_TTY(f"APPROVE {approval_request.descriptor_sha256[:16]}\n"),
        stdout=StringIO(),
    )
    ticket = harness.service.issue_for_execution(
        approval_request.request_id,
        descriptor,
        operation_id=operation_id,
    )
    result = broker.execute_approved_fact_mutation(
        CommitFactMutationRequest(
            request_id=harness.ids.uuid7(),
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
    assert result.new_commit_version == preview.base_commit_version + 1
    assert result.runtime_epoch == preview.expected_runtime_epoch
    if impact_response is not None:
        diff["_impact_object_ref"] = impact_response.proposal_object_ref.model_dump(
            mode="json"
        )
    return preview, diff


def test_real_worker_partner_change_preserves_history_and_reviews_edge_effects(
    tmp_path: Path,
) -> None:
    root = tmp_path / "partner-lifecycle-scope"
    (root / "audit").mkdir(parents=True)
    marker = b"partner-lifecycle-scope\n"
    (root / ".scope-id").write_bytes(marker)
    (root / "audit" / "worker.jsonl").write_bytes(b"")
    marker_sha = hashlib.sha256(marker).hexdigest()
    harness = build_approval_harness(root, target_scope_hash=marker_sha)
    harness.clock.value = datetime.now(UTC)
    session_id = harness.ids.uuid7()
    harness.target_connection.execute(
        "INSERT INTO sessions(session_id, client_scope_hash, state, started_at) "
        "VALUES (?, ?, 'OPEN', ?)",
        (
            session_id,
            marker_sha,
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
        capability_token="partner-lifecycle-token",
        validator=_Validator(),
        target_execution_attestor_secret=b"t" * 32,
        target_execution_attestor_id="test-target-writer",
    )
    broker.start()
    try:
        partner_a_event_id = harness.ids.object_id("fact_event")
        partner_a_fact_id = harness.ids.object_id("fact")
        _approve_and_commit(
            harness,
            broker,
            session_id=session_id,
            turn_id="turn-1",
            mutation=AddMutation(
                new_fact=_event(
                    event_id=partner_a_event_id,
                    fact_id=partner_a_fact_id,
                    canonical_key="current-partner-a",
                    object_json='"partner-a"',
                    relation_type="CURRENT_RELATIONSHIP",
                    source_session_id=session_id,
                    source_turn_id="turn-1",
                    epistemic_status="asserted",
                )
            ),
        )

        weekend_event_id = harness.ids.object_id("fact_event")
        weekend_fact_id = harness.ids.object_id("fact")
        _approve_and_commit(
            harness,
            broker,
            session_id=session_id,
            turn_id="turn-2",
            mutation=AddMutation(
                new_fact=_event(
                    event_id=weekend_event_id,
                    fact_id=weekend_fact_id,
                    canonical_key="weekend-with-partner-a",
                    predicate="weekend_plan",
                    object_json='"travel-with-partner-a"',
                    source_session_id=session_id,
                    source_turn_id="turn-2",
                    epistemic_status="asserted",
                ),
                dependency_edges=(
                    DependencyEdge(
                        edge_id="dependency-weekend-partner-a",
                        dependent_fact_id=weekend_fact_id,
                        prerequisite_fact_id=partner_a_fact_id,
                        dependency_type="direct_deterministic",
                        confidence=1.0,
                        source_event_id=weekend_event_id,
                        reviewer_id="counselor",
                    ),
                ),
            ),
        )

        communication_event_id = harness.ids.object_id("fact_event")
        communication_fact_id = harness.ids.object_id("fact")
        _approve_and_commit(
            harness,
            broker,
            session_id=session_id,
            turn_id="turn-3",
            mutation=AddMutation(
                new_fact=_event(
                    event_id=communication_event_id,
                    fact_id=communication_fact_id,
                    canonical_key="communication-pattern",
                    predicate="communication_pattern",
                    object_json='"withdraws-during-conflict"',
                    cognitive_type="hypothesis",
                    source_kind="session_derived",
                    source_session_id=session_id,
                    source_turn_id="turn-3",
                    epistemic_status="uncertain",
                ),
                dependency_edges=(
                    DependencyEdge(
                        edge_id="dependency-communication-partner-a",
                        dependent_fact_id=communication_fact_id,
                        prerequisite_fact_id=partner_a_fact_id,
                        dependency_type="direct_conditional",
                        confidence=0.8,
                        source_event_id=communication_event_id,
                        reviewer_id="counselor",
                    ),
                ),
            ),
        )

        query_time = datetime(2027, 1, 1, tzinfo=UTC)
        graph_v1 = broker.call(
            QueryClientGraphRequest(
                request_id=harness.ids.uuid7(),
                effective_at=query_time,
                known_at=query_time,
                fixed_epoch=3,
            )
        )
        profile_v1 = broker.call(
            QueryProfileSnapshotRequest(
                request_id=harness.ids.uuid7(),
                effective_at=query_time,
                known_at=query_time,
                fixed_epoch=3,
            )
        )
        assert isinstance(graph_v1, QueryClientGraphResponse)
        assert isinstance(profile_v1, QueryProfileSnapshotResponse)
        assert graph_v1.edge_count == 5
        assert profile_v1.item_count == 3

        searched = broker.call(
            SearchClientGraphRequest(
                request_id=harness.ids.uuid7(),
                query="relationship dependency",
                as_of=query_time,
                max_depth=2,
                limit=20,
            )
        )
        assert isinstance(searched, SearchClientGraphResponse)
        assert searched.runtime_epoch == 3
        assert searched.count >= 3
        partner_ref = next(
            item.fact_ref
            for item in searched.items
            if item.fact_ref.object_id == partner_a_fact_id
        )
        weighted = broker.call(
            QueryClientWeightedPathRequest(
                request_id=harness.ids.uuid7(),
                source_ref=partner_a_fact_id,
                target_ref=weekend_fact_id,
                as_of=query_time,
                max_paths=3,
                max_hops=4,
            )
        )
        assert isinstance(weighted, QueryClientWeightedPathResponse)
        assert weighted.count == 1
        assert weighted.paths[0].edge_ids
        target_impact = broker.call(
            PreviewTargetDependencyImpactRequest(
                request_id=harness.ids.uuid7(),
                target_ref=partner_ref,
                action="supersede",
                as_of=query_time,
            )
        )
        assert isinstance(target_impact, PreviewTargetDependencyImpactResponse)
        assert len(target_impact.direct_invalidations) == 1
        assert len(target_impact.manual_reviews) == 1
        safe_wire = target_impact.model_dump_json()
        assert CLIENT_ID not in safe_wire
        assert "client.sqlite3" not in safe_wire

        partner_b_event_id = harness.ids.object_id("fact_event")
        partner_b_fact_id = harness.ids.object_id("fact")
        supersede = SupersedeMutation(
            target_event_id=partner_a_event_id,
            replacement=_event(
                event_id=partner_b_event_id,
                fact_id=partner_b_fact_id,
                canonical_key="current-partner-b",
                object_json='"partner-b"',
                relation_type="CURRENT_RELATIONSHIP",
                source_session_id=session_id,
                source_turn_id="turn-4",
                epistemic_status="asserted",
            ),
            effective_at=_event().effective_from,
            reason="the previous relationship ended and partner-b is current",
        )
        preview_v2, diff_v2 = _approve_and_commit(
            harness,
            broker,
            session_id=session_id,
            turn_id="turn-4",
            mutation=supersede,
        )
        assert preview_v2.direct_invalidation_count == 1
        assert preview_v2.manual_review_count == 1
        impact = diff_v2["dependency_impact"]
        assert isinstance(impact, dict)
        assert [item["fact_id"] for item in impact["direct_invalidations"]] == [
            weekend_fact_id
        ]
        assert [item["fact_id"] for item in impact["manual_reviews"]] == [
            communication_fact_id
        ]
        assert diff_v2["_impact_object_ref"] == preview_v2.diff_object_ref.model_dump(
            mode="json"
        )

        graph_v2 = broker.call(
            QueryClientGraphRequest(
                request_id=harness.ids.uuid7(),
                effective_at=query_time,
                known_at=query_time,
                fixed_epoch=4,
            )
        )
        graph_v1_again = broker.call(
            QueryClientGraphRequest(
                request_id=harness.ids.uuid7(),
                effective_at=query_time,
                known_at=query_time,
                fixed_epoch=3,
            )
        )
        profile_v2 = broker.call(
            QueryProfileSnapshotRequest(
                request_id=harness.ids.uuid7(),
                effective_at=query_time,
                known_at=query_time,
                fixed_epoch=4,
            )
        )
        assert isinstance(graph_v2, QueryClientGraphResponse)
        assert isinstance(graph_v1_again, QueryClientGraphResponse)
        assert isinstance(profile_v2, QueryProfileSnapshotResponse)
        assert graph_v2.edge_count == 3
        assert graph_v1_again.edge_count == 5
        assert graph_v1_again.graph_sha256 == graph_v1.graph_sha256
        assert profile_v2.item_count == 3
    finally:
        broker.close()

    try:
        repository = FactEventRepository(harness.target_connection)
        current = BitemporalFactQuery(repository).execute(
            FactQuery(
                effective_at=datetime.now(UTC),
                known_at=datetime.now(UTC),
                fixed_epoch=4,
                review_statuses=frozenset({"approved"}),
                validity_statuses=frozenset({"active"}),
                resolution_statuses=frozenset({"open"}),
            )
        )
        historical = BitemporalFactQuery(repository).execute(
            FactQuery(
                effective_at=datetime.now(UTC),
                known_at=datetime.now(UTC),
                fixed_epoch=3,
                review_statuses=frozenset({"approved"}),
                validity_statuses=frozenset({"active"}),
                resolution_statuses=frozenset({"open"}),
            )
        )
        assert {event.object_json for event in current if event.predicate == "current_partner"} == {
            '"partner-b"'
        }
        assert {event.object_json for event in historical if event.predicate == "current_partner"} == {
            '"partner-a"'
        }
        assert harness.target_connection.execute(
            "SELECT count(*) FROM fact_dependencies"
        ).fetchone() == (2,)
        assert harness.target_connection.execute(
            "SELECT count(*) FROM fact_events"
        ).fetchone() == (5,)
    finally:
        harness.close()


def test_real_worker_next_session_queries_hide_private_session_fact_oracles(
    tmp_path: Path,
) -> None:
    root = tmp_path / "private-session-query-scope"
    (root / "audit").mkdir(parents=True)
    marker = b"private-session-query-scope\n"
    (root / ".scope-id").write_bytes(marker)
    (root / "audit" / "worker.jsonl").write_bytes(b"")
    marker_sha = hashlib.sha256(marker).hexdigest()
    harness = build_approval_harness(root, target_scope_hash=marker_sha)
    harness.clock.value = datetime.now(UTC)
    session_id = harness.ids.uuid7()
    harness.target_connection.execute(
        "INSERT INTO sessions(session_id, client_scope_hash, state, started_at) "
        "VALUES (?, ?, 'OPEN', ?)",
        (
            session_id,
            marker_sha,
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
        capability_token="private-session-query-token",
        validator=_Validator(),
        target_execution_attestor_secret=b"t" * 32,
        target_execution_attestor_id="test-target-writer",
    )
    broker.start()
    try:
        _approve_and_commit(
            harness,
            broker,
            session_id=session_id,
            turn_id="turn-private",
            mutation=AddMutation(
                new_fact=_event(
                    event_id=harness.ids.object_id("fact_event"),
                    fact_id=harness.ids.object_id("fact"),
                    object_json='"private-session-secret"',
                    privacy_level="private_session",
                    source_session_id=session_id,
                    source_turn_id="turn-private",
                )
            ),
        )
        query_time = datetime(2027, 1, 1, tzinfo=UTC)
        fact_response = broker.call(
            QueryFactSnapshotRequest(
                request_id=harness.ids.uuid7(),
                effective_at=query_time,
                known_at=query_time,
                fixed_epoch=1,
            )
        )
        profile_response = broker.call(
            QueryProfileSnapshotRequest(
                request_id=harness.ids.uuid7(),
                effective_at=query_time,
                known_at=query_time,
                fixed_epoch=1,
            )
        )
        graph_response = broker.call(
            QueryClientGraphRequest(
                request_id=harness.ids.uuid7(),
                effective_at=query_time,
                known_at=query_time,
                fixed_epoch=1,
            )
        )
        assert isinstance(fact_response, QueryFactSnapshotResponse)
        assert isinstance(profile_response, QueryProfileSnapshotResponse)
        assert isinstance(graph_response, QueryClientGraphResponse)
        assert fact_response.event_count == 0
        assert profile_response.item_count == 0
        assert graph_response.edge_count == 0
        assert harness.target_connection.execute(
            "SELECT count(*) FROM fact_events"
        ).fetchone() == (1,)
    finally:
        broker.close()
        harness.close()
