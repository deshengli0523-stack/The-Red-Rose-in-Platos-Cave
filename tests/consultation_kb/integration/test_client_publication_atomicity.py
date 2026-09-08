from __future__ import annotations

import hashlib
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from consultation_kb.approvals.attestation import LocalHmacTargetExecutionAttestor
from consultation_kb.client.publication import (
    ClientPublicationError,
    ClientPublicationExecutor,
    ClientPublicationPlan,
    ClientPublicationPlanner,
)
from consultation_kb.client.bitemporal import BitemporalFactQuery, FactQuery
from consultation_kb.lifecycle.publish import ArtifactDraft, ContentDraft
from consultation_kb.models.facts import AddMutation
from consultation_kb.security.scoped_worker import (
    ScopeDenied,
    ScopedWorkerBroker,
    WorkerScopeDescriptor,
)
from consultation_kb.security.worker_protocol import (
    QueryFactSnapshotRequest,
    QueryFactSnapshotResponse,
)
from consultation_kb.storage.client_ledger import FactEventRepository
from tests.consultation_kb.approval_support import ApprovalHarness, build_approval_harness
from tests.consultation_kb.unit.test_fact_schema import _event


pytestmark = pytest.mark.integration


@pytest.fixture
def harness(tmp_path: Path) -> ApprovalHarness:
    value = build_approval_harness(tmp_path)
    yield value
    value.close()


def _plan(harness: ApprovalHarness) -> ClientPublicationPlan:
    operation_id = harness.operation_id()
    draft_event_id = harness.ids.object_id("fact_draft")
    return ClientPublicationPlanner(
        harness.target_connection,
    ).prepare(
        AddMutation(
            new_fact=_event(
                event_id=harness.ids.object_id("fact_event"),
                fact_id=harness.ids.object_id("fact"),
            )
        ),
        draft_event_id=draft_event_id,
        operation_id=operation_id,
        expected_runtime_epoch=1,
        publication_timestamp=harness.clock.now(),
    )


def _successor_plan(
    harness: ApprovalHarness,
    *,
    expected_runtime_epoch: int = 2,
) -> ClientPublicationPlan:
    operation_id = harness.operation_id()
    draft_event_id = harness.ids.object_id("fact_draft")
    suffix = harness.ids.object_id("fact_suffix")
    return ClientPublicationPlanner(harness.target_connection).prepare(
        AddMutation(
            new_fact=_event(
                event_id=harness.ids.object_id("fact_event"),
                fact_id=harness.ids.object_id("fact"),
                canonical_key=f"goal-{suffix}",
                predicate="career_goal",
                object_json='"explore-a-new-role"',
                transaction_id=harness.ids.object_id("fact_transaction"),
            )
        ),
        draft_event_id=draft_event_id,
        operation_id=operation_id,
        expected_runtime_epoch=expected_runtime_epoch,
        publication_timestamp=harness.clock.now(),
    )


def _ticket(harness: ApprovalHarness, plan: ClientPublicationPlan):
    request = harness.service.request(
        plan.descriptor,
        diff_object_ref=harness.diff_object_ref(),
    )
    receipt = harness.signer.confirm(
        harness.service.challenge_for_review(request.request_id)
    )
    harness.service.confirm(receipt)
    return harness.service.issue_for_execution(
        request.request_id,
        plan.descriptor,
        operation_id=plan.operation_id,
    )


def _executor(harness: ApprovalHarness, scope_root: Path) -> ClientPublicationExecutor:
    return ClientPublicationExecutor(
        harness.target_connection,
        scope_root=scope_root,
        execution_proof_signer=LocalHmacTargetExecutionAttestor(
            secret=b"t" * 32,
            attestor_id="test-target-writer",
        ),
        clock=harness.clock,
    )


class _InjectedPublicationFault(RuntimeError):
    pass


def _raise_at(expected_point: str):
    def inject(point: str) -> None:
        if point == expected_point:
            raise _InjectedPublicationFault(point)

    return inject


def _faulting_executor(
    harness: ApprovalHarness,
    scope_root: Path,
    *,
    point: str,
) -> ClientPublicationExecutor:
    return ClientPublicationExecutor(
        harness.target_connection,
        scope_root=scope_root,
        execution_proof_signer=LocalHmacTargetExecutionAttestor(
            secret=b"t" * 32,
            attestor_id="test-target-writer",
        ),
        clock=harness.clock,
        fault_injector=_raise_at(point),
    )


def _active_artifact_versions(harness: ApprovalHarness) -> list[tuple[str, int]]:
    rows = harness.target_connection.execute(
        "SELECT aa.artifact_key, am.source_version "
        "FROM active_artifacts AS aa "
        "JOIN artifact_manifests AS am ON am.manifest_id = aa.manifest_id "
        "JOIN runtime_epochs AS re ON re.epoch = aa.epoch "
        "WHERE re.state = 'ACTIVE' ORDER BY aa.artifact_key"
    ).fetchall()
    return [(str(artifact_key), int(source_version)) for artifact_key, source_version in rows]


def test_real_approval_guard_publishes_fact_profile_graph_as_one_epoch(
    harness: ApprovalHarness,
    tmp_path: Path,
) -> None:
    plan = _plan(harness)
    ticket = _ticket(harness, plan)

    proof = _executor(harness, tmp_path).execute(plan, ticket)
    acknowledged = harness.service.acknowledge(proof)

    assert acknowledged.state == "acknowledged"
    assert proof.applied_commit_version == 1
    assert harness.target_connection.execute(
        "SELECT commit_version FROM client_fact_authority WHERE singleton=1"
    ).fetchone() == (1,)
    assert harness.target_connection.execute(
        "SELECT epoch, state FROM runtime_epochs ORDER BY epoch"
    ).fetchall() == [(1, "ACTIVE")]
    assert harness.target_connection.execute(
        "SELECT artifact_key FROM active_artifacts WHERE epoch=1 ORDER BY artifact_key"
    ).fetchall() == [
        ("client_fact_snapshot",),
        ("client_graph",),
        ("client_profile",),
    ]
    assert harness.target_connection.execute(
        "SELECT source_commit_version, visible_runtime_epoch FROM profile_revisions"
    ).fetchone() == (1, 1)


def test_publication_plan_rebuilds_byte_identically_after_worker_restart(
    harness: ApprovalHarness,
) -> None:
    operation_id = harness.operation_id()
    draft_event_id = harness.ids.object_id("fact_draft")
    mutation = AddMutation(
        new_fact=_event(
            event_id=harness.ids.object_id("fact_event"),
            fact_id=harness.ids.object_id("fact"),
        )
    )
    arguments = {
        "draft_event_id": draft_event_id,
        "operation_id": operation_id,
        "expected_runtime_epoch": 1,
        "publication_timestamp": harness.clock.now(),
    }

    first = ClientPublicationPlanner(harness.target_connection).prepare(
        mutation,
        **arguments,
    )
    rebuilt = ClientPublicationPlanner(harness.target_connection).prepare(
        mutation,
        **arguments,
    )

    assert rebuilt.descriptor == first.descriptor
    assert rebuilt.events == first.events
    assert rebuilt.artifacts == first.artifacts
    assert rebuilt.diff_object_ref == first.diff_object_ref


def _replace_member_data(
    plan: ClientPublicationPlan,
    *,
    artifact_key: str,
) -> ClientPublicationPlan:
    artifacts: list[ArtifactDraft] = []
    for artifact in plan.artifacts:
        if artifact.artifact_key != artifact_key:
            artifacts.append(artifact)
            continue
        first, *rest = artifact.members
        replacement = ContentDraft(
            object_type=first.object_type,
            object_id=first.object_id,
            data=first.data + b"tampered",
            source_version=first.source_version,
            media_type=first.media_type,
            source_lineage=first.source_lineage,
        )
        artifacts.append(replace(artifact, members=(replacement, *rest)))
    return replace(plan, artifacts=tuple(artifacts))


@pytest.mark.parametrize(
    "tamper",
    [
        lambda plan: _replace_member_data(plan, artifact_key="client_profile"),
        lambda plan: _replace_member_data(plan, artifact_key="client_graph"),
        lambda plan: replace(plan, runtime_epoch=2),
        lambda plan: replace(plan, authority_version=2),
    ],
    ids=("profile-bytes", "graph-bytes", "runtime-epoch", "authority-version"),
)
def test_approved_closure_rejects_any_post_approval_substitution(
    harness: ApprovalHarness,
    tmp_path: Path,
    tamper,
) -> None:
    plan = _plan(harness)
    ticket = _ticket(harness, plan)

    with pytest.raises(ClientPublicationError, match="CLIENT_PUBLICATION_INVALID"):
        _executor(harness, tmp_path).execute(tamper(plan), ticket)

    assert harness.target_connection.execute(
        "SELECT count(*) FROM fact_events"
    ).fetchone() == (0,)
    assert harness.target_connection.execute(
        "SELECT count(*) FROM approval_executions"
    ).fetchone() == (0,)


@pytest.mark.parametrize(
    "fault_point",
    (
        "authoritative_event_transaction",
        "profile_finalize",
        "graph_finalize",
        "prepared",
        "verify",
        "epoch_switch",
    ),
)
def test_each_named_publication_fault_exposes_only_the_old_complete_epoch_and_retries(
    harness: ApprovalHarness,
    tmp_path: Path,
    fault_point: str,
) -> None:
    first = _plan(harness)
    first_proof = _executor(harness, tmp_path).execute(first, _ticket(harness, first))
    harness.service.acknowledge(first_proof)
    second = _successor_plan(harness)
    second_ticket = _ticket(harness, second)

    with pytest.raises(_InjectedPublicationFault, match=fault_point):
        _faulting_executor(
            harness,
            tmp_path,
            point=fault_point,
        ).execute(second, second_ticket)

    assert harness.target_connection.execute(
        "SELECT epoch, state FROM runtime_epochs ORDER BY epoch"
    ).fetchall() == [(1, "ACTIVE")]
    assert _active_artifact_versions(harness) == [
        ("client_fact_snapshot", 1),
        ("client_graph", 1),
        ("client_profile", 1),
    ]
    old_snapshot = BitemporalFactQuery(
        FactEventRepository(harness.target_connection)
    ).snapshot(
        FactQuery(
            effective_at=harness.clock.now(),
            known_at=harness.clock.now(),
            fixed_epoch=1,
        )
    )
    assert old_snapshot.event_ids == (first.events[0].event_id,)
    assert second.events[0].event_id not in old_snapshot.event_ids

    # Every named point is retryable with the same approved immutable closure.
    recovered_proof = _executor(harness, tmp_path).execute(second, second_ticket)
    harness.service.acknowledge(recovered_proof)
    assert harness.target_connection.execute(
        "SELECT epoch, state FROM runtime_epochs ORDER BY epoch"
    ).fetchall() == [(1, "RETIRED"), (2, "ACTIVE")]
    assert _active_artifact_versions(harness) == [
        ("client_fact_snapshot", 2),
        ("client_graph", 2),
        ("client_profile", 2),
    ]
    assert harness.target_connection.execute(
        "SELECT source_commit_version, visible_runtime_epoch "
        "FROM profile_revisions ORDER BY source_commit_version"
    ).fetchall() == [(1, 1), (2, 2)]


class _ReadCapabilityValidator:
    def assert_valid(self, _token: str, *, required_permission: str) -> None:
        if required_permission != "client_read":
            raise AssertionError(required_permission)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows scoped worker")
def test_public_worker_rejects_an_unactivated_future_epoch_even_when_rows_exist(
    harness: ApprovalHarness,
    tmp_path: Path,
) -> None:
    first = _plan(harness)
    first_proof = _executor(harness, tmp_path).execute(first, _ticket(harness, first))
    harness.service.acknowledge(first_proof)
    second = _successor_plan(harness)
    second_ticket = _ticket(harness, second)

    with pytest.raises(_InjectedPublicationFault, match="epoch_switch"):
        _faulting_executor(
            harness,
            tmp_path,
            point="epoch_switch",
        ).execute(second, second_ticket)

    # The hidden row is durable for recovery, but public reads are pinned to an
    # ACTIVE epoch and therefore cannot use it as a future-state oracle.
    assert harness.target_connection.execute(
        "SELECT count(*) FROM fact_events WHERE visible_runtime_epoch = 2"
    ).fetchone() == (1,)
    assert harness.target_connection.execute(
        "SELECT state FROM publication_operations WHERE operation_id = ?",
        (second.operation_id,),
    ).fetchone() == ("VERIFIED",)

    marker = b"p2-public-future-epoch-test\n"
    (tmp_path / ".scope-id").write_bytes(marker)
    (tmp_path / "audit").mkdir(exist_ok=True)
    (tmp_path / "audit" / "worker.jsonl").write_bytes(b"")
    broker = ScopedWorkerBroker(
        scope=WorkerScopeDescriptor(
            scope_root=tmp_path,
            global_descriptor_sha256="a" * 64,
            scope_marker_sha256=hashlib.sha256(marker).hexdigest(),
            client_id=first.events[0].client_id,
        ),
        capability_token="opaque-client-read-token",
        validator=_ReadCapabilityValidator(),
    )
    broker.start()
    try:
        current = broker.call(
            QueryFactSnapshotRequest(
                request_id="017f22e2-79b0-7cc3-98c4-dc0c0c073992",
                effective_at=harness.clock.now(),
                known_at=harness.clock.now(),
                fixed_epoch=1,
            )
        )
        assert isinstance(current, QueryFactSnapshotResponse)
        assert current.event_count == 1
        with pytest.raises(ScopeDenied, match="SCOPE_DENIED"):
            broker.call(
                QueryFactSnapshotRequest(
                    request_id="017f22e2-79b0-7cc3-98c4-dc0c0c073993",
                    effective_at=harness.clock.now(),
                    known_at=harness.clock.now(),
                    fixed_epoch=2,
                )
            )
    finally:
        broker.close()


def test_publication_lineage_recursively_includes_ancestor_session_and_turn(
    harness: ApprovalHarness,
) -> None:
    ancestor = _event(
        event_id="event-ancestor",
        fact_id="fact-ancestor",
        source_session_id="session-ancestor",
        source_turn_id="turn-ancestor",
        commit_version=1,
        visible_runtime_epoch=1,
    )
    replacement = _event(
        event_id="event-replacement",
        fact_id="fact-replacement",
        event_version=1,
        mutation_type="SUPERSEDE",
        source_session_id="session-replacement",
        source_turn_id="turn-replacement",
        supersedes_event_id=ancestor.event_id,
        source_event_ids=(ancestor.event_id,),
        commit_version=2,
        visible_runtime_epoch=2,
    )
    descendant = _event(
        event_id="event-descendant",
        fact_id=replacement.fact_id,
        event_version=2,
        mutation_type="CORRECT",
        source_session_id=replacement.source_session_id,
        source_turn_id=replacement.source_turn_id,
        previous_event_id=replacement.event_id,
        source_event_ids=(ancestor.event_id, replacement.event_id),
        commit_version=3,
        visible_runtime_epoch=3,
    )
    query = FactQuery(
        effective_at=harness.clock.now(),
        known_at=harness.clock.now(),
        fixed_epoch=3,
    )
    snapshot = BitemporalFactQuery.snapshot_events(
        (descendant,),
        query,
        client_commit_version=3,
    )

    lineage = ClientPublicationPlanner(harness.target_connection)._source_lineage(
        snapshot,
        projected_events=(ancestor, replacement, descendant),
        merge_members={},
        evidence={},
        dependencies=(),
    )
    identities = {(item.object_type, item.object_id) for item in lineage}

    assert {
        ("fact_event", ancestor.event_id),
        ("fact_event", replacement.event_id),
        ("fact_event", descendant.event_id),
        ("source_session", "session-ancestor"),
        ("source_turn", "turn-ancestor"),
        ("source_session", "session-replacement"),
        ("source_turn", "turn-replacement"),
    } <= identities
