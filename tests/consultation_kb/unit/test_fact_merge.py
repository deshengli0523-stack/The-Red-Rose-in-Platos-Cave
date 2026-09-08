from __future__ import annotations

import pytest

from consultation_kb.client.mutations import (
    ApprovedMutation,
    FactMutationService,
    MutationConflict,
)
from consultation_kb.models.facts import MergeMutation
from tests.consultation_kb.unit.test_fact_repository import _repository
from tests.consultation_kb.unit.test_fact_schema import _event


def test_merge_preserves_every_member_source_and_creates_one_projection() -> None:
    repository = _repository()
    first = _event(event_id="event-a", fact_id="fact-a", canonical_key="a")
    second = _event(event_id="event-b", fact_id="fact-b", canonical_key="b")
    repository.append_batch(base_commit_version=0, events=(first, second))
    service = FactMutationService(repository)
    mutation = MergeMutation(
        member_event_ids=("event-a", "event-b"),
        canonical_projection=_event(
            event_id="event-merged",
            fact_id="fact-merged",
            canonical_key="merged",
            mutation_type="MERGE",
            commit_version=2,
            visible_runtime_epoch=2,
            source_event_ids=("event-a", "event-b"),
        ),
        no_conflict_proof="same subject, predicate, value, time, and scope",
        reason="duplicate statements",
    )
    preview = service.preview(mutation)
    service.commit(
        preview,
        ApprovedMutation(
            preview_sha256=preview.preview_sha256,
            approval_operation_id="approval-merge",
            runtime_epoch=2,
            source="unit_test",
        ),
    )

    rows = repository.connection.execute(
        "SELECT member_event_id, member_session_id, member_turn_id, member_recorded_at "
        "FROM fact_merge_members ORDER BY ordinal"
    ).fetchall()
    assert [row[:3] for row in rows] == [
        ("event-a", "session-1", "turn-1"),
        ("event-b", "session-1", "turn-1"),
    ]
    assert all(row[3] for row in rows)
    assert repository.list_merge_member_ids() == frozenset({"event-a", "event-b"})


def test_merge_rejects_cross_client_projection_without_write() -> None:
    repository = _repository()
    first = _event(event_id="event-a", fact_id="fact-a", canonical_key="a")
    second = _event(event_id="event-b", fact_id="fact-b", canonical_key="b")
    repository.append_batch(base_commit_version=0, events=(first, second))
    mutation = MergeMutation(
        member_event_ids=("event-a", "event-b"),
        canonical_projection=_event(
            event_id="event-merged",
            fact_id="fact-merged",
            client_id="client_" + "b" * 12,
            canonical_key="merged",
            mutation_type="MERGE",
            commit_version=2,
            visible_runtime_epoch=2,
            source_event_ids=("event-a", "event-b"),
        ),
        no_conflict_proof="same fact",
        reason="cross-client merge must fail closed",
    )
    with pytest.raises(MutationConflict, match="FACT_MUTATION_CONFLICT"):
        FactMutationService(repository).preview(mutation)
    assert repository.current_commit_version() == 1
    assert tuple(event.event_id for event in repository.list_events()) == (
        "event-a",
        "event-b",
    )


def test_merge_rejects_an_obsolete_member_version() -> None:
    repository = _repository()
    first = _event(event_id="event-a", fact_id="fact-a", canonical_key="a")
    second = _event(event_id="event-b", fact_id="fact-b", canonical_key="b")
    repository.append_batch(base_commit_version=0, events=(first, second))
    first_latest = _event(
        event_id="event-a-v2",
        fact_id=first.fact_id,
        event_version=2,
        mutation_type="CONFIRM",
        canonical_key=first.canonical_key,
        commit_version=2,
        visible_runtime_epoch=2,
        previous_event_id=first.event_id,
        source_event_ids=(first.event_id,),
    )
    repository.append_batch(base_commit_version=1, events=(first_latest,))
    mutation = MergeMutation(
        member_event_ids=(first.event_id, second.event_id),
        canonical_projection=_event(
            event_id="event-merged",
            fact_id="fact-merged",
            canonical_key="merged",
            mutation_type="MERGE",
            commit_version=3,
            visible_runtime_epoch=3,
            source_event_ids=(first.event_id, second.event_id),
        ),
        no_conflict_proof="same content",
        reason="obsolete members must not be revived",
    )
    with pytest.raises(MutationConflict, match="FACT_MUTATION_CONFLICT"):
        FactMutationService(repository).preview(mutation)


def test_merge_rejects_members_with_different_governance_scope() -> None:
    repository = _repository()
    first = _event(event_id="event-a", fact_id="fact-a", canonical_key="a")
    second = _event(
        event_id="event-b",
        fact_id="fact-b",
        canonical_key="b",
        allowed_purposes_json='["case_archive"]',
    )
    repository.append_batch(base_commit_version=0, events=(first, second))
    mutation = MergeMutation(
        member_event_ids=(first.event_id, second.event_id),
        canonical_projection=_event(
            event_id="event-merged",
            fact_id="fact-merged",
            canonical_key="merged",
            mutation_type="MERGE",
            commit_version=2,
            visible_runtime_epoch=2,
            source_event_ids=(first.event_id, second.event_id),
        ),
        no_conflict_proof="content alone is insufficient",
        reason="governance scope must remain exact",
    )
    with pytest.raises(MutationConflict, match="FACT_MUTATION_CONFLICT"):
        FactMutationService(repository).preview(mutation)
