from __future__ import annotations

from datetime import datetime, timezone

from consultation_kb.client.bitemporal import BitemporalFactQuery, FactQuery
from tests.consultation_kb.unit.test_fact_repository import _repository
from tests.consultation_kb.unit.test_fact_schema import _event


UTC = timezone.utc


def _at(day: int) -> datetime:
    return datetime(2026, 7, day, 12, tzinfo=UTC)


def test_retroactive_partner_correction_respects_knowledge_time() -> None:
    repository = _repository()
    old = _event(
        event_id="event-old",
        fact_id="relationship",
        object_json='"甲"',
        effective_from=_at(1),
        recorded_at=_at(2),
        approved_at=_at(2),
        reported_at=_at(2),
        commit_version=1,
        visible_runtime_epoch=1,
    )
    correction = _event(
        event_id="event-correction",
        fact_id="relationship",
        event_version=2,
        mutation_type="CORRECT",
        object_json='"已于7月1日分手"',
        effective_from=_at(1),
        recorded_at=_at(16),
        approved_at=_at(16),
        reported_at=_at(16),
        commit_version=2,
        visible_runtime_epoch=2,
        previous_event_id="event-old",
    )
    repository.append_batch(base_commit_version=0, events=(old,))
    repository.append_batch(base_commit_version=1, events=(correction,))
    service = BitemporalFactQuery(repository)

    before = service.execute(
        FactQuery(effective_at=_at(5), known_at=_at(10), fixed_epoch=2)
    )
    after = service.execute(
        FactQuery(effective_at=_at(5), known_at=_at(17), fixed_epoch=2)
    )

    assert [event.event_id for event in before] == ["event-old"]
    assert [event.event_id for event in after] == ["event-correction"]


def test_future_version_does_not_hide_still_applicable_old_version() -> None:
    repository = _repository()
    old = _event(
        event_id="event-old",
        fact_id="goal",
        predicate="goal",
        object_json='"完成转岗"',
        effective_from=_at(1),
        recorded_at=_at(2),
        approved_at=_at(2),
        reported_at=_at(2),
        commit_version=1,
    )
    future = _event(
        event_id="event-future",
        fact_id="goal",
        event_version=2,
        mutation_type="CORRECT",
        predicate="goal",
        object_json='"创业"',
        effective_from=_at(20),
        recorded_at=_at(10),
        approved_at=_at(10),
        reported_at=_at(10),
        commit_version=2,
        visible_runtime_epoch=2,
        previous_event_id="event-old",
        source_event_ids=("event-old",),
    )
    repository.append_batch(base_commit_version=0, events=(old,))
    repository.append_batch(base_commit_version=1, events=(future,))

    events = BitemporalFactQuery(repository).execute(
        FactQuery(effective_at=_at(15), known_at=_at(17), fixed_epoch=2)
    )
    assert [event.event_id for event in events] == ["event-old"]


def test_known_time_correction_does_not_resurrect_the_old_incorrect_window() -> None:
    repository = _repository()
    old = _event(
        event_id="event-old-time",
        fact_id="employment-start",
        predicate="employment_start",
        object_json='"new-role"',
        effective_from=_at(1),
        recorded_at=_at(2),
        approved_at=_at(2),
        reported_at=_at(2),
        commit_version=1,
        visible_runtime_epoch=1,
    )
    corrected_time = _event(
        event_id="event-corrected-time",
        fact_id="employment-start",
        event_version=2,
        mutation_type="CORRECT",
        predicate="employment_start",
        object_json='"new-role"',
        effective_from=_at(10),
        recorded_at=_at(16),
        approved_at=_at(16),
        reported_at=_at(16),
        commit_version=2,
        visible_runtime_epoch=2,
        previous_event_id="event-old-time",
        source_event_ids=("event-old-time",),
    )
    repository.append_batch(base_commit_version=0, events=(old,))
    repository.append_batch(base_commit_version=1, events=(corrected_time,))
    service = BitemporalFactQuery(repository)

    before_correction_was_known = service.execute(
        FactQuery(effective_at=_at(5), known_at=_at(10), fixed_epoch=2)
    )
    after_correction_was_known = service.execute(
        FactQuery(effective_at=_at(5), known_at=_at(17), fixed_epoch=2)
    )
    inside_corrected_window = service.execute(
        FactQuery(effective_at=_at(12), known_at=_at(17), fixed_epoch=2)
    )

    assert [event.event_id for event in before_correction_was_known] == [
        "event-old-time"
    ]
    assert after_correction_was_known == ()
    assert [event.event_id for event in inside_corrected_window] == [
        "event-corrected-time"
    ]


def test_time_correction_stops_at_a_different_value_predecessor() -> None:
    repository = _repository()
    old_value = _event(
        event_id="event-old-value",
        fact_id="goal-transition",
        predicate="goal",
        object_json='"stay"',
        effective_from=_at(1),
        recorded_at=_at(2),
        approved_at=_at(2),
        reported_at=_at(2),
        commit_version=1,
    )
    changed_value = _event(
        event_id="event-changed-value",
        fact_id="goal-transition",
        event_version=2,
        mutation_type="CORRECT",
        predicate="goal",
        object_json='"change-role"',
        effective_from=_at(5),
        recorded_at=_at(10),
        approved_at=_at(10),
        reported_at=_at(10),
        commit_version=2,
        visible_runtime_epoch=2,
        previous_event_id="event-old-value",
        source_event_ids=("event-old-value",),
    )
    corrected_time = _event(
        event_id="event-changed-value-time",
        fact_id="goal-transition",
        event_version=3,
        mutation_type="CORRECT",
        predicate="goal",
        object_json='"change-role"',
        effective_from=_at(10),
        recorded_at=_at(16),
        approved_at=_at(16),
        reported_at=_at(16),
        commit_version=3,
        visible_runtime_epoch=3,
        previous_event_id="event-changed-value",
        source_event_ids=("event-changed-value", "event-old-value"),
    )
    repository.append_batch(base_commit_version=0, events=(old_value,))
    repository.append_batch(base_commit_version=1, events=(changed_value,))
    repository.append_batch(base_commit_version=2, events=(corrected_time,))
    service = BitemporalFactQuery(repository)

    before_changed_value = service.execute(
        FactQuery(effective_at=_at(7), known_at=_at(17), fixed_epoch=3)
    )
    after_changed_value = service.execute(
        FactQuery(effective_at=_at(12), known_at=_at(17), fixed_epoch=3)
    )

    assert [event.event_id for event in before_changed_value] == ["event-old-value"]
    assert [event.event_id for event in after_changed_value] == [
        "event-changed-value-time"
    ]


def test_axis_filters_are_independent_and_optional() -> None:
    repository = _repository()
    repository.append_batch(base_commit_version=0, events=(_event(),))
    service = BitemporalFactQuery(repository)

    assert service.execute(FactQuery(effective_at=_at(17), known_at=_at(17), fixed_epoch=1))
    assert service.execute(
        FactQuery(
            effective_at=_at(17),
            known_at=_at(17),
            fixed_epoch=1,
            epistemic_statuses=frozenset({"uncertain"}),
        )
    )
    assert not service.execute(
        FactQuery(
            effective_at=_at(17),
            known_at=_at(17),
            fixed_epoch=1,
            epistemic_statuses=frozenset({"asserted"}),
        )
    )


def test_status_filter_never_resurrects_an_obsolete_older_version() -> None:
    repository = _repository()
    active = _event(
        event_id="event-active",
        fact_id="fact-status",
        recorded_at=_at(2),
        approved_at=_at(2),
        reported_at=_at(2),
        commit_version=1,
    )
    invalidated = _event(
        event_id="event-invalidated",
        fact_id="fact-status",
        event_version=2,
        mutation_type="CORRECT",
        validity_status="invalidated",
        recorded_at=_at(16),
        approved_at=_at(16),
        reported_at=_at(16),
        commit_version=2,
        visible_runtime_epoch=2,
        previous_event_id="event-active",
    )
    repository.append_batch(base_commit_version=0, events=(active,))
    repository.append_batch(base_commit_version=1, events=(invalidated,))
    service = BitemporalFactQuery(repository)

    current_active = service.execute(
        FactQuery(
            effective_at=_at(17),
            known_at=_at(17),
            fixed_epoch=2,
            validity_statuses=frozenset({"active"}),
        )
    )
    historical_active = service.execute(
        FactQuery(
            effective_at=_at(10),
            known_at=_at(10),
            fixed_epoch=2,
            validity_statuses=frozenset({"active"}),
        )
    )

    assert current_active == ()
    assert [event.event_id for event in historical_active] == ["event-active"]
