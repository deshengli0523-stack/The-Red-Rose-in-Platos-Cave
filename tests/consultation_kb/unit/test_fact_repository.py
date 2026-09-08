from __future__ import annotations

import sqlite3

import pytest

from consultation_kb.storage.client_ledger import (
    FactEventRepository,
    FactLedgerIntegrityError,
    StaleFactPreview,
)
from consultation_kb.storage.connection import transaction
from consultation_kb.storage.migrations.client import v0001_initial, v0002_fact_ledger
from tests.consultation_kb.unit.test_fact_schema import _event


def _repository() -> FactEventRepository:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("BEGIN")
    v0001_initial.upgrade(connection)
    v0002_fact_ledger.upgrade(connection)
    connection.execute("COMMIT")
    return FactEventRepository(connection)


def test_stale_fact_preview_fails_without_half_write() -> None:
    repository = _repository()
    first = _event(event_id="event-1", fact_id="fact-1", commit_version=1)
    second = _event(event_id="event-2", fact_id="fact-2", commit_version=1)

    assert repository.append_batch(base_commit_version=0, events=(first,)) == 1
    with pytest.raises(StaleFactPreview, match="STALE_FACT_PREVIEW"):
        repository.append_batch(base_commit_version=0, events=(second,))

    assert repository.current_commit_version() == 1
    assert [event.event_id for event in repository.list_events()] == ["event-1"]


def test_event_is_invisible_until_its_runtime_epoch_is_active() -> None:
    repository = _repository()
    repository.append_batch(base_commit_version=0, events=(_event(),))
    assert repository.list_events(fixed_epoch=0) == ()
    assert tuple(event.event_id for event in repository.list_events(fixed_epoch=1)) == (
        "event-1",
    )


def test_approval_transaction_can_own_fact_append_and_rollback() -> None:
    repository = _repository()
    with pytest.raises(RuntimeError, match="fault after fact write"):
        with transaction(repository.connection):
            repository.append_batch_in_transaction(
                base_commit_version=0,
                events=(_event(),),
            )
            raise RuntimeError("fault after fact write")

    assert repository.current_commit_version() == 0
    assert repository.list_events() == ()


def test_repository_binds_first_client_and_rejects_cross_client_without_write() -> None:
    repository = _repository()
    first = _event(event_id="event-a", fact_id="fact-a")
    other = _event(
        event_id="event-b",
        fact_id="fact-b",
        client_id="client_" + "b" * 12,
        commit_version=2,
        visible_runtime_epoch=2,
    )
    repository.append_batch(base_commit_version=0, events=(first,))

    with pytest.raises(FactLedgerIntegrityError, match="FACT_LEDGER_INTEGRITY_ERROR"):
        repository.append_batch(base_commit_version=1, events=(other,))

    assert repository.bound_client_id() == first.client_id
    assert repository.current_commit_version() == 1
    assert tuple(event.event_id for event in repository.list_events()) == ("event-a",)


def test_repository_rejects_mixed_client_batch_before_binding() -> None:
    repository = _repository()
    with pytest.raises(FactLedgerIntegrityError, match="FACT_LEDGER_INTEGRITY_ERROR"):
        repository.append_batch(
            base_commit_version=0,
            events=(
                _event(event_id="event-a", fact_id="fact-a"),
                _event(
                    event_id="event-b",
                    fact_id="fact-b",
                    client_id="client_" + "b" * 12,
                ),
            ),
        )
    assert repository.current_commit_version() == 0
    assert repository.bound_client_id() is None


def test_repository_rejects_dangling_source_event_lineage() -> None:
    repository = _repository()
    with pytest.raises(FactLedgerIntegrityError, match="FACT_LEDGER_INTEGRITY_ERROR"):
        repository.append_batch(
            base_commit_version=0,
            events=(_event(source_event_ids=("missing-source-event",)),),
        )
    assert repository.current_commit_version() == 0
    assert repository.list_events() == ()
