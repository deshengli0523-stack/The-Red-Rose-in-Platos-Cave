from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from consultation_kb.models.facts import FactEvent
from consultation_kb.storage.migrations.client import v0001_initial, v0002_fact_ledger


UTC = timezone.utc
CLIENT_ID = "client" + "_aaaaaaaaaaaa"


def _database() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("BEGIN")
    v0001_initial.upgrade(connection)
    v0002_fact_ledger.upgrade(connection)
    connection.execute("COMMIT")
    return connection


def _event(**changes: object) -> FactEvent:
    values: dict[str, object] = {
        "event_id": "event-1",
        "fact_id": "fact-1",
        "client_id": CLIENT_ID,
        "event_version": 1,
        "mutation_type": "ADD",
        "canonical_key": "canonical-1",
        "subject": "来访者",
        "predicate": "current_partner",
        "object_json": '"甲"',
        "cognitive_type": "client_statement",
        "source_kind": "session_statement",
        "source_session_id": "session-1",
        "source_turn_id": "turn-1",
        "source_ref": None,
        "effective_from": datetime(2026, 7, 1, tzinfo=UTC),
        "effective_to": None,
        "time_precision": "day",
        "timezone_name": "Asia/Shanghai",
        "recorded_at": datetime(2026, 7, 16, tzinfo=UTC),
        "approved_at": datetime(2026, 7, 16, tzinfo=UTC),
        "reported_at": datetime(2026, 7, 16, tzinfo=UTC),
        "observed_at": None,
        "transaction_id": "tx-1",
        "commit_version": 1,
        "publication_operation_id": "publication-1",
        "visible_runtime_epoch": 1,
        "review_status": "approved",
        "validity_status": "active",
        "resolution_status": "open",
        "epistemic_status": "uncertain",
        "fact_confidence": 0.8,
        "model_confidence": 0.7,
        "reviewer_id": "counselor",
        "review_reason": "confirmed in review",
        "review_source": "primary_counselor",
        "privacy_level": "private_client",
        "allowed_purposes_json": '["next_session_context"]',
        "applicability_json": '{}',
        "source_anchor_json": '{}',
        "supersedes_event_id": None,
        "previous_event_id": None,
        "replacement_event_id": None,
        "source_event_ids": (),
    }
    values.update(changes)
    return FactEvent.model_validate(values)


def test_fact_event_is_append_only_and_four_axes_are_independent() -> None:
    connection = _database()
    event = _event()
    columns = tuple(event.to_record())
    connection.execute(
        f"INSERT INTO fact_events ({','.join(columns)}) "
        f"VALUES ({','.join('?' for _ in columns)})",
        tuple(event.to_record().values()),
    )

    row = connection.execute(
        "SELECT review_status, validity_status, resolution_status, "
        "epistemic_status FROM fact_events WHERE event_id = ?",
        (event.event_id,),
    ).fetchone()
    assert row == ("approved", "active", "open", "uncertain")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute(
            "UPDATE fact_events SET epistemic_status='asserted' WHERE event_id=?",
            (event.event_id,),
        )
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute("DELETE FROM fact_events WHERE event_id=?", (event.event_id,))


def test_source_contracts_are_mutually_exclusive() -> None:
    with pytest.raises(ValidationError, match="reported_at"):
        _event(reported_at=None)
    with pytest.raises(ValidationError, match="source_ref"):
        _event(
            cognitive_type="external_fact",
            source_kind="controlled_import",
            source_session_id=None,
            source_turn_id=None,
            reported_at=None,
        )

    imported = _event(
        cognitive_type="external_fact",
        source_kind="controlled_import",
        source_session_id=None,
        source_turn_id=None,
        reported_at=None,
        source_ref="source-revision-1#passage-2",
    )
    assert imported.source_ref == "source-revision-1#passage-2"
