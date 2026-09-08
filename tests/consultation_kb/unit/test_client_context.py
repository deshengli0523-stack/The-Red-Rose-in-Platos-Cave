from __future__ import annotations

from datetime import datetime, timezone

import pytest

from consultation_kb.session.context import ClientContextSnapshot, client_context_sha256
from consultation_kb.session.service import TaskScopeAlreadyBound, TransportBindingRegistry


def _snapshot() -> ClientContextSnapshot:
    now = datetime(2026, 7, 19, 2, 0, tzinfo=timezone.utc)
    payload = {
        "schema_version": "client_context.v1",
        "client_id": "client_" + "aaaaaaaaaaaa",
        "profile_revision_id": None,
        "profile_version": 0,
        "profile_sha256": None,
        "fixed_epoch": 0,
        "profile": None,
        "recent_session_summary_refs": (),
        "unresolved_items": (),
        "goals": (),
        "preferences": (),
        "constraints": (),
        "key_facts": (),
        "review_items": (),
        "created_at": now,
    }
    return ClientContextSnapshot(
        **payload,
        canonical_sha256=client_context_sha256(payload),
    )


def test_client_context_hash_binds_every_snapshot_field() -> None:
    first = _snapshot()
    assert first.profile_version == 0

    with pytest.raises(ValueError, match="client context hash mismatch"):
        first.model_copy(update={"profile_version": 1})


def test_transport_binding_is_permanent_for_one_client_and_session() -> None:
    registry = TransportBindingRegistry()
    registry.bind(
        transport_session_id="transport-1",
        client_id="client_" + "aaaaaaaaaaaa",
        session_id="018f0000-0000-7000-8000-000000000001",
    )
    registry.bind(
        transport_session_id="transport-1",
        client_id="client_" + "aaaaaaaaaaaa",
        session_id="018f0000-0000-7000-8000-000000000001",
    )

    with pytest.raises(TaskScopeAlreadyBound, match="TASK_SCOPE_ALREADY_BOUND"):
        registry.bind(
            transport_session_id="transport-1",
            client_id="client_" + "bbbbbbbbbbbb",
            session_id="018f0000-0000-7000-8000-000000000002",
        )
