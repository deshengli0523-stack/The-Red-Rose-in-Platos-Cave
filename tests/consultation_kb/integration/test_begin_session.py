from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.session.context import ClientContextSnapshot, client_context_sha256
from consultation_kb.models.profile import ProfileSnapshot, profile_sha256
from consultation_kb.session.repository import SessionRepository
from consultation_kb.session.service import (
    CapabilityGrant,
    SessionService,
    TransportBindingRegistry,
)
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore


def _snapshot(version: int, now: datetime) -> ClientContextSnapshot:
    profile_payload = {
        "schema_version": "client_profile.v1",
        "source_snapshot_sha256": "d" * 64,
        "source_client_commit_version": version,
        "effective_at": now,
        "known_at": now,
        "fixed_epoch": version,
        "sections": (),
        "current_event_ids": (),
    }
    profile = ProfileSnapshot(
        **profile_payload,
        canonical_sha256=profile_sha256(
            {
                **profile_payload,
                "effective_at": now.isoformat().replace("+00:00", "Z"),
                "known_at": now.isoformat().replace("+00:00", "Z"),
            }
        ),
    )
    payload = {
        "schema_version": "client_context.v1",
        "client_id": "client_" + "aaaaaaaaaaaa",
        "profile_revision_id": f"profile-{version}",
        "profile_version": version,
        "profile_sha256": profile.canonical_sha256,
        "fixed_epoch": version,
        "profile": profile,
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


@dataclass
class _MutableContextSource:
    current: ClientContextSnapshot

    def build(self, client_id: str) -> ClientContextSnapshot:
        assert client_id == self.current.client_id
        return self.current


class _Capabilities:
    def __init__(self) -> None:
        self.epoch = 0

    def issue(self, *, client_id: str, session_id: str) -> CapabilityGrant:
        del client_id, session_id
        self.epoch = 1
        return CapabilityGrant(session_handle="opaque-handle-1", capability_epoch=1)

    def renew(
        self,
        *,
        client_id: str,
        session_id: str,
        previous_epoch: int,
    ) -> CapabilityGrant:
        del client_id, session_id
        self.epoch = previous_epoch + 1
        return CapabilityGrant(
            session_handle=f"opaque-handle-{self.epoch}",
            capability_epoch=self.epoch,
        )

    def revoke(self, session_handle: str) -> int:
        del session_handle
        self.epoch += 1
        return self.epoch


def test_begin_freezes_context_and_resume_reissues_capability(tmp_path: Path) -> None:
    connection = connect_database(tmp_path / "client.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "client").apply()
    now = datetime(2026, 7, 19, 3, 0, tzinfo=timezone.utc)
    clock = FixedClock(now)
    values = iter(range(10, 200))
    ids = IdFactory(clock=clock, random_source=lambda: next(values))
    repository = SessionRepository(
        connection,
        content_store=ContentStore(tmp_path / "client-scope"),
        clock=clock,
        id_factory=ids,
    )
    contexts = _MutableContextSource(_snapshot(1, now))
    service = SessionService(
        repository,
        context_source=contexts,
        capability_port=_Capabilities(),
        transport_bindings=TransportBindingRegistry(),
        clock=clock,
        id_factory=ids,
        bound_client_id="client_" + "aaaaaaaaaaaa",
        client_scope_hash="a" * 64,
    )
    try:
        started = service.begin(
            "client_" + "aaaaaaaaaaaa",
            transport_session_id="transport-1",
        )
        assert started.snapshot.profile_version == 1
        assert started.capability_epoch == 1

        contexts.current = _snapshot(2, now)
        assert service.load_fixed_context(started.session_id).profile_version == 1

        resumed = service.resume(
            "client_" + "aaaaaaaaaaaa",
            started.session_id,
            transport_session_id="transport-2",
        )
        assert resumed.snapshot.profile_version == 1
        assert resumed.capability_epoch == 2
        assert resumed.session_handle != started.session_handle
    finally:
        connection.close()
