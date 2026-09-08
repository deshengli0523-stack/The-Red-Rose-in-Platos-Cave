from __future__ import annotations

import base64
import hashlib
import itertools
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from consultation_kb.core.ids import IdFactory
from consultation_kb.security.capability import (
    CapabilityDenied,
    CapabilityService,
)
from consultation_kb.security.scope_broker import ScopeBroker, ScopeBrokerDenied
from consultation_kb.security.scoped_worker import (
    BoundCapabilityValidator,
    ScopedWorkerBroker,
    ScopeDenied,
    WorkerScopeDescriptor,
)
from consultation_kb.storage.catalog import ClientCatalog
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner


NOW = datetime(2026, 7, 18, 9, 0, tzinfo=timezone.utc)
CLIENT_A = "client_" + "a1b2c3d4e5f6"
CLIENT_B = "client_" + "b1b2c3d4e5f6"


class MutableClock:
    def __init__(self) -> None:
        self.value = NOW

    def now(self) -> datetime:
        return self.value


def _service(
    tmp_path: Path,
) -> tuple[CapabilityService, ClientCatalog, object, MutableClock, IdFactory]:
    connection = connect_database(tmp_path / "global.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    catalog = ClientCatalog(connection)
    for index, client_id in enumerate((CLIENT_A, CLIENT_B), start=1):
        catalog.prepare(
            client_id=client_id,
            directory_object_id=(
                f"client_directory_01800000-0000-7000-8000-{index:012d}"
            ),
            alias_lookup_sha256=f"{index}" * 64,
            created_at=NOW,
        )
        catalog.activate(client_id, activated_at=NOW)
    clock = MutableClock()
    random_values = itertools.count(20)
    ids = IdFactory(clock, lambda: next(random_values))
    tokens = itertools.count(1)
    service = CapabilityService(
        connection,
        catalog=catalog,
        clock=clock,
        id_factory=ids,
        token_source=lambda size: next(tokens).to_bytes(size, "big"),
        ttl=timedelta(minutes=30),
    )
    return service, catalog, connection, clock, ids


def test_issue_stores_only_token_hash_and_validate_returns_frozen_scope(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    service, _catalog, connection, _clock, ids = _service(tmp_path)
    session_id = ids.uuid7()
    try:
        token = service.issue(
            client_id=CLIENT_A,
            session_id=session_id,
            permissions=frozenset({"client_read", "session_append"}),
        )
        raw = base64.urlsafe_b64decode(token + "=")
        assert len(raw) == 32
        row = connection.execute(
            "SELECT token_sha256, permissions_json FROM capabilities"
        ).fetchone()
        assert row == (
            hashlib.sha256(token.encode("ascii")).hexdigest(),
            '["client_read","session_append"]',
        )
        assert token not in repr(row)

        scope = service.validate(
            token,
            session_id=session_id,
            client_id=CLIENT_A,
            required_permissions=frozenset({"client_read"}),
        )
        assert scope.session_id == session_id
        assert scope.permissions == frozenset({"client_read", "session_append"})
        with pytest.raises(ValidationError):
            scope.session_id = ids.uuid7()
        assert token not in caplog.text
    finally:
        connection.close()  # type: ignore[union-attr]


def test_capability_rejects_cross_binding_escalation_expiry_and_revocation(
    tmp_path: Path,
) -> None:
    service, _catalog, connection, clock, ids = _service(tmp_path)
    session_id = ids.uuid7()
    token = service.issue(
        client_id=CLIENT_A,
        session_id=session_id,
        permissions=frozenset({"client_read"}),
    )
    try:
        binding = service.validate_binding(
            token,
            session_id=session_id,
            client_id=CLIENT_A,
            required_permissions=frozenset({"client_read"}),
        )
        service.assert_active_epoch(
            binding.capability_id,
            binding.capability_epoch,
        )
        attempts = (
            {"session_id": ids.uuid7(), "client_id": CLIENT_A},
            {"session_id": session_id, "client_id": CLIENT_B},
        )
        for attempt in attempts:
            with pytest.raises(CapabilityDenied, match="CAPABILITY_DENIED"):
                service.validate(
                    token,
                    required_permissions=frozenset({"client_read"}),
                    **attempt,
                )
        with pytest.raises(CapabilityDenied):
            service.validate(
                token,
                session_id=session_id,
                client_id=CLIENT_A,
                required_permissions=frozenset({"draft_write"}),
            )
        with pytest.raises(CapabilityDenied):
            service.issue(
                client_id=CLIENT_A,
                session_id=session_id,
                permissions=frozenset({"client_read"}),
            )

        clock.value = NOW + timedelta(minutes=30)
        with pytest.raises(CapabilityDenied):
            service.validate(
                token,
                session_id=session_id,
                client_id=CLIENT_A,
                required_permissions=frozenset({"client_read"}),
            )
        clock.value = NOW + timedelta(minutes=5)
        epoch = service.revoke(token)
        assert epoch == 2
        with pytest.raises(CapabilityDenied):
            service.assert_active_epoch(
                binding.capability_id,
                binding.capability_epoch,
            )
        with pytest.raises(CapabilityDenied):
            service.validate(
                token,
                session_id=session_id,
                client_id=CLIENT_A,
                required_permissions=frozenset({"client_read"}),
            )
    finally:
        connection.close()  # type: ignore[union-attr]


def test_renew_atomically_rotates_token_and_rejects_stale_epoch(
    tmp_path: Path,
) -> None:
    service, _catalog, connection, clock, ids = _service(tmp_path)
    session_id = ids.uuid7()
    old_token = service.issue(
        client_id=CLIENT_A,
        session_id=session_id,
        permissions=frozenset({"client_read", "session_append"}),
    )
    old_binding = service.validate_binding(
        old_token,
        session_id=session_id,
        client_id=CLIENT_A,
        required_permissions=frozenset({"client_read"}),
    )
    assert service.current_epoch(client_id=CLIENT_A, session_id=session_id) == 1
    clock.value = NOW + timedelta(minutes=4)
    try:
        new_token = service.renew(
            client_id=CLIENT_A,
            session_id=session_id,
            previous_epoch=old_binding.capability_epoch,
        )

        assert new_token != old_token
        row = connection.execute(
            """
            SELECT capability_id, token_sha256, client_id, session_id,
                   issued_at, expires_at, revoked_at, state, capability_epoch,
                   permissions_json
              FROM capabilities
            """
        ).fetchone()
        assert row == (
            old_binding.capability_id,
            hashlib.sha256(new_token.encode("ascii")).hexdigest(),
            CLIENT_A,
            session_id,
            "2026-07-18T09:04:00.000000Z",
            "2026-07-18T09:34:00.000000Z",
            None,
            "ACTIVE",
            2,
            '["client_read","session_append"]',
        )
        assert connection.execute(
            "SELECT COUNT(*) FROM capabilities WHERE session_id = ?",
            (session_id,),
        ).fetchone() == (1,)

        with pytest.raises(CapabilityDenied, match="CAPABILITY_DENIED"):
            service.validate(
                old_token,
                session_id=session_id,
                client_id=CLIENT_A,
                required_permissions=frozenset({"client_read"}),
            )
        with pytest.raises(CapabilityDenied, match="CAPABILITY_DENIED"):
            service.assert_active_epoch(
                old_binding.capability_id,
                old_binding.capability_epoch,
            )

        new_binding = service.validate_binding(
            new_token,
            session_id=session_id,
            client_id=CLIENT_A,
            required_permissions=frozenset({"session_append"}),
        )
        assert new_binding.capability_id == old_binding.capability_id
        assert new_binding.capability_epoch == 2
        assert service.current_epoch(client_id=CLIENT_A, session_id=session_id) == 2

        with pytest.raises(CapabilityDenied, match="CAPABILITY_DENIED"):
            service.renew(
                client_id=CLIENT_A,
                session_id=session_id,
                previous_epoch=1,
            )
        with pytest.raises(CapabilityDenied, match="CAPABILITY_DENIED"):
            service.current_epoch(client_id=CLIENT_B, session_id=session_id)
        assert connection.execute(
            "SELECT token_sha256, capability_epoch FROM capabilities"
        ).fetchone() == (
            hashlib.sha256(new_token.encode("ascii")).hexdigest(),
            2,
        )
    finally:
        connection.close()  # type: ignore[union-attr]


def test_renew_reactivates_revoked_capability_without_inserting_row(
    tmp_path: Path,
) -> None:
    service, _catalog, connection, clock, ids = _service(tmp_path)
    session_id = ids.uuid7()
    old_token = service.issue(
        client_id=CLIENT_A,
        session_id=session_id,
        permissions=frozenset({"client_read"}),
    )
    clock.value = NOW + timedelta(minutes=1)
    assert service.revoke(old_token) == 2
    clock.value = NOW + timedelta(minutes=2)
    try:
        new_token = service.renew(
            client_id=CLIENT_A,
            session_id=session_id,
            previous_epoch=2,
        )

        binding = service.validate_binding(
            new_token,
            session_id=session_id,
            client_id=CLIENT_A,
            required_permissions=frozenset({"client_read"}),
        )
        assert binding.capability_epoch == 3
        assert connection.execute(
            """
            SELECT COUNT(*), state, revoked_at, capability_epoch
              FROM capabilities WHERE session_id = ?
            """,
            (session_id,),
        ).fetchone() == (1, "ACTIVE", None, 3)
        with pytest.raises(CapabilityDenied, match="CAPABILITY_DENIED"):
            service.validate(
                old_token,
                session_id=session_id,
                client_id=CLIENT_A,
                required_permissions=frozenset({"client_read"}),
            )
    finally:
        connection.close()  # type: ignore[union-attr]


def test_renew_fails_closed_on_binding_mismatch_and_token_collision(
    tmp_path: Path,
) -> None:
    service, catalog, connection, _clock, ids = _service(tmp_path)
    session_id = ids.uuid7()
    token = service.issue(
        client_id=CLIENT_A,
        session_id=session_id,
        permissions=frozenset({"client_read"}),
    )
    original = connection.execute(
        "SELECT token_sha256, state, capability_epoch FROM capabilities"
    ).fetchone()
    try:
        for client_id, attempted_session, previous_epoch in (
            (CLIENT_B, session_id, 1),
            (CLIENT_A, ids.uuid7(), 1),
            (CLIENT_A, session_id, 2),
            (CLIENT_A, session_id, 0),
        ):
            with pytest.raises(CapabilityDenied, match="CAPABILITY_DENIED"):
                service.renew(
                    client_id=client_id,
                    session_id=attempted_session,
                    previous_epoch=previous_epoch,
                )

        raw_token = base64.urlsafe_b64decode(f"{token}=")
        collision_service = CapabilityService(
            connection,
            catalog=catalog,
            clock=_clock,
            id_factory=ids,
            token_source=lambda size: raw_token if size == 32 else b"",
            ttl=timedelta(minutes=30),
        )
        with pytest.raises(CapabilityDenied, match="CAPABILITY_DENIED"):
            collision_service.renew(
                client_id=CLIENT_A,
                session_id=session_id,
                previous_epoch=1,
            )

        assert connection.execute(
            "SELECT token_sha256, state, capability_epoch FROM capabilities"
        ).fetchone() == original
        assert connection.execute("SELECT COUNT(*) FROM capabilities").fetchone() == (
            1,
        )
        service.validate(
            token,
            session_id=session_id,
            client_id=CLIENT_A,
            required_permissions=frozenset({"client_read"}),
        )
    finally:
        connection.close()  # type: ignore[union-attr]


def test_epoch_check_denies_a_retired_client(tmp_path: Path) -> None:
    service, _catalog, connection, _clock, ids = _service(tmp_path)
    session_id = ids.uuid7()
    token = service.issue(
        client_id=CLIENT_A,
        session_id=session_id,
        permissions=frozenset({"client_read"}),
    )
    try:
        binding = service.validate_binding(
            token,
            session_id=session_id,
            client_id=CLIENT_A,
            required_permissions=frozenset({"client_read"}),
        )
        connection.execute(
            "UPDATE clients SET state = 'RETIRED' WHERE client_id = ?",
            (CLIENT_A,),
        )

        with pytest.raises(CapabilityDenied, match="CAPABILITY_DENIED"):
            service.assert_active_epoch(
                binding.capability_id,
                binding.capability_epoch,
            )
    finally:
        connection.close()  # type: ignore[union-attr]


def test_scope_broker_returns_only_exact_validated_client_paths(tmp_path: Path) -> None:
    service, catalog, connection, _clock, ids = _service(tmp_path)
    clients_root = tmp_path / "clients"
    for client_id in (CLIENT_A, CLIENT_B):
        client_root = clients_root / client_id
        client_root.mkdir(parents=True)
        client_connection = connect_database(
            client_root / "client.sqlite3",
            mode="writer",
        )
        MigrationRunner.for_scope(client_connection, "client").apply()
        client_connection.close()
        (client_root / ".scope-id").write_bytes(
            f"{catalog.get(client_id).directory_object_id}\n".encode("ascii")
        )
    session_id = ids.uuid7()
    token = service.issue(
        client_id=CLIENT_A,
        session_id=session_id,
        permissions=frozenset({"client_read"}),
    )
    broker = ScopeBroker(
        capability_service=service,
        catalog=catalog,
        clients_root=clients_root,
        global_database=tmp_path / "global.sqlite3",
    )
    try:
        bound = broker.authorize(
            token,
            session_id=session_id,
            client_id=CLIENT_A,
            required_permissions=frozenset({"client_read"}),
        )
        assert bound.client_root == clients_root / CLIENT_A
        assert bound.client_database == clients_root / CLIENT_A / "client.sqlite3"
        assert bound.scope_marker_sha256 == hashlib.sha256(
            (
                f"{catalog.get(CLIENT_A).directory_object_id}\n"
            ).encode("ascii")
        ).hexdigest()
        assert bound.global_descriptor_sha256 == hashlib.sha256(
            (tmp_path / "global.sqlite3").read_bytes()
        ).hexdigest()
        descriptor = WorkerScopeDescriptor.from_scoped_session(bound)
        assert descriptor.scope_root == bound.client_root
        assert descriptor.scope_marker_sha256 == bound.scope_marker_sha256
        assert descriptor.global_descriptor_sha256 == (
            bound.global_descriptor_sha256
        )
        validator = BoundCapabilityValidator(service, bound)
        validator.assert_valid(token, required_permission="client_read")
        worker = ScopedWorkerBroker.for_scoped_session(
            session=bound,
            capability_token=token,
            capability_service=service,
        )
        worker.close()
        assert worker.closed
        assert CLIENT_B not in repr(bound)
        assert str(clients_root) not in repr(bound)

        with pytest.raises((CapabilityDenied, ScopeBrokerDenied)):
            broker.authorize(
                token,
                session_id=session_id,
                client_id=CLIENT_A.upper(),
                required_permissions=frozenset({"client_read"}),
            )

        (clients_root / CLIENT_A / ".scope-id").write_bytes(
            f"{catalog.get(CLIENT_B).directory_object_id}\n".encode("ascii")
        )
        with pytest.raises(ScopeBrokerDenied, match="SCOPE_DENIED"):
            broker.authorize(
                token,
                session_id=session_id,
                client_id=CLIENT_A,
                required_permissions=frozenset({"client_read"}),
            )

        (clients_root / CLIENT_A / ".scope-id").write_bytes(
            f"{catalog.get(CLIENT_A).directory_object_id}\n".encode("ascii")
        )
        os.link(
            clients_root / CLIENT_A / "client.sqlite3",
            tmp_path / "client-database-alias.sqlite3",
        )
        with pytest.raises(ScopeBrokerDenied, match="SCOPE_DENIED"):
            broker.authorize(
                token,
                session_id=session_id,
                client_id=CLIENT_A,
                required_permissions=frozenset({"client_read"}),
            )
    finally:
        connection.close()  # type: ignore[union-attr]


def test_bound_worker_validator_rejects_revoked_exact_session(
    tmp_path: Path,
) -> None:
    service, catalog, connection, _clock, ids = _service(tmp_path)
    clients_root = tmp_path / "clients"
    client_root = clients_root / CLIENT_A
    client_root.mkdir(parents=True)
    client_connection = connect_database(
        client_root / "client.sqlite3",
        mode="writer",
    )
    MigrationRunner.for_scope(client_connection, "client").apply()
    client_connection.close()
    (client_root / ".scope-id").write_bytes(
        f"{catalog.get(CLIENT_A).directory_object_id}\n".encode("ascii")
    )
    session_id = ids.uuid7()
    token = service.issue(
        client_id=CLIENT_A,
        session_id=session_id,
        permissions=frozenset({"client_read"}),
    )
    try:
        scoped = ScopeBroker(
            capability_service=service,
            catalog=catalog,
            clients_root=clients_root,
            global_database=tmp_path / "global.sqlite3",
        ).authorize(
            token,
            session_id=session_id,
            client_id=CLIENT_A,
            required_permissions=frozenset({"client_read"}),
        )
        validator = BoundCapabilityValidator(service, scoped)
        service.revoke(token)

        with pytest.raises(ScopeDenied, match="SCOPE_DENIED"):
            validator.assert_valid(token, required_permission="client_read")
    finally:
        connection.close()  # type: ignore[union-attr]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junction attack")
def test_scope_broker_rejects_authority_root_and_global_parent_junctions(
    tmp_path: Path,
) -> None:
    authority = tmp_path / "authority"
    authority.mkdir()
    service, catalog, connection, _clock, ids = _service(authority)
    clients_root = authority / "clients"
    client_root = clients_root / CLIENT_A
    client_root.mkdir(parents=True)
    client_connection = connect_database(
        client_root / "client.sqlite3",
        mode="writer",
    )
    MigrationRunner.for_scope(client_connection, "client").apply()
    client_connection.close()
    (client_root / ".scope-id").write_bytes(
        f"{catalog.get(CLIENT_A).directory_object_id}\n".encode("ascii")
    )
    session_id = ids.uuid7()
    token = service.issue(
        client_id=CLIENT_A,
        session_id=session_id,
        permissions=frozenset({"client_read"}),
    )
    clients_link = tmp_path / "clients-link"
    global_parent_link = tmp_path / "global-link"
    try:
        for link, target in (
            (clients_link, clients_root),
            (global_parent_link, authority),
        ):
            result = subprocess.run(
                [
                    "cmd.exe",
                    "/d",
                    "/c",
                    "mklink",
                    "/J",
                    str(link),
                    str(target),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                pytest.skip("junction creation unavailable")

        brokers = (
            ScopeBroker(
                capability_service=service,
                catalog=catalog,
                clients_root=clients_link,
                global_database=authority / "global.sqlite3",
            ),
            ScopeBroker(
                capability_service=service,
                catalog=catalog,
                clients_root=clients_root,
                global_database=global_parent_link / "global.sqlite3",
            ),
        )
        for broker in brokers:
            with pytest.raises(ScopeBrokerDenied, match="SCOPE_DENIED") as denied:
                broker.authorize(
                    token,
                    session_id=session_id,
                    client_id=CLIENT_A,
                    required_permissions=frozenset({"client_read"}),
                )
            assert str(clients_root) not in str(denied.value)
            assert str(authority) not in str(denied.value)
    finally:
        for link in (clients_link, global_parent_link):
            if link.exists():
                os.rmdir(link)
        connection.close()  # type: ignore[union-attr]
