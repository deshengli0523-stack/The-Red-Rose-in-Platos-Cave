from __future__ import annotations

import itertools
import json
import os
import sqlite3
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pytest

from consultation_kb.core.client_ids import ClientIdFactory
from consultation_kb.core.ids import IdFactory
from consultation_kb.security.capability import CapabilityService
from consultation_kb.security.scope_broker import (
    ScopeBroker,
    ScopeBrokerDenied,
    ScopedSession,
)
from consultation_kb.security.scoped_worker import (
    ScopeDenied,
    ScopedWorkerBroker,
)
from consultation_kb.security.worker_protocol import (
    AppendScopedAuditRequest,
    AppendScopedAuditResponse,
    EmptyContextMetadataRequest,
    EmptyContextMetadataResponse,
    WorkerRequest,
)
from consultation_kb.storage.catalog import ClientCatalog
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner


pytestmark = [
    pytest.mark.integration,
    pytest.mark.acceptance_id("ISO-01"),
    pytest.mark.skipif(sys.platform != "win32", reason="Windows storage isolation"),
]


def _replace_after_transient_share_release(source: Path, target: Path) -> None:
    """Wait briefly for the post-READY rebuild probe to release SQLite."""

    deadline = time.monotonic() + 5.0
    while True:
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


class _FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)


@dataclass(slots=True)
class _IsolationHarness:
    global_connection: sqlite3.Connection
    capability_service: CapabilityService
    catalog: ClientCatalog
    clients_root: Path
    client_a: str
    client_b: str
    session_id: str
    token: str
    bound_scope: ScopedSession
    ids: IdFactory

    def worker(self) -> ScopedWorkerBroker:
        return ScopedWorkerBroker.for_scoped_session(
            session=self.bound_scope,
            capability_token=self.token,
            capability_service=self.capability_service,
            startup_timeout_seconds=10.0,
            call_timeout_seconds=10.0,
        )

    def close(self) -> None:
        self.global_connection.close()


def _build_harness(tmp_path: Path) -> _IsolationHarness:
    vault = tmp_path / "vault"
    clients_root = vault / "clients"
    clients_root.mkdir(parents=True)
    global_database = vault / "global" / "catalog.sqlite3"
    global_database.parent.mkdir()
    global_connection = connect_database(global_database, mode="writer")
    MigrationRunner.for_scope(global_connection, "global").apply()
    clock = _FixedClock()
    ids = IdFactory(clock, itertools.count(1).__next__)
    suffixes = iter(("a1b2c3d4e5f6", "b1b2c3d4e5f6"))
    client_ids = ClientIdFactory(suffix_source=suffixes.__next__)
    client_a = client_ids.new()
    client_b = client_ids.new()
    catalog = ClientCatalog(global_connection)
    for index, client_id in enumerate((client_a, client_b), start=1):
        record = catalog.prepare(
            client_id=client_id,
            directory_object_id=ids.object_id("client_directory"),
            alias_lookup_sha256=f"{index}" * 64,
            created_at=clock.now(),
        )
        catalog.activate(client_id, activated_at=clock.now())
        scope = clients_root / client_id
        (scope / "audit").mkdir(parents=True)
        (scope / ".scope-id").write_bytes(
            f"{record.directory_object_id}\n".encode("ascii")
        )
        client_connection = connect_database(
            scope / "client.sqlite3",
            mode="writer",
        )
        try:
            MigrationRunner.for_scope(client_connection, "client").apply()
        finally:
            client_connection.close()
        (scope / "audit" / "worker.jsonl").write_bytes(b"")
        (scope / "private-canary.bin").write_bytes(
            b"ISO01-PRIVATE-" + str(index).encode("ascii")
        )

    capability_service = CapabilityService(
        global_connection,
        catalog=catalog,
        clock=clock,
        id_factory=ids,
        token_source=lambda size: b"t" * size,
    )
    session_id = ids.uuid7()
    token = capability_service.issue(
        client_id=client_a,
        session_id=session_id,
        permissions=frozenset({"client_read", "session_append"}),
    )
    bound_scope = ScopeBroker(
        capability_service=capability_service,
        catalog=catalog,
        clients_root=clients_root,
        global_database=global_database,
    ).authorize(
        token,
        session_id=session_id,
        client_id=client_a,
        required_permissions=frozenset({"client_read", "session_append"}),
    )
    return _IsolationHarness(
        global_connection=global_connection,
        capability_service=capability_service,
        catalog=catalog,
        clients_root=clients_root,
        client_a=client_a,
        client_b=client_b,
        session_id=session_id,
        token=token,
        bound_scope=bound_scope,
        ids=ids,
    )


def _assert_opaque_denial(
    denied: BaseException,
    *,
    forbidden: tuple[str, ...],
) -> tuple[type[BaseException], str, str]:
    assert str(denied) == "SCOPE_DENIED"
    disclosure_surface = f"{denied!s}\n{denied!r}"
    for value in forbidden:
        assert value not in disclosure_surface
    assert "object_count" not in disclosure_surface
    assert "exists" not in disclosure_surface.lower()
    return type(denied), str(denied), repr(denied)


def test_real_capability_broker_and_worker_are_bound_only_to_client_a(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    client_a_root = harness.clients_root / harness.client_a
    client_b_root = harness.clients_root / harness.client_b
    worker = harness.worker()
    try:
        worker.start()
        metadata_request = EmptyContextMetadataRequest(
            request_id=harness.ids.uuid7()
        )
        assert worker.call(metadata_request) == EmptyContextMetadataResponse(
            request_id=metadata_request.request_id
        )
        audit_request = AppendScopedAuditRequest(request_id=harness.ids.uuid7())
        assert worker.call(audit_request) == AppendScopedAuditResponse(
            request_id=audit_request.request_id
        )
        audit = json.loads(
            (client_a_root / "audit" / "worker.jsonl").read_text("ascii")
        )
        assert audit["request_id"] == audit_request.request_id
        assert (client_b_root / "audit" / "worker.jsonl").read_bytes() == b""
        assert (client_b_root / "private-canary.bin").read_bytes() == (
            b"ISO01-PRIVATE-2"
        )
        assert repr(harness.bound_scope) == "<ScopedSession redacted>"
    finally:
        worker.close()
        harness.close()


def test_existing_and_missing_client_id_probes_are_indistinguishable(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    missing_client = "client_" + "c1b2c3d4e5f6"
    broker = ScopeBroker(
        capability_service=harness.capability_service,
        catalog=harness.catalog,
        clients_root=harness.clients_root,
        global_database=tmp_path / "vault" / "global" / "catalog.sqlite3",
    )
    signatures = []
    try:
        for probed_client in (harness.client_b, missing_client):
            with pytest.raises(ScopeBrokerDenied) as denied:
                broker.authorize(
                    harness.token,
                    session_id=harness.session_id,
                    client_id=probed_client,
                    required_permissions=frozenset({"client_read"}),
                )
            signatures.append(
                _assert_opaque_denial(
                    denied.value,
                    forbidden=(
                        harness.client_b,
                        missing_client,
                        str(harness.clients_root),
                    ),
                )
            )
        assert signatures[0] == signatures[1]
    finally:
        harness.close()


def test_absolute_parent_and_reparse_path_probes_are_uniformly_denied(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    client_b_root = harness.clients_root / harness.client_b
    probes = (
        {"client_id": harness.client_b},
        {"path": str(client_b_root / "private-canary.bin")},
        {"path": f"../{harness.client_b}/private-canary.bin"},
        {"path": "symlink-to-b/private-canary.bin"},
        {"path": "junction-to-b/private-canary.bin"},
    )
    signatures = []
    try:
        for probe in probes:
            worker = harness.worker()
            worker.start()
            try:
                with pytest.raises(ScopeDenied) as denied:
                    worker.call(cast(WorkerRequest, probe))
                signatures.append(
                    _assert_opaque_denial(
                        denied.value,
                        forbidden=(
                            harness.client_b,
                            str(client_b_root),
                            "private-canary.bin",
                            "symlink-to-b",
                            "junction-to-b",
                        ),
                    )
                )
            finally:
                worker.close()
        assert all(signature == signatures[0] for signature in signatures)
    finally:
        harness.close()


def _deny_audit_reparse(
    harness: _IsolationHarness,
    *,
    kind: str,
) -> bool:
    client_a_root = harness.clients_root / harness.client_a
    client_b_root = harness.clients_root / harness.client_b
    audit = client_a_root / "audit"
    original = client_a_root / "audit-original"
    os.replace(audit, original)
    created = False
    try:
        if kind == "symlink":
            try:
                os.symlink(client_b_root / "audit", audit, target_is_directory=True)
            except OSError:
                return False
        else:
            result = subprocess.run(
                [
                    "cmd.exe",
                    "/d",
                    "/c",
                    "mklink",
                    "/J",
                    str(audit),
                    str(client_b_root / "audit"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                pytest.fail("junction creation unavailable for ISO-01")
        created = True
        worker = harness.worker()
        worker.start()
        try:
            with pytest.raises(ScopeDenied) as denied:
                worker.call(
                    AppendScopedAuditRequest(request_id=harness.ids.uuid7())
                )
            _assert_opaque_denial(
                denied.value,
                forbidden=(harness.client_b, str(client_b_root), kind),
            )
        finally:
            worker.close()
        assert (client_b_root / "audit" / "worker.jsonl").read_bytes() == b""
        return True
    finally:
        if created and audit.exists():
            os.rmdir(audit)
        os.replace(original, audit)


def test_worker_rejects_symlink_junction_reparse_and_hardlink_attacks(
    tmp_path: Path,
    record_property: Callable[[str, object], None],
) -> None:
    harness = _build_harness(tmp_path)
    client_a_root = harness.clients_root / harness.client_a
    client_b_root = harness.clients_root / harness.client_b
    try:
        symlink_tested = _deny_audit_reparse(harness, kind="symlink")
        assert _deny_audit_reparse(harness, kind="junction")
        record_property("symlink_attack_available", symlink_tested)

        audit_a = client_a_root / "audit" / "worker.jsonl"
        audit_a.unlink()
        os.link(client_b_root / "audit" / "worker.jsonl", audit_a)
        worker = harness.worker()
        worker.start()
        try:
            with pytest.raises(ScopeDenied) as denied:
                worker.call(
                    AppendScopedAuditRequest(request_id=harness.ids.uuid7())
                )
            _assert_opaque_denial(
                denied.value,
                forbidden=(harness.client_b, str(client_b_root), "hardlink"),
            )
        finally:
            worker.close()
        assert (client_b_root / "audit" / "worker.jsonl").read_bytes() == b""
    finally:
        harness.close()


def test_directory_exchange_after_authorization_is_denied_before_ready(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    client_a_root = harness.clients_root / harness.client_a
    client_b_root = harness.clients_root / harness.client_b
    swap = harness.clients_root / ".scope-swap"
    swapped = False
    try:
        os.replace(client_a_root, swap)
        os.replace(client_b_root, client_a_root)
        os.replace(swap, client_b_root)
        swapped = True
        worker = harness.worker()
        try:
            with pytest.raises(ScopeDenied) as denied:
                worker.start()
            _assert_opaque_denial(
                denied.value,
                forbidden=(
                    harness.client_b,
                    str(client_b_root),
                    "ISO01-PRIVATE-2",
                ),
            )
            assert worker.closed
        finally:
            worker.close()
    finally:
        if swapped:
            os.replace(client_a_root, swap)
            os.replace(client_b_root, client_a_root)
            os.replace(swap, client_b_root)
        harness.close()


def test_directory_exchange_after_ready_is_denied_before_append(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    client_a_root = harness.clients_root / harness.client_a
    client_b_root = harness.clients_root / harness.client_b
    parked_a = harness.clients_root / ".ready-swap-a"
    worker = harness.worker()
    swapped = False
    try:
        worker.start()
        _replace_after_transient_share_release(client_a_root, parked_a)
        os.replace(client_b_root, client_a_root)
        swapped = True

        with pytest.raises(ScopeDenied) as denied:
            worker.call(
                AppendScopedAuditRequest(request_id=harness.ids.uuid7())
            )

        _assert_opaque_denial(
            denied.value,
            forbidden=(
                harness.client_b,
                str(client_b_root),
                "ISO01-PRIVATE-2",
            ),
        )
        assert worker.closed
        assert (client_a_root / "audit" / "worker.jsonl").read_bytes() == b""
        assert (client_a_root / "private-canary.bin").read_bytes() == (
            b"ISO01-PRIVATE-2"
        )
        assert (parked_a / "audit" / "worker.jsonl").read_bytes() == b""
    finally:
        worker.close()
        if swapped:
            os.replace(client_a_root, client_b_root)
            os.replace(parked_a, client_a_root)
        harness.close()
