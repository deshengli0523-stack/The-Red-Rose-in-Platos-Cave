from __future__ import annotations

import hashlib
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import pytest
from consultation_kb.core.errors import ChannelUnavailableError

from consultation_kb.security.scoped_worker import (
    ScopeDenied,
    ScopedWorkerBroker,
    WorkerScopeDescriptor,
)
from consultation_kb.security.worker_protocol import (
    AppendScopedAuditRequest,
    AppendScopedAuditResponse,
    EmptyContextMetadataRequest,
    EmptyContextMetadataResponse,
    PingRequest,
    PingResponse,
    WorkerProtocolError,
    WorkerRequest,
    decode_request,
)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows scoped worker"),
]
REQUEST_ID = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
REQUEST_ID_2 = "017f22e2-79b0-7cc3-98c4-dc0c0c073990"
REQUEST_ID_3 = "017f22e2-79b0-7cc3-98c4-dc0c0c073991"
SYNTHETIC_CLIENT_ID = "client" + "_bbbbbbbbbbbb"


@dataclass
class _MutableCapabilityValidator:
    valid: bool = True
    calls: list[tuple[str, str]] = field(default_factory=list)

    def assert_valid(
        self,
        capability_token: str,
        *,
        required_permission: str,
    ) -> None:
        self.calls.append((capability_token, required_permission))
        if not self.valid:
            raise PermissionError("revoked")


@pytest.fixture
def synthetic_scopes(tmp_path: Path) -> tuple[Path, Path]:
    client_a = tmp_path / "clients" / "opaque-a"
    client_b = tmp_path / "clients" / "opaque-b"
    for root in (client_a, client_b):
        (root / "audit").mkdir(parents=True)
        (root / ".scope-id").write_bytes(
            f"synthetic-{root.name}\n".encode("ascii")
        )
        (root / "client.sqlite3").write_bytes(b"synthetic-db")
        (root / "audit" / "worker.jsonl").write_bytes(b"")
    (client_b / "private-canary.bin").write_bytes(b"CLIENT_B_PRIVATE_CANARY")
    return client_a, client_b


def _broker(
    root: Path,
    validator: _MutableCapabilityValidator,
) -> ScopedWorkerBroker:
    return ScopedWorkerBroker(
        scope=WorkerScopeDescriptor(
            scope_root=root,
            global_descriptor_sha256="a" * 64,
            scope_marker_sha256=hashlib.sha256(
                (root / ".scope-id").read_bytes()
            ).hexdigest(),
        ),
        capability_token="opaque-capability-token",
        validator=validator,
        startup_timeout_seconds=10.0,
        call_timeout_seconds=10.0,
    )


def test_worker_serves_only_three_strict_operations_and_revalidates_each_rpc(
    synthetic_scopes: tuple[Path, Path],
) -> None:
    client_a, _client_b = synthetic_scopes
    validator = _MutableCapabilityValidator()
    broker = _broker(client_a, validator)
    broker.start()
    try:
        assert broker.call(PingRequest(request_id=REQUEST_ID)) == PingResponse(
            request_id=REQUEST_ID
        )
        assert broker.call(
            EmptyContextMetadataRequest(request_id=REQUEST_ID_2)
        ) == EmptyContextMetadataResponse(request_id=REQUEST_ID_2)
        assert broker.call(
            AppendScopedAuditRequest(request_id=REQUEST_ID_3)
        ) == AppendScopedAuditResponse(request_id=REQUEST_ID_3)
        assert broker.is_alive
    finally:
        broker.close()

    assert validator.calls == [
        ("opaque-capability-token", "client_read"),
        ("opaque-capability-token", "client_read"),
        ("opaque-capability-token", "client_read"),
        ("opaque-capability-token", "session_append"),
    ]
    record = json.loads((client_a / "audit" / "worker.jsonl").read_text("ascii"))
    assert record == {
        "event_code": "worker_rpc_completed",
        "request_id": REQUEST_ID_3,
        "schema_version": "1.0",
    }


def test_two_brokers_can_start_concurrently_and_remain_usable(
    synthetic_scopes: tuple[Path, Path],
) -> None:
    client_a, client_b = synthetic_scopes
    first = _broker(client_a, _MutableCapabilityValidator())
    second = _broker(client_b, _MutableCapabilityValidator())
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            starts = (executor.submit(first.start), executor.submit(second.start))
            for started in starts:
                started.result(timeout=15.0)

        assert first.call(PingRequest(request_id=REQUEST_ID)) == PingResponse(
            request_id=REQUEST_ID
        )
        assert second.call(PingRequest(request_id=REQUEST_ID_2)) == PingResponse(
            request_id=REQUEST_ID_2
        )
    finally:
        first.close()
        second.close()


def test_protocol_rejects_cross_scope_and_arbitrary_execution_fields_before_send(
    synthetic_scopes: tuple[Path, Path],
) -> None:
    _client_a, client_b = synthetic_scopes
    probes = (
        {"client_id": SYNTHETIC_CLIENT_ID},
        {"path": str(client_b / "private-canary.bin")},
        {"path": "../opaque-b/private-canary.bin"},
        {"sql": "SELECT * FROM secret"},
        {"shell": "type private-canary.bin"},
        {"payload": {"path": str(client_b)}},
    )
    for probe in probes:
        raw = json.dumps(
            {
                "schema_version": "1.0",
                "operation": "ping",
                "request_id": REQUEST_ID,
                **probe,
            }
        ).encode("utf-8")
        with pytest.raises(WorkerProtocolError, match="WORKER_PROTOCOL_INVALID"):
            decode_request(raw)


def test_broker_maps_untyped_scope_probe_to_one_denial_and_stops_worker(
    synthetic_scopes: tuple[Path, Path],
) -> None:
    client_a, client_b = synthetic_scopes
    broker = _broker(client_a, _MutableCapabilityValidator())
    broker.start()
    probe = {
        "operation": "ping",
        "path": str(client_b / "private-canary.bin"),
        "client_id": SYNTHETIC_CLIENT_ID,
    }

    with pytest.raises(ScopeDenied, match="SCOPE_DENIED") as denied:
        broker.call(cast(WorkerRequest, probe))

    assert str(denied.value) == "SCOPE_DENIED"
    assert "opaque-b" not in str(denied.value)
    assert "CLIENT_B_PRIVATE_CANARY" not in str(denied.value)
    assert broker.closed


def test_revoked_capability_fails_next_rpc_and_stops_existing_worker(
    synthetic_scopes: tuple[Path, Path],
) -> None:
    client_a, _client_b = synthetic_scopes
    validator = _MutableCapabilityValidator()
    broker = _broker(client_a, validator)
    broker.start()
    assert broker.call(PingRequest(request_id=REQUEST_ID)) == PingResponse(
        request_id=REQUEST_ID
    )

    validator.valid = False
    with pytest.raises(ScopeDenied, match="SCOPE_DENIED") as denied:
        broker.call(PingRequest(request_id=REQUEST_ID_2))

    assert str(denied.value) == "SCOPE_DENIED"
    assert not broker.is_alive
    assert broker.closed


def test_worker_fixed_audit_open_rejects_hardlink_to_other_scope(
    synthetic_scopes: tuple[Path, Path],
) -> None:
    client_a, client_b = synthetic_scopes
    audit_a = client_a / "audit" / "worker.jsonl"
    audit_a.unlink()
    os.link(client_b / "audit" / "worker.jsonl", audit_a)
    validator = _MutableCapabilityValidator()
    broker = _broker(client_a, validator)
    broker.start()
    try:
        with pytest.raises(ScopeDenied, match="SCOPE_DENIED") as denied:
            broker.call(AppendScopedAuditRequest(request_id=REQUEST_ID))
        assert str(denied.value) == "SCOPE_DENIED"
        assert "opaque-b" not in str(denied.value)
        assert "CLIENT_B_PRIVATE_CANARY" not in str(denied.value)
    finally:
        broker.close()

    assert (client_b / "audit" / "worker.jsonl").read_bytes() == b""


def test_worker_rejects_scope_marker_tampering_before_ready(
    synthetic_scopes: tuple[Path, Path],
) -> None:
    client_a, client_b = synthetic_scopes
    broker = _broker(client_a, _MutableCapabilityValidator())
    (client_a / ".scope-id").write_bytes(
        (client_b / ".scope-id").read_bytes() + b"tampered"
    )

    with pytest.raises(ScopeDenied, match="SCOPE_DENIED") as denied:
        broker.start()

    assert str(denied.value) == "SCOPE_DENIED"
    assert "opaque-b" not in str(denied.value)
    assert broker.closed


def test_worker_rejects_scope_directory_swap_before_ready(
    synthetic_scopes: tuple[Path, Path],
) -> None:
    client_a, client_b = synthetic_scopes
    broker = _broker(client_a, _MutableCapabilityValidator())
    parked = client_a.parent / "parked-a"
    client_a.rename(parked)
    client_b.rename(client_a)

    with pytest.raises(ScopeDenied, match="SCOPE_DENIED") as denied:
        broker.start()

    assert str(denied.value) == "SCOPE_DENIED"
    assert "opaque-b" not in str(denied.value)
    assert "CLIENT_B_PRIVATE_CANARY" not in str(denied.value)
    assert broker.closed


def test_worker_rejects_scope_directory_swap_after_ready_before_append(
    synthetic_scopes: tuple[Path, Path],
) -> None:
    client_a, client_b = synthetic_scopes
    broker = _broker(client_a, _MutableCapabilityValidator())
    broker.start()
    parked = client_a.parent / "parked-a"
    client_a.rename(parked)
    client_b.rename(client_a)

    with pytest.raises(ScopeDenied, match="SCOPE_DENIED") as denied:
        broker.call(AppendScopedAuditRequest(request_id=REQUEST_ID))

    assert str(denied.value) == "SCOPE_DENIED"
    assert "opaque-b" not in str(denied.value)
    assert "CLIENT_B_PRIVATE_CANARY" not in str(denied.value)
    assert (client_a / "audit" / "worker.jsonl").read_bytes() == b""
    assert (parked / "audit" / "worker.jsonl").read_bytes() == b""
    assert broker.closed


def test_close_clears_lifecycle_and_future_calls_fail_closed(
    synthetic_scopes: tuple[Path, Path],
) -> None:
    client_a, _client_b = synthetic_scopes
    broker = _broker(client_a, _MutableCapabilityValidator())
    broker.start()

    broker.close()

    assert broker.closed
    assert not broker.is_alive
    assert broker._capability_token is None
    assert broker._scope is None
    assert broker._validator is None
    assert broker._connection is None
    assert broker._process is None
    with pytest.raises(ChannelUnavailableError, match="CHANNEL_UNAVAILABLE"):
        broker.call(PingRequest(request_id=REQUEST_ID))


def test_unexpected_worker_exit_clears_token_and_scope_on_next_call(
    synthetic_scopes: tuple[Path, Path],
) -> None:
    client_a, _client_b = synthetic_scopes
    broker = _broker(client_a, _MutableCapabilityValidator())
    broker.start()
    process = broker._process
    assert process is not None
    process.terminate()
    process.join(timeout=5.0)

    with pytest.raises(ChannelUnavailableError, match="CHANNEL_UNAVAILABLE"):
        broker.call(PingRequest(request_id=REQUEST_ID))

    assert broker.closed
    assert broker._capability_token is None
    assert broker._scope is None
    assert broker._validator is None
