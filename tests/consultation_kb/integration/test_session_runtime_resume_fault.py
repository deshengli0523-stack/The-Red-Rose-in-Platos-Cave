from __future__ import annotations

import itertools
import sys
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.errors import ChannelUnavailableError
from consultation_kb.core.ids import IdFactory
from consultation_kb.mcp.context import BoundTransport
from consultation_kb.mcp.schemas import AppendSessionTurnInput, LoadClientContextInput
from consultation_kb.mcp.session_runtime import SessionRuntimeManager
from consultation_kb.security.capability import CapabilityService
from consultation_kb.security.scope_broker import ScopeBroker
from consultation_kb.storage.catalog import ClientCatalog
from consultation_kb.storage.connection import connect_database
from tests.consultation_kb.mcp_runtime_support import NOW, build_mcp_vault


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows scoped subprocess"),
]


class _InjectedResumeFault(RuntimeError):
    pass


def test_resume_recovers_after_capability_renewal_before_client_epoch_commit(
    tmp_path: Path,
) -> None:
    harness = build_mcp_vault(tmp_path)
    connection = connect_database(harness.global_database, mode="writer")
    clock = FixedClock(NOW)
    ids = IdFactory(clock, itertools.count(7001).__next__)
    catalog = ClientCatalog(connection)
    tokens = iter((b"a" * 32, b"b" * 32, b"c" * 32))
    capabilities = CapabilityService(
        connection,
        catalog=catalog,
        clock=clock,
        id_factory=ids,
        token_source=lambda _size: next(tokens),
    )
    scopes = ScopeBroker(
        capability_service=capabilities,
        catalog=catalog,
        clients_root=harness.vault_root / "clients",
        global_database=harness.global_database,
    )
    armed = False

    def fault(point: str) -> None:
        if armed and point == "after_capability_renewal":
            raise _InjectedResumeFault

    manager = SessionRuntimeManager(
        catalog=catalog,
        capability_service=capabilities,
        scope_broker=scopes,
        clock=clock,
        id_factory=ids,
        fault_injector=fault,
    )
    try:
        started = manager.invoke(
            "load_client_context",
            LoadClientContextInput(client_id=harness.client_a),
            binding=None,
        )
        assert isinstance(started, dict)
        session_id = str(started["session_id"])
        old_live = manager._by_client[harness.client_a]

        armed = True
        with pytest.raises(ChannelUnavailableError, match="CHANNEL_UNAVAILABLE"):
            manager.invoke(
                "load_client_context",
                LoadClientContextInput(
                    client_id=harness.client_a,
                    resume_session_id=session_id,
                ),
                binding=None,
            )
        assert capabilities.current_epoch(
            client_id=harness.client_a,
            session_id=session_id,
        ) == 3
        assert manager._by_client[harness.client_a] is old_live
        assert old_live.worker.closed
        assert manager._by_handle[old_live.session_handle] is old_live
        with pytest.raises(ChannelUnavailableError, match="CHANNEL_UNAVAILABLE"):
            manager.invoke(
                "append_session_turn",
                AppendSessionTurnInput(
                    session_handle=old_live.session_handle,
                    turn_id=ids.uuid7(),
                    client_message="must not reach the invalidated worker",
                ),
                binding=BoundTransport(
                    "resume-fault-transport",
                    old_live.session_handle,
                ),
            )

        armed = False
        resumed = manager.invoke(
            "load_client_context",
            LoadClientContextInput(
                client_id=harness.client_a,
                resume_session_id=session_id,
            ),
            binding=None,
        )
        assert isinstance(resumed, dict)
        assert resumed["capability_epoch"] == 4
        assert manager._by_client[harness.client_a] is not old_live
        assert old_live.worker.closed
        assert old_live.session_handle not in manager._by_handle

        client_connection = connect_database(
            harness.client_a_root / "client.sqlite3",
            mode="reader",
        )
        try:
            row = client_connection.execute(
                "SELECT capability_epoch FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        finally:
            client_connection.close()
        assert row == (4,)
    finally:
        manager.close()
        connection.close()
