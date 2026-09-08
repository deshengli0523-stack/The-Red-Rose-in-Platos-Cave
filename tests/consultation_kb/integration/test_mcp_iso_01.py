from __future__ import annotations

import hashlib
import itertools
import json
import sys
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from consultation_kb.core.clock import SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.security.capability import CapabilityService
from consultation_kb.storage.catalog import ClientCatalog
from consultation_kb.storage.connection import connect_database
from tests.consultation_kb.mcp_runtime_support import (
    McpVaultHarness,
    build_mcp_vault,
    diagnostics,
    envelope,
)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.acceptance_id("ISO-01"),
    pytest.mark.skipif(sys.platform != "win32", reason="Windows scoped subprocess"),
]


def _revoke(harness: McpVaultHarness, token: str) -> None:
    connection = connect_database(harness.global_database, mode="writer")
    clock = SystemClock()
    try:
        service = CapabilityService(
            connection,
            catalog=ClientCatalog(connection),
            clock=clock,
            id_factory=IdFactory(clock, itertools.count(900).__next__),
        )
        assert service.revoke(token) == 2
    finally:
        connection.close()


async def _exercise_iso(harness: McpVaultHarness, stderr: object) -> str:
    disclosed: list[object] = []
    ids = IdFactory(SystemClock(), itertools.count(700).__next__)
    async with stdio_client(harness.parameters(), errlog=stderr) as streams:  # type: ignore[arg-type]
        async with ClientSession(*streams) as session:
            await session.initialize()
            loaded = envelope(
                await session.call_tool(
                    "load_client_context",
                    {"client_id": harness.client_a},
                )
            )
            disclosed.append(loaded)
            assert loaded["ok"] is True, loaded
            context = loaded["result"]
            assert isinstance(context, dict)
            handle = context["session_handle"]
            assert isinstance(handle, str)

            cross_client = envelope(
                await session.call_tool(
                    "load_client_context",
                    {"client_id": harness.client_b},
                )
            )
            disclosed.append(cross_client)
            assert cross_client["ok"] is False
            assert cross_client["error"]["code"] == "TASK_SCOPE_ALREADY_BOUND"  # type: ignore[index]

            private_path = r"C:\PRIVATE-B\client.sqlite3"
            rejected = envelope(
                await session.call_tool(
                    "append_session_turn",
                    {
                        "session_handle": handle,
                        "turn_id": ids.uuid7(),
                        "client_message": "合法正文不应掩盖非法选择器。",
                        "client_id": harness.client_b,
                        "path": private_path,
                    },
                )
            )
            disclosed.append(rejected)
            assert rejected["ok"] is False
            assert rejected["error"]["code"] == "INVALID_ARGUMENTS"  # type: ignore[index]

            _revoke(harness, handle)
            revoked = envelope(
                await session.call_tool(
                    "append_session_turn",
                    {
                        "session_handle": handle,
                        "turn_id": ids.uuid7(),
                        "client_message": "已撤销能力不能继续写入。",
                    },
                )
            )
            disclosed.append(revoked)
            assert revoked["ok"] is False
            assert revoked["error"]["code"] == "SCOPE_DENIED"  # type: ignore[index]

    rendered = json.dumps(disclosed, ensure_ascii=False, sort_keys=True)
    assert harness.client_b not in rendered
    assert harness.client_b_canary not in rendered
    assert r"C:\PRIVATE-B\client.sqlite3" not in rendered
    assert hashlib.sha256(harness.client_b_canary.encode()).hexdigest() not in rendered
    return rendered


def test_real_mcp_transport_permanently_binds_a_and_rejects_revoked_handle(
    tmp_path: Path,
) -> None:
    harness = build_mcp_vault(tmp_path)
    stderr_path = tmp_path / "iso-stderr.log"
    with stderr_path.open("w+", encoding="utf-8") as stderr:
        anyio.run(_exercise_iso, harness, stderr)
        output = diagnostics(stderr)
    assert harness.client_b not in output
    assert harness.client_b_canary not in output
    assert "PRIVATE-B" not in output
    connection = connect_database(
        harness.client_b_root / "client.sqlite3",
        mode="reader",
    )
    try:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone() == (0,)
    finally:
        connection.close()
