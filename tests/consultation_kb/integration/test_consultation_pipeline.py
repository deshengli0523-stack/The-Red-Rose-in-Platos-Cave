from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, TextIO, cast

import anyio
import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from consultation_kb.approvals.provider import ProtectedProviderSecretStore
from consultation_kb.archive.case_catalog import CaseCatalog
from consultation_kb.security.dpapi import create_secret_protector
from consultation_kb.storage.connection import connect_database
from tests.consultation_kb.integration.test_mcp_stdio import (
    _exercise_real_p6_generation_pipeline,
)
from tests.consultation_kb.mcp_runtime_support import envelope
from tests.consultation_kb.p6_mcp_stdio_support import (
    PreparedP6McpVault,
    build_prepared_p6_mcp_vault,
    p6_stdio_parameters,
)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows scoped subprocess"),
]


def _vault_id(vault_root: Path) -> str:
    identity = os.path.normcase(os.path.normpath(os.fspath(vault_root.resolve())))
    return "vault_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()


async def _restart_and_start_next_session(
    harness: PreparedP6McpVault,
    session_id: str,
    turn_id: str,
    candidate_id: str,
    stderr: TextIO,
) -> dict[str, Any]:
    async with stdio_client(p6_stdio_parameters(harness), errlog=stderr) as streams:
        async with ClientSession(*streams) as session:
            await session.initialize()
            denied_resume = envelope(
                await session.call_tool(
                    "load_client_context",
                    {
                        "client_id": harness.mcp.client_a,
                        "resume_session_id": session_id,
                    },
                )
            )
            assert denied_resume["ok"] is False, denied_resume
            assert denied_resume["error"]["code"] == "SCOPE_DENIED"

            # Archive proposal closes the old session.  A new consultation for
            # the same bound client is allowed, but the closed transcript can
            # never be reopened as a mutable session after process restart.
            started_next = envelope(
                await session.call_tool(
                    "load_client_context",
                    {"client_id": harness.mcp.client_a},
                )
            )

    assert started_next["ok"] is True, started_next
    result = started_next["result"]
    assert isinstance(result, dict)
    assert result["session_id"] != session_id
    assert "recovery" not in result
    return cast(
        dict[str, Any],
        {
            "denied_resume": denied_resume,
            "started_next": started_next,
            "closed_turn_id": turn_id,
            "closed_candidate_id": candidate_id,
        },
    )


def test_real_consultation_survives_restart_after_case_publication(
    tmp_path: Path,
) -> None:
    """Exercise the cross-phase seam not covered by component acceptance tests.

    Existing focused suites own C1 ingestion, profile mutation, case lineage
    filtering, deletion, and rebuild edge cases.  This smoke test deliberately
    keeps one responsibility: prove that a real STDIO consultation, its actual
    reply, and an approved shared-case publication remain mutually consistent
    after the MCP process is restarted.
    """

    harness = build_prepared_p6_mcp_vault(tmp_path)
    ProtectedProviderSecretStore(
        harness.mcp.vault_root / "security" / "review-agent-secret.dpapi",
        protector=create_secret_protector(),
        vault_id=_vault_id(harness.mcp.vault_root),
    ).initialize()
    first_stderr_path = tmp_path / "pipeline-first-stderr.log"
    resumed_stderr_path = tmp_path / "pipeline-resumed-stderr.log"
    try:
        with first_stderr_path.open("w+", encoding="utf-8") as first_stderr:
            completed = anyio.run(
                _exercise_real_p6_generation_pipeline,
                harness,
                first_stderr,
                True,
            )
            first_stderr.flush()
            first_stderr.seek(0)
            first_diagnostics = first_stderr.read()

        with resumed_stderr_path.open("w+", encoding="utf-8") as resumed_stderr:
            restarted = anyio.run(
                _restart_and_start_next_session,
                harness,
                completed["session_id"],
                completed["turn_id"],
                completed["candidate_id"],
                resumed_stderr,
            )
            resumed_stderr.flush()
            resumed_stderr.seek(0)
            resumed_diagnostics = resumed_stderr.read()

        active_cases = CaseCatalog(
            harness.knowledge_harness.connection,
            harness.knowledge_harness.store,
        ).active_cases(purpose="answer_support")
        assert len(active_cases) == 1
        published_version = int(completed["case_published_global_version"])
        assert active_cases[0].case_ref.version == published_version

        client_connection = connect_database(
            harness.mcp.client_a_root / "client.sqlite3",
            mode="reader",
        )
        try:
            assert client_connection.execute(
                "SELECT state, archive_state FROM sessions WHERE session_id = ?",
                (completed["session_id"],),
            ).fetchone() == ("CLOSED", "DRAFT")
            assert client_connection.execute(
                "SELECT source_type, candidate_id FROM actual_replies "
                "WHERE session_id = ? AND turn_id = ?",
                (completed["session_id"], completed["turn_id"]),
            ).fetchone() == ("adopted", completed["candidate_id"])
            assert client_connection.execute(
                "SELECT state, published_global_version FROM outbox_events "
                "WHERE event_id = ?",
                (completed["case_event_id"],),
            ).fetchone() == (
                "PUBLISHED",
                published_version,
            )
        finally:
            client_connection.close()

        public_json = json.dumps(restarted, ensure_ascii=False, sort_keys=True)
        assert harness.mcp.client_a not in public_json
        assert harness.mcp.client_b not in public_json
        assert harness.mcp.client_b_canary not in public_json
        for diagnostics in (first_diagnostics, resumed_diagnostics):
            assert "Traceback" not in diagnostics
            assert completed["client_message"] not in diagnostics
            assert completed["reply_text"] not in diagnostics
            assert harness.mcp.client_b_canary not in diagnostics
            assert str(harness.mcp.vault_root) not in diagnostics
    finally:
        harness.close()
