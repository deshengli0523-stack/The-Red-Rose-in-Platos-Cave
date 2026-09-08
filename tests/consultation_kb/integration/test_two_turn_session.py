from __future__ import annotations

import itertools
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

import anyio
import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from tests.consultation_kb.mcp_runtime_support import NOW, envelope
from tests.consultation_kb.p6_mcp_stdio_support import (
    PreparedP6McpVault,
    SubmittedP6Turn,
    build_prepared_p6_mcp_vault,
    p6_stdio_parameters,
    submit_prepared_p6_turn,
)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.acceptance_id("TURN-01"),
    pytest.mark.skipif(sys.platform != "win32", reason="Windows scoped subprocess"),
]

_TURN_ONE_MESSAGE = "第一轮：我不知道是否还该继续这段关系。"
_TURN_TWO_MESSAGE = "第二轮：我更怕的是重新开始。"
_EDITED_ACTUAL = "我听见你一边舍不得，一边也在怀疑它是否仍适合你。"


@dataclass(frozen=True, slots=True)
class _CompletedSession:
    session_id: str
    turn_one: SubmittedP6Turn
    turn_two: SubmittedP6Turn


def _ids() -> IdFactory:
    return IdFactory(FixedClock(NOW), itertools.count(500).__next__)


def _disclosure_json(payloads: list[dict[str, Any]]) -> str:
    return json.dumps(payloads, ensure_ascii=False, sort_keys=True)


async def _first_lifespan(
    harness: PreparedP6McpVault,
    stderr: TextIO,
) -> _CompletedSession:
    ids = _ids()
    disclosed: list[dict[str, Any]] = []
    async with stdio_client(p6_stdio_parameters(harness), errlog=stderr) as streams:
        async with ClientSession(*streams) as session:
            await session.initialize()
            loaded = envelope(
                await session.call_tool(
                    "load_client_context",
                    {"client_id": harness.mcp.client_a},
                )
            )
            disclosed.append(loaded)
            assert loaded["ok"] is True, loaded
            context = loaded["result"]
            assert isinstance(context, dict)
            handle = context["session_handle"]
            session_id = context["session_id"]
            assert isinstance(handle, str) and isinstance(session_id, str)

            turn_one_id = ids.uuid7()
            appended = envelope(
                await session.call_tool(
                    "append_session_turn",
                    {
                        "session_handle": handle,
                        "turn_id": turn_one_id,
                        "client_message": _TURN_ONE_MESSAGE,
                    },
                )
            )
            disclosed.append(appended)
            assert appended["result"]["state"] == "client_turn_received"

            # Production P6 must never regain the legacy candidate shortcut.
            legacy = envelope(
                await session.call_tool(
                    "store_candidate_set",
                    {
                        "session_handle": handle,
                        "turn_id": turn_one_id,
                        "run_id": ids.uuid7(),
                        "idempotency_key": "turn-one:legacy-candidate-bypass",
                        "candidates": [
                            {"label": "legacy-one", "text": "不得直接写入。"},
                            {"label": "legacy-two", "text": "必须完成七阶段。"},
                        ],
                    },
                )
            )
            disclosed.append(legacy)
            assert legacy["ok"] is False
            assert legacy["error"]["code"] == "GENERATION_STAGE_ORDER_INVALID"

            turn_one = await submit_prepared_p6_turn(
                session,
                session_handle=handle,
                turn_id=turn_one_id,
                run_id=ids.uuid7(),
                idempotency_prefix="turn-one:p6",
            )
            assert len(turn_one.candidate_ids) == 2

            blocked = envelope(
                await session.call_tool(
                    "append_session_turn",
                    {
                        "session_handle": handle,
                        "turn_id": ids.uuid7(),
                        "client_message": "第二轮不能越过实际回复记录。",
                    },
                )
            )
            disclosed.append(blocked)
            assert blocked["ok"] is False
            assert blocked["error"]["code"] == "PREVIOUS_TURN_NOT_CLOSED"

            resumed = envelope(
                await session.call_tool(
                    "load_client_context",
                    {
                        "client_id": harness.mcp.client_a,
                        "resume_session_id": session_id,
                    },
                )
            )
            disclosed.append(resumed)
            assert resumed["ok"] is True
            resumed_context = resumed["result"]
            assert isinstance(resumed_context, dict)
            handle = resumed_context["session_handle"]
            recovery = resumed_context["recovery"]
            assert recovery["pending_action"] == "record_actual_reply"
            assert [
                item["candidate_id"] for item in recovery["pending_candidates"]
            ] == list(turn_one.candidate_ids)
            assert [item["text"] for item in recovery["pending_candidates"]] == list(
                turn_one.candidate_texts
            )

            recorded = envelope(
                await session.call_tool(
                    "record_actual_reply",
                    {
                        "session_handle": handle,
                        "turn_id": turn_one.turn_id,
                        "idempotency_key": "turn-one:actual-reply",
                        "mode": "edited",
                        "candidate_id": turn_one.candidate_ids[0],
                        "actual_text": _EDITED_ACTUAL,
                        "sent_at": "2026-07-19T10:01:00Z",
                    },
                )
            )
            disclosed.append(recorded)
            assert recorded["result"]["state"] == "turn_closed"
            assert recorded["result"]["source_type"] == "edited"

            turn_two_id = ids.uuid7()
            appended_two = envelope(
                await session.call_tool(
                    "append_session_turn",
                    {
                        "session_handle": handle,
                        "turn_id": turn_two_id,
                        "client_message": _TURN_TWO_MESSAGE,
                    },
                )
            )
            disclosed.append(appended_two)
            assert appended_two["result"]["state"] == "client_turn_received"
            turn_two = await submit_prepared_p6_turn(
                session,
                session_handle=handle,
                turn_id=turn_two_id,
                run_id=ids.uuid7(),
                idempotency_prefix="turn-two:p6",
            )
            assert len(turn_two.candidate_ids) == 2
            unknown = envelope(
                await session.call_tool(
                    "record_actual_reply",
                    {
                        "session_handle": handle,
                        "turn_id": turn_two.turn_id,
                        "idempotency_key": "turn-two:actual-reply",
                        "mode": "external_unknown",
                        "confirmed_at": "2026-07-19T10:02:00Z",
                    },
                )
            )
            disclosed.append(unknown)
            assert unknown["result"]["source_type"] == "external_unknown"
            assert unknown["result"]["evidence_gap"] is True

    rendered = _disclosure_json(disclosed)
    assert harness.mcp.client_b not in rendered
    assert harness.mcp.client_b_canary not in rendered
    return _CompletedSession(
        session_id=session_id,
        turn_one=turn_one,
        turn_two=turn_two,
    )


async def _second_lifespan(
    harness: PreparedP6McpVault,
    stderr: TextIO,
    completed: _CompletedSession,
) -> None:
    disclosed: list[dict[str, Any]] = []
    async with stdio_client(p6_stdio_parameters(harness), errlog=stderr) as streams:
        async with ClientSession(*streams) as session:
            await session.initialize()
            resumed = envelope(
                await session.call_tool(
                    "load_client_context",
                    {
                        "client_id": harness.mcp.client_a,
                        "resume_session_id": completed.session_id,
                    },
                )
            )
            disclosed.append(resumed)
            assert resumed["ok"] is True
            result = resumed["result"]
            assert isinstance(result, dict)
            recovery = result["recovery"]
            assert recovery["pending_action"] == "ready_for_next_turn"
            assert [item["turn_id"] for item in recovery["turns"]] == [
                completed.turn_one.turn_id,
                completed.turn_two.turn_id,
            ]
            assert [item["client_message"] for item in recovery["turns"]] == [
                _TURN_ONE_MESSAGE,
                _TURN_TWO_MESSAGE,
            ]
            actual = recovery["actual_replies"]
            assert len(actual) == 2
            assert actual[0]["turn_id"] == completed.turn_one.turn_id
            assert actual[0]["source_type"] == "edited"
            assert actual[0]["candidate_id"] == completed.turn_one.candidate_ids[0]
            assert actual[0]["actual_text"] == _EDITED_ACTUAL
            assert actual[0]["sent_at"] == "2026-07-19T10:01:00Z"
            assert actual[0]["evidence_gap"] is False
            assert actual[1]["turn_id"] == completed.turn_two.turn_id
            assert actual[1]["source_type"] == "external_unknown"
            assert actual[1]["candidate_id"] is None
            assert actual[1]["actual_text"] is None
            assert actual[1]["confirmed_at"] == "2026-07-19T10:02:00Z"
            assert actual[1]["evidence_gap"] is True
            assert recovery["pending_candidates"] == []

    rendered = _disclosure_json(disclosed)
    assert harness.mcp.client_b not in rendered
    assert harness.mcp.client_b_canary not in rendered


def _diagnostics(stream: TextIO) -> str:
    stream.flush()
    stream.seek(0)
    return stream.read()


def test_real_mcp_two_turn_session_rejects_skip_and_recovers_exact_actuals(
    tmp_path: Path,
) -> None:
    harness = build_prepared_p6_mcp_vault(tmp_path)
    first_log = tmp_path / "first-stderr.log"
    second_log = tmp_path / "second-stderr.log"
    try:
        with first_log.open("w+", encoding="utf-8") as first_stderr:
            completed = anyio.run(_first_lifespan, harness, first_stderr)
            first_diagnostics = _diagnostics(first_stderr)
        with second_log.open("w+", encoding="utf-8") as second_stderr:
            anyio.run(_second_lifespan, harness, second_stderr, completed)
            second_diagnostics = _diagnostics(second_stderr)

        for diagnostics in (first_diagnostics, second_diagnostics):
            assert "Traceback" not in diagnostics
            assert harness.mcp.client_b not in diagnostics
            assert harness.mcp.client_b_canary not in diagnostics
            assert _TURN_ONE_MESSAGE not in diagnostics
            assert _TURN_TWO_MESSAGE not in diagnostics
            assert _EDITED_ACTUAL not in diagnostics
    finally:
        harness.close()
