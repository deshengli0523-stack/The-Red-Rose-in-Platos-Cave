from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from tests.consultation_kb.fault.test_manifest_process_crash import (
    _arm,
    _assert_closed_sqlite,
    _run_worker,
)


pytestmark = [
    pytest.mark.fault,
    pytest.mark.acceptance_id("TX-01"),
]

_FAULT_POINTS = (
    "after_source_outbox",
    "after_global_copy",
    "after_global_prepare",
    "after_global_activate",
    "before_source_ack",
)


def _expected_crash_state(fault_point: str) -> tuple[str, str | None, int]:
    if fault_point == "after_source_outbox":
        return "PENDING", None, 0
    if fault_point == "after_global_copy":
        return "CLAIMED", "COPIED", 0
    if fault_point == "after_global_prepare":
        return "CLAIMED", "PREPARED", 0
    return "CLAIMED", "ACTIVE", 1


@pytest.mark.parametrize("fault_point", _FAULT_POINTS)
def test_outbox_process_crash_recovers_one_global_case_and_exact_source_ack(
    tmp_path: Path,
    fault_point: str,
) -> None:
    vault = tmp_path / f"outbox-{fault_point}"
    control = tmp_path / f"outbox-{fault_point}.json"
    _arm(vault)

    crashed = _run_worker(
        command="attempt",
        scenario="outbox",
        component="case",
        vault=vault,
        control=control,
        fault_point=fault_point,
        test_mode=True,
    )
    assert crashed.returncode == 137, crashed.stderr
    assert crashed.stdout == ""

    expected_source, expected_saga, expected_case_count = _expected_crash_state(
        fault_point
    )
    crashed_connection = sqlite3.connect(vault / "fault.sqlite3")
    try:
        assert crashed_connection.execute(
            "SELECT state FROM source_outbox"
        ).fetchone() == (expected_source,)
        saga = crashed_connection.execute(
            "SELECT state FROM global_sagas"
        ).fetchone()
        if expected_saga is None:
            assert saga is None
        else:
            assert saga == (expected_saga,)
        assert crashed_connection.execute(
            "SELECT count(*) FROM global_cases"
        ).fetchone() == (expected_case_count,)
    finally:
        crashed_connection.close()

    results: list[dict[str, str]] = []
    for _ in range(3):
        recovered = _run_worker(
            command="recover-and-query",
            scenario="outbox",
            component="case",
            vault=vault,
            control=control,
        )
        assert recovered.returncode == 0, recovered.stderr
        assert recovered.stdout == ""
        results.append(json.loads(control.read_text(encoding="ascii")))
    assert results[0] == results[1] == results[2]
    assert set(results[0]) == {"state", "content_sha256", "state_sha256"}
    assert results[0]["state"] == "PUBLISHED"

    content_sha256 = results[0]["content_sha256"]
    assert len(content_sha256) == 64
    assert len(results[0]["state_sha256"]) == 64
    connection = sqlite3.connect(vault / "fault.sqlite3")
    try:
        assert connection.execute(
            "SELECT state, published_global_version FROM source_outbox"
        ).fetchall() == [("PUBLISHED", 1)]
        assert connection.execute(
            "SELECT state, global_version, content_sha256 FROM global_sagas"
        ).fetchall() == [("ACTIVE", 1, content_sha256)]
        assert connection.execute(
            "SELECT version, content_sha256, state FROM global_cases"
        ).fetchall() == [(1, content_sha256, "ACTIVE")]
        assert connection.execute("SELECT count(*) FROM source_outbox").fetchone() == (
            1,
        )
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        connection.close()

    content_path = vault / "cas" / content_sha256[:2] / content_sha256
    assert hashlib.sha256(content_path.read_bytes()).hexdigest() == content_sha256
    assert not any(path.is_file() for path in (vault / "staging").rglob("*"))
    _assert_closed_sqlite(vault)
