from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest


pytestmark = [
    pytest.mark.fault,
    pytest.mark.acceptance_id("TX-01"),
]

_FAULT_ENV = "CONSULTATION_FAULT_POINT"
_MARKER_NAME = ".consultation-fault-test-vault"
_MARKER_BODY = "consultation-kb-fault-test-v1\n"
_PUBLICATION_OUTCOME = {
    "after_stage_write": "OLD",
    "after_file_fsync": "OLD",
    "before_prepared_tx": "OLD",
    "after_prepared_tx": "NEW",
    "after_verify": "NEW",
    "before_active_tx": "NEW",
    "after_active_tx": "NEW",
    "before_cleanup": "NEW",
}


@dataclass(frozen=True, slots=True)
class _ProcessResult:
    returncode: int
    stdout: str
    stderr: str


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _python() -> Path:
    current = Path(sys.executable).resolve()
    expected = (_repo_root() / ".venv" / "Scripts" / "python.exe").resolve()
    assert current == expected
    return current


def _worker() -> Path:
    return Path(__file__).with_name("fault_worker.py").resolve()


def _run_worker(
    *,
    command: str,
    scenario: str,
    component: str,
    vault: Path,
    control: Path,
    fault_point: str | None = None,
    test_mode: bool = False,
) -> _ProcessResult:
    environment = os.environ.copy()
    environment.pop(_FAULT_ENV, None)
    if fault_point is not None:
        environment[_FAULT_ENV] = fault_point
    arguments = [
        str(_python()),
        str(_worker()),
        command,
        "--scenario",
        scenario,
        "--component",
        component,
        "--vault",
        str(vault),
        "--control",
        str(control),
    ]
    if test_mode:
        arguments.append("--test-mode")
    process = subprocess.Popen(
        arguments,
        cwd=_repo_root(),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = process.communicate(timeout=30)
    return _ProcessResult(process.returncode, stdout, stderr)


def _arm(vault: Path) -> None:
    vault.mkdir(parents=True, exist_ok=True)
    (vault / _MARKER_NAME).write_text(_MARKER_BODY, encoding="ascii")


def _assert_closed_sqlite(vault: Path) -> None:
    database = vault / "fault.sqlite3"
    assert not database.with_name(database.name + "-wal").exists()
    assert not database.with_name(database.name + "-shm").exists()


def _run_publication_cycle(
    tmp_path: Path,
    *,
    scenario: str,
    component: str,
    fault_point: str,
) -> dict[str, str]:
    vault = tmp_path / f"{scenario}-{component}-{fault_point}"
    control = tmp_path / f"{scenario}-{component}-{fault_point}.json"
    _arm(vault)
    crashed = _run_worker(
        command="attempt",
        scenario=scenario,
        component=component,
        vault=vault,
        control=control,
        fault_point=fault_point,
        test_mode=True,
    )
    assert crashed.returncode == 137, crashed.stderr
    assert crashed.stdout == ""
    crashed_connection = sqlite3.connect(vault / "fault.sqlite3")
    try:
        crashed_active = crashed_connection.execute(
            "SELECT version FROM active_artifacts"
        ).fetchone()
        assert crashed_active == (
            (2,) if fault_point in {"after_active_tx", "before_cleanup"} else (1,)
        )
    finally:
        crashed_connection.close()

    results: list[dict[str, str]] = []
    for _ in range(3):
        recovered = _run_worker(
            command="recover-and-query",
            scenario=scenario,
            component=component,
            vault=vault,
            control=control,
        )
        assert recovered.returncode == 0, recovered.stderr
        assert recovered.stdout == ""
        results.append(json.loads(control.read_text(encoding="ascii")))
    assert results[0] == results[1] == results[2]
    result = results[0]
    assert result["state"] == _PUBLICATION_OUTCOME[fault_point]
    assert len(result["content_sha256"]) == 64
    assert len(result["state_sha256"]) == 64

    connection = sqlite3.connect(vault / "fault.sqlite3")
    try:
        active = connection.execute(
            "SELECT epoch, version, content_sha256 FROM active_artifacts"
        ).fetchone()
        assert active is not None
        expected_version = 1 if result["state"] == "OLD" else 2
        assert active[:2] == (expected_version, expected_version)
        assert active[2] == result["content_sha256"]
        assert connection.execute(
            "SELECT epoch, state FROM runtime_epochs ORDER BY epoch"
        ).fetchall() == (
            [(1, "ACTIVE")]
            if expected_version == 1
            else [(1, "RETIRED"), (2, "ACTIVE")]
        )
        assert connection.execute(
            "SELECT count(*) FROM active_artifacts"
        ).fetchone() == (1,)
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        connection.close()
    assert not any(path.is_file() for path in (vault / "staging").rglob("*"))
    _assert_closed_sqlite(vault)
    return result


def _run_approval_cycle(tmp_path: Path, *, fault_point: str) -> dict[str, str]:
    vault = tmp_path / f"approval-{fault_point}"
    control = tmp_path / f"approval-{fault_point}.json"
    _arm(vault)
    crashed = _run_worker(
        command="attempt",
        scenario="approval",
        component="target",
        vault=vault,
        control=control,
        fault_point=fault_point,
        test_mode=True,
    )
    assert crashed.returncode == 137, crashed.stderr
    assert crashed.stdout == ""
    crashed_connection = sqlite3.connect(vault / "fault.sqlite3")
    try:
        assert crashed_connection.execute(
            "SELECT state FROM approval_claims"
        ).fetchone() == ("CLAIMED",)
        expected_target_count = (
            1 if fault_point == "after_target_commit_before_ack" else 0
        )
        assert crashed_connection.execute(
            "SELECT count(*) FROM target_effects"
        ).fetchone() == (expected_target_count,)
    finally:
        crashed_connection.close()
    results: list[dict[str, str]] = []
    for _ in range(3):
        recovered = _run_worker(
            command="recover-and-query",
            scenario="approval",
            component="target",
            vault=vault,
            control=control,
        )
        assert recovered.returncode == 0, recovered.stderr
        results.append(json.loads(control.read_text(encoding="ascii")))
    assert results[0] == results[1] == results[2]
    result = results[0]
    assert result["state"] == "ACKED"
    connection = sqlite3.connect(vault / "fault.sqlite3")
    try:
        assert connection.execute(
            "SELECT state, proof_sha256 FROM approval_claims"
        ).fetchone() == ("ACKED", result["content_sha256"])
        assert connection.execute("SELECT count(*) FROM target_effects").fetchone() == (
            1,
        )
        assert connection.execute(
            "SELECT proof_sha256 FROM target_effects"
        ).fetchone() == (result["content_sha256"],)
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        connection.close()
    _assert_closed_sqlite(vault)
    return result


def test_fault_point_registry_is_exact_and_immutable() -> None:
    from consultation_kb.lifecycle.fault_points import (
        APPROVAL_EXECUTION_FAULT_POINTS,
        FAULT_POINTS,
        FAULT_POINT_REGISTRY,
        MANIFEST_PUBLICATION_FAULT_POINTS,
        OUTBOX_SAGA_FAULT_POINTS,
    )

    assert MANIFEST_PUBLICATION_FAULT_POINTS == tuple(_PUBLICATION_OUTCOME)
    assert APPROVAL_EXECUTION_FAULT_POINTS == (
        "after_approval_claim",
        "before_target_commit",
        "after_target_commit_before_ack",
    )
    assert OUTBOX_SAGA_FAULT_POINTS == (
        "after_source_outbox",
        "after_global_copy",
        "after_global_prepare",
        "after_global_activate",
        "before_source_ack",
    )
    assert FAULT_POINTS == frozenset(
        (
            *MANIFEST_PUBLICATION_FAULT_POINTS,
            *APPROVAL_EXECUTION_FAULT_POINTS,
            *OUTBOX_SAGA_FAULT_POINTS,
        )
    )
    with pytest.raises(TypeError):
        FAULT_POINT_REGISTRY["manifest_publication"] = ()  # type: ignore[index]


def test_guarded_fault_hook_ignores_only_explicit_legacy_phases() -> None:
    from consultation_kb.lifecycle.fault_points import (
        FaultConfigurationError,
        FaultInjector,
    )

    hook = FaultInjector(selected=None).guarded_hook(
        allowed_passthrough=("legacy_phase",),
    )
    hook("legacy_phase")
    hook("after_verify")
    with pytest.raises(FaultConfigurationError, match="^FAULT_POINT_UNKNOWN$"):
        hook("misspelled_phase")
    with pytest.raises(FaultConfigurationError, match="^FAULT_PASSTHROUGH_INVALID$"):
        FaultInjector(selected=None).guarded_hook(
            allowed_passthrough=("after_verify",),
        )


@pytest.mark.parametrize("fault_point", tuple(_PUBLICATION_OUTCOME))
def test_manifest_process_crash_recovers_one_complete_epoch(
    tmp_path: Path,
    fault_point: str,
) -> None:
    _run_publication_cycle(
        tmp_path,
        scenario="manifest",
        component="artifact",
        fault_point=fault_point,
    )


def test_fault_environment_is_rejected_without_explicit_test_mode(
    tmp_path: Path,
) -> None:
    vault = tmp_path / "production-vault"
    control = tmp_path / "production-control.json"
    rejected = _run_worker(
        command="attempt",
        scenario="manifest",
        component="artifact",
        vault=vault,
        control=control,
        fault_point="after_stage_write",
    )
    assert rejected.returncode == 2
    assert rejected.stderr == "FAULT_ENV_FORBIDDEN\n"
    assert not (vault / "fault.sqlite3").exists()


def test_fault_environment_is_rejected_without_vault_marker(
    tmp_path: Path,
) -> None:
    vault = tmp_path / "unmarked-test-vault"
    control = tmp_path / "unmarked-control.json"
    rejected = _run_worker(
        command="attempt",
        scenario="manifest",
        component="artifact",
        vault=vault,
        control=control,
        fault_point="after_stage_write",
        test_mode=True,
    )
    assert rejected.returncode == 2
    assert rejected.stderr == "FAULT_VAULT_MARKER_REQUIRED\n"
    assert not (vault / "fault.sqlite3").exists()
