from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
SPEC_PATH = REPO_ROOT / "requirements" / "consultation-python.toml"
RESOLVER_PATH = REPO_ROOT / "scripts" / "resolve_consultation_python.ps1"
POWERSHELL = "powershell.exe"


def _candidate(tmp_path: Path, name: str) -> str:
    path = tmp_path / name / "python.exe"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"synthetic candidate placeholder")
    return str(path.resolve())


def _probe(
    *,
    version: tuple[int, int, int] = (3, 12, 10),
    bits: int = 64,
    fts5: bool = True,
    base_executable: str = r"C:\Program Files\Python312\python.exe",
    implementation: str = "CPython",
    venv_available: bool = True,
    ssl_available: bool = True,
) -> dict[str, Any]:
    return {
        "implementation": implementation,
        "version": list(version),
        "bits": bits,
        "venv_available": venv_available,
        "ssl_available": ssl_available,
        "sqlite_version": "3.49.1",
        "fts5_available": fts5,
        "executable": base_executable,
        "base_executable": base_executable,
    }


def _write_fake_candidate_runner(tmp_path: Path, scenario: dict[str, Any]) -> tuple[Path, Path, Path]:
    scenario_path = tmp_path / "resolver-scenario.json"
    log_path = tmp_path / "resolver-runner.jsonl"
    runner_path = tmp_path / "fake-candidate-runner.ps1"
    scenario_path.write_text(json.dumps(scenario), encoding="utf-8")
    runner_path.write_text(
        r'''param(
    [Parameter(Mandatory = $true)][string]$Operation,
    [string]$Value = ""
)
$ErrorActionPreference = "Stop"
$scenario = Get-Content -Raw -Encoding UTF8 $env:CONSULTATION_RESOLVER_SCENARIO | ConvertFrom-Json
[pscustomobject]@{ operation = $Operation; value = $Value } |
    ConvertTo-Json -Compress |
    Add-Content -Encoding UTF8 $env:CONSULTATION_RESOLVER_LOG

switch ($Operation) {
    "HasPymanager" {
        if ($scenario.pymanager_available) { "true" } else { "false" }
    }
    "HasLegacyLauncher" {
        if ($scenario.legacy_available) { "true" } else { "false" }
    }
    "DiscoverPymanager" {
        @($scenario.pymanager_candidates) | ForEach-Object { [string]$_ }
    }
    "DiscoverLegacy" {
        @($scenario.legacy_candidates) | ForEach-Object { [string]$_ }
    }
    "DiscoverRegistry" {
        @($scenario.registry_candidates) | ForEach-Object { [string]$_ }
    }
    "ProbeCandidate" {
        $property = $scenario.probes.PSObject.Properties |
            Where-Object { $_.Name -ieq $Value } |
            Select-Object -First 1
        if ($null -eq $property) {
            [Console]::Error.WriteLine("No synthetic probe registered for candidate")
            exit 7
        }
        $property.Value | ConvertTo-Json -Compress -Depth 8
    }
    default {
        [Console]::Error.WriteLine("Unknown fake runner operation")
        exit 8
    }
}
''',
        encoding="utf-8-sig",
    )
    return runner_path, scenario_path, log_path


def _run_fake_resolver(
    tmp_path: Path,
    scenario: dict[str, Any],
    *,
    explicit_candidate: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[dict[str, str]]]:
    runner_path, scenario_path, log_path = _write_fake_candidate_runner(tmp_path, scenario)
    env = os.environ.copy()
    env["CONSULTATION_RESOLVER_SCENARIO"] = str(scenario_path)
    env["CONSULTATION_RESOLVER_LOG"] = str(log_path)
    if explicit_candidate is None:
        env.pop("CONSULTATION_PYTHON", None)
    else:
        env["CONSULTATION_PYTHON"] = explicit_candidate
    if extra_env:
        env.update(extra_env)

    result = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(RESOLVER_PATH),
            "-SpecPath",
            str(SPEC_PATH),
            "-CandidateRunnerScript",
            str(runner_path),
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    events = []
    if log_path.exists():
        events = [
            json.loads(line)
            for line in log_path.read_text(encoding="utf-8-sig").splitlines()
            if line.strip()
        ]
    return result, events


def _scenario(
    *,
    probes: dict[str, dict[str, Any]],
    pymanager_available: bool = False,
    legacy_available: bool = False,
    pymanager_candidates: list[str] | None = None,
    legacy_candidates: list[str] | None = None,
    registry_candidates: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "pymanager_available": pymanager_available,
        "legacy_available": legacy_available,
        "pymanager_candidates": pymanager_candidates or [],
        "legacy_candidates": legacy_candidates or [],
        "registry_candidates": registry_candidates or [],
        "probes": probes,
    }


def _run_live_resolver(
    *,
    explicit_candidate: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if explicit_candidate is None:
        env.pop("CONSULTATION_PYTHON", None)
    else:
        env["CONSULTATION_PYTHON"] = explicit_candidate
    if extra_env:
        env.update(extra_env)

    return subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(RESOLVER_PATH),
            "-SpecPath",
            str(SPEC_PATH),
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def _write_pymanager_shim(tmp_path: Path, candidates: list[Path]) -> Path:
    shim_directory = tmp_path / "pymanager-shim"
    shim_directory.mkdir()
    shim_path = shim_directory / "pymanager.cmd"
    shim_path.write_text(
        "\r\n".join(
            [
                "@echo off",
                'if /I not "%~1"=="list" exit /b 9',
                *(f'echo "{candidate}"' for candidate in candidates),
                "exit /b 0",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return shim_directory


def test_runtime_spec_freezes_supported_python_contract() -> None:
    data = tomllib.loads(SPEC_PATH.read_text(encoding="utf-8"))
    assert data["python"] == {
        "implementation": "CPython",
        "series": "3.12",
        "min_patch": 10,
        "bits": 64,
        "venv": True,
    }
    assert data["paths"]["forbidden_fragments"] == [
        ".cache/codex-runtimes",
        ".cache\\codex-runtimes",
    ]
    assert data["resolver"]["not_found_exit_code"] == 42


def test_explicit_valid_python_is_selected_and_stdout_is_path_only(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, "explicit")
    result, events = _run_fake_resolver(
        tmp_path,
        _scenario(probes={candidate: _probe()}),
        explicit_candidate=candidate,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == candidate
    assert [event["operation"] for event in events] == ["ProbeCandidate"]


@pytest.mark.parametrize(
    ("probe", "reason"),
    [
        (_probe(version=(3, 13, 0)), "series"),
        (_probe(bits=32), "64-bit"),
        (_probe(fts5=False), "FTS5"),
        (_probe(venv_available=False), "venv"),
        (_probe(ssl_available=False), "SSL"),
    ],
)
def test_invalid_explicit_candidate_fails_closed(
    tmp_path: Path,
    probe: dict[str, Any],
    reason: str,
) -> None:
    candidate = _candidate(tmp_path, reason.replace("-", "_"))
    result, _ = _run_fake_resolver(
        tmp_path,
        _scenario(probes={candidate: probe}),
        explicit_candidate=candidate,
    )

    assert result.returncode == 42
    assert result.stdout == ""
    assert reason.lower() in result.stderr.lower()


@pytest.mark.parametrize("forbidden_kind", ["codex", "repository", "vault", "temporary"])
def test_forbidden_base_executable_locations_are_rejected(
    tmp_path: Path,
    forbidden_kind: str,
) -> None:
    candidate = _candidate(tmp_path, forbidden_kind)
    extra_env: dict[str, str] = {}
    if forbidden_kind == "codex":
        base = r"C:\Users\synthetic\.cache\codex-runtimes\runtime\python.exe"
    elif forbidden_kind == "repository":
        base = str(REPO_ROOT / "synthetic-runtime" / "python.exe")
    elif forbidden_kind == "vault":
        vault = tmp_path / "synthetic-vault"
        base = str(vault / "runtime" / "python.exe")
        extra_env["CONSULTATION_VAULT_ROOT"] = str(vault)
    else:
        base = str(tmp_path / "synthetic-temp-runtime" / "python.exe")
        extra_env["TEMP"] = str(tmp_path)
        extra_env["TMP"] = str(tmp_path)

    result, _ = _run_fake_resolver(
        tmp_path,
        _scenario(probes={candidate: _probe(base_executable=base)}),
        explicit_candidate=candidate,
        extra_env=extra_env,
    )

    assert result.returncode == 42
    assert result.stdout == ""
    assert "forbidden" in result.stderr.lower()


def test_pymanager_group_outranks_legacy_and_uses_highest_valid_patch(tmp_path: Path) -> None:
    manager_310 = _candidate(tmp_path, "manager-310")
    manager_311 = _candidate(tmp_path, "manager-311")
    legacy_312 = _candidate(tmp_path, "legacy-312")
    result, events = _run_fake_resolver(
        tmp_path,
        _scenario(
            pymanager_available=True,
            legacy_available=True,
            pymanager_candidates=[manager_310, manager_311],
            legacy_candidates=[legacy_312],
            probes={
                manager_310: _probe(version=(3, 12, 10)),
                manager_311: _probe(version=(3, 12, 11)),
                legacy_312: _probe(version=(3, 12, 12)),
            },
        ),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == manager_311
    operations = [event["operation"] for event in events]
    assert operations[:2] == ["HasPymanager", "DiscoverPymanager"]
    assert "DiscoverLegacy" not in operations


def test_legacy_launcher_is_used_when_pymanager_is_unavailable(tmp_path: Path) -> None:
    legacy = _candidate(tmp_path, "legacy")
    result, events = _run_fake_resolver(
        tmp_path,
        _scenario(
            pymanager_available=False,
            legacy_available=True,
            legacy_candidates=[legacy],
            probes={legacy: _probe()},
        ),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == legacy
    operations = [event["operation"] for event in events]
    assert operations[:3] == [
        "HasPymanager",
        "HasLegacyLauncher",
        "DiscoverLegacy",
    ]


def test_registry_candidate_is_used_without_launchers(tmp_path: Path) -> None:
    registered = _candidate(tmp_path, "registered")
    result, events = _run_fake_resolver(
        tmp_path,
        _scenario(
            registry_candidates=[registered],
            probes={registered: _probe()},
        ),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == registered
    assert [event["operation"] for event in events] == [
        "HasPymanager",
        "HasLegacyLauncher",
        "DiscoverRegistry",
        "ProbeCandidate",
    ]


def test_no_candidate_returns_dedicated_exit_code_and_no_stdout(tmp_path: Path) -> None:
    result, _ = _run_fake_resolver(tmp_path, _scenario(probes={}))
    assert result.returncode == 42
    assert result.stdout == ""
    assert "no compatible" in result.stderr.lower()


def test_live_explicit_nonlaunchable_candidate_is_rejected_without_stack_trace() -> None:
    nonlaunchable = Path(os.environ["SystemRoot"]) / "System32" / "kernel32.dll"
    assert nonlaunchable.is_file()

    result = _run_live_resolver(explicit_candidate=str(nonlaunchable))

    assert result.returncode == 42
    assert result.stdout == ""
    diagnostic_lines = [line for line in result.stderr.splitlines() if line.strip()]
    assert len(diagnostic_lines) == 1
    assert "candidate probe failed" in diagnostic_lines[0].lower()
    assert "candidate process could not be launched" in diagnostic_lines[0].lower()
    assert "applicationfailedexception" not in result.stderr.lower()
    assert "categoryinfo" not in result.stderr.lower()
    assert "fullyqualifiederrorid" not in result.stderr.lower()


def test_live_discovery_skips_nonlaunchable_candidate_and_selects_valid_python(
    tmp_path: Path,
) -> None:
    nonlaunchable = Path(os.environ["SystemRoot"]) / "System32" / "kernel32.dll"
    base_python = Path(sys.base_prefix) / "python.exe"
    assert nonlaunchable.is_file()
    assert base_python.is_file()
    shim_directory = _write_pymanager_shim(
        tmp_path,
        [nonlaunchable, base_python],
    )

    result = _run_live_resolver(
        extra_env={"PATH": os.pathsep.join([str(shim_directory), os.environ["PATH"]])}
    )

    assert result.returncode == 0, result.stderr
    assert Path(result.stdout.strip()).resolve() == base_python.resolve()
    assert "rejected pymanager candidate: candidate probe failed" in result.stderr.lower()
    assert "applicationfailedexception" not in result.stderr.lower()
    assert "categoryinfo" not in result.stderr.lower()
    assert "fullyqualifiederrorid" not in result.stderr.lower()


def test_resolver_never_contains_install_or_launcher_removal_commands() -> None:
    source = RESOLVER_PATH.read_text(encoding="utf-8").lower()
    assert "py install" not in source
    assert "uninstall" not in source
    assert "remove-item" not in source


def test_real_venv_has_an_independent_non_codex_base() -> None:
    venv_root = Path(sys.prefix)
    cfg = (venv_root / "pyvenv.cfg").read_text(encoding="utf-8")
    normalized_base = str(Path(sys.base_prefix).resolve()).replace("\\", "/").lower()
    normalized_cfg = cfg.replace("\\", "/").lower()

    assert sys.prefix != sys.base_prefix
    assert ".cache/codex-runtimes" not in normalized_base
    assert ".cache/codex-runtimes" not in normalized_cfg
    assert not Path(sys.base_prefix).resolve().is_relative_to(REPO_ROOT.resolve())


def test_live_resolver_accepts_the_current_independent_base() -> None:
    base_python = Path(sys.base_prefix) / "python.exe"
    assert base_python.is_file()
    result = _run_live_resolver(explicit_candidate=str(base_python))
    assert result.returncode == 0, result.stderr
    assert Path(result.stdout.strip()).resolve() == base_python.resolve()
