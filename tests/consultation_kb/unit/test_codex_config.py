from __future__ import annotations

import os
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from consultation_kb import cli


REPO_ROOT = Path(__file__).resolve().parents[3]
TEMPLATE_PATH = REPO_ROOT / ".codex" / "config.template.toml"
WRAPPER_PATH = REPO_ROOT / ".codex" / "start-consultation-kb.ps1"


def _copy_valid_runtime(repo_root: Path) -> None:
    source = REPO_ROOT / ".venv"
    target = repo_root / ".venv"
    (target / "Scripts").mkdir(parents=True)
    shutil.copy2(source / "pyvenv.cfg", target / "pyvenv.cfg")
    shutil.copy2(source / "Scripts" / "python.exe", target / "Scripts" / "python.exe")


def _project_fixture(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    repo_root = workspace / "graphify"
    codex_root = repo_root / ".codex"
    codex_root.mkdir(parents=True)
    (repo_root / ".git").mkdir()
    (workspace / "knowledge-vault").mkdir()
    shutil.copy2(TEMPLATE_PATH, codex_root / TEMPLATE_PATH.name)
    shutil.copy2(WRAPPER_PATH, codex_root / WRAPPER_PATH.name)
    _copy_valid_runtime(repo_root)
    return repo_root


def test_template_configures_one_required_write_approved_stdio_server() -> None:
    raw = TEMPLATE_PATH.read_text(encoding="utf-8")
    data = tomllib.loads(raw)

    assert set(data) == {"mcp_servers"}
    assert set(data["mcp_servers"]) == {"consultation-kb"}
    server = data["mcp_servers"]["consultation-kb"]
    assert server == {
        "command": "powershell.exe",
        "args": [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            "start-consultation-kb.ps1",
        ],
        "cwd": ".",
        "startup_timeout_sec": 30,
        "tool_timeout_sec": 600,
        "required": True,
        "default_tools_approval_mode": "writes",
    }
    lowered = raw.lower()
    assert "secret" not in lowered
    assert "token" not in lowered
    assert "client_id" not in lowered
    assert not re.search(r"[a-z]:[\\/]", raw, flags=re.IGNORECASE)


def test_wrapper_uses_only_fixed_venv_and_keeps_stdout_for_mcp() -> None:
    source = WRAPPER_PATH.read_text(encoding="utf-8")
    lowered = source.lower()

    assert "$psscriptroot" in lowered
    assert "knowledge-vault" in lowered
    assert ".venv\\scripts\\python.exe" in lowered
    assert "pyvenv.cfg" in lowered
    assert "platform.python_implementation" in lowered
    assert "sys.version_info" in lowered
    assert "struct.calcsize" in lowered
    assert "sys.base_prefix" in lowered
    assert "fts5" in lowered
    assert ".cache/codex-runtimes" in lowered
    assert "set-location" in lowered
    assert "consultation_kb.mcp.server" in lowered
    assert "-i -x utf8 -m consultation_kb.mcp.server" in lowered
    assert "pythonutf8" in lowered
    assert "pythonunbuffered" in lowered
    assert "hf_hub_offline" in lowered
    assert "transformers_offline" in lowered
    assert "consultation_vault_root" in lowered
    assert "[console]::error.writeline" in lowered
    assert "exit $lastexitcode" in lowered

    for forbidden in (
        "write-host",
        "write-output",
        "[console]::out",
        "get-command python",
        "get-command py",
        "& python",
        "& py ",
    ):
        assert forbidden not in lowered


def test_codex_local_config_is_ignored_but_template_and_wrapper_are_tracked() -> None:
    ignored = subprocess.run(
        ["git", "check-ignore", "--quiet", ".codex/config.toml"],
        cwd=REPO_ROOT,
        check=False,
    )
    assert ignored.returncode == 0
    for path in (
        ".codex/config.template.toml",
        ".codex/start-consultation-kb.ps1",
    ):
        result = subprocess.run(
            ["git", "check-ignore", "--quiet", path],
            cwd=REPO_ROOT,
            check=False,
        )
        assert result.returncode == 1, path


def test_configure_codex_generates_only_ignored_local_config(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo_root = _project_fixture(tmp_path)

    result = cli.main(["configure-codex", "--repo-root", os.fspath(repo_root)])

    captured = capsys.readouterr()
    assert result == 0, captured.err
    assert captured.err == ""
    generated = repo_root / ".codex" / "config.toml"
    assert generated.is_file()
    assert tomllib.loads(generated.read_text(encoding="utf-8")) == tomllib.loads(
        (repo_root / ".codex" / "config.template.toml").read_text(encoding="utf-8")
    )
    assert not list((repo_root / ".codex").glob(".config.toml.*.tmp"))


def test_configure_codex_fails_closed_without_overwriting_existing_config(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo_root = _project_fixture(tmp_path)
    generated = repo_root / ".codex" / "config.toml"
    existing = "# retained on failed validation\n"
    generated.write_text(existing, encoding="utf-8")
    (repo_root / ".venv" / "pyvenv.cfg").write_text(
        "home = C:\\Users\\synthetic\\.cache\\codex-runtimes\\python\n",
        encoding="utf-8",
    )

    result = cli.main(["configure-codex", "--repo-root", os.fspath(repo_root)])

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err.startswith("consultation-kb configure-codex:")
    assert generated.read_text(encoding="utf-8") == existing
    assert not list((repo_root / ".codex").glob(".config.toml.*.tmp"))


def test_configure_codex_requires_existing_sibling_vault(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo_root = _project_fixture(tmp_path)
    (repo_root.parent / "knowledge-vault").rmdir()

    result = cli.main(["configure-codex", "--repo-root", os.fspath(repo_root)])

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err.startswith("consultation-kb configure-codex:")
    assert not (repo_root / ".codex" / "config.toml").exists()


def test_wrapper_validation_failure_writes_stderr_only(tmp_path: Path) -> None:
    repo_root = _project_fixture(tmp_path)
    (repo_root / ".venv" / "pyvenv.cfg").write_text(
        "home = C:\\Users\\synthetic\\.cache\\codex-runtimes\\python\n"
        "version = 3.12.10\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(repo_root / ".codex" / "start-consultation-kb.ps1"),
        ],
        cwd=repo_root / ".codex",
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
    )

    assert result.returncode == 42
    assert result.stdout == ""
    assert result.stderr.strip() == (
        "consultation-kb MCP startup: STARTUP_VALIDATION_FAILED"
    )
