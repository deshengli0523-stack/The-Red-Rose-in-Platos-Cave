from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest


UNSUPPORTED_PYTHON_MESSAGE = (
    "consultation-kb requires Python 3.12 or later; current interpreter is unsupported."
)


def _pyproject(repo_root: Path) -> dict[str, Any]:
    return tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))


def test_pyproject_registers_consultation_console_script(repo_root: Path) -> None:
    data = _pyproject(repo_root)
    assert data["project"]["scripts"]["consultation-kb"] == (
        "consultation_kb.entrypoint:main"
    )


def test_pyproject_packages_consultation_kb(repo_root: Path) -> None:
    data = _pyproject(repo_root)
    assert data["tool"]["setuptools"]["packages"]["find"]["include"] == [
        "graphify*",
        "consultation_kb*",
    ]


def test_pyproject_defines_consultation_extras(repo_root: Path) -> None:
    data = _pyproject(repo_root)
    extras = data["project"]["optional-dependencies"]
    assert extras["mcp"] == ["mcp>=1.28.1,<2"]
    assert extras["consultation-core"] == [
        "pydantic>=2.13.4,<3",
        "numpy>=1.26.4,<3",
        "jieba==0.42.1",
        "PyYAML>=6.0.2,<7",
        "pywin32>=312,<313; sys_platform == 'win32'",
    ]
    assert extras["consultation-ml"] == ["sentence-transformers>=5.6,<6"]
    assert extras["consultation-test"] == [
        "mcp[cli]>=1.28.1,<2",
        "pytest>=8.3,<10",
        "pytest-cov>=6,<8",
        "hypothesis>=6.100,<7",
        "ruff>=0.8,<1",
        "mypy>=2.1,<3",
        "types-networkx>=3.6,<4",
        "types-pywin32>=312.0.0.20260609,<313; sys_platform == 'win32'",
        "pip-tools==7.5.3",
    ]


def test_pyproject_preserves_upstream_metadata_and_extras(repo_root: Path) -> None:
    data = _pyproject(repo_root)
    project = data["project"]
    extras = project["optional-dependencies"]

    assert project["requires-python"] == ">=3.10"
    assert project["dependencies"] == [
        "networkx",
        "tree-sitter>=0.23.0",
        "tree-sitter-python",
        "tree-sitter-javascript",
        "tree-sitter-typescript",
        "tree-sitter-go",
        "tree-sitter-rust",
        "tree-sitter-java",
        "tree-sitter-c",
        "tree-sitter-cpp",
        "tree-sitter-ruby",
        "tree-sitter-c-sharp",
        "tree-sitter-kotlin",
        "tree-sitter-scala",
        "tree-sitter-php",
        "tree-sitter-swift",
        "tree-sitter-lua",
        "tree-sitter-zig",
        "tree-sitter-powershell",
        "tree-sitter-elixir",
        "tree-sitter-objc",
        "tree-sitter-julia",
    ]
    assert project["scripts"]["graphify"] == "graphify.__main__:main"
    assert extras["neo4j"] == ["neo4j"]
    assert extras["pdf"] == ["pypdf", "html2text"]
    assert extras["watch"] == ["watchdog"]
    assert extras["svg"] == ["matplotlib"]
    assert extras["leiden"] == ["graspologic; python_version < '3.13'"]
    assert extras["office"] == ["python-docx", "openpyxl"]
    assert extras["video"] == ["faster-whisper", "yt-dlp"]
    assert extras["all"] == [
        "mcp>=1.28.1,<2",
        "neo4j",
        "pypdf",
        "html2text",
        "watchdog",
        "graspologic; python_version < '3.13'",
        "python-docx",
        "openpyxl",
        "faster-whisper",
        "yt-dlp",
        "matplotlib",
    ]


def test_pyproject_configures_strict_mypy_and_all_markers(repo_root: Path) -> None:
    data = _pyproject(repo_root)

    assert data["tool"]["mypy"] == {
        "python_version": "3.12",
        "strict": True,
        "plugins": ["pydantic.mypy"],
    }
    marker_names = {
        marker.partition(":")[0].partition("(")[0].strip()
        for marker in data["tool"]["pytest"]["ini_options"]["markers"]
    }
    assert marker_names == {
        "integration",
        "fault",
        "golden",
        "model",
        "slow",
        "acceptance_id",
    }


def _is_ignored(repo_root: Path, path: str) -> bool:
    completed = subprocess.run(
        ["git", "check-ignore", "--no-index", "--quiet", path],
        cwd=repo_root,
        check=False,
    )
    assert completed.returncode in {0, 1}
    return completed.returncode == 0


def test_gitignore_keeps_repo_skills_trackable(repo_root: Path) -> None:
    skill_paths = [
        ".agents/skills/consultation-session/SKILL.md",
        ".agents/skills/knowledge-curator/SKILL.md",
        ".agents/skills/quality-evaluator/SKILL.md",
    ]
    assert not [path for path in skill_paths if _is_ignored(repo_root, path)]


def test_gitignore_excludes_runtime_and_local_codex_config(repo_root: Path) -> None:
    assert _is_ignored(repo_root, "knowledge-vault/client.sqlite3")
    assert _is_ignored(repo_root, ".codex/config.toml")
    assert _is_ignored(repo_root, "client.sqlite3-wal")

    lines = (repo_root / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert lines[-10:] == [
        "knowledge-vault/",
        "*.sqlite3-wal",
        "*.sqlite3-shm",
        ".consultation-staging/",
        ".consultation-models/",
        "consultation-leak-report.json",
        ".codex/config.toml",
        "!.agents/",
        "!.agents/skills/",
        "!.agents/skills/**",
    ]


def test_entrypoint_rejects_python_below_312_before_cli_import(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from consultation_kb import entrypoint

    monkeypatch.delitem(sys.modules, "consultation_kb.cli", raising=False)
    monkeypatch.setattr(entrypoint.sys, "version_info", (3, 11, 9))

    assert entrypoint.main(["doctor"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"{UNSUPPORTED_PYTHON_MESSAGE}\n"
    assert "consultation_kb.cli" not in sys.modules


def test_cli_registers_current_local_administration_commands(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from consultation_kb import cli

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])

    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    for available in (
        "doctor",
        "migrate",
        "review",
        "recover",
        "recovery-report",
        "rebuild-start",
        "rebuild-status",
        "delete-status",
    ):
        assert available in captured.out
    for deferred in ("init-vault", "serve"):
        assert deferred not in captured.out
    assert captured.err == ""


def test_doctor_help_succeeds_and_missing_vault_fails_closed(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    repo_root: Path,
) -> None:
    from consultation_kb import cli

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["doctor", "--help"])
    assert exc_info.value.code == 0
    help_output = capsys.readouterr()
    assert "doctor" in help_output.out
    assert help_output.err == ""

    monkeypatch.delenv("CONSULTATION_VAULT_ROOT", raising=False)
    assert cli.main(["doctor", "--repo-root", str(repo_root), "--json"]) == 2
    unavailable_output = capsys.readouterr()
    payload = json.loads(unavailable_output.out)
    assert payload["ok"] is False
    assert payload["checks"]["configuration"]["code"] == (
        "CONFIG_VAULT_ROOT_MISSING"
    )
    assert unavailable_output.err == (
        "consultation-kb doctor: CONFIG_VAULT_ROOT_MISSING\n"
    )


@pytest.mark.parametrize(
    "deferred",
    ["init-vault", "serve", "rebuild", "delete"],
)
def test_deferred_commands_are_not_registered(
    deferred: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from consultation_kb import cli

    with pytest.raises(SystemExit) as exc_info:
        cli.main([deferred])

    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "invalid choice" in captured.err


def test_python_m_package_exposes_cli_shell(repo_root: Path) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "consultation_kb", "--help"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "doctor" in completed.stdout
    assert completed.stderr == ""


def test_distribution_version_queries_graphifyy_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from consultation_kb.core import version

    calls: list[str] = []

    def fake_version(distribution_name: str) -> str:
        calls.append(distribution_name)
        return "9.8.7"

    monkeypatch.setattr(version.metadata, "version", fake_version)

    assert version.distribution_version() == "9.8.7"
    assert calls == ["graphifyy"]


def test_distribution_version_has_explicit_uninstalled_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from consultation_kb.core import version

    def missing_distribution(distribution_name: str) -> str:
        assert distribution_name == "graphifyy"
        raise version.metadata.PackageNotFoundError(distribution_name)

    monkeypatch.setattr(version.metadata, "version", missing_distribution)

    assert version.distribution_version() == "0.0.0+uninstalled"


def test_package_version_comes_from_shared_helper(repo_root: Path) -> None:
    source = (repo_root / "consultation_kb" / "__init__.py").read_text(encoding="utf-8")

    assert "from .core.version import distribution_version" in source
    assert "__version__ = distribution_version()" in source
    assert "metadata.version" not in source
