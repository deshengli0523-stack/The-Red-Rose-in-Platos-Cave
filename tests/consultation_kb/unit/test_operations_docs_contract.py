from __future__ import annotations

import argparse
import re
import shlex
from pathlib import Path

from consultation_kb import cli


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
DOC_ROOT = REPOSITORY_ROOT / "docs" / "consultation-kb"
DOC_PATHS = tuple(sorted(DOC_ROOT.glob("*.md")))
EXECUTABLE = r".\.venv\Scripts\consultation-kb.exe"


def _powershell_commands(text: str) -> tuple[str, ...]:
    commands: list[str] = []
    for block in re.findall(r"```powershell\s*\n(.*?)```", text, flags=re.DOTALL):
        current: list[str] = []
        for raw_line in block.splitlines():
            line = raw_line.strip()
            if not current:
                if line.startswith("& ") and "consultation-kb.exe" in line:
                    current.append(line.removesuffix("`").rstrip())
                    if not line.endswith("`"):
                        commands.append(" ".join(current))
                        current.clear()
                continue
            current.append(line.removesuffix("`").rstrip())
            if not line.endswith("`"):
                commands.append(" ".join(current))
                current.clear()
        assert not current, "PowerShell documentation contains an open continuation"
    return tuple(commands)


def _arguments(command: str) -> tuple[str, ...]:
    tokens = shlex.split(command, posix=True)
    assert tokens[:2] == ["&", EXECUTABLE]
    return tuple(tokens[2:])


def _documented_commands() -> tuple[tuple[str, tuple[str, ...]], ...]:
    extracted: list[tuple[str, tuple[str, ...]]] = []
    occurrence_count = 0
    for path in DOC_PATHS:
        text = path.read_text(encoding="utf-8")
        occurrence_count += text.count("consultation-kb.exe")
        extracted.extend(
            (path.name, _arguments(item)) for item in _powershell_commands(text)
        )
    assert len(extracted) == occurrence_count
    return tuple(extracted)


def _subcommand_names(parser: argparse.ArgumentParser) -> set[str]:
    action = next(
        item
        for item in parser._actions  # noqa: SLF001
        if isinstance(item, argparse._SubParsersAction)  # noqa: SLF001
    )
    return set(action.choices)


def test_every_documented_consultation_command_is_a_complete_argparse_command() -> None:
    parser = cli._build_parser()  # noqa: SLF001
    commands = _documented_commands()
    documented_names: set[str] = set()
    configured = {
        "doctor",
        "migrate",
        "review",
        "models-import",
        "evaluation-prepare",
        "evaluation-next",
        "evaluation-submit",
        "evaluation-finalize",
        "recover",
        "recovery-report",
        "rebuild-start",
        "rebuild-status",
        "delete-status",
    }

    for source, arguments in commands:
        assert arguments, source
        parsed = parser.parse_args(arguments)
        documented_names.add(parsed.command)
        if parsed.command in configured:
            assert "--repo-root" in arguments, (source, arguments)
            assert "--vault-root" in arguments, (source, arguments)
        if parsed.command == "migrate":
            assert "--check" in arguments

    assert documented_names == _subcommand_names(parser)


def test_install_and_model_import_docs_pin_the_two_explicit_modes() -> None:
    operations = (DOC_ROOT / "operations.md").read_text(encoding="utf-8")
    assert "pip install --no-index --no-build-isolation --no-deps ." in operations
    assert "pip install 'pip==" not in operations
    assert "pip install --no-deps -e ." not in operations
    assert "官方 Hugging Face endpoint" in operations
    assert "MCP、咨询、检索、评测和后续模型加载仍保持离线" in operations
    assert "MODEL_IMPORT_NETWORK_RESOLUTION_UNAVAILABLE" not in operations

    model_commands = [
        arguments
        for source, arguments in _documented_commands()
        if source == "operations.md" and arguments[0] == "models-import"
    ]
    assert len(model_commands) == 2
    local = next(item for item in model_commands if "--resolve-main" not in item)
    network = next(item for item in model_commands if "--resolve-main" in item)
    assert {"--source", "--revision", "--license"} <= set(local)
    assert {"--source", "--revision", "--license"}.isdisjoint(network)


def test_lifecycle_docs_use_only_the_current_full_rebuild_contract() -> None:
    recovery = (DOC_ROOT / "recovery.md").read_text(encoding="utf-8")
    assert "--purpose all" in recovery
    assert "--purpose wiki_index" not in recovery

    lifecycle = {
        arguments[0]: arguments
        for _source, arguments in _documented_commands()
        if arguments[0] in {"rebuild-start", "rebuild-status", "delete-status"}
    }
    assert set(lifecycle) == {"rebuild-start", "rebuild-status", "delete-status"}
    assert {"--purpose", "all", "--database-ref-sha256"} <= set(
        lifecycle["rebuild-start"]
    )
    assert {"--job", "--database-ref-sha256"} <= set(lifecycle["rebuild-status"])
    assert "--database-ref-sha256" in lifecycle["delete-status"]
