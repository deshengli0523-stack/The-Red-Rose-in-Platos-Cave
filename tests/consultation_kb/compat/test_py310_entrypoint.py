from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest


UNSUPPORTED_PYTHON_MESSAGE = (
    "consultation-kb requires Python 3.12 or later; current interpreter is unsupported."
)


def test_all_package_sources_parse_with_python_310_grammar(repo_root: Path) -> None:
    package_root = repo_root / "consultation_kb"
    sources = sorted(package_root.rglob("*.py"))
    assert sources

    for source_path in sources:
        ast.parse(
            source_path.read_text(encoding="utf-8"),
            filename=str(source_path),
            feature_version=(3, 10),
        )


def test_py310_entrypoint_rejects_before_loading_cli(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from consultation_kb import entrypoint

    allowed_consultation_modules = {
        "consultation_kb",
        "consultation_kb.core",
        "consultation_kb.core.version",
        "consultation_kb.entrypoint",
    }
    forbidden_roots = {"mcp", "pydantic", "sqlite3"}
    for module_name in list(sys.modules):
        if (
            module_name.partition(".")[0] in forbidden_roots
            or (
                module_name.startswith("consultation_kb.")
                and module_name not in allowed_consultation_modules
            )
        ):
            monkeypatch.delitem(sys.modules, module_name, raising=False)
    monkeypatch.setattr(entrypoint.sys, "version_info", (3, 10, 0))

    assert entrypoint.main(["doctor"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"{UNSUPPORTED_PYTHON_MESSAGE}\n"
    loaded_forbidden = {
        module_name
        for module_name in sys.modules
        if module_name.partition(".")[0] in forbidden_roots
        or (
            module_name.startswith("consultation_kb.")
            and module_name not in allowed_consultation_modules
        )
    }
    assert loaded_forbidden == set()


def test_pre_gate_modules_use_only_python_310_safe_imports(repo_root: Path) -> None:
    allowed_import_roots = {
        "__future__",
        "importlib",
        "sys",
        "typing",
        "entrypoint",
        "core",
        "version",
    }
    pre_gate_sources = [
        repo_root / "consultation_kb" / "__init__.py",
        repo_root / "consultation_kb" / "__main__.py",
        repo_root / "consultation_kb" / "entrypoint.py",
        repo_root / "consultation_kb" / "core" / "__init__.py",
        repo_root / "consultation_kb" / "core" / "version.py",
    ]

    for source_path in pre_gate_sources:
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported_roots = {
            alias.name.partition(".")[0]
            for node in tree.body
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_roots.update(
            (node.module or "").partition(".")[0]
            for node in tree.body
            if isinstance(node, ast.ImportFrom)
        )
        assert imported_roots <= allowed_import_roots, source_path

    entrypoint_tree = ast.parse(pre_gate_sources[2].read_text(encoding="utf-8"))
    main_function = next(
        node
        for node in entrypoint_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    gate_index = next(
        index for index, node in enumerate(main_function.body) if isinstance(node, ast.If)
    )
    cli_import_index = next(
        index
        for index, node in enumerate(main_function.body)
        if isinstance(node, ast.ImportFrom) and node.module == "cli"
    )
    assert gate_index < cli_import_index
