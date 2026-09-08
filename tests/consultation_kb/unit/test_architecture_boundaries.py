from __future__ import annotations

import ast
from pathlib import Path


_FORBIDDEN_CLIENT_IMPORTS = frozenset(
    {"graphify.build", "graphify.serve", "graphify.wiki"}
)


def _imports(module_path: Path) -> tuple[tuple[str, int], ...]:
    tree = ast.parse(module_path.read_text(encoding="utf-8"), filename=str(module_path))
    imports: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append((node.module, node.lineno))
            imports.extend(
                (f"{node.module}.{alias.name}", node.lineno) for alias in node.names
            )
    return tuple(imports)


def _python_files(root: Path) -> tuple[Path, ...]:
    if not root.is_dir():
        return ()
    return tuple(sorted(root.rglob("*.py")))


def test_upstream_graphify_never_imports_consultation_package(repo_root: Path) -> None:
    violations = [
        f"{module.relative_to(repo_root)}:{line} imports {imported}"
        for module in _python_files(repo_root / "graphify")
        for imported, line in _imports(module)
        if imported == "consultation_kb" or imported.startswith("consultation_kb.")
    ]
    assert violations == []


def test_client_boundary_avoids_unsafe_upstream_query_modules(repo_root: Path) -> None:
    violations = [
        f"{module.relative_to(repo_root)}:{line} imports {imported}"
        for module in _python_files(repo_root / "consultation_kb" / "client")
        for imported, line in _imports(module)
        if imported in _FORBIDDEN_CLIENT_IMPORTS
        or any(imported.startswith(f"{name}.") for name in _FORBIDDEN_CLIENT_IMPORTS)
    ]
    assert violations == []


def test_retrieval_never_imports_lifecycle_package(repo_root: Path) -> None:
    violations = [
        f"{module.relative_to(repo_root)}:{line} imports {imported}"
        for module in _python_files(repo_root / "consultation_kb" / "retrieval")
        for imported, line in _imports(module)
        if imported == "consultation_kb.lifecycle"
        or imported.startswith("consultation_kb.lifecycle.")
    ]
    assert violations == []


def test_integrity_and_core_doctor_do_not_import_higher_layers(
    repo_root: Path,
) -> None:
    targets = (
        repo_root / "consultation_kb" / "storage" / "integrity.py",
        repo_root / "consultation_kb" / "core" / "doctor.py",
    )
    forbidden = (
        "consultation_kb.lifecycle",
        "consultation_kb.operations",
        "consultation_kb.retrieval",
    )
    violations = [
        f"{module.relative_to(repo_root)}:{line} imports {imported}"
        for module in targets
        for imported, line in _imports(module)
        if any(imported == prefix or imported.startswith(f"{prefix}.") for prefix in forbidden)
    ]
    assert violations == []


def test_missing_client_directory_is_a_stable_empty_boundary(tmp_path: Path) -> None:
    assert _python_files(tmp_path / "consultation_kb" / "client") == ()
