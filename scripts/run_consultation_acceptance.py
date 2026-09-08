from __future__ import annotations

import argparse
import ast
import subprocess
import sys
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.consultation_kb.acceptance_registry import (  # noqa: E402
    ACCEPTANCE_REGISTRY,
    AcceptanceSpec,
)


class AcceptanceContractError(RuntimeError):
    """An acceptance request does not satisfy the frozen registry contract."""


def parse_acceptance_ids(raw_ids: str) -> tuple[str, ...]:
    requested: list[str] = []
    for value in raw_ids.split(","):
        acceptance_id = value.strip()
        if acceptance_id and acceptance_id not in requested:
            requested.append(acceptance_id)
    if not requested:
        raise AcceptanceContractError("at least one acceptance ID is required")
    return tuple(requested)


def _is_acceptance_marker(call: ast.Call) -> bool:
    function = call.func
    return (
        isinstance(function, ast.Attribute)
        and function.attr == "acceptance_id"
        and isinstance(function.value, ast.Attribute)
        and function.value.attr == "mark"
        and isinstance(function.value.value, ast.Name)
        and function.value.value.id == "pytest"
    )


def static_acceptance_ids(module_path: Path) -> frozenset[str]:
    try:
        tree = ast.parse(
            module_path.read_text(encoding="utf-8"), filename=str(module_path)
        )
    except (OSError, SyntaxError, UnicodeError) as error:
        raise AcceptanceContractError(
            f"cannot parse registered acceptance module {module_path}: {type(error).__name__}"
        ) from error

    marker_ids: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_acceptance_marker(node):
            continue
        marker_ids.update(
            argument.value
            for argument in node.args
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str)
        )
    return frozenset(marker_ids)


def _expected_ids_by_module(
    registry: Mapping[str, AcceptanceSpec],
) -> Mapping[str, frozenset[str]]:
    expected: defaultdict[str, set[str]] = defaultdict(set)
    for acceptance_id, spec in registry.items():
        for module in spec.modules:
            expected[module].add(acceptance_id)
    return {module: frozenset(ids) for module, ids in expected.items()}


def validate_acceptance_contract(
    repo_root: Path,
    requested: Sequence[str],
    registry: Mapping[str, AcceptanceSpec] = ACCEPTANCE_REGISTRY,
) -> tuple[Path, ...]:
    unknown = [
        acceptance_id for acceptance_id in requested if acceptance_id not in registry
    ]
    if unknown:
        raise AcceptanceContractError("unknown acceptance ID(s): " + ", ".join(unknown))

    test_root = repo_root / "tests" / "consultation_kb"
    missing_primary = [
        acceptance_id
        for acceptance_id in requested
        if not (test_root / registry[acceptance_id].primary_module).is_file()
    ]
    if missing_primary:
        raise AcceptanceContractError(
            "required primary module missing for: " + ", ".join(missing_primary)
        )

    known_ids = frozenset(registry)
    for module, expected_ids in _expected_ids_by_module(registry).items():
        module_path = test_root / module
        if not module_path.is_file():
            continue
        actual_ids = static_acceptance_ids(module_path)
        missing_ids = expected_ids.difference(actual_ids)
        drifted_ids = actual_ids.difference(known_ids)
        if missing_ids:
            raise AcceptanceContractError(
                f"registered module {module} is missing marker(s): "
                + ", ".join(sorted(missing_ids))
            )
        if drifted_ids:
            raise AcceptanceContractError(
                f"registered module {module} has unknown marker(s): "
                + ", ".join(sorted(drifted_ids))
            )

    selected_modules: list[Path] = []
    for acceptance_id in requested:
        for module in registry[acceptance_id].modules:
            module_path = test_root / module
            if module_path.is_file() and module_path not in selected_modules:
                selected_modules.append(module_path)
    return tuple(selected_modules)


def _pytest_command(
    repo_root: Path,
    modules: Sequence[Path],
    requested: Sequence[str],
    *,
    collect_only: bool,
    extra_args: Sequence[str] = (),
    module_contracts: Mapping[str, frozenset[str]] | None = None,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
    ]
    if collect_only:
        command.append("--collect-only")
    command.extend(str(module.relative_to(repo_root)) for module in modules)
    for acceptance_id in requested:
        command.extend(("--acceptance-id", acceptance_id))
    if module_contracts:
        for module, acceptance_ids in sorted(module_contracts.items()):
            command.extend(
                (
                    "--acceptance-module-contract",
                    f"{module}::{','.join(sorted(acceptance_ids))}",
                )
            )
    command.extend(extra_args)
    return command


def run_acceptance(
    repo_root: Path,
    requested: Sequence[str],
    *,
    extra_pytest_args: Sequence[str] = (),
) -> int:
    modules = validate_acceptance_contract(repo_root, requested)

    test_root = repo_root / "tests" / "consultation_kb"
    expected_by_module = _expected_ids_by_module(ACCEPTANCE_REGISTRY)
    existing_contracts = {
        module: acceptance_ids
        for module, acceptance_ids in expected_by_module.items()
        if (test_root / module).is_file()
    }
    all_registered_modules = tuple(test_root / module for module in existing_contracts)

    # One real collection pass checks every existing registered module and
    # every ID it owns. Per-module checks prevent another module sharing the
    # same ID from hiding an uncollected or misspelled marker.
    completed = subprocess.run(
        _pytest_command(
            repo_root,
            all_registered_modules,
            (),
            collect_only=True,
            module_contracts=existing_contracts,
        ),
        cwd=repo_root,
        check=False,
    )
    if completed.returncode != 0:
        return completed.returncode

    completed = subprocess.run(
        _pytest_command(
            repo_root,
            modules,
            requested,
            collect_only=False,
            extra_args=extra_pytest_args,
        ),
        cwd=repo_root,
        check=False,
    )
    return completed.returncode


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run frozen consultation acceptance IDs through pytest markers."
    )
    parser.add_argument("--ids", required=True, help="comma-separated acceptance IDs")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "pytest_args",
        nargs=argparse.REMAINDER,
        help="arguments after -- are passed to the final pytest run",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        requested = parse_acceptance_ids(args.ids)
        extra_args = tuple(args.pytest_args)
        if extra_args[:1] == ("--",):
            extra_args = extra_args[1:]
        return run_acceptance(
            args.repo_root.resolve(),
            requested,
            extra_pytest_args=extra_args,
        )
    except AcceptanceContractError as error:
        print(f"acceptance contract error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
