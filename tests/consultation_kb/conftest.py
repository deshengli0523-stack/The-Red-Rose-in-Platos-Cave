from datetime import datetime, timezone
from pathlib import Path

import pytest


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


@pytest.fixture
def fixed_now() -> datetime:
    return datetime(2026, 7, 16, 8, 0, tzinfo=timezone.utc)


@pytest.fixture
def synthetic_workspace(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    vault = tmp_path / "knowledge-vault"
    (repo / ".git").mkdir(parents=True)
    vault.mkdir()
    return repo, vault


_DIRECTORY_MARKERS = frozenset({"integration", "fault", "golden", "model"})
_TEST_ROOT = Path(__file__).resolve().parent
_ACCEPTANCE_OPTION = "acceptance_ids"
_ACCEPTANCE_CONTRACT_OPTION = "acceptance_module_contracts"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--acceptance-id",
        action="append",
        dest=_ACCEPTANCE_OPTION,
        default=[],
        metavar="ID[,ID...]",
        help="run tests carrying any requested consultation acceptance ID",
    )
    parser.addoption(
        "--acceptance-module-contract",
        action="append",
        dest=_ACCEPTANCE_CONTRACT_OPTION,
        default=[],
        metavar="MODULE::ID[,ID...]",
        help="validate collected markers for a registered acceptance module",
    )


def pytest_configure(config: pytest.Config) -> None:
    for marker_name in sorted(_DIRECTORY_MARKERS):
        config.addinivalue_line(
            "markers",
            f"{marker_name}: consultation knowledge-base {marker_name} tests",
        )
    # pyproject.toml owns the repository-wide registration. This fallback keeps
    # the conftest portable when copied into an isolated acceptance test tree.
    if hasattr(config, "getini"):
        configured_markers = config.getini("markers")
        if not any(
            marker.partition(":")[0].partition("(")[0].strip() == "acceptance_id"
            for marker in configured_markers
        ):
            config.addinivalue_line(
                "markers",
                "acceptance_id(id): consultation knowledge-base acceptance contract ID",
            )


def _requested_acceptance_ids(config: pytest.Config) -> tuple[str, ...]:
    raw_values = config.getoption(_ACCEPTANCE_OPTION, default=[])
    if not raw_values:
        return ()

    requested: list[str] = []
    for raw_value in raw_values:
        for value in raw_value.split(","):
            acceptance_id = value.strip()
            if acceptance_id and acceptance_id not in requested:
                requested.append(acceptance_id)
    if not requested:
        raise pytest.UsageError("--acceptance-id requires at least one non-empty ID")
    return tuple(requested)


def _item_acceptance_ids(item: pytest.Item) -> frozenset[str]:
    return frozenset(
        value
        for marker in item.iter_markers(name="acceptance_id")
        for value in marker.args
        if isinstance(value, str)
    )


def _acceptance_module_contracts(
    config: pytest.Config,
) -> dict[str, tuple[str, ...]]:
    contracts: dict[str, tuple[str, ...]] = {}
    for raw_contract in config.getoption(_ACCEPTANCE_CONTRACT_OPTION, default=[]):
        module, separator, raw_ids = raw_contract.partition("::")
        acceptance_ids = tuple(
            dict.fromkeys(
                value.strip() for value in raw_ids.split(",") if value.strip()
            )
        )
        normalized_module = Path(module.strip()).as_posix()
        if not separator or not normalized_module or not acceptance_ids:
            raise pytest.UsageError(
                "--acceptance-module-contract requires MODULE::ID[,ID...]"
            )
        contracts[normalized_module] = acceptance_ids
    return contracts


def _relative_item_path(item: pytest.Item) -> str | None:
    try:
        return Path(item.path).resolve().relative_to(_TEST_ROOT).as_posix()
    except (AttributeError, ValueError):
        return None


def pytest_collection_modifyitems(
    session: pytest.Session | None,
    config: pytest.Config | None,
    items: list[pytest.Item],
) -> None:
    del session
    for item in items:
        relative_path_value = _relative_item_path(item)
        if relative_path_value is None:
            continue
        directory_path = Path(relative_path_value)
        if directory_path.parts and directory_path.parts[0] in _DIRECTORY_MARKERS:
            item.add_marker(getattr(pytest.mark, directory_path.parts[0]))

    # The hook is also exercised directly by unit tests with a minimal fake
    # config. Directory marker behavior remains independent of acceptance
    # filtering in that case.
    if config is None:
        return

    module_contracts = _acceptance_module_contracts(config)
    if module_contracts:
        collected_by_module = dict.fromkeys(module_contracts, 0)
        missing_contract_markers: set[tuple[str, str]] = set()
        for item in items:
            relative_path = _relative_item_path(item)
            if relative_path not in module_contracts:
                continue
            collected_by_module[relative_path] += 1
            item_ids = _item_acceptance_ids(item)
            missing_contract_markers.update(
                (relative_path, acceptance_id)
                for acceptance_id in module_contracts[relative_path]
                if acceptance_id not in item_ids
            )
        missing_contract_markers.update(
            (module, acceptance_id)
            for module, count in collected_by_module.items()
            if count == 0
            for acceptance_id in module_contracts[module]
        )
        config._consultation_acceptance_contract_missing = tuple(  # type: ignore[attr-defined]
            sorted(missing_contract_markers)
        )

    requested = _requested_acceptance_ids(config)
    if not requested:
        return

    selected: list[pytest.Item] = []
    deselected: list[pytest.Item] = []
    selected_counts = dict.fromkeys(requested, 0)
    for item in items:
        item_ids = _item_acceptance_ids(item)
        matched_ids = item_ids.intersection(requested)
        if matched_ids:
            selected.append(item)
            for acceptance_id in matched_ids:
                selected_counts[acceptance_id] += 1
        else:
            deselected.append(item)

    if deselected:
        config.hook.pytest_deselected(items=deselected)
    items[:] = selected
    config._consultation_acceptance_missing = tuple(  # type: ignore[attr-defined]
        acceptance_id for acceptance_id, count in selected_counts.items() if count == 0
    )


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    missing = getattr(session.config, "_consultation_acceptance_missing", ())
    missing_contracts = getattr(
        session.config, "_consultation_acceptance_contract_missing", ()
    )
    if not missing and not missing_contracts:
        return

    terminal_reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if terminal_reporter is not None:
        if missing:
            terminal_reporter.write_line(
                "acceptance selection collected zero tests for: " + ", ".join(missing),
                red=True,
            )
        if missing_contracts:
            terminal_reporter.write_line(
                "acceptance module collection is missing marker(s): "
                + ", ".join(
                    f"{module}={acceptance_id}"
                    for module, acceptance_id in missing_contracts
                ),
                red=True,
            )
    if exitstatus in {pytest.ExitCode.OK, pytest.ExitCode.NO_TESTS_COLLECTED}:
        session.exitstatus = pytest.ExitCode.NO_TESTS_COLLECTED
