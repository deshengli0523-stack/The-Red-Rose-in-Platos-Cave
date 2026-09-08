from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import pytest


pytest_plugins = ("pytester",)


def test_repository_has_no_runtime_vault(repo_root: Path) -> None:
    forbidden = [repo_root / "knowledge-vault", repo_root / "clients"]
    assert not [path for path in forbidden if path.exists()]


def test_repo_root_is_the_checkout_root(repo_root: Path) -> None:
    assert (repo_root / "pyproject.toml").is_file()
    assert (repo_root / ".git").exists()


def test_fixed_now_is_a_stable_utc_instant(fixed_now: datetime) -> None:
    assert fixed_now == datetime(2026, 7, 16, 8, 0, tzinfo=timezone.utc)
    assert fixed_now.utcoffset() is not None
    assert fixed_now.utcoffset().total_seconds() == 0


def test_synthetic_workspace_is_separate_and_empty(
    synthetic_workspace: tuple[Path, Path],
) -> None:
    repo, vault = synthetic_workspace
    assert repo != vault
    assert (repo / ".git").is_dir()
    assert vault.is_dir()
    assert list(vault.iterdir()) == []
    assert "SYNTH" not in str(repo)


def test_canary_catalog_contains_only_explicit_synthetic_markers(
    repo_root: Path,
) -> None:
    catalog_path = repo_root / "tests" / "fixtures" / "consultation_kb" / "canaries.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))

    assert catalog["schema_version"] == "1.0"
    assert catalog["synthetic_only"] is True
    assert catalog["rule_id"] == "known_canary"
    assert catalog["markers"] == [
        "SYNTH-CANARY-" + "ALPHA-" + "9F3A",
        "SYNTH-CANARY-" + "BETA-" + "71D2",
    ]
    assert all(marker.startswith("SYNTH-CANARY-") for marker in catalog["markers"])


@dataclass
class _SampleItem:
    path: Path
    marker_names: list[str] = field(default_factory=list)

    def add_marker(self, marker: pytest.MarkDecorator) -> None:
        self.marker_names.append(marker.name)


@dataclass
class _SampleConfig:
    marker_lines: list[str] = field(default_factory=list)

    def addinivalue_line(self, name: str, value: str) -> None:
        assert name == "markers"
        self.marker_lines.append(value)


def test_collection_directory_markers_are_registered() -> None:
    from tests.consultation_kb import conftest as consultation_conftest

    config = _SampleConfig()
    consultation_conftest.pytest_configure(config)
    assert {line.partition(":")[0] for line in config.marker_lines} == {
        "integration",
        "fault",
        "golden",
        "model",
    }


def test_real_collection_selects_each_directory_marker_without_warnings(
    pytester: pytest.Pytester,
    repo_root: Path,
) -> None:
    marker_names = ("integration", "fault", "golden", "model")
    pytester.makeconftest(
        f"""
from pathlib import Path
import sys

sys.path.insert(0, {str(repo_root)!r})
from tests.consultation_kb import conftest as consultation_conftest

consultation_conftest._TEST_ROOT = Path(__file__).resolve().parent
pytest_configure = consultation_conftest.pytest_configure
pytest_collection_modifyitems = consultation_conftest.pytest_collection_modifyitems
"""
    )
    for directory in (*marker_names, "unit"):
        sample_path = pytester.path / directory / f"test_{directory}_sample.py"
        sample_path.parent.mkdir()
        sample_path.write_text(
            f"def test_{directory}_sample():\n    assert True\n",
            encoding="utf-8",
        )

    for marker_name in marker_names:
        result = pytester.runpytest_subprocess(
            "-q",
            "-p",
            "no:cacheprovider",
            "-m",
            marker_name,
        )
        result.assert_outcomes(passed=1, deselected=4)
        output = "\n".join((result.stdout.str(), result.stderr.str())).lower()
        assert "pytestunknownmarkwarning" not in output


@pytest.mark.parametrize("directory", ["integration", "fault", "golden", "model"])
def test_collection_hook_marks_sample_items_by_relative_directory(
    repo_root: Path,
    directory: str,
) -> None:
    from tests.consultation_kb import conftest as consultation_conftest

    item = _SampleItem(
        repo_root / "tests" / "consultation_kb" / directory / "test_synthetic_sample.py"
    )
    consultation_conftest.pytest_collection_modifyitems(None, None, [item])
    assert item.marker_names == [directory]


def test_collection_hook_does_not_mark_unrelated_unit_item(repo_root: Path) -> None:
    from tests.consultation_kb import conftest as consultation_conftest

    item = _SampleItem(
        repo_root / "tests" / "consultation_kb" / "unit" / "test_synthetic_sample.py"
    )
    consultation_conftest.pytest_collection_modifyitems(None, None, [item])
    assert item.marker_names == []
