from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.consultation_kb.acceptance_registry import ACCEPTANCE_REGISTRY


@dataclass(frozen=True)
class _RunResult:
    returncode: int
    output: str


@pytest.fixture
def mini_acceptance_repo(tmp_path: Path, repo_root: Path) -> Path:
    consultation_tests = tmp_path / "tests" / "consultation_kb"
    consultation_tests.mkdir(parents=True)
    (consultation_tests / "conftest.py").write_text(
        (repo_root / "tests" / "consultation_kb" / "conftest.py").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    return tmp_path


def _write_test_module(repo: Path, relative_path: str, source: str) -> Path:
    module = repo / "tests" / "consultation_kb" / relative_path
    module.parent.mkdir(parents=True, exist_ok=True)
    module.write_text(source, encoding="utf-8")
    return module


def _run_acceptance(repo_root: Path, mini_repo: Path, ids: str) -> _RunResult:
    completed = subprocess.run(
        [
            sys.executable,
            str(repo_root / "scripts" / "run_consultation_acceptance.py"),
            "--repo-root",
            str(mini_repo),
            "--ids",
            ids,
        ],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    return _RunResult(
        returncode=completed.returncode,
        output=completed.stdout + completed.stderr,
    )


def _marked_test(acceptance_id: str, *, assertion: str = "True") -> str:
    return f'''\
import pytest

@pytest.mark.acceptance_id("{acceptance_id}")
def test_acceptance_contract():
    assert {assertion}
'''


def test_registry_freezes_plan_primary_and_extension_ownership() -> None:
    assert {
        acceptance_id: (spec.primary_module, spec.extension_modules)
        for acceptance_id, spec in ACCEPTANCE_REGISTRY.items()
    } == {
        "ISO-01": (
            "integration/test_iso_01.py",
            ("integration/test_mcp_iso_01.py",),
        ),
        "ISO-02": ("integration/test_iso_02.py", ()),
        "CASE-01": ("integration/test_case_01_full_lineage.py", ()),
        "CASE-02": ("integration/test_case_02_authorization.py", ()),
        "TURN-01": (
            "golden/test_turn_01.py",
            ("integration/test_two_turn_session.py",),
        ),
        "FACT-01": ("golden/test_fact_01.py", ()),
        "THEORY-01": ("golden/test_theory_01_governance.py", ()),
        "GRAPH-01": (
            "golden/test_graph_01_client.py",
            ("golden/test_graph_01_global.py",),
        ),
        "WRITE-01": ("integration/test_write_01.py", ()),
        "TX-01": (
            "integration/test_manifest_visibility.py",
            (
                "fault/test_outbox_saga_exceptions.py",
                "fault/test_manifest_process_crash.py",
                "fault/test_outbox_process_crash.py",
                "fault/test_approval_execution_crash.py",
                "fault/test_client_publication_crash.py",
                "fault/test_global_knowledge_publication_crash.py",
                "fault/test_production_process_crash.py",
            ),
        ),
        "VER-01": (
            "integration/test_manifest_visibility.py",
            ("integration/test_ver_01.py",),
        ),
        "DEL-01": ("golden/test_del_01.py", ()),
        "REBUILD-01": ("golden/test_rebuild_01.py", ()),
        "RISK-01": ("golden/test_risk_01.py", ()),
        "ARCHIVE-01": ("golden/test_archive_01.py", ()),
    }


def test_runner_executes_a_single_marker_with_real_pytest(
    mini_acceptance_repo: Path,
    repo_root: Path,
) -> None:
    _write_test_module(
        mini_acceptance_repo,
        "integration/test_iso_01.py",
        _marked_test("ISO-01"),
    )

    result = _run_acceptance(repo_root, mini_acceptance_repo, "ISO-01")

    assert result.returncode == 0, result.output
    assert "1 passed" in result.output


def test_runner_accepts_one_module_carrying_multiple_markers(
    mini_acceptance_repo: Path,
    repo_root: Path,
) -> None:
    _write_test_module(
        mini_acceptance_repo,
        "integration/test_manifest_visibility.py",
        """\
import pytest

pytestmark = [
    pytest.mark.acceptance_id("TX-01"),
    pytest.mark.acceptance_id("VER-01"),
]

def test_shared_manifest_contract():
    assert True
""",
    )

    result = _run_acceptance(repo_root, mini_acceptance_repo, "TX-01,VER-01")

    assert result.returncode == 0, result.output
    assert "1 passed" in result.output


def test_runner_uses_or_semantics_for_two_requested_ids(
    mini_acceptance_repo: Path,
    repo_root: Path,
) -> None:
    _write_test_module(
        mini_acceptance_repo,
        "integration/test_iso_01.py",
        _marked_test("ISO-01"),
    )
    _write_test_module(
        mini_acceptance_repo,
        "integration/test_iso_02.py",
        _marked_test("ISO-02"),
    )

    result = _run_acceptance(repo_root, mini_acceptance_repo, "ISO-01,ISO-02")

    assert result.returncode == 0, result.output
    assert "2 passed" in result.output


def test_runner_rejects_unknown_id_before_pytest(
    mini_acceptance_repo: Path,
    repo_root: Path,
) -> None:
    result = _run_acceptance(repo_root, mini_acceptance_repo, "ISO_01")

    assert result.returncode == 2
    assert "unknown acceptance ID(s): ISO_01" in result.output


def test_runner_rejects_marker_spelling_drift(
    mini_acceptance_repo: Path,
    repo_root: Path,
) -> None:
    _write_test_module(
        mini_acceptance_repo,
        "integration/test_iso_01.py",
        _marked_test("ISO_01"),
    )

    result = _run_acceptance(repo_root, mini_acceptance_repo, "ISO-01")

    assert result.returncode == 2
    assert "missing marker(s): ISO-01" in result.output


def test_runner_rejects_missing_requested_primary_module(
    mini_acceptance_repo: Path,
    repo_root: Path,
) -> None:
    result = _run_acceptance(repo_root, mini_acceptance_repo, "ISO-02")

    assert result.returncode == 2
    assert "required primary module missing for: ISO-02" in result.output


def test_runner_rejects_requested_id_with_zero_collected_tests(
    mini_acceptance_repo: Path,
    repo_root: Path,
) -> None:
    _write_test_module(
        mini_acceptance_repo,
        "integration/test_iso_01.py",
        """\
import pytest

@pytest.mark.acceptance_id("ISO-01")
def helper_with_marker():
    pass

def test_unmarked():
    assert True
""",
    )

    result = _run_acceptance(repo_root, mini_acceptance_repo, "ISO-01")

    assert result.returncode == pytest.ExitCode.NO_TESTS_COLLECTED
    assert (
        "acceptance module collection is missing marker(s): "
        "integration/test_iso_01.py=ISO-01"
    ) in result.output


def test_runner_rejects_mixed_marked_and_unmarked_tests_in_registered_module(
    mini_acceptance_repo: Path,
    repo_root: Path,
) -> None:
    _write_test_module(
        mini_acceptance_repo,
        "integration/test_iso_01.py",
        """\
import pytest

@pytest.mark.acceptance_id("ISO-01")
def test_marked_contract():
    assert True

def test_unmarked_contract():
    assert True
""",
    )

    result = _run_acceptance(repo_root, mini_acceptance_repo, "ISO-01")

    assert result.returncode == pytest.ExitCode.NO_TESTS_COLLECTED
    assert (
        "acceptance module collection is missing marker(s): "
        "integration/test_iso_01.py=ISO-01"
    ) in result.output


def test_future_extension_can_be_absent_but_must_be_marked_once_present(
    mini_acceptance_repo: Path,
    repo_root: Path,
) -> None:
    _write_test_module(
        mini_acceptance_repo,
        "golden/test_graph_01_client.py",
        _marked_test("GRAPH-01"),
    )

    absent = _run_acceptance(repo_root, mini_acceptance_repo, "GRAPH-01")
    assert absent.returncode == 0, absent.output

    extension = _write_test_module(
        mini_acceptance_repo,
        "golden/test_graph_01_global.py",
        "def test_global_graph():\n    assert True\n",
    )
    unmarked = _run_acceptance(repo_root, mini_acceptance_repo, "GRAPH-01")
    assert unmarked.returncode == 2
    assert "test_graph_01_global.py is missing marker(s): GRAPH-01" in unmarked.output

    extension.write_text(_marked_test("GRAPH-01"), encoding="utf-8")
    marked = _run_acceptance(repo_root, mini_acceptance_repo, "GRAPH-01")
    assert marked.returncode == 0, marked.output
    assert "2 passed" in marked.output


def test_runner_preserves_final_pytest_failure_exit_code(
    mini_acceptance_repo: Path,
    repo_root: Path,
) -> None:
    _write_test_module(
        mini_acceptance_repo,
        "integration/test_iso_01.py",
        _marked_test("ISO-01", assertion="False"),
    )

    result = _run_acceptance(repo_root, mini_acceptance_repo, "ISO-01")

    assert result.returncode == pytest.ExitCode.TESTS_FAILED
    assert "1 failed" in result.output
