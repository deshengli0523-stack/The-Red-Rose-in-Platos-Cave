from __future__ import annotations

import platform
import re
import struct
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Literal

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

from scripts import export_consultation_requirements as exporter


Profile = Literal["core", "ml"]
TARGETS: tuple[tuple[str, Profile], ...] = (
    ("3.12", "core"),
    ("3.12", "ml"),
    ("3.13", "core"),
    ("3.13", "ml"),
)


def _stem(target_python: str, profile: Profile) -> str:
    profile_part = "-ml" if profile == "ml" else ""
    return f"consultation{profile_part}-win-py{target_python.replace('.', '')}"


def _pyproject(repo_root: Path) -> dict[str, Any]:
    return tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))


def _expected_input_requirements(
    repo_root: Path,
    target_python: str,
    profile: Profile,
) -> list[str]:
    return exporter.exported_requirements(
        _pyproject(repo_root),
        target_python=target_python,
        profile=profile,
    )


def _input_requirements(text: str) -> list[str]:
    return [line for line in text.splitlines() if line and not line.startswith("#")]


def _locked_requirements(lock_text: str) -> dict[str, Requirement]:
    locked: dict[str, Requirement] = {}
    for line in lock_text.splitlines():
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:==| @ )", line):
            continue
        candidate = line.partition(" --hash=")[0].rstrip()
        if candidate.endswith("\\"):
            candidate = candidate[:-1].rstrip()
        requirement = Requirement(candidate)
        name = canonicalize_name(requirement.name)
        assert name not in locked, f"duplicate lock entry for {name}"
        locked[name] = requirement
    return locked


def _assert_standard_direct_requirements_are_locked(
    input_text: str,
    lock_text: str,
) -> None:
    locked_requirements = _locked_requirements(lock_text)
    for direct_text in _input_requirements(input_text):
        direct = Requirement(direct_text)
        if direct.url is not None:
            continue
        name = canonicalize_name(direct.name)
        locked = locked_requirements.get(name)
        assert locked is not None, f"{name}: missing from lock"
        assert locked.url is None, f"{name}: unexpected URL pin"
        assert direct.marker == locked.marker, (
            f"{name}: marker mismatch: expected {direct.marker}, got {locked.marker}"
        )

        pin_specifiers = list(locked.specifier)
        assert (
            len(pin_specifiers) == 1
            and pin_specifiers[0].operator == "=="
            and "*" not in pin_specifiers[0].version
        ), f"{name}: lock entry is not one exact pin: {locked.specifier}"
        pin_version = Version(pin_specifiers[0].version)
        assert direct.specifier.contains(pin_version), (
            f"{name}: locked {pin_version} violates {direct.specifier}"
        )


@pytest.mark.parametrize(
    ("target_python", "implementation", "version_info", "pointer_size"),
    [
        ("3.12", "PyPy", (3, 12, 10), 8),
        ("3.12", "CPython", (3, 12, 9), 8),
        ("3.12", "CPython", (3, 12, 10), 4),
        ("3.12", "CPython", (3, 13, 0), 8),
        ("3.13", "CPython", (3, 12, 10), 8),
    ],
)
def test_exporter_rejects_non_contract_runtime_before_writing(
    repo_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    target_python: str,
    implementation: str,
    version_info: tuple[int, int, int],
    pointer_size: int,
) -> None:
    output = tmp_path / "must-not-exist.in"
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "version_info", version_info)
    monkeypatch.setattr(platform, "python_implementation", lambda: implementation)
    monkeypatch.setattr(struct, "calcsize", lambda _format: pointer_size)

    assert (
        exporter.main(
            [
                "--python",
                target_python,
                "--pyproject",
                str(repo_root / "pyproject.toml"),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"{exporter._runtime_error(target_python)}\n"
    assert not output.exists()


def test_exporter_rejects_non_windows_before_writing(
    repo_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "must-not-exist.in"
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(sys, "version_info", (3, 12, 10))
    monkeypatch.setattr(platform, "python_implementation", lambda: "CPython")
    monkeypatch.setattr(struct, "calcsize", lambda _format: 8)

    assert (
        exporter.main(
            [
                "--python",
                "3.12",
                "--pyproject",
                str(repo_root / "pyproject.toml"),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"{exporter._runtime_error('3.12')}\n"
    assert not output.exists()


def test_exporter_writes_current_runtime_deterministically(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.in"
    second = tmp_path / "second.in"
    command = [
        sys.executable,
        str(repo_root / "scripts" / "export_consultation_requirements.py"),
        "--python",
        "3.12",
        "--profile",
        "core",
    ]

    for output in (first, second):
        completed = subprocess.run(
            [*command, "--output", str(output)],
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr

    first_text = first.read_text(encoding="utf-8")
    assert first_text == second.read_text(encoding="utf-8")
    assert first_text.endswith("\n")


@pytest.mark.parametrize(("target_python", "profile"), TARGETS)
def test_checked_in_inputs_match_exporter_and_have_no_project_or_index_lines(
    repo_root: Path,
    target_python: str,
    profile: Profile,
) -> None:
    requirements = _expected_input_requirements(repo_root, target_python, profile)
    rendered = exporter.render_input(
        requirements,
        target_python=target_python,
        profile=profile,
    )
    checked_in = repo_root / "requirements" / f"{_stem(target_python, profile)}.in"
    assert checked_in.read_text(encoding="utf-8") == rendered
    assert _input_requirements(rendered) == requirements

    normalized = rendered.casefold()
    assert "-e " not in normalized
    assert "graphifyy" not in normalized
    assert "consultation-kb" not in normalized
    assert "--index-url" not in normalized
    assert "--extra-index-url" not in normalized
    assert "--trusted-host" not in normalized


@pytest.mark.parametrize(("target_python", "profile"), TARGETS)
def test_inputs_explicitly_pin_the_locked_build_bootstrap(
    repo_root: Path,
    target_python: str,
    profile: Profile,
) -> None:
    text = (
        repo_root / "requirements" / f"{_stem(target_python, profile)}.in"
    ).read_text(encoding="utf-8")
    requirements = _input_requirements(text)

    assert requirements.count("pip==26.0.1") == 1
    assert requirements.count("setuptools==83.0.0") == 1
    assert requirements.count("wheel==0.47.0") == 1


def test_core_inputs_preserve_312_leiden_and_make_313_degradation_explicit(
    repo_root: Path,
) -> None:
    py312 = (repo_root / "requirements" / "consultation-win-py312.in").read_text(
        encoding="utf-8"
    )
    py313 = (repo_root / "requirements" / "consultation-win-py313.in").read_text(
        encoding="utf-8"
    )
    assert "graspologic; python_version < '3.13'" in py312
    assert "graspologic" not in py313.casefold()
    assert "sentence-transformers" not in py312
    assert "sentence-transformers" not in py313
    assert "torch" not in py312
    assert "torch" not in py313


@pytest.mark.parametrize("target_python", ["3.12", "3.13"])
def test_ml_input_uses_only_the_approved_official_cpu_torch_artifact(
    repo_root: Path,
    target_python: str,
) -> None:
    path = repo_root / "requirements" / f"{_stem(target_python, 'ml')}.in"
    text = path.read_text(encoding="utf-8")
    direct = exporter.TORCH_REQUIREMENTS[target_python]
    assert _input_requirements(text).count(direct) == 1
    assert "sentence-transformers>=5.6,<6" in text
    assert "https://download-r2.pytorch.org/whl/cpu/" in direct
    assert re.search(r"#sha256=[0-9a-f]{64}$", direct)
    assert "--index-url" not in text
    assert "--extra-index-url" not in text


@pytest.mark.parametrize(("target_python", "profile"), TARGETS)
def test_hash_locks_record_compiler_command_and_target_input(
    repo_root: Path,
    target_python: str,
    profile: Profile,
) -> None:
    stem = _stem(target_python, profile)
    lock = repo_root / "requirements" / f"{stem}.lock.txt"
    text = lock.read_text(encoding="utf-8")
    header_lines: list[str] = []
    for line in text.splitlines():
        if line and not line.startswith("#"):
            break
        header_lines.append(line)
    header = "\n".join(header_lines)

    assert "pip-tools==7.5.3" in header
    assert "python -m piptools compile" in header
    assert "--generate-hashes" in header
    assert f"requirements/{stem}.in" in header.replace("\\", "/")
    assert "# warning:" not in text.casefold()


@pytest.mark.parametrize(("target_python", "profile"), TARGETS)
def test_every_standard_direct_input_distribution_is_in_hash_lock(
    repo_root: Path,
    target_python: str,
    profile: Profile,
) -> None:
    stem = _stem(target_python, profile)
    input_text = (repo_root / "requirements" / f"{stem}.in").read_text(encoding="utf-8")
    lock_text = (repo_root / "requirements" / f"{stem}.lock.txt").read_text(
        encoding="utf-8"
    )
    _assert_standard_direct_requirements_are_locked(input_text, lock_text)


def test_direct_requirement_guard_detects_stale_lock_mutation() -> None:
    input_text = "numpy>=1.26.4,<3\npydantic>=2.13.4,<3\n"
    stale_lock = "numpy==2.4.3 --hash=sha256:0000\n"
    with pytest.raises(AssertionError, match="pydantic"):
        _assert_standard_direct_requirements_are_locked(input_text, stale_lock)


def test_direct_requirement_guard_rejects_wrong_locked_version_mutation() -> None:
    input_text = "pydantic>=2.13.4,<3\n"
    wrong_version_lock = "pydantic==1.0.0 --hash=sha256:0000\n"
    with pytest.raises(AssertionError, match="pydantic"):
        _assert_standard_direct_requirements_are_locked(input_text, wrong_version_lock)


def test_direct_requirement_guard_rejects_wrong_marker_mutation() -> None:
    input_text = "graspologic; python_version < '3.13'\n"
    wrong_marker_lock = (
        'graspologic==3.4.4 ; python_version >= "3.13" --hash=sha256:0000\n'
    )
    with pytest.raises(AssertionError, match="graspologic"):
        _assert_standard_direct_requirements_are_locked(input_text, wrong_marker_lock)


@pytest.mark.parametrize(("target_python", "profile"), TARGETS)
def test_hash_locks_contain_only_hashed_third_party_artifacts(
    repo_root: Path,
    target_python: str,
    profile: Profile,
) -> None:
    stem = _stem(target_python, profile)
    text = (repo_root / "requirements" / f"{stem}.lock.txt").read_text(encoding="utf-8")
    normalized = text.casefold()
    assert "-e " not in normalized
    assert "graphifyy==" not in normalized
    assert "consultation-kb" not in normalized
    assert "--index-url" not in normalized
    assert "--extra-index-url" not in normalized
    assert "--trusted-host" not in normalized

    lines = text.splitlines()
    artifact_indices = [
        index
        for index, line in enumerate(lines)
        if re.match(
            r"^[a-z0-9][a-z0-9._-]*(?:==| @ )",
            line,
            flags=re.IGNORECASE,
        )
    ]
    assert artifact_indices
    for position, start in enumerate(artifact_indices):
        stop = (
            artifact_indices[position + 1]
            if position + 1 < len(artifact_indices)
            else len(lines)
        )
        block = "\n".join(lines[start:stop])
        assert "--hash=sha256:" in block, lines[start]


def test_lock_backend_contracts_are_version_specific(repo_root: Path) -> None:
    core312 = (
        (repo_root / "requirements" / "consultation-win-py312.lock.txt")
        .read_text(encoding="utf-8")
        .casefold()
    )
    core313 = (
        (repo_root / "requirements" / "consultation-win-py313.lock.txt")
        .read_text(encoding="utf-8")
        .casefold()
    )
    assert "graspologic==" in core312
    assert "graspologic-native==" in core312
    assert "graspologic==" not in core313
    assert "graspologic-native==" not in core313


@pytest.mark.parametrize("target_python", ["3.12", "3.13"])
def test_ml_lock_preserves_exact_cpu_torch_url_and_sha256(
    repo_root: Path,
    target_python: str,
) -> None:
    text = (
        repo_root / "requirements" / f"{_stem(target_python, 'ml')}.lock.txt"
    ).read_text(encoding="utf-8")
    expected = exporter.TORCH_REQUIREMENTS[target_python]
    expected_url, expected_hash = expected.split("#sha256=", maxsplit=1)
    assert expected_url in text
    assert f"--hash=sha256:{expected_hash}" in text
    assert "torch==" not in text.casefold()


def test_gitattributes_force_lf_for_all_consultation_locks(repo_root: Path) -> None:
    text = (repo_root / ".gitattributes").read_text(encoding="utf-8")
    assert "requirements/consultation-*.in text eol=lf" in text
    assert "requirements/consultation-*.lock.txt text eol=lf" in text
