from __future__ import annotations

import json
from pathlib import Path

from consultation_kb.cli import main
from consultation_kb.core.doctor import DoctorCheck
from consultation_kb.operations.doctor_probes import RetrievalArtifactDiagnosticProbe


def _single_json_object(stdout: str) -> dict[str, object]:
    lines = stdout.splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert isinstance(payload, dict)
    return payload


def test_doctor_json_stdout_is_exactly_one_object(
    repo_root: Path,
    tmp_path: Path,
    capsys,
) -> None:
    vault = tmp_path / "missing-vault"
    exit_code = main(
        [
            "doctor",
            "--repo-root",
            str(repo_root),
            "--vault-root",
            str(vault),
            "--json",
        ]
    )

    captured = capsys.readouterr()
    payload = _single_json_object(captured.out)
    # A missing vault is still non-mutating/not-applicable, but P5 Doctor also
    # verifies the generated, ignored Codex MCP config.  A clean checkout has
    # only the template, so readiness must fail until configure-codex runs.
    assert exit_code == 2
    assert payload["ok"] is False
    assert isinstance(payload["checks"], dict)
    checks = payload["checks"]
    assert checks["migration_checksums"]["code"] == (
        "migration_checksums_not_applicable"
    )
    assert checks["active_manifests"]["code"] == (
        "active_manifests_not_applicable"
    )
    assert checks["retrieval_artifacts"]["code"] == (
        "retrieval_artifacts_not_applicable"
    )
    assert checks["mcp_runtime"] == {
        "status": "fail",
        "code": "mcp_runtime_invalid",
        "observed_count": None,
    }
    assert "mcp_runtime_invalid" in captured.err
    assert not vault.exists()


def test_doctor_cli_resolves_plan_style_relative_roots(
    repo_root: Path,
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    vault = repo_root.parent / f".consultation-doctor-{tmp_path.name}"
    monkeypatch.chdir(repo_root)

    exit_code = main(
        [
            "doctor",
            "--repo-root",
            ".",
            "--vault-root",
            f"../{vault.name}",
            "--json",
        ]
    )

    captured = capsys.readouterr()
    payload = _single_json_object(captured.out)
    assert exit_code == 2
    assert payload["ok"] is False
    assert payload["checks"]["mcp_runtime"]["code"] == "mcp_runtime_invalid"
    assert "mcp_runtime_invalid" in captured.err
    assert not vault.exists()


def test_doctor_json_configuration_failure_is_closed_and_path_free(
    repo_root: Path,
    capsys,
) -> None:
    exit_code = main(
        [
            "doctor",
            "--repo-root",
            str(repo_root),
            "--vault-root",
            str(repo_root / "knowledge-vault"),
            "--json",
        ]
    )

    captured = capsys.readouterr()
    payload = _single_json_object(captured.out)
    assert exit_code == 2
    assert payload["ok"] is False
    assert "CONFIG_" in captured.err
    combined = captured.out + captured.err
    assert str(repo_root) not in combined


def test_doctor_cli_always_injects_retrieval_artifact_probe(
    repo_root: Path,
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    def fail_probe(
        self: RetrievalArtifactDiagnosticProbe,
        _config: object,
    ) -> DoctorCheck:
        return DoctorCheck(
            status="fail",
            code="retrieval_artifacts_invalid",
        )

    monkeypatch.setattr(RetrievalArtifactDiagnosticProbe, "run", fail_probe)

    exit_code = main(
        [
            "doctor",
            "--repo-root",
            str(repo_root),
            "--vault-root",
            str(tmp_path / "missing-vault"),
            "--json",
        ]
    )

    captured = capsys.readouterr()
    payload = _single_json_object(captured.out)
    assert exit_code == 2
    assert payload["ok"] is False
    assert payload["checks"]["retrieval_artifacts"] == {
        "status": "fail",
        "code": "retrieval_artifacts_invalid",
        "observed_count": None,
    }
    assert "retrieval_artifacts_invalid" in captured.err
