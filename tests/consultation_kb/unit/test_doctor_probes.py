from __future__ import annotations

from pathlib import Path

from consultation_kb.core.config import AppConfig
from consultation_kb.core.doctor import Doctor, DoctorCheck


class _FixedProbe:
    name = "retrieval_artifacts"

    def __init__(self, result: DoctorCheck | BaseException) -> None:
        self._result = result

    def run(self, _config: AppConfig) -> DoctorCheck:
        if isinstance(self._result, BaseException):
            raise self._result
        return self._result


def _config(tmp_path: Path) -> AppConfig:
    repo = tmp_path / "repo"
    vault = tmp_path / "vault"
    repo.mkdir()
    (repo / ".git").mkdir()
    vault.mkdir()
    return AppConfig.from_values(repo, vault)


def test_doctor_runs_injected_probe_and_serializes_fixed_safe_result(
    tmp_path: Path,
) -> None:
    probe = _FixedProbe(
        DoctorCheck(
            status="pass",
            code="retrieval_artifacts_verified",
            observed_count=3,
        )
    )

    report = Doctor(_config(tmp_path), diagnostic_probes=(probe,)).run()

    assert report.checks["retrieval_artifacts"] == probe._result
    assert report.model_dump(mode="json")["checks"]["retrieval_artifacts"] == {
        "status": "pass",
        "code": "retrieval_artifacts_verified",
        "observed_count": 3,
    }


def test_doctor_fails_closed_when_injected_probe_raises(tmp_path: Path) -> None:
    report = Doctor(
        _config(tmp_path),
        diagnostic_probes=(_FixedProbe(RuntimeError("secret path")),),
    ).run()

    check = report.checks["retrieval_artifacts"]
    assert check.status == "fail"
    assert check.code == "retrieval_artifacts_probe_failed"
    assert "secret" not in check.model_dump_json()


def test_doctor_rejects_duplicate_or_open_ended_probe_names(tmp_path: Path) -> None:
    config = _config(tmp_path)
    result = DoctorCheck(
        status="pass",
        code="retrieval_artifacts_not_applicable",
        observed_count=0,
    )
    first = _FixedProbe(result)
    second = _FixedProbe(result)

    try:
        Doctor(config, diagnostic_probes=(first, second))
    except TypeError as error:
        assert str(error) == "DOCTOR_DIAGNOSTIC_PROBES_INVALID"
    else:
        raise AssertionError("duplicate probe name was accepted")

    second.name = "client_" + "a1b2c3d4e5f6"  # type: ignore[misc]
    try:
        Doctor(config, diagnostic_probes=(second,))
    except TypeError as error:
        assert str(error) == "DOCTOR_DIAGNOSTIC_PROBES_INVALID"
    else:
        raise AssertionError("client-shaped probe name was accepted")
