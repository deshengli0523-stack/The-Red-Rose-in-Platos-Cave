from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.config import AppConfig
from consultation_kb.core.doctor import Doctor
from consultation_kb.core.ids import IdFactory
from consultation_kb.evaluation.privacy_scan import PrivacyScanner
from consultation_kb.observability import AuditEvent, AuditSink, FrozenCounts
from scripts.export_consultation_schemas import export_schemas


def _run_git(repo: Path, *args: str) -> tuple[str, ...]:
    completed = subprocess.run(
        ["git", "-c", "core.autocrlf=false", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    return tuple(line for line in completed.stdout.splitlines() if line)


def _build_synthetic_repo(
    root: Path,
    source_repo: Path,
) -> tuple[Path, Path, Path]:
    repo = root / "repo"
    vault = root / "knowledge-vault"
    repo.mkdir()
    vault.mkdir()
    shutil.copytree(source_repo / "policies", repo / "policies")
    shutil.copytree(source_repo / "schemas", repo / "schemas")
    catalog = repo / "tests" / "fixtures" / "consultation_kb" / "canaries.json"
    catalog.parent.mkdir(parents=True)
    shutil.copy2(
        source_repo / "tests" / "fixtures" / "consultation_kb" / "canaries.json",
        catalog,
    )
    (repo / "runtime-contract.txt").write_text(
        "synthetic consultation runtime contract\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["git", "init", "--quiet", str(repo)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    _run_git(repo, "add", "--", "policies", "schemas", "tests", "runtime-contract.txt")
    return repo, vault, catalog


def test_p0_vertical_slice_is_fail_closed_and_body_free(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    repo, vault, catalog = _build_synthetic_repo(tmp_path, repo_root)
    config = AppConfig.load(repo_root=repo, vault_root=vault, environ={})

    doctor_report = Doctor(config).run()
    assert doctor_report.ok is True
    assert all(check.status == "pass" for check in doctor_report.checks.values())
    assert tuple(vault.iterdir()) == ()

    tracked_paths = tuple(repo / relative for relative in _run_git(repo, "ls-files"))
    scanner = PrivacyScanner.default(
        profile="repo_tracked",
        canary_definition_path=catalog,
        hash_key=b"k" * 32,
    )
    clean = scanner.scan_paths(tracked_paths)
    assert clean.report.hit_count == 0

    leaked = repo / "synthetic-leak.txt"
    canary = "SYNTH-CANARY-" + "ALPHA-" + "9F3A"
    leaked.write_text(canary, encoding="utf-8")
    injected = scanner.scan_paths((leaked,))
    assert injected.report.hit_count == 1
    assert injected.report.hits[0].rule_id == "known_canary"
    leaked.unlink()
    recovered = scanner.scan_paths(tracked_paths)
    assert recovered.report.hit_count == 0

    exported = tmp_path / "exported-schemas"
    export_schemas(exported)
    expected_schemas = {
        path.name: path.read_bytes() for path in (repo / "schemas").glob("*.schema.json")
    }
    actual_schemas = {
        path.name: path.read_bytes() for path in exported.glob("*.schema.json")
    }
    assert actual_schemas == expected_schemas

    now = datetime(2026, 7, 16, 8, 0, tzinfo=timezone.utc)
    ids = IdFactory(FixedClock(now), lambda: 7)
    event = AuditEvent(
        event_id=ids.object_id("audit"),
        run_id=ids.uuid7(),
        event_type="p0_vertical_slice",
        occurred_at=now,
        scope_sha256="a" * 64,
        counts=FrozenCounts(
            {
                "doctor_checks": len(doctor_report.checks),
                "privacy_hits": recovered.report.hit_count,
                "schema_count": len(actual_schemas),
            }
        ),
        result_sha256="b" * 64,
    )
    audit_path = tmp_path / "audit.jsonl"
    AuditSink(audit_path).emit(event)
    encoded_audit = audit_path.read_bytes()
    assert AuditSink(audit_path).load() == (event,)
    assert canary.encode("utf-8") not in encoded_audit
    assert b"raw_text" not in encoded_audit
    assert b"transcript" not in encoded_audit
