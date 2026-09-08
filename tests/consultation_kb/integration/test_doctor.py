from __future__ import annotations

import importlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from consultation_kb.core.config import AppConfig
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.lifecycle.publish import (
    ArtifactDraft,
    ContentDraft,
    PublishCoordinator,
    publication_closure_sha256,
)
from consultation_kb.security.ntfs_acl import AclPolicy
from consultation_kb.storage.catalog import ClientCatalog
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.storage.tombstones import (
    TombstoneRepository,
    VisibilityGuard,
)
from consultation_kb.vault.content_store import ContentStore


EXPECTED_CHECKS = {
    "python_runtime",
    "vault_outside_repo",
    "sqlite_fts5_roundtrip",
    "schema_exports_match",
    "policies_load",
    "git_tracked_privacy",
    "migration_checksums",
    "vault_acl",
    "dpapi_roundtrip",
    "staging_same_volume",
    "identity_map_permissions",
    "prepared_manifests",
    "active_manifests",
}

P1_NOT_APPLICABLE_CODES = {
    "migration_checksums": "migration_checksums_not_applicable",
    "vault_acl": "vault_acl_not_applicable",
    "dpapi_roundtrip": "dpapi_roundtrip_not_applicable",
    "staging_same_volume": "staging_same_volume_not_applicable",
    "identity_map_permissions": "identity_map_permissions_not_applicable",
    "prepared_manifests": "prepared_manifests_not_applicable",
    "active_manifests": "active_manifests_not_applicable",
}


def _doctor_module() -> Any:
    try:
        return importlib.import_module("consultation_kb.core.doctor")
    except ModuleNotFoundError:
        pytest.fail("Doctor API is missing")


def _run_git(repo: Path, *args: str) -> None:
    result = subprocess.run(
        ["git", "-c", "core.autocrlf=false", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def _valid_workspace(tmp_path: Path, source_repo: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    vault = tmp_path / "knowledge-vault"
    repo.mkdir()
    vault.mkdir()

    shutil.copytree(source_repo / "policies", repo / "policies")
    shutil.copytree(source_repo / "schemas", repo / "schemas")
    canary = repo / "tests" / "fixtures" / "consultation_kb" / "canaries.json"
    canary.parent.mkdir(parents=True)
    shutil.copy2(
        source_repo / "tests" / "fixtures" / "consultation_kb" / "canaries.json",
        canary,
    )

    result = subprocess.run(
        ["git", "init", "--quiet", str(repo)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    _run_git(repo, "add", "--", "policies", "schemas", "tests")
    return repo, vault


def _initialize_empty_p1_vault(vault: Path) -> Path:
    policy = AclPolicy()
    policy.apply(vault)
    global_root = vault / "global"
    clients_root = vault / "clients"
    clients_root.mkdir()
    identity_root = vault / "identity"
    global_root.mkdir()
    identity_root.mkdir()
    for protected_directory in (global_root, clients_root, identity_root):
        policy.apply(protected_directory)
    (identity_root / "identity-map.enc").write_bytes(b"synthetic-protected-map")
    database = global_root / "catalog.sqlite3"
    connection = connect_database(database, mode="writer")
    try:
        MigrationRunner.for_scope(connection, "global").apply()
    finally:
        connection.close()
    return database


def _add_active_client_scope(
    vault: Path,
    global_database: Path,
    *,
    activated_at: datetime,
) -> tuple[str, Path]:
    client_id = "client_" + "cafe1234beef"
    directory_object_id = "client_directory_01800000-0000-7000-8000-000000000001"
    global_connection = connect_database(global_database, mode="writer")
    try:
        catalog = ClientCatalog(global_connection)
        catalog.prepare(
            client_id=client_id,
            directory_object_id=directory_object_id,
            alias_lookup_sha256="d" * 64,
            created_at=activated_at,
        )
        catalog.activate(client_id, activated_at=activated_at)
    finally:
        global_connection.close()

    client_root = vault / "clients" / client_id
    client_root.mkdir()
    (client_root / ".scope-id").write_text(
        f"{directory_object_id}\n",
        encoding="ascii",
        newline="\n",
    )
    client_connection = connect_database(
        client_root / "client.sqlite3",
        mode="writer",
    )
    try:
        MigrationRunner.for_scope(client_connection, "client").apply()
    finally:
        client_connection.close()
    AclPolicy().apply(client_root)
    return client_id, client_root


def _add_everyone_file_access(path: Path) -> None:
    ntsecuritycon = importlib.import_module("ntsecuritycon")
    win32security = importlib.import_module("win32security")
    security = win32security.GetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
    )
    dacl = security.GetSecurityDescriptorDacl()
    assert dacl is not None
    everyone = win32security.CreateWellKnownSid(
        win32security.WinWorldSid,
        None,
    )
    dacl.AddAccessAllowedAceEx(
        win32security.ACL_REVISION_DS,
        0,
        ntsecuritycon.FILE_ALL_ACCESS,
        everyone,
    )
    win32security.SetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
        None,
        None,
        dacl,
        None,
    )


def _assert_no_open_ended_diagnostics(value: object) -> None:
    if isinstance(value, dict):
        assert not {
            "body",
            "content",
            "details",
            "path",
            "raw_text",
            "transcript",
        }.intersection(value)
        for child in value.values():
            _assert_no_open_ended_diagnostics(child)
    elif isinstance(value, list):
        for child in value:
            _assert_no_open_ended_diagnostics(child)


def test_doctor_checks_real_fts5_external_vault_and_required_assets(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    repo, vault = _valid_workspace(tmp_path, repo_root)
    module = _doctor_module()

    report = module.Doctor(AppConfig.from_values(repo, vault)).run()

    assert report.ok is True
    assert set(report.checks) == EXPECTED_CHECKS
    assert all(check.status == "pass" for check in report.checks.values())
    assert report.checks["sqlite_fts5_roundtrip"].code == ("sqlite_fts5_roundtrip_ok")
    assert report.checks["vault_outside_repo"].code == "vault_roots_disjoint"
    assert report.checks["schema_exports_match"].observed_count == 21
    assert report.checks["policies_load"].observed_count == 4
    assert {
        name: report.checks[name].code for name in P1_NOT_APPLICABLE_CODES
    } == P1_NOT_APPLICABLE_CODES
    assert all(
        report.checks[name].observed_count == 0 for name in P1_NOT_APPLICABLE_CODES
    )
    assert tuple(vault.iterdir()) == ()

    encoded = report.model_dump(mode="json")
    assert set(encoded) == {"ok", "checks"}
    assert all(
        set(check) == {"status", "code", "observed_count"}
        for check in encoded["checks"].values()
    )
    _assert_no_open_ended_diagnostics(encoded)
    json.dumps(
        encoded,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def test_doctor_treats_nonempty_p0_only_vault_as_not_applicable(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    repo, vault = _valid_workspace(tmp_path, repo_root)
    p0_asset = vault / "sources" / "policy-manifest.json"
    p0_asset.parent.mkdir()
    p0_asset.write_bytes(b'{"schema_version":"1.0"}\n')
    before = {
        path.relative_to(vault): path.read_bytes()
        for path in vault.rglob("*")
        if path.is_file()
    }

    report = _doctor_module().Doctor(AppConfig.from_values(repo, vault)).run()

    assert report.ok is True
    assert {
        name: report.checks[name].code for name in P1_NOT_APPLICABLE_CODES
    } == P1_NOT_APPLICABLE_CODES
    after = {
        path.relative_to(vault): path.read_bytes()
        for path in vault.rglob("*")
        if path.is_file()
    }
    assert after == before


def test_doctor_fails_closed_for_partial_global_initialization_marker(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    repo, vault = _valid_workspace(tmp_path, repo_root)
    (vault / "global").mkdir()

    report = _doctor_module().Doctor(AppConfig.from_values(repo, vault)).run()

    assert report.ok is False
    assert report.checks["migration_checksums"].code == ("migration_checksums_invalid")
    assert report.checks["active_manifests"].code == ("active_manifests_invalid")
    assert all(report.checks[name].status == "fail" for name in P1_NOT_APPLICABLE_CODES)
    assert tuple((vault / "global").iterdir()) == ()


def test_doctor_fails_closed_when_clients_marker_precedes_global_catalog(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    repo, vault = _valid_workspace(tmp_path, repo_root)
    (vault / "clients").mkdir()

    report = _doctor_module().Doctor(AppConfig.from_values(repo, vault)).run()

    assert report.ok is False
    assert all(report.checks[name].status == "fail" for name in P1_NOT_APPLICABLE_CODES)
    assert report.checks["migration_checksums"].code == ("migration_checksums_invalid")
    assert tuple((vault / "clients").iterdir()) == ()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows P1 Doctor probes")
def test_doctor_verifies_initialized_empty_p1_vault_without_mutating_it(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    repo, vault = _valid_workspace(tmp_path, repo_root)
    _initialize_empty_p1_vault(vault)
    before = {
        path.relative_to(vault): path.read_bytes()
        for path in vault.rglob("*")
        if path.is_file()
    }

    report = _doctor_module().Doctor(AppConfig.from_values(repo, vault)).run()

    assert report.ok is True
    assert report.checks["migration_checksums"].code == ("migration_checksums_match")
    assert report.checks["vault_acl"].code == "vault_acl_verified"
    assert report.checks["dpapi_roundtrip"].code == "dpapi_roundtrip_ok"
    assert report.checks["staging_same_volume"].code == ("staging_same_volume_verified")
    assert report.checks["identity_map_permissions"].code == (
        "identity_map_permissions_verified"
    )
    assert report.checks["prepared_manifests"].code == ("prepared_manifests_absent")
    assert report.checks["active_manifests"].code == ("active_manifests_verified")
    after = {
        path.relative_to(vault): path.read_bytes()
        for path in vault.rglob("*")
        if path.is_file()
    }
    assert after == before


@pytest.mark.skipif(sys.platform != "win32", reason="Windows P1 Doctor probes")
def test_doctor_verifies_matching_identity_lock_file_acl(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    repo, vault = _valid_workspace(tmp_path, repo_root)
    _initialize_empty_p1_vault(vault)
    identity_lock = vault / "identity" / ".identity-map.lock"
    identity_lock.write_bytes(b"\x00")

    report = _doctor_module().Doctor(AppConfig.from_values(repo, vault)).run()

    assert report.ok is True
    assert report.checks["identity_map_permissions"].code == (
        "identity_map_permissions_verified"
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows P1 Doctor probes")
@pytest.mark.parametrize("attack", ["hardlink", "junction", "acl"])
def test_doctor_rejects_unsafe_identity_lock_file(
    repo_root: Path,
    tmp_path: Path,
    attack: str,
) -> None:
    repo, vault = _valid_workspace(tmp_path, repo_root)
    _initialize_empty_p1_vault(vault)
    identity_lock = vault / "identity" / ".identity-map.lock"
    created_junction = False
    if attack == "hardlink":
        outside = tmp_path / "outside-lock.bin"
        outside.write_bytes(b"\x00")
        os.link(outside, identity_lock)
    elif attack == "junction":
        outside_directory = tmp_path / "outside-lock-directory"
        outside_directory.mkdir()
        result = subprocess.run(
            [
                "cmd.exe",
                "/d",
                "/c",
                "mklink",
                "/J",
                str(identity_lock),
                str(outside_directory),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        created_junction = True
    else:
        identity_lock.write_bytes(b"\x00")
        _add_everyone_file_access(identity_lock)

    try:
        report = _doctor_module().Doctor(AppConfig.from_values(repo, vault)).run()

        assert report.ok is False
        assert report.checks["identity_map_permissions"].status == "fail"
        assert report.checks["identity_map_permissions"].code == (
            "identity_map_permissions_invalid"
        )
        encoded = json.dumps(
            report.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        assert str(identity_lock) not in encoded
        _assert_no_open_ended_diagnostics(report.model_dump(mode="json"))
    finally:
        if created_junction and identity_lock.exists():
            identity_lock.rmdir()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows P1 Doctor probes")
@pytest.mark.parametrize(
    "drifted_scope",
    ["global", "clients", "identity", "security", "active_client"],
)
def test_doctor_fails_closed_for_protected_scope_acl_drift(
    repo_root: Path,
    tmp_path: Path,
    fixed_now: datetime,
    drifted_scope: str,
) -> None:
    repo, vault = _valid_workspace(tmp_path, repo_root)
    database = _initialize_empty_p1_vault(vault)
    client_id, client_root = _add_active_client_scope(
        vault,
        database,
        activated_at=fixed_now,
    )
    security_root = vault / "security"
    security_root.mkdir()
    AclPolicy().apply(security_root)
    targets = {
        "global": vault / "global",
        "clients": vault / "clients",
        "identity": vault / "identity",
        "security": security_root,
        "active_client": client_root,
    }
    AclPolicy(backup_principals=("S-1-1-0",)).apply(targets[drifted_scope])

    report = _doctor_module().Doctor(AppConfig.from_values(repo, vault)).run()

    assert report.ok is False
    assert report.checks["vault_acl"].status == "fail"
    assert report.checks["vault_acl"].code == "vault_acl_invalid"
    encoded = json.dumps(
        report.model_dump(mode="json"),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    assert client_id not in encoded
    assert str(targets[drifted_scope]) not in encoded
    _assert_no_open_ended_diagnostics(report.model_dump(mode="json"))


@pytest.mark.skipif(sys.platform != "win32", reason="Windows P1 Doctor probes")
def test_doctor_pins_database_handle_before_snapshot_reopen(
    repo_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, vault = _valid_workspace(tmp_path, repo_root)
    database = _initialize_empty_p1_vault(vault)
    replacement = database.with_name("replacement.sqlite3")
    replacement.write_bytes(b"not-a-sqlite-database")
    module = _doctor_module()
    real_snapshot = module.connect_database_snapshot
    blocked_attempts = 0

    def attack_after_guard(path: Path) -> sqlite3.Connection:
        nonlocal blocked_attempts
        try:
            os.replace(replacement, path)
        except OSError:
            blocked_attempts += 1
        else:
            pytest.fail("verified database was replaceable before snapshot open")
        return real_snapshot(path)

    monkeypatch.setattr(module, "connect_database_snapshot", attack_after_guard)

    report = module.Doctor(AppConfig.from_values(repo, vault)).run()

    assert report.ok is True
    assert blocked_attempts >= 1
    assert report.checks["migration_checksums"].code == ("migration_checksums_match")
    assert replacement.read_bytes() == b"not-a-sqlite-database"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows P1 Doctor probes")
def test_doctor_rejects_hardlinked_database_before_sqlite_open(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    repo, vault = _valid_workspace(tmp_path, repo_root)
    database = _initialize_empty_p1_vault(vault)
    os.link(database, tmp_path / "catalog-alias.sqlite3")

    report = _doctor_module().Doctor(AppConfig.from_values(repo, vault)).run()

    assert report.ok is False
    assert report.checks["migration_checksums"].code == ("migration_checksums_invalid")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows P1 Doctor probes")
def test_doctor_verifies_active_manifest_bytes_and_detects_corruption(
    repo_root: Path,
    tmp_path: Path,
    fixed_now,
) -> None:
    repo, vault = _valid_workspace(tmp_path, repo_root)
    database = _initialize_empty_p1_vault(vault)
    connection = connect_database(database, mode="writer")
    ids = IdFactory(FixedClock(fixed_now))
    store = ContentStore(vault / "global")
    coordinator = PublishCoordinator(
        connection,
        store,
        VisibilityGuard(TombstoneRepository(connection, clock=FixedClock(fixed_now))),
        clock=FixedClock(fixed_now),
    )
    payload = b'{"active":true}\n'
    artifact = ArtifactDraft(
        manifest_id=ids.object_id("manifest"),
        artifact_key="policy_manifest",
        artifact_kind="policy_manifest",
        source_version=1,
        members=(
            ContentDraft(
                object_type="artifact",
                object_id=ids.object_id("artifact"),
                data=payload,
                source_version=1,
                media_type="application/json",
                source_lineage=(),
            ),
        ),
    )
    prepared_artifacts = coordinator.stage_artifacts(
        purpose="policy_publish",
        artifacts=(artifact,),
    )
    operation_id = ids.object_id("operation")
    request_id = ids.object_id("approval_request")
    descriptor_sha256 = "a" * 64
    connection.execute(
        "INSERT INTO approval_executions("
        "operation_id, request_id, descriptor_sha256, draft_sha256, "
        "descriptor_base_version, target_scope_hash, "
        "nonce_sha256, state, applied_commit_version, applied_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, 'CLAIMED', NULL, NULL)",
        (
            operation_id,
            request_id,
            descriptor_sha256,
            publication_closure_sha256(
                purpose="policy_publish",
                authority_base_version=1,
                expected_current_epoch=None,
                artifacts=prepared_artifacts,
            ),
            0,
            "b" * 64,
            "c" * 64,
        ),
    )
    operation = coordinator.prepare(
        operation_id=operation_id,
        purpose="policy_publish",
        authority_base_version=1,
        approval_request_id=request_id,
        descriptor_sha256=descriptor_sha256,
        expected_current_epoch=None,
        artifacts=prepared_artifacts,
    )
    connection.execute(
        "UPDATE approval_executions SET state = 'APPLIED', "
        "applied_commit_version = 1, applied_at = ? WHERE operation_id = ?",
        ("2026-07-16T08:00:00.000000Z", operation_id),
    )
    coordinator.verify(operation.operation_id)
    coordinator.activate(operation.operation_id)
    reference = prepared_artifacts[0].members[0].reference
    connection.close()

    healthy = _doctor_module().Doctor(AppConfig.from_values(repo, vault)).run()

    assert healthy.ok is True
    assert healthy.checks["active_manifests"].observed_count == 1
    assert healthy.checks["staging_same_volume"].observed_count == 1

    reference.path.write_bytes(b'{"active":null}\n')
    corrupted = _doctor_module().Doctor(AppConfig.from_values(repo, vault)).run()

    assert corrupted.ok is False
    assert corrupted.checks["active_manifests"].code == ("active_manifests_invalid")


def test_doctor_fails_closed_if_validated_roots_are_tampered_to_overlap(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    repo, vault = _valid_workspace(tmp_path, repo_root)
    config = AppConfig.from_values(repo, vault)
    nested_vault = repo / "runtime-vault"
    nested_vault.mkdir()
    object.__setattr__(config, "vault_root", nested_vault)

    report = _doctor_module().Doctor(config).run()

    assert report.ok is False
    assert report.checks["vault_outside_repo"].status == "fail"
    assert report.checks["vault_outside_repo"].code == "vault_root_overlap"


def test_doctor_fails_closed_when_fts5_is_unavailable(
    repo_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, vault = _valid_workspace(tmp_path, repo_root)
    module = _doctor_module()

    def deny_sqlite(*_args: object, **_kwargs: object) -> sqlite3.Connection:
        raise sqlite3.OperationalError("synthetic fts5 denial")

    monkeypatch.setattr(module, "_SQLITE_CONNECT", deny_sqlite)

    report = module.Doctor(AppConfig.from_values(repo, vault)).run()

    assert report.ok is False
    assert report.checks["sqlite_fts5_roundtrip"].status == "fail"
    assert report.checks["sqlite_fts5_roundtrip"].code == (
        "sqlite_fts5_roundtrip_failed"
    )


def test_doctor_fails_closed_on_checked_in_schema_drift(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    repo, vault = _valid_workspace(tmp_path, repo_root)
    drifted = repo / "schemas" / "version_ref.schema.json"
    drifted.write_bytes(drifted.read_bytes() + b"\n")

    report = _doctor_module().Doctor(AppConfig.from_values(repo, vault)).run()

    assert report.ok is False
    assert report.checks["schema_exports_match"].status == "fail"
    assert report.checks["schema_exports_match"].code == "schema_exports_drift"


def test_doctor_fails_closed_on_tracked_privacy_hit(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    repo, vault = _valid_workspace(tmp_path, repo_root)
    leak = repo / "synthetic-leak.txt"
    stable_client_canary = "client" + "_abcdefghijkl"
    leak.write_text(f"{stable_client_canary}\n", encoding="utf-8")
    _run_git(repo, "add", "--", leak.name)

    report = _doctor_module().Doctor(AppConfig.from_values(repo, vault)).run()

    privacy = report.checks["git_tracked_privacy"]
    assert report.ok is False
    assert privacy.status == "fail"
    assert privacy.code == "git_tracked_privacy_hits"
    assert privacy.observed_count is not None and privacy.observed_count >= 1


def test_doctor_excludes_only_tracked_test_fixtures_and_implementation_plans(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    repo, vault = _valid_workspace(tmp_path, repo_root)
    test_fixture = repo / "tests" / "synthetic_contract.py"
    stable_client_canary = "client" + "_abcdefghijkl"
    test_fixture.write_text(
        f'INVALID_CLIENT = "{stable_client_canary}"\n'
        'INVALID_EMAIL = "policy-contract-test@example.invalid"\n',
        encoding="utf-8",
    )
    plan = repo / "docs" / "superpowers" / "plans" / "synthetic.md"
    plan.parent.mkdir(parents=True)
    plan.write_text(
        '@pytest.mark.acceptance_id("SYNTHETIC-01")\n',
        encoding="utf-8",
    )
    _run_git(repo, "add", "--", "tests", "docs")

    report = _doctor_module().Doctor(AppConfig.from_values(repo, vault)).run()

    assert report.ok is True
    assert report.checks["git_tracked_privacy"].status == "pass"
