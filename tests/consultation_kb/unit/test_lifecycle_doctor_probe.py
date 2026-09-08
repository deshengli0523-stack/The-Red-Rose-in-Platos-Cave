from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from consultation_kb.cli import main
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.config import AppConfig
from consultation_kb.core.ids import IdFactory
from consultation_kb.lifecycle.publish import (
    ArtifactDraft,
    ContentDraft,
    PublishCoordinator,
    publication_closure_sha256,
)
from consultation_kb.lifecycle.production_rebuild import (
    CONFIG_FILENAME,
    ProductionRebuildConfig,
)
from consultation_kb.operations.doctor_probes import (
    ActiveClosureDiagnosticProbe,
    RebuildCapabilityDiagnosticProbe,
    RecoveryPendingDiagnosticProbe,
    lifecycle_diagnostic_probes,
)
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner, load_migrations
from consultation_kb.storage.tombstones import TombstoneRepository, VisibilityGuard
from consultation_kb.vault.content_store import ContentStore
from consultation_kb.vault.content_store import ContentObjectRef
from consultation_kb.security.scope_identity import global_approval_scope_sha256
from tests.consultation_kb.retrieval_support import model_descriptor


NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)


def _migrated_vault(
    tmp_path: Path,
) -> tuple[AppConfig, sqlite3.Connection, ContentStore]:
    repo_root = tmp_path / "synthetic-repo"
    (repo_root / ".git").mkdir(parents=True)
    vault = tmp_path / "synthetic-vault"
    global_root = vault / "global"
    global_root.mkdir(parents=True)
    (vault / "clients").mkdir()
    connection = connect_database(global_root / "catalog.sqlite3", mode="writer")
    MigrationRunner(connection, load_migrations("global")).apply()
    config = AppConfig.from_values(repo_root, vault)
    rebuild = ProductionRebuildConfig.create_global(
        scope_sha256=global_approval_scope_sha256(config.vault_root),
        model_descriptor=model_descriptor(),
        embedder_kind="deterministic_test",
        deterministic_vocabulary={"synthetic": (1.0, 0.0)},
        test_mode=True,
        graphify_production=False,
    )
    (global_root / CONFIG_FILENAME).write_bytes(rebuild.canonical_bytes)
    return config, connection, ContentStore(global_root)


def _publish_one_active_artifact(
    connection: sqlite3.Connection,
    store: ContentStore,
) -> ContentObjectRef:
    ids = IdFactory(FixedClock(NOW), random_source=iter(range(1, 100)).__next__)
    coordinator = PublishCoordinator(
        connection,
        store,
        VisibilityGuard(
            TombstoneRepository(connection, clock=FixedClock(NOW))
        ),
        clock=FixedClock(NOW),
    )
    artifact = ArtifactDraft(
        manifest_id=ids.object_id("manifest"),
        artifact_key="policy_manifest",
        artifact_kind="policy_manifest",
        source_version=1,
        members=(
            ContentDraft(
                object_type="artifact",
                object_id=ids.object_id("artifact"),
                data=b'{"lifecycle":"healthy"}\n',
                source_version=1,
                media_type="application/json",
                source_lineage=(),
            ),
        ),
    )
    staged = coordinator.stage_artifacts(
        purpose="policy_publish",
        artifacts=(artifact,),
    )
    operation_id = ids.object_id("operation")
    request_id = ids.object_id("approval_request")
    descriptor_sha256 = "a" * 64
    closure = publication_closure_sha256(
        purpose="policy_publish",
        authority_base_version=1,
        expected_current_epoch=None,
        artifacts=staged,
    )
    connection.execute(
        "UPDATE knowledge_catalog_state SET catalog_version = 1 "
        "WHERE singleton = 1"
    )
    connection.execute(
        "INSERT INTO approval_executions("
        "operation_id, request_id, descriptor_sha256, draft_sha256, "
        "descriptor_base_version, target_scope_hash, nonce_sha256, state, "
        "applied_commit_version, applied_at"
        ") VALUES (?, ?, ?, ?, 0, ?, ?, 'CLAIMED', NULL, NULL)",
        (
            operation_id,
            request_id,
            descriptor_sha256,
            closure,
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
        artifacts=staged,
    )
    connection.execute(
        "UPDATE approval_executions SET state = 'APPLIED', "
        "applied_commit_version = 1, applied_at = ? WHERE operation_id = ?",
        ("2026-07-19T12:00:00.000000Z", operation_id),
    )
    coordinator.verify(operation.operation_id)
    coordinator.activate(operation.operation_id)
    return staged[0].members[0].reference


def test_lifecycle_probe_set_checks_real_empty_v6_scope(
    tmp_path: Path,
) -> None:
    config, connection, _store = _migrated_vault(tmp_path)
    try:
        results = {
            probe.name: probe.run(config)
            for probe in lifecycle_diagnostic_probes()
        }

        assert set(results) == {
            "recovery_pending",
            "active_closure",
            "tombstone_epoch",
            "cleanup_queue",
            "backup_queue",
            "case_index_invalidations",
            "wal_checkpoint",
            "rebuild_capability",
        }
        assert all(result.status == "pass" for result in results.values())
        assert results["rebuild_capability"].observed_count is not None
        assert results["rebuild_capability"].observed_count > 0
    finally:
        connection.close()


def test_global_lifecycle_probes_never_open_catalogued_client_databases(
    tmp_path: Path,
) -> None:
    config, connection, _store = _migrated_vault(tmp_path)
    try:
        connection.execute(
            "INSERT INTO clients("
            "client_id, directory_object_id, alias_lookup_sha256, state, "
            "created_at, activated_at"
            ") VALUES (?, ?, ?, 'ACTIVE', ?, ?)",
            (
            "client" + "_abcdefghijkl",
                "private-directory-object",
                "d" * 64,
                "2026-07-19T12:00:00.000000Z",
                "2026-07-19T12:00:00.000000Z",
            ),
        )
        # No private directory exists.  The global probes must remain healthy:
        # following this catalog row would both fail and cross the task/client
        # boundary.  Client checks belong to the bound scoped worker instead.
        results = {
            probe.name: probe.run(config)
            for probe in lifecycle_diagnostic_probes()
        }

        assert all(result.status == "pass" for result in results.values())
    finally:
        connection.close()


def test_recovery_probe_fails_on_real_prepared_publication(
    tmp_path: Path,
) -> None:
    config, connection, _store = _migrated_vault(tmp_path)
    try:
        connection.execute(
            "INSERT INTO publication_operations("
            "operation_id, purpose, authority_base_version, approval_request_id, "
            "descriptor_sha256, state, required_manifests_json, "
            "required_manifest_count, verified_manifest_count, "
            "expected_current_epoch, runtime_epoch, created_at, activated_at"
            ") VALUES ('operation_pending', 'policy_publish', 1, "
            "'approval_pending', ?, 'PREPARED', '[]', 0, 0, NULL, NULL, ?, NULL)",
            ("a" * 64, "2026-07-19T12:00:00.000000Z"),
        )

        result = RecoveryPendingDiagnosticProbe().run(config)

        assert result.status == "fail"
        assert result.code == "recovery_pending_invalid"
    finally:
        connection.close()


def test_rebuild_capability_rejects_missing_or_mutated_production_binding(
    tmp_path: Path,
) -> None:
    config, connection, _store = _migrated_vault(tmp_path)
    try:
        production_path = config.vault_root / "global" / CONFIG_FILENAME
        production_path.write_bytes(b"{}")

        result = RebuildCapabilityDiagnosticProbe().run(config)

        assert result.status == "fail"
        assert result.code == "rebuild_capability_invalid"
    finally:
        connection.close()


def test_active_corruption_fails_real_gate_and_default_cli_composition(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config, connection, store = _migrated_vault(tmp_path)
    try:
        reference = _publish_one_active_artifact(connection, store)
        healthy = ActiveClosureDiagnosticProbe().run(config)
        assert healthy.status == "pass"
        assert healthy.observed_count == 1

        reference.path.write_bytes(b'{"lifecycle":"corrupt"}\n')
        corrupted = ActiveClosureDiagnosticProbe().run(config)
        assert corrupted.status == "fail"
        assert corrupted.code == "active_closure_invalid"

        exit_code = main(
            [
                "doctor",
                "--repo-root",
                str(config.repo_root),
                "--vault-root",
                str(config.vault_root),
                "--json",
            ]
        )
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert exit_code == 2
        assert payload["checks"]["active_closure"]["code"] == (
            "active_closure_invalid"
        )
        assert "active_closure_invalid" in captured.err
    finally:
        connection.close()
