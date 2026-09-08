from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.lifecycle.equivalence import EquivalenceItem, make_equivalence_report
from consultation_kb.lifecycle.rebuild import (
    RebuildCoordinator,
    RebuildRequest,
    SqliteCasRebuildArtifactStore,
    SqliteRebuildAuthoritySource,
)
from consultation_kb.lifecycle.rebuild_jobs import RebuildJobRepository
from consultation_kb.lifecycle.rebuild_registry import BuilderRegistry
from consultation_kb.models.common import VersionRef
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.integrity import (
    ActiveArtifact,
    ActiveIntegrityGate,
    ArtifactUnavailable,
    IntegrityStore,
)
from consultation_kb.storage.manifests import ArtifactManifest, ManifestRepository
from consultation_kb.storage.migrate import MigrationRunner, load_migrations
from consultation_kb.storage.tombstones import lineage_hash, target_hash
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.integration.test_rebuild_all import (
    MODEL_HASH,
    NOW,
    POLICY_HASH,
    SCOPE_HASH,
    _Builder,
    _ids,
    _seed_approved_source_with_unreadable_draft,
    _start_approved,
)


pytestmark = pytest.mark.acceptance_id("REBUILD-01")

TOMBSTONED_SOURCE = b"REBUILD_01_TOMBSTONED_SOURCE_CANARY"


def _seed_tombstoned_source(
    connection: sqlite3.Connection,
    content_store: ContentStore,
) -> None:
    ids = _ids(70_000)
    staged = content_store.stage_bytes(
        TOMBSTONED_SOURCE,
        purpose="source_import",
        manifest_id=ids.object_id("source_manifest"),
        media_type="text/plain",
    )
    stored = content_store.finalize(staged)
    connection.execute(
        "INSERT INTO sources("
        "source_id, logical_path, logical_path_key, document_type, "
        "current_version, created_at"
        ") VALUES ('source_tombstoned', 'removed.txt', 'removed.txt', "
        "'text', 1, ?)",
        ("2026-07-19T10:00:00.000000Z",),
    )
    connection.execute(
        "INSERT INTO source_versions("
        "source_id, version, content_sha256, content_object_ref, size_bytes, "
        "license, domain, language, sensitivity, source_grade, status, "
        "imported_at, metadata_json, metadata_sha256"
        ") VALUES ('source_tombstoned', 1, ?, ?, ?, 'owned', "
        "'consultation', 'zh', 'normal', 'C1', 'APPROVED', ?, '{}', ?)",
        (
            stored.content_sha256,
            f"sha256:{stored.content_sha256}",
            stored.size_bytes,
            "2026-07-19T10:00:00.000000Z",
            canonical_sha256({}),
        ),
    )
    connection.execute(
        "INSERT INTO tombstones("
        "tombstone_id, target_type, target_id_hash, source_lineage_hash, "
        "reason_code, created_at"
        ") VALUES (?, 'source', ?, ?, 'client_requested_deletion', ?)",
        (
            ids.object_id("tombstone"),
            target_hash("source", "source_tombstoned"),
            lineage_hash("source", "source_tombstoned"),
            "2026-07-19T10:00:00.000000Z",
        ),
    )
    connection.execute(
        "UPDATE deletion_authority_state SET tombstone_epoch = 1 "
        "WHERE singleton = 1"
    )


def _active_set(
    connection: sqlite3.Connection,
) -> tuple[int, tuple[ActiveArtifact, ...], tuple[ArtifactManifest, ...]]:
    epoch_row = connection.execute(
        "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
    ).fetchone()
    assert epoch_row is not None
    epoch = int(epoch_row[0])
    repository = ManifestRepository(connection)
    manifests = tuple(
        repository.get(str(row[1]))
        for row in connection.execute(
            "SELECT artifact_key, manifest_id FROM active_artifacts "
            "WHERE epoch = ? ORDER BY artifact_key",
            (epoch,),
        ).fetchall()
    )
    artifacts = tuple(
        ActiveArtifact(
            artifact_key=manifest.artifact_key,
            manifest_ref=VersionRef(
                object_id=manifest.manifest_id,
                version=manifest.source_version,
                content_sha256=manifest.manifest_sha256,
            ),
        )
        for manifest in manifests
    )
    return epoch, artifacts, manifests


def _verify_active(
    connection: sqlite3.Connection,
    content_store: ContentStore,
) -> tuple[ArtifactManifest, ...]:
    epoch, artifacts, manifests = _active_set(connection)
    source_versions = {manifest.source_version for manifest in manifests}
    assert len(source_versions) == 1
    authority = connection.execute(
        "SELECT catalog_version, authorization_epoch, tombstone_epoch "
        "FROM knowledge_catalog_state WHERE singleton = 1"
    ).fetchone()
    assert authority is not None
    ActiveIntegrityGate(
        IntegrityStore(
            scope="global",
            connection=connection,
            content_store=content_store,
        )
    ).verify(
        epoch=epoch,
        artifacts=artifacts,
        source_version=next(iter(source_versions)),
        authority_version=int(authority[0]),
        tombstone_epoch=int(authority[2]),
        authorization_epoch=int(authority[1]),
    )
    return manifests


def test_rebuild_01_restores_deleted_derivatives_from_exact_authority(
    tmp_path: Path,
) -> None:
    connection = connect_database(tmp_path / "global.sqlite3", mode="writer")
    MigrationRunner(connection, load_migrations("global")).apply()
    content_store = ContentStore(tmp_path / "global-cas")
    _seed_approved_source_with_unreadable_draft(
        connection,
        content_store,
        _ids(20_000),
    )
    _seed_tombstoned_source(connection, content_store)
    registry = BuilderRegistry.production()
    jobs = RebuildJobRepository(
        connection,
        database_scope="global",
        clock=FixedClock(NOW),
        id_factory=_ids(30_000),
    )
    authority = SqliteRebuildAuthoritySource(
        connection,
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        content_store=content_store,
    )
    store = SqliteCasRebuildArtifactStore(
        connection,
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        content_store=content_store,
        clock=FixedClock(NOW),
        id_factory=_ids(40_000),
    )
    descriptors = registry.plan(database_scope="global", purpose="all")
    builders = {
        descriptor.builder_id: _Builder(descriptor) for descriptor in descriptors
    }
    coordinator = RebuildCoordinator(
        registry=registry,
        jobs=jobs,
        authority=authority,
        artifact_store=store,
        builders=builders,
    )
    request = RebuildRequest(
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        purpose="all",
        policy_sha256=POLICY_HASH,
        model_descriptor_sha256=MODEL_HASH,
    )
    try:
        _start_approved(
            connection,
            coordinator,
            coordinator.plan(request),
            idempotency_key="rebuild-01-baseline",
        )
        baseline_job = coordinator.run_next()
        assert baseline_job is not None and baseline_job.state == "succeeded"
        baseline_manifests = _verify_active(connection, content_store)
        baseline_hashes = tuple(
            sorted(
                member.object_sha256
                for manifest in baseline_manifests
                for member in manifest.members
            )
        )

        for manifest in baseline_manifests:
            for member in manifest.members:
                content_store.reference(
                    content_sha256=member.object_sha256,
                    media_type=member.media_type,
                    size_bytes=member.size_bytes,
                ).path.unlink()
        with pytest.raises(ArtifactUnavailable, match="ARTIFACT_UNAVAILABLE"):
            _verify_active(connection, content_store)

        _start_approved(
            connection,
            coordinator,
            coordinator.plan(request),
            idempotency_key="rebuild-01-after-derived-loss",
        )
        rebuilt = coordinator.run_next()
        assert rebuilt is not None and rebuilt.state == "succeeded"
        rebuilt_manifests = _verify_active(connection, content_store)
        rebuilt_hashes = tuple(
            sorted(
                member.object_sha256
                for manifest in rebuilt_manifests
                for member in manifest.members
            )
        )
        assert rebuilt_hashes == baseline_hashes
        assert rebuilt.equivalence_report_sha256 is not None
        payload = json.loads(
            content_store.read_hash_verified(
                rebuilt.equivalence_report_sha256
            )
        )
        assert payload["domain"] == "consultation_kb.rebuild_equivalence.v1"
        report = make_equivalence_report(
            tuple(
                EquivalenceItem.model_validate_json(
                    json.dumps(item, separators=(",", ":"), sort_keys=True)
                )
                for item in payload["items"]
            )
        )
        assert report.report_sha256 == rebuilt.equivalence_report_sha256
        assert report.equivalent
        assert report.activation_eligible
        seen = b"\n".join(
            payload
            for builder in builders.values()
            for payload in builder.seen_payloads
        )
        assert TOMBSTONED_SOURCE not in seen
        assert base64.b64encode(TOMBSTONED_SOURCE) not in seen
    finally:
        connection.close()
