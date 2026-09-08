from __future__ import annotations

from pathlib import Path

from consultation_kb.core.clock import FixedClock
from consultation_kb.lifecycle.rebuild import (
    RebuildCoordinator,
    RebuildRequest,
    SqliteCasRebuildArtifactStore,
    SqliteRebuildAuthoritySource,
)
from consultation_kb.lifecycle.rebuild_jobs import RebuildJobRepository
from consultation_kb.lifecycle.rebuild_registry import BuilderRegistry
from consultation_kb.operations.doctor_probes import lifecycle_diagnostic_probes
from tests.consultation_kb.golden.test_rebuild_01 import _verify_active
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
from tests.consultation_kb.unit.test_lifecycle_doctor_probe import _migrated_vault


def test_real_rebuild_integrity_and_production_doctor_end_to_end(
    tmp_path: Path,
) -> None:
    config, connection, content_store = _migrated_vault(tmp_path)
    registry = BuilderRegistry.production()
    _seed_approved_source_with_unreadable_draft(
        connection,
        content_store,
        _ids(60_000),
    )
    jobs = RebuildJobRepository(
        connection,
        database_scope="global",
        clock=FixedClock(NOW),
        id_factory=_ids(61_000),
    )
    authority = SqliteRebuildAuthoritySource(
        connection,
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        content_store=content_store,
    )
    artifact_store = SqliteCasRebuildArtifactStore(
        connection,
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        content_store=content_store,
        clock=FixedClock(NOW),
        id_factory=_ids(62_000),
    )
    descriptors = registry.plan(database_scope="global", purpose="all")
    coordinator = RebuildCoordinator(
        registry=registry,
        jobs=jobs,
        authority=authority,
        artifact_store=artifact_store,
        builders={
            descriptor.builder_id: _Builder(descriptor)
            for descriptor in descriptors
        },
    )
    request = RebuildRequest(
        database_scope="global",
        scope_sha256=SCOPE_HASH,
        purpose="all",
        policy_sha256=POLICY_HASH,
        model_descriptor_sha256=MODEL_HASH,
    )
    try:
        plan = coordinator.plan(request)
        queued = _start_approved(
            connection,
            coordinator,
            plan,
            idempotency_key="lifecycle-end-to-end",
        )
        completed = coordinator.run_next()

        assert completed is not None
        assert completed.job_id == queued.job_id
        assert completed.state == "succeeded"
        manifests = _verify_active(connection, content_store)
        assert len(manifests) == len(descriptors)

        results = {
            probe.name: probe.run(config)
            for probe in lifecycle_diagnostic_probes()
        }
        assert all(result.status == "pass" for result in results.values())
        assert results["recovery_pending"].observed_count == 0
        assert results["active_closure"].observed_count == len(descriptors)
        assert results["cleanup_queue"].observed_count == 0
        assert results["backup_queue"].observed_count == 0
        assert results["rebuild_capability"].observed_count == len(descriptors)
    finally:
        connection.close()
