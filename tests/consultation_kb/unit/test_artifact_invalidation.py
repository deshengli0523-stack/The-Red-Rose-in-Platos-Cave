from __future__ import annotations

from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.invalidation import (
    ArtifactInvalidationError,
    ArtifactInvalidator,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner


NOW = datetime(2026, 7, 18, 8, 0, tzinfo=timezone.utc)


def test_metadata_only_change_stales_all_dependent_outputs_and_is_idempotent(
    tmp_path: Path,
) -> None:
    connection = connect_database(tmp_path / "global.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    counter = iter(range(1, 1000))
    ids = IdFactory(FixedClock(NOW), lambda: next(counter))
    claim_id = ids.object_id("claim")
    artifacts = [
        (ids.object_id("artifact"), kind)
        for kind in ("wiki", "graph", "bm25", "vector")
    ]
    for artifact_id, kind in artifacts:
        connection.execute(
            """
            INSERT INTO artifact_versions(
                artifact_id, version, artifact_kind, source_catalog_version,
                metadata_sha256, manifest_id, state, created_at
            ) VALUES (?, 1, ?, 1, ?, NULL, 'CURRENT', ?)
            """,
            (artifact_id, kind, "1" * 64, "2026-07-18T08:00:00.000000Z"),
        )
        connection.execute(
            """
            INSERT INTO artifact_dependencies(
                upstream_type, upstream_id, upstream_version,
                downstream_artifact_id, downstream_artifact_version,
                dependency_kind
            ) VALUES ('claim', ?, 1, ?, 1, 'metadata')
            """,
            (claim_id, artifact_id),
        )
    invalidator = ArtifactInvalidator(
        connection, id_factory=ids, clock=FixedClock(NOW)
    )
    first = invalidator.mark_stale(
        upstream_type="claim",
        upstream_id=claim_id,
        catalog_version=2,
        reason="review_status_changed",
    )
    second = invalidator.mark_stale(
        upstream_type="claim",
        upstream_id=claim_id,
        catalog_version=2,
        reason="review_status_changed",
    )

    assert first == second
    assert first.required_outputs == frozenset({"wiki", "graph", "bm25", "vector"})
    assert connection.execute(
        "SELECT count(*) FROM artifact_versions WHERE state = 'STALE'"
    ).fetchone() == (4,)
    assert connection.execute("SELECT count(*) FROM rebuild_queue").fetchone() == (1,)
    connection.close()


def test_authority_tightening_and_tombstone_advance_live_filter_epochs(
    tmp_path: Path,
) -> None:
    connection = connect_database(tmp_path / "global.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    ids = IdFactory(FixedClock(NOW), lambda: 9)
    invalidator = ArtifactInvalidator(
        connection, id_factory=ids, clock=FixedClock(NOW)
    )
    invalidator.mark_stale(
        upstream_type="theory",
        upstream_id=ids.object_id("theory"),
        catalog_version=1,
        reason="authority_revoked",
        authority_tightening=True,
        tombstone=True,
    )
    assert connection.execute(
        "SELECT authorization_epoch, tombstone_epoch FROM knowledge_catalog_state"
    ).fetchone() == (1, 1)
    connection.close()


def test_existing_rebuild_queue_cannot_swallow_later_security_epoch_events(
    tmp_path: Path,
) -> None:
    connection = connect_database(tmp_path / "global.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    ids = IdFactory(FixedClock(NOW), lambda: 11)
    invalidator = ArtifactInvalidator(
        connection, id_factory=ids, clock=FixedClock(NOW)
    )
    theory_id = ids.object_id("theory")
    invalidator.mark_stale(
        upstream_type="theory",
        upstream_id=theory_id,
        catalog_version=7,
        reason="metadata_changed",
    )
    invalidator.mark_stale(
        upstream_type="theory",
        upstream_id=theory_id,
        catalog_version=7,
        reason="authority_revoked",
        authority_tightening=True,
        tombstone=True,
    )
    invalidator.mark_stale(
        upstream_type="theory",
        upstream_id=theory_id,
        catalog_version=7,
        reason="authority_revoked_retry",
        authority_tightening=True,
        tombstone=True,
    )

    assert connection.execute(
        "SELECT authorization_epoch, tombstone_epoch FROM knowledge_catalog_state"
    ).fetchone() == (1, 1)
    assert connection.execute("SELECT count(*) FROM rebuild_queue").fetchone() == (1,)
    assert connection.execute(
        "SELECT count(*) FROM security_invalidation_events"
    ).fetchone() == (2,)
    connection.close()


def test_two_writers_converge_on_one_queue_and_one_security_event(
    tmp_path: Path,
) -> None:
    database = tmp_path / "global.sqlite3"
    setup = connect_database(database, mode="writer")
    MigrationRunner.for_scope(setup, "global").apply()
    setup.close()
    barrier = Barrier(2)
    theory_id = IdFactory(FixedClock(NOW), lambda: 40).object_id("theory")

    def worker(seed: int) -> str:
        connection = connect_database(database, mode="writer")
        ids = IdFactory(FixedClock(NOW), lambda: seed)
        barrier.wait()
        try:
            return ArtifactInvalidator(
                connection,
                id_factory=ids,
                clock=FixedClock(NOW),
            ).mark_stale(
                upstream_type="theory",
                upstream_id=theory_id,
                catalog_version=9,
                reason="concurrent_revoke",
                authority_tightening=True,
            ).queue_id
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        queue_ids = tuple(pool.map(worker, (41, 42)))

    verify = connect_database(database, mode="reader")
    assert len(set(queue_ids)) == 1
    assert verify.execute("SELECT count(*) FROM rebuild_queue").fetchone() == (1,)
    assert verify.execute(
        "SELECT count(*) FROM security_invalidation_events"
    ).fetchone() == (1,)
    assert verify.execute(
        "SELECT authorization_epoch FROM knowledge_catalog_state"
    ).fetchone() == (1,)
    verify.close()


def test_dependency_writer_requires_exact_existing_versions_and_is_idempotent(
    tmp_path: Path,
) -> None:
    connection = connect_database(tmp_path / "global.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    upstream_id = IdFactory(FixedClock(NOW), lambda: 71).object_id("artifact")
    downstream_id = IdFactory(FixedClock(NOW), lambda: 72).object_id("artifact")
    for artifact_id, digest in (
        (upstream_id, "1" * 64),
        (downstream_id, "2" * 64),
    ):
        connection.execute(
            """
            INSERT INTO artifact_versions(
                artifact_id, version, artifact_kind, source_catalog_version,
                metadata_sha256, manifest_id, state, created_at
            ) VALUES (?, 1, 'graph', 1, ?, NULL, 'CURRENT', ?)
            """,
            (artifact_id, digest, "2026-07-18T08:00:00.000000Z"),
        )
    invalidator = ArtifactInvalidator(connection, clock=FixedClock(NOW))
    upstream = VersionRef(
        object_id=upstream_id, version=1, content_sha256="1" * 64
    )
    downstream = VersionRef(
        object_id=downstream_id, version=1, content_sha256="2" * 64
    )
    for _ in range(2):
        invalidator.register_dependency(
            upstream_type="artifact",
            upstream_ref=upstream,
            downstream_artifact_ref=downstream,
            dependency_kind="metadata",
        )
    assert connection.execute(
        "SELECT count(*) FROM artifact_dependencies"
    ).fetchone() == (1,)

    with pytest.raises(
        ArtifactInvalidationError, match="DEPENDENCY_UPSTREAM_VERSION_NOT_FOUND"
    ):
        invalidator.register_dependency(
            upstream_type="artifact",
            upstream_ref=upstream.model_copy(update={"version": 2}),
            downstream_artifact_ref=downstream,
            dependency_kind="metadata",
        )
    with pytest.raises(
        ArtifactInvalidationError, match="DEPENDENCY_UPSTREAM_HASH_MISMATCH"
    ):
        invalidator.register_dependency(
            upstream_type="artifact",
            upstream_ref=upstream.model_copy(update={"content_sha256": "3" * 64}),
            downstream_artifact_ref=downstream,
            dependency_kind="metadata",
        )
    connection.close()


def test_two_dependency_writers_converge_on_one_exact_edge(tmp_path: Path) -> None:
    database = tmp_path / "global.sqlite3"
    setup = connect_database(database, mode="writer")
    MigrationRunner.for_scope(setup, "global").apply()
    upstream_id = IdFactory(FixedClock(NOW), lambda: 81).object_id("artifact")
    downstream_id = IdFactory(FixedClock(NOW), lambda: 82).object_id("artifact")
    for artifact_id, digest in (
        (upstream_id, "4" * 64),
        (downstream_id, "5" * 64),
    ):
        setup.execute(
            """
            INSERT INTO artifact_versions(
                artifact_id, version, artifact_kind, source_catalog_version,
                metadata_sha256, manifest_id, state, created_at
            ) VALUES (?, 1, 'graph', 1, ?, NULL, 'CURRENT', ?)
            """,
            (artifact_id, digest, "2026-07-18T08:00:00.000000Z"),
        )
    setup.close()
    barrier = Barrier(2)
    upstream = VersionRef(
        object_id=upstream_id, version=1, content_sha256="4" * 64
    )
    downstream = VersionRef(
        object_id=downstream_id, version=1, content_sha256="5" * 64
    )

    def writer(_: int) -> None:
        connection = connect_database(database, mode="writer")
        try:
            barrier.wait()
            ArtifactInvalidator(connection).register_dependency(
                upstream_type="artifact",
                upstream_ref=upstream,
                downstream_artifact_ref=downstream,
                dependency_kind="authority",
            )
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        tuple(pool.map(writer, (1, 2)))

    verify = connect_database(database, mode="reader")
    assert verify.execute(
        "SELECT count(*) FROM artifact_dependencies"
    ).fetchone() == (1,)
    verify.close()
