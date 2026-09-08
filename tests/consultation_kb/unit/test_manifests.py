from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from consultation_kb.core.ids import IdFactory
from consultation_kb.storage import MigrationRunner, connect_database
from consultation_kb.storage.manifests import (
    ConcurrentActivation,
    ManifestIntegrityError,
    ManifestMember,
    ManifestNotReady,
    ManifestRepository,
)


_NOW = "2026-07-16T08:00:00.000000Z"


def _database(path: Path):  # type: ignore[no-untyped-def]
    connection = connect_database(path, mode="writer")
    MigrationRunner.for_scope(connection, "client").apply()
    return connection


def _ids() -> tuple[str, str, str, str]:
    factory = IdFactory()
    return (
        factory.object_id("operation"),
        factory.object_id("approval_request"),
        factory.object_id("manifest"),
        factory.object_id("artifact"),
    )


def _insert_operation(
    connection,
    *,
    operation_id: str,
    approval_id: str,
    manifest_ids: tuple[str, ...],
    expected_epoch: int | None = None,
) -> None:  # type: ignore[no-untyped-def]
    required = tuple(sorted(manifest_ids))
    connection.execute(
        """
        INSERT INTO publication_operations(
            operation_id, purpose, authority_base_version, approval_request_id,
            descriptor_sha256, state, required_manifests_json, required_manifest_count,
            verified_manifest_count, expected_current_epoch, runtime_epoch,
            created_at, activated_at
        ) VALUES (?, 'test', 1, ?, ?, 'PREPARED', ?, ?, 0, ?, NULL, ?, NULL)
        """,
        (
            operation_id,
            approval_id,
            "a" * 64,
            json.dumps(required, separators=(",", ":")),
            len(required),
            expected_epoch,
            _NOW,
        ),
    )


def _member(object_id: str, *, version: int = 1) -> ManifestMember:
    payload = b"payload"
    return ManifestMember(
        ordinal=0,
        object_type="artifact",
        object_id=object_id,
        object_sha256=hashlib.sha256(payload).hexdigest(),
        source_version=version,
        media_type="application/octet-stream",
        size_bytes=len(payload),
        source_lineage_hashes=(),
    )


def test_prepared_manifest_is_not_an_active_query_result(tmp_path: Path) -> None:
    connection = _database(tmp_path / "client.sqlite3")
    operation, approval, manifest_id, object_id = _ids()
    _insert_operation(
        connection,
        operation_id=operation,
        approval_id=approval,
        manifest_ids=(manifest_id,),
    )
    repository = ManifestRepository(connection)
    prepared = repository.insert_prepared(
        manifest_id=manifest_id,
        operation_id=operation,
        artifact_key="profile",
        artifact_kind="profile",
        source_version=1,
        members=(_member(object_id),),
        created_at=_NOW,
    )
    assert prepared.state == "PREPARED"
    with pytest.raises(ManifestNotReady):
        repository.get_active("profile", epoch=1)
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "UPDATE artifact_manifests SET state = 'DRAFT' WHERE manifest_id = ?",
            (manifest_id,),
        )


def test_manifest_rejects_member_source_version_mismatch(tmp_path: Path) -> None:
    connection = _database(tmp_path / "client.sqlite3")
    operation, approval, manifest_id, object_id = _ids()
    _insert_operation(
        connection,
        operation_id=operation,
        approval_id=approval,
        manifest_ids=(manifest_id,),
    )
    with pytest.raises(ManifestIntegrityError):
        ManifestRepository(connection).insert_prepared(
            manifest_id=manifest_id,
            operation_id=operation,
            artifact_key="profile",
            artifact_kind="profile",
            source_version=2,
            members=(_member(object_id, version=1),),
            created_at=_NOW,
        )


def test_manifest_get_recomputes_hash_and_member_version(tmp_path: Path) -> None:
    connection = _database(tmp_path / "client.sqlite3")
    operation, approval, manifest_id, object_id = _ids()
    _insert_operation(
        connection,
        operation_id=operation,
        approval_id=approval,
        manifest_ids=(manifest_id,),
    )
    repository = ManifestRepository(connection)
    repository.insert_prepared(
        manifest_id=manifest_id,
        operation_id=operation,
        artifact_key="profile",
        artifact_kind="profile",
        source_version=1,
        members=(_member(object_id),),
        created_at=_NOW,
    )
    connection.execute(
        "UPDATE artifact_members SET source_version = '2' WHERE manifest_id = ?",
        (manifest_id,),
    )
    with pytest.raises(ManifestIntegrityError, match="^ARTIFACT_VERSION_MISMATCH$"):
        repository.get(manifest_id)


def test_activate_expected_uses_optimistic_epoch_check(tmp_path: Path) -> None:
    connection = _database(tmp_path / "client.sqlite3")
    operation, approval, manifest_id, object_id = _ids()
    _insert_operation(
        connection,
        operation_id=operation,
        approval_id=approval,
        manifest_ids=(manifest_id,),
    )
    repository = ManifestRepository(connection)
    repository.insert_prepared(
        manifest_id=manifest_id,
        operation_id=operation,
        artifact_key="profile",
        artifact_kind="profile",
        source_version=1,
        members=(_member(object_id),),
        created_at=_NOW,
    )
    repository.mark_verified(
        manifest_id,
        expected_source_version=1,
        verified_at=_NOW,
    )
    connection.execute(
        """
        UPDATE publication_operations
        SET state = 'VERIFIED', verified_manifest_count = 1
        WHERE operation_id = ?
        """,
        (operation,),
    )

    with pytest.raises(ConcurrentActivation):
        repository.activate_expected(
            operation,
            expected_current_epoch=99,
            activated_at=_NOW,
        )
    assert connection.execute("SELECT count(*) FROM runtime_epochs").fetchone()[0] == 0
    assert (
        connection.execute("SELECT count(*) FROM active_artifacts").fetchone()[0] == 0
    )

    epoch = repository.activate_expected(
        operation,
        expected_current_epoch=None,
        activated_at=_NOW,
    )
    assert epoch == 1
    assert repository.get_active("profile", epoch=epoch).manifest_id == manifest_id
    connection.execute(
        "UPDATE active_artifacts SET artifact_key = 'graph' WHERE epoch = ?",
        (epoch,),
    )
    with pytest.raises(ManifestIntegrityError):
        repository.get_active("graph", epoch=epoch)
