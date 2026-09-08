from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.storage.tombstones import (
    ObjectIdentity,
    ObjectTombstoned,
    TombstoneRepository,
    VisibilityGuard,
    lineage_hash,
    target_hash,
)


def _open_database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, isolation_level=None)
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS tombstones(
            tombstone_id TEXT PRIMARY KEY,
            target_type TEXT NOT NULL,
            target_id_hash TEXT NOT NULL,
            source_lineage_hash TEXT NOT NULL DEFAULT '',
            reason_code TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(target_type, target_id_hash, source_lineage_hash)
        )
        """
    )
    return connection


def test_tombstone_immediately_blocks_an_active_object_and_survives_reopen(
    tmp_path: Path,
    fixed_now,
) -> None:
    database = tmp_path / "scope.sqlite3"
    target = ObjectIdentity("claim", "claim-private-value")
    connection = _open_database(database)
    repository = TombstoneRepository(connection, clock=FixedClock(fixed_now))
    guard = VisibilityGuard(repository)
    guard.assert_visible(target, source_lineage_hashes=())
    record = repository.add(target, reason_code="deletion_requested")
    assert record.target_id_hash == target_hash("claim", "claim-private-value")

    with pytest.raises(ObjectTombstoned) as denied:
        guard.assert_visible(target, source_lineage_hashes=())
    assert "claim-private-value" not in str(denied.value)
    connection.close()

    reopened = _open_database(database)
    with pytest.raises(ObjectTombstoned):
        VisibilityGuard(TombstoneRepository(reopened)).assert_visible(
            target,
            source_lineage_hashes=(),
        )
    reopened.close()


def test_visibility_guard_checks_transitive_source_lineage(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection = _open_database(tmp_path / "scope.sqlite3")
    repository = TombstoneRepository(connection, clock=FixedClock(fixed_now))
    source = ObjectIdentity("source", "source-secret-id")
    requested = ObjectIdentity("artifact", "derived-object-id")
    repository.add(source, reason_code="authorization_revoked")

    with pytest.raises(ObjectTombstoned) as denied:
        VisibilityGuard(repository).assert_visible(
            requested,
            source_lineage_hashes=(lineage_hash(source.object_type, source.object_id),),
        )
    message = str(denied.value)
    assert "derived-object-id" not in message
    assert "source-secret-id" not in message
    assert denied.value.object_type == "artifact"
    assert denied.value.object_hash == target_hash("artifact", "derived-object-id")


def test_tombstone_table_never_stores_plain_target_or_source_ids(
    tmp_path: Path,
    fixed_now,
) -> None:
    connection = _open_database(tmp_path / "scope.sqlite3")
    repository = TombstoneRepository(connection, clock=FixedClock(fixed_now))
    repository.add(
        ObjectIdentity("case", "private-case-identifier"),
        reason_code="consent_revoked",
        source_lineage=ObjectIdentity("source", "private-source-identifier"),
    )

    serialized_rows = repr(connection.execute("SELECT * FROM tombstones").fetchall())
    assert "private-case-identifier" not in serialized_rows
    assert "private-source-identifier" not in serialized_rows

    with pytest.raises(ObjectTombstoned):
        VisibilityGuard(repository).assert_visible(
            ObjectIdentity("artifact", "another-derived-object"),
            source_lineage_hashes=(
                lineage_hash("source", "private-source-identifier"),
            ),
        )


def test_repeated_tombstone_is_idempotent(tmp_path: Path, fixed_now) -> None:
    connection = _open_database(tmp_path / "scope.sqlite3")
    repository = TombstoneRepository(connection, clock=FixedClock(fixed_now))
    target = ObjectIdentity("claim", "same-claim")

    first = repository.add(target, reason_code="deletion_requested")
    second = repository.add(target, reason_code="deletion_requested")

    assert second == first
    assert connection.execute("SELECT count(*) FROM tombstones").fetchone()[0] == 1
