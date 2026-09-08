"""Low-layer case-index/catalog serialization contracts.

Case publication, knowledge revocation, lifecycle deletion, and rebuild all
need to bind the same body-free set of pending case-index ledgers.  Keeping
that contract beside the SQLite authority primitives avoids making those
packages depend on the high-level archive publication service.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Literal

from pydantic import field_validator, model_validator

from consultation_kb.models.common import (
    ObjectId,
    PositiveInt,
    Sha256Hex,
    StrictModel,
    VersionRef,
)


class CaseIndexSerializationError(RuntimeError):
    """A body-free case-index serialization invariant was violated."""

    def __init__(self, code: str = "CASE_INDEX_PUBLICATION_INVALID") -> None:
        self.code = code
        super().__init__(code)


# Backward-compatible public name used by the archive publication boundary.
CaseIndexPublicationError = CaseIndexSerializationError


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise CaseIndexSerializationError("CASE_INDEX_TIMESTAMP_INVALID")
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


class CaseIndexRebuildIdentity(StrictModel):
    """Body-free immutable identity bound by an authority-write approval."""

    manifest_ref: VersionRef
    operation_id: ObjectId
    approval_descriptor_sha256: Sha256Hex
    pattern_id: ObjectId
    pattern_version: PositiveInt
    queue_id: ObjectId
    target_catalog_version: PositiveInt


class CaseIndexRebuildIntent(StrictModel):
    """One pending ledger plus its mutable worker-claim state."""

    manifest_ref: VersionRef
    operation_id: ObjectId
    approval_descriptor_sha256: Sha256Hex
    pattern_id: ObjectId
    pattern_version: PositiveInt
    queue_id: ObjectId
    target_catalog_version: PositiveInt
    queue_state: Literal["PENDING", "CLAIMED"]

    def stable_identity(self) -> CaseIndexRebuildIdentity:
        return CaseIndexRebuildIdentity(
            manifest_ref=self.manifest_ref,
            operation_id=self.operation_id,
            approval_descriptor_sha256=self.approval_descriptor_sha256,
            pattern_id=self.pattern_id,
            pattern_version=self.pattern_version,
            queue_id=self.queue_id,
            target_catalog_version=self.target_catalog_version,
        )


class CaseIndexRebuildSnapshot(StrictModel):
    """Canonical full pending set; PENDING/CLAIMED changes do not change it."""

    schema_version: Literal["case_index_rebuild_snapshot.v1"] = (
        "case_index_rebuild_snapshot.v1"
    )
    target_catalog_version: PositiveInt
    identities: tuple[CaseIndexRebuildIdentity, ...]

    @field_validator("identities")
    @classmethod
    def _canonical_identities(
        cls,
        value: tuple[CaseIndexRebuildIdentity, ...],
    ) -> tuple[CaseIndexRebuildIdentity, ...]:
        keys = tuple(
            (
                item.manifest_ref.object_id,
                item.manifest_ref.version,
                item.manifest_ref.content_sha256,
                item.operation_id,
                item.approval_descriptor_sha256,
                item.pattern_id,
                item.pattern_version,
                item.queue_id,
                item.target_catalog_version,
            )
            for item in value
        )
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("case index rebuild snapshot is not canonical")
        return value

    @model_validator(mode="after")
    def _one_target(self) -> CaseIndexRebuildSnapshot:
        if any(
            item.target_catalog_version != self.target_catalog_version
            for item in self.identities
        ):
            raise ValueError("case index rebuild snapshot target mismatch")
        return self

    @property
    def identity_sha256(self) -> str:
        return _canonical_sha256(self.model_dump(mode="json"))


def snapshot_pending_case_index_invalidations(
    connection: sqlite3.Connection,
) -> CaseIndexRebuildSnapshot:
    """Snapshot every body-free pending identity for a governed write plan."""

    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("case index invalidation snapshot requires SQLite")
    state = connection.execute(
        "SELECT catalog_version FROM knowledge_catalog_state WHERE singleton = 1"
    ).fetchone()
    if state is None or type(state[0]) is not int or int(state[0]) < 0:
        raise CaseIndexSerializationError("CASE_INDEX_CATALOG_STATE_MISSING")
    target = int(state[0]) + 1
    raw_count = connection.execute(
        "SELECT COUNT(*) FROM rebuild_queue AS queue "
        "JOIN case_patterns AS pattern "
        "  ON pattern.manifest_id = queue.upstream_id "
        "WHERE queue.upstream_type = 'case_index' "
        "AND queue.state IN ('PENDING', 'CLAIMED') "
        "AND pattern.state = 'PREPARED'"
    ).fetchone()
    rows = connection.execute(
        "SELECT manifest.manifest_id, manifest.source_version, "
        "manifest.manifest_sha256, operation.operation_id, "
        "operation.descriptor_sha256, pattern.pattern_id, pattern.version, "
        "queue.queue_id, queue.catalog_version "
        "FROM rebuild_queue AS queue "
        "JOIN case_patterns AS pattern "
        "  ON pattern.manifest_id = queue.upstream_id "
        "JOIN artifact_manifests AS manifest "
        "  ON manifest.manifest_id = queue.upstream_id "
        "JOIN publication_operations AS operation "
        "  ON operation.operation_id = manifest.operation_id "
        "LEFT JOIN case_index_rebuild_invalidations AS invalidation "
        "  ON invalidation.queue_id = queue.queue_id "
        "WHERE queue.upstream_type = 'case_index' "
        "AND queue.state IN ('PENDING', 'CLAIMED') "
        "AND queue.catalog_version = ? "
        "AND pattern.state = 'PREPARED' "
        "AND manifest.artifact_kind = 'case_index' "
        "AND manifest.state = 'VERIFIED' AND manifest.verified = 1 "
        "AND manifest.source_version = queue.catalog_version "
        "AND operation.purpose = 'case_publish' "
        "AND operation.state = 'VERIFIED' "
        "AND operation.runtime_epoch IS NULL "
        "AND operation.authority_base_version = queue.catalog_version "
        "AND invalidation.queue_id IS NULL "
        "ORDER BY manifest.manifest_id",
        (target,),
    ).fetchall()
    if (
        raw_count is None
        or type(raw_count[0]) is not int
        or int(raw_count[0]) != len(rows)
    ):
        raise CaseIndexSerializationError("CASE_INDEX_INVALIDATION_SET_INVALID")
    identities = tuple(
        CaseIndexRebuildIdentity(
            manifest_ref=VersionRef(
                object_id=str(row[0]),
                version=int(str(row[1])),
                content_sha256=str(row[2]),
            ),
            operation_id=str(row[3]),
            approval_descriptor_sha256=str(row[4]),
            pattern_id=str(row[5]),
            pattern_version=int(str(row[6])),
            queue_id=str(row[7]),
            target_catalog_version=int(str(row[8])),
        )
        for row in rows
    )
    return CaseIndexRebuildSnapshot(
        target_catalog_version=target,
        identities=identities,
    )


def invalidate_pending_case_indexes_in_transaction(
    connection: sqlite3.Connection,
    *,
    expected_snapshot: CaseIndexRebuildSnapshot,
    authority_request_id: str,
    reason_code: str,
    next_authorization_epoch: int,
    next_tombstone_epoch: int,
    invalidated_at: datetime,
) -> tuple[str, ...]:
    """Invalidate exactly a plan-bound pending set in the caller transaction."""

    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("case index invalidation requires SQLite")
    if not connection.in_transaction:
        raise CaseIndexSerializationError(
            "CASE_INDEX_INVALIDATION_TRANSACTION_REQUIRED"
        )
    if type(expected_snapshot) is not CaseIndexRebuildSnapshot:
        raise TypeError("case index invalidation snapshot required")
    if (
        type(authority_request_id) is not str
        or not authority_request_id
        or type(reason_code) is not str
        or not 0 < len(reason_code) <= 64
        or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789_"
            for character in reason_code
        )
        or type(next_authorization_epoch) is not int
        or type(next_tombstone_epoch) is not int
    ):
        raise CaseIndexSerializationError(
            "CASE_INDEX_INVALIDATION_ARGUMENT_INVALID"
        )
    current = snapshot_pending_case_index_invalidations(connection)
    if current != expected_snapshot:
        raise CaseIndexSerializationError("CASE_INDEX_INVALIDATION_SET_CHANGED")
    catalog = connection.execute(
        "SELECT catalog_version, authorization_epoch, tombstone_epoch "
        "FROM knowledge_catalog_state WHERE singleton = 1"
    ).fetchone()
    if catalog is None or tuple(type(value) for value in catalog) != (int, int, int):
        raise CaseIndexSerializationError("CASE_INDEX_CATALOG_STATE_MISSING")
    base_catalog, authorization_epoch, tombstone_epoch = map(int, catalog)
    if (
        expected_snapshot.target_catalog_version != base_catalog + 1
        or next_authorization_epoch < authorization_epoch
        or next_tombstone_epoch < tombstone_epoch
        or (
            next_authorization_epoch == authorization_epoch
            and next_tombstone_epoch == tombstone_epoch
        )
    ):
        raise CaseIndexSerializationError("CASE_INDEX_INVALIDATION_EPOCH_INVALID")
    invalidated_at_text = _utc(invalidated_at)
    set_sha256 = expected_snapshot.identity_sha256
    queue_ids: list[str] = []
    for identity in expected_snapshot.identities:
        inserted = connection.execute(
            "INSERT INTO case_index_rebuild_invalidations("
            "queue_id, authority_request_id, invalidation_set_sha256, "
            "reason_code, base_catalog_version, target_catalog_version, "
            "prior_authorization_epoch, authorization_epoch, "
            "prior_tombstone_epoch, tombstone_epoch, invalidated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                identity.queue_id,
                authority_request_id,
                set_sha256,
                reason_code,
                base_catalog,
                identity.target_catalog_version,
                authorization_epoch,
                next_authorization_epoch,
                tombstone_epoch,
                next_tombstone_epoch,
                invalidated_at_text,
            ),
        ).rowcount
        revoked = connection.execute(
            "UPDATE case_patterns SET state = 'REVOKED' "
            "WHERE pattern_id = ? AND version = ? AND manifest_id = ? "
            "AND state = 'PREPARED'",
            (
                identity.pattern_id,
                identity.pattern_version,
                identity.manifest_ref.object_id,
            ),
        ).rowcount
        if inserted != 1 or revoked != 1:
            raise CaseIndexSerializationError("CASE_INDEX_INVALIDATION_SET_CHANGED")
        queue_ids.append(identity.queue_id)
    remaining = snapshot_pending_case_index_invalidations(connection)
    if remaining.identities:
        raise CaseIndexSerializationError("CASE_INDEX_INVALIDATION_SET_CHANGED")
    return tuple(queue_ids)


__all__ = [
    "CaseIndexPublicationError",
    "CaseIndexRebuildIdentity",
    "CaseIndexRebuildIntent",
    "CaseIndexRebuildSnapshot",
    "CaseIndexSerializationError",
    "invalidate_pending_case_indexes_in_transaction",
    "snapshot_pending_case_index_invalidations",
]
