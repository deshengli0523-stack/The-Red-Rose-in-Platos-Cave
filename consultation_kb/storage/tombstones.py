"""Persistent, hash-only tombstones and the mandatory visibility guard."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.storage.connection import transaction


_SAFE_KEY_RE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_CLIENT_ID_RE = re.compile(r"client_[a-z0-9]{12}")
_OBJECT_ID_RE = re.compile(
    r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*_"
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class TombstoneError(RuntimeError):
    """Base class for fixed-code tombstone failures."""


class InvalidTombstoneTarget(TombstoneError):
    def __init__(self) -> None:
        super().__init__("TOMBSTONE_TARGET_INVALID")


class ObjectTombstoned(TombstoneError):
    """Safe denial containing only the requested type and irreversible hash."""

    def __init__(self, *, object_type: str, object_hash: str) -> None:
        self.object_type = object_type
        self.object_hash = object_hash
        super().__init__(f"OBJECT_TOMBSTONED:{object_type}:{object_hash}")


def _safe_key(value: str) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 64
        or _SAFE_KEY_RE.fullmatch(value) is None
        or _CLIENT_ID_RE.search(value) is not None
    ):
        raise InvalidTombstoneTarget
    return value


def _opaque_id(value: str) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 512
        or _CONTROL_RE.search(value) is not None
    ):
        raise InvalidTombstoneTarget
    return value


def _object_id(value: str) -> str:
    if (
        type(value) is not str
        or not 38 <= len(value) <= 101
        or _OBJECT_ID_RE.fullmatch(value) is None
        or _CLIENT_ID_RE.search(value[:-37]) is not None
    ):
        raise InvalidTombstoneTarget
    return value


def _utc_text(value: datetime) -> str:
    if (
        value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError("TOMBSTONE_CLOCK_NOT_UTC")
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _identity_hash(domain: bytes, object_type: str, object_id: str) -> str:
    type_value = _safe_key(object_type)
    id_value = _opaque_id(object_id)
    return hashlib.sha256(
        domain
        + b"\0"
        + type_value.encode("ascii")
        + b"\0"
        + id_value.encode("utf-8", errors="strict")
    ).hexdigest()


def target_hash(object_type: str, object_id: str) -> str:
    """Return the irreversible lookup key stored for a direct target."""

    return _identity_hash(
        b"consultation-kb-tombstone-target-v1", object_type, object_id
    )


def lineage_hash(object_type: str, object_id: str) -> str:
    """Return the irreversible lookup key stored for a lineage source."""

    return _identity_hash(
        b"consultation-kb-tombstone-lineage-v1", object_type, object_id
    )


def _lineage_digest(value: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise InvalidTombstoneTarget
    return value


@dataclass(frozen=True, slots=True)
class ObjectIdentity:
    object_type: str
    object_id: str

    def __post_init__(self) -> None:
        _safe_key(self.object_type)
        _opaque_id(self.object_id)


@dataclass(frozen=True, slots=True)
class TombstoneRecord:
    tombstone_id: str
    target_type: str
    target_id_hash: str
    source_lineage_hash: str
    reason_code: str
    created_at: str


class TombstoneRepository:
    """Hash-only tombstone persistence for one authority database."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        clock: Clock | None = None,
        id_factory: IdFactory | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SQLITE_CONNECTION_REQUIRED")
        self._connection = connection
        self._clock = clock if clock is not None else SystemClock()
        self._ids = (
            id_factory if id_factory is not None else IdFactory(clock=self._clock)
        )

    def add(
        self,
        target: ObjectIdentity,
        *,
        reason_code: str,
        source_lineage: ObjectIdentity | None = None,
        tombstone_id: str | None = None,
    ) -> TombstoneRecord:
        if type(target) is not ObjectIdentity:
            raise TypeError("OBJECT_IDENTITY_REQUIRED")
        if source_lineage is not None and type(source_lineage) is not ObjectIdentity:
            raise TypeError("OBJECT_IDENTITY_REQUIRED")
        reason = _safe_key(reason_code)
        target_digest = target_hash(target.object_type, target.object_id)
        # A direct tombstone is also a lineage root.  Persisting its self-lineage
        # digest lets immutable manifests carry hash-only provenance and still
        # fail closed without retaining the source's raw identifier.
        lineage_source = target if source_lineage is None else source_lineage
        lineage_digest = lineage_hash(
            lineage_source.object_type,
            lineage_source.object_id,
        )
        identifier = (
            self._ids.object_id("tombstone")
            if tombstone_id is None
            else _object_id(tombstone_id)
        )
        created_at = _utc_text(self._clock.now())
        with transaction(self._connection):
            self._connection.execute(
                """
                INSERT OR IGNORE INTO tombstones(
                    tombstone_id,
                    target_type,
                    target_id_hash,
                    source_lineage_hash,
                    reason_code,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    identifier,
                    target.object_type,
                    target_digest,
                    lineage_digest,
                    reason,
                    created_at,
                ),
            )
            row = self._connection.execute(
                """
                SELECT tombstone_id, target_type, target_id_hash,
                       source_lineage_hash, reason_code, created_at
                FROM tombstones
                WHERE target_type = ? AND target_id_hash = ?
                  AND source_lineage_hash = ?
                """,
                (target.object_type, target_digest, lineage_digest),
            ).fetchone()
        if row is None:
            raise TombstoneError("TOMBSTONE_WRITE_FAILED")
        return TombstoneRecord(
            tombstone_id=str(row[0]),
            target_type=str(row[1]),
            target_id_hash=str(row[2]),
            source_lineage_hash=str(row[3]),
            reason_code=str(row[4]),
            created_at=str(row[5]),
        )

    def has_direct(self, target: ObjectIdentity) -> bool:
        if type(target) is not ObjectIdentity:
            raise TypeError("OBJECT_IDENTITY_REQUIRED")
        digest = target_hash(target.object_type, target.object_id)
        return (
            self._connection.execute(
                """
                SELECT 1 FROM tombstones
                WHERE target_type = ? AND target_id_hash = ?
                LIMIT 1
                """,
                (target.object_type, digest),
            ).fetchone()
            is not None
        )

    def has_lineage(self, source: ObjectIdentity) -> bool:
        if type(source) is not ObjectIdentity:
            raise TypeError("OBJECT_IDENTITY_REQUIRED")
        direct_digest = target_hash(source.object_type, source.object_id)
        lineage_digest = lineage_hash(source.object_type, source.object_id)
        return (
            self._connection.execute(
                """
                SELECT 1 FROM tombstones
                WHERE (target_type = ? AND target_id_hash = ?)
                   OR source_lineage_hash = ?
                LIMIT 1
                """,
                (source.object_type, direct_digest, lineage_digest),
            ).fetchone()
            is not None
        )

    def has_lineage_hash(self, source_lineage_hash: str) -> bool:
        """Look up an immutable manifest's hash-only lineage proof."""

        digest = _lineage_digest(source_lineage_hash)
        return (
            self._connection.execute(
                """
                SELECT 1 FROM tombstones
                WHERE source_lineage_hash = ?
                LIMIT 1
                """,
                (digest,),
            ).fetchone()
            is not None
        )


class VisibilityGuard:
    """Fail-closed tombstone gate for direct objects and their lineage."""

    def __init__(self, repository: TombstoneRepository) -> None:
        if type(repository) is not TombstoneRepository:
            raise TypeError("TOMBSTONE_REPOSITORY_REQUIRED")
        self._repository = repository

    def assert_visible(
        self,
        target: ObjectIdentity,
        *,
        source_lineage_hashes: Iterable[str],
    ) -> None:
        if type(target) is not ObjectIdentity:
            raise TypeError("OBJECT_IDENTITY_REQUIRED")
        requested_hash = target_hash(target.object_type, target.object_id)
        denied = self._repository.has_direct(target)
        if not denied:
            lineage = tuple(_lineage_digest(value) for value in source_lineage_hashes)
            if lineage != tuple(sorted(set(lineage))):
                raise InvalidTombstoneTarget
            for digest in lineage:
                if self._repository.has_lineage_hash(digest):
                    denied = True
                    break
        if denied:
            raise ObjectTombstoned(
                object_type=target.object_type,
                object_hash=requested_hash,
            )
