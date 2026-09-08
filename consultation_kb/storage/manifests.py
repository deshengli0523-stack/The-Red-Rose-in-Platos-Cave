"""Persistence primitives for immutable artifact manifests and active epochs."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Literal, cast

from consultation_kb.storage.connection import transaction
from consultation_kb.storage.tombstones import ObjectIdentity, TombstoneRepository


_SAFE_KEY_RE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z")
_CLIENT_ID_RE = re.compile(r"client_[a-z0-9]{12}")
_OBJECT_ID_RE = re.compile(
    r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*_"
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_MEDIA_TYPE_RE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*\Z")

ManifestState = Literal["PREPARED", "VERIFIED", "ACTIVE"]


class ManifestError(RuntimeError):
    """Base class for fixed-code manifest failures."""


class ManifestIntegrityError(ManifestError):
    def __init__(self) -> None:
        super().__init__("ARTIFACT_VERSION_MISMATCH")


class ManifestNotFound(ManifestError):
    def __init__(self) -> None:
        super().__init__("MANIFEST_NOT_FOUND")


class ManifestConflict(ManifestError):
    def __init__(self) -> None:
        super().__init__("MANIFEST_CONFLICT")


class ManifestNotReady(ManifestError):
    def __init__(self) -> None:
        super().__init__("MANIFEST_NOT_READY")


class ConcurrentActivation(ManifestError):
    def __init__(self) -> None:
        super().__init__("ACTIVE_EPOCH_CONFLICT")


def _object_id(value: str) -> str:
    if (
        type(value) is not str
        or not 38 <= len(value) <= 101
        or _OBJECT_ID_RE.fullmatch(value) is None
        or _CLIENT_ID_RE.search(value[:-37]) is not None
    ):
        raise ManifestIntegrityError
    return value


def _safe_key(value: str) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 64
        or _SAFE_KEY_RE.fullmatch(value) is None
        or _CLIENT_ID_RE.search(value) is not None
    ):
        raise ManifestIntegrityError
    return value


def _object_type(value: str, object_id: str) -> str:
    object_type = _safe_key(value)
    identifier = _object_id(object_id)
    if identifier[:-37] != object_type:
        raise ManifestIntegrityError
    return object_type


def _positive(value: int) -> int:
    if type(value) is not int or value <= 0:
        raise ManifestIntegrityError
    return value


def _nonnegative(value: int) -> int:
    if type(value) is not int or value < 0:
        raise ManifestIntegrityError
    return value


def _sha256(value: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ManifestIntegrityError
    return value


def _canonical_hashes(values: Iterable[str]) -> tuple[str, ...]:
    hashes = tuple(_sha256(value) for value in values)
    if hashes != tuple(sorted(set(hashes))):
        raise ManifestIntegrityError
    return hashes


def _media_type(value: str) -> str:
    if (
        type(value) is not str
        or not 3 <= len(value) <= 127
        or _MEDIA_TYPE_RE.fullmatch(value) is None
    ):
        raise ManifestIntegrityError
    return value


def _timestamp(value: str | None, *, optional: bool = False) -> str | None:
    if value is None:
        if optional:
            return None
        raise ManifestIntegrityError
    if type(value) is not str or not value.endswith("Z"):
        raise ManifestIntegrityError
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ManifestIntegrityError from exc
    if parsed.utcoffset() != timedelta(0):
        raise ManifestIntegrityError
    return value


def _stored_positive(value: object) -> int:
    if type(value) is int:
        return _positive(value)
    if type(value) is str and value and value.isascii() and value.isdecimal():
        parsed = int(value)
        if value == str(parsed):
            return _positive(parsed)
    raise ManifestIntegrityError


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


@dataclass(frozen=True, slots=True)
class ManifestMember:
    ordinal: int
    object_type: str
    object_id: str
    object_sha256: str
    source_version: int
    media_type: str
    size_bytes: int
    source_lineage_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        _nonnegative(self.ordinal)
        _object_type(self.object_type, self.object_id)
        _object_id(self.object_id)
        _sha256(self.object_sha256)
        _positive(self.source_version)
        _media_type(self.media_type)
        _nonnegative(self.size_bytes)
        if type(self.source_lineage_hashes) is not tuple:
            raise ManifestIntegrityError
        _canonical_hashes(self.source_lineage_hashes)


@dataclass(frozen=True, slots=True)
class ArtifactManifest:
    manifest_id: str
    operation_id: str
    artifact_key: str
    artifact_kind: str
    source_version: int
    manifest_sha256: str
    state: ManifestState
    verified: bool
    created_at: str
    verified_at: str | None
    members: tuple[ManifestMember, ...]

    def __post_init__(self) -> None:
        _object_id(self.manifest_id)
        _object_id(self.operation_id)
        _safe_key(self.artifact_key)
        _safe_key(self.artifact_kind)
        _positive(self.source_version)
        _sha256(self.manifest_sha256)
        if self.state not in {"PREPARED", "VERIFIED", "ACTIVE"}:
            raise ManifestIntegrityError
        if type(self.verified) is not bool:
            raise ManifestIntegrityError
        if self.state == "PREPARED" and self.verified:
            raise ManifestIntegrityError
        if self.state in {"VERIFIED", "ACTIVE"} and not self.verified:
            raise ManifestIntegrityError
        _timestamp(self.created_at)
        _timestamp(self.verified_at, optional=True)
        if self.state == "PREPARED" and self.verified_at is not None:
            raise ManifestIntegrityError
        if self.state in {"VERIFIED", "ACTIVE"} and self.verified_at is None:
            raise ManifestIntegrityError
        if not self.members:
            raise ManifestIntegrityError
        if tuple(member.ordinal for member in self.members) != tuple(
            range(len(self.members))
        ):
            raise ManifestIntegrityError
        if any(member.source_version != self.source_version for member in self.members):
            raise ManifestIntegrityError


def manifest_sha256(
    *,
    manifest_id: str,
    operation_id: str,
    artifact_key: str,
    artifact_kind: str,
    source_version: int,
    members: Iterable[ManifestMember],
) -> str:
    """Hash the path-free immutable manifest body."""

    body_members = tuple(members)
    payload = {
        "artifact_key": _safe_key(artifact_key),
        "artifact_kind": _safe_key(artifact_kind),
        "manifest_id": _object_id(manifest_id),
        "members": [
            {
                "media_type": member.media_type,
                "object_type": member.object_type,
                "object_id": member.object_id,
                "object_sha256": member.object_sha256,
                "ordinal": member.ordinal,
                "size_bytes": member.size_bytes,
                "source_lineage_hashes": list(member.source_lineage_hashes),
                "source_version": member.source_version,
            }
            for member in body_members
        ],
        "operation_id": _object_id(operation_id),
        "source_version": _positive(source_version),
    }
    return hashlib.sha256((_canonical_json(payload) + "\n").encode("ascii")).hexdigest()


class ManifestRepository:
    """Low-level manifest persistence; orchestration belongs to PublishCoordinator."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SQLITE_CONNECTION_REQUIRED")
        self._connection = connection

    def _write_context(self) -> AbstractContextManager[sqlite3.Connection]:
        if self._connection.in_transaction:
            return nullcontext(self._connection)
        return transaction(self._connection)

    def insert_prepared(
        self,
        *,
        manifest_id: str,
        operation_id: str,
        artifact_key: str,
        artifact_kind: str,
        source_version: int,
        members: Iterable[ManifestMember],
        created_at: str,
    ) -> ArtifactManifest:
        identifier = _object_id(manifest_id)
        operation = _object_id(operation_id)
        key = _safe_key(artifact_key)
        kind = _safe_key(artifact_kind)
        version = _positive(source_version)
        member_tuple = tuple(members)
        if not member_tuple:
            raise ManifestIntegrityError
        if tuple(member.ordinal for member in member_tuple) != tuple(
            range(len(member_tuple))
        ) or any(member.source_version != version for member in member_tuple):
            raise ManifestIntegrityError
        digest = manifest_sha256(
            manifest_id=identifier,
            operation_id=operation,
            artifact_key=key,
            artifact_kind=kind,
            source_version=version,
            members=member_tuple,
        )
        try:
            with self._write_context():
                operation_row = self._connection.execute(
                    """
                    SELECT state, required_manifests_json
                    FROM publication_operations WHERE operation_id = ?
                    """,
                    (operation,),
                ).fetchone()
                if operation_row is None or str(operation_row[0]) != "PREPARED":
                    raise ManifestNotReady
                try:
                    required = json.loads(str(operation_row[1]))
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ManifestIntegrityError from exc
                if (
                    type(required) is not list
                    or identifier not in required
                    or any(type(value) is not str for value in required)
                    or tuple(sorted(set(required))) != tuple(required)
                ):
                    raise ManifestIntegrityError
                self._connection.execute(
                    """
                    INSERT INTO artifact_manifests(
                        manifest_id, operation_id, artifact_key, artifact_kind,
                        source_version, manifest_sha256, state, verified,
                        created_at, verified_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'PREPARED', 0, ?, NULL)
                    """,
                    (identifier, operation, key, kind, version, digest, created_at),
                )
                self._connection.executemany(
                    """
                    INSERT INTO artifact_members(
                        manifest_id, ordinal, object_type, object_id, object_sha256,
                        source_version, media_type, size_bytes, source_lineage_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            identifier,
                            member.ordinal,
                            member.object_type,
                            member.object_id,
                            member.object_sha256,
                            member.source_version,
                            member.media_type,
                            member.size_bytes,
                            _canonical_json(member.source_lineage_hashes),
                        )
                        for member in member_tuple
                    ],
                )
        except sqlite3.IntegrityError as exc:
            raise ManifestConflict from exc
        return self.get(identifier)

    def get(self, manifest_id: str) -> ArtifactManifest:
        identifier = _object_id(manifest_id)
        row = self._connection.execute(
            """
            SELECT manifest_id, operation_id, artifact_key, artifact_kind,
                   source_version, manifest_sha256, state, verified,
                   created_at, verified_at
            FROM artifact_manifests
            WHERE manifest_id = ?
            """,
            (identifier,),
        ).fetchone()
        if row is None:
            raise ManifestNotFound
        member_rows = self._connection.execute(
            """
            SELECT ordinal, object_type, object_id, object_sha256,
                   source_version, media_type, size_bytes, source_lineage_json
            FROM artifact_members
            WHERE manifest_id = ?
            ORDER BY ordinal
            """,
            (identifier,),
        ).fetchall()
        try:
            parsed_members: list[ManifestMember] = []
            for member in member_rows:
                decoded_lineage = json.loads(str(member[7]))
                if type(decoded_lineage) is not list or any(
                    type(value) is not str for value in decoded_lineage
                ):
                    raise ManifestIntegrityError
                lineage_hashes = _canonical_hashes(decoded_lineage)
                if str(member[7]) != _canonical_json(lineage_hashes):
                    raise ManifestIntegrityError
                parsed_members.append(
                    ManifestMember(
                        ordinal=int(member[0]),
                        object_type=str(member[1]),
                        object_id=str(member[2]),
                        object_sha256=str(member[3]),
                        source_version=_stored_positive(member[4]),
                        media_type=str(member[5]),
                        size_bytes=int(member[6]),
                        source_lineage_hashes=lineage_hashes,
                    )
                )
            members = tuple(parsed_members)
            verified_value = int(row[7])
            if verified_value not in {0, 1}:
                raise ManifestIntegrityError
            manifest = ArtifactManifest(
                manifest_id=str(row[0]),
                operation_id=str(row[1]),
                artifact_key=str(row[2]),
                artifact_kind=str(row[3]),
                source_version=_stored_positive(row[4]),
                manifest_sha256=str(row[5]),
                state=cast(ManifestState, str(row[6])),
                verified=bool(verified_value),
                created_at=str(row[8]),
                verified_at=None if row[9] is None else str(row[9]),
                members=members,
            )
        except (TypeError, ValueError, ManifestError) as exc:
            raise ManifestIntegrityError from exc
        expected = manifest_sha256(
            manifest_id=manifest.manifest_id,
            operation_id=manifest.operation_id,
            artifact_key=manifest.artifact_key,
            artifact_kind=manifest.artifact_kind,
            source_version=manifest.source_version,
            members=manifest.members,
        )
        if expected != manifest.manifest_sha256:
            raise ManifestIntegrityError
        return manifest

    def list_for_operation(self, operation_id: str) -> tuple[ArtifactManifest, ...]:
        operation = _object_id(operation_id)
        identifiers = self._connection.execute(
            """
            SELECT manifest_id FROM artifact_manifests
            WHERE operation_id = ? ORDER BY manifest_id
            """,
            (operation,),
        ).fetchall()
        return tuple(self.get(str(row[0])) for row in identifiers)

    def mark_verified(
        self,
        manifest_id: str,
        *,
        expected_source_version: int,
        verified_at: str,
    ) -> ArtifactManifest:
        identifier = _object_id(manifest_id)
        version = _positive(expected_source_version)
        with self._write_context():
            current = self.get(identifier)
            if current.source_version != version:
                raise ManifestIntegrityError
            if current.state == "PREPARED":
                changed = self._connection.execute(
                    """
                    UPDATE artifact_manifests
                    SET state = 'VERIFIED', verified = 1, verified_at = ?
                    WHERE manifest_id = ? AND state = 'PREPARED'
                      AND verified = 0 AND source_version = ?
                    """,
                    (verified_at, identifier, version),
                ).rowcount
                if changed != 1:
                    raise ManifestConflict
        return self.get(identifier)

    def get_active(self, artifact_key: str, *, epoch: int) -> ArtifactManifest:
        key = _safe_key(artifact_key)
        epoch_value = _positive(epoch)
        epoch_row = self._connection.execute(
            "SELECT state FROM runtime_epochs WHERE epoch = ?",
            (epoch_value,),
        ).fetchone()
        if epoch_row is None or str(epoch_row[0]) not in {"ACTIVE", "RETIRED"}:
            raise ManifestNotReady
        row = self._connection.execute(
            """
            SELECT manifest_id FROM active_artifacts
            WHERE epoch = ? AND artifact_key = ?
            """,
            (epoch_value, key),
        ).fetchone()
        if row is None:
            raise ManifestNotFound
        manifest = self.get(str(row[0]))
        if manifest.state != "ACTIVE" or manifest.artifact_key != key:
            raise ManifestIntegrityError
        return manifest

    def activate_expected(
        self,
        operation_id: str,
        *,
        expected_current_epoch: int | None,
        activated_at: str,
        drop_tombstoned_carry_forward: bool = False,
    ) -> int:
        """Atomically publish a complete verified closure as a new epoch."""

        operation = _object_id(operation_id)
        if type(drop_tombstoned_carry_forward) is not bool:
            raise ManifestIntegrityError
        expected_epoch = (
            None
            if expected_current_epoch is None
            else _positive(expected_current_epoch)
        )
        with self._write_context():
            current_rows = self._connection.execute(
                "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
            ).fetchall()
            if len(current_rows) > 1:
                raise ManifestIntegrityError
            current_epoch = None if not current_rows else int(current_rows[0][0])
            if current_epoch != expected_epoch:
                raise ConcurrentActivation
            operation_row = self._connection.execute(
                """
                SELECT state, required_manifests_json, required_manifest_count,
                       verified_manifest_count, expected_current_epoch
                FROM publication_operations WHERE operation_id = ?
                """,
                (operation,),
            ).fetchone()
            if operation_row is None or str(operation_row[0]) != "VERIFIED":
                raise ManifestNotReady
            try:
                decoded_required = json.loads(str(operation_row[1]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ManifestIntegrityError from exc
            if type(decoded_required) is not list:
                raise ManifestIntegrityError
            required = tuple(decoded_required)
            if (
                not required
                or any(type(value) is not str for value in required)
                or tuple(sorted(set(required))) != required
                or int(operation_row[2]) != len(required)
                or int(operation_row[3]) != len(required)
                or (None if operation_row[4] is None else int(operation_row[4]))
                != expected_epoch
            ):
                raise ManifestIntegrityError
            manifests = self.list_for_operation(operation)
            if (
                tuple(sorted(manifest.manifest_id for manifest in manifests))
                != required
            ):
                raise ManifestIntegrityError
            if any(
                manifest.state != "VERIFIED" or not manifest.verified
                for manifest in manifests
            ):
                raise ManifestNotReady

            next_epoch = int(
                self._connection.execute(
                    "SELECT COALESCE(MAX(epoch), 0) + 1 FROM runtime_epochs"
                ).fetchone()[0]
            )
            self._connection.execute(
                """
                INSERT INTO runtime_epochs(
                    epoch, operation_id, state, created_at, activated_at
                ) VALUES (?, ?, 'PREPARED', ?, NULL)
                """,
                (next_epoch, operation, activated_at),
            )
            if current_epoch is not None:
                retired_keys = (
                    self._tombstoned_artifact_keys(current_epoch)
                    if drop_tombstoned_carry_forward
                    else ()
                )
                if retired_keys:
                    placeholders = ",".join("?" for _ in retired_keys)
                    self._connection.execute(
                        f"""
                        INSERT INTO active_artifacts(
                            epoch, artifact_key, manifest_id, activated_at
                        )
                        SELECT ?, artifact_key, manifest_id, ?
                        FROM active_artifacts
                        WHERE epoch = ?
                          AND artifact_key NOT IN ({placeholders})
                        """,
                        (next_epoch, activated_at, current_epoch, *retired_keys),
                    )
                else:
                    self._connection.execute(
                        """
                        INSERT INTO active_artifacts(
                            epoch, artifact_key, manifest_id, activated_at
                        )
                        SELECT ?, artifact_key, manifest_id, ?
                        FROM active_artifacts WHERE epoch = ?
                        """,
                        (next_epoch, activated_at, current_epoch),
                    )
            for manifest in manifests:
                self._connection.execute(
                    """
                    INSERT INTO active_artifacts(
                        epoch, artifact_key, manifest_id, activated_at
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(epoch, artifact_key) DO UPDATE SET
                        manifest_id = excluded.manifest_id,
                        activated_at = excluded.activated_at
                    """,
                    (
                        next_epoch,
                        manifest.artifact_key,
                        manifest.manifest_id,
                        activated_at,
                    ),
                )
            self._connection.execute(
                """
                UPDATE artifact_manifests SET state = 'ACTIVE'
                WHERE operation_id = ? AND state = 'VERIFIED' AND verified = 1
                """,
                (operation,),
            )
            if current_epoch is not None:
                self._connection.execute(
                    "UPDATE runtime_epochs SET state = 'RETIRED' WHERE epoch = ?",
                    (current_epoch,),
                )
            self._connection.execute(
                """
                UPDATE runtime_epochs
                SET state = 'ACTIVE', activated_at = ? WHERE epoch = ?
                """,
                (activated_at, next_epoch),
            )
            changed = self._connection.execute(
                """
                UPDATE publication_operations
                SET state = 'ACTIVE', runtime_epoch = ?, activated_at = ?
                WHERE operation_id = ? AND state = 'VERIFIED'
                """,
                (next_epoch, activated_at, operation),
            ).rowcount
            if changed != 1:
                raise ManifestConflict
        return next_epoch

    def _tombstoned_artifact_keys(self, epoch: int) -> tuple[str, ...]:
        """Return active keys whose immutable closure is no longer visible."""

        repository = TombstoneRepository(self._connection)
        rows = self._connection.execute(
            "SELECT artifact_key, manifest_id FROM active_artifacts "
            "WHERE epoch = ? ORDER BY artifact_key",
            (epoch,),
        ).fetchall()
        denied: list[str] = []
        for artifact_key, manifest_id in rows:
            manifest = self.get(str(manifest_id))
            if any(
                repository.has_direct(
                    ObjectIdentity(
                        object_type=member.object_type,
                        object_id=member.object_id,
                    )
                )
                or any(
                    repository.has_lineage_hash(value)
                    for value in member.source_lineage_hashes
                )
                for member in manifest.members
            ):
                denied.append(_safe_key(str(artifact_key)))
        return tuple(denied)
