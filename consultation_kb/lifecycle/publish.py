"""Atomic publication operations over scope-local CAS and SQLite manifests."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import AbstractContextManager, contextmanager, nullcontext
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Iterator, Literal, cast

from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.storage.connection import transaction
from consultation_kb.storage.manifests import (
    ArtifactManifest,
    ManifestIntegrityError,
    ManifestMember,
    ManifestNotFound,
    ManifestNotReady,
    ManifestRepository,
)
from consultation_kb.storage.publication_drafts import (
    ArtifactDraft as ArtifactDraft,
    ContentDraft as ContentDraft,
    PublicationError as PublicationError,
    PublicationIntegrityError as PublicationIntegrityError,
)
from consultation_kb.storage.tombstones import ObjectIdentity, VisibilityGuard
from consultation_kb.storage.tombstones import lineage_hash
from consultation_kb.vault.content_store import ContentObjectRef, ContentStore


_SAFE_KEY_RE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z")
_CLIENT_ID_RE = re.compile(r"client_[a-z0-9]{12}")
_OBJECT_ID_RE = re.compile(
    r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*_"
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_MEDIA_TYPE_RE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

PublicationState = Literal["PREPARED", "VERIFIED", "ACTIVE", "FAILED"]
EpochState = Literal["ACTIVE", "RETIRED"]


class PublicationConflict(PublicationError):
    def __init__(self) -> None:
        super().__init__("PUBLICATION_CONFLICT")


class PublicationNotFound(PublicationError):
    def __init__(self) -> None:
        super().__init__("PUBLICATION_NOT_FOUND")


class PublicationApprovalRequired(PublicationError):
    def __init__(self) -> None:
        super().__init__("PUBLICATION_APPROVAL_REQUIRED")


class PublicationStageTransactionOpen(PublicationError):
    def __init__(self) -> None:
        super().__init__("PUBLICATION_STAGE_TRANSACTION_OPEN")


def _object_id(value: str) -> str:
    if (
        type(value) is not str
        or not 38 <= len(value) <= 101
        or _OBJECT_ID_RE.fullmatch(value) is None
        or _CLIENT_ID_RE.search(value[:-37]) is not None
    ):
        raise PublicationIntegrityError
    return value


def _safe_key(value: str) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 64
        or _SAFE_KEY_RE.fullmatch(value) is None
        or _CLIENT_ID_RE.search(value) is not None
    ):
        raise PublicationIntegrityError
    return value


def _object_type(value: str, object_id: str) -> str:
    object_type = _safe_key(value)
    identifier = _object_id(object_id)
    if identifier[:-37] != object_type:
        raise PublicationIntegrityError
    return object_type


def _positive(value: int) -> int:
    if type(value) is not int or value <= 0:
        raise PublicationIntegrityError
    return value


def _media_type(value: str) -> str:
    if (
        type(value) is not str
        or not 3 <= len(value) <= 127
        or _MEDIA_TYPE_RE.fullmatch(value) is None
    ):
        raise PublicationIntegrityError
    return value


def _sha256(value: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise PublicationIntegrityError
    return value


def _utc_text(value: datetime) -> str:
    if (
        value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != timedelta(0)
    ):
        raise PublicationIntegrityError
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _stored_timestamp(value: str | None, *, optional: bool = False) -> str | None:
    if value is None:
        if optional:
            return None
        raise PublicationIntegrityError
    if type(value) is not str or not value.endswith("Z"):
        raise PublicationIntegrityError
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PublicationIntegrityError from exc
    if parsed.utcoffset() != timedelta(0):
        raise PublicationIntegrityError
    return value


def _canonical_ids(values: Iterable[str]) -> tuple[str, ...]:
    identifiers = tuple(_object_id(value) for value in values)
    if not identifiers or len(set(identifiers)) != len(identifiers):
        raise PublicationIntegrityError
    return tuple(sorted(identifiers))


@dataclass(frozen=True, slots=True)
class PreparedContentDraft:
    object_type: str
    object_id: str
    reference: ContentObjectRef
    source_version: int
    source_lineage_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        _object_type(self.object_type, self.object_id)
        _object_id(self.object_id)
        if type(self.reference) is not ContentObjectRef:
            raise PublicationIntegrityError
        _positive(self.source_version)
        if (
            type(self.source_lineage_hashes) is not tuple
            or any(
                type(value) is not str or _SHA256_RE.fullmatch(value) is None
                for value in self.source_lineage_hashes
            )
            or tuple(sorted(set(self.source_lineage_hashes)))
            != self.source_lineage_hashes
        ):
            raise PublicationIntegrityError


@dataclass(frozen=True, slots=True)
class PreparedArtifactDraft:
    purpose: str
    manifest_id: str
    artifact_key: str
    artifact_kind: str
    source_version: int
    members: tuple[PreparedContentDraft, ...]

    def __post_init__(self) -> None:
        _safe_key(self.purpose)
        _object_id(self.manifest_id)
        _safe_key(self.artifact_key)
        _safe_key(self.artifact_kind)
        _positive(self.source_version)
        if not self.members or any(
            type(member) is not PreparedContentDraft for member in self.members
        ):
            raise PublicationIntegrityError
        if len({member.object_id for member in self.members}) != len(self.members):
            raise PublicationIntegrityError
        if any(member.source_version != self.source_version for member in self.members):
            raise PublicationIntegrityError


ClosureArtifact = ArtifactDraft | PreparedArtifactDraft | ArtifactManifest


def _source_lineage_hashes(sources: Iterable[ObjectIdentity]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {lineage_hash(source.object_type, source.object_id) for source in sources}
        )
    )


def publication_closure_sha256(
    *,
    purpose: str,
    authority_base_version: int,
    expected_current_epoch: int | None,
    artifacts: Iterable[ClosureArtifact],
) -> str:
    """Hash the complete publication envelope before and after staging.

    ``authority_base_version`` is the new authority/source version being
    published (the persisted legacy field name is retained). It must be exactly
    one greater than the approved descriptor base version.
    """

    purpose_value = _safe_key(purpose)
    authority_version = _positive(authority_base_version)
    expected_epoch = (
        None if expected_current_epoch is None else _positive(expected_current_epoch)
    )
    artifact_values = tuple(artifacts)
    if not artifact_values:
        raise PublicationIntegrityError
    bodies: list[dict[str, object]] = []
    artifact_keys: list[str] = []
    manifest_ids: list[str] = []
    for artifact in artifact_values:
        if type(artifact) not in {
            ArtifactDraft,
            PreparedArtifactDraft,
            ArtifactManifest,
        }:
            raise PublicationIntegrityError
        manifest_id = _object_id(artifact.manifest_id)
        artifact_key = _safe_key(artifact.artifact_key)
        artifact_kind = _safe_key(artifact.artifact_kind)
        source_version = _positive(artifact.source_version)
        if source_version != authority_version:
            raise PublicationIntegrityError
        manifest_ids.append(manifest_id)
        artifact_keys.append(artifact_key)
        members: list[dict[str, object]] = []
        for ordinal, member in enumerate(artifact.members):
            if type(member) is ContentDraft:
                object_type = member.object_type
                object_id = member.object_id
                content_sha256 = hashlib.sha256(member.data).hexdigest()
                member_version = member.source_version
                media_type = member.media_type
                size_bytes = len(member.data)
                source_lineage_hashes = _source_lineage_hashes(member.source_lineage)
            elif type(member) is PreparedContentDraft:
                object_type = member.object_type
                object_id = member.object_id
                content_sha256 = member.reference.content_sha256
                member_version = member.source_version
                media_type = member.reference.media_type
                size_bytes = member.reference.size_bytes
                source_lineage_hashes = member.source_lineage_hashes
            elif type(member) is ManifestMember:
                object_type = member.object_type
                object_id = member.object_id
                content_sha256 = member.object_sha256
                member_version = member.source_version
                media_type = member.media_type
                size_bytes = member.size_bytes
                source_lineage_hashes = member.source_lineage_hashes
            else:
                raise PublicationIntegrityError
            if member_version != source_version:
                raise PublicationIntegrityError
            members.append(
                {
                    "content_sha256": _sha256(content_sha256),
                    "media_type": _media_type(media_type),
                    "object_id": _object_id(object_id),
                    "object_type": _object_type(object_type, object_id),
                    "ordinal": ordinal,
                    "size_bytes": size_bytes,
                    "source_lineage_hashes": list(source_lineage_hashes),
                    "source_version": _positive(member_version),
                }
            )
        if not members:
            raise PublicationIntegrityError
        bodies.append(
            {
                "artifact_key": artifact_key,
                "artifact_kind": artifact_kind,
                "manifest_id": manifest_id,
                "members": members,
                "source_version": source_version,
            }
        )
    if len(set(manifest_ids)) != len(manifest_ids) or len(set(artifact_keys)) != len(
        artifact_keys
    ):
        raise PublicationIntegrityError
    payload = {
        "artifacts": sorted(bodies, key=lambda value: str(value["manifest_id"])),
        "authority_base_version": authority_version,
        "expected_current_epoch": expected_epoch,
        "purpose": purpose_value,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(
        b"consultation-kb-publication-envelope-v2\0" + encoded
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class PublicationOperation:
    operation_id: str
    purpose: str
    authority_base_version: int
    approval_request_id: str
    descriptor_sha256: str
    required_manifest_ids: tuple[str, ...]
    state: PublicationState
    verified_manifest_count: int
    expected_current_epoch: int | None
    runtime_epoch: int | None
    created_at: str
    activated_at: str | None

    def __post_init__(self) -> None:
        _object_id(self.operation_id)
        _safe_key(self.purpose)
        _positive(self.authority_base_version)
        _object_id(self.approval_request_id)
        _sha256(self.descriptor_sha256)
        if _canonical_ids(self.required_manifest_ids) != self.required_manifest_ids:
            raise PublicationIntegrityError
        if self.state not in {"PREPARED", "VERIFIED", "ACTIVE", "FAILED"}:
            raise PublicationIntegrityError
        if type(
            self.verified_manifest_count
        ) is not int or not 0 <= self.verified_manifest_count <= len(
            self.required_manifest_ids
        ):
            raise PublicationIntegrityError
        if self.expected_current_epoch is not None:
            _positive(self.expected_current_epoch)
        if self.runtime_epoch is not None:
            _positive(self.runtime_epoch)
        if self.state == "PREPARED" and self.verified_manifest_count != 0:
            raise PublicationIntegrityError
        if self.state in {"VERIFIED", "ACTIVE"} and (
            self.verified_manifest_count != len(self.required_manifest_ids)
        ):
            raise PublicationIntegrityError
        if self.state == "ACTIVE" and self.runtime_epoch is None:
            raise PublicationIntegrityError
        if self.state != "ACTIVE" and self.runtime_epoch is not None:
            raise PublicationIntegrityError
        _stored_timestamp(self.created_at)
        _stored_timestamp(self.activated_at, optional=True)
        if self.state == "ACTIVE" and self.activated_at is None:
            raise PublicationIntegrityError
        if self.state != "ACTIVE" and self.activated_at is not None:
            raise PublicationIntegrityError


@dataclass(frozen=True, slots=True)
class RuntimeEpochSnapshot:
    epoch: int
    operation_id: str
    state: EpochState

    def __post_init__(self) -> None:
        _positive(self.epoch)
        _object_id(self.operation_id)
        if self.state not in {"ACTIVE", "RETIRED"}:
            raise PublicationIntegrityError


class RuntimeEpochRepository:
    """Read and pin complete runtime epochs; activation is manifest-owned."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SQLITE_CONNECTION_REQUIRED")
        self._connection = connection

    def current(self) -> RuntimeEpochSnapshot | None:
        rows = self._connection.execute(
            """
            SELECT epoch, operation_id, state FROM runtime_epochs
            WHERE state = 'ACTIVE'
            """
        ).fetchall()
        if len(rows) > 1:
            raise PublicationIntegrityError
        if not rows:
            return None
        return RuntimeEpochSnapshot(
            epoch=int(rows[0][0]),
            operation_id=str(rows[0][1]),
            state=cast(EpochState, str(rows[0][2])),
        )

    def get(self, epoch: int) -> RuntimeEpochSnapshot:
        epoch_value = _positive(epoch)
        row = self._connection.execute(
            """
            SELECT epoch, operation_id, state FROM runtime_epochs WHERE epoch = ?
            """,
            (epoch_value,),
        ).fetchone()
        if row is None or str(row[2]) not in {"ACTIVE", "RETIRED"}:
            raise PublicationNotFound
        return RuntimeEpochSnapshot(
            epoch=int(row[0]),
            operation_id=str(row[1]),
            state=cast(EpochState, str(row[2])),
        )

    @contextmanager
    def pin(self, epoch: int | None = None) -> Iterator[RuntimeEpochSnapshot]:
        """Pin one complete DB snapshot for all pointer reads in the block."""

        context: AbstractContextManager[sqlite3.Connection]
        if self._connection.in_transaction:
            context = nullcontext(self._connection)
        else:
            context = transaction(self._connection, immediate=False)
        with context:
            snapshot = self.current() if epoch is None else self.get(epoch)
            if snapshot is None:
                raise PublicationNotFound
            yield snapshot


class PublishCoordinator:
    """The sole high-level prepare/verify/activate publication workflow."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        content_store: ContentStore,
        visibility_guard: VisibilityGuard,
        *,
        clock: Clock | None = None,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SQLITE_CONNECTION_REQUIRED")
        if not isinstance(content_store, ContentStore):
            raise TypeError("CONTENT_STORE_REQUIRED")
        if not isinstance(visibility_guard, VisibilityGuard):
            raise TypeError("VISIBILITY_GUARD_REQUIRED")
        self._connection = connection
        self._store = content_store
        self._visibility = visibility_guard
        self._clock = clock if clock is not None else SystemClock()
        self._fault_hook = fault_hook
        self._manifests = ManifestRepository(connection)
        self._epochs = RuntimeEpochRepository(connection)

    def _fault(self, point: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(point)

    def _write_context(self) -> AbstractContextManager[sqlite3.Connection]:
        if self._connection.in_transaction:
            return nullcontext(self._connection)
        return transaction(self._connection)

    def _require_execution(
        self,
        *,
        operation_id: str,
        approval_request_id: str,
        descriptor_sha256: str,
        draft_sha256: str | None,
        authority_base_version: int,
        expected_state: Literal["CLAIMED", "APPLIED"],
    ) -> None:
        row = self._connection.execute(
            """
            SELECT state, applied_commit_version, applied_at,
                   descriptor_base_version, draft_sha256
            FROM approval_executions
            WHERE operation_id = ? AND request_id = ?
              AND descriptor_sha256 = ?
            """,
            (
                operation_id,
                approval_request_id,
                descriptor_sha256,
            ),
        ).fetchone()
        if (
            row is None
            or str(row[0]) != expected_state
            or (draft_sha256 is not None and row[4] != draft_sha256)
        ):
            raise PublicationApprovalRequired
        # The approval descriptor names the current version; the publication
        # envelope names the single successor version.
        if type(row[3]) is not int or row[3] + 1 != authority_base_version:
            raise PublicationApprovalRequired
        if expected_state == "CLAIMED" and (row[1] is not None or row[2] is not None):
            raise PublicationApprovalRequired
        # ``applied_commit_version`` is the approval execution ledger sequence,
        # not the published authority/source version.  The immutable descriptor
        # base above binds the one permitted authority successor; APPLIED only
        # needs a durable positive execution sequence and timestamp.
        if expected_state == "APPLIED" and (
            type(row[1]) is not int or int(row[1]) <= 0 or row[2] is None
        ):
            raise PublicationApprovalRequired

    def _operation(self, operation_id: str) -> PublicationOperation:
        operation = _object_id(operation_id)
        row = self._connection.execute(
            """
            SELECT operation_id, purpose, authority_base_version,
                   approval_request_id, descriptor_sha256, state,
                   required_manifests_json,
                   required_manifest_count, verified_manifest_count,
                   expected_current_epoch, runtime_epoch, created_at, activated_at
            FROM publication_operations WHERE operation_id = ?
            """,
            (operation,),
        ).fetchone()
        if row is None:
            raise PublicationNotFound
        try:
            decoded = json.loads(str(row[6]))
            if type(decoded) is not list or any(
                type(value) is not str for value in decoded
            ):
                raise PublicationIntegrityError
            required = tuple(decoded)
            if int(row[7]) != len(required):
                raise PublicationIntegrityError
            return PublicationOperation(
                operation_id=str(row[0]),
                purpose=str(row[1]),
                authority_base_version=int(row[2]),
                approval_request_id=str(row[3]),
                descriptor_sha256=str(row[4]),
                state=cast(PublicationState, str(row[5])),
                required_manifest_ids=required,
                verified_manifest_count=int(row[8]),
                expected_current_epoch=(None if row[9] is None else int(row[9])),
                runtime_epoch=None if row[10] is None else int(row[10]),
                created_at=str(row[11]),
                activated_at=None if row[12] is None else str(row[12]),
            )
        except (TypeError, ValueError, json.JSONDecodeError, PublicationError) as exc:
            raise PublicationIntegrityError from exc

    def _closure_attestation(self, operation_id: str) -> tuple[str, str]:
        row = self._connection.execute(
            """
            SELECT approval_draft_sha256, closure_sha256
              FROM publication_closure_attestations
             WHERE operation_id = ?
            """,
            (operation_id,),
        ).fetchone()
        if row is None:
            raise PublicationIntegrityError
        try:
            return _sha256(str(row[0])), _sha256(str(row[1]))
        except PublicationError as exc:
            raise PublicationIntegrityError from exc

    def _verify_attested_closure(
        self,
        operation: PublicationOperation,
        manifests: tuple[ArtifactManifest, ...],
    ) -> str:
        approved_draft_sha256, expected_closure_sha256 = (
            self._closure_attestation(operation.operation_id)
        )
        actual_closure_sha256 = publication_closure_sha256(
            purpose=operation.purpose,
            authority_base_version=operation.authority_base_version,
            expected_current_epoch=operation.expected_current_epoch,
            artifacts=manifests,
        )
        if actual_closure_sha256 != expected_closure_sha256:
            raise PublicationIntegrityError
        return approved_draft_sha256

    def stage_artifacts(
        self,
        *,
        purpose: str,
        artifacts: Iterable[ArtifactDraft],
    ) -> tuple[PreparedArtifactDraft, ...]:
        """Complete all CAS file I/O before the approval write transaction."""

        if self._connection.in_transaction:
            raise PublicationStageTransactionOpen
        purpose_value = _safe_key(purpose)
        drafts = tuple(artifacts)
        if any(type(draft) is not ArtifactDraft for draft in drafts):
            raise PublicationIntegrityError
        _canonical_ids(draft.manifest_id for draft in drafts)
        if len({draft.artifact_key for draft in drafts}) != len(drafts):
            raise PublicationIntegrityError
        prepared: list[PreparedArtifactDraft] = []
        for draft in drafts:
            members: list[PreparedContentDraft] = []
            for content in draft.members:
                staged = self._store.stage_bytes(
                    content.data,
                    purpose=purpose_value,
                    manifest_id=draft.manifest_id,
                    media_type=content.media_type,
                )
                self._fault("after_stage_write")
                self._fault("after_file_fsync")
                reference = self._store.finalize(staged)
                source_lineage_hashes = _source_lineage_hashes(content.source_lineage)
                members.append(
                    PreparedContentDraft(
                        object_type=content.object_type,
                        object_id=content.object_id,
                        reference=reference,
                        source_version=content.source_version,
                        source_lineage_hashes=source_lineage_hashes,
                    )
                )
            prepared.append(
                PreparedArtifactDraft(
                    purpose=purpose_value,
                    manifest_id=draft.manifest_id,
                    artifact_key=draft.artifact_key,
                    artifact_kind=draft.artifact_kind,
                    source_version=draft.source_version,
                    members=tuple(members),
                )
            )
        return tuple(prepared)

    def prepare(
        self,
        *,
        operation_id: str,
        purpose: str,
        authority_base_version: int,
        approval_request_id: str,
        descriptor_sha256: str,
        approval_draft_sha256: str | None = None,
        expected_current_epoch: int | None,
        artifacts: Iterable[PreparedArtifactDraft],
    ) -> PublicationOperation:
        operation = _object_id(operation_id)
        purpose_value = _safe_key(purpose)
        base_version = _positive(authority_base_version)
        approval = _object_id(approval_request_id)
        descriptor = _sha256(descriptor_sha256)
        approved_draft = (
            None
            if approval_draft_sha256 is None
            else _sha256(approval_draft_sha256)
        )
        expected_epoch = (
            None
            if expected_current_epoch is None
            else _positive(expected_current_epoch)
        )
        drafts = tuple(artifacts)
        if any(type(draft) is not PreparedArtifactDraft for draft in drafts):
            raise PublicationIntegrityError
        required = _canonical_ids(draft.manifest_id for draft in drafts)
        if any(draft.purpose != purpose_value for draft in drafts) or len(
            {draft.artifact_key for draft in drafts}
        ) != len(drafts):
            raise PublicationIntegrityError
        for draft in drafts:
            for content in draft.members:
                self._store.assert_reference_scope(content.reference)
        closure_sha256 = publication_closure_sha256(
            purpose=purpose_value,
            authority_base_version=base_version,
            expected_current_epoch=expected_epoch,
            artifacts=drafts,
        )
        created_at = _utc_text(self._clock.now())

        self._fault("before_prepared_tx")
        try:
            with self._write_context():
                self._require_execution(
                    operation_id=operation,
                    approval_request_id=approval,
                    descriptor_sha256=descriptor,
                    draft_sha256=(
                        closure_sha256 if approved_draft is None else approved_draft
                    ),
                    authority_base_version=base_version,
                    expected_state="CLAIMED",
                )
                prepared: list[
                    tuple[PreparedArtifactDraft, tuple[ManifestMember, ...]]
                ] = []
                for draft in drafts:
                    members: list[ManifestMember] = []
                    for ordinal, content in enumerate(draft.members):
                        reference = content.reference
                        members.append(
                            ManifestMember(
                                ordinal=ordinal,
                                object_type=content.object_type,
                                object_id=content.object_id,
                                object_sha256=reference.content_sha256,
                                source_version=content.source_version,
                                media_type=reference.media_type,
                                size_bytes=reference.size_bytes,
                                source_lineage_hashes=content.source_lineage_hashes,
                            )
                        )
                    prepared.append((draft, tuple(members)))
                self._connection.execute(
                    """
                    INSERT INTO publication_operations(
                        operation_id, purpose, authority_base_version,
                        approval_request_id, descriptor_sha256, state,
                        required_manifests_json,
                        required_manifest_count, verified_manifest_count,
                        expected_current_epoch, runtime_epoch, created_at, activated_at
                    ) VALUES (?, ?, ?, ?, ?, 'PREPARED', ?, ?, 0, ?, NULL, ?, NULL)
                    """,
                    (
                        operation,
                        purpose_value,
                        base_version,
                        approval,
                        descriptor,
                        json.dumps(
                            required,
                            ensure_ascii=True,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        len(required),
                        expected_epoch,
                        created_at,
                    ),
                )
                self._connection.execute(
                    """
                    INSERT INTO publication_closure_attestations(
                        operation_id, approval_draft_sha256,
                        closure_sha256, created_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        operation,
                        closure_sha256 if approved_draft is None else approved_draft,
                        closure_sha256,
                        created_at,
                    ),
                )
                for draft, prepared_members in prepared:
                    self._manifests.insert_prepared(
                        manifest_id=draft.manifest_id,
                        operation_id=operation,
                        artifact_key=draft.artifact_key,
                        artifact_kind=draft.artifact_kind,
                        source_version=draft.source_version,
                        members=prepared_members,
                        created_at=created_at,
                    )
        except sqlite3.IntegrityError as exc:
            raise PublicationConflict from exc
        self._fault("after_prepared_tx")
        return self._operation(operation)

    def _verify_content_closure(
        self,
        operation: PublicationOperation,
    ) -> tuple[ArtifactManifest, ...]:
        manifests = self._manifests.list_for_operation(operation.operation_id)
        if tuple(sorted(manifest.manifest_id for manifest in manifests)) != (
            operation.required_manifest_ids
        ):
            raise PublicationIntegrityError
        for manifest in manifests:
            if manifest.source_version <= 0 or any(
                member.source_version != manifest.source_version
                for member in manifest.members
            ):
                raise ManifestIntegrityError
            for member in manifest.members:
                reference = self._store.reference(
                    content_sha256=member.object_sha256,
                    media_type=member.media_type,
                    size_bytes=member.size_bytes,
                )
                self._store.read_verified(reference)
        return manifests

    def _verify_visibility_closure(
        self,
        manifests: Iterable[ArtifactManifest],
    ) -> None:
        """Reject a publication whose target or immutable lineage is tombstoned."""

        for manifest in manifests:
            for member in manifest.members:
                self._visibility.assert_visible(
                    ObjectIdentity(member.object_type, member.object_id),
                    source_lineage_hashes=member.source_lineage_hashes,
                )

    def verify(self, operation_id: str) -> PublicationOperation:
        operation = self._operation(operation_id)
        if operation.state == "ACTIVE":
            return self.activate(operation.operation_id)
        if operation.state == "FAILED":
            raise ManifestNotReady
        manifests = self._verify_content_closure(operation)
        self._verify_attested_closure(operation, manifests)
        self._verify_visibility_closure(manifests)
        if operation.state == "VERIFIED":
            return operation
        verified_at = _utc_text(self._clock.now())
        with transaction(self._connection):
            for manifest in manifests:
                self._manifests.mark_verified(
                    manifest.manifest_id,
                    expected_source_version=manifest.source_version,
                    verified_at=verified_at,
                )
            changed = self._connection.execute(
                """
                UPDATE publication_operations
                SET state = 'VERIFIED', verified_manifest_count = ?
                WHERE operation_id = ? AND state = 'PREPARED'
                  AND verified_manifest_count = 0
                """,
                (len(manifests), operation.operation_id),
            ).rowcount
            if changed != 1:
                raise PublicationConflict
        self._fault("after_verify")
        return self._operation(operation.operation_id)

    def activate(self, operation_id: str) -> PublicationOperation:
        operation = self._operation(operation_id)
        if operation.state == "ACTIVE":
            manifests = self._verify_content_closure(operation)
            approved_draft_sha256 = self._verify_attested_closure(
                operation, manifests
            )
            self._verify_visibility_closure(manifests)
            self._require_execution(
                operation_id=operation.operation_id,
                approval_request_id=operation.approval_request_id,
                descriptor_sha256=operation.descriptor_sha256,
                draft_sha256=approved_draft_sha256,
                authority_base_version=operation.authority_base_version,
                expected_state="APPLIED",
            )
            return operation
        if operation.state != "VERIFIED":
            raise ManifestNotReady
        # File I/O stays outside BEGIN IMMEDIATE.  The transaction then rechecks
        # both approval execution and the complete manifest closure before switch.
        manifests = self._verify_content_closure(operation)
        approved_draft_sha256 = self._verify_attested_closure(
            operation, manifests
        )
        self._verify_visibility_closure(manifests)
        self._fault("before_active_tx")
        with self._write_context():
            current = self._operation(operation.operation_id)
            if current.state != "VERIFIED":
                raise PublicationConflict
            current_manifests = self._manifests.list_for_operation(current.operation_id)
            # BEGIN IMMEDIATE prevents a concurrent tombstone writer from racing
            # this final authority check and the epoch switch.
            self._verify_visibility_closure(current_manifests)
            self._require_execution(
                operation_id=current.operation_id,
                approval_request_id=current.approval_request_id,
                descriptor_sha256=current.descriptor_sha256,
                draft_sha256=approved_draft_sha256,
                authority_base_version=current.authority_base_version,
                expected_state="APPLIED",
            )
            self._manifests.activate_expected(
                current.operation_id,
                expected_current_epoch=current.expected_current_epoch,
                activated_at=_utc_text(self._clock.now()),
            )
        self._fault("after_active_tx")
        self._fault("before_cleanup")
        return self._operation(operation.operation_id)

    def recover(self, operation_id: str) -> PublicationOperation:
        operation = self._operation(operation_id)
        if operation.state == "ACTIVE":
            return self.activate(operation.operation_id)
        if operation.state == "PREPARED":
            operation = self.verify(operation.operation_id)
        if operation.state == "VERIFIED":
            return self.activate(operation.operation_id)
        raise ManifestNotReady

    def read_active_member(
        self,
        *,
        target: ObjectIdentity,
        artifact_key: str,
        epoch: int | None = None,
    ) -> bytes:
        """Read using only hash-bound lineage from the active manifest."""

        with self._epochs.pin(epoch) as snapshot:
            manifest = self._manifests.get_active(
                artifact_key,
                epoch=snapshot.epoch,
            )
            member = next(
                (
                    candidate
                    for candidate in manifest.members
                    if candidate.object_type == target.object_type
                    and candidate.object_id == target.object_id
                ),
                None,
            )
            if member is None:
                raise ManifestNotFound
            if member.source_version != manifest.source_version:
                raise ManifestIntegrityError
            authoritative_target = ObjectIdentity(
                member.object_type,
                member.object_id,
            )
            self._visibility.assert_visible(
                authoritative_target,
                source_lineage_hashes=member.source_lineage_hashes,
            )
            reference = self._store.reference(
                content_sha256=member.object_sha256,
                media_type=member.media_type,
                size_bytes=member.size_bytes,
            )
            payload = self._store.read_verified(reference)
        # Do not return bytes if a tombstone became visible while files were read.
        self._visibility.assert_visible(
            authoritative_target,
            source_lineage_hashes=member.source_lineage_hashes,
        )
        return payload
