"""Global client catalog and approved empty-client creation workflow."""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import os
import re
import sqlite3
import stat
import threading
import time
import unicodedata
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO, Iterator, Literal, Protocol, TypeAlias, cast, final

from pydantic import ValidationError

from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.models import ApprovalRequest
from consultation_kb.approvals.store import ApprovalError, ApprovalService
from consultation_kb.core.client_ids import ClientIdFactory
from consultation_kb.core.clock import Clock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import VersionRef
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.security.dpapi import SecretProtector
from consultation_kb.security.path_guard import PathGuard, ScopePathDenied
from consultation_kb.storage.connection import (
    connect_database,
    connect_database_snapshot,
    transaction,
)
from consultation_kb.storage.migrate import MigrationRunner


ClientState: TypeAlias = Literal["PREPARED", "ACTIVE", "RETIRED"]
_CLIENT_ID_RE = re.compile(r"client_[a-z0-9]{12}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_IDENTITY_PURPOSE = "identity_map"
_IDENTITY_SCHEMA_VERSION = 2
_IDEMPOTENCY_KEY_RE = re.compile(r"[A-Za-z0-9._:-]{16,256}\Z")
_REPARSE_ATTRIBUTE = 0x400
_SCOPE_MARKER = ".scope-id"
_CLIENT_DATABASE = "client.sqlite3"
_MAX_IDENTITY_MAP_BYTES = 8 * 1024 * 1024
_MAX_SCOPE_MARKER_BYTES = 4096
_IDENTITY_MAP_LOCK = threading.RLock()
_IDENTITY_LOCK_FILE = ".identity-map.lock"
_IDENTITY_LOCK_SENTINEL = b"\x00"
_IDENTITY_LOCK_TIMEOUT_SECONDS = 30.0
_IDENTITY_LOCK_RETRY_SECONDS = 0.01


class ClientCatalogError(RuntimeError):
    """Fixed-code catalog failure."""


class ClientCatalogConflict(ClientCatalogError):
    def __init__(self) -> None:
        super().__init__("CLIENT_CATALOG_CONFLICT")


class ClientNotFound(ClientCatalogError):
    def __init__(self) -> None:
        super().__init__("CLIENT_NOT_FOUND")


class DuplicateClientAlias(ClientCatalogError):
    def __init__(self) -> None:
        super().__init__("CLIENT_ALIAS_DUPLICATE")


class ClientCreationFailed(ClientCatalogError):
    def __init__(self) -> None:
        super().__init__("CLIENT_CREATION_FAILED")


class DirectoryAclPolicy(Protocol):
    def apply(self, path: Path) -> object: ...

    def verify(self, path: Path) -> object: ...


DiffRefFactory: TypeAlias = Callable[[str, str], VersionRef]
ReplaceOperation: TypeAlias = Callable[[Path, Path], None]


def _require_utc(value: object) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ClientCatalogConflict
    return value


def _utc_text(value: datetime) -> str:
    return _require_utc(value).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise ClientCatalogConflict
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ClientCatalogConflict from None
    return _require_utc(parsed)


def _valid_client_id(value: object) -> str:
    if type(value) is not str or _CLIENT_ID_RE.fullmatch(value) is None:
        raise ClientNotFound
    return value


def _valid_sha256(value: object) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ClientCatalogConflict
    return value


def _idempotency_key_sha256(value: object) -> str:
    if type(value) is not str or _IDEMPOTENCY_KEY_RE.fullmatch(value) is None:
        raise ClientCreationFailed
    return hashlib.sha256(value.encode("ascii", errors="strict")).hexdigest()


@final
@dataclass(frozen=True, slots=True)
class ClientRecord:
    client_id: str
    directory_object_id: str
    alias_lookup_sha256: str
    state: ClientState
    created_at: datetime
    activated_at: datetime | None


IdentityState: TypeAlias = Literal[
    "PREVIEW",
    "STAGED",
    "STAGED_REAPPROVAL",
    "ACTIVE",
]


@final
@dataclass(frozen=True, slots=True, repr=False)
class ClientCreationPreview:
    request_id: str
    client_id: str
    directory_object_id: str
    descriptor: DraftDescriptor
    diff_object_ref: VersionRef

    def __repr__(self) -> str:
        return "<ClientCreationPreview identity-redacted>"


@final
@dataclass(frozen=True, slots=True)
class IdentityMapEraseResult:
    """Body-free proof that one exact encrypted identity binding is absent."""

    client_id: str
    alias_lookup_sha256: str
    directory_object_id: str
    entry_removed: bool
    encrypted_map_sha256: str


@dataclass(frozen=True, slots=True)
class _IdentityEntry:
    alias: str
    alias_lookup_sha256: str
    client_id: str
    directory_object_id: str
    operation_id: str
    request_id: str
    idempotency_key_sha256: str | None
    descriptor: DraftDescriptor
    diff_object_ref: VersionRef
    state: IdentityState
    empty_db_sha256: str | None = None


@final
class ClientCatalog:
    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("client catalog requires sqlite3.Connection")
        self._connection = connection

    def uses_connection(self, connection: sqlite3.Connection) -> bool:
        return connection is self._connection

    def _row_to_record(self, row: tuple[object, ...]) -> ClientRecord:
        if len(row) != 6 or row[3] not in {"PREPARED", "ACTIVE", "RETIRED"}:
            raise ClientCatalogConflict
        client_id = _valid_client_id(row[0])
        if type(row[1]) is not str or not row[1]:
            raise ClientCatalogConflict
        alias_hash = _valid_sha256(row[2])
        activated = None if row[5] is None else _parse_utc(row[5])
        return ClientRecord(
            client_id=client_id,
            directory_object_id=row[1],
            alias_lookup_sha256=alias_hash,
            state=row[3],
            created_at=_parse_utc(row[4]),
            activated_at=activated,
        )

    def _select_client(self, client_id: str) -> ClientRecord | None:
        row = self._connection.execute(
            """
            SELECT client_id, directory_object_id, alias_lookup_sha256,
                   state, created_at, activated_at
              FROM clients WHERE client_id = ?
            """,
            (client_id,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_record(tuple(row))

    def get(self, client_id: str) -> ClientRecord:
        validated = _valid_client_id(client_id)
        record = self._select_client(validated)
        if record is None:
            raise ClientNotFound
        return record

    def find_by_alias_hash(self, alias_lookup_sha256: str) -> ClientRecord | None:
        validated = _valid_sha256(alias_lookup_sha256)
        row = self._connection.execute(
            """
            SELECT client_id, directory_object_id, alias_lookup_sha256,
                   state, created_at, activated_at
              FROM clients WHERE alias_lookup_sha256 = ?
            """,
            (validated,),
        ).fetchone()
        return None if row is None else self._row_to_record(tuple(row))

    def prepare(
        self,
        *,
        client_id: str,
        directory_object_id: str,
        alias_lookup_sha256: str,
        created_at: datetime,
    ) -> ClientRecord:
        with transaction(self._connection):
            return self.prepare_in_transaction(
                client_id=client_id,
                directory_object_id=directory_object_id,
                alias_lookup_sha256=alias_lookup_sha256,
                created_at=created_at,
            )

    def prepare_in_transaction(
        self,
        *,
        client_id: str,
        directory_object_id: str,
        alias_lookup_sha256: str,
        created_at: datetime,
    ) -> ClientRecord:
        if not self._connection.in_transaction:
            raise ClientCatalogConflict
        validated_id = _valid_client_id(client_id)
        if type(directory_object_id) is not str or not directory_object_id:
            raise ClientCatalogConflict
        alias_hash = _valid_sha256(alias_lookup_sha256)
        created_text = _utc_text(created_at)
        existing = self._select_client(validated_id)
        if existing is not None:
            if (
                existing.directory_object_id == directory_object_id
                and existing.alias_lookup_sha256 == alias_hash
                and existing.created_at == _require_utc(created_at)
                and existing.state in {"PREPARED", "ACTIVE"}
            ):
                return existing
            raise ClientCatalogConflict
        try:
            self._connection.execute(
                """
                INSERT INTO clients(
                    client_id, directory_object_id, alias_lookup_sha256,
                    state, created_at, activated_at
                ) VALUES (?, ?, ?, 'PREPARED', ?, NULL)
                """,
                (validated_id, directory_object_id, alias_hash, created_text),
            )
        except sqlite3.IntegrityError:
            raise ClientCatalogConflict from None
        return self.get(validated_id)

    def activate(self, client_id: str, *, activated_at: datetime) -> ClientRecord:
        validated = _valid_client_id(client_id)
        activated = _require_utc(activated_at)
        with transaction(self._connection):
            existing = self._select_client(validated)
            if existing is None:
                raise ClientNotFound
            if existing.state == "ACTIVE":
                return existing
            if existing.state != "PREPARED" or activated < existing.created_at:
                raise ClientCatalogConflict
            updated = self._connection.execute(
                """
                UPDATE clients SET state = 'ACTIVE', activated_at = ?
                 WHERE client_id = ? AND state = 'PREPARED'
                """,
                (_utc_text(activated), validated),
            )
            if updated.rowcount != 1:
                raise ClientCatalogConflict
        return self.get(validated)

    def require_active(self, client_id: str) -> ClientRecord:
        record = self.get(client_id)
        if record.state != "ACTIVE":
            raise ClientNotFound
        return record

    def active_client_ids(self) -> tuple[str, ...]:
        return tuple(
            row[0]
            for row in self._connection.execute(
                "SELECT client_id FROM clients WHERE state = 'ACTIVE' ORDER BY client_id"
            )
        )


def _safe_directory(path: Path) -> bool:
    try:
        status = os.lstat(path)
    except OSError:
        return False
    attributes = int(getattr(status, "st_file_attributes", 0))
    return (
        stat.S_ISDIR(status.st_mode)
        and not stat.S_ISLNK(status.st_mode)
        and not attributes & _REPARSE_ATTRIBUTE
    )


def _safe_regular_file(path: Path) -> bool:
    try:
        status = os.lstat(path)
    except OSError:
        return False
    attributes = int(getattr(status, "st_file_attributes", 0))
    return (
        stat.S_ISREG(status.st_mode)
        and not stat.S_ISLNK(status.st_mode)
        and not attributes & _REPARSE_ATTRIBUTE
        and status.st_nlink == 1
    )


def _canonical_alias(value: object) -> tuple[str, str]:
    if type(value) is not str:
        raise ClientCreationFailed
    alias = unicodedata.normalize("NFKC", value).strip()
    if (
        not alias
        or len(alias) > 256
        or any(unicodedata.category(character).startswith("C") for character in alias)
    ):
        raise ClientCreationFailed
    return alias, unicodedata.normalize("NFKC", alias).casefold()


def _hash_stream(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    stream.seek(0)
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _initialize_identity_lock_file(parent: Path) -> None:
    """Create the fixed lock inode without ever following a pre-existing link."""

    lock_path = parent / _IDENTITY_LOCK_FILE
    guard = PathGuard(parent)

    def verify_existing_inode() -> None:
        # Do not read byte zero here: Windows byte-range locks are mandatory,
        # so a concurrent holder would turn a normal wait into a false failure.
        with guard.open_scoped(_IDENTITY_LOCK_FILE, mode="r+b"):
            pass

    try:
        try:
            verify_existing_inode()
            return
        except ScopePathDenied:
            pass
        with guard.pin_root():
            try:
                descriptor = os.open(
                    lock_path,
                    os.O_CREAT
                    | os.O_EXCL
                    | os.O_WRONLY
                    | getattr(os, "O_BINARY", 0),
                    0o600,
                )
            except FileExistsError:
                descriptor = None
            if descriptor is not None:
                try:
                    if os.write(descriptor, _IDENTITY_LOCK_SENTINEL) != 1:
                        raise OSError
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        verify_existing_inode()
    except ClientCreationFailed:
        raise
    except Exception:
        raise ClientCreationFailed from None


@contextmanager
def _identity_map_write_lock(identity_map_path: Path) -> Iterator[None]:
    """Serialize one identity-map read/modify/write across threads and processes."""

    parent = identity_map_path.parent
    with _IDENTITY_MAP_LOCK:
        _initialize_identity_lock_file(parent)
        stream: BinaryIO | None = None
        msvcrt: Any | None = None
        unlock: int | None = None
        locked = False
        try:
            msvcrt = importlib.import_module("msvcrt")
            nonblocking_lock = int(msvcrt.LK_NBLCK)
            unlock = int(msvcrt.LK_UNLCK)
            guard = PathGuard(parent)
            stream = guard.open_scoped(_IDENTITY_LOCK_FILE, mode="r+b")
            deadline = time.monotonic() + _IDENTITY_LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), nonblocking_lock, 1)
                    locked = True
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise ClientCreationFailed from None
                    time.sleep(_IDENTITY_LOCK_RETRY_SECONDS)
            stream.seek(0)
            current = stream.read(2)
            if current == b"":
                stream.seek(0)
                if stream.write(_IDENTITY_LOCK_SENTINEL) != 1:
                    raise OSError
                stream.flush()
                os.fsync(stream.fileno())
                stream.seek(0)
                current = stream.read(2)
            if current != _IDENTITY_LOCK_SENTINEL:
                raise ClientCreationFailed
        except Exception:
            if stream is not None:
                try:
                    if locked and msvcrt is not None and unlock is not None:
                        stream.seek(0)
                        msvcrt.locking(stream.fileno(), unlock, 1)
                except OSError:
                    pass
                stream.close()
            raise ClientCreationFailed from None
        if stream is None:
            raise ClientCreationFailed
        try:
            yield
        finally:
            try:
                if locked and msvcrt is not None and unlock is not None:
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), unlock, 1)
            except OSError:
                raise ClientCreationFailed from None
            finally:
                stream.close()


def _nonempty_string(value: object) -> str:
    if type(value) is not str or not value:
        raise ClientCreationFailed
    return value


def _creation_draft_sha256(
    *,
    alias_lookup_sha256: str,
    client_id: str,
    diff_object_ref: VersionRef,
    directory_object_id: str,
) -> str:
    material = json.dumps(
        {
            "alias_lookup_sha256": alias_lookup_sha256,
            "client_id": client_id,
            "diff_object_ref": diff_object_ref.model_dump(mode="json"),
            "directory_object_id": directory_object_id,
        },
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()


@final
class ClientCreationService:
    def __init__(
        self,
        *,
        catalog: ClientCatalog,
        approval_service: ApprovalService,
        execution_guard: ApprovalExecutionGuard,
        protector: SecretProtector,
        acl_policy: DirectoryAclPolicy,
        clock: Clock,
        id_factory: IdFactory,
        client_id_factory: ClientIdFactory,
        clients_root: Path,
        identity_map_path: Path,
        vault_id: str,
        alias_lookup_secret: bytes,
        diff_ref_factory: DiffRefFactory,
        replace: ReplaceOperation = os.replace,
    ) -> None:
        if not isinstance(catalog, ClientCatalog):
            raise TypeError("client creation requires ClientCatalog")
        if not isinstance(approval_service, ApprovalService):
            raise TypeError("client creation requires ApprovalService")
        if not isinstance(execution_guard, ApprovalExecutionGuard):
            raise TypeError("client creation requires ApprovalExecutionGuard")
        if type(vault_id) is not str or not vault_id.strip():
            raise ValueError("client creation requires a vault ID")
        if type(alias_lookup_secret) is not bytes or len(alias_lookup_secret) < 32:
            raise ValueError("alias lookup secret must contain at least 256 bits")
        root = Path(clients_root)
        identity_path = Path(identity_map_path)
        if (
            not root.is_absolute()
            or ".." in root.parts
            or not _safe_directory(root)
            or not identity_path.is_absolute()
            or ".." in identity_path.parts
            or identity_path.name != "identity-map.enc"
            or not _safe_directory(identity_path.parent)
        ):
            raise ClientCreationFailed
        try:
            with PathGuard(root).pin_root():
                pass
            with PathGuard(identity_path.parent).pin_root():
                pass
        except ScopePathDenied:
            raise ClientCreationFailed from None
        self._catalog = catalog
        self._approval_service = approval_service
        self._execution_guard = execution_guard
        self._protector = protector
        self._acl_policy = acl_policy
        self._clock = clock
        self._id_factory = id_factory
        self._client_id_factory = client_id_factory
        self._clients_root = root
        self._identity_map_path = identity_path
        self._vault_id = vault_id
        self._alias_lookup_secret = bytes(alias_lookup_secret)
        self._diff_ref_factory = diff_ref_factory
        self._replace = replace

    def _entry_from_json(
        self,
        alias_hash: object,
        value: object,
        *,
        schema_version: int,
    ) -> _IdentityEntry:
        expected_keys = {
            "alias",
            "alias_lookup_sha256",
            "client_id",
            "descriptor",
            "diff_object_ref",
            "directory_object_id",
            "empty_db_sha256",
            "operation_id",
            "request_id",
            "state",
        }
        if schema_version == 2:
            expected_keys.add("idempotency_key_sha256")
        if (
            type(alias_hash) is not str
            or _SHA256_RE.fullmatch(alias_hash) is None
            or type(value) is not dict
            or set(value) != expected_keys
            or value["alias_lookup_sha256"] != alias_hash
        ):
            raise ClientCreationFailed
        try:
            descriptor = DraftDescriptor.model_validate(value["descriptor"])
            diff_ref = VersionRef.model_validate(value["diff_object_ref"])
        except ValidationError:
            raise ClientCreationFailed from None
        state = value["state"]
        empty_hash = value["empty_db_sha256"]
        if (
            state not in {"PREVIEW", "STAGED", "STAGED_REAPPROVAL", "ACTIVE"}
            or (
                empty_hash is not None
                and (type(empty_hash) is not str or _SHA256_RE.fullmatch(empty_hash) is None)
            )
            or (state == "PREVIEW" and empty_hash is not None)
            or (
                state in {"STAGED", "STAGED_REAPPROVAL", "ACTIVE"}
                and empty_hash is None
            )
        ):
            raise ClientCreationFailed
        try:
            client_id = _valid_client_id(value["client_id"])
        except ClientNotFound:
            raise ClientCreationFailed from None
        alias = _nonempty_string(value["alias"])
        idempotency_key_sha256 = (
            None if schema_version == 1 else value["idempotency_key_sha256"]
        )
        directory_object_id = _nonempty_string(value["directory_object_id"])
        canonical_alias, lookup_alias = _canonical_alias(alias)
        if (
            alias != canonical_alias
            or (
                idempotency_key_sha256 is not None
                and (
                    type(idempotency_key_sha256) is not str
                    or _SHA256_RE.fullmatch(idempotency_key_sha256) is None
                )
            )
            or not hmac.compare_digest(self._alias_hash(lookup_alias), alias_hash)
            or descriptor.client_id != client_id
            or descriptor.purpose != "create_client"
            or descriptor.target_id != directory_object_id
            or descriptor.base_version != 0
            or descriptor.session_id is not None
            or not hmac.compare_digest(
                descriptor.draft_sha256,
                _creation_draft_sha256(
                    alias_lookup_sha256=alias_hash,
                    client_id=client_id,
                    diff_object_ref=diff_ref,
                    directory_object_id=directory_object_id,
                ),
            )
        ):
            raise ClientCreationFailed
        return _IdentityEntry(
            alias=alias,
            alias_lookup_sha256=alias_hash,
            client_id=client_id,
            directory_object_id=directory_object_id,
            operation_id=_nonempty_string(value["operation_id"]),
            request_id=_nonempty_string(value["request_id"]),
            idempotency_key_sha256=idempotency_key_sha256,
            descriptor=descriptor,
            diff_object_ref=diff_ref,
            state=cast(IdentityState, state),
            empty_db_sha256=empty_hash,
        )

    @staticmethod
    def _entry_json(entry: _IdentityEntry) -> dict[str, object]:
        return {
            "alias": entry.alias,
            "alias_lookup_sha256": entry.alias_lookup_sha256,
            "client_id": entry.client_id,
            "descriptor": entry.descriptor.model_dump(mode="json"),
            "diff_object_ref": entry.diff_object_ref.model_dump(mode="json"),
            "directory_object_id": entry.directory_object_id,
            "empty_db_sha256": entry.empty_db_sha256,
            "idempotency_key_sha256": entry.idempotency_key_sha256,
            "operation_id": entry.operation_id,
            "request_id": entry.request_id,
            "state": entry.state,
        }

    def _load_identity_entries(self) -> dict[str, _IdentityEntry]:
        try:
            guard = PathGuard(self._identity_map_path.parent)
            with guard.pin_root():
                if not self._identity_map_path.exists():
                    return {}
                with guard.open_scoped(
                    self._identity_map_path.name,
                    mode="rb",
                ) as identity_stream:
                    protected = identity_stream.read(_MAX_IDENTITY_MAP_BYTES + 1)
                if not protected or len(protected) > _MAX_IDENTITY_MAP_BYTES:
                    raise ClientCreationFailed
            plaintext = self._protector.unprotect(
                protected,
                purpose=_IDENTITY_PURPOSE,
                vault_id=self._vault_id,
            )
            payload = json.loads(plaintext)
        except Exception:
            raise ClientCreationFailed from None
        if (
            type(payload) is not dict
            or set(payload) != {"entries", "schema_version"}
            or type(payload["schema_version"]) is not int
            or payload["schema_version"] not in {1, _IDENTITY_SCHEMA_VERSION}
            or type(payload["entries"]) is not dict
        ):
            raise ClientCreationFailed
        schema_version = payload["schema_version"]
        return {
            alias_hash: self._entry_from_json(
                alias_hash,
                value,
                schema_version=schema_version,
            )
            for alias_hash, value in payload["entries"].items()
        }

    def _write_identity_entries(self, entries: dict[str, _IdentityEntry]) -> None:
        payload = {
            "entries": {
                key: self._entry_json(entries[key]) for key in sorted(entries)
            },
            "schema_version": _IDENTITY_SCHEMA_VERSION,
        }
        plaintext = json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        temporary = self._identity_map_path.with_name(
            f".{self._identity_map_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            protected = self._protector.protect(
                plaintext,
                purpose=_IDENTITY_PURPOSE,
                vault_id=self._vault_id,
            )
            if not protected or len(protected) > _MAX_IDENTITY_MAP_BYTES:
                raise ClientCreationFailed
            guard = PathGuard(self._identity_map_path.parent)
            with guard.pin_root():
                descriptor = os.open(
                    temporary,
                    os.O_CREAT
                    | os.O_EXCL
                    | os.O_WRONLY
                    | getattr(os, "O_BINARY", 0),
                    0o600,
                )
                try:
                    if os.write(descriptor, protected) != len(protected):
                        raise OSError
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.replace(temporary, self._identity_map_path)
                with guard.open_scoped(
                    self._identity_map_path.name,
                    mode="rb",
                ) as identity_stream:
                    written_hash = _hash_stream(identity_stream)
                if not hmac.compare_digest(
                    written_hash,
                    hashlib.sha256(protected).hexdigest(),
                ):
                    raise ClientCreationFailed
        except Exception:
            try:
                if temporary.exists():
                    temporary.unlink()
            except OSError:
                pass
            raise ClientCreationFailed from None

    @staticmethod
    def _exact_identity_entry_key(
        entries: dict[str, _IdentityEntry],
        *,
        client_id: str,
        alias_lookup_sha256: str,
        directory_object_id: str,
    ) -> str | None:
        relevant = tuple(
            (key, entry)
            for key, entry in entries.items()
            if entry.client_id == client_id
            or key == alias_lookup_sha256
            or entry.directory_object_id == directory_object_id
        )
        if not relevant:
            return None
        if len(relevant) != 1:
            raise ClientCreationFailed
        key, entry = relevant[0]
        if (
            key != alias_lookup_sha256
            or entry.alias_lookup_sha256 != alias_lookup_sha256
            or entry.client_id != client_id
            or entry.directory_object_id != directory_object_id
            or entry.state != "ACTIVE"
        ):
            raise ClientCreationFailed
        return key

    def _identity_map_ciphertext_sha256(self) -> str:
        try:
            guard = PathGuard(self._identity_map_path.parent)
            with guard.open_scoped(
                self._identity_map_path.name,
                mode="rb",
            ) as identity_stream:
                return _hash_stream(identity_stream)
        except Exception:
            raise ClientCreationFailed from None

    def has_exact_identity_entry(
        self,
        *,
        client_id: str,
        alias_lookup_sha256: str,
        directory_object_id: str,
    ) -> bool:
        """Read the encrypted map under its process lock and match one entry."""

        validated_client = _valid_client_id(client_id)
        validated_alias = _valid_sha256(alias_lookup_sha256)
        directory_id = _nonempty_string(directory_object_id)
        with _identity_map_write_lock(self._identity_map_path):
            entries = self._load_identity_entries()
            return (
                self._exact_identity_entry_key(
                    entries,
                    client_id=validated_client,
                    alias_lookup_sha256=validated_alias,
                    directory_object_id=directory_id,
                )
                is not None
            )

    def erase_exact_identity_entry(
        self,
        *,
        client_id: str,
        alias_lookup_sha256: str,
        directory_object_id: str,
        allow_absent: bool = False,
    ) -> IdentityMapEraseResult:
        """Atomically remove one exact identity entry, then decrypt and reread.

        The global catalog row is deliberately retained as a body-free audit
        proof and must already be ``RETIRED``.  ``allow_absent`` exists only for
        lifecycle crash replay after the client directory has been verified
        absent; callers cannot use it to weaken the exact-match checks for any
        remaining entry.
        """

        validated_client = _valid_client_id(client_id)
        validated_alias = _valid_sha256(alias_lookup_sha256)
        directory_id = _nonempty_string(directory_object_id)
        if type(allow_absent) is not bool:
            raise ClientCreationFailed
        record = self._catalog.get(validated_client)
        if (
            record.state != "RETIRED"
            or record.alias_lookup_sha256 != validated_alias
            or record.directory_object_id != directory_id
        ):
            raise ClientCreationFailed
        with _identity_map_write_lock(self._identity_map_path):
            entries = self._load_identity_entries()
            key = self._exact_identity_entry_key(
                entries,
                client_id=validated_client,
                alias_lookup_sha256=validated_alias,
                directory_object_id=directory_id,
            )
            if key is None:
                if not allow_absent:
                    raise ClientCreationFailed
                return IdentityMapEraseResult(
                    client_id=validated_client,
                    alias_lookup_sha256=validated_alias,
                    directory_object_id=directory_id,
                    entry_removed=False,
                    encrypted_map_sha256=self._identity_map_ciphertext_sha256(),
                )
            expected = dict(entries)
            del expected[key]
            self._write_identity_entries(expected)
            verified = self._load_identity_entries()
            if verified != expected or self._exact_identity_entry_key(
                verified,
                client_id=validated_client,
                alias_lookup_sha256=validated_alias,
                directory_object_id=directory_id,
            ) is not None:
                raise ClientCreationFailed
            return IdentityMapEraseResult(
                client_id=validated_client,
                alias_lookup_sha256=validated_alias,
                directory_object_id=directory_id,
                entry_removed=True,
                encrypted_map_sha256=self._identity_map_ciphertext_sha256(),
            )

    def _alias_hash(self, lookup_alias: str) -> str:
        return hmac.new(
            self._alias_lookup_secret,
            lookup_alias.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _new_client_id(self, entries: dict[str, _IdentityEntry]) -> str:
        used = {entry.client_id for entry in entries.values()}
        for _attempt in range(32):
            client_id = self._client_id_factory.new()
            if client_id in used or (self._clients_root / client_id).exists():
                continue
            try:
                self._catalog.get(client_id)
            except ClientNotFound:
                return client_id
        raise ClientCreationFailed

    @staticmethod
    def _preview_result(entry: _IdentityEntry) -> ClientCreationPreview:
        return ClientCreationPreview(
            request_id=entry.request_id,
            client_id=entry.client_id,
            directory_object_id=entry.directory_object_id,
            descriptor=entry.descriptor,
            diff_object_ref=entry.diff_object_ref,
        )

    @staticmethod
    def _validate_entry_request(
        entry: _IdentityEntry,
        request: ApprovalRequest,
    ) -> None:
        if (
            request.request_id != entry.request_id
            or request.descriptor != entry.descriptor
            or request.diff_object_ref != entry.diff_object_ref
        ):
            raise ClientCreationFailed

    def _ensure_preview_request(self, entry: _IdentityEntry) -> ApprovalRequest:
        try:
            request = self._approval_service.request(
                entry.descriptor,
                diff_object_ref=entry.diff_object_ref,
                request_id=entry.request_id,
            )
        except ApprovalError:
            raise
        except Exception:
            raise ClientCreationFailed from None
        self._validate_entry_request(entry, request)
        return request

    def _load_staged_request(self, entry: _IdentityEntry) -> ApprovalRequest:
        try:
            request = self._approval_service.get(entry.request_id)
        except ApprovalError:
            raise
        except Exception:
            raise ClientCreationFailed from None
        self._validate_entry_request(entry, request)
        return request

    def _renew_creation_request(
        self,
        entry: _IdentityEntry,
        entries: dict[str, _IdentityEntry],
        *,
        rotate_operation: bool,
    ) -> _IdentityEntry:
        renewed = _IdentityEntry(
            alias=entry.alias,
            alias_lookup_sha256=entry.alias_lookup_sha256,
            client_id=entry.client_id,
            directory_object_id=entry.directory_object_id,
            operation_id=(
                self._id_factory.object_id("create_client")
                if rotate_operation
                else entry.operation_id
            ),
            request_id=self._id_factory.object_id("approval_request"),
            idempotency_key_sha256=entry.idempotency_key_sha256,
            descriptor=entry.descriptor,
            diff_object_ref=entry.diff_object_ref,
            state=(
                "STAGED_REAPPROVAL"
                if entry.state in {"STAGED", "STAGED_REAPPROVAL"}
                else entry.state
            ),
            empty_db_sha256=entry.empty_db_sha256,
        )
        entries[entry.alias_lookup_sha256] = renewed
        # Persist the exact reserved request ID before crossing into the global
        # approval store.  A crash after this point is repaired by the same-key
        # retry through ApprovalService.request's exact-ID idempotency.
        self._write_identity_entries(entries)
        self._ensure_preview_request(renewed)
        return renewed

    def _binding_state(self, entry: _IdentityEntry) -> tuple[bool, str | None]:
        try:
            is_bound = self._approval_service.has_execution_binding(
                entry.request_id,
                entry.descriptor,
            )
            bound_unapplied_operation = self._approval_service.bound_operation_id(
                entry.request_id,
                entry.descriptor,
            )
        except ApprovalError:
            raise
        except Exception:
            raise ClientCreationFailed from None
        if (
            (bound_unapplied_operation is not None and not is_bound)
            or (
                bound_unapplied_operation is not None
                and bound_unapplied_operation != entry.operation_id
            )
        ):
            raise ClientCreationFailed
        return is_bound, bound_unapplied_operation

    def preview(self, *, alias: str, idempotency_key: str) -> ClientCreationPreview:
        canonical_alias, lookup_alias = _canonical_alias(alias)
        alias_hash = self._alias_hash(lookup_alias)
        idempotency_hash = _idempotency_key_sha256(idempotency_key)
        with _identity_map_write_lock(self._identity_map_path):
            entries = self._load_identity_entries()
            if any(
                entry.alias_lookup_sha256 != alias_hash
                and entry.idempotency_key_sha256 is not None
                and hmac.compare_digest(
                    entry.idempotency_key_sha256,
                    idempotency_hash,
                )
                for entry in entries.values()
            ):
                raise DuplicateClientAlias
            existing = entries.get(alias_hash)
            if existing is not None:
                if (
                    existing.state == "ACTIVE"
                    or existing.idempotency_key_sha256 is None
                    or not hmac.compare_digest(
                        existing.idempotency_key_sha256,
                        idempotency_hash,
                    )
                ):
                    raise DuplicateClientAlias
                request = (
                    self._load_staged_request(existing)
                    if existing.state == "STAGED"
                    else self._ensure_preview_request(existing)
                )
                is_bound, bound_unapplied_operation = self._binding_state(existing)
                if existing.state == "STAGED" and not is_bound:
                    raise ClientCreationFailed
                if request.state == "acknowledged":
                    raise ClientCreationFailed
                needs_renewal = (
                    request.state == "rejected"
                    or self._clock.now() >= request.expires_at
                )
                if not needs_renewal:
                    return self._preview_result(existing)
                if is_bound and bound_unapplied_operation is None:
                    # The target transaction is already APPLIED. Its original
                    # receipt remains the only authority for exact replay even
                    # after TTL; silently renewing would break one-shot binding.
                    return self._preview_result(existing)
                existing = self._renew_creation_request(
                    existing,
                    entries,
                    rotate_operation=bound_unapplied_operation is not None,
                )
                return self._preview_result(existing)

            if self._catalog.find_by_alias_hash(alias_hash):
                raise DuplicateClientAlias
            client_id = self._new_client_id(entries)
            directory_object_id = self._id_factory.object_id("client_directory")
            operation_id = self._id_factory.object_id("create_client")
            request_id = self._id_factory.object_id("approval_request")
            try:
                diff_ref = VersionRef.model_validate(
                    self._diff_ref_factory(canonical_alias, client_id)
                )
            except (TypeError, ValueError, ValidationError):
                raise ClientCreationFailed from None
            descriptor = DraftDescriptor(
                purpose="create_client",
                target_id=directory_object_id,
                client_id=client_id,
                base_version=0,
                draft_sha256=_creation_draft_sha256(
                    alias_lookup_sha256=alias_hash,
                    client_id=client_id,
                    diff_object_ref=diff_ref,
                    directory_object_id=directory_object_id,
                ),
                session_id=None,
            )
            entry = _IdentityEntry(
                alias=canonical_alias,
                alias_lookup_sha256=alias_hash,
                client_id=client_id,
                directory_object_id=directory_object_id,
                operation_id=operation_id,
                request_id=request_id,
                idempotency_key_sha256=idempotency_hash,
                descriptor=descriptor,
                diff_object_ref=diff_ref,
                state="PREVIEW",
            )
            entries[alias_hash] = entry
            # The encrypted creation intent is the durable owner of every
            # allocated identifier.  Only after it is safely replaced do we
            # create the cross-store approval row with the reserved ID.
            self._write_identity_entries(entries)
            self._ensure_preview_request(entry)
            return self._preview_result(entry)

    @staticmethod
    def _entry_for_request(
        entries: dict[str, _IdentityEntry],
        request_id: str,
    ) -> _IdentityEntry:
        matches = [entry for entry in entries.values() if entry.request_id == request_id]
        if len(matches) != 1:
            raise ClientCreationFailed
        return matches[0]

    def _scope_paths(self, entry: _IdentityEntry) -> tuple[Path, Path, Path]:
        staging_root = self._clients_root / ".staging"
        return (
            staging_root,
            staging_root / entry.client_id,
            self._clients_root / entry.client_id,
        )

    @staticmethod
    def _safe_cleanup(path: Path, staging_root: Path) -> None:
        """Intentionally retain a failed staged scope for retry/recovery.

        A residual may contain the scope marker and migrated empty database; it
        is never active or worker-visible. Safe recursive removal requires an
        authority-preserving delete primitive, not a resolve-then-delete path
        check. Retention is therefore safer than following a swapped staging
        junction and is reconciled by deterministic retry or later recovery.
        """
        del path, staging_root

    def _create_staged_scope(
        self,
        entry: _IdentityEntry,
        entries: dict[str, _IdentityEntry],
    ) -> _IdentityEntry:
        staging_root, temporary, _final = self._scope_paths(entry)
        relative_scope = Path(".staging") / entry.client_id
        try:
            guard = PathGuard(self._clients_root)
            with guard.pin_root():
                staging_root.mkdir(exist_ok=True)
            with guard.pin_scoped_directory(Path(".staging")):
                created = not temporary.exists()
                if created:
                    temporary.mkdir()
            with guard.pin_scoped_directory(relative_scope):
                if created:
                    marker = temporary / _SCOPE_MARKER
                    with marker.open(
                        "x",
                        encoding="ascii",
                        newline="\n",
                    ) as stream:
                        stream.write(f"{entry.directory_object_id}\n")
                        stream.flush()
                        os.fsync(stream.fileno())
                    connection = connect_database(
                        temporary / _CLIENT_DATABASE,
                        mode="writer",
                    )
                    try:
                        MigrationRunner.for_scope(
                            connection,
                            "client",
                        ).apply()
                        MigrationRunner.for_scope(
                            connection,
                            "client",
                        ).check()
                    finally:
                        connection.close()
                    self._acl_policy.apply(temporary)
            database_hash = self._inspect_scope_directory(
                temporary,
                relative_scope=relative_scope,
                entry=entry,
                expected_database_sha256=None,
            )
            staged = _IdentityEntry(
                alias=entry.alias,
                alias_lookup_sha256=entry.alias_lookup_sha256,
                client_id=entry.client_id,
                directory_object_id=entry.directory_object_id,
                operation_id=entry.operation_id,
                request_id=entry.request_id,
                idempotency_key_sha256=entry.idempotency_key_sha256,
                descriptor=entry.descriptor,
                diff_object_ref=entry.diff_object_ref,
                state="STAGED",
                empty_db_sha256=database_hash,
            )
            entries[entry.alias_lookup_sha256] = staged
            self._write_identity_entries(entries)
            return staged
        except ClientCreationFailed:
            raise
        except Exception:
            raise ClientCreationFailed from None

    def _inspect_scope_directory(
        self,
        path: Path,
        *,
        relative_scope: Path,
        entry: _IdentityEntry,
        expected_database_sha256: str | None,
    ) -> str:
        expected_marker = f"{entry.directory_object_id}\n".encode("ascii")
        guard = PathGuard(self._clients_root)
        try:
            with guard.pin_scoped_directory(relative_scope):
                with guard.open_scoped(
                    relative_scope / _SCOPE_MARKER,
                    mode="rb",
                ) as marker_stream:
                    marker = marker_stream.read(_MAX_SCOPE_MARKER_BYTES + 1)
                    if not hmac.compare_digest(marker, expected_marker):
                        raise ClientCreationFailed
                    with guard.open_scoped(
                        relative_scope / _CLIENT_DATABASE,
                        mode="rb",
                    ) as database_stream:
                        database_hash = _hash_stream(database_stream)
                        if expected_database_sha256 is not None and not (
                            hmac.compare_digest(
                                database_hash,
                                expected_database_sha256,
                            )
                        ):
                            raise ClientCreationFailed
                        database = path / _CLIENT_DATABASE
                        connection = connect_database_snapshot(database)
                        try:
                            MigrationRunner.for_scope(
                                connection,
                                "client",
                            ).check()
                        finally:
                            connection.close()
                        if not hmac.compare_digest(
                            _hash_stream(database_stream),
                            database_hash,
                        ):
                            raise ClientCreationFailed
                        self._acl_policy.verify(path)
            return database_hash
        except (OSError, ScopePathDenied, UnicodeError):
            raise ClientCreationFailed from None

    def _validate_scope_directory(self, path: Path, entry: _IdentityEntry) -> None:
        if entry.empty_db_sha256 is None:
            raise ClientCreationFailed
        _staging_root, temporary, final = self._scope_paths(entry)
        if path == temporary:
            relative_scope = Path(".staging") / entry.client_id
        elif path == final:
            relative_scope = Path(entry.client_id)
        else:
            raise ClientCreationFailed
        self._inspect_scope_directory(
            path,
            relative_scope=relative_scope,
            entry=entry,
            expected_database_sha256=entry.empty_db_sha256,
        )

    def _finalize_scope(self, entry: _IdentityEntry) -> None:
        staging_root, temporary, final = self._scope_paths(entry)
        if final.exists():
            self._validate_scope_directory(final, entry)
            if temporary.exists():
                self._safe_cleanup(temporary, staging_root)
            return
        if not temporary.exists():
            raise ClientCreationFailed
        self._validate_scope_directory(temporary, entry)
        try:
            guard = PathGuard(self._clients_root)
            with guard.pin_scoped_directory(Path(".staging")):
                self._replace(temporary, final)
        except Exception:
            raise ClientCreationFailed from None
        self._validate_scope_directory(final, entry)

    def commit(self, request_id: str) -> ClientRecord:
        validated_request = _nonempty_string(request_id)
        with _identity_map_write_lock(self._identity_map_path):
            entries = self._load_identity_entries()
            entry = self._entry_for_request(entries, validated_request)
            ticket = self._approval_service.issue_for_execution(
                entry.request_id,
                entry.descriptor,
                operation_id=entry.operation_id,
            )
            staging_root, temporary, _final = self._scope_paths(entry)
            prepared_committed = False
            try:
                if entry.state == "PREVIEW":
                    entry = self._create_staged_scope(entry, entries)
                elif (
                    entry.state not in {"STAGED", "STAGED_REAPPROVAL"}
                    or entry.empty_db_sha256 is None
                ):
                    raise ClientCreationFailed

                def prepare_catalog(_connection: sqlite3.Connection) -> None:
                    self._catalog.prepare_in_transaction(
                        client_id=entry.client_id,
                        directory_object_id=entry.directory_object_id,
                        alias_lookup_sha256=entry.alias_lookup_sha256,
                        created_at=self._clock.now(),
                    )

                execution = self._execution_guard.apply_in_transaction(
                    ticket,
                    entry.descriptor,
                    prepare_catalog,
                )
                prepared_committed = True
                self._finalize_scope(entry)
                record = self._catalog.activate(
                    entry.client_id,
                    activated_at=self._clock.now(),
                )
                active_entry = _IdentityEntry(
                    alias=entry.alias,
                    alias_lookup_sha256=entry.alias_lookup_sha256,
                    client_id=entry.client_id,
                    directory_object_id=entry.directory_object_id,
                    operation_id=entry.operation_id,
                    request_id=entry.request_id,
                    idempotency_key_sha256=entry.idempotency_key_sha256,
                    descriptor=entry.descriptor,
                    diff_object_ref=entry.diff_object_ref,
                    state="ACTIVE",
                    empty_db_sha256=entry.empty_db_sha256,
                )
                entries[entry.alias_lookup_sha256] = active_entry
                self._write_identity_entries(entries)
                self._approval_service.acknowledge(execution)
                return record
            except ClientCatalogConflict:
                duplicate = self._catalog.find_by_alias_hash(
                    entry.alias_lookup_sha256
                )
                if duplicate is not None and duplicate.client_id != entry.client_id:
                    if not prepared_committed:
                        self._safe_cleanup(temporary, staging_root)
                    raise DuplicateClientAlias from None
                raise
            except ClientCreationFailed:
                if not prepared_committed:
                    self._safe_cleanup(temporary, staging_root)
                raise
            except Exception:
                if not prepared_committed:
                    self._safe_cleanup(temporary, staging_root)
                raise ClientCreationFailed from None


__all__ = [
    "ClientCatalog",
    "ClientCatalogConflict",
    "ClientCatalogError",
    "ClientCreationFailed",
    "ClientCreationPreview",
    "ClientCreationService",
    "ClientNotFound",
    "ClientRecord",
    "DuplicateClientAlias",
    "IdentityMapEraseResult",
]
