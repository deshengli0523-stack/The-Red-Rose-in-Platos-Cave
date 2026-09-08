"""Scope-local immutable content-addressed storage.

The store deliberately has no global lookup or cross-scope deduplication API.
References are bound to the exact resolved scope that created them and every
read re-hashes the payload before returning bytes.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Literal, final

from consultation_kb.security.path_guard import PathGuard, ScopePathDenied


_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_COMPONENT_RE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z")
_CLIENT_ID_RE = re.compile(r"client_[a-z0-9]{12}")
_OBJECT_ID_RE = re.compile(
    r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*_"
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_MEDIA_TYPE_RE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*\Z")
_REPARSE_ATTRIBUTE = 0x400


class ContentStoreError(RuntimeError):
    """Base class for fixed-code content-store failures."""


class ContentHashMismatch(ContentStoreError):
    """The immutable payload does not match its declared address."""

    def __init__(self) -> None:
        super().__init__("CONTENT_HASH_MISMATCH")


class ContentScopeMismatch(ContentStoreError):
    """A reference was produced by another physical scope."""

    def __init__(self) -> None:
        super().__init__("CONTENT_SCOPE_MISMATCH")


class InvalidContentReference(ContentStoreError):
    """A content reference or staging request is structurally invalid."""

    def __init__(self) -> None:
        super().__init__("CONTENT_REFERENCE_INVALID")


DirectorySyncResult = Literal["completed", "unsupported"]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _scope_binding(scope_root: Path) -> str:
    encoded = os.path.normcase(str(scope_root)).encode("utf-8", errors="strict")
    return hashlib.sha256(b"consultation-kb-scope-v1\0" + encoded).hexdigest()


def _require_exact_path(value: Path) -> Path:
    if not isinstance(value, Path):
        raise TypeError("CONTENT_SCOPE_PATH_REQUIRED")
    try:
        absolute = Path(os.path.abspath(value))
    except (OSError, ValueError):
        raise InvalidContentReference from None
    if not absolute.is_absolute():
        raise InvalidContentReference
    return absolute


def _require_component(value: str, *, object_id: bool = False) -> str:
    if type(value) is not str:
        raise TypeError("CONTENT_COMPONENT_STRING_REQUIRED")
    pattern = _OBJECT_ID_RE if object_id else _SAFE_COMPONENT_RE
    maximum = 101 if object_id else 64
    if (
        not 1 <= len(value) <= maximum
        or pattern.fullmatch(value) is None
        or _CLIENT_ID_RE.search(value) is not None
    ):
        raise InvalidContentReference
    return value


def _require_media_type(value: str) -> str:
    if type(value) is not str:
        raise TypeError("CONTENT_MEDIA_TYPE_STRING_REQUIRED")
    if not 3 <= len(value) <= 127 or _MEDIA_TYPE_RE.fullmatch(value) is None:
        raise InvalidContentReference
    return value


def _sync_directory(path: Path) -> DirectorySyncResult:
    """Best-effort directory fsync with an explicit platform result.

    CPython on Windows cannot normally open a directory through ``os.open``.
    We therefore report ``unsupported`` instead of claiming durability that the
    platform did not provide. Payload files themselves are always fsynced.
    """

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(path, flags)
    except (OSError, NotImplementedError):
        return "unsupported"
    try:
        os.fsync(descriptor)
    except (OSError, NotImplementedError):
        return "unsupported"
    finally:
        os.close(descriptor)
    return "completed"


def _is_reparse(status: os.stat_result) -> bool:
    attributes = int(getattr(status, "st_file_attributes", 0))
    return stat.S_ISLNK(status.st_mode) or bool(attributes & _REPARSE_ATTRIBUTE)


def _validate_directory(path: Path) -> None:
    try:
        status = os.lstat(path)
    except OSError:
        raise InvalidContentReference from None
    if not stat.S_ISDIR(status.st_mode) or _is_reparse(status):
        raise InvalidContentReference


@contextmanager
def _pinned_directory_chains(
    scope_root: Path,
    *directories: Path,
) -> Iterator[None]:
    """Create and pin one or more directory chains under one root handle."""

    if not directories:
        raise InvalidContentReference
    try:
        relatives = tuple(
            directory.relative_to(scope_root) for directory in directories
        )
    except ValueError:
        raise InvalidContentReference from None
    try:
        scope_root.mkdir(exist_ok=True)
    except OSError:
        raise InvalidContentReference from None
    _validate_directory(scope_root)
    try:
        with PathGuard(scope_root).pin_scoped_directories(
            relatives,
            create_missing=True,
        ):
            yield
    except ScopePathDenied:
        raise InvalidContentReference from None


def _validate_regular_object(path: Path) -> None:
    """Require a single-name, non-reparse regular file after a CAS write."""

    try:
        status = os.lstat(path)
    except OSError:
        raise ContentHashMismatch from None
    if (
        not stat.S_ISREG(status.st_mode)
        or _is_reparse(status)
        or int(status.st_nlink) != 1
    ):
        raise ContentHashMismatch


@final
class StagedContent:
    """Internal scope-bound handle for one fsynced staging payload."""

    __slots__ = (
        "_path",
        "_scope_binding",
        "content_sha256",
        "directory_sync",
        "media_type",
        "size_bytes",
    )
    _path: Path
    _scope_binding: str
    content_sha256: str
    directory_sync: DirectorySyncResult
    media_type: str
    size_bytes: int

    def __init__(
        self,
        *,
        path: Path,
        scope_binding: str,
        content_sha256: str,
        media_type: str,
        size_bytes: int,
        directory_sync: DirectorySyncResult,
    ) -> None:
        object.__setattr__(self, "_path", path)
        object.__setattr__(self, "_scope_binding", scope_binding)
        object.__setattr__(self, "content_sha256", content_sha256)
        object.__setattr__(self, "media_type", media_type)
        object.__setattr__(self, "size_bytes", size_bytes)
        object.__setattr__(self, "directory_sync", directory_sync)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("STAGED_CONTENT_FROZEN")

    def __repr__(self) -> str:
        return (
            "StagedContent(content_sha256="
            f"{self.content_sha256!r}, size_bytes={self.size_bytes!r}, "
            f"media_type={self.media_type!r}, directory_sync={self.directory_sync!r})"
        )


@final
class ContentObjectRef:
    """Internal reference to one immutable object.

    This is intentionally not a Pydantic model and has no serialization
    method, preventing its private filesystem path from entering Tool schemas.
    """

    __slots__ = (
        "_path",
        "_scope_binding",
        "content_sha256",
        "directory_sync",
        "media_type",
        "size_bytes",
    )
    _path: Path
    _scope_binding: str
    content_sha256: str
    directory_sync: DirectorySyncResult
    media_type: str
    size_bytes: int

    def __init__(
        self,
        *,
        path: Path,
        scope_binding: str,
        content_sha256: str,
        media_type: str,
        size_bytes: int,
        directory_sync: DirectorySyncResult,
    ) -> None:
        object.__setattr__(self, "_path", path)
        object.__setattr__(self, "_scope_binding", scope_binding)
        object.__setattr__(self, "content_sha256", content_sha256)
        object.__setattr__(self, "media_type", media_type)
        object.__setattr__(self, "size_bytes", size_bytes)
        object.__setattr__(self, "directory_sync", directory_sync)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("CONTENT_OBJECT_REF_FROZEN")

    @property
    def path(self) -> Path:
        """Internal-only path for storage adapters and integrity tests."""

        return self._path

    def __repr__(self) -> str:
        return (
            "ContentObjectRef(content_sha256="
            f"{self.content_sha256!r}, size_bytes={self.size_bytes!r}, "
            f"media_type={self.media_type!r}, directory_sync={self.directory_sync!r})"
        )


class ContentStore:
    """Immutable CAS rooted inside exactly one broker-approved scope."""

    def __init__(
        self,
        scope_root: Path,
        *,
        write_hook: Callable[[str, Path], None] | None = None,
    ) -> None:
        self._scope_root = _require_exact_path(scope_root)
        self._binding = _scope_binding(self._scope_root)
        self._write_hook = write_hook

    def _before_replace(self, phase: str, directory: Path) -> None:
        if self._write_hook is not None:
            self._write_hook(phase, directory)

    def _object_path(self, content_sha256: str) -> Path:
        if _SHA256_RE.fullmatch(content_sha256) is None:
            raise InvalidContentReference
        return (
            self._scope_root
            / "objects"
            / "sha256"
            / content_sha256[:2]
            / content_sha256
            / "payload"
        )

    def _read_scoped(self, path: Path) -> bytes:
        """Read only through the exact handle whose final path was verified."""

        try:
            relative = path.relative_to(self._scope_root)
            with PathGuard(self._scope_root).open_scoped(relative, mode="rb") as stream:
                return stream.read()
        except (OSError, ScopePathDenied, ValueError):
            raise ContentHashMismatch from None

    def stage_bytes(
        self,
        data: bytes,
        *,
        purpose: str,
        manifest_id: str,
        media_type: str,
    ) -> StagedContent:
        if type(data) is not bytes:
            raise TypeError("CONTENT_BYTES_REQUIRED")
        safe_purpose = _require_component(purpose)
        safe_manifest_id = _require_component(manifest_id, object_id=True)
        safe_media_type = _require_media_type(media_type)
        digest = _sha256(data)
        staging_directory = (
            self._scope_root / ".staging" / safe_purpose / safe_manifest_id / digest
        )
        temporary = staging_directory / f"payload.{secrets.token_hex(16)}.tmp"
        staged_path = staging_directory / "payload.stage"
        with _pinned_directory_chains(self._scope_root, staging_directory):
            try:
                with temporary.open("xb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                _validate_regular_object(temporary)
                self._before_replace("stage", staging_directory)
                os.replace(temporary, staged_path)
                _validate_regular_object(staged_path)
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
            directory_sync = _sync_directory(staging_directory)
        return StagedContent(
            path=staged_path,
            scope_binding=self._binding,
            content_sha256=digest,
            media_type=safe_media_type,
            size_bytes=len(data),
            directory_sync=directory_sync,
        )

    def finalize(self, staged: StagedContent) -> ContentObjectRef:
        if type(staged) is not StagedContent:
            raise TypeError("STAGED_CONTENT_REQUIRED")
        if staged._scope_binding != self._binding:
            raise ContentScopeMismatch
        final_path = self._object_path(staged.content_sha256)
        final_directory = final_path.parent
        with _pinned_directory_chains(
            self._scope_root,
            staged._path.parent,
            final_directory,
        ):
            payload = self._read_scoped(staged._path)
            if (
                len(payload) != staged.size_bytes
                or _sha256(payload) != staged.content_sha256
            ):
                raise ContentHashMismatch
            try:
                os.lstat(final_path)
            except FileNotFoundError:
                self._before_replace("finalize", final_directory)
                os.replace(staged._path, final_path)
                _validate_regular_object(final_path)
                written = self._read_scoped(final_path)
                if (
                    len(written) != staged.size_bytes
                    or _sha256(written) != staged.content_sha256
                ):
                    raise ContentHashMismatch
            except OSError:
                raise ContentHashMismatch from None
            else:
                existing = self._read_scoped(final_path)
                if (
                    len(existing) != staged.size_bytes
                    or _sha256(existing) != staged.content_sha256
                ):
                    raise ContentHashMismatch
                staged._path.unlink(missing_ok=True)
            directory_sync = _sync_directory(final_directory)
        return ContentObjectRef(
            path=final_path,
            scope_binding=self._binding,
            content_sha256=staged.content_sha256,
            media_type=staged.media_type,
            size_bytes=staged.size_bytes,
            directory_sync=directory_sync,
        )

    def reference(
        self,
        *,
        content_sha256: str,
        media_type: str,
        size_bytes: int,
    ) -> ContentObjectRef:
        """Reconstitute an internal reference from verified manifest metadata."""

        if type(size_bytes) is not int or size_bytes < 0:
            raise InvalidContentReference
        path = self._object_path(content_sha256)
        return ContentObjectRef(
            path=path,
            scope_binding=self._binding,
            content_sha256=content_sha256,
            media_type=_require_media_type(media_type),
            size_bytes=size_bytes,
            directory_sync="unsupported",
        )

    def assert_reference_scope(self, reference: ContentObjectRef) -> None:
        """Validate an opaque reference without touching the filesystem."""

        if type(reference) is not ContentObjectRef:
            raise TypeError("CONTENT_OBJECT_REF_REQUIRED")
        expected_path = self._object_path(reference.content_sha256)
        if (
            reference._scope_binding != self._binding
            or reference._path != expected_path
        ):
            raise ContentScopeMismatch

    def read_verified(self, reference: ContentObjectRef) -> bytes:
        self.assert_reference_scope(reference)
        payload = self.read_hash_verified(reference.content_sha256)
        if len(payload) != reference.size_bytes:
            raise ContentHashMismatch
        return payload

    def read_hash_verified(self, content_sha256: str) -> bytes:
        """Read one scope-local CAS object using only its verified address."""

        digest = content_sha256
        if type(digest) is not str or _SHA256_RE.fullmatch(digest) is None:
            raise InvalidContentReference
        payload = self._read_scoped(self._object_path(digest))
        if _sha256(payload) != digest:
            raise ContentHashMismatch
        return payload
