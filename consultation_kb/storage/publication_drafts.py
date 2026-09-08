"""Layer-neutral immutable drafts for CAS-backed artifact publication.

The retrieval package builds these values while the lifecycle package consumes
them.  Keeping the contracts in storage prevents a retrieval-to-lifecycle
dependency that would otherwise form a package cycle once rebuild imports the
real retrieval builders.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from consultation_kb.storage.tombstones import ObjectIdentity


_SAFE_KEY_RE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z")
_CLIENT_ID_RE = re.compile(r"client_[a-z0-9]{12}")
_OBJECT_ID_RE = re.compile(
    r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*_"
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_MEDIA_TYPE_RE = re.compile(
    r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*\Z"
)


class PublicationError(RuntimeError):
    """Base class for fixed-code publication failures."""


class PublicationIntegrityError(PublicationError):
    def __init__(self) -> None:
        super().__init__("PUBLICATION_INTEGRITY_ERROR")


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


@dataclass(frozen=True, slots=True)
class ContentDraft:
    object_type: str
    object_id: str
    data: bytes
    source_version: int
    media_type: str
    source_lineage: tuple[ObjectIdentity, ...]

    def __post_init__(self) -> None:
        _object_type(self.object_type, self.object_id)
        _object_id(self.object_id)
        if type(self.data) is not bytes:
            raise PublicationIntegrityError
        _positive(self.source_version)
        _media_type(self.media_type)
        if type(self.source_lineage) is not tuple or any(
            type(source) is not ObjectIdentity for source in self.source_lineage
        ):
            raise PublicationIntegrityError


@dataclass(frozen=True, slots=True)
class ArtifactDraft:
    manifest_id: str
    artifact_key: str
    artifact_kind: str
    source_version: int
    members: tuple[ContentDraft, ...]

    def __post_init__(self) -> None:
        _object_id(self.manifest_id)
        _safe_key(self.artifact_key)
        _safe_key(self.artifact_kind)
        _positive(self.source_version)
        if not self.members or any(
            type(member) is not ContentDraft for member in self.members
        ):
            raise PublicationIntegrityError
        if len({member.object_id for member in self.members}) != len(self.members):
            raise PublicationIntegrityError
        if any(member.source_version != self.source_version for member in self.members):
            raise PublicationIntegrityError


__all__ = [
    "ArtifactDraft",
    "ContentDraft",
    "PublicationError",
    "PublicationIntegrityError",
]
