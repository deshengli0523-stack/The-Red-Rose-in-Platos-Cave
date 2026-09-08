"""Reproducible minimum client context snapshots for one consultation."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any, Literal

from pydantic import field_validator, model_validator

from consultation_kb.models.common import (
    ClientId,
    NonEmptyStr,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    VersionRef,
)
from consultation_kb.models.profile import ProfileItem, ProfileSnapshot
from consultation_kb.vault.content_store import ContentStore


class ClientContextError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("CLIENT_CONTEXT_INVALID")


def _json_value(value: object) -> object:
    if isinstance(value, StrictModel):
        return value.model_dump(mode="json")
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError("client context contains a non-JSON value")


def client_context_sha256(payload: object) -> str:
    encoded = (
        json.dumps(
            _json_value(payload),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class ClientContextSnapshot(StrictModel):
    schema_version: Literal["client_context.v1"] = "client_context.v1"
    client_id: ClientId
    profile_revision_id: NonEmptyStr | None
    profile_version: int
    profile_sha256: Sha256Hex | None
    fixed_epoch: int
    profile: ProfileSnapshot | None
    recent_session_summary_refs: tuple[VersionRef, ...]
    unresolved_items: tuple[ProfileItem, ...]
    goals: tuple[ProfileItem, ...]
    preferences: tuple[ProfileItem, ...]
    constraints: tuple[ProfileItem, ...]
    key_facts: tuple[ProfileItem, ...]
    review_items: tuple[ProfileItem, ...]
    created_at: UtcDateTime
    canonical_sha256: Sha256Hex

    @field_validator("profile_version", "fixed_epoch")
    @classmethod
    def _nonnegative_version(cls, value: int) -> int:
        if type(value) is not int or value < 0:
            raise ValueError("context versions must be non-negative integers")
        return value

    @model_validator(mode="after")
    def _snapshot_contract(self) -> "ClientContextSnapshot":
        expected = client_context_sha256(
            self.model_dump(mode="json", exclude={"canonical_sha256"})
        )
        if expected != self.canonical_sha256:
            raise ValueError("client context hash mismatch")
        if self.profile is None:
            if (
                self.profile_revision_id is not None
                or self.profile_sha256 is not None
                or self.profile_version != 0
                or self.fixed_epoch != 0
                or any(
                    (
                        self.unresolved_items,
                        self.goals,
                        self.preferences,
                        self.constraints,
                        self.key_facts,
                        self.review_items,
                    )
                )
            ):
                raise ValueError("empty client context has inconsistent profile fields")
        elif (
            self.profile_revision_id is None
            or self.profile_sha256 != self.profile.canonical_sha256
            or self.profile_version != self.profile.source_client_commit_version
            or self.fixed_epoch != self.profile.fixed_epoch
        ):
            raise ValueError("profile context binding mismatch")
        return self

    def canonical_bytes(self) -> bytes:
        return (
            json.dumps(
                self.model_dump(mode="json"),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")


class ClientContextBuilder:
    """Read only the latest active profile and materialize a minimum snapshot."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        content_store: ContentStore,
        now: Callable[[], datetime],
        recent_summary_refs: Callable[[str], tuple[VersionRef, ...]] | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("ClientContextBuilder requires sqlite3.Connection")
        self._connection = connection
        self._content_store = content_store
        self._now = now
        self._recent_summary_refs = recent_summary_refs or (lambda _client_id: ())

    def build(self, client_id: str) -> ClientContextSnapshot:
        row = self._connection.execute(
            """
            SELECT pr.revision_id, pr.source_commit_version,
                   pr.visible_runtime_epoch, pr.profile_sha256,
                   am.object_sha256, am.media_type, am.size_bytes
              FROM profile_revisions pr
              JOIN artifact_manifests manifest
                ON manifest.operation_id = pr.publication_operation_id
               AND manifest.state = 'ACTIVE' AND manifest.verified = 1
              JOIN artifact_members am
                ON am.manifest_id = manifest.manifest_id
               AND am.object_id = pr.json_object_id
             ORDER BY pr.source_commit_version DESC,
                      pr.visible_runtime_epoch DESC, pr.revision_id DESC
             LIMIT 1
            """
        ).fetchone()
        recent = self._recent_summary_refs(client_id)
        if row is None:
            payload: dict[str, Any] = {
                "schema_version": "client_context.v1",
                "client_id": client_id,
                "profile_revision_id": None,
                "profile_version": 0,
                "profile_sha256": None,
                "fixed_epoch": 0,
                "profile": None,
                "recent_session_summary_refs": recent,
                "unresolved_items": (),
                "goals": (),
                "preferences": (),
                "constraints": (),
                "key_facts": (),
                "review_items": (),
                "created_at": self._now(),
            }
            return ClientContextSnapshot(
                **payload,
                canonical_sha256=client_context_sha256(payload),
            )
        if len(row) != 7:
            raise ClientContextError
        try:
            reference = self._content_store.reference(
                content_sha256=str(row[4]),
                media_type=str(row[5]),
                size_bytes=int(row[6]),
            )
            profile = ProfileSnapshot.model_validate_json(
                self._content_store.read_verified(reference)
            )
        except Exception:
            raise ClientContextError from None
        if (
            row[1] != profile.source_client_commit_version
            or row[2] != profile.fixed_epoch
            or row[3] != profile.canonical_sha256
        ):
            raise ClientContextError
        sections = {section.name: section.items for section in profile.sections}
        key_facts = tuple(
            item
            for name in ("relationships", "active_facts")
            for item in sections.get(name, ())
        )
        review_items = tuple(
            item
            for name in ("uncertainty_disputes", "pending_review")
            for item in sections.get(name, ())
        )
        payload = {
            "schema_version": "client_context.v1",
            "client_id": client_id,
            "profile_revision_id": row[0],
            "profile_version": profile.source_client_commit_version,
            "profile_sha256": profile.canonical_sha256,
            "fixed_epoch": profile.fixed_epoch,
            "profile": profile,
            "recent_session_summary_refs": recent,
            "unresolved_items": sections.get("unresolved_issues", ()),
            "goals": sections.get("goals", ()),
            "preferences": sections.get("preferences", ()),
            "constraints": sections.get("constraints", ()),
            "key_facts": key_facts,
            "review_items": review_items,
            "created_at": self._now(),
        }
        return ClientContextSnapshot(
            **payload,
            canonical_sha256=client_context_sha256(payload),
        )


__all__ = [
    "ClientContextBuilder",
    "ClientContextError",
    "ClientContextSnapshot",
    "client_context_sha256",
]
