"""Canonical multi-member payloads for production rebuild artifacts.

The rebuild coordinator historically accepted a single opaque byte string per
builder.  Production retrieval and client-history consumers do not consume
such blobs: they consume an exact manifest kind with an ordered role/media
layout.  This module is the body-preserving, path-free bridge between those two
contracts.

Object ids and publication/runtime ids are deliberately absent from the
comparison closure.  Builders provide a stable comparison digest per member
and one stable semantic-basis digest.  Consequently a restart may allocate new
ids while a policy, model, role, media type, lineage, or semantic row change is
still detected.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sqlite3
from typing import Literal, cast

from pydantic import field_validator, model_validator

from consultation_kb.knowledge._canonical import canonical_json_bytes, canonical_sha256
from consultation_kb.models.common import (
    NonEmptyStr,
    ObjectId,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
)
from consultation_kb.retrieval.artifact_contracts import (
    derived_artifact_media_type_layout,
    derived_artifact_role_layout,
)


_UUID7_SUFFIX = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)

# These ids are allocated by the publication/rebuild attempt.  Authority ids
# (claim, passage, fact_event, case, policy, and so on) are deliberately absent
# from this list and therefore remain part of semantic comparison.
_OPERATIONAL_OBJECT_PREFIXES = frozenset(
    {
        "artifact_manifest",
        "client_graph",
        "ephemeral_publication",
        "fact_snapshot",
        "global_graph",
        "graph_build_manifest",
        "graph_builder_input",
        "graph_community_annotations",
        "graph_edge",
        "graph_edge_authority",
        "graph_edge_authority_catalog",
        "graphify_projection",
        "knowledge_publication",
        "knowledge_registry",
        "knowledge_registry_build_manifest",
        "knowledge_registry_builder_input",
        "lexical_build_manifest",
        "lexical_builder_input",
        "lexical_index",
        "manifest",
        "mutation_review_commitment",
        "private_archive_draft",
        "profile_json",
        "profile_markdown",
        "rebuild_artifact",
        "rebuild_job",
        "rebuild_manifest",
        "rebuild_operation",
        "retrieval_route_policy",
        "vector_build_manifest",
        "vector_builder_input",
        "wiki_index",
        "wiki_index_build_manifest",
        "wiki_index_builder_input",
    }
)

# These digests are closures over attempt-local ids/epochs or over another
# member that is compared independently.  Dropping the digest does not drop the
# represented payload: the normalized source rows/member bytes remain below.
_OPERATIONAL_DERIVED_DIGEST_KEYS = frozenset(
    {
        "assigned_input_set_sha256",
        "authority_closure_sha256",
        "builder_input_sha256",
        "candidate_authority_sha256",
        "catalog_sha256",
        "canonical_sha256",
        "edge_authority_catalog_sha256",
        "edge_mapping_sha256",
        "expected_row_mapping_sha256",
        "index_closure_sha256",
        "manifest_sha256",
        "mapping_sha256",
        "member_content_sha256",
        "retrieval_input_descriptor_sha256",
        "row_closure_sha256",
        "row_content_hashes",
        "row_mapping_sha256",
        "source_snapshot_sha256",
    }
)

_BUILD_MANIFEST_MEMBER_DIGEST_KEYS = frozenset(
    {"index_sha256", "metadata_sha256"}
)

_CLIENT_LAYOUTS: dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {
    "client_fact_snapshot": (
        "fact_snapshot",
        ("fact_snapshot", "mutation_review_commitment"),
        ("application/json", "application/json"),
    ),
    "client_profile": (
        "profile",
        ("profile_json", "profile_markdown"),
        ("application/json", "text/markdown"),
    ),
    "client_graph": (
        "graph",
        ("client_graph",),
        ("application/json",),
    ),
}


def _operational_object_prefix(value: str) -> str | None:
    if len(value) <= 37 or value[-37] != "_":
        return None
    prefix = value[:-37]
    if (
        prefix not in _OPERATIONAL_OBJECT_PREFIXES
        or _UUID7_SUFFIX.fullmatch(value[-36:]) is None
    ):
        return None
    return prefix


def _normalized_json_value(
    value: object,
    *,
    role: str,
    path: tuple[str, ...] = (),
) -> object:
    if isinstance(value, dict):
        raw_object_id = value.get("object_id")
        generated_reference = (
            isinstance(raw_object_id, str)
            and _operational_object_prefix(raw_object_id) is not None
        )
        descriptor_closure = {
            "descriptor_sha256",
            "records",
            "route_policy_ref",
        } <= value.keys()
        normalized: dict[str, object] = {}
        for raw_key, child in sorted(value.items()):
            key = str(raw_key)
            if (
                key in _OPERATIONAL_DERIVED_DIGEST_KEYS
                or (descriptor_closure and key == "descriptor_sha256")
                or (
                    role.endswith("_build_manifest")
                    and key in _BUILD_MANIFEST_MEMBER_DIGEST_KEYS
                )
                or (generated_reference and key == "content_sha256")
            ):
                continue
            if key == "epoch" or key.endswith("_epoch"):
                normalized[key] = "<operational-epoch>"
                continue
            if role == "global_graph" and not path and key == "effective_at":
                normalized[key] = "<operational-build-time>"
                continue
            normalized[key] = _normalized_json_value(
                cast(object, child),
                role=role,
                path=(*path, key),
            )
        return normalized
    if isinstance(value, list):
        return [
            _normalized_json_value(cast(object, child), role=role, path=path)
            for child in value
        ]
    if isinstance(value, str):
        prefix = _operational_object_prefix(value)
        if prefix is not None:
            return f"{prefix}_<operational-id>"
        if len(value) > 1 and value[0] in "[{":
            try:
                embedded = cast(object, json.loads(value))
            except (TypeError, ValueError, json.JSONDecodeError):
                return value
            return _normalized_json_value(embedded, role=role, path=path)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise StructuredArtifactError


def _sqlite_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _sqlite_value(value: object, *, role: str, column: str) -> object:
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, bytes):
        return {"base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, str):
        return _normalized_json_value(value, role=role, path=(column,))
    raise StructuredArtifactError


def _sqlite_semantic_snapshot(payload: bytes, *, role: str) -> dict[str, object]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        connection.deserialize(payload)
        schema_rows = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()
        schema = [
            {
                "type": str(row[0]),
                "name": str(row[1]),
                "table": str(row[2]),
                "sql": None if row[3] is None else str(row[3]),
            }
            for row in schema_rows
        ]
        tables: list[dict[str, object]] = []
        for row in schema_rows:
            if str(row[0]) != "table":
                continue
            table = str(row[1])
            quoted = _sqlite_identifier(table)
            columns = tuple(
                str(column[1])
                for column in connection.execute(
                    f"PRAGMA table_info({quoted})"
                ).fetchall()
            )
            compared_columns = tuple(
                column for column in columns if column != "row_sha256"
            )
            positions = tuple(columns.index(column) for column in compared_columns)
            normalized_rows = [
                {
                    column: _sqlite_value(
                        cast(object, sql_row[position]),
                        role=role,
                        column=column,
                    )
                    for column, position in zip(
                        compared_columns, positions, strict=True
                    )
                }
                for sql_row in connection.execute(f"SELECT * FROM {quoted}")
            ]
            normalized_rows.sort(key=canonical_json_bytes)
            tables.append(
                {
                    "name": table,
                    "columns": list(compared_columns),
                    "rows": normalized_rows,
                }
            )
    except (sqlite3.DatabaseError, UnicodeError, ValueError, TypeError):
        raise StructuredArtifactError from None
    finally:
        connection.close()
    return {"schema": schema, "tables": tables}


def stable_member_payload_sha256(
    *,
    role: str,
    media_type: str,
    payload: bytes,
) -> str:
    """Hash actual member semantics while excluding proven attempt allocation.

    JSON and SQLite members are decoded so job/runtime ids and epochs can be
    removed at their typed boundaries.  Every remaining field, table, row, and
    byte is hashed.  Binary vectors and text are compared byte-for-byte.
    """

    if type(payload) is not bytes or not payload:
        raise StructuredArtifactError
    if media_type == "application/vnd.sqlite3":
        normalized: object = _sqlite_semantic_snapshot(payload, role=role)
    elif media_type == "application/json":
        try:
            parsed = cast(object, json.loads(payload))
        except (UnicodeError, ValueError, json.JSONDecodeError):
            raise StructuredArtifactError from None
        normalized = _normalized_json_value(parsed, role=role)
    else:
        normalized = {
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
        }
    return canonical_sha256(
        {
            "domain": "consultation_kb.structured_rebuild_member_semantics.v1",
            "role": role,
            "media_type": media_type,
            "normalized_payload": normalized,
        }
    )


class StructuredArtifactError(RuntimeError):
    def __init__(self, code: str = "REBUILD_STRUCTURED_ARTIFACT_INVALID") -> None:
        self.code = code
        super().__init__(code)


class StructuredArtifactMember(StrictModel):
    role: SafePolicyKey
    object_id: ObjectId | None = None
    media_type: NonEmptyStr
    payload_base64: NonEmptyStr
    comparison_sha256: Sha256Hex
    source_lineage_hashes: tuple[Sha256Hex, ...] = ()

    @field_validator("source_lineage_hashes")
    @classmethod
    def _canonical_lineage(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("structured artifact lineage must be sorted and unique")
        return value

    @model_validator(mode="after")
    def _canonical_payload(self) -> "StructuredArtifactMember":
        try:
            decoded = base64.b64decode(self.payload_base64, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("structured artifact member payload is invalid") from None
        if not decoded or base64.b64encode(decoded).decode("ascii") != self.payload_base64:
            raise ValueError("structured artifact member payload is not canonical")
        if self.object_id is not None and self.object_id[:-37] != self.role:
            raise ValueError("structured artifact member identity does not match role")
        try:
            expected = stable_member_payload_sha256(
                role=self.role,
                media_type=self.media_type,
                payload=decoded,
            )
        except StructuredArtifactError:
            raise ValueError("structured artifact member semantics are invalid") from None
        if self.comparison_sha256 != expected:
            raise ValueError("structured artifact member comparison hash mismatch")
        return self

    @classmethod
    def from_bytes(
        cls,
        *,
        role: str,
        object_id: str | None = None,
        media_type: str,
        payload: bytes,
        comparison_sha256: str | None = None,
        source_lineage_hashes: tuple[str, ...] = (),
    ) -> "StructuredArtifactMember":
        if type(payload) is not bytes or not payload:
            raise TypeError("structured artifact member bytes are required")
        stable_sha256 = stable_member_payload_sha256(
            role=role,
            media_type=media_type,
            payload=payload,
        )
        if comparison_sha256 is not None and comparison_sha256 != stable_sha256:
            raise StructuredArtifactError
        return cls(
            role=role,
            object_id=object_id,
            media_type=media_type,
            payload_base64=base64.b64encode(payload).decode("ascii"),
            comparison_sha256=stable_sha256,
            source_lineage_hashes=source_lineage_hashes,
        )

    @property
    def payload(self) -> bytes:
        return base64.b64decode(self.payload_base64, validate=True)


class StructuredArtifactEnvelope(StrictModel):
    domain: Literal["consultation_kb.structured_rebuild_artifact.v1"] = (
        "consultation_kb.structured_rebuild_artifact.v1"
    )
    artifact_key: SafePolicyKey
    artifact_kind: SafePolicyKey
    source_version: PositiveInt
    semantic_basis_sha256: Sha256Hex
    members: tuple[StructuredArtifactMember, ...]

    @model_validator(mode="after")
    def _closed_layout(self) -> "StructuredArtifactEnvelope":
        if not self.members:
            raise ValueError("structured artifact members must be non-empty")
        object_ids = tuple(
            member.object_id
            for member in self.members
            if member.object_id is not None
        )
        if len(object_ids) != len(set(object_ids)):
            raise ValueError("structured artifact member identities must be unique")
        roles = tuple(member.role for member in self.members)
        media_types = tuple(member.media_type for member in self.members)
        if self.artifact_key in {
            "wiki_index",
            "knowledge_registry",
            "graph",
            "lexical",
            "vector",
        }:
            if (
                self.artifact_kind != self.artifact_key
                or roles != derived_artifact_role_layout(self.artifact_key)
                or media_types
                != derived_artifact_media_type_layout(self.artifact_key)
            ):
                raise ValueError("structured global artifact layout is invalid")
        elif self.artifact_key in _CLIENT_LAYOUTS:
            artifact_kind, expected_roles, expected_media = _CLIENT_LAYOUTS[
                self.artifact_key
            ]
            if (
                self.artifact_kind != artifact_kind
                or roles != expected_roles
                or media_types != expected_media
            ):
                raise ValueError("structured client artifact layout is invalid")
        elif self.artifact_key == "private_archive":
            if (
                self.artifact_kind != "private_archive"
                or any(role != "private_archive_draft" for role in roles)
                or any(media_type != "application/json" for media_type in media_types)
            ):
                raise ValueError("structured private archive layout is invalid")
        elif self.artifact_key == "wiki_page":
            if (
                self.artifact_kind != "wiki_page"
                or any(role != "wiki" for role in roles)
                or any(media_type != "application/json" for media_type in media_types)
            ):
                raise ValueError("structured wiki page layout is invalid")
        elif self.artifact_key == "claims":
            if (
                self.artifact_kind != "claims"
                or any(role != "claim" for role in roles)
                or any(media_type != "text/plain" for media_type in media_types)
            ):
                raise ValueError("structured claims layout is invalid")
        elif self.artifact_key == "c1_revision":
            governed_theory = (
                self.artifact_kind == "c1_revision"
                and all(role == "theory" for role in roles)
                and all(
                    media_type == "application/json" for media_type in media_types
                )
            )
            governed_absence = (
                self.artifact_kind == "c1_absence"
                and roles == ("c1_absence",)
                and media_types == ("application/json",)
            )
            if not (governed_theory or governed_absence):
                raise ValueError("structured C1 artifact layout is invalid")
        return self

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))

    @property
    def comparison_content_sha256(self) -> str:
        return canonical_sha256(
            {
                "domain": "consultation_kb.structured_rebuild_content.v1",
                "artifact_key": self.artifact_key,
                "artifact_kind": self.artifact_kind,
                "members": [
                    {
                        "role": member.role,
                        "media_type": member.media_type,
                        "comparison_sha256": member.comparison_sha256,
                        "source_lineage_hashes": list(member.source_lineage_hashes),
                    }
                    for member in self.members
                ],
            }
        )

    @property
    def semantic_fingerprint_sha256(self) -> str:
        return canonical_sha256(
            {
                "domain": "consultation_kb.structured_rebuild_semantics.v1",
                "artifact_key": self.artifact_key,
                "artifact_kind": self.artifact_kind,
                "semantic_basis_sha256": self.semantic_basis_sha256,
                "members": [
                    {
                        "role": member.role,
                        "media_type": member.media_type,
                        "comparison_sha256": member.comparison_sha256,
                        "source_lineage_hashes": list(member.source_lineage_hashes),
                    }
                    for member in self.members
                ],
            }
        )


def parse_structured_artifact(payload: bytes) -> StructuredArtifactEnvelope | None:
    """Return ``None`` only when bytes are not a structured rebuild envelope."""

    if type(payload) is not bytes:
        raise TypeError("structured artifact payload must be bytes")
    try:
        value = StructuredArtifactEnvelope.model_validate_json(payload, strict=True)
    except ValueError:
        # An arbitrary legacy builder payload is valid input to the generic
        # staging path.  Bytes claiming our domain, however, must fail closed.
        if b"consultation_kb.structured_rebuild_artifact.v1" in payload:
            raise StructuredArtifactError from None
        return None
    if value.canonical_bytes != payload:
        raise StructuredArtifactError
    return value


__all__ = [
    "StructuredArtifactEnvelope",
    "StructuredArtifactError",
    "StructuredArtifactMember",
    "parse_structured_artifact",
    "stable_member_payload_sha256",
]
