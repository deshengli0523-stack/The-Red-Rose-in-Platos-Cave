"""Fail-closed P1 drafts for immutable derived retrieval artifacts."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from pydantic import field_validator, model_validator

from consultation_kb.models.common import ObjectId, SafePolicyKey, StrictModel
from consultation_kb.security.path_guard import PathGuard, ScopePathDenied
from consultation_kb.storage.publication_drafts import ArtifactDraft, ContentDraft
from consultation_kb.storage.tombstones import ObjectIdentity

from .artifact_contracts import (
    ArtifactBinding,
    ArtifactBoundRetriever,
    ArtifactMemberIdentity,
    DerivedArtifactBuilderInputV2,
    DerivedArtifactKind,
    GenericDerivedBuildManifestV2,
    KnowledgeRegistryPayloadV1,
    derived_artifact_media_type_layout,
    derived_artifact_role_layout,
    validate_derived_artifact_media_type_layout,
    validate_derived_artifact_role_layout,
)
from .contracts import canonical_json_bytes
from .evidence_pack import ArtifactVersionMismatch
from .lexical_builder import LexicalBuildManifest
from .vector_builder import VectorBuildManifest
from .wiki_builder import WikiNavigationIndexPayloadV2


class RetrievalArtifactPublicationError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("RETRIEVAL_ARTIFACT_PUBLICATION_INVALID")


class ArtifactPublicationIds(StrictModel):
    """Caller-assigned immutable identities for one exact P1 role layout."""

    manifest_id: ObjectId
    member_object_ids: dict[SafePolicyKey, ObjectId]

    @field_validator("member_object_ids")
    @classmethod
    def _member_ids_nonempty(cls, value: dict[str, str]) -> dict[str, str]:
        if not value or len(value.values()) != len(set(value.values())):
            raise ValueError("RETRIEVAL_ARTIFACT_PUBLICATION_INVALID")
        return value

    @model_validator(mode="after")
    def _object_types_match_ids(self) -> "ArtifactPublicationIds":
        if any(identifier[:-37] != role for role, identifier in self.member_object_ids.items()):
            raise ValueError("RETRIEVAL_ARTIFACT_PUBLICATION_INVALID")
        return self

    def require_layout(self, artifact_kind: str) -> tuple[str, ...]:
        roles = derived_artifact_role_layout(artifact_kind)
        if tuple(self.member_object_ids) != roles:
            raise RetrievalArtifactPublicationError
        return roles


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def validate_builder_manifest_binding(
    artifact_kind: str,
    builder_input: DerivedArtifactBuilderInputV2,
    build_manifest: LexicalBuildManifest | VectorBuildManifest,
) -> None:
    """Validate all authority/assignment fields shared by a builder and manifest."""

    try:
        if (
            artifact_kind not in {"lexical", "vector"}
            or builder_input.artifact_kind != artifact_kind
            or build_manifest.builder_input_sha256 != builder_input.canonical_sha256
            or build_manifest.retrieval_input_descriptor_sha256
            != builder_input.retrieval_input_descriptor.descriptor_sha256
            or build_manifest.assigned_input_set_sha256
            != builder_input.retrieval_input_descriptor.assigned_input_set_sha256(
                artifact_kind
            )
            or build_manifest.row_mapping_sha256
            != builder_input.retrieval_input_descriptor.expected_row_mapping_sha256(
                artifact_kind
            )
            or build_manifest.source_catalog_version
            != builder_input.source_catalog_version
            or build_manifest.target_runtime_epoch
            != builder_input.target_runtime_epoch
            or build_manifest.row_count
            != len(
                builder_input.retrieval_input_descriptor.assigned_records(
                    artifact_kind
                )
            )
            or len(build_manifest.row_content_hashes) != build_manifest.row_count
        ):
            raise RetrievalArtifactPublicationError
    except (AttributeError, TypeError, ValueError):
        raise RetrievalArtifactPublicationError from None


class RetrievalArtifactDraftFactory:
    """Read staged build outputs through one guarded root and form P1 drafts."""

    def __init__(self, staging_root: Path) -> None:
        if not isinstance(staging_root, Path):
            raise TypeError("RETRIEVAL_ARTIFACT_STAGING_ROOT_REQUIRED")
        try:
            root = Path(os.path.abspath(staging_root))
        except (OSError, ValueError):
            raise RetrievalArtifactPublicationError from None
        if not root.is_absolute() or not root.is_dir():
            raise RetrievalArtifactPublicationError
        self._root = root

    def _read(self, path: Path) -> bytes:
        if not isinstance(path, Path):
            raise TypeError("RETRIEVAL_ARTIFACT_PATH_REQUIRED")
        try:
            absolute = Path(os.path.abspath(path))
            relative = absolute.relative_to(self._root)
            if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
                raise RetrievalArtifactPublicationError
            with PathGuard(self._root).open_scoped(relative, mode="rb") as stream:
                return stream.read()
        except RetrievalArtifactPublicationError:
            raise
        except (OSError, ScopePathDenied, ValueError):
            raise RetrievalArtifactPublicationError from None

    @staticmethod
    def _draft(
        *,
        artifact_kind: str,
        builder_input: DerivedArtifactBuilderInputV2,
        member_payloads: tuple[tuple[str, bytes, str], ...],
        ids: ArtifactPublicationIds,
        source_lineage: tuple[ObjectIdentity, ...],
    ) -> ArtifactDraft:
        roles = ids.require_layout(artifact_kind)
        validate_derived_artifact_role_layout(
            artifact_kind,
            tuple(role for role, _payload, _media_type in member_payloads),
        )
        validate_derived_artifact_media_type_layout(
            artifact_kind,
            tuple(media_type for _role, _payload, media_type in member_payloads),
        )
        if tuple(role for role, _payload, _media_type in member_payloads) != roles:
            raise RetrievalArtifactPublicationError
        try:
            members = tuple(
                ContentDraft(
                    object_type=role,
                    object_id=ids.member_object_ids[role],
                    data=payload,
                    source_version=builder_input.source_catalog_version,
                    media_type=media_type,
                    source_lineage=source_lineage,
                )
                for role, payload, media_type in member_payloads
            )
            return ArtifactDraft(
                manifest_id=ids.manifest_id,
                artifact_key=artifact_kind,
                artifact_kind=artifact_kind,
                source_version=builder_input.source_catalog_version,
                members=members,
            )
        except Exception as exc:
            raise RetrievalArtifactPublicationError from exc

    def fixed_layout(
        self,
        *,
        artifact_kind: DerivedArtifactKind,
        builder_input: DerivedArtifactBuilderInputV2,
        member_paths: dict[str, Path],
        member_media_types: dict[str, str],
        ids: ArtifactPublicationIds,
        source_lineage: tuple[ObjectIdentity, ...],
    ) -> ArtifactDraft:
        """Publish wiki/registry/graph bytes with their exact frozen role layout.

        Lexical and vector callers must use their stronger methods below so
        their build-manifest hashes cannot be bypassed.
        """

        try:
            if (
                artifact_kind not in {"wiki_index", "knowledge_registry", "graph"}
                or builder_input.artifact_kind != artifact_kind
            ):
                raise RetrievalArtifactPublicationError
            roles = derived_artifact_role_layout(artifact_kind)
            builder_role = f"{artifact_kind}_builder_input"
            if roles[0] != builder_role:
                raise RetrievalArtifactPublicationError
            expected_file_roles = set(roles[1:])
            expected_media_types = dict(
                zip(
                    roles[1:],
                    derived_artifact_media_type_layout(artifact_kind)[1:],
                    strict=True,
                )
            )
            if (
                type(member_paths) is not dict
                or type(member_media_types) is not dict
                or set(member_paths) != expected_file_roles
                or set(member_media_types) != expected_file_roles
                or member_media_types != expected_media_types
            ):
                raise RetrievalArtifactPublicationError
            payloads: list[tuple[str, bytes, str]] = [
                (
                    builder_role,
                    canonical_json_bytes(builder_input.model_dump(mode="json")),
                    "application/json",
                )
            ]
            for role in roles[1:]:
                payload = self._read(member_paths[role])
                media_type = member_media_types[role]
                if not payload or type(media_type) is not str:
                    raise RetrievalArtifactPublicationError
                if media_type == "application/json" and not (
                    artifact_kind == "graph" and role == "global_graph"
                ):
                    decoded = json.loads(payload)
                    if payload != canonical_json_bytes(decoded):
                        raise RetrievalArtifactPublicationError
                payloads.append((role, payload, media_type))
            payload_by_role = {
                role: payload for role, payload, _media_type in payloads
            }
            if artifact_kind in {"wiki_index", "knowledge_registry"}:
                manifest = GenericDerivedBuildManifestV2.model_validate_json(
                    payload_by_role[f"{artifact_kind}_build_manifest"],
                    strict=True,
                )
                manifest.verify_builder_input(builder_input)
                if manifest.member_content_sha256 != {
                    role: _sha256(payload_by_role[role]) for role in roles[2:]
                }:
                    raise RetrievalArtifactPublicationError
                if artifact_kind == "wiki_index":
                    wiki_index = WikiNavigationIndexPayloadV2.model_validate_json(
                        payload_by_role["wiki_index"], strict=True
                    )
                    wiki_index.verify_builder_input(builder_input)
                if artifact_kind == "knowledge_registry":
                    registry = KnowledgeRegistryPayloadV1.model_validate_json(
                        payload_by_role["knowledge_registry"], strict=True
                    )
                    registry.verify_descriptor(
                        builder_input.retrieval_input_descriptor
                    )
                    policy_payload = payload_by_role["retrieval_route_policy"]
                    policy_ref = builder_input.retrieval_input_descriptor.route_policy_ref
                    if (
                        policy_ref.object_id
                        != ids.member_object_ids["retrieval_route_policy"]
                        or policy_ref.version != builder_input.source_catalog_version
                        or policy_ref.content_sha256 != _sha256(policy_payload)
                    ):
                        raise RetrievalArtifactPublicationError
            else:
                from consultation_kb.graph.artifact_contracts import (
                    verify_graph_member_payloads,
                )

                graph_members = tuple(
                    ArtifactMemberIdentity(
                        role=role,
                        object_id=ids.member_object_ids[role],
                        content_sha256=_sha256(payload_by_role[role]),
                        media_type=media_type,
                        size_bytes=len(payload_by_role[role]),
                    )
                    for role, _payload, media_type in payloads
                )
                verify_graph_member_payloads(
                    payload_by_role,
                    members=graph_members,
                )
            return self._draft(
                artifact_kind=artifact_kind,
                builder_input=builder_input,
                member_payloads=tuple(payloads),
                ids=ids,
                source_lineage=source_lineage,
            )
        except RetrievalArtifactPublicationError:
            raise
        except Exception as exc:
            raise RetrievalArtifactPublicationError from exc

    def lexical(
        self,
        *,
        builder_input: DerivedArtifactBuilderInputV2,
        build_manifest: LexicalBuildManifest,
        index_path: Path,
        ids: ArtifactPublicationIds,
        source_lineage: tuple[ObjectIdentity, ...],
    ) -> ArtifactDraft:
        try:
            validate_builder_manifest_binding("lexical", builder_input, build_manifest)
            index = self._read(index_path)
            if _sha256(index) != build_manifest.index_sha256:
                raise RetrievalArtifactPublicationError
            return self._draft(
                artifact_kind="lexical",
                builder_input=builder_input,
                member_payloads=(
                    (
                        "lexical_builder_input",
                        canonical_json_bytes(builder_input.model_dump(mode="json")),
                        "application/json",
                    ),
                    (
                        "lexical_build_manifest",
                        canonical_json_bytes(build_manifest.model_dump(mode="json")),
                        "application/json",
                    ),
                    ("lexical_index", index, "application/vnd.sqlite3"),
                ),
                ids=ids,
                source_lineage=source_lineage,
            )
        except RetrievalArtifactPublicationError:
            raise
        except Exception as exc:
            raise RetrievalArtifactPublicationError from exc

    def vector(
        self,
        *,
        builder_input: DerivedArtifactBuilderInputV2,
        build_manifest: VectorBuildManifest,
        vector_directory: Path,
        ids: ArtifactPublicationIds,
        source_lineage: tuple[ObjectIdentity, ...],
    ) -> ArtifactDraft:
        try:
            validate_builder_manifest_binding("vector", builder_input, build_manifest)
            manifest_bytes = self._read(vector_directory / "vector-manifest.json")
            stored_manifest = VectorBuildManifest.model_validate_json(
                manifest_bytes,
                strict=True,
            )
            if stored_manifest != build_manifest:
                raise RetrievalArtifactPublicationError
            metadata = self._read(vector_directory / build_manifest.metadata_filename)
            shard = self._read(vector_directory / build_manifest.vector_filename)
            if (
                _sha256(metadata) != build_manifest.metadata_sha256
                or _sha256(shard) != build_manifest.vector_sha256
            ):
                raise RetrievalArtifactPublicationError
            return self._draft(
                artifact_kind="vector",
                builder_input=builder_input,
                member_payloads=(
                    (
                        "vector_builder_input",
                        canonical_json_bytes(builder_input.model_dump(mode="json")),
                        "application/json",
                    ),
                    (
                        "vector_build_manifest",
                        canonical_json_bytes(build_manifest.model_dump(mode="json")),
                        "application/json",
                    ),
                    ("vector_metadata", metadata, "application/vnd.sqlite3"),
                    ("vector_shard", shard, "application/octet-stream"),
                ),
                ids=ids,
                source_lineage=source_lineage,
            )
        except RetrievalArtifactPublicationError:
            raise
        except Exception as exc:
            raise RetrievalArtifactPublicationError from exc


def require_retriever_artifact_binding(
    retriever: ArtifactBoundRetriever,
    expected: ArtifactBinding,
) -> None:
    """Require a retriever to be bound to the exact currently-active artifact."""

    try:
        actual = retriever.artifact_binding
        if actual is None or actual.identity != expected.identity:
            raise ArtifactVersionMismatch
        expected.verify_current()
        if actual is not expected:
            actual.verify_current()
    except ArtifactVersionMismatch:
        raise
    except Exception:
        raise ArtifactVersionMismatch from None


__all__ = [
    "ArtifactPublicationIds",
    "ArtifactVersionMismatch",
    "RetrievalArtifactDraftFactory",
    "RetrievalArtifactPublicationError",
    "derived_artifact_role_layout",
    "derived_artifact_media_type_layout",
    "require_retriever_artifact_binding",
    "validate_builder_manifest_binding",
]
