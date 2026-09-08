"""Contracts for versioned derived retrieval artifacts.

The public Pydantic models are path-free.  Filesystem handles live only in the
opaque :class:`ArtifactBinding`, which is created after active-manifest and CAS
verification by :mod:`consultation_kb.retrieval.artifact_discovery`.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, Protocol, TypeAlias, final

from pydantic import field_serializer, field_validator, model_validator

from consultation_kb.models.common import (
    NonEmptyStr,
    NonNegativeInt,
    ObjectId,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    VersionRef,
)
from consultation_kb.models.evidence import (
    EvidenceFreshnessSnapshot,
    EvidenceLocator,
    Provenance,
)
from consultation_kb.vault.content_store import ContentObjectRef, ContentStore

from .contracts import CandidateMetadata, CandidateRef, canonical_json_bytes


DerivedArtifactKind: TypeAlias = Literal[
    "wiki_index",
    "knowledge_registry",
    "graph",
    "lexical",
    "vector",
]

_ROLE_LAYOUTS: Final[dict[str, tuple[str, ...]]] = {
    "wiki_index": (
        "wiki_index_builder_input",
        "wiki_index_build_manifest",
        "wiki_index",
    ),
    "knowledge_registry": (
        "knowledge_registry_builder_input",
        "knowledge_registry_build_manifest",
        "retrieval_route_policy",
        "knowledge_registry",
    ),
    "graph": (
        "graph_builder_input",
        "graph_build_manifest",
        "global_graph",
        "graph_edge_authority_catalog",
        "graphify_projection",
        "graph_community_annotations",
    ),
    "lexical": (
        "lexical_builder_input",
        "lexical_build_manifest",
        "lexical_index",
    ),
    "vector": (
        "vector_builder_input",
        "vector_build_manifest",
        "vector_metadata",
        "vector_shard",
    ),
}

_MEDIA_TYPE_LAYOUTS: Final[dict[str, tuple[str, ...]]] = {
    "wiki_index": (
        "application/json",
        "application/json",
        "application/json",
    ),
    "knowledge_registry": (
        "application/json",
        "application/json",
        "application/json",
        "application/json",
    ),
    "graph": (
        "application/json",
        "application/json",
        "application/json",
        "application/json",
        "application/json",
        "application/json",
    ),
    "lexical": (
        "application/json",
        "application/json",
        "application/vnd.sqlite3",
    ),
    "vector": (
        "application/json",
        "application/json",
        "application/vnd.sqlite3",
        "application/octet-stream",
    ),
}

ARTIFACT_KIND_TO_EVIDENCE_CHANNEL: Final[dict[str, str]] = {
    "wiki_index": "wiki",
    "graph": "global_graph",
    "lexical": "lexical",
    "vector": "vector",
}


def derived_artifact_role_layout(artifact_kind: str) -> tuple[str, ...]:
    """Return the exact ordered P1 member object types for one derived root."""

    try:
        return _ROLE_LAYOUTS[artifact_kind]
    except (KeyError, TypeError):
        raise ValueError("DERIVED_ARTIFACT_KIND_INVALID") from None


def validate_derived_artifact_role_layout(
    artifact_kind: str,
    roles: tuple[str, ...],
) -> tuple[str, ...]:
    """Fail closed on missing, additional, reordered, or substituted roles."""

    expected = derived_artifact_role_layout(artifact_kind)
    if type(roles) is not tuple or roles != expected:
        raise ValueError("DERIVED_ARTIFACT_ROLE_LAYOUT_INVALID")
    return roles


def derived_artifact_media_type_layout(artifact_kind: str) -> tuple[str, ...]:
    """Return exact member media types in the same order as the role layout."""

    try:
        return _MEDIA_TYPE_LAYOUTS[artifact_kind]
    except (KeyError, TypeError):
        raise ValueError("DERIVED_ARTIFACT_KIND_INVALID") from None


def validate_derived_artifact_media_type_layout(
    artifact_kind: str,
    media_types: tuple[str, ...],
) -> tuple[str, ...]:
    expected = derived_artifact_media_type_layout(artifact_kind)
    if type(media_types) is not tuple or media_types != expected:
        raise ValueError("DERIVED_ARTIFACT_MEDIA_TYPE_LAYOUT_INVALID")
    return media_types


def _sha256(value: object, *, domain: bytes) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def _ref_key(reference: VersionRef) -> tuple[str, int, str]:
    return reference.object_id, reference.version, reference.content_sha256


def _record_key(
    record: "RetrievalInputRecord",
) -> tuple[str, int, str, str, int, str]:
    return (*_ref_key(record.candidate_ref), *_ref_key(record.content_ref))


def retrieval_row_id(candidate: CandidateRef) -> str:
    """Stable row identity for one exact Claim/content evidence pair."""

    value = CandidateRef.model_validate(candidate)
    return _sha256(
        {
            "candidate_ref": value.reference.model_dump(mode="json"),
            "content_ref": value.content_ref.model_dump(mode="json"),
        },
        domain=b"consultation-kb-retrieval-row-id-v1\0",
    )


class RetrievalAuthorityInput(StrictModel):
    """Every governance field of a candidate, excluding route/run scores."""

    reference: VersionRef
    content_ref: VersionRef
    object_type: SafePolicyKey
    metadata: CandidateMetadata
    provenance: Provenance
    location: EvidenceLocator
    freshness: EvidenceFreshnessSnapshot

    @classmethod
    def from_candidate(cls, candidate: CandidateRef) -> "RetrievalAuthorityInput":
        value = CandidateRef.model_validate(candidate)
        if (
            value.filter_binding is not None
            or value.score != 0.0
            or value.score_components
        ):
            raise ValueError("RETRIEVAL_INPUT_CANDIDATE_STATE_INVALID")
        return cls(
            reference=value.reference,
            content_ref=value.content_ref,
            object_type=value.object_type,
            metadata=value.metadata,
            provenance=value.provenance,
            location=value.location,
            freshness=value.freshness,
        )


class RetrievalInputRecord(StrictModel):
    """Body-free canonical assignment reconstructed from authority storage."""

    candidate_ref: VersionRef
    content_ref: VersionRef
    object_type: SafePolicyKey
    authority_manifest_ref: VersionRef
    anchor_refs: tuple[VersionRef, ...]
    provenance_closure_sha256: Sha256Hex
    candidate_authority_sha256: Sha256Hex
    target_channels: frozenset[DerivedArtifactKind]

    @field_validator("anchor_refs")
    @classmethod
    def _canonical_anchor_refs(
        cls,
        value: tuple[VersionRef, ...],
    ) -> tuple[VersionRef, ...]:
        keys = [_ref_key(reference) for reference in value]
        if len(keys) != len(set(keys)):
            raise ValueError("RETRIEVAL_INPUT_DUPLICATE_ANCHOR")
        return tuple(sorted(value, key=_ref_key))

    @field_serializer("target_channels")
    def _serialize_target_channels(self, value: frozenset[str]) -> list[str]:
        return sorted(value)


class RetrievalInputAssignment(StrictModel):
    """Authority adapter input used by P3 and the index builders."""

    authority: RetrievalAuthorityInput
    target_channels: frozenset[DerivedArtifactKind]

    @classmethod
    def from_candidate(
        cls,
        candidate: CandidateRef,
        *,
        target_channels: frozenset[DerivedArtifactKind],
    ) -> "RetrievalInputAssignment":
        return cls(
            authority=RetrievalAuthorityInput.from_candidate(candidate),
            target_channels=target_channels,
        )

    @model_validator(mode="after")
    def _require_targets(self) -> "RetrievalInputAssignment":
        if not self.target_channels or "knowledge_registry" in self.target_channels:
            raise ValueError("RETRIEVAL_INPUT_TARGET_INVALID")
        return self

    def to_record(self) -> RetrievalInputRecord:
        authority_payload = self.authority.model_dump(mode="json")
        provenance_payload = {
            "anchor_refs": [
                reference.model_dump(mode="json")
                for reference in self.authority.location.anchor_refs
            ],
            "provenance": self.authority.provenance.model_dump(mode="json"),
            "source_lineage_hashes": list(
                self.authority.metadata.source_lineage_hashes
            ),
        }
        return RetrievalInputRecord(
            candidate_ref=self.authority.reference,
            content_ref=self.authority.content_ref,
            object_type=self.authority.object_type,
            authority_manifest_ref=self.authority.metadata.manifest_ref,
            anchor_refs=self.authority.location.anchor_refs,
            provenance_closure_sha256=_sha256(
                provenance_payload,
                domain=b"consultation-kb-retrieval-provenance-closure-v1\0",
            ),
            candidate_authority_sha256=_sha256(
                authority_payload,
                domain=b"consultation-kb-retrieval-candidate-authority-v1\0",
            ),
            target_channels=self.target_channels,
        )


class RetrievalInputDescriptor(StrictModel):
    """Canonical, non-self-referential description of assigned index inputs."""

    contract: Literal["retrieval_input_descriptor_v1"] = (
        "retrieval_input_descriptor_v1"
    )
    route_policy_ref: VersionRef
    records: tuple[RetrievalInputRecord, ...]
    descriptor_sha256: Sha256Hex

    @field_validator("records")
    @classmethod
    def _canonical_records(
        cls,
        value: tuple[RetrievalInputRecord, ...],
    ) -> tuple[RetrievalInputRecord, ...]:
        if not value:
            raise ValueError("RETRIEVAL_INPUT_RECORDS_REQUIRED")
        keys = [_record_key(record) for record in value]
        if len(keys) != len(set(keys)):
            raise ValueError("RETRIEVAL_INPUT_DUPLICATE_CANDIDATE")
        versions: dict[str, tuple[str, int, str]] = {}
        for record in value:
            candidate_key = _ref_key(record.candidate_ref)
            existing = versions.setdefault(record.candidate_ref.object_id, candidate_key)
            if existing != candidate_key:
                raise ValueError("RETRIEVAL_INPUT_STABLE_VERSION_CONFLICT")
        return tuple(sorted(value, key=_record_key))

    @model_validator(mode="after")
    def _verify_descriptor_hash(self) -> "RetrievalInputDescriptor":
        expected = self._hash_records(self.records, self.route_policy_ref)
        if self.descriptor_sha256 != expected:
            raise ValueError("RETRIEVAL_INPUT_DESCRIPTOR_HASH_MISMATCH")
        return self

    @classmethod
    def _hash_records(
        cls,
        records: tuple[RetrievalInputRecord, ...],
        route_policy_ref: VersionRef,
    ) -> str:
        return _sha256(
            {
                "contract": "retrieval_input_descriptor_v1",
                "records": [record.model_dump(mode="json") for record in records],
                "route_policy_ref": route_policy_ref.model_dump(mode="json"),
            },
            domain=b"consultation-kb-retrieval-input-descriptor-v1\0",
        )

    @classmethod
    def from_assignments(
        cls,
        assignments: tuple[RetrievalInputAssignment, ...],
        *,
        route_policy_ref: VersionRef,
    ) -> "RetrievalInputDescriptor":
        if type(assignments) is not tuple or any(
            type(assignment) is not RetrievalInputAssignment
            for assignment in assignments
        ):
            raise TypeError("RETRIEVAL_INPUT_ASSIGNMENTS_REQUIRED")
        policy = VersionRef.model_validate(route_policy_ref)
        if policy.object_id[:-37] != "retrieval_route_policy":
            raise ValueError("RETRIEVAL_ROUTE_POLICY_REF_INVALID")
        merged: dict[
            tuple[str, int, str, str, int, str], RetrievalInputRecord
        ] = {}
        versions: dict[str, tuple[str, int, str]] = {}
        for assignment in assignments:
            record = assignment.to_record()
            candidate_key = _ref_key(record.candidate_ref)
            existing_version = versions.setdefault(
                record.candidate_ref.object_id,
                candidate_key,
            )
            if existing_version != candidate_key:
                raise ValueError("RETRIEVAL_INPUT_STABLE_VERSION_CONFLICT")
            key = _record_key(record)
            existing = merged.get(key)
            if existing is None:
                merged[key] = record
                continue
            comparable = existing.model_copy(
                update={"target_channels": record.target_channels}
            )
            if comparable != record:
                raise ValueError("RETRIEVAL_INPUT_AUTHORITY_CONFLICT")
            merged[key] = existing.model_copy(
                update={
                    "target_channels": existing.target_channels
                    | record.target_channels
                }
            )
        records = tuple(sorted(merged.values(), key=_record_key))
        return cls(
            route_policy_ref=policy,
            records=records,
            descriptor_sha256=cls._hash_records(records, policy),
        )

    def assigned_records(self, channel: str) -> tuple[RetrievalInputRecord, ...]:
        derived_artifact_role_layout(channel)
        if channel == "knowledge_registry":
            return self.records
        return tuple(
            record for record in self.records if channel in record.target_channels
        )

    def assigned_input_set_sha256(self, channel: str) -> str:
        records = self.assigned_records(channel)
        return _sha256(
            {
                "channel": channel,
                "descriptor_sha256": self.descriptor_sha256,
                "records": [record.model_dump(mode="json") for record in records],
            },
            domain=b"consultation-kb-retrieval-assigned-input-set-v1\0",
        )

    def expected_row_mapping_sha256(self, channel: str) -> str:
        records = self.assigned_records(channel)
        mapping = [
            {
                "authority_manifest_ref": record.authority_manifest_ref.model_dump(
                    mode="json"
                ),
                "candidate_authority_sha256": record.candidate_authority_sha256,
                "candidate_ref": record.candidate_ref.model_dump(mode="json"),
                "content_ref": record.content_ref.model_dump(mode="json"),
                "row_index": row_index,
            }
            for row_index, record in enumerate(records)
        ]
        return _sha256(
            mapping,
            domain=b"consultation-kb-retrieval-row-mapping-v1\0",
        )

    def verify_candidates(
        self,
        channel: str,
        candidates: tuple[CandidateRef, ...],
    ) -> None:
        expected = self.assigned_records(channel)
        if type(candidates) is not tuple:
            raise TypeError("RETRIEVAL_CANDIDATES_REQUIRED")
        expected_by_ref = {
            _record_key(record): record for record in expected
        }
        expected_evidence_channel = ARTIFACT_KIND_TO_EVIDENCE_CHANNEL.get(channel)
        actual: list[RetrievalInputRecord] = []
        for candidate in candidates:
            if type(candidate) is not CandidateRef or (
                expected_evidence_channel is not None
                and candidate.channel != expected_evidence_channel
            ):
                raise ValueError("RETRIEVAL_INPUT_SET_MISMATCH")
            candidate_key = (
                *_ref_key(candidate.reference),
                *_ref_key(candidate.content_ref),
            )
            record = expected_by_ref.get(candidate_key)
            if record is None:
                raise ValueError("RETRIEVAL_INPUT_SET_MISMATCH")
            assignment = RetrievalInputAssignment.from_candidate(
                candidate,
                target_channels=record.target_channels,
            )
            actual.append(assignment.to_record())
        actual_tuple = tuple(sorted(actual, key=_record_key))
        if actual_tuple != expected:
            raise ValueError("RETRIEVAL_INPUT_SET_MISMATCH")


class DerivedAuthorityObjectVersion(StrictModel):
    object_id: ObjectId
    version: PositiveInt
    object_sha256: Sha256Hex


class DerivedAuthoritySnapshotV2(StrictModel):
    """Exact staging snapshot whose canonical bytes enter approval closure."""

    catalog_version: NonNegativeInt
    authorization_epoch: NonNegativeInt
    tombstone_epoch: NonNegativeInt
    publication_authority_version: PositiveInt
    expected_current_epoch: PositiveInt | None
    maximum_runtime_epoch: NonNegativeInt
    target_runtime_epoch: PositiveInt
    theory: DerivedAuthorityObjectVersion | None
    wiki: DerivedAuthorityObjectVersion | None
    claims: tuple[DerivedAuthorityObjectVersion, ...]

    @field_validator("claims")
    @classmethod
    def _canonical_claims(
        cls,
        value: tuple[DerivedAuthorityObjectVersion, ...],
    ) -> tuple[DerivedAuthorityObjectVersion, ...]:
        keys = [
            (item.object_id, item.version, item.object_sha256) for item in value
        ]
        if len(keys) != len(set(keys)):
            raise ValueError("DERIVED_AUTHORITY_DUPLICATE_CLAIM")
        return tuple(sorted(value, key=lambda item: (item.object_id, item.version)))

    @model_validator(mode="after")
    def _validate_epochs(self) -> "DerivedAuthoritySnapshotV2":
        if (
            self.expected_current_epoch is not None
            and self.expected_current_epoch > self.maximum_runtime_epoch
        ) or self.target_runtime_epoch != self.maximum_runtime_epoch + 1:
            raise ValueError("DERIVED_BUILDER_RUNTIME_EPOCH_INVALID")
        return self


class DerivedArtifactBuilderInputV2(StrictModel):
    """Approval-bound input shared by all five derived knowledge artifacts."""

    contract: Literal["knowledge_builder_input_v2"] = "knowledge_builder_input_v2"
    artifact_kind: DerivedArtifactKind
    authority_closure_sha256: Sha256Hex
    authority_snapshot: DerivedAuthoritySnapshotV2
    retrieval_input_descriptor: RetrievalInputDescriptor
    target_runtime_epoch: PositiveInt

    @model_validator(mode="after")
    def _verify_closure(self) -> "DerivedArtifactBuilderInputV2":
        snapshot = self.authority_snapshot
        if self.target_runtime_epoch != snapshot.target_runtime_epoch:
            raise ValueError("DERIVED_BUILDER_RUNTIME_EPOCH_INVALID")
        if hashlib.sha256(
            canonical_json_bytes(snapshot.model_dump(mode="json"))
        ).hexdigest() != self.authority_closure_sha256:
            raise ValueError("DERIVED_BUILDER_AUTHORITY_HASH_MISMATCH")
        return self

    @property
    def source_catalog_version(self) -> int:
        return self.authority_snapshot.publication_authority_version

    @property
    def authority_catalog_version(self) -> int:
        return self.authority_snapshot.catalog_version

    @property
    def canonical_sha256(self) -> str:
        return _sha256(
            self.model_dump(mode="json"),
            domain=b"consultation-kb-derived-builder-input-v2\0",
        )


class GenericDerivedBuildManifestV2(StrictModel):
    """Acyclic build closure for wiki-index and knowledge-registry members."""

    contract: Literal["generic_derived_build_manifest_v2"] = (
        "generic_derived_build_manifest_v2"
    )
    artifact_kind: Literal["wiki_index", "knowledge_registry"]
    builder_input_sha256: Sha256Hex
    retrieval_input_descriptor_sha256: Sha256Hex
    assigned_input_set_sha256: Sha256Hex
    expected_row_mapping_sha256: Sha256Hex
    source_catalog_version: PositiveInt
    target_runtime_epoch: PositiveInt
    member_content_sha256: dict[SafePolicyKey, Sha256Hex]
    manifest_sha256: Sha256Hex

    @model_validator(mode="after")
    def _verify_manifest(self) -> "GenericDerivedBuildManifestV2":
        expected_roles = set(derived_artifact_role_layout(self.artifact_kind)[2:])
        if set(self.member_content_sha256) != expected_roles:
            raise ValueError("GENERIC_DERIVED_MEMBER_SET_INVALID")
        expected = self._hash_payload(
            self.model_dump(mode="json", exclude={"manifest_sha256"})
        )
        if self.manifest_sha256 != expected:
            raise ValueError("GENERIC_DERIVED_MANIFEST_HASH_MISMATCH")
        return self

    @staticmethod
    def _hash_payload(payload: object) -> str:
        return _sha256(
            payload,
            domain=b"consultation-kb-generic-derived-build-manifest-v2\0",
        )

    @classmethod
    def create(
        cls,
        *,
        artifact_kind: Literal["wiki_index", "knowledge_registry"],
        builder_input: DerivedArtifactBuilderInputV2,
        member_content_sha256: dict[str, str],
    ) -> "GenericDerivedBuildManifestV2":
        if builder_input.artifact_kind != artifact_kind:
            raise ValueError("GENERIC_DERIVED_BUILDER_KIND_MISMATCH")
        descriptor = builder_input.retrieval_input_descriptor
        values = {
            "artifact_kind": artifact_kind,
            "builder_input_sha256": builder_input.canonical_sha256,
            "retrieval_input_descriptor_sha256": descriptor.descriptor_sha256,
            "assigned_input_set_sha256": descriptor.assigned_input_set_sha256(
                artifact_kind
            ),
            "expected_row_mapping_sha256": descriptor.expected_row_mapping_sha256(
                artifact_kind
            ),
            "source_catalog_version": builder_input.source_catalog_version,
            "target_runtime_epoch": builder_input.target_runtime_epoch,
            "member_content_sha256": member_content_sha256,
        }
        payload = {
            "contract": "generic_derived_build_manifest_v2",
            **values,
        }
        return cls(
            **values,  # type: ignore[arg-type]
            manifest_sha256=cls._hash_payload(payload),
        )

    def verify_builder_input(
        self,
        builder_input: DerivedArtifactBuilderInputV2,
    ) -> None:
        descriptor = builder_input.retrieval_input_descriptor
        if (
            builder_input.artifact_kind != self.artifact_kind
            or self.builder_input_sha256 != builder_input.canonical_sha256
            or self.retrieval_input_descriptor_sha256
            != descriptor.descriptor_sha256
            or self.assigned_input_set_sha256
            != descriptor.assigned_input_set_sha256(self.artifact_kind)
            or self.expected_row_mapping_sha256
            != descriptor.expected_row_mapping_sha256(self.artifact_kind)
            or self.source_catalog_version != builder_input.source_catalog_version
            or self.target_runtime_epoch != builder_input.target_runtime_epoch
        ):
            raise ValueError("GENERIC_DERIVED_BUILD_CLOSURE_MISMATCH")


class KnowledgeRegistryPayloadV1(StrictModel):
    """Complete body-free projection of every assigned retrieval authority row."""

    contract: Literal["knowledge_registry_payload_v1"] = (
        "knowledge_registry_payload_v1"
    )
    retrieval_input_descriptor_sha256: Sha256Hex
    route_policy_ref: VersionRef
    records: tuple[RetrievalInputRecord, ...]

    @field_validator("records")
    @classmethod
    def _canonical_records(
        cls,
        value: tuple[RetrievalInputRecord, ...],
    ) -> tuple[RetrievalInputRecord, ...]:
        keys = tuple(_record_key(record) for record in value)
        if not value or keys != tuple(sorted(set(keys))):
            raise ValueError("KNOWLEDGE_REGISTRY_RECORDS_INVALID")
        return value

    @classmethod
    def from_descriptor(
        cls,
        descriptor: RetrievalInputDescriptor,
    ) -> "KnowledgeRegistryPayloadV1":
        exact = RetrievalInputDescriptor.model_validate(descriptor)
        return cls(
            retrieval_input_descriptor_sha256=exact.descriptor_sha256,
            route_policy_ref=exact.route_policy_ref,
            records=exact.records,
        )

    def verify_descriptor(self, descriptor: RetrievalInputDescriptor) -> None:
        if self != self.from_descriptor(descriptor):
            raise ValueError("KNOWLEDGE_REGISTRY_DESCRIPTOR_MISMATCH")


class ArtifactMemberIdentity(StrictModel):
    role: SafePolicyKey
    object_id: ObjectId
    content_sha256: Sha256Hex
    media_type: NonEmptyStr
    size_bytes: NonNegativeInt


class ArtifactBindingIdentity(StrictModel):
    artifact_key: DerivedArtifactKind
    root_ref: VersionRef
    active_runtime_epoch: PositiveInt
    source_catalog_version: PositiveInt
    target_runtime_epoch: PositiveInt
    members: tuple[ArtifactMemberIdentity, ...]
    binding_sha256: Sha256Hex

    @field_validator("members")
    @classmethod
    def _canonical_members(
        cls,
        value: tuple[ArtifactMemberIdentity, ...],
    ) -> tuple[ArtifactMemberIdentity, ...]:
        if not value or len({member.role for member in value}) != len(value):
            raise ValueError("ARTIFACT_BINDING_MEMBERS_INVALID")
        return value

    @model_validator(mode="after")
    def _verify_binding_hash(self) -> "ArtifactBindingIdentity":
        payload = self.model_dump(mode="json", exclude={"binding_sha256"})
        expected = _sha256(
            payload,
            domain=b"consultation-kb-active-artifact-binding-v1\0",
        )
        if self.binding_sha256 != expected:
            raise ValueError("ARTIFACT_BINDING_HASH_MISMATCH")
        return self

    @classmethod
    def create(
        cls,
        *,
        artifact_key: DerivedArtifactKind,
        root_ref: VersionRef,
        active_runtime_epoch: int,
        source_catalog_version: int,
        target_runtime_epoch: int,
        members: tuple[ArtifactMemberIdentity, ...],
    ) -> "ArtifactBindingIdentity":
        exact_root = VersionRef.model_validate(root_ref)
        exact_members = tuple(
            ArtifactMemberIdentity.model_validate(member) for member in members
        )
        payload: dict[str, object] = {
            "artifact_key": artifact_key,
            "root_ref": exact_root.model_dump(mode="json"),
            "active_runtime_epoch": active_runtime_epoch,
            "source_catalog_version": source_catalog_version,
            "target_runtime_epoch": target_runtime_epoch,
            "members": [
                member.model_dump(mode="json") for member in exact_members
            ],
        }
        return cls(
            artifact_key=artifact_key,
            root_ref=exact_root,
            active_runtime_epoch=active_runtime_epoch,
            source_catalog_version=source_catalog_version,
            target_runtime_epoch=target_runtime_epoch,
            members=exact_members,
            binding_sha256=_sha256(
                payload,
                domain=b"consultation-kb-active-artifact-binding-v1\0",
            ),
        )


@dataclass(frozen=True, slots=True)
class _BoundMember:
    identity: ArtifactMemberIdentity
    reference: ContentObjectRef


_BINDING_TOKEN: Final = object()


@final
class ArtifactBinding:
    """Opaque exact CAS binding; it deliberately has no serialization API."""

    __slots__ = (
        "_authority_connection",
        "_identity",
        "_live_verifier",
        "_members",
        "_store",
    )

    def __init__(
        self,
        identity: ArtifactBindingIdentity,
        members: tuple[_BoundMember, ...],
        store: ContentStore,
        live_verifier: Callable[[ArtifactBindingIdentity], None],
        authority_connection: sqlite3.Connection | None,
        *,
        _token: object,
    ) -> None:
        if _token is not _BINDING_TOKEN:
            raise TypeError("ARTIFACT_BINDING_DISCOVERY_REQUIRED")
        if (
            type(identity) is not ArtifactBindingIdentity
            or type(store) is not ContentStore
            or not callable(live_verifier)
            or (
                authority_connection is not None
                and not isinstance(authority_connection, sqlite3.Connection)
            )
        ):
            raise TypeError("ARTIFACT_BINDING_INVALID")
        if tuple(member.identity for member in members) != identity.members:
            raise ValueError("ARTIFACT_BINDING_MEMBERS_INVALID")
        self._identity = identity
        self._members = members
        self._store = store
        self._live_verifier = live_verifier
        self._authority_connection = authority_connection

    @property
    def identity(self) -> ArtifactBindingIdentity:
        return self._identity

    def path_for(self, role: str) -> Path:
        if type(role) is not str:
            raise TypeError("ARTIFACT_MEMBER_ROLE_REQUIRED")
        for member in self._members:
            if member.identity.role == role:
                return member.reference.path
        raise ValueError("ARTIFACT_MEMBER_ROLE_NOT_FOUND")

    def verify_current(self) -> ArtifactBindingIdentity:
        self._live_verifier(self._identity)
        for member in self._members:
            payload = self._store.read_verified(member.reference)
            if hashlib.sha256(payload).hexdigest() != member.identity.content_sha256:
                raise ValueError("ARTIFACT_BINDING_BYTES_CHANGED")
        self._live_verifier(self._identity)
        return self._identity

    def verify_authority_connection(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        """Require the exact live authority capability that created this binding."""

        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SQLITE_CONNECTION_REQUIRED")
        if (
            self._authority_connection is None
            or connection is not self._authority_connection
        ):
            raise ValueError("ARTIFACT_BINDING_AUTHORITY_SCOPE_MISMATCH")

    def __repr__(self) -> str:
        return (
            "ArtifactBinding(artifact_key="
            f"{self._identity.artifact_key!r}, root_ref={self._identity.root_ref!r}, "
            f"binding_sha256={self._identity.binding_sha256!r})"
        )


def _new_artifact_binding(
    *,
    identity: ArtifactBindingIdentity,
    members: tuple[tuple[ArtifactMemberIdentity, ContentObjectRef], ...],
    store: ContentStore,
    live_verifier: Callable[[ArtifactBindingIdentity], None],
    authority_connection: sqlite3.Connection | None = None,
) -> ArtifactBinding:
    """Internal constructor used only after discovery verifies every member."""

    return ArtifactBinding(
        identity,
        tuple(_BoundMember(member, reference) for member, reference in members),
        store,
        live_verifier,
        authority_connection,
        _token=_BINDING_TOKEN,
    )


class ArtifactBoundRetriever(Protocol):
    @property
    def artifact_binding(self) -> ArtifactBinding | None: ...


__all__ = [
    "ArtifactBinding",
    "ArtifactBindingIdentity",
    "ArtifactBoundRetriever",
    "ArtifactMemberIdentity",
    "ARTIFACT_KIND_TO_EVIDENCE_CHANNEL",
    "DerivedArtifactBuilderInputV2",
    "DerivedAuthorityObjectVersion",
    "DerivedAuthoritySnapshotV2",
    "DerivedArtifactKind",
    "GenericDerivedBuildManifestV2",
    "KnowledgeRegistryPayloadV1",
    "RetrievalAuthorityInput",
    "RetrievalInputAssignment",
    "RetrievalInputDescriptor",
    "RetrievalInputRecord",
    "derived_artifact_role_layout",
    "derived_artifact_media_type_layout",
    "retrieval_row_id",
    "validate_derived_artifact_role_layout",
    "validate_derived_artifact_media_type_layout",
]
