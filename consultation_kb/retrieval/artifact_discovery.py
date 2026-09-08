"""Shared discovery and gating for the complete active retrieval closure."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass

from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import AuthoritativeFilterSnapshot
from consultation_kb.storage.manifests import ArtifactManifest, ManifestRepository
from consultation_kb.vault.content_store import ContentObjectRef, ContentStore

from .artifact_contracts import (
    ArtifactBinding,
    ArtifactBindingIdentity,
    ArtifactMemberIdentity,
    DerivedArtifactBuilderInputV2,
    DerivedArtifactKind,
    GenericDerivedBuildManifestV2,
    KnowledgeRegistryPayloadV1,
    _new_artifact_binding,
    validate_derived_artifact_media_type_layout,
    validate_derived_artifact_role_layout,
)
from .artifact_publication import validate_builder_manifest_binding
from .contracts import Retriever
from .evidence_pack import ArtifactVersionMismatch, RootManifestSet
from .lexical_builder import LexicalBuildManifest
from .vector_builder import VectorBuildManifest
from .wiki_builder import WikiNavigationIndexPayloadV2


_COMPLETE_KINDS: tuple[DerivedArtifactKind, ...] = (
    "wiki_index",
    "knowledge_registry",
    "lexical",
    "vector",
    "graph",
)
DEDICATED_ACTIVE_ARTIFACT_KEYS = frozenset(
    {"risk_model_descriptor", "risk_rule_policy"}
)


@dataclass(frozen=True, slots=True)
class _DiscoveredArtifact:
    binding: ArtifactBinding
    builder_input: DerivedArtifactBuilderInputV2
    payloads: dict[str, bytes]


@dataclass(frozen=True, slots=True)
class ActiveRetrievalArtifactSet:
    """Five-root active closure; only four route roots enter EvidencePack."""

    wiki_index: ArtifactBinding
    knowledge_registry: ArtifactBinding
    lexical: ArtifactBinding
    vector: ArtifactBinding
    graph: ArtifactBinding

    @property
    def active_runtime_epoch(self) -> int:
        return self.lexical.identity.active_runtime_epoch

    @property
    def source_catalog_version(self) -> int:
        return self.lexical.identity.source_catalog_version

    @property
    def roots(self) -> RootManifestSet:
        return RootManifestSet(
            catalog_version=self.source_catalog_version,
            wiki_manifest_ref=self.wiki_index.identity.root_ref,
            lexical_manifest_ref=self.lexical.identity.root_ref,
            vector_manifest_ref=self.vector.identity.root_ref,
            graph_manifest_ref=self.graph.identity.root_ref,
        )

    def bindings(self) -> tuple[ArtifactBinding, ...]:
        return (
            self.wiki_index,
            self.knowledge_registry,
            self.lexical,
            self.vector,
            self.graph,
        )


# Backward-compatible name for the earlier lexical/vector-only discovery API.
ActiveRetrievalIndexSet = ActiveRetrievalArtifactSet


class ActiveRetrievalArtifactDiscovery:
    """Resolve all active manifests to hash-verified, independently bound CAS files."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        content_store: ContentStore,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SQLITE_CONNECTION_REQUIRED")
        if type(content_store) is not ContentStore:
            raise TypeError("CONTENT_STORE_REQUIRED")
        self._connection = connection
        self._store = content_store

    def discover_current_set(self) -> ActiveRetrievalArtifactSet | None:
        """Discover the sole complete ACTIVE five-root set, or a clean empty DB."""

        began = False
        try:
            if not self._connection.in_transaction:
                self._connection.execute("BEGIN")
                began = True
            epoch_rows = self._connection.execute(
                "SELECT runtime.epoch, runtime.operation_id, operation.state, "
                "operation.runtime_epoch, operation.authority_base_version "
                "FROM runtime_epochs AS runtime "
                "JOIN publication_operations AS operation "
                "  ON operation.operation_id = runtime.operation_id "
                "WHERE runtime.state = 'ACTIVE'"
            ).fetchall()
            if not epoch_rows:
                active_artifacts = int(
                    self._connection.execute(
                        "SELECT count(*) FROM active_artifacts AS active "
                        "JOIN runtime_epochs AS runtime ON runtime.epoch = active.epoch "
                        "WHERE runtime.state = 'ACTIVE'"
                    ).fetchone()[0]
                )
                if active_artifacts != 0:
                    raise ArtifactVersionMismatch
                if began:
                    self._connection.execute("COMMIT")
                return None
            if len(epoch_rows) != 1:
                raise ArtifactVersionMismatch
            epoch = int(epoch_rows[0][0])
            operation_id = str(epoch_rows[0][1])
            if (
                str(epoch_rows[0][2]) != "ACTIVE"
                or int(epoch_rows[0][3]) != epoch
            ):
                raise ArtifactVersionMismatch
            active_keys = frozenset(
                str(row[0])
                for row in self._connection.execute(
                    "SELECT artifact_key FROM active_artifacts "
                    "WHERE epoch = ?",
                    (epoch,),
                ).fetchall()
            )
            retrieval_keys = active_keys.intersection(_COMPLETE_KINDS)
            if not retrieval_keys:
                # Other independently governed runtimes (currently risk)
                # may own the sole ACTIVE epoch before any retrieval closure
                # has been published.  Their dedicated startup verifier owns
                # those artifacts; absence of every retrieval root is the
                # retrieval runtime's clean-empty state.
                if began:
                    self._connection.execute("COMMIT")
                return None
            if retrieval_keys != frozenset(_COMPLETE_KINDS):
                raise ArtifactVersionMismatch
            authority_base_version = int(epoch_rows[0][4])
            self._validate_active_operation_closure(
                epoch=epoch,
                operation_id=operation_id,
                source_catalog_version=authority_base_version,
            )
            repository = ManifestRepository(self._connection)
            manifests: dict[DerivedArtifactKind, ArtifactManifest] = {}
            for kind in _COMPLETE_KINDS:
                manifests[kind] = repository.get_active(kind, epoch=epoch)
            source_versions = {
                manifest.source_version for manifest in manifests.values()
            }
            if (
                len(source_versions) != 1
                or next(iter(source_versions)) != authority_base_version
            ):
                raise ArtifactVersionMismatch
            source_catalog_version = next(iter(source_versions))
            discovered: dict[DerivedArtifactKind, _DiscoveredArtifact] = {}
            for kind in _COMPLETE_KINDS:
                manifest = manifests[kind]
                expected_ref = VersionRef(
                    object_id=manifest.manifest_id,
                    version=manifest.source_version,
                    content_sha256=manifest.manifest_sha256,
                )
                discovered[kind] = self._discover(
                    epoch=epoch,
                    expected_ref=expected_ref,
                    artifact_kind=kind,
                    source_catalog_version=source_catalog_version,
                    expected_operation_id=operation_id,
                )
            self._validate_shared_builder_inputs(discovered)
            for kind in _COMPLETE_KINDS:
                self._validate_artifact(discovered[kind])
            result = ActiveRetrievalArtifactSet(
                wiki_index=discovered["wiki_index"].binding,
                knowledge_registry=discovered["knowledge_registry"].binding,
                lexical=discovered["lexical"].binding,
                vector=discovered["vector"].binding,
                graph=discovered["graph"].binding,
            )
            if began:
                self._connection.execute("COMMIT")
            for binding in result.bindings():
                binding.verify_current()
            return result
        except ArtifactVersionMismatch:
            if began and self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        except Exception:
            if began and self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise ArtifactVersionMismatch from None

    def discover_indexes(
        self,
        snapshot: AuthoritativeFilterSnapshot,
        roots: RootManifestSet,
    ) -> ActiveRetrievalArtifactSet:
        authority = AuthoritativeFilterSnapshot.model_validate(snapshot)
        root_set = RootManifestSet.model_validate(roots)
        current = self.discover_current_set()
        if (
            current is None
            or current.active_runtime_epoch != authority.global_runtime_epoch
            or current.roots != root_set
        ):
            raise ArtifactVersionMismatch
        return current

    def discover_root(
        self,
        snapshot: AuthoritativeFilterSnapshot,
        *,
        expected_ref: VersionRef,
        artifact_kind: DerivedArtifactKind,
        source_catalog_version: int,
    ) -> ArtifactBinding:
        """Discover and semantically validate one named active root."""

        authority = AuthoritativeFilterSnapshot.model_validate(snapshot)
        expected = VersionRef.model_validate(expected_ref)
        began = False
        try:
            if not self._connection.in_transaction:
                self._connection.execute("BEGIN")
                began = True
            discovered = self._discover(
                epoch=authority.global_runtime_epoch,
                expected_ref=expected,
                artifact_kind=artifact_kind,
                source_catalog_version=source_catalog_version,
                expected_operation_id=self._active_operation_id(
                    authority.global_runtime_epoch,
                    source_catalog_version=source_catalog_version,
                ),
            )
            self._validate_artifact(discovered)
            if began:
                self._connection.execute("COMMIT")
            discovered.binding.verify_current()
            return discovered.binding
        except ArtifactVersionMismatch:
            if began and self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        except Exception:
            if began and self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise ArtifactVersionMismatch from None

    def _discover(
        self,
        *,
        epoch: int,
        expected_ref: VersionRef,
        artifact_kind: DerivedArtifactKind,
        source_catalog_version: int,
        expected_operation_id: str,
    ) -> _DiscoveredArtifact:
        if type(source_catalog_version) is not int or source_catalog_version <= 0:
            raise ArtifactVersionMismatch
        state = self._connection.execute(
            "SELECT state FROM runtime_epochs WHERE epoch = ?",
            (epoch,),
        ).fetchone()
        if state != ("ACTIVE",):
            raise ArtifactVersionMismatch
        manifest = ManifestRepository(self._connection).get_active(
            artifact_kind,
            epoch=epoch,
        )
        self._validate_manifest(
            manifest,
            expected_ref=expected_ref,
            artifact_kind=artifact_kind,
            source_catalog_version=source_catalog_version,
            expected_operation_id=expected_operation_id,
        )
        identities: list[ArtifactMemberIdentity] = []
        references: list[tuple[ArtifactMemberIdentity, ContentObjectRef]] = []
        payloads: dict[str, bytes] = {}
        for member in manifest.members:
            reference = self._store.reference(
                content_sha256=member.object_sha256,
                media_type=member.media_type,
                size_bytes=member.size_bytes,
            )
            payload = self._store.read_verified(reference)
            if (
                len(payload) != member.size_bytes
                or hashlib.sha256(payload).hexdigest() != member.object_sha256
            ):
                raise ArtifactVersionMismatch
            identity = ArtifactMemberIdentity(
                role=member.object_type,
                object_id=member.object_id,
                content_sha256=member.object_sha256,
                media_type=member.media_type,
                size_bytes=member.size_bytes,
            )
            identities.append(identity)
            references.append((identity, reference))
            payloads[member.object_type] = payload
        builder_input = self._parse_builder_input(
            payloads[f"{artifact_kind}_builder_input"],
            artifact_kind=artifact_kind,
            source_catalog_version=source_catalog_version,
            target_runtime_epoch=epoch,
        )
        root_ref = VersionRef(
            object_id=manifest.manifest_id,
            version=manifest.source_version,
            content_sha256=manifest.manifest_sha256,
        )
        binding_identity = ArtifactBindingIdentity.create(
            artifact_key=artifact_kind,
            root_ref=root_ref,
            active_runtime_epoch=epoch,
            source_catalog_version=source_catalog_version,
            target_runtime_epoch=epoch,
            members=tuple(identities),
        )
        return _DiscoveredArtifact(
            binding=_new_artifact_binding(
                identity=binding_identity,
                members=tuple(references),
                store=self._store,
                live_verifier=self._verify_identity,
                authority_connection=self._connection,
            ),
            builder_input=builder_input,
            payloads=payloads,
        )

    def _active_operation_id(
        self,
        epoch: int,
        *,
        source_catalog_version: int,
    ) -> str:
        row = self._connection.execute(
            "SELECT runtime.operation_id, runtime.state, operation.state, "
            "operation.runtime_epoch, operation.authority_base_version "
            "FROM runtime_epochs AS runtime "
            "JOIN publication_operations AS operation "
            "  ON operation.operation_id = runtime.operation_id "
            "WHERE runtime.epoch = ?",
            (epoch,),
        ).fetchone()
        if (
            row is None
            or str(row[1]) != "ACTIVE"
            or str(row[2]) != "ACTIVE"
            or int(row[3]) != epoch
            or int(row[4]) != source_catalog_version
        ):
            raise ArtifactVersionMismatch
        operation_id = str(row[0])
        self._validate_active_operation_closure(
            epoch=epoch,
            operation_id=operation_id,
            source_catalog_version=source_catalog_version,
        )
        return operation_id

    def _validate_active_operation_closure(
        self,
        *,
        epoch: int,
        operation_id: str,
        source_catalog_version: int,
    ) -> None:
        """Revalidate the immutable operation-to-active-epoch closure."""

        operation = self._connection.execute(
            "SELECT state, required_manifests_json, required_manifest_count, "
            "verified_manifest_count, runtime_epoch, authority_base_version "
            "FROM publication_operations WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        runtime = self._connection.execute(
            "SELECT operation_id, state FROM runtime_epochs WHERE epoch = ?",
            (epoch,),
        ).fetchone()
        if (
            operation is None
            or runtime is None
            or str(operation[0]) != "ACTIVE"
            or type(operation[4]) is not int
            or operation[4] != epoch
            or type(operation[5]) is not int
            or operation[5] != source_catalog_version
            or str(runtime[0]) != operation_id
            or str(runtime[1]) != "ACTIVE"
        ):
            raise ArtifactVersionMismatch

        encoded_required = str(operation[1])
        decoded_required = json.loads(encoded_required)
        if type(decoded_required) is not list or any(
            type(value) is not str for value in decoded_required
        ):
            raise ArtifactVersionMismatch
        required = tuple(decoded_required)
        canonical_required = json.dumps(
            decoded_required,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        if (
            not required
            or required != tuple(sorted(set(required)))
            or encoded_required != canonical_required
            or type(operation[2]) is not int
            or type(operation[3]) is not int
        ):
            raise ArtifactVersionMismatch

        manifests = ManifestRepository(self._connection).list_for_operation(
            operation_id
        )
        actual_manifest_ids = tuple(manifest.manifest_id for manifest in manifests)
        manifest_count = len(manifests)
        generic_manifests = tuple(
            manifest
            for manifest in manifests
            if manifest.artifact_kind not in DEDICATED_ACTIVE_ARTIFACT_KEYS
        )
        dedicated_manifests = tuple(
            manifest
            for manifest in manifests
            if manifest.artifact_kind in DEDICATED_ACTIVE_ARTIFACT_KEYS
        )
        if (
            actual_manifest_ids != required
            or operation[2] != manifest_count
            or operation[3] != manifest_count
            or len(generic_manifests) + len(dedicated_manifests)
            != manifest_count
            or any(
                manifest.operation_id != operation_id
                or manifest.state != "ACTIVE"
                or not manifest.verified
                for manifest in manifests
            )
            or any(
                manifest.artifact_key in DEDICATED_ACTIVE_ARTIFACT_KEYS
                or manifest.artifact_kind in DEDICATED_ACTIVE_ARTIFACT_KEYS
                for manifest in generic_manifests
            )
            or any(
                manifest.artifact_key != manifest.artifact_kind
                for manifest in dedicated_manifests
            )
            or any(
                manifest.source_version != source_catalog_version
                for manifest in generic_manifests
            )
        ):
            raise ArtifactVersionMismatch

        active_rows = tuple(
            (str(row[0]), str(row[1]))
            for row in self._connection.execute(
                "SELECT artifact_key, manifest_id FROM active_artifacts "
                "WHERE epoch = ? ORDER BY artifact_key",
                (epoch,),
            ).fetchall()
        )
        expected_active_rows = tuple(
            sorted(
                (manifest.artifact_key, manifest.manifest_id)
                for manifest in manifests
            )
        )
        if active_rows != expected_active_rows:
            raise ArtifactVersionMismatch

    @staticmethod
    def _validate_manifest(
        manifest: ArtifactManifest,
        *,
        expected_ref: VersionRef,
        artifact_kind: DerivedArtifactKind,
        source_catalog_version: int,
        expected_operation_id: str,
    ) -> None:
        actual_ref = VersionRef(
            object_id=manifest.manifest_id,
            version=manifest.source_version,
            content_sha256=manifest.manifest_sha256,
        )
        validate_derived_artifact_role_layout(
            artifact_kind,
            tuple(member.object_type for member in manifest.members),
        )
        validate_derived_artifact_media_type_layout(
            artifact_kind,
            tuple(member.media_type for member in manifest.members),
        )
        if (
            actual_ref != expected_ref
            or manifest.artifact_key != artifact_kind
            or manifest.artifact_kind != artifact_kind
            or manifest.operation_id != expected_operation_id
            or manifest.source_version != source_catalog_version
            or manifest.state != "ACTIVE"
            or not manifest.verified
            or any(
                member.source_version != source_catalog_version
                for member in manifest.members
            )
        ):
            raise ArtifactVersionMismatch

    @staticmethod
    def _parse_builder_input(
        payload: bytes,
        *,
        artifact_kind: DerivedArtifactKind,
        source_catalog_version: int,
        target_runtime_epoch: int,
    ) -> DerivedArtifactBuilderInputV2:
        value = DerivedArtifactBuilderInputV2.model_validate_json(
            payload,
            strict=True,
        )
        if (
            value.artifact_kind != artifact_kind
            or value.source_catalog_version != source_catalog_version
            or value.target_runtime_epoch != target_runtime_epoch
        ):
            raise ArtifactVersionMismatch
        return value

    @staticmethod
    def _validate_shared_builder_inputs(
        discovered: Mapping[DerivedArtifactKind, _DiscoveredArtifact],
    ) -> None:
        if set(discovered) != set(_COMPLETE_KINDS):
            raise ArtifactVersionMismatch
        first = discovered[_COMPLETE_KINDS[0]].builder_input
        shared = (
            first.authority_closure_sha256,
            first.authority_snapshot,
            first.retrieval_input_descriptor,
            first.target_runtime_epoch,
        )
        for kind in _COMPLETE_KINDS:
            value = discovered[kind].builder_input
            if (
                value.artifact_kind != kind
                or (
                    value.authority_closure_sha256,
                    value.authority_snapshot,
                    value.retrieval_input_descriptor,
                    value.target_runtime_epoch,
                )
                != shared
            ):
                raise ArtifactVersionMismatch

    @staticmethod
    def _validate_artifact(discovered: _DiscoveredArtifact) -> None:
        kind = discovered.binding.identity.artifact_key
        payloads = discovered.payloads
        builder_input = discovered.builder_input
        members = discovered.binding.identity.members
        if kind == "lexical":
            lexical_manifest = LexicalBuildManifest.model_validate_json(
                payloads["lexical_build_manifest"], strict=True
            )
            validate_builder_manifest_binding(
                "lexical", builder_input, lexical_manifest
            )
            by_role = {member.role: member for member in members}
            if (
                lexical_manifest.index_sha256
                != by_role["lexical_index"].content_sha256
            ):
                raise ArtifactVersionMismatch
            return
        if kind == "vector":
            vector_manifest = VectorBuildManifest.model_validate_json(
                payloads["vector_build_manifest"], strict=True
            )
            validate_builder_manifest_binding(
                "vector", builder_input, vector_manifest
            )
            by_role = {member.role: member for member in members}
            if (
                vector_manifest.metadata_sha256
                != by_role["vector_metadata"].content_sha256
                or vector_manifest.vector_sha256
                != by_role["vector_shard"].content_sha256
            ):
                raise ArtifactVersionMismatch
            return
        if kind in {"wiki_index", "knowledge_registry"}:
            generic_manifest = GenericDerivedBuildManifestV2.model_validate_json(
                payloads[f"{kind}_build_manifest"], strict=True
            )
            generic_manifest.verify_builder_input(builder_input)
            by_role = {member.role: member for member in members}
            if generic_manifest.member_content_sha256 != {
                role: by_role[role].content_sha256
                for role in generic_manifest.member_content_sha256
            }:
                raise ArtifactVersionMismatch
            if kind == "knowledge_registry":
                registry = KnowledgeRegistryPayloadV1.model_validate_json(
                    payloads["knowledge_registry"], strict=True
                )
                registry.verify_descriptor(
                    builder_input.retrieval_input_descriptor
                )
                member = by_role["retrieval_route_policy"]
                expected_policy_ref = VersionRef(
                    object_id=member.object_id,
                    version=builder_input.source_catalog_version,
                    content_sha256=member.content_sha256,
                )
                if (
                    builder_input.retrieval_input_descriptor.route_policy_ref
                    != expected_policy_ref
                ):
                    raise ArtifactVersionMismatch
            else:
                wiki_index = WikiNavigationIndexPayloadV2.model_validate_json(
                    payloads["wiki_index"], strict=True
                )
                wiki_index.verify_builder_input(builder_input)
            return
        if kind == "graph":
            from consultation_kb.graph.artifact_contracts import (
                verify_graph_member_payloads,
            )

            verify_graph_member_payloads(payloads, members=members)
            return
        raise ArtifactVersionMismatch

    def _verify_identity(self, identity: ArtifactBindingIdentity) -> None:
        began = False
        try:
            if not self._connection.in_transaction:
                self._connection.execute("BEGIN")
                began = True
            state = self._connection.execute(
                "SELECT state FROM runtime_epochs WHERE epoch = ?",
                (identity.active_runtime_epoch,),
            ).fetchone()
            if state != ("ACTIVE",):
                raise ArtifactVersionMismatch
            manifest = ManifestRepository(self._connection).get_active(
                identity.artifact_key,
                epoch=identity.active_runtime_epoch,
            )
            self._validate_manifest(
                manifest,
                expected_ref=identity.root_ref,
                artifact_kind=identity.artifact_key,
                source_catalog_version=identity.source_catalog_version,
                expected_operation_id=self._active_operation_id(
                    identity.active_runtime_epoch,
                    source_catalog_version=identity.source_catalog_version,
                ),
            )
            actual_members = tuple(
                ArtifactMemberIdentity(
                    role=member.object_type,
                    object_id=member.object_id,
                    content_sha256=member.object_sha256,
                    media_type=member.media_type,
                    size_bytes=member.size_bytes,
                )
                for member in manifest.members
            )
            if actual_members != identity.members:
                raise ArtifactVersionMismatch
            payloads: dict[str, bytes] = {}
            for member in manifest.members:
                reference = self._store.reference(
                    content_sha256=member.object_sha256,
                    media_type=member.media_type,
                    size_bytes=member.size_bytes,
                )
                payload = self._store.read_verified(reference)
                if hashlib.sha256(payload).hexdigest() != member.object_sha256:
                    raise ArtifactVersionMismatch
                payloads[member.object_type] = payload
            self._parse_builder_input(
                payloads[f"{identity.artifact_key}_builder_input"],
                artifact_kind=identity.artifact_key,
                source_catalog_version=identity.source_catalog_version,
                target_runtime_epoch=identity.target_runtime_epoch,
            )
            if began:
                self._connection.execute("COMMIT")
        except ArtifactVersionMismatch:
            if began and self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        except Exception:
            if began and self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise ArtifactVersionMismatch from None


class ActiveRetrievalArtifactGate:
    """Coordinator gate for exact roots and opaque route-retriever bindings."""

    def __init__(self, discovery: ActiveRetrievalArtifactDiscovery) -> None:
        if type(discovery) is not ActiveRetrievalArtifactDiscovery:
            raise TypeError("RETRIEVAL_ARTIFACT_DISCOVERY_REQUIRED")
        self._discovery = discovery

    def verify(
        self,
        snapshot: AuthoritativeFilterSnapshot,
        roots: RootManifestSet,
        retrievers: Mapping[str, Retriever],
        routes: tuple[str, ...],
    ) -> None:
        try:
            current = self._discovery.discover_indexes(snapshot, roots)
            expected = {
                "wiki": current.wiki_index,
                "lexical": current.lexical,
                "vector": current.vector,
                "global_graph": current.graph,
            }
            for route in routes:
                if route in {"profile", "client_history"}:
                    continue
                if route == "case":
                    retriever = retrievers.get(route)
                    actual_bindings = getattr(
                        retriever,
                        "artifact_bindings",
                        None,
                    )
                    case_expected = {
                        "lexical": current.lexical,
                        "vector": current.vector,
                    }
                    if (
                        not isinstance(actual_bindings, Mapping)
                        or set(actual_bindings) != set(case_expected)
                    ):
                        raise ArtifactVersionMismatch
                    for name, expected_binding in case_expected.items():
                        actual = actual_bindings.get(name)
                        if (
                            type(actual) is not ArtifactBinding
                            or actual.identity != expected_binding.identity
                        ):
                            raise ArtifactVersionMismatch
                        actual.verify_current()
                    continue
                binding = expected.get(route)
                retriever = retrievers.get(route)
                actual = getattr(retriever, "artifact_binding", None)
                if (
                    binding is None
                    or type(actual) is not ArtifactBinding
                    or actual.identity != binding.identity
                ):
                    raise ArtifactVersionMismatch
                actual.verify_current()
        except ArtifactVersionMismatch:
            raise
        except Exception:
            raise ArtifactVersionMismatch from None


__all__ = [
    "ActiveRetrievalArtifactDiscovery",
    "ActiveRetrievalArtifactGate",
    "ActiveRetrievalArtifactSet",
    "ActiveRetrievalIndexSet",
]
