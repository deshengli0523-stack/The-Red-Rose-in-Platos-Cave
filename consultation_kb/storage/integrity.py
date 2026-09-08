"""Fail-closed integrity contracts for active artifacts and closure DAGs."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, TypeAlias

from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import AuthoritativeFilterSnapshot
from consultation_kb.storage.manifests import (
    ArtifactManifest,
    ManifestRepository,
)
from consultation_kb.storage.tombstones import (
    ObjectIdentity,
    TombstoneRepository,
    VisibilityGuard,
)
from consultation_kb.vault.content_store import ContentStore


IntegrityScope: TypeAlias = Literal["global", "client_private", "session", "run"]

_ROLE_SCOPES: dict[str, frozenset[IntegrityScope]] = {
    "authority_snapshot": frozenset({"run"}),
    "authority_policy": frozenset({"global"}),
    "client_manifest": frozenset({"client_private"}),
    "client_snapshot": frozenset({"client_private"}),
    "temporary_fact": frozenset({"session"}),
    "candidate_manifest": frozenset({"global", "client_private"}),
    "candidate_object": frozenset({"global", "client_private"}),
    "candidate_text": frozenset({"global", "client_private"}),
    "candidate_anchor": frozenset({"global", "client_private"}),
    "candidate_provenance": frozenset({"global", "client_private", "run"}),
    "locator_policy": frozenset({"global"}),
    "freshness_policy": frozenset({"global"}),
    "derivation_rule": frozenset({"global"}),
    "c1_revision": frozenset({"global"}),
    "c1_scope_policy": frozenset({"global"}),
    "c1_rule_manifest": frozenset({"global"}),
    "c1_context_field_manifest": frozenset({"global"}),
    "unresolved_conflict": frozenset({"run"}),
    "exclusion_proof": frozenset({"run"}),
    "wiki_manifest": frozenset({"global"}),
    "lexical_manifest": frozenset({"global"}),
    "vector_manifest": frozenset({"global"}),
    "graph_manifest": frozenset({"global"}),
    "knowledge_manifest": frozenset({"global"}),
    "reranker_descriptor": frozenset({"global"}),
    "leave_one_out_variant": frozenset({"global"}),
    "leave_one_out_mapping": frozenset({"global"}),
    "leave_one_out_parent": frozenset({"global"}),
    "leave_one_out_authority_manifest": frozenset({"global"}),
    "leave_one_out_provenance": frozenset({"global"}),
}
_AUTHORITY_BOUND_ROLES = frozenset(
    {
        "candidate_manifest",
        "candidate_object",
        "candidate_text",
        "candidate_anchor",
        "candidate_provenance",
        "leave_one_out_variant",
        "leave_one_out_mapping",
        "leave_one_out_parent",
        "leave_one_out_authority_manifest",
        "leave_one_out_provenance",
    }
)
_LOO_ROLES = frozenset(
    {
        "leave_one_out_variant",
        "leave_one_out_mapping",
        "leave_one_out_parent",
        "leave_one_out_authority_manifest",
        "leave_one_out_provenance",
    }
)
_SAFE_KEY = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z")


def _publication_manifest_closure_sha256(
    *,
    purpose: str,
    authority_version: int,
    expected_current_epoch: int | None,
    artifacts: tuple[ArtifactManifest, ...],
) -> str:
    """Recompute the persisted publication-v2 envelope from storage models."""

    if (
        type(purpose) is not str
        or _SAFE_KEY.fullmatch(purpose) is None
        or type(authority_version) is not int
        or authority_version <= 0
        or (
            expected_current_epoch is not None
            and (
                type(expected_current_epoch) is not int
                or expected_current_epoch <= 0
            )
        )
        or type(artifacts) is not tuple
        or not artifacts
        or any(type(value) is not ArtifactManifest for value in artifacts)
    ):
        raise ArtifactUnavailable
    bodies: list[dict[str, object]] = []
    manifest_ids: list[str] = []
    artifact_keys: list[str] = []
    for artifact in artifacts:
        if artifact.source_version != authority_version:
            raise ArtifactUnavailable
        manifest_ids.append(artifact.manifest_id)
        artifact_keys.append(artifact.artifact_key)
        bodies.append(
            {
                "artifact_key": artifact.artifact_key,
                "artifact_kind": artifact.artifact_kind,
                "manifest_id": artifact.manifest_id,
                "members": [
                    {
                        "content_sha256": member.object_sha256,
                        "media_type": member.media_type,
                        "object_id": member.object_id,
                        "object_type": member.object_type,
                        "ordinal": ordinal,
                        "size_bytes": member.size_bytes,
                        "source_lineage_hashes": list(
                            member.source_lineage_hashes
                        ),
                        "source_version": member.source_version,
                    }
                    for ordinal, member in enumerate(artifact.members)
                ],
                "source_version": artifact.source_version,
            }
        )
    if (
        len(set(manifest_ids)) != len(manifest_ids)
        or len(set(artifact_keys)) != len(artifact_keys)
    ):
        raise ArtifactUnavailable
    encoded = json.dumps(
        {
            "artifacts": sorted(
                bodies,
                key=lambda value: str(value["manifest_id"]),
            ),
            "authority_base_version": authority_version,
            "expected_current_epoch": expected_current_epoch,
            "purpose": purpose,
        },
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(
        b"consultation-kb-publication-envelope-v2\0" + encoded
    ).hexdigest()


class ArtifactUnavailable(RuntimeError):
    """Uniform non-oracular denial for missing, corrupt, or unauthorized data."""

    def __init__(self) -> None:
        super().__init__("ARTIFACT_UNAVAILABLE")


@dataclass(frozen=True, slots=True)
class IntegrityStore:
    scope: IntegrityScope
    connection: sqlite3.Connection
    content_store: ContentStore
    client_id: str | None = None

    def __post_init__(self) -> None:
        if self.scope not in {"global", "client_private", "session", "run"}:
            raise ValueError("INTEGRITY_SCOPE_INVALID")
        if not isinstance(self.connection, sqlite3.Connection):
            raise TypeError("INTEGRITY_CONNECTION_REQUIRED")
        if type(self.content_store) is not ContentStore:
            raise TypeError("INTEGRITY_CONTENT_STORE_REQUIRED")
        if self.scope == "global":
            if self.client_id is not None:
                raise ValueError("GLOBAL_INTEGRITY_CLIENT_UNEXPECTED")
        elif type(self.client_id) is not str or not self.client_id:
            raise ValueError("SCOPED_INTEGRITY_CLIENT_REQUIRED")


@dataclass(frozen=True, slots=True)
class ActiveArtifact:
    artifact_key: str
    manifest_ref: VersionRef

    def __post_init__(self) -> None:
        if type(self.artifact_key) is not str or not self.artifact_key:
            raise ValueError("ACTIVE_ARTIFACT_KEY_INVALID")
        VersionRef.model_validate(self.manifest_ref)


@dataclass(frozen=True, slots=True)
class ScopedReference:
    scope: IntegrityScope
    reference: VersionRef


@dataclass(frozen=True, slots=True)
class ClosureNode:
    role: str
    reference: VersionRef
    scope: IntegrityScope
    authority_ref: VersionRef | None = None
    owner_client_id: str | None = None
    run_id: str | None = None
    session_id: str | None = None
    selection_version: int | None = None
    closure_group: str | None = None

    @property
    def key(self) -> ScopedReference:
        return ScopedReference(scope=self.scope, reference=self.reference)


@dataclass(frozen=True, slots=True)
class ClosureEdge:
    parent: ScopedReference
    child: ScopedReference


@dataclass(frozen=True, slots=True)
class IntegrityContext:
    authority_snapshot: AuthoritativeFilterSnapshot
    current_client_id: str
    session_id: str
    selection_cutoff_version: int

    def __post_init__(self) -> None:
        AuthoritativeFilterSnapshot.model_validate(self.authority_snapshot)
        if type(self.current_client_id) is not str or not self.current_client_id:
            raise ValueError("INTEGRITY_CLIENT_INVALID")
        if type(self.session_id) is not str or not self.session_id:
            raise ValueError("INTEGRITY_SESSION_INVALID")
        if (
            type(self.selection_cutoff_version) is not int
            or self.selection_cutoff_version < 0
        ):
            raise ValueError("INTEGRITY_SELECTION_CUTOFF_INVALID")


class IntegrityVerifier:
    """Verify exact active manifests and their scope-bound immutable closure."""

    def __init__(self, stores: tuple[IntegrityStore, ...]) -> None:
        if (
            type(stores) is not tuple
            or not stores
            or any(type(value) is not IntegrityStore for value in stores)
        ):
            raise TypeError("INTEGRITY_STORE_TUPLE_REQUIRED")
        scopes = tuple(value.scope for value in stores)
        if len(scopes) != len(set(scopes)):
            raise ValueError("INTEGRITY_STORE_SCOPE_CONFLICT")
        self._stores = {value.scope: value for value in stores}

    def verify_active(
        self,
        *,
        scope: IntegrityScope,
        epoch: int,
        artifacts: tuple[ActiveArtifact, ...],
        dedicated_artifacts: tuple[ActiveArtifact, ...] = (),
        source_version: int,
        authority_version: int | None = None,
        tombstone_epoch: int | None = None,
        authorization_epoch: int | None = None,
    ) -> None:
        try:
            self._verify_active(
                scope=scope,
                epoch=epoch,
                artifacts=artifacts,
                dedicated_artifacts=dedicated_artifacts,
                source_version=source_version,
                authority_version=authority_version,
                tombstone_epoch=tombstone_epoch,
                authorization_epoch=authorization_epoch,
            )
        except ArtifactUnavailable:
            raise
        except Exception:
            raise ArtifactUnavailable from None

    def verify_closure(
        self,
        *,
        context: IntegrityContext,
        roots: tuple[ClosureNode, ...],
        nodes: tuple[ClosureNode, ...],
        edges: tuple[ClosureEdge, ...],
    ) -> None:
        try:
            self._verify_closure(
                context=context,
                roots=roots,
                nodes=nodes,
                edges=edges,
            )
        except ArtifactUnavailable:
            raise
        except Exception:
            raise ArtifactUnavailable from None

    def _store(self, scope: IntegrityScope) -> IntegrityStore:
        value = self._stores.get(scope)
        if value is None:
            raise ArtifactUnavailable
        return value

    def _verify_active(
        self,
        *,
        scope: IntegrityScope,
        epoch: int,
        artifacts: tuple[ActiveArtifact, ...],
        dedicated_artifacts: tuple[ActiveArtifact, ...] = (),
        source_version: int,
        authority_version: int | None,
        tombstone_epoch: int | None,
        authorization_epoch: int | None,
    ) -> None:
        if (
            scope not in {"global", "client_private", "session", "run"}
            or type(epoch) is not int
            or epoch <= 0
            or type(source_version) is not int
            or source_version <= 0
            or (
                authority_version is not None
                and (
                    type(authority_version) is not int
                    or authority_version < 0
                )
            )
            or (
                tombstone_epoch is not None
                and (type(tombstone_epoch) is not int or tombstone_epoch < 0)
            )
            or (
                authorization_epoch is not None
                and (type(authorization_epoch) is not int or authorization_epoch < 0)
            )
            or type(artifacts) is not tuple
            or not artifacts
            or any(type(value) is not ActiveArtifact for value in artifacts)
            or type(dedicated_artifacts) is not tuple
            or any(
                type(value) is not ActiveArtifact
                for value in dedicated_artifacts
            )
        ):
            raise ArtifactUnavailable
        all_artifacts = (*artifacts, *dedicated_artifacts)
        keys = tuple(value.artifact_key for value in all_artifacts)
        if len(keys) != len(set(keys)):
            raise ArtifactUnavailable
        store = self._store(scope)
        connection = store.connection
        active_epochs = connection.execute(
            "SELECT epoch, operation_id FROM runtime_epochs "
            "WHERE state = 'ACTIVE' ORDER BY epoch"
        ).fetchall()
        if len(active_epochs) != 1 or int(active_epochs[0][0]) != epoch:
            raise ArtifactUnavailable
        operation_id = str(active_epochs[0][1])
        active_rows = connection.execute(
            "SELECT artifact_key, manifest_id FROM active_artifacts "
            "WHERE epoch = ? ORDER BY artifact_key",
            (epoch,),
        ).fetchall()
        expected = {
            value.artifact_key: value.manifest_ref for value in all_artifacts
        }
        if len(active_rows) != len(expected):
            raise ArtifactUnavailable
        matches = [
            (str(row[0]), str(row[1])) for row in active_rows if str(row[0]) in expected
        ]
        if len(matches) != len(expected):
            raise ArtifactUnavailable
        actual = dict(matches)
        for artifact in artifacts:
            reference = VersionRef.model_validate(artifact.manifest_ref)
            if (
                reference.version != source_version
                or actual.get(artifact.artifact_key) != reference.object_id
            ):
                raise ArtifactUnavailable
            manifest = self._manifest(store, reference)
            if (
                manifest.operation_id != operation_id
                or manifest.artifact_key != artifact.artifact_key
                or manifest.source_version != source_version
                or manifest.state != "ACTIVE"
                or not manifest.verified
            ):
                raise ArtifactUnavailable
        for artifact in dedicated_artifacts:
            reference = VersionRef.model_validate(artifact.manifest_ref)
            if actual.get(artifact.artifact_key) != reference.object_id:
                raise ArtifactUnavailable
            manifest = ManifestRepository(connection).get(reference.object_id)
            if (
                manifest.operation_id != operation_id
                or manifest.artifact_key != artifact.artifact_key
                or manifest.source_version != reference.version
                or manifest.manifest_sha256 != reference.content_sha256
                or manifest.state != "ACTIVE"
                or not manifest.verified
            ):
                raise ArtifactUnavailable
        self._verify_authority_epochs(
            store,
            epoch=epoch,
            source_version=source_version,
            authority_version=authority_version,
            tombstone_epoch=tombstone_epoch,
            authorization_epoch=authorization_epoch,
        )

    def _verify_authority_epochs(
        self,
        store: IntegrityStore,
        *,
        epoch: int,
        source_version: int,
        authority_version: int | None,
        tombstone_epoch: int | None,
        authorization_epoch: int | None,
    ) -> None:
        operation = store.connection.execute(
            "SELECT publication.purpose, binding.tombstone_epoch "
            "FROM runtime_epochs AS runtime "
            "JOIN publication_operations AS publication "
            "  ON publication.operation_id = runtime.operation_id "
            "LEFT JOIN rebuild_stage_bindings AS binding "
            "  ON binding.operation_id = runtime.operation_id "
            "WHERE runtime.epoch = ? AND runtime.state = 'ACTIVE'",
            (epoch,),
        ).fetchone()
        if operation is None:
            raise ArtifactUnavailable
        rebuild_tombstone_epoch = (
            None
            if operation[0] != "rebuild" or operation[1] is None
            else int(operation[1])
        )
        if operation[0] == "rebuild" and rebuild_tombstone_epoch is None:
            raise ArtifactUnavailable
        if store.scope == "global":
            row = store.connection.execute(
                "SELECT catalog_version, authorization_epoch, tombstone_epoch "
                "FROM knowledge_catalog_state WHERE singleton = 1"
            ).fetchone()
            expected_authority_version = (
                source_version
                if authority_version is None
                else authority_version
            )
            if row is None or int(row[0]) != expected_authority_version:
                raise ArtifactUnavailable
            if (
                rebuild_tombstone_epoch is not None
                and rebuild_tombstone_epoch != int(row[2])
            ):
                raise ArtifactUnavailable
            if tombstone_epoch is not None and int(row[2]) != tombstone_epoch:
                raise ArtifactUnavailable
            if authorization_epoch is not None and int(row[1]) != authorization_epoch:
                raise ArtifactUnavailable
            return
        if authority_version is not None and authority_version != source_version:
            raise ArtifactUnavailable
        if authorization_epoch is not None:
            raise ArtifactUnavailable
        authority = store.connection.execute(
            "SELECT commit_version, client_id FROM client_fact_authority "
            "WHERE singleton = 1"
        ).fetchone()
        if (
            authority is None
            or int(authority[0]) < source_version
            or str(authority[1]) != store.client_id
        ):
            raise ArtifactUnavailable
        current_version = int(authority[0])
        if current_version > source_version:
            active_execution = store.connection.execute(
                "SELECT execution.target_scope_hash, execution.state "
                "FROM runtime_epochs AS runtime "
                "JOIN approval_executions AS execution "
                "  ON execution.operation_id = runtime.operation_id "
                "WHERE runtime.epoch = ? AND runtime.state = 'ACTIVE'",
                (epoch,),
            ).fetchone()
            if (
                active_execution is None
                or type(active_execution[0]) is not str
                or active_execution[1] != "APPLIED"
            ):
                raise ArtifactUnavailable
            target_scope_hash = str(active_execution[0])
            pending_rows = store.connection.execute(
                "SELECT operation_id, purpose, authority_base_version, "
                "approval_request_id, descriptor_sha256, state, "
                "required_manifests_json, required_manifest_count, "
                "verified_manifest_count, expected_current_epoch, "
                "runtime_epoch "
                "FROM publication_operations "
                "WHERE authority_base_version > ? "
                "AND authority_base_version <= ? "
                "AND state IN ('PREPARED', 'VERIFIED') "
                "ORDER BY authority_base_version, operation_id",
                (source_version, current_version),
            ).fetchall()
            expected_versions = tuple(range(source_version + 1, current_version + 1))
            if tuple(int(row[2]) for row in pending_rows) != expected_versions:
                raise ArtifactUnavailable
            for row in pending_rows:
                if (
                    type(row[0]) is not str
                    or type(row[1]) is not str
                    or type(row[3]) is not str
                    or type(row[4]) is not str
                    or row[5] not in {"PREPARED", "VERIFIED"}
                    or row[9] != epoch
                    or row[10] is not None
                ):
                    raise ArtifactUnavailable
                execution = store.connection.execute(
                    "SELECT request_id, descriptor_sha256, draft_sha256, "
                    "descriptor_base_version, target_scope_hash, state, "
                    "applied_commit_version, applied_at "
                    "FROM approval_executions WHERE operation_id = ?",
                    (row[0],),
                ).fetchone()
                if (
                    execution is None
                    or execution[0] != row[3]
                    or execution[1] != row[4]
                    or type(execution[2]) is not str
                    or type(execution[3]) is not int
                    or int(execution[3]) + 1 != int(row[2])
                    or execution[4] != target_scope_hash
                    or execution[5] != "APPLIED"
                    or type(execution[6]) is not int
                    or int(execution[6]) <= 0
                    or execution[7] is None
                ):
                    raise ArtifactUnavailable
                try:
                    required_value = json.loads(str(row[6]))
                except json.JSONDecodeError:
                    raise ArtifactUnavailable from None
                if (
                    type(required_value) is not list
                    or any(type(value) is not str for value in required_value)
                ):
                    raise ArtifactUnavailable
                required = tuple(required_value)
                if (
                    not required
                    or required != tuple(sorted(set(required)))
                    or type(row[7]) is not int
                    or int(row[7]) != len(required)
                    or type(row[8]) is not int
                ):
                    raise ArtifactUnavailable
                manifest_ids = tuple(
                    str(value[0])
                    for value in store.connection.execute(
                        "SELECT manifest_id FROM artifact_manifests "
                        "WHERE operation_id = ? ORDER BY manifest_id",
                        (row[0],),
                    )
                )
                if manifest_ids != required:
                    raise ArtifactUnavailable
                manifests = tuple(
                    ManifestRepository(store.connection).get(manifest_id)
                    for manifest_id in manifest_ids
                )
                if (
                    any(
                        manifest.operation_id != row[0]
                        or manifest.source_version != int(row[2])
                        or manifest.state not in {"PREPARED", "VERIFIED"}
                        for manifest in manifests
                    )
                    or sum(manifest.verified for manifest in manifests)
                    != int(row[8])
                    or (
                        row[5] == "VERIFIED"
                        and int(row[8]) != len(manifests)
                    )
                ):
                    raise ArtifactUnavailable
                attestation = store.connection.execute(
                    "SELECT approval_draft_sha256, closure_sha256 "
                    "FROM publication_closure_attestations "
                    "WHERE operation_id = ?",
                    (row[0],),
                ).fetchone()
                if (
                    attestation is None
                    or attestation[0] != execution[2]
                    or attestation[1]
                    != _publication_manifest_closure_sha256(
                        purpose=str(row[1]),
                        authority_version=int(row[2]),
                        expected_current_epoch=(
                            None if row[9] is None else int(row[9])
                        ),
                        artifacts=manifests,
                    )
                ):
                    raise ArtifactUnavailable
        if tombstone_epoch is not None:
            row = store.connection.execute("SELECT COUNT(*) FROM tombstones").fetchone()
            if row is None or int(row[0]) != tombstone_epoch:
                raise ArtifactUnavailable
            if (
                rebuild_tombstone_epoch is not None
                and rebuild_tombstone_epoch != tombstone_epoch
            ):
                raise ArtifactUnavailable

    def _manifest(
        self,
        store: IntegrityStore,
        reference: VersionRef,
    ) -> ArtifactManifest:
        exact = VersionRef.model_validate(reference)
        manifest = ManifestRepository(store.connection).get(exact.object_id)
        if (
            manifest.source_version != exact.version
            or manifest.manifest_sha256 != exact.content_sha256
            or manifest.state != "ACTIVE"
            or not manifest.verified
        ):
            raise ArtifactUnavailable
        guard = VisibilityGuard(TombstoneRepository(store.connection))
        guard.assert_visible(
            ObjectIdentity(
                object_type=manifest.manifest_id[:-37],
                object_id=manifest.manifest_id,
            ),
            source_lineage_hashes=(),
        )
        for member in manifest.members:
            if member.source_version != manifest.source_version:
                raise ArtifactUnavailable
            guard.assert_visible(
                ObjectIdentity(
                    object_type=member.object_type,
                    object_id=member.object_id,
                ),
                source_lineage_hashes=member.source_lineage_hashes,
            )
            opaque = store.content_store.reference(
                content_sha256=member.object_sha256,
                media_type=member.media_type,
                size_bytes=member.size_bytes,
            )
            store.content_store.read_verified(opaque)
        return manifest

    def _verify_closure(
        self,
        *,
        context: IntegrityContext,
        roots: tuple[ClosureNode, ...],
        nodes: tuple[ClosureNode, ...],
        edges: tuple[ClosureEdge, ...],
    ) -> None:
        if (
            type(context) is not IntegrityContext
            or type(roots) is not tuple
            or not roots
            or type(nodes) is not tuple
            or not nodes
            or type(edges) is not tuple
            or any(type(value) is not ClosureNode for value in (*roots, *nodes))
            or any(type(value) is not ClosureEdge for value in edges)
        ):
            raise ArtifactUnavailable
        snapshot = AuthoritativeFilterSnapshot.model_validate(
            context.authority_snapshot
        )
        all_nodes = (*roots, *nodes)
        by_key = {node.key: node for node in all_nodes}
        if len(by_key) != len(all_nodes):
            raise ArtifactUnavailable
        root_keys = frozenset(node.key for node in roots)
        node_keys = frozenset(node.key for node in nodes)
        if root_keys & node_keys:
            raise ArtifactUnavailable
        for node in all_nodes:
            self._verify_node(node, context=context, snapshot=snapshot)
            self._verify_node_store_binding(node, context=context)
        self._verify_root_sets(roots, snapshot=snapshot)

        edge_pairs = {(edge.parent, edge.child) for edge in edges}
        if len(edge_pairs) != len(edges):
            raise ArtifactUnavailable
        children: dict[ScopedReference, set[ScopedReference]] = defaultdict(set)
        parents: dict[ScopedReference, set[ScopedReference]] = defaultdict(set)
        for parent_key, child_key in edge_pairs:
            if (
                parent_key not in by_key
                or child_key not in by_key
                or child_key in root_keys
                or parent_key.scope != child_key.scope
            ):
                raise ArtifactUnavailable
            parent = by_key[parent_key]
            child = by_key[child_key]
            manifest = self._manifest(
                self._store(parent.scope),
                parent.reference,
            )
            if not self._manifest_contains(manifest, child.reference):
                raise ArtifactUnavailable
            children[parent_key].add(child_key)
            parents[child_key].add(parent_key)
        if any(key not in parents for key in node_keys):
            raise ArtifactUnavailable
        self._assert_reachable_acyclic(
            root_keys=root_keys,
            all_keys=frozenset(by_key),
            children=children,
        )
        self._verify_loo_groups(nodes, parents=parents)

    def _verify_root_sets(
        self,
        roots: tuple[ClosureNode, ...],
        *,
        snapshot: AuthoritativeFilterSnapshot,
    ) -> None:
        grouped: dict[IntegrityScope, list[ActiveArtifact]] = defaultdict(list)
        versions: dict[IntegrityScope, set[int]] = defaultdict(set)
        for root in roots:
            store = self._store(root.scope)
            manifest = self._manifest(store, root.reference)
            grouped[root.scope].append(
                ActiveArtifact(manifest.artifact_key, root.reference)
            )
            versions[root.scope].add(root.reference.version)
        for scope, artifacts in grouped.items():
            if len(versions[scope]) != 1:
                raise ArtifactUnavailable
            version = next(iter(versions[scope]))
            if scope == "global":
                self._verify_active(
                    scope=scope,
                    epoch=snapshot.global_runtime_epoch,
                    artifacts=tuple(artifacts),
                    source_version=version,
                    authority_version=None,
                    tombstone_epoch=snapshot.tombstone_epoch >> 32,
                    authorization_epoch=snapshot.authorization_epoch,
                )
            else:
                self._verify_active(
                    scope=scope,
                    epoch=snapshot.client_runtime_epoch,
                    artifacts=tuple(artifacts),
                    source_version=version,
                    authority_version=None,
                    tombstone_epoch=snapshot.tombstone_epoch & (2**32 - 1),
                    authorization_epoch=None,
                )

    @staticmethod
    def _manifest_contains(
        manifest: ArtifactManifest,
        reference: VersionRef,
    ) -> bool:
        exact = VersionRef.model_validate(reference)
        matches = tuple(
            member for member in manifest.members if member.object_id == exact.object_id
        )
        return len(matches) == 1 and (
            matches[0].object_sha256 == exact.content_sha256
            and matches[0].source_version == exact.version
        )

    @staticmethod
    def _verify_node(
        node: ClosureNode,
        *,
        context: IntegrityContext,
        snapshot: AuthoritativeFilterSnapshot,
    ) -> None:
        allowed_scopes = _ROLE_SCOPES.get(node.role)
        if allowed_scopes is None or node.scope not in allowed_scopes:
            raise ArtifactUnavailable
        if node.scope == "global":
            if (
                node.owner_client_id is not None
                or node.run_id is not None
                or node.session_id is not None
            ):
                raise ArtifactUnavailable
        elif node.scope == "client_private":
            if (
                node.owner_client_id != context.current_client_id
                or node.run_id is not None
                or node.session_id is not None
            ):
                raise ArtifactUnavailable
        elif node.scope == "session":
            if (
                node.owner_client_id != context.current_client_id
                or node.session_id != context.session_id
                or node.run_id is not None
            ):
                raise ArtifactUnavailable
        else:
            if node.owner_client_id != context.current_client_id:
                raise ArtifactUnavailable
            if node.run_id != snapshot.run_id or node.session_id is not None:
                raise ArtifactUnavailable
        if node.role in {"client_snapshot", "temporary_fact"}:
            if (
                type(node.selection_version) is not int
                or node.selection_version < 0
                or node.selection_version > context.selection_cutoff_version
            ):
                raise ArtifactUnavailable
        elif node.selection_version is not None:
            raise ArtifactUnavailable
        if node.role == "authority_policy" and node.reference != snapshot.policy_ref:
            raise ArtifactUnavailable
        if node.role in _AUTHORITY_BOUND_ROLES:
            if (
                node.authority_ref is None
                or node.authority_ref.object_id not in snapshot.allowed_ref_ids
            ):
                raise ArtifactUnavailable
        elif node.authority_ref is not None:
            raise ArtifactUnavailable

    def _verify_node_store_binding(
        self,
        node: ClosureNode,
        *,
        context: IntegrityContext,
    ) -> None:
        store = self._store(node.scope)
        if node.scope != "global" and store.client_id != context.current_client_id:
            raise ArtifactUnavailable

    @staticmethod
    def _assert_reachable_acyclic(
        *,
        root_keys: frozenset[ScopedReference],
        all_keys: frozenset[ScopedReference],
        children: dict[ScopedReference, set[ScopedReference]],
    ) -> None:
        visited: set[ScopedReference] = set()
        visiting: set[ScopedReference] = set()

        def visit(key: ScopedReference) -> None:
            if key in visiting:
                raise ArtifactUnavailable
            if key in visited:
                return
            visiting.add(key)
            for child in children.get(key, set()):
                visit(child)
            visiting.remove(key)
            visited.add(key)

        for root in root_keys:
            visit(root)
        if visited != set(all_keys):
            raise ArtifactUnavailable

    @staticmethod
    def _verify_loo_groups(
        nodes: tuple[ClosureNode, ...],
        *,
        parents: dict[ScopedReference, set[ScopedReference]],
    ) -> None:
        groups: dict[str, dict[str, ClosureNode]] = defaultdict(dict)
        for node in nodes:
            if node.role not in _LOO_ROLES:
                if node.closure_group is not None:
                    raise ArtifactUnavailable
                continue
            if not node.closure_group or node.role in groups[node.closure_group]:
                raise ArtifactUnavailable
            groups[node.closure_group][node.role] = node
        for group in groups.values():
            if set(group) != _LOO_ROLES:
                raise ArtifactUnavailable
            variant = group["leave_one_out_variant"]
            if variant.authority_ref != variant.reference:
                raise ArtifactUnavailable
            if any(
                node.scope != "global"
                or node.authority_ref != variant.reference
                or parents.get(node.key) != parents.get(variant.key)
                for node in group.values()
            ):
                raise ArtifactUnavailable


class ActiveIntegrityGate:
    """Mandatory query/startup gate around one scope's active artifact set.

    Callers provide body-free active references plus probes owned by the
    artifact binding layer.  Probes run on both sides of the metadata check so
    a cached/open artifact handle cannot turn a concurrent file replacement
    into a successful query.  The gate deliberately performs the complete
    verification on every entry: correctness is more important than avoiding
    the bounded local CAS reads.
    """

    def __init__(self, store: IntegrityStore) -> None:
        if type(store) is not IntegrityStore:
            raise TypeError("ACTIVE_INTEGRITY_STORE_REQUIRED")
        self._scope = store.scope
        self._verifier = IntegrityVerifier((store,))

    def verify(
        self,
        *,
        epoch: int,
        artifacts: tuple[ActiveArtifact, ...],
        dedicated_artifacts: tuple[ActiveArtifact, ...] = (),
        source_version: int,
        authority_version: int | None = None,
        tombstone_epoch: int | None = None,
        authorization_epoch: int | None = None,
        content_probes: tuple[Callable[[], object], ...] = (),
    ) -> None:
        try:
            if type(content_probes) is not tuple or any(
                not callable(probe) for probe in content_probes
            ):
                raise ArtifactUnavailable
            for probe in content_probes:
                probe()
            self._verifier.verify_active(
                scope=self._scope,
                epoch=epoch,
                artifacts=artifacts,
                dedicated_artifacts=dedicated_artifacts,
                source_version=source_version,
                authority_version=authority_version,
                tombstone_epoch=tombstone_epoch,
                authorization_epoch=authorization_epoch,
            )
            for probe in content_probes:
                probe()
        except ArtifactUnavailable:
            raise
        except Exception:
            raise ArtifactUnavailable from None


__all__ = [
    "ActiveArtifact",
    "ActiveIntegrityGate",
    "ArtifactUnavailable",
    "ClosureEdge",
    "ClosureNode",
    "IntegrityContext",
    "IntegrityScope",
    "IntegrityStore",
    "IntegrityVerifier",
    "ScopedReference",
]
