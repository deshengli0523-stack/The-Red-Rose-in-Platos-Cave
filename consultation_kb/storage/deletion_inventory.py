"""Read-only deletion inventories from the governed SQLite schemas.

The adapter deliberately reads identifiers, hashes, versions and structured
provenance only.  It never opens the content store and therefore cannot move
consultation or case bodies into the control plane.
"""

from __future__ import annotations

import sqlite3
from collections import deque
from datetime import datetime
from typing import Literal, cast

from consultation_kb.storage.case_index_serialization import (
    CaseIndexPublicationError,
    snapshot_pending_case_index_invalidations,
)
from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.cases import CaseProvenanceRecord
from consultation_kb.models.deletion import (
    DeletionBaseVersion,
    DeletionCaseIndexInvalidationSnapshot,
    DeletionActionType,
    DeletionClosureNode,
    DeletionDependency,
    DeletionInventory,
    DeletionObjectRef,
    DeletionPreviewRequest,
    DeletionTarget,
    deletion_ref_key,
    target_scope_sha256,
)


class DeletionInventoryError(RuntimeError):
    """Fixed-code, body-free inventory failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _one(rows: list[tuple[object, ...]], code: str) -> tuple[object, ...]:
    if len(rows) != 1:
        raise DeletionInventoryError(code)
    return rows[0]


def _integer_source_version(value: object, *, fallback: int) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return fallback
    return parsed if parsed >= 0 else fallback


def _as_int(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        raise DeletionInventoryError("DELETION_INVENTORY_INTEGER_INVALID") from None


def _scope_hash(authority_key: str, scope: object) -> str:
    return canonical_sha256({"authority_key": authority_key, "scope": scope})


def client_authority_sha256(
    *,
    client_id: str,
    directory_object_id: str,
    alias_lookup_sha256: str,
    created_at: str,
) -> str:
    """Hash the immutable, body-free global client authority row."""

    return canonical_sha256(
        {
            "alias_lookup_sha256": alias_lookup_sha256,
            "client_id": client_id,
            "created_at": created_at,
            "directory_object_id": directory_object_id,
        }
    )


def session_authority_sha256(
    *,
    session_id: str,
    client_id: str,
    client_scope_hash: str,
    client_snapshot_version: int,
    client_snapshot_canonical_sha256: str | None,
    started_at: str,
) -> str:
    """Hash the immutable session binding without reading any turn body."""

    return canonical_sha256(
        {
            "client_id": client_id,
            "client_scope_hash": client_scope_hash,
            "client_snapshot_canonical_sha256": client_snapshot_canonical_sha256,
            "client_snapshot_version": client_snapshot_version,
            "session_id": session_id,
            "started_at": started_at,
        }
    )


class _InventoryGraph:
    def __init__(self) -> None:
        self.nodes: dict[
            tuple[str, str, int, str, str], DeletionClosureNode
        ] = {}
        self.edges: dict[
            tuple[
                tuple[str, str, int, str, str],
                tuple[str, str, int, str, str],
                str,
            ],
            DeletionDependency,
        ] = {}

    def add_node(self, node: DeletionClosureNode) -> DeletionClosureNode:
        exact = DeletionClosureNode.model_validate(node)
        key = deletion_ref_key(exact.object_ref)
        previous = self.nodes.get(key)
        if previous is not None and previous != exact:
            raise DeletionInventoryError("DELETION_INVENTORY_NODE_CONFLICT")
        self.nodes[key] = exact
        return exact

    def add_edge(
        self,
        source: DeletionObjectRef,
        dependent: DeletionObjectRef,
        relation: str,
    ) -> None:
        source_key = deletion_ref_key(source)
        dependent_key = deletion_ref_key(dependent)
        if source_key == dependent_key:
            return
        key = source_key, dependent_key, relation
        if key in self.edges:
            return
        edge_id = "edge_" + canonical_sha256(
            {
                "dependent": dependent.model_dump(mode="json"),
                "relation": relation,
                "source": source.model_dump(mode="json"),
            }
        )[:32]
        self.edges[key] = DeletionDependency(
            edge_id=edge_id,
            source_ref=source,
            dependent_ref=dependent,
            relation=relation,
        )


class SqliteDeletionInventoryAdapter:
    """Resolve exact deletion closure from one already-scoped authority DB."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        authority_scope: str,
        client_id: str | None = None,
        contributor_client_hash: str | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("DELETION_INVENTORY_SQLITE_REQUIRED")
        if authority_scope not in {"global", "client"}:
            raise ValueError("DELETION_INVENTORY_SCOPE_INVALID")
        if authority_scope == "global" and client_id is not None:
            raise ValueError("DELETION_GLOBAL_CLIENT_ID_FORBIDDEN")
        if authority_scope == "client" and (
            type(client_id) is not str or not client_id
        ):
            raise ValueError("DELETION_CLIENT_ID_REQUIRED")
        self._connection = connection
        self._scope: Literal["global", "client"] = cast(
            Literal["global", "client"], authority_scope
        )
        self._client_id = client_id
        if contributor_client_hash is not None and (
            type(contributor_client_hash) is not str
            or len(contributor_client_hash) != 64
            or any(
                value not in "0123456789abcdef"
                for value in contributor_client_hash
            )
        ):
            raise ValueError("DELETION_CONTRIBUTOR_HASH_INVALID")
        self._contributor_client_hash = contributor_client_hash

    def _table_exists(self, name: str) -> bool:
        return (
            self._connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (name,),
            ).fetchone()
            is not None
        )

    def _pending_case_index_invalidation(
        self,
    ) -> DeletionCaseIndexInvalidationSnapshot | None:
        if self._scope != "global" or not self._table_exists(
            "case_index_rebuild_invalidations"
        ):
            return None
        try:
            snapshot = snapshot_pending_case_index_invalidations(
                self._connection
            )
        except CaseIndexPublicationError:
            raise DeletionInventoryError(
                "DELETION_CASE_INDEX_INVALIDATION_SNAPSHOT_INVALID"
            ) from None
        return DeletionCaseIndexInvalidationSnapshot.model_validate_json(
            snapshot.model_dump_json(),
            strict=True,
        )

    def snapshot(self, request: DeletionPreviewRequest) -> DeletionInventory:
        exact = DeletionPreviewRequest.model_validate(request)
        target = exact.target
        if target.object_ref.authority_scope != self._scope:
            raise DeletionInventoryError("DELETION_INVENTORY_SCOPE_MISMATCH")
        if target.target_type == "case":
            if self._scope != "global":
                raise DeletionInventoryError("DELETION_CASE_GLOBAL_REQUIRED")
            return self._case_inventory(exact)
        if target.target_type == "case_authorization":
            if self._scope != "global":
                raise DeletionInventoryError("DELETION_CASE_GLOBAL_REQUIRED")
            return self._case_authorization_inventory(exact)
        if target.target_type in {"passage", "claim"}:
            if self._scope != "global":
                raise DeletionInventoryError("DELETION_KNOWLEDGE_GLOBAL_REQUIRED")
            return self._knowledge_inventory(exact)
        if target.target_type == "session":
            if self._scope != "client" or target.client_id != self._client_id:
                raise DeletionInventoryError("DELETION_SESSION_CLIENT_MISMATCH")
            return self._session_inventory(exact)
        if target.target_type == "client":
            if self._scope != "global":
                raise DeletionInventoryError("DELETION_CLIENT_GLOBAL_REQUIRED")
            return self._client_inventory(exact)
        raise DeletionInventoryError("DELETION_INVENTORY_TARGET_UNSUPPORTED")

    def _client_inventory(self, request: DeletionPreviewRequest) -> DeletionInventory:
        target = request.target.object_ref
        if request.target.client_id != target.object_id:
            raise DeletionInventoryError("DELETION_CLIENT_TARGET_MISMATCH")
        if self._contributor_client_hash is None:
            raise DeletionInventoryError("DELETION_CONTRIBUTOR_HASH_REQUIRED")
        row = _one(
            self._connection.execute(
                """
                SELECT directory_object_id, alias_lookup_sha256, state, created_at
                  FROM clients WHERE client_id = ?
                """,
                (target.object_id,),
            ).fetchall(),
            "DELETION_CLIENT_AUTHORITY_CARDINALITY",
        )
        expected_hash = client_authority_sha256(
            client_id=target.object_id,
            directory_object_id=str(row[0]),
            alias_lookup_sha256=str(row[1]),
            created_at=str(row[3]),
        )
        if row[2] != "ACTIVE" or target.content_sha256 != expected_hash:
            raise DeletionInventoryError("DELETION_CLIENT_AUTHORITY_NOT_ACTIVE")
        active_epoch = self._active_epoch(required=False)
        graph = _InventoryGraph()
        root = graph.add_node(
            DeletionClosureNode(
                object_ref=target,
                role="authority",
                actions=("tombstone_now", "physical_delete"),
                authority_effect="revoke_authorization",
            )
        ).object_ref

        capability_rows = self._connection.execute(
            """
            SELECT capability_id, capability_epoch, token_sha256
              FROM capabilities
             WHERE client_id = ? AND state = 'ACTIVE'
             ORDER BY capability_id
            """,
            (target.object_id,),
        ).fetchall()
        for capability_row in capability_rows:
            capability = graph.add_node(
                DeletionClosureNode(
                    object_ref=DeletionObjectRef(
                        object_type="client_capability",
                        object_id=str(capability_row[0]),
                        version=_as_int(capability_row[1]),
                        content_sha256=str(capability_row[2]),
                        authority_scope="global",
                    ),
                    role="authorization",
                    actions=("tombstone_now",),
                )
            ).object_ref
            graph.add_edge(root, capability, "client_capability")

        case_rows = self._connection.execute(
            """
            SELECT cv.case_id, cv.version, cv.global_content_sha256
              FROM case_versions AS cv
              JOIN cases AS c
                ON c.case_id = cv.case_id AND c.current_version = cv.version
              JOIN case_authorizations AS ca
                ON ca.case_id = cv.case_id AND ca.case_version = cv.version
             WHERE c.state = 'ACTIVE' AND cv.state = 'ACTIVE'
               AND ca.reuse_authorized = 1 AND ca.revoked_at IS NULL
               AND ca.contributor_client_hash = ?
             ORDER BY cv.case_id, cv.version
            """,
            (self._contributor_client_hash,),
        ).fetchall()
        for case_row in case_rows:
            case_ref = DeletionObjectRef(
                object_type="case",
                object_id=str(case_row[0]),
                version=_as_int(case_row[1]),
                content_sha256=str(case_row[2]),
                authority_scope="global",
            )
            nested_request = DeletionPreviewRequest(
                request_id=request.request_id,
                target=DeletionTarget(
                    target_type="case",
                    object_ref=case_ref,
                ),
                reason_code=request.reason_code,
                requested_at=request.requested_at,
            )
            nested = self._case_inventory(nested_request)
            skipped_roles = {"audit_proof", "backup", "hosted_product"}
            accepted_keys = {
                deletion_ref_key(node.object_ref)
                for node in nested.nodes
                if node.role not in skipped_roles
            }
            for node in nested.nodes:
                if deletion_ref_key(node.object_ref) in accepted_keys:
                    graph.add_node(node)
            for edge in nested.dependencies:
                if (
                    deletion_ref_key(edge.source_ref) in accepted_keys
                    and deletion_ref_key(edge.dependent_ref) in accepted_keys
                ):
                    graph.add_edge(
                        edge.source_ref, edge.dependent_ref, edge.relation
                    )
            graph.add_edge(root, case_ref, "client_case_contribution")

        self._add_policy_followups(graph, request, root)
        deletion_version, tombstone_epoch, authorization_epoch, catalog_version = (
            self._authority_state()
        )
        base_versions: list[DeletionBaseVersion] = [
            DeletionBaseVersion(
                authority_key="authorization",
                scope_sha256=_scope_hash(
                    "authorization", self._contributor_client_hash
                ),
                version=authorization_epoch,
            ),
            DeletionBaseVersion(
                authority_key="catalog",
                scope_sha256=_scope_hash("catalog", "global"),
                version=catalog_version,
            ),
            DeletionBaseVersion(
                authority_key="client_authority",
                scope_sha256=target_scope_sha256(request.target),
                version=target.version,
            ),
        ]
        if active_epoch > 0:
            base_versions.append(
                DeletionBaseVersion(
                    authority_key="global_runtime",
                    scope_sha256=_scope_hash("global_runtime", "global"),
                    version=active_epoch,
                )
            )
        return DeletionInventory(
            nodes=tuple(
                sorted(
                    graph.nodes.values(),
                    key=lambda node: deletion_ref_key(node.object_ref),
                )
            ),
            dependencies=tuple(
                sorted(graph.edges.values(), key=lambda edge: edge.edge_id)
            ),
            active_manifest_refs=tuple(
                sorted(
                    (
                        node.object_ref
                        for node in graph.nodes.values()
                        if node.role == "active_manifest"
                    ),
                    key=deletion_ref_key,
                )
            ),
            base_versions=tuple(base_versions),
            deletion_version=deletion_version,
            tombstone_epoch=tombstone_epoch,
            authorization_epoch=authorization_epoch,
            pending_case_index_invalidation=(
                self._pending_case_index_invalidation()
            ),
        )

    def _authority_state(self) -> tuple[int, int, int, int]:
        deletion = _one(
            self._connection.execute(
                "SELECT deletion_version, tombstone_epoch "
                "FROM deletion_authority_state WHERE singleton = 1"
            ).fetchall(),
            "DELETION_AUTHORITY_STATE_INVALID",
        )
        if self._scope == "client":
            return _as_int(deletion[0]), _as_int(deletion[1]), 0, 0
        catalog = _one(
            self._connection.execute(
                "SELECT catalog_version, authorization_epoch, tombstone_epoch "
                "FROM knowledge_catalog_state WHERE singleton = 1"
            ).fetchall(),
            "DELETION_CATALOG_STATE_INVALID",
        )
        if _as_int(deletion[1]) != _as_int(catalog[2]):
            raise DeletionInventoryError("DELETION_TOMBSTONE_EPOCH_DIVERGED")
        return (
            _as_int(deletion[0]),
            _as_int(deletion[1]),
            _as_int(catalog[1]),
            _as_int(catalog[0]),
        )

    def _active_epoch(self, *, required: bool) -> int:
        rows = self._connection.execute(
            "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
        ).fetchall()
        if len(rows) > 1 or (required and len(rows) != 1):
            raise DeletionInventoryError("DELETION_ACTIVE_EPOCH_CARDINALITY")
        return 0 if not rows else _as_int(rows[0][0])

    def _case_inventory(self, request: DeletionPreviewRequest) -> DeletionInventory:
        target = request.target.object_ref
        row = _one(
            self._connection.execute(
                """
                SELECT c.state, c.current_version, cv.state,
                       cv.global_content_sha256, cv.manifest_id,
                       cv.provenance_id, cv.provenance_version,
                       ca.authorization_id, ca.authorization_version,
                       ca.authorization_sha256, ca.reuse_authorized,
                       ca.valid_from, ca.expires_at, ca.revoked_at
                  FROM cases AS c
                  JOIN case_versions AS cv
                    ON cv.case_id = c.case_id AND cv.version = c.current_version
                  JOIN case_authorizations AS ca
                    ON ca.case_id = cv.case_id AND ca.case_version = cv.version
                 WHERE c.case_id = ? AND cv.version = ?
                   AND cv.global_content_sha256 = ?
                """,
                (target.object_id, target.version, target.content_sha256),
            ).fetchall(),
            "DELETION_CASE_ACTIVE_CARDINALITY",
        )
        if (
            row[0] != "ACTIVE"
            or _as_int(row[1]) != target.version
            or row[2] != "ACTIVE"
            or _as_int(row[10]) != 1
            or row[13] is not None
        ):
            raise DeletionInventoryError("DELETION_CASE_AUTHORITY_NOT_ACTIVE")
        requested_at = request.requested_at
        if _parse_time(str(row[11])) > requested_at or (
            row[12] is not None and _parse_time(str(row[12])) <= requested_at
        ):
            raise DeletionInventoryError("DELETION_CASE_AUTHORITY_NOT_ACTIVE")

        active_epoch = self._active_epoch(required=False)
        manifest_id = str(row[4])
        manifest = _one(
            self._connection.execute(
                """
                SELECT am.manifest_sha256, am.source_version, am.state,
                       operation.state, operation.purpose,
                       CASE WHEN runtime.epoch IS NULL THEN 0 ELSE 1 END
                  FROM artifact_manifests AS am
                  JOIN publication_operations AS operation
                    ON operation.operation_id = am.operation_id
                  LEFT JOIN active_artifacts AS active
                    ON active.manifest_id = am.manifest_id
                  LEFT JOIN runtime_epochs AS runtime
                    ON runtime.epoch = active.epoch AND runtime.state = 'ACTIVE'
                 WHERE am.manifest_id = ? AND am.artifact_kind = 'shared_case'
                   AND am.verified = 1
                """,
                (manifest_id,),
            ).fetchall(),
            "DELETION_CASE_AUTHORITY_MANIFEST_CARDINALITY",
        )
        manifest_is_active = _as_int(manifest[5]) == 1
        if (
            str(manifest[4]) != "case_publish"
            or (
                manifest_is_active
                and (str(manifest[2]), str(manifest[3])) != ("ACTIVE", "ACTIVE")
            )
            or (
                not manifest_is_active
                and (str(manifest[2]), str(manifest[3]))
                != ("VERIFIED", "VERIFIED")
            )
        ):
            raise DeletionInventoryError(
                "DELETION_CASE_AUTHORITY_MANIFEST_INVALID"
            )

        graph = _InventoryGraph()
        root = graph.add_node(
            DeletionClosureNode(
                object_ref=target,
                role="authority",
                actions=("tombstone_now", "physical_delete"),
                authority_effect="revoke_case",
            )
        ).object_ref
        authorization = graph.add_node(
            DeletionClosureNode(
                object_ref=DeletionObjectRef(
                    object_type="case_authorization",
                    object_id=str(row[7]),
                    version=_as_int(row[8]),
                    content_sha256=str(row[9]),
                    authority_scope="global",
                ),
                role="authorization",
                actions=("tombstone_now",),
                authority_effect="revoke_authorization",
            )
        ).object_ref
        graph.add_edge(root, authorization, "case_reuse_authorization")

        root_manifest = self._manifest_node(
            graph,
            manifest_id=manifest_id,
            manifest_sha256=str(manifest[0]),
            source_version=manifest[1],
            active_epoch=active_epoch,
            role=("active_manifest" if manifest_is_active else "verified_manifest"),
        )
        graph.add_edge(
            root,
            root_manifest,
            "active_manifest" if manifest_is_active else "verified_authority_manifest",
        )
        self._manifest_member_closure(graph, manifest=root_manifest)

        selected = self._case_provenance_closure(target)
        provenance_to_artifact = {
            (
                record.provenance_ref.object_id,
                record.provenance_ref.version,
                record.provenance_ref.content_sha256,
            ): record.artifact_ref
            for record in selected
        }
        artifact_refs = {deletion_ref_key(root): root}
        for record in selected:
            artifact = DeletionObjectRef(
                object_type=record.artifact_kind,
                object_id=record.artifact_ref.object_id,
                version=record.artifact_ref.version,
                content_sha256=record.artifact_ref.content_sha256,
                authority_scope="global",
            )
            if deletion_ref_key(artifact) != deletion_ref_key(root):
                artifact = graph.add_node(
                    DeletionClosureNode(
                        object_ref=artifact,
                        role=(
                            "case_pattern"
                            if record.artifact_kind == "case_pattern"
                            else "case_derivative"
                        ),
                        actions=("tombstone_now", "physical_delete", "rebuild"),
                    )
                ).object_ref
            else:
                artifact = root
            artifact_refs[deletion_ref_key(artifact)] = artifact
            provenance = graph.add_node(
                DeletionClosureNode(
                    object_ref=DeletionObjectRef(
                        object_type="case_provenance",
                        object_id=record.provenance_ref.object_id,
                        version=record.provenance_ref.version,
                        content_sha256=record.provenance_ref.content_sha256,
                        authority_scope="global",
                    ),
                    role="provenance",
                    actions=("tombstone_now",),
                )
            ).object_ref
            graph.add_edge(artifact, provenance, "provenance_record")
            if record.parent_provenance_refs:
                for parent in record.parent_provenance_refs:
                    parent_ref = provenance_to_artifact.get(
                        (parent.object_id, parent.version, parent.content_sha256)
                    )
                    if parent_ref is None:
                        raise DeletionInventoryError(
                            "DELETION_CASE_PROVENANCE_PARENT_MISSING"
                        )
                    graph.add_edge(
                        DeletionObjectRef(
                            object_type=_artifact_kind(selected, parent_ref),
                            object_id=parent_ref.object_id,
                            version=parent_ref.version,
                            content_sha256=parent_ref.content_sha256,
                            authority_scope="global",
                        ),
                        artifact,
                        "case_provenance_dependency",
                    )
            elif artifact != root:
                graph.add_edge(root, artifact, "case_contribution_dependency")

        self._case_pattern_authority_manifests(
            graph,
            artifacts=tuple(artifact_refs.values()),
            active_epoch=active_epoch,
        )
        if active_epoch > 0:
            for artifact in tuple(artifact_refs.values()):
                self._active_manifests_for_artifact(
                    graph,
                    artifact=artifact,
                    active_epoch=active_epoch,
                )
        self._artifact_dependency_closure(
            graph,
            roots=tuple(artifact_refs.values()),
        )
        self._leave_one_out_closure(
            graph,
            roots=tuple(artifact_refs.values()),
            active_epoch=active_epoch,
        )
        self._add_policy_followups(graph, request, root)

        deletion_version, tombstone_epoch, authorization_epoch, catalog_version = (
            self._authority_state()
        )
        base_versions: list[DeletionBaseVersion] = [
            DeletionBaseVersion(
                authority_key="authorization",
                scope_sha256=_scope_hash(
                    "authorization", authorization.model_dump(mode="json")
                ),
                version=authorization_epoch,
            ),
            DeletionBaseVersion(
                authority_key="case_current",
                scope_sha256=target_scope_sha256(request.target),
                version=target.version,
            ),
            DeletionBaseVersion(
                authority_key="catalog",
                scope_sha256=_scope_hash("catalog", "global"),
                version=catalog_version,
            ),
        ]
        if active_epoch > 0:
            base_versions.append(
                DeletionBaseVersion(
                    authority_key="global_runtime",
                    scope_sha256=_scope_hash("global_runtime", "global"),
                    version=active_epoch,
                )
            )
        active_refs = tuple(
            sorted(
                (
                    node.object_ref
                    for node in graph.nodes.values()
                    if node.role == "active_manifest"
                ),
                key=deletion_ref_key,
            )
        )
        return DeletionInventory(
            nodes=tuple(sorted(graph.nodes.values(), key=lambda n: deletion_ref_key(n.object_ref))),
            dependencies=tuple(sorted(graph.edges.values(), key=lambda e: e.edge_id)),
            active_manifest_refs=active_refs,
            base_versions=tuple(base_versions),
            deletion_version=deletion_version,
            tombstone_epoch=tombstone_epoch,
            authorization_epoch=authorization_epoch,
            pending_case_index_invalidation=(
                self._pending_case_index_invalidation()
            ),
        )

    def _case_authorization_inventory(
        self,
        request: DeletionPreviewRequest,
    ) -> DeletionInventory:
        target = request.target.object_ref
        row = _one(
            self._connection.execute(
                """
                SELECT ca.case_id, ca.case_version, ca.authorization_sha256,
                       ca.reuse_authorized, ca.valid_from, ca.expires_at,
                       ca.revoked_at, c.state, c.current_version, cv.state,
                       cv.global_content_sha256
                  FROM case_authorizations AS ca
                  JOIN cases AS c ON c.case_id = ca.case_id
                  JOIN case_versions AS cv
                    ON cv.case_id = ca.case_id AND cv.version = ca.case_version
                 WHERE ca.authorization_id = ?
                   AND ca.authorization_version = ?
                """,
                (target.object_id, target.version),
            ).fetchall(),
            "DELETION_CASE_AUTHORIZATION_CARDINALITY",
        )
        if (
            str(row[2]) != target.content_sha256
            or _as_int(row[3]) != 1
            or row[6] is not None
            or row[7] != "ACTIVE"
            or _as_int(row[8]) != _as_int(row[1])
            or row[9] != "ACTIVE"
            or _parse_time(str(row[4])) > request.requested_at
            or (
                row[5] is not None
                and _parse_time(str(row[5])) <= request.requested_at
            )
        ):
            raise DeletionInventoryError(
                "DELETION_CASE_AUTHORIZATION_NOT_ACTIVE"
            )
        case_ref = DeletionObjectRef(
            object_type="case",
            object_id=str(row[0]),
            version=_as_int(row[1]),
            content_sha256=str(row[10]),
            authority_scope="global",
        )
        nested = self._case_inventory(
            DeletionPreviewRequest(
                request_id=request.request_id,
                target=DeletionTarget(
                    target_type="case",
                    object_ref=case_ref,
                ),
                reason_code=request.reason_code,
                requested_at=request.requested_at,
            )
        )
        graph = _InventoryGraph()
        for node in nested.nodes:
            reference = node.object_ref
            replacement = node
            if deletion_ref_key(reference) == deletion_ref_key(target):
                replacement = node.model_copy(
                    update={
                        "actions": ("tombstone_now",),
                        "authority_effect": "revoke_authorization",
                    }
                )
            elif deletion_ref_key(reference) == deletion_ref_key(case_ref):
                replacement = node.model_copy(
                    update={
                        "actions": ("tombstone_now", "rebuild"),
                        "authority_effect": "revoke_case",
                    }
                )
            elif (
                reference.content_sha256 == case_ref.content_sha256
                and "physical_delete" in node.actions
            ):
                actions = tuple(
                    action
                    for action in node.actions
                    if action != "physical_delete"
                )
                replacement = node.model_copy(
                    update={
                        "actions": actions or ("tombstone_now", "rebuild")
                    }
                )
            graph.add_node(replacement)
        for edge in nested.dependencies:
            graph.add_edge(edge.source_ref, edge.dependent_ref, edge.relation)
        graph.add_edge(target, case_ref, "authorization_case_visibility")
        return DeletionInventory(
            nodes=tuple(
                sorted(
                    graph.nodes.values(),
                    key=lambda node: deletion_ref_key(node.object_ref),
                )
            ),
            dependencies=tuple(
                sorted(graph.edges.values(), key=lambda edge: edge.edge_id)
            ),
            active_manifest_refs=nested.active_manifest_refs,
            base_versions=nested.base_versions,
            deletion_version=nested.deletion_version,
            tombstone_epoch=nested.tombstone_epoch,
            authorization_epoch=nested.authorization_epoch,
            pending_case_index_invalidation=(
                nested.pending_case_index_invalidation
            ),
        )

    def _case_provenance_closure(
        self, target: DeletionObjectRef
    ) -> tuple[CaseProvenanceRecord, ...]:
        selected: list[CaseProvenanceRecord] = []
        rows = self._connection.execute(
            """
            SELECT provenance_id, provenance_version, provenance_sha256,
                   artifact_object_id, artifact_version, artifact_sha256,
                   artifact_kind, closure_json, closure_sha256
              FROM case_provenance
             ORDER BY provenance_id, provenance_version
            """
        ).fetchall()
        for row in rows:
            try:
                record = CaseProvenanceRecord.model_validate_json(str(row[7]))
            except ValueError:
                raise DeletionInventoryError(
                    "DELETION_CASE_PROVENANCE_CORRUPT"
                ) from None
            stored = (
                str(row[0]),
                int(row[1]),
                str(row[2]),
                str(row[3]),
                int(row[4]),
                str(row[5]),
                str(row[6]),
                str(row[8]),
            )
            parsed = (
                record.provenance_ref.object_id,
                record.provenance_ref.version,
                record.provenance_ref.content_sha256,
                record.artifact_ref.object_id,
                record.artifact_ref.version,
                record.artifact_ref.content_sha256,
                record.artifact_kind,
                record.closure_sha256,
            )
            if stored != parsed:
                raise DeletionInventoryError(
                    "DELETION_CASE_PROVENANCE_BINDING_MISMATCH"
                )
            if any(
                contribution.case_ref.object_id == target.object_id
                and contribution.case_ref.version == target.version
                and contribution.case_ref.content_sha256 == target.content_sha256
                for contribution in record.case_contributions
            ):
                selected.append(record)
        if not selected or not any(record.artifact_kind == "case" for record in selected):
            raise DeletionInventoryError("DELETION_CASE_PROVENANCE_CLOSURE_MISSING")
        return tuple(selected)

    def _manifest_node(
        self,
        graph: _InventoryGraph,
        *,
        manifest_id: str,
        manifest_sha256: str,
        source_version: object,
        active_epoch: int,
        role: Literal["active_manifest", "verified_manifest"] = "active_manifest",
    ) -> DeletionObjectRef:
        candidate = DeletionClosureNode(
            object_ref=DeletionObjectRef(
                object_type="artifact_manifest",
                object_id=manifest_id,
                version=_integer_source_version(
                    source_version, fallback=active_epoch
                ),
                content_sha256=manifest_sha256,
                authority_scope=self._scope,
            ),
            role=role,
            actions=("tombstone_now", "rebuild"),
        )
        existing = graph.nodes.get(deletion_ref_key(candidate.object_ref))
        if existing is not None:
            return existing.object_ref
        return graph.add_node(candidate).object_ref

    def _manifest_member_closure(
        self,
        graph: _InventoryGraph,
        *,
        manifest: DeletionObjectRef,
    ) -> None:
        rows = self._connection.execute(
            """
            SELECT object_type, object_id, object_sha256, source_version
              FROM artifact_members
             WHERE manifest_id = ?
             ORDER BY ordinal
            """,
            (manifest.object_id,),
        ).fetchall()
        if not rows:
            raise DeletionInventoryError("DELETION_AUTHORITY_MANIFEST_EMPTY")
        for row in rows:
            candidate = DeletionClosureNode(
                object_ref=DeletionObjectRef(
                    object_type=str(row[0]),
                    object_id=str(row[1]),
                    version=_integer_source_version(
                        row[3], fallback=manifest.version
                    ),
                    content_sha256=str(row[2]),
                    authority_scope="global",
                ),
                role="manifest_member",
                actions=("tombstone_now", "physical_delete", "rebuild"),
            )
            key = deletion_ref_key(candidate.object_ref)
            if key in graph.nodes:
                continue
            member = graph.add_node(candidate).object_ref
            graph.add_edge(manifest, member, "manifest_member")

    def _case_pattern_authority_manifests(
        self,
        graph: _InventoryGraph,
        *,
        artifacts: tuple[DeletionObjectRef, ...],
        active_epoch: int,
    ) -> None:
        for artifact in artifacts:
            if artifact.object_type != "case_pattern":
                continue
            row = _one(
                self._connection.execute(
                    """
                    SELECT manifest.manifest_id, manifest.manifest_sha256,
                           manifest.source_version, manifest.state,
                           operation.state, operation.purpose,
                           CASE WHEN runtime.epoch IS NULL THEN 0 ELSE 1 END
                      FROM case_patterns AS pattern
                      JOIN artifact_manifests AS manifest
                        ON manifest.manifest_id = pattern.manifest_id
                      JOIN publication_operations AS operation
                        ON operation.operation_id = manifest.operation_id
                      LEFT JOIN active_artifacts AS active
                        ON active.manifest_id = manifest.manifest_id
                      LEFT JOIN runtime_epochs AS runtime
                        ON runtime.epoch = active.epoch
                       AND runtime.state = 'ACTIVE'
                     WHERE pattern.pattern_id = ? AND pattern.version = ?
                       AND pattern.global_content_sha256 = ?
                       AND pattern.state = 'ACTIVE'
                       AND manifest.artifact_kind = 'case_index'
                       AND manifest.verified = 1
                    """,
                    (
                        artifact.object_id,
                        artifact.version,
                        artifact.content_sha256,
                    ),
                ).fetchall(),
                "DELETION_CASE_INDEX_MANIFEST_CARDINALITY",
            )
            is_active = _as_int(row[6]) == 1
            if (
                str(row[5]) != "case_publish"
                or (
                    is_active
                    and (str(row[3]), str(row[4])) != ("ACTIVE", "ACTIVE")
                )
                or (
                    not is_active
                    and (str(row[3]), str(row[4]))
                    != ("VERIFIED", "VERIFIED")
                )
            ):
                raise DeletionInventoryError(
                    "DELETION_CASE_INDEX_MANIFEST_INVALID"
                )
            manifest = self._manifest_node(
                graph,
                manifest_id=str(row[0]),
                manifest_sha256=str(row[1]),
                source_version=row[2],
                active_epoch=active_epoch,
                role=("active_manifest" if is_active else "verified_manifest"),
            )
            graph.add_edge(
                artifact,
                manifest,
                (
                    "active_manifest_membership"
                    if is_active
                    else "verified_manifest_membership"
                ),
            )
            self._manifest_member_closure(graph, manifest=manifest)

    def _active_manifests_for_artifact(
        self,
        graph: _InventoryGraph,
        *,
        artifact: DeletionObjectRef,
        active_epoch: int,
    ) -> None:
        rows = self._connection.execute(
            """
            SELECT am.manifest_id, am.manifest_sha256, am.source_version
              FROM artifact_members AS member
              JOIN artifact_manifests AS am
                ON am.manifest_id = member.manifest_id
              JOIN active_artifacts AS aa
                ON aa.manifest_id = am.manifest_id AND aa.epoch = ?
             WHERE member.object_id = ? AND member.object_sha256 = ?
               AND am.state = 'ACTIVE' AND am.verified = 1
             ORDER BY am.manifest_id
            """,
            (active_epoch, artifact.object_id, artifact.content_sha256),
        ).fetchall()
        for row in rows:
            manifest = self._manifest_node(
                graph,
                manifest_id=str(row[0]),
                manifest_sha256=str(row[1]),
                source_version=row[2],
                active_epoch=active_epoch,
            )
            graph.add_edge(artifact, manifest, "active_manifest_membership")

    def _artifact_dependency_closure(
        self,
        graph: _InventoryGraph,
        *,
        roots: tuple[DeletionObjectRef, ...],
    ) -> None:
        pending: deque[tuple[str, str, int, DeletionObjectRef]] = deque(
            (root.object_type, root.object_id, root.version, root) for root in roots
        )
        seen: set[tuple[str, str, int]] = set()
        while pending:
            upstream_type, upstream_id, upstream_version, upstream_ref = pending.popleft()
            key = upstream_type, upstream_id, upstream_version
            if key in seen:
                continue
            seen.add(key)
            rows = self._connection.execute(
                """
                SELECT dependency.downstream_artifact_id,
                       dependency.downstream_artifact_version,
                       dependency.dependency_kind, artifact.metadata_sha256
                  FROM artifact_dependencies AS dependency
                  JOIN artifact_versions AS artifact
                    ON artifact.artifact_id = dependency.downstream_artifact_id
                   AND artifact.version = dependency.downstream_artifact_version
                 WHERE dependency.upstream_type = ?
                   AND dependency.upstream_id = ?
                   AND dependency.upstream_version = ?
                   AND artifact.state = 'CURRENT'
                 ORDER BY dependency.downstream_artifact_id,
                          dependency.downstream_artifact_version
                """,
                (upstream_type, upstream_id, upstream_version),
            ).fetchall()
            for row in rows:
                dependent = graph.add_node(
                    DeletionClosureNode(
                        object_ref=DeletionObjectRef(
                            object_type="artifact_version",
                            object_id=str(row[0]),
                            version=int(row[1]),
                            content_sha256=str(row[3]),
                            authority_scope="global",
                        ),
                        role="derived_artifact",
                        actions=("tombstone_now", "physical_delete", "rebuild"),
                    )
                ).object_ref
                graph.add_edge(upstream_ref, dependent, str(row[2]))
                pending.append(("artifact", dependent.object_id, dependent.version, dependent))

    def _leave_one_out_closure(
        self,
        graph: _InventoryGraph,
        *,
        roots: tuple[DeletionObjectRef, ...],
        active_epoch: int,
    ) -> None:
        for parent in roots:
            rows = self._connection.execute(
                """
                SELECT mapping_id, mapping_version, mapping_sha256,
                       variant_object_id, variant_version, variant_sha256,
                       content_object_id, content_version, content_sha256,
                       authority_manifest_id, authority_manifest_version,
                       authority_manifest_sha256
                  FROM case_leave_one_out_variants
                 WHERE parent_object_id = ? AND parent_version = ?
                   AND parent_sha256 = ? AND state = 'ACTIVE'
                 ORDER BY mapping_id, mapping_version
                """,
                (parent.object_id, parent.version, parent.content_sha256),
            ).fetchall()
            for row in rows:
                mapping = graph.add_node(
                    DeletionClosureNode(
                        object_ref=DeletionObjectRef(
                            object_type="case_leave_one_out",
                            object_id=str(row[0]),
                            version=int(row[1]),
                            content_sha256=str(row[2]),
                            authority_scope="global",
                        ),
                        role="leave_one_out",
                        actions=("tombstone_now", "physical_delete", "rebuild"),
                    )
                ).object_ref
                variant = graph.add_node(
                    DeletionClosureNode(
                        object_ref=DeletionObjectRef(
                            object_type="case_variant",
                            object_id=str(row[3]),
                            version=int(row[4]),
                            content_sha256=str(row[5]),
                            authority_scope="global",
                        ),
                        role="case_derivative",
                        actions=("tombstone_now", "physical_delete", "rebuild"),
                    )
                ).object_ref
                content = graph.add_node(
                    DeletionClosureNode(
                        object_ref=DeletionObjectRef(
                            object_type="case_variant_content",
                            object_id=str(row[6]),
                            version=int(row[7]),
                            content_sha256=str(row[8]),
                            authority_scope="global",
                        ),
                        role="derived_artifact",
                        actions=("tombstone_now", "physical_delete", "rebuild"),
                    )
                ).object_ref
                manifest = self._manifest_node(
                    graph,
                    manifest_id=str(row[9]),
                    manifest_sha256=str(row[11]),
                    source_version=row[10],
                    active_epoch=active_epoch,
                )
                graph.add_edge(parent, mapping, "leave_one_out_mapping")
                graph.add_edge(mapping, variant, "leave_one_out_variant")
                graph.add_edge(variant, content, "leave_one_out_content")
                graph.add_edge(mapping, manifest, "leave_one_out_authority")

    def _add_policy_followups(
        self,
        graph: _InventoryGraph,
        request: DeletionPreviewRequest,
        root: DeletionObjectRef,
    ) -> None:
        scope_hash = target_scope_sha256(request.target)
        descriptors: tuple[
            tuple[
                str,
                str,
                str,
                tuple[DeletionActionType, ...],
                str,
            ],
            ...,
        ] = (
            (
                "backup_set",
                "backup_set:" + scope_hash,
                "backup",
                ("backup_expiry",),
                "backup_policy",
            ),
            (
                "managed_task_control",
                "managed_task_control:" + scope_hash,
                "hosted_product",
                ("manual_product_action",),
                "hosted_product_policy",
            ),
        )
        for object_type, object_id, role, actions, relation in descriptors:
            dependent = graph.add_node(
                DeletionClosureNode(
                    object_ref=DeletionObjectRef(
                        object_type=object_type,
                        object_id=object_id,
                        version=1,
                        content_sha256=canonical_sha256(
                            {
                                "object_type": object_type,
                                "scope_sha256": scope_hash,
                            }
                        ),
                        authority_scope=self._scope,
                    ),
                    role=role,
                    actions=actions,
                )
            ).object_ref
            graph.add_edge(root, dependent, relation)
        audit = graph.add_node(
            DeletionClosureNode(
                object_ref=DeletionObjectRef(
                    object_type="deletion_audit_proof",
                    object_id=request.request_id,
                    version=1,
                    content_sha256=canonical_sha256(
                        {
                            "reason_code": request.reason_code,
                            "request_id": request.request_id,
                            "target_scope_sha256": scope_hash,
                        }
                    ),
                    authority_scope=self._scope,
                ),
                role="audit_proof",
                actions=(),
                retention="retain_body_free_audit",
            )
        ).object_ref
        graph.add_edge(root, audit, "deletion_audit")

    def _knowledge_inventory(
        self, request: DeletionPreviewRequest
    ) -> DeletionInventory:
        target = request.target.object_ref
        exact_target, status = self._global_governed_ref(
            target.object_type,
            target.object_id,
            target.version,
        )
        if exact_target != target or status != "APPROVED":
            raise DeletionInventoryError(
                "DELETION_KNOWLEDGE_AUTHORITY_NOT_ACTIVE"
            )
        graph = _InventoryGraph()
        root = graph.add_node(
            DeletionClosureNode(
                object_ref=target,
                role="authority",
                actions=("tombstone_now", "physical_delete", "rebuild"),
            )
        ).object_ref
        pending: deque[DeletionObjectRef] = deque((root,))
        seen: set[tuple[str, str, int, str, str]] = set()
        while pending:
            source = pending.popleft()
            source_key = deletion_ref_key(source)
            if source_key in seen:
                continue
            seen.add(source_key)
            rows = self._connection.execute(
                """
                SELECT relation, to_type, to_id, to_version
                  FROM provenance_edges
                 WHERE from_type = ? AND from_id = ? AND from_version = ?
                 ORDER BY relation, to_type, to_id, to_version
                """,
                (source.object_type, source.object_id, source.version),
            ).fetchall()
            for row in rows:
                dependent, _status = self._global_governed_ref(
                    str(row[1]), str(row[2]), _as_int(row[3])
                )
                dependent = graph.add_node(
                    DeletionClosureNode(
                        object_ref=dependent,
                        role="provenance_dependent",
                        actions=("tombstone_now", "physical_delete", "rebuild"),
                    )
                ).object_ref
                graph.add_edge(source, dependent, str(row[0]).lower())
                pending.append(dependent)

        active_epoch = self._active_epoch(required=False)
        governed_refs = tuple(
            node.object_ref
            for node in graph.nodes.values()
            if node.object_ref.authority_scope == "global"
        )
        if active_epoch > 0:
            for reference in governed_refs:
                self._active_manifests_for_artifact(
                    graph,
                    artifact=reference,
                    active_epoch=active_epoch,
                )
        self._artifact_dependency_closure(graph, roots=governed_refs)
        self._add_policy_followups(graph, request, root)
        deletion_version, tombstone_epoch, authorization_epoch, catalog_version = (
            self._authority_state()
        )
        base_versions: list[DeletionBaseVersion] = [
            DeletionBaseVersion(
                authority_key="catalog",
                scope_sha256=_scope_hash("catalog", "global"),
                version=catalog_version,
            )
        ]
        if active_epoch > 0:
            base_versions.append(
                DeletionBaseVersion(
                    authority_key="global_runtime",
                    scope_sha256=_scope_hash("global_runtime", "global"),
                    version=active_epoch,
                )
            )
        return DeletionInventory(
            nodes=tuple(
                sorted(
                    graph.nodes.values(),
                    key=lambda node: deletion_ref_key(node.object_ref),
                )
            ),
            dependencies=tuple(
                sorted(graph.edges.values(), key=lambda edge: edge.edge_id)
            ),
            active_manifest_refs=tuple(
                sorted(
                    (
                        node.object_ref
                        for node in graph.nodes.values()
                        if node.role == "active_manifest"
                    ),
                    key=deletion_ref_key,
                )
            ),
            base_versions=tuple(base_versions),
            deletion_version=deletion_version,
            tombstone_epoch=tombstone_epoch,
            authorization_epoch=authorization_epoch,
            pending_case_index_invalidation=(
                self._pending_case_index_invalidation()
            ),
        )

    def _global_governed_ref(
        self,
        object_type: str,
        object_id: str,
        version: int,
    ) -> tuple[DeletionObjectRef, str | None]:
        query = {
            "passage": (
                "SELECT normalized_text_sha256, review_status FROM passages "
                "WHERE passage_id = ? AND version = ?"
            ),
            "claim": (
                "SELECT claim_sha256, review_status FROM claims "
                "WHERE claim_id = ? AND version = ?"
            ),
            "artifact": (
                "SELECT metadata_sha256, state FROM artifact_versions "
                "WHERE artifact_id = ? AND version = ?"
            ),
            "artifact_version": (
                "SELECT metadata_sha256, state FROM artifact_versions "
                "WHERE artifact_id = ? AND version = ?"
            ),
            "case": (
                "SELECT global_content_sha256, state FROM case_versions "
                "WHERE case_id = ? AND version = ?"
            ),
            "wiki": (
                "SELECT body_sha256, review_status FROM wiki_revisions "
                "WHERE wiki_id = ? AND revision = ?"
            ),
            "theory": (
                "SELECT revision_sha256, status FROM theory_revisions "
                "WHERE theory_id = ? AND revision = ?"
            ),
        }.get(object_type)
        if query is None:
            raise DeletionInventoryError(
                "DELETION_PROVENANCE_OBJECT_TYPE_UNSUPPORTED"
            )
        row = _one(
            self._connection.execute(query, (object_id, version)).fetchall(),
            "DELETION_PROVENANCE_OBJECT_CARDINALITY",
        )
        return (
            DeletionObjectRef(
                object_type=(
                    "artifact_version" if object_type == "artifact" else object_type
                ),
                object_id=object_id,
                version=version,
                content_sha256=str(row[0]),
                authority_scope="global",
            ),
            None if row[1] is None else str(row[1]),
        )

    def _session_inventory(
        self, request: DeletionPreviewRequest
    ) -> DeletionInventory:
        target = request.target.object_ref
        row = _one(
            self._connection.execute(
                """
                SELECT client_id, client_scope_hash, client_snapshot_version,
                       client_snapshot_canonical_sha256, started_at,
                       last_closed_turn_ordinal
                  FROM sessions WHERE session_id = ?
                """,
                (target.object_id,),
            ).fetchall(),
            "DELETION_SESSION_AUTHORITY_CARDINALITY",
        )
        if row[0] != self._client_id:
            raise DeletionInventoryError("DELETION_SESSION_CLIENT_MISMATCH")
        expected_hash = session_authority_sha256(
            session_id=target.object_id,
            client_id=str(row[0]),
            client_scope_hash=str(row[1]),
            client_snapshot_version=_as_int(row[2]),
            client_snapshot_canonical_sha256=(
                None if row[3] is None else str(row[3])
            ),
            started_at=str(row[4]),
        )
        if (
            target.version != _as_int(row[5])
            or target.content_sha256 != expected_hash
        ):
            raise DeletionInventoryError("DELETION_SESSION_AUTHORITY_STALE")

        graph = _InventoryGraph()
        root = graph.add_node(
            DeletionClosureNode(
                object_ref=target,
                role="authority",
                actions=("tombstone_now", "physical_delete"),
            )
        ).object_ref
        bundle_rows = self._connection.execute(
            """
            SELECT bundle_id, actual_transcript_object_id,
                   actual_transcript_version, actual_transcript_sha256
              FROM archive_bundles WHERE session_id = ?
            """,
            (target.object_id,),
        ).fetchall()
        if len(bundle_rows) > 1:
            raise DeletionInventoryError("DELETION_SESSION_ARCHIVE_CARDINALITY")
        if bundle_rows:
            bundle_row = bundle_rows[0]
            bundle = graph.add_node(
                DeletionClosureNode(
                    object_ref=DeletionObjectRef(
                        object_type="archive_bundle",
                        object_id=str(bundle_row[0]),
                        version=1,
                        content_sha256=canonical_sha256(
                            {
                                "actual_transcript_sha256": str(bundle_row[3]),
                                "bundle_id": str(bundle_row[0]),
                                "session_id": target.object_id,
                            }
                        ),
                        authority_scope="client",
                    ),
                    role="archive_bundle",
                    actions=("tombstone_now", "physical_delete"),
                )
            ).object_ref
            transcript = graph.add_node(
                DeletionClosureNode(
                    object_ref=DeletionObjectRef(
                        object_type="actual_transcript",
                        object_id=str(bundle_row[1]),
                        version=_as_int(bundle_row[2]),
                        content_sha256=str(bundle_row[3]),
                        authority_scope="client",
                    ),
                    role="private_record",
                    actions=("tombstone_now", "physical_delete"),
                )
            ).object_ref
            graph.add_edge(root, bundle, "session_archive_bundle")
            graph.add_edge(bundle, transcript, "actual_transcript")
            self._session_archive_derivatives(graph, bundle)

        active_epoch = self._active_epoch(required=False)
        if active_epoch > 0:
            for reference in tuple(
                node.object_ref for node in graph.nodes.values()
            ):
                self._active_manifests_for_artifact(
                    graph,
                    artifact=reference,
                    active_epoch=active_epoch,
                )
        self._add_policy_followups(graph, request, root)
        deletion_version, tombstone_epoch, authorization_epoch, _catalog = (
            self._authority_state()
        )
        base_versions: list[DeletionBaseVersion] = [
            DeletionBaseVersion(
                authority_key="session_current",
                scope_sha256=target_scope_sha256(request.target),
                version=target.version,
            )
        ]
        if active_epoch > 0:
            base_versions.append(
                DeletionBaseVersion(
                    authority_key="client_runtime",
                    scope_sha256=_scope_hash("client_runtime", self._client_id),
                    version=active_epoch,
                )
            )
        return DeletionInventory(
            nodes=tuple(
                sorted(
                    graph.nodes.values(),
                    key=lambda node: deletion_ref_key(node.object_ref),
                )
            ),
            dependencies=tuple(
                sorted(graph.edges.values(), key=lambda edge: edge.edge_id)
            ),
            active_manifest_refs=tuple(
                sorted(
                    (
                        node.object_ref
                        for node in graph.nodes.values()
                        if node.role == "active_manifest"
                    ),
                    key=deletion_ref_key,
                )
            ),
            base_versions=tuple(base_versions),
            deletion_version=deletion_version,
            tombstone_epoch=tombstone_epoch,
            authorization_epoch=authorization_epoch,
        )

    def _session_archive_derivatives(
        self,
        graph: _InventoryGraph,
        bundle: DeletionObjectRef,
    ) -> None:
        rows_and_specs = (
            (
                "SELECT revision_id, revision, draft_sha256 "
                "FROM private_archive_revisions WHERE bundle_id = ?",
                "private_archive",
                "private_record",
            ),
            (
                "SELECT draft_id, revision, draft_sha256 "
                "FROM profile_diff_drafts WHERE bundle_id = ?",
                "profile_diff",
                "profile_derivative",
            ),
            (
                "SELECT candidate_id, version, candidate_sha256 "
                "FROM shared_case_candidates WHERE bundle_id = ?",
                "shared_case_candidate",
                "case_candidate",
            ),
        )
        for query, object_type, role in rows_and_specs:
            rows = self._connection.execute(query, (bundle.object_id,)).fetchall()
            for row in rows:
                reference = graph.add_node(
                    DeletionClosureNode(
                        object_ref=DeletionObjectRef(
                            object_type=object_type,
                            object_id=str(row[0]),
                            version=_as_int(row[1]),
                            content_sha256=str(row[2]),
                            authority_scope="client",
                        ),
                        role=role,
                        actions=("tombstone_now", "physical_delete", "rebuild"),
                    )
                ).object_ref
                graph.add_edge(bundle, reference, object_type)


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise DeletionInventoryError("DELETION_AUTHORITY_TIME_INVALID") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DeletionInventoryError("DELETION_AUTHORITY_TIME_INVALID")
    return parsed


def _artifact_kind(
    records: tuple[CaseProvenanceRecord, ...], artifact_ref: object
) -> str:
    for record in records:
        if record.artifact_ref == artifact_ref:
            return record.artifact_kind
    raise DeletionInventoryError("DELETION_CASE_PROVENANCE_PARENT_MISSING")


__all__ = [
    "DeletionInventoryError",
    "SqliteDeletionInventoryAdapter",
    "client_authority_sha256",
    "session_authority_sha256",
]
