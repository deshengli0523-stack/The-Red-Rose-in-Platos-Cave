"""Live authority snapshots frozen across global and client metadata."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import TypeAdapter, ValidationError

from consultation_kb.archive.provenance import CaseContributorHasher
from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.cases import CaseProvenanceRecord
from consultation_kb.models.common import ObjectId, Sha256Hex, VersionRef
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    RetrievalScope,
)
from consultation_kb.storage.tombstones import lineage_hash, target_hash
from consultation_kb.vault.content_store import ContentStore, ContentStoreError

from .artifact_contracts import (
    ArtifactMemberIdentity,
    DerivedArtifactBuilderInputV2,
    DerivedArtifactKind,
    RetrievalInputAssignment,
    RetrievalInputRecord,
    derived_artifact_media_type_layout,
    derived_artifact_role_layout,
)
from .contracts import (
    CandidateMetadata,
    CandidateRef,
    FilterCapabilityBinding,
    candidate_capability_payload,
)
from .filters import (
    AuthoritySnapshotStale,
    CandidateAuthorityStatus,
)


_OBJECT_ID = TypeAdapter(ObjectId)
_SHA256 = TypeAdapter(Sha256Hex)
_CLIENT_SCHEMA = "client_authority"

_GLOBAL_CONTENT_AUTHORITY_KINDS = {
    "claims": "claim",
    "wiki_page": "wiki",
    "c1_revision": "theory",
}
_CLIENT_CONTENT_AUTHORITY_KINDS = {
    "fact_snapshot": "fact_snapshot",
    "profile": "profile_json",
    "graph": "client_graph",
}
_CASE_ROUTE_KIND_BY_CHANNEL: dict[str, DerivedArtifactKind] = {
    "wiki": "wiki_index",
    "global_graph": "graph",
    "lexical": "lexical",
    "vector": "vector",
}
_FIVE_DERIVED_ROOTS = frozenset(
    {"wiki_index", "knowledge_registry", "graph", "lexical", "vector"}
)


@dataclass(frozen=True, slots=True)
class CandidateAuthorityMembership:
    """Exact active authority path for one body-free candidate."""

    artifact_kind: str
    content_mode: Literal["manifest_member", "claim_passage"]


class AuthoritySnapshotError(RuntimeError):
    def __init__(self, code: str = "AUTHORITY_SNAPSHOT_INVALID") -> None:
        super().__init__(code)


def _table_exists(
    connection: sqlite3.Connection,
    schema: str,
    table: str,
) -> bool:
    row = connection.execute(
        f"SELECT 1 FROM {schema}.sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def _active_epoch(connection: sqlite3.Connection, schema: str) -> int:
    row = connection.execute(
        f"SELECT epoch FROM {schema}.runtime_epochs WHERE state = 'ACTIVE'"
    ).fetchone()
    return 0 if row is None else int(row[0])


def _safe_authorized_ids(
    rows: list[tuple[object, ...]],
    direct_tombstones: frozenset[tuple[str, str]],
    lineage_tombstones: frozenset[str],
) -> frozenset[str]:
    result: set[str] = set()
    for row in rows:
        if len(row) < 2 or type(row[0]) is not str or not row[0]:
            continue
        try:
            identifier = _OBJECT_ID.validate_python(row[1], strict=True)
        except (ValidationError, TypeError, ValueError):
            # Legacy/non-object ledger identifiers never become cross-boundary
            # retrieval capabilities merely because they exist in SQLite.
            continue
        try:
            lineage_raw = [] if len(row) < 3 else json.loads(str(row[2]))
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if (
            type(lineage_raw) is not list
            or any(type(value) is not str for value in lineage_raw)
            or lineage_raw != sorted(set(lineage_raw))
        ):
            continue
        try:
            lineage = tuple(
                _SHA256.validate_python(value, strict=True) for value in lineage_raw
            )
        except (ValidationError, TypeError, ValueError):
            continue
        if (
            (row[0], target_hash(row[0], identifier)) not in direct_tombstones
            and not lineage_tombstones.intersection(lineage)
        ):
            result.add(identifier)
    return frozenset(result)


def _exact_graph_support_passage(
    connection: sqlite3.Connection,
    *,
    claim_ref: VersionRef,
    passage_ref: VersionRef,
) -> bool:
    row = connection.execute(
        "SELECT 1 FROM main.claims AS claim "
        "JOIN main.claim_evidence AS edge "
        "  ON edge.claim_id = claim.claim_id "
        " AND edge.claim_version = claim.version "
        "JOIN main.passages AS passage "
        "  ON passage.passage_id = edge.passage_id "
        " AND passage.version = edge.passage_version "
        "JOIN main.source_versions AS source_version "
        "  ON source_version.source_id = passage.source_id "
        " AND source_version.version = passage.source_version "
        "JOIN main.sources AS source ON source.source_id = passage.source_id "
        "WHERE claim.claim_id = ? AND claim.version = ? "
        "AND claim.claim_sha256 = ? AND claim.review_status = 'APPROVED' "
        "AND claim.privacy_scope = 'GLOBAL' AND edge.relation = 'SUPPORTS' "
        "AND passage.passage_id = ? AND passage.version = ? "
        "AND passage.normalized_text_sha256 = ? "
        "AND passage.retrieval_content_ref = ? "
        "AND passage.review_status = 'APPROVED' "
        "AND passage.privacy_scope = 'GLOBAL' "
        "AND source_version.status = 'APPROVED' "
        "AND source.current_version = source_version.version",
        (
            claim_ref.object_id,
            claim_ref.version,
            claim_ref.content_sha256,
            passage_ref.object_id,
            passage_ref.version,
            passage_ref.content_sha256,
            f"sha256:{passage_ref.content_sha256}",
        ),
    ).fetchone()
    return row is not None


class AuthoritativeSnapshotRepository:
    """One attached SQLite read transaction for both authority scopes.

    The connection's ``main`` schema is the global authority database and the
    client database is attached under a fixed internal schema name.  No caller
    supplied schema, table, path, or SQL is accepted after construction.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        policy_ref_provider: Callable[[], VersionRef],
        clock: Clock | None = None,
        id_factory: IdFactory | None = None,
        client_schema: str = _CLIENT_SCHEMA,
        global_content_store: ContentStore | None = None,
        case_contributor_hasher: CaseContributorHasher | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SQLITE_CONNECTION_REQUIRED")
        if client_schema != _CLIENT_SCHEMA:
            raise AuthoritySnapshotError
        if not callable(policy_ref_provider):
            raise TypeError("POLICY_REF_PROVIDER_REQUIRED")
        if (
            global_content_store is not None
            and type(global_content_store) is not ContentStore
        ):
            raise TypeError("CONTENT_STORE_REQUIRED")
        if case_contributor_hasher is not None and not isinstance(
            case_contributor_hasher, CaseContributorHasher
        ):
            raise TypeError("CASE_CONTRIBUTOR_HASHER_REQUIRED")
        self._connection = connection
        self._policy_ref_provider = policy_ref_provider
        self._clock = clock if clock is not None else SystemClock()
        self._ids = id_factory if id_factory is not None else IdFactory(self._clock)
        self._global_content_store = global_content_store
        self._case_contributor_hasher = case_contributor_hasher
        self._issued: dict[str, AuthoritativeFilterSnapshot] = {}
        self._issued_scopes: dict[str, RetrievalScope] = {}
        self._assert_schema()

    @classmethod
    def open(
        cls,
        global_database: Path,
        client_database: Path,
        *,
        policy_ref_provider: Callable[[], VersionRef],
        clock: Clock | None = None,
        id_factory: IdFactory | None = None,
        global_content_store: ContentStore | None = None,
        case_contributor_hasher: CaseContributorHasher | None = None,
    ) -> "AuthoritativeSnapshotRepository":
        if not isinstance(global_database, Path) or not isinstance(client_database, Path):
            raise TypeError("AUTHORITY_DATABASE_PATH_REQUIRED")
        global_path = global_database.resolve(strict=True)
        client_path = client_database.resolve(strict=True)
        connection = sqlite3.connect(
            f"{global_path.as_uri()}?mode=ro",
            uri=True,
            isolation_level=None,
            timeout=5.0,
        )
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute(
                f"ATTACH DATABASE ? AS {_CLIENT_SCHEMA}",
                (f"{client_path.as_uri()}?mode=ro",),
            )
            connection.execute("PRAGMA query_only = ON")
            return cls(
                connection,
                policy_ref_provider=policy_ref_provider,
                clock=clock,
                id_factory=id_factory,
                global_content_store=global_content_store,
                case_contributor_hasher=case_contributor_hasher,
            )
        except BaseException:
            connection.close()
            raise

    def close(self) -> None:
        self._issued.clear()
        self._issued_scopes.clear()
        self._connection.close()

    def __enter__(self) -> "AuthoritativeSnapshotRepository":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _assert_schema(self) -> None:
        required = (
            ("main", "runtime_epochs"),
            ("main", "tombstones"),
            ("main", "knowledge_catalog_state"),
            (_CLIENT_SCHEMA, "runtime_epochs"),
            (_CLIENT_SCHEMA, "tombstones"),
        )
        if any(
            not _table_exists(self._connection, schema, table)
            for schema, table in required
        ):
            raise AuthoritySnapshotError

    def freeze(self, scope: RetrievalScope) -> AuthoritativeFilterSnapshot:
        if type(scope) is not RetrievalScope:
            raise TypeError("RETRIEVAL_SCOPE_REQUIRED")
        if self._connection.in_transaction:
            raise AuthoritySnapshotError("AUTHORITY_TRANSACTION_NESTED")
        self._connection.execute("BEGIN")
        try:
            state = self._read_state()
            allowed = self._read_allowed_ids(
                global_epoch=state[0],
                client_epoch=state[1],
            )
            policy_ref = self._policy_ref_provider()
            if type(policy_ref) is not VersionRef:
                raise AuthoritySnapshotError
            snapshot = AuthoritativeFilterSnapshot(
                run_id=self._ids.uuid7(),
                global_runtime_epoch=state[0],
                client_runtime_epoch=state[1],
                tombstone_epoch=state[2],
                authorization_epoch=state[3],
                allowed_ref_ids=allowed,
                policy_ref=policy_ref,
                created_at=self._clock.now(),
            )
            self._connection.execute("COMMIT")
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        self._issued[snapshot.run_id] = snapshot
        self._issued_scopes[snapshot.run_id] = scope
        return snapshot

    def _read_state(self) -> tuple[int, int, int, int]:
        global_epoch = _active_epoch(self._connection, "main")
        client_epoch = _active_epoch(self._connection, _CLIENT_SCHEMA)
        catalog = self._connection.execute(
            "SELECT authorization_epoch, tombstone_epoch "
            "FROM main.knowledge_catalog_state WHERE singleton = 1"
        ).fetchone()
        if catalog is None:
            raise AuthoritySnapshotError
        client_tombstones_row = self._connection.execute(
            f"SELECT COUNT(*) FROM {_CLIENT_SCHEMA}.tombstones"
        ).fetchone()
        if client_tombstones_row is None:
            raise AuthoritySnapshotError
        client_tombstones = int(client_tombstones_row[0])
        if client_tombstones >= 2**32:
            raise AuthoritySnapshotError("AUTHORITY_TOMBSTONE_EPOCH_EXHAUSTED")
        tombstone_epoch = (int(catalog[1]) << 32) | client_tombstones
        return global_epoch, client_epoch, tombstone_epoch, int(catalog[0])

    def _read_allowed_ids(
        self,
        *,
        global_epoch: int,
        client_epoch: int,
    ) -> frozenset[str]:
        global_rows: list[tuple[object, ...]] = []
        client_rows: list[tuple[object, ...]] = []
        if global_epoch > 0:
            global_rows.extend(
                self._connection.execute(
                    "SELECT member.object_type, member.object_id, "
                    "member.source_lineage_json "
                    "FROM main.active_artifacts AS active "
                    "JOIN main.runtime_epochs AS runtime ON runtime.epoch = active.epoch "
                    "JOIN main.artifact_manifests AS manifest "
                    "  ON manifest.manifest_id = active.manifest_id "
                    "JOIN main.artifact_members AS member "
                    "  ON member.manifest_id = manifest.manifest_id "
                    "WHERE runtime.state = 'ACTIVE' AND active.epoch = ? "
                    "  AND manifest.state = 'ACTIVE' AND manifest.verified = 1",
                    (global_epoch,),
                ).fetchall()
            )
            global_rows.extend(self._read_graph_nested_rows(global_epoch))
        if client_epoch > 0:
            client_rows.extend(
                self._connection.execute(
                    f"SELECT member.object_type, member.object_id, "
                    "member.source_lineage_json "
                    f"FROM {_CLIENT_SCHEMA}.active_artifacts AS active "
                    f"JOIN {_CLIENT_SCHEMA}.runtime_epochs AS runtime "
                    "  ON runtime.epoch = active.epoch "
                    f"JOIN {_CLIENT_SCHEMA}.artifact_manifests AS manifest "
                    "  ON manifest.manifest_id = active.manifest_id "
                    f"JOIN {_CLIENT_SCHEMA}.artifact_members AS member "
                    "  ON member.manifest_id = manifest.manifest_id "
                    "WHERE runtime.state = 'ACTIVE' AND active.epoch = ? "
                    "  AND manifest.state = 'ACTIVE' AND manifest.verified = 1",
                    (client_epoch,),
                ).fetchall()
            )
        global_direct, global_lineage = self._tombstones("main")
        client_direct, client_lineage = self._tombstones(_CLIENT_SCHEMA)
        return _safe_authorized_ids(
            global_rows,
            global_direct,
            global_lineage,
        ) | _safe_authorized_ids(
            client_rows,
            client_direct,
            client_lineage,
        )

    def _read_graph_nested_rows(
        self,
        global_epoch: int,
    ) -> list[tuple[object, ...]]:
        from consultation_kb.graph.artifact_contracts import (
            GraphBuildClosureError,
            GraphEdgeAuthorityCatalogPayload,
            verify_graph_member_payloads,
        )

        rows = self._connection.execute(
            "SELECT manifest.manifest_id, manifest.source_version, "
            "member.ordinal, member.object_type, member.object_id, "
            "member.object_sha256, member.source_lineage_json, "
            "member.media_type, member.size_bytes "
            "FROM main.active_artifacts AS active "
            "JOIN main.runtime_epochs AS runtime ON runtime.epoch = active.epoch "
            "JOIN main.artifact_manifests AS manifest "
            "  ON manifest.manifest_id = active.manifest_id "
            "JOIN main.artifact_members AS member "
            "  ON member.manifest_id = manifest.manifest_id "
            "WHERE active.epoch = ? AND runtime.state = 'ACTIVE' "
            "AND manifest.artifact_kind = 'graph' "
            "AND manifest.state = 'ACTIVE' AND manifest.verified = 1 "
            "ORDER BY manifest.manifest_id, member.ordinal",
            (global_epoch,),
        ).fetchall()
        if not rows:
            return []
        manifest_ids = {str(row[0]) for row in rows}
        roles = tuple(str(row[3]) for row in rows)
        media_types = tuple(str(row[7]) for row in rows)
        if (
            len(manifest_ids) != 1
            or roles != derived_artifact_role_layout("graph")
            or media_types != derived_artifact_media_type_layout("graph")
            or tuple(int(row[2]) for row in rows) != tuple(range(len(rows)))
        ):
            raise AuthoritySnapshotError("AUTHORITY_GRAPH_CLOSURE_INVALID")
        if self._global_content_store is None:
            raise AuthoritySnapshotError("AUTHORITY_GRAPH_CAS_REQUIRED")
        try:
            members = tuple(
                ArtifactMemberIdentity(
                    role=str(row[3]),
                    object_id=str(row[4]),
                    content_sha256=str(row[5]),
                    media_type=str(row[7]),
                    size_bytes=int(row[8]),
                )
                for row in rows
            )
            payloads = {
                member.role: self._global_content_store.read_verified(
                    self._global_content_store.reference(
                        content_sha256=member.content_sha256,
                        media_type=member.media_type,
                        size_bytes=member.size_bytes,
                    )
                )
                for member in members
            }
            verify_graph_member_payloads(payloads, members=members)
            graph_payload = json.loads(payloads["global_graph"])
            catalog = GraphEdgeAuthorityCatalogPayload.model_validate_json(
                payloads["graph_edge_authority_catalog"],
                strict=True,
            )
        except (
            ContentStoreError,
            GraphBuildClosureError,
            OSError,
            TypeError,
            ValueError,
            ValidationError,
            json.JSONDecodeError,
        ):
            raise AuthoritySnapshotError("AUTHORITY_GRAPH_CLOSURE_INVALID") from None
        if not isinstance(graph_payload, dict) or not isinstance(
            graph_payload.get("edges"), list
        ):
            raise AuthoritySnapshotError("AUTHORITY_GRAPH_CLOSURE_INVALID")

        source_version = int(str(rows[0][1]))
        lineage_by_role = {str(row[3]): str(row[6]) for row in rows}
        nested: list[tuple[object, ...]] = []
        relation_refs: set[VersionRef] = set()
        for raw_edge in graph_payload["edges"]:
            if not isinstance(raw_edge, dict) or not isinstance(
                raw_edge.get("attributes"), dict
            ):
                raise AuthoritySnapshotError("AUTHORITY_GRAPH_CLOSURE_INVALID")
            attributes = raw_edge["attributes"]
            try:
                relation_ref = VersionRef.model_validate(attributes["relation_ref"])
                claim_ref = VersionRef.model_validate(attributes["claim_ref"])
                passage_refs = tuple(
                    VersionRef.model_validate(value)
                    for value in attributes["passage_refs"]
                )
            except (KeyError, TypeError, ValueError):
                raise AuthoritySnapshotError(
                    "AUTHORITY_GRAPH_CLOSURE_INVALID"
                ) from None
            if (
                relation_ref.version != source_version
                or relation_ref in relation_refs
                or not passage_refs
            ):
                raise AuthoritySnapshotError("AUTHORITY_GRAPH_CLOSURE_INVALID")
            relation_refs.add(relation_ref)
            nested.append(
                (
                    "graph_edge",
                    relation_ref.object_id,
                    lineage_by_role["global_graph"],
                )
            )
            for passage_ref in passage_refs:
                if not _exact_graph_support_passage(
                    self._connection,
                    claim_ref=claim_ref,
                    passage_ref=passage_ref,
                ):
                    raise AuthoritySnapshotError(
                        "AUTHORITY_GRAPH_CLOSURE_INVALID"
                    )
                nested.append(
                    (
                        "passage",
                        passage_ref.object_id,
                        lineage_by_role["global_graph"],
                    )
                )
        catalog_relations: set[VersionRef] = set()
        for record in catalog.records:
            if (
                record.relation_ref.version != source_version
                or record.authority_ref.version != source_version
            ):
                raise AuthoritySnapshotError("AUTHORITY_GRAPH_CLOSURE_INVALID")
            catalog_relations.add(record.relation_ref)
            nested.append(
                (
                    "graph_edge_authority",
                    record.authority_ref.object_id,
                    lineage_by_role["graph_edge_authority_catalog"],
                )
            )
        if catalog_relations != relation_refs:
            raise AuthoritySnapshotError("AUTHORITY_GRAPH_CLOSURE_INVALID")
        return nested

    def _tombstones(
        self,
        schema: str,
    ) -> tuple[frozenset[tuple[str, str]], frozenset[str]]:
        rows = self._connection.execute(
            f"SELECT target_type, target_id_hash, source_lineage_hash "
            f"FROM {schema}.tombstones"
        ).fetchall()
        return (
            frozenset((str(row[0]), str(row[1])) for row in rows),
            frozenset(str(row[2]) for row in rows if str(row[2])),
        )

    def assert_snapshot_current(
        self,
        snapshot: AuthoritativeFilterSnapshot,
    ) -> None:
        issued = self._issued.get(snapshot.run_id)
        if issued != snapshot or self._connection.in_transaction:
            raise AuthoritySnapshotStale
        self._connection.execute("BEGIN")
        try:
            state = self._read_state()
            current_policy = self._policy_ref_provider()
            allowed = self._read_allowed_ids(
                global_epoch=state[0], client_epoch=state[1]
            )
            self._connection.execute("COMMIT")
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise AuthoritySnapshotStale from None
        if (
            state
            != (
                snapshot.global_runtime_epoch,
                snapshot.client_runtime_epoch,
                snapshot.tombstone_epoch,
                snapshot.authorization_epoch,
            )
            or current_policy != snapshot.policy_ref
            or allowed != snapshot.allowed_ref_ids
        ):
            raise AuthoritySnapshotStale

    def assert_binding_current(self, binding: FilterCapabilityBinding) -> None:
        snapshot = self._issued.get(binding.run_id)
        if snapshot is None or (
            binding.global_runtime_epoch != snapshot.global_runtime_epoch
            or binding.client_runtime_epoch != snapshot.client_runtime_epoch
            or binding.tombstone_epoch != snapshot.tombstone_epoch
            or binding.authorization_epoch != snapshot.authorization_epoch
            or binding.policy_ref != snapshot.policy_ref
        ):
            raise AuthoritySnapshotStale
        self.assert_snapshot_current(snapshot)

    def assert_candidate_binding_visible(
        self,
        candidate: CandidateRef,
        binding: FilterCapabilityBinding,
    ) -> None:
        self.assert_binding_current(binding)
        snapshot = self._issued.get(binding.run_id)
        if snapshot is None or self.candidate_status(candidate, snapshot) != "visible":
            raise AuthoritySnapshotStale
        if candidate.provenance.provenance_scope in {"case_derived", "mixed"}:
            issued_scope = self._issued_scopes.get(binding.run_id)
            hasher = self._case_contributor_hasher
            if issued_scope is None or hasher is None:
                raise AuthoritySnapshotStale
            try:
                current_alias = hasher.pseudonymous_client_id(
                    issued_scope.current_client_id
                )
            except Exception:
                raise AuthoritySnapshotStale from None
            if current_alias in candidate.provenance.case_contributor_client_ids:
                raise AuthoritySnapshotStale

    def candidate_status(
        self,
        candidate: CandidateRef,
        snapshot: AuthoritativeFilterSnapshot,
    ) -> CandidateAuthorityStatus:
        schemas = (
            (_CLIENT_SCHEMA,)
            if candidate.provenance.provenance_scope == "client_private"
            else ("main",)
        )
        target_digest = target_hash(candidate.object_type, candidate.reference.object_id)
        lineage_digests = candidate.metadata.source_lineage_hashes
        for schema in schemas:
            direct = self._connection.execute(
                f"SELECT 1 FROM {schema}.tombstones "
                "WHERE target_type = ? AND target_id_hash = ? LIMIT 1",
                (candidate.object_type, target_digest),
            ).fetchone()
            if direct is not None:
                return "tombstoned"
            if lineage_digests:
                placeholders = ",".join("?" for _ in lineage_digests)
                row = self._connection.execute(
                    f"SELECT 1 FROM {schema}.tombstones "
                    f"WHERE source_lineage_hash IN ({placeholders}) LIMIT 1",
                    lineage_digests,
                ).fetchone()
                if row is not None:
                    return "tombstoned"
        if candidate.reference.object_id not in snapshot.allowed_ref_ids:
            return "unauthorized"
        if not self._exact_reference_is_authorized(candidate, snapshot):
            return "unauthorized"
        return "visible"

    def _exact_reference_is_authorized(
        self,
        candidate: CandidateRef,
        snapshot: AuthoritativeFilterSnapshot,
    ) -> bool:
        schema = (
            _CLIENT_SCHEMA
            if candidate.provenance.provenance_scope == "client_private"
            else "main"
        )
        epoch = (
            snapshot.client_runtime_epoch
            if schema == _CLIENT_SCHEMA
            else snapshot.global_runtime_epoch
        )
        return (
            candidate_authority_membership(
                self._connection,
                schema=schema,
                epoch=epoch,
                candidate=candidate,
                global_content_store=self._global_content_store,
                clock=self._clock,
            )
            is not None
        )


def _exact_active_manifest_kind(
    connection: sqlite3.Connection,
    *,
    schema: str,
    epoch: int,
    reference: VersionRef,
) -> str | None:
    if epoch <= 0:
        return None
    rows = connection.execute(
        f"SELECT manifest.artifact_kind "
        f"FROM {schema}.active_artifacts AS active "
        f"JOIN {schema}.runtime_epochs AS runtime ON runtime.epoch = active.epoch "
        f"JOIN {schema}.artifact_manifests AS manifest "
        "  ON manifest.manifest_id = active.manifest_id "
        f"JOIN {schema}.publication_operations AS operation "
        "  ON operation.operation_id = manifest.operation_id "
        "WHERE active.epoch = ? AND runtime.state = 'ACTIVE' "
        "AND runtime.operation_id = operation.operation_id "
        "AND operation.state = 'ACTIVE' AND operation.runtime_epoch = active.epoch "
        "AND operation.authority_base_version = ? "
        "AND manifest.source_version = CAST(operation.authority_base_version AS TEXT) "
        "AND manifest.state = 'ACTIVE' AND manifest.verified = 1 "
        "AND manifest.manifest_id = ? AND manifest.manifest_sha256 = ? "
        "AND manifest.source_version = ?",
        (
            epoch,
            reference.version,
            reference.object_id,
            reference.content_sha256,
            str(reference.version),
        ),
    ).fetchall()
    if len(rows) != 1 or type(rows[0][0]) is not str:
        return None
    return str(rows[0][0])


def _active_case_route_builder(
    connection: sqlite3.Connection,
    *,
    epoch: int,
    channel: str,
    content_store: ContentStore,
) -> tuple[DerivedArtifactKind, DerivedArtifactBuilderInputV2] | None:
    """Open the exact same-operation derived root which assigned a case row."""

    route_kind = _CASE_ROUTE_KIND_BY_CHANNEL.get(channel)
    if route_kind is None:
        return None
    builder_role = f"{route_kind}_builder_input"
    rows = connection.execute(
        "SELECT manifest.manifest_id, manifest.source_version, "
        "manifest.manifest_sha256, manifest.operation_id, "
        "member.object_sha256, member.media_type, member.size_bytes, "
        "operation.required_manifests_json, "
        "operation.required_manifest_count "
        "FROM main.active_artifacts AS active "
        "JOIN main.runtime_epochs AS runtime ON runtime.epoch = active.epoch "
        "JOIN main.artifact_manifests AS manifest "
        "  ON manifest.manifest_id = active.manifest_id "
        "JOIN main.publication_operations AS operation "
        "  ON operation.operation_id = runtime.operation_id "
        "JOIN main.artifact_members AS member "
        "  ON member.manifest_id = manifest.manifest_id "
        "WHERE active.epoch = ? AND runtime.state = 'ACTIVE' "
        "AND operation.state = 'ACTIVE' AND operation.runtime_epoch = ? "
        "AND manifest.operation_id = operation.operation_id "
        "AND manifest.artifact_kind = ? AND manifest.state = 'ACTIVE' "
        "AND manifest.verified = 1 "
        "AND manifest.source_version = CAST(operation.authority_base_version AS TEXT) "
        "AND member.object_type = ? "
        "AND member.source_version = manifest.source_version",
        (epoch, epoch, route_kind, builder_role),
    ).fetchall()
    if len(rows) != 1:
        return None
    row = rows[0]
    if str(row[5]) != "application/json":
        return None
    operation_id = str(row[3])
    source_version = int(str(row[1]))
    active_rows = connection.execute(
        "SELECT manifest.artifact_kind, manifest.manifest_id, "
        "manifest.source_version, manifest.operation_id "
        "FROM main.active_artifacts AS active "
        "JOIN main.artifact_manifests AS manifest "
        "  ON manifest.manifest_id = active.manifest_id "
        "WHERE active.epoch = ? "
        "AND manifest.state = 'ACTIVE' AND manifest.verified = 1 "
        "ORDER BY manifest.artifact_kind",
        (epoch,),
    ).fetchall()
    derived = tuple(
        item for item in active_rows if str(item[0]) in _FIVE_DERIVED_ROOTS
    )
    if (
        len(derived) != len(_FIVE_DERIVED_ROOTS)
        or {str(item[0]) for item in derived} != _FIVE_DERIVED_ROOTS
        or any(str(item[3]) != operation_id for item in active_rows)
        or any(int(str(item[2])) != source_version for item in active_rows)
    ):
        return None
    try:
        required = json.loads(str(row[7]))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if (
        type(required) is not list
        or any(type(item) is not str for item in required)
        or int(str(row[8])) != len(required)
        or set(required) != {str(item[1]) for item in active_rows}
    ):
        return None
    catalog = connection.execute(
        "SELECT catalog_version FROM main.knowledge_catalog_state "
        "WHERE singleton = 1"
    ).fetchone()
    if catalog is None or int(str(catalog[0])) != source_version:
        return None
    try:
        payload = content_store.read_verified(
            content_store.reference(
                content_sha256=str(row[4]),
                media_type=str(row[5]),
                size_bytes=int(str(row[6])),
            )
        )
        builder = DerivedArtifactBuilderInputV2.model_validate_json(
            payload,
            strict=True,
        )
    except (ContentStoreError, OSError, TypeError, ValueError):
        return None
    if (
        builder.artifact_kind != route_kind
        or builder.target_runtime_epoch != epoch
        or builder.source_catalog_version != source_version
    ):
        return None
    return route_kind, builder


def _case_route_record(
    builder: DerivedArtifactBuilderInputV2,
    *,
    route_kind: DerivedArtifactKind,
    candidate: CandidateRef,
) -> RetrievalInputRecord | None:
    records = tuple(
        record
        for record in builder.retrieval_input_descriptor.assigned_records(route_kind)
        if record.candidate_ref == candidate.reference
        and record.content_ref == candidate.content_ref
    )
    if len(records) != 1:
        return None
    expected_channel = {
        "wiki_index": "wiki",
        "graph": "global_graph",
        "lexical": "lexical",
        "vector": "vector",
    }.get(route_kind)
    if candidate.channel != expected_channel:
        return None
    normalized = candidate.model_copy(
        update={"score": 0.0, "score_components": (), "filter_binding": None}
    )
    try:
        actual = RetrievalInputAssignment.from_candidate(
            normalized,
            target_channels=records[0].target_channels,
        ).to_record()
    except (TypeError, ValueError):
        return None
    return records[0] if actual == records[0] else None


def _exact_leave_one_out_parent(
    connection: sqlite3.Connection,
    *,
    epoch: int,
    candidate: CandidateRef,
) -> VersionRef | None:
    """Validate the exact active LOO mapping without needing the private body."""

    manifest_ref = candidate.metadata.manifest_ref
    if _exact_active_manifest_kind(
        connection,
        schema="main",
        epoch=epoch,
        reference=manifest_ref,
    ) != "leave_one_out_authority_manifest":
        return None
    row = connection.execute(
        "SELECT parent_object_id, parent_version, parent_sha256, "
        "excluded_client_hash, provenance_id, provenance_version "
        "FROM main.case_leave_one_out_variants "
        "WHERE variant_object_id = ? AND variant_version = ? "
        "AND variant_sha256 = ? AND content_object_id = ? "
        "AND content_version = ? AND content_sha256 = ? "
        "AND authority_manifest_id = ? AND authority_manifest_version = ? "
        "AND authority_manifest_sha256 = ? AND state = 'ACTIVE'",
        (
            candidate.reference.object_id,
            candidate.reference.version,
            candidate.reference.content_sha256,
            candidate.content_ref.object_id,
            candidate.content_ref.version,
            candidate.content_ref.content_sha256,
            manifest_ref.object_id,
            manifest_ref.version,
            manifest_ref.content_sha256,
        ),
    ).fetchall()
    if len(row) != 1:
        return None
    parent_ref = VersionRef(
        object_id=str(row[0][0]),
        version=int(str(row[0][1])),
        content_sha256=str(row[0][2]),
    )
    try:
        from consultation_kb.archive.leave_one_out import (
            LeaveOneOutAuthorityRepository,
        )

        authority = LeaveOneOutAuthorityRepository(connection).resolve_active(
            parent_ref=parent_ref,
            excluded_client_hash=str(row[0][3]),
        )
    except Exception:
        return None
    if authority is None or (
        authority.variant_ref != candidate.reference
        or authority.content_ref != candidate.content_ref
        or authority.authority_manifest_ref != manifest_ref
        or authority.allowed_uses != candidate.metadata.allowed_uses
        or authority.approved_at != candidate.metadata.approved_at
        or authority.approved_at != candidate.metadata.effective_from
        or authority.effective_to != candidate.metadata.effective_to
        or authority.review_status != candidate.metadata.review_status
        or authority.source_grade != candidate.metadata.source_grade
        or authority.remaining_independent_source_count
        != candidate.metadata.source_count
        or authority.regeneration_rule_ref
        != candidate.provenance.derivation_rule_ref
        or authority.content_ref not in candidate.location.anchor_refs
    ):
        return None
    provenance_row = connection.execute(
        "SELECT closure_json FROM main.case_provenance "
        "WHERE provenance_id = ? AND provenance_version = ? "
        "AND provenance_sha256 = ?",
        (
            str(row[0][4]),
            int(str(row[0][5])),
            authority.provenance_ref.content_sha256,
        ),
    ).fetchone()
    if provenance_row is None:
        return None
    try:
        provenance = CaseProvenanceRecord.model_validate_json(
            str(provenance_row[0]), strict=True
        )
    except ValueError:
        return None
    if (
        provenance.provenance_ref != authority.provenance_ref
        or provenance.artifact_ref != candidate.reference
        or provenance.artifact_kind != candidate.object_type
        or provenance.allowed_uses != candidate.metadata.allowed_uses
        or provenance.source_grade != candidate.metadata.source_grade
        or provenance.effective_to != candidate.metadata.effective_to
        or provenance.derivation_rule_ref
        != candidate.provenance.derivation_rule_ref
        or provenance.contributor_client_hashes
        != candidate.provenance.case_contributor_client_ids
        or frozenset(
            item.case_ref.object_id for item in provenance.case_contributions
        )
        != candidate.provenance.case_ids
        or frozenset(
            item.evidence_ref.object_id for item in provenance.independent_evidence
        )
        != candidate.provenance.source_ids
    ):
        return None
    member = connection.execute(
        "SELECT media_type, size_bytes FROM main.artifact_members "
        "WHERE manifest_id = ? AND object_id = ? AND object_sha256 = ?",
        (
            manifest_ref.object_id,
            candidate.content_ref.object_id,
            candidate.content_ref.content_sha256,
        ),
    ).fetchone()
    if member is None or tuple(member) != (
        candidate.metadata.media_type,
        candidate.metadata.size_bytes,
    ):
        return None
    return parent_ref


def _leave_one_out_route_record(
    connection: sqlite3.Connection,
    *,
    epoch: int,
    candidate: CandidateRef,
    parent_ref: VersionRef,
    content_store: ContentStore,
    clock: Clock | None,
) -> bool:
    route = _active_case_route_builder(
        connection,
        epoch=epoch,
        channel=candidate.channel,
        content_store=content_store,
    )
    if route is None:
        return False
    route_kind, builder = route
    parent_records = tuple(
        record
        for record in builder.retrieval_input_descriptor.assigned_records(route_kind)
        if record.candidate_ref == parent_ref
    )
    if len(parent_records) != 1:
        return False
    try:
        from consultation_kb.archive.case_index_publication import (
            CaseIndexPublicationRepository,
        )

        repository = CaseIndexPublicationRepository(
            connection,
            content_store,
            clock=clock,
        )
        bundle = repository.replay_manifest(
            parent_records[0].authority_manifest_ref
        )
    except Exception:
        return False
    parent = next(
        (
            item
            for item in bundle.candidates
            if item.reference == parent_ref
            and item.content_ref == parent_records[0].content_ref
        ),
        None,
    )
    if parent is None or parent.metadata.leave_one_out is None:
        return False
    routed_parent = parent.model_copy(update={"channel": candidate.channel})
    if (
        not repository.is_exact_published_candidate(routed_parent)
        or _case_route_record(
            builder,
            route_kind=route_kind,
            candidate=routed_parent,
        )
        != parent_records[0]
    ):
        return False
    variant = parent.metadata.leave_one_out
    expected = CandidateRef(
        reference=variant.reference,
        content_ref=variant.content_ref,
        object_type=variant.object_type,
        channel=candidate.channel,
        metadata=CandidateMetadata(
            manifest_ref=variant.manifest_ref,
            review_status=variant.review_status,
            allowed_uses=variant.allowed_uses,
            approved_at=variant.approved_at,
            effective_from=variant.effective_from,
            effective_to=variant.effective_to,
            review_due_at=variant.review_due_at,
            sensitivity=variant.sensitivity,
            source_grade=variant.source_grade,
            framework_priority=variant.framework_priority,
            empirical_support=variant.empirical_support,
            source_count=variant.source_count,
            minimum_leave_one_out_sources=(
                parent.metadata.minimum_leave_one_out_sources
            ),
            contributor_identity_scheme=(
                parent.metadata.contributor_identity_scheme
            ),
            source_lineage_hashes=variant.source_lineage_hashes,
            media_type=variant.media_type,
            size_bytes=variant.size_bytes,
            leave_one_out=None,
        ),
        provenance=variant.provenance,
        location=variant.location,
        freshness=variant.freshness,
        score=0.0,
    )
    return candidate_capability_payload(expected) == candidate_capability_payload(
        candidate
    )


def _exact_manifest_member(
    connection: sqlite3.Connection,
    *,
    schema: str,
    manifest_id: str,
    object_type: str,
    reference: VersionRef,
    media_type: str | None = None,
    size_bytes: int | None = None,
) -> bool:
    row = connection.execute(
        f"SELECT member.media_type, member.size_bytes "
        f"FROM {schema}.artifact_members AS member "
        f"JOIN {schema}.artifact_manifests AS manifest "
        "  ON manifest.manifest_id = member.manifest_id "
        "WHERE member.manifest_id = ? AND member.object_type = ? "
        "AND member.object_id = ? AND member.object_sha256 = ? "
        "AND member.source_version = manifest.source_version",
        (
            manifest_id,
            object_type,
            reference.object_id,
            reference.content_sha256,
        ),
    ).fetchone()
    if row is None:
        return False
    if media_type is not None and str(row[0]) != media_type:
        return False
    if size_bytes is not None:
        try:
            return int(str(row[1])) == size_bytes
        except ValueError:
            return False
    return True


def _exact_global_authority_row(
    connection: sqlite3.Connection,
    candidate: CandidateRef,
) -> bool:
    reference = candidate.reference
    if candidate.object_type == "claim":
        row = connection.execute(
            "SELECT 1 FROM main.claims WHERE claim_id = ? AND version = ? "
            "AND claim_sha256 = ? AND review_status = 'APPROVED' "
            "AND privacy_scope = 'GLOBAL'",
            (
                reference.object_id,
                reference.version,
                reference.content_sha256,
            ),
        ).fetchone()
    elif candidate.object_type == "wiki":
        row = connection.execute(
            "SELECT 1 FROM main.wiki_revisions WHERE wiki_id = ? AND revision = ? "
            "AND body_sha256 = ? AND review_status = 'ACTIVE'",
            (
                reference.object_id,
                reference.version,
                reference.content_sha256,
            ),
        ).fetchone()
    elif candidate.object_type == "theory":
        row = connection.execute(
            "SELECT 1 FROM main.theory_revisions WHERE theory_id = ? AND revision = ? "
            "AND revision_sha256 = ? AND status = 'ACTIVE'",
            (
                reference.object_id,
                reference.version,
                reference.content_sha256,
            ),
        ).fetchone()
    else:
        return False
    return row is not None


def _exact_claim_passage_closure(
    connection: sqlite3.Connection,
    candidate: CandidateRef,
) -> bool:
    claim = candidate.reference
    passage = candidate.content_ref
    row = connection.execute(
        "SELECT passage.retrieval_content_ref "
        "FROM main.claim_evidence AS edge "
        "JOIN main.passages AS passage "
        "  ON passage.passage_id = edge.passage_id "
        " AND passage.version = edge.passage_version "
        "JOIN main.source_versions AS source_version "
        "  ON source_version.source_id = passage.source_id "
        " AND source_version.version = passage.source_version "
        "JOIN main.sources AS source ON source.source_id = passage.source_id "
        "WHERE edge.claim_id = ? AND edge.claim_version = ? "
        "AND edge.relation = 'SUPPORTS' "
        "AND passage.passage_id = ? AND passage.version = ? "
        "AND passage.normalized_text_sha256 = ? "
        "AND passage.review_status = 'APPROVED' "
        "AND passage.privacy_scope = 'GLOBAL' "
        "AND source_version.status = 'APPROVED' "
        "AND source.current_version = source_version.version",
        (
            claim.object_id,
            claim.version,
            passage.object_id,
            passage.version,
            passage.content_sha256,
        ),
    ).fetchone()
    return (
        row is not None
        and str(row[0]) == f"sha256:{passage.content_sha256}"
        and passage.object_id in candidate.provenance.passage_ids
        and passage in candidate.location.anchor_refs
    )


def candidate_authority_membership(
    connection: sqlite3.Connection,
    *,
    schema: str,
    epoch: int,
    candidate: CandidateRef,
    global_content_store: ContentStore | None = None,
    clock: Clock | None = None,
) -> CandidateAuthorityMembership | None:
    """Resolve a candidate only through its exact active content authority root.

    Derived Wiki/lexical/vector/graph roots remain valid control-plane members,
    but can never be borrowed as a content authority manifest.  P4 has no
    governed case/LOO authority root, so case-derived evidence is closed off.
    """

    if schema not in {"main", _CLIENT_SCHEMA} or epoch <= 0:
        return None
    provenance_scope = candidate.provenance.provenance_scope
    if schema == "main":
        if provenance_scope in {"case_derived", "mixed"}:
            if global_content_store is None:
                return None
            try:
                if _exact_active_manifest_kind(
                    connection,
                    schema=schema,
                    epoch=epoch,
                    reference=candidate.metadata.manifest_ref,
                ) == "leave_one_out_authority_manifest":
                    parent_ref = _exact_leave_one_out_parent(
                        connection,
                        epoch=epoch,
                        candidate=candidate,
                    )
                    if parent_ref is None or not _leave_one_out_route_record(
                        connection,
                        epoch=epoch,
                        candidate=candidate,
                        parent_ref=parent_ref,
                        content_store=global_content_store,
                        clock=clock,
                    ):
                        return None
                    return CandidateAuthorityMembership(
                        artifact_kind="leave_one_out_authority_manifest",
                        content_mode="manifest_member",
                    )
                from consultation_kb.archive.case_index_publication import (
                    CaseIndexPublicationRepository,
                )

                repository = CaseIndexPublicationRepository(
                    connection,
                    global_content_store,
                    clock=clock,
                )
                if not repository.is_exact_published_candidate(candidate):
                    return None
                route = _active_case_route_builder(
                    connection,
                    epoch=epoch,
                    channel=candidate.channel,
                    content_store=global_content_store,
                )
                if route is None:
                    return None
                route_kind, builder = route
                if _case_route_record(
                    builder,
                    route_kind=route_kind,
                    candidate=candidate,
                ) is None:
                    return None
            except Exception:
                return None
            return CandidateAuthorityMembership(
                artifact_kind="case_index",
                content_mode="manifest_member",
            )
        if provenance_scope != "global_source":
            return None
        allowed_kinds = _GLOBAL_CONTENT_AUTHORITY_KINDS
    else:
        if provenance_scope != "client_private":
            return None
        allowed_kinds = _CLIENT_CONTENT_AUTHORITY_KINDS

    manifest = candidate.metadata.manifest_ref
    artifact_kind = _exact_active_manifest_kind(
        connection,
        schema=schema,
        epoch=epoch,
        reference=manifest,
    )
    if artifact_kind is None:
        return None
    expected_type = allowed_kinds.get(artifact_kind)
    if expected_type != candidate.object_type:
        return None
    if not _exact_manifest_member(
        connection,
        schema=schema,
        manifest_id=manifest.object_id,
        object_type=candidate.object_type,
        reference=candidate.reference,
    ):
        return None

    if schema == _CLIENT_SCHEMA:
        if candidate.content_ref != candidate.reference:
            return None
        if not _exact_manifest_member(
            connection,
            schema=schema,
            manifest_id=manifest.object_id,
            object_type=candidate.object_type,
            reference=candidate.content_ref,
            media_type=candidate.metadata.media_type,
            size_bytes=candidate.metadata.size_bytes,
        ):
            return None
        return CandidateAuthorityMembership(
            artifact_kind=artifact_kind,
            content_mode="manifest_member",
        )

    if not _exact_global_authority_row(connection, candidate):
        return None
    if candidate.content_ref == candidate.reference:
        if not _exact_manifest_member(
            connection,
            schema=schema,
            manifest_id=manifest.object_id,
            object_type=candidate.object_type,
            reference=candidate.content_ref,
            media_type=candidate.metadata.media_type,
            size_bytes=candidate.metadata.size_bytes,
        ):
            return None
        return CandidateAuthorityMembership(
            artifact_kind=artifact_kind,
            content_mode="manifest_member",
        )
    if candidate.object_type == "claim" and _exact_claim_passage_closure(
        connection, candidate
    ):
        return CandidateAuthorityMembership(
            artifact_kind=artifact_kind,
            content_mode="claim_passage",
        )
    return None


def source_lineage_digest(object_type: str, object_id: str) -> str:
    """Expose the exact immutable lineage hashing domain to index builders."""

    return lineage_hash(object_type, object_id)


__all__ = [
    "AuthoritativeSnapshotRepository",
    "AuthoritySnapshotError",
    "CandidateAuthorityMembership",
    "candidate_authority_membership",
    "source_lineage_digest",
]
