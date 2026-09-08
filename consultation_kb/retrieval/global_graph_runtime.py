"""Cold-start reconstruction of the production global-graph retrieval runtime."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from pydantic import ValidationError

from consultation_kb.graph.artifact_contracts import (
    GraphBuildManifestPayload,
    GraphEdgeAuthorityCatalogPayload,
    verify_graph_build_closure,
    verify_graph_member_payloads,
)
from consultation_kb.graph.authority_filter import (
    GraphEdgeAuthorityResolver,
    StaticGraphEdgeAuthorityCatalog,
)
from consultation_kb.graph.global_builder import GlobalGraphArtifact, ref_key
from consultation_kb.graph.serialization import (
    global_graph_artifact_from_canonical_bytes,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import (
    EmpiricalSupport,
    EvidenceFreshnessSnapshot,
    EvidenceLocator,
    Provenance,
    SourceGrade,
)
from consultation_kb.vault.content_store import ContentStore, ContentStoreError

from .artifact_contracts import (
    ArtifactBinding,
    ArtifactBindingIdentity,
    DerivedArtifactBuilderInputV2,
    RetrievalInputAssignment,
    RetrievalInputRecord,
    derived_artifact_role_layout,
)
from .artifact_discovery import ActiveRetrievalArtifactDiscovery
from .contracts import CandidateMetadata, CandidateRef
from .global_graph import (
    GraphCandidateCatalogSnapshot,
    GraphRouteCandidate,
    StaticGraphCandidateCatalog,
)


class GlobalGraphRuntimeError(RuntimeError):
    def __init__(self, code: str = "GLOBAL_GRAPH_RUNTIME_INVALID") -> None:
        self.code = code
        super().__init__(code)


def _digest_ref(value: object) -> str:
    text = str(value)
    if (
        len(text) != 71
        or not text.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in text[7:])
    ):
        raise GlobalGraphRuntimeError("GLOBAL_GRAPH_RUNTIME_CONTENT_REF_INVALID")
    return text[7:]


def _utc(value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise GlobalGraphRuntimeError(
            "GLOBAL_GRAPH_RUNTIME_TIMESTAMP_INVALID"
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise GlobalGraphRuntimeError("GLOBAL_GRAPH_RUNTIME_TIMESTAMP_INVALID")
    return parsed.astimezone(timezone.utc)


def _json_string_set(value: object) -> frozenset[str]:
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        raise GlobalGraphRuntimeError(
            "GLOBAL_GRAPH_RUNTIME_AUTHORITY_INVALID"
        ) from None
    if (
        type(parsed) is not list
        or not parsed
        or any(type(item) is not str or not item for item in parsed)
        or parsed != sorted(set(parsed))
    ):
        raise GlobalGraphRuntimeError("GLOBAL_GRAPH_RUNTIME_AUTHORITY_INVALID")
    return frozenset(parsed)


def _content_store_from_binding(binding: ArtifactBinding) -> ContentStore:
    roots: set[Path] = set()
    members = {member.role: member for member in binding.identity.members}
    for role in derived_artifact_role_layout("graph"):
        path = binding.path_for(role).resolve(strict=True)
        digest = path.parent.name
        if (
            path.name != "payload"
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
            or digest != members[role].content_sha256
            or path.parent.parent.name != digest[:2]
            or path.parent.parent.parent.name != "sha256"
            or path.parent.parent.parent.parent.name != "objects"
        ):
            raise GlobalGraphRuntimeError("GLOBAL_GRAPH_RUNTIME_CAS_SCOPE_INVALID")
        roots.add(path.parents[4])
    if len(roots) != 1:
        raise GlobalGraphRuntimeError("GLOBAL_GRAPH_RUNTIME_CAS_SCOPE_INVALID")
    return ContentStore(roots.pop())


def _lineage_for_claim(
    connection: sqlite3.Connection,
    record: RetrievalInputRecord,
    *,
    claim: tuple[object, ...],
) -> tuple[str, ...]:
    rows = connection.execute(
        "SELECT m.manifest_sha256, m.source_version, m.state, m.verified, "
        "a.object_sha256, a.source_version, a.source_lineage_json, "
        "a.media_type, a.size_bytes "
        "FROM artifact_manifests AS m JOIN artifact_members AS a "
        "ON a.manifest_id = m.manifest_id "
        "WHERE m.manifest_id = ? AND a.object_type = 'claim' "
        "AND a.object_id = ?",
        (record.authority_manifest_ref.object_id, record.candidate_ref.object_id),
    ).fetchall()
    if len(rows) != 1:
        raise GlobalGraphRuntimeError("GLOBAL_GRAPH_RUNTIME_MANIFEST_INVALID")
    row = rows[0]
    try:
        lineage = json.loads(str(row[6]))
    except (TypeError, ValueError, json.JSONDecodeError):
        raise GlobalGraphRuntimeError(
            "GLOBAL_GRAPH_RUNTIME_MANIFEST_INVALID"
        ) from None
    if (
        str(row[0]) != record.authority_manifest_ref.content_sha256
        or int(row[1]) != record.authority_manifest_ref.version
        or str(row[2]) != "ACTIVE"
        or int(row[3]) != 1
        or str(row[4]) != record.candidate_ref.content_sha256
        or int(row[5]) != record.authority_manifest_ref.version
        or str(row[7]) != str(claim[2])
        or int(row[8]) != int(str(claim[1]))
        or type(lineage) is not list
        or any(
            type(value) is not str
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
            for value in lineage
        )
        or lineage != sorted(set(lineage))
    ):
        raise GlobalGraphRuntimeError("GLOBAL_GRAPH_RUNTIME_MANIFEST_INVALID")
    return tuple(lineage)


def _claim_row(
    connection: sqlite3.Connection,
    record: RetrievalInputRecord,
) -> tuple[object, ...]:
    row = connection.execute(
        "SELECT claim_object_ref, claim_object_size_bytes, "
        "claim_object_media_type, claim_sha256, source_grade, "
        "empirical_support, review_status, effective_from, effective_to, "
        "review_due_at, allowed_uses_json, provenance_json, privacy_scope, "
        "created_at FROM claims WHERE claim_id = ? AND version = ?",
        (record.candidate_ref.object_id, record.candidate_ref.version),
    ).fetchone()
    if row is None:
        raise GlobalGraphRuntimeError("GLOBAL_GRAPH_RUNTIME_CLAIM_INVALID")
    if (
        _digest_ref(row[0]) != record.candidate_ref.content_sha256
        or str(row[3]) != record.candidate_ref.content_sha256
        or str(row[6]) != "APPROVED"
        or str(row[12]) != "GLOBAL"
    ):
        raise GlobalGraphRuntimeError("GLOBAL_GRAPH_RUNTIME_CLAIM_INVALID")
    return tuple(row)


def _supporting_passage_rows(
    connection: sqlite3.Connection,
    record: RetrievalInputRecord,
) -> tuple[tuple[object, ...], ...]:
    raw_count = int(
        str(
        connection.execute(
            "SELECT COUNT(*) FROM claim_evidence "
            "WHERE claim_id = ? AND claim_version = ? "
            "AND relation = 'SUPPORTS'",
            (record.candidate_ref.object_id, record.candidate_ref.version),
        ).fetchone()[0]
        )
    )
    rows = tuple(
        tuple(value)
        for value in connection.execute(
            "SELECT p.passage_id, p.version, p.normalized_text_sha256, "
            "p.retrieval_content_ref, p.locator_json, p.created_at, "
            "p.source_id, sv.imported_at FROM claim_evidence AS ce "
            "JOIN passages AS p ON p.passage_id = ce.passage_id "
            "AND p.version = ce.passage_version "
            "JOIN source_versions AS sv ON sv.source_id = p.source_id "
            "AND sv.version = p.source_version "
            "JOIN sources AS s ON s.source_id = p.source_id "
            "WHERE ce.claim_id = ? AND ce.claim_version = ? "
            "AND ce.relation = 'SUPPORTS' "
            "AND p.review_status = 'APPROVED' AND p.privacy_scope = 'GLOBAL' "
            "AND sv.status = 'APPROVED' AND s.current_version = sv.version "
            "ORDER BY p.passage_id, p.version",
            (record.candidate_ref.object_id, record.candidate_ref.version),
        ).fetchall()
    )
    if not rows or len(rows) != raw_count:
        raise GlobalGraphRuntimeError("GLOBAL_GRAPH_RUNTIME_PASSAGE_INVALID")
    return rows


def _candidate_from_authority(
    connection: sqlite3.Connection,
    store: ContentStore,
    record: RetrievalInputRecord,
    *,
    route_policy_ref: VersionRef,
) -> CandidateRef:
    claim = _claim_row(connection, record)
    passage_rows = _supporting_passage_rows(connection, record)
    matching = tuple(
        row
        for row in passage_rows
        if (
            str(row[0]),
            int(str(row[1])),
            str(row[2]),
        )
        == (
            record.content_ref.object_id,
            record.content_ref.version,
            record.content_ref.content_sha256,
        )
    )
    if len(matching) != 1:
        raise GlobalGraphRuntimeError("GLOBAL_GRAPH_RUNTIME_PASSAGE_INVALID")
    passage = matching[0]
    passage_digest = _digest_ref(passage[3])
    if passage_digest != record.content_ref.content_sha256:
        raise GlobalGraphRuntimeError("GLOBAL_GRAPH_RUNTIME_PASSAGE_INVALID")
    try:
        claim_body = store.read_hash_verified(record.candidate_ref.content_sha256)
        body = store.read_hash_verified(passage_digest)
        provenance = Provenance.model_validate_json(str(claim[11]), strict=True)
        locator = EvidenceLocator.model_validate_json(str(passage[4]), strict=True)
    except (ContentStoreError, OSError, ValidationError, TypeError, ValueError):
        raise GlobalGraphRuntimeError(
            "GLOBAL_GRAPH_RUNTIME_AUTHORITY_INVALID"
        ) from None
    if len(claim_body) != int(str(claim[1])):
        raise GlobalGraphRuntimeError("GLOBAL_GRAPH_RUNTIME_CLAIM_INVALID")
    if provenance.provenance_scope != "global_source":
        raise GlobalGraphRuntimeError("GLOBAL_GRAPH_RUNTIME_AUTHORITY_INVALID")
    allowed_uses = _json_string_set(claim[10])
    if "consultation" not in allowed_uses:
        raise GlobalGraphRuntimeError("GLOBAL_GRAPH_RUNTIME_AUTHORITY_INVALID")
    source_count = len({str(value[6]) for value in passage_rows})
    lineage = _lineage_for_claim(connection, record, claim=claim)
    candidate = CandidateRef(
        reference=record.candidate_ref,
        content_ref=record.content_ref,
        object_type="claim",
        channel="global_graph",
        metadata=CandidateMetadata(
            manifest_ref=record.authority_manifest_ref,
            review_status="approved",
            allowed_uses=allowed_uses,
            approved_at=_utc(claim[13]),
            effective_from=None if claim[7] is None else _utc(claim[7]),
            effective_to=None if claim[8] is None else _utc(claim[8]),
            review_due_at=None if claim[9] is None else _utc(claim[9]),
            sensitivity=1,
            source_grade=cast(SourceGrade, str(claim[4])),
            framework_priority="highest" if str(claim[4]) == "C1" else "normal",
            empirical_support=cast(EmpiricalSupport, str(claim[5])),
            source_count=source_count,
            source_lineage_hashes=lineage,
            media_type="text/plain",
            size_bytes=len(body),
        ),
        provenance=provenance,
        location=locator.model_copy(
            update={
                "anchor_refs": tuple(
                    sorted(
                        {*locator.anchor_refs, record.content_ref},
                        key=ref_key,
                    )
                )
            }
        ),
        freshness=EvidenceFreshnessSnapshot(
            status="not_time_sensitive",
            evaluated_at=_utc(passage[5]),
            source_observed_at=_utc(passage[7]),
            last_reviewed_at=_utc(passage[5]),
            review_due_at=None,
            policy_ref=route_policy_ref,
        ),
        score=0.0,
    )
    assignment = RetrievalInputAssignment(
        authority=RetrievalInputAssignment.from_candidate(
            candidate,
            target_channels=record.target_channels,
        ).authority,
        target_channels=record.target_channels,
    )
    if assignment.to_record() != record:
        raise GlobalGraphRuntimeError(
            "GLOBAL_GRAPH_RUNTIME_CANDIDATE_AUTHORITY_MISMATCH"
        )
    return candidate


def _member_ref(
    identity: ArtifactBindingIdentity,
    role: str,
) -> VersionRef:
    member = next((value for value in identity.members if value.role == role), None)
    if member is None:
        raise GlobalGraphRuntimeError("GLOBAL_GRAPH_RUNTIME_MEMBER_MISSING")
    return VersionRef(
        object_id=member.object_id,
        version=identity.source_catalog_version,
        content_sha256=member.content_sha256,
    )


def _active_claims_manifest_ref(
    connection: sqlite3.Connection,
    identity: ArtifactBindingIdentity,
) -> VersionRef:
    rows = connection.execute(
        "SELECT manifest.manifest_id, manifest.source_version, "
        "manifest.manifest_sha256, manifest.state, manifest.verified, "
        "manifest.operation_id, manifest.artifact_kind, manifest.artifact_key, "
        "runtime.operation_id, runtime.state, operation.state, "
        "operation.runtime_epoch, operation.authority_base_version "
        "FROM active_artifacts AS active "
        "JOIN artifact_manifests AS manifest "
        "ON manifest.manifest_id = active.manifest_id "
        "JOIN runtime_epochs AS runtime ON runtime.epoch = active.epoch "
        "JOIN publication_operations AS operation "
        "ON operation.operation_id = runtime.operation_id "
        "WHERE active.epoch = ? AND active.artifact_key = 'claims'",
        (identity.active_runtime_epoch,),
    ).fetchall()
    if len(rows) != 1:
        raise GlobalGraphRuntimeError(
            "GLOBAL_GRAPH_RUNTIME_CLAIMS_MANIFEST_INVALID"
        )
    row = rows[0]
    if (
        str(row[1]) != str(identity.source_catalog_version)
        or str(row[3]) != "ACTIVE"
        or int(str(row[4])) != 1
        or str(row[5]) != str(row[8])
        or str(row[6]) != "claims"
        or str(row[7]) != "claims"
        or str(row[9]) != "ACTIVE"
        or str(row[10]) != "ACTIVE"
        or int(str(row[11])) != identity.active_runtime_epoch
        or int(str(row[12])) != identity.source_catalog_version
    ):
        raise GlobalGraphRuntimeError(
            "GLOBAL_GRAPH_RUNTIME_CLAIMS_MANIFEST_INVALID"
        )
    try:
        return VersionRef(
            object_id=str(row[0]),
            version=identity.source_catalog_version,
            content_sha256=str(row[2]),
        )
    except ValidationError:
        raise GlobalGraphRuntimeError(
            "GLOBAL_GRAPH_RUNTIME_CLAIMS_MANIFEST_INVALID"
        ) from None


@dataclass(frozen=True, slots=True)
class GlobalGraphRuntime:
    """All restart-safe dependencies required by ``GlobalGraphRetriever``."""

    artifact_binding: ArtifactBinding
    artifact: GlobalGraphArtifact
    edge_authority_resolver: GraphEdgeAuthorityResolver
    candidate_catalog: StaticGraphCandidateCatalog
    builder_input: DerivedArtifactBuilderInputV2
    build_manifest: GraphBuildManifestPayload
    authority_catalog: GraphEdgeAuthorityCatalogPayload

    @classmethod
    def from_artifact_binding(
        cls,
        binding: ArtifactBinding,
        *,
        global_connection: sqlite3.Connection,
    ) -> "GlobalGraphRuntime":
        if type(binding) is not ArtifactBinding:
            raise TypeError("GLOBAL_GRAPH_ARTIFACT_BINDING_REQUIRED")
        if not isinstance(global_connection, sqlite3.Connection):
            raise TypeError("GLOBAL_GRAPH_CONNECTION_REQUIRED")
        try:
            binding.verify_authority_connection(global_connection)
            before = binding.verify_current()
            if (
                before.artifact_key != "graph"
                or before.target_runtime_epoch != before.active_runtime_epoch
                or tuple(member.role for member in before.members)
                != derived_artifact_role_layout("graph")
            ):
                raise GlobalGraphRuntimeError()
            payloads = {
                role: binding.path_for(role).read_bytes()
                for role in derived_artifact_role_layout("graph")
            }
            protected_mapping = verify_graph_member_payloads(
                payloads,
                members=before.members,
            )
            builder_input = DerivedArtifactBuilderInputV2.model_validate_json(
                payloads["graph_builder_input"], strict=True
            )
            build_manifest = GraphBuildManifestPayload.model_validate_json(
                payloads["graph_build_manifest"], strict=True
            )
            authority_catalog = (
                GraphEdgeAuthorityCatalogPayload.model_validate_json(
                    payloads["graph_edge_authority_catalog"], strict=True
                )
            )
            artifact = global_graph_artifact_from_canonical_bytes(
                payloads["global_graph"],
                expected_sha256=_member_ref(before, "global_graph").content_sha256,
            )
            if (
                builder_input.source_catalog_version
                != before.source_catalog_version
                or builder_input.target_runtime_epoch != before.target_runtime_epoch
                or artifact.source_catalog_version != before.source_catalog_version
                or artifact.source_runtime_epoch != before.target_runtime_epoch
            ):
                raise GlobalGraphRuntimeError()
            store = _content_store_from_binding(binding)
            independently_discovered = ActiveRetrievalArtifactDiscovery(
                global_connection,
                store,
            ).discover_current_set()
            if (
                independently_discovered is None
                or independently_discovered.graph.identity != before
            ):
                raise GlobalGraphRuntimeError(
                    "GLOBAL_GRAPH_RUNTIME_AUTHORITY_DB_MISMATCH"
                )
            authority_binding = independently_discovered.graph
            if authority_binding.verify_current() != before:
                raise GlobalGraphRuntimeError(
                    "GLOBAL_GRAPH_RUNTIME_AUTHORITY_DB_MISMATCH"
                )

            began = False
            try:
                if not global_connection.in_transaction:
                    global_connection.execute("BEGIN")
                    began = True
                descriptor = builder_input.retrieval_input_descriptor
                records = descriptor.assigned_records("graph")
                claims_manifest_ref = _active_claims_manifest_ref(
                    global_connection,
                    before,
                )
                if any(
                    record.authority_manifest_ref != claims_manifest_ref
                    for record in records
                ):
                    raise GlobalGraphRuntimeError(
                        "GLOBAL_GRAPH_RUNTIME_CLAIMS_MANIFEST_MISMATCH"
                    )
                candidates = tuple(
                    _candidate_from_authority(
                        global_connection,
                        store,
                        record,
                        route_policy_ref=descriptor.route_policy_ref,
                    )
                    for record in records
                )
                during = binding.verify_current()
                authority_during = authority_binding.verify_current()
                if during != before or authority_during != before:
                    raise GlobalGraphRuntimeError(
                        "GLOBAL_GRAPH_RUNTIME_BINDING_STALE"
                    )
            finally:
                if began and global_connection.in_transaction:
                    global_connection.execute("ROLLBACK")

            mapping = verify_graph_build_closure(
                artifact,
                builder_input=builder_input,
                candidates=candidates,
                authority_catalog=authority_catalog,
                build_manifest=build_manifest,
            )
            if mapping != protected_mapping:
                raise GlobalGraphRuntimeError(
                    "GLOBAL_GRAPH_RUNTIME_MAPPING_MISMATCH"
                )
            candidate_by_pair = {
                (*ref_key(value.reference), *ref_key(value.content_ref)): value
                for value in candidates
            }
            entries = tuple(
                GraphRouteCandidate(
                    relation_refs=tuple(
                        link.relation_ref for link in row.relation_links
                    ),
                    candidate=candidate_by_pair[
                        (*ref_key(row.candidate_ref), *ref_key(row.content_ref))
                    ],
                )
                for row in mapping.rows
            )
            candidate_catalog = StaticGraphCandidateCatalog(
                GraphCandidateCatalogSnapshot(
                    build_manifest_ref=_member_ref(
                        before, "graph_build_manifest"
                    ),
                    graph_root_ref=before.root_ref,
                    graph_version=_member_ref(before, "global_graph"),
                    runtime_epoch=before.target_runtime_epoch,
                    entries=entries,
                )
            )
            edge_authority_resolver = GraphEdgeAuthorityResolver(
                StaticGraphEdgeAuthorityCatalog(
                    authority_catalog.records,
                    runtime_epoch=before.target_runtime_epoch,
                )
            )
            after = binding.verify_current()
            authority_after = authority_binding.verify_current()
            if after != before or authority_after != before:
                raise GlobalGraphRuntimeError(
                    "GLOBAL_GRAPH_RUNTIME_BINDING_STALE"
                )
            return cls(
                artifact_binding=binding,
                artifact=artifact,
                edge_authority_resolver=edge_authority_resolver,
                candidate_catalog=candidate_catalog,
                builder_input=builder_input,
                build_manifest=build_manifest,
                authority_catalog=authority_catalog,
            )
        except GlobalGraphRuntimeError:
            raise
        except Exception:
            raise GlobalGraphRuntimeError() from None


__all__ = ["GlobalGraphRuntime", "GlobalGraphRuntimeError"]
