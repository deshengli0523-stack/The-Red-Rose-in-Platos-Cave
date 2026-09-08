from __future__ import annotations

import hashlib
import itertools
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.lifecycle.publish import publication_closure_sha256
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import AuthoritativeFilterSnapshot
from consultation_kb.storage.integrity import (
    ActiveArtifact,
    ActiveIntegrityGate,
    ArtifactUnavailable,
    ClosureEdge,
    ClosureNode,
    IntegrityContext,
    IntegrityStore,
    IntegrityVerifier,
)
from consultation_kb.storage.manifests import (
    ManifestMember,
    ManifestRepository,
    manifest_sha256,
)
from consultation_kb.storage.tombstones import target_hash
from consultation_kb.vault.content_store import ContentStore


NOW = datetime(2026, 7, 19, 10, 0, tzinfo=timezone.utc)
CLIENT = "client" + "_aaaaaaaaaaaa"
_IDS = IdFactory(FixedClock(NOW), itertools.count(40_000).__next__)


def _id(kind: str) -> str:
    return _IDS.object_id(kind)


def _ref(kind: str, body: bytes, *, version: int = 1) -> VersionRef:
    return VersionRef(
        object_id=_id(kind),
        version=version,
        content_sha256=hashlib.sha256(body).hexdigest(),
    )


@dataclass
class _StoredScope:
    binding: IntegrityStore
    manifest_ref: VersionRef
    members: dict[str, VersionRef]
    paths: dict[str, Path]


def _stored_scope(
    tmp_path: Path,
    *,
    scope: str,
    artifact_key: str,
    member_bodies: tuple[tuple[str, bytes], ...],
    tombstone_epoch: int = 0,
) -> _StoredScope:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.executescript(
        """
        CREATE TABLE runtime_epochs(
            epoch INTEGER PRIMARY KEY,
            operation_id TEXT NOT NULL,
            state TEXT NOT NULL
        );
        CREATE TABLE publication_operations(
            operation_id TEXT PRIMARY KEY,
            purpose TEXT NOT NULL,
            authority_base_version INTEGER NOT NULL,
            approval_request_id TEXT NOT NULL,
            descriptor_sha256 TEXT NOT NULL,
            state TEXT NOT NULL,
            required_manifests_json TEXT NOT NULL,
            required_manifest_count INTEGER NOT NULL,
            verified_manifest_count INTEGER NOT NULL,
            expected_current_epoch INTEGER,
            runtime_epoch INTEGER,
            created_at TEXT NOT NULL,
            activated_at TEXT
        );
        CREATE TABLE rebuild_stage_bindings(
            operation_id TEXT PRIMARY KEY,
            tombstone_epoch INTEGER NOT NULL
        );
        CREATE TABLE approval_executions(
            operation_id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            descriptor_sha256 TEXT NOT NULL,
            draft_sha256 TEXT NOT NULL,
            descriptor_base_version INTEGER NOT NULL,
            target_scope_hash TEXT NOT NULL,
            nonce_sha256 TEXT NOT NULL,
            state TEXT NOT NULL,
            applied_commit_version INTEGER,
            applied_at TEXT
        );
        CREATE TABLE publication_closure_attestations(
            operation_id TEXT PRIMARY KEY,
            approval_draft_sha256 TEXT NOT NULL,
            closure_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE artifact_manifests(
            manifest_id TEXT PRIMARY KEY,
            operation_id TEXT NOT NULL,
            artifact_key TEXT NOT NULL,
            artifact_kind TEXT NOT NULL,
            source_version TEXT NOT NULL,
            manifest_sha256 TEXT NOT NULL,
            state TEXT NOT NULL,
            verified INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            verified_at TEXT
        );
        CREATE TABLE artifact_members(
            manifest_id TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            object_type TEXT NOT NULL,
            object_id TEXT NOT NULL,
            object_sha256 TEXT NOT NULL,
            source_version TEXT NOT NULL,
            media_type TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            source_lineage_json TEXT NOT NULL
        );
        CREATE TABLE active_artifacts(
            epoch INTEGER NOT NULL,
            artifact_key TEXT NOT NULL,
            manifest_id TEXT NOT NULL,
            activated_at TEXT NOT NULL
        );
        CREATE TABLE tombstones(
            tombstone_id TEXT PRIMARY KEY,
            target_type TEXT NOT NULL,
            target_id_hash TEXT NOT NULL,
            source_lineage_hash TEXT NOT NULL,
            reason_code TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE knowledge_catalog_state(
            singleton INTEGER PRIMARY KEY,
            catalog_version INTEGER NOT NULL,
            authorization_epoch INTEGER NOT NULL,
            tombstone_epoch INTEGER NOT NULL
        );
        CREATE TABLE client_fact_authority(
            singleton INTEGER PRIMARY KEY,
            commit_version INTEGER NOT NULL,
            client_id TEXT NOT NULL
        );
        """
    )
    operation_id = _id("publication_operation")
    manifest_id = _id("manifest")
    store = ContentStore(tmp_path / f"{scope}-{artifact_key}")
    refs: dict[str, VersionRef] = {}
    paths: dict[str, Path] = {}
    members: list[ManifestMember] = []
    for ordinal, (object_type, body) in enumerate(member_bodies):
        reference = _ref(object_type, body)
        content = store.finalize(
            store.stage_bytes(
                body,
                purpose="integrity_test",
                manifest_id=manifest_id,
                media_type="text/plain",
            )
        )
        refs[object_type] = reference
        paths[object_type] = content.path
        members.append(
            ManifestMember(
                ordinal=ordinal,
                object_type=object_type,
                object_id=reference.object_id,
                object_sha256=reference.content_sha256,
                source_version=1,
                media_type="text/plain",
                size_bytes=len(body),
                source_lineage_hashes=(),
            )
        )
    digest = manifest_sha256(
        manifest_id=manifest_id,
        operation_id=operation_id,
        artifact_key=artifact_key,
        artifact_kind=artifact_key,
        source_version=1,
        members=members,
    )
    stamp = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
    connection.execute(
        "INSERT INTO runtime_epochs VALUES (1, ?, 'ACTIVE')",
        (operation_id,),
    )
    connection.execute(
        "INSERT INTO publication_operations VALUES ("
        "?, 'knowledge_publish', 1, ?, ?, 'ACTIVE', ?, 1, 1, NULL, 1, ?, ?)",
        (
            operation_id,
            _id("approval_request"),
            "a" * 64,
            json.dumps([manifest_id], separators=(",", ":")),
            stamp,
            stamp,
        ),
    )
    active_request_id = str(
        connection.execute(
            "SELECT approval_request_id FROM publication_operations "
            "WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()[0]
    )
    connection.execute(
        "INSERT INTO approval_executions VALUES "
        "(?, ?, ?, ?, 0, ?, ?, 'APPLIED', 41, ?)",
        (
            operation_id,
            active_request_id,
            "a" * 64,
            "b" * 64,
            "c" * 64,
            "d" * 64,
            stamp,
        ),
    )
    connection.execute(
        "INSERT INTO artifact_manifests VALUES (?, ?, ?, ?, '1', ?, 'ACTIVE', 1, ?, ?)",
        (manifest_id, operation_id, artifact_key, artifact_key, digest, stamp, stamp),
    )
    connection.executemany(
        "INSERT INTO artifact_members VALUES (?, ?, ?, ?, ?, '1', 'text/plain', ?, ?)",
        (
            (
                manifest_id,
                member.ordinal,
                member.object_type,
                member.object_id,
                member.object_sha256,
                member.size_bytes,
                json.dumps(list(member.source_lineage_hashes)),
            )
            for member in members
        ),
    )
    connection.execute(
        "INSERT INTO active_artifacts VALUES (1, ?, ?, ?)",
        (artifact_key, manifest_id, stamp),
    )
    connection.execute(
        "INSERT INTO knowledge_catalog_state VALUES (1, 1, 0, ?)",
        (tombstone_epoch,),
    )
    connection.execute(
        "INSERT INTO client_fact_authority VALUES (1, 1, ?)",
        (CLIENT,),
    )
    manifest_ref = VersionRef(
        object_id=manifest_id,
        version=1,
        content_sha256=digest,
    )
    return _StoredScope(
        binding=IntegrityStore(
            scope=scope,  # type: ignore[arg-type]
            connection=connection,
            content_store=store,
            client_id=(
                CLIENT if scope in {"client_private", "session", "run"} else None
            ),
        ),
        manifest_ref=manifest_ref,
        members=refs,
        paths=paths,
    )


def _add_pending_client_publication(
    stored: _StoredScope,
    *,
    applied_commit_version: int,
) -> str:
    connection = stored.binding.connection
    operation_id = _id("publication_operation")
    request_id = _id("approval_request")
    manifest_id = _id("manifest")
    member_id = _id("profile_json")
    body = b'{"profile":"pending"}'
    content = stored.binding.content_store.finalize(
        stored.binding.content_store.stage_bytes(
            body,
            purpose="profile_update",
            manifest_id=manifest_id,
            media_type="application/json",
        )
    )
    member = ManifestMember(
        ordinal=0,
        object_type="profile_json",
        object_id=member_id,
        object_sha256=content.content_sha256,
        source_version=2,
        media_type=content.media_type,
        size_bytes=content.size_bytes,
        source_lineage_hashes=(),
    )
    digest = manifest_sha256(
        manifest_id=manifest_id,
        operation_id=operation_id,
        artifact_key="profile",
        artifact_kind="profile",
        source_version=2,
        members=(member,),
    )
    stamp = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
    descriptor_sha256 = "e" * 64
    approval_draft_sha256 = "f" * 64
    connection.execute(
        "INSERT INTO approval_executions VALUES "
        "(?, ?, ?, ?, 1, ?, ?, 'APPLIED', ?, ?)",
        (
            operation_id,
            request_id,
            descriptor_sha256,
            approval_draft_sha256,
            "c" * 64,
            hashlib.sha256(operation_id.encode("ascii")).hexdigest(),
            applied_commit_version,
            stamp,
        ),
    )
    connection.execute(
        "INSERT INTO publication_operations VALUES "
        "(?, 'profile_update', 2, ?, ?, 'PREPARED', ?, 1, 0, 1, NULL, ?, NULL)",
        (
            operation_id,
            request_id,
            descriptor_sha256,
            json.dumps([manifest_id], separators=(",", ":")),
            stamp,
        ),
    )
    connection.execute(
        "INSERT INTO artifact_manifests VALUES "
        "(?, ?, 'profile', 'profile', '2', ?, 'PREPARED', 0, ?, NULL)",
        (manifest_id, operation_id, digest, stamp),
    )
    connection.execute(
        "INSERT INTO artifact_members VALUES "
        "(?, 0, 'profile_json', ?, ?, '2', 'application/json', ?, '[]')",
        (manifest_id, member_id, content.content_sha256, content.size_bytes),
    )
    manifest = ManifestRepository(connection).get(manifest_id)
    closure_sha256 = publication_closure_sha256(
        purpose="profile_update",
        authority_base_version=2,
        expected_current_epoch=1,
        artifacts=(manifest,),
    )
    connection.execute(
        "INSERT INTO publication_closure_attestations VALUES (?, ?, ?, ?)",
        (operation_id, approval_draft_sha256, closure_sha256, stamp),
    )
    connection.execute(
        "UPDATE client_fact_authority SET commit_version = 2 WHERE singleton = 1"
    )
    return operation_id


def _snapshot(
    *allowed: VersionRef,
    tombstone_epoch: int = 0,
) -> AuthoritativeFilterSnapshot:
    return AuthoritativeFilterSnapshot(
        run_id=_IDS.uuid7(),
        global_runtime_epoch=1,
        client_runtime_epoch=1,
        tombstone_epoch=tombstone_epoch,
        authorization_epoch=0,
        allowed_ref_ids=frozenset(item.object_id for item in allowed),
        policy_ref=_ref("authority_policy", b"policy"),
        created_at=NOW,
    )


def test_verify_active_accepts_only_the_exact_hash_verified_epoch(
    tmp_path: Path,
) -> None:
    stored = _stored_scope(
        tmp_path,
        scope="global",
        artifact_key="wiki",
        member_bodies=(("wiki_payload", b"governed wiki"),),
    )
    verifier = IntegrityVerifier((stored.binding,))

    verifier.verify_active(
        scope="global",
        epoch=1,
        artifacts=(ActiveArtifact("wiki", stored.manifest_ref),),
        source_version=1,
        tombstone_epoch=0,
        authorization_epoch=0,
    )


def test_verify_active_rejects_an_unbound_extra_active_artifact(
    tmp_path: Path,
) -> None:
    stored = _stored_scope(
        tmp_path,
        scope="global",
        artifact_key="wiki",
        member_bodies=(("wiki_payload", b"governed wiki"),),
    )
    stored.binding.connection.execute(
        "INSERT INTO active_artifacts VALUES (1, 'unbound_extra', ?, ?)",
        (
            stored.manifest_ref.object_id,
            NOW.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        ),
    )

    with pytest.raises(ArtifactUnavailable, match="^ARTIFACT_UNAVAILABLE$"):
        IntegrityVerifier((stored.binding,)).verify_active(
            scope="global",
            epoch=1,
            artifacts=(ActiveArtifact("wiki", stored.manifest_ref),),
            source_version=1,
            tombstone_epoch=0,
            authorization_epoch=0,
        )


def test_active_integrity_gate_rechecks_content_on_every_query_entry(
    tmp_path: Path,
) -> None:
    stored = _stored_scope(
        tmp_path,
        scope="global",
        artifact_key="wiki",
        member_bodies=(("wiki_payload", b"governed wiki"),),
    )
    probe_calls = 0

    def probe() -> None:
        nonlocal probe_calls
        probe_calls += 1

    gate = ActiveIntegrityGate(stored.binding)
    gate.verify(
        epoch=1,
        artifacts=(ActiveArtifact("wiki", stored.manifest_ref),),
        source_version=1,
        tombstone_epoch=0,
        authorization_epoch=0,
        content_probes=(probe,),
    )
    assert probe_calls == 2

    stored.paths["wiki_payload"].write_bytes(b"tampered")
    with pytest.raises(ArtifactUnavailable, match="^ARTIFACT_UNAVAILABLE$"):
        gate.verify(
            epoch=1,
            artifacts=(ActiveArtifact("wiki", stored.manifest_ref),),
            source_version=1,
            tombstone_epoch=0,
            authorization_epoch=0,
            content_probes=(probe,),
        )


def test_active_integrity_gate_invalidates_on_tombstone_epoch_change(
    tmp_path: Path,
) -> None:
    stored = _stored_scope(
        tmp_path,
        scope="global",
        artifact_key="graph",
        member_bodies=(("graph_payload", b"governed graph"),),
    )
    gate = ActiveIntegrityGate(stored.binding)
    artifacts = (ActiveArtifact("graph", stored.manifest_ref),)
    gate.verify(
        epoch=1,
        artifacts=artifacts,
        source_version=1,
        tombstone_epoch=0,
        authorization_epoch=0,
    )
    stored.binding.connection.execute(
        "UPDATE knowledge_catalog_state SET tombstone_epoch = 1 WHERE singleton = 1"
    )

    with pytest.raises(ArtifactUnavailable, match="^ARTIFACT_UNAVAILABLE$"):
        gate.verify(
            epoch=1,
            artifacts=artifacts,
            source_version=1,
            tombstone_epoch=0,
            authorization_epoch=0,
        )


def test_global_gate_separates_publication_version_from_authority_catalog(
    tmp_path: Path,
) -> None:
    stored = _stored_scope(
        tmp_path,
        scope="global",
        artifact_key="knowledge",
        member_bodies=(("knowledge_payload", b"governed knowledge"),),
    )
    stored.binding.connection.execute(
        "UPDATE knowledge_catalog_state SET catalog_version = 19 WHERE singleton = 1"
    )
    gate = ActiveIntegrityGate(stored.binding)
    artifacts = (ActiveArtifact("knowledge", stored.manifest_ref),)

    gate.verify(
        epoch=1,
        artifacts=artifacts,
        source_version=1,
        authority_version=19,
        tombstone_epoch=0,
        authorization_epoch=0,
    )
    with pytest.raises(ArtifactUnavailable, match="^ARTIFACT_UNAVAILABLE$"):
        gate.verify(
            epoch=1,
            artifacts=artifacts,
            source_version=1,
            authority_version=18,
            tombstone_epoch=0,
            authorization_epoch=0,
        )


def test_client_pending_publication_accepts_independent_audit_sequence(
    tmp_path: Path,
) -> None:
    stored = _stored_scope(
        tmp_path,
        scope="client_private",
        artifact_key="profile",
        member_bodies=(("profile_json", b"active profile"),),
    )
    _add_pending_client_publication(
        stored,
        applied_commit_version=91,
    )

    IntegrityVerifier((stored.binding,)).verify_active(
        scope="client_private",
        epoch=1,
        artifacts=(ActiveArtifact("profile", stored.manifest_ref),),
        source_version=1,
    )


@pytest.mark.parametrize(
    "corruption",
    ("descriptor_base", "descriptor", "scope", "closure"),
)
def test_client_pending_publication_rejects_approval_or_closure_drift(
    tmp_path: Path,
    corruption: str,
) -> None:
    stored = _stored_scope(
        tmp_path,
        scope="client_private",
        artifact_key="profile",
        member_bodies=(("profile_json", b"active profile"),),
    )
    operation_id = _add_pending_client_publication(
        stored,
        applied_commit_version=91,
    )
    if corruption == "descriptor_base":
        stored.binding.connection.execute(
            "UPDATE approval_executions SET descriptor_base_version = 7 "
            "WHERE operation_id = ?",
            (operation_id,),
        )
    elif corruption == "descriptor":
        stored.binding.connection.execute(
            "UPDATE approval_executions SET descriptor_sha256 = ? "
            "WHERE operation_id = ?",
            ("0" * 64, operation_id),
        )
    elif corruption == "scope":
        stored.binding.connection.execute(
            "UPDATE approval_executions SET target_scope_hash = ? "
            "WHERE operation_id = ?",
            ("0" * 64, operation_id),
        )
    else:
        stored.binding.connection.execute(
            "UPDATE publication_closure_attestations SET closure_sha256 = ? "
            "WHERE operation_id = ?",
            ("0" * 64, operation_id),
        )

    with pytest.raises(ArtifactUnavailable, match="^ARTIFACT_UNAVAILABLE$"):
        IntegrityVerifier((stored.binding,)).verify_active(
            scope="client_private",
            epoch=1,
            artifacts=(ActiveArtifact("profile", stored.manifest_ref),),
            source_version=1,
        )


@pytest.mark.parametrize(
    "corruption",
    (
        "manifest_hash",
        "payload",
        "member_source_version",
        "tombstone",
        "epoch",
        "authorization_epoch",
    ),
)
def test_verify_active_collapses_every_integrity_failure_to_one_safe_error(
    tmp_path: Path,
    corruption: str,
) -> None:
    stored = _stored_scope(
        tmp_path,
        scope="global",
        artifact_key="vector",
        member_bodies=(("vector_payload", b"governed vector"),),
    )
    manifest_ref = stored.manifest_ref
    epoch = 1
    authorization_epoch = 0
    if corruption == "manifest_hash":
        manifest_ref = manifest_ref.model_copy(update={"content_sha256": "f" * 64})
    elif corruption == "payload":
        stored.paths["vector_payload"].write_bytes(b"tampered")
    elif corruption == "member_source_version":
        stored.binding.connection.execute(
            "UPDATE artifact_members SET source_version = '2'"
        )
    elif corruption == "tombstone":
        member = stored.members["vector_payload"]
        stored.binding.connection.execute(
            "INSERT INTO tombstones VALUES (?, ?, ?, '', 'deleted', ?)",
            (
                _id("tombstone"),
                "vector_payload",
                target_hash("vector_payload", member.object_id),
                NOW.isoformat().replace("+00:00", "Z"),
            ),
        )
    elif corruption == "epoch":
        epoch = 2
    else:
        authorization_epoch = 3

    with pytest.raises(ArtifactUnavailable, match="^ARTIFACT_UNAVAILABLE$"):
        IntegrityVerifier((stored.binding,)).verify_active(
            scope="global",
            epoch=epoch,
            artifacts=(ActiveArtifact("vector", manifest_ref),),
            source_version=1,
            tombstone_epoch=0,
            authorization_epoch=authorization_epoch,
        )


def _closure_fixture(
    tmp_path: Path,
) -> tuple[
    IntegrityVerifier,
    IntegrityContext,
    tuple[ClosureNode, ...],
    tuple[ClosureNode, ...],
    tuple[ClosureEdge, ...],
]:
    loo_members = (
        ("case", b"variant"),
        ("case_leave_one_out_variant", b"mapping"),
        ("case_pattern", b"parent"),
        ("case_authority_manifest", b"authority"),
        ("case_provenance", b"provenance"),
        ("claim", b"global candidate"),
    )
    global_scope = _stored_scope(
        tmp_path,
        scope="global",
        artifact_key="knowledge",
        member_bodies=loo_members,
        tombstone_epoch=2,
    )
    client_scope = _stored_scope(
        tmp_path,
        scope="client_private",
        artifact_key="client_snapshot",
        member_bodies=(("client_snapshot", b"client snapshot"),),
    )
    variant = global_scope.members["case"]
    claim = global_scope.members["claim"]
    context = IntegrityContext(
        authority_snapshot=_snapshot(
            variant,
            claim,
            tombstone_epoch=2 << 32,
        ),
        current_client_id=CLIENT,
        session_id=_IDS.uuid7(),
        selection_cutoff_version=1,
    )
    roots = (
        ClosureNode(
            role="wiki_manifest",
            reference=global_scope.manifest_ref,
            scope="global",
        ),
        ClosureNode(
            role="client_manifest",
            reference=client_scope.manifest_ref,
            scope="client_private",
            owner_client_id=CLIENT,
        ),
    )
    nodes = (
        ClosureNode(
            role="candidate_object",
            reference=claim,
            scope="global",
            authority_ref=claim,
        ),
        ClosureNode(
            role="client_snapshot",
            reference=client_scope.members["client_snapshot"],
            scope="client_private",
            owner_client_id=CLIENT,
            selection_version=1,
        ),
        ClosureNode(
            role="leave_one_out_variant",
            reference=variant,
            scope="global",
            authority_ref=variant,
            closure_group="loo-1",
        ),
        ClosureNode(
            role="leave_one_out_mapping",
            reference=global_scope.members["case_leave_one_out_variant"],
            scope="global",
            authority_ref=variant,
            closure_group="loo-1",
        ),
        ClosureNode(
            role="leave_one_out_parent",
            reference=global_scope.members["case_pattern"],
            scope="global",
            authority_ref=variant,
            closure_group="loo-1",
        ),
        ClosureNode(
            role="leave_one_out_authority_manifest",
            reference=global_scope.members["case_authority_manifest"],
            scope="global",
            authority_ref=variant,
            closure_group="loo-1",
        ),
        ClosureNode(
            role="leave_one_out_provenance",
            reference=global_scope.members["case_provenance"],
            scope="global",
            authority_ref=variant,
            closure_group="loo-1",
        ),
    )
    edges = tuple(
        ClosureEdge(parent=roots[0].key, child=node.key)
        for node in nodes
        if node.scope == "global"
    ) + (ClosureEdge(parent=roots[1].key, child=nodes[1].key),)
    return (
        IntegrityVerifier((global_scope.binding, client_scope.binding)),
        context,
        roots,
        nodes,
        edges,
    )


def test_verify_closure_accepts_one_exact_authorized_scope_bound_dag(
    tmp_path: Path,
) -> None:
    verifier, context, roots, nodes, edges = _closure_fixture(tmp_path)

    verifier.verify_closure(
        context=context,
        roots=roots,
        nodes=nodes,
        edges=edges,
    )


@pytest.mark.parametrize(
    "corruption",
    (
        "alternate_store",
        "unauthorized",
        "cross_scope",
        "orphan",
        "incomplete_loo",
        "client_tombstone_epoch",
    ),
)
def test_verify_closure_has_no_cross_scope_or_latest_fallback(
    tmp_path: Path,
    corruption: str,
) -> None:
    verifier, context, roots, nodes, edges = _closure_fixture(tmp_path)
    changed_nodes = nodes
    changed_edges = edges
    if corruption == "alternate_store":
        changed_nodes = (
            nodes[0].__class__(
                role=nodes[0].role,
                reference=nodes[0].reference,
                scope="client_private",
                authority_ref=nodes[0].authority_ref,
                owner_client_id=CLIENT,
            ),
            *nodes[1:],
        )
        changed_edges = (
            ClosureEdge(parent=roots[1].key, child=changed_nodes[0].key),
            *edges[1:],
        )
    elif corruption == "unauthorized":
        changed_nodes = (
            nodes[0].__class__(
                role=nodes[0].role,
                reference=nodes[0].reference,
                scope=nodes[0].scope,
                authority_ref=_ref("claim", b"not authorized"),
            ),
            *nodes[1:],
        )
    elif corruption == "cross_scope":
        changed_edges = (
            *edges,
            ClosureEdge(parent=roots[0].key, child=nodes[1].key),
        )
    elif corruption == "orphan":
        changed_edges = tuple(edge for edge in edges if edge.child != nodes[1].key)
    elif corruption == "client_tombstone_epoch":
        context = IntegrityContext(
            authority_snapshot=context.authority_snapshot.model_copy(
                update={"tombstone_epoch": (2 << 32) | 1}
            ),
            current_client_id=context.current_client_id,
            session_id=context.session_id,
            selection_cutoff_version=context.selection_cutoff_version,
        )
    else:
        removed = nodes[3]
        changed_nodes = tuple(node for node in nodes if node != removed)
        changed_edges = tuple(edge for edge in edges if edge.child != removed.key)

    with pytest.raises(ArtifactUnavailable, match="^ARTIFACT_UNAVAILABLE$"):
        verifier.verify_closure(
            context=context,
            roots=roots,
            nodes=changed_nodes,
            edges=changed_edges,
        )
