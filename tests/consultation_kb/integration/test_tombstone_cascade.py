from __future__ import annotations

import itertools
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from consultation_kb.approvals.attestation import (
    LocalHmacTargetExecutionAttestor,
    LocalHmacTargetExecutionProofVerifier,
)
from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.provider import (
    LocalHmacApprovalSigner,
    LocalHmacApprovalVerifier,
)
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.archive.case_catalog import CaseCatalog
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.lifecycle.deletion import DeletionPlanStale, DeletionService
from consultation_kb.lifecycle.deletion_plan import DeletionPlanBuilder
from consultation_kb.models.cases import (
    CaseProvenanceRecord,
    case_provenance_payload,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.deletion import (
    DeletionObjectRef,
    DeletionPreviewRequest,
    DeletionTarget,
)
from consultation_kb.storage.deletion_inventory import (
    SqliteDeletionInventoryAdapter,
    client_authority_sha256,
    session_authority_sha256,
)
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.storage.manifests import ManifestMember, ManifestRepository
from consultation_kb.storage.tombstones import target_hash
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.approval_support import MutableClock, TestProtector
from tests.consultation_kb.integration.test_case_publish_saga import (
    _MutableCasePublishAuthority,
    _global_database,
    _package,
    _publisher,
)


pytestmark = pytest.mark.integration

KNOWLEDGE_NOW = datetime(2026, 7, 19, 9, 0, tzinfo=timezone.utc)
_APPROVAL_RANDOM_VALUES = itertools.count(4000)
_APPROVAL_NONCE_VALUES = itertools.count(1)


def _published_case(tmp_path: Path):
    connection = _global_database(tmp_path / "global.sqlite3")
    store_root = tmp_path / "global_cas"
    event, transfer, published_at = _package()
    authority = _MutableCasePublishAuthority(transfer)
    publication = _publisher(
        connection, store_root, published_at, authority
    ).process(event, transfer)
    catalog = CaseCatalog(connection, ContentStore(store_root))
    record = catalog.active_cases(purpose="answer_support")[0]

    # Two explicit P1 dependency edges prove that the preview is a graph
    # closure rather than a substring or directory scan.
    first_hash = "a" * 64
    second_hash = "b" * 64
    connection.execute(
        """
        INSERT INTO artifact_versions(
            artifact_id, version, artifact_kind, source_catalog_version,
            metadata_sha256, manifest_id, state, created_at
        ) VALUES ('case_graph_fixture', 1, 'graph', 0, ?, NULL, 'CURRENT', ?),
                 ('case_vector_fixture', 1, 'vector', 0, ?, NULL, 'CURRENT', ?)
        """,
        (
            first_hash,
            published_at.isoformat(),
            second_hash,
            published_at.isoformat(),
        ),
    )
    connection.execute(
        """
        INSERT INTO artifact_dependencies(
            upstream_type, upstream_id, upstream_version,
            downstream_artifact_id, downstream_artifact_version,
            dependency_kind
        ) VALUES ('case', ?, ?, 'case_graph_fixture', 1, 'case_to_graph'),
                 ('artifact', 'case_graph_fixture', 1,
                  'case_vector_fixture', 1, 'graph_to_vector')
        """,
        (record.case_ref.object_id, record.case_ref.version),
    )
    assert publication.case_ref == record.case_ref
    return connection, store_root, record, transfer, published_at


def _plan(connection, record, requested_at, *, request_suffix: str = "1"):
    target = DeletionTarget(
        target_type="case",
        object_ref=DeletionObjectRef(
            object_type="case",
            object_id=record.case_ref.object_id,
            version=record.case_ref.version,
            content_sha256=record.case_ref.content_sha256,
            authority_scope="global",
        ),
    )
    request = DeletionPreviewRequest(
        request_id=(
            "deletion_request_019f743d-4400-7000-8000-00000000000"
            + request_suffix
        ),
        target=target,
        reason_code="authorization_revoked",
        requested_at=requested_at,
    )
    adapter = SqliteDeletionInventoryAdapter(
        connection, authority_scope="global"
    )
    inventory = adapter.snapshot(request)
    return request, adapter, DeletionPlanBuilder().preview(request, inventory)


def _approval(connection, plan, now):
    clock = MutableClock(now)
    ids = IdFactory(clock, lambda: next(_APPROVAL_RANDOM_VALUES))
    signer = LocalHmacApprovalSigner(
        secret=b"p" * 32,
        provider_id="local-review-agent",
        clock=clock,
    )
    service = ApprovalService(
        connection,
        provider=LocalHmacApprovalVerifier(
            secret=b"p" * 32,
            provider_id="local-review-agent",
        ),
        protector=TestProtector(),
        clock=clock,
        id_factory=ids,
        target_scope_hash=plan.target_scope_hash,
        vault_id="synthetic-global-vault",
        execution_secret=b"e" * 32,
        execution_proof_verifier=LocalHmacTargetExecutionProofVerifier(
            secret=b"t" * 32,
            attestor_id="test-global-writer",
        ),
        nonce_source=lambda size: next(_APPROVAL_NONCE_VALUES).to_bytes(
            size, "big"
        ),
    )
    guard = ApprovalExecutionGuard(
        connection,
        approval_service=service,
        execution_proof_signer=LocalHmacTargetExecutionAttestor(
            secret=b"t" * 32,
            attestor_id="test-global-writer",
        ),
        clock=clock,
    )
    requested = service.request(
        plan.descriptor,
        diff_object_ref=VersionRef(
            object_id=ids.object_id("deletion_diff"),
            version=1,
            content_sha256="d" * 64,
        ),
    )
    service.confirm(signer.confirm(service.challenge_for_review(requested.request_id)))
    ticket = service.issue_for_execution(
        requested.request_id,
        plan.descriptor,
        operation_id=ids.object_id("deletion_operation"),
    )
    return guard, ticket

def test_case_and_authorization_revocation_cascades_before_rebuild(
    tmp_path: Path,
) -> None:
    connection, store_root, record, transfer, published_at = _published_case(tmp_path)
    now = published_at + timedelta(minutes=4)
    request, adapter, plan = _plan(connection, record, now)
    guard, ticket = _approval(connection, plan, now)
    service = DeletionService(
        connection,
        approval_guard=guard,
        clock=MutableClock(now),
        inventory_adapter=adapter,
    )
    try:
        object_types = {node.object_ref.object_type for node in plan.closure_nodes}
        assert {
            "case",
            "case_authorization",
            "case_provenance",
            "artifact_manifest",
            "artifact_version",
        } <= object_types
        assert {action.action_type for action in plan.actions} == {
            "tombstone_now",
            "physical_delete",
            "rebuild",
            "backup_expiry",
            "manual_product_action",
        }
        rendered = plan.model_dump_json()
        assert transfer.candidate.sections[0].text not in rendered

        result = service.commit_tombstone(plan, ticket)
        replay = service.commit_tombstone(plan, ticket)

        assert replay == result
        assert result.authorization_epoch == 1
        assert result.tombstone_epoch == 1
        assert CaseCatalog(
            connection, ContentStore(store_root)
        ).active_cases(purpose="answer_support") == ()
        assert connection.execute(
            "SELECT state FROM cases WHERE case_id = ?",
            (record.case_ref.object_id,),
        ).fetchone() == ("REVOKED",)
        assert connection.execute(
            "SELECT state FROM case_versions WHERE case_id = ? AND version = ?",
            (record.case_ref.object_id, record.case_ref.version),
        ).fetchone() == ("REVOKED",)
        assert connection.execute(
            "SELECT artifact_id, state FROM artifact_versions "
            "WHERE artifact_id LIKE 'case_%_fixture' ORDER BY artifact_id"
        ).fetchall() == [
            ("case_graph_fixture", "STALE"),
            ("case_vector_fixture", "STALE"),
        ]
        assert connection.execute(
            "SELECT effect FROM deletion_revocations ORDER BY effect"
        ).fetchall() == [("revoke_authorization",), ("revoke_case",)]
        assert connection.execute(
            "SELECT authorization_epoch, tombstone_epoch "
            "FROM knowledge_catalog_state WHERE singleton = 1"
        ).fetchone() == (1, 1)
        assert connection.execute(
            "SELECT event_kind FROM security_invalidation_events "
            "WHERE upstream_id = ? ORDER BY event_kind",
            (record.case_ref.object_id,),
        ).fetchall() == [("AUTHORIZATION",), ("TOMBSTONE",)]
        assert connection.execute(
            "SELECT count(*) FROM deletion_requests"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT count(*) FROM approval_executions "
            "WHERE request_id = ?",
            (ticket.request_id,),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT count(*) FROM tombstones "
            "WHERE target_type = 'case_authorization' AND target_id_hash = ?",
            (target_hash("case_authorization", record.authorization_ref.object_id),),
        ).fetchone() == (1,)
        # The immutable grant remains an audit record; the formal append-only
        # revocation and epoch/tombstone gates are now the live authority.
        assert connection.execute(
            "SELECT authorization_sha256, revoked_at FROM case_authorizations"
        ).fetchone() == (record.authorization_ref.content_sha256, None)
    finally:
        connection.close()


def test_exact_case_authorization_target_commits_as_first_class_deletion(
    tmp_path: Path,
) -> None:
    connection, _store_root, record, _transfer, published_at = _published_case(
        tmp_path
    )
    now = published_at + timedelta(minutes=4)
    target = DeletionTarget(
        target_type="case_authorization",
        object_ref=DeletionObjectRef(
            object_type="case_authorization",
            object_id=record.authorization_ref.object_id,
            version=record.authorization_ref.version,
            content_sha256=record.authorization_ref.content_sha256,
            authority_scope="global",
        ),
    )
    request = DeletionPreviewRequest(
        request_id="deletion_request_019f743d-4400-7000-8000-000000000009",
        target=target,
        reason_code="authorization_revoked",
        requested_at=now,
    )
    adapter = SqliteDeletionInventoryAdapter(
        connection,
        authority_scope="global",
    )
    plan = DeletionPlanBuilder().preview(request, adapter.snapshot(request))
    guard, ticket = _approval(connection, plan, now)
    service = DeletionService(
        connection,
        approval_guard=guard,
        clock=MutableClock(now),
        inventory_adapter=adapter,
    )
    try:
        result = service.commit_tombstone(plan, ticket)

        assert result.tombstone_epoch == 1
        assert connection.execute(
            "SELECT target_type FROM deletion_requests WHERE request_id = ?",
            (request.request_id,),
        ).fetchone() == ("case_authorization",)
        assert connection.execute(
            "SELECT state FROM cases WHERE case_id = ?",
            (record.case_ref.object_id,),
        ).fetchone() == ("REVOKED",)
        assert connection.execute(
            "SELECT COUNT(*) FROM tombstones "
            "WHERE target_type = 'case_authorization' AND target_id_hash = ?",
            (
                target_hash(
                    "case_authorization",
                    record.authorization_ref.object_id,
                ),
            ),
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_tombstone_identity_collision_rolls_back_the_entire_deletion(
    tmp_path: Path,
) -> None:
    connection, _store_root, record, _transfer, published_at = _published_case(
        tmp_path
    )
    now = published_at + timedelta(minutes=4)
    _request, adapter, plan = _plan(connection, record, now)
    guard, ticket = _approval(connection, plan, now)
    connection.execute(
        "INSERT INTO tombstones("
        "tombstone_id, target_type, target_id_hash, source_lineage_hash, "
        "reason_code, created_at) VALUES (?, 'collision_fixture', ?, '', ?, ?)",
        (
            f"tombstone_0001_{plan.request_id[-36:]}",
            "f" * 64,
            "collision_fixture",
            now.isoformat(),
        ),
    )
    service = DeletionService(
        connection,
        approval_guard=guard,
        clock=MutableClock(now),
        inventory_adapter=adapter,
    )
    try:
        with pytest.raises(
            DeletionPlanStale,
            match="DELETION_TOMBSTONE_INSERT_STALE",
        ):
            service.commit_tombstone(plan, ticket)

        assert connection.execute(
            "SELECT COUNT(*) FROM deletion_requests WHERE request_id = ?",
            (plan.request_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT state FROM cases WHERE case_id = ?",
            (record.case_ref.object_id,),
        ).fetchone() == ("ACTIVE",)
        assert connection.execute(
            "SELECT state FROM approval_executions WHERE operation_id = ?",
            (ticket.operation_id,),
        ).fetchone() is None
    finally:
        connection.close()


def test_case_delete_includes_verified_authority_ledgers_and_cas_members(
    tmp_path: Path,
) -> None:
    connection, _store_root, record, _transfer, published_at = _published_case(
        tmp_path
    )
    ids = IdFactory(
        MutableClock(published_at + timedelta(minutes=1)),
        lambda: next(_APPROVAL_RANDOM_VALUES),
    )
    root_manifest_id = str(
        connection.execute(
            "SELECT manifest_id FROM case_versions WHERE case_id = ? AND version = ?",
            (record.case_ref.object_id, record.case_ref.version),
        ).fetchone()[0]
    )
    root_operation_id = str(
        connection.execute(
            "SELECT operation_id FROM artifact_manifests WHERE manifest_id = ?",
            (root_manifest_id,),
        ).fetchone()[0]
    )
    assert connection.execute(
        "SELECT state, verified FROM artifact_manifests WHERE manifest_id = ?",
        (root_manifest_id,),
    ).fetchone() == ("VERIFIED", 1)
    assert connection.execute(
        "SELECT state, runtime_epoch FROM publication_operations "
        "WHERE operation_id = ?",
        (root_operation_id,),
    ).fetchone() == ("VERIFIED", None)
    assert connection.execute(
        "SELECT count(*) FROM runtime_epochs WHERE state = 'ACTIVE'"
    ).fetchone() == (0,)

    root_row = connection.execute(
        "SELECT closure_json FROM case_provenance WHERE artifact_object_id = ? "
        "AND artifact_version = ?",
        (record.case_ref.object_id, record.case_ref.version),
    ).fetchone()
    assert root_row is not None
    root_provenance = CaseProvenanceRecord.model_validate_json(str(root_row[0]))
    pattern_ref = VersionRef(
        object_id=ids.object_id("case_pattern"),
        version=1,
        content_sha256="c" * 64,
    )
    provenance_id = ids.object_id("case_provenance")
    provenance_material = case_provenance_payload(
        provenance_id=provenance_id,
        version=1,
        artifact_ref=pattern_ref,
        artifact_kind="case_pattern",
        parent_provenance_refs=(root_provenance.provenance_ref,),
        ancestor_artifact_refs=(root_provenance.artifact_ref,),
        case_contributions=root_provenance.case_contributions,
        independent_evidence=root_provenance.independent_evidence,
        contributor_client_hashes=root_provenance.contributor_client_hashes,
        derivation_rule_ref=root_provenance.derivation_rule_ref,
        policy_manifest_ref=root_provenance.policy_manifest_ref,
        source_grade=root_provenance.source_grade,
        provenance_scope="case_derived",
        allowed_uses=root_provenance.allowed_uses,
        effective_to=root_provenance.effective_to,
    )
    provenance_sha256 = canonical_sha256(provenance_material)
    pattern_provenance = CaseProvenanceRecord(
        provenance_ref=VersionRef(
            object_id=provenance_id,
            version=1,
            content_sha256=provenance_sha256,
        ),
        artifact_ref=pattern_ref,
        artifact_kind="case_pattern",
        parent_provenance_refs=(root_provenance.provenance_ref,),
        ancestor_artifact_refs=(root_provenance.artifact_ref,),
        case_contributions=root_provenance.case_contributions,
        independent_evidence=root_provenance.independent_evidence,
        contributor_client_hashes=root_provenance.contributor_client_hashes,
        derivation_rule_ref=root_provenance.derivation_rule_ref,
        policy_manifest_ref=root_provenance.policy_manifest_ref,
        source_grade=root_provenance.source_grade,
        provenance_scope="case_derived",
        allowed_uses=root_provenance.allowed_uses,
        effective_to=root_provenance.effective_to,
        closure_sha256=provenance_sha256,
    )
    connection.execute(
        """
        INSERT INTO case_provenance(
            provenance_id, provenance_version, provenance_sha256,
            artifact_object_id, artifact_version, artifact_sha256,
            artifact_kind, contributor_client_hashes_json,
            independent_source_count, derivation_rule_id,
            derivation_rule_version, derivation_rule_sha256,
            policy_manifest_id, policy_manifest_version,
            policy_manifest_sha256, source_grade, provenance_scope,
            allowed_uses_json, effective_to, closure_json, closure_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            pattern_provenance.provenance_ref.object_id,
            pattern_provenance.provenance_ref.version,
            pattern_provenance.closure_sha256,
            pattern_ref.object_id,
            pattern_ref.version,
            pattern_ref.content_sha256,
            pattern_provenance.artifact_kind,
            json.dumps(
                sorted(pattern_provenance.contributor_client_hashes),
                separators=(",", ":"),
            ),
            len(pattern_provenance.independent_evidence),
            pattern_provenance.derivation_rule_ref.object_id,
            pattern_provenance.derivation_rule_ref.version,
            pattern_provenance.derivation_rule_ref.content_sha256,
            pattern_provenance.policy_manifest_ref.object_id,
            pattern_provenance.policy_manifest_ref.version,
            pattern_provenance.policy_manifest_ref.content_sha256,
            pattern_provenance.source_grade,
            pattern_provenance.provenance_scope,
            json.dumps(
                sorted(pattern_provenance.allowed_uses), separators=(",", ":")
            ),
            None,
            pattern_provenance.model_dump_json(),
            pattern_provenance.closure_sha256,
        ),
    )

    operation_id = ids.object_id("case_index_operation")
    manifest_id = ids.object_id("case_index_manifest")
    replay_id = ids.object_id("case_index_descriptor")
    created_at = published_at.isoformat().replace("+00:00", "Z")
    connection.execute(
        """
        INSERT INTO publication_operations(
            operation_id, purpose, authority_base_version,
            approval_request_id, descriptor_sha256, state,
            required_manifests_json, required_manifest_count,
            verified_manifest_count, expected_current_epoch,
            runtime_epoch, created_at, activated_at
        ) VALUES (?, 'case_publish', 2, ?, ?, 'PREPARED', ?, 1, 0,
                  NULL, NULL, ?, NULL)
        """,
        (
            operation_id,
            ids.object_id("approval_request"),
            "e" * 64,
            json.dumps([manifest_id], separators=(",", ":")),
            created_at,
        ),
    )
    manifests = ManifestRepository(connection)
    manifests.insert_prepared(
        manifest_id=manifest_id,
        operation_id=operation_id,
        artifact_key="case_index_fixture",
        artifact_kind="case_index",
        source_version=2,
        members=(
            ManifestMember(
                ordinal=0,
                object_type="case_pattern",
                object_id=pattern_ref.object_id,
                object_sha256=pattern_ref.content_sha256,
                source_version=2,
                media_type="text/plain",
                size_bytes=64,
                source_lineage_hashes=(record.case_ref.content_sha256,),
            ),
            ManifestMember(
                ordinal=1,
                object_type="case_index_descriptor",
                object_id=replay_id,
                object_sha256="d" * 64,
                source_version=2,
                media_type="application/json",
                size_bytes=64,
                source_lineage_hashes=(record.case_ref.content_sha256,),
            ),
        ),
        created_at=created_at,
    )
    manifests.mark_verified(
        manifest_id,
        expected_source_version=2,
        verified_at=created_at,
    )
    connection.execute(
        "UPDATE publication_operations SET state = 'VERIFIED', "
        "verified_manifest_count = 1 WHERE operation_id = ?",
        (operation_id,),
    )
    connection.execute(
        """
        INSERT INTO case_patterns(
            pattern_id, version, global_content_ref, global_content_sha256,
            global_content_size_bytes, manifest_id, provenance_id,
            provenance_version, allowed_uses_json, state, created_at
        ) VALUES (?, ?, 'sha256:' || ?, ?, 64, ?, ?, ?, ?, 'ACTIVE', ?)
        """,
        (
            pattern_ref.object_id,
            pattern_ref.version,
            pattern_ref.content_sha256,
            pattern_ref.content_sha256,
            manifest_id,
            pattern_provenance.provenance_ref.object_id,
            pattern_provenance.provenance_ref.version,
            json.dumps(
                sorted(pattern_provenance.allowed_uses), separators=(",", ":")
            ),
            created_at,
        ),
    )

    try:
        _request, _adapter, plan = _plan(
            connection,
            record,
            published_at + timedelta(minutes=4),
            request_suffix="7",
        )
        nodes = {
            (node.object_ref.object_type, node.object_ref.object_id): node
            for node in plan.closure_nodes
        }
        assert nodes[("artifact_manifest", root_manifest_id)].role == (
            "verified_manifest"
        )
        assert nodes[("artifact_manifest", manifest_id)].role == (
            "verified_manifest"
        )
        assert nodes[("case_index_descriptor", replay_id)].role == (
            "manifest_member"
        )
        assert plan.active_manifest_refs == ()
        assert "global_runtime" not in {
            item.authority_key for item in plan.base_versions
        }
    finally:
        connection.close()


def test_authority_epoch_change_rejects_stale_plan_without_partial_revocation(
    tmp_path: Path,
) -> None:
    connection, _store_root, record, _transfer, published_at = _published_case(tmp_path)
    now = published_at + timedelta(minutes=4)
    _request, adapter, plan = _plan(
        connection, record, now, request_suffix="2"
    )
    guard, ticket = _approval(connection, plan, now)
    connection.execute(
        "UPDATE knowledge_catalog_state SET authorization_epoch = 1 "
        "WHERE singleton = 1"
    )
    try:
        with pytest.raises(
            DeletionPlanStale, match="DELETION_CATALOG_EPOCH_STALE"
        ):
            DeletionService(
                connection,
                approval_guard=guard,
                clock=MutableClock(now),
                inventory_adapter=adapter,
            ).commit_tombstone(plan, ticket)
        assert connection.execute(
            "SELECT state FROM cases WHERE case_id = ?",
            (record.case_ref.object_id,),
        ).fetchone() == ("ACTIVE",)
        assert connection.execute(
            "SELECT count(*) FROM deletion_requests"
        ).fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM tombstones").fetchone() == (
            0,
        )
        assert connection.execute(
            "SELECT count(*) FROM approval_executions WHERE request_id = ?",
            (ticket.request_id,),
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_client_revocation_includes_every_owned_case_and_live_capability(
    tmp_path: Path,
) -> None:
    connection, store_root, record, transfer, published_at = _published_case(tmp_path)
    now = published_at + timedelta(minutes=4)
    now_text = now.isoformat(timespec="microseconds").replace("+00:00", "Z")
    client_id = "client" + "_aaaaaaaaaaaa"
    directory_id = "client_directory_fixture"
    alias_hash = "c" * 64
    connection.execute(
        """
        INSERT INTO clients(
            client_id, directory_object_id, alias_lookup_sha256,
            state, created_at, activated_at
        ) VALUES (?, ?, ?, 'ACTIVE', ?, ?)
        """,
        (client_id, directory_id, alias_hash, now_text, now_text),
    )
    connection.execute(
        """
        INSERT INTO capabilities(
            capability_id, token_sha256, session_id, client_id,
            permissions_json, issued_at, expires_at, revoked_at,
            state, capability_epoch
        ) VALUES ('capability_fixture', ?, 'session_fixture', ?, '["read"]',
                  ?, ?, NULL, 'ACTIVE', 1)
        """,
        (
            "e" * 64,
            client_id,
            now_text,
            (now + timedelta(hours=1))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
        ),
    )
    target = DeletionTarget(
        target_type="client",
        object_ref=DeletionObjectRef(
            object_type="client",
            object_id=client_id,
            version=1,
            content_sha256=client_authority_sha256(
                client_id=client_id,
                directory_object_id=directory_id,
                alias_lookup_sha256=alias_hash,
                created_at=now_text,
            ),
            authority_scope="global",
        ),
        client_id=client_id,
    )
    request = DeletionPreviewRequest(
        request_id="deletion_request_019f743d-4400-7000-8000-000000000003",
        target=target,
        reason_code="client_erasure_requested",
        requested_at=now,
    )
    contributor_hash = transfer.authorization.contributor_client_hash
    adapter = SqliteDeletionInventoryAdapter(
        connection,
        authority_scope="global",
        contributor_client_hash=contributor_hash,
    )
    plan = DeletionPlanBuilder().preview(request, adapter.snapshot(request))
    guard, ticket = _approval(connection, plan, now)
    try:
        assert record.case_ref.object_id in {
            action.target_ref.object_id
            for action in plan.actions
            if action.authority_effect == "revoke_case"
        }
        assert "capability_fixture" in {
            node.object_ref.object_id
            for node in plan.closure_nodes
            if node.object_ref.object_type == "client_capability"
        }

        result = DeletionService(
            connection,
            approval_guard=guard,
            clock=MutableClock(now),
            inventory_adapter=adapter,
        ).commit_tombstone(plan, ticket)

        assert result.authorization_epoch == result.tombstone_epoch == 1
        assert connection.execute(
            "SELECT state FROM clients WHERE client_id = ?", (client_id,)
        ).fetchone() == ("RETIRED",)
        assert connection.execute(
            "SELECT state, capability_epoch, revoked_at FROM capabilities "
            "WHERE capability_id = 'capability_fixture'"
        ).fetchone() == ("REVOKED", 2, now_text)
        assert connection.execute(
            "SELECT state FROM cases WHERE case_id = ?",
            (record.case_ref.object_id,),
        ).fetchone() == ("REVOKED",)
        assert CaseCatalog(
            connection, ContentStore(store_root)
        ).active_cases(purpose="answer_support") == ()
        assert connection.execute(
            "SELECT count(*) FROM tombstones "
            "WHERE target_type = 'case' AND target_id_hash = ?",
            (target_hash("case", record.case_ref.object_id),),
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_passage_revocation_uses_real_provenance_artifact_closure(
    tmp_path: Path,
) -> None:
    connection = _global_database(tmp_path / "global.sqlite3")
    passage_hash = "6" * 64
    artifact_hash = "7" * 64
    now_text = KNOWLEDGE_NOW.isoformat()
    connection.execute(
        """
        INSERT INTO sources(
            source_id, logical_path, logical_path_key, document_type,
            current_version, created_at
        ) VALUES ('source_fixture', 'fixture.md', 'fixture.md', 'counseling', 1, ?)
        """,
        (now_text,),
    )
    connection.execute(
        """
        INSERT INTO source_versions(
            source_id, version, content_sha256, content_object_ref, size_bytes,
            license, domain, language, sensitivity, source_grade, status,
            imported_at, metadata_json, metadata_sha256
        ) VALUES ('source_fixture', 1, ?, 'sha256:source', 1, 'private',
                  'counseling', 'zh', 'low', 'K1', 'APPROVED', ?, '{}', ?)
        """,
        ("5" * 64, now_text, "4" * 64),
    )
    connection.execute(
        """
        INSERT INTO passages(
            passage_id, version, source_id, source_version, document_type,
            structural_path, locator_json, normalized_text_sha256,
            raw_content_ref, retrieval_content_ref, context_before_ref,
            context_after_ref, extractor_version, privacy_scope,
            provenance_json, review_status, created_at
        ) VALUES ('passage_fixture', 1, 'source_fixture', 1, 'counseling',
                  'section.1', '{}', ?, 'sha256:raw', 'sha256:retrieval',
                  NULL, NULL, '1', 'GLOBAL', '{}', 'APPROVED', ?)
        """,
        (passage_hash, now_text),
    )
    connection.execute(
        """
        INSERT INTO artifact_versions(
            artifact_id, version, artifact_kind, source_catalog_version,
            metadata_sha256, manifest_id, state, created_at
        ) VALUES ('passage_graph_fixture', 1, 'graph', 0, ?, NULL,
                  'CURRENT', ?)
        """,
        (artifact_hash, now_text),
    )
    connection.execute(
        """
        INSERT INTO artifact_dependencies(
            upstream_type, upstream_id, upstream_version,
            downstream_artifact_id, downstream_artifact_version,
            dependency_kind
        ) VALUES ('passage', 'passage_fixture', 1,
                  'passage_graph_fixture', 1, 'passage_to_graph')
        """
    )
    target = DeletionTarget(
        target_type="passage",
        object_ref=DeletionObjectRef(
            object_type="passage",
            object_id="passage_fixture",
            version=1,
            content_sha256=passage_hash,
            authority_scope="global",
        ),
    )
    request = DeletionPreviewRequest(
        request_id="deletion_request_019f743d-4400-7000-8000-000000000004",
        target=target,
        reason_code="knowledge_source_revoked",
        requested_at=KNOWLEDGE_NOW,
    )
    adapter = SqliteDeletionInventoryAdapter(
        connection, authority_scope="global"
    )
    plan = DeletionPlanBuilder().preview(request, adapter.snapshot(request))
    guard, ticket = _approval(connection, plan, KNOWLEDGE_NOW)
    try:
        assert "passage_graph_fixture" in {
            node.object_ref.object_id for node in plan.closure_nodes
        }
        result = DeletionService(
            connection,
            approval_guard=guard,
            clock=MutableClock(KNOWLEDGE_NOW),
            inventory_adapter=adapter,
        ).commit_tombstone(plan, ticket)
        assert result.authorization_epoch == 0
        assert result.tombstone_epoch == 1
        assert connection.execute(
            "SELECT review_status FROM passages WHERE passage_id = 'passage_fixture'"
        ).fetchone() == ("REVOKED",)
        assert connection.execute(
            "SELECT state FROM artifact_versions "
            "WHERE artifact_id = 'passage_graph_fixture'"
        ).fetchone() == ("STALE",)
    finally:
        connection.close()


def test_session_preview_reads_only_client_metadata_from_v1_to_v6_schema(
    tmp_path: Path,
) -> None:
    connection = connect_database(tmp_path / "client.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "client").apply()
    session_id = "019f743d-4400-7000-8000-000000000005"
    client_id = "client" + "_bbbbbbbbbbbb"
    scope_hash = "8" * 64
    started_at = KNOWLEDGE_NOW.isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )
    connection.execute(
        """
        INSERT INTO sessions(
            session_id, client_scope_hash, state, started_at, closed_at,
            client_id, client_snapshot_version,
            client_snapshot_canonical_sha256, capability_epoch,
            last_closed_turn_ordinal, archive_state, updated_at
        ) VALUES (?, ?, 'CLOSED', ?, ?, ?, 0, NULL, 1, 0,
                  'NOT_STARTED', ?)
        """,
        (session_id, scope_hash, started_at, started_at, client_id, started_at),
    )
    target = DeletionTarget(
        target_type="session",
        object_ref=DeletionObjectRef(
            object_type="session",
            object_id=session_id,
            version=0,
            content_sha256=session_authority_sha256(
                session_id=session_id,
                client_id=client_id,
                client_scope_hash=scope_hash,
                client_snapshot_version=0,
                client_snapshot_canonical_sha256=None,
                started_at=started_at,
            ),
            authority_scope="client",
        ),
        client_id=client_id,
        session_id=session_id,
    )
    request = DeletionPreviewRequest(
        request_id="deletion_request_019f743d-4400-7000-8000-000000000005",
        target=target,
        reason_code="session_erasure_requested",
        requested_at=KNOWLEDGE_NOW,
    )
    try:
        inventory = SqliteDeletionInventoryAdapter(
            connection,
            authority_scope="client",
            client_id=client_id,
        ).snapshot(request)
        plan = DeletionPlanBuilder().preview(request, inventory)
        assert {node.object_ref.object_type for node in plan.closure_nodes} == {
            "backup_set",
            "deletion_audit_proof",
            "managed_task_control",
            "session",
        }
        assert "client message" not in plan.model_dump_json().lower()
        assert plan.base_versions[0].authority_key == "session_current"
        assert plan.next_authorization_epoch == plan.base_authorization_epoch
    finally:
        connection.close()
