from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from importlib import import_module
from pathlib import Path
from typing import cast

import pytest

from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.models import ApprovalExecutionTicket
from consultation_kb.archive.case_catalog import ActiveCaseRecord, CaseCatalog
from consultation_kb.archive.case_publisher import CasePublishTransfer
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.lifecycle.backup_queue import (
    BackupDestructionQueue,
    BackupDestructionRecord,
    BackupDestructionWorker,
)
from consultation_kb.lifecycle.cleanup_authority import CleanupAuthorityResolver
from consultation_kb.lifecycle.deletion import DeletionService
from consultation_kb.lifecycle.deletion_plan import DeletionPlanBuilder
from consultation_kb.lifecycle.physical_cleanup import AuthorizedPhysicalCleanupWorker
from consultation_kb.lifecycle.rebuild import (
    RebuildCoordinator,
    RebuildRequest,
    SqliteCasRebuildArtifactStore,
    SqliteRebuildAuthoritySource,
)
from consultation_kb.lifecycle.rebuild_jobs import RebuildJobRepository
from consultation_kb.lifecycle.rebuild_registry import BuilderRegistry
from consultation_kb.lifecycle.sqlite_cleanup import (
    SYNTHETIC_VAULT_MARKER,
    SYNTHETIC_VAULT_MARKER_BYTES,
    SyntheticCleanupScope,
)
from consultation_kb.lifecycle.whole_client_cleanup import (
    WholeClientCleanupCoordinator,
)
from consultation_kb.models.deletion import (
    DeletionObjectRef,
    DeletionPlan,
    DeletionPreviewRequest,
    DeletionTarget,
)
from consultation_kb.retrieval.filters import CandidateFilter
from consultation_kb.storage.cleanup_inventory import SqlitePhysicalCleanupInventory
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.deletion_inventory import SqliteDeletionInventoryAdapter
from consultation_kb.storage.integrity import ArtifactUnavailable
from consultation_kb.storage.manifests import ManifestMember, manifest_sha256
from consultation_kb.storage.tombstones import target_hash
from consultation_kb.vault.content_store import ContentHashMismatch, ContentStore
from tests.consultation_kb.approval_support import MutableClock
from tests.consultation_kb.golden.test_rebuild_01 import _verify_active
from tests.consultation_kb.integration.test_rebuild_all import (
    MODEL_HASH,
    NOW,
    POLICY_HASH,
    _Builder,
    _start_approved,
)
from tests.consultation_kb.integration.test_live_authority_prefilter import (
    _authority,
    _global_claim_candidate,
    _seed_global_authority,
)
from tests.consultation_kb.integration.test_case_publish_saga import (
    _MutableCasePublishAuthority,
    _package,
    _publisher,
)
from tests.consultation_kb.integration.test_whole_client_cleanup import (
    _MappedHasher,
    _Quiescer,
    _activate_two_clients,
    _commit_real_client_deletion,
    _finish_siblings_and_backup,
)
from tests.consultation_kb.retrieval_support import object_id, reference, scope
pytestmark = pytest.mark.acceptance_id("DEL-01")

DERIVATIVE_PAYLOAD = b"DEL_01_DERIVATIVE_PHYSICAL_CLEANUP_CANARY"
BACKUP_PROOF = "e" * 64

_cascade = import_module(
    "tests.consultation_kb.integration.test_tombstone_cascade"
)
_published_case = cast(
    Callable[
        [Path],
        tuple[
            sqlite3.Connection,
            Path,
            ActiveCaseRecord,
            CasePublishTransfer,
            datetime,
        ],
    ],
    getattr(_cascade, "_published_case"),
)
_plan = cast(
    Callable[
        [sqlite3.Connection, ActiveCaseRecord, datetime],
        tuple[
            DeletionPreviewRequest,
            SqliteDeletionInventoryAdapter,
            DeletionPlan,
        ],
    ],
    getattr(_cascade, "_plan"),
)
_approval = cast(
    Callable[
        [sqlite3.Connection, DeletionPlan, datetime],
        tuple[ApprovalExecutionGuard, ApprovalExecutionTicket],
    ],
    getattr(_cascade, "_approval"),
)


@dataclass(frozen=True, slots=True)
class _BackupProofAdapter:
    def destroy(self, record: BackupDestructionRecord) -> str:
        assert record.location_class == "offline_media"
        return BACKUP_PROOF


class _LifecycleBuilder(_Builder):
    """One root per production descriptor, versioned by deletion authority."""

    def build(self, context):  # type: ignore[no-untyped-def]
        artifact = super().build(context)
        return replace(artifact, version=context.tombstone_epoch + 1)


def _connect(database: Path) -> sqlite3.Connection:
    return sqlite3.connect(database, isolation_level=None, timeout=5.0)


def _intent_ids(
    connection: sqlite3.Connection,
    request_id: str,
    action_type: str,
) -> tuple[str, ...]:
    return tuple(
        str(row[0])
        for row in connection.execute(
            "SELECT intent_id FROM deletion_queue_intents "
            "WHERE request_id = ? AND action_type = ? ORDER BY intent_id",
            (request_id, action_type),
        ).fetchall()
    )


def _intent_id_for_value(
    connection: sqlite3.Connection,
    intent_ids: tuple[str, ...],
    *,
    column: str,
    value: str,
) -> str:
    if column not in {"object_type", "target_content_sha256"}:
        raise ValueError("DEL_01_INTENT_COLUMN_INVALID")
    matches = tuple(
        intent_id
        for intent_id in intent_ids
        if connection.execute(
            f"SELECT {column} FROM deletion_queue_intents WHERE intent_id = ?",
            (intent_id,),
        ).fetchone()
        == (value,)
    )
    assert len(matches) == 1
    return matches[0]


def _physical_object_closure(
    connection: sqlite3.Connection,
    physical_intents: tuple[str, ...],
) -> tuple[str, ...]:
    resolved: set[str] = set()
    for intent_id in physical_intents:
        authority = CleanupAuthorityResolver(
            connection,
            authority_scope="global",
        ).resolve(intent_id, expected_action_type="physical_delete")
        inventory = SqlitePhysicalCleanupInventory(
            connection,
            authority_scope="global",
        ).resolve(authority)
        resolved.update(inventory.content_sha256s)
    return tuple(sorted(resolved))


def _run_rebuild(
    connection: sqlite3.Connection,
    *,
    content_store: ContentStore,
    scope_sha256: str,
    source_intent_id: str | None,
    idempotency_key: str,
    at: datetime = NOW,
) -> None:
    registry = BuilderRegistry.production()
    jobs = RebuildJobRepository(
        connection,
        database_scope="global",
        clock=FixedClock(at),
        id_factory=IdFactory(clock=FixedClock(at)),
    )
    authority = SqliteRebuildAuthoritySource(
        connection,
        database_scope="global",
        scope_sha256=scope_sha256,
        content_store=content_store,
    )
    artifact_store = SqliteCasRebuildArtifactStore(
        connection,
        database_scope="global",
        scope_sha256=scope_sha256,
        content_store=content_store,
        clock=FixedClock(at),
        id_factory=IdFactory(clock=FixedClock(at)),
    )
    descriptors = registry.plan(database_scope="global", purpose="all")
    coordinator = RebuildCoordinator(
        registry=registry,
        jobs=jobs,
        authority=authority,
        artifact_store=artifact_store,
        builders={
            descriptor.builder_id: _LifecycleBuilder(descriptor)
            for descriptor in descriptors
        },
    )
    plan = coordinator.plan(
        RebuildRequest(
            database_scope="global",
            source_intent_id=source_intent_id,
            scope_sha256=scope_sha256,
            purpose="all",
            policy_sha256=POLICY_HASH,
            model_descriptor_sha256=MODEL_HASH,
        )
    )
    queued = _start_approved(
        connection,
        coordinator,
        plan,
        idempotency_key=idempotency_key,
    )
    assert queued.source_intent_id == source_intent_id
    completed = coordinator.run_next()
    assert completed is not None
    assert completed.job_id == queued.job_id
    assert completed.state == "succeeded", completed.last_error_code


def _run_rebuild_intents(
    connection: sqlite3.Connection,
    *,
    content_store: ContentStore,
    scope_sha256: str,
    intent_ids: tuple[str, ...],
    at: datetime = NOW,
) -> None:
    for ordinal, intent_id in enumerate(intent_ids, start=1):
        _run_rebuild(
            connection,
            content_store=content_store,
            scope_sha256=scope_sha256,
            source_intent_id=intent_id,
            idempotency_key=f"del-01-rebuild-{ordinal:02d}",
            at=at,
        )


def _assert_no_payload_residue(root: Path, payloads: tuple[bytes, ...]) -> None:
    for candidate in root.rglob("*"):
        if not candidate.is_file():
            continue
        content = candidate.read_bytes()
        for payload in payloads:
            assert payload not in content, candidate


def test_del_01_tombstone_restart_rebuild_backup_and_physical_cleanup(
    tmp_path: Path,
) -> None:
    database = tmp_path / "global.sqlite3"
    connection, store_root, record, transfer, published_at = _published_case(
        tmp_path
    )
    content_store = ContentStore(store_root)
    case_payload = content_store.read_hash_verified(
        record.case_ref.content_sha256
    )
    derivative = content_store.finalize(
        content_store.stage_bytes(
            DERIVATIVE_PAYLOAD,
            purpose="cleanup",
            manifest_id=record.case_ref.object_id,
            media_type="application/octet-stream",
        )
    )
    connection.execute(
        "UPDATE artifact_versions SET metadata_sha256 = ? "
        "WHERE artifact_id = 'case_graph_fixture' AND version = 1",
        (derivative.content_sha256,),
    )
    cache_copy = tmp_path / "cache" / "deleted-derivative.bin"
    cache_copy.parent.mkdir()
    cache_copy.write_bytes(DERIVATIVE_PAYLOAD)
    now = published_at + timedelta(minutes=4)
    _, _, initial_plan = _plan(connection, record, now)
    _run_rebuild(
        connection,
        content_store=content_store,
        scope_sha256=initial_plan.target_scope_hash,
        source_intent_id=None,
        idempotency_key="del-01-baseline-complete-epoch",
        at=now,
    )
    active_roots = connection.execute(
        "SELECT aa.artifact_key, am.operation_id FROM active_artifacts aa "
        "JOIN runtime_epochs re ON re.epoch = aa.epoch AND re.state = 'ACTIVE' "
        "JOIN artifact_manifests am ON am.manifest_id = aa.manifest_id "
        "ORDER BY aa.artifact_key"
    ).fetchall()
    assert len(active_roots) >= 5
    assert len({str(row[1]) for row in active_roots}) == 1
    _verify_active(connection, content_store)

    # Re-preview after the active closure exists so the immutable deletion
    # plan captures the live manifest dependencies and base epoch exactly.
    request, adapter, plan = _plan(connection, record, now)
    assert plan.target_scope_hash == initial_plan.target_scope_hash
    guard, ticket = _approval(connection, plan, now)
    result = DeletionService(
        connection,
        approval_guard=guard,
        clock=MutableClock(now),
        inventory_adapter=adapter,
    ).commit_tombstone(plan, ticket)
    assert result.tombstone_epoch == 1
    assert CaseCatalog(connection, content_store).active_cases(
        purpose="answer_support"
    ) == ()
    connection.close()

    # A process restart must not resurrect a case before any asynchronous work.
    connection = connect_database(database, mode="writer")
    try:
        assert CaseCatalog(connection, content_store).active_cases(
            purpose="answer_support"
        ) == ()
        assert connection.execute(
            "SELECT state FROM cases WHERE case_id = ?",
            (record.case_ref.object_id,),
        ).fetchone() == ("REVOKED",)
        assert connection.execute(
            "SELECT state FROM case_versions "
            "WHERE case_id = ? AND version = ?",
            (record.case_ref.object_id, record.case_ref.version),
        ).fetchone() == ("REVOKED",)
        assert connection.execute(
            "SELECT artifact_id, state FROM artifact_versions "
            "WHERE artifact_id LIKE 'case_%_fixture' ORDER BY artifact_id"
        ).fetchall() == [
            ("case_graph_fixture", "STALE"),
            ("case_vector_fixture", "STALE"),
        ]
        with pytest.raises(ArtifactUnavailable):
            _verify_active(connection, content_store)

        physical_intents = _intent_ids(
            connection, request.request_id, "physical_delete"
        )
        rebuild_intents = _intent_ids(connection, request.request_id, "rebuild")
        backup_intents = _intent_ids(
            connection, request.request_id, "backup_expiry"
        )
        assert physical_intents and rebuild_intents and backup_intents
        object_closure = _physical_object_closure(connection, physical_intents)
        case_intent = _intent_id_for_value(
            connection,
            physical_intents,
            column="object_type",
            value="case",
        )
        derivative_intent = _intent_id_for_value(
            connection,
            physical_intents,
            column="target_content_sha256",
            value=derivative.content_sha256,
        )
    finally:
        connection.close()

    (tmp_path / SYNTHETIC_VAULT_MARKER).write_bytes(
        SYNTHETIC_VAULT_MARKER_BYTES
    )
    scope = SyntheticCleanupScope.open(
        tmp_path,
        allowed_parent=tmp_path.parent,
    )
    worker = AuthorizedPhysicalCleanupWorker(
        lambda: _connect(database),
        authority_scope="global",
        scope=scope,
        database_path=database,
        cas_root=store_root,
        clock=lambda: NOW,
    )

    # The old active epoch is rollback authority until an approved rebuild
    # replaces it, so early physical reclamation must fail closed.
    blocked_by_active = worker.process(case_intent)
    assert blocked_by_active.state == "retry_pending"
    assert blocked_by_active.active_reference_count > 0
    assert content_store.read_hash_verified(record.case_ref.content_sha256) == (
        case_payload
    )

    connection = connect_database(database, mode="writer")
    try:
        queue = BackupDestructionQueue(connection)
        for ordinal, intent_id in enumerate(backup_intents, start=1):
            queue.enqueue_authorized(
                intent_id=intent_id,
                backup_id=f"del-01-backup-{ordinal:02d}",
                object_sha256s=object_closure,
                location_class="offline_media",
                due_at=now,
                created_at=now,
                authority_scope="global",
            )
    finally:
        connection.close()

    blocked_by_backup = worker.process(derivative_intent)
    assert blocked_by_backup.state == "retry_pending"
    assert blocked_by_backup.pending_backup_count > 0
    assert cache_copy.is_file()

    connection = connect_database(database, mode="writer")
    try:
        backup_worker = BackupDestructionWorker(
            connection,
            authority_scope="global",
            adapter=_BackupProofAdapter(),
            clock=lambda: NOW,
        )
        for ordinal, intent_id in enumerate(backup_intents, start=1):
            backup_completed = backup_worker.process(
                backup_id=f"del-01-backup-{ordinal:02d}",
                intent_id=intent_id,
            )
            assert backup_completed.state == "succeeded"
            assert backup_completed.operator_proof_sha256 == BACKUP_PROOF

        _run_rebuild_intents(
            connection,
            content_store=content_store,
            scope_sha256=plan.target_scope_hash,
            intent_ids=rebuild_intents,
        )
        _verify_active(connection, content_store)
        assert connection.execute(
            "SELECT DISTINCT state FROM deletion_queue_intents "
            "WHERE request_id = ? AND action_type = 'rebuild'",
            (request.request_id,),
        ).fetchall() == [("SUCCEEDED",)]
    finally:
        connection.close()

    deleted_files = 0
    for intent_id in physical_intents:
        cleanup_completed = worker.process(intent_id)
        assert cleanup_completed.state == "succeeded"
        assert cleanup_completed.active_reference_count == 0
        assert cleanup_completed.pending_backup_count == 0
        deleted_files += cleanup_completed.deleted_file_count
    assert deleted_files >= 3
    assert not cache_copy.exists()

    connection = connect_database(database, mode="writer")
    try:
        assert CaseCatalog(connection, content_store).active_cases(
            purpose="answer_support"
        ) == ()
        assert connection.execute(
            "SELECT state, queue_state FROM deletion_requests "
            "WHERE request_id = ?",
            (request.request_id,),
        ).fetchone() == ("PHYSICAL_CLEANUP_COMPLETE", "SUCCEEDED")
        assert connection.execute(
            "SELECT DISTINCT state FROM deletion_queue_intents "
            "WHERE request_id = ?",
            (request.request_id,),
        ).fetchall() == [("SUCCEEDED",)]
        assert connection.execute(
            "SELECT count(*) FROM tombstones WHERE source_lineage_hash = ("
            "SELECT source_lineage_hash FROM deletion_intent_authority_proofs "
            "WHERE request_id = ? LIMIT 1)",
            (request.request_id,),
        ).fetchone()[0] > 0
    finally:
        connection.close()

    with pytest.raises(ContentHashMismatch):
        content_store.read_hash_verified(record.case_ref.content_sha256)
    with pytest.raises(ContentHashMismatch):
        content_store.read_hash_verified(derivative.content_sha256)
    _assert_no_payload_residue(
        tmp_path,
        (case_payload, DERIVATIVE_PAYLOAD, transfer.candidate.sections[0].text.encode()),
    )


def test_del_01_whole_client_cleanup_restarts_without_resurrection(
    tmp_path: Path,
) -> None:
    (
        fixture,
        client_a,
        client_b,
        _protector,
        clients_root,
        _identity_map,
    ) = _activate_two_clients(tmp_path)
    creation, _catalog, connection, *_rest = fixture
    event, transfer, published_at = _package()
    global_root = tmp_path / "vault" / "global"
    publication = _publisher(
        connection,
        global_root,
        published_at,
        _MutableCasePublishAuthority(transfer),
    ).process(event, transfer)
    requested_at = published_at + timedelta(minutes=4)
    requested_text = requested_at.isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )
    connection.execute(
        "INSERT INTO capabilities("
        "capability_id, token_sha256, session_id, client_id, permissions_json, "
        "issued_at, expires_at, revoked_at, state, capability_epoch"
        ") VALUES ('del_01_client_capability', ?, 'del_01_client_session', ?, "
        "'[\"read\"]', ?, ?, NULL, 'ACTIVE', 1)",
        (
            "9" * 64,
            client_a.client_id,
            requested_text,
            (requested_at + timedelta(hours=1))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
        ),
    )
    contributor_hash = transfer.authorization.contributor_client_hash
    request_id, root_intent_id = _commit_real_client_deletion(
        connection,
        client_id=client_a.client_id,
        contributor_hash=contributor_hash,
        requested_at=requested_at,
    )
    client_a_root = clients_root / client_a.client_id
    client_b_root = clients_root / client_b.client_id
    (client_a_root / "cache").mkdir()
    (client_a_root / "cache" / "private.bin").write_bytes(
        b"DEL_01_CLIENT_A_PRIVATE_CANARY"
    )
    (client_b_root / "cache").mkdir()
    sibling_canary = client_b_root / "cache" / "sibling.bin"
    sibling_canary.write_bytes(b"DEL_01_CLIENT_B_MUST_SURVIVE")
    staging = clients_root / ".staging" / client_a.client_id
    staging.mkdir(parents=True)
    (staging / ".scope-id").write_text(
        f"{client_a.directory_object_id}\n",
        encoding="ascii",
        newline="\n",
    )
    (staging / "unfinished.tmp").write_bytes(b"DEL_01_CLIENT_A_STAGING")
    _finish_siblings_and_backup(
        connection,
        request_id=request_id,
        root_intent_id=root_intent_id,
        at=requested_at,
    )

    database = global_root / "catalog.sqlite3"
    hasher = _MappedHasher(client_a.client_id, contributor_hash, [])
    quiescer = _Quiescer()
    coordinator = WholeClientCleanupCoordinator(
        lambda: _connect(database),
        global_database_path=database,
        clients_root=clients_root,
        contributor_hasher=hasher,
        quiescer=quiescer,
        identity_registry=creation,
        clock=lambda: requested_at,
    )
    try:
        completed = coordinator.process(root_intent_id)

        assert completed.state == "succeeded"
        assert completed.identity_entry_removed
        assert completed.cryptographic_erasure_claimed is False
        assert quiescer.close_calls == 1
        assert quiescer.verify_calls >= 2
        assert not client_a_root.exists()
        assert not staging.exists()
        assert not creation.has_exact_identity_entry(
            client_id=client_a.client_id,
            alias_lookup_sha256=client_a.alias_lookup_sha256,
            directory_object_id=client_a.directory_object_id,
        )
        assert creation.has_exact_identity_entry(
            client_id=client_b.client_id,
            alias_lookup_sha256=client_b.alias_lookup_sha256,
            directory_object_id=client_b.directory_object_id,
        )
        assert sibling_canary.read_bytes() == b"DEL_01_CLIENT_B_MUST_SURVIVE"
        assert connection.execute(
            "SELECT state FROM clients WHERE client_id = ?",
            (client_a.client_id,),
        ).fetchone() == ("RETIRED",)
        assert connection.execute(
            "SELECT state FROM clients WHERE client_id = ?",
            (client_b.client_id,),
        ).fetchone() == ("ACTIVE",)
        assert connection.execute(
            "SELECT state, capability_epoch FROM capabilities "
            "WHERE capability_id = 'del_01_client_capability'"
        ).fetchone() == ("REVOKED", 2)
        assert connection.execute(
            "SELECT state FROM cases WHERE case_id = ?",
            (publication.case_ref.object_id,),
        ).fetchone() == ("REVOKED",)
        assert connection.execute(
            "SELECT count(*) FROM case_authorizations "
            "WHERE case_id = ? AND contributor_client_hash = ?",
            (publication.case_ref.object_id, contributor_hash),
        ).fetchone() == (1,)
        assert CaseCatalog(
            connection,
            ContentStore(global_root),
        ).active_cases(purpose="answer_support") == ()
        lineage = connection.execute(
            "SELECT root_lineage_hash FROM deletion_intent_authority_proofs "
            "WHERE intent_id = ?",
            (root_intent_id,),
        ).fetchone()
        assert lineage is not None
        tombstone_types = {
            str(row[0])
            for row in connection.execute(
                "SELECT target_type FROM tombstones "
                "WHERE source_lineage_hash = ?",
                (str(lineage[0]),),
            ).fetchall()
        }
        assert {
            "client",
            "client_capability",
            "case",
            "case_authorization",
            "case_provenance",
        } <= tombstone_types
        assert connection.execute(
            "SELECT state, queue_state FROM deletion_requests "
            "WHERE request_id = ?",
            (request_id,),
        ).fetchone() == ("PHYSICAL_CLEANUP_COMPLETE", "SUCCEEDED")

        # A newly constructed worker re-attests durable authority and rescans
        # both client scopes and the encrypted map instead of trusting the ACK.
        restarted = WholeClientCleanupCoordinator(
            lambda: _connect(database),
            global_database_path=database,
            clients_root=clients_root,
            contributor_hasher=_MappedHasher(
                client_a.client_id,
                contributor_hash,
                [],
            ),
            quiescer=_Quiescer(),
            identity_registry=creation,
            clock=lambda: requested_at,
        )
        replay = restarted.process(root_intent_id)
        assert replay.state == "succeeded"
        assert replay.removed_file_count == 0
        assert replay.removed_directory_count == 0
        assert not replay.identity_entry_removed
        assert not client_a_root.exists()
        assert not staging.exists()
        assert sibling_canary.read_bytes() == b"DEL_01_CLIENT_B_MUST_SURVIVE"
    finally:
        connection.close()


def test_del_01_claim_passage_authority_is_invisible_before_rebuild_cleanup(
    tmp_path: Path,
) -> None:
    claim_text = "DEL_01_CLAIM_PASSAGE_AUTHORITY_CANARY"
    claim = _global_claim_candidate(
        951,
        text=claim_text,
        channel="lexical",
        manifest_ref=reference("artifact_manifest", 9_951),
    )
    passage_bytes = claim_text.encode("utf-8")
    claim_object_bytes = b"X" + passage_bytes[1:]
    claim = claim.model_copy(
        update={
            "reference": claim.reference.model_copy(
                update={
                    "content_sha256": hashlib.sha256(
                        claim_object_bytes
                    ).hexdigest()
                }
            )
        }
    )
    member = ManifestMember(
        ordinal=0,
        object_type=claim.object_type,
        object_id=claim.reference.object_id,
        object_sha256=claim.reference.content_sha256,
        source_version=claim.metadata.manifest_ref.version,
        media_type=claim.metadata.media_type,
        size_bytes=claim.metadata.size_bytes,
        source_lineage_hashes=claim.metadata.source_lineage_hashes,
    )
    exact_manifest_sha256 = manifest_sha256(
        manifest_id=claim.metadata.manifest_ref.object_id,
        operation_id=object_id("publication_operation", 8_100),
        artifact_key="claims",
        artifact_kind="claims",
        source_version=claim.metadata.manifest_ref.version,
        members=(member,),
    )
    claim = claim.model_copy(
        update={
            "metadata": claim.metadata.model_copy(
                update={
                    "manifest_ref": claim.metadata.manifest_ref.model_copy(
                        update={"content_sha256": exact_manifest_sha256}
                    )
                }
            )
        }
    )
    global_database, client_database = _seed_global_authority(tmp_path, (claim,))
    content_store_root = tmp_path / "global_cas"
    content_store = ContentStore(content_store_root)
    stored_claim = content_store.finalize(
        content_store.stage_bytes(
            claim_object_bytes,
            purpose="cleanup",
            manifest_id=claim.reference.object_id,
            media_type="text/plain",
        )
    )
    assert stored_claim.content_sha256 == claim.reference.content_sha256
    stored_passage = content_store.finalize(
        content_store.stage_bytes(
            passage_bytes,
            purpose="cleanup",
            manifest_id=claim.content_ref.object_id,
            media_type="text/plain",
        )
    )
    assert stored_passage.content_sha256 == claim.content_ref.content_sha256
    for source_id in claim.provenance.source_ids:
        source_bytes = f"source:{source_id}".encode("utf-8")
        source_object = content_store.finalize(
            content_store.stage_bytes(
                source_bytes,
                purpose="cleanup",
                manifest_id=source_id,
                media_type="text/plain",
            )
        )
        assert source_object.content_sha256 == hashlib.sha256(source_bytes).hexdigest()

    with _authority(
        global_database,
        client_database,
        random_bits=9_952,
    ) as repository:
        before = repository.freeze(scope())
        assert tuple(
            value.reference
            for value in CandidateFilter(repository)
            .filter(scope(), (claim,), before)
            .allowed
        ) == (claim.reference,)

    requested_at = NOW + timedelta(minutes=4)
    connection = connect_database(global_database, mode="writer")
    try:
        target = DeletionTarget(
            target_type="claim",
            object_ref=DeletionObjectRef(
                object_type="claim",
                object_id=claim.reference.object_id,
                version=claim.reference.version,
                content_sha256=claim.reference.content_sha256,
                authority_scope="global",
            ),
        )
        request = DeletionPreviewRequest(
            request_id=(
                "deletion_request_019f743d-4400-7000-8000-00000000c102"
            ),
            target=target,
            reason_code="knowledge_source_revoked",
            requested_at=requested_at,
        )
        adapter = SqliteDeletionInventoryAdapter(
            connection,
            authority_scope="global",
        )
        plan = DeletionPlanBuilder().preview(request, adapter.snapshot(request))
        guard, ticket = _approval(connection, plan, requested_at)
        result = DeletionService(
            connection,
            approval_guard=guard,
            clock=MutableClock(requested_at),
            inventory_adapter=adapter,
        ).commit_tombstone(plan, ticket)
        assert result.tombstone_epoch == 1
        assert connection.execute(
            "SELECT review_status FROM claims WHERE claim_id = ? AND version = ?",
            (claim.reference.object_id, claim.reference.version),
        ).fetchone() == ("REVOKED",)
        assert connection.execute(
            "SELECT review_status FROM passages WHERE passage_id = ? AND version = ?",
            (claim.content_ref.object_id, claim.content_ref.version),
        ).fetchone() == ("APPROVED",)
        assert connection.execute(
            "SELECT count(*) FROM tombstones WHERE target_type = 'claim' "
            "AND target_id_hash = ?",
            (target_hash("claim", claim.reference.object_id),),
        ).fetchone() == (1,)
    finally:
        connection.close()

    # Restarted retrieval must consult tombstone/claim/passage authority before
    # any lexical, vector or graph body read, even while the old epoch exists.
    with _authority(
        global_database,
        client_database,
        random_bits=9_953,
    ) as repository:
        after = repository.freeze(scope())
        decision = CandidateFilter(repository).filter(scope(), (claim,), after)
        assert decision.allowed == ()
        assert decision.proof.reasons == {"tombstoned": 1}
        assert claim.reference.object_id not in after.allowed_ref_ids

    connection = connect_database(global_database, mode="writer")
    try:
        physical_intents = _intent_ids(
            connection,
            request.request_id,
            "physical_delete",
        )
        rebuild_intents = _intent_ids(
            connection,
            request.request_id,
            "rebuild",
        )
        backup_intents = _intent_ids(
            connection,
            request.request_id,
            "backup_expiry",
        )
        assert physical_intents and rebuild_intents and backup_intents
        object_closure = _physical_object_closure(connection, physical_intents)
        queue = BackupDestructionQueue(connection)
        for ordinal, intent_id in enumerate(backup_intents, start=1):
            queue.enqueue_authorized(
                intent_id=intent_id,
                backup_id=f"del-01-claim-backup-{ordinal:02d}",
                object_sha256s=object_closure,
                location_class="offline_media",
                due_at=requested_at,
                created_at=requested_at,
                authority_scope="global",
            )
        backup_worker = BackupDestructionWorker(
            connection,
            authority_scope="global",
            adapter=_BackupProofAdapter(),
            clock=lambda: requested_at,
        )
        for ordinal, intent_id in enumerate(backup_intents, start=1):
            assert backup_worker.process(
                backup_id=f"del-01-claim-backup-{ordinal:02d}",
                intent_id=intent_id,
            ).state == "succeeded"
        _run_rebuild_intents(
            connection,
            content_store=content_store,
            scope_sha256=plan.target_scope_hash,
            intent_ids=rebuild_intents,
            at=requested_at,
        )
        _verify_active(connection, content_store)
    finally:
        connection.close()

    (tmp_path / SYNTHETIC_VAULT_MARKER).write_bytes(
        SYNTHETIC_VAULT_MARKER_BYTES
    )
    cleanup_scope = SyntheticCleanupScope.open(
        tmp_path,
        allowed_parent=tmp_path.parent,
    )
    worker = AuthorizedPhysicalCleanupWorker(
        lambda: _connect(global_database),
        authority_scope="global",
        scope=cleanup_scope,
        database_path=global_database,
        cas_root=content_store_root,
        clock=lambda: requested_at,
    )
    for intent_id in physical_intents:
        assert worker.process(intent_id).state == "succeeded"

    # A second worker instance performs a durable ACK replay and must neither
    # resurrect authority nor require the deleted body to exist.
    restarted_worker = AuthorizedPhysicalCleanupWorker(
        lambda: _connect(global_database),
        authority_scope="global",
        scope=cleanup_scope,
        database_path=global_database,
        cas_root=content_store_root,
        clock=lambda: requested_at,
    )
    for intent_id in physical_intents:
        assert restarted_worker.process(intent_id).state == "succeeded"
    with pytest.raises(ContentHashMismatch):
        content_store.read_hash_verified(claim.reference.content_sha256)
    assert content_store.read_hash_verified(claim.content_ref.content_sha256) == (
        passage_bytes
    )

    connection = connect_database(global_database, mode="writer")
    try:
        assert connection.execute(
            "SELECT state, queue_state FROM deletion_requests "
            "WHERE request_id = ?",
            (request.request_id,),
        ).fetchone() == ("PHYSICAL_CLEANUP_COMPLETE", "SUCCEEDED")
        assert connection.execute(
            "SELECT DISTINCT state FROM deletion_queue_intents "
            "WHERE request_id = ?",
            (request.request_id,),
        ).fetchall() == [("SUCCEEDED",)]
    finally:
        connection.close()
