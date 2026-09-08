from __future__ import annotations

import itertools
import sqlite3
from dataclasses import dataclass
from datetime import timedelta
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
from consultation_kb.lifecycle.backup_queue import BackupDestructionQueue
from consultation_kb.lifecycle.cleanup_authority import CleanupAuthorityResolver
from consultation_kb.lifecycle.deletion import DeletionService
from consultation_kb.lifecycle.deletion_plan import DeletionPlanBuilder
from consultation_kb.lifecycle.whole_client_cleanup import (
    AnchoredClientVaultEraser,
    ClientQuiescenceProof,
    WholeClientCleanupCoordinator,
    WholeClientCleanupError,
    client_quiescence_proof_sha256,
)
from consultation_kb.models.deletion import (
    DeletionObjectRef,
    DeletionPreviewRequest,
    DeletionTarget,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.storage.cleanup_inventory import SqlitePhysicalCleanupInventory
from consultation_kb.storage.deletion_inventory import (
    SqliteDeletionInventoryAdapter,
    client_authority_sha256,
)
from consultation_kb.storage.tombstones import target_hash
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.approval_support import MutableClock, TestProtector
from tests.consultation_kb.integration.test_case_publish_saga import (
    _MutableCasePublishAuthority,
    _package,
    _publisher,
)
from tests.consultation_kb.integration.test_create_client import (
    _build_creation,
    _confirm,
    _identity_payload,
)


pytestmark = pytest.mark.integration


@dataclass
class _MappedHasher:
    client_id: str
    contributor_hash: str
    calls: list[str]

    def hash_client_id(self, client_id: str) -> str:
        self.calls.append(client_id)
        if client_id != self.client_id:
            raise AssertionError("coordinator hashed the wrong client")
        return self.contributor_hash


@dataclass
class _Quiescer:
    close_successfully: bool = True
    close_calls: int = 0
    verify_calls: int = 0

    def close_and_verify(self, client_id: str) -> ClientQuiescenceProof:
        self.close_calls += 1
        closed = self.close_successfully
        return ClientQuiescenceProof(
            client_id=client_id,
            worker_handles_closed=closed,
            sqlite_handles_closed=closed,
            mmap_handles_closed=closed,
            proof_sha256=client_quiescence_proof_sha256(
                client_id=client_id,
                worker_handles_closed=closed,
                sqlite_handles_closed=closed,
                mmap_handles_closed=closed,
            ),
        )

    def verify_closed(self, proof: ClientQuiescenceProof) -> bool:
        self.verify_calls += 1
        return self.close_successfully and all(
            (
                proof.worker_handles_closed,
                proof.sqlite_handles_closed,
                proof.mmap_handles_closed,
            )
        )


class _LockOnce:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, path: Path) -> None:
        self.calls += 1
        if self.calls == 1:
            raise PermissionError("synthetic client vault sharing violation")
        path.unlink()


def _activate_two_clients(tmp_path: Path):
    fixture = _build_creation(tmp_path)
    (
        creation,
        catalog,
        connection,
        approval,
        provider,
        protector,
        clients_root,
        identity_map,
        _clock,
    ) = fixture
    first = creation.preview(
        alias="Synthetic Client Alpha",
        idempotency_key="whole-client-cleanup-alpha",
    )
    _confirm(approval, provider, first.request_id)
    client_a = creation.commit(first.request_id)
    second = creation.preview(
        alias="Synthetic Client Beta",
        idempotency_key="whole-client-cleanup-beta",
    )
    _confirm(approval, provider, second.request_id)
    client_b = creation.commit(second.request_id)
    assert catalog.require_active(client_a.client_id) == client_a
    assert catalog.require_active(client_b.client_id) == client_b
    return fixture, client_a, client_b, protector, clients_root, identity_map


def _commit_real_client_deletion(
    connection: sqlite3.Connection,
    *,
    client_id: str,
    contributor_hash: str,
    requested_at,
) -> tuple[str, str]:
    row = connection.execute(
        "SELECT directory_object_id, alias_lookup_sha256, created_at "
        "FROM clients WHERE client_id = ?",
        (client_id,),
    ).fetchone()
    assert row is not None
    target = DeletionTarget(
        target_type="client",
        object_ref=DeletionObjectRef(
            object_type="client",
            object_id=client_id,
            version=1,
            content_sha256=client_authority_sha256(
                client_id=client_id,
                directory_object_id=str(row[0]),
                alias_lookup_sha256=str(row[1]),
                created_at=str(row[2]),
            ),
            authority_scope="global",
        ),
        client_id=client_id,
    )
    request = DeletionPreviewRequest(
        request_id="deletion_request_019f743d-4400-7000-8000-00000000c101",
        target=target,
        reason_code="client_erasure_requested",
        requested_at=requested_at,
    )
    adapter = SqliteDeletionInventoryAdapter(
        connection,
        authority_scope="global",
        contributor_client_hash=contributor_hash,
    )
    plan = DeletionPlanBuilder().preview(request, adapter.snapshot(request))
    guard, ticket = _deletion_approval(connection, plan, requested_at)
    DeletionService(
        connection,
        approval_guard=guard,
        clock=MutableClock(requested_at),
        inventory_adapter=adapter,
    ).commit_tombstone(plan, ticket)
    root_hash = target_hash("client", client_id)
    rows = connection.execute(
        "SELECT intent_id FROM deletion_queue_intents "
        "WHERE request_id = ? AND action_type = 'physical_delete' "
        "AND object_type = 'client' AND target_id_hash = ?",
        (request.request_id, root_hash),
    ).fetchall()
    assert len(rows) == 1
    return request.request_id, str(rows[0][0])


def _deletion_approval(connection: sqlite3.Connection, plan, now):
    clock = MutableClock(now)
    random_values = itertools.count(9000)
    nonce_values = itertools.count(1000)
    ids = IdFactory(clock, lambda: next(random_values))
    signer = LocalHmacApprovalSigner(
        secret=b"p" * 32,
        provider_id="whole-client-reviewer",
        clock=clock,
    )
    service = ApprovalService(
        connection,
        provider=LocalHmacApprovalVerifier(
            secret=b"p" * 32,
            provider_id="whole-client-reviewer",
        ),
        protector=TestProtector(),
        clock=clock,
        id_factory=ids,
        target_scope_hash=plan.target_scope_hash,
        vault_id="whole-client-global-vault",
        execution_secret=b"e" * 32,
        execution_proof_verifier=LocalHmacTargetExecutionProofVerifier(
            secret=b"t" * 32,
            attestor_id="whole-client-writer",
        ),
        nonce_source=lambda size: next(nonce_values).to_bytes(size, "big"),
    )
    guard = ApprovalExecutionGuard(
        connection,
        approval_service=service,
        execution_proof_signer=LocalHmacTargetExecutionAttestor(
            secret=b"t" * 32,
            attestor_id="whole-client-writer",
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


def _finish_siblings_and_backup(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    root_intent_id: str,
    at,
) -> None:
    resolver = CleanupAuthorityResolver(connection, authority_scope="global")
    inventory = SqlitePhysicalCleanupInventory(
        connection,
        authority_scope="global",
    )
    object_hashes: set[str] = set()
    for (intent_id,) in connection.execute(
        "SELECT intent_id FROM deletion_queue_intents "
        "WHERE request_id = ? AND action_type = 'physical_delete'",
        (request_id,),
    ).fetchall():
        authority = resolver.resolve(
            str(intent_id),
            expected_action_type="physical_delete",
        )
        object_hashes.update(inventory.resolve(authority).content_sha256s)
    queue = BackupDestructionQueue(connection)
    queue.enqueue(
        backup_id="whole-client-backup",
        request_id=request_id,
        object_sha256s=tuple(sorted(object_hashes)),
        location_class="offline_media",
        due_at=at,
        created_at=at,
    )
    queue.complete(
        "whole-client-backup",
        operator_proof_sha256="f" * 64,
        finished_at=at,
    )
    stamp = at.isoformat(timespec="microseconds").replace("+00:00", "Z")
    connection.execute(
        "UPDATE deletion_queue_intents SET state = 'CLAIMED', attempt_count = 1, "
        "claimed_at = ? WHERE request_id = ? AND intent_id != ?",
        (stamp, request_id, root_intent_id),
    )
    connection.execute(
        "UPDATE deletion_queue_intents SET state = 'SUCCEEDED', finished_at = ? "
        "WHERE request_id = ? AND intent_id != ?",
        (stamp, request_id, root_intent_id),
    )


def test_whole_client_cleanup_waits_for_global_closure_and_handles_then_retries_lock(
    tmp_path: Path,
) -> None:
    (
        fixture,
        client_a,
        client_b,
        protector,
        clients_root,
        identity_map,
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
    contributor_hash = transfer.authorization.contributor_client_hash
    requested_at = published_at + timedelta(minutes=4)
    request_id, root_intent_id = _commit_real_client_deletion(
        connection,
        client_id=client_a.client_id,
        contributor_hash=contributor_hash,
        requested_at=requested_at,
    )
    client_a_root = clients_root / client_a.client_id
    client_b_root = clients_root / client_b.client_id
    (client_a_root / "cache").mkdir()
    (client_a_root / "cache" / "private-a.bin").write_bytes(b"CLIENT_A_CANARY")
    (client_a_root / "cas" / "objects").mkdir(parents=True)
    (client_a_root / "cas" / "objects" / "old.bin").write_bytes(
        b"CLIENT_A_OLD_CAS"
    )
    (client_b_root / "cache").mkdir()
    (client_b_root / "cache" / "private-b.bin").write_bytes(b"CLIENT_B_MUST_SURVIVE")
    staging = clients_root / ".staging" / client_a.client_id
    staging.mkdir(parents=True)
    (staging / ".scope-id").write_text(
        f"{client_a.directory_object_id}\n",
        encoding="ascii",
        newline="\n",
    )
    (staging / "stale.tmp").write_bytes(b"CLIENT_A_STAGING_CANARY")
    original_identity_map = identity_map.read_bytes()
    hasher = _MappedHasher(client_a.client_id, contributor_hash, [])
    quiescer = _Quiescer(close_successfully=True)
    lock_once = _LockOnce()
    eraser = AnchoredClientVaultEraser(clients_root, file_unlink=lock_once)
    database = global_root / "catalog.sqlite3"
    coordinator = WholeClientCleanupCoordinator(
        lambda: sqlite3.connect(database, isolation_level=None, timeout=5.0),
        global_database_path=database,
        clients_root=clients_root,
        contributor_hasher=hasher,
        quiescer=quiescer,
        identity_registry=creation,
        vault_eraser=eraser,
        clock=lambda: requested_at,
    )
    try:
        pending_global = coordinator.process(root_intent_id)

        assert pending_global.state == "retry_pending"
        assert client_a_root.is_dir()
        assert creation.has_exact_identity_entry(
            client_id=client_a.client_id,
            alias_lookup_sha256=client_a.alias_lookup_sha256,
            directory_object_id=client_a.directory_object_id,
        )
        assert quiescer.close_calls == 0
        _finish_siblings_and_backup(
            connection,
            request_id=request_id,
            root_intent_id=root_intent_id,
            at=requested_at,
        )

        quiescer.close_successfully = False
        handles_open = coordinator.process(root_intent_id)

        assert handles_open.state == "retry_pending"
        assert client_a_root.is_dir()
        assert quiescer.close_calls == 1

        quiescer.close_successfully = True
        locked = coordinator.process(root_intent_id)

        assert locked.state == "retry_pending"
        assert client_a_root.is_dir()
        assert connection.execute(
            "SELECT state, last_error_code FROM deletion_queue_intents "
            "WHERE intent_id = ?",
            (root_intent_id,),
        ).fetchone() == ("FAILED", "FILE_LOCK_RETRY")

        completed = coordinator.process(root_intent_id)
        replay = coordinator.process(root_intent_id)

        assert completed.state == replay.state == "succeeded"
        assert completed.attempt_count == replay.attempt_count == 4
        assert completed.identity_entry_removed
        assert not replay.identity_entry_removed
        assert completed.cryptographic_erasure_claimed is False
        assert not client_a_root.exists()
        assert not staging.exists()
        assert client_b_root.joinpath("cache/private-b.bin").read_bytes() == (
            b"CLIENT_B_MUST_SURVIVE"
        )
        payload = _identity_payload(protector, identity_map)
        entries = payload["entries"]
        assert type(entries) is dict
        assert len(entries) == 1
        assert next(iter(entries.values()))["client_id"] == client_b.client_id
        assert connection.execute(
            "SELECT state FROM clients WHERE client_id = ?",
            (client_a.client_id,),
        ).fetchone() == ("RETIRED",)
        assert connection.execute(
            "SELECT state FROM clients WHERE client_id = ?",
            (client_b.client_id,),
        ).fetchone() == ("ACTIVE",)
        assert connection.execute(
            "SELECT state, queue_state FROM deletion_requests WHERE request_id = ?",
            (request_id,),
        ).fetchone() == ("PHYSICAL_CLEANUP_COMPLETE", "SUCCEEDED")
        assert connection.execute(
            "SELECT count(*) FROM tombstones WHERE source_lineage_hash = ("
            "SELECT source_lineage_hash FROM tombstones "
            "WHERE target_type = 'client' LIMIT 1)"
        ).fetchone()[0] > 1
        assert CaseCatalog(
            connection,
            ContentStore(global_root),
        ).active_cases(purpose="answer_support") == ()
        assert hasher.calls and set(hasher.calls) == {client_a.client_id}
        assert publication.case_ref.object_id in {
            row[0]
            for row in connection.execute(
                "SELECT case_id FROM cases WHERE state = 'REVOKED'"
            ).fetchall()
        }

        # A restored directory or old encrypted identity-map snapshot must not
        # be accepted merely because the durable intent already says success.
        client_a_root.mkdir()
        (client_a_root / ".scope-id").write_text(
            f"{client_a.directory_object_id}\n",
            encoding="ascii",
            newline="\n",
        )
        identity_map.write_bytes(original_identity_map)
        with pytest.raises(
            WholeClientCleanupError,
            match="WHOLE_CLIENT_RESIDUE_REAPPEARED",
        ):
            coordinator.process(root_intent_id)
        assert connection.execute(
            "SELECT state, attempt_count FROM deletion_queue_intents "
            "WHERE intent_id = ?",
            (root_intent_id,),
        ).fetchone() == ("SUCCEEDED", 4)
    finally:
        connection.close()


def test_identity_entry_erase_rejects_nonretired_catalog_and_preserves_peer(
    tmp_path: Path,
) -> None:
    (
        fixture,
        client_a,
        client_b,
        protector,
        _clients_root,
        identity_map,
    ) = _activate_two_clients(tmp_path)
    creation, _catalog, connection, *_rest = fixture
    try:
        with pytest.raises(RuntimeError, match="CLIENT_CREATION_FAILED"):
            creation.erase_exact_identity_entry(
                client_id=client_a.client_id,
                alias_lookup_sha256=client_a.alias_lookup_sha256,
                directory_object_id=client_a.directory_object_id,
            )
        connection.execute(
            "UPDATE clients SET state = 'RETIRED' WHERE client_id = ?",
            (client_a.client_id,),
        )

        erased = creation.erase_exact_identity_entry(
            client_id=client_a.client_id,
            alias_lookup_sha256=client_a.alias_lookup_sha256,
            directory_object_id=client_a.directory_object_id,
        )

        assert erased.entry_removed
        payload = _identity_payload(protector, identity_map)
        entries = payload["entries"]
        assert type(entries) is dict
        assert len(entries) == 1
        assert next(iter(entries.values()))["client_id"] == client_b.client_id
        assert creation.has_exact_identity_entry(
            client_id=client_b.client_id,
            alias_lookup_sha256=client_b.alias_lookup_sha256,
            directory_object_id=client_b.directory_object_id,
        )
    finally:
        connection.close()
