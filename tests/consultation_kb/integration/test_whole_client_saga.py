from __future__ import annotations

import itertools
import sqlite3
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
from consultation_kb.archive.provenance import CaseContributorHasher
from consultation_kb.core.ids import IdFactory
from consultation_kb.lifecycle.whole_client_cleanup import (
    WholeClientCleanupCoordinator,
)
from consultation_kb.lifecycle.whole_client_saga import (
    WholeClientDeletionSaga,
    WholeClientSagaError,
)
from consultation_kb.models.deletion import DeletionBaseVersion
from consultation_kb.security.worker_protocol import ArchiveContentRef
from consultation_kb.storage.catalog import ClientCatalogError
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.tombstones import target_hash
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.approval_support import MutableClock, TestProtector
from tests.consultation_kb.integration.test_whole_client_cleanup import (
    _Quiescer,
    _activate_two_clients,
    _finish_siblings_and_backup,
)


pytestmark = pytest.mark.integration


def _approval_factory(
    connection: sqlite3.Connection,
    *,
    clock: MutableClock,
    ids: IdFactory,
):
    authorities: dict[str, object] = {}

    def factory(scope_hash: str):
        from consultation_kb.mcp.global_lifecycle_runtime import (
            TargetScopedDeletionAuthority,
        )

        existing = authorities.get(scope_hash)
        if existing is not None:
            return existing
        service = ApprovalService(
            connection,
            provider=LocalHmacApprovalVerifier(
                secret=b"p" * 32,
                provider_id="whole-client-saga-reviewer",
            ),
            protector=TestProtector(),
            clock=clock,
            id_factory=ids,
            target_scope_hash=scope_hash,
            vault_id="whole-client-saga-vault",
            execution_secret=b"e" * 32,
            execution_proof_verifier=LocalHmacTargetExecutionProofVerifier(
                secret=b"t" * 32,
                attestor_id="whole-client-saga-writer",
            ),
            nonce_source=lambda size: next(nonces).to_bytes(size, "big"),
        )
        authority = TargetScopedDeletionAuthority(
            approval_service=service,
            execution_guard=ApprovalExecutionGuard(
                connection,
                approval_service=service,
                execution_proof_signer=LocalHmacTargetExecutionAttestor(
                    secret=b"t" * 32,
                    attestor_id="whole-client-saga-writer",
                ),
                clock=clock,
            ),
        )
        authorities[scope_hash] = authority
        return authority

    nonces = itertools.count(1000)
    return factory


def test_current_client_saga_is_body_free_tombstone_first_and_restart_safe(
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
    (
        creation,
        catalog,
        connection,
        _creation_approval,
        _creation_provider,
        _fixture_protector,
        _fixture_clients_root,
        _fixture_identity_map,
        clock,
    ) = fixture
    ids = IdFactory(clock, itertools.count(12_000).__next__)
    global_root = tmp_path / "vault" / "global"
    database = global_root / "catalog.sqlite3"
    store = ContentStore(global_root)
    hasher = CaseContributorHasher(hash_key=b"h" * 32)
    quiescer = _Quiescer()
    factory = _approval_factory(connection, clock=clock, ids=ids)
    cleanup = WholeClientCleanupCoordinator(
        lambda: connect_database(database, mode="writer"),
        global_database_path=database,
        clients_root=clients_root,
        contributor_hasher=hasher,
        quiescer=quiescer,
        identity_registry=creation,
        clock=clock.now,
    )
    saga = WholeClientDeletionSaga(
        connection,
        content_store=store,
        approval_factory=factory,
        contributor_hasher=hasher,
        quiescer=quiescer,
        clock=clock,
        id_factory=ids,
        cleanup_coordinator=cleanup,
    )
    client_a_root = clients_root / client_a.client_id
    client_b_root = clients_root / client_b.client_id
    client_a_root.joinpath("private-canary.bin").write_bytes(b"PRIVATE_A")
    client_b_root.joinpath("private-canary.bin").write_bytes(b"PRIVATE_B")
    try:
        preview = saga.preview(
            bound_client_id=client_a.client_id,
            reason_code="client_erasure_requested",
        )
        public_preview = preview.model_dump_json()
        assert client_a.client_id not in public_preview
        assert client_b.client_id not in public_preview
        assert str(clients_root) not in public_preview
        assert "client_id" not in preview.model_json_schema()["properties"]
        authority = factory(preview.target_scope_hash)
        signer = LocalHmacApprovalSigner(
            secret=b"p" * 32,
            provider_id="whole-client-saga-reviewer",
            clock=clock,
        )
        authority.approval_service.confirm(
            signer.confirm(
                authority.approval_service.challenge_for_review(
                    preview.approval_request_id
                )
            )
        )

        before_invalid_commits = (
            connection.execute(
                "SELECT client_id, state FROM clients ORDER BY client_id"
            ).fetchall(),
            connection.execute("SELECT count(*) FROM tombstones").fetchone(),
            connection.execute(
                "SELECT count(*) FROM deletion_queue_intents"
            ).fetchone(),
            connection.execute(
                "SELECT count(*) FROM approval_executions"
            ).fetchone(),
        )
        with pytest.raises(
            WholeClientSagaError,
            match="WHOLE_CLIENT_PLAN_BINDING_MISMATCH",
        ):
            saga.commit(
                bound_client_id=client_b.client_id,
                plan_ref=preview.plan_ref,
                plan_sha256=preview.plan_sha256,
                target_scope_hash=preview.target_scope_hash,
                base_versions=preview.base_versions,
                approval_operation_id=preview.proposed_operation_id,
                approval_request_id=preview.approval_request_id,
            )
        with pytest.raises(
            WholeClientSagaError,
            match="WHOLE_CLIENT_PLAN_BINDING_MISMATCH",
        ):
            saga.commit(
                bound_client_id=client_a.client_id,
                plan_ref=preview.plan_ref,
                plan_sha256=preview.plan_sha256,
                target_scope_hash="f" * 64,
                base_versions=preview.base_versions,
                approval_operation_id=preview.proposed_operation_id,
                approval_request_id=preview.approval_request_id,
            )
        stale_bases = tuple(
            DeletionBaseVersion(
                authority_key=value.authority_key,
                scope_sha256=value.scope_sha256,
                version=value.version + int(index == 0),
            )
            for index, value in enumerate(preview.base_versions)
        )
        with pytest.raises(
            WholeClientSagaError,
            match="WHOLE_CLIENT_PLAN_BINDING_MISMATCH",
        ):
            saga.commit(
                bound_client_id=client_a.client_id,
                plan_ref=preview.plan_ref,
                plan_sha256=preview.plan_sha256,
                target_scope_hash=preview.target_scope_hash,
                base_versions=stale_bases,
                approval_operation_id=preview.proposed_operation_id,
                approval_request_id=preview.approval_request_id,
            )
        with pytest.raises(
            WholeClientSagaError,
            match="WHOLE_CLIENT_PLAN_UNAVAILABLE",
        ):
            saga.commit(
                bound_client_id=client_a.client_id,
                plan_ref=ArchiveContentRef(
                    object_id=preview.plan_ref.object_id,
                    version=preview.plan_ref.version,
                    content_sha256="f" * 64,
                    size_bytes=preview.plan_ref.size_bytes,
                    media_type="application/json",
                ),
                plan_sha256=preview.plan_sha256,
                target_scope_hash=preview.target_scope_hash,
                base_versions=preview.base_versions,
                approval_operation_id=preview.proposed_operation_id,
                approval_request_id=preview.approval_request_id,
            )
        after_invalid_commits = (
            connection.execute(
                "SELECT client_id, state FROM clients ORDER BY client_id"
            ).fetchall(),
            connection.execute("SELECT count(*) FROM tombstones").fetchone(),
            connection.execute(
                "SELECT count(*) FROM deletion_queue_intents"
            ).fetchone(),
            connection.execute(
                "SELECT count(*) FROM approval_executions"
            ).fetchone(),
        )
        assert after_invalid_commits == before_invalid_commits

        committed = saga.commit(
            bound_client_id=client_a.client_id,
            plan_ref=preview.plan_ref,
            plan_sha256=preview.plan_sha256,
            target_scope_hash=preview.target_scope_hash,
            base_versions=preview.base_versions,
            approval_operation_id=preview.proposed_operation_id,
            approval_request_id=preview.approval_request_id,
        )
        replayed_commit = saga.commit(
            bound_client_id=client_a.client_id,
            plan_ref=preview.plan_ref,
            plan_sha256=preview.plan_sha256,
            target_scope_hash=preview.target_scope_hash,
            base_versions=preview.base_versions,
            approval_operation_id=preview.proposed_operation_id,
            approval_request_id=preview.approval_request_id,
        )

        assert committed == replayed_commit
        assert committed.result.tombstone_committed
        assert quiescer.close_calls == 2
        with pytest.raises(ClientCatalogError):
            catalog.require_active(client_a.client_id)
        assert catalog.require_active(client_b.client_id) == client_b
        assert client_a_root.is_dir(), "physical erasure must follow the tombstone"
        assert client_b_root.joinpath("private-canary.bin").read_bytes() == b"PRIVATE_B"
        root_rows = connection.execute(
            "SELECT request_id, intent_id, state FROM deletion_queue_intents "
            "WHERE action_type = 'physical_delete' AND object_type = 'client' "
            "AND target_id_hash = ?",
            (target_hash("client", client_a.client_id),),
        ).fetchall()
        assert len(root_rows) == 1
        request_id, root_intent_id, state = map(str, root_rows[0])
        # Commit immediately drove the dedicated coordinator.  Global sibling
        # and backup closure are not complete yet, so the retry is durable.
        assert state == "FAILED"

        pending = saga.replay_cleanup_intent(root_intent_id)
        assert pending.state == "retry_pending"
        assert client_a_root.is_dir()
        _finish_siblings_and_backup(
            connection,
            request_id=request_id,
            root_intent_id=root_intent_id,
            at=clock.now(),
        )

        completed_without_restart = saga.recover_pending_cleanup()
        assert (
            len(completed_without_restart) == 1
            and completed_without_restart[0].state == "succeeded"
        )
        assert not client_a_root.exists()
        assert client_b_root.joinpath("private-canary.bin").read_bytes() == b"PRIVATE_B"

        # A fresh coordinator/saga can replay the exact completed intent.  It
        # receives only the global database and fixed clients root, never a
        # caller-selected path, and cannot resurrect the removed scope.
        restarted_cleanup = WholeClientCleanupCoordinator(
            lambda: connect_database(database, mode="writer"),
            global_database_path=database,
            clients_root=clients_root,
            contributor_hasher=hasher,
            quiescer=quiescer,
            identity_registry=creation,
            clock=clock.now,
        )
        restarted = WholeClientDeletionSaga(
            connection,
            content_store=store,
            approval_factory=factory,
            contributor_hasher=hasher,
            quiescer=quiescer,
            clock=clock,
            id_factory=ids,
            cleanup_coordinator=restarted_cleanup,
        )
        recovered = restarted.replay_cleanup_intent(root_intent_id)

        assert recovered.state == "succeeded"
        assert not client_a_root.exists()
        assert client_b_root.joinpath("private-canary.bin").read_bytes() == b"PRIVATE_B"
        assert connection.execute(
            "SELECT state FROM clients WHERE client_id = ?",
            (client_b.client_id,),
        ).fetchone() == ("ACTIVE",)
    finally:
        connection.close()
