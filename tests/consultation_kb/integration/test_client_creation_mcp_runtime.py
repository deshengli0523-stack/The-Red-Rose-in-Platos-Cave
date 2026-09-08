from __future__ import annotations

import hashlib
import itertools
import json
from datetime import datetime, timezone
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
from consultation_kb.core.client_ids import ClientIdFactory
from consultation_kb.core.errors import (
    ScopedObjectAccessDeniedError,
    map_exception_to_client_error,
)
from consultation_kb.core.ids import IdFactory
from consultation_kb.mcp.client_creation_runtime import (
    ClientCreationRuntime,
    _DeidentifiedCreationDiffFactory,
)
from consultation_kb.security.ntfs_acl import AclVerification
from consultation_kb.storage.catalog import ClientCatalog, ClientCreationService
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.approval_support import MutableClock, TestProtector


NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)
IDEMPOTENCY_KEY = "client-preview:real-0001"


class FakeAclPolicy:
    def apply(self, path: Path) -> AclVerification:
        assert path.is_dir()
        return AclVerification(allowed_principal_count=2)

    def verify(self, path: Path) -> AclVerification:
        assert path.is_dir()
        return AclVerification(allowed_principal_count=2)


class PreviewRequest:
    action = "preview"
    approval_request_id = None

    def __init__(self, alias: str, idempotency_key: str = IDEMPOTENCY_KEY) -> None:
        self.alias = alias
        self.idempotency_key = idempotency_key


class CommitRequest:
    action = "commit"
    alias = None
    idempotency_key = None

    def __init__(self, approval_request_id: str) -> None:
        self.approval_request_id = approval_request_id


def test_runtime_uses_real_p1_approval_and_keeps_alias_out_of_global_cas(
    tmp_path: Path,
) -> None:
    alias = "Private Real Service Alias"
    vault = tmp_path / "vault"
    global_root = vault / "global"
    clients_root = vault / "clients"
    identity_map = vault / "identity" / "identity-map.enc"
    global_root.mkdir(parents=True)
    clients_root.mkdir()
    identity_map.parent.mkdir()
    connection = connect_database(global_root / "catalog.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    clock = MutableClock(NOW)
    ids = IdFactory(clock, itertools.count(100).__next__)
    protector = TestProtector()
    approval_signer = LocalHmacApprovalSigner(
        secret=b"p" * 32,
        provider_id="local-review-agent",
        clock=clock,
    )
    approval_service = ApprovalService(
        connection,
        provider=LocalHmacApprovalVerifier(
            secret=b"p" * 32,
            provider_id="local-review-agent",
        ),
        protector=protector,
        clock=clock,
        id_factory=ids,
        target_scope_hash="a" * 64,
        vault_id="synthetic-vault",
        execution_secret=b"e" * 32,
        execution_proof_verifier=LocalHmacTargetExecutionProofVerifier(
            secret=b"t" * 32,
            attestor_id="test-global-writer",
        ),
        nonce_source=lambda size: b"n" * size,
    )
    execution_guard = ApprovalExecutionGuard(
        connection,
        approval_service=approval_service,
        execution_proof_signer=LocalHmacTargetExecutionAttestor(
            secret=b"t" * 32,
            attestor_id="test-global-writer",
        ),
        clock=clock,
    )
    content_store = ContentStore(global_root)
    catalog = ClientCatalog(connection)
    creation = ClientCreationService(
        catalog=catalog,
        approval_service=approval_service,
        execution_guard=execution_guard,
        protector=protector,
        acl_policy=FakeAclPolicy(),
        clock=clock,
        id_factory=ids,
        client_id_factory=ClientIdFactory(
            suffix_source=lambda: "a1b2c3d4e5f6"
        ),
        clients_root=clients_root,
        identity_map_path=identity_map,
        vault_id="synthetic-vault",
        alias_lookup_secret=b"l" * 32,
        diff_ref_factory=_DeidentifiedCreationDiffFactory(content_store, ids),
    )
    runtime = ClientCreationRuntime(creation)
    try:
        preview = runtime.invoke(
            "create_client",
            PreviewRequest(alias),
            binding=None,
        )
        preview_payload = preview.model_dump(mode="json")
        assert set(preview_payload) == {
            "status",
            "client_id",
            "approval_request_id",
        }
        assert alias not in preview.model_dump_json()
        assert IDEMPOTENCY_KEY not in preview.model_dump_json()

        # A lost preview response is recovered exactly from the encrypted
        # intent instead of allocating a second client, diff, or approval.
        replayed_preview = runtime.invoke(
            "create_client",
            PreviewRequest(alias),
            binding=None,
        )
        assert replayed_preview == preview

        for changed_request in (
            PreviewRequest(alias, "client-preview:real-0002"),
            PreviewRequest("Different Private Alias", IDEMPOTENCY_KEY),
        ):
            with pytest.raises(ScopedObjectAccessDeniedError):
                runtime.invoke(
                    "create_client",
                    changed_request,
                    binding=None,
                )

        challenge = approval_service.challenge_for_review(
            preview_payload["approval_request_id"]
        )
        diff = json.loads(
            content_store.read_hash_verified(
                challenge.request.diff_object_ref.content_sha256
            )
        )
        assert diff == {
            "client_id": preview_payload["client_id"],
            "description": "Create a new empty consultation client scope.",
            "operation": "create_client",
            "schema_version": 1,
        }
        encoded_diff = json.dumps(diff, sort_keys=True)
        assert alias not in encoded_diff
        assert IDEMPOTENCY_KEY not in encoded_diff
        assert "alias" not in encoded_diff.lower()
        assert "path" not in encoded_diff.lower()
        assert "sha256" not in encoded_diff.lower()

        with pytest.raises(ScopedObjectAccessDeniedError) as denied:
            runtime.invoke(
                "create_client",
                CommitRequest(preview_payload["approval_request_id"]),
                binding=None,
            )
        outward = map_exception_to_client_error(denied.value).model_dump_json()
        assert '"code":"SCOPE_DENIED"' in outward
        assert alias not in outward
        assert "approval" not in outward.lower()

        approval_service.confirm(approval_signer.confirm(challenge))
        committed = runtime.invoke(
            "create_client",
            CommitRequest(preview_payload["approval_request_id"]),
            binding=None,
        )
        assert committed.model_dump(mode="json") == {
            "status": "active",
            "client_id": preview_payload["client_id"],
        }
        assert catalog.get(preview_payload["client_id"]).state == "ACTIVE"
        client_database = (
            clients_root / preview_payload["client_id"] / "client.sqlite3"
        )
        reader = connect_database(client_database, mode="reader")
        try:
            MigrationRunner.for_scope(reader, "client").check()
        finally:
            reader.close()

        ciphertext = identity_map.read_bytes()
        assert alias.encode("utf-8") not in ciphertext
        plaintext = protector.unprotect(
            ciphertext,
            purpose="identity_map",
            vault_id="synthetic-vault",
        )
        assert alias in plaintext.decode("ascii")
        assert IDEMPOTENCY_KEY.encode("ascii") not in plaintext
        assert hashlib.sha256(IDEMPOTENCY_KEY.encode("ascii")).hexdigest() in (
            plaintext.decode("ascii")
        )
    finally:
        connection.close()
