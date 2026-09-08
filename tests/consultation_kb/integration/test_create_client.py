from __future__ import annotations

import hashlib
import itertools
import json
import os
import sqlite3
import subprocess
import sys
from collections.abc import Callable
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
from consultation_kb.approvals.store import (
    ApprovalRequired,
    ApprovalService,
    ApprovalUnavailable,
)
from consultation_kb.core.client_ids import ClientIdFactory
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import VersionRef
from consultation_kb.security.ntfs_acl import AclVerification
from consultation_kb.storage.catalog import (
    ClientCatalog,
    ClientCreationFailed,
    ClientCreationService,
    ClientNotFound,
    DuplicateClientAlias,
)
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from tests.consultation_kb.approval_support import MutableClock, TestProtector


NOW = datetime(2026, 7, 18, 9, 0, tzinfo=timezone.utc)
PREVIEW_KEY = "client-preview:0001"


class FakeAclPolicy:
    def __init__(self) -> None:
        self.applied = 0
        self.verified = 0

    def apply(self, path: Path) -> AclVerification:
        assert path.is_dir()
        self.applied += 1
        return AclVerification(allowed_principal_count=2)

    def verify(self, path: Path) -> AclVerification:
        assert path.is_dir()
        self.verified += 1
        return AclVerification(allowed_principal_count=2)


def _build_creation(
    tmp_path: Path,
    *,
    replace: Callable[[Path, Path], None] = os.replace,
) -> tuple[
    ClientCreationService,
    ClientCatalog,
    sqlite3.Connection,
    ApprovalService,
    LocalHmacApprovalSigner,
    TestProtector,
    Path,
    Path,
    MutableClock,
]:
    vault = tmp_path / "vault"
    clients_root = vault / "clients"
    identity_map = vault / "identity" / "identity-map.enc"
    clients_root.mkdir(parents=True)
    identity_map.parent.mkdir(parents=True)
    global_database = vault / "global" / "catalog.sqlite3"
    global_database.parent.mkdir(parents=True)
    connection = connect_database(global_database, mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    clock = MutableClock(NOW)
    random_values = itertools.count(100)
    nonce_values = itertools.count(1)
    ids = IdFactory(clock, lambda: next(random_values))
    protector = TestProtector()
    signer = LocalHmacApprovalSigner(
        secret=b"p" * 32,
        provider_id="local-review-agent",
        clock=clock,
    )
    verifier = LocalHmacApprovalVerifier(
        secret=b"p" * 32,
        provider_id="local-review-agent",
    )
    approval = ApprovalService(
        connection,
        provider=verifier,
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
        nonce_source=lambda size: next(nonce_values).to_bytes(size, "big"),
    )
    guard = ApprovalExecutionGuard(
        connection,
        approval_service=approval,
        execution_proof_signer=LocalHmacTargetExecutionAttestor(
            secret=b"t" * 32,
            attestor_id="test-global-writer",
        ),
        clock=clock,
    )
    catalog = ClientCatalog(connection)
    suffixes = iter(("a1b2c3d4e5f6", "b1b2c3d4e5f6", "c1b2c3d4e5f6"))

    def diff_ref(alias: str, client_id: str) -> VersionRef:
        digest = hashlib.sha256(f"{alias}\0{client_id}".encode("utf-8")).hexdigest()
        return VersionRef(
            object_id=ids.object_id("client_creation_diff"),
            version=1,
            content_sha256=digest,
        )

    creation = ClientCreationService(
        catalog=catalog,
        approval_service=approval,
        execution_guard=guard,
        protector=protector,
        acl_policy=FakeAclPolicy(),
        clock=clock,
        id_factory=ids,
        client_id_factory=ClientIdFactory(suffix_source=lambda: next(suffixes)),
        clients_root=clients_root,
        identity_map_path=identity_map,
        vault_id="synthetic-vault",
        alias_lookup_secret=b"l" * 32,
        diff_ref_factory=diff_ref,
        replace=replace,
    )
    return (
        creation,
        catalog,
        connection,
        approval,
        signer,
        protector,
        clients_root,
        identity_map,
        clock,
    )


def _confirm(
    approval: ApprovalService,
    provider: LocalHmacApprovalSigner,
    request_id: str,
) -> None:
    challenge = approval.challenge_for_review(request_id)
    approval.confirm(provider.confirm(challenge))


def _identity_payload(
    protector: TestProtector,
    identity_map: Path,
) -> dict[str, object]:
    plaintext = protector.unprotect(
        identity_map.read_bytes(),
        purpose="identity_map",
        vault_id="synthetic-vault",
    )
    payload = json.loads(plaintext)
    assert type(payload) is dict
    return payload


def _write_identity_payload(
    protector: TestProtector,
    identity_map: Path,
    payload: dict[str, object],
) -> None:
    identity_map.write_bytes(
        protector.protect(
            json.dumps(
                payload,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii"),
            purpose="identity_map",
            vault_id="synthetic-vault",
        )
    )


def test_preview_response_loss_replays_the_exact_durable_intent(
    tmp_path: Path,
) -> None:
    (
        creation,
        _catalog,
        connection,
        approval,
        _provider,
        protector,
        _clients_root,
        identity_map,
        _clock,
    ) = _build_creation(tmp_path)
    alias = "Synthetic Lost Preview Response"
    key = "client-preview:response-loss"
    try:
        first = creation.preview(alias=alias, idempotency_key=key)
        replay = creation.preview(alias=alias, idempotency_key=key)

        assert replay == first
        assert connection.execute(
            "SELECT COUNT(*) FROM approval_requests"
        ).fetchone() == (1,)
        payload = _identity_payload(protector, identity_map)
        encoded = json.dumps(payload, sort_keys=True)
        assert alias in encoded
        assert key not in encoded
        assert hashlib.sha256(key.encode("ascii")).hexdigest() in encoded

        with pytest.raises(DuplicateClientAlias):
            creation.preview(
                alias=alias,
                idempotency_key="client-preview:changed-payload",
            )
        with pytest.raises(DuplicateClientAlias):
            creation.preview(
                alias="Synthetic Changed Alias",
                idempotency_key=key,
            )
    finally:
        connection.close()


def test_intent_then_approval_failure_is_repaired_with_reserved_ids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        creation,
        _catalog,
        connection,
        approval,
        _provider,
        protector,
        _clients_root,
        identity_map,
        _clock,
    ) = _build_creation(tmp_path)
    alias = "Synthetic Approval Crash Window"
    key = "client-preview:intent-first"
    original_request = approval.request

    def fail_before_approval(*_args: object, **_kwargs: object) -> object:
        raise ApprovalUnavailable("injected after durable intent")

    try:
        monkeypatch.setattr(approval, "request", fail_before_approval)
        with pytest.raises(ApprovalUnavailable):
            creation.preview(alias=alias, idempotency_key=key)

        payload = _identity_payload(protector, identity_map)
        entries = payload["entries"]
        assert type(entries) is dict
        persisted = next(iter(entries.values()))
        assert type(persisted) is dict
        assert connection.execute(
            "SELECT COUNT(*) FROM approval_requests"
        ).fetchone() == (0,)

        monkeypatch.setattr(approval, "request", original_request)
        recovered = creation.preview(alias=alias, idempotency_key=key)

        assert recovered.request_id == persisted["request_id"]
        assert recovered.client_id == persisted["client_id"]
        assert recovered.descriptor.model_dump(mode="json") == persisted["descriptor"]
        assert recovered.diff_object_ref.model_dump(mode="json") == persisted[
            "diff_object_ref"
        ]
        assert connection.execute(
            "SELECT COUNT(*) FROM approval_requests"
        ).fetchone() == (1,)
        assert key not in json.dumps(payload, sort_keys=True)
    finally:
        connection.close()


@pytest.mark.parametrize("renewal_reason", ("expired", "rejected"))
def test_unbound_preview_renews_without_reallocating_the_client_or_diff(
    tmp_path: Path,
    renewal_reason: str,
) -> None:
    (
        creation,
        catalog,
        connection,
        approval,
        provider,
        _protector,
        clients_root,
        _identity_map,
        clock,
    ) = _build_creation(tmp_path)
    alias = "Synthetic Renewable Preview"
    key = "client-preview:renewable-0001"
    try:
        first = creation.preview(alias=alias, idempotency_key=key)
        first_request = approval.get(first.request_id)
        if renewal_reason == "expired":
            # Exactly the five-minute TTL boundary is no longer reviewable.
            clock.value = NOW + timedelta(minutes=5)
            assert clock.value == first_request.expires_at
        else:
            connection.execute(
                "UPDATE approval_requests SET state = 'REJECTED' WHERE request_id = ?",
                (first.request_id,),
            )

        renewed = creation.preview(alias=alias, idempotency_key=key)

        assert renewed.request_id != first.request_id
        assert renewed.client_id == first.client_id
        assert renewed.directory_object_id == first.directory_object_id
        assert renewed.descriptor == first.descriptor
        assert renewed.diff_object_ref == first.diff_object_ref
        with pytest.raises(ClientCreationFailed, match="CLIENT_CREATION_FAILED"):
            creation.commit(first.request_id)

        _confirm(approval, provider, renewed.request_id)
        active = creation.commit(renewed.request_id)
        assert active.client_id == first.client_id
        assert active.state == "ACTIVE"
        assert catalog.get(active.client_id).state == "ACTIVE"
        assert (clients_root / active.client_id / "client.sqlite3").is_file()
    finally:
        connection.close()


def test_v1_preview_remains_committable_but_cannot_claim_a_new_key(
    tmp_path: Path,
) -> None:
    (
        creation,
        _catalog,
        connection,
        approval,
        provider,
        protector,
        _clients_root,
        identity_map,
        _clock,
    ) = _build_creation(tmp_path)
    alias = "Synthetic V1 Preview"
    try:
        preview = creation.preview(
            alias=alias,
            idempotency_key="client-preview:v1-migration",
        )
        payload = _identity_payload(protector, identity_map)
        entries = payload["entries"]
        assert type(entries) is dict
        entry = next(iter(entries.values()))
        assert type(entry) is dict
        del entry["idempotency_key_sha256"]
        payload["schema_version"] = 1
        identity_map.write_bytes(
            protector.protect(
                json.dumps(
                    payload,
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii"),
                purpose="identity_map",
                vault_id="synthetic-vault",
            )
        )

        with pytest.raises(DuplicateClientAlias):
            creation.preview(
                alias=alias,
                idempotency_key="client-preview:unknown-v1-key",
            )
        _confirm(approval, provider, preview.request_id)
        active = creation.commit(preview.request_id)
        assert active.client_id == preview.client_id
        migrated = _identity_payload(protector, identity_map)
        assert migrated["schema_version"] == 2
        migrated_entries = migrated["entries"]
        assert type(migrated_entries) is dict
        migrated_entry = next(iter(migrated_entries.values()))
        assert type(migrated_entry) is dict
        assert migrated_entry["state"] == "ACTIVE"
        assert migrated_entry["idempotency_key_sha256"] is None
    finally:
        connection.close()


def test_bound_unapplied_preview_rotates_request_and_operation_after_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        creation,
        _catalog,
        connection,
        approval,
        provider,
        protector,
        _clients_root,
        identity_map,
        clock,
    ) = _build_creation(tmp_path)
    alias = "Synthetic Bound Preview"
    key = "client-preview:bound-replay"
    original_stage = creation._create_staged_scope

    def fail_after_binding(*_args: object, **_kwargs: object) -> object:
        raise ClientCreationFailed

    try:
        preview = creation.preview(alias=alias, idempotency_key=key)
        _confirm(approval, provider, preview.request_id)
        monkeypatch.setattr(creation, "_create_staged_scope", fail_after_binding)
        with pytest.raises(ClientCreationFailed, match="CLIENT_CREATION_FAILED"):
            creation.commit(preview.request_id)
        before = _identity_payload(protector, identity_map)
        before_entries = before["entries"]
        assert type(before_entries) is dict
        before_entry = next(iter(before_entries.values()))
        assert type(before_entry) is dict
        assert before_entry["state"] == "PREVIEW"
        old_operation_id = before_entry["operation_id"]

        clock.value = approval.get(preview.request_id).expires_at
        renewed = creation.preview(alias=alias, idempotency_key=key)
        assert renewed.request_id != preview.request_id
        assert renewed.client_id == preview.client_id
        assert renewed.descriptor == preview.descriptor
        assert renewed.diff_object_ref == preview.diff_object_ref
        after = _identity_payload(protector, identity_map)
        after_entries = after["entries"]
        assert type(after_entries) is dict
        after_entry = next(iter(after_entries.values()))
        assert type(after_entry) is dict
        assert after_entry["state"] == "PREVIEW"
        assert after_entry["operation_id"] != old_operation_id
        with pytest.raises(ClientCreationFailed, match="CLIENT_CREATION_FAILED"):
            creation.commit(preview.request_id)

        monkeypatch.setattr(creation, "_create_staged_scope", original_stage)
        _confirm(approval, provider, renewed.request_id)
        active = creation.commit(renewed.request_id)
        assert active.state == "ACTIVE"
        assert active.client_id == preview.client_id
    finally:
        connection.close()


def test_bound_unapplied_staged_scope_renews_without_losing_staged_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        creation,
        _catalog,
        connection,
        approval,
        provider,
        protector,
        _clients_root,
        identity_map,
        clock,
    ) = _build_creation(tmp_path)
    alias = "Synthetic Bound Staged"
    key = "client-preview:staged-renewal"
    guard = creation._execution_guard
    original_apply = guard.apply_in_transaction

    def fail_after_staging(*_args: object, **_kwargs: object) -> object:
        raise ClientCreationFailed

    try:
        preview = creation.preview(alias=alias, idempotency_key=key)
        _confirm(approval, provider, preview.request_id)
        monkeypatch.setattr(guard, "apply_in_transaction", fail_after_staging)
        with pytest.raises(ClientCreationFailed, match="CLIENT_CREATION_FAILED"):
            creation.commit(preview.request_id)

        before = _identity_payload(protector, identity_map)
        before_entries = before["entries"]
        assert type(before_entries) is dict
        before_entry = next(iter(before_entries.values()))
        assert type(before_entry) is dict
        assert before_entry["state"] == "STAGED"
        old_operation_id = before_entry["operation_id"]
        empty_db_sha256 = before_entry["empty_db_sha256"]
        assert type(empty_db_sha256) is str

        clock.value = approval.get(preview.request_id).expires_at
        renewed = creation.preview(alias=alias, idempotency_key=key)
        assert renewed.request_id != preview.request_id
        assert renewed.client_id == preview.client_id
        assert renewed.descriptor == preview.descriptor
        assert renewed.diff_object_ref == preview.diff_object_ref
        after = _identity_payload(protector, identity_map)
        after_entries = after["entries"]
        assert type(after_entries) is dict
        after_entry = next(iter(after_entries.values()))
        assert type(after_entry) is dict
        assert after_entry["state"] == "STAGED_REAPPROVAL"
        assert after_entry["empty_db_sha256"] == empty_db_sha256
        assert after_entry["operation_id"] != old_operation_id
        replayed = creation.preview(alias=alias, idempotency_key=key)
        assert replayed == renewed
        assert _identity_payload(protector, identity_map) == after
        with pytest.raises(ClientCreationFailed, match="CLIENT_CREATION_FAILED"):
            creation.commit(preview.request_id)

        monkeypatch.setattr(guard, "apply_in_transaction", original_apply)
        _confirm(approval, provider, renewed.request_id)
        active = creation.commit(renewed.request_id)
        assert active.state == "ACTIVE"
        assert active.client_id == preview.client_id
    finally:
        connection.close()


def test_staged_reapproval_intent_repairs_missing_reserved_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        creation,
        _catalog,
        connection,
        approval,
        provider,
        protector,
        _clients_root,
        identity_map,
        clock,
    ) = _build_creation(tmp_path)
    alias = "Synthetic Staged Reapproval Crash"
    key = "client-preview:staged-intent-first"
    guard = creation._execution_guard
    original_apply = guard.apply_in_transaction
    original_request = approval.request

    def fail_after_staging(*_args: object, **_kwargs: object) -> object:
        raise ClientCreationFailed

    def fail_before_reapproval(*_args: object, **_kwargs: object) -> object:
        raise ApprovalUnavailable("injected after staged reapproval intent")

    try:
        preview = creation.preview(alias=alias, idempotency_key=key)
        _confirm(approval, provider, preview.request_id)
        monkeypatch.setattr(guard, "apply_in_transaction", fail_after_staging)
        with pytest.raises(ClientCreationFailed, match="CLIENT_CREATION_FAILED"):
            creation.commit(preview.request_id)

        clock.value = approval.get(preview.request_id).expires_at
        monkeypatch.setattr(approval, "request", fail_before_reapproval)
        with pytest.raises(ApprovalUnavailable):
            creation.preview(alias=alias, idempotency_key=key)

        persisted = _identity_payload(protector, identity_map)
        persisted_entries = persisted["entries"]
        assert type(persisted_entries) is dict
        persisted_entry = next(iter(persisted_entries.values()))
        assert type(persisted_entry) is dict
        assert persisted_entry["state"] == "STAGED_REAPPROVAL"
        assert type(persisted_entry["empty_db_sha256"]) is str
        reserved_request_id = persisted_entry["request_id"]
        assert reserved_request_id != preview.request_id
        assert connection.execute(
            "SELECT COUNT(*) FROM approval_requests"
        ).fetchone() == (1,)

        monkeypatch.setattr(approval, "request", original_request)
        recovered = creation.preview(alias=alias, idempotency_key=key)
        assert recovered.request_id == reserved_request_id
        assert recovered.client_id == preview.client_id
        assert recovered.descriptor == preview.descriptor
        assert recovered.diff_object_ref == preview.diff_object_ref
        assert _identity_payload(protector, identity_map) == persisted
        assert connection.execute(
            "SELECT COUNT(*) FROM approval_requests"
        ).fetchone() == (2,)

        monkeypatch.setattr(guard, "apply_in_transaction", original_apply)
        _confirm(approval, provider, recovered.request_id)
        active = creation.commit(recovered.request_id)
        assert active.state == "ACTIVE"
        assert active.client_id == preview.client_id
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("state", "empty_db_sha256"),
    (
        ("STAGED_REAPPROVAL", None),
        ("PREVIEW", "0" * 64),
        ("UNKNOWN", "0" * 64),
    ),
)
def test_identity_parser_rejects_invalid_state_hash_combinations(
    tmp_path: Path,
    state: str,
    empty_db_sha256: str | None,
) -> None:
    (
        creation,
        _catalog,
        connection,
        _approval,
        _provider,
        protector,
        _clients_root,
        identity_map,
        _clock,
    ) = _build_creation(tmp_path)
    alias = "Synthetic State Hash Invariant"
    key = "client-preview:state-hash"
    try:
        creation.preview(alias=alias, idempotency_key=key)
        payload = _identity_payload(protector, identity_map)
        entries = payload["entries"]
        assert type(entries) is dict
        entry = next(iter(entries.values()))
        assert type(entry) is dict
        entry["state"] = state
        entry["empty_db_sha256"] = empty_db_sha256
        _write_identity_payload(protector, identity_map, payload)

        with pytest.raises(ClientCreationFailed, match="CLIENT_CREATION_FAILED"):
            creation.preview(alias=alias, idempotency_key=key)
    finally:
        connection.close()


def test_plain_staged_without_an_execution_binding_is_not_reapproval(
    tmp_path: Path,
) -> None:
    (
        creation,
        _catalog,
        connection,
        _approval,
        _provider,
        protector,
        _clients_root,
        identity_map,
        _clock,
    ) = _build_creation(tmp_path)
    alias = "Synthetic Unbound Staged"
    key = "client-preview:unbound-staged"
    try:
        creation.preview(alias=alias, idempotency_key=key)
        payload = _identity_payload(protector, identity_map)
        entries = payload["entries"]
        assert type(entries) is dict
        entry = next(iter(entries.values()))
        assert type(entry) is dict
        entry["state"] = "STAGED"
        entry["empty_db_sha256"] = "0" * 64
        _write_identity_payload(protector, identity_map, payload)

        with pytest.raises(ClientCreationFailed, match="CLIENT_CREATION_FAILED"):
            creation.preview(alias=alias, idempotency_key=key)
    finally:
        connection.close()


def test_client_creation_requires_matching_approval_and_creates_empty_scope(
    tmp_path: Path,
) -> None:
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
    ) = _build_creation(tmp_path)
    alias = "Synthetic Client Alpha"
    try:
        preview = creation.preview(alias=alias, idempotency_key=PREVIEW_KEY)
        with pytest.raises(ApprovalRequired):
            creation.commit(preview.request_id)
        assert not (clients_root / preview.client_id).exists()

        _confirm(approval, provider, preview.request_id)
        record = creation.commit(preview.request_id)
        assert record.state == "ACTIVE"
        assert record.client_id == preview.client_id
        client_database = clients_root / record.client_id / "client.sqlite3"
        reader = connect_database(client_database, mode="reader")
        try:
            MigrationRunner.for_scope(reader, "client").check()
        finally:
            reader.close()
        assert catalog.get(record.client_id).state == "ACTIVE"

        ciphertext = identity_map.read_bytes()
        assert alias.encode("utf-8") not in ciphertext
        plaintext = protector.unprotect(
            ciphertext,
            purpose="identity_map",
            vault_id="synthetic-vault",
        )
        identity_payload = json.loads(plaintext)
        assert identity_payload["entries"][record.alias_lookup_sha256]["alias"] == alias
        with pytest.raises(DuplicateClientAlias):
            creation.preview(
                alias=alias.upper(),
                idempotency_key="client-preview:0002",
            )
    finally:
        connection.close()


def test_prepared_client_recovers_after_atomic_rename_failure(tmp_path: Path) -> None:
    calls = 0

    def fail_once(source: Path, target: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected rename failure")
        os.replace(source, target)

    (
        creation,
        catalog,
        connection,
        approval,
        provider,
        _protector,
        clients_root,
        _identity_map,
        clock,
    ) = _build_creation(tmp_path, replace=fail_once)
    try:
        preview = creation.preview(
            alias="Synthetic Recovery",
            idempotency_key=PREVIEW_KEY,
        )
        _confirm(approval, provider, preview.request_id)

        with pytest.raises(ClientCreationFailed, match="CLIENT_CREATION_FAILED"):
            creation.commit(preview.request_id)
        assert catalog.get(preview.client_id).state == "PREPARED"
        assert not (clients_root / preview.client_id).exists()

        clock.value = approval.get(preview.request_id).expires_at
        staged_replay = creation.preview(
            alias="Synthetic Recovery",
            idempotency_key=PREVIEW_KEY,
        )
        assert staged_replay == preview

        recovered = creation.commit(preview.request_id)
        assert recovered.state == "ACTIVE"
        assert (clients_root / preview.client_id / "client.sqlite3").is_file()
    finally:
        connection.close()


def test_identity_map_fields_cannot_escape_the_approved_descriptor(
    tmp_path: Path,
) -> None:
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
    ) = _build_creation(tmp_path)
    try:
        preview = creation.preview(
            alias="Synthetic Binding",
            idempotency_key=PREVIEW_KEY,
        )
        plaintext = protector.unprotect(
            identity_map.read_bytes(),
            purpose="identity_map",
            vault_id="synthetic-vault",
        )
        payload = json.loads(plaintext)
        entry = next(iter(payload["entries"].values()))
        entry["directory_object_id"] = (
            "client_directory_01800000-0000-7000-8000-999999999999"
        )
        identity_map.write_bytes(
            protector.protect(
                json.dumps(
                    payload,
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii"),
                purpose="identity_map",
                vault_id="synthetic-vault",
            )
        )
        _confirm(approval, provider, preview.request_id)

        with pytest.raises(ClientCreationFailed, match="CLIENT_CREATION_FAILED"):
            creation.commit(preview.request_id)
        with pytest.raises(ClientNotFound):
            catalog.get(preview.client_id)
        assert not (clients_root / preview.client_id).exists()
    finally:
        connection.close()


def test_identity_map_hardlink_is_rejected_before_scope_creation(
    tmp_path: Path,
) -> None:
    (
        creation,
        catalog,
        connection,
        approval,
        provider,
        _protector,
        clients_root,
        identity_map,
        _clock,
    ) = _build_creation(tmp_path)
    try:
        preview = creation.preview(
            alias="Synthetic Identity Hardlink",
            idempotency_key=PREVIEW_KEY,
        )
        original = identity_map.with_name("identity-original.enc")
        os.replace(identity_map, original)
        os.link(original, identity_map)
        _confirm(approval, provider, preview.request_id)

        with pytest.raises(ClientCreationFailed, match="CLIENT_CREATION_FAILED"):
            creation.commit(preview.request_id)
        with pytest.raises(ClientNotFound):
            catalog.get(preview.client_id)
        assert not (clients_root / preview.client_id).exists()
    finally:
        connection.close()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junction attack")
def test_prepositioned_staging_junction_is_rejected_before_prepare(
    tmp_path: Path,
) -> None:
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
    ) = _build_creation(tmp_path)
    junction: Path | None = None
    try:
        preview = creation.preview(
            alias="Synthetic Junction",
            idempotency_key=PREVIEW_KEY,
        )
        _confirm(approval, provider, preview.request_id)
        staging_root = clients_root / ".staging"
        staging_root.mkdir()
        outside = tmp_path / "outside-scope"
        outside.mkdir()
        (outside / ".scope-id").write_bytes(
            f"{preview.directory_object_id}\n".encode("ascii")
        )
        outside_database = outside / "client.sqlite3"
        outside_connection = connect_database(outside_database, mode="writer")
        try:
            MigrationRunner.for_scope(outside_connection, "client").apply()
        finally:
            outside_connection.close()
        outside_hash = hashlib.sha256(outside_database.read_bytes()).hexdigest()
        junction = staging_root / preview.client_id
        result = subprocess.run(
            [
                "cmd.exe",
                "/d",
                "/c",
                "mklink",
                "/J",
                str(junction),
                str(outside),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.skip("junction creation unavailable")

        with pytest.raises(ClientCreationFailed, match="CLIENT_CREATION_FAILED"):
            creation.commit(preview.request_id)
        with pytest.raises(ClientNotFound):
            catalog.get(preview.client_id)
        assert hashlib.sha256(outside_database.read_bytes()).hexdigest() == outside_hash
        identity_payload = json.loads(
            protector.unprotect(
                identity_map.read_bytes(),
                purpose="identity_map",
                vault_id="synthetic-vault",
            )
        )
        assert next(iter(identity_payload["entries"].values()))["state"] == "PREVIEW"
    finally:
        if junction is not None and junction.exists():
            os.rmdir(junction)
        connection.close()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junction attack")
def test_staging_root_junction_never_deletes_same_named_external_directory(
    tmp_path: Path,
) -> None:
    (
        creation,
        catalog,
        connection,
        approval,
        provider,
        _protector,
        clients_root,
        _identity_map,
        _clock,
    ) = _build_creation(tmp_path)
    staging_root = clients_root / ".staging"
    try:
        preview = creation.preview(
            alias="Synthetic Cleanup Boundary",
            idempotency_key=PREVIEW_KEY,
        )
        _confirm(approval, provider, preview.request_id)
        outside = tmp_path / "outside-staging"
        external_client = outside / preview.client_id
        external_client.mkdir(parents=True)
        sentinel = external_client / "must-survive.bin"
        sentinel.write_bytes(b"external-sentinel")
        result = subprocess.run(
            [
                "cmd.exe",
                "/d",
                "/c",
                "mklink",
                "/J",
                str(staging_root),
                str(outside),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.skip("junction creation unavailable")

        with pytest.raises(ClientCreationFailed, match="CLIENT_CREATION_FAILED"):
            creation.commit(preview.request_id)
        with pytest.raises(ClientNotFound):
            catalog.get(preview.client_id)
        assert sentinel.read_bytes() == b"external-sentinel"
    finally:
        if staging_root.exists():
            os.rmdir(staging_root)
        connection.close()
