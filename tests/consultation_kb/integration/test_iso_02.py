from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

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
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.config import AppConfig
from consultation_kb.core.ids import IdFactory
from consultation_kb.evaluation.privacy_scan import PrivacyScanner
from consultation_kb.lifecycle.publish import (
    ArtifactDraft,
    ContentDraft,
    PublicationOperation,
    PublishCoordinator,
    publication_closure_sha256,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.security.dpapi import WindowsDpapiProtector
from consultation_kb.security.ntfs_acl import AclPolicy
from consultation_kb.storage.catalog import (
    ClientCatalog,
    ClientCreationService,
    ClientRecord,
)
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.storage.tombstones import TombstoneRepository, VisibilityGuard
from consultation_kb.vault.content_store import ContentObjectRef, ContentStore
from consultation_kb.vault.layout import VaultLayout


pytestmark = [
    pytest.mark.integration,
    pytest.mark.acceptance_id("ISO-02"),
    pytest.mark.skipif(sys.platform != "win32", reason="Windows storage isolation"),
]


NOW = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)
VAULT_ID = "synthetic-iso-02"
ALIAS_LOOKUP_SECRET = b"l" * 32
SAFE_DIFF_BYTES = b"approved synthetic diff without subject fields\n"
MANIFEST_TABLES = (
    "publication_operations",
    "runtime_epochs",
    "artifact_manifests",
    "artifact_members",
    "active_artifacts",
)


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def _files_below(root: Path) -> set[Path]:
    return {path for path in root.rglob("*") if path.is_file()}


def _privacy_scanner(repo_root: Path) -> PrivacyScanner:
    return PrivacyScanner.default(
        profile="shared_derivative",
        canary_definition_path=(
            repo_root / "tests" / "fixtures" / "consultation_kb" / "canaries.json"
        ),
        hash_key=b"s" * 32,
    )


def _read_manifest_projection(database: Path) -> tuple[bytes, dict[str, int]]:
    connection = connect_database(database, mode="reader")
    try:
        projection: dict[str, object] = {}
        counts: dict[str, int] = {}
        for table in MANIFEST_TABLES:
            columns = tuple(
                str(row[1])
                for row in connection.execute(f"PRAGMA table_info({table})")
            )
            rows = tuple(
                tuple(row)
                for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1")
            )
            projection[table] = {"columns": columns, "rows": rows}
            counts[table] = len(rows)
        return _json_bytes(projection), counts
    finally:
        connection.close()


def _read_client_rows(database: Path) -> tuple[tuple[str, str, str, str], ...]:
    connection = connect_database(database, mode="reader")
    try:
        return tuple(
            (str(row[0]), str(row[1]), str(row[2]), str(row[3]))
            for row in connection.execute(
                "SELECT client_id, directory_object_id, alias_lookup_sha256, state "
                "FROM clients ORDER BY client_id"
            )
        )
    finally:
        connection.close()


@dataclass
class _Iso02Harness:
    layout: VaultLayout
    global_connection: sqlite3.Connection
    clock: FixedClock
    ids: IdFactory
    signer: LocalHmacApprovalSigner
    approval: ApprovalService
    guard: ApprovalExecutionGuard
    creation: ClientCreationService
    protector: WindowsDpapiProtector
    coordinator: PublishCoordinator

    def close(self) -> None:
        self.global_connection.close()

    def create_client(self, alias: str) -> ClientRecord:
        preview = self.creation.preview(
            alias=alias,
            idempotency_key=(
                "iso02:" + hashlib.sha256(alias.encode("utf-8")).hexdigest()
            ),
        )
        challenge = self.approval.challenge_for_review(preview.request_id)
        self.approval.confirm(self.signer.confirm(challenge))
        record = self.creation.commit(preview.request_id)
        assert record.client_id == preview.client_id
        assert record.state == "ACTIVE"
        return record

    def publish_global(self, payload: bytes) -> ContentObjectRef:
        authority_base_version = 1
        purpose: Literal["wiki_publish"] = "wiki_publish"
        artifact = ArtifactDraft(
            manifest_id=self.ids.object_id("shared_manifest"),
            artifact_key="shared_summary",
            artifact_kind="shared_summary",
            source_version=authority_base_version,
            members=(
                ContentDraft(
                    object_type="shared_artifact",
                    object_id=self.ids.object_id("shared_artifact"),
                    data=payload,
                    source_version=authority_base_version,
                    media_type="application/json",
                    source_lineage=(),
                ),
            ),
        )
        prepared = self.coordinator.stage_artifacts(
            purpose=purpose,
            artifacts=(artifact,),
        )
        draft = DraftDescriptor(
            purpose=purpose,
            target_id=artifact.manifest_id,
            client_id=None,
            base_version=authority_base_version - 1,
            draft_sha256=publication_closure_sha256(
                purpose=purpose,
                authority_base_version=authority_base_version,
                expected_current_epoch=None,
                artifacts=(artifact,),
            ),
            session_id=None,
        )
        diff_ref = VersionRef(
            object_id=self.ids.object_id("publication_diff"),
            version=1,
            content_sha256=hashlib.sha256(SAFE_DIFF_BYTES).hexdigest(),
        )
        request = self.approval.request(draft, diff_object_ref=diff_ref)
        challenge = self.approval.challenge_for_review(request.request_id)
        self.approval.confirm(self.signer.confirm(challenge))
        ticket = self.approval.issue_for_execution(
            request.request_id,
            draft,
            operation_id=self.ids.object_id("publish_operation"),
        )
        operation: PublicationOperation | None = None

        def prepare_in_claim(_connection: sqlite3.Connection) -> None:
            nonlocal operation
            operation = self.coordinator.prepare(
                operation_id=ticket.operation_id,
                purpose=purpose,
                authority_base_version=authority_base_version,
                approval_request_id=ticket.request_id,
                descriptor_sha256=ticket.descriptor_sha256,
                expected_current_epoch=None,
                artifacts=prepared,
            )

        proof = self.guard.apply_in_transaction(ticket, draft, prepare_in_claim)
        self.approval.acknowledge(proof)
        assert operation is not None
        verified = self.coordinator.verify(operation.operation_id)
        assert verified.state == "VERIFIED"
        active = self.coordinator.activate(operation.operation_id)
        assert active.state == "ACTIVE"
        return prepared[0].members[0].reference


def _build_harness(repo_root: Path, tmp_path: Path) -> _Iso02Harness:
    vault = tmp_path / "vault"
    vault.mkdir()
    layout = VaultLayout.from_config(  # type: ignore[attr-defined]
        AppConfig.from_values(repo_root, vault)
    )
    global_root = layout.global_db.parent
    identity_root = layout.identity_map.parent
    for directory in (global_root, layout.clients_root, identity_root):
        directory.mkdir()

    acl_policy = AclPolicy()
    for directory in (vault, global_root, layout.clients_root, identity_root):
        acl_policy.apply(directory)

    connection = connect_database(layout.global_db, mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    clock = FixedClock(NOW)
    ids = IdFactory(clock, itertools.count(1).__next__)
    nonce_values = itertools.count(1)
    protector = WindowsDpapiProtector()
    signer = LocalHmacApprovalSigner(
        secret=b"p" * 32,
        provider_id="local-review-agent",
        clock=clock,
    )
    verifier = LocalHmacApprovalVerifier(
        secret=b"p" * 32,
        provider_id="local-review-agent",
    )
    target_scope_hash = hashlib.sha256(b"iso-02-global-scope-v1").hexdigest()
    target_attestor = LocalHmacTargetExecutionAttestor(
        secret=b"t" * 32,
        attestor_id="iso-02-global-writer",
    )
    approval = ApprovalService(
        connection,
        provider=verifier,
        protector=protector,
        clock=clock,
        id_factory=ids,
        target_scope_hash=target_scope_hash,
        vault_id=VAULT_ID,
        execution_secret=b"e" * 32,
        execution_proof_verifier=LocalHmacTargetExecutionProofVerifier(
            secret=b"t" * 32,
            attestor_id="iso-02-global-writer",
        ),
        nonce_source=lambda size: next(nonce_values).to_bytes(size, "big"),
    )
    guard = ApprovalExecutionGuard(
        connection,
        approval_service=approval,
        execution_proof_signer=target_attestor,
        clock=clock,
    )

    def safe_diff_ref(_alias: str, _client_id: str) -> VersionRef:
        return VersionRef(
            object_id=ids.object_id("client_creation_diff"),
            version=1,
            content_sha256=hashlib.sha256(SAFE_DIFF_BYTES).hexdigest(),
        )

    suffixes = iter(("a1b2c3d4e5f6", "b1b2c3d4e5f6"))
    catalog = ClientCatalog(connection)
    creation = ClientCreationService(
        catalog=catalog,
        approval_service=approval,
        execution_guard=guard,
        protector=protector,
        acl_policy=acl_policy,
        clock=clock,
        id_factory=ids,
        client_id_factory=ClientIdFactory(suffix_source=suffixes.__next__),
        clients_root=layout.clients_root,
        identity_map_path=layout.identity_map,
        vault_id=VAULT_ID,
        alias_lookup_secret=ALIAS_LOOKUP_SECRET,
        diff_ref_factory=safe_diff_ref,
    )
    global_store = ContentStore(global_root)
    coordinator = PublishCoordinator(
        connection,
        global_store,
        VisibilityGuard(
            TombstoneRepository(connection, clock=clock, id_factory=ids)
        ),
        clock=clock,
    )
    return _Iso02Harness(
        layout=layout,
        global_connection=connection,
        clock=clock,
        ids=ids,
        signer=signer,
        approval=approval,
        guard=guard,
        creation=creation,
        protector=protector,
        coordinator=coordinator,
    )


def test_shared_derivatives_contain_no_client_canary_or_reversible_identifier(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    canary_a = ("SYNTH-CANARY-" + "ALPHA-9F3A").encode("ascii")
    canary_b = ("SYNTH-CANARY-" + "BETA-71D2").encode("ascii")
    alias_a = "Synthetic Alias " + "Alpha 19"
    alias_b = "Synthetic Alias " + "Beta 27"
    safe_payload = b'{"aggregate_count":2,"schema_version":"1.0"}\n'
    harness = _build_harness(repo_root, tmp_path)
    try:
        record_a = harness.create_client(alias_a)
        record_b = harness.create_client(alias_b)
        client_references: dict[str, ContentObjectRef] = {}
        for record, canary in ((record_a, canary_a), (record_b, canary_b)):
            store = ContentStore(harness.layout.clients_root / record.client_id)
            staged = store.stage_bytes(
                canary,
                purpose="synthetic_isolation_probe",
                manifest_id=harness.ids.object_id("private_manifest"),
                media_type="text/plain",
            )
            client_references[record.client_id] = store.finalize(staged)
        global_reference = harness.publish_global(safe_payload)
    finally:
        harness.close()

    layout = harness.layout
    vault = layout.clients_root.parent
    identity_lock = layout.identity_map.parent / ".identity-map.lock"
    catalog_exceptions = {layout.global_db}
    identity_exceptions = {layout.identity_map, identity_lock}
    private_files = {
        layout.clients_root / record_a.client_id / ".scope-id",
        layout.clients_root / record_a.client_id / "client.sqlite3",
        client_references[record_a.client_id].path,
        layout.clients_root / record_b.client_id / ".scope-id",
        layout.clients_root / record_b.client_id / "client.sqlite3",
        client_references[record_b.client_id].path,
    }
    shared_derivative_files = {global_reference.path}
    assert _files_below(vault) == (
        catalog_exceptions
        | identity_exceptions
        | private_files
        | shared_derivative_files
    )
    for nonexistent in (
        layout.audit_root,
        vault / "backups",
        layout.global_db.parent / "logs",
        layout.global_db.parent / "temporary-backup",
    ):
        assert not nonexistent.exists()

    scanner = _privacy_scanner(repo_root)
    local_outcome = scanner.scan_paths(
        tuple(reference.path for reference in client_references.values())
    )
    assert local_outcome.report.hit_count == 2
    assert {hit.rule_id for hit in local_outcome.report.hits} == {"known_canary"}

    shared_outcome = scanner.scan_paths((global_reference.path,))
    assert shared_outcome.report.hits == ()
    identity_outcome = scanner.scan_paths((layout.identity_map,))
    assert {hit.rule_id for hit in identity_outcome.report.hits} == {
        "forbidden_path_suffix"
    }
    assert scanner.scan_paths((identity_lock,)).report.hits == ()
    catalog_outcome = scanner.scan_paths((layout.global_db,))
    assert {hit.rule_id for hit in catalog_outcome.report.hits} == {
        "forbidden_path_suffix",
        "stable_client_id",
    }
    assert sum(
        hit.rule_id == "stable_client_id" for hit in catalog_outcome.report.hits
    ) >= 2

    client_rows = _read_client_rows(layout.global_db)
    expected_rows = tuple(
        sorted(
            (
                record.client_id,
                record.directory_object_id,
                hmac.new(
                    ALIAS_LOOKUP_SECRET,
                    alias.casefold().encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest(),
                "ACTIVE",
            )
            for record, alias in ((record_a, alias_a), (record_b, alias_b))
        )
    )
    assert client_rows == expected_rows

    catalog_bytes = layout.global_db.read_bytes()
    for record in (record_a, record_b):
        assert record.client_id.encode("ascii") in catalog_bytes
        assert record.directory_object_id.encode("ascii") in catalog_bytes
    for private_value in (alias_a.encode(), alias_b.encode(), canary_a, canary_b):
        assert private_value not in catalog_bytes

    identity_ciphertext = layout.identity_map.read_bytes()
    private_needles = (
        record_a.client_id.encode("ascii"),
        record_b.client_id.encode("ascii"),
        record_a.directory_object_id.encode("ascii"),
        record_b.directory_object_id.encode("ascii"),
        alias_a.encode("utf-8"),
        alias_b.encode("utf-8"),
        canary_a,
        canary_b,
    )
    assert all(needle not in identity_ciphertext for needle in private_needles)
    identity_plaintext = harness.protector.unprotect(
        identity_ciphertext,
        purpose="identity_map",
        vault_id=VAULT_ID,
    )
    identity_payload = json.loads(identity_plaintext)
    entries = tuple(identity_payload["entries"].values())
    assert {
        (
            entry["alias"],
            entry["client_id"],
            entry["directory_object_id"],
            entry["state"],
        )
        for entry in entries
    } == {
        (alias_a, record_a.client_id, record_a.directory_object_id, "ACTIVE"),
        (alias_b, record_b.client_id, record_b.directory_object_id, "ACTIVE"),
    }

    projection_bytes, projection_counts = _read_manifest_projection(layout.global_db)
    assert projection_counts == {table: 1 for table in MANIFEST_TABLES}
    assert global_reference.path.read_bytes() == safe_payload
    shared_bytes = global_reference.path.read_bytes() + projection_bytes
    assert all(needle not in shared_bytes for needle in private_needles)

    local_a_bytes = b"".join(
        path.read_bytes()
        for path in private_files
        if path.is_relative_to(layout.clients_root / record_a.client_id)
    )
    local_b_bytes = b"".join(
        path.read_bytes()
        for path in private_files
        if path.is_relative_to(layout.clients_root / record_b.client_id)
    )
    assert canary_a in local_a_bytes and canary_b not in local_a_bytes
    assert canary_b in local_b_bytes and canary_a not in local_b_bytes


def test_real_global_publication_with_known_canary_is_detected(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    canary = ("SYNTH-CANARY-" + "ALPHA-9F3A").encode("ascii")
    harness = _build_harness(repo_root, tmp_path)
    try:
        reference = harness.publish_global(canary)
    finally:
        harness.close()

    layout = harness.layout
    vault = layout.clients_root.parent
    assert _files_below(vault) == {layout.global_db, reference.path}
    for nonexistent in (
        layout.identity_map,
        layout.identity_map.parent / ".identity-map.lock",
        layout.audit_root,
        vault / "backups",
        layout.global_db.parent / "logs",
        layout.global_db.parent / "temporary-backup",
    ):
        assert not nonexistent.exists()

    outcome = _privacy_scanner(repo_root).scan_paths((reference.path,))
    assert outcome.report.hit_count == 1
    assert {hit.rule_id for hit in outcome.report.hits} == {"known_canary"}
    projection_bytes, projection_counts = _read_manifest_projection(layout.global_db)
    assert projection_counts == {table: 1 for table in MANIFEST_TABLES}
    assert canary not in projection_bytes
    assert reference.path.read_bytes() == canary
