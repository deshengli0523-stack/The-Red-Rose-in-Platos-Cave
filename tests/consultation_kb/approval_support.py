from __future__ import annotations

import hashlib
import itertools
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

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
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import VersionRef
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner


NOW = datetime(2026, 7, 18, 8, 0, tzinfo=timezone.utc)
TARGET_SCOPE_HASH = "a" * 64
DIFF_BYTES = b"verified synthetic diff\n"


class MutableClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class TestProtector:
    def _context(self, *, purpose: str, vault_id: str) -> bytes:
        return hashlib.sha256(f"{vault_id}\0{purpose}".encode("utf-8")).digest()

    def protect(
        self,
        data: bytes,
        *,
        purpose: str,
        vault_id: str,
    ) -> bytes:
        context = self._context(purpose=purpose, vault_id=vault_id)
        return context + bytes(
            value ^ context[index % len(context)] for index, value in enumerate(data)
        )

    def unprotect(
        self,
        blob: bytes,
        *,
        purpose: str,
        vault_id: str,
    ) -> bytes:
        context = self._context(purpose=purpose, vault_id=vault_id)
        if len(blob) < len(context) or blob[: len(context)] != context:
            raise ValueError("wrong protection context")
        payload = blob[len(context) :]
        return bytes(
            value ^ context[index % len(context)] for index, value in enumerate(payload)
        )


@dataclass
class ApprovalHarness:
    global_connection: sqlite3.Connection
    target_connection: sqlite3.Connection
    clock: MutableClock
    ids: IdFactory
    signer: LocalHmacApprovalSigner
    verifier: LocalHmacApprovalVerifier
    service: ApprovalService
    guard: ApprovalExecutionGuard

    def draft(self) -> DraftDescriptor:
        return DraftDescriptor(
            purpose="profile_update",
            target_id="synthetic-profile",
            client_id="client_" + "a" * 12,
            base_version=0,
            draft_sha256="1" * 64,
            session_id=self.ids.uuid7(),
        )

    def operation_id(self) -> str:
        return self.ids.object_id("approval_operation")

    def diff_object_ref(self) -> VersionRef:
        return VersionRef(
            object_id=self.ids.object_id("approval_diff"),
            version=1,
            content_sha256=hashlib.sha256(DIFF_BYTES).hexdigest(),
        )

    def close(self) -> None:
        self.target_connection.close()
        self.global_connection.close()


def build_approval_harness(
    tmp_path: Path,
    *,
    target_scope_hash: str = TARGET_SCOPE_HASH,
) -> ApprovalHarness:
    global_connection = connect_database(tmp_path / "global.sqlite3", mode="writer")
    target_connection = connect_database(tmp_path / "client.sqlite3", mode="writer")
    MigrationRunner.for_scope(global_connection, "global").apply()
    MigrationRunner.for_scope(target_connection, "client").apply()
    target_connection.execute(
        "CREATE TABLE synthetic_business(id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
    )
    clock = MutableClock()
    random_values = itertools.count(1)
    nonce_values = itertools.count(1)
    ids = IdFactory(clock, lambda: next(random_values))
    signer = LocalHmacApprovalSigner(
        secret=b"p" * 32,
        provider_id="local-review-agent",
        clock=clock,
    )
    verifier = LocalHmacApprovalVerifier(
        secret=b"p" * 32,
        provider_id="local-review-agent",
    )
    service = ApprovalService(
        global_connection,
        provider=verifier,
        protector=TestProtector(),
        clock=clock,
        id_factory=ids,
        target_scope_hash=target_scope_hash,
        vault_id="synthetic-vault",
        execution_secret=b"e" * 32,
        execution_proof_verifier=LocalHmacTargetExecutionProofVerifier(
            secret=b"t" * 32,
            attestor_id="test-target-writer",
        ),
        nonce_source=lambda size: next(nonce_values).to_bytes(size, "big"),
    )
    guard = ApprovalExecutionGuard(
        target_connection,
        approval_service=service,
        execution_proof_signer=LocalHmacTargetExecutionAttestor(
            secret=b"t" * 32,
            attestor_id="test-target-writer",
        ),
        clock=clock,
    )
    return ApprovalHarness(
        global_connection=global_connection,
        target_connection=target_connection,
        clock=clock,
        ids=ids,
        signer=signer,
        verifier=verifier,
        service=service,
        guard=guard,
    )
