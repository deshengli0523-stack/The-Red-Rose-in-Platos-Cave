from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path

import pytest

from consultation_kb.approvals.provider import ProtectedProviderSecretStore
from consultation_kb.core.clock import SystemClock
from consultation_kb.core.config import AppConfig
from consultation_kb.mcp import (
    McpHandlerContext,
    TransportBindingRegistry,
    build_handler_registry,
)
from consultation_kb.mcp.client_creation_runtime import vault_security_id
from consultation_kb.mcp.runtime import ProductionRuntime
from consultation_kb.mcp.schemas import CreateClientInput
from consultation_kb.policy.loader import PolicyLoader
from consultation_kb.security.dpapi import create_secret_protector
from consultation_kb.security.ntfs_acl import AclPolicy
from consultation_kb.storage.catalog import ClientCatalog
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from tests.consultation_kb.risk_support import insert_approved_risk_policy_epoch


pytestmark = pytest.mark.integration


def _install_policy_bundle(repo: Path) -> None:
    source = Path(__file__).resolve().parents[3] / "policies"
    shutil.copytree(source, repo / "policies")


def _corrupted_secret_workspace(tmp_path: Path) -> tuple[AppConfig, bytes]:
    repo = tmp_path / "corrupt-repo"
    (repo / ".git").mkdir(parents=True)
    _install_policy_bundle(repo)
    vault = (tmp_path / "corrupt-vault").resolve()
    (vault / "clients").mkdir(parents=True)
    global_root = vault / "global"
    global_root.mkdir()
    connection = connect_database(
        global_root / "catalog.sqlite3",
        mode="writer",
    )
    try:
        MigrationRunner.for_scope(connection, "global").apply()
        risk_policy = PolicyLoader.from_config(
            AppConfig.from_values(repo, vault)
        ).load_all().risk_rules
        insert_approved_risk_policy_epoch(
            connection,
            risk_policy,
            epoch=1,
            suffix=919_000,
        )
    finally:
        connection.close()
    canary = b"PRIVATE-CORRUPTED-SECRET-CANARY"
    secret = vault / "security" / "review-agent-secret.dpapi"
    secret.parent.mkdir()
    secret.write_bytes(canary)
    return AppConfig.from_values(repo, vault), canary


def _secured_workspace(tmp_path: Path) -> tuple[AppConfig, Path]:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    _install_policy_bundle(repo)
    vault = (tmp_path / "vault").resolve()
    clients = vault / "clients"
    global_root = vault / "global"
    identity = vault / "identity"
    security = vault / "security"
    for directory in (clients, global_root, identity, security):
        directory.mkdir(parents=True)
    connection = connect_database(
        global_root / "catalog.sqlite3",
        mode="writer",
    )
    try:
        MigrationRunner.for_scope(connection, "global").apply()
        risk_policy = PolicyLoader.from_config(
            AppConfig.from_values(repo, vault)
        ).load_all().risk_rules
        insert_approved_risk_policy_epoch(
            connection,
            risk_policy,
            epoch=1,
            suffix=920_000,
        )
    finally:
        connection.close()

    acl = AclPolicy()
    for directory in (clients, identity, global_root, security):
        acl.apply(directory)
        acl.verify(directory)
    secret_path = security / "review-agent-secret.dpapi"
    ProtectedProviderSecretStore(
        secret_path,
        protector=create_secret_protector(),
        vault_id=vault_security_id(vault),
    ).initialize(random_source=lambda size: b"p" * size)
    return AppConfig.from_values(repo, vault), secret_path


@pytest.mark.skipif(sys.platform != "win32", reason="production DPAPI and NTFS ACL")
def test_production_runtime_executes_real_two_phase_client_creation(
    tmp_path: Path,
) -> None:
    config, secret_path = _secured_workspace(tmp_path)
    runtime = ProductionRuntime.open(config=config)
    try:
        assert runtime.knowledge_available
        assert runtime.client_creation_available
        router = runtime.handler_services.write
        preview = router.invoke(
            "create_client",
            CreateClientInput(
                action="preview",
                alias="Production Client Alias",
                idempotency_key="create-client:production-0001",
            ),
            binding=None,
        )
        preview_payload = preview.model_dump(mode="json")
        request_id = preview_payload["approval_request_id"]

        creation_runtime = router._client_creation
        creation_service = creation_runtime._service
        knowledge_runtime = router._knowledge
        assert creation_service._approval_service is knowledge_runtime._approvals
        assert (
            creation_service._execution_guard
            is knowledge_runtime._passages._executor._guard
        )
        assert creation_service._diff_ref_factory._store is knowledge_runtime._store

        challenge = creation_service._approval_service.challenge_for_review(
            request_id
        )
        signer = ProtectedProviderSecretStore(
            secret_path,
            protector=create_secret_protector(),
            vault_id=vault_security_id(config.vault_root),
        ).load_signer(clock=SystemClock())
        creation_service._approval_service.confirm(signer.confirm(challenge))

        committed = router.invoke(
            "create_client",
            CreateClientInput(
                action="commit",
                approval_request_id=request_id,
            ),
            binding=None,
        )
        committed_payload = committed.model_dump(mode="json")
        assert committed_payload == {
            "status": "active",
            "client_id": preview_payload["client_id"],
        }
        assert ClientCatalog(runtime._connection).get(
            committed_payload["client_id"]
        ).state == "ACTIVE"
        client_database = (
            config.vault_root
            / "clients"
            / committed_payload["client_id"]
            / "client.sqlite3"
        )
        reader = connect_database(client_database, mode="reader")
        try:
            MigrationRunner.for_scope(reader, "client").check()
        finally:
            reader.close()
    finally:
        runtime.close()


@pytest.mark.skipif(sys.platform != "win32", reason="production DPAPI")
def test_corrupted_protected_secret_degrades_only_global_write_channels(
    tmp_path: Path,
) -> None:
    config, secret_canary = _corrupted_secret_workspace(tmp_path)

    runtime = ProductionRuntime.open(config=config)
    try:
        assert not runtime.knowledge_available
        assert not runtime.client_creation_available
        registry = build_handler_registry(
            McpHandlerContext(
                transport_session_id="corrupted-secret-transport",
                bindings=TransportBindingRegistry(),
                services=runtime.handler_services,
            )
        )
        create = asyncio.run(
            registry["create_client"](
                {
                    "action": "preview",
                    "alias": "Corrupted Secret Client",
                    "idempotency_key": "create-client:corrupt-secret-0001",
                }
            )
        )
        knowledge = asyncio.run(registry["list_source_inbox"]({}))
        session = asyncio.run(
            registry["load_client_context"](
                {"client_id": "client_" + "aaaaaaaaaaaa"}
            )
        )

        for envelope in (create, knowledge):
            assert not envelope.ok
            assert envelope.error is not None
            assert envelope.error.code == "CHANNEL_UNAVAILABLE"
            assert envelope.error.safe_details == {}
        # The session service was composed and reached its normal closed
        # object boundary; it did not fail because the optional writer key did.
        assert not session.ok
        assert session.error is not None
        assert session.error.code == "SCOPE_DENIED"

        outward = "\n".join(
            envelope.model_dump_json()
            for envelope in (create, knowledge, session)
        )
        assert secret_canary.decode("ascii") not in outward
        assert str(config.vault_root) not in outward
        assert "ProviderSecretUnavailable" not in outward
        assert "review-agent-secret" not in outward
    finally:
        runtime.close()
