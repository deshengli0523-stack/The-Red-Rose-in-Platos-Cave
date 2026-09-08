from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from consultation_kb.approvals.provider import ProtectedProviderSecretStore
from consultation_kb.core.clock import SystemClock
from consultation_kb.mcp import (
    McpHandlerContext,
    TransportBindingRegistry,
    build_handler_registry,
)
from consultation_kb.mcp.client_creation_runtime import vault_security_id
from consultation_kb.mcp.runtime import ProductionRuntime
from consultation_kb.mcp.schemas import (
    CommitDeleteInput,
    CreateClientInput,
    PreviewDeleteInput,
)
from consultation_kb.security.dpapi import create_secret_protector
from consultation_kb.storage.catalog import ClientCatalog
from tests.consultation_kb.integration.test_production_client_creation_composition import (
    _secured_workspace,
)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="production DPAPI and worker"),
]


def _create_client(
    runtime: ProductionRuntime,
    *,
    alias: str,
    idempotency_key: str,
    secret_path: Path,
) -> str:
    router = runtime.handler_services.write
    preview = router.invoke(
        "create_client",
        CreateClientInput(
            action="preview",
            alias=alias,
            idempotency_key=idempotency_key,
        ),
        binding=None,
    )
    payload = preview.model_dump(mode="json")
    service = router._client_creation.lifecycle_identity_registry
    signer = ProtectedProviderSecretStore(
        secret_path,
        protector=create_secret_protector(),
        vault_id=vault_security_id(secret_path.parents[1]),
    ).load_signer(clock=SystemClock())
    service._approval_service.confirm(
        signer.confirm(
            service._approval_service.challenge_for_review(
                str(payload["approval_request_id"])
            )
        )
    )
    committed = router.invoke(
        "create_client",
        CreateClientInput(
            action="commit",
            approval_request_id=str(payload["approval_request_id"]),
        ),
        binding=None,
    )
    return str(committed.model_dump(mode="json")["client_id"])


def test_real_mcp_current_client_delete_closes_worker_without_identity_fields(
    tmp_path: Path,
) -> None:
    config, secret_path = _secured_workspace(tmp_path)
    runtime = ProductionRuntime.open(config=config)
    client_a = ""
    client_b = ""
    try:
        client_a = _create_client(
            runtime,
            alias="Whole Client MCP A",
            idempotency_key="whole-client-mcp:create:a",
            secret_path=secret_path,
        )
        client_b = _create_client(
            runtime,
            alias="Whole Client MCP B",
            idempotency_key="whole-client-mcp:create:b",
            secret_path=secret_path,
        )
        b_canary = config.vault_root / "clients" / client_b / "b-canary.txt"
        b_canary.write_text("CLIENT_B_SURVIVES", encoding="ascii")
        registry = build_handler_registry(
            McpHandlerContext(
                transport_session_id="whole-client-production-mcp",
                bindings=TransportBindingRegistry(),
                services=runtime.handler_services,
            )
        )
        loaded = asyncio.run(
            registry["load_client_context"]({"client_id": client_a})
        )
        assert loaded.ok and isinstance(loaded.result, dict)
        handle = str(loaded.result["session_handle"])
        scope_sha256 = str(loaded.result["scope_sha256"])
        assert client_a not in str(loaded.result)

        public_preview_payload = {
            "session_handle": handle,
            "database_scope": "client",
            "scope_sha256": scope_sha256,
            "target_type": "client",
            "target_id": "current-client",
            "reason_code": "client_erasure_requested",
        }
        parsed = PreviewDeleteInput.model_validate(public_preview_payload)
        schema_text = str(parsed.model_json_schema())
        assert "client_id" not in schema_text
        assert "path" not in parsed.model_json_schema().get("properties", {})
        assert "sql" not in parsed.model_json_schema().get("properties", {})
        preview = asyncio.run(registry["preview_delete"](public_preview_payload))
        assert preview.ok and isinstance(preview.result, dict)
        outward_preview = str(preview.result)
        assert client_a not in outward_preview
        assert client_b not in outward_preview
        assert str(config.vault_root) not in outward_preview

        saga = runtime._sessions._whole_client_lifecycle
        assert saga is not None
        approval_authority = saga._authority(
            str(preview.result["target_scope_hash"])
        )
        signer = ProtectedProviderSecretStore(
            secret_path,
            protector=create_secret_protector(),
            vault_id=vault_security_id(config.vault_root),
        ).load_signer(clock=SystemClock())
        approval_authority.approval_service.confirm(
            signer.confirm(
                approval_authority.approval_service.challenge_for_review(
                    str(preview.result["approval_request_id"])
                )
            )
        )
        commit_payload = {
                    "session_handle": handle,
                    "database_scope": "client",
                    "scope_sha256": scope_sha256,
                    "approval_operation_id": preview.result[
                        "proposed_operation_id"
                    ],
                    "approval_request_id": preview.result[
                        "approval_request_id"
                    ],
                    "plan_sha256": preview.result["plan_sha256"],
                    "base_versions": preview.result["base_versions"],
                    "plan_ref": preview.result["plan_ref"],
                    "target_scope_hash": preview.result[
                        "target_scope_hash"
                    ],
                    "deletion_subject": "current_client",
                }
        CommitDeleteInput.model_validate(commit_payload)
        commit = asyncio.run(
            registry["commit_delete"](
                commit_payload
            )
        )

        assert commit.ok and isinstance(commit.result, dict)
        assert commit.result["status"] == "tombstone_committed"
        assert commit.result["client_scope_state"] == "closed"
        assert client_a not in str(commit.result)
        assert client_b not in str(commit.result)
        assert ClientCatalog(runtime._connection).get(client_a).state == "RETIRED"
        assert ClientCatalog(runtime._connection).get(client_b).state == "ACTIVE"
        assert (config.vault_root / "clients" / client_a).is_dir()
        assert b_canary.read_text(encoding="ascii") == "CLIENT_B_SURVIVES"

        denied = asyncio.run(registry["preview_delete"](public_preview_payload))
        assert not denied.ok and denied.error is not None
        assert denied.error.code == "SCOPE_DENIED"
    finally:
        runtime.close()

    # Startup replay may retry the pending physical saga, but it must never
    # reactivate A or touch B while global sibling/backup closure is incomplete.
    restarted = ProductionRuntime.open(config=config)
    try:
        catalog = ClientCatalog(restarted._connection)
        assert catalog.get(client_a).state == "RETIRED"
        assert catalog.get(client_b).state == "ACTIVE"
        assert (
            config.vault_root / "clients" / client_b / "b-canary.txt"
        ).read_text(encoding="ascii") == "CLIENT_B_SURVIVES"
    finally:
        restarted.close()
