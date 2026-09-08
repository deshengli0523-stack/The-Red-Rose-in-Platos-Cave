from __future__ import annotations

import asyncio
import itertools
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.mcp import (
    HandlerServices,
    McpHandlerContext,
    P8_TOOL_NAMES,
    P9_TOOL_NAMES,
    TransportBindingRegistry,
    build_handler_registry,
)
from consultation_kb.mcp.context import BoundTransport
from consultation_kb.mcp.schemas import (
    CancelRebuildInput,
    LIFECYCLE_TOOL_INPUT_MODELS,
    RollbackVersionInput,
    StartRebuildInput,
    TOOL_INPUT_MODELS,
    ToolAccess,
)
from consultation_kb.models.common import StrictModel


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=UTC)
CLIENT_ID = "client" + "_aaaaaaaaaaaa"
HANDLE = "opaque-session-handle-p8-0001"
SCOPE_SHA256 = "a" * 64
PLAN_SHA256 = "b" * 64
_COUNTER = itertools.count(500)
_IDS = IdFactory(FixedClock(NOW), lambda: next(_COUNTER))


def _id(kind: str) -> str:
    return _IDS.object_id(kind)


def _properties(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        properties = value.get("properties")
        if isinstance(properties, dict):
            found.update(str(name) for name in properties)
        for nested in value.values():
            found.update(_properties(nested))
    elif isinstance(value, list):
        for nested in value:
            found.update(_properties(nested))
    return found


class _Service:
    def __init__(self) -> None:
        self.calls: list[tuple[str, StrictModel, BoundTransport | None]] = []

    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object:
        self.calls.append((tool_name, request, binding))
        if tool_name == "load_client_context":
            return {"session_handle": HANDLE, "snapshot_version": 1}
        if tool_name == "get_rebuild_status":
            return {"job_id": request.job_id, "state": "queued"}  # type: ignore[attr-defined]
        return {"status": "accepted", "tool": tool_name}


def _registry() -> tuple[_Service, object]:
    service = _Service()
    services = HandlerServices(
        read=service,
        graph=service,
        session=service,
        knowledge=service,
        write=service,
    )
    registry = build_handler_registry(
        McpHandlerContext(
            transport_session_id="stdio-p8-lifecycle",
            bindings=TransportBindingRegistry(),
            services=services,
        )
    )
    return service, registry


def _start_payload() -> dict[str, object]:
    return {
        "session_handle": HANDLE,
        "database_scope": "client",
        "scope_sha256": SCOPE_SHA256,
        "approval_operation_id": _id("approval_operation"),
        "approval_request_id": _id("approval_request"),
        "plan_sha256": PLAN_SHA256,
        "plan_ref": {
            "object_id": _id("lifecycle_plan"),
            "version": 1,
            "content_sha256": "c" * 64,
            "media_type": "application/json",
            "size_bytes": 256,
        },
        "base_versions": (
            {
                "authority_key": "tombstone_epoch",
                "scope_sha256": SCOPE_SHA256,
                "version": 3,
            },
        ),
        "idempotency_key": "client-profile-rebuild-once",
    }


def test_p8_registry_assigns_read_draft_and_formal_lifecycle_access() -> None:
    _service, registry = _registry()

    assert tuple(registry) == P9_TOOL_NAMES  # type: ignore[arg-type]
    assert tuple(LIFECYCLE_TOOL_INPUT_MODELS) == P8_TOOL_NAMES[-8:]
    expected = {
        "rollback_version": ToolAccess.FORMAL_WRITE,
        "start_rebuild": ToolAccess.FORMAL_WRITE,
        "get_rebuild_status": ToolAccess.READ,
        "get_rebuild_report": ToolAccess.READ,
        "cancel_rebuild": ToolAccess.FORMAL_WRITE,
        "preview_rebuild": ToolAccess.DRAFT_WRITE,
        "preview_delete": ToolAccess.DRAFT_WRITE,
        "commit_delete": ToolAccess.FORMAL_WRITE,
    }
    for name, access in expected.items():
        handler = registry[name]  # type: ignore[index]
        assert handler.annotations.access is access
        assert handler.annotations.approval_required is (
            access is ToolAccess.FORMAL_WRITE
        )
        assert handler.annotations.read_only is (access is ToolAccess.READ)
        assert handler.annotations.destructive is (
            access is ToolAccess.FORMAL_WRITE
        )


def test_lifecycle_schemas_require_plan_approval_base_versions_and_no_locator() -> None:
    forbidden = {"client", "client_id", "path", "root", "sql", "ticket", "nonce"}
    for name, model in LIFECYCLE_TOOL_INPUT_MODELS.items():
        schema = model.model_json_schema()
        assert _properties(schema).isdisjoint(forbidden), name
        assert schema.get("additionalProperties") is False

    start = StartRebuildInput.model_validate(_start_payload())
    assert start.plan_sha256 == PLAN_SHA256
    assert start.base_versions[0].version == 3
    for removed in (
        "approval_operation_id",
        "approval_request_id",
        "plan_sha256",
        "base_versions",
        "plan_ref",
    ):
        invalid = _start_payload()
        invalid.pop(removed)
        with pytest.raises(ValidationError):
            StartRebuildInput.model_validate(invalid)
    with pytest.raises(ValidationError):
        StartRebuildInput.model_validate(
            {**_start_payload(), "path": "C:/vault/client.sqlite3"}
        )

    extra_base = _start_payload()
    extra_base["base_versions"] = (
        *extra_base["base_versions"],  # type: ignore[misc]
        {
            "authority_key": "unrelated_epoch",
            "scope_sha256": "c" * 64,
            "version": 9,
        },
    )
    with pytest.raises(ValidationError, match="single tombstone epoch"):
        StartRebuildInput.model_validate(extra_base)

    cancel = {
        key: value
        for key, value in _start_payload().items()
        if key
        in {
            "session_handle",
            "database_scope",
            "scope_sha256",
            "approval_operation_id",
            "approval_request_id",
            "plan_sha256",
            "base_versions",
            "plan_ref",
        }
    }
    cancel["base_versions"] = extra_base["base_versions"]
    with pytest.raises(ValidationError, match="single tombstone epoch"):
        CancelRebuildInput.model_validate(cancel)


def test_read_status_is_scoped_but_does_not_require_write_approval() -> None:
    service, registry = _registry()
    job_id = _id("rebuild_job")
    payload = {
        "session_handle": HANDLE,
        "database_scope": "client",
        "scope_sha256": SCOPE_SHA256,
        "job_id": job_id,
    }

    denied = asyncio.run(registry["get_rebuild_status"](payload))  # type: ignore[index]
    assert not denied.ok
    assert denied.error is not None and denied.error.code == "SCOPE_DENIED"
    assert not service.calls

    loaded = asyncio.run(
        registry["load_client_context"]({"client_id": CLIENT_ID})  # type: ignore[index]
    )
    assert loaded.ok
    status = asyncio.run(registry["get_rebuild_status"](payload))  # type: ignore[index]

    assert status.ok
    assert status.result == {"job_id": job_id, "state": "queued"}
    assert service.calls[-1][2] == BoundTransport(
        "stdio-p8-lifecycle",
        HANDLE,
    )


def test_rollback_schema_strictly_separates_preview_and_commit_payloads() -> None:
    base = _start_payload()
    scope = {
        key: base[key]
        for key in (
            "session_handle",
            "database_scope",
            "scope_sha256",
        )
    }
    preview = RollbackVersionInput(
        **scope,  # type: ignore[arg-type]
        action="preview",
        target_kind="wiki",
        target_id=_id("wiki"),
        current_version=4,
        restore_version=2,
        reason="restore the reviewed historical revision",
    )
    assert preview.restore_version < preview.current_version
    with pytest.raises(ValidationError):
        RollbackVersionInput.model_validate(
            {
                **preview.model_dump(mode="json", exclude_none=True),
                "restore_version": preview.current_version,
            }
        )
    with pytest.raises(ValidationError):
        RollbackVersionInput.model_validate(
            {
                **preview.model_dump(mode="json", exclude_none=True),
                "plan_sha256": PLAN_SHA256,
            }
        )
    with pytest.raises(ValidationError):
        RollbackVersionInput.model_validate(
            {
                **preview.model_dump(mode="json", exclude_none=True),
                "source_plan_ref": base["plan_ref"],
            }
        )
    artifact_preview = RollbackVersionInput.model_validate(
        {
            **preview.model_dump(mode="json", exclude_none=True),
            "target_kind": "artifact",
            "target_id": "client_profile",
            "source_plan_ref": base["plan_ref"],
        }
    )
    assert artifact_preview.source_plan_ref is not None
    assert artifact_preview.source_plan_ref.model_dump(mode="json") == base[
        "plan_ref"
    ]
    with pytest.raises(ValidationError):
        RollbackVersionInput.model_validate(
            {
                **artifact_preview.model_dump(mode="json", exclude_none=True),
                "source_plan_ref": None,
            }
        )

    commit = RollbackVersionInput(
        **scope,  # type: ignore[arg-type]
        action="commit",
        plan_ref=base["plan_ref"],  # type: ignore[arg-type]
        approval_operation_id=base["approval_operation_id"],  # type: ignore[arg-type]
        approval_request_id=base["approval_request_id"],  # type: ignore[arg-type]
        plan_sha256=base["plan_sha256"],  # type: ignore[arg-type]
        base_versions=base["base_versions"],  # type: ignore[arg-type]
    )
    assert commit.plan_ref is not None
    with pytest.raises(ValidationError):
        RollbackVersionInput.model_validate(
            {
                **commit.model_dump(mode="json", exclude_none=True),
                "target_kind": "wiki",
            }
        )
    with pytest.raises(ValidationError):
        RollbackVersionInput.model_validate(
            {
                **commit.model_dump(mode="json", exclude_none=True),
                "source_plan_ref": base["plan_ref"],
            }
        )

    assert set(TOOL_INPUT_MODELS).issuperset(LIFECYCLE_TOOL_INPUT_MODELS)


@pytest.mark.parametrize(
    "arguments",
    (
        ("recover", "--apply", "--json"),
        (
            "rebuild-start",
            "--purpose",
            "all",
            "--database-ref-sha256",
            "f" * 64,
            "--apply",
            "--json",
        ),
    ),
)
def test_cli_formal_lifecycle_operations_fail_closed_without_signed_approval(
    arguments: tuple[str, ...],
    capsys: pytest.CaptureFixture[str],
) -> None:
    from consultation_kb import cli

    assert cli.main(arguments) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "ok": False,
        "code": "LIFECYCLE_APPROVAL_REQUIRED",
    }
    assert "LIFECYCLE_APPROVAL_REQUIRED" in captured.err


def test_cli_rebuild_start_rejects_partial_root_purpose() -> None:
    from consultation_kb import cli

    with pytest.raises(SystemExit) as rejected:
        cli.main(
            (
                "rebuild-start",
                "--purpose",
                "wiki_index",
                "--database-ref-sha256",
                "f" * 64,
            )
        )
    assert rejected.value.code == 2


def test_cli_read_only_report_preview_and_delete_status_use_opaque_global_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from consultation_kb import cli
    from consultation_kb.lifecycle.production_rebuild import (
        CONFIG_FILENAME,
        ProductionRebuildConfig,
        resolve_global_rebuild,
    )
    from consultation_kb.lifecycle.rebuild import RebuildRequest
    from consultation_kb.security.scope_identity import (
        global_approval_scope_sha256,
    )
    from consultation_kb.storage.connection import connect_database
    from consultation_kb.storage.migrate import MigrationRunner
    from tests.consultation_kb.retrieval_support import model_descriptor

    vault = tmp_path / "vault"
    database = vault / "global" / "catalog.sqlite3"
    database.parent.mkdir(parents=True)
    connection = connect_database(database, "writer")
    try:
        MigrationRunner.for_scope(connection, "global").apply()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()
    approval_scope = global_approval_scope_sha256(vault.resolve())
    rebuild_config = ProductionRebuildConfig.create_global(
        scope_sha256=approval_scope,
        model_descriptor=model_descriptor(),
        embedder_kind="deterministic_test",
        deterministic_vocabulary={"synthetic": (1.0, 0.0)},
        test_mode=True,
        graphify_production=False,
    )
    (database.parent / CONFIG_FILENAME).write_bytes(rebuild_config.canonical_bytes)
    wal_keeper = connect_database(database, "writer")
    assert database.with_name(database.name + "-shm").exists()
    monkeypatch.setattr(
        cli,
        "_resolved_config",
        lambda _args: SimpleNamespace(vault_root=vault),
    )

    assert cli.main(("recovery-report", "--json")) == 0
    report = json.loads(capsys.readouterr().out)
    reference = report["database_ref_sha256"]
    assert report["database_scope"] == "global"
    assert report["startup_health"] == "HEALTHY"
    assert "path" not in report

    assert cli.main(
        (
            "rebuild-start",
            "--purpose",
            "all",
            "--database-ref-sha256",
            reference,
            "--json",
        )
    ) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["status"] == "preview"
    assert preview["approval_required"] is True
    assert preview["scope_sha256"] == approval_scope
    assert preview["scope_sha256"] != reference
    assert preview["builder_ids"] == [
        "c1_revision",
        "claims",
        "wiki_page",
        "wiki_index",
        "knowledge_registry",
        "graph",
        "lexical",
        "vector",
    ]
    assert preview["policy_sha256"] == rebuild_config.policy_sha256
    assert preview["base_versions"][0]["authority_key"] == "tombstone_epoch"
    assert preview["base_versions"][0]["scope_sha256"] == approval_scope
    with cli._guarded_live_reader(vault, database) as snapshot:
        exact_plan = resolve_global_rebuild(
            snapshot,
            database.parent.resolve(),
            approval_scope,
        ).plan(
            RebuildRequest(
                database_scope="global",
                scope_sha256=approval_scope,
                purpose="all",
                policy_sha256=rebuild_config.policy_sha256,
                model_descriptor_sha256=(
                    rebuild_config.model_descriptor_sha256
                ),
            )
        )
    assert preview["plan_sha256"] == exact_plan.plan_sha256

    assert cli.main(
        (
            "delete-status",
            "--database-ref-sha256",
            reference,
            "--json",
        )
    ) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["requests"] == []
    assert status["database_ref_sha256"] == reference
    wal_keeper.close()
