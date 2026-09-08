"""Read-only Doctor probe for the local MCP surface and resumable sessions."""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import io
import json
import os
import stat
import tomllib
from contextlib import closing, redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Final, cast

from pydantic import TypeAdapter, ValidationError

from consultation_kb.core.config import AppConfig
from consultation_kb.core.doctor import DoctorCheck
from consultation_kb.models.common import Uuid7String
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner


_EXPECTED_TOOL_NAMES: Final = (
    "load_client_context",
    "search_client_history",
    "search_wiki",
    "search_lexical",
    "search_vector",
    "search_cases",
    "query_global_graph",
    "query_client_graph",
    "weighted_path",
    "preview_dependency_impact",
    "append_session_turn",
    "append_temporary_fact",
    "store_candidate_set",
    "record_actual_reply",
    "submit_generation_stage",
    "get_generation_state",
    "acknowledge_risk_observation",
    "list_source_inbox",
    "register_source_draft",
    "extract_passages",
    "propose_claims",
    "preview_claim_review",
    "propose_wiki_update",
    "preview_wiki_update",
    "knowledge_lint",
    "propose_theory_revision",
    "create_client",
    "approve_passage",
    "approve_claim",
    "revoke_claim",
    "publish_wiki",
    "approve_theory_revision",
    "revoke_theory_revision",
    "propose_archive",
    "preview_private_archive",
    "commit_private_archive",
    "preview_profile_diff",
    "commit_profile_update",
    "approve_case",
    "rollback_version",
    "start_rebuild",
    "get_rebuild_status",
    "get_rebuild_report",
    "cancel_rebuild",
    "preview_rebuild",
    "preview_delete",
    "commit_delete",
    "prepare_evaluation",
    "get_next_evaluation_case",
    "submit_evaluation_result",
    "finalize_evaluation",
)
_EXPECTED_TOOL_SCHEMA_SHA256: Final = (
    "99eff229f44d3b6b05ea12f2725b9f4d4fc284701b352d067ef34d064952f129"
)
_REPARSE_ATTRIBUTE: Final = 0x400
_SESSION_ID_ADAPTER: Final = TypeAdapter(Uuid7String)
_P5_SESSION_PERMISSIONS: Final = (
    "client_read",
    "draft_write",
    "session_append",
)


class _McpDiagnosticFailure(RuntimeError):
    pass


def _plain_directory(path: Path) -> bool:
    try:
        status = os.lstat(path)
    except OSError:
        return False
    attributes = int(getattr(status, "st_file_attributes", 0))
    return (
        stat.S_ISDIR(status.st_mode)
        and not stat.S_ISLNK(status.st_mode)
        and not attributes & _REPARSE_ATTRIBUTE
    )


def _plain_regular_file(path: Path) -> bool:
    try:
        status = os.lstat(path)
    except OSError:
        return False
    attributes = int(getattr(status, "st_file_attributes", 0))
    return (
        stat.S_ISREG(status.st_mode)
        and not stat.S_ISLNK(status.st_mode)
        and not attributes & _REPARSE_ATTRIBUTE
        and status.st_nlink == 1
    )


def _property_names(schema: object) -> set[str]:
    names: set[str] = set()
    if isinstance(schema, dict):
        properties = schema.get("properties")
        if isinstance(properties, dict):
            names.update(str(key) for key in properties)
        for value in schema.values():
            names.update(_property_names(value))
    elif isinstance(schema, list):
        for value in schema:
            names.update(_property_names(value))
    return names


def _verify_mcp_surface() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    try:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            server_module = importlib.import_module("consultation_kb.mcp.server")
            lifespan_module = importlib.import_module("consultation_kb.mcp.lifespan")
            deferred = lifespan_module.DeferredHandlerServices()
            server = server_module.create_mcp(services=deferred)
            tools = asyncio.run(server.list_tools())
    except Exception:
        raise _McpDiagnosticFailure from None
    if stdout.getvalue() or stderr.getvalue() or len(tools) != len(_EXPECTED_TOOL_NAMES):
        raise _McpDiagnosticFailure
    payloads = sorted(
        (tool.model_dump(mode="json", exclude_none=True) for tool in tools),
        key=lambda value: cast(str, value["name"]),
    )
    names = tuple(cast(str, value["name"]) for value in payloads)
    if tuple(sorted(_EXPECTED_TOOL_NAMES)) != names:
        raise _McpDiagnosticFailure
    for value in payloads:
        name = cast(str, value["name"])
        schema = value.get("inputSchema")
        properties = _property_names(schema)
        if properties & {"path", "root", "sql", "ticket", "nonce"}:
            raise _McpDiagnosticFailure
        if name == "load_client_context":
            if "client_id" not in properties:
                raise _McpDiagnosticFailure
        elif "client_id" in properties:
            raise _McpDiagnosticFailure
    canonical = json.dumps(
        payloads,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != _EXPECTED_TOOL_SCHEMA_SHA256:
        raise _McpDiagnosticFailure


def _verify_project_config(repo_root: Path) -> None:
    codex_root = repo_root / ".codex"
    template = codex_root / "config.template.toml"
    generated = codex_root / "config.toml"
    wrapper = codex_root / "start-consultation-kb.ps1"
    if (
        not _plain_directory(codex_root)
        or not _plain_regular_file(template)
        or not _plain_regular_file(generated)
        or not _plain_regular_file(wrapper)
    ):
        raise _McpDiagnosticFailure
    try:
        template_bytes = template.read_bytes()
        generated_bytes = generated.read_bytes()
        parsed_template = tomllib.loads(template_bytes.decode("utf-8", errors="strict"))
        parsed_generated = tomllib.loads(
            generated_bytes.decode("utf-8", errors="strict")
        )
        script = wrapper.read_text(encoding="utf-8")
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        raise _McpDiagnosticFailure from None
    if generated_bytes != template_bytes or parsed_generated != parsed_template:
        raise _McpDiagnosticFailure
    servers = parsed_generated.get("mcp_servers")
    if not isinstance(servers, dict) or set(servers) != {"consultation-kb"}:
        raise _McpDiagnosticFailure
    config = servers["consultation-kb"]
    expected = {
        "command": "powershell.exe",
        "args": [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            "start-consultation-kb.ps1",
        ],
        "cwd": ".",
        "startup_timeout_sec": 30,
        "tool_timeout_sec": 600,
        "required": True,
        "default_tools_approval_mode": "writes",
    }
    if config != expected:
        raise _McpDiagnosticFailure
    lowered = script.casefold()
    required_fragments = (
        "[console]::error.writeline",
        "$env:pythonunbuffered = \"1\"",
        "$env:hf_hub_offline = \"1\"",
        "& $pythonexe -i -x utf8 -m consultation_kb.mcp.server",
        "exit $lastexitcode",
    )
    if any(fragment not in lowered for fragment in required_fragments):
        raise _McpDiagnosticFailure
    if "write-output" in lowered or "write-host" in lowered:
        raise _McpDiagnosticFailure


def _p5_session_binding(value: object, permissions_json: object) -> bool:
    try:
        _SESSION_ID_ADAPTER.validate_python(value, strict=True)
        permissions = json.loads(cast(str, permissions_json))
    except (ValidationError, TypeError, ValueError):
        return False
    return (
        type(permissions_json) is str
        and type(permissions) is list
        and tuple(permissions) == _P5_SESSION_PERMISSIONS
        and permissions_json
        == json.dumps(
            list(_P5_SESSION_PERMISSIONS),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        )
    )


def _active_session_count(config: AppConfig) -> int:
    """Count recoverable P5 control-plane bindings without opening client DBs.

    A legacy client-scope ``sessions.state = 'OPEN'`` row is not a recovery
    authority: P5 recovery starts from the globally bound capability and then
    lets the scoped worker validate the complete private session record.
    """

    global_root = config.vault_root / "global"
    global_database = global_root / "catalog.sqlite3"
    if not os.path.lexists(global_database):
        return 0
    if not _plain_directory(global_root) or not _plain_regular_file(global_database):
        raise _McpDiagnosticFailure
    with closing(connect_database(global_database, mode="reader")) as connection:
        MigrationRunner.for_scope(connection, "global").check()
        rows = connection.execute(
            """
            SELECT capabilities.session_id, capabilities.permissions_json
              FROM capabilities
              JOIN clients USING(client_id)
             WHERE capabilities.state = 'ACTIVE'
               AND clients.state = 'ACTIVE'
             ORDER BY capabilities.session_id
            """
        ).fetchall()
    return sum(
        1
        for row in rows
        if len(row) == 2 and _p5_session_binding(row[0], row[1])
    )


class McpRuntimeDiagnosticProbe:
    """Validate MCP import/schema/config and count resumable sessions read-only."""

    name = "mcp_runtime"

    def run(self, config: AppConfig) -> DoctorCheck:
        if type(config) is not AppConfig:
            raise TypeError("MCP_DIAGNOSTIC_CONFIG_REQUIRED")
        try:
            _verify_mcp_surface()
            _verify_project_config(config.repo_root)
            active_sessions = _active_session_count(config)
        except Exception:
            return DoctorCheck(status="fail", code="mcp_runtime_invalid")
        return DoctorCheck(
            status="pass",
            code="mcp_runtime_verified",
            observed_count=active_sessions,
        )


__all__ = ["McpRuntimeDiagnosticProbe"]
