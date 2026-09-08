from __future__ import annotations

import itertools
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from mcp import StdioServerParameters
from mcp.types import CallToolResult

from consultation_kb.core.client_ids import ClientIdFactory
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.config import AppConfig
from consultation_kb.core.ids import IdFactory
from consultation_kb.policy.loader import PolicyLoader
from consultation_kb.storage.catalog import ClientCatalog
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from tests.consultation_kb.risk_support import insert_approved_risk_policy_epoch


NOW = datetime(2026, 7, 19, 10, 0, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class McpVaultHarness:
    repo_root: Path
    vault_root: Path
    global_database: Path
    client_a: str
    client_b: str
    client_a_root: Path
    client_b_root: Path
    client_b_canary: str

    def parameters(self) -> StdioServerParameters:
        return StdioServerParameters(
            command=sys.executable,
            args=["-I", "-X", "utf8", "-m", "consultation_kb.mcp.server"],
            cwd=self.repo_root,
            env={
                "CONSULTATION_VAULT_ROOT": str(self.vault_root),
                "PYTHONUTF8": "1",
                "PYTHONUNBUFFERED": "1",
                "HF_HUB_OFFLINE": "1",
                "TRANSFORMERS_OFFLINE": "1",
                "HF_DATASETS_OFFLINE": "1",
            },
        )


def build_mcp_vault(tmp_path: Path) -> McpVaultHarness:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    shutil.copytree(Path(__file__).resolve().parents[2] / "policies", repo / "policies")
    vault = tmp_path / "knowledge-vault"
    clients_root = vault / "clients"
    global_root = vault / "global"
    clients_root.mkdir(parents=True)
    global_root.mkdir()
    global_database = global_root / "catalog.sqlite3"
    global_connection = connect_database(global_database, mode="writer")
    MigrationRunner.for_scope(global_connection, "global").apply()
    risk_policy = PolicyLoader.from_config(
        AppConfig.from_values(repo, vault)
    ).load_all().risk_rules
    insert_approved_risk_policy_epoch(
        global_connection,
        risk_policy,
        epoch=1,
        suffix=916_000,
    )
    ids = IdFactory(FixedClock(NOW), itertools.count(1).__next__)
    clients = ClientIdFactory(
        suffix_source=iter(("a1b2c3d4e5f6", "b1b2c3d4e5f6")).__next__
    )
    client_a = clients.new()
    client_b = clients.new()
    catalog = ClientCatalog(global_connection)
    roots: dict[str, Path] = {}
    for index, client_id in enumerate((client_a, client_b), start=1):
        record = catalog.prepare(
            client_id=client_id,
            directory_object_id=ids.object_id("client_directory"),
            alias_lookup_sha256=f"{index}" * 64,
            created_at=NOW,
        )
        catalog.activate(client_id, activated_at=NOW)
        root = clients_root / client_id
        root.mkdir()
        roots[client_id] = root
        (root / ".scope-id").write_bytes(
            f"{record.directory_object_id}\n".encode("ascii")
        )
        connection = connect_database(root / "client.sqlite3", mode="writer")
        try:
            MigrationRunner.for_scope(connection, "client").apply()
        finally:
            connection.close()
    global_connection.close()
    canary = "CLIENT-B-PRIVATE-MCP-CANARY-7f14"
    (roots[client_b] / "private-canary.txt").write_text(
        canary,
        encoding="utf-8",
    )
    return McpVaultHarness(
        repo_root=repo,
        vault_root=vault,
        global_database=global_database,
        client_a=client_a,
        client_b=client_b,
        client_a_root=roots[client_a],
        client_b_root=roots[client_b],
        client_b_canary=canary,
    )


def envelope(result: CallToolResult) -> dict[str, Any]:
    assert not result.isError
    assert result.structuredContent is not None
    payload = result.structuredContent
    assert set(payload) == {"ok", "result", "error"}
    return payload


def diagnostics(stderr: TextIO) -> str:
    stderr.flush()
    stderr.seek(0)
    return stderr.read()


__all__ = [
    "McpVaultHarness",
    "NOW",
    "build_mcp_vault",
    "diagnostics",
    "envelope",
]
