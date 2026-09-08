from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from consultation_kb.core.config import AppConfig
from consultation_kb.operations import mcp_doctor_probe
from consultation_kb.operations.mcp_doctor_probe import McpRuntimeDiagnosticProbe
from consultation_kb.storage.catalog import ClientCatalog
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner


CLIENT_ID = "client_" + "a1b2c3d4e5f6"
SESSION_ID = "018f0000-0000-7000-8000-000000000001"


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()
    source = Path(__file__).resolve().parents[3] / ".codex"
    target = root / ".codex"
    target.mkdir()
    for name in ("config.template.toml", "start-consultation-kb.ps1"):
        shutil.copyfile(source / name, target / name)
    shutil.copyfile(source / "config.template.toml", target / "config.toml")
    return root


def _vault_with_open_session(tmp_path: Path) -> Path:
    vault = tmp_path / "vault"
    global_root = vault / "global"
    clients_root = vault / "clients"
    global_root.mkdir(parents=True)
    clients_root.mkdir()
    global_connection = connect_database(
        global_root / "catalog.sqlite3",
        mode="writer",
    )
    MigrationRunner.for_scope(global_connection, "global").apply()
    catalog = ClientCatalog(global_connection)
    now = datetime(2026, 7, 19, tzinfo=timezone.utc)
    catalog.prepare(
        client_id=CLIENT_ID,
        directory_object_id="client-directory-object",
        alias_lookup_sha256="a" * 64,
        created_at=now,
    )
    catalog.activate(CLIENT_ID, activated_at=now)
    global_connection.execute(
        """
        INSERT INTO capabilities(
            capability_id, token_sha256, session_id, client_id,
            permissions_json, issued_at, expires_at, revoked_at,
            state, capability_epoch
        ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'ACTIVE', 1)
        """,
        (
            "capability-p5-session",
            "c" * 64,
            SESSION_ID,
            CLIENT_ID,
            '["client_read","draft_write","session_append"]',
            "2026-07-19T00:00:00.000000Z",
            "2026-07-19T01:00:00.000000Z",
        ),
    )
    global_connection.execute(
        """
        INSERT INTO capabilities(
            capability_id, token_sha256, session_id, client_id,
            permissions_json, issued_at, expires_at, revoked_at,
            state, capability_epoch
        ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'ACTIVE', 1)
        """,
        (
            "capability-legacy-session",
            "d" * 64,
            "session-open",
            CLIENT_ID,
            '["client_read","draft_write","session_append"]',
            "2026-07-19T00:00:00.000000Z",
            "2026-07-19T01:00:00.000000Z",
        ),
    )
    global_connection.commit()
    global_connection.close()
    client_root = clients_root / CLIENT_ID
    client_root.mkdir()
    client_connection = connect_database(
        client_root / "client.sqlite3",
        mode="writer",
    )
    MigrationRunner.for_scope(client_connection, "client").apply()
    client_connection.execute(
        """
        INSERT INTO sessions(session_id, client_scope_hash, state, started_at)
        VALUES ('session-open', ?, 'OPEN', '2026-07-19T00:00:00.000000Z')
        """,
        ("b" * 64,),
    )
    client_connection.execute(
        """
        INSERT INTO sessions(
            session_id, client_scope_hash, state, started_at, closed_at,
            client_id, client_snapshot_version,
            client_snapshot_canonical_sha256,
            client_snapshot_object_id, client_snapshot_sha256,
            client_snapshot_media_type, client_snapshot_size_bytes,
            capability_epoch, last_closed_turn_ordinal,
            archive_state, updated_at
        ) VALUES (?, ?, 'OPEN', ?, NULL, ?, 1, ?, ?, ?, 'application/json',
                  2, 1, 0, 'NOT_STARTED', ?)
        """,
        (
            SESSION_ID,
            "e" * 64,
            "2026-07-19T00:00:00.000000Z",
            CLIENT_ID,
            "f" * 64,
            "snapshot-object",
            "1" * 64,
            "2026-07-19T00:00:00.000000Z",
        ),
    )
    client_connection.commit()
    client_connection.close()
    return vault


def test_mcp_doctor_verifies_surface_config_and_reports_open_sessions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = AppConfig.from_values(_repo(tmp_path), _vault_with_open_session(tmp_path))
    real_connect = mcp_doctor_probe.connect_database
    opened: list[Path] = []

    def tracked_connect(path: Path, *, mode: str):  # type: ignore[no-untyped-def]
        opened.append(path)
        if path.name == "client.sqlite3":
            raise AssertionError("the Doctor control process opened a client database")
        return real_connect(path, mode=mode)

    monkeypatch.setattr(mcp_doctor_probe, "connect_database", tracked_connect)

    result = McpRuntimeDiagnosticProbe().run(config)

    assert result.status == "pass"
    assert result.code == "mcp_runtime_verified"
    assert result.observed_count == 1
    assert opened == [config.vault_root / "global" / "catalog.sqlite3"]


def test_mcp_doctor_fails_closed_on_wrapper_stdout_drift(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    vault = tmp_path / "vault"
    vault.mkdir()
    wrapper = repo / ".codex" / "start-consultation-kb.ps1"
    wrapper.write_text(
        wrapper.read_text(encoding="utf-8") + '\nWrite-Output "leak"\n',
        encoding="utf-8",
    )

    result = McpRuntimeDiagnosticProbe().run(AppConfig.from_values(repo, vault))

    assert result.status == "fail"
    assert result.code == "mcp_runtime_invalid"


@pytest.mark.parametrize("generated_state", ["missing", "drifted"])
def test_mcp_doctor_checks_the_generated_codex_config_not_only_the_template(
    tmp_path: Path,
    generated_state: str,
) -> None:
    repo = _repo(tmp_path)
    generated = repo / ".codex" / "config.toml"
    if generated_state == "missing":
        generated.unlink()
    else:
        generated.write_text(
            generated.read_text(encoding="utf-8").replace(
                "tool_timeout_sec = 600",
                "tool_timeout_sec = 601",
            ),
            encoding="utf-8",
        )
    vault = tmp_path / "vault"
    vault.mkdir()

    result = McpRuntimeDiagnosticProbe().run(AppConfig.from_values(repo, vault))

    assert result.status == "fail"
    assert result.code == "mcp_runtime_invalid"
