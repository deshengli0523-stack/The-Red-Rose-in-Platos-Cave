from __future__ import annotations

from pathlib import Path
from typing import Literal

from consultation_kb.cli import main
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner


def _migrate_database(
    path: Path,
    scope: Literal["global", "client"],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = connect_database(path, mode="writer")
    try:
        MigrationRunner.for_scope(connection, scope).apply()
    finally:
        connection.close()


def _run_check(repo: Path, vault: Path) -> int:
    return main(
        [
            "migrate",
            "--check",
            "--repo-root",
            str(repo),
            "--vault-root",
            str(vault),
        ]
    )


def _snapshot(vault: Path) -> dict[str, bytes]:
    return {
        path.relative_to(vault).as_posix(): path.read_bytes()
        for path in vault.rglob("*")
        if path.is_file()
    }


def test_migrate_check_missing_database_is_read_only(
    synthetic_workspace: tuple[Path, Path],
) -> None:
    repo, vault = synthetic_workspace
    global_database = vault / "global" / "catalog.sqlite3"

    exit_code = _run_check(repo, vault)

    assert exit_code == 2
    assert not global_database.exists()
    assert tuple(vault.rglob("*.sqlite3")) == ()


def test_migrate_check_validates_global_and_existing_client_without_writes(
    synthetic_workspace: tuple[Path, Path],
) -> None:
    repo, vault = synthetic_workspace
    _migrate_database(vault / "global" / "catalog.sqlite3", "global")
    _migrate_database(vault / "clients" / "client-a" / "client.sqlite3", "client")
    (vault / "clients" / ".staging").mkdir()
    before = _snapshot(vault)

    assert _run_check(repo, vault) == 0
    assert _snapshot(vault) == before


def test_migrate_check_rejects_behind_client_without_bootstrapping_it(
    synthetic_workspace: tuple[Path, Path],
) -> None:
    repo, vault = synthetic_workspace
    _migrate_database(vault / "global" / "catalog.sqlite3", "global")
    client_database = vault / "clients" / "client-a" / "client.sqlite3"
    client_database.parent.mkdir(parents=True)
    connection = connect_database(client_database, mode="writer")
    connection.close()
    before = _snapshot(vault)

    assert _run_check(repo, vault) == 2
    assert _snapshot(vault) == before


def test_migrate_check_rejects_checksum_mismatch_without_writes(
    synthetic_workspace: tuple[Path, Path],
) -> None:
    repo, vault = synthetic_workspace
    global_database = vault / "global" / "catalog.sqlite3"
    _migrate_database(global_database, "global")
    connection = connect_database(global_database, mode="writer")
    try:
        connection.execute(
            "UPDATE schema_migrations SET sha256 = ? WHERE version = 1",
            ("0" * 64,),
        )
    finally:
        connection.close()
    before = _snapshot(vault)

    assert _run_check(repo, vault) == 2
    assert _snapshot(vault) == before


def test_migrate_check_rejects_missing_active_client_database_without_creation(
    synthetic_workspace: tuple[Path, Path],
) -> None:
    repo, vault = synthetic_workspace
    global_database = vault / "global" / "catalog.sqlite3"
    _migrate_database(global_database, "global")
    connection = connect_database(global_database, mode="writer")
    try:
        connection.execute(
            """
            INSERT INTO clients(
                client_id, directory_object_id, alias_lookup_sha256,
                state, created_at, activated_at
            ) VALUES (?, ?, ?, 'ACTIVE', ?, ?)
            """,
            (
                "client-missing",
                "directory-object-distinct-from-client-id",
                "a" * 64,
                "2026-07-18T00:00:00Z",
                "2026-07-18T00:00:01Z",
            ),
        )
    finally:
        connection.close()
    expected_database = vault / "clients" / "client-missing" / "client.sqlite3"
    before = _snapshot(vault)

    assert _run_check(repo, vault) == 2
    assert not expected_database.exists()
    assert _snapshot(vault) == before
