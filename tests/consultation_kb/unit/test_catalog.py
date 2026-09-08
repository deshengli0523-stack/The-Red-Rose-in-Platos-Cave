from __future__ import annotations

import multiprocessing
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from consultation_kb.core.client_ids import ClientIdFactory
from consultation_kb.storage.catalog import (
    ClientCatalog,
    ClientCatalogConflict,
    ClientCreationFailed,
    ClientNotFound,
    _identity_map_write_lock,
)
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner


NOW = datetime(2026, 7, 18, 9, 0, tzinfo=timezone.utc)
CLIENT_A = "client_" + "a1b2c3d4e5f6"
CLIENT_B = "client_" + "b1b2c3d4e5f6"
CLIENT_NEAR = "client_" + "a1b2c3d4e5f7"


def _increment_under_identity_lock(
    identity_map: str,
    counter_path: str,
    started: object,
    entered: object,
    release: object,
    result: object,
) -> None:
    """Spawn target proving the identity-map lock spans read/modify/write."""

    try:
        started.set()  # type: ignore[attr-defined]
        with _identity_map_write_lock(Path(identity_map)):
            counter = Path(counter_path)
            value = int(counter.read_text(encoding="ascii"))
            entered.set()  # type: ignore[attr-defined]
            if not release.wait(10.0):  # type: ignore[attr-defined]
                raise RuntimeError("release timeout")
            counter.write_text(str(value + 1), encoding="ascii")
        result.put(None)  # type: ignore[attr-defined]
    except BaseException as error:
        result.put(f"{type(error).__name__}:{error}")  # type: ignore[attr-defined]


def _catalog(tmp_path: Path) -> tuple[ClientCatalog, object]:
    connection = connect_database(tmp_path / "global.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    return ClientCatalog(connection), connection


def test_client_id_factory_uses_only_canonical_service_generated_ids() -> None:
    factory = ClientIdFactory(suffix_source=lambda: "a1b2c3d4e5f6")

    assert factory.new() == CLIENT_A
    assert re.fullmatch(r"client_[a-z0-9]{12}", factory.new()) is not None


@pytest.mark.parametrize("suffix", ["SHORT", "abcdefghijkl!", "abcdefghijklM", 1])
def test_client_id_factory_rejects_invalid_random_source(suffix: object) -> None:
    factory = ClientIdFactory(suffix_source=lambda: suffix)  # type: ignore[arg-type,return-value]

    with pytest.raises(ValueError, match="CLIENT_ID_GENERATION_FAILED"):
        factory.new()


def test_catalog_prepare_activate_and_exact_lookup(tmp_path: Path) -> None:
    catalog, connection = _catalog(tmp_path)
    try:
        prepared = catalog.prepare(
            client_id=CLIENT_A,
            directory_object_id="client_directory_01800000-0000-7000-8000-000000000001",
            alias_lookup_sha256="a" * 64,
            created_at=NOW,
        )
        assert prepared.state == "PREPARED"
        active = catalog.activate(prepared.client_id, activated_at=NOW)
        assert active.state == "ACTIVE"
        assert catalog.get(prepared.client_id) == active

        with pytest.raises(ClientNotFound):
            catalog.get("CLIENT_" + "a1b2c3d4e5f6")
        with pytest.raises(ClientNotFound):
            catalog.get(CLIENT_NEAR)
    finally:
        connection.close()  # type: ignore[union-attr]


def test_catalog_rejects_duplicate_alias_hash_without_storing_identity(
    tmp_path: Path,
) -> None:
    catalog, connection = _catalog(tmp_path)
    try:
        catalog.prepare(
            client_id=CLIENT_A,
            directory_object_id="client_directory_01800000-0000-7000-8000-000000000001",
            alias_lookup_sha256="b" * 64,
            created_at=NOW,
        )
        with pytest.raises(ClientCatalogConflict):
            catalog.prepare(
                client_id=CLIENT_B,
                directory_object_id=(
                    "client_directory_01800000-0000-7000-8000-000000000002"
                ),
                alias_lookup_sha256="b" * 64,
                created_at=NOW,
            )

        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(clients)")
        }
        assert columns == {
            "client_id",
            "directory_object_id",
            "alias_lookup_sha256",
            "state",
            "created_at",
            "activated_at",
        }
        serialized_rows = repr(connection.execute("SELECT * FROM clients").fetchall())
        assert "real person" not in serialized_rows
        assert "transcript" not in serialized_rows
    finally:
        connection.close()  # type: ignore[union-attr]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows file locking")
def test_identity_map_read_modify_write_is_serialized_between_processes(
    tmp_path: Path,
) -> None:
    identity_map = tmp_path / "identity" / "identity-map.enc"
    identity_map.parent.mkdir()
    counter = tmp_path / "counter.txt"
    counter.write_text("0", encoding="ascii")
    context = multiprocessing.get_context("spawn")
    started_first = context.Event()
    entered_first = context.Event()
    release_first = context.Event()
    started_second = context.Event()
    entered_second = context.Event()
    release_second = context.Event()
    result = context.Queue()
    first = context.Process(
        target=_increment_under_identity_lock,
        args=(
            str(identity_map),
            str(counter),
            started_first,
            entered_first,
            release_first,
            result,
        ),
    )
    second = context.Process(
        target=_increment_under_identity_lock,
        args=(
            str(identity_map),
            str(counter),
            started_second,
            entered_second,
            release_second,
            result,
        ),
    )
    first.start()
    second_started = False
    try:
        assert started_first.wait(10.0)
        assert entered_first.wait(10.0)
        second.start()
        second_started = True
        assert started_second.wait(10.0)
        assert not entered_second.wait(0.5)
        release_first.set()
        first.join(10.0)
        assert first.exitcode == 0
        assert result.get(timeout=2.0) is None
        if not entered_second.wait(10.0):
            second.join(2.0)
            pytest.fail(
                "second process did not acquire released identity lock: "
                f"exit={second.exitcode}, result={result.get(timeout=2.0)!r}"
            )
        release_second.set()
        second.join(10.0)
        assert second.exitcode == 0
        assert result.get(timeout=2.0) is None
        assert counter.read_text(encoding="ascii") == "2"
        lock_path = identity_map.parent / ".identity-map.lock"
        assert lock_path.read_bytes() == b"\x00"
        assert os.stat(lock_path, follow_symlinks=False).st_nlink == 1
    finally:
        release_first.set()
        release_second.set()
        if first.is_alive():
            first.terminate()
            first.join(2.0)
        if second_started and second.is_alive():
            second.terminate()
            second.join(2.0)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows hardlink attack")
def test_identity_map_lock_rejects_prepositioned_hardlink(tmp_path: Path) -> None:
    identity_map = tmp_path / "identity" / "identity-map.enc"
    identity_map.parent.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"must-survive")
    os.link(outside, identity_map.parent / ".identity-map.lock")

    with pytest.raises(ClientCreationFailed, match="CLIENT_CREATION_FAILED"):
        with _identity_map_write_lock(identity_map):
            pytest.fail("hardlinked lock must never be acquired")

    assert outside.read_bytes() == b"must-survive"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows file locking")
def test_identity_map_lock_preserves_body_exception(tmp_path: Path) -> None:
    identity_map = tmp_path / "identity" / "identity-map.enc"
    identity_map.parent.mkdir()

    with pytest.raises(ValueError, match="expected body failure"):
        with _identity_map_write_lock(identity_map):
            raise ValueError("expected body failure")
