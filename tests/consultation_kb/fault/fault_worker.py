"""Real subprocess worker used only by the P8 crash-fault test suite."""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

from consultation_kb.lifecycle.fault_points import (
    FaultConfigurationError,
    FaultInjector,
)


_DATABASE_NAME = "fault.sqlite3"


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _payload(scenario: str, component: str, version: int) -> bytes:
    return f"{scenario}:{component}:version:{version}\n".encode("ascii")


def _connect(vault: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(vault / _DATABASE_NAME, isolation_level=None)
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = FULL")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS runtime_epochs(
            epoch INTEGER PRIMARY KEY,
            state TEXT NOT NULL CHECK(state IN ('ACTIVE', 'RETIRED'))
        );
        CREATE TABLE IF NOT EXISTS artifact_versions(
            component TEXT NOT NULL,
            version INTEGER NOT NULL,
            content_sha256 TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('PREPARED', 'ACTIVE', 'RETIRED')),
            PRIMARY KEY(component, version)
        );
        CREATE TABLE IF NOT EXISTS active_artifacts(
            component TEXT PRIMARY KEY,
            epoch INTEGER NOT NULL REFERENCES runtime_epochs(epoch),
            version INTEGER NOT NULL,
            content_sha256 TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS publication_intents(
            operation_id TEXT PRIMARY KEY,
            scenario TEXT NOT NULL,
            component TEXT NOT NULL,
            version INTEGER NOT NULL,
            content_sha256 TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('PREPARED', 'ACTIVE'))
        );
        CREATE TABLE IF NOT EXISTS approval_claims(
            operation_id TEXT PRIMARY KEY,
            state TEXT NOT NULL CHECK(state IN ('CLAIMED', 'ACKED')),
            proof_sha256 TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS target_effects(
            operation_id TEXT PRIMARY KEY,
            proof_sha256 TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS source_outbox(
            event_id TEXT PRIMARY KEY,
            candidate_sha256 TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('PENDING', 'CLAIMED', 'PUBLISHED')),
            published_global_version INTEGER
        );
        CREATE TABLE IF NOT EXISTS global_sagas(
            event_id TEXT PRIMARY KEY,
            candidate_sha256 TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('COPIED', 'PREPARED', 'ACTIVE')),
            global_version INTEGER NOT NULL CHECK(global_version = 1),
            content_sha256 TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS global_cases(
            event_id TEXT PRIMARY KEY,
            version INTEGER NOT NULL CHECK(version = 1),
            content_sha256 TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state = 'ACTIVE')
        );
        """
    )
    return connection


def _cas_path(vault: Path, content_sha256: str) -> Path:
    return vault / "cas" / content_sha256[:2] / content_sha256


def _stage_path(vault: Path, scenario: str, component: str) -> Path:
    return vault / "staging" / scenario / component / "version-2.payload"


def _outbox_stage_path(vault: Path) -> Path:
    return vault / "staging" / "outbox" / "case" / "version-1.payload"


def _durable_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _verify_file(path: Path, expected_sha256: str) -> None:
    with path.open("rb") as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as view:
            actual = hashlib.sha256(view).hexdigest()
    if actual != expected_sha256:
        raise RuntimeError("FAULT_WORKER_HASH_MISMATCH")


def _finalize(vault: Path, staged: Path, expected_sha256: str) -> Path:
    destination = _cas_path(vault, expected_sha256)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        _verify_file(destination, expected_sha256)
        staged.unlink(missing_ok=True)
    else:
        os.replace(staged, destination)
    _verify_file(destination, expected_sha256)
    return destination


def _initialize_old_active(
    connection: sqlite3.Connection,
    vault: Path,
    *,
    scenario: str,
    component: str,
) -> None:
    if connection.execute("SELECT 1 FROM active_artifacts").fetchone() is not None:
        return
    payload = _payload(scenario, component, 1)
    content_sha256 = _sha256(payload)
    _durable_write(_cas_path(vault, content_sha256), payload)
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute("INSERT INTO runtime_epochs VALUES (1, 'ACTIVE')")
        connection.execute(
            "INSERT INTO artifact_versions VALUES (?, 1, ?, 'ACTIVE')",
            (component, content_sha256),
        )
        connection.execute(
            "INSERT INTO active_artifacts VALUES (?, 1, 1, ?)",
            (component, content_sha256),
        )
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise


def _prepare_publication(
    connection: sqlite3.Connection,
    *,
    operation_id: str,
    scenario: str,
    component: str,
    content_sha256: str,
) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "INSERT INTO publication_intents VALUES (?, ?, ?, 2, ?, 'PREPARED')",
            (operation_id, scenario, component, content_sha256),
        )
        connection.execute(
            "INSERT INTO artifact_versions VALUES (?, 2, ?, 'PREPARED')",
            (component, content_sha256),
        )
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise


def _activate_publication(
    connection: sqlite3.Connection,
    *,
    operation_id: str,
    component: str,
    content_sha256: str,
) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "UPDATE runtime_epochs SET state = 'RETIRED' WHERE state = 'ACTIVE'"
        )
        connection.execute("INSERT OR IGNORE INTO runtime_epochs VALUES (2, 'ACTIVE')")
        connection.execute("UPDATE runtime_epochs SET state = 'ACTIVE' WHERE epoch = 2")
        connection.execute(
            "UPDATE artifact_versions SET state = 'RETIRED' "
            "WHERE component = ? AND version = 1",
            (component,),
        )
        connection.execute(
            "UPDATE artifact_versions SET state = 'ACTIVE' "
            "WHERE component = ? AND version = 2 AND content_sha256 = ?",
            (component, content_sha256),
        )
        connection.execute(
            "UPDATE active_artifacts SET epoch = 2, version = 2, "
            "content_sha256 = ? WHERE component = ?",
            (content_sha256, component),
        )
        connection.execute(
            "UPDATE publication_intents SET state = 'ACTIVE' "
            "WHERE operation_id = ? AND content_sha256 = ?",
            (operation_id, content_sha256),
        )
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise


def _cleanup_staging(vault: Path) -> None:
    staging = vault / "staging"
    for path in sorted(staging.rglob("*"), reverse=True) if staging.exists() else ():
        if path.is_file():
            path.unlink()
        elif path.is_dir():
            try:
                path.rmdir()
            except OSError:
                pass


def _attempt_publication(
    connection: sqlite3.Connection,
    vault: Path,
    *,
    scenario: str,
    component: str,
    injector: FaultInjector,
) -> None:
    _initialize_old_active(
        connection,
        vault,
        scenario=scenario,
        component=component,
    )
    operation_id = f"{scenario}:{component}:version:2"
    payload = _payload(scenario, component, 2)
    content_sha256 = _sha256(payload)
    staged = _stage_path(vault, scenario, component)
    staged.parent.mkdir(parents=True, exist_ok=True)
    with staged.open("wb") as handle:
        handle.write(payload)
        injector.hit("after_stage_write")
        handle.flush()
        os.fsync(handle.fileno())
    injector.hit("after_file_fsync")
    injector.hit("before_prepared_tx")
    _prepare_publication(
        connection,
        operation_id=operation_id,
        scenario=scenario,
        component=component,
        content_sha256=content_sha256,
    )
    injector.hit("after_prepared_tx")
    _verify_file(staged, content_sha256)
    injector.hit("after_verify")
    _finalize(vault, staged, content_sha256)
    injector.hit("before_active_tx")
    _activate_publication(
        connection,
        operation_id=operation_id,
        component=component,
        content_sha256=content_sha256,
    )
    injector.hit("after_active_tx")
    injector.hit("before_cleanup")
    _cleanup_staging(vault)


def _recover_publication(connection: sqlite3.Connection, vault: Path) -> None:
    intent = connection.execute(
        "SELECT operation_id, scenario, component, content_sha256, state "
        "FROM publication_intents"
    ).fetchone()
    if intent is None:
        _cleanup_staging(vault)
        return
    operation_id, scenario, component, content_sha256, state = map(str, intent)
    staged = _stage_path(vault, scenario, component)
    destination = _cas_path(vault, content_sha256)
    if state == "PREPARED":
        source = destination if destination.exists() else staged
        _verify_file(source, content_sha256)
        if source == staged:
            _finalize(vault, staged, content_sha256)
        _activate_publication(
            connection,
            operation_id=operation_id,
            component=component,
            content_sha256=content_sha256,
        )
    elif state != "ACTIVE":
        raise RuntimeError("FAULT_WORKER_INTENT_STATE_INVALID")
    _verify_file(destination, content_sha256)
    _cleanup_staging(vault)


def _approval_proof() -> str:
    return _sha256(b"approval-target-effect-v1")


def _attempt_approval(
    connection: sqlite3.Connection,
    *,
    injector: FaultInjector,
) -> None:
    operation_id = "approval-execution-v1"
    proof_sha256 = _approval_proof()
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "INSERT OR IGNORE INTO approval_claims VALUES (?, 'CLAIMED', ?)",
            (operation_id, proof_sha256),
        )
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    injector.hit("after_approval_claim")
    injector.hit("before_target_commit")
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "INSERT INTO target_effects VALUES (?, ?)",
            (operation_id, proof_sha256),
        )
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    injector.hit("after_target_commit_before_ack")
    connection.execute(
        "UPDATE approval_claims SET state = 'ACKED' WHERE operation_id = ?",
        (operation_id,),
    )


def _recover_approval(connection: sqlite3.Connection) -> None:
    claim = connection.execute(
        "SELECT operation_id, state, proof_sha256 FROM approval_claims"
    ).fetchone()
    if claim is None:
        raise RuntimeError("FAULT_WORKER_APPROVAL_CLAIM_MISSING")
    operation_id, state, proof_sha256 = map(str, claim)
    target = connection.execute(
        "SELECT proof_sha256 FROM target_effects WHERE operation_id = ?",
        (operation_id,),
    ).fetchone()
    if target is None:
        connection.execute(
            "INSERT INTO target_effects VALUES (?, ?)",
            (operation_id, proof_sha256),
        )
    elif target != (proof_sha256,):
        raise RuntimeError("FAULT_WORKER_APPROVAL_PROOF_MISMATCH")
    if state != "ACKED":
        connection.execute(
            "UPDATE approval_claims SET state = 'ACKED' WHERE operation_id = ?",
            (operation_id,),
        )


def _outbox_identity() -> tuple[str, bytes, str]:
    event_id = "outbox-event-v1"
    payload = _payload("outbox", "case", 1)
    return event_id, payload, _sha256(payload)


def _write_source_outbox(
    connection: sqlite3.Connection,
    *,
    event_id: str,
    content_sha256: str,
) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "INSERT OR IGNORE INTO source_outbox "
            "VALUES (?, ?, 'PENDING', NULL)",
            (event_id, content_sha256),
        )
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise


def _copy_outbox_to_global(
    connection: sqlite3.Connection,
    vault: Path,
    *,
    event_id: str,
    payload: bytes,
    content_sha256: str,
) -> None:
    staged = _outbox_stage_path(vault)
    if not staged.exists():
        _durable_write(staged, payload)
    _verify_file(staged, content_sha256)
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "UPDATE source_outbox SET state = 'CLAIMED' "
            "WHERE event_id = ? AND state IN ('PENDING', 'CLAIMED')",
            (event_id,),
        )
        connection.execute(
            "INSERT OR IGNORE INTO global_sagas "
            "VALUES (?, ?, 'COPIED', 1, ?)",
            (event_id, content_sha256, content_sha256),
        )
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise


def _prepare_outbox_global(
    connection: sqlite3.Connection,
    *,
    event_id: str,
    content_sha256: str,
) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "UPDATE global_sagas SET state = 'PREPARED' "
            "WHERE event_id = ? AND content_sha256 = ? AND state = 'COPIED'",
            (event_id, content_sha256),
        )
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise


def _activate_outbox_global(
    connection: sqlite3.Connection,
    vault: Path,
    *,
    event_id: str,
    content_sha256: str,
) -> None:
    staged = _outbox_stage_path(vault)
    destination = _cas_path(vault, content_sha256)
    if staged.exists():
        _finalize(vault, staged, content_sha256)
    else:
        _verify_file(destination, content_sha256)
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "INSERT OR IGNORE INTO global_cases "
            "VALUES (?, 1, ?, 'ACTIVE')",
            (event_id, content_sha256),
        )
        connection.execute(
            "UPDATE global_sagas SET state = 'ACTIVE' "
            "WHERE event_id = ? AND content_sha256 = ? "
            "AND state IN ('PREPARED', 'ACTIVE')",
            (event_id, content_sha256),
        )
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise


def _ack_source_outbox(
    connection: sqlite3.Connection,
    *,
    event_id: str,
    content_sha256: str,
) -> None:
    active = connection.execute(
        "SELECT version, content_sha256, state FROM global_cases "
        "WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    if active != (1, content_sha256, "ACTIVE"):
        raise RuntimeError("FAULT_WORKER_OUTBOX_ACTIVE_MISSING")
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "UPDATE source_outbox SET state = 'PUBLISHED', "
            "published_global_version = 1 "
            "WHERE event_id = ? AND candidate_sha256 = ? "
            "AND state IN ('CLAIMED', 'PUBLISHED')",
            (event_id, content_sha256),
        )
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise


def _attempt_outbox(
    connection: sqlite3.Connection,
    vault: Path,
    *,
    injector: FaultInjector,
) -> None:
    event_id, payload, content_sha256 = _outbox_identity()
    _write_source_outbox(
        connection,
        event_id=event_id,
        content_sha256=content_sha256,
    )
    injector.hit("after_source_outbox")
    _copy_outbox_to_global(
        connection,
        vault,
        event_id=event_id,
        payload=payload,
        content_sha256=content_sha256,
    )
    injector.hit("after_global_copy")
    _prepare_outbox_global(
        connection,
        event_id=event_id,
        content_sha256=content_sha256,
    )
    injector.hit("after_global_prepare")
    _activate_outbox_global(
        connection,
        vault,
        event_id=event_id,
        content_sha256=content_sha256,
    )
    injector.hit("after_global_activate")
    injector.hit("before_source_ack")
    _ack_source_outbox(
        connection,
        event_id=event_id,
        content_sha256=content_sha256,
    )
    _cleanup_staging(vault)


def _recover_outbox(connection: sqlite3.Connection, vault: Path) -> None:
    event_id, payload, content_sha256 = _outbox_identity()
    source = connection.execute(
        "SELECT candidate_sha256, state, published_global_version "
        "FROM source_outbox WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    if source is None or source[0] != content_sha256:
        raise RuntimeError("FAULT_WORKER_OUTBOX_SOURCE_MISSING")
    saga = connection.execute(
        "SELECT state, content_sha256 FROM global_sagas WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    if saga is None:
        _copy_outbox_to_global(
            connection,
            vault,
            event_id=event_id,
            payload=payload,
            content_sha256=content_sha256,
        )
        saga = ("COPIED", content_sha256)
    if saga[1] != content_sha256:
        raise RuntimeError("FAULT_WORKER_OUTBOX_SAGA_MISMATCH")
    if saga[0] == "COPIED":
        _prepare_outbox_global(
            connection,
            event_id=event_id,
            content_sha256=content_sha256,
        )
        saga = ("PREPARED", content_sha256)
    if saga[0] == "PREPARED":
        _activate_outbox_global(
            connection,
            vault,
            event_id=event_id,
            content_sha256=content_sha256,
        )
        saga = ("ACTIVE", content_sha256)
    if saga[0] != "ACTIVE":
        raise RuntimeError("FAULT_WORKER_OUTBOX_SAGA_STATE_INVALID")
    _verify_file(_cas_path(vault, content_sha256), content_sha256)
    _ack_source_outbox(
        connection,
        event_id=event_id,
        content_sha256=content_sha256,
    )
    _cleanup_staging(vault)


def _state_result(
    connection: sqlite3.Connection,
    *,
    scenario: str,
) -> dict[str, str]:
    if scenario == "approval":
        claim = connection.execute(
            "SELECT state, proof_sha256 FROM approval_claims"
        ).fetchone()
        if claim is None:
            raise RuntimeError("FAULT_WORKER_APPROVAL_STATE_MISSING")
        state, content_sha256 = map(str, claim)
        state_rows: Any = {
            "claim": claim,
            "targets": connection.execute(
                "SELECT operation_id, proof_sha256 FROM target_effects"
            ).fetchall(),
        }
    elif scenario == "outbox":
        source = connection.execute(
            "SELECT state, candidate_sha256, published_global_version "
            "FROM source_outbox"
        ).fetchone()
        if source is None:
            raise RuntimeError("FAULT_WORKER_OUTBOX_STATE_MISSING")
        state, content_sha256 = str(source[0]), str(source[1])
        state_rows = {
            "source": source,
            "sagas": connection.execute(
                "SELECT event_id, candidate_sha256, state, global_version, "
                "content_sha256 FROM global_sagas"
            ).fetchall(),
            "cases": connection.execute(
                "SELECT event_id, version, content_sha256, state "
                "FROM global_cases"
            ).fetchall(),
        }
    else:
        active = connection.execute(
            "SELECT version, content_sha256 FROM active_artifacts"
        ).fetchone()
        if active is None:
            raise RuntimeError("FAULT_WORKER_ACTIVE_STATE_MISSING")
        version, content_sha256 = int(active[0]), str(active[1])
        state = "OLD" if version == 1 else "NEW"
        state_rows = {
            "active": active,
            "epochs": connection.execute(
                "SELECT epoch, state FROM runtime_epochs ORDER BY epoch"
            ).fetchall(),
            "versions": connection.execute(
                "SELECT component, version, content_sha256, state "
                "FROM artifact_versions ORDER BY component, version"
            ).fetchall(),
        }
    state_sha256 = _sha256(
        json.dumps(
            state_rows,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    )
    return {
        "state": state,
        "content_sha256": content_sha256,
        "state_sha256": state_sha256,
    }


def _write_control(path: Path, result: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_suffix(path.suffix + ".pending")
    with pending.open("w", encoding="ascii", newline="\n") as handle:
        json.dump(
            result, handle, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        )
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(pending, path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("attempt", "recover-and-query"))
    parser.add_argument(
        "--scenario",
        choices=("manifest", "approval", "client", "global", "outbox"),
        required=True,
    )
    parser.add_argument("--component", required=True)
    parser.add_argument("--vault", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--test-mode", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    vault: Path = args.vault.resolve()
    vault.mkdir(parents=True, exist_ok=True)
    try:
        injector = FaultInjector.from_environment(
            test_mode=bool(args.test_mode),
            vault_root=vault,
        )
    except FaultConfigurationError as exc:
        sys.stderr.write(f"{exc}\n")
        return 2
    connection = _connect(vault)
    try:
        if args.command == "attempt":
            if args.scenario == "approval":
                _attempt_approval(connection, injector=injector)
            elif args.scenario == "outbox":
                _attempt_outbox(connection, vault, injector=injector)
            else:
                _attempt_publication(
                    connection,
                    vault,
                    scenario=args.scenario,
                    component=args.component,
                    injector=injector,
                )
        elif args.scenario == "approval":
            _recover_approval(connection)
        elif args.scenario == "outbox":
            _recover_outbox(connection, vault)
        else:
            _recover_publication(connection, vault)
        _write_control(
            args.control.resolve(),
            _state_result(connection, scenario=args.scenario),
        )
    finally:
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
