"""Command-line shell for consultation knowledge-base operations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Sequence, cast

if TYPE_CHECKING:
    import sqlite3

    from consultation_kb.core.config import AppConfig
    from consultation_kb.core.doctor import DoctorReport


class _LifecycleCliError(RuntimeError):
    """Fixed-code failure for the body-free operator boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _configuration_failure(code: str) -> dict[str, object]:
    return {
        "ok": False,
        "checks": {
            "configuration": {
                "status": "fail",
                "code": code,
                "observed_count": None,
            }
        },
    }


def _emit_report(report: DoctorReport, *, json_mode: bool) -> None:
    payload = report.model_dump(mode="json")
    if json_mode:
        print(_canonical_json(payload))
        return
    print("doctor: pass" if report.ok else "doctor: fail")
    for name, check in report.checks.items():
        count = "" if check.observed_count is None else f" count={check.observed_count}"
        print(f"{name}: {check.status} code={check.code}{count}")


def _emit_failure(code: str, *, json_mode: bool) -> None:
    if json_mode:
        print(_canonical_json(_configuration_failure(code)))
    else:
        print("doctor: fail")
    print(f"consultation-kb doctor: {code}", file=sys.stderr)


def _resolved_config(args: argparse.Namespace) -> AppConfig:
    from consultation_kb.core.config import AppConfig

    repo_root = args.repo_root.resolve(strict=False)
    vault_root = (
        None if args.vault_root is None else args.vault_root.resolve(strict=False)
    )
    return AppConfig.load(repo_root=repo_root, vault_root=vault_root)


def _run_doctor(args: argparse.Namespace) -> int:
    from consultation_kb.core.config import ConfigurationError
    from consultation_kb.core.doctor import Doctor
    from consultation_kb.operations.doctor_probes import (
        RetrievalArtifactDiagnosticProbe,
        lifecycle_diagnostic_probes,
    )
    from consultation_kb.operations.mcp_doctor_probe import (
        McpRuntimeDiagnosticProbe,
    )

    try:
        config = _resolved_config(args)
    except ConfigurationError as error:
        _emit_failure(error.code, json_mode=args.json)
        return 2
    except Exception:
        _emit_failure("DOCTOR_CONFIGURATION_FAILED", json_mode=args.json)
        return 2

    try:
        report = Doctor(
            config,
            diagnostic_probes=(
                RetrievalArtifactDiagnosticProbe(),
                McpRuntimeDiagnosticProbe(),
                *lifecycle_diagnostic_probes(),
            ),
        ).run()
    except Exception:
        _emit_failure("DOCTOR_EXECUTION_FAILED", json_mode=args.json)
        return 2
    _emit_report(report, json_mode=args.json)
    if not report.ok:
        failed_codes = sorted(
            check.code for check in report.checks.values() if check.status == "fail"
        )
        for code in failed_codes:
            print(f"consultation-kb doctor: {code}", file=sys.stderr)
        return 2
    return 0


def _migration_failure(code: str) -> int:
    print(f"consultation-kb migrate: {code}", file=sys.stderr)
    return 2


def _review_failure(code: str) -> int:
    print(f"consultation-kb review: {code}", file=sys.stderr)
    return 2


def _configure_codex_failure(code: str) -> int:
    print(f"consultation-kb configure-codex: {code}", file=sys.stderr)
    return 2


def _vault_security_id(vault_root: Path) -> str:
    identity = os.path.normcase(os.path.normpath(os.fspath(vault_root)))
    return (
        "vault_" + hashlib.sha256(identity.encode("utf-8", errors="strict")).hexdigest()
    )


def _is_plain_directory(path: Path) -> bool:
    try:
        status = os.lstat(path)
    except OSError:
        return False
    reparse = int(getattr(status, "st_file_attributes", 0)) & int(
        getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )
    return (
        stat.S_ISDIR(status.st_mode)
        and not stat.S_ISLNK(status.st_mode)
        and not reparse
    )


def _is_single_link_file(path: Path) -> bool:
    try:
        status = os.lstat(path)
    except OSError:
        return False
    reparse = int(getattr(status, "st_file_attributes", 0)) & int(
        getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )
    return (
        stat.S_ISREG(status.st_mode)
        and not stat.S_ISLNK(status.st_mode)
        and not reparse
        and int(status.st_nlink) == 1
    )


@contextmanager
def _guarded_snapshot(root: Path, database: Path) -> Iterator[sqlite3.Connection]:
    """Hold the verified Windows file handle while SQLite reopens read-only."""

    from consultation_kb.security.path_guard import PathGuard
    from consultation_kb.storage.connection import connect_database_snapshot

    try:
        relative = database.relative_to(root)
    except ValueError:
        raise RuntimeError("MIGRATION_SCOPE_LAYOUT_INVALID") from None
    with PathGuard(root).open_scoped(relative, mode="rb"):
        connection = connect_database_snapshot(database)
        try:
            yield connection
        finally:
            connection.close()


@contextmanager
def _guarded_live_reader(
    root: Path,
    database: Path,
) -> Iterator[sqlite3.Connection]:
    """Read one transaction-consistent live SQLite view, including WAL."""

    from consultation_kb.security.path_guard import PathGuard
    from consultation_kb.storage.connection import connect_database

    try:
        relative = database.relative_to(root)
    except ValueError:
        raise RuntimeError("MIGRATION_SCOPE_LAYOUT_INVALID") from None
    with PathGuard(root).open_scoped(relative, mode="rb"):
        connection = connect_database(database, "reader")
        try:
            connection.execute("BEGIN")
            yield connection
        finally:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            connection.close()


def _run_migrate_check(args: argparse.Namespace) -> int:
    from consultation_kb.core.config import ConfigurationError
    from consultation_kb.storage.migrate import (
        MigrationError,
        MigrationRunner,
        MigrationScope,
    )

    if not args.check:
        return _migration_failure("MIGRATION_CHECK_REQUIRED")
    try:
        config = _resolved_config(args)
    except ConfigurationError as error:
        return _migration_failure(error.code)
    except Exception:
        return _migration_failure("MIGRATION_CONFIGURATION_FAILED")

    global_database = config.vault_root / "global" / "catalog.sqlite3"
    clients_root = config.vault_root / "clients"
    databases: dict[Path, MigrationScope] = {global_database: "global"}
    try:
        if clients_root.exists():
            if not _is_plain_directory(clients_root):
                return _migration_failure("MIGRATION_SCOPE_LAYOUT_INVALID")
            for client_root in sorted(
                clients_root.iterdir(), key=lambda item: item.name
            ):
                if client_root.name == ".staging":
                    if not _is_plain_directory(client_root):
                        return _migration_failure("MIGRATION_SCOPE_LAYOUT_INVALID")
                    continue
                if not _is_plain_directory(client_root):
                    return _migration_failure("MIGRATION_SCOPE_LAYOUT_INVALID")
                database = client_root / "client.sqlite3"
                if not _is_single_link_file(database):
                    return _migration_failure("MIGRATION_DATABASE_MISSING")
                databases[database] = "client"
    except OSError:
        return _migration_failure("MIGRATION_SCOPE_LAYOUT_INVALID")

    try:
        if not _is_single_link_file(global_database):
            return _migration_failure("MIGRATION_DATABASE_MISSING")
        with _guarded_snapshot(config.vault_root, global_database) as global_connection:
            MigrationRunner.for_scope(global_connection, "global").check()
            active_directories = global_connection.execute(
                "SELECT client_id FROM clients WHERE state = 'ACTIVE'"
            ).fetchall()
    except MigrationError as error:
        return _migration_failure(error.code)
    except Exception:
        return _migration_failure("MIGRATION_CHECK_FAILED")

    for row in active_directories:
        if (
            len(row) != 1
            or type(row[0]) is not str
            or not row[0]
            or Path(row[0]).name != row[0]
            or row[0] in {".", ".."}
        ):
            return _migration_failure("MIGRATION_SCOPE_LAYOUT_INVALID")
        required_database = clients_root / row[0] / "client.sqlite3"
        if not _is_single_link_file(required_database):
            return _migration_failure("MIGRATION_DATABASE_MISSING")
        databases[required_database] = "client"

    for database, scope in databases.items():
        if scope == "global":
            continue
        if not _is_single_link_file(database):
            return _migration_failure("MIGRATION_DATABASE_MISSING")
        try:
            with _guarded_snapshot(config.vault_root, database) as connection:
                MigrationRunner.for_scope(connection, scope).check()
        except MigrationError as error:
            return _migration_failure(error.code)
        except Exception:
            return _migration_failure("MIGRATION_CHECK_FAILED")
    print(f"migrate: pass databases={len(databases)}")
    return 0


def _run_review(args: argparse.Namespace) -> int:
    """Run the signer only inside this explicit, interactive local process."""

    from consultation_kb.approvals.provider import ProtectedProviderSecretStore
    from consultation_kb.approvals.review_agent import (
        ReviewAgent,
        VerifiedReviewDiff,
        run_review_agent,
    )
    from consultation_kb.approvals.store import ApprovalService
    from consultation_kb.core.clock import SystemClock
    from consultation_kb.core.config import ConfigurationError
    from consultation_kb.core.ids import IdFactory
    from consultation_kb.security.dpapi import create_secret_protector
    from consultation_kb.security.path_guard import PathGuard
    from consultation_kb.storage.connection import connect_database
    from consultation_kb.storage.migrate import MigrationRunner
    from consultation_kb.vault.content_store import ContentStore

    try:
        config = _resolved_config(args)
    except ConfigurationError as error:
        return _review_failure(error.code)
    except Exception:
        return _review_failure("REVIEW_CONFIGURATION_FAILED")

    global_database = config.vault_root / "global" / "catalog.sqlite3"
    if not _is_single_link_file(global_database):
        return _review_failure("REVIEW_DATABASE_UNAVAILABLE")
    connection = None
    try:
        relative_database = global_database.relative_to(config.vault_root)
        with PathGuard(config.vault_root).open_scoped(relative_database, mode="rb"):
            connection = connect_database(global_database, mode="writer")
            MigrationRunner.for_scope(connection, "global").check()
            row = connection.execute(
                "SELECT target_scope_hash FROM approval_requests WHERE request_id = ?",
                (args.request,),
            ).fetchone()
            if (
                row is None
                or len(row) != 1
                or type(row[0]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", row[0]) is None
            ):
                return _review_failure("REVIEW_REQUEST_UNAVAILABLE")

            clock = SystemClock()
            vault_id = _vault_security_id(config.vault_root)
            protector = create_secret_protector()
            secret_store = ProtectedProviderSecretStore(
                config.vault_root / "security" / "review-agent-secret.dpapi",
                protector=protector,
                vault_id=vault_id,
            )
            service = ApprovalService(
                connection,
                provider=secret_store.load_verifier(),
                protector=protector,
                clock=clock,
                id_factory=IdFactory(clock),
                target_scope_hash=row[0],
                vault_id=vault_id,
                execution_secret=secret_store.load_execution_secret(),
                execution_proof_verifier=(
                    secret_store.load_target_execution_proof_verifier()
                ),
            )
            content_store = ContentStore(config.vault_root / "global")

            def load_verified_diff(reference: object) -> VerifiedReviewDiff:
                from consultation_kb.models.common import VersionRef

                validated = VersionRef.model_validate(reference)
                return VerifiedReviewDiff(
                    reference=validated,
                    content=content_store.read_hash_verified(validated.content_sha256),
                )

            agent = ReviewAgent(
                service=service,
                signer=secret_store.load_signer(clock=clock),
                render_verified_diff=load_verified_diff,
            )
            return run_review_agent(
                agent,
                args.request,
                stdin=sys.stdin,
                stdout=sys.stdout,
                stderr=sys.stderr,
            )
    except Exception:
        return _review_failure("REVIEW_SETUP_FAILED")
    finally:
        if connection is not None:
            connection.close()


def _path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _probe_configured_python(
    python_executable: Path,
    *,
    repo_root: Path,
    vault_root: Path,
    configured_home: Path,
    configured_version: tuple[int, int, int],
) -> bool:
    probe = (
        "import json,platform,sqlite3,struct,sys;"
        "c=sqlite3.connect(':memory:');"
        "c.execute('CREATE VIRTUAL TABLE p USING fts5(body)');"
        "c.execute(\"INSERT INTO p(body) VALUES ('probe')\");"
        "f=c.execute(\"SELECT count(*) FROM p WHERE p MATCH 'probe'\").fetchone()[0]==1;"
        "c.close();"
        "print(json.dumps({"
        "'base_prefix':sys.base_prefix,"
        "'bits':struct.calcsize('P')*8,"
        "'executable':sys.executable,"
        "'fts5':f,"
        "'implementation':platform.python_implementation(),"
        "'prefix':sys.prefix,"
        "'ssl':__import__('ssl') is not None,"
        "'venv':__import__('venv') is not None,"
        "'version':list(sys.version_info[:3])"
        "},sort_keys=True,separators=(',',':')))"
    )
    try:
        completed = subprocess.run(
            (str(python_executable), "-I", "-c", probe),
            cwd=repo_root,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=15,
            check=False,
        )
        payload = json.loads(completed.stdout)
        version = payload.get("version")
        prefix = Path(str(payload.get("prefix"))).resolve(strict=True)
        base_prefix = Path(str(payload.get("base_prefix"))).resolve(strict=True)
        executable = Path(str(payload.get("executable"))).resolve(strict=True)
        expected_prefix = python_executable.parents[1].resolve(strict=True)
        expected_executable = python_executable.resolve(strict=True)
        expected_home = configured_home.resolve(strict=True)
        normalized_base = os.path.normcase(os.fspath(base_prefix)).replace("/", "\\")
        return bool(
            completed.returncode == 0
            and completed.stderr == ""
            and type(payload) is dict
            and type(version) is list
            and len(version) == 3
            and all(type(value) is int for value in version)
            and tuple(version) == configured_version
            and configured_version >= (3, 12, 10)
            and configured_version[:2] == (3, 12)
            and payload.get("bits") == 64
            and payload.get("implementation") == "CPython"
            and payload.get("fts5") is True
            and payload.get("ssl") is True
            and payload.get("venv") is True
            and prefix == expected_prefix
            and executable == expected_executable
            and prefix != base_prefix
            and base_prefix == expected_home
            and ".cache\\codex-runtimes" not in normalized_base.lower()
            and not _path_is_within(base_prefix, repo_root)
            and not _path_is_within(base_prefix, vault_root)
        )
    except Exception:
        return False


def _read_pyvenv_config(path: Path) -> tuple[Path, tuple[int, int, int]] | None:
    try:
        values: dict[str, str] = {}
        for raw_line in path.read_text(encoding="utf-8", errors="strict").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            normalized_key = key.strip().lower()
            normalized_value = value.strip()
            if (
                not separator
                or not normalized_key
                or not normalized_value
                or normalized_key in values
                or any(ord(character) < 0x20 for character in normalized_value)
            ):
                return None
            values[normalized_key] = normalized_value
        home_text = values["home"]
        version_text = values["version"]
        home = Path(home_text)
        if not home.is_absolute():
            return None
        normalized_home = os.path.normcase(os.fspath(home)).replace("/", "\\").lower()
        if ".cache\\codex-runtimes" in normalized_home:
            return None
        version_parts = version_text.split(".")
        if len(version_parts) != 3 or any(
            not part.isascii() or not part.isdecimal() for part in version_parts
        ):
            return None
        version = (
            int(version_parts[0]),
            int(version_parts[1]),
            int(version_parts[2]),
        )
        return home, version
    except (KeyError, OSError, UnicodeError, ValueError):
        return None


def _run_configure_codex(args: argparse.Namespace) -> int:
    from consultation_kb.core.config import AppConfig, ConfigurationError

    try:
        repo_root = args.repo_root.resolve(strict=True)
        codex_root = repo_root / ".codex"
        template = codex_root / "config.template.toml"
        wrapper = codex_root / "start-consultation-kb.ps1"
        python_executable = repo_root / ".venv" / "Scripts" / "python.exe"
        pyvenv_config = repo_root / ".venv" / "pyvenv.cfg"
        vault_root = (repo_root.parent / "knowledge-vault").resolve(strict=True)
        AppConfig.load(repo_root=repo_root, vault_root=vault_root)
    except (ConfigurationError, OSError, RuntimeError, ValueError):
        return _configure_codex_failure("CONFIGURE_SCOPE_INVALID")

    if (
        not _is_plain_directory(codex_root)
        or not _is_plain_directory(vault_root)
        or not _is_single_link_file(template)
        or not _is_single_link_file(wrapper)
        or not _is_single_link_file(python_executable)
        or not _is_single_link_file(pyvenv_config)
    ):
        return _configure_codex_failure("CONFIGURE_INPUT_INVALID")

    try:
        template_bytes = template.read_bytes()
        template_text = template_bytes.decode("utf-8", errors="strict")
        parsed = tomllib.loads(template_text)
        servers = parsed.get("mcp_servers")
        if (
            type(servers) is not dict
            or tuple(servers) != ("consultation-kb",)
            or not template_bytes
            or b"\x00" in template_bytes
        ):
            raise ValueError
    except (OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError):
        return _configure_codex_failure("CONFIGURE_TEMPLATE_INVALID")

    venv_configuration = _read_pyvenv_config(pyvenv_config)
    if venv_configuration is None:
        return _configure_codex_failure("CONFIGURE_RUNTIME_INVALID")
    configured_home, configured_version = venv_configuration
    try:
        canonical_home = configured_home.resolve(strict=True)
    except OSError:
        return _configure_codex_failure("CONFIGURE_RUNTIME_INVALID")
    if _path_is_within(canonical_home, repo_root) or _path_is_within(
        canonical_home, vault_root
    ):
        return _configure_codex_failure("CONFIGURE_RUNTIME_INVALID")

    if not _probe_configured_python(
        python_executable,
        repo_root=repo_root,
        vault_root=vault_root,
        configured_home=canonical_home,
        configured_version=configured_version,
    ):
        return _configure_codex_failure("CONFIGURE_RUNTIME_INVALID")

    target = codex_root / "config.toml"
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".config.toml.",
            suffix=".tmp",
            dir=codex_root,
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(template_bytes)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        temporary = None
    except OSError:
        return _configure_codex_failure("CONFIGURE_WRITE_FAILED")
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    print("configure-codex: pass")
    return 0


def _lifecycle_failure(
    command: str,
    code: str,
    *,
    json_mode: bool,
) -> int:
    if json_mode:
        print(_canonical_json({"ok": False, "code": code}))
    print(f"consultation-kb {command}: {code}", file=sys.stderr)
    return 2


def _emit_lifecycle(value: dict[str, object], *, json_mode: bool) -> None:
    if json_mode:
        print(_canonical_json(value))
        return
    print(_canonical_json(value))


def _global_database_reference(vault_root: Path) -> str:
    """Return an opaque, vault-bound reference without exposing a locator."""

    from consultation_kb.lifecycle.sqlite_recovery import (
        global_database_reference,
    )

    return global_database_reference(vault_root)


def _lifecycle_global_target(
    args: argparse.Namespace,
    *,
    require_reference: bool,
) -> tuple[AppConfig, Path, str]:
    from consultation_kb.core.config import ConfigurationError

    try:
        config = _resolved_config(args)
    except ConfigurationError as error:
        raise _LifecycleCliError(error.code) from None
    except Exception:
        raise _LifecycleCliError("LIFECYCLE_CONFIGURATION_FAILED") from None
    database = config.vault_root / "global" / "catalog.sqlite3"
    if not _is_single_link_file(database):
        raise _LifecycleCliError("LIFECYCLE_DATABASE_UNAVAILABLE")
    reference = _global_database_reference(config.vault_root)
    supplied = getattr(args, "database_ref_sha256", None)
    if require_reference and supplied != reference:
        raise _LifecycleCliError("LIFECYCLE_SCOPE_UNAVAILABLE")
    if supplied is not None and supplied != reference:
        raise _LifecycleCliError("LIFECYCLE_SCOPE_UNAVAILABLE")
    return config, database, reference


def _database_sidecar_status(database: Path) -> dict[str, object]:
    values: dict[str, object] = {}
    for name, suffix in (
        ("wal", "-wal"),
        ("shm", "-shm"),
        ("journal", "-journal"),
    ):
        sidecar = database.with_name(database.name + suffix)
        try:
            present = sidecar.exists()
            size = sidecar.stat().st_size if present else 0
        except OSError:
            present = True
            size = -1
        values[f"{name}_present"] = present
        values[f"{name}_size_bytes"] = size
    return values


def _require_tables(
    connection: sqlite3.Connection,
    names: tuple[str, ...],
) -> None:
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall()
    present = {str(row[0]) for row in rows if len(row) == 1}
    if not set(names).issubset(present):
        raise _LifecycleCliError("LIFECYCLE_SCHEMA_UNAVAILABLE")


def _grouped_counts(
    connection: sqlite3.Connection,
    *,
    table: str,
    column: str,
) -> dict[str, int]:
    allowed = {
        ("publication_operations", "state"),
        ("outbox_events", "state"),
        ("rebuild_jobs", "state"),
        ("deletion_requests", "state"),
        ("deletion_requests", "queue_state"),
        ("deletion_queue_intents", "state"),
        ("backup_destruction_queue", "state"),
    }
    if (table, column) not in allowed:
        raise _LifecycleCliError("LIFECYCLE_REPORT_QUERY_INVALID")
    rows = connection.execute(
        f"SELECT {column}, count(*) FROM {table} GROUP BY {column} ORDER BY {column}"
    ).fetchall()
    if any(
        len(row) != 2 or type(row[0]) is not str or type(row[1]) is not int
        for row in rows
    ):
        raise _LifecycleCliError("LIFECYCLE_REPORT_INVALID")
    return {str(row[0]): int(row[1]) for row in rows}


def _read_recovery_report(
    args: argparse.Namespace,
) -> tuple[dict[str, object], bool]:
    _config, database, reference = _lifecycle_global_target(
        args,
        require_reference=False,
    )
    try:
        from consultation_kb.lifecycle.sqlite_recovery import (
            compose_global_recovery,
        )
        from consultation_kb.models.recovery import RecoveryScan
        from consultation_kb.vault.content_store import ContentStore

        scan = compose_global_recovery(
            database=database,
            content_store=ContentStore(database.parent),
            database_ref_sha256=reference,
            apply=False,
        )
        if type(scan) is not RecoveryScan:
            raise _LifecycleCliError("LIFECYCLE_REPORT_INVALID")
        return _render_recovery_report(database, reference, scan), True
    except _LifecycleCliError:
        raise
    except Exception:
        raise _LifecycleCliError("LIFECYCLE_REPORT_FAILED") from None


def _render_recovery_report(
    database: Path,
    reference: str,
    scan: object,
) -> dict[str, object]:
    from consultation_kb.models.recovery import RecoveryScan
    from consultation_kb.storage.connection import connect_database

    checked = RecoveryScan.model_validate(scan)
    actions: dict[str, int] = {}
    for decision in checked.decisions:
        actions[decision.action] = actions.get(decision.action, 0) + 1
    connection = connect_database(database, "reader")
    try:
        _require_tables(
            connection,
            (
                "publication_operations",
                "rebuild_jobs",
                "deletion_requests",
                "deletion_queue_intents",
                "backup_destruction_queue",
                "deletion_authority_state",
            ),
        )
        authority = connection.execute(
            "SELECT deletion_version, tombstone_epoch "
            "FROM deletion_authority_state WHERE singleton = 1"
        ).fetchone()
        if (
            authority is None
            or len(authority) != 2
            or any(type(value) is not int for value in authority)
        ):
            raise _LifecycleCliError("LIFECYCLE_REPORT_INVALID")
        return {
            "ok": True,
            "database_ref_sha256": reference,
            "database_scope": "global",
            "snapshot_available": True,
            "startup_health": checked.startup_health,
            "query_ready": checked.query_ready,
            "recovery": {
                "scan_sha256": checked.scan_sha256,
                "inventory_count": checked.inventory_count,
                "mutating_decision_count": sum(
                    decision.requires_writer for decision in checked.decisions
                ),
                "rebuild_required_count": len(checked.rebuild_commands),
                "actions": dict(sorted(actions.items())),
            },
            "deletion_version": int(authority[0]),
            "tombstone_epoch": int(authority[1]),
            "publication_operations": _grouped_counts(
                connection,
                table="publication_operations",
                column="state",
            ),
            # Source outbox rows live in client databases and may only be
            # inventoried by their already-scoped workers.
            "outbox": {"status": "SCOPED_WORKER_REQUIRED"},
            "rebuild_jobs": _grouped_counts(
                connection,
                table="rebuild_jobs",
                column="state",
            ),
            "deletion_requests": {
                "lifecycle": _grouped_counts(
                    connection,
                    table="deletion_requests",
                    column="state",
                ),
                "cleanup": _grouped_counts(
                    connection,
                    table="deletion_requests",
                    column="queue_state",
                ),
            },
            "cleanup_queue": _grouped_counts(
                connection,
                table="deletion_queue_intents",
                column="state",
            ),
            "backup_queue": _grouped_counts(
                connection,
                table="backup_destruction_queue",
                column="state",
            ),
            # WAL/journal files are valid for the production SQLite scan and
            # are therefore diagnostic only, never a recovery blocker.
            "sidecars": _database_sidecar_status(database),
        }
    finally:
        connection.close()


def _run_recovery_report(args: argparse.Namespace) -> int:
    try:
        report, complete = _read_recovery_report(args)
    except _LifecycleCliError as error:
        return _lifecycle_failure(
            "recovery-report",
            error.code,
            json_mode=args.json,
        )
    _emit_lifecycle(report, json_mode=args.json)
    if not complete:
        print(
            "consultation-kb recovery-report: LIFECYCLE_SNAPSHOT_UNSAFE",
            file=sys.stderr,
        )
        return 2
    return 0


def _run_recover(args: argparse.Namespace) -> int:
    if args.apply and args.database_ref_sha256 is None:
        return _lifecycle_failure(
            "recover",
            "LIFECYCLE_APPROVAL_REQUIRED",
            json_mode=args.json,
        )
    if args.apply:
        try:
            _config, database, reference = _lifecycle_global_target(
                args,
                require_reference=True,
            )
            from consultation_kb.lifecycle.sqlite_recovery import (
                compose_global_recovery,
            )
            from consultation_kb.models.recovery import RecoveryReport
            from consultation_kb.vault.content_store import ContentStore

            result = compose_global_recovery(
                database=database,
                content_store=ContentStore(database.parent),
                database_ref_sha256=reference,
                apply=True,
            )
            if type(result) is not RecoveryReport:
                raise _LifecycleCliError("LIFECYCLE_RECOVERY_FAILED")
            report = {
                **_render_recovery_report(database, reference, result.scan),
                "mode": "apply",
                "applied_count": len(result.receipts),
            }
        except _LifecycleCliError as error:
            return _lifecycle_failure("recover", error.code, json_mode=args.json)
        except Exception:
            return _lifecycle_failure(
                "recover",
                "LIFECYCLE_RECOVERY_FAILED",
                json_mode=args.json,
            )
        _emit_lifecycle(report, json_mode=args.json)
        return 0
    try:
        report, complete = _read_recovery_report(args)
    except _LifecycleCliError as error:
        return _lifecycle_failure("recover", error.code, json_mode=args.json)
    report = {**report, "mode": "dry_run", "applied_count": 0}
    _emit_lifecycle(report, json_mode=args.json)
    if not complete:
        print(
            "consultation-kb recover: LIFECYCLE_SNAPSHOT_UNSAFE",
            file=sys.stderr,
        )
        return 2
    return 0


def _safe_policy_key(value: str) -> str:
    if re.fullmatch(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*", value) is None:
        raise argparse.ArgumentTypeError("expected a lower-snake policy key")
    return value


def _model_import_failure(code: str, *, json_mode: bool) -> int:
    if json_mode:
        print(_canonical_json({"ok": False, "code": code}))
    print(f"consultation-kb models-import: {code}", file=sys.stderr)
    return 2


def _model_resolver_staging_root(vault_root: Path) -> Path:
    """Create one non-reparse resolver staging root inside the model vault."""

    model_root = vault_root / "models"
    staging_root = model_root / ".huggingface-staging"
    try:
        staging_root.mkdir(parents=True, exist_ok=True)
        exact_model_root = model_root.resolve(strict=True)
        exact_staging_root = staging_root.resolve(strict=True)
    except OSError:
        raise _LifecycleCliError("MODEL_IMPORT_STAGING_FAILED") from None
    if (
        not _is_plain_directory(model_root)
        or not _is_plain_directory(staging_root)
        or exact_model_root != model_root
        or exact_staging_root != staging_root
        or exact_staging_root.parent != exact_model_root
    ):
        raise _LifecycleCliError("MODEL_IMPORT_STAGING_INVALID")
    return exact_staging_root


def _run_models_import(args: argparse.Namespace) -> int:
    """Resolve or import one snapshot into the offline runtime registry."""

    from consultation_kb.core.config import ConfigurationError
    from consultation_kb.models.importer import (
        LocalRepositorySnapshot,
        ModelImportError,
        ModelImporter,
        detect_runtime_library_versions,
    )
    from consultation_kb.models.model_lock import (
        ModelLockError,
        RUNTIME_MANIFEST_RELPATH,
        load_tracked_model_spec,
    )

    if args.resolve_main and (
        args.source is not None
        or args.revision is not None
        or args.license_id is not None
    ):
        return _model_import_failure(
            "MODEL_IMPORT_MODE_CONFLICT",
            json_mode=args.json,
        )
    if args.source is None or args.revision is None or args.license_id is None:
        if not args.resolve_main:
            return _model_import_failure(
                "MODEL_IMPORT_LOCAL_SNAPSHOT_REQUIRED",
                json_mode=args.json,
            )
    try:
        config = _resolved_config(args)
        candidates = load_tracked_model_spec(
            config.repo_root / "models" / "consultation-models.json"
        )
        candidate = candidates.candidate_for_repo(args.repo)
        importer = ModelImporter(
            artifact_root=(config.vault_root / "models").resolve(strict=False),
            runtime_manifest_path=(
                config.repo_root / Path(RUNTIME_MANIFEST_RELPATH)
            ).resolve(strict=False),
            candidates=candidates,
        )
        versions = detect_runtime_library_versions()
        if args.resolve_main:
            from consultation_kb.models.huggingface_resolver import (
                HuggingFaceResolverError,
                HuggingFaceSnapshotResolver,
            )

            try:
                resolver = HuggingFaceSnapshotResolver(
                    candidates=candidates,
                    temporary_root=_model_resolver_staging_root(config.vault_root),
                )
                with resolver.resolve_main(args.repo) as snapshot:
                    manifest = importer.import_snapshot(
                        candidate.model_id,
                        snapshot,
                        versions=versions,
                    )
            except HuggingFaceResolverError as error:
                return _model_import_failure(error.code, json_mode=args.json)
        else:
            manifest = importer.import_snapshot(
                candidate.model_id,
                LocalRepositorySnapshot(
                    directory=args.source,
                    repo=args.repo,
                    revision=args.revision,
                    license_id=args.license_id,
                ),
                versions=versions,
            )
        record = next(
            item for item in manifest.models if item.model_id == candidate.model_id
        )
    except ConfigurationError as error:
        return _model_import_failure(error.code, json_mode=args.json)
    except _LifecycleCliError as error:
        return _model_import_failure(error.code, json_mode=args.json)
    except (ModelImportError, ModelLockError) as error:
        return _model_import_failure(error.code, json_mode=args.json)
    except Exception:
        return _model_import_failure(
            "MODEL_IMPORT_FAILED",
            json_mode=args.json,
        )
    payload: dict[str, object] = {
        "ok": True,
        "model_id": record.model_id,
        "role": record.role,
        "repo": record.repo,
        "revision": record.revision,
        "descriptor_sha256": record.descriptor_sha256,
        "runtime_manifest_sha256": manifest.canonical_sha256,
        "registered_model_count": len(manifest.models),
    }
    if args.json:
        print(_canonical_json(payload))
    else:
        print(
            f"models-import: pass model_id={record.model_id} revision={record.revision}"
        )
    return 0


def _model_benchmark_failure(code: str, *, json_mode: bool) -> int:
    if json_mode:
        print(_canonical_json({"ok": False, "code": code}))
    print(f"consultation-kb model-benchmark: {code}", file=sys.stderr)
    return 2


def _run_model_benchmark(args: argparse.Namespace) -> int:
    """Run the fixed synthetic suite against all four imported local pairs."""

    from consultation_kb.core.config import ConfigurationError
    from consultation_kb.evaluation import model_benchmark
    from consultation_kb.models.model_lock import (
        ModelLockError,
        RUNTIME_MANIFEST_RELPATH,
        load_runtime_model_manifest,
        load_tracked_model_spec,
    )

    try:
        config = _resolved_config(args)
        candidates = load_tracked_model_spec(
            config.repo_root / "models" / "consultation-models.json"
        )
        artifact_root = (config.vault_root / "models").resolve(strict=False)
        runtime_manifest = load_runtime_model_manifest(
            config.repo_root / Path(RUNTIME_MANIFEST_RELPATH),
            candidates=candidates,
            artifact_root=artifact_root,
        )
        cases = model_benchmark.load_model_benchmark_suite(
            config.repo_root / Path(model_benchmark.MODEL_BENCHMARK_SUITE_RELPATH)
        )
        backends = model_benchmark.build_sentence_transformers_benchmark_backends(
            runtime_manifest=runtime_manifest,
            artifact_root=artifact_root,
        )
        report = model_benchmark.run_model_benchmark(
            cases,
            backends,
            runtime_manifest=runtime_manifest,
        )
        report_sha256 = model_benchmark.write_model_benchmark_report_atomic(
            (config.repo_root / ".consultation-models" / "benchmarks").resolve(
                strict=False
            ),
            args.output_ref,
            report,
        )
    except ConfigurationError as error:
        return _model_benchmark_failure(error.code, json_mode=args.json)
    except (ModelLockError, model_benchmark.ModelBenchmarkError) as error:
        return _model_benchmark_failure(error.code, json_mode=args.json)
    except Exception:
        return _model_benchmark_failure(
            "MODEL_BENCHMARK_FAILED",
            json_mode=args.json,
        )
    payload: dict[str, object] = {
        "ok": True,
        "output_ref": args.output_ref,
        "report_sha256": report_sha256,
        "runtime_manifest_sha256": report.runtime_manifest_sha256,
        "suite_sha256": report.suite_sha256,
        "candidate_count": len(report.candidates),
        "selected_embedding_model_id": report.selected_embedding_model_id,
        "selected_reranker_model_id": report.selected_reranker_model_id,
    }
    if args.json:
        print(_canonical_json(payload))
    else:
        print(
            "model-benchmark: pass "
            f"output_ref={args.output_ref} report_sha256={report_sha256}"
        )
    return 0


def _evaluation_failure(action: str, code: str, *, json_mode: bool) -> int:
    if json_mode:
        print(_canonical_json({"ok": False, "code": code}))
    print(f"consultation-kb evaluation-{action}: {code}", file=sys.stderr)
    return 2


def _read_evaluation_request(path: Path) -> bytes:
    if not _is_single_link_file(path):
        raise _LifecycleCliError("EVALUATION_REQUEST_UNAVAILABLE")
    try:
        size = path.stat().st_size
        if not 0 < size <= 32 * 1024 * 1024:
            raise _LifecycleCliError("EVALUATION_REQUEST_INVALID")
        return path.read_bytes()
    except _LifecycleCliError:
        raise
    except OSError as exc:
        raise _LifecycleCliError("EVALUATION_REQUEST_UNAVAILABLE") from exc


def _emit_evaluation_result(
    action: str,
    result: object,
    *,
    json_mode: bool,
) -> None:
    from pydantic import BaseModel

    payload = (
        result.model_dump(mode="json") if isinstance(result, BaseModel) else result
    )
    if json_mode:
        print(_canonical_json({"ok": True, "result": payload}))
        return
    if isinstance(payload, dict):
        status = payload.get("status", "pass")
        pending = payload.get("pending")
        suffix = "" if pending is None else f" pending={str(pending).lower()}"
        print(f"evaluation-{action}: {status}{suffix}")
    else:
        print(f"evaluation-{action}: pass")


def _run_evaluation_command(args: argparse.Namespace) -> int:
    """Run one exact local evaluation operation from a strict JSON request."""

    from pydantic import ValidationError

    from consultation_kb.core.config import ConfigurationError
    from consultation_kb.evaluation.runtime import (
        EvaluationRuntime,
        EvaluationRuntimeError,
    )
    from consultation_kb.mcp.evaluation_tools import EvaluationToolRuntime
    from consultation_kb.mcp.schemas import (
        FinalizeEvaluationInput,
        GetNextEvaluationCaseInput,
        PrepareEvaluationInput,
        SubmitEvaluationResultInput,
    )
    from consultation_kb.models.common import StrictModel

    models: dict[str, type[StrictModel]] = {
        "prepare": PrepareEvaluationInput,
        "next": GetNextEvaluationCaseInput,
        "submit": SubmitEvaluationResultInput,
        "finalize": FinalizeEvaluationInput,
    }
    try:
        config = _resolved_config(args)
        request = models[args.evaluation_action].model_validate_json(
            _read_evaluation_request(args.request),
            strict=True,
        )
        runtime = EvaluationToolRuntime(
            EvaluationRuntime(
                repo_root=config.repo_root,
                vault_root=config.vault_root,
            )
        )
        result = runtime.invoke(
            {
                "prepare": "prepare_evaluation",
                "next": "get_next_evaluation_case",
                "submit": "submit_evaluation_result",
                "finalize": "finalize_evaluation",
            }[args.evaluation_action],
            request,
            binding=None,
        )
    except ConfigurationError as error:
        return _evaluation_failure(
            args.evaluation_action,
            error.code,
            json_mode=args.json,
        )
    except EvaluationRuntimeError as error:
        return _evaluation_failure(
            args.evaluation_action,
            error.code,
            json_mode=args.json,
        )
    except _LifecycleCliError as error:
        return _evaluation_failure(
            args.evaluation_action,
            error.code,
            json_mode=args.json,
        )
    except ValidationError:
        return _evaluation_failure(
            args.evaluation_action,
            "EVALUATION_REQUEST_INVALID",
            json_mode=args.json,
        )
    except Exception:
        return _evaluation_failure(
            args.evaluation_action,
            "EVALUATION_COMMAND_FAILED",
            json_mode=args.json,
        )
    _emit_evaluation_result(
        args.evaluation_action,
        result,
        json_mode=args.json,
    )
    return 0


def _run_rebuild_start(args: argparse.Namespace) -> int:
    if args.apply:
        return _lifecycle_failure(
            "rebuild-start",
            "LIFECYCLE_APPROVAL_REQUIRED",
            json_mode=args.json,
        )
    try:
        config, database, reference = _lifecycle_global_target(
            args,
            require_reference=True,
        )
        from consultation_kb.lifecycle.production_rebuild import (
            ProductionRebuildError,
            load_production_rebuild_config,
            resolve_global_rebuild,
        )
        from consultation_kb.lifecycle.rebuild import (
            RebuildCoordinatorError,
            RebuildRequest,
        )
        from consultation_kb.lifecycle.rebuild_registry import BuilderRegistryError
        from consultation_kb.security.scope_identity import (
            global_approval_scope_sha256,
        )

        scope_sha256 = global_approval_scope_sha256(config.vault_root)
        global_root = database.parent.resolve(strict=False)
        production = load_production_rebuild_config(
            global_root,
            database_scope="global",
            scope_sha256=scope_sha256,
        )
        with _guarded_live_reader(config.vault_root, database) as connection:
            coordinator = resolve_global_rebuild(
                connection,
                global_root,
                scope_sha256,
            )
            plan = coordinator.plan(
                RebuildRequest(
                    database_scope="global",
                    scope_sha256=scope_sha256,
                    purpose=args.purpose,
                    policy_sha256=production.policy_sha256,
                    model_descriptor_sha256=(production.model_descriptor_sha256),
                )
            )
        _emit_lifecycle(
            {
                "ok": True,
                "status": "preview",
                "approval_required": True,
                "database_ref_sha256": reference,
                "database_scope": "global",
                "scope_sha256": plan.scope_sha256,
                "purpose": plan.purpose,
                "plan_sha256": plan.plan_sha256,
                "builder_ids": plan.builder_ids,
                "builder_dag_sha256": plan.builder_dag_sha256,
                "input_authority_versions_sha256": (
                    plan.input_authority_versions_sha256
                ),
                "policy_sha256": plan.policy_sha256,
                "model_descriptor_sha256": plan.model_descriptor_sha256,
                "base_versions": [
                    {
                        "authority_key": "tombstone_epoch",
                        "scope_sha256": plan.scope_sha256,
                        "version": plan.tombstone_epoch,
                    }
                ],
            },
            json_mode=args.json,
        )
        return 0
    except (
        BuilderRegistryError,
        ProductionRebuildError,
        RebuildCoordinatorError,
    ) as error:
        return _lifecycle_failure(
            "rebuild-start",
            error.code,
            json_mode=args.json,
        )
    except _LifecycleCliError as error:
        return _lifecycle_failure(
            "rebuild-start",
            error.code,
            json_mode=args.json,
        )
    except Exception:
        return _lifecycle_failure(
            "rebuild-start",
            "REBUILD_PREVIEW_FAILED",
            json_mode=args.json,
        )


def _run_rebuild_status(args: argparse.Namespace) -> int:
    from consultation_kb.lifecycle.rebuild_jobs import (
        RebuildJobError,
        RebuildJobRepository,
    )

    try:
        config, database, reference = _lifecycle_global_target(
            args,
            require_reference=True,
        )
        with _guarded_live_reader(config.vault_root, database) as connection:
            _require_tables(connection, ("rebuild_jobs", "rebuild_job_journal"))
            repository = RebuildJobRepository(
                connection,
                database_scope="global",
            )
            job = repository.get(args.job)
            journal = repository.journal(args.job)
        _emit_lifecycle(
            {
                "ok": True,
                "database_ref_sha256": reference,
                "database_scope": "global",
                "job_id": job.job_id,
                "purpose": job.purpose,
                "state": job.state,
                "attempt_count": job.attempt_count,
                "plan_sha256": job.plan_sha256,
                "output_manifest_set_sha256": job.output_manifest_set_sha256,
                "equivalence_report_sha256": job.equivalence_report_sha256,
                "last_error_code": job.last_error_code,
                "updated_at": job.updated_at,
                "journal": tuple(
                    {
                        "sequence": entry.sequence,
                        "state": entry.state,
                        "evidence_sha256": entry.evidence_sha256,
                        "occurred_at": entry.occurred_at,
                    }
                    for entry in journal
                ),
            },
            json_mode=args.json,
        )
        return 0
    except RebuildJobError as error:
        return _lifecycle_failure(
            "rebuild-status",
            error.code,
            json_mode=args.json,
        )
    except _LifecycleCliError as error:
        return _lifecycle_failure(
            "rebuild-status",
            error.code,
            json_mode=args.json,
        )
    except Exception:
        return _lifecycle_failure(
            "rebuild-status",
            "REBUILD_STATUS_FAILED",
            json_mode=args.json,
        )


def _run_delete_status(args: argparse.Namespace) -> int:
    try:
        config, database, reference = _lifecycle_global_target(
            args,
            require_reference=True,
        )
        with _guarded_live_reader(config.vault_root, database) as connection:
            _require_tables(
                connection,
                ("deletion_requests", "deletion_queue_intents"),
            )
            if args.request is None:
                rows = connection.execute(
                    "SELECT request_id, plan_sha256, target_type, "
                    "target_id_hash, committed_deletion_version, "
                    "tombstone_epoch, state, queue_state, created_at "
                    "FROM deletion_requests ORDER BY created_at, request_id"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT request_id, plan_sha256, target_type, "
                    "target_id_hash, committed_deletion_version, "
                    "tombstone_epoch, state, queue_state, created_at "
                    "FROM deletion_requests WHERE request_id = ?",
                    (args.request,),
                ).fetchall()
            if args.request is not None and not rows:
                raise _LifecycleCliError("DELETION_REQUEST_NOT_FOUND")
            requests = tuple(
                {
                    "request_id": row[0],
                    "plan_sha256": row[1],
                    "target_type": row[2],
                    "target_id_hash": row[3],
                    "deletion_version": row[4],
                    "tombstone_epoch": row[5],
                    "state": row[6],
                    "queue_state": row[7],
                    "created_at": row[8],
                }
                for row in rows
                if len(row) == 9
            )
            if len(requests) != len(rows):
                raise _LifecycleCliError("DELETION_STATUS_INVALID")
        _emit_lifecycle(
            {
                "ok": True,
                "database_ref_sha256": reference,
                "database_scope": "global",
                "requests": requests,
            },
            json_mode=args.json,
        )
        return 0
    except _LifecycleCliError as error:
        return _lifecycle_failure(
            "delete-status",
            error.code,
            json_mode=args.json,
        )
    except Exception:
        return _lifecycle_failure(
            "delete-status",
            "DELETION_STATUS_FAILED",
            json_mode=args.json,
        )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="consultation-kb")
    subcommands = parser.add_subparsers(dest="command", required=True)

    doctor = subcommands.add_parser(
        "doctor",
        help="run local readiness checks without downloading or creating a vault",
    )
    doctor.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Git repository root (defaults to the current directory)",
    )
    doctor.add_argument(
        "--vault-root",
        type=Path,
        default=None,
        help="external vault root (or set CONSULTATION_VAULT_ROOT)",
    )
    doctor.add_argument(
        "--json",
        action="store_true",
        help="write exactly one machine-readable JSON object to stdout",
    )
    doctor.set_defaults(handler=_run_doctor)

    migrate = subcommands.add_parser(
        "migrate",
        help="check existing database migrations without creating or updating files",
    )
    migrate.add_argument(
        "--check",
        action="store_true",
        help="verify migration history and packaged checksums",
    )
    migrate.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Git repository root (defaults to the current directory)",
    )
    migrate.add_argument(
        "--vault-root",
        type=Path,
        default=None,
        help="external vault root (or set CONSULTATION_VAULT_ROOT)",
    )
    migrate.set_defaults(handler=_run_migrate_check)

    review = subcommands.add_parser(
        "review",
        help="interactively review one immutable pending approval request",
    )
    review.add_argument(
        "--request",
        required=True,
        help="opaque approval request identifier",
    )
    review.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Git repository root (defaults to the current directory)",
    )
    review.add_argument(
        "--vault-root",
        type=Path,
        default=None,
        help="external vault root (or set CONSULTATION_VAULT_ROOT)",
    )
    review.set_defaults(handler=_run_review)

    configure_codex = subcommands.add_parser(
        "configure-codex",
        help="validate and install the repository-local Codex MCP configuration",
    )
    configure_codex.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Git repository root (defaults to the current directory)",
    )
    configure_codex.set_defaults(handler=_run_configure_codex)

    models_import = subcommands.add_parser(
        "models-import",
        help="explicitly resolve or import a tracked model for offline use",
    )
    models_import.add_argument(
        "--repo",
        required=True,
        help="exact tracked BAAI repository identifier",
    )
    models_import.add_argument(
        "--source",
        type=Path,
        default=None,
        help="already materialized local snapshot directory",
    )
    models_import.add_argument(
        "--revision",
        default=None,
        help="exact lowercase 40-hex snapshot commit",
    )
    models_import.add_argument(
        "--license",
        dest="license_id",
        default=None,
        help="verified canonical license identifier",
    )
    models_import.add_argument(
        "--resolve-main",
        action="store_true",
        help="explicitly resolve and download the tracked public main snapshot",
    )
    models_import.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Git repository root (defaults to the current directory)",
    )
    models_import.add_argument(
        "--vault-root",
        type=Path,
        default=None,
        help="external vault root (or set CONSULTATION_VAULT_ROOT)",
    )
    models_import.add_argument(
        "--json",
        action="store_true",
        help="write exactly one path-free JSON object to stdout",
    )
    models_import.set_defaults(handler=_run_models_import)

    model_benchmark = subcommands.add_parser(
        "model-benchmark",
        help="run the fixed body-free 2x2 local model benchmark",
    )
    model_benchmark.add_argument(
        "--output-ref",
        required=True,
        type=_safe_policy_key,
        help="opaque lower-snake report reference",
    )
    model_benchmark.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Git repository root (defaults to the current directory)",
    )
    model_benchmark.add_argument(
        "--vault-root",
        type=Path,
        default=None,
        help="external vault root (or set CONSULTATION_VAULT_ROOT)",
    )
    model_benchmark.add_argument(
        "--json",
        action="store_true",
        help="write exactly one path-free JSON object to stdout",
    )
    model_benchmark.set_defaults(handler=_run_model_benchmark)

    for action, help_text in (
        ("prepare", "freeze one synthetic paired evaluation queue"),
        ("next", "read the next controlled synthetic evaluation case"),
        ("submit", "submit one hash-bound evaluation result"),
        ("finalize", "finalize a complete or explicitly incomplete evaluation"),
    ):
        evaluation = subcommands.add_parser(
            f"evaluation-{action}",
            help=help_text,
        )
        evaluation.add_argument(
            "--request",
            type=Path,
            required=True,
            help="strict JSON request matching the corresponding MCP schema",
        )
        evaluation.add_argument(
            "--repo-root",
            type=Path,
            default=Path.cwd(),
            help="Git repository root (defaults to the current directory)",
        )
        evaluation.add_argument(
            "--vault-root",
            type=Path,
            default=None,
            help="external vault root (or set CONSULTATION_VAULT_ROOT)",
        )
        evaluation.add_argument(
            "--json",
            action="store_true",
            help="write exactly one machine-readable JSON object to stdout",
        )
        evaluation.set_defaults(
            handler=_run_evaluation_command,
            evaluation_action=action,
        )

    def add_lifecycle_configuration(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--repo-root",
            type=Path,
            default=Path.cwd(),
            help="Git repository root (defaults to the current directory)",
        )
        command.add_argument(
            "--vault-root",
            type=Path,
            default=None,
            help="external vault root (or set CONSULTATION_VAULT_ROOT)",
        )
        command.add_argument(
            "--json",
            action="store_true",
            help="write exactly one body-free JSON object to stdout",
        )

    recover = subcommands.add_parser(
        "recover",
        help="dry-run lifecycle recovery; formal application requires approval",
    )
    add_lifecycle_configuration(recover)
    recover.add_argument(
        "--apply",
        action="store_true",
        help="resume only durable, exactly pre-approved recovery transitions",
    )
    recover.add_argument(
        "--database-ref-sha256",
        default=None,
        help="exact opaque global database reference (required with --apply)",
    )
    recover.set_defaults(handler=_run_recover)

    recovery_report = subcommands.add_parser(
        "recovery-report",
        help="read body-free global recovery and queue status",
    )
    add_lifecycle_configuration(recovery_report)
    recovery_report.add_argument(
        "--database-ref-sha256",
        default=None,
        help="optional exact opaque global database reference",
    )
    recovery_report.set_defaults(handler=_run_recovery_report)

    rebuild_start = subcommands.add_parser(
        "rebuild-start",
        help="preview a rebuild plan; queueing requires formal approval",
    )
    add_lifecycle_configuration(rebuild_start)
    rebuild_start.add_argument(
        "--purpose",
        type=_safe_policy_key,
        choices=("all",),
        required=True,
        help="full production closure (all)",
    )
    rebuild_start.add_argument(
        "--database-ref-sha256",
        required=True,
        help="exact opaque database reference from recovery-report",
    )
    rebuild_start.add_argument(
        "--apply",
        action="store_true",
        help="request queueing (fails closed without the signed approval channel)",
    )
    rebuild_start.set_defaults(handler=_run_rebuild_start)

    rebuild_status = subcommands.add_parser(
        "rebuild-status",
        help="read one durable rebuild job and its body-free journal",
    )
    add_lifecycle_configuration(rebuild_status)
    rebuild_status.add_argument(
        "--job",
        required=True,
        help="opaque rebuild job identifier",
    )
    rebuild_status.add_argument(
        "--database-ref-sha256",
        required=True,
        help="exact opaque database reference from recovery-report",
    )
    rebuild_status.set_defaults(handler=_run_rebuild_status)

    delete_status = subcommands.add_parser(
        "delete-status",
        help="read tombstone and physical-cleanup status",
    )
    add_lifecycle_configuration(delete_status)
    delete_status.add_argument(
        "--request",
        default=None,
        help="optional exact opaque deletion request identifier",
    )
    delete_status.add_argument(
        "--database-ref-sha256",
        required=True,
        help="exact opaque database reference from recovery-report",
    )
    delete_status.set_defaults(handler=_run_delete_status)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse CLI arguments and return a process exit code."""
    args = _build_parser().parse_args(argv)
    handler = cast(Callable[[argparse.Namespace], int], args.handler)
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
