"""Fail-closed, side-effect-limited readiness checks for consultation-kb."""

from __future__ import annotations

import importlib
import os
import platform
import re
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Final, Literal, Protocol, TypeAlias, final

from pydantic import field_serializer, field_validator, model_validator
from typing_extensions import Self

from consultation_kb.core.config import AppConfig
from consultation_kb.evaluation.privacy_scan import PrivacyScanner
from consultation_kb.models.common import (
    NonNegativeInt,
    SafePolicyKey,
    StrictModel,
)
from consultation_kb.policy.loader import PolicyLoader
from consultation_kb.security.dpapi import create_secret_protector
from consultation_kb.security.ntfs_acl import (
    FULL_CONTROL_MASK,
    AclPolicy,
)
from consultation_kb.security.path_guard import PathGuard
from consultation_kb.storage.connection import connect_database_snapshot
from consultation_kb.storage.manifests import ManifestRepository
from consultation_kb.storage.migrate import MigrationRunner, MigrationScope
from consultation_kb.vault.content_store import ContentStore
from scripts.export_consultation_schemas import export_schemas


DoctorStatus: TypeAlias = Literal["pass", "fail"]
_VaultState: TypeAlias = Literal["absent", "initialized", "invalid"]
DoctorCheckName: TypeAlias = Literal[
    "python_runtime",
    "vault_outside_repo",
    "sqlite_fts5_roundtrip",
    "schema_exports_match",
    "policies_load",
    "git_tracked_privacy",
    "migration_checksums",
    "vault_acl",
    "dpapi_roundtrip",
    "staging_same_volume",
    "identity_map_permissions",
    "prepared_manifests",
    "active_manifests",
]

_CHECK_NAMES: Final[tuple[DoctorCheckName, ...]] = (
    "python_runtime",
    "vault_outside_repo",
    "sqlite_fts5_roundtrip",
    "schema_exports_match",
    "policies_load",
    "git_tracked_privacy",
    "migration_checksums",
    "vault_acl",
    "dpapi_roundtrip",
    "staging_same_volume",
    "identity_map_permissions",
    "prepared_manifests",
    "active_manifests",
)
_PASS_CODES: Final[Mapping[DoctorCheckName, str]] = MappingProxyType(
    {
        "python_runtime": "python_runtime_supported",
        "vault_outside_repo": "vault_roots_disjoint",
        "sqlite_fts5_roundtrip": "sqlite_fts5_roundtrip_ok",
        "schema_exports_match": "schema_exports_match",
        "policies_load": "policies_loaded",
        "git_tracked_privacy": "git_tracked_privacy_clean",
        "migration_checksums": "migration_checksums_match",
        "vault_acl": "vault_acl_verified",
        "dpapi_roundtrip": "dpapi_roundtrip_ok",
        "staging_same_volume": "staging_same_volume_verified",
        "identity_map_permissions": "identity_map_permissions_verified",
        "prepared_manifests": "prepared_manifests_absent",
        "active_manifests": "active_manifests_verified",
    }
)
_NOT_APPLICABLE_CODES: Final[Mapping[DoctorCheckName, str]] = MappingProxyType(
    {
        "migration_checksums": "migration_checksums_not_applicable",
        "vault_acl": "vault_acl_not_applicable",
        "dpapi_roundtrip": "dpapi_roundtrip_not_applicable",
        "staging_same_volume": "staging_same_volume_not_applicable",
        "identity_map_permissions": "identity_map_permissions_not_applicable",
        "prepared_manifests": "prepared_manifests_not_applicable",
        "active_manifests": "active_manifests_not_applicable",
    }
)
_EXPECTED_FAILURE_CODES: Final[Mapping[DoctorCheckName, frozenset[str]]] = (
    MappingProxyType(
        {
            "python_runtime": frozenset({"python_runtime_unsupported"}),
            "vault_outside_repo": frozenset({"vault_root_overlap"}),
            "sqlite_fts5_roundtrip": frozenset(
                {"sqlite_fts5_roundtrip_failed"}
            ),
            "schema_exports_match": frozenset({"schema_exports_drift"}),
            "policies_load": frozenset({"policy_load_failed"}),
            "git_tracked_privacy": frozenset(
                {"git_tracked_privacy_hits"}
            ),
            "migration_checksums": frozenset(
                {"migration_checksums_invalid"}
            ),
            "vault_acl": frozenset({"vault_acl_invalid"}),
            "dpapi_roundtrip": frozenset({"dpapi_roundtrip_failed"}),
            "staging_same_volume": frozenset(
                {"staging_volume_invalid"}
            ),
            "identity_map_permissions": frozenset(
                {"identity_map_permissions_invalid"}
            ),
            "prepared_manifests": frozenset(
                {"prepared_manifests_present"}
            ),
            "active_manifests": frozenset(
                {"active_manifests_invalid"}
            ),
        }
    )
)
_PROBE_FAILURE_CODES: Final[Mapping[DoctorCheckName, str]] = MappingProxyType(
    {
        "python_runtime": "python_runtime_check_failed",
        "vault_outside_repo": "vault_check_failed",
        "sqlite_fts5_roundtrip": "sqlite_fts5_roundtrip_failed",
        "schema_exports_match": "schema_export_check_failed",
        "policies_load": "policy_load_failed",
        "git_tracked_privacy": "git_tracked_privacy_check_failed",
        "migration_checksums": "migration_checksum_check_failed",
        "vault_acl": "vault_acl_check_failed",
        "dpapi_roundtrip": "dpapi_roundtrip_check_failed",
        "staging_same_volume": "staging_volume_check_failed",
        "identity_map_permissions": "identity_map_check_failed",
        "prepared_manifests": "prepared_manifest_check_failed",
        "active_manifests": "active_manifest_check_failed",
    }
)

_CANARY_DEFINITION: Final = Path(
    "tests/fixtures/consultation_kb/canaries.json"
)
_NON_RUNTIME_TRACKED_PREFIXES: Final[tuple[tuple[str, ...], ...]] = (
    ("tests",),
    ("docs", "superpowers", "plans"),
)
_FTS5_MARKER: Final = "doctor_fts5_marker_71d2"
_SQLITE_CONNECT: Callable[..., sqlite3.Connection] = sqlite3.connect
_EXPORT_SCHEMAS: Callable[[Path], None] = export_schemas
_CLIENT_ID_RE: Final = re.compile(r"client_[a-z0-9]{12}\Z")
_REPARSE_ATTRIBUTE: Final = 0x400
_DPAPI_PROBE_BYTES: Final = b"consultation-kb-doctor-roundtrip-v1"


class DoctorCheck(StrictModel):
    """One fixed-code check result with an optional non-sensitive count."""

    status: DoctorStatus
    code: SafePolicyKey
    observed_count: NonNegativeInt | None = None


class DiagnosticProbe(Protocol):
    """One high-level readiness probe injected by the composition root."""

    @property
    def name(self) -> str: ...

    def run(self, config: AppConfig) -> DoctorCheck: ...


class DoctorReport(StrictModel):
    """Exact required-check report suitable for canonical JSON encoding."""

    ok: bool
    checks: Mapping[SafePolicyKey, DoctorCheck]

    @field_validator("checks")
    @classmethod
    def _freeze_exact_checks(
        cls,
        value: Mapping[str, DoctorCheck],
    ) -> Mapping[str, DoctorCheck]:
        if not set(_CHECK_NAMES) <= set(value):
            raise ValueError("doctor report requires every core check")
        extras = sorted(set(value) - set(_CHECK_NAMES))
        if any(
            len(name) > 48
            or _CLIENT_ID_RE.search(name) is not None
            or not value[name].code.startswith(f"{name}_")
            for name in extras
        ):
            raise ValueError("doctor diagnostic probe result is invalid")
        ordered = (*_CHECK_NAMES, *extras)
        return MappingProxyType({name: value[name] for name in ordered})

    @model_validator(mode="after")
    def _validate_status_codes_and_summary(self) -> Self:
        for name in _CHECK_NAMES:
            check = self.checks[name]
            if check.status == "pass":
                allowed_pass_codes = {_PASS_CODES[name]}
                not_applicable = _NOT_APPLICABLE_CODES.get(name)
                if not_applicable is not None:
                    allowed_pass_codes.add(not_applicable)
                if check.code not in allowed_pass_codes:
                    raise ValueError("doctor pass code does not match check")
            else:
                allowed = _EXPECTED_FAILURE_CODES[name] | frozenset(
                    {_PROBE_FAILURE_CODES[name]}
                )
                if check.code not in allowed:
                    raise ValueError("doctor failure code does not match check")
        expected_ok = all(check.status == "pass" for check in self.checks.values())
        if self.ok is not expected_ok:
            raise ValueError("doctor summary does not match required checks")
        return self

    @field_serializer("checks")
    def _serialize_checks(
        self,
        value: Mapping[str, DoctorCheck],
    ) -> dict[str, object]:
        return {name: check.model_dump(mode="json") for name, check in value.items()}


class _ProbeFailure(RuntimeError):
    """Internal marker whose text is never exposed in a DoctorReport."""


def _pass(name: DoctorCheckName, count: int | None = None) -> DoctorCheck:
    return DoctorCheck(
        status="pass",
        code=_PASS_CODES[name],
        observed_count=count,
    )


def _fail(code: str, count: int | None = None) -> DoctorCheck:
    return DoctorCheck(status="fail", code=code, observed_count=count)


def _not_applicable(name: DoctorCheckName) -> DoctorCheck:
    code = _NOT_APPLICABLE_CODES.get(name)
    if code is None:
        raise _ProbeFailure
    return DoctorCheck(status="pass", code=code, observed_count=0)


def _check_python_runtime(_config: AppConfig) -> DoctorCheck:
    pointer_bits = struct.calcsize("P") * 8
    supported = (
        platform.python_implementation() == "CPython"
        and sys.version_info[:2] == (3, 12)
        and pointer_bits == 64
    )
    if not supported:
        return _fail("python_runtime_unsupported", pointer_bits)
    return _pass("python_runtime", pointer_bits)


def _normalized_identity(path: Path) -> str:
    return os.path.normcase(os.path.normpath(os.fspath(path)))


def _check_vault_outside_repo(config: AppConfig) -> DoctorCheck:
    repo = _normalized_identity(config.repo_root)
    vault = _normalized_identity(config.vault_root)
    if not os.path.isabs(repo) or not os.path.isabs(vault):
        raise _ProbeFailure
    try:
        common = os.path.commonpath((repo, vault))
    except ValueError:
        return _pass("vault_outside_repo")
    if common == repo or common == vault:
        return _fail("vault_root_overlap")
    return _pass("vault_outside_repo")


def _check_sqlite_fts5(_config: AppConfig) -> DoctorCheck:
    connection: sqlite3.Connection | None = None
    try:
        connection = _SQLITE_CONNECT(":memory:")
        connection.execute(
            "CREATE VIRTUAL TABLE doctor_fts USING fts5(document_text)"
        )
        connection.execute(
            "INSERT INTO doctor_fts(document_text) VALUES (?)",
            (_FTS5_MARKER,),
        )
        row = connection.execute(
            "SELECT count(*) FROM doctor_fts "
            "WHERE doctor_fts MATCH ?",
            (_FTS5_MARKER,),
        ).fetchone()
        if row != (1,):
            return _fail("sqlite_fts5_roundtrip_failed", 0)
        return _pass("sqlite_fts5_roundtrip", 1)
    except Exception:
        return _fail("sqlite_fts5_roundtrip_failed")
    finally:
        if connection is not None:
            connection.close()


def _read_schema_bytes(root: Path) -> dict[str, bytes]:
    if not root.is_dir():
        return {}
    schemas: dict[str, bytes] = {}
    for path in sorted(root.glob("*.schema.json"), key=lambda item: item.name):
        status = path.lstat()
        attributes = int(getattr(status, "st_file_attributes", 0))
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        if (
            path.is_symlink()
            or attributes & reparse_flag
            or not stat.S_ISREG(status.st_mode)
        ):
            raise _ProbeFailure
        schemas[path.name] = path.read_bytes()
    return schemas


def _check_schema_exports(config: AppConfig) -> DoctorCheck:
    with tempfile.TemporaryDirectory(prefix="consultation-kb-doctor-") as raw:
        generated_root = Path(raw) / "schemas"
        _EXPORT_SCHEMAS(generated_root)
        generated = _read_schema_bytes(generated_root)
        checked_in = _read_schema_bytes(config.repo_root / "schemas")
    if generated != checked_in:
        return _fail("schema_exports_drift", len(checked_in))
    return _pass("schema_exports_match", len(generated))


def _check_policies(config: AppConfig) -> DoctorCheck:
    try:
        bundle = PolicyLoader.from_config(config).load_all()
    except Exception:
        return _fail("policy_load_failed")
    loaded = (
        bundle.evidence_levels,
        bundle.relation_types,
        bundle.retention,
        bundle.risk_rules,
    )
    return _pass("policies_load", len(loaded))


def _git_tracked_paths(repo_root: Path) -> tuple[Path, ...]:
    result = subprocess.run(
        [
            "git",
            "-c",
            "core.quotepath=false",
            "-C",
            os.fspath(repo_root),
            "ls-files",
            "--cached",
            "-z",
            "--",
        ],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0 or not result.stdout:
        raise _ProbeFailure
    if not result.stdout.endswith(b"\0"):
        raise _ProbeFailure
    encoded_paths = result.stdout[:-1].split(b"\0")
    if not encoded_paths or len(encoded_paths) != len(set(encoded_paths)):
        raise _ProbeFailure

    repo_identity = _normalized_identity(repo_root)
    paths: list[Path] = []
    for encoded in encoded_paths:
        try:
            text = encoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise _ProbeFailure from None
        relative = PurePosixPath(text)
        if (
            not text
            or "\\" in text
            or relative.is_absolute()
            or relative.as_posix() != text
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise _ProbeFailure
        candidate = repo_root.joinpath(*relative.parts)
        candidate_identity = _normalized_identity(candidate.resolve(strict=False))
        try:
            common = os.path.commonpath((repo_identity, candidate_identity))
        except ValueError:
            raise _ProbeFailure from None
        if common != repo_identity:
            raise _ProbeFailure
        paths.append(candidate)
    return tuple(paths)


def _check_git_tracked_privacy(config: AppConfig) -> DoctorCheck:
    tracked = _git_tracked_paths(config.repo_root)
    catalog = config.repo_root / _CANARY_DEFINITION
    if catalog not in tracked:
        raise _ProbeFailure
    scan_paths = tuple(
        path
        for path in tracked
        if not any(
            path.relative_to(config.repo_root).parts[: len(prefix)] == prefix
            for prefix in _NON_RUNTIME_TRACKED_PREFIXES
        )
    )
    if not scan_paths:
        raise _ProbeFailure
    scanner = PrivacyScanner.default(
        profile="repo_tracked",
        canary_definition_path=catalog,
    )
    outcome = scanner.scan_paths(scan_paths)
    hit_count = outcome.report.hit_count
    if hit_count:
        return _fail("git_tracked_privacy_hits", hit_count)
    return _pass("git_tracked_privacy", 0)


@dataclass(frozen=True, slots=True)
class _DatabaseScope:
    migration_scope: MigrationScope
    database_path: Path
    scope_root: Path


def _safe_directory(path: Path) -> bool:
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


def _safe_regular_file(path: Path) -> bool:
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


def _vault_state(config: AppConfig) -> _VaultState:
    root = config.vault_root
    try:
        status = os.lstat(root)
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "invalid"
    attributes = int(getattr(status, "st_file_attributes", 0))
    if (
        not stat.S_ISDIR(status.st_mode)
        or stat.S_ISLNK(status.st_mode)
        or attributes & _REPARSE_ATTRIBUTE
    ):
        return "invalid"
    global_root = root / "global"
    catalog = global_root / "catalog.sqlite3"
    try:
        global_status = os.lstat(global_root)
    except FileNotFoundError:
        try:
            if any(
                os.path.lexists(root / marker)
                for marker in ("clients", "identity", "security")
            ):
                return "invalid"
        except OSError:
            return "invalid"
        return "absent"
    except OSError:
        return "invalid"
    global_attributes = int(
        getattr(global_status, "st_file_attributes", 0)
    )
    if (
        not stat.S_ISDIR(global_status.st_mode)
        or stat.S_ISLNK(global_status.st_mode)
        or global_attributes & _REPARSE_ATTRIBUTE
    ):
        return "invalid"
    return "initialized" if _safe_regular_file(catalog) else "invalid"


def _p1_gate(
    config: AppConfig,
    name: DoctorCheckName,
    *,
    invalid_code: str,
) -> DoctorCheck | None:
    state = _vault_state(config)
    if state == "absent":
        return _not_applicable(name)
    if state == "invalid":
        return _fail(invalid_code)
    return None


def _require_direct_child(parent: Path, child: Path, *, directory: bool) -> None:
    if child.parent != parent:
        raise _ProbeFailure
    safe = _safe_directory(child) if directory else _safe_regular_file(child)
    if not safe:
        raise _ProbeFailure


@contextmanager
def _open_checked_database(
    scope: _DatabaseScope,
) -> Iterator[sqlite3.Connection]:
    _require_direct_child(
        scope.scope_root,
        scope.database_path,
        directory=False,
    )
    try:
        guard = PathGuard(scope.scope_root)
        with guard.pin_root():
            with guard.open_scoped(scope.database_path.name, mode="rb"):
                connection = connect_database_snapshot(scope.database_path)
                try:
                    MigrationRunner.for_scope(
                        connection,
                        scope.migration_scope,
                    ).check()
                    yield connection
                finally:
                    connection.close()
    except _ProbeFailure:
        raise
    except Exception:
        raise _ProbeFailure from None


def _database_scopes(config: AppConfig) -> tuple[_DatabaseScope, ...]:
    vault = config.vault_root
    global_root = vault / "global"
    clients_root = vault / "clients"
    _require_direct_child(vault, global_root, directory=True)
    _require_direct_child(vault, clients_root, directory=True)
    global_scope = _DatabaseScope(
        migration_scope="global",
        database_path=global_root / "catalog.sqlite3",
        scope_root=global_root,
    )
    with _open_checked_database(global_scope) as connection:
        try:
            rows = connection.execute(
                "SELECT client_id FROM clients WHERE state = 'ACTIVE' "
                "ORDER BY client_id"
            ).fetchall()
        except sqlite3.DatabaseError:
            raise _ProbeFailure from None
    identifiers = tuple(str(row[0]) for row in rows if len(row) == 1)
    if (
        len(identifiers) != len(rows)
        or len(set(identifiers)) != len(identifiers)
        or any(_CLIENT_ID_RE.fullmatch(value) is None for value in identifiers)
    ):
        raise _ProbeFailure
    client_scopes: list[_DatabaseScope] = []
    for client_id in identifiers:
        client_root = clients_root / client_id
        _require_direct_child(clients_root, client_root, directory=True)
        client_scopes.append(
            _DatabaseScope(
                migration_scope="client",
                database_path=client_root / "client.sqlite3",
                scope_root=client_root,
            )
        )
    return (global_scope, *client_scopes)


def _check_migration_checksums(config: AppConfig) -> DoctorCheck:
    gated = _p1_gate(
        config,
        "migration_checksums",
        invalid_code="migration_checksums_invalid",
    )
    if gated is not None:
        return gated
    try:
        scopes = _database_scopes(config)
        for scope in scopes:
            with _open_checked_database(scope):
                pass
    except Exception:
        return _fail("migration_checksums_invalid")
    return _pass("migration_checksums", len(scopes))


def _check_vault_acl(config: AppConfig) -> DoctorCheck:
    gated = _p1_gate(config, "vault_acl", invalid_code="vault_acl_invalid")
    if gated is not None:
        return gated
    try:
        vault_root = config.vault_root
        clients_root = vault_root / "clients"
        identity_root = vault_root / "identity"
        security_root = vault_root / "security"
        _require_direct_child(vault_root, clients_root, directory=True)
        _require_direct_child(vault_root, identity_root, directory=True)
        security_directories: tuple[Path, ...] = ()
        if os.path.lexists(security_root):
            _require_direct_child(vault_root, security_root, directory=True)
            security_directories = (security_root,)
        database_scopes = _database_scopes(config)
        if not database_scopes or database_scopes[0].migration_scope != "global":
            raise _ProbeFailure
        protected_directories = (
            vault_root,
            database_scopes[0].scope_root,
            clients_root,
            identity_root,
            *security_directories,
            *(scope.scope_root for scope in database_scopes[1:]),
        )
        policy = AclPolicy()
        principal_count: int | None = None
        for directory in protected_directories:
            verification = policy.verify(directory)
            if principal_count is None:
                principal_count = verification.allowed_principal_count
            elif verification.allowed_principal_count != principal_count:
                raise _ProbeFailure
        if principal_count is None:
            raise _ProbeFailure
    except Exception:
        return _fail("vault_acl_invalid")
    return _pass("vault_acl", principal_count)


def _check_dpapi_roundtrip(config: AppConfig) -> DoctorCheck:
    gated = _p1_gate(
        config,
        "dpapi_roundtrip",
        invalid_code="dpapi_roundtrip_failed",
    )
    if gated is not None:
        return gated
    try:
        protector = create_secret_protector()
        vault_id = sha256(
            _normalized_identity(config.vault_root).encode("utf-8")
        ).hexdigest()
        blob = protector.protect(
            _DPAPI_PROBE_BYTES,
            purpose="doctor_roundtrip",
            vault_id=vault_id,
        )
        recovered = protector.unprotect(
            blob,
            purpose="doctor_roundtrip",
            vault_id=vault_id,
        )
        if recovered != _DPAPI_PROBE_BYTES or blob == _DPAPI_PROBE_BYTES:
            raise _ProbeFailure
    except Exception:
        return _fail("dpapi_roundtrip_failed")
    return _pass("dpapi_roundtrip", 1)


def _check_staging_same_volume(config: AppConfig) -> DoctorCheck:
    gated = _p1_gate(
        config,
        "staging_same_volume",
        invalid_code="staging_volume_invalid",
    )
    if gated is not None:
        return gated
    try:
        scopes = _database_scopes(config)
        verified_count = 0
        for scope in scopes:
            staging = scope.scope_root / ".staging"
            objects = scope.scope_root / "objects"
            staging_exists = staging.exists()
            objects_exist = objects.exists()
            if staging_exists is not objects_exist:
                raise _ProbeFailure
            if not staging_exists:
                continue
            _require_direct_child(scope.scope_root, staging, directory=True)
            _require_direct_child(scope.scope_root, objects, directory=True)
            devices = {
                os.stat(scope.scope_root, follow_symlinks=False).st_dev,
                os.stat(staging, follow_symlinks=False).st_dev,
                os.stat(objects, follow_symlinks=False).st_dev,
            }
            if len(devices) != 1:
                raise _ProbeFailure
            verified_count += 1
    except Exception:
        return _fail("staging_volume_invalid")
    return _pass("staging_same_volume", verified_count)


@dataclass(frozen=True, slots=True)
class _IdentityFileAcl:
    owner_sid: str
    control: int
    entries: tuple[tuple[int, int, int, str], ...]

    @property
    def principal_count(self) -> int:
        return len(self.entries)


def _identity_file_acl(path: Path) -> _IdentityFileAcl:
    if sys.platform != "win32":
        raise _ProbeFailure
    try:
        win32api = importlib.import_module("win32api")
        win32con = importlib.import_module("win32con")
        win32security = importlib.import_module("win32security")
        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32con.TOKEN_QUERY,
        )
        current_sid, _attributes = win32security.GetTokenInformation(
            token,
            win32security.TokenUser,
        )
        system_sid = win32security.CreateWellKnownSid(
            win32security.WinLocalSystemSid,
            None,
        )
        current_text = win32security.ConvertSidToStringSid(current_sid).upper()
        allowed = {
            current_text,
            win32security.ConvertSidToStringSid(system_sid).upper(),
        }
        security = win32security.GetNamedSecurityInfo(
            os.fspath(path),
            win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION
            | win32security.DACL_SECURITY_INFORMATION,
        )
        owner = win32security.ConvertSidToStringSid(
            security.GetSecurityDescriptorOwner()
        ).upper()
        control, _revision = security.GetSecurityDescriptorControl()
        dacl = security.GetSecurityDescriptorDacl()
        if owner != current_text or dacl is None:
            raise _ProbeFailure
        observed: list[str] = []
        entries: list[tuple[int, int, int, str]] = []
        for index in range(dacl.GetAceCount()):
            header, mask, sid = dacl.GetAce(index)
            ace_type, ace_flags = header
            sid_text = win32security.ConvertSidToStringSid(sid).upper()
            if (
                int(ace_type) != win32security.ACCESS_ALLOWED_ACE_TYPE
                or int(mask) & FULL_CONTROL_MASK != FULL_CONTROL_MASK
                or sid_text not in allowed
            ):
                raise _ProbeFailure
            observed.append(sid_text)
            entries.append(
                (int(ace_type), int(ace_flags), int(mask), sid_text)
            )
        if set(observed) != allowed or len(observed) != len(allowed):
            raise _ProbeFailure
        return _IdentityFileAcl(
            owner_sid=owner,
            control=int(control),
            entries=tuple(entries),
        )
    except _ProbeFailure:
        raise
    except Exception:
        raise _ProbeFailure from None


def _check_identity_map_permissions(config: AppConfig) -> DoctorCheck:
    gated = _p1_gate(
        config,
        "identity_map_permissions",
        invalid_code="identity_map_permissions_invalid",
    )
    if gated is not None:
        return gated
    identity_root = config.vault_root / "identity"
    identity_map = identity_root / "identity-map.enc"
    identity_lock = identity_root / ".identity-map.lock"
    try:
        _require_direct_child(config.vault_root, identity_root, directory=True)
        _require_direct_child(identity_root, identity_map, directory=False)
        map_acl = _identity_file_acl(identity_map)
        if os.path.lexists(identity_lock):
            _require_direct_child(identity_root, identity_lock, directory=False)
            if _identity_file_acl(identity_lock) != map_acl:
                raise _ProbeFailure
    except Exception:
        return _fail("identity_map_permissions_invalid")
    return _pass("identity_map_permissions", map_acl.principal_count)


def _check_prepared_manifests(config: AppConfig) -> DoctorCheck:
    gated = _p1_gate(
        config,
        "prepared_manifests",
        invalid_code="prepared_manifest_check_failed",
    )
    if gated is not None:
        return gated
    try:
        prepared_count = 0
        for scope in _database_scopes(config):
            with _open_checked_database(scope) as connection:
                prepared_count += int(
                    connection.execute(
                        "SELECT count(*) FROM publication_operations "
                        "WHERE state = 'PREPARED'"
                    ).fetchone()[0]
                )
                prepared_count += int(
                    connection.execute(
                        "SELECT count(*) FROM artifact_manifests "
                        "WHERE state = 'PREPARED'"
                    ).fetchone()[0]
                )
                prepared_count += int(
                    connection.execute(
                        "SELECT count(*) FROM runtime_epochs "
                        "WHERE state = 'PREPARED'"
                    ).fetchone()[0]
                )
    except Exception:
        return _fail("prepared_manifest_check_failed")
    if prepared_count:
        return _fail("prepared_manifests_present", prepared_count)
    return _pass("prepared_manifests", 0)


def _verify_active_manifests(scope: _DatabaseScope) -> int:
    with _open_checked_database(scope) as connection:
        active_epoch_count = int(
            connection.execute(
                "SELECT count(*) FROM runtime_epochs WHERE state = 'ACTIVE'"
            ).fetchone()[0]
        )
        if active_epoch_count > 1:
            raise _ProbeFailure
        rows = connection.execute(
            "SELECT aa.epoch, aa.artifact_key "
            "FROM active_artifacts AS aa "
            "JOIN runtime_epochs AS re ON re.epoch = aa.epoch "
            "WHERE re.state IN ('ACTIVE', 'RETIRED') "
            "ORDER BY aa.epoch, aa.artifact_key"
        ).fetchall()
        all_pointer_count = int(
            connection.execute("SELECT count(*) FROM active_artifacts").fetchone()[0]
        )
        if len(rows) != all_pointer_count:
            raise _ProbeFailure
        active_manifest_ids = {
            str(row[0])
            for row in connection.execute(
                "SELECT manifest_id FROM artifact_manifests WHERE state = 'ACTIVE'"
            ).fetchall()
        }
        referenced_manifest_ids = {
            str(row[0])
            for row in connection.execute(
                "SELECT DISTINCT manifest_id FROM active_artifacts"
            ).fetchall()
        }
        if active_manifest_ids != referenced_manifest_ids:
            raise _ProbeFailure
        repository = ManifestRepository(connection)
        store = ContentStore(scope.scope_root)
        verified_count = 0
        for epoch_value, artifact_key in rows:
            manifest = repository.get_active(
                str(artifact_key),
                epoch=int(epoch_value),
            )
            if not manifest.verified:
                raise _ProbeFailure
            for member in manifest.members:
                reference = store.reference(
                    content_sha256=member.object_sha256,
                    media_type=member.media_type,
                    size_bytes=member.size_bytes,
                )
                store.read_verified(reference)
            verified_count += 1
        return verified_count


def _check_active_manifests(config: AppConfig) -> DoctorCheck:
    gated = _p1_gate(
        config,
        "active_manifests",
        invalid_code="active_manifests_invalid",
    )
    if gated is not None:
        return gated
    try:
        verified_count = sum(
            _verify_active_manifests(scope)
            for scope in _database_scopes(config)
        )
    except Exception:
        return _fail("active_manifests_invalid")
    return _pass("active_manifests", verified_count)


_CHECK_OPERATIONS: Final[
    Mapping[DoctorCheckName, Callable[[AppConfig], DoctorCheck]]
] = MappingProxyType(
    {
        "python_runtime": _check_python_runtime,
        "vault_outside_repo": _check_vault_outside_repo,
        "sqlite_fts5_roundtrip": _check_sqlite_fts5,
        "schema_exports_match": _check_schema_exports,
        "policies_load": _check_policies,
        "git_tracked_privacy": _check_git_tracked_privacy,
        "migration_checksums": _check_migration_checksums,
        "vault_acl": _check_vault_acl,
        "dpapi_roundtrip": _check_dpapi_roundtrip,
        "staging_same_volume": _check_staging_same_volume,
        "identity_map_permissions": _check_identity_map_permissions,
        "prepared_manifests": _check_prepared_manifests,
        "active_manifests": _check_active_manifests,
    }
)


@final
class Doctor:
    """Run every required readiness probe and retain only fixed safe output."""

    __slots__ = ("_config", "_diagnostic_probes")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("DOCTOR_SUBCLASS_FORBIDDEN")

    def __init__(
        self,
        config: AppConfig,
        *,
        diagnostic_probes: tuple[DiagnosticProbe, ...] = (),
    ) -> None:
        if (
            type(self) is not Doctor
            or type(config) is not AppConfig
            or type(diagnostic_probes) is not tuple
        ):
            raise TypeError("DOCTOR_VALIDATED_CONFIG_REQUIRED")
        names: list[str] = []
        for probe in diagnostic_probes:
            name = getattr(probe, "name", None)
            run = getattr(probe, "run", None)
            if (
                type(name) is not str
                or not 1 <= len(name) <= 48
                or re.fullmatch(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*", name) is None
                or _CLIENT_ID_RE.search(name) is not None
                or name in _CHECK_NAMES
                or not callable(run)
            ):
                raise TypeError("DOCTOR_DIAGNOSTIC_PROBES_INVALID")
            names.append(name)
        if len(names) != len(set(names)):
            raise TypeError("DOCTOR_DIAGNOSTIC_PROBES_INVALID")
        self._config = config
        self._diagnostic_probes = tuple(
            probe
            for _name, probe in sorted(
                zip(names, diagnostic_probes, strict=True),
                key=lambda item: item[0],
            )
        )

    def __repr__(self) -> str:
        return "<Doctor redacted>"

    def run(self) -> DoctorReport:
        checks: dict[str, DoctorCheck] = {}
        for name in _CHECK_NAMES:
            try:
                check = _CHECK_OPERATIONS[name](self._config)
                if type(check) is not DoctorCheck:
                    raise _ProbeFailure
            except Exception:
                check = _fail(_PROBE_FAILURE_CODES[name])
            checks[name] = check
        for probe in self._diagnostic_probes:
            diagnostic_name = probe.name
            try:
                check = probe.run(self._config)
                if (
                    type(check) is not DoctorCheck
                    or not check.code.startswith(f"{diagnostic_name}_")
                ):
                    raise _ProbeFailure
            except Exception:
                check = _fail(f"{diagnostic_name}_probe_failed")
            checks[diagnostic_name] = check
        return DoctorReport(
            ok=all(check.status == "pass" for check in checks.values()),
            checks=checks,
        )


__all__ = ["DiagnosticProbe", "Doctor", "DoctorCheck", "DoctorReport"]
