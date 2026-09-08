"""Validated, redacted roots for the consultation knowledge base."""

from __future__ import annotations

import ctypes
import ntpath
import os
import posixpath
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, TypeAlias, cast, final


SCOPE_INTERACTION_MODE: Final[Literal["codex_text"]] = "codex_text"
SCOPE_SINGLE_COUNSELOR: Final[Literal[True]] = True
SCOPE_RUNTIME_NETWORK_INGEST: Final[Literal[False]] = False
SCOPE_AUTOMATIC_FORMAL_WRITEBACK: Final[Literal[False]] = False

PathInput: TypeAlias = str | os.PathLike[str]


_SCOPE_TYPES_AND_VALUES: Final[tuple[tuple[str, type[object], object], ...]] = (
    ("interaction_mode", str, SCOPE_INTERACTION_MODE),
    ("single_counselor", bool, SCOPE_SINGLE_COUNSELOR),
    ("runtime_network_ingest", bool, SCOPE_RUNTIME_NETWORK_INGEST),
    (
        "automatic_formal_writeback",
        bool,
        SCOPE_AUTOMATIC_FORMAL_WRITEBACK,
    ),
)
_WINDOWS_LOCAL_DRIVE_TYPES: Final[frozenset[int]] = frozenset({2, 3, 5, 6})
_WINDOWS_RESERVED_NAMES: Final[frozenset[str]] = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }
)
_WINDOWS_ALIAS_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[^ .\\/:]{1,6}~[0-9]{1,6}(?:\.[^ .\\/:]{1,3})?$",
    flags=re.ASCII | re.IGNORECASE,
)
_ENV_VAULT_ROOT: Final = "CONSULTATION_VAULT_ROOT"
_ENV_PYTHON: Final = "CONSULTATION_PYTHON"
_ENV_RESERVED: Final[frozenset[str]] = frozenset(
    {
        "CONSULTATION_RESOLVER_SCENARIO",
        "CONSULTATION_RESOLVER_SCENARIO_LOG",
        "CONSULTATION_FAULT_POINT",
    }
)
_ENV_KNOWN: Final[frozenset[str]] = frozenset({_ENV_VAULT_ROOT, _ENV_PYTHON})


class ConfigurationError(ValueError):
    """A fixed-code configuration failure with no caller-controlled text."""

    code: str
    field: str | None

    def __init__(self, code: str, field: str | None = None) -> None:
        self.code = code
        self.field = field
        message = code if field is None else f"{code}:{field}"
        super().__init__(message)


def _path_error(code: str, field: str) -> ConfigurationError:
    return ConfigurationError(code, field)


def _stdlib_lexists(value: PathInput) -> bool:
    return os.path.lexists(value)


def _stdlib_lstat(value: PathInput) -> os.stat_result:
    return os.lstat(value)


def _stdlib_realpath(value: str) -> str:
    return os.path.realpath(value, strict=False)


def _stdlib_windows_drive_type(root: str) -> int:
    drive_type: int | None = None
    query_failed = False
    try:
        get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
        get_drive_type.argtypes = (ctypes.c_wchar_p,)
        get_drive_type.restype = ctypes.c_uint
        drive_type = int(get_drive_type(root))
    except Exception:
        query_failed = True
    if query_failed or drive_type is None:
        raise OSError
    return drive_type


_LEXISTS: Callable[[PathInput], bool] = _stdlib_lexists
_LSTAT: Callable[[PathInput], os.stat_result] = _stdlib_lstat
_REALPATH: Callable[[str], str] = _stdlib_realpath
_DRIVE_TYPE_QUERY: Callable[[str], int] = _stdlib_windows_drive_type


def _snapshot_builtin_string(value: object) -> str | None:
    if not issubclass(type(value), str):
        return None
    return str.__str__(cast(str, value))


def _coerce_raw_path(value: object, field: str) -> str:
    raw = _snapshot_builtin_string(value)
    if raw is None:
        candidate: object = None
        coercion_failed = False
        try:
            candidate = os.fspath(value)  # type: ignore[call-overload]
        except Exception:
            coercion_failed = True
        if coercion_failed:
            raise _path_error("CONFIG_PATH_TYPE", field)
        raw = _snapshot_builtin_string(candidate)
        if raw is None:
            raise _path_error("CONFIG_PATH_TYPE", field)
    if not str.strip(raw):
        raise _path_error("CONFIG_PATH_EMPTY", field)
    if any(ord(character) < 32 or ord(character) == 127 for character in raw):
        raise _path_error("CONFIG_PATH_NUL_OR_CONTROL", field)
    return raw


def _raw_parts(raw: str, *, windows: bool) -> tuple[str, ...]:
    if windows:
        _drive, tail = ntpath.splitdrive(raw)
        return tuple(tail.replace("/", "\\").split("\\"))
    return tuple(raw.split("/"))


def _validate_raw_syntax(raw: str, field: str, *, windows: bool) -> None:
    if windows:
        drive, tail = ntpath.splitdrive(raw)
        if raw.startswith(("\\\\", "//", "\\??\\", "/??/")):
            raise _path_error("CONFIG_PATH_NAMESPACE_UNSUPPORTED", field)
        if drive:
            ordinary_drive = (
                len(drive) == 2
                and drive[0].isascii()
                and drive[0].isalpha()
                and drive[1] == ":"
            )
            if not ordinary_drive or not tail or tail[0] not in "\\/":
                raise _path_error("CONFIG_PATH_NAMESPACE_UNSUPPORTED", field)
            absolute = ntpath.isabs(raw)
        elif ntpath.isabs(raw) or raw.startswith(("\\", "/")):
            raise _path_error("CONFIG_PATH_NAMESPACE_UNSUPPORTED", field)
        else:
            absolute = False
    else:
        absolute = posixpath.isabs(raw)
    if not absolute:
        raise _path_error("CONFIG_PATH_NOT_ABSOLUTE", field)
    if any(part in {".", ".."} for part in _raw_parts(raw, windows=windows)):
        raise _path_error("CONFIG_PATH_TRAVERSAL", field)


def _validate_windows_drive(raw: str, field: str) -> None:
    drive, tail = ntpath.splitdrive(raw)
    ordinary_drive = (
        len(drive) == 2
        and drive[0].isascii()
        and drive[0].isalpha()
        and drive[1] == ":"
        and bool(tail)
        and tail[0] in "\\/"
    )
    if not ordinary_drive:
        raise _path_error("CONFIG_PATH_NAMESPACE_UNSUPPORTED", field)
    drive_type: object = None
    query_failed = False
    try:
        drive_type = _DRIVE_TYPE_QUERY(f"{drive}\\")
    except Exception:
        query_failed = True
    if (
        query_failed
        or type(drive_type) is not int
        or drive_type not in _WINDOWS_LOCAL_DRIVE_TYPES
    ):
        raise _path_error("CONFIG_PATH_DRIVE_UNSUPPORTED", field)


def _validate_path_components(raw: str, field: str, *, windows: bool) -> None:
    if not windows:
        return
    for component in _raw_parts(raw, windows=True):
        if not component:
            continue
        base_name = component.split(".", 1)[0]
        if (
            ":" in component
            or "*" in component
            or "?" in component
            or component.endswith((".", " "))
            or base_name.upper() in _WINDOWS_RESERVED_NAMES
        ):
            raise _path_error("CONFIG_PATH_COMPONENT_UNSUPPORTED", field)
        if _WINDOWS_ALIAS_PATTERN.fullmatch(component) is not None:
            raise _path_error("CONFIG_PATH_ALIAS_UNSUPPORTED", field)


def _path_prefixes(path: str, *, windows: bool) -> tuple[str, ...]:
    if windows:
        drive, tail = ntpath.splitdrive(path)
        root = f"{drive}\\"
        parts = tuple(
            part for part in tail.replace("/", "\\").split("\\") if part
        )
        prefixes = [root]
        current = root
        for part in parts:
            current = ntpath.join(current, part)
            prefixes.append(current)
        return tuple(prefixes)
    parts = tuple(part for part in path.split("/") if part)
    prefixes = ["/"]
    current = "/"
    for part in parts:
        current = posixpath.join(current, part)
        prefixes.append(current)
    return tuple(prefixes)


def _status_is_reparse(status: object, field: str) -> bool:
    mode: object = None
    attributes: object = None
    inspection_failed = False
    try:
        mode = getattr(status, "st_mode", None)
        attributes = getattr(status, "st_file_attributes", 0)
    except Exception:
        inspection_failed = True
    if (
        inspection_failed
        or type(mode) is not int
        or type(attributes) is not int
    ):
        raise _path_error("CONFIG_PATH_INSPECTION_FAILED", field)
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(mode) or bool(attributes & reparse_flag)


def _inspect_prefixes(path: str, field: str, *, windows: bool) -> None:
    for prefix in _path_prefixes(path, windows=windows):
        exists_or_link: object = None
        inspection_failed = False
        try:
            exists_or_link = _LEXISTS(prefix)
        except Exception:
            inspection_failed = True
        if inspection_failed:
            raise _path_error("CONFIG_PATH_INSPECTION_FAILED", field)
        if type(exists_or_link) is not bool:
            raise _path_error("CONFIG_PATH_INSPECTION_FAILED", field)
        status: object = None
        if not exists_or_link:
            prefix_missing = False
            inspection_failed = False
            try:
                status = _LSTAT(prefix)
            except FileNotFoundError:
                prefix_missing = True
            except Exception:
                inspection_failed = True
            if inspection_failed:
                raise _path_error("CONFIG_PATH_INSPECTION_FAILED", field)
            if prefix_missing:
                break
        else:
            inspection_failed = False
            try:
                status = _LSTAT(prefix)
            except Exception:
                inspection_failed = True
            if inspection_failed:
                raise _path_error("CONFIG_PATH_INSPECTION_FAILED", field)
        if _status_is_reparse(status, field):
            raise _path_error("CONFIG_PATH_REPARSE", field)


def _normalize_root(value: object, field: str) -> Path:
    raw = _coerce_raw_path(value, field)
    windows = os.name == "nt"
    _validate_raw_syntax(raw, field, windows=windows)
    if windows:
        _validate_windows_drive(raw, field)
    _validate_path_components(raw, field, windows=windows)
    path_module = ntpath if windows else posixpath
    normalized = path_module.normpath(raw)
    _inspect_prefixes(normalized, field, windows=windows)
    canonical_result: object = None
    inspection_failed = False
    try:
        canonical_result = _REALPATH(normalized)
    except Exception:
        inspection_failed = True
    if inspection_failed:
        raise _path_error("CONFIG_PATH_INSPECTION_FAILED", field)
    canonical = _snapshot_builtin_string(canonical_result)
    if canonical is None:
        raise _path_error("CONFIG_PATH_INSPECTION_FAILED", field)
    if windows:
        _validate_raw_syntax(canonical, field, windows=True)
        _validate_windows_drive(canonical, field)
        _validate_path_components(canonical, field, windows=True)
    elif not path_module.isabs(canonical):
        raise _path_error("CONFIG_PATH_INSPECTION_FAILED", field)
    _inspect_prefixes(canonical, field, windows=windows)
    return Path(canonical)


def _canonical_identity(value: str | os.PathLike[str], *, windows: bool) -> str:
    raw = os.fspath(value)
    if windows:
        return ntpath.normcase(ntpath.normpath(raw))
    return posixpath.normpath(raw)


def _roots_overlap(
    repo_root: str | os.PathLike[str],
    vault_root: str | os.PathLike[str],
    *,
    windows: bool,
) -> bool:
    repo_identity = _canonical_identity(repo_root, windows=windows)
    vault_identity = _canonical_identity(vault_root, windows=windows)
    if repo_identity == vault_identity:
        return True
    try:
        common = (
            ntpath.commonpath((repo_identity, vault_identity))
            if windows
            else posixpath.commonpath((repo_identity, vault_identity))
        )
    except ValueError:
        return False
    return common == repo_identity or common == vault_identity


def _validate_repo(repo_root: Path) -> None:
    repo_exists: object = None
    inspection_failed = False
    try:
        repo_exists = _LEXISTS(repo_root)
    except Exception:
        inspection_failed = True
    if inspection_failed or type(repo_exists) is not bool:
        raise ConfigurationError("CONFIG_REPO_INVALID")
    if not repo_exists:
        raise ConfigurationError("CONFIG_REPO_INVALID")

    repo_status: object = None
    inspection_failed = False
    try:
        repo_status = _LSTAT(repo_root)
    except Exception:
        inspection_failed = True
    if inspection_failed:
        raise ConfigurationError("CONFIG_REPO_INVALID")
    if _status_is_reparse(repo_status, "repo_root"):
        raise _path_error("CONFIG_PATH_REPARSE", "repo_root")
    repo_mode: object = None
    inspection_failed = False
    try:
        repo_mode = getattr(repo_status, "st_mode", None)
    except Exception:
        inspection_failed = True
    if (
        inspection_failed
        or type(repo_mode) is not int
        or not stat.S_ISDIR(repo_mode)
    ):
        raise ConfigurationError("CONFIG_REPO_INVALID")

    marker = repo_root / ".git"
    marker_exists: object = None
    inspection_failed = False
    try:
        marker_exists = _LEXISTS(marker)
    except Exception:
        inspection_failed = True
    if inspection_failed or type(marker_exists) is not bool:
        raise ConfigurationError("CONFIG_REPO_MARKER_INVALID")
    if not marker_exists:
        raise ConfigurationError("CONFIG_REPO_MARKER_INVALID")

    marker_status: object = None
    inspection_failed = False
    try:
        marker_status = _LSTAT(marker)
    except Exception:
        inspection_failed = True
    if inspection_failed:
        raise ConfigurationError("CONFIG_REPO_MARKER_INVALID")

    marker_is_reparse = False
    marker_status_invalid = False
    try:
        marker_is_reparse = _status_is_reparse(marker_status, "repo_root")
    except ConfigurationError:
        marker_status_invalid = True
    if marker_status_invalid or marker_is_reparse:
        raise ConfigurationError("CONFIG_REPO_MARKER_INVALID")

    marker_mode: object = None
    inspection_failed = False
    try:
        marker_mode = getattr(marker_status, "st_mode", None)
    except Exception:
        inspection_failed = True
    if (
        inspection_failed
        or type(marker_mode) is not int
        or not (stat.S_ISREG(marker_mode) or stat.S_ISDIR(marker_mode))
    ):
        raise ConfigurationError("CONFIG_REPO_MARKER_INVALID")


def _validate_vault(vault_root: Path) -> None:
    exists_or_link: object = None
    inspection_failed = False
    try:
        exists_or_link = _LEXISTS(vault_root)
    except Exception:
        inspection_failed = True
    if inspection_failed:
        raise _path_error("CONFIG_PATH_INSPECTION_FAILED", "vault_root")
    if type(exists_or_link) is not bool:
        raise _path_error("CONFIG_PATH_INSPECTION_FAILED", "vault_root")
    if not exists_or_link:
        vault_missing = False
        inspection_failed = False
        try:
            _LSTAT(vault_root)
        except FileNotFoundError:
            vault_missing = True
        except Exception:
            inspection_failed = True
        if inspection_failed:
            raise _path_error("CONFIG_PATH_INSPECTION_FAILED", "vault_root")
        if vault_missing:
            return
        raise _path_error("CONFIG_PATH_INSPECTION_FAILED", "vault_root")
    vault_status: object = None
    inspection_failed = False
    try:
        vault_status = _LSTAT(vault_root)
    except Exception:
        inspection_failed = True
    if inspection_failed:
        raise _path_error("CONFIG_PATH_INSPECTION_FAILED", "vault_root")
    if _status_is_reparse(vault_status, "vault_root"):
        raise _path_error("CONFIG_PATH_REPARSE", "vault_root")
    vault_mode: object = None
    inspection_failed = False
    try:
        vault_mode = getattr(vault_status, "st_mode", None)
    except Exception:
        inspection_failed = True
    if (
        inspection_failed
        or type(vault_mode) is not int
        or not stat.S_ISDIR(vault_mode)
    ):
        raise ConfigurationError("CONFIG_VAULT_INVALID")


def _validate_scope_values(
    interaction_mode: object,
    single_counselor: object,
    runtime_network_ingest: object,
    automatic_formal_writeback: object,
) -> None:
    values = (
        interaction_mode,
        single_counselor,
        runtime_network_ingest,
        automatic_formal_writeback,
    )
    for (field_name, required_type, required_value), value in zip(
        _SCOPE_TYPES_AND_VALUES,
        values,
        strict=True,
    ):
        if type(value) is not required_type or value != required_value:
            raise ConfigurationError("CONFIG_SCOPE_LOCKED", field_name)


def _ascii_upper(value: str) -> str:
    return "".join(
        chr(ord(character) - 32) if "a" <= character <= "z" else character
        for character in value
    )


def _validated_environment(
    environ: Mapping[str, str] | None,
) -> dict[str, str]:
    if environ is not None and not isinstance(environ, Mapping):
        raise ConfigurationError("CONFIG_ENV_INVALID")
    snapshot: dict[str, str] = {}
    snapshot_failed = False
    try:
        snapshot = dict(os.environ) if environ is None else dict(environ)
    except Exception:
        snapshot_failed = True
    if snapshot_failed:
        raise ConfigurationError("CONFIG_ENV_INVALID")

    normalized: dict[str, str] = {}
    for key, value in snapshot.items():
        if type(key) is not str:
            raise ConfigurationError("CONFIG_ENV_INVALID")
        normalized_key = _ascii_upper(key)
        if not normalized_key.startswith("CONSULTATION_"):
            continue
        if type(value) is not str or not value.strip():
            raise ConfigurationError("CONFIG_ENV_INVALID")
        if normalized_key in normalized:
            raise ConfigurationError("CONFIG_ENV_INVALID")
        normalized[normalized_key] = value

    if any(key in _ENV_RESERVED for key in normalized):
        raise ConfigurationError("CONFIG_ENV_RESERVED")
    if any(key not in _ENV_KNOWN for key in normalized):
        raise ConfigurationError("CONFIG_ENV_UNKNOWN")
    return normalized


def _validate_values(
    *,
    repo_root: object,
    vault_root: object,
    interaction_mode: object,
    single_counselor: object,
    runtime_network_ingest: object,
    automatic_formal_writeback: object,
) -> tuple[Path, Path]:
    _validate_scope_values(
        interaction_mode,
        single_counselor,
        runtime_network_ingest,
        automatic_formal_writeback,
    )
    canonical_repo = _normalize_root(repo_root, "repo_root")
    canonical_vault = _normalize_root(vault_root, "vault_root")
    _validate_repo(canonical_repo)
    _validate_vault(canonical_vault)
    if _roots_overlap(canonical_repo, canonical_vault, windows=os.name == "nt"):
        raise ConfigurationError("CONFIG_ROOTS_OVERLAP")
    return canonical_repo, canonical_vault


class _AppConfigMeta(type):
    """Reject every class whose bases include an AppConfig-governed type."""

    def __new__(
        mcls,
        name: str,
        bases: tuple[type, ...],
        namespace: dict[str, object],
        **kwargs: object,
    ) -> _AppConfigMeta:
        if any(isinstance(base, _AppConfigMeta) for base in bases):
            raise TypeError("CONFIG_SUBCLASS_FORBIDDEN")
        return super().__new__(mcls, name, bases, namespace, **kwargs)


@final
@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class AppConfig(metaclass=_AppConfigMeta):
    """Closed-scope, canonical and disjoint repository and vault roots."""

    repo_root: Path
    vault_root: Path
    interaction_mode: Literal["codex_text"] = SCOPE_INTERACTION_MODE
    single_counselor: Literal[True] = SCOPE_SINGLE_COUNSELOR
    runtime_network_ingest: Literal[False] = SCOPE_RUNTIME_NETWORK_INGEST
    automatic_formal_writeback: Literal[False] = SCOPE_AUTOMATIC_FORMAL_WRITEBACK

    def __post_init__(self) -> None:
        repo_root, vault_root = _validate_values(
            repo_root=self.repo_root,
            vault_root=self.vault_root,
            interaction_mode=self.interaction_mode,
            single_counselor=self.single_counselor,
            runtime_network_ingest=self.runtime_network_ingest,
            automatic_formal_writeback=self.automatic_formal_writeback,
        )
        object.__setattr__(self, "repo_root", repo_root)
        object.__setattr__(self, "vault_root", vault_root)

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("CONFIG_SUBCLASS_FORBIDDEN")

    def __repr__(self) -> str:
        return "<AppConfig redacted>"

    @classmethod
    def from_values(
        cls,
        repo_root: PathInput,
        vault_root: PathInput,
        *,
        interaction_mode: object = SCOPE_INTERACTION_MODE,
        single_counselor: object = SCOPE_SINGLE_COUNSELOR,
        runtime_network_ingest: object = SCOPE_RUNTIME_NETWORK_INGEST,
        automatic_formal_writeback: object = SCOPE_AUTOMATIC_FORMAL_WRITEBACK,
    ) -> AppConfig:
        return cls(
            repo_root=repo_root,  # type: ignore[arg-type]
            vault_root=vault_root,  # type: ignore[arg-type]
            interaction_mode=interaction_mode,  # type: ignore[arg-type]
            single_counselor=single_counselor,  # type: ignore[arg-type]
            runtime_network_ingest=runtime_network_ingest,  # type: ignore[arg-type]
            automatic_formal_writeback=automatic_formal_writeback,  # type: ignore[arg-type]
        )

    @classmethod
    def load(
        cls,
        *,
        repo_root: PathInput,
        vault_root: PathInput | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> AppConfig:
        environment = _validated_environment(environ)
        environment_vault = environment.get(_ENV_VAULT_ROOT)
        if vault_root is None and environment_vault is None:
            raise ConfigurationError("CONFIG_VAULT_ROOT_MISSING")
        selected_vault: PathInput
        if vault_root is None:
            if environment_vault is None:
                raise ConfigurationError("CONFIG_VAULT_ROOT_MISSING")
            selected_vault = environment_vault
        elif environment_vault is None:
            selected_vault = vault_root
        else:
            explicit_canonical = _normalize_root(vault_root, "vault_root")
            environment_canonical = _normalize_root(environment_vault, "vault_root")
            windows = os.name == "nt"
            if _canonical_identity(
                explicit_canonical,
                windows=windows,
            ) != _canonical_identity(environment_canonical, windows=windows):
                raise ConfigurationError("CONFIG_VAULT_SOURCE_CONFLICT")
            selected_vault = explicit_canonical
        return cls(
            repo_root=repo_root,  # type: ignore[arg-type]
            vault_root=selected_vault,  # type: ignore[arg-type]
        )
