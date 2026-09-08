"""Strict, redacted policy artifacts loaded from a validated checkout."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Final,
    Callable,
    Generic,
    Literal,
    NoReturn,
    TypeAlias,
    TypeVar,
    cast,
    final,
    get_args,
)

import yaml  # type: ignore[import-untyped]
from pydantic import TypeAdapter

from consultation_kb.core.config import AppConfig
from consultation_kb.models.common import SafePolicyKey
from consultation_kb.models.evidence import EmpiricalSupport, SourceGrade


PolicyId: TypeAlias = Literal[
    "evidence_levels",
    "relation_types",
    "retention",
    "risk_rules",
]
PolicyFilename: TypeAlias = Literal[
    "evidence-levels.yaml",
    "relation-types.yaml",
    "retention.yaml",
    "risk-rules.yaml",
]

T = TypeVar("T")
V = TypeVar("V")

_MAX_POLICY_BYTES: Final = 65_536
_MAX_BUNDLE_BYTES: Final = 262_144
_MAX_YAML_NODES: Final = 4_096
_MAX_YAML_DEPTH: Final = 16
_MAX_SCALAR_CODEPOINTS: Final = 4_096
_READ_CHUNK_BYTES: Final = 64 * 1024
_PLATFORM_NAME = os.name
_O_BINARY: Final = int(getattr(os, "O_BINARY", 0))
_O_CLOEXEC: Final = int(getattr(os, "O_CLOEXEC", 0))
_O_NOFOLLOW = cast(int | None, getattr(os, "O_NOFOLLOW", None))
_O_DIRECTORY = cast(int | None, getattr(os, "O_DIRECTORY", None))
_O_NONBLOCK = cast(int | None, getattr(os, "O_NONBLOCK", None))
_WINDOWS_GENERIC_READ: Final = 0x80000000
_WINDOWS_FILE_LIST_DIRECTORY: Final = 0x00000001
_WINDOWS_FILE_READ_ATTRIBUTES: Final = 0x00000080
_WINDOWS_FILE_SHARE_READ: Final = 0x00000001
_WINDOWS_FILE_SHARE_WRITE: Final = 0x00000002
_WINDOWS_OPEN_EXISTING: Final = 3
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT: Final = 0x00200000
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS: Final = 0x02000000
_REPARSE_ATTRIBUTE: Final = int(
    getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
)
_RAW_MARKER_LINE: Final[re.Pattern[bytes]] = re.compile(
    rb"^[ ]*(?:%|---(?:[ ]|$)|\.\.\.(?:[ ]|$))"
)
_SHA256_HEX: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_POLICY_FILES: Final[tuple[tuple[PolicyId, PolicyFilename], ...]] = (
    ("evidence_levels", "evidence-levels.yaml"),
    ("relation_types", "relation-types.yaml"),
    ("retention", "retention.yaml"),
    ("risk_rules", "risk-rules.yaml"),
)
_POLICY_FILE_SET: Final[frozenset[str]] = frozenset(
    filename for _policy_id, filename in _POLICY_FILES
)
_SOURCE_GRADES: Final[tuple[str, ...]] = (
    "T1",
    "T2",
    "T3",
    "T4",
    "C1",
    "C2",
    "C3",
    "C4",
    "C5",
    "C6",
    "K1",
    "K2",
    "K3",
    "K4",
    "L1",
    "L2",
    "L3",
    "L4",
)
_EMPIRICAL_SUPPORT: Final[tuple[str, ...]] = (
    "unassessed",
    "case_supported",
    "observation_supported",
    "empirically_supported",
    "guideline_consistent",
    "conflicting",
)
_RELATION_TYPES: Final[tuple[str, ...]] = (
    "CITES",
    "SUPPORTS",
    "CONTRADICTS",
    "INTERPRETS",
    "DERIVED_FROM",
    "APPLIES_TO",
    "NOT_APPLICABLE_TO",
    "ANALOGOUS_TO",
    "DISTINCT_FROM",
    "CONTRAINDICATED_FOR",
    "REQUIRES_REFERRAL",
    "EXEMPLIFIED_BY",
    "SUPERSEDES",
)
_RETENTION_CATEGORIES: Final[tuple[str, ...]] = (
    "identity_mapping",
    "source_record",
    "private_session_record",
    "approved_fact_governance",
    "approved_shared_case",
    "rebuildable_derivative",
    "temporary_staging",
    "minimal_noncontent_audit",
)
_RISK_RULE_VALUES: Final[tuple[tuple[object, ...], ...]] = (
    (
        "synthetic_general_observation",
        1,
        "synthetic_general_observation",
        "general",
        "literal",
        "SYNTH-RISK-GENERAL-4C2E",
        0,
        ("synthetic_context_present",),
        ("SYNTH-QUESTION-GENERAL-VERIFY",),
    ),
    (
        "synthetic_high_observation",
        1,
        "synthetic_high_observation",
        "high",
        "literal",
        "SYNTH-RISK-HIGH-7D1A",
        0,
        ("synthetic_context_present",),
        ("SYNTH-QUESTION-HIGH-VERIFY",),
    ),
    (
        "suicide_intent_zh",
        1,
        "suicide_intent",
        "high",
        "literal",
        "我想自杀",
        6,
        (),
        ("确认当前意图、计划、可用手段、时间范围和保护因素。",),
    ),
    (
        "suicide_intent_en",
        1,
        "suicide_intent",
        "high",
        "literal",
        "I want to kill myself",
        6,
        (),
        (
            "Confirm current intent, plan, access to means, timeframe, and protective factors.",
        ),
    ),
    (
        "suicide_plan_zh",
        1,
        "suicide_plan",
        "high",
        "literal",
        "我准备自杀",
        6,
        (),
        ("确认计划、可用手段、预定时间、准备行为和保护因素。",),
    ),
    (
        "suicide_plan_en",
        1,
        "suicide_plan",
        "high",
        "literal",
        "I plan to kill myself",
        6,
        (),
        (
            "Confirm the plan, access to means, intended timeframe, preparations, and protective factors.",
        ),
    ),
    (
        "self_harm_intent_zh",
        1,
        "self_harm_intent",
        "high",
        "literal",
        "我想伤害自己",
        6,
        (),
        ("确认伤害冲动、具体方式、可用手段和当前可控性。",),
    ),
    (
        "self_harm_intent_en",
        1,
        "self_harm_intent",
        "high",
        "literal",
        "I want to hurt myself",
        6,
        (),
        (
            "Confirm the urge, intended method, access to means, and current ability to stay safe.",
        ),
    ),
    (
        "harm_other_intent_zh",
        1,
        "harm_other_intent",
        "high",
        "literal",
        "我准备伤害别人",
        6,
        (),
        ("确认目标、意图、计划、手段、时间范围和当前隔离条件。",),
    ),
    (
        "harm_other_intent_en",
        1,
        "harm_other_intent",
        "high",
        "literal",
        "I plan to hurt someone",
        6,
        (),
        (
            "Confirm the target, intent, plan, access to means, timeframe, and current separation.",
        ),
    ),
    (
        "immediate_interpersonal_danger_zh",
        1,
        "immediate_interpersonal_danger",
        "high",
        "literal",
        "他现在要杀我",
        6,
        (),
        ("确认威胁者是否在场、是否有武器及当前可安全联系的支持。",),
    ),
    (
        "immediate_interpersonal_danger_en",
        1,
        "immediate_interpersonal_danger",
        "high",
        "literal",
        "He is going to kill me",
        6,
        (),
        (
            "Confirm whether the threatening person is present, has a weapon, and what support can be contacted safely.",
        ),
    ),
    (
        "ongoing_interpersonal_violence_zh",
        1,
        "ongoing_interpersonal_violence",
        "general",
        "literal",
        "他经常打我",
        6,
        (),
        ("确认事件频率、最近一次时间、伤势、升级趋势和当前安全条件。",),
    ),
    (
        "ongoing_interpersonal_violence_en",
        1,
        "ongoing_interpersonal_violence",
        "general",
        "literal",
        "He keeps hitting me",
        6,
        (),
        (
            "Confirm frequency, recency, injuries, escalation, and present safety conditions.",
        ),
    ),
)
_SAFE_POLICY_KEY_ADAPTER: Final[TypeAdapter[SafePolicyKey]] = TypeAdapter(
    SafePolicyKey
)
_SOURCE_GRADE_ADAPTER: Final[TypeAdapter[SourceGrade]] = TypeAdapter(SourceGrade)
_EMPIRICAL_SUPPORT_ADAPTER: Final[TypeAdapter[EmpiricalSupport]] = TypeAdapter(
    EmpiricalSupport
)

_LSTAT = os.lstat
_STAT = os.stat
_FSTAT = os.fstat
_FSTAT_DIRECTORY = os.fstat
_OPEN = os.open
_READ = os.read
_CLOSE = os.close
_CLOSE_DIRECTORY = os.close
_SCANDIR = os.scandir
_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
_STAT_SUPPORTS_DIR_FD = os.stat in os.supports_dir_fd
_STAT_SUPPORTS_NOFOLLOW = os.stat in os.supports_follow_symlinks
_SCANDIR_SUPPORTS_FD = os.scandir in os.supports_fd

_WindowsCreateFile: TypeAlias = Callable[
    [str, int, int, int, int, int, int],
    int,
]
_WindowsOpenOsfhandle: TypeAlias = Callable[[int, int], int]
_WindowsCloseHandle: TypeAlias = Callable[[int], None]

_WINDOWS_CREATE_FILE: _WindowsCreateFile | None = None
_WINDOWS_OPEN_OSFHANDLE: _WindowsOpenOsfhandle | None = None
_WINDOWS_CLOSE_HANDLE: _WindowsCloseHandle | None = None
_WINDOWS_INVALID_HANDLE_VALUE: int | None = None

if _PLATFORM_NAME == "nt":
    try:
        _winapi_module = importlib.import_module("_winapi")
        _msvcrt_module = importlib.import_module("msvcrt")
        _WINDOWS_CREATE_FILE = cast(
            _WindowsCreateFile,
            getattr(_winapi_module, "CreateFile"),
        )
        _WINDOWS_OPEN_OSFHANDLE = cast(
            _WindowsOpenOsfhandle,
            getattr(_msvcrt_module, "open_osfhandle"),
        )
        _WINDOWS_CLOSE_HANDLE = cast(
            _WindowsCloseHandle,
            getattr(_winapi_module, "CloseHandle"),
        )
        _invalid_handle_value = getattr(
            _winapi_module,
            "INVALID_HANDLE_VALUE",
        )
        if type(_invalid_handle_value) is not int:
            raise AttributeError
        _WINDOWS_INVALID_HANDLE_VALUE = _invalid_handle_value
    except (ImportError, AttributeError):
        _WINDOWS_CREATE_FILE = None
        _WINDOWS_OPEN_OSFHANDLE = None
        _WINDOWS_CLOSE_HANDLE = None
        _WINDOWS_INVALID_HANDLE_VALUE = None

_StatIdentity: TypeAlias = tuple[int, int, int, int, int, int, int, int]
_DirectorySnapshot: TypeAlias = tuple[
    _StatIdentity,
    tuple[tuple[str, _StatIdentity], ...],
]


@dataclass(frozen=True, slots=True)
class _DirectoryGuard:
    path: Path
    descriptor: int
    handle_relative: bool


def _serialization_forbidden() -> NoReturn:
    raise TypeError("POLICY_SERIALIZATION_FORBIDDEN")


class _SerializationForbidden:
    __slots__ = ()

    def __copy__(self) -> NoReturn:
        _serialization_forbidden()

    def __deepcopy__(self, memo: object) -> NoReturn:
        del memo
        _serialization_forbidden()

    def __reduce__(self) -> NoReturn:
        _serialization_forbidden()

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        del protocol
        _serialization_forbidden()


class PolicyLoadError(ValueError):
    """A policy failure containing only a fixed code and optional policy ID."""

    code: str
    policy_id: PolicyId | None

    def __init__(self, code: str, policy_id: PolicyId | None = None) -> None:
        self.code = code
        self.policy_id = policy_id
        message = code if policy_id is None else f"{code}:{policy_id}"
        super().__init__(message)

    def __repr__(self) -> str:
        return "<PolicyLoadError redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class PolicyAuditMetadata(_SerializationForbidden):
    filename: PolicyFilename
    policy_id: PolicyId
    policy_version: Literal[1]
    raw_bytes_sha256: str
    content_sha256: str

    def __repr__(self) -> str:
        return "<PolicyAuditMetadata redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class EvidenceLevelsPolicy(_SerializationForbidden):
    schema_version: Literal["1.0"]
    policy_id: Literal["evidence_levels"]
    policy_version: Literal[1]
    source_grades: tuple[SourceGrade, ...]
    empirical_support: tuple[EmpiricalSupport, ...]

    def __repr__(self) -> str:
        return "<EvidenceLevelsPolicy redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class RelationTypesPolicy(_SerializationForbidden):
    schema_version: Literal["1.0"]
    policy_id: Literal["relation_types"]
    policy_version: Literal[1]
    global_relation_types: tuple[str, ...]

    def __repr__(self) -> str:
        return "<RelationTypesPolicy redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class RetentionPolicy(_SerializationForbidden):
    schema_version: Literal["1.0"]
    policy_id: Literal["retention"]
    policy_version: Literal[1]
    retention_categories: tuple[SafePolicyKey, ...]

    def __repr__(self) -> str:
        return "<RetentionPolicy redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class RiskRulePolicy(_SerializationForbidden):
    rule_id: SafePolicyKey
    version: Literal[1]
    category: SafePolicyKey
    level: Literal["general", "high"]
    pattern_type: Literal["literal"]
    pattern: str
    negation_window_tokens: int
    required_context: tuple[SafePolicyKey, ...]
    suggested_questions: tuple[str, ...]

    def __repr__(self) -> str:
        return "<RiskRulePolicy redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class RiskRulesPolicy(_SerializationForbidden):
    schema_version: Literal["1.0"]
    policy_id: Literal["risk_rules"]
    policy_version: Literal[1]
    rules: tuple[RiskRulePolicy, ...]

    def __repr__(self) -> str:
        return "<RiskRulesPolicy redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class LoadedPolicy(_SerializationForbidden, Generic[T]):
    filename: PolicyFilename
    schema_version: Literal["1.0"]
    policy_id: PolicyId
    policy_version: Literal[1]
    raw_bytes_sha256: str
    canonical_bytes: bytes
    content_sha256: str
    document: T

    def __repr__(self) -> str:
        return "<LoadedPolicy redacted>"

    def audit_metadata(self) -> PolicyAuditMetadata:
        return PolicyAuditMetadata(
            filename=self.filename,
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            raw_bytes_sha256=self.raw_bytes_sha256,
            content_sha256=self.content_sha256,
        )


@dataclass(frozen=True, slots=True, repr=False)
class RiskRuleMemberIdentity(_SerializationForbidden):
    owner_schema_version: Literal["1.0"]
    owner_policy_id: Literal["risk_rules"]
    owner_policy_version: Literal[1]
    owner_content_sha256: str
    member_kind: Literal["risk_rule"]
    member_ordinal: int
    rule_id: SafePolicyKey
    version: Literal[1]
    canonical_bytes: bytes
    content_sha256: str

    def __repr__(self) -> str:
        return "<RiskRuleMemberIdentity redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class PolicyBundle(_SerializationForbidden):
    evidence_levels: LoadedPolicy[EvidenceLevelsPolicy]
    relation_types: LoadedPolicy[RelationTypesPolicy]
    retention: LoadedPolicy[RetentionPolicy]
    risk_rules: LoadedPolicy[RiskRulesPolicy]

    def __repr__(self) -> str:
        return "<PolicyBundle redacted>"


class _DirectoryMissing(Exception):
    pass


class _DirectoryUnsafe(Exception):
    pass


class _DuplicateKeyDetected(Exception):
    pass


class _ConstructedTypeInvalid(Exception):
    pass


class _DuplicateRejectingSafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    def construct_mapping(
        self,
        node: yaml.MappingNode,
        deep: bool = False,
    ) -> dict[object, object]:
        if not isinstance(node, yaml.MappingNode):
            raise _ConstructedTypeInvalid from None
        seen: set[str] = set()
        for key_node, _value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if type(key) is not str:
                raise _ConstructedTypeInvalid from None
            if key in seen:
                raise _DuplicateKeyDetected from None
            seen.add(key)
        return cast(
            dict[object, object],
            super().construct_mapping(node, deep=deep),
        )


def _stat_integer(status: object, name: str, default: int | None = None) -> int:
    try:
        value = getattr(status, name) if default is None else getattr(status, name, default)
    except Exception:
        raise _DirectoryUnsafe from None
    if type(value) is not int:
        raise _DirectoryUnsafe from None
    return value


def _stat_identity(status: object) -> _StatIdentity:
    return (
        _stat_integer(status, "st_mode"),
        _stat_integer(status, "st_dev"),
        _stat_integer(status, "st_ino"),
        _stat_integer(status, "st_nlink"),
        _stat_integer(status, "st_size"),
        _stat_integer(status, "st_mtime_ns"),
        _stat_integer(status, "st_ctime_ns"),
        _stat_integer(status, "st_file_attributes", 0),
    )


def _is_reparse(status: object) -> bool:
    identity = _stat_identity(status)
    return stat.S_ISLNK(identity[0]) or bool(identity[7] & _REPARSE_ATTRIBUTE)


def _validate_directory(status: object) -> _StatIdentity:
    identity = _stat_identity(status)
    if not stat.S_ISDIR(identity[0]) or _is_reparse(status):
        raise _DirectoryUnsafe
    return identity


def _windows_descriptor(path: Path, *, directory: bool) -> int:
    create_file = _WINDOWS_CREATE_FILE
    open_osfhandle = _WINDOWS_OPEN_OSFHANDLE
    close_handle = _WINDOWS_CLOSE_HANDLE
    invalid_handle = _WINDOWS_INVALID_HANDLE_VALUE
    if (
        create_file is None
        or open_osfhandle is None
        or close_handle is None
        or type(invalid_handle) is not int
    ):
        raise _DirectoryUnsafe

    desired_access = (
        _WINDOWS_FILE_LIST_DIRECTORY | _WINDOWS_FILE_READ_ATTRIBUTES
        if directory
        else _WINDOWS_GENERIC_READ
    )
    share_mode = (
        _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE
        if directory
        else _WINDOWS_FILE_SHARE_READ
    )
    flags = _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS

    handle: int | None = None
    try:
        handle = create_file(
            os.fspath(path),
            desired_access,
            share_mode,
            0,
            _WINDOWS_OPEN_EXISTING,
            flags,
            0,
        )
        if type(handle) is not int or handle == invalid_handle:
            raise _DirectoryUnsafe
        descriptor = open_osfhandle(handle, os.O_RDONLY | _O_BINARY)
        if type(descriptor) is not int or descriptor < 0:
            raise _DirectoryUnsafe
        handle = None
        return descriptor
    except Exception:
        if handle is not None and handle != invalid_handle:
            try:
                close_handle(handle)
            except Exception:
                pass
        raise _DirectoryUnsafe from None


def _posix_primitives_available() -> bool:
    return (
        type(_O_NOFOLLOW) is int
        and type(_O_DIRECTORY) is int
        and type(_O_NONBLOCK) is int
        and _OPEN_SUPPORTS_DIR_FD
        and _STAT_SUPPORTS_DIR_FD
        and _STAT_SUPPORTS_NOFOLLOW
        and _SCANDIR_SUPPORTS_FD
    )


def _open_directory_descriptor(path: Path) -> int:
    if _PLATFORM_NAME == "nt":
        return _windows_descriptor(path, directory=True)
    if _PLATFORM_NAME == "posix" and _posix_primitives_available():
        nofollow = cast(int, _O_NOFOLLOW)
        directory = cast(int, _O_DIRECTORY)
        return _OPEN(
            os.fspath(path),
            os.O_RDONLY | nofollow | directory | _O_CLOEXEC,
        )
    raise _DirectoryUnsafe


def _open_file_descriptor_no_follow(
    guard: _DirectoryGuard,
    filename: str,
) -> int:
    if _PLATFORM_NAME == "nt" and not guard.handle_relative:
        return _windows_descriptor(guard.path / filename, directory=False)
    if (
        _PLATFORM_NAME == "posix"
        and guard.handle_relative
        and _posix_primitives_available()
    ):
        nofollow = cast(int, _O_NOFOLLOW)
        nonblock = cast(int, _O_NONBLOCK)
        return _OPEN(
            filename,
            os.O_RDONLY | nofollow | nonblock | _O_CLOEXEC,
            dir_fd=guard.descriptor,
        )
    raise _DirectoryUnsafe


def _entry_lstat(guard: _DirectoryGuard, name: str) -> object:
    if guard.handle_relative:
        if not _posix_primitives_available():
            raise _DirectoryUnsafe
        return _STAT(
            name,
            dir_fd=guard.descriptor,
            follow_symlinks=False,
        )
    return _LSTAT(guard.path / name)


def _open_policy_directory(path: Path) -> _DirectoryGuard:
    try:
        path_before = _LSTAT(path)
    except FileNotFoundError:
        raise _DirectoryMissing from None
    except Exception:
        raise _DirectoryUnsafe from None
    try:
        before_identity = _validate_directory(path_before)
    except _DirectoryUnsafe:
        raise

    descriptor: int | None = None
    try:
        descriptor = _open_directory_descriptor(path)
        handle_status = _FSTAT_DIRECTORY(descriptor)
        handle_identity = _validate_directory(handle_status)
        path_after = _LSTAT(path)
        after_identity = _validate_directory(path_after)
        if (
            before_identity != after_identity
            or not _same_path_and_handle(before_identity, handle_identity)
            or not _same_path_and_handle(after_identity, handle_identity)
        ):
            raise _DirectoryUnsafe
        return _DirectoryGuard(
            path=path,
            descriptor=descriptor,
            handle_relative=_PLATFORM_NAME == "posix",
        )
    except Exception:
        if descriptor is not None:
            try:
                _CLOSE_DIRECTORY(descriptor)
            except Exception:
                pass
        raise _DirectoryUnsafe from None


def _snapshot_directory(guard: _DirectoryGuard) -> _DirectorySnapshot:
    try:
        path_before = _LSTAT(guard.path)
        path_before_identity = _validate_directory(path_before)
        handle_before = _FSTAT_DIRECTORY(guard.descriptor)
        handle_before_identity = _validate_directory(handle_before)
        if not _same_path_and_handle(
            path_before_identity,
            handle_before_identity,
        ):
            raise _DirectoryUnsafe
    except _DirectoryUnsafe:
        raise
    except Exception:
        raise _DirectoryUnsafe from None

    entries: list[tuple[str, _StatIdentity]] = []
    try:
        scan_target: Path | int = (
            guard.descriptor if guard.handle_relative else guard.path
        )
        with _SCANDIR(scan_target) as iterator:
            for entry in iterator:
                name = entry.name
                if type(name) is not str:
                    raise _DirectoryUnsafe from None
                entry_status = _entry_lstat(guard, name)
                entries.append((name, _stat_identity(entry_status)))
        handle_after = _FSTAT_DIRECTORY(guard.descriptor)
        handle_after_identity = _validate_directory(handle_after)
        path_after = _LSTAT(guard.path)
        path_after_identity = _validate_directory(path_after)
    except _DirectoryUnsafe:
        raise
    except Exception:
        raise _DirectoryUnsafe from None
    if (
        path_after_identity != path_before_identity
        or handle_after_identity != handle_before_identity
        or not _same_path_and_handle(path_after_identity, handle_after_identity)
    ):
        raise _DirectoryUnsafe
    entries.sort(key=lambda item: item[0])
    return path_before_identity, tuple(entries)


def _file_error(code: str, policy_id: PolicyId) -> PolicyLoadError:
    return PolicyLoadError(code, policy_id)


def _validate_regular_file(status: object, policy_id: PolicyId) -> _StatIdentity:
    try:
        identity = _stat_identity(status)
        reparse = _is_reparse(status)
    except _DirectoryUnsafe:
        raise _file_error("POLICY_FILE_UNSAFE", policy_id) from None
    if (
        not stat.S_ISREG(identity[0])
        or reparse
        or identity[3] != 1
    ):
        raise _file_error("POLICY_FILE_UNSAFE", policy_id)
    if identity[4] > _MAX_POLICY_BYTES:
        raise _file_error("POLICY_SIZE_LIMIT", policy_id)
    return identity


def _same_path_and_handle(
    path_identity: _StatIdentity,
    handle_identity: _StatIdentity,
) -> bool:
    # CPython/Windows can report creation-time semantics for path ``ctime``
    # while the opened handle reports the preserved source ``ctime``.  Keep
    # ctime closure within each observation channel and compare every other
    # identity field across the path/handle boundary.
    return (
        path_identity[:6] == handle_identity[:6]
        and path_identity[7] == handle_identity[7]
    )


def _read_exact_file(
    guard: _DirectoryGuard,
    policy_id: PolicyId,
    filename: PolicyFilename,
    expected_identity: _StatIdentity,
) -> bytes:
    try:
        path_before = _entry_lstat(guard, filename)
    except Exception:
        raise _file_error("POLICY_CHANGED_DURING_READ", policy_id) from None
    before_identity = _validate_regular_file(path_before, policy_id)
    if before_identity != expected_identity:
        raise _file_error("POLICY_CHANGED_DURING_READ", policy_id)

    close_failed = False
    try:
        descriptor = _open_file_descriptor_no_follow(guard, filename)
    except Exception:
        raise _file_error("POLICY_CHANGED_DURING_READ", policy_id) from None

    try:
        handle_before = _FSTAT(descriptor)
        handle_before_identity = _validate_regular_file(handle_before, policy_id)
        if not _same_path_and_handle(before_identity, handle_before_identity):
            raise _file_error("POLICY_CHANGED_DURING_READ", policy_id)

        chunks: list[bytes] = []
        byte_count = 0
        while byte_count <= _MAX_POLICY_BYTES:
            chunk = _READ(
                descriptor,
                min(_READ_CHUNK_BYTES, _MAX_POLICY_BYTES + 1 - byte_count),
            )
            if type(chunk) is not bytes:
                raise _file_error("POLICY_FILE_UNSAFE", policy_id)
            if not chunk:
                break
            chunks.append(chunk)
            byte_count += len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _MAX_POLICY_BYTES:
            raise _file_error("POLICY_SIZE_LIMIT", policy_id)

        handle_after = _FSTAT(descriptor)
        handle_after_identity = _validate_regular_file(handle_after, policy_id)
        if handle_after_identity != handle_before_identity:
            raise _file_error("POLICY_CHANGED_DURING_READ", policy_id)
        if len(raw) != handle_after_identity[4]:
            raise _file_error("POLICY_CHANGED_DURING_READ", policy_id)
    except PolicyLoadError:
        raise
    except Exception:
        raise _file_error("POLICY_CHANGED_DURING_READ", policy_id) from None
    finally:
        try:
            _CLOSE(descriptor)
        except Exception:
            close_failed = True

    if close_failed:
        raise _file_error("POLICY_CHANGED_DURING_READ", policy_id)

    try:
        path_after = _entry_lstat(guard, filename)
        path_after_identity = _validate_regular_file(path_after, policy_id)
    except PolicyLoadError:
        raise
    except Exception:
        raise _file_error("POLICY_CHANGED_DURING_READ", policy_id) from None
    if path_after_identity != before_identity:
        raise _file_error("POLICY_CHANGED_DURING_READ", policy_id)
    if not _same_path_and_handle(path_after_identity, handle_after_identity):
        raise _file_error("POLICY_CHANGED_DURING_READ", policy_id)
    return raw


def _validate_raw_bytes(raw: bytes, policy_id: PolicyId) -> None:
    if len(raw) > _MAX_POLICY_BYTES:
        raise _file_error("POLICY_SIZE_LIMIT", policy_id)
    if raw.startswith(
        (
            b"\xef\xbb\xbf",
            b"\xff\xfe",
            b"\xfe\xff",
            b"\xff\xfe\x00\x00",
            b"\x00\x00\xfe\xff",
        )
    ):
        raise _file_error("POLICY_ENCODING_INVALID", policy_id)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise _file_error("POLICY_ENCODING_INVALID", policy_id) from None
    if (
        not raw
        or b"\x00" in raw
        or b"\r" in raw
        or any(separator in text for separator in ("\u0085", "\u2028", "\u2029"))
        or b"#" in raw
        or b"\t" in raw
        or not raw.endswith(b"\n")
        or raw.endswith(b"\n\n")
        or re.search(rb"\n[ ]*\n$", raw) is not None
    ):
        raise _file_error("POLICY_RAW_FORMAT_INVALID", policy_id)
    for line in raw.splitlines():
        if _RAW_MARKER_LINE.match(line) is not None:
            raise _file_error("POLICY_RAW_FORMAT_INVALID", policy_id)


def _validate_yaml_nodes(root: yaml.Node, policy_id: PolicyId) -> None:
    count = 0

    def visit(node: yaml.Node, depth: int) -> None:
        nonlocal count
        count += 1
        if count > _MAX_YAML_NODES or depth > _MAX_YAML_DEPTH:
            raise _file_error("POLICY_STRUCTURE_LIMIT", policy_id)
        if isinstance(node, yaml.ScalarNode):
            if len(node.value) > _MAX_SCALAR_CODEPOINTS:
                raise _file_error("POLICY_STRUCTURE_LIMIT", policy_id)
            return
        if isinstance(node, yaml.MappingNode):
            for key_node, value_node in node.value:
                visit(key_node, depth + 1)
                visit(value_node, depth + 1)
            return
        if isinstance(node, yaml.SequenceNode):
            for value_node in node.value:
                visit(value_node, depth + 1)
            return
        raise _file_error("POLICY_YAML_FORBIDDEN_FEATURE", policy_id)

    try:
        visit(root, 1)
    except RecursionError:
        raise _file_error("POLICY_STRUCTURE_LIMIT", policy_id) from None


def _parse_yaml(raw: bytes, policy_id: PolicyId) -> object:
    text = raw.decode("utf-8")
    forbidden_tokens = (
        yaml.tokens.AliasToken,
        yaml.tokens.AnchorToken,
        yaml.tokens.DirectiveToken,
        yaml.tokens.DocumentEndToken,
        yaml.tokens.DocumentStartToken,
        yaml.tokens.TagToken,
    )
    try:
        for token in yaml.scan(text, Loader=yaml.SafeLoader):
            if isinstance(token, forbidden_tokens):
                raise _file_error("POLICY_YAML_FORBIDDEN_FEATURE", policy_id)
            if isinstance(token, yaml.tokens.ScalarToken) and token.value == "<<":
                raise _file_error("POLICY_YAML_FORBIDDEN_FEATURE", policy_id)
        root = yaml.compose(text, Loader=yaml.SafeLoader)
        if root is None:
            raise _file_error("POLICY_YAML_PARSE_FAILED", policy_id)
        _validate_yaml_nodes(root, policy_id)
        return yaml.load(text, Loader=_DuplicateRejectingSafeLoader)
    except PolicyLoadError:
        raise
    except _DuplicateKeyDetected:
        raise _file_error("POLICY_YAML_DUPLICATE_KEY", policy_id) from None
    except _ConstructedTypeInvalid:
        raise _file_error("POLICY_YAML_TYPE_INVALID", policy_id) from None
    except RecursionError:
        raise _file_error("POLICY_STRUCTURE_LIMIT", policy_id) from None
    except yaml.YAMLError:
        raise _file_error("POLICY_YAML_PARSE_FAILED", policy_id) from None
    except Exception:
        raise _file_error("POLICY_YAML_PARSE_FAILED", policy_id) from None


def _validate_constructed_types(value: object, policy_id: PolicyId) -> None:
    value_type = type(value)
    if value_type is str or value_type is int:
        return
    if value_type is list:
        for item in cast(list[object], value):
            _validate_constructed_types(item, policy_id)
        return
    if value_type is dict:
        for key, item in cast(dict[object, object], value).items():
            if type(key) is not str:
                raise _file_error("POLICY_YAML_TYPE_INVALID", policy_id)
            _validate_constructed_types(item, policy_id)
        return
    raise _file_error("POLICY_YAML_TYPE_INVALID", policy_id)


def _exact_mapping(
    value: object,
    keys: tuple[str, ...],
    policy_id: PolicyId,
) -> dict[str, object]:
    if type(value) is not dict:
        raise _file_error("POLICY_SCHEMA_INVALID", policy_id)
    mapping = cast(dict[str, object], value)
    if tuple(mapping) != keys:
        raise _file_error("POLICY_SCHEMA_INVALID", policy_id)
    return mapping


def _exact_string_list(value: object, policy_id: PolicyId) -> tuple[str, ...]:
    if type(value) is not list:
        raise _file_error("POLICY_SCHEMA_INVALID", policy_id)
    items = cast(list[object], value)
    if any(type(item) is not str for item in items):
        raise _file_error("POLICY_SCHEMA_INVALID", policy_id)
    strings = cast(tuple[str, ...], tuple(items))
    if len(set(strings)) != len(strings):
        raise _file_error("POLICY_SCHEMA_INVALID", policy_id)
    return strings


def _validate_adapter(
    adapter: TypeAdapter[V],
    value: object,
    policy_id: PolicyId,
) -> None:
    try:
        validated = adapter.validate_python(value)
    except Exception:
        raise _file_error("POLICY_MODEL_PARITY_FAILED", policy_id) from None
    if validated != value or type(validated) is not type(value):
        raise _file_error("POLICY_MODEL_PARITY_FAILED", policy_id)


def _validate_policy_keys(values: tuple[str, ...], policy_id: PolicyId) -> None:
    for value in values:
        _validate_adapter(_SAFE_POLICY_KEY_ADAPTER, value, policy_id)


def _validate_envelope(
    mapping: dict[str, object],
    policy_id: PolicyId,
) -> None:
    if mapping["schema_version"] != "1.0":
        raise _file_error("POLICY_VERSION_UNSUPPORTED", policy_id)
    if mapping["policy_version"] != 1 or type(mapping["policy_version"]) is not int:
        raise _file_error("POLICY_VERSION_UNSUPPORTED", policy_id)
    if type(mapping["policy_id"]) is str:
        _validate_adapter(_SAFE_POLICY_KEY_ADAPTER, mapping["policy_id"], policy_id)
    if mapping["policy_id"] != policy_id or type(mapping["policy_id"]) is not str:
        raise _file_error("POLICY_SCHEMA_INVALID", policy_id)


def _construct_document(policy_id: PolicyId, parsed: object) -> object:
    if policy_id == "evidence_levels":
        mapping = _exact_mapping(
            parsed,
            (
                "schema_version",
                "policy_id",
                "policy_version",
                "source_grades",
                "empirical_support",
            ),
            policy_id,
        )
        _validate_envelope(mapping, policy_id)
        source_grades = _exact_string_list(mapping["source_grades"], policy_id)
        empirical_support = _exact_string_list(
            mapping["empirical_support"],
            policy_id,
        )
        for source_grade in source_grades:
            _validate_adapter(_SOURCE_GRADE_ADAPTER, source_grade, policy_id)
        for support in empirical_support:
            _validate_adapter(_EMPIRICAL_SUPPORT_ADAPTER, support, policy_id)
        if (
            source_grades != _SOURCE_GRADES
            or source_grades != get_args(SourceGrade)
            or empirical_support != _EMPIRICAL_SUPPORT
            or empirical_support != get_args(EmpiricalSupport)
        ):
            raise _file_error("POLICY_MODEL_PARITY_FAILED", policy_id)
        return EvidenceLevelsPolicy(
            schema_version="1.0",
            policy_id="evidence_levels",
            policy_version=1,
            source_grades=cast(tuple[SourceGrade, ...], source_grades),
            empirical_support=cast(
                tuple[EmpiricalSupport, ...],
                empirical_support,
            ),
        )
    if policy_id == "relation_types":
        mapping = _exact_mapping(
            parsed,
            (
                "schema_version",
                "policy_id",
                "policy_version",
                "global_relation_types",
            ),
            policy_id,
        )
        _validate_envelope(mapping, policy_id)
        relations = _exact_string_list(
            mapping["global_relation_types"],
            policy_id,
        )
        if relations != _RELATION_TYPES:
            raise _file_error("POLICY_SEMANTICS_INVALID", policy_id)
        return RelationTypesPolicy(
            schema_version="1.0",
            policy_id="relation_types",
            policy_version=1,
            global_relation_types=relations,
        )
    if policy_id == "retention":
        mapping = _exact_mapping(
            parsed,
            (
                "schema_version",
                "policy_id",
                "policy_version",
                "retention_categories",
            ),
            policy_id,
        )
        _validate_envelope(mapping, policy_id)
        categories = _exact_string_list(mapping["retention_categories"], policy_id)
        _validate_policy_keys(categories, policy_id)
        if categories != _RETENTION_CATEGORIES:
            raise _file_error("POLICY_SEMANTICS_INVALID", policy_id)
        return RetentionPolicy(
            schema_version="1.0",
            policy_id="retention",
            policy_version=1,
            retention_categories=categories,
        )

    mapping = _exact_mapping(
        parsed,
        ("schema_version", "policy_id", "policy_version", "rules"),
        policy_id,
    )
    _validate_envelope(mapping, policy_id)
    rules_value = mapping["rules"]
    if type(rules_value) is not list:
        raise _file_error("POLICY_SCHEMA_INVALID", policy_id)
    rules: list[RiskRulePolicy] = []
    for value in cast(list[object], rules_value):
        rule = _exact_mapping(
            value,
            (
                "rule_id",
                "version",
                "category",
                "level",
                "pattern_type",
                "pattern",
                "negation_window_tokens",
                "required_context",
                "suggested_questions",
            ),
            policy_id,
        )
        if rule["version"] != 1 or type(rule["version"]) is not int:
            raise _file_error("POLICY_VERSION_UNSUPPORTED", policy_id)
        scalar_strings = (
            rule["rule_id"],
            rule["category"],
            rule["level"],
            rule["pattern_type"],
            rule["pattern"],
        )
        if any(type(item) is not str for item in scalar_strings):
            raise _file_error("POLICY_SCHEMA_INVALID", policy_id)
        if (
            type(rule["negation_window_tokens"]) is not int
            or not 0 <= rule["negation_window_tokens"] <= 32
        ):
            raise _file_error("POLICY_SCHEMA_INVALID", policy_id)
        required_context = _exact_string_list(rule["required_context"], policy_id)
        suggested_questions = _exact_string_list(
            rule["suggested_questions"],
            policy_id,
        )
        _validate_policy_keys(
            (
                cast(str, rule["rule_id"]),
                cast(str, rule["category"]),
                *required_context,
            ),
            policy_id,
        )
        rules.append(
            RiskRulePolicy(
                rule_id=cast(SafePolicyKey, rule["rule_id"]),
                version=1,
                category=cast(SafePolicyKey, rule["category"]),
                level=cast(Literal["general", "high"], rule["level"]),
                pattern_type=cast(Literal["literal"], rule["pattern_type"]),
                pattern=cast(str, rule["pattern"]),
                negation_window_tokens=rule["negation_window_tokens"],
                required_context=required_context,
                suggested_questions=suggested_questions,
            )
        )
    observed_rules = tuple(
        (
            rule.rule_id,
            rule.version,
            rule.category,
            rule.level,
            rule.pattern_type,
            rule.pattern,
            rule.negation_window_tokens,
            rule.required_context,
            rule.suggested_questions,
        )
        for rule in rules
    )
    if observed_rules != _RISK_RULE_VALUES:
        raise _file_error("POLICY_SEMANTICS_INVALID", policy_id)
    return RiskRulesPolicy(
        schema_version="1.0",
        policy_id="risk_rules",
        policy_version=1,
        rules=tuple(rules),
    )


def _plain_semantic_document(
    policy_id: PolicyId,
    document: object,
) -> dict[str, object]:
    if policy_id == "evidence_levels" and type(document) is EvidenceLevelsPolicy:
        evidence = document
        return {
            "schema_version": evidence.schema_version,
            "policy_id": evidence.policy_id,
            "policy_version": evidence.policy_version,
            "source_grades": list(evidence.source_grades),
            "empirical_support": list(evidence.empirical_support),
        }
    if policy_id == "relation_types" and type(document) is RelationTypesPolicy:
        relations = document
        return {
            "schema_version": relations.schema_version,
            "policy_id": relations.policy_id,
            "policy_version": relations.policy_version,
            "global_relation_types": list(relations.global_relation_types),
        }
    if policy_id == "retention" and type(document) is RetentionPolicy:
        retention = document
        return {
            "schema_version": retention.schema_version,
            "policy_id": retention.policy_id,
            "policy_version": retention.policy_version,
            "retention_categories": list(retention.retention_categories),
        }
    if policy_id == "risk_rules" and type(document) is RiskRulesPolicy:
        risk_rules = document
        return {
            "schema_version": risk_rules.schema_version,
            "policy_id": risk_rules.policy_id,
            "policy_version": risk_rules.policy_version,
            "rules": [_plain_risk_rule(rule) for rule in risk_rules.rules],
        }
    raise _file_error("POLICY_CANONICALIZATION_FAILED", policy_id)


def _plain_risk_rule(rule: RiskRulePolicy) -> dict[str, object]:
    return {
        "rule_id": rule.rule_id,
        "version": rule.version,
        "category": rule.category,
        "level": rule.level,
        "pattern_type": rule.pattern_type,
        "pattern": rule.pattern,
        "negation_window_tokens": rule.negation_window_tokens,
        "required_context": list(rule.required_context),
        "suggested_questions": list(rule.suggested_questions),
    }


def _canonical_json_bytes(plain: object) -> bytes:
    return json.dumps(
        plain,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _artifact_hashes(
    raw: bytes,
    policy_id: PolicyId,
    document: object,
) -> tuple[str, bytes, str]:
    try:
        plain = _plain_semantic_document(policy_id, document)
        canonical = _canonical_json_bytes(plain)
        raw_hash = hashlib.sha256(raw).hexdigest()
        content_hash = hashlib.sha256(canonical).hexdigest()
    except PolicyLoadError:
        raise
    except Exception:
        raise _file_error("POLICY_CANONICALIZATION_FAILED", policy_id) from None
    return raw_hash, canonical, content_hash


def _risk_rule_member_identities_strict(
    loaded: LoadedPolicy[RiskRulesPolicy],
) -> tuple[RiskRuleMemberIdentity, ...]:
    if type(loaded) is not LoadedPolicy:
        raise ValueError
    if (
        type(loaded.filename) is not str
        or loaded.filename != "risk-rules.yaml"
        or type(loaded.schema_version) is not str
        or loaded.schema_version != "1.0"
        or type(loaded.policy_id) is not str
        or loaded.policy_id != "risk_rules"
        or type(loaded.policy_version) is not int
        or loaded.policy_version != 1
        or type(loaded.raw_bytes_sha256) is not str
        or _SHA256_HEX.fullmatch(loaded.raw_bytes_sha256) is None
        or type(loaded.canonical_bytes) is not bytes
        or type(loaded.content_sha256) is not str
        or _SHA256_HEX.fullmatch(loaded.content_sha256) is None
        or type(loaded.document) is not RiskRulesPolicy
    ):
        raise ValueError

    document = loaded.document
    if (
        type(document.schema_version) is not str
        or document.schema_version != "1.0"
        or type(document.policy_id) is not str
        or document.policy_id != "risk_rules"
        or type(document.policy_version) is not int
        or document.policy_version != 1
        or type(document.rules) is not tuple
        or len(document.rules) != len(_RISK_RULE_VALUES)
    ):
        raise ValueError

    observed_rules: list[tuple[object, ...]] = []
    for rule in document.rules:
        if type(rule) is not RiskRulePolicy:
            raise ValueError
        if (
            type(rule.rule_id) is not str
            or type(rule.version) is not int
            or type(rule.category) is not str
            or type(rule.level) is not str
            or type(rule.pattern_type) is not str
            or type(rule.pattern) is not str
            or type(rule.negation_window_tokens) is not int
            or type(rule.required_context) is not tuple
            or any(type(value) is not str for value in rule.required_context)
            or type(rule.suggested_questions) is not tuple
            or any(type(value) is not str for value in rule.suggested_questions)
        ):
            raise ValueError
        observed_rules.append(
            (
                rule.rule_id,
                rule.version,
                rule.category,
                rule.level,
                rule.pattern_type,
                rule.pattern,
                rule.negation_window_tokens,
                rule.required_context,
                rule.suggested_questions,
            )
        )
    if tuple(observed_rules) != _RISK_RULE_VALUES:
        raise ValueError

    whole_plain = _plain_semantic_document("risk_rules", document)
    whole_canonical = _canonical_json_bytes(whole_plain)
    whole_content_hash = hashlib.sha256(whole_canonical).hexdigest()
    if (
        loaded.canonical_bytes != whole_canonical
        or loaded.content_sha256 != whole_content_hash
        or loaded.schema_version != document.schema_version
        or loaded.policy_id != document.policy_id
        or loaded.policy_version != document.policy_version
    ):
        raise ValueError

    identities: list[RiskRuleMemberIdentity] = []
    for ordinal, rule in enumerate(document.rules):
        envelope = {
            "owner": {
                "schema_version": loaded.schema_version,
                "policy_id": loaded.policy_id,
                "policy_version": loaded.policy_version,
                "content_sha256": loaded.content_sha256,
            },
            "member_kind": "risk_rule",
            "member_ordinal": ordinal,
            "member": _plain_risk_rule(rule),
        }
        canonical = _canonical_json_bytes(envelope)
        content_hash = hashlib.sha256(canonical).hexdigest()
        identities.append(
            RiskRuleMemberIdentity(
                owner_schema_version="1.0",
                owner_policy_id="risk_rules",
                owner_policy_version=1,
                owner_content_sha256=loaded.content_sha256,
                member_kind="risk_rule",
                member_ordinal=ordinal,
                rule_id=rule.rule_id,
                version=rule.version,
                canonical_bytes=canonical,
                content_sha256=content_hash,
            )
        )
    return tuple(identities)


def risk_rule_member_identities(
    loaded: LoadedPolicy[RiskRulesPolicy],
) -> tuple[RiskRuleMemberIdentity, ...]:
    """Bind validated v1 risk-rule members to their exact owner artifact."""

    try:
        return _risk_rule_member_identities_strict(loaded)
    except Exception:
        pass
    raise PolicyLoadError("POLICY_MEMBER_IDENTITY_INVALID")


@final
class PolicyLoader(_SerializationForbidden):
    """A fixed-root loader derived from an exact validated ``AppConfig``."""

    __slots__ = ("_repo_root",)

    _repo_root: Path

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("POLICY_LOADER_SUBCLASS_FORBIDDEN")

    def __init__(self, config: AppConfig) -> None:
        if type(self) is not PolicyLoader or type(config) is not AppConfig:
            raise PolicyLoadError("POLICY_VALIDATED_CONFIG_REQUIRED")
        object.__setattr__(self, "_repo_root", config.repo_root)

    def __setattr__(self, name: str, value: object) -> NoReturn:
        del self, name, value
        raise AttributeError("POLICY_LOADER_FROZEN")

    def __delattr__(self, name: str) -> NoReturn:
        del self, name
        raise AttributeError("POLICY_LOADER_FROZEN")

    def __repr__(self) -> str:
        return "<PolicyLoader redacted>"

    @classmethod
    def from_config(cls, config: AppConfig) -> PolicyLoader:
        if cls is not PolicyLoader or type(config) is not AppConfig:
            raise PolicyLoadError("POLICY_VALIDATED_CONFIG_REQUIRED")
        return cls(config)

    def load_all(self) -> PolicyBundle:
        if type(self) is not PolicyLoader:
            raise PolicyLoadError("POLICY_VALIDATED_CONFIG_REQUIRED")
        failure_code: str | None = None
        failure_policy_id: PolicyId | None = None
        try:
            return self._load_all()
        except PolicyLoadError as failure:
            failure_code = failure.code
            failure_policy_id = failure.policy_id
        if failure_code is None:
            failure_code = "POLICY_CANONICALIZATION_FAILED"
        raise PolicyLoadError(failure_code, failure_policy_id)

    def _load_all(self) -> PolicyBundle:
        policy_root = self._repo_root / "policies"
        try:
            guard = _open_policy_directory(policy_root)
        except _DirectoryMissing:
            raise PolicyLoadError("POLICY_DIRECTORY_MISSING") from None
        except _DirectoryUnsafe:
            raise PolicyLoadError("POLICY_DIRECTORY_UNSAFE") from None

        try:
            return self._load_from_guard(guard)
        finally:
            try:
                _CLOSE_DIRECTORY(guard.descriptor)
            except Exception:
                raise PolicyLoadError("POLICY_CHANGED_DURING_READ") from None

    def _load_from_guard(self, guard: _DirectoryGuard) -> PolicyBundle:
        try:
            initial_snapshot = _snapshot_directory(guard)
        except (_DirectoryMissing, _DirectoryUnsafe):
            raise PolicyLoadError("POLICY_DIRECTORY_UNSAFE") from None

        if frozenset(name for name, _identity in initial_snapshot[1]) != _POLICY_FILE_SET:
            raise PolicyLoadError("POLICY_FILE_SET_MISMATCH")
        initial_identities = dict(initial_snapshot[1])

        loaded: dict[PolicyId, LoadedPolicy[object]] = {}
        bundle_bytes = 0
        for policy_id, filename in _POLICY_FILES:
            raw = _read_exact_file(
                guard,
                policy_id,
                filename,
                initial_identities[filename],
            )
            bundle_bytes += len(raw)
            if bundle_bytes > _MAX_BUNDLE_BYTES:
                raise _file_error("POLICY_SIZE_LIMIT", policy_id)
            _validate_raw_bytes(raw, policy_id)
            parsed = _parse_yaml(raw, policy_id)
            _validate_constructed_types(parsed, policy_id)
            document = _construct_document(policy_id, parsed)
            raw_hash, canonical, content_hash = _artifact_hashes(
                raw,
                policy_id,
                document,
            )
            loaded[policy_id] = LoadedPolicy(
                filename=filename,
                schema_version="1.0",
                policy_id=policy_id,
                policy_version=1,
                raw_bytes_sha256=raw_hash,
                canonical_bytes=canonical,
                content_sha256=content_hash,
                document=document,
            )

        try:
            final_snapshot = _snapshot_directory(guard)
        except (_DirectoryMissing, _DirectoryUnsafe):
            raise PolicyLoadError("POLICY_CHANGED_DURING_READ") from None
        if final_snapshot != initial_snapshot:
            raise PolicyLoadError("POLICY_CHANGED_DURING_READ")

        return PolicyBundle(
            evidence_levels=cast(
                LoadedPolicy[EvidenceLevelsPolicy],
                loaded["evidence_levels"],
            ),
            relation_types=cast(
                LoadedPolicy[RelationTypesPolicy],
                loaded["relation_types"],
            ),
            retention=cast(
                LoadedPolicy[RetentionPolicy],
                loaded["retention"],
            ),
            risk_rules=cast(
                LoadedPolicy[RiskRulesPolicy],
                loaded["risk_rules"],
            ),
        )
