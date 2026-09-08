"""Redacted privacy-scanner value and construction contracts."""

from __future__ import annotations

import _thread
import hashlib
import hmac
import importlib
import json
import os
import re
import secrets
import stat
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import MappingProxyType
from typing import (
    Final,
    Literal,
    NoReturn,
    SupportsIndex,
    TypeAlias,
    cast,
    final,
)


ScanProfile: TypeAlias = Literal["repo_tracked", "shared_derivative"]

SCAN_CHUNK_BYTES: Final = 65_536
SCAN_CARRY_BYTES: Final = 512

# A valid v1 email can occupy 254 bytes, longer than every other content
# token. Delayed end-offset emission can therefore span one maximum token on
# each side of a read boundary, plus the byte context used by token bounds.
_MAX_STREAM_TOKEN_BYTES: Final = 254
_MIN_STREAM_CARRY_BYTES: Final = 2 * _MAX_STREAM_TOKEN_BYTES + 2
if SCAN_CARRY_BYTES < _MIN_STREAM_CARRY_BYTES:
    raise RuntimeError("SCAN_STREAMING_INVARIANT")

_SERIALIZATION_ERROR: Final = "SCAN_SERIALIZATION_FORBIDDEN"
_FROZEN_ERROR: Final = "SCAN_SCANNER_FROZEN"
_INITIALIZATION_RESERVED: Final = object()
_INITIALIZATION_STARTED: Final = object()
_INITIALIZATION_COMPLETE: Final = object()
_REPARSE_ATTRIBUTE: Final = int(
    getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
)
_PLATFORM_NAME = os.name
_O_BINARY: Final = int(getattr(os, "O_BINARY", 0))
_O_CLOEXEC: Final = int(getattr(os, "O_CLOEXEC", 0))
_O_NOFOLLOW = cast(int | None, getattr(os, "O_NOFOLLOW", None))
_O_NONBLOCK = cast(int | None, getattr(os, "O_NONBLOCK", None))
_WINDOWS_GENERIC_READ: Final = 0x80000000
_WINDOWS_FILE_SHARE_READ: Final = 0x00000001
_WINDOWS_FILE_SHARE_WRITE: Final = 0x00000002
_WINDOWS_OPEN_EXISTING: Final = 3
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT: Final = 0x00200000

_CN_MOBILE_NUMBER_PATTERN: Final[re.Pattern[bytes]] = re.compile(
    rb"(?<![0-9A-Za-z])(?:(?:\+86|0086)[ -]?)?1[3-9][0-9]"
    rb"(?:[ -]?[0-9]){8}(?![0-9A-Za-z])"
)
_CN_RESIDENT_ID_PATTERN: Final[re.Pattern[bytes]] = re.compile(
    rb"(?<![0-9A-Za-z])[1-9][0-9]{5}(?:18|19|20)[0-9]{2}"
    rb"(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])"
    rb"[0-9]{3}[0-9Xx](?![0-9A-Za-z])"
)
_EMAIL_ADDRESS_PATTERN: Final[re.Pattern[bytes]] = re.compile(
    rb"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    rb"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@"
    rb"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    rb"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
    rb"(?![A-Za-z0-9.-])"
)
_STABLE_CLIENT_ID_PATTERN: Final[re.Pattern[bytes]] = re.compile(
    rb"(?i:client_[a-z0-9]{12})"
)
_FORBIDDEN_SUFFIXES: Final[tuple[bytes, ...]] = (
    b".sqlite3-journal",
    b".sqlite3-wal",
    b".sqlite3-shm",
    b".sqlite3",
    b".db-journal",
    b".db-wal",
    b".db-shm",
    b".db",
)
_IDENTITY_MAP_BASENAME: Final = b"identity-map.enc"

_LSTAT = os.lstat
_FSTAT = os.fstat
_OPEN = os.open
_READ = os.read
_CLOSE = os.close
_SCANDIR = os.scandir


def _stdlib_realpath(path: str) -> str:
    return os.path.realpath(path, strict=True)


_REALPATH: Callable[[str], str] = _stdlib_realpath

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


@dataclass(frozen=True, slots=True)
class ScanLimits:
    """Inclusive scanner resource limits."""

    max_input_paths: int = 100_000
    max_roots: int = 50_000
    max_tree_entries: int = 500_000
    max_files: int = 100_000
    max_depth: int = 64
    max_native_relative_bytes: int = 32_768
    max_file_bytes: int = 1_073_741_824
    max_total_bytes: int = 8_589_934_592
    max_hits: int = 10_000
    max_catalog_bytes: int = 65_536
    max_markers: int = 256
    max_marker_bytes: int = 128


DEFAULT_SCAN_LIMITS: Final = ScanLimits()

_LIMIT_FIELDS: Final[tuple[str, ...]] = (
    "max_input_paths",
    "max_roots",
    "max_tree_entries",
    "max_files",
    "max_depth",
    "max_native_relative_bytes",
    "max_file_bytes",
    "max_total_bytes",
    "max_hits",
    "max_catalog_bytes",
    "max_markers",
    "max_marker_bytes",
)
_HARD_LIMIT_VALUES: Final[tuple[int, ...]] = (
    1_000_000,
    100_000,
    2_000_000,
    1_000_000,
    256,
    32_768,
    8_589_934_592,
    68_719_476_736,
    100_000,
    65_536,
    256,
    128,
)


class PrivacyScanError(RuntimeError):
    """A fixed-code scanner failure without caller-controlled text."""

    code: str
    location_ref: str | None

    def __init__(self, code: str, location_ref: str | None = None) -> None:
        self.code = code
        self.location_ref = location_ref
        super().__init__(code)

    def __repr__(self) -> str:
        return "<PrivacyScanError redacted>"


def _serialization_forbidden() -> NoReturn:
    raise TypeError(_SERIALIZATION_ERROR)


class _SerializationForbidden:
    __slots__ = ()

    def __copy__(self) -> NoReturn:
        _serialization_forbidden()

    def __deepcopy__(self, memo: object) -> NoReturn:
        del memo
        _serialization_forbidden()

    def __reduce__(self) -> NoReturn:
        _serialization_forbidden()

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        _serialization_forbidden()


@dataclass(frozen=True, slots=True)
class PrivacyHit:
    """One redacted privacy-rule occurrence."""

    location_ref: str
    rule_id: str
    line_number: int | None
    hit_hash: str


@dataclass(frozen=True, slots=True)
class PrivacyScanReport:
    """An ordered, value-comparable tuple of redacted occurrences."""

    hits: tuple[PrivacyHit, ...]

    @property
    def hit_count(self) -> int:
        return len(self.hits)


@final
class ScanResolutionHandle(_SerializationForbidden):
    """An opaque identity capability issued only by a committed scan."""

    __slots__ = ()

    def __new__(cls) -> NoReturn:
        del cls
        raise TypeError("SCAN_LOCATION_UNAVAILABLE")

    def __repr__(self) -> str:
        return "<ScanResolutionHandle redacted>"


def _issue_resolution_handle() -> ScanResolutionHandle:
    handle_type = cast(type[ScanResolutionHandle], ScanResolutionHandle)
    return object.__new__(handle_type)


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class PrivacyScanOutcome(_SerializationForbidden):
    """A report paired with an opaque, current-generation capability."""

    report: PrivacyScanReport
    resolution_handle: ScanResolutionHandle

    def __repr__(self) -> str:
        return "<PrivacyScanOutcome redacted>"


_StatIdentity: TypeAlias = tuple[int, int, int, int, int, int, int, int]
_MarkerSpan: TypeAlias = tuple[int, int]


@dataclass(frozen=True, slots=True, repr=False)
class _CatalogBinding:
    canonical_path: Path
    identity: _StatIdentity
    raw_sha256: str
    markers: tuple[bytes, ...]
    marker_spans: tuple[_MarkerSpan, ...]


@dataclass(frozen=True, slots=True)
class _JsonObject:
    pairs: tuple[tuple[str, object], ...]


class _CatalogFailure(Exception):
    code: str

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _DuplicateJsonKey(Exception):
    pass


class _ScanFailure(Exception):
    code: str

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True, repr=False)
class _ValidatedRoot:
    canonical_path: Path
    identity: _StatIdentity
    is_directory: bool


@dataclass(frozen=True, slots=True, repr=False)
class _Generation:
    handle: ScanResolutionHandle
    mapping: Mapping[str, Path]


@dataclass(frozen=True, slots=True, repr=False)
class _FilePlan:
    canonical_path: Path
    initial_identity: _StatIdentity
    owner_root: Path
    root_label: bytes
    owner_identity: bytes
    native_relative: bytes
    location_ref: str


@dataclass(frozen=True, slots=True, repr=False)
class _RawOccurrence:
    start: int
    end: int
    rule_id: str
    matched: bytes


_DirectoryIdentity: TypeAlias = tuple[int, int, int, int, int, int, int]
_ChildSnapshot: TypeAlias = tuple[bytes, _StatIdentity]


@dataclass(frozen=True, slots=True, repr=False)
class _TreeChild:
    canonical_path: Path
    identity: _StatIdentity
    is_directory: bool
    depth: int


@dataclass(frozen=True, slots=True, repr=False)
class _DirectorySnapshot:
    identity: _DirectoryIdentity
    children: tuple[_ChildSnapshot, ...]


@dataclass(frozen=True, slots=True, repr=False)
class _DirectoryRecord:
    canonical_path: Path
    depth: int
    initial: _DirectorySnapshot


@dataclass(frozen=True, slots=True, repr=False)
class _ExplicitRoot:
    validated: _ValidatedRoot
    key: str
    label: bytes


def _status_field(status: object, name: str) -> int:
    value = getattr(status, name)
    if type(value) is not int:
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
    return value


def _status_identity(status: object, limits: ScanLimits) -> _StatIdentity:
    mode = _status_field(status, "st_mode")
    device = _status_field(status, "st_dev")
    inode = _status_field(status, "st_ino")
    nlink = _status_field(status, "st_nlink")
    size = _status_field(status, "st_size")
    mtime_ns = _status_field(status, "st_mtime_ns")
    ctime_ns = _status_field(status, "st_ctime_ns")
    file_attributes = getattr(status, "st_file_attributes", 0)
    if type(file_attributes) is not int:
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
    identity = (
        mode,
        device,
        inode,
        nlink,
        size,
        mtime_ns,
        ctime_ns,
        file_attributes,
    )
    if (
        not stat.S_ISREG(mode)
        or bool(file_attributes & _REPARSE_ATTRIBUTE)
        or nlink != 1
        or size < 0
    ):
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
    if size > limits.max_catalog_bytes:
        raise _CatalogFailure("SCAN_LIMIT_CATALOG_BYTES")
    return identity


def _same_path_and_handle(
    path_identity: _StatIdentity,
    handle_identity: _StatIdentity,
) -> bool:
    return (
        path_identity[:6] == handle_identity[:6]
        and path_identity[7] == handle_identity[7]
    )


def _freeze_path_input(value: object) -> tuple[str, Path]:
    """Coerce a supported Path once, then discard its virtual surface."""

    if not isinstance(value, Path):
        raise TypeError
    path_text = os.fspath(value)
    if type(path_text) is not str:
        raise TypeError
    trusted_path = Path(path_text)
    if type(trusted_path) is not type(Path()):
        raise TypeError
    return path_text, trusted_path


def _windows_catalog_descriptor(path: Path) -> int:
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
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")

    handle: int | None = None
    try:
        handle = create_file(
            os.fspath(path),
            _WINDOWS_GENERIC_READ,
            _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
            0,
            _WINDOWS_OPEN_EXISTING,
            _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
            0,
        )
        if type(handle) is not int or handle == invalid_handle:
            raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
        descriptor = open_osfhandle(handle, os.O_RDONLY | _O_BINARY)
        if type(descriptor) is not int or descriptor < 0:
            raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
        handle = None
        return descriptor
    except _CatalogFailure:
        if handle is not None and handle != invalid_handle:
            try:
                close_handle(handle)
            except Exception:
                pass
        raise
    except Exception:
        if handle is not None and handle != invalid_handle:
            try:
                close_handle(handle)
            except Exception:
                pass
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID") from None


def _open_catalog_descriptor(path: Path) -> int:
    if _PLATFORM_NAME == "nt":
        return _windows_catalog_descriptor(path)
    if (
        _PLATFORM_NAME == "posix"
        and type(_O_NOFOLLOW) is int
        and type(_O_NONBLOCK) is int
    ):
        return _OPEN(
            os.fspath(path),
            os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC,
        )
    raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")


def _read_catalog_file(
    canary_definition_path: object,
    limits: ScanLimits,
) -> tuple[Path, _StatIdentity, bytes]:
    try:
        path_text, input_path = _freeze_path_input(canary_definition_path)
    except Exception:
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
    if not _native_is_absolute(path_text):
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")

    raw_path_before = _status_identity(
        _LSTAT(input_path),
        limits,
    )
    canonical_text = _REALPATH(path_text)
    if type(canonical_text) is not str:
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
    canonical_path = Path(canonical_text)
    if type(canonical_path) is not type(Path()) or not _native_is_absolute(
        canonical_text
    ):
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
    canonical_before = _status_identity(_LSTAT(canonical_path), limits)
    if raw_path_before != canonical_before:
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")

    descriptor = _open_catalog_descriptor(canonical_path)
    raw: bytes | None = None
    handle_before: _StatIdentity | None = None
    handle_after: _StatIdentity | None = None
    failure_code: str | None = None
    try:
        handle_before = _status_identity(_FSTAT(descriptor), limits)
        if not _same_path_and_handle(canonical_before, handle_before):
            raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")

        chunks: list[bytes] = []
        byte_count = 0
        while byte_count <= limits.max_catalog_bytes:
            chunk = _READ(
                descriptor,
                min(
                    SCAN_CHUNK_BYTES,
                    limits.max_catalog_bytes + 1 - byte_count,
                ),
            )
            if type(chunk) is not bytes:
                raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
            if not chunk:
                break
            chunks.append(chunk)
            byte_count += len(chunk)
        raw = b"".join(chunks)
        if len(raw) > limits.max_catalog_bytes:
            raise _CatalogFailure("SCAN_LIMIT_CATALOG_BYTES")

        handle_after = _status_identity(_FSTAT(descriptor), limits)
        if handle_after != handle_before or len(raw) != handle_after[4]:
            raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
    except _CatalogFailure as failure:
        failure_code = failure.code
    except Exception:
        failure_code = "SCAN_CANARY_CATALOG_INVALID"

    try:
        _CLOSE(descriptor)
    except Exception:
        failure_code = "SCAN_CANARY_CATALOG_INVALID"
    if failure_code is not None:
        raise _CatalogFailure(failure_code)
    if raw is None or handle_before is None or handle_after is None:
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")

    canonical_after = _status_identity(_LSTAT(canonical_path), limits)
    raw_path_after = _status_identity(
        _LSTAT(input_path),
        limits,
    )
    if (
        canonical_after != canonical_before
        or raw_path_after != raw_path_before
        or not _same_path_and_handle(canonical_after, handle_after)
    ):
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
    return canonical_path, canonical_after, raw


def _duplicate_rejecting_object(
    pairs: list[tuple[str, object]],
) -> _JsonObject:
    seen: set[str] = set()
    normalized: list[tuple[str, object]] = []
    for key, value in pairs:
        if type(key) is not str or key in seen:
            raise _DuplicateJsonKey
        seen.add(key)
        normalized.append((key, value))
    return _JsonObject(tuple(normalized))


def _json_string_tokens(
    raw: bytes,
) -> tuple[tuple[str, int, int, bool], ...]:
    tokens: list[tuple[str, int, int, bool]] = []
    index = 0
    while index < len(raw):
        if raw[index] != 0x22:
            index += 1
            continue
        quote_start = index
        content_start = index + 1
        index += 1
        escaped = False
        while index < len(raw):
            value = raw[index]
            if value == 0x5C:
                escaped = True
                index += 2
                continue
            if value == 0x22:
                content_end = index
                token_raw = raw[quote_start : index + 1]
                try:
                    decoded = json.loads(token_raw.decode("utf-8"))
                except Exception:
                    raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID") from None
                if type(decoded) is not str:
                    raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
                tokens.append((decoded, content_start, content_end, escaped))
                index += 1
                break
            index += 1
        else:
            raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
    return tuple(tokens)


def _parse_catalog(
    raw: bytes,
    limits: ScanLimits,
) -> tuple[tuple[bytes, ...], tuple[_MarkerSpan, ...]]:
    parsed: object | None = None
    try:
        decoded = raw.decode("utf-8")
        parsed = json.loads(
            decoded,
            object_pairs_hook=_duplicate_rejecting_object,
        )
    except Exception:
        pass
    if type(parsed) is not _JsonObject:
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")

    expected_keys = (
        "schema_version",
        "synthetic_only",
        "rule_id",
        "markers",
    )
    if tuple(key for key, _value in parsed.pairs) != expected_keys:
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
    schema_version, synthetic_only, rule_id, marker_values = (
        value for _key, value in parsed.pairs
    )
    if type(schema_version) is not str or schema_version != "1.0":
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
    if type(synthetic_only) is not bool or synthetic_only is not True:
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
    if type(rule_id) is not str or rule_id != "known_canary":
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
    if type(marker_values) is not list or not marker_values:
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
    if len(marker_values) > limits.max_markers:
        raise _CatalogFailure("SCAN_LIMIT_MARKERS")

    markers: list[bytes] = []
    marker_strings: list[str] = []
    for marker in marker_values:
        if type(marker) is not str:
            raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
        try:
            marker_bytes = marker.encode("ascii")
        except UnicodeEncodeError:
            raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID") from None
        if not marker_bytes:
            raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
        if len(marker_bytes) > limits.max_marker_bytes:
            raise _CatalogFailure("SCAN_LIMIT_MARKER_BYTES")
        if any(value < 0x20 or value > 0x7E for value in marker_bytes):
            raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
        markers.append(marker_bytes)
        marker_strings.append(marker)

    if len(set(markers)) != len(markers):
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
    for left_index, left in enumerate(markers):
        for right_index, right in enumerate(markers):
            if left_index != right_index and left in right:
                raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")

    tokens = _json_string_tokens(raw)
    expected_tokens = (
        "schema_version",
        "1.0",
        "synthetic_only",
        "rule_id",
        "known_canary",
        "markers",
        *marker_strings,
    )
    if tuple(token[0] for token in tokens) != expected_tokens:
        raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")

    marker_spans: list[_MarkerSpan] = []
    for marker_bytes, token in zip(markers, tokens[6:]):
        _decoded, start, end, escaped = token
        if escaped or raw[start:end] != marker_bytes:
            raise _CatalogFailure("SCAN_CANARY_CATALOG_INVALID")
        marker_spans.append((start, end))
    return tuple(markers), tuple(marker_spans)


def _strict_catalog_binding(
    canary_definition_path: object,
    limits: ScanLimits,
) -> _CatalogBinding:
    canonical_path, identity, raw = _read_catalog_file(
        canary_definition_path,
        limits,
    )
    markers, marker_spans = _parse_catalog(raw, limits)
    return _CatalogBinding(
        canonical_path=canonical_path,
        identity=identity,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        markers=markers,
        marker_spans=marker_spans,
    )


def _catalog_binding(
    canary_definition_path: object,
    limits: ScanLimits,
) -> _CatalogBinding:
    failure_code: str | None = None
    try:
        return _strict_catalog_binding(canary_definition_path, limits)
    except _CatalogFailure as failure:
        failure_code = failure.code
    except Exception:
        failure_code = "SCAN_CANARY_CATALOG_INVALID"
    if failure_code is None:
        failure_code = "SCAN_CANARY_CATALOG_INVALID"
    raise PrivacyScanError(failure_code)


def _validate_limits(limits: object) -> ScanLimits:
    if type(limits) is not ScanLimits:
        raise PrivacyScanError("SCAN_LIMIT_CONFIGURATION_INVALID")
    for field_name, hard_value in zip(_LIMIT_FIELDS, _HARD_LIMIT_VALUES):
        value = getattr(limits, field_name)
        if type(value) is not int or value <= 0 or value > hard_value:
            raise PrivacyScanError("SCAN_LIMIT_CONFIGURATION_INVALID")
    return limits


def _validate_profile(profile: object) -> ScanProfile:
    if type(profile) is not str or profile not in (
        "repo_tracked",
        "shared_derivative",
    ):
        raise PrivacyScanError("SCAN_PROFILE_INVALID")
    return cast(ScanProfile, profile)


def _validate_key(hash_key: object) -> bytes:
    if type(hash_key) is not bytes or len(hash_key) != 32:
        raise PrivacyScanError("SCAN_KEY_INVALID")
    return hash_key


def _generate_scan_key() -> bytes:
    candidate: object | None = None
    try:
        candidate = secrets.token_bytes(32)
    except Exception:
        pass
    if type(candidate) is not bytes or len(candidate) != 32:
        raise PrivacyScanError("SCAN_KEY_INVALID")
    return candidate


def _frame_parts(*parts: bytes) -> bytes:
    framed: list[bytes] = []
    for part in parts:
        if type(part) is not bytes:
            raise PrivacyScanError("SCAN_INPUT_INVALID")
        framed.append(len(part).to_bytes(8, byteorder="big", signed=False))
        framed.append(part)
    return b"".join(framed)


def _hit_hash(
    scan_key: bytes,
    rule_id: bytes,
    exact_match_bytes: bytes,
) -> str:
    validated_key = _validate_key(scan_key)
    payload = _frame_parts(
        b"consultation-privacy-hit-v1",
        rule_id,
        exact_match_bytes,
    )
    return hmac.new(validated_key, payload, hashlib.sha256).hexdigest()


def _limits_canonical_bytes(limits: ScanLimits) -> bytes:
    validated = _validate_limits(limits)
    return (
        f"inputs={validated.max_input_paths};"
        f"roots={validated.max_roots};"
        f"tree_entries={validated.max_tree_entries};"
        f"files={validated.max_files};"
        f"depth={validated.max_depth};"
        f"native={validated.max_native_relative_bytes};"
        f"file={validated.max_file_bytes};"
        f"total={validated.max_total_bytes};"
        f"hits={validated.max_hits};"
        f"catalog={validated.max_catalog_bytes};"
        f"markers={validated.max_markers};"
        f"marker_bytes={validated.max_marker_bytes};"
        f"chunk={SCAN_CHUNK_BYTES};"
        f"carry={SCAN_CARRY_BYTES}"
    ).encode("ascii")


def _location_ref(
    scan_key: bytes,
    profile: bytes,
    root_label: bytes,
    limits_canonical_bytes: bytes,
    owner_root_identity_bytes: bytes,
    native_relative_bytes: bytes,
) -> str:
    validated_key = _validate_key(scan_key)
    payload = _frame_parts(
        b"consultation-privacy-location-v1",
        profile,
        root_label,
        limits_canonical_bytes,
        owner_root_identity_bytes,
        native_relative_bytes,
    )
    digest = hmac.new(validated_key, payload, hashlib.sha256).hexdigest()
    try:
        root_label_text = root_label.decode("ascii")
    except UnicodeDecodeError:
        raise PrivacyScanError("SCAN_INPUT_INVALID") from None
    return f"{root_label_text}/pth1_{digest}"


def _email_candidate_valid(candidate: bytes) -> bool:
    if len(candidate) > 254:
        return False
    local, separator, domain = candidate.partition(b"@")
    if separator != b"@" or not local or not domain or len(local) > 64:
        return False
    if local.startswith(b".") or local.endswith(b".") or b".." in local:
        return False
    labels = domain.split(b".")
    if len(labels) < 2:
        return False
    return all(
        1 <= len(label) <= 63
        and not label.startswith(b"-")
        and not label.endswith(b"-")
        for label in labels
    )


def _candidate_matches(rule_id: str, data: bytes) -> tuple[bytes, ...]:
    if type(rule_id) is not str or type(data) is not bytes:
        raise PrivacyScanError("SCAN_INPUT_INVALID")
    pattern: re.Pattern[bytes]
    if rule_id == "cn_mobile_number":
        pattern = _CN_MOBILE_NUMBER_PATTERN
    elif rule_id == "cn_resident_id":
        pattern = _CN_RESIDENT_ID_PATTERN
    elif rule_id == "email_address":
        pattern = _EMAIL_ADDRESS_PATTERN
    elif rule_id == "stable_client_id":
        pattern = _STABLE_CLIENT_ID_PATTERN
    else:
        raise PrivacyScanError("SCAN_INPUT_INVALID")

    matches: list[bytes] = []
    for match in pattern.finditer(data):
        candidate = match.group(0)
        if rule_id == "email_address" and not _email_candidate_valid(candidate):
            continue
        matches.append(candidate)
    return tuple(matches)


def _canary_matches(
    data: bytes,
    markers: tuple[bytes, ...],
) -> tuple[bytes, ...]:
    if type(data) is not bytes or type(markers) is not tuple:
        raise PrivacyScanError("SCAN_INPUT_INVALID")
    occurrences: list[tuple[int, int, bytes]] = []
    for marker_ordinal, marker in enumerate(markers):
        if type(marker) is not bytes or not marker:
            raise PrivacyScanError("SCAN_INPUT_INVALID")
        start = 0
        while True:
            offset = data.find(marker, start)
            if offset < 0:
                break
            occurrences.append((offset, marker_ordinal, marker))
            start = offset + len(marker)
    occurrences.sort(key=lambda item: (item[0], item[1]))
    return tuple(marker for _offset, _ordinal, marker in occurrences)


def _forbidden_suffix_match(
    profile: ScanProfile,
    final_basename: bytes,
) -> bytes | None:
    _validate_profile(profile)
    if type(final_basename) is not bytes:
        raise PrivacyScanError("SCAN_INPUT_INVALID")
    separators: tuple[bytes, ...]
    if _PLATFORM_NAME == "nt":
        separators = (b"/", b"\\")
    elif _PLATFORM_NAME == "posix":
        separators = (b"/",)
    else:
        raise PrivacyScanError("SCAN_INPUT_INVALID")
    if any(separator in final_basename for separator in separators):
        return None
    lowered = final_basename.lower()
    if lowered == _IDENTITY_MAP_BASENAME:
        return final_basename
    for suffix in _FORBIDDEN_SUFFIXES:
        if lowered.endswith(suffix):
            return final_basename[-len(suffix) :]
    return None


def _scan_status_identity(status: object) -> _StatIdentity:
    values: list[int] = []
    for name in (
        "st_mode",
        "st_dev",
        "st_ino",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    ):
        value = getattr(status, name)
        if type(value) is not int:
            raise _ScanFailure("SCAN_PATH_UNSUPPORTED")
        values.append(value)
    file_attributes = getattr(status, "st_file_attributes", 0)
    if type(file_attributes) is not int:
        raise _ScanFailure("SCAN_PATH_UNSUPPORTED")
    values.append(file_attributes)
    return cast(_StatIdentity, tuple(values))


def _path_has_control(path_text: str) -> bool:
    return any(
        ord(character) < 0x20 or ord(character) == 0x7F
        for character in path_text
    )


def _native_separators() -> tuple[str, ...]:
    if _PLATFORM_NAME == "nt":
        return ("/", "\\")
    if _PLATFORM_NAME == "posix":
        return ("/",)
    return ()


def _native_component_supported(name: object) -> bool:
    if type(name) is not str or not name or name in (".", ".."):
        return False
    separators = _native_separators()
    return bool(separators) and not _path_has_control(name) and not any(
        separator in name for separator in separators
    )


def _native_is_absolute(path_text: str) -> bool:
    if _PLATFORM_NAME == "nt":
        return PureWindowsPath(path_text).is_absolute()
    if _PLATFORM_NAME == "posix":
        return PurePosixPath(path_text).is_absolute()
    return False


def _unsupported_namespace(path_text: str) -> bool:
    if _PLATFORM_NAME != "nt":
        return False
    normalized = path_text.replace("/", "\\")
    if normalized.startswith("\\\\"):
        return True
    lowered = normalized.lower()
    nt_families = (
        "\\??\\",
        "\\device\\",
        "\\global??\\",
        "\\dosdevices\\",
    )
    if any(
        lowered == family[:-1] or lowered.startswith(family)
        for family in nt_families
    ):
        return True
    return (
        len(normalized) >= 2
        and normalized[0].isascii()
        and normalized[0].isalpha()
        and normalized[1] == ":"
        and (len(normalized) == 2 or normalized[2] != "\\")
    )


def _root_observation(path: object) -> _ValidatedRoot:
    try:
        path_text, input_path = _freeze_path_input(path)
    except Exception:
        raise _ScanFailure("SCAN_INPUT_INVALID") from None
    if _unsupported_namespace(path_text):
        raise _ScanFailure("SCAN_PATH_NAMESPACE_UNSUPPORTED")
    if not _native_is_absolute(path_text):
        raise _ScanFailure("SCAN_PATH_NOT_ABSOLUTE")
    if _path_has_control(path_text):
        raise _ScanFailure("SCAN_PATH_UNSUPPORTED")

    try:
        raw_identity = _scan_status_identity(_LSTAT(input_path))
    except FileNotFoundError:
        raise _ScanFailure("SCAN_PATH_NOT_FOUND") from None
    except _ScanFailure:
        raise
    except OSError:
        raise _ScanFailure("SCAN_UNREADABLE") from None
    except Exception:
        raise _ScanFailure("SCAN_INPUT_INVALID") from None

    mode = raw_identity[0]
    if stat.S_ISLNK(mode) or bool(raw_identity[7] & _REPARSE_ATTRIBUTE):
        raise _ScanFailure("SCAN_LINK_OR_REPARSE")
    is_directory = stat.S_ISDIR(mode)
    if not is_directory and not stat.S_ISREG(mode):
        raise _ScanFailure("SCAN_PATH_UNSUPPORTED")

    try:
        canonical_text = _REALPATH(path_text)
    except FileNotFoundError:
        raise _ScanFailure("SCAN_PATH_NOT_FOUND") from None
    except OSError:
        raise _ScanFailure("SCAN_UNREADABLE") from None
    except Exception:
        raise _ScanFailure("SCAN_INPUT_INVALID") from None
    if type(canonical_text) is not str:
        raise _ScanFailure("SCAN_INPUT_INVALID")
    canonical = Path(canonical_text)
    if type(canonical) is not type(Path()) or not _native_is_absolute(
        canonical_text
    ):
        raise _ScanFailure("SCAN_ROOT_ESCAPE")
    try:
        lexical_key = os.path.normcase(os.path.normpath(os.path.abspath(path_text)))
        canonical_key = os.path.normcase(os.path.normpath(canonical_text))
    except Exception:
        raise _ScanFailure("SCAN_INPUT_INVALID") from None
    if lexical_key != canonical_key:
        raise _ScanFailure("SCAN_ROOT_ESCAPE")
    try:
        canonical_identity = _scan_status_identity(_LSTAT(canonical))
    except FileNotFoundError:
        raise _ScanFailure("SCAN_PATH_NOT_FOUND") from None
    except _ScanFailure:
        raise
    except OSError:
        raise _ScanFailure("SCAN_UNREADABLE") from None
    except Exception:
        raise _ScanFailure("SCAN_INPUT_INVALID") from None
    if raw_identity != canonical_identity:
        raise _ScanFailure("SCAN_ROOT_ESCAPE")
    return _ValidatedRoot(canonical, canonical_identity, is_directory)


def _bounded_raw_roots(
    paths: object,
    limits: ScanLimits,
) -> tuple[_ValidatedRoot, ...]:
    if isinstance(paths, (str, bytes, bytearray, memoryview)) or not isinstance(
        paths,
        Sequence,
    ):
        raise _ScanFailure("SCAN_INPUT_INVALID")
    roots: list[_ValidatedRoot] = []
    root_keys: set[str] = set()
    index = 0
    while True:
        try:
            path = paths[index]
        except IndexError:
            break
        except Exception:
            raise _ScanFailure("SCAN_INPUT_INVALID") from None
        index += 1
        if index > limits.max_input_paths:
            raise _ScanFailure("SCAN_LIMIT_INPUT_PATHS")
        root = _root_observation(path)
        root_key = _canonical_path_key(root.canonical_path)
        if root_key in root_keys:
            continue
        if len(root_keys) >= limits.max_roots:
            raise _ScanFailure("SCAN_LIMIT_ROOTS")
        root_keys.add(root_key)
        roots.append(root)
    return tuple(roots)


def _scan_catalog_check(
    binding: object,
    limits: ScanLimits,
) -> None:
    if type(binding) is not _CatalogBinding:
        raise _ScanFailure("SCAN_CATALOG_CHANGED")
    failure = False
    canonical_path: Path | None = None
    identity: _StatIdentity | None = None
    raw: bytes | None = None
    try:
        canonical_path, identity, raw = _read_catalog_file(
            binding.canonical_path,
            limits,
        )
    except Exception:
        failure = True
    if (
        failure
        or canonical_path != binding.canonical_path
        or identity != binding.identity
        or type(raw) is not bytes
        or hashlib.sha256(raw).hexdigest() != binding.raw_sha256
    ):
        raise _ScanFailure("SCAN_CATALOG_CHANGED")


def _operation_lock_for(
    scanner: object,
    invalid_code: str,
) -> _thread.LockType:
    if type(scanner) is not PrivacyScanner:
        raise _ScanFailure(invalid_code)
    try:
        state = object.__getattribute__(
            scanner,
            "_PrivacyScanner__initialization_state",
        )
    except Exception:
        raise _ScanFailure(invalid_code) from None
    if state is not _INITIALIZATION_COMPLETE:
        raise _ScanFailure(invalid_code)
    try:
        lock = object.__getattribute__(
            scanner,
            "_PrivacyScanner__operation_lock",
        )
    except Exception:
        raise _ScanFailure(invalid_code) from None
    if type(lock) is not _thread.LockType:
        raise _ScanFailure(invalid_code)
    acquired = False
    try:
        acquired = lock.acquire(blocking=False)
    except Exception:
        raise _ScanFailure(invalid_code) from None
    if not acquired:
        raise _ScanFailure("SCAN_CONCURRENT_USE")
    return lock


def _scanner_runtime_state(
    scanner: PrivacyScanner,
) -> tuple[ScanLimits, ScanProfile, bytes, _CatalogBinding]:
    try:
        limits = object.__getattribute__(scanner, "_PrivacyScanner__limits")
        profile = object.__getattribute__(scanner, "_PrivacyScanner__profile")
        scan_key = object.__getattribute__(scanner, "_PrivacyScanner__scan_key")
        binding = object.__getattribute__(
            scanner,
            "_PrivacyScanner__catalog_binding",
        )
    except Exception:
        raise _ScanFailure("SCAN_INPUT_INVALID") from None
    if (
        type(limits) is not ScanLimits
        or type(profile) is not str
        or profile not in ("repo_tracked", "shared_derivative")
        or type(scan_key) is not bytes
        or len(scan_key) != 32
        or type(binding) is not _CatalogBinding
    ):
        raise _ScanFailure("SCAN_INPUT_INVALID")
    return limits, cast(ScanProfile, profile), scan_key, binding


def _canonical_path_key(path: Path) -> str:
    try:
        return os.path.normcase(os.path.normpath(os.fspath(path)))
    except Exception:
        raise _ScanFailure("SCAN_INPUT_INVALID") from None


def _owner_identity(path: Path) -> bytes:
    try:
        text = os.fspath(path)
        if _PLATFORM_NAME == "nt":
            text = os.path.normcase(os.path.normpath(text))
        encoded = os.fsencode(text)
    except Exception:
        raise _ScanFailure("SCAN_INPUT_INVALID") from None
    if type(encoded) is not bytes or not encoded:
        raise _ScanFailure("SCAN_INPUT_INVALID")
    return encoded


def _validated_native_relative(
    relative: Path,
    limits: ScanLimits,
) -> bytes:
    try:
        parts = relative.parts
        encoded = os.fsencode(os.fspath(relative))
    except Exception:
        raise _ScanFailure("SCAN_INPUT_INVALID") from None
    if (
        type(encoded) is not bytes
        or not encoded
        or not parts
        or any(not _native_component_supported(part) for part in parts)
    ):
        raise _ScanFailure("SCAN_INPUT_INVALID")
    if len(encoded) > limits.max_native_relative_bytes:
        raise _ScanFailure("SCAN_LIMIT_NATIVE_RELATIVE_BYTES")
    return encoded


def _directory_identity(identity: _StatIdentity) -> _DirectoryIdentity:
    if stat.S_ISLNK(identity[0]) or bool(identity[7] & _REPARSE_ATTRIBUTE):
        raise _ScanFailure("SCAN_LINK_OR_REPARSE")
    if not stat.S_ISDIR(identity[0]):
        raise _ScanFailure("SCAN_TREE_CHANGED")
    return (
        identity[0],
        identity[1],
        identity[2],
        identity[3],
        identity[5],
        identity[6],
        identity[7],
    )


def _directory_snapshot(
    path: Path,
    depth: int,
    limits: ScanLimits,
    tree_observations: list[int],
) -> tuple[_DirectorySnapshot, tuple[_TreeChild, ...]]:
    failure_code: str | None = None
    directory_identity: _DirectoryIdentity | None = None
    children: list[_TreeChild] = []
    child_snapshots: list[_ChildSnapshot] = []
    iterator: object | None = None
    try:
        directory_identity = _directory_identity(
            _scan_status_identity(_LSTAT(path))
        )
        iterator = _SCANDIR(path)
        entries = cast(Iterator[os.DirEntry[str]], iterator)
        for entry in entries:
            tree_observations[0] += 1
            if tree_observations[0] > limits.max_tree_entries:
                raise _ScanFailure("SCAN_LIMIT_TREE_ENTRIES")
            child_depth = depth + 1
            if child_depth > limits.max_depth:
                raise _ScanFailure("SCAN_LIMIT_DEPTH")
            name = entry.name
            if type(name) is not str:
                raise _ScanFailure("SCAN_INPUT_INVALID")
            try:
                name_bytes = os.fsencode(name)
            except Exception:
                raise _ScanFailure("SCAN_INPUT_INVALID") from None
            if (
                type(name_bytes) is not bytes
                or not name_bytes
                or not _native_component_supported(name)
            ):
                raise _ScanFailure("SCAN_INPUT_INVALID")
            child_path = path / name
            child_identity = _scan_status_identity(_LSTAT(child_path))
            if stat.S_ISLNK(child_identity[0]) or bool(
                child_identity[7] & _REPARSE_ATTRIBUTE
            ):
                raise _ScanFailure("SCAN_LINK_OR_REPARSE")
            is_directory = stat.S_ISDIR(child_identity[0])
            if not is_directory and not stat.S_ISREG(child_identity[0]):
                raise _ScanFailure("SCAN_PATH_UNSUPPORTED")
            child = _TreeChild(
                canonical_path=child_path,
                identity=child_identity,
                is_directory=is_directory,
                depth=child_depth,
            )
            children.append(child)
            child_snapshots.append((name_bytes, child_identity))
    except _ScanFailure as failure:
        failure_code = failure.code
    except FileNotFoundError:
        failure_code = "SCAN_TREE_CHANGED"
    except Exception:
        failure_code = "SCAN_TREE_CHANGED"
    if iterator is not None:
        try:
            close = getattr(iterator, "close", None)
            if close is not None:
                close()
        except Exception:
            failure_code = "SCAN_TREE_CHANGED"
    if failure_code is not None:
        raise _ScanFailure(failure_code)
    if directory_identity is None:
        raise _ScanFailure("SCAN_TREE_CHANGED")
    ordered_children = tuple(
        sorted(children, key=lambda child: os.fsencode(child.canonical_path.name))
    )
    ordered_snapshot = tuple(sorted(child_snapshots, key=lambda item: item[0]))
    return (
        _DirectorySnapshot(directory_identity, ordered_snapshot),
        ordered_children,
    )


def _owner_index_lookup(
    owner_index: Mapping[str, _ExplicitRoot],
    path_key: str,
) -> _ExplicitRoot | None:
    return owner_index.get(path_key)


def _most_specific_owner(
    path: Path,
    path_key: str,
    file_roots: Mapping[str, _ExplicitRoot],
    directory_roots: Mapping[str, _ExplicitRoot],
    max_depth: int,
) -> _ExplicitRoot:
    exact = _owner_index_lookup(file_roots, path_key)
    if exact is not None:
        return exact

    parent = path.parent
    for _probe in range(max_depth):
        owner = _owner_index_lookup(
            directory_roots,
            _canonical_path_key(parent),
        )
        if owner is not None:
            return owner
        next_parent = parent.parent
        if next_parent == parent:
            break
        parent = next_parent
    raise _ScanFailure("SCAN_ROOT_ESCAPE")


def _build_scan_plan(
    roots: tuple[_ValidatedRoot, ...],
    limits: ScanLimits,
    profile: ScanProfile,
    scan_key: bytes,
) -> tuple[
    tuple[_FilePlan, ...],
    tuple[_DirectoryRecord, ...],
    list[int],
]:
    by_key: dict[str, _ValidatedRoot] = {}
    for validated_root in roots:
        key = _canonical_path_key(validated_root.canonical_path)
        if key not in by_key:
            by_key[key] = validated_root
    if len(by_key) > limits.max_roots:
        raise _ScanFailure("SCAN_LIMIT_ROOTS")
    explicit_roots = tuple(
        _ExplicitRoot(
            validated=by_key[key],
            key=key,
            label=f"root_{ordinal:04d}".encode("ascii"),
        )
        for ordinal, key in enumerate(sorted(by_key), start=1)
    )
    file_roots = {
        root.key: root
        for root in explicit_roots
        if not root.validated.is_directory
    }
    directory_roots = {
        root.key: root
        for root in explicit_roots
        if root.validated.is_directory
    }

    tree_observations = [0]
    directory_records: list[_DirectoryRecord] = []
    candidates: dict[str, tuple[Path, _StatIdentity]] = {}

    def remember_file(path: Path, identity: _StatIdentity) -> None:
        key = _canonical_path_key(path)
        current = candidates.get(key)
        if current is not None and current[1] != identity:
            raise _ScanFailure("SCAN_TREE_CHANGED")
        candidates[key] = (path, identity)

    def traverse_directory(
        path: Path,
        depth: int,
        expected_identity: _StatIdentity,
    ) -> None:
        initial, children = _directory_snapshot(
            path,
            depth,
            limits,
            tree_observations,
        )
        if initial.identity != _directory_identity(expected_identity):
            raise _ScanFailure("SCAN_TREE_CHANGED")
        directory_records.append(_DirectoryRecord(path, depth, initial))
        for child in children:
            if child.is_directory:
                traverse_directory(
                    child.canonical_path,
                    child.depth,
                    child.identity,
                )
            else:
                remember_file(child.canonical_path, child.identity)

    for explicit_root in explicit_roots:
        if explicit_root.validated.is_directory:
            traverse_directory(
                explicit_root.validated.canonical_path,
                0,
                explicit_root.validated.identity,
            )
        else:
            remember_file(
                explicit_root.validated.canonical_path,
                explicit_root.validated.identity,
            )

    limits_bytes = _limits_canonical_bytes(limits)
    plans: list[_FilePlan] = []
    file_count = 0
    planned_total = 0
    for key in sorted(candidates):
        path, identity = candidates[key]
        owner = _most_specific_owner(
            path,
            key,
            file_roots,
            directory_roots,
            limits.max_depth,
        )
        file_count += 1
        if file_count > limits.max_files:
            raise _ScanFailure("SCAN_LIMIT_FILES")
        if owner.validated.is_directory:
            try:
                relative = path.relative_to(owner.validated.canonical_path)
            except ValueError:
                raise _ScanFailure("SCAN_ROOT_ESCAPE") from None
        else:
            relative = Path(path.name)
        native_relative = _validated_native_relative(relative, limits)
        size = identity[4]
        if size < 0:
            raise _ScanFailure("SCAN_FILE_CHANGED")
        if size > limits.max_file_bytes:
            raise _ScanFailure("SCAN_LIMIT_FILE_BYTES")
        planned_total += size
        if planned_total > limits.max_total_bytes:
            raise _ScanFailure("SCAN_LIMIT_TOTAL_BYTES")
        owner_identity = _owner_identity(owner.validated.canonical_path)
        location = _location_ref(
            scan_key,
            profile.encode("ascii"),
            owner.label,
            limits_bytes,
            owner_identity,
            native_relative,
        )
        plans.append(
            _FilePlan(
                canonical_path=path,
                initial_identity=identity,
                owner_root=owner.validated.canonical_path,
                root_label=owner.label,
                owner_identity=owner_identity,
                native_relative=native_relative,
                location_ref=location,
            )
        )
    return tuple(plans), tuple(directory_records), tree_observations


def _close_directory_records(
    records: tuple[_DirectoryRecord, ...],
    limits: ScanLimits,
    tree_observations: list[int],
) -> None:
    for record in reversed(records):
        try:
            final, _children = _directory_snapshot(
                record.canonical_path,
                record.depth,
                limits,
                tree_observations,
            )
        except _ScanFailure as failure:
            if failure.code in (
                "SCAN_LIMIT_TREE_ENTRIES",
                "SCAN_LIMIT_DEPTH",
            ):
                raise
            raise _ScanFailure("SCAN_TREE_CHANGED") from None
        if final != record.initial:
            raise _ScanFailure("SCAN_TREE_CHANGED")


def _open_scan_descriptor(path: Path) -> int:
    try:
        descriptor = _open_catalog_descriptor(path)
    except Exception:
        raise _ScanFailure("SCAN_UNREADABLE") from None
    if type(descriptor) is not int or descriptor < 0:
        raise _ScanFailure("SCAN_UNREADABLE")
    return descriptor


def _raw_occurrences(
    data: bytes,
    markers: tuple[bytes, ...],
) -> tuple[_RawOccurrence, ...]:
    occurrences: list[_RawOccurrence] = []
    for marker in markers:
        start = 0
        while True:
            offset = data.find(marker, start)
            if offset < 0:
                break
            occurrences.append(
                _RawOccurrence(
                    start=offset,
                    end=offset + len(marker),
                    rule_id="known_canary",
                    matched=marker,
                )
            )
            start = offset + len(marker)
    patterns = (
        ("cn_mobile_number", _CN_MOBILE_NUMBER_PATTERN),
        ("cn_resident_id", _CN_RESIDENT_ID_PATTERN),
        ("email_address", _EMAIL_ADDRESS_PATTERN),
        ("stable_client_id", _STABLE_CLIENT_ID_PATTERN),
    )
    for rule_id, pattern in patterns:
        for match in pattern.finditer(data):
            candidate = match.group(0)
            if rule_id == "email_address" and not _email_candidate_valid(candidate):
                continue
            start, end = match.span()
            occurrences.append(
                _RawOccurrence(start, end, rule_id, candidate)
            )
    occurrences.sort(
        key=lambda occurrence: (
            occurrence.start,
            occurrence.end,
            occurrence.rule_id,
            occurrence.matched,
        )
    )
    return tuple(occurrences)


def _advance_line_state(
    data: bytes,
    line: int,
    previous_cr: bool,
) -> tuple[int, bool]:
    for value in data:
        if value == 0x0D:
            line += 1
            previous_cr = True
        elif value == 0x0A:
            if not previous_cr:
                line += 1
            previous_cr = False
        else:
            previous_cr = False
    return line, previous_cr


def _definition_occurrence_exempt(
    plan: _FilePlan,
    handle_identity: _StatIdentity,
    binding: _CatalogBinding,
    occurrence: _RawOccurrence,
    absolute_start: int,
    absolute_end: int,
) -> bool:
    if (
        occurrence.rule_id != "known_canary"
        or plan.canonical_path != binding.canonical_path
        or not _same_path_and_handle(binding.identity, handle_identity)
    ):
        return False
    for marker, span in zip(binding.markers, binding.marker_spans):
        if occurrence.matched == marker and (absolute_start, absolute_end) == span:
            return True
    return False


def _append_privacy_hit(
    hits: list[PrivacyHit],
    limits: ScanLimits,
    scan_key: bytes,
    location_ref: str,
    rule_id: str,
    line_number: int | None,
    matched: bytes,
) -> None:
    if len(hits) >= limits.max_hits:
        raise _ScanFailure("SCAN_LIMIT_HITS")
    hits.append(
        PrivacyHit(
            location_ref=location_ref,
            rule_id=rule_id,
            line_number=line_number,
            hit_hash=_hit_hash(scan_key, rule_id.encode("ascii"), matched),
        )
    )


def _emit_content_window(
    *,
    window: bytes,
    base_offset: int,
    emit_after: int,
    emit_through: int,
    base_line: int,
    base_previous_cr: bool,
    plan: _FilePlan,
    handle_identity: _StatIdentity,
    binding: _CatalogBinding,
    limits: ScanLimits,
    scan_key: bytes,
    hits: list[PrivacyHit],
) -> None:
    selected: list[tuple[_RawOccurrence, int, int]] = []
    for occurrence in _raw_occurrences(window, binding.markers):
        absolute_start = base_offset + occurrence.start
        absolute_end = base_offset + occurrence.end
        if absolute_end <= emit_after or absolute_end > emit_through:
            continue
        if _definition_occurrence_exempt(
            plan,
            handle_identity,
            binding,
            occurrence,
            absolute_start,
            absolute_end,
        ):
            continue
        selected.append((occurrence, absolute_start, absolute_end))

    selected.sort(key=lambda item: (item[0].start, item[0].end, item[0].rule_id))
    cursor = 0
    line = base_line
    previous_cr = base_previous_cr
    for occurrence, _absolute_start, _absolute_end in selected:
        if occurrence.start > cursor:
            line, previous_cr = _advance_line_state(
                window[cursor : occurrence.start],
                line,
                previous_cr,
            )
            cursor = occurrence.start
        _append_privacy_hit(
            hits,
            limits,
            scan_key,
            plan.location_ref,
            occurrence.rule_id,
            line,
            occurrence.matched,
        )


def _emit_path_hits(
    plan: _FilePlan,
    profile: ScanProfile,
    binding: _CatalogBinding,
    limits: ScanLimits,
    scan_key: bytes,
    hits: list[PrivacyHit],
) -> None:
    try:
        relative_path = Path(os.fsdecode(plan.native_relative))
        segment_bytes = tuple(os.fsencode(part) for part in relative_path.parts)
    except Exception:
        raise _ScanFailure("SCAN_INPUT_INVALID") from None
    for segment in segment_bytes:
        for occurrence in _raw_occurrences(segment, binding.markers):
            _append_privacy_hit(
                hits,
                limits,
                scan_key,
                plan.location_ref,
                occurrence.rule_id,
                None,
                occurrence.matched,
            )
    final_basename = segment_bytes[-1]
    suffix = _forbidden_suffix_match(profile, final_basename)
    if suffix is not None:
        _append_privacy_hit(
            hits,
            limits,
            scan_key,
            plan.location_ref,
            "forbidden_path_suffix",
            None,
            suffix,
        )


def _unsupported_bom(prefix: bytes) -> bool:
    return prefix.startswith(
        (b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")
    )


def _scan_file_plan(
    plan: _FilePlan,
    profile: ScanProfile,
    binding: _CatalogBinding,
    limits: ScanLimits,
    scan_key: bytes,
    total_before: int,
    hits: list[PrivacyHit],
) -> int:
    _emit_path_hits(plan, profile, binding, limits, scan_key, hits)
    descriptor: int | None = None
    failure_code: str | None = None
    file_count = 0
    handle_before: _StatIdentity | None = None
    handle_after: _StatIdentity | None = None
    try:
        descriptor = _open_scan_descriptor(plan.canonical_path)
        handle_before = _scan_status_identity(_FSTAT(descriptor))
        if not _same_path_and_handle(
            plan.initial_identity,
            handle_before,
        ) or not stat.S_ISREG(handle_before[0]):
            raise _ScanFailure("SCAN_FILE_CHANGED")

        carry = b""
        carry_line = 1
        carry_previous_cr = False
        emitted_through = 0
        first_prefix = b""
        while True:
            request_size = min(
                SCAN_CHUNK_BYTES,
                limits.max_file_bytes + 1 - file_count,
                limits.max_total_bytes + 1 - total_before - file_count,
            )
            if request_size <= 0:
                raise _ScanFailure("SCAN_LIMIT_TOTAL_BYTES")
            chunk = _READ(descriptor, request_size)
            if type(chunk) is not bytes:
                raise _ScanFailure("SCAN_UNREADABLE")
            if not chunk:
                _emit_content_window(
                    window=carry,
                    base_offset=file_count - len(carry),
                    emit_after=emitted_through,
                    emit_through=file_count,
                    base_line=carry_line,
                    base_previous_cr=carry_previous_cr,
                    plan=plan,
                    handle_identity=handle_before,
                    binding=binding,
                    limits=limits,
                    scan_key=scan_key,
                    hits=hits,
                )
                break

            if len(first_prefix) < 4:
                first_prefix += chunk[: 4 - len(first_prefix)]
            if _unsupported_bom(first_prefix):
                raise _ScanFailure("SCAN_UNSUPPORTED_ENCODING")
            file_count += len(chunk)
            if file_count > limits.max_file_bytes:
                raise _ScanFailure("SCAN_LIMIT_FILE_BYTES")
            if total_before + file_count > limits.max_total_bytes:
                raise _ScanFailure("SCAN_LIMIT_TOTAL_BYTES")
            window = carry + chunk
            base_offset = file_count - len(window)
            safe_through = max(0, file_count - _MAX_STREAM_TOKEN_BYTES)
            _emit_content_window(
                window=window,
                base_offset=base_offset,
                emit_after=emitted_through,
                emit_through=safe_through,
                base_line=carry_line,
                base_previous_cr=carry_previous_cr,
                plan=plan,
                handle_identity=handle_before,
                binding=binding,
                limits=limits,
                scan_key=scan_key,
                hits=hits,
            )
            emitted_through = safe_through
            retained = min(SCAN_CARRY_BYTES, len(window))
            removed = len(window) - retained
            carry_line, carry_previous_cr = _advance_line_state(
                window[:removed],
                carry_line,
                carry_previous_cr,
            )
            carry = window[-retained:] if retained else b""

        handle_after = _scan_status_identity(_FSTAT(descriptor))
        if handle_after != handle_before or file_count != handle_after[4]:
            raise _ScanFailure("SCAN_FILE_CHANGED")
    except _ScanFailure as failure:
        failure_code = failure.code
    except Exception:
        failure_code = "SCAN_FILE_CHANGED"
    if descriptor is not None:
        try:
            _CLOSE(descriptor)
        except Exception:
            failure_code = "SCAN_FILE_CHANGED"
    if failure_code is not None:
        raise _ScanFailure(failure_code)
    if handle_before is None or handle_after is None:
        raise _ScanFailure("SCAN_FILE_CHANGED")
    try:
        final_identity = _scan_status_identity(_LSTAT(plan.canonical_path))
    except Exception:
        raise _ScanFailure("SCAN_FILE_CHANGED") from None
    if final_identity != plan.initial_identity or not _same_path_and_handle(
        final_identity,
        handle_after,
    ):
        raise _ScanFailure("SCAN_FILE_CHANGED")
    try:
        plan.canonical_path.relative_to(plan.owner_root)
    except ValueError:
        raise _ScanFailure("SCAN_ROOT_ESCAPE")
    return file_count


class _PrivacyScannerMeta(type):
    """Reject scanner subclass creation before instances can be constructed."""

    def __new__(
        mcls,
        name: str,
        bases: tuple[type, ...],
        namespace: dict[str, object],
        **kwargs: object,
    ) -> _PrivacyScannerMeta:
        if any(isinstance(base, _PrivacyScannerMeta) for base in bases):
            raise TypeError(_FROZEN_ERROR)
        return super().__new__(mcls, name, bases, namespace, **kwargs)


def _transition_initialization_state(
    scanner: object,
    initialization_lock: _thread.LockType,
    expected_state: object,
    replacement_state: object,
) -> None:
    if not initialization_lock.acquire(blocking=False):
        raise TypeError(_FROZEN_ERROR)
    transitioned = False
    try:
        if (
            object.__getattribute__(
                scanner,
                "_PrivacyScanner__initialization_state",
            )
            is expected_state
        ):
            object.__setattr__(
                scanner,
                "_PrivacyScanner__initialization_state",
                replacement_state,
            )
            transitioned = True
    except AttributeError:
        pass
    finally:
        initialization_lock.release()
    if not transitioned:
        raise TypeError(_FROZEN_ERROR)


@final
class PrivacyScanner(_SerializationForbidden, metaclass=_PrivacyScannerMeta):
    """An immutable scanner construction boundary."""

    __slots__ = (
        "__catalog_binding",
        "__generation",
        "__initialization_lock",
        "__initialization_state",
        "__limits",
        "__operation_lock",
        "__profile",
        "__scan_key",
    )

    __catalog_binding: _CatalogBinding
    __generation: _Generation | None
    __initialization_lock: _thread.LockType
    __initialization_state: object
    __limits: ScanLimits
    __operation_lock: _thread.LockType
    __profile: ScanProfile
    __scan_key: bytes

    def __init_subclass__(cls, **kwargs: object) -> NoReturn:
        del cls, kwargs
        raise TypeError(_FROZEN_ERROR)

    def __new__(
        cls,
        *_args: object,
        **_kwargs: object,
    ) -> PrivacyScanner:
        del _args, _kwargs
        if cls is not PrivacyScanner:
            raise TypeError(_FROZEN_ERROR)
        instance = object.__new__(cls)
        object.__setattr__(
            instance,
            "_PrivacyScanner__initialization_lock",
            _thread.allocate_lock(),
        )
        object.__setattr__(
            instance,
            "_PrivacyScanner__initialization_state",
            _INITIALIZATION_RESERVED,
        )
        object.__setattr__(
            instance,
            "_PrivacyScanner__operation_lock",
            _thread.allocate_lock(),
        )
        object.__setattr__(instance, "_PrivacyScanner__generation", None)
        return instance

    def __init__(
        self,
        *,
        profile: ScanProfile,
        canary_definition_path: Path,
        hash_key: bytes | None = None,
        limits: ScanLimits = DEFAULT_SCAN_LIMITS,
    ) -> None:
        if type(self) is not PrivacyScanner:
            raise TypeError(_FROZEN_ERROR)
        lock_candidate: object | None = None
        try:
            lock_candidate = object.__getattribute__(
                self,
                "_PrivacyScanner__initialization_lock",
            )
        except AttributeError:
            pass
        if type(lock_candidate) is not _thread.LockType:
            raise TypeError(_FROZEN_ERROR)
        initialization_lock = lock_candidate
        _transition_initialization_state(
            self,
            initialization_lock,
            _INITIALIZATION_RESERVED,
            _INITIALIZATION_STARTED,
        )

        validated_profile = _validate_profile(profile)
        validated_limits = _validate_limits(limits)
        catalog_binding = _catalog_binding(
            canary_definition_path,
            validated_limits,
        )
        selected_key = _generate_scan_key() if hash_key is None else hash_key
        validated_key = _validate_key(selected_key)
        object.__setattr__(self, "_PrivacyScanner__profile", validated_profile)
        object.__setattr__(self, "_PrivacyScanner__limits", validated_limits)
        object.__setattr__(self, "_PrivacyScanner__scan_key", validated_key)
        object.__setattr__(
            self,
            "_PrivacyScanner__catalog_binding",
            catalog_binding,
        )
        _transition_initialization_state(
            self,
            initialization_lock,
            _INITIALIZATION_STARTED,
            _INITIALIZATION_COMPLETE,
        )

    @classmethod
    def default(
        cls,
        *,
        profile: ScanProfile,
        canary_definition_path: Path,
        hash_key: bytes | None = None,
        limits: ScanLimits = DEFAULT_SCAN_LIMITS,
    ) -> PrivacyScanner:
        if cls is not PrivacyScanner:
            raise PrivacyScanError("SCAN_INPUT_INVALID")
        return cls(
            profile=profile,
            canary_definition_path=canary_definition_path,
            hash_key=hash_key,
            limits=limits,
        )

    def scan_paths(self, paths: Sequence[Path]) -> PrivacyScanOutcome:
        operation_lock: _thread.LockType | None = None
        failure_code: str | None = None
        outcome: PrivacyScanOutcome | None = None
        try:
            operation_lock = _operation_lock_for(self, "SCAN_INPUT_INVALID")
            object.__setattr__(self, "_PrivacyScanner__generation", None)
            limits, _profile, _scan_key, binding = _scanner_runtime_state(self)
            _scan_catalog_check(binding, limits)
            roots = _bounded_raw_roots(paths, limits)
            plans, directory_records, tree_observations = _build_scan_plan(
                roots,
                limits,
                _profile,
                _scan_key,
            )
            hits: list[PrivacyHit] = []
            mapping: dict[str, Path] = {}
            total_bytes = 0
            for plan in plans:
                hits_before = len(hits)
                total_bytes += _scan_file_plan(
                    plan,
                    _profile,
                    binding,
                    limits,
                    _scan_key,
                    total_bytes,
                    hits,
                )
                if len(hits) > hits_before:
                    mapping[plan.location_ref] = plan.canonical_path
            _close_directory_records(
                directory_records,
                limits,
                tree_observations,
            )
            _scan_catalog_check(binding, limits)
            hits.sort(
                key=lambda hit: (
                    hit.location_ref,
                    hit.line_number or 0,
                    hit.rule_id,
                    hit.hit_hash,
                )
            )
            handle = _issue_resolution_handle()
            generation = _Generation(
                handle=handle,
                mapping=MappingProxyType(dict(mapping)),
            )
            report = PrivacyScanReport(hits=tuple(hits))
            outcome = PrivacyScanOutcome(
                report=report,
                resolution_handle=handle,
            )
            object.__setattr__(
                self,
                "_PrivacyScanner__generation",
                generation,
            )
        except _ScanFailure as failure:
            failure_code = failure.code
        except Exception:
            failure_code = "SCAN_INPUT_INVALID"
        finally:
            if operation_lock is not None:
                operation_lock.release()
        if failure_code is not None:
            raise PrivacyScanError(failure_code)
        if outcome is None:
            failure_code = "SCAN_INPUT_INVALID"
            raise PrivacyScanError(failure_code)
        return outcome

    def resolve_location(
        self,
        handle: ScanResolutionHandle,
        location_ref: str,
    ) -> Path:
        operation_lock: _thread.LockType | None = None
        failure_code: str | None = None
        result: Path | None = None
        try:
            operation_lock = _operation_lock_for(
                self,
                "SCAN_LOCATION_UNAVAILABLE",
            )
            generation = object.__getattribute__(
                self,
                "_PrivacyScanner__generation",
            )
            if (
                type(generation) is not _Generation
                or type(handle) is not ScanResolutionHandle
                or handle is not generation.handle
                or type(location_ref) is not str
                or location_ref not in generation.mapping
            ):
                raise _ScanFailure("SCAN_LOCATION_UNAVAILABLE")
            result = generation.mapping[location_ref]
        except _ScanFailure as failure:
            failure_code = failure.code
        except Exception:
            failure_code = "SCAN_LOCATION_UNAVAILABLE"
        finally:
            if operation_lock is not None:
                operation_lock.release()
        if failure_code is not None:
            raise PrivacyScanError(failure_code)
        if not isinstance(result, Path):
            raise PrivacyScanError("SCAN_LOCATION_UNAVAILABLE")
        return result

    def close(self) -> None:
        operation_lock: _thread.LockType | None = None
        failure_code: str | None = None
        try:
            operation_lock = _operation_lock_for(self, "SCAN_INPUT_INVALID")
            object.__setattr__(self, "_PrivacyScanner__generation", None)
        except _ScanFailure as failure:
            failure_code = failure.code
        except Exception:
            failure_code = "SCAN_INPUT_INVALID"
        finally:
            if operation_lock is not None:
                operation_lock.release()
        if failure_code is not None:
            raise PrivacyScanError(failure_code)

    def __setattr__(self, name: str, value: object) -> NoReturn:
        del self, name, value
        raise AttributeError(_FROZEN_ERROR)

    def __delattr__(self, name: str) -> NoReturn:
        del self, name
        raise AttributeError(_FROZEN_ERROR)

    def __repr__(self) -> str:
        return "<PrivacyScanner redacted>"
