"""Append-only audit records that structurally cannot contain content bodies."""

from __future__ import annotations

import copy
import importlib
import json
import os
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Final, Literal, TypeAlias, TypeVar, cast

from pydantic import (
    Field,
    GetCoreSchemaHandler,
    GetJsonSchemaHandler,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema, core_schema

from consultation_kb.models.common import (
    ObjectId,
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    Uuid7String,
    VersionRef,
)


_MAX_JSONL_RECORD_BYTES = 1_048_576
_ModelT = TypeVar("_ModelT", bound=StrictModel)
_LOCAL_LOCKS_GUARD = threading.Lock()
_LOCAL_LOCKS: dict[str, threading.RLock] = {}

AuditEventType: TypeAlias = Literal[
    "approval_executed",
    "approval_issued",
    "archive_completed",
    "case_contribution_created",
    "client_snapshot_updated",
    "deletion_completed",
    "doctor_completed",
    "evaluation_completed",
    "generation_completed",
    "p0_vertical_slice",
    "privacy_scan_completed",
    "rebuild_completed",
    "recovery_completed",
    "retrieval_completed",
    "risk_observed",
    "run_completed",
    "run_started",
    "scope_denied",
    "write_committed",
    "write_rejected",
]
AuditErrorCode: TypeAlias = Literal[
    "APPROVAL_REJECTED",
    "ARCHIVE_REJECTED",
    "CONFIGURATION_FAILED",
    "CRITIQUE_RETRY",
    "INSUFFICIENT_EVIDENCE",
    "POLICY_REJECTED",
    "PRIVACY_SCAN_FAILED",
    "RECOVERY_REQUIRED",
    "RERANKER_UNAVAILABLE",
    "SCHEMA_DRIFT",
    "SCOPE_DENIED",
    "TRANSACTION_FAILED",
    "UNRESOLVED_CONFLICT",
    "WRITE_REJECTED",
]
AuditCountName: TypeAlias = Literal[
    "after",
    "allowed",
    "attempted",
    "before",
    "candidates",
    "cases",
    "claims",
    "created",
    "deleted",
    "denied",
    "doctor_checks",
    "errors",
    "evidence",
    "facts",
    "failed",
    "filtered",
    "hits",
    "objects",
    "passages",
    "policies",
    "privacy_hits",
    "records",
    "rejected",
    "relations",
    "retries",
    "schema_count",
    "scope_denied",
    "selected",
    "sources",
    "succeeded",
    "updated",
    "versions",
    "warnings",
    "writes",
]
_AUDIT_COUNT_NAMES: Final[frozenset[str]] = frozenset(
    {
        "after",
        "allowed",
        "attempted",
        "before",
        "candidates",
        "cases",
        "claims",
        "created",
        "deleted",
        "denied",
        "doctor_checks",
        "errors",
        "evidence",
        "facts",
        "failed",
        "filtered",
        "hits",
        "objects",
        "passages",
        "policies",
        "privacy_hits",
        "records",
        "rejected",
        "relations",
        "retries",
        "schema_count",
        "scope_denied",
        "selected",
        "sources",
        "succeeded",
        "updated",
        "versions",
        "warnings",
        "writes",
    }
)


class ObservabilityStoreError(RuntimeError):
    """Stable no-path error boundary for observability storage failures."""


class ObservabilityCorruptionError(ObservabilityStoreError):
    """Raised when an existing append-only stream is not canonical JSONL."""


class FrozenCounts(Mapping[AuditCountName, int]):
    """Copied, immutable and key-sorted non-negative aggregate counts."""

    __slots__ = ("_items",)
    _items: tuple[tuple[AuditCountName, int], ...]

    def __init__(self, values: Mapping[str, int]) -> None:
        checked: dict[AuditCountName, int] = {}
        for key, value in values.items():
            if type(key) is not str:
                raise ValueError("count keys must be exact strings")
            if key not in _AUDIT_COUNT_NAMES:
                raise ValueError("count key is not in the audit count registry")
            if type(value) is not int or value < 0:
                raise ValueError("counts must be exact non-negative integers")
            checked[cast(AuditCountName, key)] = value
        object.__setattr__(self, "_items", tuple(sorted(checked.items())))

    def __setattr__(self, name: str, value: Any) -> None:
        del name, value
        raise TypeError("FrozenCounts is immutable")

    def __delattr__(self, name: str) -> None:
        del name
        raise TypeError("FrozenCounts is immutable")

    def __getitem__(self, key: AuditCountName) -> int:
        for candidate, value in self._items:
            if candidate == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[AuditCountName]:
        return (key for key, _ in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return f"FrozenCounts({dict(self._items)!r})"

    def __copy__(self) -> "FrozenCounts":
        return type(self)(dict(self._items))

    def __deepcopy__(self, memo: dict[int, Any]) -> "FrozenCounts":
        copied = type(self)(copy.deepcopy(dict(self._items), memo))
        memo[id(self)] = copied
        return copied

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source_type: Any,
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        del source_type, handler
        mapping_schema = core_schema.dict_schema(
            keys_schema=core_schema.literal_schema(sorted(_AUDIT_COUNT_NAMES)),
            values_schema=core_schema.int_schema(strict=True, ge=0),
            strict=True,
        )
        validated_mapping = core_schema.no_info_after_validator_function(
            cls,
            mapping_schema,
        )

        def mapping_to_dict(value: Any) -> Any:
            if isinstance(value, Mapping):
                return dict(value)
            return value

        python_mapping = core_schema.no_info_before_validator_function(
            mapping_to_dict,
            validated_mapping,
        )
        return core_schema.json_or_python_schema(
            json_schema=validated_mapping,
            python_schema=python_mapping,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda value: dict(value.items()),
                return_schema=mapping_schema,
                when_used="always",
            ),
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        rendered = handler(schema)
        rendered["title"] = "FrozenCounts"
        rendered["propertyNames"] = {"enum": sorted(_AUDIT_COUNT_NAMES)}
        rendered["additionalProperties"] = {"type": "integer", "minimum": 0}
        return rendered


class AuditEventV1(StrictModel):
    """Fixed no-body audit shape; unknown fields are rejected by construction."""

    schema_version: Literal["1.0"] = "1.0"
    event_id: ObjectId
    run_id: Uuid7String
    event_type: AuditEventType
    occurred_at: UtcDateTime
    scope_sha256: Sha256Hex
    object_ids: tuple[ObjectId, ...] = ()
    versions: tuple[VersionRef, ...] = ()
    counts: FrozenCounts = Field(default_factory=lambda: FrozenCounts({}))
    error_codes: tuple[AuditErrorCode, ...] = ()
    result_sha256: Sha256Hex | None = None

    @field_validator("object_ids")
    @classmethod
    def _canonical_object_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("audit object IDs must be unique")
        return tuple(sorted(value))

    @field_validator("versions")
    @classmethod
    def _canonical_versions(
        cls,
        value: tuple[VersionRef, ...],
    ) -> tuple[VersionRef, ...]:
        closure: dict[tuple[str, int], str] = {}
        for item in value:
            key = (item.object_id, item.version)
            existing_hash = closure.get(key)
            if existing_hash is not None:
                if existing_hash != item.content_sha256:
                    raise ValueError(
                        "audit version closure contains conflicting content hashes"
                    )
                raise ValueError("audit versions must be unique")
            closure[key] = item.content_sha256
        return tuple(
            sorted(
                value,
                key=lambda item: (
                    item.object_id,
                    item.version,
                    item.content_sha256,
                ),
            )
        )

    @field_validator("error_codes")
    @classmethod
    def _canonical_error_codes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("audit error codes must be unique")
        return tuple(sorted(value))

    @field_serializer("counts")
    def _serialize_counts(self, value: FrozenCounts) -> dict[str, int]:
        return dict(value.items())


AuditEvent: TypeAlias = AuditEventV1


class AuditEventV2(StrictModel):
    """Lineage-aware no-body event; V1 remains the public compatibility alias."""

    schema_version: Literal["2.0"] = "2.0"
    event_id: ObjectId
    run_id: Uuid7String
    event_type: AuditEventType
    occurred_at: UtcDateTime
    scope_sha256: Sha256Hex
    object_ids: tuple[ObjectId, ...] = ()
    versions: tuple[VersionRef, ...] = ()
    counts: FrozenCounts = Field(default_factory=lambda: FrozenCounts({}))
    error_codes: tuple[AuditErrorCode, ...] = ()
    result_sha256: Sha256Hex | None = None
    root_run_id: Uuid7String
    parent_run_id: Uuid7String | None
    governed_refs: tuple[VersionRef, ...] = ()

    @field_validator("object_ids")
    @classmethod
    def _canonical_object_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("audit object IDs must be unique")
        return tuple(sorted(value))

    @field_validator("versions", "governed_refs")
    @classmethod
    def _canonical_version_groups(
        cls,
        value: tuple[VersionRef, ...],
    ) -> tuple[VersionRef, ...]:
        closure: dict[tuple[str, int], str] = {}
        for item in value:
            key = (item.object_id, item.version)
            existing_hash = closure.get(key)
            if existing_hash is not None:
                if existing_hash != item.content_sha256:
                    raise ValueError(
                        "audit reference closure contains conflicting content hashes"
                    )
                raise ValueError("audit references must be unique")
            closure[key] = item.content_sha256
        return tuple(
            sorted(
                value,
                key=lambda item: (
                    item.object_id,
                    item.version,
                    item.content_sha256,
                ),
            )
        )

    @field_validator("error_codes")
    @classmethod
    def _canonical_error_codes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("audit error codes must be unique")
        return tuple(sorted(value))

    @field_serializer("counts")
    def _serialize_counts(self, value: FrozenCounts) -> dict[str, int]:
        return dict(value.items())

    @model_validator(mode="after")
    def _validate_lineage(self) -> "AuditEventV2":
        if self.parent_run_id is None:
            if self.root_run_id != self.run_id:
                raise ValueError("root audit event must identify its run as root")
        elif self.parent_run_id == self.run_id:
            raise ValueError("child audit event must identify a distinct direct parent")
        closure: dict[tuple[str, int], str] = {}
        for reference in (*self.versions, *self.governed_refs):
            key = (reference.object_id, reference.version)
            previous = closure.setdefault(key, reference.content_sha256)
            if previous != reference.content_sha256:
                raise ValueError("audit event contains a conflicting exact version")
        return self


AuditRecord: TypeAlias = AuditEventV1 | AuditEventV2
_AUDIT_EVENT_MODELS: Final[Mapping[str, type[StrictModel]]] = {
    "1.0": AuditEventV1,
    "2.0": AuditEventV2,
}


def _canonical_json_line(model: StrictModel) -> bytes:
    payload = model.model_dump(mode="json")
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    if len(encoded) > _MAX_JSONL_RECORD_BYTES:
        raise ObservabilityStoreError("observability record exceeds the size limit")
    return encoded + b"\n"


def _append_line(path: Path, line: bytes) -> None:
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            written = os.write(descriptor, line)
            if written != len(line):
                raise OSError("short append")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise ObservabilityStoreError("observability store append failed") from None


def _local_lock(path: Path) -> threading.RLock:
    key = os.path.normcase(os.path.abspath(os.fspath(path)))
    with _LOCAL_LOCKS_GUARD:
        lock = _LOCAL_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _LOCAL_LOCKS[key] = lock
        return lock


def _lock_descriptor(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        return
    fcntl_module = importlib.import_module("fcntl")
    flock = cast(Callable[[int, int], None], getattr(fcntl_module, "flock"))
    flock(descriptor, int(getattr(fcntl_module, "LOCK_EX")))


def _unlock_descriptor(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        return
    fcntl_module = importlib.import_module("fcntl")
    flock = cast(Callable[[int, int], None], getattr(fcntl_module, "flock"))
    flock(descriptor, int(getattr(fcntl_module, "LOCK_UN")))


@contextmanager
def _exclusive_store_lock(path: Path) -> Iterator[None]:
    """Serialize one stream across threads and cooperating local processes."""

    lock_path = path.with_name(f"{path.name}.lock")
    with _local_lock(path):
        descriptor: int | None = None
        locked = False
        try:
            flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_BINARY", 0)
            descriptor = os.open(lock_path, flags, 0o600)
            if os.fstat(descriptor).st_size == 0:
                if os.write(descriptor, b"\0") != 1:
                    raise OSError("short lock initialization")
                os.fsync(descriptor)
            _lock_descriptor(descriptor)
            locked = True
        except OSError:
            if descriptor is not None:
                os.close(descriptor)
            raise ObservabilityStoreError("observability store lock failed") from None
        try:
            yield
        finally:
            if descriptor is not None:
                if locked:
                    try:
                        _unlock_descriptor(descriptor)
                    except OSError:
                        pass
                os.close(descriptor)


def _load_records(
    path: Path,
    model_types: Mapping[str, type[_ModelT]],
) -> tuple[_ModelT, ...]:
    records: list[_ModelT] = []
    try:
        if not path.exists():
            return ()
        with path.open("rb") as stream:
            while line := stream.readline(_MAX_JSONL_RECORD_BYTES + 2):
                if (
                    len(line) > _MAX_JSONL_RECORD_BYTES + 1
                    or not line.endswith(b"\n")
                    or line == b"\n"
                    or b"\r" in line
                ):
                    raise ObservabilityCorruptionError(
                        "observability JSONL record is malformed"
                    )
                raw_record = line[:-1]
                raw_value = json.loads(raw_record)
                if type(raw_value) is not dict:
                    raise ObservabilityCorruptionError(
                        "observability JSONL record is not an object"
                    )
                schema_version = raw_value.get("schema_version")
                if type(schema_version) is not str:
                    raise ObservabilityCorruptionError(
                        "observability JSONL record has no schema version"
                    )
                model_type = model_types.get(schema_version)
                if model_type is None:
                    raise ObservabilityCorruptionError(
                        "observability JSONL schema version is unsupported"
                    )
                record = model_type.model_validate_json(raw_record)
                if _canonical_json_line(record) != line:
                    raise ObservabilityCorruptionError(
                        "observability JSONL record is not canonical"
                    )
                records.append(record)
    except ObservabilityStoreError:
        raise
    except (OSError, UnicodeError, ValueError):
        raise ObservabilityCorruptionError(
            "observability JSONL stream is unreadable"
        ) from None
    return tuple(records)


class AuditSink:
    """Append and strictly reload canonical :class:`AuditEvent` records."""

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise TypeError("audit path must be pathlib.Path")
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    def emit(self, event: AuditRecord) -> None:
        if isinstance(event, AuditEventV2):
            validated: AuditRecord = AuditEventV2.model_validate(event)
        else:
            validated = AuditEventV1.model_validate(event)
        with _exclusive_store_lock(self._path):
            existing = self._load_unlocked()
            if any(item.event_id == validated.event_id for item in existing):
                raise ObservabilityStoreError("audit event ID is already present")
            _append_line(self._path, _canonical_json_line(validated))

    def load(self) -> tuple[AuditRecord, ...]:
        with _exclusive_store_lock(self._path):
            return self._load_unlocked()

    def _load_unlocked(self) -> tuple[AuditRecord, ...]:
        loaded = _load_records(self._path, _AUDIT_EVENT_MODELS)
        records = cast(tuple[AuditRecord, ...], loaded)
        event_ids = tuple(record.event_id for record in records)
        if len(event_ids) != len(set(event_ids)):
            raise ObservabilityCorruptionError(
                "audit stream contains a duplicate event ID"
            )
        return records
