"""Shared strict scalar and value-object contracts."""

from __future__ import annotations

import copy
import re
import uuid
from collections.abc import Iterator, Mapping
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal, TypeAlias

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    GetCoreSchemaHandler,
    GetJsonSchemaHandler,
    StringConstraints,
    field_serializer,
)
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema, core_schema
from typing_extensions import Self


_CLIENT_ID_RE = re.compile(r"client_[a-z0-9]{12}")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_CONTROL_OR_LINE_SEPARATOR_RE = re.compile(r"[\x00-\x1f\x7f\u2028\u2029]")
_LOWER_SNAKE_RE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_JSON_LINE_SEPARATOR_PATTERN = r"[\r\n\u2028\u2029]"
_FROZEN_STRIP_WHITESPACE_CHARS = frozenset(
    "\t\n\v\f\r\x1c\x1d\x1e\x1f \x85\xa0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)
_FROZEN_STRIP_WHITESPACE_JSON_CLASS = (
    r"[\x09-\x0d\x1c-\x20\u0085\u00a0\u1680\u2000-\u200a"
    r"\u2028\u2029\u202f\u205f\u3000]"
)
_FROZEN_BLANK_JSON_PATTERN = rf"^{_FROZEN_STRIP_WHITESPACE_JSON_CLASS}+$"
_CLIENT_ID_JSON_PATTERN = r"^client_[a-z0-9]{12}$"
_OBJECT_ID_JSON_PATTERN = (
    r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*_"
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_SAFE_POLICY_KEY_JSON_PATTERN = r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$"
_SAFE_LOCATOR_TEXT_JSON_PATTERN = r"^[^\x00-\x1f\x7f]+$"
_SAFE_DETAIL_STRING_PATTERN = r"^[^\x00-\x1f\x7f]*$"
_FORBIDDEN_SAFE_DETAIL_KEY_PATTERN = (
    r"(?:^|_)(?:body|client|content|directory|existence|exists|file|filename|"
    r"filepath|found|path|subject|transcript)(?:_|$)"
)
_SAFE_DETAIL_PATH_PATTERN = r"[\\/]"
_SAFE_DETAIL_TRAVERSAL_PATTERN = r"\.\."
_ASCII_NONWORD_PATTERN = r"[^A-Za-z0-9_]"
_ASCII_LEFT_TOKEN_BOUNDARY = rf"(?:^|{_ASCII_NONWORD_PATTERN})"
_ASCII_RIGHT_TOKEN_BOUNDARY = rf"(?:$|{_ASCII_NONWORD_PATTERN})"
_PORTABLE_ANY_CHARACTER_PATTERN = r"(?:.|\r|\n|\u2028|\u2029)"


def _ascii_case_insensitive(value: str) -> str:
    return "".join(
        f"[{char}{char.upper()}]" if "a" <= char <= "z" else re.escape(char)
        for char in value
    )


_BODY_PREFIX_PATTERN = "|".join(
    _ascii_case_insensitive(value)
    for value in ("full", "raw", "consultation", "session")
)
_BODY_NOUN_PATTERN = "|".join(
    _ascii_case_insensitive(value) for value in ("body", "content", "transcript")
)
_BODY_PATTERN = (
    rf"{_ASCII_LEFT_TOKEN_BOUNDARY}"
    rf"(?:(?:{_BODY_PREFIX_PATTERN}){_FROZEN_STRIP_WHITESPACE_JSON_CLASS}+)+"
    rf"(?:{_BODY_NOUN_PATTERN}){_ASCII_RIGHT_TOKEN_BOUNDARY}"
)
_EXISTENCE_SUBJECT_PATTERN = "|".join(
    _ascii_case_insensitive(value) for value in ("object", "case", "resource")
)
_EXISTENCE_VERB_PATTERN = "|".join(
    (
        _ascii_case_insensitive("exists"),
        rf"{_ascii_case_insensitive('does')}{_FROZEN_STRIP_WHITESPACE_JSON_CLASS}+"
        rf"{_ascii_case_insensitive('not')}{_FROZEN_STRIP_WHITESPACE_JSON_CLASS}+"
        rf"{_ascii_case_insensitive('exist')}",
        rf"{_ascii_case_insensitive('not')}{_FROZEN_STRIP_WHITESPACE_JSON_CLASS}+"
        rf"{_ascii_case_insensitive('found')}",
        _ascii_case_insensitive("found"),
        _ascii_case_insensitive("unauthorized"),
        _ascii_case_insensitive("forbidden"),
    )
)
_EXISTENCE_GAP_PATTERN = (
    rf"(?:{_ASCII_NONWORD_PATTERN}|{_ASCII_NONWORD_PATTERN}"
    rf"{_PORTABLE_ANY_CHARACTER_PATTERN}{{0,46}}{_ASCII_NONWORD_PATTERN})"
)
_EXISTENCE_PATTERN = (
    rf"{_ASCII_LEFT_TOKEN_BOUNDARY}(?:{_EXISTENCE_SUBJECT_PATTERN})"
    rf"{_EXISTENCE_GAP_PATTERN}(?:{_EXISTENCE_VERB_PATTERN})"
    rf"{_ASCII_RIGHT_TOKEN_BOUNDARY}"
)
_BODY_RE = re.compile(_BODY_PATTERN)
_EXISTENCE_RE = re.compile(_EXISTENCE_PATTERN)
_FORBIDDEN_SAFE_DETAIL_KEY_TOKENS = frozenset(
    {
        "body",
        "client",
        "content",
        "directory",
        "existence",
        "exists",
        "file",
        "filename",
        "filepath",
        "found",
        "path",
        "subject",
        "transcript",
    }
)


def require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must use UTC offset +00:00")
    return value.astimezone(timezone.utc)


def _require_nonblank(value: str) -> str:
    if not value or all(char in _FROZEN_STRIP_WHITESPACE_CHARS for char in value):
        raise ValueError("string must not be blank")
    return value


def _require_safe_locator_text(value: str) -> str:
    if _CONTROL_OR_LINE_SEPARATOR_RE.search(value):
        raise ValueError("locator text must not contain control or line-separator characters")
    return _require_nonblank(value)


def _require_uuid7(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError("identifier must be a canonical UUIDv7 string") from exc
    if str(parsed) != value or parsed.version != 7 or parsed.variant != uuid.RFC_4122:
        raise ValueError("identifier must be a canonical lowercase RFC 9562 UUIDv7 string")
    return value


def _require_object_id(value: str) -> str:
    if len(value) < 38 or value[-37] != "_":
        raise ValueError("object identifier must be <kind>_<uuidv7>")
    kind = value[:-37]
    suffix = value[-36:]
    if not 1 <= len(kind) <= 64:
        raise ValueError("object kind length must be between 1 and 64")
    if _LOWER_SNAKE_RE.fullmatch(kind) is None:
        raise ValueError("object kind must use canonical lower-snake form")
    if _CLIENT_ID_RE.search(kind):
        raise ValueError("object kind must not contain a client identifier")
    _require_uuid7(suffix)
    return value


def _require_safe_policy_key(value: str) -> str:
    if not 1 <= len(value) <= 64:
        raise ValueError("safe policy key length must be between 1 and 64")
    if _LOWER_SNAKE_RE.fullmatch(value) is None:
        raise ValueError("safe policy key must use canonical lower-snake form")
    if _CLIENT_ID_RE.search(value):
        raise ValueError("safe policy key must not contain a client identifier")
    return value


UtcDateTime: TypeAlias = Annotated[
    datetime,
    AfterValidator(require_utc),
    Field(json_schema_extra={"x-utc-only": True}),
]
NonEmptyStr: TypeAlias = Annotated[
    str,
    StringConstraints(strict=True, min_length=1),
    Field(json_schema_extra={"not": {"pattern": _FROZEN_BLANK_JSON_PATTERN}}),
    AfterValidator(_require_nonblank),
]
Sha256Hex: TypeAlias = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
]
ClientId: TypeAlias = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=19,
        max_length=19,
        pattern=r"^client_[a-z0-9]{12}$",
    ),
    Field(
        json_schema_extra={
            "pattern": _CLIENT_ID_JSON_PATTERN,
            "not": {"pattern": _JSON_LINE_SEPARATOR_PATTERN},
        }
    ),
]
Uuid7String: TypeAlias = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=36,
        max_length=36,
        pattern=(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        ),
    ),
    AfterValidator(_require_uuid7),
]
ObjectId: TypeAlias = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=38,
        max_length=101,
        pattern=(
            r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*_"
            r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        ),
    ),
    Field(
        json_schema_extra={
            "pattern": _OBJECT_ID_JSON_PATTERN,
            "not": {
                "anyOf": [
                    {"pattern": r"client_[a-z0-9]{12}"},
                    {"pattern": _JSON_LINE_SEPARATOR_PATTERN},
                ]
            },
        }
    ),
    AfterValidator(_require_object_id),
]
SafePolicyKey: TypeAlias = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$",
    ),
    Field(
        json_schema_extra={
            "pattern": _SAFE_POLICY_KEY_JSON_PATTERN,
            "not": {
                "anyOf": [
                    {"pattern": r"client_[a-z0-9]{12}"},
                    {"pattern": _JSON_LINE_SEPARATOR_PATTERN},
                ]
            },
        }
    ),
    AfterValidator(_require_safe_policy_key),
]
SafeLocatorText: TypeAlias = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=512,
        pattern=r"^[^\x00-\x1f\x7f]+$",
    ),
    Field(
        json_schema_extra={
            "pattern": _SAFE_LOCATOR_TEXT_JSON_PATTERN,
            "not": {
                "anyOf": [
                    {"pattern": _JSON_LINE_SEPARATOR_PATTERN},
                    {"pattern": _FROZEN_BLANK_JSON_PATTERN},
                ]
            },
        }
    ),
    AfterValidator(_require_safe_locator_text),
]
PositiveInt: TypeAlias = Annotated[int, Field(strict=True, gt=0)]
NonNegativeInt: TypeAlias = Annotated[int, Field(strict=True, ge=0)]
FiniteFloat: TypeAlias = Annotated[float, Field(strict=True, allow_inf_nan=False)]

SafeDetailScalar: TypeAlias = str | int | bool


class FrozenSafeDetails(Mapping[str, SafeDetailScalar]):
    """Copied immutable scalar mapping with mechanical sensitive-canary checks.

    This type cannot prove arbitrary prose semantically safe. Client-visible
    emission must still pass through the controlled factory in ``core.errors``.
    """

    __slots__ = ("_items",)
    _items: tuple[tuple[str, SafeDetailScalar], ...]

    def __init__(self, values: Mapping[str, SafeDetailScalar]) -> None:
        checked: dict[str, SafeDetailScalar] = {}
        for key, value in values.items():
            if type(key) is not str:
                raise ValueError("safe detail keys must be exact strings")
            if type(value) not in (str, int, bool):
                raise ValueError("safe detail values must be str, int, or bool scalars")
            if _LOWER_SNAKE_RE.fullmatch(key) is None:
                raise ValueError("safe detail keys must use canonical lower-snake form")
            key_tokens = frozenset(key.split("_"))
            if key_tokens & _FORBIDDEN_SAFE_DETAIL_KEY_TOKENS:
                raise ValueError("safe detail key is not permitted at the structural boundary")
            if type(value) is str:
                if _CONTROL_OR_LINE_SEPARATOR_RE.search(value):
                    raise ValueError("safe detail strings must not contain control characters")
                if _CLIENT_ID_RE.search(value):
                    raise ValueError("safe details must not contain a client identifier")
                if "/" in value or "\\" in value or ".." in value:
                    raise ValueError("safe details must not contain a path or traversal")
                if _BODY_RE.search(value):
                    raise ValueError("safe details must not contain an obvious content body")
                if _EXISTENCE_RE.search(value):
                    raise ValueError("safe details must not expose object existence")
            checked[key] = value
        object.__setattr__(self, "_items", tuple(sorted(checked.items())))

    def __setattr__(self, name: str, value: Any) -> None:
        del name, value
        raise TypeError("FrozenSafeDetails attributes are immutable")

    def __delattr__(self, name: str) -> None:
        del name
        raise TypeError("FrozenSafeDetails attributes are immutable")

    def __getitem__(self, key: str) -> SafeDetailScalar:
        for candidate, value in self._items:
            if candidate == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (key for key, _ in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return f"FrozenSafeDetails({dict(self._items)!r})"

    def __copy__(self) -> "FrozenSafeDetails":
        return type(self)(dict(self._items))

    def __deepcopy__(self, memo: dict[int, Any]) -> "FrozenSafeDetails":
        copied = type(self)(dict(self._items))
        memo[id(self)] = copied
        return copied

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source_type: Any,
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        del source_type, handler
        scalar_schema = core_schema.union_schema(
            [
                core_schema.str_schema(strict=True),
                core_schema.int_schema(strict=True),
                core_schema.bool_schema(strict=True),
            ]
        )
        mapping_schema = core_schema.dict_schema(
            keys_schema=core_schema.str_schema(strict=True),
            values_schema=scalar_schema,
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
        rendered["title"] = "FrozenSafeDetails"
        rendered["propertyNames"] = {
            "pattern": _SAFE_POLICY_KEY_JSON_PATTERN,
            "not": {
                "anyOf": [
                    {"pattern": _CONTROL_RE.pattern},
                    {"pattern": _JSON_LINE_SEPARATOR_PATTERN},
                    {"pattern": _FORBIDDEN_SAFE_DETAIL_KEY_PATTERN},
                ]
            },
        }
        additional_properties = rendered.get("additionalProperties")
        if not isinstance(additional_properties, dict):
            raise TypeError("FrozenSafeDetails Schema must expose scalar branches")
        scalar_branches = additional_properties.get("anyOf")
        if not isinstance(scalar_branches, list):
            raise TypeError("FrozenSafeDetails Schema must expose an anyOf scalar union")
        string_branch = next(
            (
                branch
                for branch in scalar_branches
                if isinstance(branch, dict) and branch.get("type") == "string"
            ),
            None,
        )
        if string_branch is None:
            raise TypeError("FrozenSafeDetails Schema must contain a string branch")
        string_branch["pattern"] = _SAFE_DETAIL_STRING_PATTERN
        string_branch["not"] = {
            "anyOf": [
                {"pattern": _CONTROL_RE.pattern},
                {"pattern": _JSON_LINE_SEPARATOR_PATTERN},
                {"pattern": _CLIENT_ID_RE.pattern},
                {"pattern": _SAFE_DETAIL_PATH_PATTERN},
                {"pattern": _SAFE_DETAIL_TRAVERSAL_PATTERN},
                {"pattern": _BODY_PATTERN},
                {"pattern": _EXISTENCE_PATTERN},
            ]
        }
        return rendered


EMPTY_SAFE_DETAILS = FrozenSafeDetails({})


class StrictModel(BaseModel):
    """Immutable domain base with validated copies and nested revalidation.

    ``model_construct`` remains Pydantic's explicit trusted-internal escape
    hatch. Normal construction, validation, and ``model_copy`` fail closed.
    """

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_default=True,
        revalidate_instances="always",
    )

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        """Return a replacement reconstructed through full validation."""

        values = copy.deepcopy(self.__dict__) if deep else dict(self.__dict__)
        if update is not None:
            values.update(update)
        validated = self.__class__.model_validate(values)
        fields_set = set(self.__pydantic_fields_set__)
        if update is not None:
            fields_set.update(update)
        object.__setattr__(validated, "__pydantic_fields_set__", fields_set)
        return validated


class VersionRef(StrictModel):
    object_id: ObjectId
    version: PositiveInt
    content_sha256: Sha256Hex


Permission = Literal[
    "client_read",
    "session_append",
    "draft_write",
    "formal_write",
]


class SessionScope(StrictModel):
    session_handle: NonEmptyStr
    session_id: Uuid7String
    permissions: frozenset[Permission]
    expires_at: UtcDateTime

    @field_serializer("permissions")
    def _serialize_permissions(self, value: frozenset[Permission]) -> list[str]:
        return sorted(value)
