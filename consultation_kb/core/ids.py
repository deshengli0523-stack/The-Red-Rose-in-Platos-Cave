"""RFC 9562 UUIDv7 identifiers with injectable clock and randomness."""

from __future__ import annotations

import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable

from .clock import Clock, SystemClock


_MAX_RANDOM_74 = 1 << 74
_MAX_TIMESTAMP_48 = 1 << 48
_OBJECT_KIND_RE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z")
_CLIENT_ID_RE = re.compile(r"client_[a-z0-9]{12}")
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _secure_random_74() -> int:
    return secrets.randbits(74)


def _unix_milliseconds(value: datetime) -> int:
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None or offset != timedelta(0):
        raise ValueError("UUIDv7 clock must return timezone-aware UTC")
    delta = value - _UNIX_EPOCH
    milliseconds = (
        delta.days * 86_400_000
        + delta.seconds * 1_000
        + delta.microseconds // 1_000
    )
    if not 0 <= milliseconds < _MAX_TIMESTAMP_48:
        raise ValueError("UUIDv7 timestamp must fit in unsigned 48-bit milliseconds")
    return milliseconds


class IdFactory:
    """Construct canonical UUIDv7 and object identifiers."""

    def __init__(
        self,
        clock: Clock | None = None,
        random_source: Callable[[], int] | None = None,
    ) -> None:
        self._clock = clock if clock is not None else SystemClock()
        self._random_source = (
            random_source if random_source is not None else _secure_random_74
        )

    def uuid7(self) -> str:
        timestamp_ms = _unix_milliseconds(self._clock.now())
        randomness = self._random_source()
        if type(randomness) is not int:
            raise TypeError("UUIDv7 randomness must be an exact int")
        if not 0 <= randomness < _MAX_RANDOM_74:
            raise ValueError("UUIDv7 randomness must fit in unsigned 74 bits")

        rand_a = randomness >> 62
        rand_b = randomness & ((1 << 62) - 1)
        bits = (
            (timestamp_ms << 80)
            | (0x7 << 76)
            | (rand_a << 64)
            | (0b10 << 62)
            | rand_b
        )
        return str(uuid.UUID(int=bits))

    def object_id(self, kind: str) -> str:
        if type(kind) is not str:
            raise TypeError("object kind must be an exact string")
        if not 1 <= len(kind) <= 64:
            raise ValueError("object kind length must be between 1 and 64")
        if _OBJECT_KIND_RE.fullmatch(kind) is None:
            raise ValueError("object kind must use canonical lower-snake form")
        if _CLIENT_ID_RE.search(kind):
            raise ValueError("object kind must not contain a client identifier")
        return f"{kind}_{self.uuid7()}"

    def new(self, prefix: str) -> str:
        """Compatibility spelling for the frozen IdFactory protocol."""

        return self.object_id(prefix)
