"""Injectable UTC clocks used by consultation contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol


def _require_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock value must be timezone-aware UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError("clock value must use UTC offset +00:00")
    return value


class Clock(Protocol):
    """Minimal clock interface for deterministic domain operations."""

    def now(self) -> datetime:
        """Return the current aware UTC datetime."""


class SystemClock:
    """Production wall clock."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


@dataclass(frozen=True)
class FixedClock:
    """Clock pinned to one already-UTC instant for deterministic tests."""

    value: datetime

    def __post_init__(self) -> None:
        _require_utc(self.value)

    def now(self) -> datetime:
        return self.value
