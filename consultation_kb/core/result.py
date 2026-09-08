"""Internal exactly-one-of result value."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

from .errors import ToolError


T = TypeVar("T")


@dataclass(frozen=True)
class Result(Generic[T]):
    value: T | None = None
    error: ToolError | None = None

    def __post_init__(self) -> None:
        if (self.value is None) == (self.error is None):
            raise ValueError("result requires exactly one of value or error")

    @classmethod
    def ok(cls, value: T) -> "Result[T]":
        return cls(value=value)

    @classmethod
    def fail(cls, error: ToolError) -> "Result[T]":
        return cls(error=error)
