"""Service-generated opaque client identifiers."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from typing import final


_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def _secure_suffix() -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(12))


@final
class ClientIdFactory:
    def __init__(self, *, suffix_source: Callable[[], str] | None = None) -> None:
        self._suffix_source = _secure_suffix if suffix_source is None else suffix_source

    def new(self) -> str:
        try:
            suffix = self._suffix_source()
        except Exception:
            raise ValueError("CLIENT_ID_GENERATION_FAILED") from None
        if (
            type(suffix) is not str
            or len(suffix) != 12
            or any(character not in _ALPHABET for character in suffix)
        ):
            raise ValueError("CLIENT_ID_GENERATION_FAILED")
        return f"client_{suffix}"
