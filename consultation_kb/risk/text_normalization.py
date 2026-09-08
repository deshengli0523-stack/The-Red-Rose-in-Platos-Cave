"""Shared body-free normalization for private risk text fingerprints."""

from __future__ import annotations

import hashlib
import unicodedata


def normalize_sensitive_text(value: str) -> str:
    """Return the separator-insensitive form used only for privacy matching."""

    if type(value) is not str:
        raise TypeError("sensitive text must be a string")
    normalized = unicodedata.normalize("NFKD", value).casefold()
    return "".join(
        char
        for char in normalized
        if not unicodedata.category(char).startswith(("C", "M", "P", "Z"))
        and not char.isspace()
    )


def normalized_sensitive_fingerprint(value: str) -> tuple[int, str]:
    """Return only normalized character length and SHA-256, never the body."""

    normalized = normalize_sensitive_text(value)
    if not normalized:
        raise ValueError("sensitive text must retain searchable characters")
    return len(normalized), hashlib.sha256(normalized.encode("utf-8")).hexdigest()


__all__ = ["normalize_sensitive_text", "normalized_sensitive_fingerprint"]
