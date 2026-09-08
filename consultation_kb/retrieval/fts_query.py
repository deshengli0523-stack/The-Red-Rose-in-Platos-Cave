"""Injection-safe FTS5 query grammar builder."""

from __future__ import annotations

import unicodedata
from collections.abc import Sequence


class FtsQueryError(ValueError):
    def __init__(self) -> None:
        super().__init__("FTS_QUERY_INVALID")


class FtsQueryBuilder:
    def __init__(self, *, max_tokens: int = 128, max_token_characters: int = 128) -> None:
        if type(max_tokens) is not int or not 1 <= max_tokens <= 1024:
            raise ValueError("FTS_QUERY_LIMIT_INVALID")
        if type(max_token_characters) is not int or not 1 <= max_token_characters <= 512:
            raise ValueError("FTS_QUERY_LIMIT_INVALID")
        self._max_tokens = max_tokens
        self._max_token_characters = max_token_characters

    def build(self, groups: Sequence[Sequence[str]]) -> str:
        if not groups or isinstance(groups, (str, bytes)):
            raise FtsQueryError
        rendered_groups: list[str] = []
        total = 0
        for group in groups:
            if isinstance(group, (str, bytes)) or any(
                type(token) is not str for token in group
            ):
                raise FtsQueryError
            unique = tuple(dict.fromkeys(group))
            if not unique:
                raise FtsQueryError
            quoted: list[str] = []
            for token in unique:
                total += 1
                if total > self._max_tokens:
                    raise FtsQueryError
                quoted.append(self._quote(token))
            rendered_groups.append(
                quoted[0] if len(quoted) == 1 else "(" + " OR ".join(quoted) + ")"
            )
        return " AND ".join(rendered_groups)

    def build_any(self, tokens: Sequence[str]) -> str:
        return self.build((tokens,))

    def _quote(self, token: str) -> str:
        if (
            type(token) is not str
            or not token
            or not token.strip()
            or len(token) > self._max_token_characters
            or any(
                ord(char) == 0 or unicodedata.category(char) in {"Cc", "Zl", "Zp"}
                for char in token
            )
        ):
            raise FtsQueryError
        return '"' + token.replace('"', '""') + '"'


__all__ = ["FtsQueryBuilder", "FtsQueryError"]
