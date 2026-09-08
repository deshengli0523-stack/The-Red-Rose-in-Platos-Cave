"""Deterministic Chinese normalization and word/character tokenization."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping

import jieba  # type: ignore[import-untyped]


NORMALIZATION_VERSION = "consultation_nfkc_tokens_v1"
_HAN_RUN = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]+")
_ALNUM = re.compile(r"[A-Za-z0-9]+")


class NormalizationError(ValueError):
    def __init__(self) -> None:
        super().__init__("NORMALIZATION_INPUT_INVALID")


def _validate_text(value: str, *, maximum: int = 16_384) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise NormalizationError
    if any(
        ord(char) == 0
        or (unicodedata.category(char) == "Cc" and char not in {"\t", "\n", "\r"})
        for char in value
    ):
        raise NormalizationError
    return value


def normalize_text(value: str) -> str:
    """NFKC and stable boundaries without simplified/traditional rewriting."""

    normalized = unicodedata.normalize("NFKC", _validate_text(value))
    boundary_text = "".join(
        " " if unicodedata.category(char)[0] in {"P", "S", "Z"} else char
        for char in normalized
    )
    result = " ".join(boundary_text.split())
    if not result:
        raise NormalizationError
    return result


class ApprovedAliasDictionary:
    """Immutable, explicitly approved aliases; never an implicit script map."""

    def __init__(self, aliases: Mapping[str, tuple[str, ...]] | None = None) -> None:
        canonical: dict[str, tuple[str, ...]] = {}
        used_terms: set[str] = set()
        for headword, values in (aliases or {}).items():
            key = normalize_text(headword)
            raw_values = tuple(normalize_text(value) for value in values)
            normalized_values = tuple(sorted(set(raw_values)))
            if (
                not normalized_values
                or len(normalized_values) != len(raw_values)
                or key in normalized_values
                or key in used_terms
                or used_terms.intersection(normalized_values)
            ):
                raise NormalizationError
            canonical[key] = normalized_values
            used_terms.add(key)
            used_terms.update(normalized_values)
        self._aliases = tuple(sorted(canonical.items()))
        self.sha256 = hashlib.sha256(
            json.dumps(
                self._aliases,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    @property
    def entries(self) -> tuple[tuple[str, tuple[str, ...]], ...]:
        return self._aliases

    def expansions(self, text: str) -> tuple[str, ...]:
        normalized = normalize_text(text)
        additions: set[str] = set()
        for headword, aliases in self._aliases:
            if headword in normalized:
                additions.update(aliases)
            for alias in aliases:
                if alias in normalized:
                    additions.add(headword)
        return tuple(sorted(additions))


class ChineseTokenizer:
    def __init__(
        self,
        aliases: ApprovedAliasDictionary | None = None,
    ) -> None:
        self.aliases = aliases if aliases is not None else ApprovedAliasDictionary()
        self._tokenizer = jieba.Tokenizer()
        for headword, values in self.aliases.entries:
            self._tokenizer.add_word(headword, freq=10_000_000)
            for value in values:
                self._tokenizer.add_word(value, freq=10_000_000)

    @property
    def jieba_version(self) -> str:
        return str(jieba.__version__)

    def word_tokens(self, value: str) -> tuple[str, ...]:
        normalized = normalize_text(value)
        sources = (normalized, *self.aliases.expansions(value))
        tokens: set[str] = set()
        for source in sources:
            for token in self._tokenizer.cut_for_search(source, HMM=False):
                cleaned = "".join(
                    char
                    for char in token
                    if unicodedata.category(char)[0] not in {"P", "S", "Z", "C"}
                ).strip()
                if cleaned:
                    tokens.add(cleaned.casefold())
        return tuple(sorted(tokens))

    def character_tokens(self, value: str) -> tuple[str, ...]:
        normalized = normalize_text(value)
        tokens: set[str] = set()
        for match in _HAN_RUN.finditer(normalized):
            run = match.group(0)
            for width in (2, 3):
                tokens.update(
                    run[index : index + width]
                    for index in range(0, len(run) - width + 1)
                )
        tokens.update(match.group(0).casefold() for match in _ALNUM.finditer(normalized))
        for expansion in self.aliases.expansions(value):
            for match in _HAN_RUN.finditer(expansion):
                run = match.group(0)
                for width in (2, 3):
                    tokens.update(
                        run[index : index + width]
                        for index in range(0, len(run) - width + 1)
                    )
        return tuple(sorted(tokens))


__all__ = [
    "ApprovedAliasDictionary",
    "ChineseTokenizer",
    "NORMALIZATION_VERSION",
    "NormalizationError",
    "normalize_text",
]
