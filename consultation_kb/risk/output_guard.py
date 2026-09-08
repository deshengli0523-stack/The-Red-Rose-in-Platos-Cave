"""Fail-closed guard for client reply candidates; it never edits text."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping
from typing import Final

from pydantic import ValidationError

from consultation_kb.generation.contracts import ClientReplyCandidate

from .text_normalization import normalize_sensitive_text


_ALLOWED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "candidate_id",
        "label",
        "strategy",
        "text",
        "core_positions",
        "action_directions",
    }
)
_INTERNAL_PHRASES: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern, flags=re.IGNORECASE)
    for pattern in (
        r"系统(?:告警|警报|风险提示)",
        r"(?:风险|風險)(?:等级|等級|级别|級別|标签|標籤|规则|規則|告警|警报|警報|预警|預警)",
        r"内部(?:风险|告警|观察)",
        r"(?:触发|命中)(?:了)?(?:内部)?(?:风险)?规则",
        r"(?:高关注|一般关注)(?:信号|观察|提示|等级|级别|标签)?",
        r"(?:关注)?级别\s*[:：]?\s*(?:一般|高)",
        r"\brisk[ _-]?(?:level|label|rule|alert|observation)\b",
        r"\b(?:system[ _-]?alert|internal[ _-]?risk|rule[ _-]?id|trigger[ _-]?quote)\b",
        r"\blevel\s*[:=]\s*(?:general|high)\b",
        r"\bcategory\s*[:=]",
        r"\bsynthetic_(?:general|high)_observation\b",
        r"\bSYNTH-RISK-(?:GENERAL|HIGH)-[A-Z0-9]+\b",
        r"\brisk_observation_[0-9a-f-]{36}\b",
        r"\brisk_rule_[0-9a-f-]{36}\b",
    )
)
_SHA256_HEX: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_INTERNAL_FIELD_CANARIES: Final[tuple[str, ...]] = tuple(
    normalize_sensitive_text(value)
    for value in (
        "source_kind",
        "trigger_turn_ids",
        "start_offset",
        "end_offset",
        "span_sha256",
        "normalized_length",
        "normalized_span_sha256",
    )
)


class ClientReplyLeakageError(RuntimeError):
    def __init__(self, code: str = "CLIENT_REPLY_RISK_LEAKAGE") -> None:
        super().__init__(code)


def _all_strings(candidate: ClientReplyCandidate) -> tuple[str, ...]:
    return (
        candidate.candidate_id,
        candidate.label,
        candidate.strategy,
        candidate.text,
        *candidate.core_positions,
        *candidate.action_directions,
    )


def _scan_form(value: str) -> str:
    # Compatibility decomposition closes width/ligature tricks; stripping all
    # combining marks also closes variation-selector and split-diacritic bypasses.
    # Case folding is shared by phrase and exact-canary scans.
    normalized = unicodedata.normalize("NFKD", value).casefold()
    return "".join(
        char
        for char in normalized
        if not unicodedata.category(char).startswith(("C", "M"))
    )


class ClientReplyOutputGuard:
    def __init__(
        self,
        *,
        internal_canaries: tuple[str, ...] = (),
        internal_levels: tuple[str, ...] = (),
        internal_span_fingerprints: tuple[tuple[int, str], ...] = (),
    ) -> None:
        if any(type(value) is not str or not value for value in internal_canaries):
            raise ValueError("internal canaries must be non-empty exact strings")
        normalized_canaries = tuple(
            normalize_sensitive_text(value) for value in internal_canaries
        )
        if any(not value for value in normalized_canaries):
            raise ValueError("internal canaries must retain searchable characters")
        if any(level not in {"general", "high"} for level in internal_levels):
            raise ValueError("internal risk levels must use the closed vocabulary")
        if len(internal_levels) != len(set(internal_levels)):
            raise ValueError("internal risk levels must be unique")

        fingerprints: dict[int, set[str]] = {}
        for length, digest in internal_span_fingerprints:
            if (
                type(length) is not int
                or length <= 0
                or type(digest) is not str
                or _SHA256_HEX.fullmatch(digest) is None
            ):
                raise ValueError("internal span fingerprints must be positive SHA-256 pairs")
            fingerprints.setdefault(length, set()).add(digest)

        self._canaries = tuple(dict.fromkeys(normalized_canaries))
        self._levels = tuple(sorted(internal_levels))
        self._span_fingerprints = tuple(
            (length, frozenset(digests))
            for length, digests in sorted(fingerprints.items())
        )

    def _contains_internal_level(self, value: str) -> bool:
        """Match only labelled level values, never ordinary words like ``high``."""

        normalized = _scan_form(value)
        for level in self._levels:
            if re.search(
                rf"\b(?:risk[ _-]?)?level\s*[:=]\s*{re.escape(level)}\b",
                normalized,
            ):
                return True
            localized = "高" if level == "high" else "一般"
            if re.search(
                rf"(?:风险|風險)(?:等级|等級|级别|級別)\s*[:：]?\s*{localized}",
                normalized,
            ):
                return True
        return False

    def _contains_trigger_quote(self, value: str) -> bool:
        """Detect normalized private text from only normalized length plus SHA-256."""

        normalized = normalize_sensitive_text(value)
        for length, digests in self._span_fingerprints:
            if len(normalized) < length:
                continue
            for start in range(len(normalized) - length + 1):
                candidate = normalized[start : start + length]
                if hashlib.sha256(candidate.encode("utf-8")).hexdigest() in digests:
                    return True
        return False

    def validate(
        self,
        value: ClientReplyCandidate | Mapping[str, object],
    ) -> ClientReplyCandidate:
        if isinstance(value, Mapping) and set(value) != _ALLOWED_FIELDS:
            raise ClientReplyLeakageError("CLIENT_REPLY_SCHEMA_NOT_ALLOWLISTED")
        if isinstance(value, Mapping):
            try:
                candidate = ClientReplyCandidate.model_validate_json(
                    json.dumps(
                        dict(value),
                        ensure_ascii=False,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
            except (TypeError, ValueError, ValidationError):
                raise ClientReplyLeakageError(
                    "CLIENT_REPLY_SCHEMA_NOT_ALLOWLISTED"
                ) from None
        else:
            try:
                candidate = ClientReplyCandidate.model_validate(value, strict=True)
            except ValidationError:
                raise ClientReplyLeakageError(
                    "CLIENT_REPLY_SCHEMA_NOT_ALLOWLISTED"
                ) from None

        raw_strings = _all_strings(candidate)
        strings = tuple(_scan_form(value) for value in raw_strings)
        sensitive_strings = tuple(
            normalize_sensitive_text(value) for value in raw_strings
        )
        if any(
            canary in text
            for canary in self._canaries
            for text in sensitive_strings
        ):
            raise ClientReplyLeakageError("CLIENT_REPLY_INTERNAL_CANARY")
        if any(
            field in text
            for field in _INTERNAL_FIELD_CANARIES
            for text in sensitive_strings
        ):
            raise ClientReplyLeakageError
        if any(pattern.search(text) for text in strings for pattern in _INTERNAL_PHRASES):
            raise ClientReplyLeakageError
        if any(self._contains_internal_level(value) for value in raw_strings):
            raise ClientReplyLeakageError("CLIENT_REPLY_INTERNAL_LEVEL")
        if any(self._contains_trigger_quote(value) for value in raw_strings):
            raise ClientReplyLeakageError("CLIENT_REPLY_TRIGGER_QUOTE")
        return candidate

    def validate_many(
        self,
        values: tuple[ClientReplyCandidate | Mapping[str, object], ...],
    ) -> tuple[ClientReplyCandidate, ...]:
        return tuple(self.validate(value) for value in values)


__all__ = ["ClientReplyLeakageError", "ClientReplyOutputGuard"]
