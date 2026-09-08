"""Deterministic, report-safe deidentification for shared case drafts.

This scanner is intentionally conservative.  It removes direct identifiers,
records only keyed hashes of matched spans, and raises a separate rare-
combination finding for semantic review.  A successful automatic transform is
never treated as publication approval.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re
import unicodedata

from pydantic import TypeAdapter

from consultation_kb.knowledge._canonical import text_sha256
from consultation_kb.models.cases import (
    DeidentificationCategory,
    DeidentificationFinding,
    DeidentificationScan,
    DeidentificationTransform,
    RareCombinationFinding,
)
from consultation_kb.models.common import SafePolicyKey


_SAFE_POLICY_ADAPTER = TypeAdapter(SafePolicyKey)


@dataclass(frozen=True)
class _Rule:
    name: str
    category: DeidentificationCategory
    pattern: re.Pattern[str]
    replacement_category: str
    replacement_text: str


@dataclass(frozen=True)
class _Match:
    rule: _Rule
    start: int
    end: int
    value: str


@dataclass(frozen=True)
class _NormalizedView:
    text: str
    original_text: str
    spans: tuple[tuple[int, int], ...]
    format_control_spans: tuple[tuple[int, int], ...]

    def original_span(self, start: int, end: int) -> tuple[int, int, str]:
        if start < 0 or end <= start or end > len(self.spans):
            raise ValueError("normalized match cannot be mapped to source text")
        original_start = self.spans[start][0]
        original_end = self.spans[end - 1][1]
        return (
            original_start,
            original_end,
            self.original_text[original_start:original_end],
        )


_RULES: tuple[_Rule, ...] = (
    _Rule(
        "internal_client_identifier",
        "internal_identifier",
        re.compile(r"client_[a-z0-9]{12}"),
        "internal_identifier_removed",
        "[内部标识已隐去]",
    ),
    _Rule(
        "internal_uuid_identifier",
        "internal_identifier",
        re.compile(
            r"(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![0-9a-f])",
            re.IGNORECASE,
        ),
        "internal_identifier_removed",
        "[内部标识已隐去]",
    ),
    _Rule(
        "email_address",
        "email",
        re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])"),
        "email_removed",
        "[邮箱已隐去]",
    ),
    _Rule(
        "national_identity_number",
        "national_id",
        re.compile(r"(?<!\d)\d{17}[0-9Xx](?!\d)"),
        "national_id_removed",
        "[证件号码已隐去]",
    ),
    _Rule(
        "mobile_phone_number",
        "phone",
        re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"),
        "phone_removed",
        "[电话号码已隐去]",
    ),
    _Rule(
        "landline_phone_number",
        "phone",
        re.compile(r"(?<!\d)(?:0\d{2,3}[- ]?)?\d{7,8}(?!\d)"),
        "phone_removed",
        "[电话号码已隐去]",
    ),
    _Rule(
        "exact_calendar_date",
        "exact_date",
        re.compile(
            r"(?<!\d)(?:19|20)\d{2}(?:[-/.年])(?:0?[1-9]|1[0-2])"
            r"(?:[-/.月])(?:0?[1-9]|[12]\d|3[01])日?(?!\d)"
        ),
        "date_generalized",
        "[具体日期已泛化]",
    ),
    _Rule(
        "labelled_person_name",
        "person_name",
        re.compile(
            r"(?:姓名|名字)[：:\s]*(?P<value>[\u3400-\u9fff·]{2,8})"
            r"|(?:我叫|本人叫)(?P<value_alt>[\u3400-\u9fff·]{2,8})"
        ),
        "person_generalized",
        "[人物已泛化]",
    ),
    _Rule(
        "third_party_person_name",
        "third_party_person",
        re.compile(
            r"(?:朋友|同事|老师|医生|前任|丈夫|妻子|伴侣|男朋友|女朋友)"
            r"(?:叫|名为)(?P<value>[\u3400-\u9fff·]{2,8})"
        ),
        "third_party_generalized",
        "[第三方人物已泛化]",
    ),
    _Rule(
        "labelled_exact_address",
        "exact_address",
        re.compile(
            r"(?:住址|详细地址|家庭地址)[：:\s]*"
            r"(?P<value>[^,，。；;\r\n]{3,80})"
        ),
        "address_generalized",
        "[地址已泛化]",
    ),
    _Rule(
        "residential_location",
        "exact_address",
        re.compile(r"(?:住在|居住于)(?P<value>[^,，。；;\r\n]{3,60})"),
        "address_generalized",
        "[居住地已泛化]",
    ),
    _Rule(
        "labelled_organization",
        "organization",
        re.compile(
            r"(?:任职单位|工作单位|单位|公司|学校|医院)[：:\s]*"
            r"(?P<value>[^,，。；;\r\n]{2,60})"
        ),
        "organization_generalized",
        "[机构已泛化]",
    ),
    _Rule(
        "workplace_organization",
        "organization",
        re.compile(
            r"在(?P<value>[^,，。；;\r\n]{2,40}(?:公司|学校|医院|机构|单位))工作"
        ),
        "organization_generalized",
        "[机构已泛化]",
    ),
    _Rule(
        "rare_origin_location",
        "rare_location",
        re.compile(r"(?:来自|老家在|出生于)(?P<value>[^,，。；;\r\n]{2,50})"),
        "location_generalized",
        "[地点已泛化]",
    ),
    _Rule(
        "labelled_occupation",
        "occupation",
        re.compile(
            r"(?:职业|具体职业|岗位)[：:\s]*(?P<value>[^,，。；;\r\n]{2,40})"
        ),
        "occupation_generalized",
        "[职业已泛化]",
    ),
)

_FORMAT_CONTROL_RULE = _Rule(
    "unicode_format_control",
    "internal_identifier",
    re.compile(r"(?!x)x"),
    "format_control_removed",
    "[鏍煎紡鎺у埗瀛楃宸茬Щ闄",
)


def _normalized_view(text: str) -> _NormalizedView:
    characters: list[str] = []
    spans: list[tuple[int, int]] = []
    format_control_spans: list[tuple[int, int]] = []
    for index, character in enumerate(text):
        if unicodedata.category(character) == "Cf":
            format_control_spans.append((index, index + 1))
            continue
        normalized = unicodedata.normalize("NFKC", character).casefold()
        for normalized_character in normalized:
            if unicodedata.category(normalized_character) == "Cf":
                format_control_spans.append((index, index + 1))
                continue
            characters.append(normalized_character)
            spans.append((index, index + 1))
    return _NormalizedView(
        text="".join(characters),
        original_text=text,
        spans=tuple(spans),
        format_control_spans=tuple(sorted(set(format_control_spans))),
    )


def _merge_overlapping_matches(text: str, values: list[_Match]) -> list[_Match]:
    if not values:
        return []
    priority = {rule.name: index for index, rule in enumerate(_RULES)}
    priority[_FORMAT_CONTROL_RULE.name] = len(priority)
    ordered = sorted(values, key=lambda item: (item.start, item.end, item.rule.name))
    merged: list[_Match] = []
    group: list[_Match] = [ordered[0]]
    group_end = ordered[0].end

    def finish(items: list[_Match]) -> _Match:
        start = min(item.start for item in items)
        end = max(item.end for item in items)
        winner = min(
            items,
            key=lambda item: (
                -(item.end - item.start),
                priority[item.rule.name],
                item.rule.name,
            ),
        )
        return _Match(
            rule=winner.rule,
            start=start,
            end=end,
            value=text[start:end],
        )

    for item in ordered[1:]:
        if item.start < group_end:
            group.append(item)
            group_end = max(group_end, item.end)
            continue
        merged.append(finish(group))
        group = [item]
        group_end = item.end
    merged.append(finish(group))
    return merged


_FAMILY_SIGNAL_RE = re.compile(
    r"独生子女|单亲家庭|重组家庭|再婚家庭|家中排行|有[一二两三四五六七八九十\d]+个孩子"
)
_OCCUPATION_SIGNAL_RE = re.compile(
    r"(?:职业|具体职业|岗位)[：:\s]*[^,，。；;\r\n]{2,40}|"
    r"从事[^,，。；;\r\n]{2,30}(?:工作|行业)"
)
_LOCATION_SIGNAL_RE = re.compile(
    r"(?:来自|老家在|出生于|住在|居住于|住址|详细地址|家庭地址)"
    r"[：:\s]*[^,，。；;\r\n]{2,60}"
)
_DATE_SIGNAL_RE = re.compile(
    r"(?<!\d)(?:19|20)\d{2}(?:[-/.年])(?:0?[1-9]|1[0-2])"
    r"(?:[-/.月])(?:0?[1-9]|[12]\d|3[01])日?(?!\d)"
)


def _captured_span(match: re.Match[str]) -> tuple[int, int, str]:
    for group_name in ("value", "value_alt"):
        try:
            value = match.group(group_name)
        except IndexError:
            continue
        if value is not None:
            start, end = match.span(group_name)
            return start, end, value
    start, end = match.span(0)
    return start, end, match.group(0)


class Deidentifier:
    """Keyed scanner and deterministic replacer.

    ``span_hash_key`` must be vault-managed secret material.  A keyed digest is
    used instead of plain SHA-256 so short names and phone numbers cannot be
    recovered from a small dictionary attack against a shared report.
    """

    def __init__(
        self,
        *,
        span_hash_key: bytes,
        rule_version: str = "case_deidentification_v1",
    ) -> None:
        if not isinstance(span_hash_key, bytes) or len(span_hash_key) < 32:
            raise ValueError("deidentification span hash key must contain at least 32 bytes")
        self._key = bytes(span_hash_key)
        self._rule_version = _SAFE_POLICY_ADAPTER.validate_python(rule_version)

    @property
    def rule_version(self) -> str:
        return self._rule_version

    def private_value_hmac(self, value: str, *, domain: str) -> str:
        """Return a domain-separated hash suitable for shared lineage metadata."""

        if type(value) is not str or not value:
            raise ValueError("private value hash requires a non-empty exact string")
        checked_domain = _SAFE_POLICY_ADAPTER.validate_python(domain)
        return hmac.new(
            self._key,
            f"{checked_domain}\0{value}".encode("utf-8", errors="strict"),
            hashlib.sha256,
        ).hexdigest()

    def scan(self, text: str) -> DeidentificationScan:
        if type(text) is not str or not text.strip():
            raise ValueError("deidentification scan requires non-blank exact text")

        view = _normalized_view(text)
        matches: list[_Match] = [
            _Match(
                rule=_FORMAT_CONTROL_RULE,
                start=start,
                end=end,
                value=text[start:end],
            )
            for start, end in view.format_control_spans
        ]
        for rule in _RULES:
            for match in rule.pattern.finditer(view.text):
                normalized_start, normalized_end, _ = _captured_span(match)
                start, end, value = view.original_span(
                    normalized_start,
                    normalized_end,
                )
                matches.append(_Match(rule=rule, start=start, end=end, value=value))

        matches = _merge_overlapping_matches(text, matches)
        findings = tuple(
            DeidentificationFinding(
                rule=item.rule.name,
                category=item.rule.category,
                span_hmac_sha256=self.private_value_hmac(
                    item.value,
                    domain=f"span_{item.rule.name}_{item.start}_{item.end}",
                ),
                start=item.start,
                end=item.end,
                replacement_category=item.rule.replacement_category,
                automatic_action="replace",
            )
            for item in matches
        )

        quasi_values: dict[DeidentificationCategory, tuple[str, ...]] = {}
        signals: tuple[
            tuple[DeidentificationCategory, re.Pattern[str]], ...
        ] = (
            ("rare_location", _LOCATION_SIGNAL_RE),
            ("occupation", _OCCUPATION_SIGNAL_RE),
            ("family_structure", _FAMILY_SIGNAL_RE),
            ("exact_date", _DATE_SIGNAL_RE),
        )
        for category, pattern in signals:
            values = tuple(
                view.original_span(match.start(), match.end())[2]
                for match in pattern.finditer(view.text)
            )
            if values:
                quasi_values[category] = values

        rare_combinations: tuple[RareCombinationFinding, ...] = ()
        if len(quasi_values) >= 3:
            component_hashes = sorted(
                self.private_value_hmac(value, domain=f"rare_{category}")
                for category, values in quasi_values.items()
                for value in values
            )
            combination_hash = self.private_value_hmac(
                "|".join(component_hashes), domain="rare_combination"
            )
            rare_combinations = (
                RareCombinationFinding(
                    categories=frozenset(quasi_values),
                    combination_hmac_sha256=combination_hash,
                ),
            )

        return DeidentificationScan(
            input_sha256=text_sha256(text),
            rule_version=self._rule_version,
            findings=findings,
            rare_combinations=rare_combinations,
            scanned_categories=frozenset(
                {
                    "internal_identifier",
                    "person_name",
                    "phone",
                    "email",
                    "national_id",
                    "exact_address",
                    "organization",
                    "exact_date",
                    "third_party_person",
                    "rare_location",
                    "occupation",
                    "family_structure",
                }
            ),
        )

    def transform(
        self,
        text: str,
        scan: DeidentificationScan | None = None,
    ) -> DeidentificationTransform:
        authoritative = self.scan(text)
        validated = (
            authoritative
            if scan is None
            else DeidentificationScan.model_validate(scan)
        )
        if validated.rule_version != self._rule_version:
            raise ValueError("deidentification scan rule version mismatch")
        if validated.input_sha256 != text_sha256(text):
            raise ValueError("deidentification scan does not bind the supplied text")
        if validated != authoritative:
            raise ValueError("deidentification scan does not match authoritative rescan")

        replacements = {rule.name: rule.replacement_text for rule in _RULES}
        output = text
        for finding in reversed(validated.findings):
            replacement = replacements.get(finding.rule)
            if replacement is None:
                raise ValueError("deidentification finding uses an unknown rule")
            output = output[: finding.start] + replacement + output[finding.end :]

        return DeidentificationTransform(
            input_sha256=validated.input_sha256,
            output_sha256=text_sha256(output),
            rule_version=self._rule_version,
            output_text=output,
            applied_finding_hashes=tuple(
                item.span_hmac_sha256 for item in validated.findings
            ),
            unresolved_rare_combination_hashes=tuple(
                item.combination_hmac_sha256 for item in validated.rare_combinations
            ),
        )


__all__ = ["Deidentifier"]
