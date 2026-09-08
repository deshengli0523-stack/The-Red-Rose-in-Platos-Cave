"""Deterministic risk evaluation with model observations as constrained drafts."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Iterable
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import (
    NonEmptyStr,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    Uuid7String,
    VersionRef,
)
from consultation_kb.models.risk import InternalRiskObservation

from .repository import (
    InternalRiskObservationRecord,
    InternalRiskObservationRepository,
    RiskObservationSource,
    RiskTriggerSpan,
)
from .rules import (
    MaterializedRiskRule,
    PersistentRiskRuleCatalogResolver,
    RiskRuleCatalog,
    RiskRuleClosureError,
    RiskRulePolicyBinding,
)
from .text_normalization import normalized_sensitive_fingerprint


_NEGATION_TOKENS = frozenset(
    {
        "not",
        "no",
        "never",
        "without",
        "没有",
        "没",
        "不是",
        "并不",
        "并未",
        "不会",
        "不想",
        "从未",
    }
)
_WORD_RE = re.compile(r"[A-Za-z0-9_]+|[\u4e00-\u9fff]")
_REPORTING_OR_EXAMPLE_PREFIXES = (
    "他说",
    "她说",
    "对方说",
    "朋友说",
    "来访者说",
    "案例中",
    "文章中",
    "引用",
    "例如",
    "比如",
    "假设",
    "如果",
    "he said",
    "she said",
    "they said",
    "the client said",
    "the article says",
    "the example says",
    "quote",
    "for example",
    "hypothetically",
    "what if",
    "if ",
)
_UNCERTAIN_OR_HISTORICAL_PREFIXES = (
    "也许",
    "可能",
    "好像",
    "似乎",
    "不确定是否",
    "以前",
    "曾经",
    "过去",
    "当时",
    "之前",
    "maybe",
    "might",
    "perhaps",
    "possibly",
    "last year",
    "previously",
    "used to",
    "in the past",
)
_HISTORICAL_OR_RETRACTION_SUFFIXES = (
    "是以前的事",
    "只是过去",
    "但现在不",
    "was in the past",
    "but not now",
)
_QUOTE_PAIRS = (
    ('"', '"'),
    ("'", "'"),
    ("“", "”"),
    ("「", "」"),
    ("『", "』"),
    ("‘", "’"),
)
_SENTENCE_BOUNDARIES = frozenset("。！？.!?\n；;")


class RiskEvaluationError(RuntimeError):
    def __init__(self, code: str = "RISK_EVALUATION_INVALID") -> None:
        super().__init__(code)


class RiskTextSegment(StrictModel):
    turn_id: Uuid7String
    content_ref: VersionRef
    text: NonEmptyStr
    statement_mode: Literal["direct", "quoted", "historical", "ambiguous"] = "direct"


class ModelRiskObservationDraft(StrictModel):
    """Model-supplied observation with no lifecycle or client-facing text fields."""

    schema_version: Literal["1.0"] = "1.0"
    rule_ref: VersionRef
    category: SafePolicyKey
    level: Literal["general", "high"]
    model_ref: VersionRef
    trigger_turn_id: Uuid7String
    trigger_content_ref: VersionRef
    start_offset: Annotated[int, Field(strict=True, ge=0)]
    end_offset: Annotated[int, Field(strict=True, gt=0)]
    span_sha256: Sha256Hex
    confidence: Annotated[float, Field(strict=True, gt=0.0, lt=1.0)]
    rationale_summary: Annotated[str, Field(strict=True, min_length=1, max_length=512)]
    requires_counselor_confirmation: Literal[True] = True

    @model_validator(mode="after")
    def _valid_offsets(self) -> "ModelRiskObservationDraft":
        if self.end_offset <= self.start_offset:
            raise ValueError("model risk span end must be after start")
        return self


class RiskEvaluationInput(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    session_id: Uuid7String
    segments: Annotated[tuple[RiskTextSegment, ...], Field(min_length=1)]
    context_keys: frozenset[SafePolicyKey]
    model_drafts: Annotated[
        tuple[ModelRiskObservationDraft, ...],
        Field(max_length=64),
    ] = ()

    @field_validator("segments")
    @classmethod
    def _unique_segments(
        cls,
        value: tuple[RiskTextSegment, ...],
    ) -> tuple[RiskTextSegment, ...]:
        keys = tuple((item.turn_id, item.content_ref) for item in value)
        if len(keys) != len(set(keys)):
            raise ValueError("risk text segments must be unique")
        return value


class RiskEvaluationResult(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    observations: tuple[InternalRiskObservationRecord, ...]
    persisted_visible_observations: tuple[InternalRiskObservationRecord, ...] = ()


def _span_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _span_identity_key(
    span: RiskTriggerSpan,
) -> tuple[str, str, int, str, int, int, str, int, str]:
    return (
        span.turn_id,
        span.content_ref.object_id,
        span.content_ref.version,
        span.content_ref.content_sha256,
        span.start_offset,
        span.end_offset,
        span.span_sha256,
        span.normalized_length,
        span.normalized_span_sha256,
    )


def _canonical_trigger_spans(
    spans: tuple[RiskTriggerSpan, ...],
) -> tuple[RiskTriggerSpan, ...]:
    return tuple(sorted(spans, key=_span_identity_key))


def _stable_observation_id(
    *,
    session_id: str,
    rule_ref: VersionRef,
    trigger_spans: tuple[RiskTriggerSpan, ...],
) -> str:
    """Derive one retry-stable UUIDv7-shaped ID from immutable evidence."""

    canonical_spans = _canonical_trigger_spans(trigger_spans)
    payload = json.dumps(
        {
            "identity_schema": "risk_observation/v1",
            "rule_ref": {
                "content_sha256": rule_ref.content_sha256,
                "object_id": rule_ref.object_id,
                "version": rule_ref.version,
            },
            "session_id": session_id,
            "trigger_spans": [
                {
                    "content_ref": {
                        "content_sha256": span.content_ref.content_sha256,
                        "object_id": span.content_ref.object_id,
                        "version": span.content_ref.version,
                    },
                    "end_offset": span.end_offset,
                    "normalized_length": span.normalized_length,
                    "normalized_span_sha256": span.normalized_span_sha256,
                    "span_sha256": span.span_sha256,
                    "start_offset": span.start_offset,
                    "turn_id": span.turn_id,
                }
                for span in canonical_spans
            ],
        },
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    digest = hashlib.sha256(
        b"consultation-kb/risk-observation-identity/v1\x00" + payload
    ).digest()
    value = int.from_bytes(digest[:16], "big")
    value = (value & ~(0xF << 76)) | (0x7 << 76)
    value = (value & ~(0b11 << 62)) | (0b10 << 62)
    return f"risk_observation_{uuid.UUID(int=value)}"


def _literal_offsets(text: str, pattern: str) -> tuple[tuple[int, int], ...]:
    offsets: list[tuple[int, int]] = []
    cursor = 0
    while True:
        start = text.find(pattern, cursor)
        if start < 0:
            return tuple(offsets)
        end = start + len(pattern)
        offsets.append((start, end))
        cursor = end


def _is_negated(text: str, start: int, window: int) -> bool:
    if window <= 0:
        return False
    prefix = text[:start]
    tokens = _WORD_RE.findall(prefix.lower())
    recent = tokens[-window:]
    if any(token in _NEGATION_TOKENS for token in recent):
        return True
    # Chinese negators are often adjacent to a longer tokenization context.
    tail = prefix[-max(8, window * 4) :]
    return any(token in tail for token in _NEGATION_TOKENS if not token.isascii())


def _inside_balanced_quote(text: str, start: int, end: int) -> bool:
    """Conservatively identify a literal inside a paired quotation span."""

    for opener, closer in _QUOTE_PAIRS:
        prefix = text[:start]
        if opener == closer:
            if prefix.count(opener) % 2 == 1 and closer in text[end:]:
                return True
            continue
        if prefix.rfind(opener) > prefix.rfind(closer) and closer in text[end:]:
            return True
    return False


def _is_contextually_qualified(text: str, start: int, end: int) -> bool:
    """Return true unless a literal is a direct, current assertion.

    Reported speech, examples, hypotheticals, uncertain wording, historical
    accounts, and immediate questions remain eligible for trusted model review,
    but never become a deterministic finding merely through substring matching.
    """

    if _inside_balanced_quote(text, start, end):
        return True
    prefix = text[max(0, start - 48) : start]
    last_boundary = max(
        (prefix.rfind(marker) for marker in _SENTENCE_BOUNDARIES),
        default=-1,
    )
    prefix = prefix[last_boundary + 1 :].casefold()
    suffix = text[end : min(len(text), end + 24)].casefold()
    if any(marker.casefold() in prefix for marker in _REPORTING_OR_EXAMPLE_PREFIXES):
        return True
    if any(marker.casefold() in prefix for marker in _UNCERTAIN_OR_HISTORICAL_PREFIXES):
        return True
    if any(
        marker.casefold() in suffix for marker in _HISTORICAL_OR_RETRACTION_SUFFIXES
    ):
        return True
    return suffix.lstrip().startswith(("?", "？"))


def _canonical_sources(
    values: Iterable[RiskObservationSource],
) -> tuple[RiskObservationSource, ...]:
    by_key = {(value.source_kind, value.source_ref): value for value in values}
    return tuple(
        by_key[key]
        for key in sorted(
            by_key,
            key=lambda item: (
                item[0],
                item[1].object_id,
                item[1].version,
                item[1].content_sha256,
            ),
        )
    )


class RiskEngine:
    def __init__(
        self,
        resolver: PersistentRiskRuleCatalogResolver,
        *,
        policy_binding: RiskRulePolicyBinding,
        clock: Clock | None = None,
        id_factory: IdFactory | None = None,
        repository: InternalRiskObservationRepository | None = None,
    ) -> None:
        if type(resolver) is not PersistentRiskRuleCatalogResolver:
            raise RiskRuleClosureError("RISK_RULE_PERSISTENT_RESOLVER_REQUIRED")
        self._resolver = resolver
        self._policy_binding = RiskRulePolicyBinding.model_validate(policy_binding)
        self._catalog = resolver.resolve(self._policy_binding)
        self._clock = clock if clock is not None else SystemClock()
        self._ids = (
            id_factory if id_factory is not None else IdFactory(clock=self._clock)
        )
        self._repository = repository

    @staticmethod
    def _span(
        segment: RiskTextSegment,
        start: int,
        end: int,
    ) -> RiskTriggerSpan:
        span_text = segment.text[start:end]
        normalized_length, normalized_span_sha256 = normalized_sensitive_fingerprint(
            span_text
        )
        return RiskTriggerSpan(
            turn_id=segment.turn_id,
            content_ref=segment.content_ref,
            start_offset=start,
            end_offset=end,
            span_sha256=_span_sha256(span_text),
            normalized_length=normalized_length,
            normalized_span_sha256=normalized_span_sha256,
        )

    def _record(
        self,
        *,
        session_id: str,
        rule: MaterializedRiskRule,
        spans: tuple[RiskTriggerSpan, ...],
        sources: tuple[RiskObservationSource, ...],
        confidence: float,
    ) -> InternalRiskObservationRecord:
        canonical_spans = _canonical_trigger_spans(spans)
        observation = InternalRiskObservation(
            observation_id=_stable_observation_id(
                session_id=session_id,
                rule_ref=rule.rule_ref,
                trigger_spans=canonical_spans,
            ),
            category=rule.category,
            level=rule.level,
            trigger_turn_ids=tuple(sorted({span.turn_id for span in canonical_spans})),
            rule_ref=rule.rule_ref,
            detected_at=self._clock.now(),
            suggested_questions=rule.suggested_questions,
        )
        return InternalRiskObservationRecord(
            session_id=session_id,
            observation=observation,
            trigger_spans=canonical_spans,
            sources=_canonical_sources(sources),
            confidence=confidence,
        )

    def _deterministic_findings(
        self,
        request: RiskEvaluationInput,
        catalog: RiskRuleCatalog,
    ) -> list[InternalRiskObservationRecord]:
        findings: list[InternalRiskObservationRecord] = []
        for rule in catalog.rules:
            if not set(rule.required_context).issubset(request.context_keys):
                continue
            spans: list[RiskTriggerSpan] = []
            for segment in request.segments:
                # Quoted, historical, and ambiguous wording needs model/human review.
                if segment.statement_mode != "direct":
                    continue
                for start, end in _literal_offsets(segment.text, rule.pattern):
                    if _is_negated(segment.text, start, rule.negation_window_tokens):
                        continue
                    if _is_contextually_qualified(segment.text, start, end):
                        continue
                    spans.append(self._span(segment, start, end))
            if not spans:
                continue
            findings.append(
                self._record(
                    session_id=request.session_id,
                    rule=rule,
                    spans=tuple(spans),
                    sources=(
                        RiskObservationSource(
                            source_kind="deterministic_rule",
                            source_ref=rule.rule_ref,
                        ),
                    ),
                    confidence=1.0,
                )
            )
        return findings

    @staticmethod
    def _draft_span(
        draft: ModelRiskObservationDraft,
        segments: tuple[RiskTextSegment, ...],
    ) -> RiskTriggerSpan:
        segment = next(
            (
                item
                for item in segments
                if item.turn_id == draft.trigger_turn_id
                and item.content_ref == draft.trigger_content_ref
            ),
            None,
        )
        if segment is None or draft.end_offset > len(segment.text):
            raise RiskEvaluationError("MODEL_RISK_SPAN_INVALID")
        span_text = segment.text[draft.start_offset : draft.end_offset]
        if _span_sha256(span_text) != draft.span_sha256:
            raise RiskEvaluationError("MODEL_RISK_SPAN_HASH_MISMATCH")
        normalized_length, normalized_span_sha256 = normalized_sensitive_fingerprint(
            span_text
        )
        return RiskTriggerSpan(
            turn_id=draft.trigger_turn_id,
            content_ref=draft.trigger_content_ref,
            start_offset=draft.start_offset,
            end_offset=draft.end_offset,
            span_sha256=draft.span_sha256,
            normalized_length=normalized_length,
            normalized_span_sha256=normalized_span_sha256,
        )

    def _merge_model_drafts(
        self,
        request: RiskEvaluationInput,
        findings: list[InternalRiskObservationRecord],
        catalog: RiskRuleCatalog,
    ) -> list[InternalRiskObservationRecord]:
        for draft in request.model_drafts:
            rule = catalog.get_by_ref(draft.rule_ref)
            if draft.category != rule.category or draft.level != rule.level:
                raise RiskEvaluationError("MODEL_RISK_RULE_FIELDS_MISMATCH")
            if not set(rule.required_context).issubset(request.context_keys):
                raise RiskEvaluationError("MODEL_RISK_REQUIRED_CONTEXT_MISSING")
            span = self._draft_span(draft, request.segments)
            model_source = RiskObservationSource(
                source_kind="model_observation",
                source_ref=draft.model_ref,
            )
            matching_index = next(
                (
                    index
                    for index, finding in enumerate(findings)
                    if finding.observation.rule_ref == rule.rule_ref
                    and span in finding.trigger_spans
                ),
                None,
            )
            if matching_index is not None:
                finding = findings[matching_index]
                findings[matching_index] = finding.model_copy(
                    update={
                        "sources": _canonical_sources((*finding.sources, model_source)),
                        "confidence": max(finding.confidence, draft.confidence),
                    }
                )
                continue
            duplicate_index = next(
                (
                    index
                    for index, finding in enumerate(findings)
                    if finding.observation.rule_ref == rule.rule_ref
                    and finding.trigger_spans == (span,)
                ),
                None,
            )
            if duplicate_index is not None:
                finding = findings[duplicate_index]
                findings[duplicate_index] = finding.model_copy(
                    update={
                        "sources": _canonical_sources((*finding.sources, model_source)),
                        "confidence": max(finding.confidence, draft.confidence),
                    }
                )
                continue
            findings.append(
                self._record(
                    session_id=request.session_id,
                    rule=rule,
                    spans=(span,),
                    sources=(model_source,),
                    confidence=draft.confidence,
                )
            )
        return findings

    def evaluate(self, request: RiskEvaluationInput) -> RiskEvaluationResult:
        exact = RiskEvaluationInput.model_validate(request)
        catalog = self._resolver.resolve(self._policy_binding)
        if catalog != self._catalog:
            raise RiskRuleClosureError("RISK_RULE_CLOSURE_CHANGED")
        findings = self._merge_model_drafts(
            exact,
            self._deterministic_findings(exact, catalog),
            catalog,
        )
        persisted: tuple[InternalRiskObservationRecord, ...] = ()
        if self._repository is not None:
            for finding in findings:
                self._repository.add(finding)
            persisted = self._repository.list_visible(exact.session_id)
        return RiskEvaluationResult(
            observations=tuple(findings),
            persisted_visible_observations=persisted,
        )


__all__ = [
    "ModelRiskObservationDraft",
    "RiskEngine",
    "RiskEvaluationError",
    "RiskEvaluationInput",
    "RiskEvaluationResult",
    "RiskTextSegment",
]
