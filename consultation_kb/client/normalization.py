"""Deterministic canonical keys and duplicate/conflict classification."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from datetime import datetime

from pydantic import model_validator

from consultation_kb.models.common import NonEmptyStr, StrictModel, UtcDateTime
from consultation_kb.models.facts import FactEvent, canonical_json


_WHITESPACE = re.compile(r"\s+")
_ROLE_ALIASES = {
    "男朋友": "male_partner",
    "男友": "male_partner",
    "现男友": "male_partner",
    "现任男友": "male_partner",
    "boyfriend": "male_partner",
    "女朋友": "female_partner",
    "女友": "female_partner",
    "现女友": "female_partner",
    "现任女友": "female_partner",
    "girlfriend": "female_partner",
    "伴侣": "partner",
    "现伴侣": "partner",
    "currentpartner": "partner",
}


def normalize_text(value: str) -> str:
    if type(value) is not str:
        raise TypeError("normalization input must be an exact string")
    normalized = unicodedata.normalize("NFKC", value)
    normalized = _WHITESPACE.sub(" ", normalized).strip().casefold()
    if not normalized:
        raise ValueError("normalized text must not be blank")
    return normalized


def normalize_role(value: str) -> str:
    normalized = normalize_text(value)
    compact = normalized.replace(" ", "")
    return _ROLE_ALIASES.get(compact, normalized)


class CanonicalFactKey(StrictModel):
    subject: NonEmptyStr
    predicate: NonEmptyStr
    normalized_value_json: NonEmptyStr
    effective_from: UtcDateTime
    effective_to: UtcDateTime | None
    scope: NonEmptyStr
    digest: NonEmptyStr

    @model_validator(mode="after")
    def _digest(self) -> "CanonicalFactKey":
        expected = self._calculate(
            self.subject,
            self.predicate,
            self.normalized_value_json,
            self.effective_from,
            self.effective_to,
            self.scope,
        )
        if self.digest != expected:
            raise ValueError("canonical key digest mismatch")
        return self

    @classmethod
    def build(
        cls,
        *,
        subject: str,
        predicate: str,
        value: object,
        effective_from: datetime,
        effective_to: datetime | None,
        scope: str,
    ) -> "CanonicalFactKey":
        normalized_subject = normalize_text(subject)
        normalized_predicate = normalize_text(predicate).replace(" ", "_")
        normalized_scope = normalize_text(scope).replace(" ", "_")
        if isinstance(value, str):
            normalized_value: object = normalize_role(value)
        else:
            normalized_value = value
        normalized_value_json = canonical_json(normalized_value)
        digest = cls._calculate(
            normalized_subject,
            normalized_predicate,
            normalized_value_json,
            effective_from,
            effective_to,
            normalized_scope,
        )
        return cls(
            subject=normalized_subject,
            predicate=normalized_predicate,
            normalized_value_json=normalized_value_json,
            effective_from=effective_from,
            effective_to=effective_to,
            scope=normalized_scope,
            digest=digest,
        )

    @staticmethod
    def _calculate(
        subject: str,
        predicate: str,
        normalized_value_json: str,
        effective_from: datetime,
        effective_to: datetime | None,
        scope: str,
    ) -> str:
        payload = {
            "effective_from": effective_from.isoformat().replace("+00:00", "Z"),
            "effective_to": (
                None
                if effective_to is None
                else effective_to.isoformat().replace("+00:00", "Z")
            ),
            "normalized_value_json": normalized_value_json,
            "predicate": predicate,
            "scope": scope,
            "subject": subject,
        }
        return hashlib.sha256((canonical_json(payload) + "\n").encode("utf-8")).hexdigest()


class DuplicateCandidate(StrictModel):
    event_id: NonEmptyStr
    fact_id: NonEmptyStr
    classification: str
    reason: NonEmptyStr


def classify_candidates(
    proposed: FactEvent,
    current: tuple[FactEvent, ...],
) -> tuple[DuplicateCandidate, ...]:
    candidates: list[DuplicateCandidate] = []
    for existing in current:
        if existing.review_status != "approved" or existing.validity_status != "active":
            continue
        if existing.canonical_key == proposed.canonical_key:
            candidates.append(
                DuplicateCandidate(
                    event_id=existing.event_id,
                    fact_id=existing.fact_id,
                    classification="exact_duplicate",
                    reason="canonical key is identical",
                )
            )
        elif (
            normalize_text(existing.subject) == normalize_text(proposed.subject)
            and normalize_text(existing.predicate) == normalize_text(proposed.predicate)
            and "current_partner" in normalize_text(proposed.predicate).replace(" ", "_")
            and existing.object_json != proposed.object_json
        ):
            candidates.append(
                DuplicateCandidate(
                    event_id=existing.event_id,
                    fact_id=existing.fact_id,
                    classification="conflict",
                    reason="current relationship values conflict and must not be merged",
                )
            )
    return tuple(sorted(candidates, key=lambda item: (item.classification, item.event_id)))


__all__ = [
    "CanonicalFactKey",
    "DuplicateCandidate",
    "classify_candidates",
    "normalize_role",
    "normalize_text",
]
