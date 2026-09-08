from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import Provenance
from consultation_kb.models.knowledge import ClaimApplicability, ClaimRecord


NOW = datetime(2026, 7, 18, 8, 0, tzinfo=timezone.utc)


def _ids() -> IdFactory:
    counter = iter(range(1, 100))
    return IdFactory(FixedClock(NOW), lambda: next(counter))


def _claim_values() -> dict[str, object]:
    ids = _ids()
    source_id = ids.object_id("source")
    passage_id = ids.object_id("passage")
    return {
        "claim_id": ids.object_id("claim"),
        "version": 1,
        "text": "合成的咨询框架主张",
        "text_sha256": "1" * 64,
        "cognitive_type": "counselor_judgment",
        "source_grade": "C1",
        "framework_eligibility": "conditional",
        "empirical_support": "unassessed",
        "model_confidence": None,
        "review_status": "approved",
        "effective_from": NOW,
        "effective_to": None,
        "review_due_at": None,
        "applicability": ClaimApplicability(
            domains=frozenset({"emotional_consultation"}),
            populations=frozenset(),
            contexts=frozenset(),
            required_conditions=frozenset(),
            exclusions=frozenset(),
            contraindications=frozenset(),
        ),
        "privacy_scope": "global",
        "allowed_uses": frozenset({"consultation"}),
        "passage_refs": (
            VersionRef(object_id=passage_id, version=1, content_sha256="2" * 64),
        ),
        "provenance": Provenance(
            source_ids=frozenset({source_id}),
            passage_ids=frozenset({passage_id}),
            provenance_scope="global_source",
            derivation_rule_ref=VersionRef(
                object_id=ids.object_id("policy"),
                version=1,
                content_sha256="3" * 64,
            ),
        ),
        "created_at": NOW,
    }


def test_generic_c1_claim_requires_theory_revision() -> None:
    with pytest.raises(ValidationError, match="theory revision"):
        ClaimRecord(**_claim_values())


def test_framework_highest_is_runtime_derived_not_stored() -> None:
    values = _claim_values()
    values["theory_revision_ref"] = VersionRef(
        object_id=_ids().object_id("theory_revision"),
        version=1,
        content_sha256="4" * 64,
    )
    values["framework_priority"] = "highest"

    with pytest.raises(ValidationError):
        ClaimRecord(**values)


def test_claim_applicability_is_deeply_immutable_and_rejects_sensitive_values() -> None:
    domains = {"emotional_consultation"}
    scope = ClaimApplicability(
        domains=frozenset(domains),
        populations=frozenset(),
        contexts=frozenset(),
        required_conditions=frozenset(),
        exclusions=frozenset(),
        contraindications=frozenset(),
    )
    domains.add("career_consultation")
    assert scope.domains == frozenset({"emotional_consultation"})
    with pytest.raises(AttributeError):
        scope.domains.add("career_consultation")  # type: ignore[attr-defined]

    with pytest.raises(ValidationError):
        ClaimApplicability(
            domains=frozenset({"client_" + "a" * 12}),
            populations=frozenset(),
            contexts=frozenset(),
            required_conditions=frozenset(),
            exclusions=frozenset(),
            contraindications=frozenset(),
        )
    with pytest.raises(ValidationError):
        ClaimApplicability(
            domains=frozenset({"c:/private/path"}),
            populations=frozenset(),
            contexts=frozenset(),
            required_conditions=frozenset(),
            exclusions=frozenset(),
            contraindications=frozenset(),
        )
