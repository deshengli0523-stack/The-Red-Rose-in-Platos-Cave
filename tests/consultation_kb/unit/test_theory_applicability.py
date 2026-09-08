from __future__ import annotations

from datetime import datetime, timezone

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.applicability import (
    ApplicabilityGate,
    ApplicabilityPolicyError,
    ScopePolicyManifest,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.theory import TheoryScope


NOW = datetime(2026, 7, 18, 8, 0, tzinfo=timezone.utc)


def _ids() -> IdFactory:
    counter = iter(range(10, 100))
    return IdFactory(FixedClock(NOW), lambda: next(counter))


def _policy() -> ScopePolicyManifest:
    ids = _ids()
    return ScopePolicyManifest(
        policy_ref=VersionRef(
            object_id=ids.object_id("scope_policy"),
            version=1,
            content_sha256="a" * 64,
        ),
        rule_members=frozenset(
            {
                "adult_population",
                "contraindication_match",
                "domain_match",
                "exclusion_match",
            }
        ),
        context_fields=frozenset(
            {"contraindications", "domain", "exclusions", "population"}
        ),
    )


def _revision_ref() -> VersionRef:
    ids = _ids()
    return VersionRef(
        object_id=ids.object_id("theory_revision"),
        version=1,
        content_sha256="b" * 64,
    )


def test_unknown_policy_key_fails_closed() -> None:
    gate = ApplicabilityGate(_policy())
    scope = TheoryScope(
        domains=frozenset({"emotional_consultation"}),
        populations=frozenset({"adult"}),
        contexts=frozenset(),
        required_conditions=frozenset(),
        exclusions=frozenset(),
        contraindications=frozenset(),
    )

    with pytest.raises(ApplicabilityPolicyError, match="POLICY_KEY_NOT_APPROVED"):
        gate.evaluate(
            revision=_revision_ref(),
            scope=scope,
            context={"domain": "emotional_consultation", "client_secret": "x"},
        )


def test_missing_approved_context_is_deterministic() -> None:
    gate = ApplicabilityGate(_policy())
    scope = TheoryScope(
        domains=frozenset({"emotional_consultation"}),
        populations=frozenset({"adult"}),
        contexts=frozenset(),
        required_conditions=frozenset(),
        exclusions=frozenset(),
        contraindications=frozenset(),
    )
    result = gate.evaluate(
        revision=_revision_ref(),
        scope=scope,
        context={"domain": "emotional_consultation"},
    )

    assert result.status == "insufficient_context"
    assert result.missing_context_fields == ("population",)


@pytest.mark.parametrize(
    ("scope_field", "context_field", "scope_value"),
    [
        ("exclusions", "exclusions", "outside_scope"),
        ("contraindications", "contraindications", "medical_diagnosis"),
    ],
)
def test_unknown_exclusion_or_contraindication_is_insufficient_context(
    scope_field: str,
    context_field: str,
    scope_value: str,
) -> None:
    scope_values = {
        "domains": frozenset({"emotional_consultation"}),
        "populations": frozenset({"adult"}),
        "contexts": frozenset(),
        "required_conditions": frozenset(),
        "exclusions": frozenset(),
        "contraindications": frozenset(),
    }
    scope_values[scope_field] = frozenset({scope_value})
    scope = TheoryScope.model_validate(scope_values)
    gate = ApplicabilityGate(_policy())

    missing = gate.evaluate(
        revision=_revision_ref(),
        scope=scope,
        context={
            "domain": "emotional_consultation",
            "population": "adult",
        },
    )
    known_empty = gate.evaluate(
        revision=_revision_ref(),
        scope=scope,
        context={
            "domain": "emotional_consultation",
            "population": "adult",
            context_field: (),
        },
    )
    matched = gate.evaluate(
        revision=_revision_ref(),
        scope=scope,
        context={
            "domain": "emotional_consultation",
            "population": "adult",
            context_field: (scope_value,),
        },
    )

    assert missing.status == "insufficient_context"
    assert missing.missing_context_fields == (context_field,)
    assert known_empty.status == "applicable"
    assert matched.status == "not_applicable"
