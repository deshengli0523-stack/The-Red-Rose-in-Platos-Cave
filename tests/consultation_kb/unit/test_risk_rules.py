from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

import pytest
from pydantic import ValidationError

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import VersionRef
from consultation_kb.policy.loader import risk_rule_member_identities
from consultation_kb.risk.engine import (
    ModelRiskObservationDraft,
    RiskEngine,
    RiskEvaluationError,
    RiskEvaluationInput,
    RiskTextSegment,
    _is_negated,
)
from consultation_kb.risk.rules import (
    PersistentRiskRuleCatalogResolver,
    RiskRuleCatalog,
    RiskRuleClosureError,
    RiskRulePolicyBinding,
)
from consultation_kb.risk.text_normalization import normalized_sensitive_fingerprint
from tests.consultation_kb.risk_support import (
    insert_approved_risk_policy_epoch,
    persistent_risk_authority,
)


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
SESSION_ID = "018f0000-0000-7000-8000-000000000101"
TURN_ID = "018f0000-0000-7000-8000-000000000102"


def _ref(kind: str, suffix: int, digest: str | None = None) -> VersionRef:
    return VersionRef(
        object_id=f"{kind}_018f0000-0000-7000-8000-{suffix:012x}",
        version=1,
        content_sha256=digest or f"{suffix % 16:x}" * 64,
    )


def _engine(
    resolver: PersistentRiskRuleCatalogResolver,
    binding: RiskRulePolicyBinding,
) -> RiskEngine:
    clock = FixedClock(NOW)
    values = iter(range(100, 200))
    return RiskEngine(
        resolver,
        policy_binding=binding,
        clock=clock,
        id_factory=IdFactory(clock=clock, random_source=lambda: next(values)),
    )


def _segment(
    text: str,
    *,
    mode: Literal["direct", "quoted", "historical", "ambiguous"] = "direct",
    suffix: int = 20,
) -> RiskTextSegment:
    return RiskTextSegment(
        turn_id=TURN_ID,
        content_ref=_ref("private_span", suffix),
        text=text,
        statement_mode=mode,
    )


def test_loaded_policy_and_each_rule_require_exact_immutable_version_refs(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    connection, loaded, catalog, _, _ = persistent_risk_authority(repo_root, tmp_path)
    try:
        assert len(catalog.rules) == 14
        assert all(rule.policy_ref == catalog.policy_ref for rule in catalog.rules)
        assert all(
            rule.rule_ref.content_sha256 != catalog.policy_ref.content_sha256
            for rule in catalog.rules
        )

        identities = risk_rule_member_identities(loaded)
        with pytest.raises(RiskRuleClosureError, match="RISK_RULE_CLOSURE_INVALID"):
            RiskRuleCatalog.from_loaded_policy(
                loaded,
                policy_ref=_ref("risk_policy", 50, "0" * 64),
                rule_refs={
                    identity.rule_id: _ref(
                        "risk_rule",
                        60 + identity.member_ordinal,
                        identity.content_sha256,
                    )
                    for identity in identities
                },
            )
    finally:
        connection.close()


def test_deterministic_general_and_high_rules_require_context_and_ignore_quoted_history(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    connection, _, _, resolver, binding = persistent_risk_authority(repo_root, tmp_path)
    try:
        text = "SYNTH-RISK-GENERAL-4C2E and SYNTH-RISK-HIGH-7D1A"
        request = RiskEvaluationInput(
            session_id=SESSION_ID,
            segments=(_segment(text),),
            context_keys=frozenset({"synthetic_context_present"}),
        )
        result = _engine(resolver, binding).evaluate(request)
        assert {item.observation.level for item in result.observations} == {
            "general",
            "high",
        }
        assert all(
            item.observation.client_facing_visibility == "never"
            for item in result.observations
        )
        assert all(item.trigger_spans[0].span_sha256 for item in result.observations)
        for item in result.observations:
            span = item.trigger_spans[0]
            trigger = text[span.start_offset : span.end_offset]
            assert (
                span.normalized_length,
                span.normalized_span_sha256,
            ) == normalized_sensitive_fingerprint(trigger)

        no_context = request.model_copy(update={"context_keys": frozenset()})
        assert _engine(resolver, binding).evaluate(no_context).observations == ()
        for mode in ("quoted", "historical", "ambiguous"):
            changed = request.model_copy(
                update={"segments": (_segment(text, mode=mode),)}
            )
            assert _engine(resolver, binding).evaluate(changed).observations == ()
    finally:
        connection.close()


def test_negation_window_is_deterministic_and_not_a_single_classifier_score(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    connection, _, catalog, resolver, binding = persistent_risk_authority(
        repo_root, tmp_path
    )
    try:
        rule = catalog.rules[0]
        context = frozenset(rule.required_context)
        assert _is_negated("not SIGNAL-X", 4, 2) is True
        assert _is_negated("today SIGNAL-X", 6, 2) is False
        positive = _engine(resolver, binding).evaluate(
            RiskEvaluationInput(
                session_id=SESSION_ID,
                segments=(_segment(f"today {rule.pattern}"),),
                context_keys=context,
            )
        )
        assert positive.observations[0].confidence == 1.0
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("text", "category"),
    (
        ("我想自杀", "suicide_intent"),
        ("也许以后再说。现在我想自杀", "suicide_intent"),
        ("I want to kill myself", "suicide_intent"),
        ("我想伤害自己", "self_harm_intent"),
        ("I plan to hurt someone", "harm_other_intent"),
        ("他经常打我", "ongoing_interpersonal_violence"),
        ("He is going to kill me", "immediate_interpersonal_danger"),
    ),
)
def test_production_rules_create_only_counselor_visible_observations(
    repo_root: Path,
    tmp_path: Path,
    text: str,
    category: str,
) -> None:
    connection, _, _, resolver, binding = persistent_risk_authority(
        repo_root,
        tmp_path,
        suffix=33,
    )
    try:
        result = _engine(resolver, binding).evaluate(
            RiskEvaluationInput(
                session_id=SESSION_ID,
                segments=(_segment(text),),
                context_keys=frozenset(),
            )
        )
    finally:
        connection.close()

    assert len(result.observations) == 1
    observation = result.observations[0]
    assert observation.observation.category == category
    assert observation.observation.client_facing_visibility == "never"
    assert {source.source_kind for source in observation.sources} == {
        "deterministic_rule"
    }
    assert observation.confidence == 1.0


@pytest.mark.parametrize(
    "text",
    (
        '他说："我想自杀"。',
        "例如我想自杀可能会触发规则。",
        "也许我想自杀",
        "以前我想自杀",
        "我没有说我想自杀",
        "我想自杀？",
        "我想自杀是以前的事",
        'She said "I want to kill myself".',
        "She said 'I want to kill myself'.",
        "Maybe I want to kill myself",
        "Previously I want to kill myself",
        "I do not think I want to kill myself",
        "I want to kill myself?",
    ),
)
def test_production_literals_do_not_turn_qualified_text_into_certain_findings(
    repo_root: Path,
    tmp_path: Path,
    text: str,
) -> None:
    connection, _, _, resolver, binding = persistent_risk_authority(
        repo_root,
        tmp_path,
        suffix=34,
    )
    try:
        result = _engine(resolver, binding).evaluate(
            RiskEvaluationInput(
                session_id=SESSION_ID,
                segments=(_segment(text),),
                context_keys=frozenset(),
            )
        )
    finally:
        connection.close()

    assert result.observations == ()


def test_observation_identity_is_stable_across_engines_and_changes_with_inputs(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    connection, _, catalog, resolver, binding = persistent_risk_authority(
        repo_root,
        tmp_path,
        suffix=12,
    )
    first_clock = FixedClock(NOW)
    retry_clock = FixedClock(NOW + timedelta(hours=3))
    first_engine = RiskEngine(
        resolver,
        policy_binding=binding,
        clock=first_clock,
        id_factory=IdFactory(first_clock, lambda: 1),
    )
    retry_engine = RiskEngine(
        resolver,
        policy_binding=binding,
        clock=retry_clock,
        id_factory=IdFactory(retry_clock, lambda: (1 << 74) - 1),
    )
    general_rule = next(rule for rule in catalog.rules if rule.level == "general")
    request = RiskEvaluationInput(
        session_id=SESSION_ID,
        segments=(_segment(general_rule.pattern),),
        context_keys=frozenset(general_rule.required_context),
    )
    try:
        first = first_engine.evaluate(request).observations[0]
        retried = retry_engine.evaluate(request).observations[0]
        changed_span = retry_engine.evaluate(
            request.model_copy(
                update={"segments": (_segment(f"prefix {general_rule.pattern}"),)}
            )
        ).observations[0]
        changed_session = retry_engine.evaluate(
            request.model_copy(
                update={"session_id": "018f0000-0000-7000-8000-000000000103"}
            )
        ).observations[0]
        different_rules = retry_engine.evaluate(
            request.model_copy(
                update={
                    "segments": (
                        _segment("SYNTH-RISK-GENERAL-4C2E SYNTH-RISK-HIGH-7D1A"),
                    )
                }
            )
        ).observations
    finally:
        connection.close()

    assert first.observation.observation_id == retried.observation.observation_id
    assert first.observation.detected_at != retried.observation.detected_at
    assert changed_span.observation.observation_id != first.observation.observation_id
    assert (
        changed_session.observation.observation_id != first.observation.observation_id
    )
    assert len({item.observation.observation_id for item in different_rules}) == 2


def test_observation_identity_uses_canonical_trigger_span_order(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    connection, _, catalog, resolver, binding = persistent_risk_authority(
        repo_root,
        tmp_path,
        suffix=14,
    )
    rule = next(rule for rule in catalog.rules if rule.level == "general")
    first_segment = _segment(rule.pattern, suffix=31)
    second_segment = RiskTextSegment(
        turn_id="018f0000-0000-7000-8000-000000000104",
        content_ref=_ref("private_span", 32),
        text=rule.pattern,
    )
    forward = RiskEvaluationInput(
        session_id=SESSION_ID,
        segments=(first_segment, second_segment),
        context_keys=frozenset(rule.required_context),
    )
    reverse = forward.model_copy(update={"segments": tuple(reversed(forward.segments))})
    try:
        forward_record = _engine(resolver, binding).evaluate(forward).observations[0]
        reverse_record = _engine(resolver, binding).evaluate(reverse).observations[0]
    finally:
        connection.close()

    assert forward_record.observation.observation_id == (
        reverse_record.observation.observation_id
    )
    assert forward_record.trigger_spans == reverse_record.trigger_spans


def test_model_draft_may_support_or_add_review_but_cannot_change_rule_or_lifecycle(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    connection, _, catalog, resolver, binding = persistent_risk_authority(
        repo_root, tmp_path
    )
    rule = catalog.rules[0]
    segment = _segment(rule.pattern)
    draft = ModelRiskObservationDraft(
        rule_ref=rule.rule_ref,
        category=rule.category,
        level=rule.level,
        model_ref=_ref("model", 80),
        trigger_turn_id=segment.turn_id,
        trigger_content_ref=segment.content_ref,
        start_offset=0,
        end_offset=len(rule.pattern),
        span_sha256=hashlib.sha256(rule.pattern.encode()).hexdigest(),
        confidence=0.63,
        rationale_summary="Synthetic ambiguity requires counselor confirmation.",
    )
    result = _engine(resolver, binding).evaluate(
        RiskEvaluationInput(
            session_id=SESSION_ID,
            segments=(segment,),
            context_keys=frozenset({"synthetic_context_present"}),
            model_drafts=(draft,),
        )
    )
    assert len(result.observations) == 1
    assert {source.source_kind for source in result.observations[0].sources} == {
        "deterministic_rule",
        "model_observation",
    }
    assert result.observations[0].confidence == 1.0

    with pytest.raises(ValidationError):
        ModelRiskObservationDraft.model_validate(
            {**draft.model_dump(), "acknowledged_at": NOW}
        )
    with pytest.raises(RiskEvaluationError, match="MODEL_RISK_RULE_FIELDS_MISMATCH"):
        _engine(resolver, binding).evaluate(
            RiskEvaluationInput(
                session_id=SESSION_ID,
                segments=(segment,),
                context_keys=frozenset(),
                model_drafts=(
                    draft.model_copy(update={"category": "invented_category"}),
                ),
            )
        )

    ambiguous = _segment("SYNTH-AMBIGUOUS-9A", mode="ambiguous", suffix=21)
    ambiguous_draft = draft.model_copy(
        update={
            "trigger_content_ref": ambiguous.content_ref,
            "start_offset": 0,
            "end_offset": len(ambiguous.text),
            "span_sha256": hashlib.sha256(ambiguous.text.encode()).hexdigest(),
            "confidence": 0.58,
        }
    )
    model_only = _engine(resolver, binding).evaluate(
        RiskEvaluationInput(
            session_id=SESSION_ID,
            segments=(ambiguous,),
            context_keys=frozenset({"synthetic_context_present"}),
            model_drafts=(ambiguous_draft,),
        )
    )
    assert len(model_only.observations) == 1
    assert model_only.observations[0].confidence == 0.58
    assert {source.source_kind for source in model_only.observations[0].sources} == {
        "model_observation"
    }
    assert model_only.observations[0].observation.suggested_questions == (
        "SYNTH-QUESTION-GENERAL-VERIFY",
    )
    connection.close()


def test_engine_requires_persistent_exact_resolver_and_explicit_binding(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    connection, loaded, catalog, resolver, binding = persistent_risk_authority(
        repo_root, tmp_path, suffix=20
    )
    try:
        with pytest.raises(
            RiskRuleClosureError,
            match="RISK_RULE_PERSISTENT_RESOLVER_REQUIRED",
        ):
            RiskEngine(
                catalog,  # type: ignore[arg-type]
                policy_binding=binding,
            )

        forged_binding = binding.model_copy(
            update={
                "manifest_ref": binding.manifest_ref.model_copy(
                    update={"content_sha256": "f" * 64}
                )
            }
        )
        with pytest.raises(RiskRuleClosureError):
            resolver.resolve(forged_binding)

        restarted = PersistentRiskRuleCatalogResolver(
            connection,
            loaded,
            database_scope="global",
        )
        assert restarted.resolve(binding) == catalog

        next_binding = insert_approved_risk_policy_epoch(
            connection,
            loaded,
            epoch=2,
            suffix=40,
            retire_current=True,
        )
        assert next_binding.manifest_ref != binding.manifest_ref
        # The old explicit epoch remains resolvable and cannot be substituted by
        # whichever manifest is now current.
        assert restarted.resolve(binding) == catalog
        assert restarted.resolve(next_binding).policy_ref != catalog.policy_ref

        with pytest.raises(
            sqlite3.IntegrityError,
            match="approval execution transition invalid",
        ):
            connection.execute(
                """
                UPDATE approval_executions
                   SET state = 'CLAIMED',
                       applied_commit_version = NULL,
                       applied_at = NULL
                 WHERE operation_id = (
                     SELECT operation_id FROM runtime_epochs WHERE epoch = 2
                 )
                """
            )
        assert restarted.resolve(next_binding).policy_ref != catalog.policy_ref
    finally:
        connection.close()
