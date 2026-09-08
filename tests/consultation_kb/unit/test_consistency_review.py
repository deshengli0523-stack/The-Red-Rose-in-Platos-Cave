from __future__ import annotations

import pytest
from pydantic import ValidationError

from consultation_kb.generation.consistency import ConsistencyReviewer
from consultation_kb.models.consistency import (
    ActionDirection,
    ConclusionChangeRecord,
    ConsistencySnapshot,
    CorePosition,
    FactPosition,
)

from tests.consultation_kb.unit.p6_quality_support import object_id


CURRENT_EVIDENCE = object_id("evidence", 1)
PREVIOUS_EVIDENCE = object_id("evidence", 2)


def _snapshot(
    key: str,
    *,
    source: str = "current_candidate",
    fact_state: str = "affirmed",
    stance: str = "support",
    disposition: str = "explore",
    conclusion: str = "先澄清事实，再决定行动。",
    evidence_id: str = CURRENT_EVIDENCE,
) -> ConsistencySnapshot:
    return ConsistencySnapshot(
        snapshot_key=key,
        source=source,
        facts=(
            FactPosition(
                fact_key="relationship_changed",
                state=fact_state,
                evidence_ids=(evidence_id,),
            ),
        ),
        core_positions=(
            CorePosition(position_key="clarify_before_deciding", stance=stance),
        ),
        action_directions=(
            ActionDirection(
                action_key="relationship_change",
                disposition=disposition,
            ),
        ),
        conclusion=conclusion,
        conclusion_evidence_ids=(evidence_id,),
    )


def _change(subject_key: str) -> ConclusionChangeRecord:
    return ConclusionChangeRecord(
        subject_key=subject_key,
        old_conclusion="此前建议先维持原行动。",
        new_information="本轮出现了新的关系变化事实。",
        change_reason="新证据改变了原结论的事实前提。",
        impact_on_advice="行动方向改为先探索变化。",
        impact_on_profile="将变化记录为当前信息，旧信息转为历史。",
        follow_up="后续核对变化是否持续。",
        previous_evidence_ids=(PREVIOUS_EVIDENCE,),
        current_evidence_ids=(CURRENT_EVIDENCE,),
    )


def test_style_and_order_difference_is_allowed_when_structured_core_matches() -> None:
    gentle = _snapshot("gentle_candidate", conclusion="我理解这很难受，我们先澄清。")
    direct = _snapshot("direct_candidate", conclusion="先澄清，再行动。")

    result = ConsistencyReviewer().review(current_candidates=(gentle, direct))

    assert result.decision == "pass"
    assert not result.findings


def test_candidate_omitting_a_structured_axis_is_blocking() -> None:
    complete = _snapshot("complete")
    omitted = _snapshot("omitted").model_copy(update={"action_directions": ()})

    result = ConsistencyReviewer().review(current_candidates=(complete, omitted))

    assert result.decision == "rewrite"
    assert result.findings[0].code == "candidate_action_conflict"


@pytest.mark.parametrize(
    ("left", "right", "code"),
    [
        (
            _snapshot("fact_yes", fact_state="affirmed"),
            _snapshot("fact_no", fact_state="denied"),
            "candidate_fact_conflict",
        ),
        (
            _snapshot("position_yes", stance="support"),
            _snapshot("position_no", stance="oppose"),
            "candidate_core_position_conflict",
        ),
        (
            _snapshot("break_up_now", disposition="pursue"),
            _snapshot("relationship_no_change", disposition="avoid"),
            "candidate_action_conflict",
        ),
    ],
)
def test_candidate_fact_core_and_action_opposites_are_blocking(
    left: ConsistencySnapshot,
    right: ConsistencySnapshot,
    code: str,
) -> None:
    result = ConsistencyReviewer().review(current_candidates=(left, right))

    assert result.decision == "rewrite"
    assert code in {item.code for item in result.findings}
    assert all(item.severity == "blocking" for item in result.findings)


def test_cross_turn_conclusion_change_requires_full_explanation() -> None:
    current = _snapshot("current", disposition="pursue")
    earlier = _snapshot(
        "earlier",
        source="session_earlier",
        disposition="avoid",
        evidence_id=PREVIOUS_EVIDENCE,
    )

    result = ConsistencyReviewer().review(
        current_candidates=(current,),
        session_earlier=(earlier,),
    )

    assert result.decision == "rewrite"
    assert result.findings[0].code == "unexplained_conclusion_change"
    assert result.findings[0].subject_key == "relationship_change"


def test_cross_turn_added_action_axis_requires_change_record() -> None:
    current = _snapshot("current")
    earlier = _snapshot("earlier", source="session_earlier").model_copy(
        update={"action_directions": ()}
    )

    result = ConsistencyReviewer().review(
        current_candidates=(current,),
        session_earlier=(earlier,),
    )

    assert result.decision == "rewrite"
    assert result.findings[0].subject_key == "relationship_change"


def test_auditable_new_evidence_explains_cross_turn_change() -> None:
    current = _snapshot("current", disposition="pursue")
    earlier = _snapshot(
        "profile",
        source="client_profile",
        disposition="avoid",
        evidence_id=PREVIOUS_EVIDENCE,
    )

    result = ConsistencyReviewer().review(
        current_candidates=(current,),
        client_profiles=(earlier,),
        conclusion_changes=(_change("relationship_change"),),
    )

    assert result.decision == "pass"
    assert result.conclusion_changes[0].old_conclusion
    assert result.conclusion_changes[0].new_information
    assert result.conclusion_changes[0].change_reason
    assert result.conclusion_changes[0].impact_on_advice
    assert result.conclusion_changes[0].impact_on_profile
    assert result.conclusion_changes[0].follow_up


def test_change_record_must_bind_current_evidence() -> None:
    with pytest.raises(ValidationError, match="requires current evidence"):
        ConclusionChangeRecord(
            subject_key="relationship_change",
            old_conclusion="旧结论。",
            new_information="新信息。",
            change_reason="变化原因。",
            impact_on_advice="建议影响。",
            impact_on_profile="资料影响。",
            follow_up="后续核对。",
            previous_evidence_ids=(PREVIOUS_EVIDENCE,),
            current_evidence_ids=(),
        )


def test_change_record_must_bind_previous_evidence() -> None:
    with pytest.raises(ValidationError, match="requires previous evidence"):
        ConclusionChangeRecord(
            subject_key="relationship_change",
            old_conclusion="旧结论。",
            new_information="新信息。",
            change_reason="变化原因。",
            impact_on_advice="建议影响。",
            impact_on_profile="资料影响。",
            follow_up="后续核对。",
            previous_evidence_ids=(),
            current_evidence_ids=(CURRENT_EVIDENCE,),
        )


def test_retry_is_bounded_and_exhaustion_requires_counselor_judgment() -> None:
    left = _snapshot("break_up_now", disposition="pursue")
    right = _snapshot("relationship_no_change", disposition="avoid")

    exhausted = ConsistencyReviewer().review(
        current_candidates=(left, right),
        retry_count=2,
    )

    assert exhausted.decision == "needs_counselor_judgment"
    with pytest.raises(ValueError, match="between zero and two"):
        ConsistencyReviewer().review(
            current_candidates=(left, right),
            retry_count=3,
        )
