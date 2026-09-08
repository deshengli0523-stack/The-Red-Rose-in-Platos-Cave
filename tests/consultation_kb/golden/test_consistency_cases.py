from __future__ import annotations

from typing import Any

import pytest

from consultation_kb.generation.consistency import ConsistencyReviewer
from consultation_kb.models.consistency import ConclusionChangeRecord

from tests.consultation_kb.unit.p6_quality_support import object_id
from tests.consultation_kb.unit.test_consistency_review import (
    CURRENT_EVIDENCE,
    PREVIOUS_EVIDENCE,
    _change,
    _snapshot,
)


@pytest.mark.parametrize(
    ("left_update", "right_update", "expected_code"),
    [
        (
            {"fact_state": "affirmed"},
            {"fact_state": "denied"},
            "candidate_fact_conflict",
        ),
        (
            {"stance": "support"},
            {"stance": "oppose"},
            "candidate_core_position_conflict",
        ),
        (
            {"disposition": "pursue"},
            {"disposition": "avoid"},
            "candidate_action_conflict",
        ),
    ],
)
def test_candidate_fact_position_and_action_conflicts_are_blocking(
    left_update: dict[str, Any],
    right_update: dict[str, Any],
    expected_code: str,
) -> None:
    left = _snapshot("candidate_left", **left_update)
    right = _snapshot("candidate_right", **right_update)

    result = ConsistencyReviewer().review(current_candidates=(left, right))

    assert result.decision == "rewrite"
    matching = tuple(
        finding for finding in result.findings if finding.code == expected_code
    )
    assert matching
    assert all(finding.severity == "blocking" for finding in matching)


def test_conclusion_change_requires_and_accepts_bilateral_evidence() -> None:
    current = _snapshot("current", disposition="pursue")
    earlier = _snapshot(
        "earlier",
        source="session_earlier",
        disposition="avoid",
        evidence_id=PREVIOUS_EVIDENCE,
    )
    reviewer = ConsistencyReviewer()

    unexplained = reviewer.review(
        current_candidates=(current,),
        session_earlier=(earlier,),
    )
    assert unexplained.decision == "rewrite"
    assert "unexplained_conclusion_change" in {
        finding.code for finding in unexplained.findings
    }

    change = _change("relationship_change")
    explained = reviewer.review(
        current_candidates=(current,),
        session_earlier=(earlier,),
        conclusion_changes=(change,),
    )
    assert explained.decision == "pass"
    assert explained.findings == ()
    assert change.previous_evidence_ids == (PREVIOUS_EVIDENCE,)
    assert change.current_evidence_ids == (CURRENT_EVIDENCE,)
    assert change.old_conclusion
    assert change.new_information
    assert change.change_reason
    assert change.impact_on_advice
    assert change.impact_on_profile
    assert change.follow_up


def test_foreign_evidence_cannot_explain_a_conclusion_change() -> None:
    current = _snapshot("current", disposition="pursue")
    earlier = _snapshot(
        "earlier",
        source="session_earlier",
        disposition="avoid",
        evidence_id=PREVIOUS_EVIDENCE,
    )
    valid = _change("relationship_change")
    foreign = ConclusionChangeRecord.model_validate(
        {
            **valid.model_dump(mode="python"),
            "current_evidence_ids": (object_id("evidence", 999),),
        }
    )

    result = ConsistencyReviewer().review(
        current_candidates=(current,),
        session_earlier=(earlier,),
        conclusion_changes=(foreign,),
    )

    assert result.decision == "rewrite"
    assert "unexplained_conclusion_change" in {
        finding.code for finding in result.findings
    }
