from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from consultation_kb.generation.contracts import (
    ClientReplyCandidate,
    CounselorInternalAnalysis,
    FinalTurnBundle,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.risk import InternalRiskObservation
from consultation_kb.risk.output_guard import (
    ClientReplyLeakageError,
    ClientReplyOutputGuard,
)
from consultation_kb.risk.projection import RiskResponseProjector


def _ref(kind: str, suffix: int) -> VersionRef:
    return VersionRef(
        object_id=f"{kind}_018f0000-0000-7000-8000-{suffix:012x}",
        version=1,
        content_sha256=f"{suffix % 16:x}" * 64,
    )


@pytest.mark.acceptance_id("RISK-01")
def test_risk_01_internal_reminder_is_persistent_but_client_schema_has_zero_labels() -> None:
    observation = InternalRiskObservation(
        observation_id="risk_observation_018f0000-0000-7000-8000-000000000501",
        category="synthetic_high_observation",
        level="high",
        trigger_turn_ids=("018f0000-0000-7000-8000-000000000502",),
        rule_ref=_ref("risk_rule", 1),
        detected_at=datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc),
        suggested_questions=("SYNTH-QUESTION-HIGH-VERIFY",),
    )
    goals = RiskResponseProjector.to_client_goals((observation,))
    assert "check_immediate_safety" in goals.goals
    assert "invite_real_world_support" in goals.goals
    assert observation.client_facing_visibility == "never"

    natural = ClientReplyCandidate(
        candidate_id="natural_safety_check",
        label="自然确认",
        strategy="gentle_empathy",
        text="我很在意你此刻的处境。你现在是否安全？身边有没有可以联系并陪伴你的人？",
        core_positions=("respect_autonomy",),
        action_directions=("check_immediate_safety", "invite_real_world_support"),
    )
    assert ClientReplyOutputGuard().validate(natural) == natural
    assert set(FinalTurnBundle.model_fields) == {
        "envelope",
        "evidence_pack_sha256",
        "counselor_internal",
        "client_reply_candidates",
        "follow_up_guidance",
        "evidence_quality",
    }
    assert "risk_observations" in CounselorInternalAnalysis.model_fields
    assert all("risk" not in field for field in ClientReplyCandidate.model_fields)

    with pytest.raises(ValidationError):
        ClientReplyCandidate.model_validate(
            {**natural.model_dump(), "internal_observation": observation.model_dump()}
        )
    with pytest.raises(ClientReplyLeakageError):
        ClientReplyOutputGuard().validate(
            natural.model_copy(update={"text": "系统告警：风险等级为高。"})
        )
