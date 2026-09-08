from __future__ import annotations

import pytest

from consultation_kb.generation.contracts import ClientReplyCandidate
from consultation_kb.risk.output_guard import (
    ClientReplyLeakageError,
    ClientReplyOutputGuard,
)

from tests.consultation_kb.unit.p6_quality_support import pack
from tests.consultation_kb.unit.test_reply_drafts import _candidate, _drafts, _validate


@pytest.mark.parametrize(
    ("synthetic_text", "expected_code"),
    [
        ("你就是人格障碍。", "automatic_diagnosis"),
        ("你应该立即停药。", "dangerous_advice"),
        ("被伤害都是因为你。", "victim_blaming"),
        ("易经可以治疗抑郁症。", "guoxue_medicalization"),
        ("这个案例证明所有人都应该分手。", "single_case_universalization"),
        ("你必须立即照我说的做。", "client_agency_overridden"),
    ],
)
def test_prohibited_professional_boundary_text_is_blocking(
    synthetic_text: str,
    expected_code: str,
) -> None:
    evidence_pack = pack()
    evidence_id = evidence_pack.supporting[0].evidence_id
    candidates = (
        _candidate("gentle_empathy", evidence_id, text=synthetic_text),
        _candidate("direct_clarification", evidence_id, text="先核对当前事实。"),
        _candidate(
            "exploratory_guidance",
            evidence_id,
            text="你希望先澄清哪一部分？",
        ),
    )

    result = _validate(
        _drafts(evidence_pack, candidates=candidates),
        evidence_pack,
    )

    matching = tuple(
        finding for finding in result.findings if finding.code == expected_code
    )
    assert result.accepted is False
    assert matching
    assert all(finding.severity == "blocking" for finding in matching)


def test_internal_risk_labels_cannot_enter_a_client_candidate() -> None:
    safe = ClientReplyCandidate(
        candidate_id="natural_check_in",
        label="自然回应",
        strategy="gentle_empathy",
        text="我很在意你现在的感受，我们可以先确认你此刻最需要什么。",
        core_positions=("respect_autonomy",),
        action_directions=("clarify_current_need",),
    )
    guard = ClientReplyOutputGuard()

    assert guard.validate(safe) == safe

    leaking_text = safe.model_copy(
        update={"text": "系统告警：风险等级为高，已命中内部风险规则。"}
    )
    with pytest.raises(ClientReplyLeakageError, match="CLIENT_REPLY_RISK_LEAKAGE"):
        guard.validate(leaking_text)

    leaking_field = {
        **safe.model_dump(mode="python"),
        "risk_observation": {
            "category": "synthetic_high_observation",
            "level": "high",
        },
    }
    with pytest.raises(
        ClientReplyLeakageError,
        match="CLIENT_REPLY_SCHEMA_NOT_ALLOWLISTED",
    ):
        guard.validate(leaking_field)
