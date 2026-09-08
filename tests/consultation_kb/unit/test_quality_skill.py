from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SKILL_PATH = REPO_ROOT / ".agents" / "skills" / "quality-evaluator" / "SKILL.md"


def _text() -> str:
    return SKILL_PATH.read_text(encoding="utf-8")


def _normalized() -> str:
    return re.sub(r"\s+", " ", _text()).strip().lower()


def test_quality_evaluator_skill_is_on_demand_and_has_exact_flow() -> None:
    raw = _text()
    match = re.match(r"\A---\n(?P<body>.*?)\n---(?:\n|\Z)", raw, re.DOTALL)
    assert match is not None
    fields = dict(
        line.partition(":")[::2]
        for line in match.group("body").splitlines()
        if ":" in line
    )
    assert fields["name"].strip() == "quality-evaluator"
    description = fields["description"].strip()
    assert description.startswith("Use on demand when ")
    assert "evaluation" in description.lower()

    text = _normalized()
    flow = raw.lower().split("## 执行流程", 1)[1].split("\n## ", 1)[0]
    ordered = (
        "doctor",
        "frozen",
        "`prepare_evaluation`",
        "`get_next_evaluation_case`",
        "`submit_evaluation_result`",
        "`finalize_evaluation`",
        "deterministic",
        "blind",
        "report",
    )
    positions = [flow.index(item) for item in ordered]
    assert positions == sorted(positions)

    assert "openai api" in text and "不得" in text
    assert "queue_order_seed" in text and "generation_seed" in text
    assert "temperature" in text and "host_unknown_fields" in text
    assert "跨 variant" in text and "evidencepack" in text and "不得" in text
    assert "missing reasons" in text and "incomplete" in text
    assert "内部风险标签" in text and "盲评包" in text
    assert "client id" in text and "正文" in text


def test_quality_evaluator_skill_closes_observed_pressure_loopholes() -> None:
    text = _normalized()
    assert "不得跳过 doctor" in text
    assert "版本冻结" in text and "不得跳过" in text
    assert "一半" in text and "成功" in text and "不得" in text
    assert "时间压力" in text and "不能" in text
