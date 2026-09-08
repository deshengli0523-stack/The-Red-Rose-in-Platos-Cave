from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
AGENTS_PATH = REPO_ROOT / "AGENTS.md"
CONSULTATION_SKILL_PATH = (
    REPO_ROOT / ".agents" / "skills" / "consultation-session" / "SKILL.md"
)
CURATOR_SKILL_PATH = (
    REPO_ROOT / ".agents" / "skills" / "knowledge-curator" / "SKILL.md"
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _normalized(path: Path) -> str:
    return re.sub(r"\s+", " ", _read(path)).strip().lower()


def _frontmatter(path: Path) -> dict[str, str]:
    text = _read(path)
    match = re.match(r"\A---\n(?P<body>.*?)\n---(?:\n|\Z)", text, re.DOTALL)
    assert match is not None, f"missing YAML frontmatter: {path}"
    fields: dict[str, str] = {}
    for line in match.group("body").splitlines():
        key, separator, value = line.partition(":")
        assert separator, f"invalid frontmatter line: {line!r}"
        fields[key.strip()] = value.strip()
    return fields


def _assert_privacy_boundary(text: str) -> None:
    assert "粘贴到 codex 前" in text
    assert "不能撤回" in text or "无法撤回" in text
    assert "git" in text
    assert "memory" in text
    assert "chronicle" in text


def test_root_agents_locks_project_security_and_consultation_invariants() -> None:
    text = _normalized(AGENTS_PATH)

    assert "一个 codex task" in text
    assert "一个 client" in text
    assert "永久绑定" in text
    assert "不得读取其他客户" in text
    assert "来源客户" in text and "排除" in text
    assert "profile" in text and "只读" in text
    assert "候选回复不是实际回复" in text
    assert "external_reply_unknown" in text
    assert "下一条来访者消息" in text
    assert "精确 diff" in text and "一次性" in text and "本地批准" in text
    assert "模型输出" in text and "证据" in text
    assert "一致性检查" in text and "前后矛盾" in text
    assert "git" in text and "memory" in text and "chronicle" in text
    assert "风险标签" in text and "仅供咨询师内部" in text
    assert "superpowers" in text and "全部 skill" in text and "按需调用" in text
    assert "每轮" in text and "自动" in text and "不得" in text


def test_consultation_skill_is_on_demand_and_uses_exact_p6_flow() -> None:
    fields = _frontmatter(CONSULTATION_SKILL_PATH)
    assert fields["name"] == "consultation-session"
    assert fields["description"].startswith("Use on demand when ")
    description = fields["description"].lower()
    for trigger in ("start", "continue", "resume", "end", "adopt"):
        assert trigger in description

    raw = _read(CONSULTATION_SKILL_PATH).lower()
    text = _normalized(CONSULTATION_SKILL_PATH)
    for phrase in ("开始咨询", "继续咨询", "恢复咨询", "结束咨询", "采用版本"):
        assert phrase in text
    for tool in (
        "load_client_context",
        "append_session_turn",
        "append_temporary_fact",
        "submit_generation_stage",
        "get_generation_state",
        "acknowledge_risk_observation",
        "record_actual_reply",
    ):
        assert f"`{tool}`" in text
    assert "`store_candidate_set`" not in text

    flow = raw.split("## 每轮流程", 1)[1].split("\n## ", 1)[0]
    ordered_flow = (
        "`append_session_turn`",
        "确定性内部风险",
        "`append_temporary_fact`",
        "query binding",
        "`query_plan`",
        "retrieval_status=ready",
        "evidencepack",
        "`conceptualization`",
        "`theory_comparison`",
        "`reply_drafts`",
        "`evidence_audit`",
        "`consistency_risk_review`",
        "`final_bundle`",
        "咨询师选择",
        "`record_actual_reply`",
    )
    positions = [flow.index(value) for value in ordered_flow]
    assert positions == sorted(positions)
    assert "2–3" in flow or "2-3" in flow

    assert "retrieve_more" in flow
    assert "rewrite" in flow
    assert "最多 2 次" in flow
    assert "修改上游" in flow
    assert "needs_counselor_judgment" in flow
    assert "不得伪造确定性" in flow

    p6_tools = raw.split("## p6 mcp 工具边界", 1)[1].split("\n## ", 1)[0]
    listed_tools = re.findall(
        r"^- `([a-z][a-z0-9_]*)`\s*$",
        p6_tools,
        flags=re.MULTILINE,
    )
    assert set(listed_tools) == {
        "submit_generation_stage",
        "get_generation_state",
        "acknowledge_risk_observation",
    }
    assert len(listed_tools) == 3
    assert "上一轮" in text and "先关闭" in text
    assert "active session" in text
    assert "任何新的来访者正文" in text
    assert "都视为“继续咨询”" in text
    assert "不得因正文没有命令词而跳过" in text
    assert "候选回复不是实际回复" in text
    assert "external_reply_unknown" in text
    assert "内部分析" in text
    assert "2–3" in text or "2-3" in text
    assert "引导建议" in text
    assert "依据与一致性" in text
    assert "风险标签" in text and "来访者文本" in text
    assert "默认无引用" in text
    assert "c1" in text and "最高框架" in text
    assert "事实硬约束" in text and "不得覆盖" in text
    assert "多代理" in text and "安全边界" in text and "不得" in text
    assert "profile" in text and "只读" in text
    assert "临时事实" in text and "正式事实" in text
    assert "来源客户" in text and "排除" in text
    _assert_privacy_boundary(text)


def test_knowledge_curator_skill_requires_exact_local_approval_chain() -> None:
    fields = _frontmatter(CURATOR_SKILL_PATH)
    assert fields["name"] == "knowledge-curator"
    assert fields["description"].startswith("Use on demand when ")
    description = fields["description"].lower()
    for trigger in ("curate", "review", "publish", "c1"):
        assert trigger in description

    text = _normalized(CURATOR_SKILL_PATH)
    sequence = (
        "list_source_inbox",
        "register_source_draft",
        "extract_passages",
        "approve_passage",
        "propose_claims",
        "preview_claim_review",
        "approve_claim",
        "propose_wiki_update",
        "preview_wiki_update",
        "publish_wiki",
        "knowledge_lint",
    )
    positions = [text.index(f"`{tool}`") for tool in sequence]
    assert positions == sorted(positions)
    assert "固定本地 source inbox" in text
    assert "任意文件路径" in text and "不得" in text
    assert "自动联网" in text and "不得" in text
    assert "propose_theory_revision" in text
    assert "approve_theory_revision" in text
    assert "c1" in text and "正式本地批准" in text
    assert "start_rebuild" in text and "p8" in text and "不得" in text
    assert "精确 diff" in text and "一次性" in text and "本地批准" in text
    assert "模型" in text and "批准" in text
    _assert_privacy_boundary(text)
