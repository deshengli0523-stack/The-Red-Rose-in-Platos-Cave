from __future__ import annotations

import pytest

from consultation_kb.mcp.session_runtime import SessionRuntimeManager


@pytest.mark.parametrize(
    "relationship_term",
    (
        "男朋友",
        "女朋友",
        "配偶",
        "丈夫",
        "妻子",
        "恋人",
        "对象",
        "前任",
    ),
)
def test_relationship_terms_map_to_closed_history_category(
    relationship_term: str,
) -> None:
    assert (
        SessionRuntimeManager._history_category(
            f"请查找与{relationship_term}有关的历史变化"
        )
        == "relationship_history"
    )
