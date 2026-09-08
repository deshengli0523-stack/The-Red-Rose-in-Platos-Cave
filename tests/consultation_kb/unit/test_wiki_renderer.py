from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.wiki_renderer import REQUIRED_SECTION_KEYS, WikiRenderer
from consultation_kb.models.common import VersionRef
from consultation_kb.models.wiki import (
    WikiRelationship,
    WikiRevision,
    WikiSection,
)


NOW = datetime(2026, 7, 18, 8, 0, tzinfo=timezone.utc)


def _revision() -> WikiRevision:
    counter = iter(range(1, 1000))
    ids = IdFactory(FixedClock(NOW), lambda: next(counter))
    claim = VersionRef(
        object_id=ids.object_id("claim"), version=1, content_sha256="1" * 64
    )
    passage = VersionRef(
        object_id=ids.object_id("passage"), version=1, content_sha256="2" * 64
    )
    source = VersionRef(
        object_id=ids.object_id("source"), version=1, content_sha256="3" * 64
    )
    sections = tuple(
        WikiSection(
            key=key,
            heading=key,
            body=f"{key} 合成内容",
            claim_refs=(claim,),
            passage_refs=(passage,),
        )
        for key in sorted(REQUIRED_SECTION_KEYS)
    )
    return WikiRevision(
        wiki_id=ids.object_id("wiki"),
        revision=1,
        slug="wu-wei-and-acceptance",
        title="无为与接纳的边界",
        base_revision=0,
        diff_kind="add",
        sections=sections,
        theory_revision_refs=(),
        relationships=(
            WikiRelationship(
                target_id=ids.object_id("concept"),
                relationship="ANALOGOUS_TO",
                scope=("cultural_interpretation",),
                source_refs=(source,),
                reviewed=True,
            ),
        ),
        review_due_at=None,
        unresolved_questions=("仍需外部实证复核",),
        body_sha256="4" * 64,
        diff_sha256="5" * 64,
        status="prepared",
        approval_request_id=ids.object_id("approval_request"),
        created_at=NOW,
    )


def test_renderer_emits_complete_page_contract_and_source_anchors() -> None:
    rendered = WikiRenderer().render(_revision())
    for key in REQUIRED_SECTION_KEYS:
        assert f"## {key}" in rendered
    assert "主张：[claim_" in rendered
    assert "原文锚点：[passage_" in rendered
    assert "ANALOGOUS_TO" in rendered
    assert "未解决问题" in rendered


@pytest.mark.parametrize("forbidden", ["EQUIVALENT", "CAUSES"])
def test_traditional_relationship_cannot_be_equivalence_or_causation(
    forbidden: str,
) -> None:
    values = _revision().relationships[0].model_dump()
    values["relationship"] = forbidden
    with pytest.raises(ValidationError):
        WikiRelationship(**values)


def test_formal_wiki_does_not_import_graphify_wiki_export() -> None:
    import consultation_kb.knowledge.wiki as module

    assert "graphify.wiki" not in module.__dict__
