from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.anchors import locator_policy_ref
from consultation_kb.knowledge.extractors import ExtractedBlock
from consultation_kb.knowledge.passages import PassageSegmenter
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import EvidenceLocator, Provenance


NOW = datetime(2026, 7, 18, 8, 0, tzinfo=timezone.utc)


def _ids() -> IdFactory:
    counter = iter(range(500, 1000))
    return IdFactory(FixedClock(NOW), lambda: next(counter))


def _source(ids: IdFactory, version: int, digit: str) -> VersionRef:
    if not hasattr(_source, "source_id"):
        _source.source_id = ids.object_id("source")  # type: ignore[attr-defined]
    return VersionRef(
        object_id=_source.source_id,  # type: ignore[attr-defined]
        version=version,
        content_sha256=digit * 64,
    )


def _block(
    source_ref: VersionRef, text: str, *, path: str, line: int
) -> ExtractedBlock:
    return ExtractedBlock(
        text=text,
        document_type="md",
        extractor_version="test-v1",
        structural_path=path,
        locator=EvidenceLocator(
            locator_kind="source_line_span",
            anchor_refs=(source_ref,),
            display_locator=f"lines:{line}-{line}",
            locator_policy_ref=locator_policy_ref(),
        ),
    )


def test_passage_id_is_stable_across_text_version_but_hash_changes() -> None:
    ids = _ids()
    first_source = _source(ids, 1, "1")
    second_source = _source(ids, 2, "2")
    first = PassageSegmenter(
        logical_source_id=first_source.object_id, source_ref=first_source
    ).segment("md", [_block(first_source, "原段落", path="chapter-1/line-1", line=1)])[0]
    second = PassageSegmenter(
        logical_source_id=second_source.object_id, source_ref=second_source
    ).segment("md", [_block(second_source, "修改后的段落", path="chapter-1/line-1", line=1)])[0]

    assert second.passage_id == first.passage_id
    assert second.version == 2
    assert second.normalized_text_sha256 != first.normalized_text_sha256


def test_adjacent_context_changes_do_not_change_atomic_passage_identity() -> None:
    ids = _ids()
    source1 = _source(ids, 1, "3")
    source2 = _source(ids, 2, "4")
    blocks1 = (
        _block(source1, "前文一", path="chapter/line-1", line=1),
        _block(source1, "原子正文", path="chapter/line-2", line=2),
        _block(source1, "后文一", path="chapter/line-3", line=3),
    )
    blocks2 = (
        _block(source2, "前文二", path="chapter/line-1", line=1),
        _block(source2, "原子正文", path="chapter/line-2", line=2),
        _block(source2, "后文二", path="chapter/line-3", line=3),
    )
    first = PassageSegmenter(
        logical_source_id=source1.object_id, source_ref=source1
    ).segment("md", blocks1)[1]
    second = PassageSegmenter(
        logical_source_id=source2.object_id, source_ref=source2
    ).segment("md", blocks2)[1]
    assert second.passage_id == first.passage_id
    assert second.normalized_text_sha256 == first.normalized_text_sha256
    assert second.context_before_ref != first.context_before_ref


def test_structural_path_change_creates_new_passage_id() -> None:
    ids = _ids()
    source = _source(ids, 1, "5")
    segmenter = PassageSegmenter(logical_source_id=source.object_id, source_ref=source)
    first = segmenter.segment(
        "md", [_block(source, "相同正文", path="chapter-a/line-1", line=1)]
    )[0]
    second = segmenter.segment(
        "md", [_block(source, "相同正文", path="chapter-b/line-1", line=1)]
    )[0]
    assert first.passage_id != second.passage_id


def test_page_pairs_support_cross_page_and_reject_reverse() -> None:
    ids = _ids()
    ref = _source(ids, 1, "6")
    locator = EvidenceLocator(
        locator_kind="source_page_span",
        anchor_refs=(ref,),
        display_locator="pages:1:3-2:1",
        locator_policy_ref=locator_policy_ref(),
    )
    assert locator.display_locator == "pages:1:3-2:1"
    with pytest.raises(ValidationError):
        EvidenceLocator(
            locator_kind="source_page_span",
            anchor_refs=(ref,),
            display_locator="pages:2:1-1:3",
            locator_policy_ref=locator_policy_ref(),
        )


def test_separate_dialogue_blocks_are_never_joined() -> None:
    ids = _ids()
    source = _source(ids, 1, "7")
    records = PassageSegmenter(
        logical_source_id=source.object_id, source_ref=source
    ).segment(
        "md",
        (
            _block(source, "来访者：第一轮", path="session/turn-1", line=1),
            _block(source, "咨询师：第二轮", path="session/turn-2", line=2),
        ),
        privacy_scope="private",
        provenance=Provenance(
            client_ids=frozenset({"client_" + "a" * 12}),
            provenance_scope="client_private",
            private_owner_client_id="client_" + "a" * 12,
            derivation_rule_ref=locator_policy_ref(),
        ),
    )
    assert len(records) == 2
    assert all(record.privacy_scope == "private" for record in records)
