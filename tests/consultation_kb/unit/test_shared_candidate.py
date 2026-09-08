from __future__ import annotations

from datetime import datetime, timezone
import json

import pytest

from consultation_kb.archive.deidentification import Deidentifier
from consultation_kb.archive.shared_candidate import SharedCaseCandidateBuilder
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import canonical_sha256, text_sha256
from consultation_kb.models.archive import (
    ActualTranscript,
    ActualTranscriptTurn,
    actual_transcript_payload,
)
from consultation_kb.models.cases import (
    PrivateActualCaseRecord,
    PrivateCaseSourceItem,
    SharedCaseSectionProposal,
    private_actual_case_record_payload,
)
from consultation_kb.models.common import VersionRef


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)


def _ids() -> IdFactory:
    counter = iter(range(100, 5000))
    return IdFactory(FixedClock(NOW), lambda: next(counter))


def _ref(ids: IdFactory, kind: str, content: str) -> VersionRef:
    return VersionRef(
        object_id=ids.object_id(kind),
        version=1,
        content_sha256=text_sha256(content),
    )


def _actual_transcript_ref(
    ids: IdFactory,
    *,
    session_id: str,
    turns: tuple[ActualTranscriptTurn, ...],
    incomplete_evidence: bool,
) -> VersionRef:
    payload = actual_transcript_payload(
        session_id=session_id,
        turns=turns,
        incomplete_evidence=incomplete_evidence,
        captured_at=NOW,
    )
    canonical_text = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return VersionRef(
        object_id=ids.object_id("actual_transcript"),
        version=1,
        content_sha256=text_sha256(canonical_text),
    )


def _private_record_ref(
    ids: IdFactory,
    *,
    actual_transcript_ref: VersionRef,
    items: tuple[PrivateCaseSourceItem, ...],
    incomplete_evidence: bool,
    object_id: str | None = None,
) -> VersionRef:
    record_id = object_id or ids.object_id("private_actual_record")
    payload = private_actual_case_record_payload(
        record_id=record_id,
        version=1,
        actual_transcript_ref=actual_transcript_ref,
        items=items,
        incomplete_evidence=incomplete_evidence,
    )
    return VersionRef(
        object_id=record_id,
        version=1,
        content_sha256=canonical_sha256(payload),
    )


def _source(ids: IdFactory) -> tuple[PrivateActualCaseRecord, ActualTranscript]:
    client_message = "我叫张三，手机是13800138000，最近和男朋友反复争吵。"
    actual_reply = "我先确认她最希望改变的部分，再和她一起梳理边界。"
    analysis = "可能存在通过反复确认来缓解关系不安的循环，但仍是假设。"
    reflection = "本轮节奏偏快，下次先确认来访者是否愿意继续讨论边界。"
    items = (
        PrivateCaseSourceItem(
            source_ref=_ref(ids, "client_turn", client_message),
            source_kind="client_message",
            content=client_message,
            actual_recorded=True,
            selected_for_delivery=False,
        ),
        PrivateCaseSourceItem(
            source_ref=_ref(ids, "actual_reply", actual_reply),
            source_kind="actual_reply",
            content=actual_reply,
            actual_recorded=True,
            selected_for_delivery=True,
        ),
        PrivateCaseSourceItem(
            source_ref=_ref(ids, "model_analysis", analysis),
            source_kind="model_analysis",
            content=analysis,
            actual_recorded=False,
            selected_for_delivery=False,
        ),
        PrivateCaseSourceItem(
            source_ref=_ref(ids, "counselor_reflection", reflection),
            source_kind="counselor_reflection",
            content=reflection,
            actual_recorded=False,
            selected_for_delivery=False,
        ),
    )
    session_id = ids.uuid7()
    transcript_turn = ActualTranscriptTurn(
        ordinal=1,
        turn_id=ids.uuid7(),
        client_message_ref=items[0].source_ref,
        client_message_text=client_message,
        actual_reply_ref=items[1].source_ref,
        reply_text=actual_reply,
        reply_source_type="adopted",
        evidence_gap=False,
    )
    transcript_ref = _actual_transcript_ref(
        ids,
        session_id=session_id,
        turns=(transcript_turn,),
        incomplete_evidence=False,
    )
    authority = ActualTranscript(
        actual_transcript_ref=transcript_ref,
        session_id=session_id,
        turns=(transcript_turn,),
        incomplete_evidence=False,
        captured_at=NOW,
    )
    source = PrivateActualCaseRecord(
        record_ref=_private_record_ref(
            ids,
            actual_transcript_ref=transcript_ref,
            items=items,
            incomplete_evidence=False,
        ),
        actual_transcript_ref=transcript_ref,
        items=items,
        incomplete_evidence=False,
    )
    return source, authority


def _proposals(source: PrivateActualCaseRecord) -> tuple[SharedCaseSectionProposal, ...]:
    by_kind = {item.source_kind: item.source_ref for item in source.items}
    return (
        SharedCaseSectionProposal(
            section_kind="factual_context",
            source_item_refs=(by_kind["client_message"],),
            abstracted_text=(
                "来访者报告亲密关系冲突反复出现，姓名：张三需要进一步泛化，"
                "内部标识client_" + "aaaaaaaaaaaa也必须移除。"
            ),
        ),
        SharedCaseSectionProposal(
            section_kind="actual_response",
            source_item_refs=(by_kind["actual_reply"],),
            abstracted_text="咨询师采用目标澄清与边界梳理的顺序回应。",
        ),
        SharedCaseSectionProposal(
            section_kind="model_analysis",
            source_item_refs=(by_kind["model_analysis"],),
            abstracted_text="关系冲突可能受确认需求影响，此解释仍需后续验证。",
        ),
        SharedCaseSectionProposal(
            section_kind="counselor_reflection",
            source_item_refs=(by_kind["counselor_reflection"],),
            abstracted_text="后续宜放慢推进速度，并先征得讨论边界议题的同意。",
        ),
    )


def _builder(ids: IdFactory) -> SharedCaseCandidateBuilder:
    return SharedCaseCandidateBuilder(
        id_factory=ids,
        deidentifier=Deidentifier(
            span_hash_key=b"synthetic-test-key-32-bytes-long!!"
        ),
    )


def test_builder_keeps_sections_typed_and_emits_no_source_identity_or_verbatim() -> None:
    ids = _ids()
    source, authority = _source(ids)

    result = _builder(ids).build(
        source,
        _proposals(source),
        contributor_client_hash="a" * 64,
        provenance_ref=VersionRef(
            object_id=ids.object_id("case_provenance"),
            version=1,
            content_sha256="3" * 64,
        ),
        derivation_rule_ref=VersionRef(
            object_id=ids.object_id("policy"),
            version=1,
            content_sha256="4" * 64,
        ),
        requested_allowed_uses=frozenset({"answer_support"}),
        created_at=NOW,
        actual_transcript=authority,
    )

    assert [item.section_kind for item in result.candidate.sections] == [
        "factual_context",
        "actual_response",
        "model_analysis",
        "counselor_reflection",
    ]
    serialized = result.model_dump_json()
    assert "张三" not in serialized
    assert "13800138000" not in serialized
    assert "client_" + "aaaaaaaaaaaa" not in serialized
    assert source.record_ref.object_id not in serialized
    assert source.actual_transcript_ref.object_id not in serialized
    for item in source.items:
        assert item.source_ref.object_id not in serialized
        assert item.content not in serialized
    assert all(item.content_form == "abstracted_summary" for item in result.candidate.sections)
    assert all(item.no_verbatim_source for item in result.candidate.sections)
    assert result.candidate.source_grade == "K1"


def test_builder_rejects_verbatim_source_even_when_direct_identifiers_could_be_removed() -> None:
    ids = _ids()
    source, authority = _source(ids)
    client_item = next(item for item in source.items if item.source_kind == "client_message")
    proposal = SharedCaseSectionProposal(
        section_kind="factual_context",
        source_item_refs=(client_item.source_ref,),
        abstracted_text=client_item.content,
    )

    with pytest.raises(ValueError, match="verbatim source"):
        _builder(ids).build(
            source,
            (proposal,),
            contributor_client_hash="a" * 64,
            provenance_ref=VersionRef(
                object_id=ids.object_id("case_provenance"),
                version=1,
                content_sha256="3" * 64,
            ),
            derivation_rule_ref=VersionRef(
                object_id=ids.object_id("policy"),
                version=1,
                content_sha256="4" * 64,
            ),
            requested_allowed_uses=frozenset({"answer_support"}),
            created_at=NOW,
            actual_transcript=authority,
        )


def test_actual_response_cannot_be_sourced_from_model_analysis() -> None:
    ids = _ids()
    source, authority = _source(ids)
    analysis = next(item for item in source.items if item.source_kind == "model_analysis")
    proposal = SharedCaseSectionProposal(
        section_kind="actual_response",
        source_item_refs=(analysis.source_ref,),
        abstracted_text="咨询师采用了目标澄清。",
    )

    with pytest.raises(ValueError, match="crosses the actual"):
        _builder(ids).build(
            source,
            (proposal,),
            contributor_client_hash="a" * 64,
            provenance_ref=VersionRef(
                object_id=ids.object_id("case_provenance"),
                version=1,
                content_sha256="3" * 64,
            ),
            derivation_rule_ref=VersionRef(
                object_id=ids.object_id("policy"),
                version=1,
                content_sha256="4" * 64,
            ),
            requested_allowed_uses=frozenset({"answer_support"}),
            created_at=NOW,
            actual_transcript=authority,
        )


def test_unselected_reply_cannot_be_constructed_as_actual_source() -> None:
    ids = _ids()
    content = "候选但没有实际发送的回复"

    with pytest.raises(ValueError, match="selected for delivery"):
        PrivateCaseSourceItem(
            source_ref=_ref(ids, "actual_reply", content),
            source_kind="actual_reply",
            content=content,
            actual_recorded=True,
            selected_for_delivery=False,
        )


def test_unselected_reply_reference_cannot_be_relabelled_as_analysis() -> None:
    ids = _ids()
    content = "候选但没有实际发送的回复"

    with pytest.raises(ValueError, match="governed reference"):
        PrivateCaseSourceItem(
            source_ref=_ref(ids, "reply_candidate", content),
            source_kind="model_analysis",
            content=content,
            actual_recorded=False,
            selected_for_delivery=False,
        )


def test_candidate_source_requires_an_actual_transcript_authority_reference() -> None:
    ids = _ids()
    source, _authority = _source(ids)
    invalid_transcript_ref = VersionRef(
        object_id=ids.object_id("reply_candidate"),
        version=1,
        content_sha256="2" * 64,
    )

    with pytest.raises(ValueError, match="ActualTranscript"):
        source.model_copy(
            update={
                "record_ref": _private_record_ref(
                    ids,
                    actual_transcript_ref=invalid_transcript_ref,
                    items=source.items,
                    incomplete_evidence=source.incomplete_evidence,
                    object_id=source.record_ref.object_id,
                ),
                "actual_transcript_ref": invalid_transcript_ref,
            }
        )


def test_private_actual_record_ref_binds_exact_source_items() -> None:
    ids = _ids()
    source, _authority = _source(ids)
    replacement = "伪造但未实际发送的回复"
    mutated_reply = source.items[1].model_copy(
        update={
            "content": replacement,
            "source_ref": _ref(ids, "actual_reply", replacement),
        }
    )

    with pytest.raises(ValueError, match="private actual record canonical hash mismatch"):
        source.model_copy(
            update={"items": (source.items[0], mutated_reply, *source.items[2:])}
        )


def test_builder_requires_exact_actual_transcript_authority() -> None:
    ids = _ids()
    source, _authority = _source(ids)

    with pytest.raises(ValueError, match="exact ActualTranscript authority"):
        _builder(ids).build(
            source,
            _proposals(source),
            contributor_client_hash="a" * 64,
            provenance_ref=VersionRef(
                object_id=ids.object_id("case_provenance"),
                version=1,
                content_sha256="3" * 64,
            ),
            derivation_rule_ref=VersionRef(
                object_id=ids.object_id("policy"),
                version=1,
                content_sha256="4" * 64,
            ),
            requested_allowed_uses=frozenset({"answer_support"}),
            created_at=NOW,
        )


def test_builder_rejects_forged_actual_reply_outside_transcript() -> None:
    ids = _ids()
    source, authority = _source(ids)
    replacement = "伪造但未实际发送的回复"
    forged_reply = source.items[1].model_copy(
        update={
            "content": replacement,
            "source_ref": _ref(ids, "actual_reply", replacement),
        }
    )
    forged_items = (source.items[0], forged_reply, *source.items[2:])
    forged_source = source.model_copy(
        update={
            "record_ref": _private_record_ref(
                ids,
                actual_transcript_ref=source.actual_transcript_ref,
                items=forged_items,
                incomplete_evidence=False,
                object_id=source.record_ref.object_id,
            ),
            "items": forged_items,
        }
    )

    with pytest.raises(ValueError, match="does not exactly match ActualTranscript"):
        _builder(ids).build(
            forged_source,
            _proposals(forged_source),
            contributor_client_hash="a" * 64,
            provenance_ref=VersionRef(
                object_id=ids.object_id("case_provenance"),
                version=1,
                content_sha256="3" * 64,
            ),
            derivation_rule_ref=VersionRef(
                object_id=ids.object_id("policy"),
                version=1,
                content_sha256="4" * 64,
            ),
            requested_allowed_uses=frozenset({"answer_support"}),
            created_at=NOW,
            actual_transcript=authority,
        )


def test_builder_rejects_cross_transcript_authority() -> None:
    ids = _ids()
    source, _authority = _source(ids)
    _other_source, other_authority = _source(ids)

    with pytest.raises(ValueError, match="exact ActualTranscript reference"):
        _builder(ids).build(
            source,
            _proposals(source),
            contributor_client_hash="a" * 64,
            provenance_ref=VersionRef(
                object_id=ids.object_id("case_provenance"),
                version=1,
                content_sha256="3" * 64,
            ),
            derivation_rule_ref=VersionRef(
                object_id=ids.object_id("policy"),
                version=1,
                content_sha256="4" * 64,
            ),
            requested_allowed_uses=frozenset({"answer_support"}),
            created_at=NOW,
            actual_transcript=other_authority,
        )
