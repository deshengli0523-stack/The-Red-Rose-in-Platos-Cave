from __future__ import annotations

import itertools
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from consultation_kb.archive.bundles import ArchiveBundleService
from consultation_kb.archive.deidentification import Deidentifier
from consultation_kb.archive.private_record import (
    ActualTranscriptReader,
    PrivateArchiveDraftBuilder,
)
from consultation_kb.archive.profile_diff import ProfileDiffBuilder
from consultation_kb.archive.shared_candidate import SharedCaseCandidateBuilder
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import canonical_sha256, text_sha256
from consultation_kb.models.archive import PrivateArchiveAnalysis
from consultation_kb.models.cases import (
    PrivateActualCaseRecord,
    PrivateCaseSourceItem,
    SharedCaseSectionProposal,
    private_actual_case_record_payload,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.session.actual_replies import ActualReplyService
from consultation_kb.session.candidate_sets import CandidateSetService
from consultation_kb.session.repository import SessionRepository
from consultation_kb.session.turns import TurnService
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.unit.test_case_release_policy import (
    _authorization,
    _policy,
    _review,
)
from tests.consultation_kb.unit.test_profile_diff import (
    CLIENT_ID,
    SESSION_ID,
    TURN_ID,
    partner_change_request,
)
from tests.consultation_kb.private_archive_approval_support import (
    commit_private_archive_with_guard,
)


pytestmark = [
    pytest.mark.golden,
    pytest.mark.acceptance_id("ARCHIVE-01"),
]

NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
SECOND_TURN_ID = "018f0000-0000-7000-8000-000000000703"
FIRST_RUN_ID = "018f0000-0000-7000-8000-000000000704"
SECOND_RUN_ID = "018f0000-0000-7000-8000-000000000705"
UNSELECTED_REPLY = "直接断言对方一定不爱你，并要求立刻结束关系。"
UNKNOWN_REPLY_CANDIDATE = "这条候选回复发生在外部，实际发送内容无法确认。"
UNKNOWN_ALTERNATIVE = "另一条候选同样不能被当作已经发送的回复。"


def _repository(tmp_path: Path) -> tuple[sqlite3.Connection, SessionRepository]:
    connection = connect_database(tmp_path / "archive-01.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "client").apply()
    clock = FixedClock(NOW)
    values = itertools.count(100_000)
    repository = SessionRepository(
        connection,
        content_store=ContentStore(tmp_path / "client-scope"),
        clock=clock,
        id_factory=IdFactory(clock=clock, random_source=lambda: next(values)),
    )
    repository.create_session(
        session_id=SESSION_ID,
        client_id=CLIENT_ID,
        client_scope_hash="a" * 64,
        snapshot_version=7,
        snapshot_canonical_sha256="b" * 64,
        snapshot_bytes=b'{"profile":"before-session"}\n',
    )
    return connection, repository


def _record_session(repository: SessionRepository) -> None:
    turns = TurnService(repository)
    candidates = CandidateSetService(repository)
    actual = ActualReplyService(repository)

    turns.append(
        SESSION_ID,
        TURN_ID,
        "我已经结束上一段关系，现在有了新的伴侣，希望重新梳理沟通目标。",
    )
    turns.begin_generation(SESSION_ID, TURN_ID, run_id=FIRST_RUN_ID)
    first = candidates.store_and_await(
        SESSION_ID,
        TURN_ID,
        (
            "我们先确认你希望厘清的目标，再梳理哪些信息仍然有效。",
            UNSELECTED_REPLY,
        ),
        run_id=FIRST_RUN_ID,
        idempotency_key="archive-01-first-candidates",
    )
    actual.record_adopted(
        SESSION_ID,
        TURN_ID,
        first.candidates[0].candidate_id,
        sent_at=NOW,
        idempotency_key="archive-01-first-actual",
    )

    turns.append(
        SESSION_ID,
        SECOND_TURN_ID,
        "会谈末尾在外部继续了一小段，但无法确认咨询师实际发出的文字。",
    )
    turns.begin_generation(SESSION_ID, SECOND_TURN_ID, run_id=SECOND_RUN_ID)
    candidates.store_and_await(
        SESSION_ID,
        SECOND_TURN_ID,
        (UNKNOWN_REPLY_CANDIDATE, UNKNOWN_ALTERNATIVE),
        run_id=SECOND_RUN_ID,
        idempotency_key="archive-01-second-candidates",
    )
    actual.record_external_unknown(
        SESSION_ID,
        SECOND_TURN_ID,
        confirmed_at=NOW + timedelta(minutes=1),
        idempotency_key="archive-01-external-unknown",
    )


def _private_case_source(
    repository: SessionRepository,
    analysis: PrivateArchiveAnalysis,
) -> PrivateActualCaseRecord:
    transcript = ActualTranscriptReader(repository).snapshot(SESSION_ID)
    items: list[PrivateCaseSourceItem] = []
    for turn in transcript.turns:
        items.append(
            PrivateCaseSourceItem(
                source_ref=turn.client_message_ref,
                source_kind="client_message",
                content=turn.client_message_text,
                actual_recorded=True,
                selected_for_delivery=False,
            )
        )
        if turn.reply_text is not None:
            assert turn.actual_reply_ref is not None
            items.append(
                PrivateCaseSourceItem(
                    source_ref=turn.actual_reply_ref,
                    source_kind="actual_reply",
                    content=turn.reply_text,
                    actual_recorded=True,
                    selected_for_delivery=True,
                )
            )

    model_text = analysis.model_analysis[0]
    reflection_text = analysis.counselor_reflection[0]
    items.extend(
        (
            PrivateCaseSourceItem(
                source_ref=VersionRef(
                    object_id=repository.id_factory.object_id("model_analysis"),
                    version=1,
                    content_sha256=text_sha256(model_text),
                ),
                source_kind="model_analysis",
                content=model_text,
                actual_recorded=False,
                selected_for_delivery=False,
            ),
            PrivateCaseSourceItem(
                source_ref=VersionRef(
                    object_id=repository.id_factory.object_id("counselor_reflection"),
                    version=1,
                    content_sha256=text_sha256(reflection_text),
                ),
                source_kind="counselor_reflection",
                content=reflection_text,
                actual_recorded=False,
                selected_for_delivery=False,
            ),
        )
    )
    record_id = repository.id_factory.object_id("private_actual_record")
    members = tuple(items)
    record_ref = VersionRef(
        object_id=record_id,
        version=1,
        content_sha256=canonical_sha256(
            private_actual_case_record_payload(
                record_id=record_id,
                version=1,
                actual_transcript_ref=transcript.actual_transcript_ref,
                items=members,
                incomplete_evidence=True,
            )
        ),
    )
    return PrivateActualCaseRecord(
        record_ref=record_ref,
        actual_transcript_ref=transcript.actual_transcript_ref,
        items=members,
        incomplete_evidence=True,
    )


def _shared_proposals(
    source: PrivateActualCaseRecord,
) -> tuple[SharedCaseSectionProposal, ...]:
    messages = tuple(
        item.source_ref for item in source.items if item.source_kind == "client_message"
    )
    reply = next(
        item.source_ref for item in source.items if item.source_kind == "actual_reply"
    )
    model = next(
        item.source_ref for item in source.items if item.source_kind == "model_analysis"
    )
    reflection = next(
        item.source_ref
        for item in source.items
        if item.source_kind == "counselor_reflection"
    )
    return (
        SharedCaseSectionProposal(
            section_kind="factual_context",
            source_item_refs=messages,
            abstracted_text="来访者报告亲密关系状态改变，并希望重整当前沟通方向。",
        ),
        SharedCaseSectionProposal(
            section_kind="actual_response",
            source_item_refs=(reply,),
            abstracted_text="咨询师采用了分步澄清和有效信息复核的回应顺序。",
        ),
        SharedCaseSectionProposal(
            section_kind="model_analysis",
            source_item_refs=(model,),
            abstracted_text="关系转换可能影响既有判断，相关解释仍需后续验证。",
        ),
        SharedCaseSectionProposal(
            section_kind="counselor_reflection",
            source_item_refs=(reflection,),
            abstracted_text="后续应区分直接失效信息与需要人工复核的一般模式。",
        ),
    )


def test_archive_01_preserves_each_purpose_and_cleans_only_current_profile(
    tmp_path: Path,
) -> None:
    connection, repository = _repository(tmp_path)
    try:
        _record_session(repository)
        bundle = ArchiveBundleService(repository).propose(SESSION_ID)
        transcript = ActualTranscriptReader(repository).snapshot(SESSION_ID)
        analysis = PrivateArchiveAnalysis(
            key_events=("来访者报告伴侣关系发生变化",),
            actual_interventions=("咨询师实际进行了目标澄清",),
            client_responses=("来访者确认需要清理失效资料",),
            model_analysis=("旧关系中的部分解释可能已经失效，但仍需区分直接与间接影响。",),
            counselor_reflection=("一般沟通模式不能因伴侣变化被自动删除，应留待人工复核。",),
        )
        draft = PrivateArchiveDraftBuilder(repository).build(
            SESSION_ID,
            analysis=analysis,
        )
        _private_decision, private_publication, _private_replay = (
            commit_private_archive_with_guard(repository, draft)
        )

        assert private_publication.purpose_state.state == "ACTIVE"
        assert bundle.incomplete_evidence is True
        assert [item.evidence_gap for item in transcript.turns] == [False, True]
        assert [item.reply_text for item in transcript.turns] == [
            "我们先确认你希望厘清的目标，再梳理哪些信息仍然有效。",
            None,
        ]
        assert UNSELECTED_REPLY not in transcript.canonical_text
        assert UNKNOWN_REPLY_CANDIDATE not in transcript.canonical_text
        assert UNKNOWN_ALTERNATIVE not in transcript.canonical_text
        assert UNSELECTED_REPLY not in private_publication.draft.canonical_text
        assert UNKNOWN_REPLY_CANDIDATE not in private_publication.draft.canonical_text
        assert UNKNOWN_ALTERNATIVE not in private_publication.draft.canonical_text
        assert private_publication.draft.analysis == analysis

        request = partner_change_request().model_copy(
            update={
                "archive_bundle_id": bundle.bundle_id,
                "session_actual": transcript,
            }
        )
        profile_diff = ProfileDiffBuilder().build(request)
        operations = {item.mutation.operation for item in profile_diff.operations}
        assert operations == {
            "ADD",
            "CONFIRM",
            "CORRECT",
            "SUPERSEDE",
            "RESOLVE",
            "MERGE",
        }
        assert set(profile_diff.current_view_removed_fact_ids) == {
            "fact_current_partner",
            "fact_duplicate_one",
            "fact_duplicate_two",
            "fact_resolved_issue",
            "fact_weekend_arrangement",
        }
        assert {item.fact_id for item in profile_diff.direct_impacts} == {
            "fact_weekend_arrangement"
        }
        assert {item.fact_id for item in profile_diff.indirect_reviews} == {
            "fact_communication_pattern"
        }
        assert "event_communication_pattern" not in (
            profile_diff.current_view_removed_event_ids
        )
        assert "fact_resolved_issue" not in (
            profile_diff.projected_profile.minimum_next_session_summary.unresolved_issue_fact_ids
        )
        assert {
            item.fact_id for item in profile_diff.projected_profile.preferences
        } == {"fact_confirmed_preference", "fact_merged_preference"}
        assert profile_diff.base_session_sha256 == (
            transcript.actual_transcript_ref.content_sha256
        )

        source = _private_case_source(repository, analysis)
        built = SharedCaseCandidateBuilder(
            id_factory=repository.id_factory,
            deidentifier=Deidentifier(
                span_hash_key=b"archive-01-deidentifier-test-key!!"
            ),
        ).build(
            source,
            _shared_proposals(source),
            contributor_client_hash="a" * 64,
            provenance_ref=VersionRef(
                object_id=repository.id_factory.object_id("case_provenance"),
                version=1,
                content_sha256="c" * 64,
            ),
            derivation_rule_ref=VersionRef(
                object_id=repository.id_factory.object_id("policy"),
                version=1,
                content_sha256="d" * 64,
            ),
            requested_allowed_uses=frozenset({"answer_support"}),
            created_at=NOW,
            actual_transcript=transcript,
        )
        authorization = _authorization(
            repository.id_factory,
            reuse=False,
            contributor_client_hash="a" * 64,
        )
        review = _review(repository.id_factory, built.candidate)
        release = _policy(repository.id_factory).evaluate(
            built.candidate,
            authorization,
            review,
            purpose="answer_support",
            at=NOW + timedelta(minutes=2),
        )

        shared_json = built.candidate.model_dump_json()
        assert release.outcome == "private_only"
        assert {"reuse_not_authorized", "incomplete_evidence"}.issubset(
            release.reasons
        )
        assert CLIENT_ID not in shared_json
        assert SESSION_ID not in shared_json
        assert UNSELECTED_REPLY not in shared_json
        assert UNKNOWN_REPLY_CANDIDATE not in shared_json
        assert UNKNOWN_ALTERNATIVE not in shared_json
        assert all(item.content not in shared_json for item in source.items)
        assert connection.execute("SELECT count(*) FROM outbox_events").fetchone() == (
            0,
        )
        current = ArchiveBundleService(repository).get(bundle.bundle_id)
        assert current.state_for("private_archive").state == "ACTIVE"
        assert current.state_for("profile_diff").state == "DRAFT"
        assert current.state_for("shared_case").state == "DRAFT"
    finally:
        connection.close()
