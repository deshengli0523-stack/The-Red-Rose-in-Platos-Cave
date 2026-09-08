from __future__ import annotations

import os
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import BaseModel

from consultation_kb.archive.private_record import ActualTranscriptReader
from consultation_kb.archive.profile_diff import (
    ProfileDiffBuildInput,
    ProfileMutationCandidate,
)
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.facts import AddMutation, FactEvent, canonical_json
from consultation_kb.models.session import CandidateDraft
from consultation_kb.archive.provenance import CaseContributorHasher
from consultation_kb.archive.case_catalog import CaseCatalog
from consultation_kb.archive.case_publisher import SharedCasePublisher
from consultation_kb.archive.publication_proof import (
    LocalHmacCasePublicationProofSigner,
)
from consultation_kb.security.scope_broker import ScopedSession
from consultation_kb.security.scoped_worker import ScopeDenied, ScopedWorkerBroker
from consultation_kb.security.worker_protocol import (
    ArchiveContentRef,
    AppendClientTurnRequest,
    AppendTemporaryFactRequest,
    AppendTemporaryFactResponse,
    BeginGenerationRequest,
    BeginSessionRequest,
    BuildPrivateArchiveRequest,
    BuildPrivateArchiveResponse,
    BuildProfileDiffRequest,
    BuildProfileDiffResponse,
    CommitPrivateArchiveRequest,
    CommitPrivateArchiveResponse,
    CommitProfileUpdateRequest,
    CommitProfileUpdateResponse,
    RecordActualReplyRequest,
    ResumeSessionRequest,
    ResumeSessionResponse,
    StageSharedCaseOutboxRequest,
    StageSharedCaseOutboxResponse,
    StoreCandidateSetRequest,
    StoreCandidateSetResponse,
    decode_request,
    encode_message,
)
from consultation_kb.storage.connection import connect_database
from consultation_kb.client.bitemporal import BitemporalFactQuery, FactQuery
from consultation_kb.client.profile import ProfileMaterializer
from consultation_kb.session.repository import SessionRepository
from consultation_kb.storage.client_ledger import FactEventRepository
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.integration.test_session_worker_boundary import (
    RISK_AUTHORITY,
    _build_harness,
    _FixedClock,
    _request_id,
)
from tests.consultation_kb.approval_support import build_approval_harness


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows scoped subprocess"),
]


class _LostAckService:
    def __init__(self, service: object) -> None:
        self._service = service

    def verify_ticket(self, *args: object, **kwargs: object) -> object:
        return self._service.verify_ticket(*args, **kwargs)  # type: ignore[attr-defined]

    def acknowledge(self, _proof: object) -> object:
        raise RuntimeError("simulated archive approval ACK loss")


def _property_names(schema: object) -> set[str]:
    names: set[str] = set()
    if isinstance(schema, dict):
        properties = schema.get("properties")
        if isinstance(properties, dict):
            names.update(str(key) for key in properties)
        for value in schema.values():
            names.update(_property_names(value))
    elif isinstance(schema, list):
        for value in schema:
            names.update(_property_names(value))
    return names


def test_archive_requests_have_no_scope_path_or_sql_selector() -> None:
    models: tuple[type[BaseModel], ...] = (
        BuildPrivateArchiveRequest,
        CommitPrivateArchiveRequest,
        BuildProfileDiffRequest,
        CommitProfileUpdateRequest,
        StageSharedCaseOutboxRequest,
    )
    for model in models:
        assert _property_names(model.model_json_schema()).isdisjoint(
            {"client", "client_id", "path", "root", "sql"}
        )
        assert model.model_config["frozen"] is True


def test_archive_protocol_round_trip_carries_only_handle_and_exact_refs() -> None:
    request = BuildProfileDiffRequest(
        request_id="018f0000-0000-7000-8000-000000000901",
        session_handle="opaque-session-handle",
        build_input_ref=ArchiveContentRef(
            object_id="profile_diff_build_input_018f0000-0000-7000-8000-000000000902",
            version=1,
            content_sha256="a" * 64,
            size_bytes=128,
        ),
    )
    frame = encode_message(request)
    assert decode_request(frame) == request
    assert b"client_id" not in frame and b"path" not in frame and b"sql" not in frame


def test_real_subprocess_builds_private_archive_only_inside_bound_scope(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    worker = harness.worker()
    client_b_before = {
        path.relative_to(harness.client_b_root): path.read_bytes()
        for path in harness.client_b_root.rglob("*")
        if path.is_file()
    }
    try:
        worker.start()
        assert worker._process is not None
        assert getattr(worker._process, "pid", None) != os.getpid()
        worker.call(
            BeginSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                capability_epoch=1,
            )
        )
        turn_id = harness.ids.uuid7()
        worker.call(
            AppendClientTurnRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                client_message="来访者本轮实际表达",
                risk_authority=RISK_AUTHORITY,
            )
        )
        run_id = harness.ids.uuid7()
        worker.call(
            BeginGenerationRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                run_id=run_id,
            )
        )
        candidates = worker.call(
            StoreCandidateSetRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                run_id=run_id,
                idempotency_key="archive-worker-candidates",
                candidates=(
                    CandidateDraft(label="采用", text="咨询师实际采用的回复"),
                    CandidateDraft(label="未采用", text="不得进入实际归档的候选"),
                ),
            )
        )
        assert isinstance(candidates, StoreCandidateSetResponse)
        worker.call(
            RecordActualReplyRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                idempotency_key="archive-worker-actual",
                mode="adopted",
                candidate_id=candidates.candidate_ids[0],
                sent_at=datetime(2026, 7, 19, 4, 5, tzinfo=timezone.utc),
            )
        )
        response = worker.call(
            BuildPrivateArchiveRequest(
                request_id=_request_id(harness),
                session_handle=harness.token,
            )
        )
        assert isinstance(response, BuildPrivateArchiveResponse)
        assert response.private_archive_state == "DRAFT"
        assert response.actual_transcript_ref.object_id.startswith(
            "actual_transcript_"
        )
        assert response.draft_ref.object_id.startswith("private_archive_draft_")

        client = connect_database(
            harness.client_a_root / "client.sqlite3",
            "reader",
        )
        try:
            assert client.execute(
                "SELECT session_id FROM archive_bundles WHERE bundle_id = ?",
                (response.bundle_id,),
            ).fetchone() == (harness.session_id,)
            assert client.execute(
                "SELECT count(*) FROM archive_purpose_states WHERE bundle_id = ?",
                (response.bundle_id,),
            ).fetchone() == (3,)
        finally:
            client.close()
        assert any((harness.client_a_root / "cas").rglob("*"))
        client_b_after = {
            path.relative_to(harness.client_b_root): path.read_bytes()
            for path in harness.client_b_root.rglob("*")
            if path.is_file()
        }
        assert client_b_after == client_b_before
    finally:
        worker.close()
        harness.close()


def test_real_subprocess_consumes_approval_once_and_recovers_case_publish(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path / "scope")
    harness.global_connection.execute(
        "UPDATE capabilities SET permissions_json = ? WHERE session_id = ?",
        (
            '["client_read","draft_write","session_append"]',
            harness.session_id,
        ),
    )
    archive_token = harness.token
    def new_broker() -> ScopedWorkerBroker:
        return ScopedWorkerBroker.for_scoped_session(
            session=harness.scope,
            capability_token=archive_token,
            capability_service=harness.capability_service,
            target_execution_attestor_secret=b"t" * 32,
            target_execution_attestor_id="test-target-writer",
            startup_timeout_seconds=10.0,
            call_timeout_seconds=10.0,
        )

    broker = new_broker()
    approval = None
    try:
        broker.start()
        broker.call(
            BeginSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                capability_epoch=1,
            )
        )
        turn_id = harness.ids.uuid7()
        broker.call(
            AppendClientTurnRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                client_message="用于私有归档批准边界的实际消息",
                risk_authority=RISK_AUTHORITY,
            )
        )
        temporary_fact = broker.call(
            AppendTemporaryFactRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                idempotency_key="profile-recovery-temporary-fact",
                event_kind="ADD",
                cognitive_type="client_statement",
                value={"goal": "build_stable_communication"},
            )
        )
        assert isinstance(temporary_fact, AppendTemporaryFactResponse)
        run_id = harness.ids.uuid7()
        broker.call(
            BeginGenerationRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                run_id=run_id,
            )
        )
        candidates = broker.call(
            StoreCandidateSetRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                run_id=run_id,
                idempotency_key="private-approval-candidates",
                candidates=(
                    CandidateDraft(label="实际", text="实际采用回复"),
                    CandidateDraft(label="未采用", text="未采用回复"),
                ),
            )
        )
        assert isinstance(candidates, StoreCandidateSetResponse)
        broker.call(
            RecordActualReplyRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                idempotency_key="private-approval-actual",
                mode="adopted",
                candidate_id=candidates.candidate_ids[0],
                sent_at=datetime(2026, 7, 19, 4, 6, tzinfo=timezone.utc),
            )
        )
        built = broker.call(
            BuildPrivateArchiveRequest(
                request_id=_request_id(harness),
                session_handle=archive_token,
            )
        )
        assert isinstance(built, BuildPrivateArchiveResponse)
        marker_sha = hashlib.sha256(
            (harness.client_a_root / ".scope-id").read_bytes()
        ).hexdigest()
        (tmp_path / "approval").mkdir()
        approval = build_approval_harness(
            tmp_path / "approval",
            target_scope_hash=marker_sha,
        )
        approval.clock.value = datetime.now(timezone.utc)
        descriptor = DraftDescriptor(
            purpose="private_archive_publish",
            target_id=built.draft_ref.object_id,
            client_id=harness.client_a,
            base_version=built.base_version,
            draft_sha256=built.draft_ref.content_sha256,
            session_id=harness.session_id,
        )
        approval_request = approval.service.request(
            descriptor,
            diff_object_ref=built.review_diff_ref,
        )
        approval.service.confirm(
            approval.signer.confirm(
                approval.service.challenge_for_review(approval_request.request_id)
            )
        )
        operation_id = approval.operation_id()
        ticket = approval.service.issue_for_execution(
            approval_request.request_id,
            descriptor,
            operation_id=operation_id,
        )

        commit_request = CommitPrivateArchiveRequest(
            request_id=_request_id(harness),
            session_handle=archive_token,
            bundle_id=built.bundle_id,
            draft_ref=built.draft_ref,
            base_version=built.base_version,
            approval_operation_id=ticket.operation_id,
            approval_request_id=ticket.request_id,
        )
        frame = encode_message(commit_request)
        assert b"client_id" not in frame and b"path" not in frame and b"sql" not in frame

        # Simulate control-side ticket binding followed by a crash before the
        # target handler starts.  The real worker must return sealed exact
        # NOT_APPLIED without closing the channel; only then may normal commit
        # run once.
        assert (
            broker.recover_applied_archive_operation(
                commit_request,
                ticket=ticket,
                approval_service=approval.service,
            )
            is None
        )
        before_target = connect_database(
            harness.client_a_root / "client.sqlite3",
            "reader",
        )
        try:
            assert before_target.execute(
                "SELECT count(*) FROM approval_executions WHERE operation_id = ?",
                (ticket.operation_id,),
            ).fetchone() == (0,)
        finally:
            before_target.close()
        with pytest.raises(ScopeDenied, match="SCOPE_DENIED"):
            broker.execute_approved_archive_operation(
                commit_request,
                ticket=ticket,
                approval_service=_LostAckService(approval.service),  # type: ignore[arg-type]
            )
        assert approval.service.get(ticket.request_id).state == "confirmed"
        broker.close()
        broker = new_broker()
        broker.start()
        committed = broker.recover_applied_archive_operation(
            commit_request,
            ticket=ticket,
            approval_service=approval.service,
        )
        assert isinstance(committed, CommitPrivateArchiveResponse)
        assert committed.bundle_id == built.bundle_id
        assert committed.state == "ACTIVE"

        client = connect_database(harness.client_a_root / "client.sqlite3", "reader")
        try:
            assert client.execute(
                "SELECT state FROM archive_purpose_states WHERE bundle_id = ? "
                "AND purpose = 'private_archive'",
                (built.bundle_id,),
            ).fetchone() == ("ACTIVE",)
            assert client.execute(
                "SELECT state FROM archive_purpose_states WHERE bundle_id = ? "
                "AND purpose = 'profile_diff'",
                (built.bundle_id,),
            ).fetchone() == ("DRAFT",)
            assert client.execute(
                "SELECT state FROM archive_purpose_states WHERE bundle_id = ? "
                "AND purpose = 'shared_case'",
                (built.bundle_id,),
            ).fetchone() == ("DRAFT",)
            assert client.execute(
                "SELECT request_id, state, applied_commit_version "
                "FROM approval_executions WHERE operation_id = ?",
                (ticket.operation_id,),
            ).fetchone() == (
                ticket.request_id,
                "APPLIED",
                committed.applied_commit_version,
            )
            assert client.execute(
                "SELECT count(*) FROM private_archive_revisions "
                "WHERE bundle_id = ? AND draft_sha256 = ?",
                (built.bundle_id, built.draft_ref.content_sha256),
            ).fetchone() == (1,)
            private_attestation = client.execute(
                "SELECT a.approval_draft_sha256, a.closure_sha256 "
                "FROM private_archive_revisions AS r "
                "JOIN artifact_manifests AS m "
                "ON m.manifest_id = r.manifest_id "
                "JOIN publication_closure_attestations AS a "
                "ON a.operation_id = m.operation_id "
                "WHERE r.bundle_id = ? AND r.draft_sha256 = ?",
                (built.bundle_id, built.draft_ref.content_sha256),
            ).fetchone()
            assert private_attestation is not None
            assert private_attestation[0] == ticket.descriptor.draft_sha256
            assert len(private_attestation[1]) == 64
        finally:
            client.close()
        assert approval.service.get(ticket.request_id).state == "acknowledged"

        # Build one exact profile ADD from the fixed actual transcript and the
        # real temporary ledger.  The future operation ID is fixed up front so
        # the projected snapshot is byte-for-byte the one publication will
        # materialize.
        profile_published_at = datetime.now(timezone.utc)
        profile_operation_id = approval.operation_id()
        profile_connection = connect_database(
            harness.client_a_root / "client.sqlite3",
            "writer",
        )
        try:
            profile_connection.execute(
                "UPDATE client_fact_authority SET client_id = ? "
                "WHERE singleton = 1 AND client_id IS NULL",
                (harness.client_a,),
            )
            session_repository = SessionRepository(
                profile_connection,
                content_store=ContentStore(harness.client_a_root / "cas"),
                clock=_FixedClock(),
                id_factory=harness.ids,
            )
            profile_query = FactQuery(
                effective_at=profile_published_at,
                known_at=profile_published_at,
                fixed_epoch=1,
            )
            base_snapshot = BitemporalFactQuery(
                FactEventRepository(profile_connection)
            ).snapshot(profile_query)
            base_profile = ProfileMaterializer().build(base_snapshot)
            profile_event = FactEvent(
                event_id=harness.ids.object_id("fact_event"),
                fact_id=harness.ids.object_id("fact"),
                client_id=harness.client_a,
                event_version=1,
                mutation_type="ADD",
                canonical_key="client|goal|stable-communication",
                subject="client",
                predicate="goal",
                object_json=canonical_json(
                    {"goal": "build_stable_communication"}
                ),
                cognitive_type="client_statement",
                source_kind="session_statement",
                source_session_id=harness.session_id,
                source_turn_id=turn_id,
                source_ref=None,
                effective_from=profile_published_at,
                effective_to=None,
                time_precision="instant",
                timezone_name="Asia/Shanghai",
                recorded_at=profile_published_at,
                approved_at=profile_published_at,
                reported_at=profile_published_at,
                observed_at=None,
                transaction_id=profile_operation_id,
                commit_version=1,
                publication_operation_id=profile_operation_id,
                visible_runtime_epoch=1,
                review_status="approved",
                validity_status="active",
                resolution_status="open",
                epistemic_status="asserted",
                fact_confidence=0.95,
                model_confidence=None,
                reviewer_id="counselor-profile-review",
                review_reason="actual client statement approved for profile",
                review_source="primary_counselor",
                privacy_level="private_client",
                allowed_purposes_json=canonical_json(
                    ["client_history", "next_session_context"]
                ),
                applicability_json=canonical_json(
                    {"scope": "client_private"}
                ),
                source_anchor_json=canonical_json({"turn_id": turn_id}),
                supersedes_event_id=None,
                previous_event_id=None,
                replacement_event_id=None,
                source_event_ids=(),
                relation_type=None,
            )
            projected_snapshot = BitemporalFactQuery.snapshot_events(
                (profile_event,),
                profile_query,
                client_commit_version=1,
            )
            projected_profile = ProfileMaterializer().build(
                projected_snapshot
            )
            transcript = ActualTranscriptReader(session_repository).snapshot(
                harness.session_id
            )
            temporary_ledger = session_repository.list_temporary_facts(
                harness.session_id
            )
            assert len(temporary_ledger) == 1
            build_input = ProfileDiffBuildInput(
                diff_id=harness.ids.object_id("profile_diff"),
                archive_bundle_id=built.bundle_id,
                client_id=harness.client_a,
                session_actual=transcript,
                temporary_ledger=temporary_ledger,
                base_profile=base_profile,
                projected_profile=projected_profile,
                candidates=(
                    ProfileMutationCandidate(
                        operation_id="profile-add-stable-communication-goal",
                        ordinal=1,
                        mutation=AddMutation(new_fact=profile_event),
                        old_value_json=canonical_json(None),
                        new_value_json=profile_event.object_json,
                        source_temporary_event_id=temporary_fact.event_id,
                        source_content_sha256=(
                            temporary_fact.content_sha256
                        ),
                        source_turn_id=turn_id,
                        source_reason="actual session goal statement",
                        evidence_origin="actual_client_statement",
                        cognitive_type="client_statement",
                        confidence=0.95,
                    ),
                ),
            )
            build_input_body = (
                json.dumps(
                    build_input.model_dump(mode="json"),
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            stored_build_input = session_repository.store_json(
                build_input_body,
                kind="profile_diff_build_input",
            )
            build_input_ref = ArchiveContentRef(
                object_id=stored_build_input.object_id,
                version=1,
                content_sha256=stored_build_input.content_sha256,
                media_type=stored_build_input.media_type,
                size_bytes=stored_build_input.size_bytes,
            )
        finally:
            profile_connection.close()

        built_profile = broker.call(
            BuildProfileDiffRequest(
                request_id=_request_id(harness),
                session_handle=archive_token,
                action="BUILD",
                build_input_ref=build_input_ref,
            )
        )
        assert isinstance(built_profile, BuildProfileDiffResponse)
        prepared_profile = broker.call(
            BuildProfileDiffRequest(
                request_id=_request_id(harness),
                session_handle=archive_token,
                action="PREPARE_APPROVAL",
                draft_ref=built_profile.draft_ref,
                selected_operation_ids=built_profile.operation_ids,
            )
        )
        assert isinstance(prepared_profile, BuildProfileDiffResponse)
        assert prepared_profile.approval_draft_sha256 is not None
        assert prepared_profile.approval_diff_ref is not None
        profile_descriptor = DraftDescriptor(
            purpose="profile_update",
            target_id=prepared_profile.diff_id,
            client_id=harness.client_a,
            base_version=prepared_profile.base_client_commit_version,
            draft_sha256=prepared_profile.approval_draft_sha256,
            session_id=harness.session_id,
        )
        approval.clock.value = profile_published_at
        profile_approval = approval.service.request(
            profile_descriptor,
            diff_object_ref=prepared_profile.approval_diff_ref,
        )
        approval.service.confirm(
            approval.signer.confirm(
                approval.service.challenge_for_review(
                    profile_approval.request_id
                )
            )
        )
        profile_ticket = approval.service.issue_for_execution(
            profile_approval.request_id,
            profile_descriptor,
            operation_id=profile_operation_id,
        )
        profile_commit = CommitProfileUpdateRequest(
            request_id=_request_id(harness),
            session_handle=archive_token,
            bundle_id=built.bundle_id,
            draft_ref=prepared_profile.draft_ref,
            selected_operation_ids=prepared_profile.operation_ids,
            approval_operation_id=profile_ticket.operation_id,
            approval_request_id=profile_ticket.request_id,
            expected_runtime_epoch=1,
            publication_timestamp=profile_published_at,
        )
        with pytest.raises(ScopeDenied, match="SCOPE_DENIED"):
            broker.execute_approved_archive_operation(
                profile_commit,
                ticket=profile_ticket,
                approval_service=_LostAckService(approval.service),  # type: ignore[arg-type]
            )
        assert (
            approval.service.get(profile_ticket.request_id).state
            == "confirmed"
        )
        broker.close()
        broker = new_broker()
        broker.start()
        committed_profile = broker.recover_applied_archive_operation(
            profile_commit,
            ticket=profile_ticket,
            approval_service=approval.service,
        )
        assert isinstance(committed_profile, CommitProfileUpdateResponse)
        assert committed_profile.new_commit_version == 1
        assert committed_profile.runtime_epoch == 1
        assert committed_profile.event_count == 1
        assert len(committed_profile.manifest_ids) == 3
        profile_rows = connect_database(
            harness.client_a_root / "client.sqlite3",
            "reader",
        )
        try:
            assert profile_rows.execute(
                "SELECT count(*) FROM fact_events "
                "WHERE publication_operation_id = ?",
                (profile_ticket.operation_id,),
            ).fetchone() == (1,)
            assert profile_rows.execute(
                "SELECT count(*) FROM profile_revisions "
                "WHERE publication_operation_id = ?",
                (profile_ticket.operation_id,),
            ).fetchone() == (1,)
            assert profile_rows.execute(
                "SELECT count(*) FROM artifact_manifests "
                "WHERE operation_id = ? AND state = 'ACTIVE'",
                (profile_ticket.operation_id,),
            ).fetchone() == (3,)
            profile_attestation = profile_rows.execute(
                "SELECT approval_draft_sha256, closure_sha256 "
                "FROM publication_closure_attestations "
                "WHERE operation_id = ?",
                (profile_ticket.operation_id,),
            ).fetchone()
            assert profile_attestation is not None
            assert profile_attestation[0] == profile_ticket.descriptor.draft_sha256
            assert len(profile_attestation[1]) == 64
        finally:
            profile_rows.close()

        # Recovery remains proof-only and idempotent even after receipt expiry.
        approval.clock.value = profile_ticket.receipt.expires_at + timedelta(
            seconds=1
        )
        assert (
            broker.recover_applied_archive_operation(
                profile_commit,
                ticket=profile_ticket,
                approval_service=approval.service,
            )
            == committed_profile
        )
        approval.clock.value = datetime.now(timezone.utc)

        prepared_case = broker.call(
            StageSharedCaseOutboxRequest(
                request_id=_request_id(harness),
                session_handle=archive_token,
                bundle_id=built.bundle_id,
                action="PREPARE",
                section_drafts=(
                    {
                        "section_kind": "factual_context",
                        "abstracted_text": "来访者希望梳理当前困扰及其影响模式。",
                    },
                    {
                        "section_kind": "actual_response",
                        "abstracted_text": "咨询师帮助其区分体验并形成后续行动方向。",
                    },
                ),
                decision="approved",
                checked_categories=frozenset(
                    {
                        "direct_identifiers",
                        "third_party_people",
                        "rare_attributes",
                        "location_occupation_family_time",
                        "section_boundaries",
                        "no_verbatim_quotes",
                    }
                ),
                residual_risk="low",
                rare_combination_disposition="not_present",
                reuse_authorized=True,
                allowed_uses=frozenset({"answer_support"}),
                authorization_expires_at=datetime(
                    2027, 7, 19, 4, 5, tzinfo=timezone.utc
                ),
            )
        )
        assert isinstance(prepared_case, StageSharedCaseOutboxResponse)
        assert prepared_case.candidate_ref is not None
        assert prepared_case.scan_ref is not None
        assert prepared_case.review_policy_draft_ref is not None
        assert prepared_case.approval_diff_ref is not None
        candidate_payload = json.loads(
            ContentStore(harness.client_a_root / "cas")
            .read_verified(
                ContentStore(harness.client_a_root / "cas").reference(
                    content_sha256=(
                        prepared_case.candidate_ref.content_sha256
                    ),
                    media_type=prepared_case.candidate_ref.media_type,
                    size_bytes=prepared_case.candidate_ref.size_bytes,
                )
            )
            .decode("utf-8")
        )
        assert candidate_payload["provenance"][
            "contributor_client_hashes"
        ] == [
            CaseContributorHasher(hash_key=b"t" * 32).hash_client_id(
                harness.client_a
            )
        ]
        approval.clock.value = datetime.now(timezone.utc)
        case_descriptor = DraftDescriptor(
            purpose="case_publish",
            target_id=prepared_case.candidate_ref.object_id,
            client_id=harness.client_a,
            base_version=prepared_case.candidate_ref.version,
            draft_sha256=(
                prepared_case.review_policy_draft_ref.content_sha256
            ),
            session_id=harness.session_id,
        )
        case_approval = approval.service.request(
            case_descriptor,
            diff_object_ref=prepared_case.approval_diff_ref,
        )
        approval.service.confirm(
            approval.signer.confirm(
                approval.service.challenge_for_review(
                    case_approval.request_id
                )
            )
        )
        case_ticket = approval.service.issue_for_execution(
            case_approval.request_id,
            case_descriptor,
            operation_id=approval.operation_id(),
        )
        case_commit = StageSharedCaseOutboxRequest(
            request_id=_request_id(harness),
            session_handle=archive_token,
            bundle_id=built.bundle_id,
            action="COMMIT",
            decision="approved",
            checked_categories=frozenset(
                {
                    "direct_identifiers",
                    "third_party_people",
                    "rare_attributes",
                    "location_occupation_family_time",
                    "section_boundaries",
                    "no_verbatim_quotes",
                }
            ),
            residual_risk="low",
            rare_combination_disposition="not_present",
            reuse_authorized=True,
            allowed_uses=frozenset({"answer_support"}),
            authorization_expires_at=datetime(
                2027, 7, 19, 4, 5, tzinfo=timezone.utc
            ),
            candidate_ref=prepared_case.candidate_ref,
            scan_ref=prepared_case.scan_ref,
            review_policy_draft_ref=(
                prepared_case.review_policy_draft_ref
            ),
            approval_operation_id=case_ticket.operation_id,
            approval_request_id=case_ticket.request_id,
        )
        with pytest.raises(ScopeDenied, match="SCOPE_DENIED"):
            broker.execute_approved_archive_operation(
                case_commit,
                ticket=case_ticket,
                approval_service=_LostAckService(approval.service),  # type: ignore[arg-type]
            )
        assert approval.service.get(case_ticket.request_id).state == "confirmed"
        broker.close()
        broker = new_broker()
        broker.start()
        committed_case = broker.recover_applied_archive_operation(
            case_commit,
            ticket=case_ticket,
            approval_service=approval.service,
        )
        assert isinstance(committed_case, StageSharedCaseOutboxResponse)
        assert committed_case.action == "COMMIT"
        assert committed_case.state == "PENDING"
        assert committed_case.payload_ref is not None
        assert committed_case.applied_commit_version is not None
        assert (
            broker.recover_applied_archive_operation(
                case_commit,
                ticket=case_ticket,
                approval_service=approval.service,
            )
            == committed_case
        )

        client = connect_database(
            harness.client_a_root / "client.sqlite3",
            "reader",
        )
        try:
            assert client.execute(
                "SELECT state FROM approval_executions WHERE operation_id = ?",
                (case_ticket.operation_id,),
            ).fetchone() == ("APPLIED",)
            assert client.execute(
                "SELECT decision FROM review_decisions WHERE decision_id = ?",
                (case_ticket.request_id,),
            ).fetchone() == ("APPROVED",)
            assert client.execute(
                "SELECT state FROM outbox_events WHERE event_id = ?",
                (committed_case.event_id,),
            ).fetchone() == ("PENDING",)
            assert client.execute(
                "SELECT count(*) FROM outbox_events WHERE bundle_id = ?",
                (built.bundle_id,),
            ).fetchone() == (1,)
            assert client.execute(
                "SELECT state FROM archive_purpose_states WHERE bundle_id = ? "
                "AND purpose = 'shared_case'",
                (built.bundle_id,),
            ).fetchone() == ("PREPARED",)
        finally:
            client.close()
        assert (
            approval.service.get(case_ticket.request_id).state
            == "acknowledged"
        )
        assert committed_case.event_id is not None
        exported = broker.export_pending_case_publish(
            event_id=committed_case.event_id
        )
        assert exported is not None
        source_event, transfer = exported
        assert source_event.state == "CLAIMED"
        assert source_event.attempt_count == 1
        global_store = ContentStore(harness.clients_root.parent / "global")
        interrupted_publisher = SharedCasePublisher(
            harness.global_connection,
            global_store,
            authority_resolver=broker,
            publication_proof_signer=LocalHmacCasePublicationProofSigner(
                secret=b"t" * 32,
                attestor_id="test-target-writer",
            ),
        )

        def fail_after_copy(phase: str) -> None:
            if phase == "after_copy":
                raise RuntimeError("injected-publisher-failure-after-copy")

        with pytest.raises(
            RuntimeError,
            match="injected-publisher-failure-after-copy",
        ):
            interrupted_publisher.process(
                source_event,
                transfer,
                fault_hook=fail_after_copy,
            )
        assert harness.global_connection.execute(
            "SELECT state FROM global_publish_sagas WHERE source_event_id = ?",
            (committed_case.event_id,),
        ).fetchone() == ("COPIED",)
        client = connect_database(
            harness.client_a_root / "client.sqlite3",
            "reader",
        )
        try:
            assert client.execute(
                "SELECT state, attempt_count FROM outbox_events "
                "WHERE event_id = ?",
                (committed_case.event_id,),
            ).fetchone() == ("CLAIMED", 1)
        finally:
            client.close()
        assert (
            approval.service.get(case_ticket.request_id).state
            == "acknowledged"
        )
        claimed_recovery = broker.recover_applied_archive_operation(
            case_commit,
            ticket=case_ticket,
            approval_service=approval.service,
        )
        assert isinstance(claimed_recovery, StageSharedCaseOutboxResponse)
        assert claimed_recovery.event_id == committed_case.event_id
        assert claimed_recovery.state == "CLAIMED"
        assert claimed_recovery.attempt_count == 1

        # Simulate the control process restarting after the publisher fault.
        # Resume uses a renewed capability, but never reissues or reconsumes the
        # already-acknowledged external case approval.
        broker.close()
        renewed_token = harness.capability_service.renew(
            client_id=harness.client_a,
            session_id=harness.session_id,
            previous_epoch=1,
        )
        binding = harness.capability_service.validate_binding(
            renewed_token,
            session_id=harness.session_id,
            client_id=harness.client_a,
            required_permissions=frozenset(
                {"client_read", "draft_write", "session_append"}
            ),
        )
        renewed_scope = ScopedSession(
            session_scope=binding.session_scope,
            client_id=harness.scope.client_id,
            client_root=harness.scope.client_root,
            client_database=harness.scope.client_database,
            global_database=harness.scope.global_database,
            scope_marker_sha256=harness.scope.scope_marker_sha256,
            global_descriptor_sha256=(
                harness.scope.global_descriptor_sha256
            ),
            capability_id=binding.capability_id,
            capability_epoch=binding.capability_epoch,
        )
        broker = ScopedWorkerBroker.for_scoped_session(
            session=renewed_scope,
            capability_token=renewed_token,
            capability_service=harness.capability_service,
            target_execution_attestor_secret=b"t" * 32,
            target_execution_attestor_id="test-target-writer",
            startup_timeout_seconds=10.0,
            call_timeout_seconds=10.0,
        )
        broker.start()
        resumed = broker.call(
            ResumeSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                previous_capability_epoch=1,
                capability_epoch=2,
            )
        )
        assert isinstance(resumed, ResumeSessionResponse)
        recovered = broker.export_pending_case_publish(
            event_id=committed_case.event_id
        )
        assert recovered is not None
        recovered_event, recovered_transfer = recovered
        assert recovered_event.state == "CLAIMED"
        assert recovered_event.attempt_count == 1
        assert recovered_transfer == transfer
        publication = SharedCasePublisher(
            harness.global_connection,
            global_store,
            authority_resolver=broker,
            publication_proof_signer=LocalHmacCasePublicationProofSigner(
                secret=b"t" * 32,
                attestor_id="test-target-writer",
            ),
        ).replay(recovered_event, recovered_transfer)
        acknowledged = broker.acknowledge_case_publication(publication)
        assert acknowledged.state == "PUBLISHED"
        assert acknowledged.published_global_version == publication.case_ref.version
        renewed_case_commit = case_commit.model_copy(
            update={"session_handle": renewed_token}
        )
        published_recovery = broker.recover_applied_archive_operation(
            renewed_case_commit,
            ticket=case_ticket,
            approval_service=approval.service,
        )
        assert isinstance(published_recovery, StageSharedCaseOutboxResponse)
        assert published_recovery.event_id == committed_case.event_id
        assert published_recovery.state == "PUBLISHED"
        assert (
            published_recovery.published_global_version
            == publication.case_ref.version
        )
        active = CaseCatalog(
            harness.global_connection,
            global_store,
        ).get_active(publication.case_ref.object_id, purpose="answer_support")
        assert active is not None and active.case_ref == publication.case_ref
        client = connect_database(
            harness.client_a_root / "client.sqlite3",
            "reader",
        )
        try:
            assert client.execute(
                "SELECT state, published_global_version FROM outbox_events "
                "WHERE event_id = ?",
                (committed_case.event_id,),
            ).fetchone() == ("PUBLISHED", publication.case_ref.version)
            assert client.execute(
                "SELECT count(*) FROM outbox_events WHERE bundle_id = ?",
                (built.bundle_id,),
            ).fetchone() == (1,)
            proof_payload = publication.proof.payload
            assert client.execute(
                "SELECT approval_operation_id, approval_request_id, "
                "approval_descriptor_sha256, approval_draft_sha256, "
                "approval_descriptor_base_version, "
                "approval_applied_commit_version, "
                "approval_target_scope_hash, publication_closure_sha256 "
                "FROM case_publication_proofs WHERE event_id = ?",
                (committed_case.event_id,),
            ).fetchone() == (
                proof_payload.approval_operation_id,
                proof_payload.approval_request_id,
                proof_payload.approval_descriptor_sha256,
                proof_payload.approval_draft_sha256,
                proof_payload.approval_descriptor_base_version,
                proof_payload.approval_applied_commit_version,
                proof_payload.approval_target_scope_hash,
                proof_payload.publication_closure_sha256,
            )
        finally:
            client.close()
        tampered_publication = publication.model_copy(
            update={
                "proof": publication.proof.model_copy(
                    update={
                        "payload": publication.proof.payload.model_copy(
                            update={"publication_closure_sha256": "0" * 64}
                        )
                    }
                )
            }
        )
        with pytest.raises(ScopeDenied):
            broker.acknowledge_case_publication(tampered_publication)

        # A compromised/stale local row must not turn an arbitrary positive
        # integer into a recoverable profile commit.  Profile publication has
        # an independent authority-version anchor, so recovery rejects the
        # altered approval-execution version before returning a proof.
        tamper_connection = connect_database(
            harness.client_a_root / "client.sqlite3",
            "writer",
        )
        try:
            tamper_connection.execute(
                "DROP TRIGGER approval_executions_update_guard"
            )
            tamper_connection.execute(
                "UPDATE approval_executions SET applied_commit_version = ? "
                "WHERE operation_id = ?",
                (
                    committed_profile.new_commit_version + 100,
                    profile_ticket.operation_id,
                ),
            )
        finally:
            tamper_connection.close()
        renewed_profile_commit = profile_commit.model_copy(
            update={"session_handle": renewed_token}
        )
        with pytest.raises(ScopeDenied):
            broker.recover_applied_archive_operation(
                renewed_profile_commit,
                ticket=profile_ticket,
                approval_service=approval.service,
            )

        # Once globally published, shared recovery has a separately signed
        # publication proof.  Altering only the local execution sequence must
        # therefore fail its exact proof comparison as well.
        tamper_connection = connect_database(
            harness.client_a_root / "client.sqlite3",
            "writer",
        )
        try:
            tamper_connection.execute(
                "UPDATE approval_executions SET applied_commit_version = ? "
                "WHERE operation_id = ?",
                (
                    committed_case.applied_commit_version + 100,
                    case_ticket.operation_id,
                ),
            )
        finally:
            tamper_connection.close()
        with pytest.raises(ScopeDenied):
            broker.recover_applied_archive_operation(
                renewed_case_commit,
                ticket=case_ticket,
                approval_service=approval.service,
            )
    finally:
        broker.close()
        if approval is not None:
            approval.close()
        harness.close()
