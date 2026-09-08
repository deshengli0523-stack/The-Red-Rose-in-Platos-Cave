from __future__ import annotations

import hashlib
import itertools
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from consultation_kb.archive.bundles import ArchiveBundleService
from consultation_kb.archive.case_catalog import CaseCatalog
from consultation_kb.archive.case_indexing import (
    CaseContributorBinding,
    CaseIndexGovernance,
    CaseIndexRootAuthority,
    CaseIndexTextSet,
    CaseIndexingError,
    CaseIndexingService,
)
from consultation_kb.archive.case_publisher import (
    CasePublishAuthoritySnapshot,
    CasePublishTransfer,
    SharedCasePublisher,
    case_release_decision_sha256,
    shared_candidate_bytes,
)
from consultation_kb.archive.publication_proof import (
    LocalHmacCasePublicationProofSigner,
)
from consultation_kb.archive.private_record import PrivateArchiveDraftBuilder
from consultation_kb.archive.profile_review import ProfileDiffReviewService
from consultation_kb.archive.provenance import (
    CaseContributorHasher,
    CaseProvenanceService,
)
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.archive import PrivateArchiveAnalysis
from consultation_kb.models.cases import CaseProvenanceRecord
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import AuthoritativeFilterSnapshot, RetrievalScope
from consultation_kb.models.session import StoredContentRef
from consultation_kb.retrieval.contracts import FilterCapabilityBinding
from consultation_kb.retrieval.filters import (
    AuthoritySnapshotStale,
    CandidateAuthorityStatus,
    CandidateFilter,
    StaticAuthorityGuard,
)
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.storage.outbox import (
    CasePublishOutboxPayload,
    OutboxRecord,
    case_publish_payload_bytes,
    case_publish_payload_sha256,
)
from consultation_kb.storage.tombstones import (
    ObjectIdentity,
    ObjectTombstoned,
    TombstoneRepository,
    VisibilityGuard,
)
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.case_index_support import (
    StaticCaseIndexAuthority,
    StaticCaseSourceAuthority,
)
from tests.consultation_kb.private_archive_approval_support import (
    commit_private_archive_with_guard,
)
from tests.consultation_kb.unit.test_case_release_policy import (
    NOW,
    _authorization,
    _candidate,
    _ids as release_ids,
    _policy,
    _review,
)
from tests.consultation_kb.unit.test_private_archive_review import _closed_bundle
from tests.consultation_kb.unit.test_profile_diff import build_partner_diff
from tests.consultation_kb.unit.test_shared_candidate import (
    _builder as shared_builder,
    _proposals as shared_proposals,
    _source as shared_source,
)


pytestmark = pytest.mark.integration

CLIENT_A = "client_" + "a" * 12
CLIENT_B = "client_" + "b" * 12
CONTRIBUTOR_KEY = b"archive-end-to-end-contributor-key"


class _StaticCasePublishAuthority:
    def __init__(self, transfer: CasePublishTransfer) -> None:
        payload = transfer.outbox_payload
        self._snapshot = CasePublishAuthoritySnapshot(
            candidate_ref=payload.candidate_ref,
            authorization_ref=payload.authorization_ref,
            review_ref=payload.review_ref,
            release_policy_ref=payload.release_policy_ref,
            release_decision_sha256=payload.release_decision_sha256,
            provenance_ref=payload.provenance_ref,
            purpose=payload.purpose,
            approval_operation_id=payload.approval_operation_id,
            approval_request_id=payload.approval_request_id,
            approval_descriptor_sha256=payload.approval_descriptor_sha256,
            approval_draft_sha256=payload.approval_draft_sha256,
            approval_descriptor_base_version=payload.candidate_ref.version,
            approval_applied_commit_version=1,
            approval_target_scope_hash=payload.approval_target_scope_hash,
            authority_epoch=1,
            state="active",
        )

    def resolve_case_publish_authority(
        self,
        *,
        payload: CasePublishOutboxPayload,
        as_of: datetime,
    ) -> CasePublishAuthoritySnapshot | None:
        del payload, as_of
        return self._snapshot


class _TombstoneAwareGuard:
    def __init__(
        self,
        snapshot: AuthoritativeFilterSnapshot,
        repository: TombstoneRepository,
    ) -> None:
        self._snapshot = snapshot
        self._visibility = VisibilityGuard(repository)

    def assert_snapshot_current(self, snapshot: AuthoritativeFilterSnapshot) -> None:
        if snapshot != self._snapshot:
            raise AuthoritySnapshotStale

    def candidate_status(
        self,
        candidate,
        snapshot: AuthoritativeFilterSnapshot,
    ) -> CandidateAuthorityStatus:
        self.assert_snapshot_current(snapshot)
        try:
            self._visibility.assert_visible(
                ObjectIdentity(candidate.object_type, candidate.reference.object_id),
                source_lineage_hashes=candidate.metadata.source_lineage_hashes,
            )
        except ObjectTombstoned:
            return "tombstoned"
        return (
            "visible"
            if candidate.reference.object_id in snapshot.allowed_ref_ids
            else "unauthorized"
        )

    def assert_binding_current(self, binding: FilterCapabilityBinding) -> None:
        if binding.run_id != self._snapshot.run_id:
            raise AuthoritySnapshotStale

    def assert_candidate_binding_visible(self, candidate, binding) -> None:
        self.assert_binding_current(binding)
        if self.candidate_status(candidate, self._snapshot) != "visible":
            raise AuthoritySnapshotStale


def _review_state(draft) -> dict[str, object]:
    return {
        "current_profile_sha256": draft.base_profile_sha256,
        "current_session_sha256": draft.base_session_sha256,
        "current_client_commit_version": draft.base_client_commit_version,
    }


def test_private_and_profile_paths_remain_available_when_case_is_private_only(
    tmp_path: Path,
) -> None:
    connection, repository, session_id, _actual, bundle = _closed_bundle(
        tmp_path,
        suffix=31,
    )
    try:
        analysis = PrivateArchiveAnalysis(
            model_analysis=("关系解释仍需后续验证。",),
            counselor_reflection=("先保留多种解释，不把假设写成事实。",),
        )
        private = PrivateArchiveDraftBuilder(repository).build(
            session_id,
            analysis=analysis,
        )
        _private_decision, private_publication, _private_replay = (
            commit_private_archive_with_guard(repository, private)
        )

        profile = build_partner_diff()
        profile_service = ProfileDiffReviewService()
        preview = profile_service.preview(profile, **_review_state(profile))
        prepared_profile = profile_service.approve_partial(
            preview,
            approved_operation_ids=tuple(
                item.operation_id for item in profile.operations
            ),
            dismissed_indirect_review_fact_ids=("fact_communication_pattern",),
            **_review_state(profile),
        )

        ids = release_ids()
        candidate = _candidate(ids)
        authorization = _authorization(ids, reuse=False)
        release = _policy(ids).evaluate(
            candidate,
            authorization,
            _review(ids, candidate),
            purpose="answer_support",
            at=NOW + timedelta(minutes=2),
        )
        decision_id = repository.id_factory.object_id("review_decision")
        connection.execute(
            """
            INSERT INTO review_decisions(
                decision_id, session_id, object_id, decision,
                reviewer_id_hash, decided_at
            ) VALUES (?, ?, ?, 'REJECTED', ?, ?)
            """,
            (
                decision_id,
                session_id,
                candidate.candidate_ref.object_id,
                "d" * 64,
                repository.clock.now().isoformat().replace("+00:00", "Z"),
            ),
        )
        changed = ArchiveBundleService(repository).transition(
            bundle.bundle_id,
            purpose="shared_case",
            state="PRIVATE_ONLY",
            review_decision_id=decision_id,
        )

        assert private_publication.purpose_state.state == "ACTIVE"
        assert prepared_profile.requires_atomic_client_publication is True
        assert prepared_profile.pending_indirect_review_fact_ids == ()
        assert prepared_profile.unapproved_direct_impact_fact_ids == ()
        assert release.outcome == "private_only"
        assert "reuse_not_authorized" in release.reasons
        assert changed.state_for("shared_case").state == "PRIVATE_ONLY"
        assert changed.state_for("private_archive").state == "ACTIVE"
        assert connection.execute("SELECT count(*) FROM outbox_events").fetchone() == (
            0,
        )
    finally:
        connection.close()


def _authorized_transfer(
    ids: IdFactory,
    contributor_hash: str,
) -> tuple[OutboxRecord, CasePublishTransfer, datetime]:
    source, actual_transcript = shared_source(ids)
    candidate = shared_builder(ids).build(
        source,
        shared_proposals(source),
        contributor_client_hash=contributor_hash,
        provenance_ref=VersionRef(
            object_id=ids.object_id("case_source_provenance"),
            version=1,
            content_sha256=hashlib.sha256(b"source-provenance").hexdigest(),
        ),
        derivation_rule_ref=VersionRef(
            object_id=ids.object_id("case_derivation_rule"),
            version=1,
            content_sha256=hashlib.sha256(b"case-index-rule").hexdigest(),
        ),
        requested_allowed_uses=frozenset({"answer_support"}),
        created_at=NOW,
        actual_transcript=actual_transcript,
    ).candidate
    authorization = _authorization(
        ids,
        contributor_client_hash=contributor_hash,
    )
    review = _review(ids, candidate)
    evaluated_at = NOW + timedelta(minutes=2)
    decision = _policy(ids).evaluate(
        candidate,
        authorization,
        review,
        purpose="answer_support",
        at=evaluated_at,
    )
    candidate_body = shared_candidate_bytes(candidate)
    approval_request_id = ids.object_id("source_case_review")
    payload = CasePublishOutboxPayload(
        candidate_ref=candidate.candidate_ref,
        candidate_sha256=candidate.candidate_sha256,
        candidate_size_bytes=len(candidate_body),
        authorization_ref=authorization.authorization_ref,
        review_ref=review.review_ref,
        release_policy_ref=decision.policy_ref,
        release_decision_sha256=case_release_decision_sha256(decision),
        provenance_ref=candidate.provenance.provenance_ref,
        purpose="answer_support",
        approval_operation_id=ids.object_id("case_publish_operation"),
        approval_request_id=approval_request_id,
        approval_descriptor_sha256="1" * 64,
        approval_draft_sha256="2" * 64,
        approval_target_scope_hash="3" * 64,
        source_review_decision_id=approval_request_id,
        idempotency_key="archive-end-to-end-publish",
    )
    serialized = case_publish_payload_bytes(payload)
    event = OutboxRecord(
        event_id=ids.object_id("case_outbox_event"),
        bundle_id=ids.object_id("archive_bundle"),
        idempotency_key=payload.idempotency_key,
        payload=StoredContentRef(
            object_id=ids.object_id("case_outbox_payload"),
            content_sha256=case_publish_payload_sha256(payload),
            media_type="application/json",
            size_bytes=len(serialized),
        ),
        state="CLAIMED",
        attempt_count=1,
        created_at=evaluated_at,
        updated_at=evaluated_at,
    )
    return (
        event,
        CasePublishTransfer(
            outbox_payload=payload,
            candidate=candidate,
            authorization=authorization,
            review=review,
            release_decision=decision,
        ),
        evaluated_at,
    )


def _snapshot(bundle, at: datetime) -> AuthoritativeFilterSnapshot:
    first = bundle.candidates[0]
    return AuthoritativeFilterSnapshot(
        run_id="019f743d-4400-7000-8000-000000000099",
        global_runtime_epoch=1,
        client_runtime_epoch=0,
        tombstone_epoch=0,
        authorization_epoch=0,
        allowed_ref_ids=frozenset(
            candidate.reference.object_id for candidate in bundle.candidates
        ),
        policy_ref=first.metadata.manifest_ref,
        created_at=at,
    )


def _scope(client_id: str, at: datetime) -> RetrievalScope:
    return RetrievalScope(
        current_client_id=client_id,
        allowed_uses=frozenset({"answer_support"}),
        maximum_sensitivity=1,
        effective_at=at,
        known_at=at,
    )


def _allowed(filter_: CandidateFilter, bundle, snapshot, client_id: str, at: datetime):
    return tuple(
        allowed
        for candidate in bundle.candidates
        for allowed in filter_.filter(
            _scope(client_id, at),
            (candidate,),
            snapshot,
        ).allowed
    )


def test_authorized_case_is_global_for_b_excluded_for_a_and_legacy_revoke_fails_closed(
    tmp_path: Path,
) -> None:
    connection = connect_database(tmp_path / "global.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    global_store = ContentStore(tmp_path / "global-cas")
    values = itertools.count(300_000)
    ids = IdFactory(FixedClock(NOW), lambda: next(values))
    hasher = CaseContributorHasher(hash_key=CONTRIBUTOR_KEY)
    contributor_hash = hasher.hash_client_id(CLIENT_A)
    event, transfer, evaluated_at = _authorized_transfer(ids, contributor_hash)
    indexed_at = evaluated_at + timedelta(minutes=1)
    publisher = SharedCasePublisher(
        connection,
        global_store,
        authority_resolver=_StaticCasePublishAuthority(transfer),
        publication_proof_signer=LocalHmacCasePublicationProofSigner(
            secret=b"c" * 32,
            attestor_id="case-publication-test",
        ),
        clock=FixedClock(indexed_at),
        id_factory=ids,
    )
    try:
        publication = publisher.process(event, transfer)
        catalog = CaseCatalog(connection, global_store)
        visible = catalog.active_cases(purpose="answer_support")
        assert len(visible) == 1
        assert visible[0].case_ref == publication.case_ref
        global_body = catalog.read_body(visible[0]).model_dump_json()
        assert CLIENT_A not in global_body
        assert contributor_hash not in global_body

        row = connection.execute(
            "SELECT closure_json FROM case_provenance "
            "WHERE artifact_object_id = ? AND artifact_version = ?",
            (publication.case_ref.object_id, publication.case_ref.version),
        ).fetchone()
        assert row is not None
        root = CaseProvenanceRecord.model_validate_json(row[0])
        source_authority = StaticCaseSourceAuthority()
        source_authority.authorize_case(root.case_contributions[0])
        provenance = CaseProvenanceService(
            id_factory=ids,
            policy_manifest_ref=root.policy_manifest_ref,
            approved_derivation_rules=(root.derivation_rule_ref,),
            authority_resolver=source_authority,
            clock=FixedClock(indexed_at),
        )
        manifest_ref = VersionRef(
            object_id=publication.manifest_id,
            version=1,
            content_sha256=hashlib.sha256(b"case-manifest").hexdigest(),
        )
        index_authority = StaticCaseIndexAuthority()
        index_authority.authorize(
            CaseIndexRootAuthority(
                case_ref=publication.case_ref,
                source_candidate_ref=transfer.candidate.candidate_ref,
                authorization=transfer.authorization,
                review=transfer.review,
                release_decision=transfer.release_decision,
                authority_manifest_ref=manifest_ref,
                source_catalog_version=1,
            )
        )
        indexing = CaseIndexingService(
            id_factory=ids,
            provenance_service=provenance,
            contributor_hasher=hasher,
            authority_resolver=index_authority,
            connection=connection,
            clock=FixedClock(indexed_at),
        )
        bundle = indexing.build(
            root,
            authorization=transfer.authorization,
            review=transfer.review,
            release_decision=transfer.release_decision,
            contributor=CaseContributorBinding(
                client_id=CLIENT_A,
                contributor_client_hash=contributor_hash,
            ),
            texts=CaseIndexTextSet(
                case_record="来访者在关系冲突后先稳定情绪，再澄清当前需求。",
                reviewed_pattern="相似条件下，降低唤醒水平可为后续沟通创造条件。",
                conditional_claim="情绪唤醒较高时，可先短暂停顿并确认具体需要。",
                wiki_section="情绪稳定与需求澄清可作为有条件的咨询参考顺序。",
                graph_relation="情绪稳定可能支持后续的需求澄清。",
            ),
            governance=CaseIndexGovernance(
                source_candidate_ref=transfer.candidate.candidate_ref,
                authority_manifest_ref=manifest_ref,
                release_policy_ref=transfer.release_decision.policy_ref,
                locator_policy_ref=VersionRef(
                    object_id=ids.object_id("locator_policy"),
                    version=1,
                    content_sha256=hashlib.sha256(b"locator").hexdigest(),
                ),
                freshness_policy_ref=VersionRef(
                    object_id=ids.object_id("freshness_policy"),
                    version=1,
                    content_sha256=hashlib.sha256(b"freshness").hexdigest(),
                ),
                source_catalog_version=1,
                indexed_at=indexed_at,
            ),
            derivation_rule_ref=root.derivation_rule_ref,
        )
        snapshot = _snapshot(bundle, indexed_at)
        prefilter = CandidateFilter(
            StaticAuthorityGuard(snapshot),
            contributor_identity_hasher=hasher,
        )
        allowed_b = _allowed(prefilter, bundle, snapshot, CLIENT_B, indexed_at)
        allowed_a = _allowed(prefilter, bundle, snapshot, CLIENT_A, indexed_at)

        assert len(allowed_b) == 5
        assert allowed_a == ()
        for candidate in allowed_b:
            text = bundle.body_for(candidate).decode("utf-8")
            assert CLIENT_A not in text
            assert contributor_hash not in text
            assert "不代表普遍规律" in text

        catalog_version = connection.execute(
            "SELECT catalog_version FROM knowledge_catalog_state WHERE singleton = 1"
        ).fetchone()
        assert catalog_version is not None
        total_changes = connection.total_changes
        with pytest.raises(
            CaseIndexingError,
            match="CASE_REVOCATION_REQUIRES_FORMAL_DELETION",
        ):
            indexing.revoke(
                publication.case_ref,
                authorization_ref=transfer.authorization.authorization_ref,
                catalog_version=int(catalog_version[0]),
            )
        assert connection.total_changes == total_changes
        postfilter = CandidateFilter(
            _TombstoneAwareGuard(snapshot, TombstoneRepository(connection)),
            contributor_identity_hasher=hasher,
        )

        assert len(_allowed(postfilter, bundle, snapshot, CLIENT_B, indexed_at)) == 5
        assert len(catalog.active_cases(purpose="answer_support")) == 1
        assert connection.execute("SELECT state FROM cases").fetchone() == (
            "ACTIVE",
        )
        assert connection.execute("SELECT count(*) FROM rebuild_queue").fetchone() == (
            0,
        )
        assert connection.execute(
            "SELECT authorization_epoch, tombstone_epoch "
            "FROM knowledge_catalog_state WHERE singleton = 1"
        ).fetchone() == (0, 0)
    finally:
        connection.close()
