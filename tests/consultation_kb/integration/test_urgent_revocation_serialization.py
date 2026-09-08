from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest

from consultation_kb.archive.case_index_publication import (
    CaseIndexPublicationRepository,
)
from consultation_kb.knowledge.approval import GovernedWriteExecutor
from consultation_kb.knowledge.claims import (
    ClaimGovernanceError,
    ClaimProposalService,
)
from consultation_kb.knowledge.review import ClaimReviewResolver
from consultation_kb.models.common import ObjectId
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.storage.case_index_serialization import (
    snapshot_pending_case_index_invalidations,
)
from consultation_kb.storage.connection import transaction
from tests.consultation_kb.integration.test_case_01_full_lineage import _fixture
from tests.consultation_kb.integration.test_case_index_publication_authority import (
    _publish_case_index,
    _seed_verified_shared_case,
)
from tests.consultation_kb.knowledge_integration_support import (
    GlobalKnowledgeHarness,
    build_global_knowledge_harness,
    prepare_governed_knowledge,
)


def _seed_pending_case_index(
    harness: GlobalKnowledgeHarness,
    *,
    counter_start: int,
) -> str:
    bundle, _ = _fixture(counter_start=counter_start)
    publication = _publish_case_index(
        harness,
        _seed_verified_shared_case(harness, bundle),
    )
    return str(publication.rebuild_queue_id)


def _claim_service(
    harness: GlobalKnowledgeHarness,
    *,
    executor: GovernedWriteExecutor | None = None,
) -> ClaimProposalService:
    return ClaimProposalService(
        review_resolver=ClaimReviewResolver(
            lambda _reference: (_ for _ in ()).throw(
                AssertionError("revoke must not resolve passage text")
            )
        ),
        id_factory=harness.ids,
        clock=harness.clock,
        connection=harness.connection,
        approval_executor=executor or harness.executor,
        content_store=harness.store,
    )


def _assert_exact_invalidation(
    harness: GlobalKnowledgeHarness,
    *,
    queue_id: str,
    request_id: str,
    reason_code: str,
    identity_sha256: str,
    target_catalog_version: int,
) -> None:
    assert harness.connection.execute(
        "SELECT authority_request_id, invalidation_set_sha256, reason_code, "
        "base_catalog_version, target_catalog_version, "
        "prior_authorization_epoch, authorization_epoch, "
        "prior_tombstone_epoch, tombstone_epoch "
        "FROM case_index_rebuild_invalidations WHERE queue_id = ?",
        (queue_id,),
    ).fetchone() == (
        request_id,
        identity_sha256,
        reason_code,
        target_catalog_version - 1,
        target_catalog_version,
        0,
        1,
        0,
        1,
    )
    assert harness.connection.execute(
        "SELECT state FROM case_patterns WHERE manifest_id = ("
        "SELECT upstream_id FROM rebuild_queue WHERE queue_id = ?)",
        (queue_id,),
    ).fetchone() == ("REVOKED",)
    assert harness.connection.execute(
        "SELECT catalog_version, authorization_epoch, tombstone_epoch "
        "FROM knowledge_catalog_state WHERE singleton = 1"
    ).fetchone() == (target_catalog_version, 1, 1)
    assert not snapshot_pending_case_index_invalidations(
        harness.connection
    ).identities
    assert CaseIndexPublicationRepository(
        harness.connection,
        harness.store,
        clock=harness.clock,
    ).replay_approved() == ()


def test_claim_revoke_invalidates_exact_pending_case_set_before_epoch_change(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        queue_id = _seed_pending_case_index(harness, counter_start=210_000)
        planned = snapshot_pending_case_index_invalidations(harness.connection)
        assert tuple(item.queue_id for item in planned.identities) == (queue_id,)
        claim = knowledge.claims[0]
        service = _claim_service(harness)
        descriptor = service.preview_revoke(claim.claim_id, claim.version)
        request_id = harness.confirm(descriptor)

        revoked = service.revoke(
            claim.claim_id,
            claim.version,
            approval_request_id=request_id,
        )

        assert revoked.review_status == "revoked"
        _assert_exact_invalidation(
            harness,
            queue_id=queue_id,
            request_id=request_id,
            reason_code="claim_revoked",
            identity_sha256=planned.identity_sha256,
            target_catalog_version=planned.target_catalog_version,
        )
    finally:
        harness.close()


def test_theory_revoke_invalidates_exact_pending_case_set_before_epoch_change(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        queue_id = _seed_pending_case_index(harness, counter_start=220_000)
        planned = snapshot_pending_case_index_invalidations(harness.connection)
        descriptor = knowledge.theory_service.preview_revoke(
            knowledge.theory.theory_id,
            knowledge.theory.revision,
        )
        request_id = harness.confirm(descriptor)

        revoked = knowledge.theory_service.revoke(
            knowledge.theory.theory_id,
            knowledge.theory.revision,
            actor="primary_counselor",
            approval_request_id=request_id,
        )

        assert revoked.status == "revoked"
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM claims "
            "WHERE source_grade = 'C1' AND review_status = 'REVOKED'"
        ).fetchone() == (len(knowledge.theory.claim_refs),)
        _assert_exact_invalidation(
            harness,
            queue_id=queue_id,
            request_id=request_id,
            reason_code="theory_revoked",
            identity_sha256=planned.identity_sha256,
            target_catalog_version=planned.target_catalog_version,
        )
    finally:
        harness.close()


class _DriftBeforeTargetTransaction:
    def __init__(
        self,
        delegate: GovernedWriteExecutor,
        drift: Callable[[], None],
    ) -> None:
        self._delegate = delegate
        self._drift = drift

    def execute(
        self,
        *,
        approval_request_id: str,
        descriptor: DraftDescriptor,
        operation_kind: str,
        apply: Callable[[sqlite3.Connection], None],
    ) -> ObjectId:
        self._drift()
        return self._delegate.execute(
            approval_request_id=approval_request_id,
            descriptor=descriptor,
            operation_kind=operation_kind,
            apply=apply,
        )


def test_new_pending_case_between_preview_and_target_transaction_is_atomic(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        first_queue = _seed_pending_case_index(harness, counter_start=230_000)
        drifted = False

        def add_second_pending_case() -> None:
            nonlocal drifted
            assert not drifted
            drifted = True
            _seed_pending_case_index(harness, counter_start=240_000)

        service = _claim_service(
            harness,
            executor=_DriftBeforeTargetTransaction(
                harness.executor,
                add_second_pending_case,
            ),
        )
        claim = knowledge.claims[0]
        descriptor = service.preview_revoke(claim.claim_id, claim.version)
        request_id = harness.confirm(descriptor)
        base_catalog_version = snapshot_pending_case_index_invalidations(
            harness.connection
        ).target_catalog_version - 1

        with pytest.raises(
            ClaimGovernanceError,
            match="CLAIM_REVOKE_AUTHORITY_CHANGED",
        ):
            service.revoke(
                claim.claim_id,
                claim.version,
                approval_request_id=request_id,
            )

        assert service.get(claim.claim_id, claim.version).review_status == "approved"
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM case_index_rebuild_invalidations"
        ).fetchone() == (0,)
        assert harness.connection.execute(
            "SELECT state, COUNT(*) FROM case_patterns GROUP BY state"
        ).fetchall() == [("PREPARED", 2)]
        assert len(
            snapshot_pending_case_index_invalidations(harness.connection).identities
        ) == 2
        assert first_queue in {
            str(row[0])
            for row in harness.connection.execute(
                "SELECT queue_id FROM rebuild_queue WHERE upstream_type = 'case_index'"
            ).fetchall()
        }
        assert harness.connection.execute(
            "SELECT catalog_version, authorization_epoch, tombstone_epoch "
            "FROM knowledge_catalog_state WHERE singleton = 1"
        ).fetchone() == (base_catalog_version, 0, 0)
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM approval_executions WHERE request_id = ?",
            (request_id,),
        ).fetchone() == (0,)
    finally:
        harness.close()


def test_claim_revoke_without_pending_case_keeps_existing_behavior(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        claim = knowledge.claims[0]
        service = _claim_service(harness)
        descriptor = service.preview_revoke(claim.claim_id, claim.version)
        request_id = harness.confirm(descriptor)
        base_catalog_version = harness.connection.execute(
            "SELECT catalog_version FROM knowledge_catalog_state WHERE singleton = 1"
        ).fetchone()[0]

        assert service.revoke(
            claim.claim_id,
            claim.version,
            approval_request_id=request_id,
        ).review_status == "revoked"
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM case_index_rebuild_invalidations"
        ).fetchone() == (0,)
        assert harness.connection.execute(
            "SELECT catalog_version, authorization_epoch, tombstone_epoch "
            "FROM knowledge_catalog_state WHERE singleton = 1"
        ).fetchone() == (base_catalog_version + 1, 1, 1)
    finally:
        harness.close()


def test_ordinary_catalog_writer_cannot_bypass_pending_case_serialization(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        _seed_pending_case_index(harness, counter_start=250_000)
        with pytest.raises(sqlite3.IntegrityError, match="pending case index rebuild"):
            with transaction(harness.connection):
                harness.connection.execute(
                    "UPDATE knowledge_catalog_state "
                    "SET catalog_version = catalog_version + 1 WHERE singleton = 1"
                )
        assert harness.connection.execute(
            "SELECT catalog_version, authorization_epoch, tombstone_epoch "
            "FROM knowledge_catalog_state WHERE singleton = 1"
        ).fetchone() == (0, 0, 0)
    finally:
        harness.close()
