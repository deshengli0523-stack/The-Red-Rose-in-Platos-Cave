from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from consultation_kb.knowledge.claims import ClaimProposalService
from consultation_kb.knowledge.provenance import ProvenancePolicyManifest
from consultation_kb.knowledge.publication import (
    KnowledgePublicationError,
    KnowledgePublicationService,
)
from consultation_kb.knowledge.review import ClaimReviewResolver
from consultation_kb.knowledge.theory import TheoryRevisionService
from consultation_kb.knowledge.wiki import WikiRevisionService
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import EvidenceLocator
from consultation_kb.vault.content_store import ContentHashMismatch
from tests.consultation_kb.knowledge_integration_support import (
    GlobalKnowledgeHarness,
    PUBLICATION_KINDS,
    PreparedKnowledge,
    build_global_knowledge_harness,
    prepare_global_publication,
    prepare_governed_knowledge,
    prepare_successor_knowledge,
    rebuild_authority_services,
)


def _with_rebuilt_services(
    knowledge: PreparedKnowledge,
    *,
    theory_service: TheoryRevisionService,
    wiki_service: WikiRevisionService,
) -> PreparedKnowledge:
    return PreparedKnowledge(
        claims=knowledge.claims,
        claim_service=knowledge.claim_service,
        claim_drafts=knowledge.claim_drafts,
        theory=theory_service.get(
            knowledge.theory.theory_id,
            knowledge.theory.revision,
        ),
        wiki=wiki_service.get(knowledge.wiki.wiki_id, knowledge.wiki.revision),
        theory_service=theory_service,
        wiki_service=wiki_service,
        source_ids=knowledge.source_ids,
    )


def _rebuild_claim_service(
    harness: GlobalKnowledgeHarness, knowledge: PreparedKnowledge
) -> ClaimProposalService:
    def resolve(reference: VersionRef) -> tuple[str, None, None, EvidenceLocator]:
        row = harness.connection.execute(
            """
            SELECT retrieval_content_ref, locator_json FROM passages
             WHERE passage_id = ? AND version = ?
            """,
            (reference.object_id, reference.version),
        ).fetchone()
        assert row is not None
        digest = str(row[0]).removeprefix("sha256:")
        text = harness.store.read_hash_verified(digest).decode("utf-8")
        return text, None, None, EvidenceLocator.model_validate_json(str(row[1]))

    rule = knowledge.claim_drafts[0].provenance.derivation_rule_ref
    return ClaimProposalService(
        review_resolver=ClaimReviewResolver(resolve),
        id_factory=harness.ids,
        clock=harness.clock,
        connection=harness.connection,
        approval_executor=harness.executor,
        content_store=harness.store,
        provenance_policy=ProvenancePolicyManifest(
            manifest_ref=VersionRef(
                object_id=harness.ids.object_id("provenance_manifest"),
                version=1,
                content_sha256="6" * 64,
            ),
            rule_members=(rule,),
        ),
    )


def test_prepared_authority_survives_restart_and_publishes_from_cas(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        original = prepare_governed_knowledge(harness)
        theory_service, wiki_service = rebuild_authority_services(harness)
        recovered = _with_rebuilt_services(
            original,
            theory_service=theory_service,
            wiki_service=wiki_service,
        )
        assert recovered.theory.status == "prepared"
        assert recovered.wiki.status == "prepared"

        publication = prepare_global_publication(harness, recovered)
        active = publication.service.publish_theory_and_wiki(
            publication.operation_id,
            theory_id=recovered.theory.theory_id,
            theory_revision=recovered.theory.revision,
            wiki_id=recovered.wiki.wiki_id,
            wiki_revision=recovered.wiki.revision,
        )
        assert active.runtime_epoch == 1

        restarted_theory, restarted_wiki = rebuild_authority_services(harness)
        active_theory = restarted_theory.get_active(recovered.theory.theory_id)
        active_wiki = restarted_wiki.get_active(recovered.wiki.wiki_id)
        assert active_theory is not None and active_theory.revision == 1
        assert active_wiki is not None and active_wiki.revision == 1
        assert harness.connection.execute(
            """
            SELECT review_status FROM claims
             WHERE source_grade = 'C1' AND theory_revision_id = ?
               AND theory_revision = 1
            """,
            (recovered.theory.theory_id,),
        ).fetchall() == [("APPROVED",)]
    finally:
        harness.close()


def test_epoch_two_failure_rolls_back_authority_and_retries_atomically(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        first = prepare_governed_knowledge(harness)
        first_publication = prepare_global_publication(harness, first)
        first_publication.service.publish_theory_and_wiki(
            first_publication.operation_id,
            theory_id=first.theory.theory_id,
            theory_revision=1,
            wiki_id=first.wiki.wiki_id,
            wiki_revision=1,
        )
        second = prepare_successor_knowledge(harness, first)

        phases: list[str] = []

        def fail_once(phase: str) -> None:
            phases.append(phase)
            if phase == "epoch_switched" and phases.count(phase) == 1:
                raise RuntimeError("synthetic post-switch failure")

        second_publication = prepare_global_publication(
            harness,
            second,
            authority_base_version=2,
            expected_current_epoch=1,
            failure_hook=fail_once,
        )
        with pytest.raises(RuntimeError, match="post-switch failure"):
            second_publication.service.publish_theory_and_wiki(
                second_publication.operation_id,
                theory_id=second.theory.theory_id,
                theory_revision=2,
                wiki_id=second.wiki.wiki_id,
                wiki_revision=2,
            )

        assert harness.connection.execute(
            "SELECT epoch, state FROM runtime_epochs ORDER BY epoch"
        ).fetchall() == [(1, "ACTIVE")]
        assert harness.connection.execute(
            "SELECT revision, status FROM theory_revisions ORDER BY revision"
        ).fetchall() == [(1, "ACTIVE"), (2, "PREPARED")]
        assert harness.connection.execute(
            "SELECT revision, review_status FROM wiki_revisions ORDER BY revision"
        ).fetchall() == [(1, "ACTIVE"), (2, "PREPARED")]
        assert harness.connection.execute(
            """
            SELECT theory_revision, review_status FROM claims
             WHERE source_grade = 'C1' ORDER BY theory_revision
            """
        ).fetchall() == [(1, "APPROVED"), (2, "REVIEWED")]
        assert second_publication.coordinator.verify(
            second_publication.operation_id
        ).state == "VERIFIED"

        active = second_publication.service.publish_theory_and_wiki(
            second_publication.operation_id,
            theory_id=second.theory.theory_id,
            theory_revision=2,
            wiki_id=second.wiki.wiki_id,
            wiki_revision=2,
        )
        assert active.runtime_epoch == 2
        assert harness.connection.execute(
            "SELECT epoch, state FROM runtime_epochs ORDER BY epoch"
        ).fetchall() == [(1, "RETIRED"), (2, "ACTIVE")]
        assert harness.connection.execute(
            "SELECT revision, status FROM theory_revisions ORDER BY revision"
        ).fetchall() == [(1, "SUPERSEDED"), (2, "ACTIVE")]
        assert harness.connection.execute(
            "SELECT revision, review_status FROM wiki_revisions ORDER BY revision"
        ).fetchall() == [(1, "SUPERSEDED"), (2, "ACTIVE")]
        assert harness.connection.execute(
            """
            SELECT theory_revision, review_status FROM claims
             WHERE source_grade = 'C1' ORDER BY theory_revision
            """
        ).fetchall() == [(1, "REVOKED"), (2, "APPROVED")]

        restarted_theory, restarted_wiki = rebuild_authority_services(harness)
        active_theory = restarted_theory.get_active(second.theory.theory_id)
        active_wiki = restarted_wiki.get_active(second.wiki.wiki_id)
        assert active_theory is not None and active_theory.revision == 2
        assert active_wiki is not None and active_wiki.revision == 2
    finally:
        harness.close()


def test_closure_cannot_activate_another_revision_or_standalone_c1_wiki(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        first = prepare_governed_knowledge(harness)
        second = prepare_successor_knowledge(harness, first)
        first_publication = prepare_global_publication(harness, first)

        with pytest.raises(
            KnowledgePublicationError,
            match="KNOWLEDGE_(?:WIKI|C1)_CLOSURE_MISMATCH",
        ):
            first_publication.service.publish_theory_and_wiki(
                first_publication.operation_id,
                theory_id=second.theory.theory_id,
                theory_revision=second.theory.revision,
                wiki_id=second.wiki.wiki_id,
                wiki_revision=second.wiki.revision,
            )
        with pytest.raises(
            KnowledgePublicationError,
            match="KNOWLEDGE_COMBINED_PUBLICATION_REQUIRED",
        ):
            first_publication.service.publish_wiki(
                first_publication.operation_id,
                wiki_id=first.wiki.wiki_id,
                wiki_revision=first.wiki.revision,
            )
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM runtime_epochs"
        ).fetchone() == (0,)
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM claims WHERE source_grade = 'C1' AND review_status = 'APPROVED'"
        ).fetchone() == (0,)
    finally:
        harness.close()


def test_claim_theory_and_wiki_refs_are_real_verified_cas_objects(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        for table, ref_column, size_column, media_column in (
            (
                "claims",
                "claim_object_ref",
                "claim_object_size_bytes",
                "claim_object_media_type",
            ),
            (
                "theory_revisions",
                "revision_object_ref",
                "revision_object_size_bytes",
                "revision_object_media_type",
            ),
            (
                "wiki_revisions",
                "body_object_ref",
                "body_object_size_bytes",
                "body_object_media_type",
            ),
            (
                "wiki_revisions",
                "diff_object_ref",
                "diff_object_size_bytes",
                "diff_object_media_type",
            ),
        ):
            rows = harness.connection.execute(
                f"SELECT {ref_column}, {size_column}, {media_column} FROM {table}"
            ).fetchall()
            assert rows
            for row in rows:
                digest = str(row[0]).removeprefix("sha256:")
                reference = harness.store.reference(
                    content_sha256=digest,
                    size_bytes=int(row[1]),
                    media_type=str(row[2]),
                )
                assert harness.store.read_verified(reference)

        def unreachable(_reference):  # type: ignore[no-untyped-def]
            raise AssertionError("loader must not invoke the review resolver")

        restarted_claims = ClaimProposalService(
            review_resolver=ClaimReviewResolver(unreachable),
            connection=harness.connection,
            content_store=harness.store,
        )
        assert restarted_claims.get(knowledge.claims[0].claim_id).text == knowledge.claims[0].text

        body_row = harness.connection.execute(
            """
            SELECT body_object_ref, body_object_size_bytes,
                   body_object_media_type FROM wiki_revisions
             WHERE wiki_id = ? AND revision = ?
            """,
            (knowledge.wiki.wiki_id, knowledge.wiki.revision),
        ).fetchone()
        assert body_row is not None
        body_reference = harness.store.reference(
            content_sha256=str(body_row[0]).removeprefix("sha256:"),
            size_bytes=int(body_row[1]),
            media_type=str(body_row[2]),
        )
        body_reference.path.write_bytes(b"tampered")
        _, restarted_wiki = rebuild_authority_services(harness)
        with pytest.raises(ContentHashMismatch):
            restarted_wiki.get(knowledge.wiki.wiki_id, knowledge.wiki.revision)
    finally:
        harness.close()


def test_missing_required_artifact_kind_fails_closed_without_db_mutation(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        publication = prepare_global_publication(harness, knowledge)
        incomplete = KnowledgePublicationService(
            coordinator=publication.coordinator,
            theory_service=knowledge.theory_service,
            wiki_service=knowledge.wiki_service,
            connection=harness.connection,
            required_artifact_kinds=(*PUBLICATION_KINDS, "missing_required"),
            lint_error_count=lambda: 0,
            content_store=harness.store,
        )
        with pytest.raises(
            KnowledgePublicationError,
            match="KNOWLEDGE_CLOSURE_INCOMPLETE",
        ):
            incomplete.publish_theory_and_wiki(
                publication.operation_id,
                theory_id=knowledge.theory.theory_id,
                theory_revision=knowledge.theory.revision,
                wiki_id=knowledge.wiki.wiki_id,
                wiki_revision=knowledge.wiki.revision,
            )
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM runtime_epochs"
        ).fetchone() == (0,)
    finally:
        harness.close()


def test_builder_contract_rejects_placeholder_and_extra_revoked_claim(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        placeholder = prepare_global_publication(
            harness,
            knowledge,
            invalid_derived_kind="vector",
        )
        with pytest.raises(
            KnowledgePublicationError,
            match="KNOWLEDGE_BUILDER_INPUT_INVALID",
        ):
            placeholder.service.publish_theory_and_wiki(
                placeholder.operation_id,
                theory_id=knowledge.theory.theory_id,
                theory_revision=knowledge.theory.revision,
                wiki_id=knowledge.wiki.wiki_id,
                wiki_revision=knowledge.wiki.revision,
            )

        extra_draft = knowledge.claim_drafts[0].model_copy(
            update={"text": "不属于该 Wiki 的撤销主张"}
        )
        proposal = knowledge.claim_service.propose(extra_draft)
        preview = knowledge.claim_service.preview(proposal.proposal_id)
        extra = knowledge.claim_service.commit(
            proposal.proposal_id,
            descriptor=preview.descriptor,
            approval_request_id=harness.confirm(preview.descriptor),
        )
        harness.connection.execute(
            "UPDATE claims SET review_status = 'REVOKED' WHERE claim_id = ?",
            (extra.claim_id,),
        )
        overbroad = prepare_global_publication(
            harness,
            knowledge,
            extra_claim_ids=(extra.claim_id,),
        )
        with pytest.raises(
            KnowledgePublicationError,
            match="KNOWLEDGE_CLAIM_CLOSURE_MISMATCH",
        ):
            overbroad.service.publish_theory_and_wiki(
                overbroad.operation_id,
                theory_id=knowledge.theory.theory_id,
                theory_revision=knowledge.theory.revision,
                wiki_id=knowledge.wiki.wiki_id,
                wiki_revision=knowledge.wiki.revision,
            )
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM runtime_epochs"
        ).fetchone() == (0,)
    finally:
        harness.close()


def test_production_publication_rejects_legacy_builder_inputs(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        publication = prepare_global_publication(
            harness,
            knowledge,
            legacy_derived_kind="vector",
        )

        with pytest.raises(
            KnowledgePublicationError,
            match="KNOWLEDGE_BUILDER_INPUT_INVALID",
        ):
            publication.service.publish_theory_and_wiki(
                publication.operation_id,
                theory_id=knowledge.theory.theory_id,
                theory_revision=knowledge.theory.revision,
                wiki_id=knowledge.wiki.wiki_id,
                wiki_revision=knowledge.wiki.revision,
            )

        assert harness.connection.execute(
            "SELECT COUNT(*) FROM runtime_epochs"
        ).fetchone() == (0,)
    finally:
        harness.close()


def test_legacy_builder_input_escape_hatch_is_absent() -> None:
    assert "allow_legacy_builder_inputs" not in inspect.signature(
        KnowledgePublicationService
    ).parameters
    assert "allow_legacy_builder_inputs" not in inspect.signature(
        prepare_global_publication
    ).parameters


def test_publication_rejects_two_manifests_for_one_derived_kind(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        publication = prepare_global_publication(
            harness,
            knowledge,
            duplicate_derived_kind="vector",
        )

        with pytest.raises(
            KnowledgePublicationError,
            match="KNOWLEDGE_DERIVED_MANIFEST_CARDINALITY_INVALID",
        ):
            publication.service.publish_theory_and_wiki(
                publication.operation_id,
                theory_id=knowledge.theory.theory_id,
                theory_revision=knowledge.theory.revision,
                wiki_id=knowledge.wiki.wiki_id,
                wiki_revision=knowledge.wiki.revision,
            )

        assert harness.connection.execute(
            "SELECT COUNT(*) FROM runtime_epochs"
        ).fetchone() == (0,)
    finally:
        harness.close()


def test_builder_cas_tamper_before_epoch_switch_fails_inside_transaction(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)

        def tamper_builder_cas(phase: str) -> None:
            if phase != "closure_verified":
                return
            row = harness.connection.execute(
                """
                SELECT a.object_sha256, a.size_bytes, a.media_type
                  FROM artifact_manifests AS m
                  JOIN artifact_members AS a ON a.manifest_id = m.manifest_id
                 WHERE m.artifact_kind = 'vector'
                """
            ).fetchone()
            assert row is not None
            reference = harness.store.reference(
                content_sha256=str(row[0]),
                size_bytes=int(row[1]),
                media_type=str(row[2]),
            )
            reference.path.write_bytes(b"{}")

        publication = prepare_global_publication(
            harness,
            knowledge,
            failure_hook=tamper_builder_cas,
        )

        with pytest.raises(
            KnowledgePublicationError,
            match="KNOWLEDGE_ARTIFACT_CAS_INVALID",
        ):
            publication.service.publish_theory_and_wiki(
                publication.operation_id,
                theory_id=knowledge.theory.theory_id,
                theory_revision=knowledge.theory.revision,
                wiki_id=knowledge.wiki.wiki_id,
                wiki_revision=knowledge.wiki.revision,
            )

        assert harness.connection.execute(
            "SELECT COUNT(*) FROM runtime_epochs"
        ).fetchone() == (0,)
        assert harness.connection.execute(
            "SELECT status FROM theory_revisions"
        ).fetchall() == [("PREPARED",)]
    finally:
        harness.close()


def test_catalog_change_after_verify_before_begin_rejects_stale_snapshot(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)

        def mutate_catalog(phase: str) -> None:
            if phase == "closure_verified":
                harness.connection.execute(
                    """
                    UPDATE knowledge_catalog_state
                       SET catalog_version = catalog_version + 1
                     WHERE singleton = 1
                    """
                )

        publication = prepare_global_publication(
            harness,
            knowledge,
            failure_hook=mutate_catalog,
        )
        with pytest.raises(
            KnowledgePublicationError,
            match="KNOWLEDGE_CATALOG_SNAPSHOT_STALE",
        ):
            publication.service.publish_theory_and_wiki(
                publication.operation_id,
                theory_id=knowledge.theory.theory_id,
                theory_revision=knowledge.theory.revision,
                wiki_id=knowledge.wiki.wiki_id,
                wiki_revision=knowledge.wiki.revision,
            )
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM runtime_epochs"
        ).fetchone() == (0,)
        assert harness.connection.execute(
            "SELECT status FROM theory_revisions"
        ).fetchall() == [("PREPARED",)]
    finally:
        harness.close()


def test_restart_can_revoke_c1_and_no_active_wiki_or_epoch_bypasses_it(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        publication = prepare_global_publication(harness, knowledge)
        publication.service.publish_theory_and_wiki(
            publication.operation_id,
            theory_id=knowledge.theory.theory_id,
            theory_revision=knowledge.theory.revision,
            wiki_id=knowledge.wiki.wiki_id,
            wiki_revision=knowledge.wiki.revision,
        )
        restarted_theory, restarted_wiki = rebuild_authority_services(harness)
        descriptor = restarted_theory.preview_revoke(
            knowledge.theory.theory_id,
            knowledge.theory.revision,
        )
        revoked = restarted_theory.revoke(
            knowledge.theory.theory_id,
            knowledge.theory.revision,
            actor="primary_counselor",
            approval_request_id=harness.confirm(descriptor),
        )

        assert revoked.status == "revoked"
        assert restarted_theory.get_active(knowledge.theory.theory_id) is None
        assert restarted_wiki.get_active(knowledge.wiki.wiki_id) is None
        assert harness.connection.execute(
            "SELECT review_status FROM wiki_revisions"
        ).fetchall() == [("REVOKED",)]
        assert harness.connection.execute(
            "SELECT review_status FROM claims WHERE source_grade = 'C1'"
        ).fetchall() == [("REVOKED",)]
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM runtime_epochs WHERE state = 'ACTIVE'"
        ).fetchone() == (0,)
        assert harness.connection.execute(
            """
            SELECT authorization_epoch, tombstone_epoch
              FROM knowledge_catalog_state WHERE singleton = 1
            """
        ).fetchone() == (1, 1)
    finally:
        harness.close()


def test_restart_can_revoke_generic_claim_and_dependent_wiki_fails_closed(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        publication = prepare_global_publication(harness, knowledge)
        publication.service.publish_theory_and_wiki(
            publication.operation_id,
            theory_id=knowledge.theory.theory_id,
            theory_revision=knowledge.theory.revision,
            wiki_id=knowledge.wiki.wiki_id,
            wiki_revision=knowledge.wiki.revision,
        )
        restarted_claims = _rebuild_claim_service(harness, knowledge)
        target = knowledge.claims[0]
        descriptor = restarted_claims.preview_revoke(target.claim_id, target.version)
        revoked = restarted_claims.revoke(
            target.claim_id,
            target.version,
            approval_request_id=harness.confirm(descriptor),
        )

        assert revoked.review_status == "revoked"
        assert _rebuild_claim_service(harness, knowledge).get(
            target.claim_id, target.version
        ).review_status == "revoked"
        _, restarted_wiki = rebuild_authority_services(harness)
        assert restarted_wiki.get_active(knowledge.wiki.wiki_id) is None
        assert harness.connection.execute(
            "SELECT review_status FROM wiki_revisions"
        ).fetchall() == [("REVOKED",)]
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM runtime_epochs WHERE state = 'ACTIVE'"
        ).fetchone() == (0,)
        assert harness.connection.execute(
            """
            SELECT authorization_epoch, tombstone_epoch
              FROM knowledge_catalog_state WHERE singleton = 1
            """
        ).fetchone() == (1, 1)
    finally:
        harness.close()


def test_same_catalog_authority_change_between_verify_and_begin_is_rechecked(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)
        target_claim = knowledge.claims[0].claim_id

        def revoke_without_catalog_bump(phase: str) -> None:
            if phase == "closure_verified":
                harness.connection.execute(
                    "UPDATE claims SET review_status = 'REVOKED' WHERE claim_id = ?",
                    (target_claim,),
                )

        publication = prepare_global_publication(
            harness,
            knowledge,
            failure_hook=revoke_without_catalog_bump,
        )
        with pytest.raises(
            KnowledgePublicationError,
            match="KNOWLEDGE_CLAIM_NOT_PUBLISHABLE",
        ):
            publication.service.publish_theory_and_wiki(
                publication.operation_id,
                theory_id=knowledge.theory.theory_id,
                theory_revision=knowledge.theory.revision,
                wiki_id=knowledge.wiki.wiki_id,
                wiki_revision=knowledge.wiki.revision,
            )
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM runtime_epochs"
        ).fetchone() == (0,)
    finally:
        harness.close()


def test_manifest_version_tamper_after_verify_is_rejected_inside_transaction(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        knowledge = prepare_governed_knowledge(harness)

        def tamper_manifest_version(phase: str) -> None:
            if phase == "closure_verified":
                harness.connection.execute(
                    """
                    UPDATE artifact_manifests SET source_version = '99'
                     WHERE operation_id = ? AND artifact_kind = 'vector'
                    """,
                    (publication.operation_id,),
                )

        publication = prepare_global_publication(
            harness,
            knowledge,
            failure_hook=tamper_manifest_version,
        )
        with pytest.raises(
            KnowledgePublicationError,
            match="KNOWLEDGE_ARTIFACT_VERSION_MISMATCH",
        ):
            publication.service.publish_theory_and_wiki(
                publication.operation_id,
                theory_id=knowledge.theory.theory_id,
                theory_revision=knowledge.theory.revision,
                wiki_id=knowledge.wiki.wiki_id,
                wiki_revision=knowledge.wiki.revision,
            )
        assert harness.connection.execute(
            "SELECT COUNT(*) FROM runtime_epochs"
        ).fetchone() == (0,)
    finally:
        harness.close()
