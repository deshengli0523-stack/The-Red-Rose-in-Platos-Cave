from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import pytest

from consultation_kb.approvals.models import (
    ApprovalExecutionTicket,
    ApprovalRequest,
)
from consultation_kb.core.errors import WorkflowErrorCode, WorkflowOperationalError
from consultation_kb.knowledge.theory import TheoryRevisionService
from consultation_kb.knowledge.wiki import WikiRevisionService
from consultation_kb.lifecycle.rollback import (
    ArtifactRollbackPlan,
    RollbackError,
    RollbackPlanEnvelope,
    RollbackPreview,
    SqliteRollbackWorkflow,
)
from consultation_kb.mcp.context import BoundTransport
from consultation_kb.mcp.global_lifecycle_runtime import (
    ProductionGlobalLifecycleRuntime,
)
from consultation_kb.mcp.schemas import RollbackVersionInput
from consultation_kb.models.wiki import WikiRevisionDraft
from tests.consultation_kb.knowledge_integration_support import (
    GlobalKnowledgeHarness,
    PreparedKnowledge,
    build_global_knowledge_harness,
    prepare_global_publication,
    prepare_governed_knowledge,
    prepare_successor_knowledge,
    rebuild_authority_services,
)


RollbackSource = Literal["wiki", "theory"]
SCOPE_SHA256 = "a" * 64


@dataclass(slots=True)
class _GlobalRollbackFixture:
    harness: GlobalKnowledgeHarness
    historical: PreparedKnowledge
    current: PreparedKnowledge
    theories: TheoryRevisionService
    wikis: WikiRevisionService
    workflow: SqliteRollbackWorkflow

    def close(self) -> None:
        self.harness.close()


def _prepare_wiki_successor(
    harness: GlobalKnowledgeHarness,
    historical: PreparedKnowledge,
) -> PreparedKnowledge:
    """Prepare a Wiki-only successor whose exact C1 dependency stays active."""

    draft = WikiRevisionDraft(
        wiki_id=historical.wiki.wiki_id,
        slug=historical.wiki.slug,
        title=f"{historical.wiki.title}（Wiki 2.0）",
        base_revision=historical.wiki.revision,
        diff_kind="supersede",
        sections=tuple(
            section.model_copy(update={"body": f"{section.body}（Wiki 2.0 修订）"})
            for section in historical.wiki.sections
        ),
        theory_revision_refs=historical.wiki.theory_revision_refs,
        relationships=historical.wiki.relationships,
        graph_relations=historical.wiki.graph_relations,
        review_due_at=historical.wiki.review_due_at,
        unresolved_questions=historical.wiki.unresolved_questions,
    )
    proposal = historical.wiki_service.propose_diff(draft)
    wiki = historical.wiki_service.approve(
        proposal.proposal_id,
        actor="primary_counselor",
        approval_request_id=harness.confirm(
            historical.wiki_service.preview(proposal.proposal_id)
        ),
    )
    return PreparedKnowledge(
        claims=historical.claims,
        claim_service=historical.claim_service,
        claim_drafts=historical.claim_drafts,
        theory=historical.theory,
        wiki=wiki,
        theory_service=historical.theory_service,
        wiki_service=historical.wiki_service,
        source_ids=historical.source_ids,
    )


def _fixture(
    tmp_path: Path,
    source: RollbackSource,
    *,
    production_runtime_layout: bool = False,
) -> _GlobalRollbackFixture:
    harness = (
        build_global_knowledge_harness(
            tmp_path,
            root=(tmp_path / "global").resolve(),
            database_name="catalog.sqlite3",
        )
        if production_runtime_layout
        else build_global_knowledge_harness(tmp_path)
    )
    try:
        historical = prepare_governed_knowledge(harness)
        first_publication = prepare_global_publication(harness, historical)
        first_publication.service.publish_theory_and_wiki(
            first_publication.operation_id,
            theory_id=historical.theory.theory_id,
            theory_revision=historical.theory.revision,
            wiki_id=historical.wiki.wiki_id,
            wiki_revision=historical.wiki.revision,
        )

        current = (
            _prepare_wiki_successor(harness, historical)
            if source == "wiki"
            else prepare_successor_knowledge(harness, historical)
        )
        if source == "wiki":
            # Re-stage the unchanged synthetic C1 authority with the Wiki-only
            # successor.  This keeps both Wiki revisions bound to the same exact
            # C1 revision while exercising the production combined closure.
            harness.connection.execute(
                "UPDATE theory_revisions SET status = 'PREPARED' "
                "WHERE theory_id = ? AND revision = ? AND status = 'ACTIVE'",
                (current.theory.theory_id, current.theory.revision),
            )
            harness.connection.execute(
                "UPDATE claims SET review_status = 'REVIEWED' "
                "WHERE source_grade = 'C1' AND theory_revision_id = ? "
                "AND theory_revision = ? AND review_status = 'APPROVED'",
                (current.theory.theory_id, current.theory.revision),
            )
        second_publication = prepare_global_publication(
            harness,
            current,
            authority_base_version=2,
            expected_current_epoch=1,
        )
        if source == "wiki":
            second_publication.service.publish_theory_and_wiki(
                second_publication.operation_id,
                theory_id=current.theory.theory_id,
                theory_revision=current.theory.revision,
                wiki_id=current.wiki.wiki_id,
                wiki_revision=current.wiki.revision,
            )
        else:
            second_publication.service.publish_theory_and_wiki(
                second_publication.operation_id,
                theory_id=current.theory.theory_id,
                theory_revision=current.theory.revision,
                wiki_id=current.wiki.wiki_id,
                wiki_revision=current.wiki.revision,
            )

        theories, wikis = rebuild_authority_services(harness)
        workflow = SqliteRollbackWorkflow(
            harness.connection,
            database_scope="global",
            scope_sha256=SCOPE_SHA256,
            content_store=harness.store,
            clock=harness.clock,
            id_factory=harness.ids,
            approval_guard=harness.guard,
            wiki_service=wikis,
            theory_service=theories,
            scope_policy_repository=harness.scope_policies,
        )
        return _GlobalRollbackFixture(
            harness=harness,
            historical=historical,
            current=current,
            theories=theories,
            wikis=wikis,
            workflow=workflow,
        )
    except BaseException:
        harness.close()
        raise


def _preview_source(
    fixture: _GlobalRollbackFixture,
    source: RollbackSource,
    *,
    reason: str,
) -> RollbackPreview:
    if source == "wiki":
        return fixture.workflow.preview_wiki(
            wiki_id=fixture.current.wiki.wiki_id,
            current_version=2,
            restore_version=1,
            reason=reason,
        )
    return fixture.workflow.preview_theory(
        theory_id=fixture.current.theory.theory_id,
        current_version=2,
        restore_version=1,
        reason=reason,
    )


def _approve(
    fixture: _GlobalRollbackFixture,
    preview: RollbackPreview,
) -> tuple[ApprovalRequest, ApprovalExecutionTicket]:
    approvals = fixture.harness.approvals
    request = approvals.request(
        preview.descriptor,
        diff_object_ref=preview.plan_ref.version_ref,
    )
    approvals.confirm(
        fixture.harness.signer.confirm(
            approvals.challenge_for_review(request.request_id)
        )
    )
    ticket = approvals.issue_for_execution(
        request.request_id,
        preview.descriptor,
        operation_id=preview.proposed_operation_id,
    )
    return request, ticket


def _commit(
    fixture: _GlobalRollbackFixture,
    preview: RollbackPreview,
    request: ApprovalRequest,
    ticket: ApprovalExecutionTicket,
):
    return fixture.workflow.commit(
        plan_ref=preview.plan_ref,
        plan_sha256=preview.plan_sha256,
        base_versions=preview.base_versions,
        ticket=ticket,
        approval_request=request,
    )


def _read_envelope(
    fixture: _GlobalRollbackFixture,
    preview: RollbackPreview,
) -> RollbackPlanEnvelope:
    reference = preview.plan_ref
    payload = fixture.harness.store.read_verified(
        fixture.harness.store.reference(
            content_sha256=reference.content_sha256,
            media_type=reference.media_type,
            size_bytes=reference.size_bytes,
        )
    )
    return RollbackPlanEnvelope.model_validate_json(payload, strict=True)


def _write_footprint(fixture: _GlobalRollbackFixture) -> dict[str, object]:
    connection = fixture.harness.connection
    counted_tables = (
        "wiki_revisions",
        "theory_revisions",
        "claims",
        "approval_executions",
        "lifecycle_approval_attestations",
        "lifecycle_plan_objects",
        "rebuild_source_intents",
        "publication_operations",
        "runtime_epochs",
        "artifact_manifests",
        "active_artifacts",
    )
    return {
        "counts": tuple(
            (
                table,
                int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]),
            )
            for table in counted_tables
        ),
        "catalog": tuple(
            connection.execute(
                "SELECT catalog_version, authorization_epoch, tombstone_epoch "
                "FROM knowledge_catalog_state WHERE singleton = 1"
            ).fetchone()
        ),
        "wiki_statuses": tuple(
            connection.execute(
                "SELECT wiki_id, revision, review_status FROM wiki_revisions "
                "ORDER BY wiki_id, revision"
            ).fetchall()
        ),
        "theory_statuses": tuple(
            connection.execute(
                "SELECT theory_id, revision, status FROM theory_revisions "
                "ORDER BY theory_id, revision"
            ).fetchall()
        ),
        "claim_statuses": tuple(
            connection.execute(
                "SELECT claim_id, version, review_status FROM claims "
                "ORDER BY claim_id, version"
            ).fetchall()
        ),
    }


def _assert_prepared_successor(
    fixture: _GlobalRollbackFixture,
    source: RollbackSource,
) -> None:
    connection = fixture.harness.connection
    if source == "wiki":
        assert connection.execute(
            "SELECT revision, review_status FROM wiki_revisions WHERE wiki_id = ? "
            "ORDER BY revision",
            (fixture.current.wiki.wiki_id,),
        ).fetchall() == [
            (1, "SUPERSEDED"),
            (2, "ACTIVE"),
            (3, "PREPARED"),
        ]
        historical = fixture.wikis.get(fixture.historical.wiki.wiki_id, 1)
        successor = fixture.wikis.get(fixture.historical.wiki.wiki_id, 3)
        assert successor.title == historical.title
        assert successor.sections == historical.sections
        assert successor.base_revision == 2
        return

    assert connection.execute(
        "SELECT revision, status FROM theory_revisions WHERE theory_id = ? "
        "ORDER BY revision",
        (fixture.current.theory.theory_id,),
    ).fetchall() == [
        (1, "SUPERSEDED"),
        (2, "ACTIVE"),
        (3, "PREPARED"),
    ]
    historical = fixture.theories.get(fixture.historical.theory.theory_id, 1)
    successor = fixture.theories.get(fixture.historical.theory.theory_id, 3)
    assert successor.core_claims == historical.core_claims
    assert successor.declared_version == historical.declared_version
    assert successor.supersedes_ref is not None
    assert successor.supersedes_ref.version == 2


@pytest.mark.parametrize("source", ("wiki", "theory"))
def test_direct_global_rollback_prepares_successor_and_replays_idempotently(
    tmp_path: Path,
    source: RollbackSource,
) -> None:
    fixture = _fixture(tmp_path, source)
    try:
        preview = _preview_source(
            fixture,
            source,
            reason=f"restore historical {source} authority",
        )
        request, ticket = _approve(fixture, preview)

        committed = _commit(fixture, preview, request, ticket)

        assert committed.summary.rollback_kind == source
        assert committed.summary.successor_ref.version == 3
        assert committed.summary.requires_combined_publication is True
        _assert_prepared_successor(fixture, source)

        after_first_commit = _write_footprint(fixture)
        replayed = _commit(fixture, preview, request, ticket)
        assert replayed == committed
        assert _write_footprint(fixture) == after_first_commit
    finally:
        fixture.close()


@pytest.mark.parametrize("invalid_binding", ("operation", "plan_ref"))
def test_global_runtime_preflights_before_binding_one_shot_approval(
    tmp_path: Path,
    invalid_binding: str,
) -> None:
    fixture = _fixture(tmp_path, "wiki", production_runtime_layout=True)
    try:
        runtime = ProductionGlobalLifecycleRuntime(
            fixture.harness.connection,
            global_root=fixture.harness.root,
            scope_sha256=SCOPE_SHA256,
            approval_service=fixture.harness.approvals,
            execution_guard=fixture.harness.guard,
            rollback_workflow=fixture.workflow,
            content_store=fixture.harness.store,
            clock=fixture.harness.clock,
            id_factory=fixture.harness.ids,
        )
        binding = BoundTransport(
            "stdio-global-rollback",
            "opaque-global-session-handle-0001",
        )
        preview = runtime.invoke(
            "rollback_version",
            RollbackVersionInput(
                session_handle=binding.session_handle,
                database_scope="global",
                scope_sha256=SCOPE_SHA256,
                action="preview",
                target_kind="wiki",
                target_id=fixture.current.wiki.wiki_id,
                current_version=2,
                restore_version=1,
                reason="preflight exact global rollback binding",
            ),
            binding=binding,
        )
        assert isinstance(preview, dict)
        request_id = str(preview["approval_request_id"])
        fixture.harness.approvals.confirm(
            fixture.harness.signer.confirm(
                fixture.harness.approvals.challenge_for_review(request_id)
            )
        )
        commit = RollbackVersionInput(
            session_handle=binding.session_handle,
            database_scope="global",
            scope_sha256=SCOPE_SHA256,
            action="commit",
            plan_ref=preview["plan_ref"],
            approval_operation_id=str(preview["approval_operation_id"]),
            approval_request_id=request_id,
            plan_sha256=str(preview["plan_sha256"]),
            base_versions=preview["base_versions"],
        )
        if invalid_binding == "operation":
            invalid = commit.model_copy(
                update={
                    "approval_operation_id": fixture.harness.ids.object_id(
                        "rollback_operation"
                    )
                }
            )
        else:
            assert commit.plan_ref is not None
            invalid = commit.model_copy(
                update={
                    "plan_ref": commit.plan_ref.model_copy(
                        update={
                            "object_id": fixture.harness.ids.object_id(
                                "lifecycle_plan"
                            )
                        }
                    )
                }
            )

        with pytest.raises(WorkflowOperationalError) as rejected:
            runtime.invoke("rollback_version", invalid, binding=binding)

        assert rejected.value.code in {
            WorkflowErrorCode.LIFECYCLE_APPROVAL_REQUIRED,
            WorkflowErrorCode.LIFECYCLE_PLAN_MISMATCH,
        }
        assert fixture.harness.connection.execute(
            "SELECT operation_id FROM approval_receipts WHERE request_id = ?",
            (request_id,),
        ).fetchone() == (None,)

        committed = runtime.invoke("rollback_version", commit, binding=binding)
        assert isinstance(committed, dict)
        assert committed["status"] == "rollback_prepared"
        assert fixture.harness.connection.execute(
            "SELECT operation_id FROM approval_receipts WHERE request_id = ?",
            (request_id,),
        ).fetchone() == (str(preview["approval_operation_id"]),)
    finally:
        fixture.close()


@pytest.mark.parametrize(
    ("source", "artifact_key"),
    (
        ("wiki", "wiki_page"),
        ("wiki", "graph"),
        ("theory", "c1_revision"),
        ("theory", "vector"),
    ),
)
def test_artifact_rollback_binds_outer_plan_to_exact_source_successor(
    tmp_path: Path,
    source: RollbackSource,
    artifact_key: str,
) -> None:
    fixture = _fixture(tmp_path, source)
    try:
        reason = f"restore {source} authority and rebuild complete global closure"
        source_preview = _preview_source(fixture, source, reason=reason)
        catalog_version = fixture.harness.connection.execute(
            "SELECT catalog_version FROM knowledge_catalog_state WHERE singleton = 1"
        ).fetchone()
        assert catalog_version == ((20,) if source == "wiki" else (21,))
        artifact_preview = fixture.workflow.preview_artifact(
            artifact_key=artifact_key,
            current_version=2,
            restore_version=1,
            reason=reason,
            source_plan_ref=source_preview.plan_ref,
        )
        envelope = _read_envelope(fixture, artifact_preview)
        assert isinstance(envelope.plan, ArtifactRollbackPlan)
        assert envelope.plan.source_plan_ref == source_preview.plan_ref
        assert envelope.plan.source_plan_sha256 == source_preview.plan_sha256
        assert envelope.plan.source_rollback_kind == source
        assert envelope.plan.full_closure_purpose == "all"

        artifact_rows_before = fixture.harness.connection.execute(
            "SELECT count(*) FROM artifact_manifests"
        ).fetchone()
        active_rows_before = fixture.harness.connection.execute(
            "SELECT count(*) FROM active_artifacts"
        ).fetchone()
        request, ticket = _approve(fixture, artifact_preview)
        committed = _commit(fixture, artifact_preview, request, ticket)

        assert committed.summary.rollback_kind == "artifact"
        assert committed.summary.successor_ref.version == 3
        assert committed.summary.requires_combined_publication is True
        assert fixture.harness.connection.execute(
            "SELECT plan_object_id FROM lifecycle_approval_attestations "
            "WHERE operation_id = ?",
            (artifact_preview.proposed_operation_id,),
        ).fetchone() == (artifact_preview.plan_ref.object_id,)
        assert (
            fixture.harness.connection.execute(
                "SELECT count(*) FROM artifact_manifests"
            ).fetchone()
            == artifact_rows_before
        )
        assert (
            fixture.harness.connection.execute(
                "SELECT count(*) FROM active_artifacts"
            ).fetchone()
            == active_rows_before
        )
        _assert_prepared_successor(fixture, source)
    finally:
        fixture.close()


def test_artifact_rollback_rejects_forged_unattested_source_ref_without_write(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path, "wiki")
    try:
        reason = "reject an unattested source-plan identity"
        source = _preview_source(fixture, "wiki", reason=reason)
        forged = source.plan_ref.model_copy(
            update={
                "object_id": fixture.harness.ids.object_id("lifecycle_plan"),
            }
        )
        before = _write_footprint(fixture)

        with pytest.raises(RollbackError) as rejected:
            fixture.workflow.preview_artifact(
                artifact_key="wiki_page",
                current_version=2,
                restore_version=1,
                reason=reason,
                source_plan_ref=forged,
            )

        assert rejected.value.code == "ROLLBACK_PLAN_ATTESTATION_MISMATCH"
        assert _write_footprint(fixture) == before
    finally:
        fixture.close()


def test_shared_source_lineage_without_exact_revision_attestation_is_rejected(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path, "wiki")
    try:
        reason = "shared source lineage is not exact Wiki revision authority"
        source = _preview_source(fixture, "wiki", reason=reason)
        before = _write_footprint(fixture)

        with pytest.raises(RollbackError) as rejected:
            fixture.workflow.preview_artifact(
                artifact_key="claims",
                current_version=2,
                restore_version=1,
                reason=reason,
                source_plan_ref=source.plan_ref,
            )

        assert rejected.value.code == "ROLLBACK_ARTIFACT_SOURCE_LINEAGE_MISMATCH"
        assert _write_footprint(fixture) == before
    finally:
        fixture.close()


@pytest.mark.parametrize("source", ("wiki", "theory"))
def test_global_rollback_authority_drift_fails_before_business_write(
    tmp_path: Path,
    source: RollbackSource,
) -> None:
    fixture = _fixture(tmp_path, source)
    try:
        preview = _preview_source(
            fixture,
            source,
            reason=f"stale {source} rollback must not commit",
        )
        request, ticket = _approve(fixture, preview)
        fixture.harness.connection.execute(
            "UPDATE knowledge_catalog_state "
            "SET authorization_epoch = authorization_epoch + 1 "
            "WHERE singleton = 1"
        )
        before = _write_footprint(fixture)

        with pytest.raises(RollbackError) as rejected:
            _commit(fixture, preview, request, ticket)

        assert rejected.value.code == "ROLLBACK_AUTHORITY_CHANGED"
        assert _write_footprint(fixture) == before
    finally:
        fixture.close()


def test_wiki_rollback_rejects_superseded_c1_dependency_without_write(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path, "theory")
    try:
        before = _write_footprint(fixture)

        with pytest.raises(RollbackError) as rejected:
            fixture.workflow.preview_wiki(
                wiki_id=fixture.current.wiki.wiki_id,
                current_version=2,
                restore_version=1,
                reason="do not resurrect a superseded C1 dependency",
            )

        assert rejected.value.code == "ROLLBACK_DEPENDENCY_STALE"
        assert _write_footprint(fixture) == before
    finally:
        fixture.close()
