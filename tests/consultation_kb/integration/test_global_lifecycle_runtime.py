from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from consultation_kb.approvals.attestation import (
    LocalHmacTargetExecutionAttestor,
    LocalHmacTargetExecutionProofVerifier,
)
from consultation_kb.approvals.models import (
    ApprovalExecutionTicket,
    descriptor_sha256 as ticket_descriptor_sha256,
)
from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.provider import (
    LocalHmacApprovalSigner,
    LocalHmacApprovalVerifier,
)
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.core.errors import (
    ScopedObjectAccessDeniedError,
    WorkflowErrorCode,
    WorkflowOperationalError,
)
from consultation_kb.core.ids import IdFactory
from consultation_kb.lifecycle.production_rebuild import (
    CONFIG_FILENAME,
    ProductionRebuildConfig,
    resolve_global_rebuild,
)
from consultation_kb.mcp.context import BoundTransport
from consultation_kb.mcp.global_lifecycle_runtime import (
    ProductionGlobalLifecycleRuntime,
    TargetScopedDeletionAuthority,
)
from consultation_kb.mcp.schemas import (
    CancelRebuildInput,
    CommitDeleteInput,
    GetRebuildReportInput,
    GetRebuildStatusInput,
    LifecycleBaseVersion,
    PreviewDeleteInput,
    PreviewRebuildInput,
    StartRebuildInput,
)
from consultation_kb.models.manifests import ApprovalReceipt, DraftDescriptor
from consultation_kb.security.scope_identity import global_approval_scope_sha256
from consultation_kb.storage.connection import connect_database
from consultation_kb.vault.content_store import ContentStore
from consultation_kb.security.worker_protocol import ArchiveContentRef
from tests.consultation_kb.approval_support import MutableClock, TestProtector
from tests.consultation_kb.retrieval_support import model_descriptor
from tests.consultation_kb.knowledge_integration_support import (
    build_global_knowledge_harness,
    prepare_global_publication,
    prepare_governed_knowledge,
)
from tests.consultation_kb.integration.test_case_publish_saga import (
    _MutableCasePublishAuthority,
    _global_database,
    _package,
    _publisher,
)


class _WrongScopeApprovalRuntime:
    def __init__(self, ticket: ApprovalExecutionTicket) -> None:
        self.ticket = ticket

    def issue_for_execution(
        self,
        request_id: str,
        descriptor: DraftDescriptor,
        *,
        operation_id: str,
    ) -> ApprovalExecutionTicket:
        assert request_id == self.ticket.request_id
        assert descriptor == self.ticket.descriptor
        assert operation_id == self.ticket.operation_id
        return self.ticket

    def acknowledge(self, _proof: object) -> object:
        raise AssertionError("wrong-scope approval must not be acknowledged")


class _UnreachableExecutionRuntime:
    def apply_in_transaction(self, *_args: object) -> object:
        raise AssertionError("wrong-scope approval must not reach execution")


def test_global_runtime_rejects_approval_ticket_for_another_scope(
    tmp_path: Path,
) -> None:
    global_root = (tmp_path / "global").resolve()
    global_root.mkdir()
    connection = connect_database(global_root / "catalog.sqlite3", "writer")
    try:
        ids = IdFactory()
        scope_sha256 = "a" * 64
        descriptor = DraftDescriptor(
            purpose="rebuild",
            target_id="global_rebuild:wiki_index",
            base_version=0,
            draft_sha256="b" * 64,
        )
        request_id = ids.object_id("approval_request")
        operation_id = ids.object_id("approval_operation")
        now = datetime.now(UTC)
        ticket = ApprovalExecutionTicket(
            operation_id=operation_id,
            target_scope_hash="f" * 64,
            descriptor=descriptor,
            receipt=ApprovalReceipt(
                request_id=request_id,
                descriptor_sha256=ticket_descriptor_sha256(descriptor),
                approver_role="primary_counselor",
                approved_at=now,
                expires_at=now + timedelta(minutes=5),
                nonce="wrong-scope-ticket-nonce",
                provider_id="test-provider",
                signature="test-provider-signature",
            ),
            issuance_signature="c" * 64,
        )
        runtime = ProductionGlobalLifecycleRuntime(
            connection,
            global_root=global_root,
            scope_sha256=scope_sha256,
            approval_service=_WrongScopeApprovalRuntime(ticket),
            execution_guard=_UnreachableExecutionRuntime(),
        )
        store = ContentStore(global_root / "cas")
        plan_object_id = ids.object_id("lifecycle_plan")
        stored = store.finalize(
            store.stage_bytes(
                b'{"schema_version":"wrong_scope_test.v1"}',
                purpose="rebuild",
                manifest_id=plan_object_id,
                media_type="application/json",
            )
        )
        request = StartRebuildInput(
            session_handle="opaque-global-session-handle-0001",
            database_scope="global",
            scope_sha256=scope_sha256,
            approval_operation_id=operation_id,
            approval_request_id=request_id,
            plan_sha256=descriptor.draft_sha256,
            base_versions=(
                LifecycleBaseVersion(
                    authority_key="tombstone_epoch",
                    scope_sha256=scope_sha256,
                    version=0,
                ),
            ),
            plan_ref=ArchiveContentRef(
                object_id=plan_object_id,
                version=1,
                content_sha256=stored.content_sha256,
                media_type=stored.media_type,
                size_bytes=stored.size_bytes,
            ),
            idempotency_key="wrong-scope-ticket-test",
        )

        with pytest.raises(WorkflowOperationalError) as denied:
            runtime._execute_approved(  # noqa: SLF001
                request,
                descriptor,
                lambda _connection: None,
            )
        assert denied.value.code is WorkflowErrorCode.LIFECYCLE_APPROVAL_REQUIRED
    finally:
        connection.close()


def test_global_runtime_rejects_a_client_database_root(tmp_path: Path) -> None:
    client_root = (tmp_path / "clients" / "opaque-client-root").resolve()
    client_root.mkdir(parents=True)
    connection = connect_database(client_root / "client.sqlite3", "writer")
    try:
        with pytest.raises(TypeError, match="GLOBAL_LIFECYCLE_DATABASE_REQUIRED"):
            ProductionGlobalLifecycleRuntime(
                connection,
                global_root=client_root,
                scope_sha256="a" * 64,
            )
    finally:
        connection.close()


def test_global_delete_preview_commit_and_restart_safe_replay(
    tmp_path: Path,
) -> None:
    vault = (tmp_path / "vault").resolve()
    global_root = vault / "global"
    global_root.mkdir(parents=True)
    connection = _global_database(global_root / "catalog.sqlite3")
    try:
        event, transfer, published_at = _package()
        authority = _MutableCasePublishAuthority(transfer)
        publication = _publisher(
            connection,
            global_root,
            published_at,
            authority,
        ).process(event, transfer)
        clock = MutableClock(published_at + timedelta(minutes=4))
        counters = itertools.count(20_000)
        nonces = itertools.count(1)
        ids = IdFactory(clock, lambda: next(counters))
        signer = LocalHmacApprovalSigner(
            secret=b"p" * 32,
            provider_id="local-review-agent",
            clock=clock,
        )
        scoped: dict[str, TargetScopedDeletionAuthority] = {}

        def target_authority(scope_sha256: str) -> TargetScopedDeletionAuthority:
            existing = scoped.get(scope_sha256)
            if existing is not None:
                return existing
            approvals = ApprovalService(
                connection,
                provider=LocalHmacApprovalVerifier(
                    secret=b"p" * 32,
                    provider_id="local-review-agent",
                ),
                protector=TestProtector(),
                clock=clock,
                id_factory=ids,
                target_scope_hash=scope_sha256,
                vault_id="synthetic-global-delete-vault",
                execution_secret=b"e" * 32,
                execution_proof_verifier=(
                    LocalHmacTargetExecutionProofVerifier(
                        secret=b"t" * 32,
                        attestor_id="global-delete-writer",
                    )
                ),
                nonce_source=lambda size: next(nonces).to_bytes(size, "big"),
            )
            created = TargetScopedDeletionAuthority(
                approval_service=approvals,
                execution_guard=ApprovalExecutionGuard(
                    connection,
                    approval_service=approvals,
                    execution_proof_signer=LocalHmacTargetExecutionAttestor(
                        secret=b"t" * 32,
                        attestor_id="global-delete-writer",
                    ),
                    clock=clock,
                ),
            )
            scoped[scope_sha256] = created
            return created

        scope_sha256 = global_approval_scope_sha256(vault)
        runtime = ProductionGlobalLifecycleRuntime(
            connection,
            global_root=global_root,
            scope_sha256=scope_sha256,
            target_approval_factory=target_authority,
            content_store=ContentStore(global_root),
            clock=clock,
            id_factory=ids,
        )
        binding = BoundTransport(
            "stdio-global-delete",
            "opaque-global-session-handle-0001",
        )
        preview = runtime.invoke(
            "preview_delete",
            PreviewDeleteInput(
                session_handle=binding.session_handle,
                database_scope="global",
                scope_sha256=scope_sha256,
                target_type="case",
                target_id=publication.case_ref.object_id,
                target_version=publication.case_ref.version,
                target_content_sha256=publication.case_ref.content_sha256,
                reason_code="authorization_revoked",
            ),
            binding=binding,
        )
        assert isinstance(preview, dict)
        plan_ref = preview["plan_ref"]
        assert hasattr(plan_ref, "version_ref")
        target = target_authority(str(preview["target_scope_hash"]))
        target.approval_service.confirm(
            signer.confirm(
                target.approval_service.challenge_for_review(
                    str(preview["approval_request_id"])
                )
            )
        )
        commit = CommitDeleteInput(
            session_handle=binding.session_handle,
            database_scope="global",
            scope_sha256=scope_sha256,
            approval_operation_id=str(preview["proposed_operation_id"]),
            approval_request_id=str(preview["approval_request_id"]),
            plan_sha256=str(preview["plan_sha256"]),
            base_versions=tuple(preview["base_versions"]),
            plan_ref=plan_ref,
            target_scope_hash=str(preview["target_scope_hash"]),
        )

        with pytest.raises(WorkflowOperationalError) as mismatched_ref:
            runtime.invoke(
                "commit_delete",
                commit.model_copy(
                    update={
                        "plan_ref": plan_ref.model_copy(
                            update={"object_id": ids.object_id("lifecycle_plan")}
                        )
                    }
                ),
                binding=binding,
            )
        assert (
            mismatched_ref.value.code
            is WorkflowErrorCode.LIFECYCLE_APPROVAL_REQUIRED
        )

        committed = runtime.invoke("commit_delete", commit, binding=binding)
        replayed = runtime.invoke("commit_delete", commit, binding=binding)
        assert committed == replayed
        assert isinstance(committed, dict)
        assert committed["status"] == "tombstone_committed"
        assert connection.execute(
            "SELECT state FROM cases WHERE case_id = ?",
            (publication.case_ref.object_id,),
        ).fetchone() == ("REVOKED",)
        assert target.approval_service.get(
            str(preview["approval_request_id"])
        ).state == "acknowledged"
    finally:
        connection.close()


def test_global_runtime_queues_reports_and_cancels_with_real_p1_authority(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(
        tmp_path,
        root=(tmp_path / "vault" / "global").resolve(),
        database_name="catalog.sqlite3",
    )
    connection = harness.connection
    global_root = harness.root.resolve()
    try:
        knowledge = prepare_governed_knowledge(
            harness,
            include_graph_relation=True,
        )
        authority_version = int(
            connection.execute(
                "SELECT COALESCE(MAX(applied_commit_version), 0) + 1 "
                "FROM approval_executions"
            ).fetchone()[0]
        )
        publication = prepare_global_publication(
            harness,
            knowledge,
            authority_base_version=authority_version,
        )
        publication.service.publish_theory_and_wiki(
            publication.operation_id,
            theory_id=knowledge.theory.theory_id,
            theory_revision=knowledge.theory.revision,
            wiki_id=knowledge.wiki.wiki_id,
            wiki_revision=knowledge.wiki.revision,
        )
        scope_sha256 = "a" * 64
        descriptor = model_descriptor()
        vocabulary: dict[str, tuple[float, ...]] = {}
        for (reference,) in connection.execute(
            "SELECT retrieval_content_ref FROM passages "
            "ORDER BY passage_id, version"
        ):
            text = harness.store.read_hash_verified(
                str(reference).removeprefix("sha256:")
            ).decode("utf-8", errors="strict")
            vocabulary[text] = (1.0, 0.0)
        production = ProductionRebuildConfig.create_global(
            scope_sha256=scope_sha256,
            model_descriptor=descriptor,
            embedder_kind="deterministic_test",
            deterministic_vocabulary=vocabulary,
            test_mode=True,
            target_wiki_id=knowledge.wiki.wiki_id,
            cas_directory="global-content",
            graphify_production=False,
        )
        (global_root / CONFIG_FILENAME).write_bytes(production.canonical_bytes)

        approvals = harness.approvals
        guard = harness.guard
        runtime = ProductionGlobalLifecycleRuntime(
            connection,
            global_root=global_root,
            scope_sha256=scope_sha256,
            approval_service=approvals,
            execution_guard=guard,
        )
        binding = BoundTransport(
            "stdio-global-lifecycle",
            "opaque-global-session-handle-0001",
        )

        preview = runtime.invoke(
            "preview_rebuild",
            PreviewRebuildInput(
                session_handle=binding.session_handle,
                database_scope="global",
                scope_sha256=scope_sha256,
                action="start",
                purpose="all",
            ),
            binding=binding,
        )
        assert isinstance(preview, dict)
        approvals.confirm(
            harness.signer.confirm(
                approvals.challenge_for_review(
                    str(preview["approval_request_id"])
                )
            )
        )
        start = StartRebuildInput(
            session_handle=binding.session_handle,
            database_scope="global",
            scope_sha256=scope_sha256,
            approval_operation_id=str(preview["proposed_operation_id"]),
            approval_request_id=str(preview["approval_request_id"]),
            plan_sha256=str(preview["plan_sha256"]),
            base_versions=preview["base_versions"],
            plan_ref=preview["plan_ref"],
            idempotency_key="global-full-closure-rebuild-once",
        )

        with pytest.raises(WorkflowOperationalError) as mismatch:
            runtime.invoke(
                "start_rebuild",
                start.model_copy(update={"plan_sha256": "f" * 64}),
                binding=binding,
            )
        assert mismatch.value.code is WorkflowErrorCode.LIFECYCLE_PLAN_MISMATCH

        stale_base = start.base_versions[0].model_copy(
            update={"version": start.base_versions[0].version + 1}
        )
        with pytest.raises(WorkflowOperationalError) as partial:
            runtime.invoke(
                "start_rebuild",
                start.model_copy(update={"base_versions": (stale_base,)}),
                binding=binding,
            )
        assert partial.value.code is WorkflowErrorCode.LIFECYCLE_PLAN_MISMATCH

        queued = runtime.invoke("start_rebuild", start, binding=binding)

        assert isinstance(queued, dict)
        assert queued["state"] == "queued"
        assert queued["plan_sha256"] == preview["plan_sha256"]
        job_id = str(queued["job_id"])
        status = runtime.invoke(
            "get_rebuild_status",
            GetRebuildStatusInput(
                session_handle=binding.session_handle,
                database_scope="global",
                scope_sha256=scope_sha256,
                job_id=job_id,
            ),
            binding=binding,
        )
        report = runtime.invoke(
            "get_rebuild_report",
            GetRebuildReportInput(
                session_handle=binding.session_handle,
                database_scope="global",
                scope_sha256=scope_sha256,
                job_id=job_id,
            ),
            binding=binding,
        )
        assert isinstance(status, dict) and status["state"] == "queued"
        assert isinstance(report, dict) and report["journal"][0]["state"] == "queued"

        completed = resolve_global_rebuild(
            connection,
            global_root,
            scope_sha256,
        ).run_next()
        assert completed is not None
        assert completed.state == "succeeded", completed.last_error_code
        assert connection.execute(
            "SELECT count(*) FROM active_artifacts WHERE epoch = ("
            "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE')"
        ).fetchone() == (8,)

        second_preview = runtime.invoke(
            "preview_rebuild",
            PreviewRebuildInput(
                session_handle=binding.session_handle,
                database_scope="global",
                scope_sha256=scope_sha256,
                action="start",
                purpose="all",
            ),
            binding=binding,
        )
        assert isinstance(second_preview, dict)
        approvals.confirm(
            harness.signer.confirm(
                approvals.challenge_for_review(
                    str(second_preview["approval_request_id"])
                )
            )
        )
        second = runtime.invoke(
            "start_rebuild",
            StartRebuildInput(
                session_handle=binding.session_handle,
                database_scope="global",
                scope_sha256=scope_sha256,
                approval_operation_id=str(
                    second_preview["proposed_operation_id"]
                ),
                approval_request_id=str(second_preview["approval_request_id"]),
                plan_sha256=str(second_preview["plan_sha256"]),
                base_versions=second_preview["base_versions"],
                plan_ref=second_preview["plan_ref"],
                idempotency_key="global-full-closure-rebuild-cancelled",
            ),
            binding=binding,
        )
        assert isinstance(second, dict) and second["state"] == "queued"
        second_job_id = str(second["job_id"])
        cancel_preview = runtime.invoke(
            "preview_rebuild",
            PreviewRebuildInput(
                session_handle=binding.session_handle,
                database_scope="global",
                scope_sha256=scope_sha256,
                action="cancel",
                job_id=second_job_id,
            ),
            binding=binding,
        )
        assert isinstance(cancel_preview, dict)
        approvals.confirm(
            harness.signer.confirm(
                approvals.challenge_for_review(
                    str(cancel_preview["approval_request_id"])
                )
            )
        )
        cancelled = runtime.invoke(
            "cancel_rebuild",
            CancelRebuildInput(
                session_handle=binding.session_handle,
                database_scope="global",
                scope_sha256=scope_sha256,
                approval_operation_id=str(
                    cancel_preview["proposed_operation_id"]
                ),
                approval_request_id=str(cancel_preview["approval_request_id"]),
                plan_sha256=str(cancel_preview["plan_sha256"]),
                base_versions=cancel_preview["base_versions"],
                plan_ref=cancel_preview["plan_ref"],
            ),
            binding=binding,
        )
        assert isinstance(cancelled, dict)
        assert cancelled["state"] == "cancelled"

        with pytest.raises(ScopedObjectAccessDeniedError):
            runtime.invoke(
                "get_rebuild_status",
                GetRebuildStatusInput(
                    session_handle=binding.session_handle,
                    database_scope="global",
                    scope_sha256="f" * 64,
                    job_id=job_id,
                ),
                binding=binding,
            )
    finally:
        harness.close()
