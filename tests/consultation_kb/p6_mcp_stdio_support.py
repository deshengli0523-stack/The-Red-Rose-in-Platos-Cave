from __future__ import annotations

import itertools
import json
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters

from consultation_kb.approvals.attestation import (
    LocalHmacTargetExecutionAttestor,
    LocalHmacTargetExecutionProofVerifier,
)
from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.provider import (
    LocalHmacApprovalSigner,
    LocalHmacApprovalVerifier,
)
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.core.client_ids import ClientIdFactory
from consultation_kb.core.config import AppConfig
from consultation_kb.core.ids import IdFactory
from consultation_kb.generation.contracts import (
    ConsistencyRiskReview,
    ConsistencySemanticAssessment,
    QueryGuardrails,
    QueryPlan,
    RouteOmission,
    Subquery,
    TheoryComparison,
    TheorySelection,
)
from consultation_kb.generation.evidence_scope import bound_evidence_ids
from consultation_kb.knowledge._canonical import text_sha256
from consultation_kb.knowledge.approval import P1GovernedWriteExecutor
from consultation_kb.knowledge.registrar import SourceRegistrar
from consultation_kb.knowledge.scope_policy import ScopePolicyRepository
from consultation_kb.policy.loader import PolicyLoader
from consultation_kb.models.evidence import EvidencePack
from consultation_kb.models.generation import GenerationStageEnvelope
from consultation_kb.storage.catalog import ClientCatalog
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.approval_support import MutableClock, TestProtector
from tests.consultation_kb.knowledge_integration_support import (
    GlobalKnowledgeHarness,
    PreparedKnowledge,
    PreparedPublication,
    prepare_global_publication,
    prepare_governed_knowledge,
)
from tests.consultation_kb.mcp_runtime_support import McpVaultHarness
from tests.consultation_kb.risk_support import attach_risk_policy_to_active_epoch


_P6_STAGE_ORDER = (
    "query_plan",
    "conceptualization",
    "theory_comparison",
    "reply_drafts",
    "evidence_audit",
    "consistency_risk_review",
    "final_bundle",
)


@dataclass(frozen=True, slots=True)
class SubmittedP6Turn:
    """Identifiers and candidate projection produced by one complete P6 run."""

    turn_id: str
    run_id: str
    candidate_ids: tuple[str, ...]
    candidate_texts: tuple[str, ...]


def p6_stdio_parameters(harness: PreparedP6McpVault) -> StdioServerParameters:
    """Start the real MCP server with deterministic offline P6 providers."""

    server = Path(__file__).parent / "integration" / "_p6_stdio_server.py"
    return StdioServerParameters(
        command=sys.executable,
        args=["-I", "-X", "utf8", str(server.resolve())],
        cwd=harness.mcp.repo_root,
        env={
            "CONSULTATION_VAULT_ROOT": str(harness.mcp.vault_root),
            "PYTHONUTF8": "1",
            "PYTHONUNBUFFERED": "1",
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "HF_DATASETS_OFFLINE": "1",
        },
    )


def _tool_envelope(result: object) -> dict[str, Any]:
    is_error = getattr(result, "isError")
    payload = getattr(result, "structuredContent")
    assert not is_error
    assert isinstance(payload, dict)
    assert set(payload) == {"ok", "result", "error"}
    return payload


def _stage_sha256(payload: dict[str, Any]) -> str:
    result = payload["result"]
    assert isinstance(result, dict)
    record = result["record"]
    assert isinstance(record, dict)
    artifact = record["artifact"]
    assert isinstance(artifact, dict)
    digest = artifact["content_sha256"]
    assert isinstance(digest, str)
    return digest


def _theory_for_pack(
    *,
    turn_id: str,
    run_id: str,
    parent_sha256s: tuple[str, ...],
    evidence_pack_sha256: str,
    evidence_id: str,
    pack: EvidencePack,
    created_at: datetime,
) -> TheoryComparison:
    decision = pack.c1_applicability
    primary = None
    questions: tuple[str, ...] = ()
    if decision.status == "applicable":
        assert decision.revision is not None
        primary = TheorySelection(
            theory_ref=decision.revision,
            role="primary_framework",
            source_grade="C1",
            empirical_support=decision.empirical_support,
            applicability="applicable",
            boundaries=(
                "Use the framework as guidance, not as a fact about the visitor.",
            ),
            evidence_ids=(evidence_id,),
        )
    elif decision.status == "insufficient_context":
        questions = (
            "Which relationship context should be clarified before applying the framework?",
        )
    return TheoryComparison(
        envelope=GenerationStageEnvelope(
            stage="theory_comparison",
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=parent_sha256s,
            created_at=created_at,
        ),
        evidence_pack_sha256=evidence_pack_sha256,
        primary_framework=primary,
        comparisons=(),
        conflicts=(),
        clarification_questions=questions,
        rationale_summary=(
            "Preserve the exact frozen C1 applicability state before drafting replies."
        ),
    )


async def _submit_stage(
    session: ClientSession,
    *,
    session_handle: str,
    idempotency_key: str,
    payload: object,
) -> dict[str, Any]:
    model_dump = getattr(payload, "model_dump")
    response = _tool_envelope(
        await session.call_tool(
            "submit_generation_stage",
            {
                "session_handle": session_handle,
                "idempotency_key": idempotency_key,
                "payload": model_dump(mode="json"),
            },
        )
    )
    assert response["ok"] is True, response
    return response


def _bind_current_consistency_semantics(
    review: ConsistencyRiskReview,
    *,
    replies: object,
) -> ConsistencyRiskReview:
    candidates = {
        candidate.candidate_id: candidate
        for candidate in getattr(replies, "candidates")
    }
    assessments: list[ConsistencySemanticAssessment] = []
    for snapshot in review.current_candidate_snapshots:
        candidate = candidates[snapshot.snapshot_key]
        axes = (
            *(("fact", item.fact_key, item.state) for item in snapshot.facts),
            *(
                ("core_position", item.position_key, item.stance)
                for item in snapshot.core_positions
            ),
            *(
                ("action_direction", item.action_key, item.disposition)
                for item in snapshot.action_directions
            ),
        )
        assessments.extend(
            ConsistencySemanticAssessment(
                snapshot_key=snapshot.snapshot_key,
                axis_kind=axis_kind,
                subject_key=subject_key,
                assessed_value=assessed_value,
                text_start_char=0,
                text_end_char=len(candidate.text),
                exact_excerpt=candidate.text,
                excerpt_sha256=text_sha256(candidate.text),
            )
            for axis_kind, subject_key, assessed_value in axes
        )
    return review.model_copy(
        update={
            "semantic_assessments": tuple(
                sorted(assessments, key=lambda item: item.assessment_key())
            )
        }
    )


async def submit_prepared_p6_turn(
    session: ClientSession,
    *,
    session_handle: str,
    turn_id: str,
    run_id: str,
    idempotency_prefix: str,
) -> SubmittedP6Turn:
    """Submit all seven P6 stages for an already-appended client turn."""

    # Keep the stage payload builders shared with the focused pipeline test so
    # semantic audit/consistency contract changes have one test authority.
    from tests.consultation_kb.integration.test_generation_pipeline import (
        _audit,
        _conceptualization,
        _consistency_review,
        _final_bundle,
        _parents,
        _reply_drafts,
    )

    state = _tool_envelope(
        await session.call_tool(
            "get_generation_state",
            {
                "session_handle": session_handle,
                "turn_id": turn_id,
                "run_id": run_id,
            },
        )
    )
    assert state["ok"] is True, state
    state_result = state["result"]
    assert isinstance(state_result, dict)
    query_binding = state_result["query_binding"]
    assert isinstance(query_binding, dict)
    created_at = datetime.fromisoformat(
        str(query_binding["created_at"]).replace("Z", "+00:00")
    )
    plan = QueryPlan(
        envelope=GenerationStageEnvelope(
            stage="query_plan",
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=(),
            created_at=created_at,
        ),
        intent="theory_guidance",
        client_snapshot_ref=query_binding["client_snapshot_ref"],
        global_runtime_epoch=query_binding["global_runtime_epoch"],
        client_runtime_epoch=query_binding["client_runtime_epoch"],
        tombstone_epoch=query_binding["tombstone_epoch"],
        authorization_epoch=query_binding["authorization_epoch"],
        guardrails=QueryGuardrails(),
        subqueries=(
            Subquery(
                subquery_id="governed_theory",
                category="theory_method_boundary",
                question="support",
                routes=("wiki",),
                required_evidence_types=(
                    "theory_applicability",
                    "theory_boundary",
                ),
                scope="global_knowledge",
            ),
        ),
        route_omissions=tuple(
            RouteOmission(
                route=route,
                reason="Not required for this bounded theory decision.",
            )
            for route in (
                "profile",
                "client_history",
                "lexical",
                "vector",
                "global_graph",
                "case",
            )
        ),
        rationale_summary="Use one governed Wiki route with exact C1 decision proof.",
    )
    query_response = await _submit_stage(
        session,
        session_handle=session_handle,
        idempotency_key=f"{idempotency_prefix}:query-plan",
        payload=plan,
    )
    query_result = query_response["result"]
    assert isinstance(query_result, dict)
    assert query_result["retrieval_status"] == "ready"
    evidence_pack_sha256 = query_result["evidence_pack_sha256"]
    assert isinstance(evidence_pack_sha256, str)
    pack = EvidencePack.model_validate_json(
        json.dumps(
            query_result["evidence_pack"],
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    evidence_id = pack.supporting[0].evidence_id
    evidence_context = query_result["evidence_context"]
    assert isinstance(evidence_context, list)
    evidence_body = next(
        item["body"] for item in evidence_context if item["evidence_id"] == evidence_id
    )
    assert isinstance(evidence_body, str)
    query_sha256 = _stage_sha256(query_response)

    concept = _conceptualization(
        turn_id=turn_id,
        run_id=run_id,
        parent_sha256s=_parents(query_sha256, evidence_pack_sha256),
        evidence_pack_sha256=evidence_pack_sha256,
        evidence_id=evidence_id,
    )
    concept_response = await _submit_stage(
        session,
        session_handle=session_handle,
        idempotency_key=f"{idempotency_prefix}:conceptualization",
        payload=concept,
    )
    theory = _theory_for_pack(
        turn_id=turn_id,
        run_id=run_id,
        parent_sha256s=_parents(_stage_sha256(concept_response), evidence_pack_sha256),
        evidence_pack_sha256=evidence_pack_sha256,
        evidence_id=evidence_id,
        pack=pack,
        created_at=concept.envelope.created_at,
    )
    theory_response = await _submit_stage(
        session,
        session_handle=session_handle,
        idempotency_key=f"{idempotency_prefix}:theory-comparison",
        payload=theory,
    )
    replies = _reply_drafts(
        turn_id=turn_id,
        run_id=run_id,
        parent_sha256s=_parents(_stage_sha256(theory_response), evidence_pack_sha256),
        evidence_pack_sha256=evidence_pack_sha256,
        evidence_id=evidence_id,
    )
    replies_response = await _submit_stage(
        session,
        session_handle=session_handle,
        idempotency_key=f"{idempotency_prefix}:reply-drafts",
        payload=replies,
    )
    audit = _audit(
        turn_id=turn_id,
        run_id=run_id,
        parent_sha256s=_parents(_stage_sha256(replies_response), evidence_pack_sha256),
        evidence_pack_sha256=evidence_pack_sha256,
        evidence_id=evidence_id,
        evidence_body=evidence_body,
    )
    audit_response = await _submit_stage(
        session,
        session_handle=session_handle,
        idempotency_key=f"{idempotency_prefix}:evidence-audit",
        payload=audit,
    )
    consistency = _bind_current_consistency_semantics(
        _consistency_review(
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=_parents(
                _stage_sha256(audit_response), evidence_pack_sha256
            ),
            evidence_pack_sha256=evidence_pack_sha256,
            evidence_id=evidence_id,
            replies=replies,
        ),
        replies=replies,
    )
    consistency_response = await _submit_stage(
        session,
        session_handle=session_handle,
        idempotency_key=f"{idempotency_prefix}:consistency-risk-review",
        payload=consistency,
    )
    final = _final_bundle(
        turn_id=turn_id,
        run_id=run_id,
        parent_sha256s=_parents(
            _stage_sha256(consistency_response), evidence_pack_sha256
        ),
        evidence_pack_sha256=evidence_pack_sha256,
        evidence_id=evidence_id,
        replies=replies,
        quality_evidence_ids=tuple(sorted(bound_evidence_ids(pack))),
    )
    final = final.model_copy(
        update={
            "counselor_internal": final.counselor_internal.model_copy(
                update={
                    "uncertainty": tuple(
                        sorted(
                            (
                                *concept.limitations,
                                *theory.clarification_questions,
                            )
                        )
                    )
                }
            )
        }
    )
    final_response = await _submit_stage(
        session,
        session_handle=session_handle,
        idempotency_key=f"{idempotency_prefix}:final-bundle",
        payload=final,
    )
    final_result = final_response["result"]
    assert isinstance(final_result, dict)
    assert final_result["turn_state"] == "awaiting_actual_reply"
    candidate_ids = final_result["candidate_ids"]
    assert isinstance(candidate_ids, list)

    complete = _tool_envelope(
        await session.call_tool(
            "get_generation_state",
            {
                "session_handle": session_handle,
                "turn_id": turn_id,
                "run_id": run_id,
            },
        )
    )
    complete_result = complete["result"]
    assert isinstance(complete_result, dict)
    records = complete_result["records"]
    assert isinstance(records, list)
    assert tuple(record["stage"] for record in records) == _P6_STAGE_ORDER
    assert complete_result["turn_state"] == "awaiting_actual_reply"
    return SubmittedP6Turn(
        turn_id=turn_id,
        run_id=run_id,
        candidate_ids=tuple(candidate_ids),
        candidate_texts=tuple(candidate.text for candidate in replies.candidates),
    )


@dataclass(slots=True)
class PreparedP6McpVault:
    """Production-layout vault whose governed retrieval epoch is not active yet."""

    mcp: McpVaultHarness
    knowledge_harness: GlobalKnowledgeHarness
    knowledge: PreparedKnowledge
    publication: PreparedPublication

    def activate_retrieval_epoch(self) -> None:
        active = self.knowledge_harness.connection.execute(
            "SELECT epoch FROM runtime_epochs WHERE state = 'ACTIVE'"
        ).fetchone()
        if active is not None:
            if active != (1,):
                raise AssertionError("unexpected governed retrieval epoch")
            return
        operation = self.publication.service.publish_theory_and_wiki(
            self.publication.operation_id,
            theory_id=self.knowledge.theory.theory_id,
            theory_revision=self.knowledge.theory.revision,
            wiki_id=self.knowledge.wiki.wiki_id,
            wiki_revision=self.knowledge.wiki.revision,
        )
        if operation.state != "ACTIVE" or operation.runtime_epoch != 1:
            raise AssertionError("governed retrieval epoch did not activate")
        loaded = (
            PolicyLoader.from_config(
                AppConfig.from_values(
                    self.mcp.repo_root,
                    self.mcp.vault_root,
                )
            )
            .load_all()
            .risk_rules
        )
        attach_risk_policy_to_active_epoch(
            self.knowledge_harness.connection,
            loaded,
            suffix=916_000,
        )

    def close(self) -> None:
        self.knowledge_harness.close()


def _production_layout_knowledge_harness(
    vault_root: Path,
) -> GlobalKnowledgeHarness:
    global_root = vault_root / "global"
    sources_root = vault_root / "sources"
    global_root.mkdir(parents=True)
    sources_root.mkdir()
    connection = connect_database(global_root / "catalog.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    clock = MutableClock()
    ids = IdFactory(clock, itertools.count(1).__next__)
    signer = LocalHmacApprovalSigner(
        secret=b"p" * 32,
        provider_id="local-review-agent",
        clock=clock,
    )
    verifier = LocalHmacApprovalVerifier(
        secret=b"p" * 32,
        provider_id="local-review-agent",
    )
    protector = TestProtector()
    nonce_values = itertools.count(1)
    approvals = ApprovalService(
        connection,
        provider=verifier,
        protector=protector,
        clock=clock,
        id_factory=ids,
        target_scope_hash="a" * 64,
        vault_id="synthetic-p6-mcp-vault",
        execution_secret=b"e" * 32,
        execution_proof_verifier=LocalHmacTargetExecutionProofVerifier(
            secret=b"t" * 32,
            attestor_id="knowledge-target-writer",
        ),
        nonce_source=lambda size: next(nonce_values).to_bytes(size, "big"),
    )
    guard = ApprovalExecutionGuard(
        connection,
        approval_service=approvals,
        execution_proof_signer=LocalHmacTargetExecutionAttestor(
            secret=b"t" * 32,
            attestor_id="knowledge-target-writer",
        ),
        clock=clock,
    )
    executor = P1GovernedWriteExecutor(
        approval_service=approvals,
        execution_guard=guard,
        id_factory=ids,
    )
    store = ContentStore(global_root)
    scope_policies = ScopePolicyRepository(
        connection,
        content_store=store,
        approval_executor=executor,
        clock=clock,
    )
    registrar = SourceRegistrar(
        connection,
        sources_root=sources_root,
        content_store=store,
        id_factory=ids,
        clock=clock,
    )
    return GlobalKnowledgeHarness(
        root=vault_root,
        connection=connection,
        clock=clock,
        ids=ids,
        signer=signer,
        approvals=approvals,
        guard=guard,
        executor=executor,
        store=store,
        registrar=registrar,
        scope_policies=scope_policies,
    )


def _seed_clients(
    harness: GlobalKnowledgeHarness,
    vault_root: Path,
) -> tuple[str, str, Path, Path]:
    clients_root = vault_root / "clients"
    clients_root.mkdir()
    clients = ClientIdFactory(
        suffix_source=iter(("a1b2c3d4e5f6", "b1b2c3d4e5f6")).__next__
    )
    client_a = clients.new()
    client_b = clients.new()
    catalog = ClientCatalog(harness.connection)
    roots: dict[str, Path] = {}
    for index, client_id in enumerate((client_a, client_b), start=1):
        record = catalog.prepare(
            client_id=client_id,
            directory_object_id=harness.ids.object_id("client_directory"),
            alias_lookup_sha256=f"{index}" * 64,
            created_at=harness.clock.now(),
        )
        catalog.activate(client_id, activated_at=harness.clock.now())
        root = clients_root / client_id
        root.mkdir()
        roots[client_id] = root
        (root / ".scope-id").write_bytes(
            f"{record.directory_object_id}\n".encode("ascii")
        )
        connection = connect_database(root / "client.sqlite3", mode="writer")
        try:
            MigrationRunner.for_scope(connection, "client").apply()
        finally:
            connection.close()
    return client_a, client_b, roots[client_a], roots[client_b]


def build_prepared_p6_mcp_vault(tmp_path: Path) -> PreparedP6McpVault:
    """Build real P1 artifacts and clients in the production on-disk layout.

    The returned fixture has one active combined retrieval/risk authority.
    """

    source_repo = Path(__file__).resolve().parents[2]
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    shutil.copytree(source_repo / "policies", repo / "policies")
    vault = tmp_path / "knowledge-vault"
    vault.mkdir()
    harness = _production_layout_knowledge_harness(vault)
    try:
        knowledge = prepare_governed_knowledge(harness)
        authority_row = harness.connection.execute(
            "SELECT catalog_version FROM knowledge_catalog_state WHERE singleton = 1"
        ).fetchone()
        if authority_row is None:
            raise AssertionError("global knowledge authority is unavailable")
        publication = prepare_global_publication(
            harness,
            knowledge,
            authority_base_version=int(authority_row[0]),
        )
        client_a, client_b, client_a_root, client_b_root = _seed_clients(
            harness,
            vault,
        )
    except BaseException:
        harness.close()
        raise
    client_b_canary = "CLIENT-B-PRIVATE-P6-STDIO-CANARY-23A7"
    (client_b_root / "private-canary.txt").write_text(
        client_b_canary,
        encoding="utf-8",
    )
    prepared = PreparedP6McpVault(
        mcp=McpVaultHarness(
            repo_root=repo,
            vault_root=vault,
            global_database=vault / "global" / "catalog.sqlite3",
            client_a=client_a,
            client_b=client_b,
            client_a_root=client_a_root,
            client_b_root=client_b_root,
            client_b_canary=client_b_canary,
        ),
        knowledge_harness=harness,
        knowledge=knowledge,
        publication=publication,
    )
    prepared.activate_retrieval_epoch()
    return prepared


__all__ = [
    "PreparedP6McpVault",
    "SubmittedP6Turn",
    "build_prepared_p6_mcp_vault",
    "p6_stdio_parameters",
    "submit_prepared_p6_turn",
]
