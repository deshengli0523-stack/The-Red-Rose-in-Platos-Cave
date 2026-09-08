from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult

from consultation_kb.approvals.provider import ProtectedProviderSecretStore
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.core.clock import FixedClock, SystemClock
from consultation_kb.core.config import AppConfig
from consultation_kb.core.ids import IdFactory
from consultation_kb.generation.contracts import (
    QueryGuardrails,
    QueryPlan,
    RouteOmission,
    Subquery,
    TheoryComparison,
    TheorySelection,
)
from consultation_kb.generation.evidence_scope import bound_evidence_ids
from consultation_kb.mcp import P9_TOOL_NAMES
from consultation_kb.mcp.runtime import ProductionRuntime
from consultation_kb.models.evidence import EvidencePack
from consultation_kb.models.generation import GenerationStageEnvelope
from consultation_kb.policy.loader import PolicyLoader
from consultation_kb.security.dpapi import create_secret_protector
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from tests.consultation_kb.integration.test_generation_pipeline import (
    _audit as generation_audit,
    _conceptualization as generation_conceptualization,
    _consistency_review as generation_consistency_review,
    _envelope as generation_envelope,
    _final_bundle as generation_final_bundle,
    _parents as generation_parents,
    _reply_drafts as generation_reply_drafts,
)
from tests.consultation_kb.p6_mcp_stdio_support import (
    PreparedP6McpVault,
    build_prepared_p6_mcp_vault,
)
from tests.consultation_kb.risk_support import insert_approved_risk_policy_epoch


pytestmark = pytest.mark.integration
_UNKNOWN_CLIENT = "client_" + "aaaaaaaaaaaa"
_P6_STAGE_ORDER = (
    "query_plan",
    "conceptualization",
    "theory_comparison",
    "reply_drafts",
    "evidence_audit",
    "consistency_risk_review",
    "final_bundle",
)


def _migrated_empty_workspace(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    source_repo = Path(__file__).resolve().parents[3]
    shutil.copytree(source_repo / "policies", repo / "policies")
    vault = tmp_path / "knowledge-vault"
    (vault / "clients").mkdir(parents=True)
    global_root = vault / "global"
    global_root.mkdir()
    connection = connect_database(global_root / "catalog.sqlite3", mode="writer")
    try:
        MigrationRunner.for_scope(connection, "global").apply()
        risk_policy = PolicyLoader.from_config(
            AppConfig.from_values(repo, vault)
        ).load_all().risk_rules
        insert_approved_risk_policy_epoch(
            connection,
            risk_policy,
            epoch=1,
            suffix=915_000,
        )
    finally:
        connection.close()
    return repo, vault


def _vault_id(vault: Path) -> str:
    identity = os.path.normcase(os.path.normpath(os.fspath(vault.resolve())))
    return "vault_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _confirm_production_archive_approval(
    harness: PreparedP6McpVault,
    request_id: str,
) -> None:
    protector = create_secret_protector()
    secret_store = ProtectedProviderSecretStore(
        (
            harness.mcp.vault_root
            / "security"
            / "review-agent-secret.dpapi"
        ).resolve(),
        protector=protector,
        vault_id=_vault_id(harness.mcp.vault_root),
    )
    clock = SystemClock()
    connection = connect_database(harness.mcp.global_database, mode="writer")
    try:
        approvals = ApprovalService(
            connection,
            provider=secret_store.load_verifier(),
            protector=protector,
            clock=clock,
            id_factory=IdFactory(clock),
            target_scope_hash=hashlib.sha256(
                (harness.mcp.client_a_root / ".scope-id").read_bytes()
            ).hexdigest(),
            vault_id=_vault_id(harness.mcp.vault_root),
            execution_secret=secret_store.load_execution_secret(),
            execution_proof_verifier=(
                secret_store.load_target_execution_proof_verifier()
            ),
        )
        challenge = approvals.challenge_for_review(request_id)
        confirmed = approvals.confirm(
            secret_store.load_signer(clock=clock).confirm(challenge)
        )
        assert confirmed.request_id == request_id
        assert approvals.get(request_id).state == "confirmed"
    finally:
        connection.close()


def _envelope(result: CallToolResult) -> dict[str, Any]:
    assert not result.isError
    assert result.structuredContent is not None
    payload = result.structuredContent
    assert set(payload) == {"ok", "result", "error"}
    return payload


def _p6_stdio_parameters(harness: PreparedP6McpVault) -> StdioServerParameters:
    server = Path(__file__).with_name("_p6_stdio_server.py").resolve()
    return StdioServerParameters(
        command=sys.executable,
        args=["-I", "-X", "utf8", str(server)],
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


def _stage_sha256(payload: dict[str, Any]) -> str:
    record = payload["result"]["record"]
    assert isinstance(record, dict)
    artifact = record["artifact"]
    assert isinstance(artifact, dict)
    digest = artifact["content_sha256"]
    assert isinstance(digest, str)
    return digest


def _theory_comparison_for_pack(
    *,
    turn_id: str,
    run_id: str,
    parent_sha256s: tuple[str, ...],
    evidence_pack_sha256: str,
    evidence_id: str,
    pack: EvidencePack,
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
        envelope=generation_envelope(
            "theory_comparison",
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=parent_sha256s,
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


async def _submit_p6_stage(
    session: ClientSession,
    *,
    session_handle: str,
    key: str,
    payload: object,
) -> dict[str, Any]:
    model_dump = getattr(payload, "model_dump")
    result = _envelope(
        await session.call_tool(
            "submit_generation_stage",
            {
                "session_handle": session_handle,
                "idempotency_key": key,
                "payload": model_dump(mode="json"),
            },
        )
    )
    assert result["ok"] is True, result
    return result


async def _exercise_real_server(
    repo_root: Path,
    vault: Path,
    stderr: TextIO,
) -> None:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-I", "-X", "utf8", "-m", "consultation_kb.mcp.server"],
        cwd=repo_root,
        env={
            "CONSULTATION_VAULT_ROOT": str(vault),
            "PYTHONUTF8": "1",
            "PYTHONUNBUFFERED": "1",
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "HF_DATASETS_OFFLINE": "1",
        },
    )
    async with stdio_client(parameters, errlog=stderr) as streams:
        async with ClientSession(*streams) as session:
            initialized = await session.initialize()
            assert initialized.serverInfo.name == "consultation-kb"

            listed = await session.list_tools()
            assert tuple(tool.name for tool in listed.tools) == P9_TOOL_NAMES
            assert len(listed.tools) == 51
            assert all(
                tool.inputSchema.get("additionalProperties") is False
                for tool in listed.tools
            )

            unknown_client = _envelope(
                await session.call_tool(
                    "load_client_context",
                    {"client_id": _UNKNOWN_CLIENT},
                )
            )
            assert unknown_client["ok"] is False
            assert unknown_client["result"] is None
            assert unknown_client["error"]["code"] == "SCOPE_DENIED"

            denied_read = _envelope(
                await session.call_tool(
                    "search_wiki",
                    {
                        "session_handle": "opaque-session-handle-0001",
                        "query": "relationship change",
                    },
                )
            )
            assert denied_read["ok"] is False
            assert denied_read["error"]["code"] == "SCOPE_DENIED"

            injected_path = "C:\\PRIVATE-CANARY\\client.sqlite3"
            rejected_unknown = await session.call_tool(
                "search_wiki",
                {
                    "session_handle": "opaque-session-handle-0001",
                    "query": "relationship change",
                    "client_id": _UNKNOWN_CLIENT,
                    "path": injected_path,
                },
            )
            rejected_payload = _envelope(rejected_unknown)
            assert rejected_payload["ok"] is False
            assert rejected_payload["error"]["code"] == "INVALID_ARGUMENTS"
            rejected_json = rejected_unknown.model_dump_json()
            assert _UNKNOWN_CLIENT not in rejected_json
            assert injected_path not in rejected_json

            approval_request_id = IdFactory(
                FixedClock(datetime(2026, 7, 19, tzinfo=timezone.utc)),
                lambda: 1,
            ).object_id("approval_request")
            denied_write = _envelope(
                await session.call_tool(
                    "create_client",
                    {
                        "action": "commit",
                        "approval_request_id": approval_request_id,
                    },
                )
            )
            assert denied_write["ok"] is False
            assert denied_write["error"]["code"] == "CHANNEL_UNAVAILABLE"


async def _exercise_real_p6_generation_pipeline(
    harness: PreparedP6McpVault,
    stderr: TextIO,
    publish_case: bool = False,
) -> dict[str, str]:
    disclosed: list[dict[str, Any]] = []
    ids = IdFactory(
        FixedClock(datetime(2026, 7, 19, 9, 0, tzinfo=timezone.utc)),
        iter(range(70_000, 71_000)).__next__,
    )
    async with stdio_client(
        _p6_stdio_parameters(harness),
        errlog=stderr,
    ) as streams:
        async with ClientSession(*streams) as session:
            await session.initialize()
            loaded = _envelope(
                await session.call_tool(
                    "load_client_context",
                    {"client_id": harness.mcp.client_a},
                )
            )
            disclosed.append(loaded)
            assert loaded["ok"] is True
            loaded_result = loaded["result"]
            assert isinstance(loaded_result, dict)
            session_handle = loaded_result["session_handle"]
            session_id = loaded_result["session_id"]
            assert isinstance(session_handle, str)
            assert isinstance(session_id, str)

            turn_id = ids.uuid7()
            run_id = ids.uuid7()
            client_message = "I feel uncertain after a disagreement."
            appended = _envelope(
                await session.call_tool(
                    "append_session_turn",
                    {
                        "session_handle": session_handle,
                        "turn_id": turn_id,
                        "client_message": client_message,
                    },
                )
            )
            disclosed.append(appended)
            assert appended["ok"] is True

            # The combined governed retrieval/risk epoch is active before the
            # turn is appended.  Even a literal no-match is not authority-free:
            # the scoped worker durably binds the empty result to that exact
            # policy manifest before QueryPlan can be accepted.
            client_reader = connect_database(
                harness.mcp.client_a_root / "client.sqlite3",
                mode="reader",
            )
            try:
                assert client_reader.execute(
                    "SELECT status, observation_count "
                    "FROM turn_risk_evaluations WHERE session_id = ? AND turn_id = ?",
                    (session_id, turn_id),
                ).fetchone() == ("completed", 0)
            finally:
                client_reader.close()

            harness.activate_retrieval_epoch()
            initial_state = _envelope(
                await session.call_tool(
                    "get_generation_state",
                    {
                        "session_handle": session_handle,
                        "turn_id": turn_id,
                        "run_id": run_id,
                    },
                )
            )
            disclosed.append(initial_state)
            assert initial_state["ok"] is True
            state_result = initial_state["result"]
            assert isinstance(state_result, dict)
            query_binding = state_result["query_binding"]
            assert isinstance(query_binding, dict)
            assert set(query_binding["available_routes"]) == {
                "profile",
                "client_history",
                "wiki",
                "lexical",
                "vector",
                "global_graph",
                "case",
            }
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
                rationale_summary=(
                    "Use one governed Wiki route with exact C1 decision proof."
                ),
            )
            query_response = await _submit_p6_stage(
                session,
                session_handle=session_handle,
                key="p6-stdio-query-plan-0001",
                payload=plan,
            )
            disclosed.append(query_response)
            query_result = query_response["result"]
            assert isinstance(query_result, dict)
            assert query_result["retrieval_status"] == "ready"
            assert query_result["evidence_context"]
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
            assert pack.run_id == run_id
            assert pack.supporting
            assert not pack.contradicting
            retrieval_metadata = query_result["retrieval_metadata"]
            assert isinstance(retrieval_metadata, dict)
            proofs = retrieval_metadata["evidence_type_proofs"]
            assert isinstance(proofs, list) and len(proofs) == 2
            assert {item["evidence_type"] for item in proofs} == {
                "theory_applicability",
                "theory_boundary",
            }
            assert all(
                item["proof_kind"] == "c1_authority"
                and item["c1_revision_ref"]
                == (
                    None
                    if pack.c1_applicability.revision is None
                    else pack.c1_applicability.revision.model_dump(mode="json")
                )
                and item["c1_scope_policy_ref"]
                == pack.c1_applicability.scope_policy_ref.model_dump(mode="json")
                and item["c1_decision_status"] == pack.c1_applicability.status
                and item["c1_effective_status"]
                == pack.c1_applicability.effective_status
                for item in proofs
            )
            evidence_id = pack.supporting[0].evidence_id
            evidence_context = query_result["evidence_context"]
            assert isinstance(evidence_context, list)
            evidence_body = next(
                item["body"]
                for item in evidence_context
                if item["evidence_id"] == evidence_id
            )
            assert isinstance(evidence_body, str)
            query_sha256 = _stage_sha256(query_response)

            concept = generation_conceptualization(
                turn_id=turn_id,
                run_id=run_id,
                parent_sha256s=generation_parents(
                    query_sha256,
                    evidence_pack_sha256,
                ),
                evidence_pack_sha256=evidence_pack_sha256,
                evidence_id=evidence_id,
            )
            concept_response = await _submit_p6_stage(
                session,
                session_handle=session_handle,
                key="p6-stdio-conceptualization-0001",
                payload=concept,
            )
            disclosed.append(concept_response)

            theory = _theory_comparison_for_pack(
                turn_id=turn_id,
                run_id=run_id,
                parent_sha256s=generation_parents(
                    _stage_sha256(concept_response),
                    evidence_pack_sha256,
                ),
                evidence_pack_sha256=evidence_pack_sha256,
                evidence_id=evidence_id,
                pack=pack,
            )
            theory_response = await _submit_p6_stage(
                session,
                session_handle=session_handle,
                key="p6-stdio-theory-comparison-0001",
                payload=theory,
            )
            disclosed.append(theory_response)

            replies = generation_reply_drafts(
                turn_id=turn_id,
                run_id=run_id,
                parent_sha256s=generation_parents(
                    _stage_sha256(theory_response),
                    evidence_pack_sha256,
                ),
                evidence_pack_sha256=evidence_pack_sha256,
                evidence_id=evidence_id,
            )
            replies_response = await _submit_p6_stage(
                session,
                session_handle=session_handle,
                key="p6-stdio-reply-drafts-0001",
                payload=replies,
            )
            disclosed.append(replies_response)

            audit = generation_audit(
                turn_id=turn_id,
                run_id=run_id,
                parent_sha256s=generation_parents(
                    _stage_sha256(replies_response),
                    evidence_pack_sha256,
                ),
                evidence_pack_sha256=evidence_pack_sha256,
                evidence_id=evidence_id,
                evidence_body=evidence_body,
            )
            audit_response = await _submit_p6_stage(
                session,
                session_handle=session_handle,
                key="p6-stdio-evidence-audit-0001",
                payload=audit,
            )
            disclosed.append(audit_response)

            consistency = generation_consistency_review(
                turn_id=turn_id,
                run_id=run_id,
                parent_sha256s=generation_parents(
                    _stage_sha256(audit_response),
                    evidence_pack_sha256,
                ),
                evidence_pack_sha256=evidence_pack_sha256,
                evidence_id=evidence_id,
                replies=replies,
            )
            consistency_response = await _submit_p6_stage(
                session,
                session_handle=session_handle,
                key="p6-stdio-consistency-review-0001",
                payload=consistency,
            )
            disclosed.append(consistency_response)

            final = generation_final_bundle(
                turn_id=turn_id,
                run_id=run_id,
                parent_sha256s=generation_parents(
                    _stage_sha256(consistency_response),
                    evidence_pack_sha256,
                ),
                evidence_pack_sha256=evidence_pack_sha256,
                evidence_id=evidence_id,
                replies=replies,
                quality_evidence_ids=tuple(sorted(bound_evidence_ids(pack))),
            )
            expected_uncertainty = tuple(
                sorted((*concept.limitations, *theory.clarification_questions))
            )
            final = final.model_copy(
                update={
                    "counselor_internal": final.counselor_internal.model_copy(
                        update={"uncertainty": expected_uncertainty}
                    )
                }
            )
            final_response = await _submit_p6_stage(
                session,
                session_handle=session_handle,
                key="p6-stdio-final-bundle-0001",
                payload=final,
            )
            disclosed.append(final_response)
            final_result = final_response["result"]
            assert isinstance(final_result, dict)
            assert final_result["turn_state"] == "awaiting_actual_reply"
            candidate_ids = final_result["candidate_ids"]
            assert isinstance(candidate_ids, list) and len(candidate_ids) == 2

            complete_state = _envelope(
                await session.call_tool(
                    "get_generation_state",
                    {
                        "session_handle": session_handle,
                        "turn_id": turn_id,
                        "run_id": run_id,
                    },
                )
            )
            disclosed.append(complete_state)
            complete_result = complete_state["result"]
            assert isinstance(complete_result, dict)
            assert (
                tuple(record["stage"] for record in complete_result["records"])
                == _P6_STAGE_ORDER
            )
            assert complete_result["turn_state"] == "awaiting_actual_reply"
            assert complete_result["risk_observations"] == []

            chosen_candidate_id = candidate_ids[0]
            assert isinstance(chosen_candidate_id, str)
            recorded = _envelope(
                await session.call_tool(
                    "record_actual_reply",
                    {
                        "session_handle": session_handle,
                        "turn_id": turn_id,
                        "idempotency_key": "p6-stdio-actual-reply-0001",
                        "mode": "adopted",
                        "candidate_id": chosen_candidate_id,
                        "sent_at": "2026-07-19T09:01:00Z",
                    },
                )
            )
            disclosed.append(recorded)
            assert recorded["ok"] is True
            assert recorded["result"]["state"] == "turn_closed"

            proposed = _envelope(
                await session.call_tool(
                    "propose_archive",
                    {"session_handle": session_handle},
                )
            )
            disclosed.append(proposed)
            assert proposed["ok"] is True
            archive = proposed["result"]
            assert isinstance(archive, dict)
            assert archive["status"] == "archive_proposed"
            assert tuple(
                state["purpose"] for state in archive["purpose_states"]
            ) == ("private_archive", "profile_diff", "shared_case")

            private_preview = _envelope(
                await session.call_tool(
                    "preview_private_archive",
                    {
                        "session_handle": session_handle,
                        "bundle_id": archive["bundle_id"],
                        "draft_ref": archive["private_archive_draft_ref"],
                        "review_diff_ref": archive[
                            "private_archive_review_diff_ref"
                        ],
                        "base_version": archive[
                            "private_archive_base_version"
                        ],
                    },
                )
            )
            disclosed.append(private_preview)
            assert private_preview["ok"] is True, private_preview
            preview = private_preview["result"]
            assert isinstance(preview, dict)
            assert preview["status"] == "pending_local_review"
            assert preview["approval_purpose"] == "private_archive_publish"

            case_event_id = ""
            case_published_global_version = 0
            if publish_case:
                case_prepare = _envelope(
                    await session.call_tool(
                        "approve_case",
                        {
                            "session_handle": session_handle,
                            "action": "PREPARE",
                            "bundle_id": archive["bundle_id"],
                            "section_drafts": [
                                {
                                    "section_kind": "factual_context",
                                    "abstracted_text": (
                                        "来访者希望梳理分歧后的不确定感及其影响模式。"
                                    ),
                                },
                                {
                                    "section_kind": "actual_response",
                                    "abstracted_text": (
                                        "咨询师帮助其区分体验并形成后续行动方向。"
                                    ),
                                },
                            ],
                            "decision": "approved",
                            "checked_categories": [
                                "direct_identifiers",
                                "third_party_people",
                                "rare_attributes",
                                "location_occupation_family_time",
                                "section_boundaries",
                                "no_verbatim_quotes",
                            ],
                            "residual_risk": "low",
                            "rare_combination_disposition": "not_present",
                            "reuse_authorized": True,
                            "allowed_uses": ["answer_support"],
                            "authorization_expires_at": "2027-07-19T09:10:00Z",
                        },
                    )
                )
                disclosed.append(case_prepare)
                assert case_prepare["ok"] is True, case_prepare
                case_preview = case_prepare["result"]
                assert isinstance(case_preview, dict)
                assert case_preview["status"] == "pending_local_review"
                assert len(case_preview["candidate_sections"]) == 2
                assert len(case_preview["deidentification_scans"]) == 2
                approval_request_id = case_preview["approval_request_id"]
                assert isinstance(approval_request_id, str)
                _confirm_production_archive_approval(
                    harness,
                    approval_request_id,
                )
                case_commit = _envelope(
                    await session.call_tool(
                        "approve_case",
                        {
                            "session_handle": session_handle,
                            "action": "COMMIT",
                            "bundle_id": archive["bundle_id"],
                            "decision": "approved",
                            "checked_categories": [
                                "direct_identifiers",
                                "third_party_people",
                                "rare_attributes",
                                "location_occupation_family_time",
                                "section_boundaries",
                                "no_verbatim_quotes",
                            ],
                            "residual_risk": "low",
                            "rare_combination_disposition": "not_present",
                            "reuse_authorized": True,
                            "allowed_uses": ["answer_support"],
                            "authorization_expires_at": "2027-07-19T09:10:00Z",
                            "candidate_ref": case_preview["candidate_ref"],
                            "scan_ref": case_preview["scan_ref"],
                            "review_policy_draft_ref": case_preview[
                                "review_policy_draft_ref"
                            ],
                            "approval_operation_id": case_preview[
                                "approval_operation_id"
                            ],
                            "approval_request_id": approval_request_id,
                        },
                    )
                )
                disclosed.append(case_commit)
                assert case_commit["ok"] is True, case_commit
                case_result = case_commit["result"]
                assert isinstance(case_result, dict)
                assert case_result["state"] == "PUBLISHED"
                assert case_result["release_outcome"] == "eligible"
                assert isinstance(case_result["event_id"], str)
                assert (
                    type(case_result["published_global_version"]) is int
                    and case_result["published_global_version"] > 0
                )
                case_event_id = case_result["event_id"]
                case_published_global_version = case_result[
                    "published_global_version"
                ]

    rendered = json.dumps(disclosed, ensure_ascii=False, sort_keys=True)
    assert harness.mcp.client_b not in rendered
    assert harness.mcp.client_b_canary not in rendered
    return {
        "session_id": session_id,
        "turn_id": turn_id,
        "run_id": run_id,
        "candidate_id": chosen_candidate_id,
        "reply_text": replies.candidates[0].text,
        "client_message": client_message,
        "archive_bundle_id": archive["bundle_id"],
        "archive_approval_request_id": preview["approval_request_id"],
        "case_event_id": case_event_id,
        "case_published_global_version": case_published_global_version,
    }


def test_real_stdio_initializes_lists_exact_tools_and_fails_closed(
    tmp_path: Path,
) -> None:
    repo_root, vault = _migrated_empty_workspace(tmp_path)
    stderr_path = tmp_path / "mcp-stderr.log"
    with stderr_path.open("w+", encoding="utf-8") as stderr:
        anyio.run(_exercise_real_server, repo_root, vault, stderr)
        stderr.flush()
        stderr.seek(0)
        diagnostics = stderr.read()

    # Successful SDK parsing proves every stdout line was protocol JSON.  The
    # diagnostic channel may contain fixed codes but never caller or path data.
    assert "Traceback" not in diagnostics
    assert _UNKNOWN_CLIENT not in diagnostics
    assert str(vault) not in diagnostics
    assert "relationship change" not in diagnostics
    assert "PRIVATE-CANARY" not in diagnostics


@pytest.mark.skipif(sys.platform != "win32", reason="Windows scoped subprocess")
@pytest.mark.acceptance_id("P7-MCP-STDIO-ARCHIVE-PREVIEW")
def test_real_stdio_runs_generation_and_previews_private_archive(
    tmp_path: Path,
) -> None:
    harness = build_prepared_p6_mcp_vault(tmp_path)
    secret_store = ProtectedProviderSecretStore(
        (
            harness.mcp.vault_root
            / "security"
            / "review-agent-secret.dpapi"
        ).resolve(),
        protector=create_secret_protector(),
        vault_id=_vault_id(harness.mcp.vault_root),
    )
    secret_store.initialize()
    stderr_path = tmp_path / "p6-mcp-stderr.log"
    try:
        with stderr_path.open("w+", encoding="utf-8") as stderr:
            result = anyio.run(
                _exercise_real_p6_generation_pipeline,
                harness,
                stderr,
            )
            stderr.flush()
            stderr.seek(0)
            diagnostics = stderr.read()

        client_connection = connect_database(
            harness.mcp.client_a_root / "client.sqlite3",
            mode="reader",
        )
        try:
            assert client_connection.execute(
                "SELECT state FROM turns WHERE session_id = ? AND turn_id = ?",
                (result["session_id"], result["turn_id"]),
            ).fetchone() == ("turn_closed",)
            assert client_connection.execute(
                "SELECT status, observation_count FROM turn_risk_evaluations "
                "WHERE session_id = ? AND turn_id = ?",
                (result["session_id"], result["turn_id"]),
            ).fetchone() == ("completed", 0)
            assert (
                tuple(
                    row[0]
                    for row in client_connection.execute(
                        "SELECT stage FROM generation_stage_revisions "
                        "WHERE session_id = ? AND turn_id = ? AND run_id = ? "
                        "ORDER BY CASE stage "
                        "WHEN 'query_plan' THEN 1 "
                        "WHEN 'conceptualization' THEN 2 "
                        "WHEN 'theory_comparison' THEN 3 "
                        "WHEN 'reply_drafts' THEN 4 "
                        "WHEN 'evidence_audit' THEN 5 "
                        "WHEN 'consistency_risk_review' THEN 6 "
                        "WHEN 'final_bundle' THEN 7 END",
                        (
                            result["session_id"],
                            result["turn_id"],
                            result["run_id"],
                        ),
                    ).fetchall()
                )
                == _P6_STAGE_ORDER
            )
            actual = client_connection.execute(
                "SELECT source_type, candidate_id, reply_sha256, evidence_gap "
                "FROM actual_replies WHERE session_id = ? AND turn_id = ?",
                (result["session_id"], result["turn_id"]),
            ).fetchone()
            assert actual == (
                "adopted",
                result["candidate_id"],
                hashlib.sha256(result["reply_text"].encode("utf-8")).hexdigest(),
                0,
            )
            assert client_connection.execute(
                "SELECT session_id FROM archive_bundles WHERE bundle_id = ?",
                (result["archive_bundle_id"],),
            ).fetchone() == (result["session_id"],)
            assert client_connection.execute(
                "SELECT purpose, state FROM archive_purpose_states "
                "WHERE bundle_id = ? ORDER BY purpose",
                (result["archive_bundle_id"],),
            ).fetchall() == [
                ("private_archive", "DRAFT"),
                ("profile_diff", "DRAFT"),
                ("shared_case", "DRAFT"),
            ]
        finally:
            client_connection.close()

        assert harness.knowledge_harness.connection.execute(
            "SELECT purpose, state FROM approval_requests WHERE request_id = ?",
            (result["archive_approval_request_id"],),
        ).fetchone() == ("private_archive_publish", "PENDING")

        client_b_connection = connect_database(
            harness.mcp.client_b_root / "client.sqlite3",
            mode="reader",
        )
        try:
            assert client_b_connection.execute(
                "SELECT COUNT(*) FROM sessions"
            ).fetchone() == (0,)
            assert client_b_connection.execute(
                "SELECT COUNT(*) FROM generation_stage_revisions"
            ).fetchone() == (0,)
        finally:
            client_b_connection.close()

        global_tables = {
            str(row[0])
            for row in harness.knowledge_harness.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert (
            not {
                "turns",
                "actual_replies",
                "generation_stage_revisions",
                "turn_risk_evaluations",
            }
            & global_tables
        )
        private_needles = tuple(
            value.encode("utf-8")
            for value in (
                result["client_message"],
                result["reply_text"],
                harness.mcp.client_b_canary,
            )
        )
        for global_file in (harness.mcp.vault_root / "global").rglob("*"):
            if global_file.is_file():
                content = global_file.read_bytes()
                assert all(needle not in content for needle in private_needles)
        assert "Traceback" not in diagnostics
        assert result["client_message"] not in diagnostics
        assert result["reply_text"] not in diagnostics
        assert harness.mcp.client_b not in diagnostics
        assert harness.mcp.client_b_canary not in diagnostics
        assert str(harness.mcp.vault_root) not in diagnostics
    finally:
        harness.close()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows scoped subprocess")
@pytest.mark.acceptance_id("P7-MCP-STDIO-CASE-PUBLISH")
def test_real_stdio_approve_case_commit_publishes_global_and_acks_source(
    tmp_path: Path,
) -> None:
    harness = build_prepared_p6_mcp_vault(tmp_path)
    secret_store = ProtectedProviderSecretStore(
        (
            harness.mcp.vault_root
            / "security"
            / "review-agent-secret.dpapi"
        ).resolve(),
        protector=create_secret_protector(),
        vault_id=_vault_id(harness.mcp.vault_root),
    )
    secret_store.initialize()
    stderr_path = tmp_path / "p7-case-publish-stderr.log"
    try:
        with stderr_path.open("w+", encoding="utf-8") as stderr:
            result = anyio.run(
                _exercise_real_p6_generation_pipeline,
                harness,
                stderr,
                True,
            )
            stderr.flush()
            stderr.seek(0)
            diagnostics = stderr.read()
        assert result["case_event_id"]
        client = connect_database(
            harness.mcp.client_a_root / "client.sqlite3",
            mode="reader",
        )
        try:
            source = client.execute(
                "SELECT state, attempt_count, published_global_version "
                "FROM outbox_events WHERE event_id = ?",
                (result["case_event_id"],),
            ).fetchone()
            assert source is not None
            assert source[0] == "PUBLISHED"
            assert source[1] == 1
            assert type(source[2]) is int and source[2] > 0
            assert source[2] == result["case_published_global_version"]
        finally:
            client.close()
        global_rows = harness.knowledge_harness.connection.execute(
            "SELECT c.state, cv.state, s.state, o.state, c.current_version, "
            "o.approval_request_id, o.descriptor_sha256 "
            "FROM cases AS c JOIN case_versions AS cv "
            "ON cv.case_id = c.case_id AND cv.version = c.current_version "
            "JOIN global_publish_sagas AS s ON s.case_id = c.case_id "
            "JOIN publication_operations AS o "
            "ON o.operation_id = s.publication_operation_id"
        ).fetchall()
        assert len(global_rows) == 1
        assert global_rows[0][:4] == (
            "ACTIVE",
            "ACTIVE",
            "ACTIVE",
            "VERIFIED",
        )
        assert global_rows[0][4] == result["case_published_global_version"]
        assert all(
            isinstance(value, str) and value
            for value in global_rows[0][5:]
        )
        assert "Traceback" not in diagnostics
        assert result["client_message"] not in diagnostics
        assert result["reply_text"] not in diagnostics
        assert str(harness.mcp.vault_root) not in diagnostics
    finally:
        harness.close()


def test_production_runtime_close_is_idempotent(
    tmp_path: Path,
) -> None:
    repo_root, vault = _migrated_empty_workspace(tmp_path)
    runtime = ProductionRuntime.open(config=AppConfig.from_values(repo_root, vault))
    assert not runtime.is_closed
    assert not runtime.knowledge_available
    assert not runtime.client_creation_available

    runtime.close()
    runtime.close()
    assert runtime.is_closed

    # A fresh writer can migrate-check after close; the lifespan retained no
    # live global connection or transaction.
    connection = connect_database(
        vault / "global" / "catalog.sqlite3",
        mode="writer",
    )
    try:
        MigrationRunner.for_scope(connection, "global").check()
        assert not connection.in_transaction
    finally:
        connection.close()


@pytest.mark.skipif(sys.platform != "win32", reason="production DPAPI")
def test_production_runtime_enables_knowledge_only_with_protected_key(
    tmp_path: Path,
) -> None:
    repo_root, vault = _migrated_empty_workspace(tmp_path)
    secret_store = ProtectedProviderSecretStore(
        (vault / "security" / "review-agent-secret.dpapi").resolve(),
        protector=create_secret_protector(),
        vault_id=_vault_id(vault),
    )
    secret_store.initialize()

    runtime = ProductionRuntime.open(config=AppConfig.from_values(repo_root, vault))
    try:
        assert runtime.knowledge_available
        # Client target ACL/identity-map prerequisites are a create-only
        # boundary and must not disable the shared knowledge authority.
        assert not runtime.client_creation_available
    finally:
        runtime.close()
