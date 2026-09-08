from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.mcp import P9_TOOL_NAMES
from consultation_kb.mcp.lifespan import DeferredHandlerServices
from consultation_kb.mcp.schemas import (
    ApprovalExecutionInput,
    AppendTemporaryFactInput,
    CreateClientInput,
    LoadClientContextInput,
    ProposeClaimsInput,
    ProposeTheoryRevisionInput,
    ProposeWikiUpdateInput,
    RecordActualReplyInput,
    SearchCasesInput,
    SearchWikiInput,
    StoreCandidateSetInput,
    TOOL_INPUT_MODELS,
)
from consultation_kb.mcp.server import create_mcp


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
CLIENT_A = "client_" + "a1b2" + "c3d4" + "e5f6"


def _ids() -> IdFactory:
    return IdFactory(FixedClock(NOW), lambda: 1)


def _property_names(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        properties = value.get("properties")
        if isinstance(properties, dict):
            found.update(str(key) for key in properties)
        for child in value.values():
            found.update(_property_names(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_property_names(child))
    return found


def test_p9_schema_set_is_exact_and_has_no_unregistered_tools() -> None:
    assert tuple(TOOL_INPUT_MODELS) == P9_TOOL_NAMES
    assert {
        "rebuild_indexes",
        "delete_client",
    }.isdisjoint(TOOL_INPUT_MODELS)


def test_only_initial_loader_schema_can_name_a_client() -> None:
    for name, input_model in TOOL_INPUT_MODELS.items():
        schema = input_model.model_json_schema()
        properties = _property_names(schema)
        if name == "load_client_context":
            assert "client_id" in properties
        else:
            assert "client_id" not in properties
        assert "path" not in properties
        assert "sql" not in properties


def test_advertised_fastmcp_schemas_are_strict_at_every_object_boundary() -> None:
    server = create_mcp(services=DeferredHandlerServices())
    tools = asyncio.run(server.list_tools())
    assert tuple(tool.name for tool in tools) == P9_TOOL_NAMES
    for tool in tools:
        assert tool.inputSchema.get("additionalProperties") is False

        def assert_closed(value: object) -> None:
            if isinstance(value, dict):
                if value.get("type") == "object" or "properties" in value:
                    assert value.get("additionalProperties") is False
                for child in value.values():
                    assert_closed(child)
            elif isinstance(value, list):
                for child in value:
                    assert_closed(child)

        assert_closed(tool.inputSchema)

    registered = server._tool_manager.get_tool("search_wiki")  # noqa: SLF001
    assert registered is not None
    sensitive = {
        "session_handle": "s" * 32,
        "query": "test",
        "client_id": CLIENT_A,
        "path": r"C:\PRIVATE-CANARY\client.sqlite3",
    }
    raw = registered.fn_metadata.arg_model.model_validate(sensitive)
    assert raw.model_dump_one_level() == sensitive


def test_all_inputs_forbid_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        LoadClientContextInput.model_validate(
            {"client_id": CLIENT_A, "path": "outside"}
        )
    with pytest.raises(ValidationError):
        SearchWikiInput.model_validate(
            {
                "session_handle": "s" * 32,
                "query": "关系变化",
                "client_id": CLIENT_A,
            }
        )


def test_case_search_use_is_fixed_by_the_server_not_selected_by_the_caller() -> None:
    request = SearchCasesInput(
        session_handle="s" * 32,
        query="相似案例",
    )
    assert set(request.model_dump()) == {"session_handle", "query", "limit"}
    assert "allowed_use" not in SearchCasesInput.model_json_schema()["properties"]
    with pytest.raises(ValidationError):
        SearchCasesInput.model_validate(
            {
                "session_handle": "s" * 32,
                "query": "相似案例",
                "allowed_use": "internal_audit",
            }
        )


def test_formal_write_schema_accepts_only_approval_request() -> None:
    request_id = _ids().object_id("approval_request")
    assert ApprovalExecutionInput(approval_request_id=request_id).model_dump() == {
        "approval_request_id": request_id
    }
    with pytest.raises(ValidationError):
        ApprovalExecutionInput.model_validate(
            {"approval_request_id": request_id, "target_id": _ids().object_id("claim")}
        )


def test_create_client_schema_is_strictly_two_phase() -> None:
    request_id = _ids().object_id("approval_request")
    assert CreateClientInput(
        action="preview",
        alias="来访者代号",
        idempotency_key="create-client:0001",
    ).model_dump() == {
        "action": "preview",
        "alias": "来访者代号",
        "idempotency_key": "create-client:0001",
        "approval_request_id": None,
    }
    assert CreateClientInput(
        action="commit",
        approval_request_id=request_id,
    ).model_dump() == {
        "action": "commit",
        "alias": None,
        "idempotency_key": None,
        "approval_request_id": request_id,
    }
    for invalid in (
        {"action": "preview", "alias": "missing idempotency"},
        {
            "action": "preview",
            "alias": " leading",
            "idempotency_key": "create-client:0002",
        },
        {
            "action": "preview",
            "alias": "bad\ncontrol",
            "idempotency_key": "create-client:0003",
        },
        {
            "action": "preview",
            "alias": "x",
            "idempotency_key": "create-client:0004",
            "approval_request_id": request_id,
        },
        {"action": "commit", "alias": "x", "approval_request_id": request_id},
        {
            "action": "commit",
            "idempotency_key": "create-client:0005",
            "approval_request_id": request_id,
        },
        {"action": "commit"},
    ):
        with pytest.raises(ValidationError):
            CreateClientInput.model_validate(invalid)


def test_candidate_set_matches_frozen_session_service_contract() -> None:
    factory = _ids()
    request = StoreCandidateSetInput(
        session_handle="s" * 32,
        turn_id=factory.uuid7(),
        run_id=factory.uuid7(),
        idempotency_key="candidate-set:0001",
        candidates=(
            {"label": "温和回应", "text": "先确认对方真正关心的问题。"},
            {"label": "行动回应", "text": "把下一步拆成一个可验证的小行动。"},
        ),
    )
    assert [item.label for item in request.candidates] == ["温和回应", "行动回应"]
    with pytest.raises(ValidationError):
        request.model_copy(update={"candidates": request.candidates[:1]})


def test_temporary_fact_input_is_scoped_strict_and_target_consistent() -> None:
    factory = _ids()
    request = AppendTemporaryFactInput(
        session_handle="s" * 32,
        turn_id=factory.uuid7(),
        idempotency_key="temporary-fact:0001",
        event_kind="GOAL",
        cognitive_type="client_statement",
        value={"goal": "clarify the next step"},
    )
    assert request.target_fact_id is None
    forbidden = {"client_id", "path", "sql"}
    assert forbidden.isdisjoint(_property_names(request.model_json_schema()))
    with pytest.raises(ValidationError):
        AppendTemporaryFactInput.model_validate(
            {
                **request.model_dump(mode="json"),
                "event_kind": "CORRECT",
            }
        )
    with pytest.raises(ValidationError):
        AppendTemporaryFactInput.model_validate(
            {**request.model_dump(mode="json"), "client_id": CLIENT_A}
        )


def test_json_transport_arrays_canonicalize_to_immutable_contracts() -> None:
    factory = _ids()
    candidate_payload = {
        "session_handle": "s" * 32,
        "turn_id": factory.uuid7(),
        "run_id": factory.uuid7(),
        "idempotency_key": "candidate-set:json-0001",
        "candidates": [
            {"label": "共情", "text": "我先陪你把感受说清楚。"},
            {"label": "行动", "text": "我们再找一个可验证的小行动。"},
        ],
    }
    candidates = StoreCandidateSetInput.model_validate_json(
        json.dumps(candidate_payload, ensure_ascii=False)
    )
    assert isinstance(candidates.candidates, tuple)

    passage_ref = {
        "object_id": factory.object_id("passage"),
        "version": 1,
        "content_sha256": "a" * 64,
    }
    claim_payload = {
        "claims": [
            {
                "text": "稳定澄清目标有助于减少前后矛盾。",
                "cognitive_type": "explicit",
                "source_grade": "C2",
                "empirical_support": "unassessed",
                "applicability": {
                    "domains": ["emotion_consultation"],
                    "populations": ["adult"],
                    "contexts": [],
                    "required_conditions": [],
                    "exclusions": [],
                    "contraindications": [],
                },
                "allowed_uses": ["consultation"],
                "evidence": [
                    {
                        "passage_ref": passage_ref,
                        "relation": "supports",
                        "evidence_role": "primary",
                    }
                ],
            }
        ]
    }
    claims = ProposeClaimsInput.model_validate_json(
        json.dumps(claim_payload, ensure_ascii=False)
    )
    assert isinstance(claims.claims, tuple)
    assert claims.claims[0].allowed_uses == frozenset({"consultation"})
    assert claims.claims[0].applicability.domains == frozenset(
        {"emotion_consultation"}
    )
    assert isinstance(claims.claims[0].evidence, tuple)

    source_ref = {
        "object_id": factory.object_id("source"),
        "version": 1,
        "content_sha256": "b" * 64,
    }
    theory_payload = {
        "draft": {
            "theory_id": factory.object_id("theory"),
            "source_ref": source_ref,
            "document_sha256": "b" * 64,
            "author": "咨询师",
            "declared_version": "1.0",
            "effective_from": NOW.isoformat(),
            "effective_to": None,
            "scope": {
                "domains": ["emotion_consultation"],
                "populations": ["adult"],
                "contexts": [],
                "required_conditions": [],
                "exclusions": [],
                "contraindications": [],
            },
            "core_claims": ["先确保事实一致，再选择解释框架。"],
            "methods": ["核对时态事实"],
            "contraindications": ["事实不明时不作确定归因"],
            "counterexamples": ["新信息推翻旧关系状态"],
            "passage_refs": [passage_ref],
            "citation_refs": [source_ref],
            "empirical_support": "unassessed",
            "scope_policy_ref": {
                "object_id": factory.object_id("policy"),
                "version": 1,
                "content_sha256": "c" * 64,
            },
        }
    }
    theory = ProposeTheoryRevisionInput.model_validate_json(
        json.dumps(theory_payload, ensure_ascii=False)
    )
    assert isinstance(theory.draft.core_claims, tuple)
    assert theory.draft.scope.domains == frozenset({"emotion_consultation"})

    wiki_payload = {
        "draft": {
            "wiki_id": factory.object_id("wiki"),
            "slug": "consistent-guidance",
            "title": "Consistent guidance",
            "base_revision": 0,
            "diff_kind": "add",
            "sections": [
                {
                    "key": "core",
                    "heading": "Core",
                    "body": "Keep the guidance consistent with current facts.",
                    "claim_refs": [
                        {
                            "object_id": factory.object_id("claim"),
                            "version": 1,
                            "content_sha256": "d" * 64,
                        }
                    ],
                    "passage_refs": [passage_ref],
                    "stance": "support",
                }
            ],
            "theory_revision_refs": [],
            "relationships": [],
            "graph_relations": [],
            "review_due_at": NOW.isoformat(),
            "unresolved_questions": ["Confirm current relationship context."],
        }
    }
    wiki = ProposeWikiUpdateInput.model_validate_json(
        json.dumps(wiki_payload, ensure_ascii=False)
    )
    assert isinstance(wiki.draft.sections, tuple)
    assert isinstance(wiki.draft.sections[0].claim_refs, tuple)
    assert isinstance(wiki.draft.theory_revision_refs, tuple)
    assert wiki.draft.review_due_at == NOW


def test_actual_reply_modes_are_mutually_exclusive() -> None:
    factory = _ids()
    common = {
        "session_handle": "s" * 32,
        "turn_id": factory.uuid7(),
        "idempotency_key": "actual-reply:0001",
    }
    adopted = RecordActualReplyInput(
        **common,
        mode="adopted",
        candidate_id=factory.object_id("candidate"),
        sent_at=NOW,
    )
    assert adopted.actual_text is None
    edited = RecordActualReplyInput(
        **common,
        mode="edited",
        candidate_id=factory.object_id("candidate"),
        actual_text="这是咨询师实际发送的编辑文本。",
        sent_at=NOW,
    )
    assert edited.actual_text is not None
    unknown = RecordActualReplyInput(
        **common,
        mode="external_unknown",
        confirmed_at=NOW,
    )
    assert unknown.candidate_id is None
    with pytest.raises(ValidationError):
        RecordActualReplyInput(
            **common,
            mode="adopted",
            candidate_id=factory.object_id("candidate"),
            actual_text="adopted must not carry replacement text",
            sent_at=NOW,
        )


def test_raw_mcp_datetime_strings_are_validated_without_sdk_reflection() -> None:
    factory = _ids()
    request = RecordActualReplyInput.model_validate(
        {
            "session_handle": "s" * 32,
            "turn_id": factory.uuid7(),
            "idempotency_key": "actual-reply:json-time",
            "mode": "adopted",
            "candidate_id": factory.object_id("candidate"),
            "sent_at": "2026-07-19T08:00:00Z",
        }
    )
    assert request.sent_at == NOW
    with pytest.raises(ValidationError):
        RecordActualReplyInput.model_validate(
            {
                "session_handle": "s" * 32,
                "turn_id": factory.uuid7(),
                "idempotency_key": "actual-reply:bad-time",
                "mode": "adopted",
                "candidate_id": factory.object_id("candidate"),
                "sent_at": r"C:\PRIVATE-CANARY\client.sqlite3",
            }
        )
