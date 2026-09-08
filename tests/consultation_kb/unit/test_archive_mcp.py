from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import BaseModel, ValidationError

from consultation_kb.approvals.models import ApprovalExecutionTicket
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.mcp import (
    HandlerServices,
    McpHandlerContext,
    P7_TOOL_NAMES,
    TransportBindingRegistry,
    build_handler_registry,
)
import consultation_kb.mcp.session_runtime as session_runtime_module
from consultation_kb.mcp.context import BoundTransport
from consultation_kb.mcp.session_runtime import (
    SessionRuntimeError,
    SessionRuntimeManager,
    _LiveSession,
)
from consultation_kb.mcp.schemas import (
    ApproveCaseInput,
    CommitPrivateArchiveInput,
    CommitProfileUpdateInput,
    PreviewProfileDiffInput,
    TOOL_INPUT_MODELS,
)
from consultation_kb.models.common import StrictModel, VersionRef
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.security.scoped_worker import ScopedWorkerBroker
from consultation_kb.security.worker_protocol import (
    ArchiveContentRef,
    BeginSessionResponse,
    CommitPrivateArchiveRequest,
    CommitPrivateArchiveResponse,
    StageSharedCaseOutboxResponse,
)
from tests.consultation_kb.approval_support import build_approval_harness


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
CLIENT_ID = "client_" + "a1b2c3d4e5f6"
HANDLE = "opaque-session-handle-p7-0001"
SCOPE_MARKER_SHA256 = "d" * 64


def _ids() -> IdFactory:
    return IdFactory(FixedClock(NOW), iter(range(800, 900)).__next__)


def _ref(kind: str, digest: str) -> ArchiveContentRef:
    return ArchiveContentRef(
        object_id=_ids().object_id(kind),
        version=1,
        content_sha256=digest * 64,
        size_bytes=128,
    )


def _property_names(value: object) -> set[str]:
    names: set[str] = set()
    if isinstance(value, dict):
        properties = value.get("properties")
        if isinstance(properties, dict):
            names.update(str(key) for key in properties)
        for child in value.values():
            names.update(_property_names(child))
    elif isinstance(value, list):
        for child in value:
            names.update(_property_names(child))
    return names


class _Service:
    def __init__(self) -> None:
        self.calls: list[tuple[str, StrictModel, BoundTransport | None]] = []

    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object | Awaitable[object]:
        self.calls.append((tool_name, request, binding))
        if tool_name == "load_client_context":
            return {"session_handle": HANDLE, "snapshot_version": 1}
        return {"status": "accepted", "tool": tool_name}


class _RecoveryRoutingWorker:
    def __init__(
        self,
        response: CommitPrivateArchiveResponse,
        *,
        target_applied: bool,
    ) -> None:
        self.response = response
        self.target_applied = target_applied
        self.recovery_calls = 0
        self.execute_calls = 0

    def recover_applied_archive_operation(
        self,
        request: CommitPrivateArchiveRequest,
        *,
        ticket: ApprovalExecutionTicket,
        approval_service: ApprovalService,
    ) -> CommitPrivateArchiveResponse | None:
        del request, ticket, approval_service
        self.recovery_calls += 1
        return self.response if self.target_applied else None

    def execute_approved_archive_operation(
        self,
        request: CommitPrivateArchiveRequest,
        *,
        ticket: ApprovalExecutionTicket,
        approval_service: ApprovalService,
    ) -> CommitPrivateArchiveResponse:
        del request, ticket, approval_service
        self.execute_calls += 1
        return self.response


def _registry() -> tuple[_Service, object]:
    service = _Service()
    services = HandlerServices(
        read=service,
        graph=service,
        session=service,
        knowledge=service,
        write=service,
    )
    registry = build_handler_registry(
        McpHandlerContext(
            transport_session_id="stdio-p7-archive",
            bindings=TransportBindingRegistry(),
            services=services,
        )
    )
    return service, registry


def test_archive_tools_are_exact_bound_and_effect_annotated() -> None:
    service, registry = _registry()
    assert tuple(registry)[: len(P7_TOOL_NAMES)] == P7_TOOL_NAMES  # type: ignore[arg-type]
    for name in ("propose_archive", "preview_private_archive", "preview_profile_diff"):
        assert not registry[name].annotations.approval_required  # type: ignore[index]
    for name in ("commit_private_archive", "commit_profile_update", "approve_case"):
        assert registry[name].annotations.approval_required  # type: ignore[index]
        assert registry[name].annotations.destructive  # type: ignore[index]

    denied = asyncio.run(
        registry["propose_archive"]({"session_handle": HANDLE})  # type: ignore[index]
    )
    assert not denied.ok
    assert denied.error is not None and denied.error.code == "SCOPE_DENIED"
    assert not service.calls

    loaded = asyncio.run(
        registry["load_client_context"]({"client_id": CLIENT_ID})  # type: ignore[index]
    )
    assert loaded.ok
    proposed = asyncio.run(
        registry["propose_archive"]({"session_handle": HANDLE})  # type: ignore[index]
    )
    assert proposed.ok
    assert service.calls[-1][2] == BoundTransport("stdio-p7-archive", HANDLE)


def test_archive_schemas_expose_only_handle_exact_refs_and_approval_ids() -> None:
    for name in P7_TOOL_NAMES[-6:]:
        schema = TOOL_INPUT_MODELS[name].model_json_schema()
        assert _property_names(schema).isdisjoint(
            {"client", "client_id", "path", "root", "sql", "ticket", "nonce"}
        )
        assert schema.get("additionalProperties") is False

    ids = _ids()
    private = CommitPrivateArchiveInput(
        session_handle=HANDLE,
        bundle_id=ids.object_id("archive_bundle"),
        draft_ref=_ref("private_archive_draft", "a"),
        base_version=0,
        approval_operation_id=ids.object_id("archive_operation"),
        approval_request_id=ids.object_id("approval_request"),
    )
    assert set(private.model_dump()) == {
        "session_handle",
        "bundle_id",
        "draft_ref",
        "base_version",
        "approval_operation_id",
        "approval_request_id",
    }
    with pytest.raises(ValidationError):
        CommitPrivateArchiveInput.model_validate(
            {**private.model_dump(mode="json"), "sql": "UPDATE private_archive"}
        )


def test_profile_and_case_phases_are_closed_and_cannot_mix_payloads() -> None:
    draft = _ref("profile_diff_draft", "b")
    operation_ids = ("profile-operation-1",)
    built = PreviewProfileDiffInput(
        session_handle=HANDLE,
        action="BUILD",
        build_input_ref=_ref("profile_diff_build_input", "c"),
    )
    assert built.draft_ref is None
    prepared = PreviewProfileDiffInput(
        session_handle=HANDLE,
        action="PREPARE_APPROVAL",
        draft_ref=draft,
        selected_operation_ids=operation_ids,
        dismissed_indirect_review_fact_ids=("review-fact-1",),
    )
    assert prepared.selected_operation_ids == operation_ids
    for payload in (
        {
            **built.model_dump(mode="json"),
            "draft_ref": draft.model_dump(mode="json"),
        },
        {
            **prepared.model_dump(mode="json"),
            "build_input_ref": _ref(
                "profile_diff_build_input", "d"
            ).model_dump(mode="json"),
        },
        {
            **prepared.model_dump(mode="json"),
            "selected_operation_ids": ["duplicate", "duplicate"],
        },
    ):
        with pytest.raises(ValidationError):
            PreviewProfileDiffInput.model_validate(payload)

    ids = _ids()
    bundle_id = ids.object_id("archive_bundle")
    with pytest.raises(ValidationError):
        ApproveCaseInput(
            session_handle=HANDLE,
            action="PREPARE",
            bundle_id=bundle_id,
        )
    case_prepare = ApproveCaseInput(
        session_handle=HANDLE,
        action="PREPARE",
        bundle_id=bundle_id,
        section_drafts=(
            {
                "section_kind": "factual_context",
                "abstracted_text": "来访者希望理解关系变化后的情绪与选择模式。",
            },
            {
                "section_kind": "actual_response",
                "abstracted_text": "咨询师帮助其区分事实、感受和可行动的下一步。",
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
        authorization_expires_at=NOW + timedelta(days=30),
    )
    assert case_prepare.candidate_ref is None
    with pytest.raises(ValidationError):
        ApproveCaseInput.model_validate(
            {
                **case_prepare.model_dump(mode="json"),
                "candidate_ref": _ref("shared_case_candidate", "e").model_dump(
                    mode="json"
                ),
            }
        )
    with pytest.raises(ValidationError):
        ApproveCaseInput(
            session_handle=HANDLE,
            action="COMMIT",
            bundle_id=bundle_id,
            decision="approved",
            checked_categories=case_prepare.checked_categories,
            residual_risk="low",
            rare_combination_disposition="not_present",
            reuse_authorized=True,
            allowed_uses=frozenset({"answer_support"}),
            authorization_expires_at=NOW + timedelta(days=30),
        )


def test_three_formal_payloads_are_structurally_independent() -> None:
    ids = _ids()
    private_payload = {
        "session_handle": HANDLE,
        "bundle_id": ids.object_id("archive_bundle"),
        "draft_ref": _ref("private_archive_draft", "f").model_dump(mode="json"),
        "base_version": 0,
        "approval_operation_id": ids.object_id("archive_operation"),
        "approval_request_id": ids.object_id("approval_request"),
    }
    private = CommitPrivateArchiveInput.model_validate(private_payload)
    with pytest.raises(ValidationError):
        CommitProfileUpdateInput.model_validate(private_payload)
    with pytest.raises(ValidationError):
        ApproveCaseInput.model_validate(private_payload)

    assert isinstance(private, BaseModel)


def test_consultation_skill_keeps_the_independent_archive_order() -> None:
    skill = (
        Path(__file__).resolve().parents[3]
        / ".agents"
        / "skills"
        / "consultation-session"
        / "SKILL.md"
    ).read_text(encoding="utf-8")
    ending = skill.split("## 结束与隐私", 1)[1].split("## P7 MCP", 1)[0]
    ordered = (
        "`record_actual_reply`",
        "`propose_archive`",
        "`preview_private_archive`",
        "`commit_private_archive`",
        "`preview_profile_diff`",
        "`commit_profile_update`",
        "`approve_case`",
    )
    positions = [ending.index(item) for item in ordered]
    assert positions == sorted(positions)
    assert "目的独立、一次性且不可互换" in ending
    assert "不得把 ActualTranscript" in ending


def test_archive_approval_purposes_cannot_be_interchanged(tmp_path: Path) -> None:
    harness = build_approval_harness(
        tmp_path,
        target_scope_hash="d" * 64,
    )
    ids = _ids()
    session_id = ids.uuid7()
    live = _LiveSession(
        client_id=CLIENT_ID,
        session_id=session_id,
        session_handle=HANDLE,
        scope_marker_sha256=SCOPE_MARKER_SHA256,
        capability_epoch=1,
        worker=cast(ScopedWorkerBroker, object()),
        start=cast(BeginSessionResponse, object()),
        archive_approvals=harness.service,
    )
    requests: dict[str, str] = {}
    try:
        for purpose in (
            "private_archive_publish",
            "profile_update",
            "case_publish",
        ):
            descriptor = DraftDescriptor(
                purpose=purpose,
                target_id=ids.object_id("archive_target"),
                client_id=CLIENT_ID,
                base_version=0,
                draft_sha256=purpose.encode("utf-8").hex()[:64].ljust(64, "0"),
                session_id=session_id,
            )
            approval = harness.service.request(
                descriptor,
                diff_object_ref=VersionRef(
                    object_id=ids.object_id("approval_diff"),
                    version=1,
                    content_sha256="e" * 64,
                ),
            )
            requests[purpose] = approval.request_id

        for purpose, request_id in requests.items():
            selected = SessionRuntimeManager._require_archive_descriptor(
                live,
                approvals=harness.service,
                request_id=request_id,
                purpose=purpose,
            )
            assert selected.purpose == purpose
            wrong = next(item for item in requests if item != purpose)
            with pytest.raises(SessionRuntimeError):
                SessionRuntimeManager._require_archive_descriptor(
                    live,
                    approvals=harness.service,
                    request_id=request_id,
                    purpose=wrong,
                )
    finally:
        harness.close()


@pytest.mark.parametrize("target_applied", [False, True])
def test_bound_archive_ticket_probes_target_before_normal_handler(
    tmp_path: Path,
    *,
    target_applied: bool,
) -> None:
    harness = build_approval_harness(tmp_path, target_scope_hash="d" * 64)
    ids = _ids()
    session_id = ids.uuid7()
    bundle_id = ids.object_id("archive_bundle")
    draft = _ref("private_archive_draft", "a")
    descriptor = DraftDescriptor(
        purpose="private_archive_publish",
        target_id=draft.object_id,
        client_id=CLIENT_ID,
        base_version=0,
        draft_sha256=draft.content_sha256,
        session_id=session_id,
    )
    approval_request = harness.service.request(
        descriptor,
        diff_object_ref=VersionRef(
            object_id=ids.object_id("approval_diff"),
            version=1,
            content_sha256="b" * 64,
        ),
    )
    harness.service.confirm(
        harness.signer.confirm(
            harness.service.challenge_for_review(approval_request.request_id)
        )
    )
    operation_id = harness.operation_id()
    harness.service.issue_for_execution(
        approval_request.request_id,
        descriptor,
        operation_id=operation_id,
    )
    request = CommitPrivateArchiveRequest(
        request_id=ids.uuid7(),
        session_handle=HANDLE,
        bundle_id=bundle_id,
        draft_ref=draft,
        base_version=0,
        approval_operation_id=operation_id,
        approval_request_id=approval_request.request_id,
    )
    response = CommitPrivateArchiveResponse(
        request_id=request.request_id,
        bundle_id=bundle_id,
        approval_operation_id=operation_id,
        applied_commit_version=1,
        revision_ref=VersionRef(
            object_id=ids.object_id("private_archive_revision"),
            version=1,
            content_sha256="c" * 64,
        ),
        manifest_ref=VersionRef(
            object_id=ids.object_id("artifact_manifest"),
            version=1,
            content_sha256="e" * 64,
        ),
    )
    worker = _RecoveryRoutingWorker(response, target_applied=target_applied)
    live = _LiveSession(
        client_id=CLIENT_ID,
        session_id=session_id,
        session_handle=HANDLE,
        scope_marker_sha256=SCOPE_MARKER_SHA256,
        capability_epoch=1,
        worker=cast(ScopedWorkerBroker, worker),
        start=cast(BeginSessionResponse, object()),
        archive_approvals=harness.service,
    )
    try:
        committed = SessionRuntimeManager._execute_approved_archive(
            live,
            request,
            descriptor=descriptor,
            operation_id=operation_id,
            request_id=approval_request.request_id,
        )
        assert committed == response
        assert worker.recovery_calls == 1
        assert worker.execute_calls == (0 if target_applied else 1)
    finally:
        harness.close()


def test_case_pipeline_faults_before_source_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    points: list[str] = []

    def fault(point: str) -> None:
        points.append(point)
        if point == "before_source_ack":
            raise RuntimeError("injected-before-source-ack")

    manager = SessionRuntimeManager(
        catalog=cast(Any, object()),
        capability_service=cast(Any, object()),
        scope_broker=cast(Any, object()),
        clock=FixedClock(NOW),
        id_factory=_ids(),
        fault_injector=fault,
    )
    manager._case_publication_connection = cast(Any, object())
    manager._case_publication_store = cast(Any, object())
    manager._archive_execution_attestor_secret = b"t" * 32
    manager._archive_execution_attestor_id = "test-target-writer"

    class _Worker:
        def __init__(self) -> None:
            self.ack_calls = 0

        def export_pending_case_publish(
            self,
            *,
            event_id: str | None = None,
        ) -> tuple[object, object]:
            return SimpleNamespace(event_id=event_id), object()

        def acknowledge_case_publication(self, publication: object) -> object:
            del publication
            self.ack_calls += 1
            return SimpleNamespace(
                event_id="unused",
                state="PUBLISHED",
                published_global_version=1,
            )

    class _Publisher:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def process(self, event: object, transfer: object) -> object:
            del event, transfer
            return SimpleNamespace(published_global_version=1)

    monkeypatch.setattr(
        session_runtime_module,
        "SharedCasePublisher",
        _Publisher,
    )
    worker = _Worker()
    live = _LiveSession(
        client_id=CLIENT_ID,
        session_id=_ids().uuid7(),
        session_handle=HANDLE,
        scope_marker_sha256=SCOPE_MARKER_SHA256,
        capability_epoch=1,
        worker=cast(ScopedWorkerBroker, worker),
        start=cast(BeginSessionResponse, object()),
    )

    with pytest.raises(RuntimeError, match="injected-before-source-ack"):
        manager._drain_case_publications(
            live,
            event_id=_ids().object_id("case_outbox_event"),
        )
    assert points == ["before_source_ack"]
    assert worker.ack_calls == 0


def test_case_pipeline_faults_after_durable_source_outbox(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = _ids()
    session_id = ids.uuid7()
    harness = build_approval_harness(tmp_path, target_scope_hash="d" * 64)
    candidate_ref = _ref("shared_case_candidate", "a")
    scan_ref = _ref("deidentification_scan", "b")
    policy_ref = _ref("case_review_policy", "c")
    descriptor = DraftDescriptor(
        purpose="case_publish",
        target_id=candidate_ref.object_id,
        client_id=CLIENT_ID,
        base_version=candidate_ref.version,
        draft_sha256=policy_ref.content_sha256,
        session_id=session_id,
    )
    approval = harness.service.request(
        descriptor,
        diff_object_ref=VersionRef(
            object_id=ids.object_id("approval_diff"),
            version=1,
            content_sha256="d" * 64,
        ),
    )
    operation_id = harness.operation_id()
    response = StageSharedCaseOutboxResponse(
        request_id=ids.uuid7(),
        bundle_id=ids.object_id("archive_bundle"),
        action="COMMIT",
        event_id=ids.object_id("case_outbox_event"),
        payload_ref=_ref("case_outbox_payload", "e"),
        approval_operation_id=operation_id,
        applied_commit_version=1,
        release_outcome="eligible",
        state="PENDING",
    )

    def committed(
        live: _LiveSession,
        request: object,
        *,
        descriptor: DraftDescriptor,
        operation_id: str,
        request_id: str,
    ) -> StageSharedCaseOutboxResponse:
        del live, request, descriptor, operation_id, request_id
        return response

    monkeypatch.setattr(
        SessionRuntimeManager,
        "_execute_approved_archive",
        staticmethod(committed),
    )
    points: list[str] = []

    def fault(point: str) -> None:
        points.append(point)
        if point == "after_source_outbox":
            raise RuntimeError("injected-after-source-outbox")

    manager = SessionRuntimeManager(
        catalog=cast(Any, object()),
        capability_service=cast(Any, object()),
        scope_broker=cast(Any, object()),
        clock=FixedClock(NOW),
        id_factory=ids,
        fault_injector=fault,
    )
    live = _LiveSession(
        client_id=CLIENT_ID,
        session_id=session_id,
        session_handle=HANDLE,
        scope_marker_sha256=SCOPE_MARKER_SHA256,
        capability_epoch=1,
        worker=cast(ScopedWorkerBroker, object()),
        start=cast(BeginSessionResponse, object()),
        archive_approvals=harness.service,
    )
    request = ApproveCaseInput(
        session_handle=HANDLE,
        action="COMMIT",
        bundle_id=response.bundle_id,
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
        authorization_expires_at=NOW + timedelta(days=30),
        candidate_ref=candidate_ref,
        scan_ref=scan_ref,
        review_policy_draft_ref=policy_ref,
        approval_operation_id=operation_id,
        approval_request_id=approval.request_id,
    )
    try:
        with pytest.raises(RuntimeError, match="injected-after-source-outbox"):
            manager._approve_case(live, request)
        assert points == ["after_source_outbox"]
    finally:
        harness.close()
