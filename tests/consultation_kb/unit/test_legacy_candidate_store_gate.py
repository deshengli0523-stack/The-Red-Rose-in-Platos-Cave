from __future__ import annotations

import itertools
from datetime import datetime, timezone
from typing import cast

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.errors import WorkflowErrorCode, WorkflowOperationalError
from consultation_kb.core.ids import IdFactory
from consultation_kb.mcp.context import BoundTransport
from consultation_kb.mcp.schemas import CandidateSubmission, StoreCandidateSetInput
from consultation_kb.mcp.session_runtime import (
    GenerationRetrievalRuntime,
    SessionRuntimeManager,
    _LiveSession,
)
from consultation_kb.security.capability import CapabilityService
from consultation_kb.security.scope_broker import ScopeBroker
from consultation_kb.security.scoped_worker import ScopedWorkerBroker
from consultation_kb.security.worker_protocol import BeginSessionResponse
from consultation_kb.storage.catalog import ClientCatalog
NOW = datetime(2026, 7, 20, 8, 0, tzinfo=timezone.utc)
_fixture_ids = IdFactory(FixedClock(NOW), itertools.count(17_000).__next__)
SESSION_ID = _fixture_ids.uuid7()
TURN_ID = _fixture_ids.uuid7()
RUN_ID = _fixture_ids.uuid7()
SESSION_HANDLE = "opaque-legacy-candidate-gate"


class _ConfiguredGenerationRuntime:
    def generation_global_binding(self, *, binding: object) -> None:
        del binding
        raise AssertionError("legacy candidate rejection must precede retrieval")


class _StateTrackingWorker:
    def __init__(self) -> None:
        self.is_alive = True
        self.turn_state = "client_turn_received"
        self.calls: list[object] = []

    def call(self, request: object) -> object:
        self.calls.append(request)
        self.turn_state = "generation_in_progress"
        raise AssertionError("legacy candidate rejection must precede worker calls")


def test_configured_generation_runtime_rejects_legacy_candidate_store_before_worker() -> None:
    values = iter(range(17_100, 17_200))
    manager = SessionRuntimeManager(
        catalog=cast(ClientCatalog, object()),
        capability_service=cast(CapabilityService, object()),
        scope_broker=cast(ScopeBroker, object()),
        clock=FixedClock(NOW),
        id_factory=IdFactory(FixedClock(NOW), lambda: next(values)),
    )
    manager.configure_generation_retrieval(
        cast(GenerationRetrievalRuntime, _ConfiguredGenerationRuntime())
    )
    worker = _StateTrackingWorker()
    live = _LiveSession(
        client_id="client_" + "aaaaaaaaaaaa",
        session_id=SESSION_ID,
        session_handle=SESSION_HANDLE,
        capability_epoch=1,
        scope_marker_sha256="a" * 64,
        worker=cast(ScopedWorkerBroker, worker),
        start=cast(BeginSessionResponse, object()),
    )
    manager._by_handle[SESSION_HANDLE] = live
    manager._by_client[live.client_id] = live

    request = StoreCandidateSetInput(
        session_handle=SESSION_HANDLE,
        turn_id=TURN_ID,
        run_id=RUN_ID,
        idempotency_key="legacy-candidate-bypass",
        candidates=(
            CandidateSubmission(
                label="empathy",
                text="I hear how difficult this feels.",
            ),
            CandidateSubmission(
                label="clarify",
                text="What matters most right now?",
            ),
        ),
    )

    with pytest.raises(WorkflowOperationalError) as captured:
        manager.invoke(
            "store_candidate_set",
            request,
            binding=BoundTransport("transport-legacy-gate", SESSION_HANDLE),
        )

    assert captured.value.code is WorkflowErrorCode.GENERATION_STAGE_ORDER_INVALID
    assert worker.calls == []
    assert worker.turn_state == "client_turn_received"
