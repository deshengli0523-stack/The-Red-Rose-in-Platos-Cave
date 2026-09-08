from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import cast

import pytest

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.mcp.schemas import (
    AcknowledgeRiskObservationInput,
    AppendSessionTurnInput,
)
from consultation_kb.mcp.session_runtime import (
    SessionRuntimeError,
    SessionRuntimeManager,
    _LiveSession,
)
from consultation_kb.models.common import VersionRef
from consultation_kb.models.risk import InternalRiskObservation
from consultation_kb.risk.repository import (
    InternalRiskObservationRecord,
    RiskEvaluationAuthorityBinding,
    RiskObservationSource,
    RiskTriggerSpan,
    canonical_risk_observation_set_sha256,
)
from consultation_kb.risk.text_normalization import normalized_sensitive_fingerprint
from consultation_kb.security.capability import CapabilityService
from consultation_kb.security.scope_broker import ScopeBroker
from consultation_kb.security.scoped_worker import ScopedWorkerBroker
from consultation_kb.security.worker_protocol import (
    AcknowledgeRiskObservationRequest,
    AcknowledgeRiskObservationResponse,
    AppendClientTurnRequest,
    AppendClientTurnResponse,
    BeginSessionResponse,
    PersistRiskObservationsRequest,
    PersistRiskObservationsResponse,
    PrepareTurnRiskEvaluationRequest,
    PrepareTurnRiskEvaluationResponse,
)
from consultation_kb.storage.catalog import ClientCatalog


NOW = datetime(2026, 7, 19, 14, 0, tzinfo=timezone.utc)
SESSION_ID = "018f0000-0000-7000-8000-000000000801"
TURN_ID = "018f0000-0000-7000-8000-000000000802"
FOREIGN_SESSION_ID = "018f0000-0000-7000-8000-000000000811"
FOREIGN_TURN_ID = "018f0000-0000-7000-8000-000000000812"
SESSION_HANDLE = "session-risk-integration-handle"
PRIVATE_TEXT = (
    "PRIVATE-APPEND-TEXT SYNTH-RISK-GENERAL-4C2E "
    "SYNTH-RISK-HIGH-7D1A"
)
MESSAGE_REF = VersionRef(
    object_id="private_turn_text_018f0000-0000-7000-8000-000000000803",
    version=1,
    content_sha256=hashlib.sha256(PRIVATE_TEXT.encode("utf-8")).hexdigest(),
)
RISK_AUTHORITY = RiskEvaluationAuthorityBinding(
    global_runtime_epoch=1,
    risk_policy_manifest_ref=VersionRef(
        object_id="risk_policy_manifest_018f0000-0000-7000-8000-000000000804",
        version=1,
        content_sha256="a" * 64,
    ),
    model_mode="deterministic_only",
)


def _ref(kind: str, suffix: int, digest: str) -> VersionRef:
    return VersionRef(
        object_id=f"{kind}_018f0000-0000-7000-8000-{suffix:012x}",
        version=1,
        content_sha256=digest * 64,
    )


def _observation(
    *,
    observation_suffix: int,
    rule_suffix: int,
    category: str,
    level: str,
    start_offset: int,
    digest: str,
) -> InternalRiskObservationRecord:
    rule_ref = _ref("risk_rule", rule_suffix, digest)
    trigger = PRIVATE_TEXT[start_offset : start_offset + 4]
    normalized_length, normalized_span_sha256 = normalized_sensitive_fingerprint(
        trigger
    )
    return InternalRiskObservationRecord(
        session_id=SESSION_ID,
        observation=InternalRiskObservation(
            observation_id=(
                "risk_observation_018f0000-0000-7000-8000-"
                f"{observation_suffix:012x}"
            ),
            category=category,
            level=level,  # type: ignore[arg-type]
            trigger_turn_ids=(TURN_ID,),
            rule_ref=rule_ref,
            detected_at=NOW,
            suggested_questions=(f"SYNTH-QUESTION-{level.upper()}-VERIFY",),
        ),
        trigger_spans=(
            RiskTriggerSpan(
                turn_id=TURN_ID,
                content_ref=MESSAGE_REF,
                start_offset=start_offset,
                end_offset=start_offset + 4,
                span_sha256=hashlib.sha256(trigger.encode("utf-8")).hexdigest(),
                normalized_length=normalized_length,
                normalized_span_sha256=normalized_span_sha256,
            ),
        ),
        sources=(
            RiskObservationSource(
                source_kind="deterministic_rule",
                source_ref=rule_ref,
            ),
        ),
        confidence=1.0,
    )


OBSERVATIONS = tuple(
    sorted(
        (
            _observation(
                observation_suffix=0x806,
                rule_suffix=0x816,
                category="synthetic_general_observation",
                level="general",
                start_offset=20,
                digest="b",
            ),
            _observation(
                observation_suffix=0x807,
                rule_suffix=0x817,
                category="synthetic_high_observation",
                level="high",
                start_offset=50,
                digest="c",
            ),
        ),
        key=lambda record: record.observation.observation_id,
    )
)


def _response_scoped_observations(
    observations: tuple[InternalRiskObservationRecord, ...],
    *,
    session_id: str,
    turn_id: str,
) -> tuple[InternalRiskObservationRecord, ...]:
    return tuple(
        item.model_copy(
            update={
                "session_id": session_id,
                "observation": item.observation.model_copy(
                    update={"trigger_turn_ids": (turn_id,)}
                ),
                "trigger_spans": tuple(
                    span.model_copy(update={"turn_id": turn_id})
                    for span in item.trigger_spans
                ),
            }
        )
        for item in observations
    )


@dataclass(frozen=True, slots=True)
class _EvaluationCall:
    session_id: str
    turn_id: str
    content_ref: VersionRef
    text: str
    approved_context_keys: frozenset[str]


class _FakeTurnRiskEvaluationRuntime:
    def __init__(
        self,
        observations: tuple[InternalRiskObservationRecord, ...],
    ) -> None:
        self.observations = observations
        self.calls: list[_EvaluationCall] = []

    def current_authority(self) -> RiskEvaluationAuthorityBinding:
        return RISK_AUTHORITY

    def evaluate_turn(
        self,
        *,
        session_id: str,
        turn_id: str,
        content_ref: VersionRef,
        text: str,
        approved_context_keys: frozenset[str],
        authority: RiskEvaluationAuthorityBinding | None = None,
    ) -> tuple[InternalRiskObservationRecord, ...]:
        assert authority == RISK_AUTHORITY
        self.calls.append(
            _EvaluationCall(
                session_id=session_id,
                turn_id=turn_id,
                content_ref=content_ref,
                text=text,
                approved_context_keys=approved_context_keys,
            )
        )
        return self.observations


class _FakeLiveWorker:
    def __init__(
        self,
        message_ref: VersionRef,
        *,
        append_session_id: str = SESSION_ID,
        append_turn_id: str = TURN_ID,
        persist_session_id: str = SESSION_ID,
        persist_turn_id: str = TURN_ID,
        persisted_observations: tuple[InternalRiskObservationRecord, ...]
        | None = None,
    ) -> None:
        self.message_ref = message_ref
        self.append_session_id = append_session_id
        self.append_turn_id = append_turn_id
        self.persist_session_id = persist_session_id
        self.persist_turn_id = persist_turn_id
        self.persisted_observations = persisted_observations
        self.calls: list[object] = []
        self.is_alive = True

    def call(self, request: object) -> object:
        self.calls.append(request)
        if type(request) is AppendClientTurnRequest:
            append = request
            return AppendClientTurnResponse(
                request_id=append.request_id,
                session_id=self.append_session_id,
                turn_id=self.append_turn_id,
                ordinal=1,
                state="client_turn_received",
                client_message_ref=self.message_ref,
                client_message_sha256=self.message_ref.content_sha256,
            )
        if type(request) is PersistRiskObservationsRequest:
            persist = request
            response_observations = (
                persist.observations
                if self.persisted_observations is None
                else self.persisted_observations
            )
            return PersistRiskObservationsResponse(
                request_id=persist.request_id,
                session_id=self.persist_session_id,
                turn_id=self.persist_turn_id,
                client_message_sha256=self.message_ref.content_sha256,
                risk_authority=persist.risk_authority,
                observation_set_sha256=(
                    canonical_risk_observation_set_sha256(
                        _response_scoped_observations(
                            response_observations,
                            session_id=self.persist_session_id,
                            turn_id=self.persist_turn_id,
                        )
                    )
                ),
                observation_count=len(response_observations),
                observations=_response_scoped_observations(
                    response_observations,
                    session_id=self.persist_session_id,
                    turn_id=self.persist_turn_id,
                ),
            )
        raise AssertionError(f"unexpected worker request: {type(request).__name__}")


class _PendingRecoveryWorker(_FakeLiveWorker):
    def call(self, request: object) -> object:
        if type(request) is PrepareTurnRiskEvaluationRequest:
            self.calls.append(request)
            return PrepareTurnRiskEvaluationResponse(
                request_id=request.request_id,
                session_id=request.session_id,
                turn_id=request.turn_id,
                client_message_ref=self.message_ref,
                client_message_sha256=self.message_ref.content_sha256,
                client_message=PRIVATE_TEXT,
                risk_authority=request.risk_authority,
                evaluation_revision=2,
                evaluation_status="pending",
            )
        return super().call(request)


def _manager(
    evaluator: _FakeTurnRiskEvaluationRuntime,
) -> SessionRuntimeManager:
    clock = FixedClock(NOW)
    values = iter(range(900, 1000))
    manager = SessionRuntimeManager(
        catalog=cast(ClientCatalog, object()),
        capability_service=cast(CapabilityService, object()),
        scope_broker=cast(ScopeBroker, object()),
        clock=clock,
        id_factory=IdFactory(clock, lambda: next(values)),
    )
    manager.configure_risk_evaluation(evaluator)
    return manager


def _manager_without_risk_runtime() -> SessionRuntimeManager:
    clock = FixedClock(NOW)
    return SessionRuntimeManager(
        catalog=cast(ClientCatalog, object()),
        capability_service=cast(CapabilityService, object()),
        scope_broker=cast(ScopeBroker, object()),
        clock=clock,
        id_factory=IdFactory(clock, lambda: 999),
    )


def _live(worker: _FakeLiveWorker) -> _LiveSession:
    return _LiveSession(
        client_id="client_" + "a1b2c3d4e5f6",
        session_id=SESSION_ID,
        session_handle=SESSION_HANDLE,
        capability_epoch=1,
        scope_marker_sha256="a" * 64,
        worker=cast(ScopedWorkerBroker, worker),
        start=cast(BeginSessionResponse, object()),
    )


def _append_input() -> AppendSessionTurnInput:
    return AppendSessionTurnInput(
        session_handle=SESSION_HANDLE,
        turn_id=TURN_ID,
        client_message=PRIVATE_TEXT,
    )


def _persist_calls(worker: _FakeLiveWorker) -> tuple[PersistRiskObservationsRequest, ...]:
    return tuple(
        call
        for call in worker.calls
        if isinstance(call, PersistRiskObservationsRequest)
    )


def _field_names(value: object) -> set[str]:
    if isinstance(value, dict):
        return {
            *(str(key) for key in value),
            *(
                name
                for item in value.values()
                for name in _field_names(item)
            ),
        }
    if isinstance(value, (list, tuple)):
        return {
            name
            for item in value
            for name in _field_names(item)
        }
    return set()


def test_append_passes_exact_message_ref_and_persists_canonical_private_risk() -> None:
    evaluator = _FakeTurnRiskEvaluationRuntime(OBSERVATIONS)
    worker = _FakeLiveWorker(MESSAGE_REF)
    manager = _manager(evaluator)
    live = _live(worker)

    first_response = manager._append(live, _append_input())
    retry_response = manager._append(live, _append_input())

    assert len(evaluator.calls) == 2
    assert all(
        call.session_id == SESSION_ID
        and call.turn_id == TURN_ID
        and call.content_ref == first_response.client_message_ref == MESSAGE_REF
        and call.text == PRIVATE_TEXT
        and call.approved_context_keys
        == frozenset({"client_turn_present", "synthetic_context_present"})
        for call in evaluator.calls
    )
    persisted = _persist_calls(worker)
    assert len(persisted) == 2
    assert all(
        request.session_id == SESSION_ID
        and request.turn_id == TURN_ID
        and request.observations == OBSERVATIONS
        and tuple(
            item.observation.observation_id for item in request.observations
        )
        == tuple(
            sorted(
                item.observation.observation_id
                for item in request.observations
            )
        )
        for request in persisted
    )
    assert persisted[0].observations == persisted[1].observations
    assert retry_response.client_message_ref == first_response.client_message_ref

    outward = first_response.model_dump(mode="json")
    outward_fields = _field_names(outward)
    assert not any(
        "risk" in field or "observation" in field
        for field in outward_fields
    )
    assert PRIVATE_TEXT not in json.dumps(outward, sort_keys=True)


def test_nonempty_append_without_risk_authority_fails_before_worker_write() -> None:
    worker = _FakeLiveWorker(MESSAGE_REF)
    manager = _manager_without_risk_runtime()

    with pytest.raises(SessionRuntimeError) as raised:
        manager._append(_live(worker), _append_input())

    assert raised.value.code == "RISK_EVALUATION_UNAVAILABLE"
    assert worker.calls == []
    assert PRIVATE_TEXT not in str(raised.value)


def test_append_with_no_risk_observations_completes_durable_evaluation() -> None:
    evaluator = _FakeTurnRiskEvaluationRuntime(())
    worker = _FakeLiveWorker(MESSAGE_REF)
    manager = _manager(evaluator)

    response = manager._append(_live(worker), _append_input())

    assert response.client_message_ref == MESSAGE_REF
    assert len(evaluator.calls) == 1
    assert evaluator.calls[0].content_ref == MESSAGE_REF
    assert tuple(type(call) for call in worker.calls) == (
        AppendClientTurnRequest,
        PersistRiskObservationsRequest,
    )
    assert len(_persist_calls(worker)) == 1
    assert _persist_calls(worker)[0].observations == ()


def test_query_plan_recovery_completes_pending_authority_revision() -> None:
    evaluator = _FakeTurnRiskEvaluationRuntime(OBSERVATIONS)
    worker = _PendingRecoveryWorker(MESSAGE_REF)
    manager = _manager(evaluator)

    manager._ensure_current_turn_risk_evaluation(
        _live(worker),
        turn_id=TURN_ID,
        authority=RISK_AUTHORITY,
    )

    assert tuple(type(call) for call in worker.calls) == (
        PrepareTurnRiskEvaluationRequest,
        PersistRiskObservationsRequest,
    )
    assert len(evaluator.calls) == 1
    assert evaluator.calls[0].content_ref == MESSAGE_REF
    assert evaluator.calls[0].text == PRIVATE_TEXT
    assert _persist_calls(worker)[0].risk_authority == RISK_AUTHORITY


@pytest.mark.parametrize(
    ("append_session_id", "append_turn_id"),
    (
        (FOREIGN_SESSION_ID, TURN_ID),
        (SESSION_ID, FOREIGN_TURN_ID),
    ),
)
def test_append_fails_closed_on_foreign_worker_response_scope(
    append_session_id: str,
    append_turn_id: str,
) -> None:
    evaluator = _FakeTurnRiskEvaluationRuntime(OBSERVATIONS)
    worker = _FakeLiveWorker(
        MESSAGE_REF,
        append_session_id=append_session_id,
        append_turn_id=append_turn_id,
    )
    manager = _manager(evaluator)

    with pytest.raises(SessionRuntimeError) as raised:
        manager._append(_live(worker), _append_input())

    assert raised.value.code == "SESSION_APPEND_FAILED"
    assert evaluator.calls == []
    assert _persist_calls(worker) == ()


@pytest.mark.parametrize(
    ("persist_session_id", "persist_turn_id"),
    (
        (FOREIGN_SESSION_ID, TURN_ID),
        (SESSION_ID, FOREIGN_TURN_ID),
    ),
)
def test_append_fails_closed_on_foreign_risk_persistence_scope(
    persist_session_id: str,
    persist_turn_id: str,
) -> None:
    evaluator = _FakeTurnRiskEvaluationRuntime(OBSERVATIONS)
    worker = _FakeLiveWorker(
        MESSAGE_REF,
        persist_session_id=persist_session_id,
        persist_turn_id=persist_turn_id,
    )
    manager = _manager(evaluator)

    with pytest.raises(SessionRuntimeError) as raised:
        manager._append(_live(worker), _append_input())

    assert raised.value.code == "RISK_PERSISTENCE_FAILED"


REPLACEMENT_OBSERVATION = _observation(
    observation_suffix=0x808,
    rule_suffix=0x818,
    category="synthetic_replacement_observation",
    level="general",
    start_offset=30,
    digest="d",
)


@pytest.mark.parametrize(
    "persisted_observations",
    (
        (),
        OBSERVATIONS[:1],
        (REPLACEMENT_OBSERVATION,),
    ),
    ids=("empty", "subset", "replacement"),
)
def test_append_fails_closed_unless_persisted_risk_matches_request_exactly(
    persisted_observations: tuple[InternalRiskObservationRecord, ...],
) -> None:
    evaluator = _FakeTurnRiskEvaluationRuntime(OBSERVATIONS)
    worker = _FakeLiveWorker(
        MESSAGE_REF,
        persisted_observations=persisted_observations,
    )
    manager = _manager(evaluator)

    with pytest.raises(SessionRuntimeError) as raised:
        manager._append(_live(worker), _append_input())

    assert raised.value.code == "RISK_PERSISTENCE_FAILED"


@pytest.mark.parametrize(
    "forgery",
    (
        "content_ref",
        "span_hash",
        "normalized_length",
        "normalized_hash",
        "span_offset",
        "foreign_session",
    ),
)
def test_append_rejects_unbound_risk_evaluator_output(forgery: str) -> None:
    first = OBSERVATIONS[0]
    span = first.trigger_spans[0]
    if forgery == "content_ref":
        forged_span = span.model_copy(
            update={"content_ref": _ref("private_turn_text", 0x899, "e")}
        )
        forged = first.model_copy(update={"trigger_spans": (forged_span,)})
    elif forgery == "span_hash":
        forged_span = span.model_copy(update={"span_sha256": "e" * 64})
        forged = first.model_copy(update={"trigger_spans": (forged_span,)})
    elif forgery == "normalized_length":
        forged_span = span.model_copy(
            update={"normalized_length": span.normalized_length + 1}
        )
        forged = first.model_copy(update={"trigger_spans": (forged_span,)})
    elif forgery == "normalized_hash":
        forged_span = span.model_copy(update={"normalized_span_sha256": "e" * 64})
        forged = first.model_copy(update={"trigger_spans": (forged_span,)})
    elif forgery == "span_offset":
        forged_span = span.model_copy(
            update={"start_offset": len(PRIVATE_TEXT) + 1, "end_offset": len(PRIVATE_TEXT) + 5}
        )
        forged = first.model_copy(update={"trigger_spans": (forged_span,)})
    else:
        forged = first.model_copy(update={"session_id": FOREIGN_SESSION_ID})

    worker = _FakeLiveWorker(MESSAGE_REF)
    manager = _manager(_FakeTurnRiskEvaluationRuntime((forged,)))

    with pytest.raises(SessionRuntimeError) as raised:
        manager._append(_live(worker), _append_input())

    assert raised.value.code == "RISK_EVALUATION_FAILED"
    assert _persist_calls(worker) == ()


class _RiskLifecycleWorker:
    def __init__(self, response: AcknowledgeRiskObservationResponse) -> None:
        self.response = response
        self.calls: list[object] = []
        self.is_alive = True

    def call(self, request: object) -> object:
        self.calls.append(request)
        assert type(request) is AcknowledgeRiskObservationRequest
        return self.response.__class__.model_construct(
            **{**self.response.__dict__, "request_id": request.request_id}
        )


def _acknowledged_observation() -> InternalRiskObservationRecord:
    return OBSERVATIONS[0].model_copy(
        update={
            "status": "acknowledged",
            "acknowledged_at": NOW,
            "counselor_disposition": "continue direct observation",
        }
    )


def _closed_observation() -> InternalRiskObservationRecord:
    return _acknowledged_observation().model_copy(
        update={
            "status": "closed",
            "closed_at": NOW,
            "close_decision": "counselor_confirmed_closed",
            "close_reason": "Counselor reviewed the later context.",
        }
    )


def test_session_runtime_forwards_explicit_close_and_validates_response_scope() -> None:
    response = AcknowledgeRiskObservationResponse(
        request_id="018f0000-0000-7000-8000-000000000820",
        session_id=SESSION_ID,
        action="close",
        observation=_closed_observation(),
    )
    worker = _RiskLifecycleWorker(response)
    manager = _manager(_FakeTurnRiskEvaluationRuntime(()))
    request = AcknowledgeRiskObservationInput(
        session_handle=SESSION_HANDLE,
        observation_id=response.observation.observation.observation_id,
        action="close",
        close_decision="counselor_confirmed_closed",
        close_reason="Counselor reviewed the later context.",
    )

    result = manager._acknowledge_risk_observation(
        _live(cast(_FakeLiveWorker, worker)),
        request,
    )

    assert result == response.model_copy(
        update={"request_id": cast(AcknowledgeRiskObservationRequest, worker.calls[0]).request_id}
    )
    forwarded = cast(AcknowledgeRiskObservationRequest, worker.calls[0])
    assert forwarded.action == "close"
    assert forwarded.close_decision == request.close_decision
    assert forwarded.close_reason == request.close_reason
    assert forwarded.counselor_disposition is None
    assert forwarded.rejection_reason is None


@pytest.mark.parametrize(
    "forgery",
    (
        "session",
        "action",
        "observation_id",
        "close_decision",
        "close_reason",
    ),
)
def test_session_runtime_rejects_forged_risk_lifecycle_response(
    forgery: str,
) -> None:
    observation = _closed_observation()
    response = AcknowledgeRiskObservationResponse(
        request_id="018f0000-0000-7000-8000-000000000821",
        session_id=SESSION_ID,
        action="close",
        observation=observation,
    )
    if forgery == "session":
        response = response.model_construct(
            **{**response.__dict__, "session_id": FOREIGN_SESSION_ID}
        )
    elif forgery == "action":
        response = response.model_construct(
            **{**response.__dict__, "action": "acknowledge"}
        )
    elif forgery == "observation_id":
        foreign = observation.model_copy(
            update={
                "observation": observation.observation.model_copy(
                    update={
                        "observation_id": (
                            "risk_observation_018f0000-0000-7000-8000-"
                            "000000000899"
                        )
                    }
                )
            }
        )
        response = response.model_copy(update={"observation": foreign})
    elif forgery == "close_decision":
        response = response.model_copy(
            update={
                "observation": observation.model_copy(
                    update={"close_decision": "different_manual_decision"}
                )
            }
        )
    else:
        response = response.model_copy(
            update={
                "observation": observation.model_copy(
                    update={"close_reason": "A different manual reason."}
                )
            }
        )
    worker = _RiskLifecycleWorker(response)
    manager = _manager(_FakeTurnRiskEvaluationRuntime(()))
    request = AcknowledgeRiskObservationInput(
        session_handle=SESSION_HANDLE,
        observation_id=observation.observation.observation_id,
        action="close",
        close_decision="counselor_confirmed_closed",
        close_reason="Counselor reviewed the later context.",
    )
    worker_request = AcknowledgeRiskObservationRequest(
        request_id=response.request_id,
        session_id=SESSION_ID,
        observation_id=request.observation_id,
        action="close",
        close_decision=request.close_decision,
        close_reason=request.close_reason,
    )

    assert not ScopedWorkerBroker._response_matches(worker_request, response)

    with pytest.raises(SessionRuntimeError, match="RISK_ACKNOWLEDGEMENT_FAILED"):
        manager._acknowledge_risk_observation(
            _live(cast(_FakeLiveWorker, worker)),
            request,
        )


@pytest.mark.parametrize(
    "manual_field",
    ("counselor_disposition", "rejection_reason"),
)
def test_risk_acknowledgement_response_binds_exact_manual_decision(
    manual_field: str,
) -> None:
    requested_disposition = (
        "continue direct observation"
        if manual_field == "counselor_disposition"
        else None
    )
    requested_rejection = (
        "Counselor rejected the automatic interpretation."
        if manual_field == "rejection_reason"
        else None
    )
    observation = _acknowledged_observation().model_copy(
        update={
            "counselor_disposition": (
                "different disposition"
                if manual_field == "counselor_disposition"
                else None
            ),
            "rejection_reason": (
                "A different rejection reason."
                if manual_field == "rejection_reason"
                else None
            ),
        }
    )
    response = AcknowledgeRiskObservationResponse(
        request_id="018f0000-0000-7000-8000-000000000822",
        session_id=SESSION_ID,
        action="acknowledge",
        observation=observation,
    )
    worker = _RiskLifecycleWorker(response)
    manager = _manager(_FakeTurnRiskEvaluationRuntime(()))
    request = AcknowledgeRiskObservationInput(
        session_handle=SESSION_HANDLE,
        observation_id=observation.observation.observation_id,
        action="acknowledge",
        counselor_disposition=requested_disposition,
        rejection_reason=requested_rejection,
    )
    worker_request = AcknowledgeRiskObservationRequest(
        request_id=response.request_id,
        session_id=SESSION_ID,
        observation_id=request.observation_id,
        action="acknowledge",
        counselor_disposition=request.counselor_disposition,
        rejection_reason=request.rejection_reason,
    )

    assert not ScopedWorkerBroker._response_matches(worker_request, response)
    with pytest.raises(SessionRuntimeError, match="RISK_ACKNOWLEDGEMENT_FAILED"):
        manager._acknowledge_risk_observation(
            _live(cast(_FakeLiveWorker, worker)),
            request,
        )
