from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import cast

import pytest
from pydantic import ValidationError

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.mcp.context import BoundTransport
from consultation_kb.mcp.schemas import (
    RecordActualReplyInput,
    SubmitGenerationStageInput,
)
from consultation_kb.mcp.session_runtime import (
    SessionRuntimeError,
    SessionRuntimeManager,
    _LiveSession,
)
from consultation_kb.models.session import ActualReply, StoredContentRef
from consultation_kb.security.capability import CapabilityService
from consultation_kb.security.scope_broker import ScopeBroker
from consultation_kb.security.scoped_worker import ScopedWorkerBroker
from consultation_kb.security.worker_protocol import (
    BeginSessionResponse,
    FinalCandidateBinding,
    GenerationStageWireRecord,
    RecordActualReplyRequest,
    RecordActualReplyResponse,
    SubmitGenerationStageRequest,
    SubmitGenerationStageResponse,
)
from consultation_kb.storage.catalog import ClientCatalog
from tests.consultation_kb.unit.p6_quality_support import NOW, object_id, sha, uuid7
from tests.consultation_kb.unit.test_generation_contracts import _final


SESSION_ID = uuid7(16_000)
REQUEST_ID = uuid7(16_001)
SESSION_HANDLE = "response-closure-session-handle-0001"


def _content(
    kind: str,
    index: int,
    digest: str,
    size: int,
    *,
    media_type: str = "text/plain",
) -> StoredContentRef:
    return StoredContentRef(
        object_id=object_id(kind, index),
        content_sha256=digest,
        media_type=media_type,
        size_bytes=size,
    )


def _canonical_sha256(payload: dict[str, object]) -> str:
    return hashlib.sha256(
        (
            json.dumps(
                payload,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
    ).hexdigest()


def _edited_exchange() -> tuple[
    RecordActualReplyRequest,
    RecordActualReplyResponse,
]:
    text = "Synthetic edited reply."
    text_digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    diff_digest = hashlib.sha256(b"synthetic diff").hexdigest()
    candidate_id = object_id("candidate_reply", 16_010)
    sent_at = NOW
    operation_sha256 = _canonical_sha256(
        {
            "candidate_id": candidate_id,
            "diff_sha256": diff_digest,
            "reply_sha256": text_digest,
            "sent_at": sent_at.isoformat(timespec="microseconds").replace(
                "+00:00", "Z"
            ),
            "source_type": "edited",
        }
    )
    actual = ActualReply(
        actual_reply_id=object_id("actual_reply", 16_011),
        session_id=SESSION_ID,
        turn_id=_final("c" * 64).envelope.turn_id,
        idempotency_key="actual-response-closure",
        operation_sha256=operation_sha256,
        source_type="edited",
        candidate_id=candidate_id,
        content=_content("actual_reply", 16_012, text_digest, len(text.encode("utf-8"))),
        diff=_content(
            "reply_diff",
            16_013,
            diff_digest,
            len(b"synthetic diff"),
            media_type="text/x-diff",
        ),
        sent_at=sent_at,
        confirmed_at=None,
        evidence_gap=False,
        created_at=NOW,
    )
    request = RecordActualReplyRequest(
        request_id=REQUEST_ID,
        session_id=SESSION_ID,
        turn_id=actual.turn_id,
        idempotency_key=actual.idempotency_key,
        mode="edited",
        candidate_id=candidate_id,
        actual_text=text,
        sent_at=sent_at,
    )
    return request, RecordActualReplyResponse(
        request_id=REQUEST_ID,
        session_id=SESSION_ID,
        turn_id=actual.turn_id,
        actual_reply_id=actual.actual_reply_id,
        source_type="edited",
        state="turn_closed",
        evidence_gap=False,
        actual_reply=actual,
    )


def _final_exchange() -> tuple[
    SubmitGenerationStageRequest,
    SubmitGenerationStageResponse,
]:
    final = _final("c" * 64)
    request = SubmitGenerationStageRequest(
        request_id=REQUEST_ID,
        session_id=SESSION_ID,
        idempotency_key="final-response-closure",
        stage_payload=final,
    )
    persistent_ids = tuple(
        object_id("candidate_reply", 16_020 + index)
        for index in range(len(final.client_reply_candidates))
    )
    bindings = tuple(
        FinalCandidateBinding(
            persistent_candidate_id=persistent_id,
            ordinal=index,
            logical_candidate_id=logical.candidate_id,
            label=logical.label,
            text_sha256=hashlib.sha256(logical.text.encode("utf-8")).hexdigest(),
        )
        for index, (persistent_id, logical) in enumerate(
            zip(persistent_ids, final.client_reply_candidates, strict=True),
            start=1,
        )
    )
    record = GenerationStageWireRecord(
        stage_revision_id=object_id("generation_stage_revision", 16_030),
        revision=1,
        stage="final_bundle",
        artifact=_content(
            "generation_stage",
            16_031,
            sha(16_031),
            1,
            media_type="application/json",
        ),
        parent_sha256s=final.envelope.parent_sha256s,
        payload=final,
        created_at=final.envelope.created_at,
    )
    return request, SubmitGenerationStageResponse(
        request_id=REQUEST_ID,
        session_id=SESSION_ID,
        turn_id=final.envelope.turn_id,
        run_id=final.envelope.run_id,
        record=record,
        turn_state="awaiting_actual_reply",
        candidate_set_id=object_id("candidate_set", 16_032),
        candidate_ids=persistent_ids,
        candidate_bindings=bindings,
    )


class _ResponseWorker:
    is_alive = True

    def __init__(self, response: object) -> None:
        self.response = response

    def call(self, request: object) -> object:
        assert hasattr(request, "request_id")
        response = cast(RecordActualReplyResponse, self.response)
        return response.__class__.model_construct(
            **{**response.__dict__, "request_id": request.request_id}
        )


def _manager() -> SessionRuntimeManager:
    entropy = iter(range(16_100, 16_200))
    return SessionRuntimeManager(
        catalog=cast(ClientCatalog, object()),
        capability_service=cast(CapabilityService, object()),
        scope_broker=cast(ScopeBroker, object()),
        clock=FixedClock(NOW),
        id_factory=IdFactory(FixedClock(NOW), lambda: next(entropy)),
    )


def _live(worker: _ResponseWorker) -> _LiveSession:
    return _LiveSession(
        client_id="client_" + "aaaaaaaaaaaa",
        session_id=SESSION_ID,
        session_handle=SESSION_HANDLE,
        capability_epoch=1,
        scope_marker_sha256="a" * 64,
        worker=cast(ScopedWorkerBroker, worker),
        start=cast(BeginSessionResponse, object()),
    )


@pytest.mark.parametrize("forgery", ("candidate", "idempotency", "text_sha", "sent_at"))
def test_actual_reply_response_rejects_same_turn_same_type_forgery(
    forgery: str,
) -> None:
    request, response = _edited_exchange()
    actual = response.actual_reply
    if forgery == "candidate":
        actual = actual.model_copy(
            update={"candidate_id": object_id("candidate_reply", 16_040)}
        )
    elif forgery == "idempotency":
        actual = actual.model_copy(update={"idempotency_key": "different-key"})
    elif forgery == "text_sha":
        assert actual.content is not None
        actual = actual.model_copy(
            update={
                "content": actual.content.model_copy(
                    update={"content_sha256": "f" * 64}
                )
            }
        )
    else:
        actual = actual.model_copy(update={"sent_at": NOW + timedelta(seconds=1)})
    forged = response.model_copy(update={"actual_reply": actual})

    assert ScopedWorkerBroker._response_matches(request, response)
    assert not ScopedWorkerBroker._response_matches(request, forged)
    worker = _ResponseWorker(forged)
    with pytest.raises(SessionRuntimeError, match="SESSION_ACTUAL_REPLY_FAILED"):
        _manager()._record_actual(
            _live(worker),
            RecordActualReplyInput(
                session_handle=SESSION_HANDLE,
                turn_id=request.turn_id,
                idempotency_key=request.idempotency_key,
                mode="edited",
                candidate_id=request.candidate_id,
                actual_text=request.actual_text,
                sent_at=request.sent_at,
            ),
        )


@pytest.mark.parametrize("forgery", ("candidate_order", "text_sha"))
def test_final_candidate_binding_rejects_swapped_or_forged_mapping(
    forgery: str,
) -> None:
    request, response = _final_exchange()
    if forgery == "candidate_order":
        forged = SubmitGenerationStageResponse.model_construct(
            **{
                **response.__dict__,
                "candidate_ids": tuple(reversed(response.candidate_ids)),
            }
        )
    else:
        first = response.candidate_bindings[0].model_copy(
            update={"text_sha256": "f" * 64}
        )
        forged = SubmitGenerationStageResponse.model_construct(
            **{
                **response.__dict__,
                "candidate_bindings": (first, *response.candidate_bindings[1:]),
            }
        )

    assert ScopedWorkerBroker._response_matches(request, response)
    assert not ScopedWorkerBroker._response_matches(request, forged)
    with pytest.raises(ValidationError, match="final candidate binding closure"):
        SubmitGenerationStageResponse.model_validate(
            forged.model_dump(mode="python"),
            strict=True,
        )


@pytest.mark.parametrize("forgery", ("candidate_order", "text_sha"))
def test_session_runtime_rejects_forged_final_candidate_mapping(
    monkeypatch: pytest.MonkeyPatch,
    forgery: str,
) -> None:
    request, response = _final_exchange()
    if forgery == "candidate_order":
        forged = SubmitGenerationStageResponse.model_construct(
            **{
                **response.__dict__,
                "candidate_ids": tuple(reversed(response.candidate_ids)),
            }
        )
    else:
        first = response.candidate_bindings[0].model_copy(
            update={"text_sha256": "e" * 64}
        )
        forged = SubmitGenerationStageResponse.model_construct(
            **{
                **response.__dict__,
                "candidate_bindings": (
                    first,
                    *response.candidate_bindings[1:],
                ),
            }
        )

    def _binding_is_current(
        _self: SessionRuntimeManager,
        _live_session: _LiveSession,
        *,
        turn_id: str,
        run_id: str,
        binding: BoundTransport,
    ) -> None:
        assert turn_id == request.stage_payload.envelope.turn_id
        assert run_id == request.stage_payload.envelope.run_id
        assert binding.session_handle == SESSION_HANDLE

    monkeypatch.setattr(
        SessionRuntimeManager,
        "_assert_generation_binding_current",
        _binding_is_current,
    )
    with pytest.raises(
        SessionRuntimeError,
        match="GENERATION_STAGE_SUBMIT_FAILED",
    ):
        _manager()._submit_generation_stage(
            _live(_ResponseWorker(forged)),
            SubmitGenerationStageInput(
                session_handle=SESSION_HANDLE,
                idempotency_key=request.idempotency_key,
                payload=request.stage_payload,
            ),
            binding=BoundTransport("response-closure-transport", SESSION_HANDLE),
        )
