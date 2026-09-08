from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

from consultation_kb.core.errors import WorkflowOperationalError
from consultation_kb.generation.contracts import (
    QueryGuardrails,
    QueryPlan,
    RouteOmission,
    Subquery,
)
from consultation_kb.models.generation import GenerationStageEnvelope
from consultation_kb.models.common import VersionRef
from consultation_kb.models.risk import InternalRiskObservation
from consultation_kb.risk.repository import (
    InternalRiskObservationRecord,
    RiskObservationSource,
    RiskTriggerSpan,
)
from consultation_kb.risk.text_normalization import normalized_sensitive_fingerprint
from consultation_kb.security.scoped_worker import ScopeDenied
from consultation_kb.security.worker_protocol import (
    AppendClientTurnRequest,
    AppendClientTurnResponse,
    BeginSessionRequest,
    GetGenerationBindingRequest,
    GetGenerationBindingResponse,
    PersistRiskObservationsRequest,
    PrepareGenerationRetrievalRequest,
    PrepareGenerationRetrievalResponse,
    PrepareTurnRiskEvaluationRequest,
    PrepareTurnRiskEvaluationResponse,
    SubmitGenerationStageRequest,
    SubmitGenerationStageResponse,
)
from consultation_kb.storage.connection import connect_database
from tests.consultation_kb.integration.test_session_worker_boundary import (
    _build_harness,
    _request_id,
)
from tests.consultation_kb.risk_support import deterministic_risk_authority
from tests.consultation_kb.unit.p6_quality_support import NOW


pytestmark = [
    pytest.mark.integration,
    pytest.mark.acceptance_id("RISK-AUTHORITY-BINDING-01"),
    pytest.mark.skipif(sys.platform != "win32", reason="Windows scoped subprocess"),
]
CLIENT_MESSAGE = "A body-private turn bound to one risk authority."


def _risk_hit(
    *,
    session_id: str,
    turn_id: str,
    content_ref: VersionRef,
    suffix: int,
    digest: str,
) -> InternalRiskObservationRecord:
    phrase = "body-private"
    start = CLIENT_MESSAGE.index(phrase)
    normalized_length, normalized_span_sha256 = normalized_sensitive_fingerprint(
        phrase
    )
    rule_ref = VersionRef(
        object_id=f"risk_rule_018f0000-0000-7000-8000-{suffix:012x}",
        version=1,
        content_sha256=digest * 64,
    )
    return InternalRiskObservationRecord(
        session_id=session_id,
        observation=InternalRiskObservation(
            observation_id=(
                "risk_observation_018f0000-0000-7000-8000-"
                f"{suffix:012x}"
            ),
            category="synthetic_authority_risk",
            level="general",
            trigger_turn_ids=(turn_id,),
            rule_ref=rule_ref,
            detected_at=NOW,
            suggested_questions=("Confirm the current authority-bound signal.",),
        ),
        trigger_spans=(
            RiskTriggerSpan(
                turn_id=turn_id,
                content_ref=content_ref,
                start_offset=start,
                end_offset=start + len(phrase),
                span_sha256=hashlib.sha256(phrase.encode("utf-8")).hexdigest(),
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


def _plan(
    *,
    turn_id: str,
    run_id: str,
    binding: GetGenerationBindingResponse,
) -> QueryPlan:
    return QueryPlan(
        envelope=GenerationStageEnvelope(
            stage="query_plan",
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=(),
            created_at=NOW,
        ),
        intent="simple_empathic_clarification",
        client_snapshot_ref=binding.binding.client_snapshot_ref,
        global_runtime_epoch=7,
        client_runtime_epoch=binding.binding.client_runtime_epoch,
        tombstone_epoch=binding.binding.client_tombstone_count,
        authorization_epoch=11,
        guardrails=QueryGuardrails(),
        subqueries=(
            Subquery(
                subquery_id="bounded_support",
                category="emotion_needs_relationship",
                question="What bounded support is relevant?",
                routes=("wiki",),
                required_evidence_types=(),
                scope="global_knowledge",
            ),
        ),
        route_omissions=tuple(
            RouteOmission(route=route, reason="Not required for this gate test.")
            for route in (
                "profile",
                "client_history",
                "lexical",
                "vector",
                "global_graph",
                "case",
            )
        ),
        rationale_summary="Exercise the exact risk-authority gate.",
    )


@pytest.mark.parametrize("forgery", ("normalized_length", "normalized_hash"))
def test_worker_recomputes_normalized_trigger_fingerprint_before_persist(
    tmp_path: Path,
    forgery: str,
) -> None:
    harness = _build_harness(tmp_path)
    authority = deterministic_risk_authority(epoch=7, suffix=916_000)
    turn_id = harness.ids.uuid7()
    worker = harness.worker()
    try:
        worker.start()
        worker.call(
            BeginSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                capability_epoch=harness.scope.capability_epoch,
            )
        )
        appended = worker.call(
            AppendClientTurnRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                client_message=CLIENT_MESSAGE,
                risk_authority=authority,
            )
        )
        assert isinstance(appended, AppendClientTurnResponse)
        record = _risk_hit(
            session_id=harness.session_id,
            turn_id=turn_id,
            content_ref=appended.client_message_ref,
            suffix=0x916100,
            digest="a",
        )
        span = record.trigger_spans[0]
        if forgery == "normalized_length":
            forged_span = span.model_copy(
                update={"normalized_length": span.normalized_length + 1}
            )
        else:
            forged_span = span.model_copy(
                update={"normalized_span_sha256": "e" * 64}
            )
        forged = record.model_copy(update={"trigger_spans": (forged_span,)})

        with pytest.raises(ScopeDenied, match="SCOPE_DENIED"):
            worker.call(
                PersistRiskObservationsRequest(
                    request_id=_request_id(harness),
                    session_id=harness.session_id,
                    turn_id=turn_id,
                    risk_authority=authority,
                    observations=(forged,),
                )
            )
        assert worker.closed
    finally:
        worker.close()


def test_restart_recovers_new_authority_revision_before_query_plan(
    tmp_path: Path,
) -> None:
    harness = _build_harness(tmp_path)
    first = deterministic_risk_authority(epoch=7, suffix=917_000)
    changed = deterministic_risk_authority(epoch=7, suffix=917_001)
    turn_id = harness.ids.uuid7()
    run_id = harness.ids.uuid7()
    worker = harness.worker()
    try:
        worker.start()
        worker.call(
            BeginSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                capability_epoch=harness.scope.capability_epoch,
            )
        )
        appended = worker.call(
            AppendClientTurnRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                client_message=CLIENT_MESSAGE,
                risk_authority=first,
            )
        )
        assert isinstance(appended, AppendClientTurnResponse)
        first_hit = _risk_hit(
            session_id=harness.session_id,
            turn_id=turn_id,
            content_ref=appended.client_message_ref,
            suffix=0x917100,
            digest="a",
        )
        worker.call(
            PersistRiskObservationsRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                risk_authority=first,
                observations=(first_hit,),
            )
        )
        worker.close()

        worker = harness.worker()
        worker.start()
        worker.call(
            BeginSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                capability_epoch=harness.scope.capability_epoch,
            )
        )
        binding = worker.call(
            GetGenerationBindingRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
            )
        )
        assert isinstance(binding, GetGenerationBindingResponse)
        plan = _plan(turn_id=turn_id, run_id=run_id, binding=binding)

        with pytest.raises(
            WorkflowOperationalError,
            match="RISK_EVALUATION_INCOMPLETE",
        ):
            worker.call(
                SubmitGenerationStageRequest(
                    request_id=_request_id(harness),
                    session_id=harness.session_id,
                    idempotency_key="stale-risk-authority-plan",
                    stage_payload=plan,
                    risk_authority=changed,
                )
            )

        prepared = worker.call(
            PrepareTurnRiskEvaluationRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                risk_authority=changed,
            )
        )
        assert isinstance(prepared, PrepareTurnRiskEvaluationResponse)
        assert prepared.evaluation_revision == 2
        assert prepared.evaluation_status == "pending"
        worker.close()

        worker = harness.worker()
        worker.start()
        worker.call(
            BeginSessionRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                capability_epoch=harness.scope.capability_epoch,
            )
        )
        recovered = worker.call(
            PrepareTurnRiskEvaluationRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                risk_authority=changed,
            )
        )
        assert isinstance(recovered, PrepareTurnRiskEvaluationResponse)
        assert recovered.evaluation_revision == prepared.evaluation_revision
        assert recovered.evaluation_status == "pending"
        assert recovered.client_message_ref == prepared.client_message_ref
        assert recovered.client_message == prepared.client_message
        worker.call(
            PersistRiskObservationsRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                risk_authority=changed,
                observations=(
                    _risk_hit(
                        session_id=harness.session_id,
                        turn_id=turn_id,
                        content_ref=recovered.client_message_ref,
                        suffix=0x917101,
                        digest="b",
                    ),
                ),
            )
        )

        submitted = worker.call(
            SubmitGenerationStageRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                idempotency_key="current-risk-authority-plan",
                stage_payload=plan,
                risk_authority=changed,
            )
        )
        assert isinstance(submitted, SubmitGenerationStageResponse)

        with pytest.raises(
            WorkflowOperationalError,
            match="RISK_EVALUATION_INCOMPLETE",
        ):
            worker.call(
                SubmitGenerationStageRequest(
                    request_id=_request_id(harness),
                    session_id=harness.session_id,
                    idempotency_key="superseded-risk-authority-plan",
                    stage_payload=plan,
                    risk_authority=first,
                )
            )
        retrieval = worker.call(
            PrepareGenerationRetrievalRequest(
                request_id=_request_id(harness),
                session_id=harness.session_id,
                turn_id=turn_id,
                run_id=run_id,
                query_plan_sha256=submitted.record.artifact.content_sha256,
                risk_authority=changed,
                query_categories=("continuity",),
            )
        )
        assert isinstance(retrieval, PrepareGenerationRetrievalResponse)
        assert retrieval.risk_context_binding.authority == changed
        assert retrieval.risk_context_binding.evaluation_observation_ids == (
            "risk_observation_018f0000-0000-7000-8000-000000917101",
        )
        assert retrieval.risk_context_binding.visible_observation_ids == (
            "risk_observation_018f0000-0000-7000-8000-000000917100",
            "risk_observation_018f0000-0000-7000-8000-000000917101",
        )

        client_reader = connect_database(
            harness.client_a_root / "client.sqlite3",
            mode="reader",
        )
        try:
            revisions = client_reader.execute(
                "SELECT evaluation_revision, status "
                "FROM turn_risk_evaluations "
                "WHERE session_id = ? AND turn_id = ? "
                "ORDER BY evaluation_revision",
                (harness.session_id, turn_id),
            ).fetchall()
        finally:
            client_reader.close()
        assert revisions == [(1, "completed"), (2, "completed")]
    finally:
        worker.close()
        harness.close()
