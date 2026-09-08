from __future__ import annotations

import hashlib
import inspect
import json
import re
from datetime import UTC, datetime
from collections.abc import Callable

import pytest
from pydantic import ValidationError

from consultation_kb.security.worker_protocol import (
    ArchiveContentRef,
    AppendScopedAuditRequest,
    AppendScopedAuditResponse,
    BeginSessionRequest,
    EmptyContextMetadataRequest,
    EmptyContextMetadataResponse,
    OperationBinding,
    PingRequest,
    PingResponse,
    QueryFactSnapshotRequest,
    QueryClientHistoryCandidatesRequest,
    ScopeDeniedResponse,
    StageSharedCaseOutboxResponse,
    WorkerOperationRegistry,
    WorkerProtocolError,
    WorkerRequest,
    WorkerResponse,
    decode_request,
    decode_response,
    encode_message,
)
from consultation_kb.security import worker_main, worker_protocol


REQUEST_ID = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
SYNTHETIC_CLIENT_ID = "client" + "_bbbbbbbbbbbb"


def _ping_handler(request: WorkerRequest) -> WorkerResponse:
    assert type(request) is PingRequest
    return PingResponse(request_id=request.request_id)


def _metadata_handler(request: WorkerRequest) -> WorkerResponse:
    assert type(request) is EmptyContextMetadataRequest
    return EmptyContextMetadataResponse(request_id=request.request_id)


def _audit_handler(request: WorkerRequest) -> WorkerResponse:
    assert type(request) is AppendScopedAuditRequest
    return AppendScopedAuditResponse(request_id=request.request_id)


def _binding(
    operation: str,
    handler: Callable[[WorkerRequest], WorkerResponse],
) -> OperationBinding:
    models = {
        "ping": (PingRequest, PingResponse, "client_read"),
        "get_empty_context_metadata": (
            EmptyContextMetadataRequest,
            EmptyContextMetadataResponse,
            "client_read",
        ),
        "append_scoped_audit": (
            AppendScopedAuditRequest,
            AppendScopedAuditResponse,
            "session_append",
        ),
    }
    request_model, response_model, permission = models[operation]
    return OperationBinding(
        schema_version="1.0",
        operation=operation,
        request_model=request_model,
        response_model=response_model,
        required_permission=permission,
        handler=handler,
    )


def test_request_models_are_flat_strict_and_have_no_generic_payload() -> None:
    request_types = (
        PingRequest,
        EmptyContextMetadataRequest,
        AppendScopedAuditRequest,
    )
    forbidden = {
        "client_id",
        "path",
        "payload",
        "receipt",
        "secret",
        "shell",
        "sql",
        "ticket",
    }

    for model_type in request_types:
        assert forbidden.isdisjoint(model_type.model_fields)
        assert set(model_type.model_fields) == {
            "schema_version",
            "operation",
            "request_id",
        }
        with pytest.raises(ValidationError):
            model_type.model_validate(
                {
                    "schema_version": "1.0",
                    "operation": model_type.model_fields["operation"].default,
                    "request_id": REQUEST_ID,
                    "payload": {},
                }
            )


def test_published_case_response_requires_exact_global_version() -> None:
    response = {
        "request_id": REQUEST_ID,
        "bundle_id": "archive_bundle_017f22e2-79b0-7cc3-98c4-dc0c0c073981",
        "action": "COMMIT",
        "event_id": "case_outbox_event_017f22e2-79b0-7cc3-98c4-dc0c0c073982",
        "payload_ref": ArchiveContentRef(
            object_id=(
                "case_outbox_payload_017f22e2-79b0-7cc3-98c4-dc0c0c073983"
            ),
            version=1,
            content_sha256="a" * 64,
            size_bytes=128,
        ),
        "approval_operation_id": (
            "approval_operation_017f22e2-79b0-7cc3-98c4-dc0c0c073984"
        ),
        "applied_commit_version": 7,
        "release_outcome": "eligible",
        "state": "PUBLISHED",
        "attempt_count": 1,
        "published_global_version": 3,
    }
    published = StageSharedCaseOutboxResponse.model_validate(response)
    assert published.published_global_version == 3

    without_version = dict(response)
    without_version.pop("published_global_version")
    with pytest.raises(ValidationError):
        StageSharedCaseOutboxResponse.model_validate(without_version)

    unpublished_with_version = {**response, "state": "CLAIMED"}
    with pytest.raises(ValidationError):
        StageSharedCaseOutboxResponse.model_validate(unpublished_with_version)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("client_id", SYNTHETIC_CLIENT_ID),
        ("path", r"C:\other-client\client.sqlite3"),
        ("sql", "SELECT * FROM clients"),
        ("shell", "whoami"),
        ("payload", {"anything": "goes"}),
    ],
)
def test_decode_request_rejects_forbidden_or_generic_fields(
    field: str,
    value: object,
) -> None:
    raw = json.dumps(
        {
            "schema_version": "1.0",
            "operation": "ping",
            "request_id": REQUEST_ID,
            field: value,
        }
    ).encode("utf-8")

    with pytest.raises(WorkerProtocolError, match="WORKER_PROTOCOL_INVALID"):
        decode_request(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":"1.0","operation":"unknown","request_id":"017f22e2-79b0-7cc3-98c4-dc0c0c07398f"}',
        b'{"schema_version":"2.0","operation":"ping","request_id":"017f22e2-79b0-7cc3-98c4-dc0c0c07398f"}',
        b'{"schema_version":"1.0","operation":"ping","operation":"append_scoped_audit","request_id":"017f22e2-79b0-7cc3-98c4-dc0c0c07398f"}',
        b'{"schema_version":"1.0","operation":"ping","request_id":"017f22e2-79b0-7cc3-98c4-dc0c0c07398f","n":NaN}',
        b"[]",
        b"not-json",
        b"",
    ],
)
def test_decode_request_fails_closed_for_unknown_version_or_malformed_json(
    raw: bytes,
) -> None:
    with pytest.raises(WorkerProtocolError, match="WORKER_PROTOCOL_INVALID"):
        decode_request(raw)


def test_decode_request_maps_excessive_json_nesting_to_protocol_error() -> None:
    raw = b'[{"x":' + (b"[" * 2_000) + b"0" + (b"]" * 2_000) + b"}]"

    with pytest.raises(WorkerProtocolError, match="WORKER_PROTOCOL_INVALID"):
        decode_request(raw)


def test_wire_encoding_is_canonical_ascii_and_round_trips_exact_model() -> None:
    request = PingRequest(request_id=REQUEST_ID)

    encoded = encode_message(request)

    assert encoded == (
        b'{"operation":"ping","request_id":"017f22e2-79b0-7cc3-98c4-'
        b'dc0c0c07398f","schema_version":"1.0"}'
    )
    assert decode_request(encoded) == request


def test_wire_round_trip_preserves_strict_utc_datetime_fields() -> None:
    request = QueryFactSnapshotRequest(
        request_id=REQUEST_ID,
        effective_at=datetime(2026, 7, 18, 8, 0, tzinfo=UTC),
        known_at=datetime(2026, 7, 18, 8, 1, tzinfo=UTC),
        fixed_epoch=0,
    )

    encoded = encode_message(request)

    assert decode_request(encoded) == request


def test_scope_denied_response_has_one_fixed_content_free_shape() -> None:
    response = ScopeDeniedResponse()

    encoded = encode_message(response)

    assert encoded == (
        b'{"error_code":"SCOPE_DENIED","response_type":"scope_denied",'
        b'"schema_version":"1.0","success":false}'
    )
    assert decode_response(encoded) == response
    assert "request" not in type(response).model_fields


def test_registry_binds_exact_models_permission_and_callable() -> None:
    registry = WorkerOperationRegistry(
        (
            _binding("ping", _ping_handler),
            _binding("get_empty_context_metadata", _metadata_handler),
            _binding("append_scoped_audit", _audit_handler),
        )
    )

    request = PingRequest(request_id=REQUEST_ID)
    binding = registry.resolve(request)

    assert binding.request_model is PingRequest
    assert binding.response_model is PingResponse
    assert binding.required_permission == "client_read"
    assert registry.dispatch(request) == PingResponse(request_id=REQUEST_ID)


def test_registry_rejects_duplicate_or_unknown_registration() -> None:
    ping = _binding("ping", _ping_handler)
    with pytest.raises(WorkerProtocolError, match="WORKER_PROTOCOL_INVALID"):
        WorkerOperationRegistry((ping, ping))

    with pytest.raises(WorkerProtocolError, match="WORKER_PROTOCOL_INVALID"):
        OperationBinding(
            schema_version="1.0",
            operation="read_path",
            request_model=PingRequest,
            response_model=PingResponse,
            required_permission="client_read",
            handler=_ping_handler,
        )


def test_registry_rejects_handler_returning_wrong_response_contract() -> None:
    def wrong_handler(request: WorkerRequest) -> WorkerResponse:
        return EmptyContextMetadataResponse(request_id=request.request_id)

    registry = WorkerOperationRegistry((_binding("ping", wrong_handler),))

    with pytest.raises(WorkerProtocolError, match="WORKER_PROTOCOL_INVALID"):
        registry.dispatch(PingRequest(request_id=REQUEST_ID))


def test_frozen_registry_surface_has_no_dynamic_execution_mechanism() -> None:
    protocol_source = inspect.getsource(worker_protocol)
    worker_source = inspect.getsource(worker_main)

    assert set(worker_protocol._REQUEST_MODELS) == {
        "ping",
        "get_empty_context_metadata",
        "append_scoped_audit",
        "query_fact_snapshot",
        "preview_fact_mutation",
        "commit_fact_mutation",
        "query_profile_snapshot",
        "query_client_graph",
        "search_client_graph",
        "query_client_weighted_path",
        "query_client_history_candidates",
        "preview_dependency_impact",
        "preview_target_dependency_impact",
        "begin_session",
        "resume_session",
        "append_client_turn",
        "append_temporary_fact",
        "begin_generation",
        "store_candidate_set",
        "record_actual_reply",
        "read_session_state",
        "submit_generation_stage",
        "get_generation_state",
        "acknowledge_risk_observation",
        "get_generation_binding",
        "prepare_generation_retrieval",
        "get_generation_evidence_for_plan",
        "store_generation_evidence_pack",
        "prepare_turn_risk_evaluation",
        "persist_risk_observations",
        "build_private_archive",
        "commit_private_archive",
        "build_profile_diff",
        "commit_profile_update",
        "stage_shared_case_outbox",
        "recover_client_manifests",
        "preflight_client_lifecycle_commit",
        "preview_client_delete",
        "commit_client_tombstone",
        "preview_client_rebuild",
        "rebuild_client_derivatives",
        "preview_client_rollback",
        "commit_client_rollback",
        "verify_client_integrity",
    }
    for forbidden_pattern in (
        r"\bimportlib\b",
        r"\bsubprocess\b",
        r"\bshell\s*=\s*True\b",
        r"(?<![A-Za-z0-9_])eval\(",
        r"(?<![A-Za-z0-9_])exec\(",
        r"(?<![A-Za-z0-9_])compile\(",
    ):
        assert re.search(forbidden_pattern, protocol_source) is None
        assert re.search(forbidden_pattern, worker_source) is None


def test_worker_second_line_rejects_foreign_session_and_history_handle() -> None:
    session_id = REQUEST_ID
    foreign_session_id = "017f22e2-79b0-7cc3-98c4-dc0c0c073990"
    capability_token = "opaque-capability-token"
    bootstrap = worker_main._WorkerBootstrap(
        scope_root="C:\\opaque-client-root",
        global_descriptor_sha256="a" * 64,
        scope_marker_sha256="b" * 64,
        session_id=session_id,
        capability_token_sha256=hashlib.sha256(
            capability_token.encode("utf-8")
        ).hexdigest(),
    )

    worker_main._verify_request_session_binding(
        BeginSessionRequest(
            request_id=REQUEST_ID,
            session_id=session_id,
            capability_epoch=1,
        ),
        bootstrap,
    )
    worker_main._verify_request_session_binding(
        QueryClientHistoryCandidatesRequest(
            request_id=REQUEST_ID,
            session_handle=capability_token,
            query_category="continuity",
        ),
        bootstrap,
    )
    with pytest.raises(WorkerProtocolError, match="WORKER_PROTOCOL_INVALID"):
        worker_main._verify_request_session_binding(
            BeginSessionRequest(
                request_id=REQUEST_ID,
                session_id=foreign_session_id,
                capability_epoch=1,
            ),
            bootstrap,
        )
    with pytest.raises(WorkerProtocolError, match="WORKER_PROTOCOL_INVALID"):
        worker_main._verify_request_session_binding(
            QueryClientHistoryCandidatesRequest(
                request_id=REQUEST_ID,
                session_handle="foreign-capability-token",
                query_category="continuity",
            ),
            bootstrap,
        )


def test_worker_binding_registry_covers_every_target_bearing_request_dto() -> None:
    request_models = tuple(worker_protocol._REQUEST_MODELS.values())
    assert {
        model
        for model in request_models
        if "session_id" in model.model_fields
    } == set(worker_protocol._SESSION_BOUND_REQUEST_TYPES)
    assert {
        model
        for model in request_models
        if "session_handle" in model.model_fields
    } == set(worker_protocol._HANDLE_BOUND_REQUEST_TYPES)
