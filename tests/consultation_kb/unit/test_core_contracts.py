from __future__ import annotations

import copy
import json
import math
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import get_args

import pytest
from pydantic import BaseModel, TypeAdapter, ValidationError

from consultation_kb.core import errors as error_contracts
from consultation_kb.core.clock import FixedClock, SystemClock
from consultation_kb.core.errors import ToolError
from consultation_kb.core.ids import IdFactory
from consultation_kb.core.result import Result
from consultation_kb.models.client import BitemporalWindow, FactState
from consultation_kb.models.common import (
    ClientId,
    FiniteFloat,
    NonNegativeInt,
    ObjectId,
    PositiveInt,
    SafePolicyKey,
    SessionScope,
    Sha256Hex,
    Uuid7String,
    VersionRef,
)
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    AuthoritySnapshotBinding,
    C1ApplicabilityDecision,
    EmpiricalSupport,
    EvidenceCandidate,
    EvidenceFreshnessSnapshot,
    EvidenceLocator,
    EvidencePack,
    EvidenceProvenanceView,
    Provenance,
    RetrievalScope,
    SourceGrade,
)
from consultation_kb.models.generation import ClientReplyOutput, GenerationStageEnvelope
from consultation_kb.models.manifests import (
    ApprovalExecution,
    ApprovalReceipt,
    DraftDescriptor,
)
from consultation_kb.models.risk import InternalRiskObservation


NOW = datetime(2026, 7, 16, 8, 0, tzinfo=timezone.utc)
CLIENT_A = "client_" + "a1b2" + "c3d4" + "e5f6"
CLIENT_B = "client_" + "b1c2" + "d3e4" + "f5a6"
CLIENT_ID_RE = re.compile(r"client_[a-z0-9]{12}")
_AUTO_REVISION = object()


def _sha(index: int) -> str:
    return f"{index:064x}"


def _uuid7(index: int = 0, *, when: datetime = NOW) -> str:
    return IdFactory(FixedClock(when), lambda: index).uuid7()


def _object_id(kind: str, index: int = 0) -> str:
    return IdFactory(FixedClock(NOW), lambda: index).object_id(kind)


def _ref(kind: str, index: int = 0, *, version: int = 1) -> VersionRef:
    return VersionRef(
        object_id=_object_id(kind, index),
        version=version,
        content_sha256=_sha(index + 1),
    )


def _locator(index: int = 10) -> EvidenceLocator:
    return EvidenceLocator(
        locator_kind="source_line_span",
        anchor_refs=(_ref("anchor", index),),
        display_locator="lines:2-4",
        locator_policy_ref=_ref("locator_policy", index + 1),
    )


def _freshness(index: int = 20) -> EvidenceFreshnessSnapshot:
    return EvidenceFreshnessSnapshot(
        status="current",
        evaluated_at=NOW,
        source_observed_at=NOW - timedelta(days=3),
        last_reviewed_at=NOW - timedelta(days=1),
        review_due_at=NOW + timedelta(days=30),
        policy_ref=_ref("freshness_policy", index),
    )


def _view(scope: str = "global_source", index: int = 30) -> EvidenceProvenanceView:
    values = {
        "global_source": {
            "source_count": 2,
            "passage_count": 1,
            "case_count": 0,
            "case_contributor_count": 0,
            "independent_source_count": 1,
            "client_exclusion_status": "not_applicable",
        },
        "client_private": {
            "source_count": 0,
            "passage_count": 1,
            "case_count": 0,
            "case_contributor_count": 0,
            "independent_source_count": 0,
            "client_exclusion_status": "current_subject_private",
        },
        "case_derived": {
            "source_count": 0,
            "passage_count": 1,
            "case_count": 1,
            "case_contributor_count": 1,
            "independent_source_count": 0,
            "client_exclusion_status": "no_subject_contribution",
        },
        "mixed": {
            "source_count": 2,
            "passage_count": 2,
            "case_count": 1,
            "case_contributor_count": 1,
            "independent_source_count": 1,
            "client_exclusion_status": "leave_one_subject_out_applied",
        },
    }
    return EvidenceProvenanceView(
        provenance_ref=_ref("provenance", index),
        provenance_scope=scope,
        derivation_rule_ref=_ref("derivation_rule", index + 1),
        **values[scope],
    )


def _candidate(
    index: int,
    *,
    scope: str = "global_source",
    channel: str = "wiki",
    supports: tuple[str, ...] = (),
    contradicts: tuple[str, ...] = (),
) -> EvidenceCandidate:
    return EvidenceCandidate(
        evidence_id=_object_id("evidence", index),
        text_ref=_ref("text", index),
        location=_locator(index + 100),
        freshness=_freshness(index + 200),
        channel=channel,
        review_status="approved",
        source_grade="T1",
        framework_priority="normal",
        empirical_support="empirically_supported",
        provenance=_view(scope, index + 300),
        supports_evidence_ids=supports,
        contradicts_evidence_ids=contradicts,
        score=0.75,
    )


def _c1(
    *,
    status: str = "applicable",
    effective_status: str = "active",
    revision: VersionRef | None | object = _AUTO_REVISION,
    matched: tuple[str, ...] = ("relationship_context",),
    missing: tuple[str, ...] = (),
    empirical_support: str = "case_supported",
    conflicts: tuple[str, ...] = (),
) -> C1ApplicabilityDecision:
    if revision is _AUTO_REVISION:
        revision = _ref("theory_revision", 700)
    return C1ApplicabilityDecision(
        status=status,
        revision=revision,  # type: ignore[arg-type]
        scope_policy_ref=_ref("scope_policy", 701),
        matched_rule_ids=matched,
        missing_context_fields=missing,
        effective_status=effective_status,
        empirical_support=empirical_support,
        conflict_evidence_ids=conflicts,
    )


def _pack(
    *,
    supporting: tuple[EvidenceCandidate, ...] | None = None,
    contradicting: tuple[EvidenceCandidate, ...] = (),
    c1: C1ApplicabilityDecision | None = None,
    run_id: str | None = None,
) -> EvidencePack:
    run_id = run_id or _uuid7(800)
    return EvidencePack(
        run_id=run_id,
        authority=AuthoritySnapshotBinding(
            snapshot_ref=_ref("authority_snapshot", 801),
            run_id=run_id,
            global_runtime_epoch=3,
            client_runtime_epoch=4,
            tombstone_epoch=5,
            authorization_epoch=6,
            policy_ref=_ref("authority_policy", 802),
            created_at=NOW,
        ),
        client_snapshot_ref=_ref("profile_snapshot", 803),
        temporary_fact_refs=(),
        supporting=supporting if supporting is not None else (_candidate(1),),
        contradicting=contradicting,
        unresolved_conflict_refs=(),
        c1_applicability=c1 or _c1(),
        exclusion_proof_ref=_ref("exclusion_proof", 804),
        wiki_manifest_ref=_ref("wiki_manifest", 805),
        lexical_manifest_ref=_ref("lexical_manifest", 806),
        vector_manifest_ref=_ref("vector_manifest", 807),
        graph_manifest_ref=_ref("graph_manifest", 808),
        reranker_descriptor_ref=_ref("reranker_descriptor", 809),
    )


def test_fact_state_rejects_collapsed_status() -> None:
    with pytest.raises(ValidationError):
        FactState.model_validate({"status": "active"})


def test_bitemporal_window_rejects_naive_time() -> None:
    with pytest.raises(ValidationError):
        BitemporalWindow(
            effective_from=datetime(2026, 7, 1),
            effective_to=None,
            recorded_at=NOW,
            superseded_at=None,
        )


def test_internal_risk_visibility_is_constant() -> None:
    item = InternalRiskObservation(
        observation_id=_object_id("risk", 1),
        category="urgent_safety",
        level="high",
        trigger_turn_ids=(_uuid7(1),),
        rule_ref=_ref("risk_policy", 2),
        detected_at=NOW,
        suggested_questions=("你现在是否处在安全的地方？",),
    )
    assert item.client_facing_visibility == "never"
    with pytest.raises(ValidationError):
        InternalRiskObservation.model_validate(
            {**item.model_dump(), "client_facing_visibility": "sometimes"}
        )


def test_non_utc_offset_is_rejected() -> None:
    with pytest.raises(ValidationError, match="UTC"):
        BitemporalWindow(
            effective_from=datetime.fromisoformat("2026-07-01T08:00:00+08:00"),
            effective_to=None,
            recorded_at=NOW,
            superseded_at=None,
        )


def test_system_and_fixed_clocks_enforce_utc() -> None:
    now = SystemClock().now()
    assert now.tzinfo is not None and now.utcoffset() == timedelta(0)
    assert FixedClock(NOW).now() == NOW
    for invalid in (
        datetime(2026, 7, 16, 8, 0),
        datetime(2026, 7, 16, 8, 0, tzinfo=timezone(timedelta(hours=8))),
    ):
        with pytest.raises(ValueError, match="UTC"):
            FixedClock(invalid)


def test_uuid7_matches_rfc_9562_appendix_a6_vector() -> None:
    timestamp = datetime.fromtimestamp(1645557742, tz=timezone.utc)
    randomness = (0xCC3 << 62) | 0x18C4DC0C0C07398F
    value = IdFactory(FixedClock(timestamp), lambda: randomness).uuid7()
    assert value == "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"


def test_uuid7_honors_falsey_injected_dependencies() -> None:
    timestamp = datetime.fromtimestamp(1645557742, tz=timezone.utc)
    randomness = (0xCC3 << 62) | 0x18C4DC0C0C07398F

    class FalseyClock:
        def __init__(self) -> None:
            self.calls = 0

        def __bool__(self) -> bool:
            return False

        def now(self) -> datetime:
            self.calls += 1
            return timestamp

    class FalseyRandomSource:
        def __init__(self) -> None:
            self.calls = 0

        def __bool__(self) -> bool:
            return False

        def __call__(self) -> int:
            self.calls += 1
            return randomness

    clock = FalseyClock()
    random_source = FalseyRandomSource()
    value = IdFactory(clock, random_source).uuid7()

    assert value == "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
    assert clock.calls == random_source.calls == 1


@pytest.mark.parametrize("randomness", [0, 2**74 - 1])
def test_uuid7_accepts_exact_random_boundaries(randomness: int) -> None:
    value = IdFactory(FixedClock(NOW), lambda: randomness).uuid7()
    parsed = uuid.UUID(value)
    assert parsed.version == 7
    assert parsed.variant == uuid.RFC_4122


@pytest.mark.parametrize("randomness", [True, False, -1, 2**74, 1.0, "1", None])
def test_uuid7_rejects_invalid_random_type_or_range(randomness: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        IdFactory(FixedClock(NOW), lambda: randomness).uuid7()  # type: ignore[arg-type,return-value]


def test_uuid7_is_unique_for_distinct_randomness_and_orders_across_milliseconds() -> None:
    first = _uuid7(1)
    second = _uuid7(2)
    later = _uuid7(0, when=NOW + timedelta(milliseconds=1))
    assert first != second
    assert first < later and second < later


def test_uuid7_rejects_48_bit_timestamp_overflow() -> None:
    outside_unsigned_range = datetime(1969, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="48-bit"):
        IdFactory(FixedClock(outside_unsigned_range), lambda: 0).uuid7()


@pytest.mark.parametrize(
    ("adapter", "valid", "invalid"),
    [
        (TypeAdapter(ClientId), CLIENT_A, ["client_0042", "CLIENT_" + "a1b2c3d4e5f6", 1]),
        (TypeAdapter(Sha256Hex), "a" * 64, ["A" * 64, "a" * 63, 1]),
        (TypeAdapter(Uuid7String), _uuid7(3), [str(uuid.uuid4()), _uuid7(3).upper(), 1]),
        (TypeAdapter(PositiveInt), 1, [0, -1, True, 1.0, "1"]),
        (TypeAdapter(NonNegativeInt), 0, [-1, True, 0.0, "0"]),
        (TypeAdapter(FiniteFloat), 0.5, [math.nan, math.inf, -math.inf, "0.5"]),
    ],
)
def test_common_scalar_contracts_are_strict(adapter, valid, invalid) -> None:
    assert adapter.validate_python(valid) == valid
    for value in invalid:
        with pytest.raises(ValidationError):
            adapter.validate_python(value)


@pytest.mark.parametrize(
    "value",
    [
        "BadKey",
        "two words",
        "../policy",
        "c:/policy",
        CLIENT_A,
        f"prefix_{CLIENT_A}_suffix",
        "a" * 65,
        "line\nbreak",
    ],
)
def test_safe_policy_key_rejects_unsafe_or_noncanonical_values(value: str) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(SafePolicyKey).validate_python(value)


@pytest.mark.parametrize(
    "value",
    [
        f"A_{_uuid7(4)}",
        f"two__parts_{_uuid7(4)}",
        f"a-thing_{_uuid7(4)}",
        f"{'a' * 65}_{_uuid7(4)}",
        f"prefix_{CLIENT_A}_{_uuid7(4)}",
        f"thing_{str(uuid.uuid4())}",
    ],
)
def test_object_id_rejects_bad_kind_client_substring_or_non_v7_uuid(value: str) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(ObjectId).validate_python(value)


def test_version_ref_is_frozen_strict_and_json_stable() -> None:
    ref = _ref("claim", 9)
    assert VersionRef.model_validate_json(ref.model_dump_json()) == ref
    with pytest.raises(ValidationError):
        VersionRef.model_validate(
            {"object_id": ref.object_id, "version": "1", "content_sha256": ref.content_sha256}
        )
    with pytest.raises(ValidationError):
        VersionRef.model_validate({**ref.model_dump(), "unexpected": True})
    with pytest.raises(ValidationError):
        ref.version = 2


def test_tool_error_safe_details_are_copied_sorted_scalar_only_and_immutable() -> None:
    source: dict[str, object] = {"z_count": 2, "a_retry": False, "m_code": "synthetic"}
    error = ToolError(code="SCOPE_DENIED", message="request denied", safe_details=source)
    assert list(error.safe_details) == ["a_retry", "m_code", "z_count"]
    source["z_count"] = 99
    assert error.safe_details["z_count"] == 2
    assert json.loads(error.model_dump_json())["safe_details"] == {
        "a_retry": False,
        "m_code": "synthetic",
        "z_count": 2,
    }
    assert ToolError.model_validate_json(error.model_dump_json()) == error
    with pytest.raises(TypeError):
        error.safe_details["new"] = "value"  # type: ignore[index]
    backing = getattr(error.safe_details, "_items")
    with pytest.raises(TypeError):
        backing[0] = ("z_count", 100)
    with pytest.raises(TypeError):
        setattr(error.safe_details, "_items", backing)
    with pytest.raises(TypeError):
        delattr(error.safe_details, "_items")
    with pytest.raises(ValidationError):
        error.safe_details = {}  # type: ignore[assignment]
    for nested in ({"items": []}, {"items": {}}, {"items": ("x",)}, {"items": 1.5}):
        with pytest.raises(ValidationError):
            ToolError(code="INVALID", message="invalid", safe_details=nested)


def test_tool_error_safe_details_cannot_be_deleted_rebound_or_shared_by_copy() -> None:
    error = ToolError(
        code="SCOPE_DENIED",
        message="request denied",
        safe_details={"code": "synthetic", "count": 1},
    )
    details_copies = (
        copy.copy(error.safe_details),
        copy.deepcopy(error.safe_details),
        error.model_copy(deep=True).safe_details,
    )

    for details in details_copies:
        assert details == error.safe_details
        assert details is not error.safe_details
        with pytest.raises(TypeError):
            delattr(details, "_items")
        with pytest.raises(TypeError):
            setattr(details, "_items", ())

    first = ToolError(code="INVALID", message="invalid")
    second = ToolError(code="INVALID", message="invalid")
    assert first.safe_details == second.safe_details == {}
    assert first.safe_details is not second.safe_details


@pytest.mark.parametrize(
    "details",
    [
        {"subject": CLIENT_A},
        {"path": "C:/clients/private/session.txt"},
        {"content": "synthetic full consultation body"},
        {"exists": "object case_example exists"},
        {"code": "../private/session"},
        {"code": "relative/private"},
        {"code": "relative\\private"},
        {"code": "line\nraw"},
        {"Code": "synthetic"},
    ],
)
def test_tool_error_rejects_obvious_sensitive_safe_detail_canaries(details) -> None:
    with pytest.raises(ValidationError):
        ToolError(code="SCOPE_DENIED", message="request denied", safe_details=details)


def test_client_visible_error_boundary_is_closed_and_non_oracular() -> None:
    absent = error_contracts.map_exception_to_client_error(
        error_contracts.ScopedObjectNotFoundError(
            f"{CLIENT_A} at C:/private/body.txt"
        )
    )
    unauthorized = error_contracts.map_exception_to_client_error(
        error_contracts.ScopedObjectAccessDeniedError("object case_example exists")
    )
    assert absent == unauthorized == error_contracts.client_visible_error(
        error_contracts.ClientVisibleErrorCode.SCOPE_DENIED
    )
    assert absent.code == "SCOPE_DENIED"
    assert absent.safe_details == {}

    unknown = error_contracts.map_exception_to_client_error(
        RuntimeError("full consultation body at C:/private/session.txt exists")
    )
    serialized = unknown.model_dump_json()
    assert unknown == error_contracts.client_visible_error(
        error_contracts.ClientVisibleErrorCode.INTERNAL_ERROR
    )
    for forbidden in ("consultation body", "C:/private", "exists", CLIENT_A):
        assert forbidden not in serialized

    with pytest.raises(TypeError):
        error_contracts.client_visible_error("SCOPE_DENIED")  # type: ignore[arg-type]


def test_internal_result_requires_exactly_one_branch() -> None:
    error = ToolError(code="INVALID", message="invalid")
    assert Result.ok("value").value == "value"
    assert Result.fail(error).error == error
    with pytest.raises(ValueError):
        Result(value="value", error=error)
    with pytest.raises(ValueError):
        Result()


def test_fact_state_has_four_orthogonal_axes_and_exact_values() -> None:
    state = FactState(
        review_status="approved",
        validity_status="active",
        resolution_status="open",
        epistemic_status="uncertain",
    )
    assert set(FactState.model_fields) == {
        "review_status",
        "validity_status",
        "resolution_status",
        "epistemic_status",
    }
    for field, bad in (
        ("review_status", "active"),
        ("validity_status", "approved"),
        ("resolution_status", "pending"),
        ("epistemic_status", "known"),
    ):
        with pytest.raises(ValidationError):
            FactState.model_validate({**state.model_dump(), field: bad})


def test_bitemporal_endpoints_are_ordered() -> None:
    valid = BitemporalWindow(
        effective_from=NOW,
        effective_to=NOW + timedelta(days=1),
        recorded_at=NOW,
        superseded_at=NOW,
    )
    assert BitemporalWindow.model_validate_json(valid.model_dump_json()) == valid
    for changes in (
        {"effective_to": NOW},
        {"effective_to": NOW - timedelta(seconds=1)},
        {"superseded_at": NOW - timedelta(seconds=1)},
    ):
        with pytest.raises(ValidationError):
            BitemporalWindow.model_validate({**valid.model_dump(), **changes})


def test_approval_receipt_and_execution_state_matrix() -> None:
    receipt = ApprovalReceipt(
        request_id=_object_id("approval_request", 1),
        descriptor_sha256=_sha(1),
        approver_role="primary_counselor",
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce="synthetic-nonce",
        provider_id="local-review-agent",
        signature="synthetic-signature",
    )
    with pytest.raises(ValidationError):
        ApprovalReceipt.model_validate({**receipt.model_dump(), "expires_at": NOW})
    for state in ("issued", "claimed"):
        ApprovalExecution(
            operation_id=_object_id("approval_operation", 2),
            request_id=receipt.request_id,
            descriptor_sha256=receipt.descriptor_sha256,
            target_scope_hash=_sha(2),
            state=state,
            applied_commit_version=None,
        )
    for state in ("applied", "acknowledged"):
        ApprovalExecution(
            operation_id=_object_id("approval_operation", 3),
            request_id=receipt.request_id,
            descriptor_sha256=receipt.descriptor_sha256,
            target_scope_hash=_sha(3),
            state=state,
            applied_commit_version=1,
        )
    for state, commit in (("issued", 1), ("claimed", 1), ("applied", None), ("acknowledged", None)):
        with pytest.raises(ValidationError):
            ApprovalExecution(
                operation_id=_object_id("approval_operation", 4),
                request_id=receipt.request_id,
                descriptor_sha256=receipt.descriptor_sha256,
                target_scope_hash=_sha(4),
                state=state,
                applied_commit_version=commit,
            )


def test_draft_descriptor_requires_strict_frozen_fields() -> None:
    item = DraftDescriptor(
        purpose="profile_update",
        target_id="synthetic-profile",
        client_id=CLIENT_A,
        base_version=0,
        draft_sha256=_sha(4),
        session_id=_uuid7(4),
    )
    assert item.purpose == "profile_update"
    with pytest.raises(ValidationError):
        DraftDescriptor.model_validate({**item.model_dump(), "base_version": -1})


@pytest.mark.parametrize(
    ("scope", "source_ids", "passage_ids", "case_ids", "client_ids", "owner", "contributors"),
    [
        ("global_source", frozenset({_object_id("source", 1)}), frozenset(), frozenset(), frozenset(), None, frozenset()),
        ("client_private", frozenset(), frozenset({_object_id("passage", 2)}), frozenset(), frozenset({CLIENT_A}), CLIENT_A, frozenset()),
        ("case_derived", frozenset(), frozenset({_object_id("passage", 3)}), frozenset({_object_id("case", 3)}), frozenset({CLIENT_B}), None, frozenset({CLIENT_B})),
        ("mixed", frozenset({_object_id("source", 4)}), frozenset(), frozenset({_object_id("case", 4)}), frozenset({CLIENT_B}), None, frozenset({CLIENT_B})),
    ],
)
def test_full_provenance_accepts_exact_closed_world_matrix(
    scope, source_ids, passage_ids, case_ids, client_ids, owner, contributors
) -> None:
    value = Provenance(
        source_ids=source_ids,
        passage_ids=passage_ids,
        case_ids=case_ids,
        client_ids=client_ids,
        provenance_scope=scope,
        private_owner_client_id=owner,
        case_contributor_client_ids=contributors,
        derivation_rule_ref=_ref("derivation_rule", 1),
    )
    dumped = value.model_dump(mode="json")
    for field in ("source_ids", "passage_ids", "case_ids", "client_ids", "case_contributor_client_ids"):
        assert dumped[field] == sorted(dumped[field])


@pytest.mark.parametrize(
    ("scope", "changes"),
    [
        ("global_source", {"source_ids": frozenset()}),
        ("global_source", {"client_ids": frozenset({CLIENT_A})}),
        ("client_private", {"private_owner_client_id": None}),
        ("client_private", {"client_ids": frozenset({CLIENT_B})}),
        ("client_private", {"case_contributor_client_ids": frozenset({CLIENT_A})}),
        ("case_derived", {"case_ids": frozenset()}),
        ("case_derived", {"private_owner_client_id": CLIENT_A}),
        ("mixed", {"source_ids": frozenset()}),
        ("mixed", {"client_ids": frozenset({CLIENT_A, CLIENT_B})}),
    ],
)
def test_full_provenance_rejects_unlisted_combinations(scope: str, changes: dict) -> None:
    bases = {
        "global_source": dict(source_ids=frozenset({_object_id("source", 1)})),
        "client_private": dict(client_ids=frozenset({CLIENT_A}), private_owner_client_id=CLIENT_A),
        "case_derived": dict(
            case_ids=frozenset({_object_id("case", 1)}),
            client_ids=frozenset({CLIENT_B}),
            case_contributor_client_ids=frozenset({CLIENT_B}),
        ),
        "mixed": dict(
            source_ids=frozenset({_object_id("source", 2)}),
            case_ids=frozenset({_object_id("case", 2)}),
            client_ids=frozenset({CLIENT_B}),
            case_contributor_client_ids=frozenset({CLIENT_B}),
        ),
    }
    with pytest.raises(ValidationError):
        Provenance(
            provenance_scope=scope,
            derivation_rule_ref=_ref("derivation_rule", 2),
            **{**bases[scope], **changes},
        )


@pytest.mark.parametrize(
    ("scope", "channel", "status"),
    [
        ("global_source", "wiki", "not_applicable"),
        ("client_private", "profile", "current_subject_private"),
        ("case_derived", "case", "no_subject_contribution"),
        ("case_derived", "vector", "leave_one_subject_out_applied"),
        ("mixed", "global_graph", "no_subject_contribution"),
    ],
)
def test_safe_provenance_and_candidate_accept_closed_world_matrix(scope, channel, status) -> None:
    view = _view(scope)
    view = view.model_copy(update={"client_exclusion_status": status})
    candidate = _candidate(10, scope=scope, channel=channel).model_copy(update={"provenance": view})
    assert EvidenceCandidate.model_validate(candidate.model_dump()).channel == channel


@pytest.mark.parametrize(
    ("scope", "channel", "changes"),
    [
        ("global_source", "profile", {}),
        ("global_source", "wiki", {"independent_source_count": 3}),
        ("global_source", "wiki", {"source_count": 0}),
        ("client_private", "case", {}),
        ("client_private", "profile", {"source_count": 1}),
        ("case_derived", "case", {"case_count": 0}),
        ("case_derived", "case", {"client_exclusion_status": "not_applicable"}),
        ("mixed", "wiki", {"independent_source_count": 0}),
    ],
)
def test_safe_provenance_and_candidate_reject_unlisted_matrix(scope, channel, changes) -> None:
    base = _view(scope).model_dump()
    with pytest.raises(ValidationError):
        view = EvidenceProvenanceView.model_validate({**base, **changes})
        EvidenceCandidate.model_validate(
            {**_candidate(11, scope=scope, channel=channel).model_dump(), "provenance": view}
        )


@pytest.mark.parametrize(
    ("kind", "label"),
    [
        ("source_page_span", "pages:1:2-1:9"),
        ("source_page_span", "pages:1:9-2:1"),
        ("source_paragraph_span", "paragraphs:2-9"),
        ("source_line_span", "lines:2-9"),
        ("source_table_span", "table:1;rows:2-9;columns:3-5"),
        ("source_sheet_range", "sheet:2;range:A1-BC20"),
        ("client_fact", f"fact:{_object_id('fact', 20)}"),
        ("session_turn", f"turn:{_uuid7(20)}"),
        ("wiki_section", "section:attachment-patterns"),
        ("case_turn", f"case:{_object_id('case', 20)};turn:2"),
        ("graph_path", f"path:{_sha(20)}"),
    ],
)
def test_evidence_locator_accepts_all_ten_exact_grammars(kind: str, label: str) -> None:
    locator = EvidenceLocator(
        locator_kind=kind,
        anchor_refs=(_ref("anchor", 2), _ref("anchor", 1)),
        display_locator=label,
        locator_policy_ref=_ref("locator_policy", 1),
    )
    assert locator.anchor_refs == tuple(sorted(locator.anchor_refs, key=lambda item: (item.object_id, item.version, item.content_sha256)))


@pytest.mark.parametrize(
    ("kind", "label"),
    [
        ("source_page_span", "pages:2:1-1:9"),
        ("source_page_span", "pages:01:1-1:2"),
        ("source_paragraph_span", "paragraphs:9-2"),
        ("source_line_span", "lines:0-2"),
        ("source_table_span", "table:1;rows:4-2;columns:1-2"),
        ("source_sheet_range", "sheet:1;range:B2-A1"),
        ("source_sheet_range", "sheet:1;range:a1-B2"),
        ("session_turn", f"turn:{_uuid7(2).upper()}"),
        ("wiki_section", "section:Free Text"),
        ("wiki_section", "section:../secret"),
        ("graph_path", "path:not-a-hash"),
        ("source_line_span", "paragraphs:1-2"),
        ("source_line_span", "lines:1-2\nraw"),
    ],
)
def test_evidence_locator_rejects_noncanonical_unsafe_or_kind_mismatched_labels(kind, label) -> None:
    with pytest.raises(ValidationError):
        EvidenceLocator(
            locator_kind=kind,
            anchor_refs=(_ref("anchor", 3),),
            display_locator=label,
            locator_policy_ref=_ref("locator_policy", 3),
        )


def test_evidence_locator_requires_unique_nonempty_anchors() -> None:
    ref = _ref("anchor", 5)
    for anchors in ((), (ref, ref)):
        with pytest.raises(ValidationError):
            EvidenceLocator(
                locator_kind="source_line_span",
                anchor_refs=anchors,
                display_locator="lines:1-2",
                locator_policy_ref=_ref("locator_policy", 5),
            )


@pytest.mark.parametrize(
    "changes",
    [
        {"source_observed_at": NOW + timedelta(seconds=1)},
        {"last_reviewed_at": NOW + timedelta(seconds=1)},
        {"status": "stale", "review_due_at": NOW + timedelta(seconds=1)},
        {"status": "current", "review_due_at": NOW},
        {"status": "current", "review_due_at": NOW - timedelta(seconds=1)},
    ],
)
def test_freshness_rejects_future_observation_or_invalid_due_matrix(changes: dict) -> None:
    with pytest.raises(ValidationError):
        EvidenceFreshnessSnapshot.model_validate({**_freshness().model_dump(), **changes})


def test_freshness_allows_source_and_review_times_in_either_order() -> None:
    for observed, reviewed in (
        (NOW - timedelta(days=2), NOW - timedelta(days=1)),
        (NOW - timedelta(days=1), NOW - timedelta(days=2)),
    ):
        item = _freshness().model_copy(
            update={"source_observed_at": observed, "last_reviewed_at": reviewed}
        )
        assert EvidenceFreshnessSnapshot.model_validate(item.model_dump())


def test_candidate_relationships_are_required_canonical_unique_and_disjoint() -> None:
    target_a = _object_id("evidence", 30)
    target_b = _object_id("evidence", 31)
    item = _candidate(32, supports=(target_b, target_a), contradicts=())
    assert item.supports_evidence_ids == (target_a, target_b)
    base = item.model_dump()
    with pytest.raises(ValidationError):
        EvidenceCandidate.model_validate({key: value for key, value in base.items() if key != "supports_evidence_ids"})
    for supports, contradicts in (
        ((target_a, target_a), ()),
        ((item.evidence_id,), ()),
        ((target_a,), (target_a,)),
    ):
        with pytest.raises(ValidationError):
            EvidenceCandidate.model_validate(
                {**base, "supports_evidence_ids": supports, "contradicts_evidence_ids": contradicts}
            )


@pytest.mark.parametrize(
    ("status", "effective", "revision", "matched", "missing", "support", "valid"),
    [
        ("applicable", "active", True, ("rule_a",), (), "case_supported", True),
        ("not_applicable", "active", True, ("exclusion_rule",), (), "unassessed", True),
        ("insufficient_context", "active", True, (), ("relationship_status",), "unassessed", True),
        ("unavailable", "none", False, (), (), "unassessed", True),
        ("unavailable", "expired", True, (), (), "case_supported", True),
        ("unavailable", "superseded", True, (), (), "unassessed", True),
        ("unavailable", "revoked", True, (), (), "unassessed", True),
        ("applicable", "active", False, ("rule_a",), (), "case_supported", False),
        ("applicable", "active", True, (), (), "case_supported", False),
        ("not_applicable", "active", True, ("rule_a",), ("missing",), "unassessed", False),
        ("insufficient_context", "active", True, (), (), "unassessed", False),
        ("unavailable", "none", True, (), (), "unassessed", False),
        ("unavailable", "none", False, (), (), "case_supported", False),
        ("unavailable", "active", True, (), (), "unassessed", False),
        ("unavailable", "expired", False, (), (), "unassessed", False),
        ("unavailable", "revoked", True, (), ("missing",), "unassessed", False),
    ],
)
def test_c1_complete_state_matrix(status, effective, revision, matched, missing, support, valid) -> None:
    kwargs = dict(
        status=status,
        effective_status=effective,
        revision=_ref("theory_revision", 8) if revision else None,
        matched=matched,
        missing=missing,
        empirical_support=support,
    )
    if valid:
        assert _c1(**kwargs).status == status
    else:
        with pytest.raises(ValidationError):
            _c1(**kwargs)


def test_c1_keys_and_conflicts_are_unique_and_canonically_sorted() -> None:
    conflict_a = _object_id("evidence", 41)
    conflict_b = _object_id("evidence", 42)
    item = _c1(matched=("rule_b", "rule_a"), conflicts=(conflict_b, conflict_a))
    assert item.matched_rule_ids == ("rule_a", "rule_b")
    assert item.conflict_evidence_ids == (conflict_a, conflict_b)
    for changes in (
        {"matched_rule_ids": ("rule_a", "rule_a")},
        {"missing_context_fields": ("missing", "missing")},
        {"conflict_evidence_ids": (conflict_a, conflict_a)},
    ):
        with pytest.raises(ValidationError):
            C1ApplicabilityDecision.model_validate({**item.model_dump(), **changes})


def test_pack_enforces_run_binding_local_references_and_role_identity() -> None:
    target = _candidate(51)
    source = _candidate(52, supports=(target.evidence_id,))
    pack = _pack(supporting=(source, target), c1=_c1(conflicts=(target.evidence_id,)))
    assert {item.evidence_id for item in pack.supporting} == {source.evidence_id, target.evidence_id}

    with pytest.raises(ValidationError):
        _pack(run_id=_uuid7(99)).model_copy(
            update={"authority": _pack().authority}
        ).__class__.model_validate(
            {
                **_pack(run_id=_uuid7(99)).model_dump(),
                "authority": _pack().authority.model_dump(),
            }
        )
    dangling = _candidate(53, supports=(_object_id("evidence", 999),))
    with pytest.raises(ValidationError):
        _pack(supporting=(dangling,))
    with pytest.raises(ValidationError):
        _pack(c1=_c1(conflicts=(_object_id("evidence", 999),)))
    changed = target.model_copy(update={"score": 0.1})
    with pytest.raises(ValidationError):
        _pack(supporting=(target,), contradicting=(changed,))
    assert _pack(supporting=(target,), contradicting=(target,))


def test_pack_rejects_duplicate_role_ids_and_canonicalizes_all_set_semantic_tuples() -> None:
    first = _candidate(61)
    second = _candidate(62)
    with pytest.raises(ValidationError):
        _pack(supporting=(first, first))

    base = _pack(supporting=(second, first))
    reversed_input = EvidencePack.model_validate(
        {
            **base.model_dump(),
            "supporting": tuple(reversed(base.supporting)),
            "temporary_fact_refs": (_ref("temporary_fact", 2), _ref("temporary_fact", 1)),
            "unresolved_conflict_refs": (_ref("conflict", 2), _ref("conflict", 1)),
        }
    )
    canonical_input = EvidencePack.model_validate(
        {
            **base.model_dump(),
            "temporary_fact_refs": (_ref("temporary_fact", 1), _ref("temporary_fact", 2)),
            "unresolved_conflict_refs": (_ref("conflict", 1), _ref("conflict", 2)),
        }
    )
    assert reversed_input.model_dump_json() == canonical_input.model_dump_json()


def test_model_copy_revalidates_every_updated_domain_invariant() -> None:
    candidate = _candidate(71)
    cases = (
        (_view(), {"source_count": 0}),
        (_locator(), {"display_locator": "free client narrative"}),
        (_freshness(), {"status": "stale", "review_due_at": None}),
        (_c1(), {"status": "unavailable", "effective_status": "active"}),
        (candidate, {"supports_evidence_ids": (candidate.evidence_id,)}),
    )
    for model, update in cases:
        with pytest.raises(ValidationError):
            model.model_copy(update=update)


def test_validated_model_copy_preserves_fields_set_semantics() -> None:
    error = ToolError(code="INVALID", message="invalid")
    copied_error = error.model_copy()
    assert copied_error.model_fields_set == error.model_fields_set == {"code", "message"}
    assert copied_error.model_dump(exclude_unset=True) == {
        "code": "INVALID",
        "message": "invalid",
    }

    reply = ClientReplyOutput(text="synthetic reply")
    copied_reply = reply.model_copy(update={"schema_version": "1.0"})
    assert copied_reply.model_fields_set == {"text", "schema_version"}
    assert copied_reply.model_dump(exclude_unset=True) == {
        "schema_version": "1.0",
        "text": "synthetic reply",
    }


def test_pack_revalidates_copied_invalid_nested_domain_instances() -> None:
    candidate = _candidate(72)
    bad_view = BaseModel.model_copy(_view(), update={"source_count": 0})
    bad_locator = BaseModel.model_copy(
        _locator(), update={"display_locator": "free client narrative"}
    )
    bad_freshness = BaseModel.model_copy(
        _freshness(), update={"status": "stale", "review_due_at": None}
    )
    bad_relationships = BaseModel.model_copy(
        candidate, update={"supports_evidence_ids": (candidate.evidence_id,)}
    )
    bad_c1 = BaseModel.model_copy(
        _c1(), update={"status": "unavailable", "effective_status": "active"}
    )

    invalid_packs = (
        {"supporting": (BaseModel.model_copy(candidate, update={"provenance": bad_view}),)},
        {"supporting": (BaseModel.model_copy(candidate, update={"location": bad_locator}),)},
        {"supporting": (BaseModel.model_copy(candidate, update={"freshness": bad_freshness}),)},
        {"supporting": (bad_relationships,)},
        {"c1": bad_c1},
    )
    for kwargs in invalid_packs:
        with pytest.raises(ValidationError):
            _pack(**kwargs)


def test_pack_requires_all_explicit_tuple_fields() -> None:
    payload = _pack().model_dump()
    for field in (
        "temporary_fact_refs",
        "supporting",
        "contradicting",
        "unresolved_conflict_refs",
    ):
        with pytest.raises(ValidationError):
            EvidencePack.model_validate({key: value for key, value in payload.items() if key != field})


def test_pack_type_graph_dump_and_json_have_no_client_identity() -> None:
    pack = _pack()
    schema_text = json.dumps(EvidencePack.model_json_schema(), sort_keys=True)
    dump_text = json.dumps(pack.model_dump(mode="json"), sort_keys=True)
    json_text = pack.model_dump_json()
    for text in (schema_text, dump_text, json_text):
        assert not CLIENT_ID_RE.search(text)
        for forbidden in (
            "client_id",
            "client_ids",
            "private_owner_client_id",
            "case_contributor_client_ids",
            CLIENT_A,
            CLIENT_B,
        ):
            assert forbidden not in text


def test_source_grade_and_empirical_support_are_exact_frozen_literals() -> None:
    assert get_args(SourceGrade) == (
        "T1", "T2", "T3", "T4",
        "C1", "C2", "C3", "C4", "C5", "C6",
        "K1", "K2", "K3", "K4",
        "L1", "L2", "L3", "L4",
    )
    assert get_args(EmpiricalSupport) == (
        "unassessed",
        "case_supported",
        "observation_supported",
        "empirically_supported",
        "guideline_consistent",
        "conflicting",
    )


def test_generation_and_reply_roots_have_exact_shapes_and_rules() -> None:
    envelope = GenerationStageEnvelope(
        stage="query_plan",
        turn_id=_uuid7(81),
        run_id=_uuid7(82),
        parent_sha256s=(_sha(2), _sha(1)),
        created_at=NOW,
    )
    assert set(GenerationStageEnvelope.model_fields) == {
        "schema_version", "stage", "turn_id", "run_id", "parent_sha256s", "created_at"
    }
    assert envelope.parent_sha256s == (_sha(1), _sha(2))
    assert set(ClientReplyOutput.model_fields) == {"schema_version", "text"}
    with pytest.raises(ValidationError):
        GenerationStageEnvelope.model_validate(
            {**envelope.model_dump(), "parent_sha256s": (_sha(1), _sha(1))}
        )
    with pytest.raises(ValidationError):
        ClientReplyOutput(text="   ")
    with pytest.raises(ValidationError):
        ClientReplyOutput.model_validate({"text": "normal reply", "risk_level": "high"})


def test_internal_risk_root_has_exact_shape_and_canonical_rules() -> None:
    item = InternalRiskObservation(
        observation_id=_object_id("risk", 91),
        category="urgent_safety",
        level="general",
        trigger_turn_ids=(_uuid7(92), _uuid7(91)),
        rule_ref=_ref("risk_policy", 91),
        detected_at=NOW,
        suggested_questions=("第一个合成问题？", "第二个合成问题？"),
    )
    assert set(InternalRiskObservation.model_fields) == {
        "schema_version",
        "observation_id",
        "category",
        "level",
        "trigger_turn_ids",
        "rule_ref",
        "detected_at",
        "suggested_questions",
        "client_facing_visibility",
    }
    assert item.trigger_turn_ids == tuple(sorted(item.trigger_turn_ids))
    assert item.suggested_questions == ("第一个合成问题？", "第二个合成问题？")
    for changes in (
        {"trigger_turn_ids": ()},
        {"trigger_turn_ids": (_uuid7(91), _uuid7(91))},
        {"suggested_questions": ()},
        {"suggested_questions": ("same", "same")},
        {"suggested_questions": (" ",)},
    ):
        with pytest.raises(ValidationError):
            InternalRiskObservation.model_validate({**item.model_dump(), **changes})


def test_scope_and_authority_models_use_exact_strict_refs_and_utc() -> None:
    scope = RetrievalScope(
        current_client_id=CLIENT_A,
        allowed_uses=frozenset({"continuity", "consultation"}),
        maximum_sensitivity=2,
        effective_at=NOW,
        known_at=NOW,
    )
    assert scope.model_dump(mode="json")["allowed_uses"] == ["consultation", "continuity"]
    snapshot = AuthoritativeFilterSnapshot(
        run_id=_uuid7(101),
        global_runtime_epoch=1,
        client_runtime_epoch=2,
        tombstone_epoch=3,
        authorization_epoch=4,
        allowed_ref_ids=frozenset({_object_id("claim", 2), _object_id("claim", 1)}),
        policy_ref=_ref("authority_policy", 101),
        created_at=NOW,
    )
    assert snapshot.model_dump(mode="json")["allowed_ref_ids"] == sorted(snapshot.allowed_ref_ids)


def test_every_direct_datetime_field_rejects_naive_and_nonzero_offsets() -> None:
    run_id = _uuid7(110)
    cases = (
        (
            SessionScope(
                session_handle="synthetic-session-handle",
                session_id=run_id,
                permissions=frozenset({"client_read"}),
                expires_at=NOW,
            ),
            {"expires_at"},
        ),
        (
            BitemporalWindow(
                effective_from=NOW,
                effective_to=NOW + timedelta(days=1),
                recorded_at=NOW,
                superseded_at=NOW + timedelta(days=1),
            ),
            {"effective_from", "effective_to", "recorded_at", "superseded_at"},
        ),
        (
            ApprovalReceipt(
                request_id=_object_id("approval_request", 110),
                descriptor_sha256=_sha(110),
                approver_role="primary_counselor",
                approved_at=NOW,
                expires_at=NOW + timedelta(days=1),
                nonce="synthetic-nonce",
                provider_id="local-review-agent",
                signature="synthetic-signature",
            ),
            {"approved_at", "expires_at"},
        ),
        (
            RetrievalScope(
                current_client_id=CLIENT_A,
                allowed_uses=frozenset({"consultation"}),
                maximum_sensitivity=1,
                effective_at=NOW,
                known_at=NOW,
            ),
            {"effective_at", "known_at"},
        ),
        (
            AuthoritativeFilterSnapshot(
                run_id=run_id,
                global_runtime_epoch=1,
                client_runtime_epoch=1,
                tombstone_epoch=1,
                authorization_epoch=1,
                allowed_ref_ids=frozenset(),
                policy_ref=_ref("authority_policy", 110),
                created_at=NOW,
            ),
            {"created_at"},
        ),
        (
            AuthoritySnapshotBinding(
                snapshot_ref=_ref("authority_snapshot", 111),
                run_id=run_id,
                global_runtime_epoch=1,
                client_runtime_epoch=1,
                tombstone_epoch=1,
                authorization_epoch=1,
                policy_ref=_ref("authority_policy", 111),
                created_at=NOW,
            ),
            {"created_at"},
        ),
        (_freshness(112), {"evaluated_at", "source_observed_at", "last_reviewed_at", "review_due_at"}),
        (
            GenerationStageEnvelope(
                stage="query_plan",
                turn_id=_uuid7(112),
                run_id=run_id,
                parent_sha256s=(),
                created_at=NOW,
            ),
            {"created_at"},
        ),
        (
            InternalRiskObservation(
                observation_id=_object_id("risk", 112),
                category="urgent_safety",
                level="general",
                trigger_turn_ids=(_uuid7(113),),
                rule_ref=_ref("risk_policy", 112),
                detected_at=NOW,
                suggested_questions=("合成问题？",),
            ),
            {"detected_at"},
        ),
    )
    invalid_values = (
        datetime(2026, 7, 16, 8, 0),
        datetime(2026, 7, 16, 8, 0, tzinfo=timezone(timedelta(hours=8))),
    )
    for item, datetime_fields in cases:
        for field_name in datetime_fields:
            for invalid in invalid_values:
                payload = dict(item.__dict__)
                payload[field_name] = invalid
                with pytest.raises(ValidationError, match="UTC"):
                    item.__class__.model_validate(payload)
