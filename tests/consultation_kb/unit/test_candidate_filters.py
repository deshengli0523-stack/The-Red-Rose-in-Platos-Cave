from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

import pytest

from consultation_kb.retrieval.contracts import LeaveOneOutVariant
from consultation_kb.retrieval.filters import CandidateFilter, StaticAuthorityGuard
from consultation_kb.retrieval.resolver import EvidenceResolver
from tests.consultation_kb.retrieval_support import (
    CLIENT_A,
    CLIENT_B,
    NOW,
    candidate,
    case_provenance,
    private_provenance,
    reference,
    scope,
    snapshot,
)


@dataclass
class TrackingReader:
    requested: list[str]

    def read_verified(self, value):
        self.requested.append(value.reference.object_id)
        return b"abc"


@dataclass(frozen=True)
class ExactLeaveOneOutVerifier:
    parent_ref: object
    variant_ref: object
    client_id: str

    def is_exact_approved_variant(
        self,
        *,
        original,
        variant,
        scope,
        authority_snapshot,
    ) -> bool:
        return (
            original.reference == self.parent_ref
            and variant.reference == self.variant_ref
            and scope.current_client_id == self.client_id
            and variant.reference.object_id in authority_snapshot.allowed_ref_ids
        )


def test_denied_current_client_case_is_never_resolved() -> None:
    current_case = candidate(10, provenance=case_provenance(10, CLIENT_A, CLIENT_B))
    authority = snapshot(current_case)
    guard = StaticAuthorityGuard(authority)
    decision = CandidateFilter(guard).filter(scope(), (current_case,), authority)
    reader = TrackingReader([])

    resolved = EvidenceResolver(guard, reader).resolve_many(decision.allowed)

    assert resolved == ()
    assert reader.requested == []
    assert decision.proof.reasons == {"source_client_excluded": 1}


def test_approved_leave_one_out_replaces_current_client_lineage() -> None:
    original = candidate(20, provenance=case_provenance(20, CLIENT_A, CLIENT_B))
    variant_ref = reference("passage", 21)
    variant_provenance = case_provenance(21, CLIENT_B)
    variant = LeaveOneOutVariant(
        reference=variant_ref,
        content_ref=variant_ref,
        object_type="passage",
        manifest_ref=reference("artifact_manifest", 321),
        review_status="approved",
        allowed_uses=frozenset({"answer_support"}),
        approved_at=NOW,
        sensitivity=1,
        source_grade="K3",
        source_count=1,
        provenance=variant_provenance,
        location=original.location,
        freshness=original.freshness,
        media_type="text/plain",
        size_bytes=3,
    )
    original = original.model_copy(
        update={
            "metadata": original.metadata.model_copy(
                update={"leave_one_out": variant}
            )
        }
    )
    replacement = candidate(21, provenance=variant_provenance)
    authority = snapshot(original, replacement)

    untrusted = CandidateFilter(StaticAuthorityGuard(authority)).filter(
        scope(), (original,), authority
    )
    assert untrusted.allowed == ()
    assert untrusted.proof.reasons == {"leave_one_out_ineligible": 1}

    decision = CandidateFilter(
        StaticAuthorityGuard(authority),
        leave_one_out_verifier=ExactLeaveOneOutVerifier(
            original.reference,
            variant_ref,
            CLIENT_A,
        ),
    ).filter(scope(), (original,), authority)

    assert tuple(item.reference for item in decision.allowed) == (variant_ref,)
    assert decision.proof.denied_count == 0
    assert CLIENT_A not in decision.allowed[0].provenance.case_contributor_client_ids


def test_private_history_is_continuity_only_and_owner_bound() -> None:
    history = candidate(
        30,
        provenance=private_provenance(30),
        channel="client_history",
        object_type="client_graph",
        allowed_uses=frozenset({"continuity"}),
    )
    authority = snapshot(history)
    filterer = CandidateFilter(StaticAuthorityGuard(authority))

    allowed = filterer.filter(scope(use="continuity"), (history,), authority)
    denied_use = filterer.filter(scope(use="case_example"), (history,), authority)
    denied_owner = filterer.filter(
        scope(client_id=CLIENT_B, use="continuity"), (history,), authority
    )

    assert len(allowed.allowed) == 1
    assert denied_use.proof.reasons == {"use_denied": 1}
    assert denied_owner.proof.reasons == {"scope_denied": 1}


def test_unfiltered_candidate_cannot_reach_resolver() -> None:
    value = candidate(40)
    authority = snapshot(value)
    reader = TrackingReader([])

    with pytest.raises(Exception, match="EVIDENCE_RESOLUTION_DENIED"):
        EvidenceResolver(StaticAuthorityGuard(authority), reader).resolve_many((value,))

    assert reader.requested == []


def test_filter_capability_binds_content_ref_and_all_candidate_metadata() -> None:
    value = candidate(41)
    authority = snapshot(value)
    guard = StaticAuthorityGuard(authority)
    decision = CandidateFilter(guard).filter(scope(), (value,), authority)
    tampered = decision.allowed[0].model_copy(
        update={"content_ref": reference("passage", 999)}
    )
    reader = TrackingReader([])

    with pytest.raises(Exception, match="EVIDENCE_RESOLUTION_DENIED"):
        EvidenceResolver(guard, reader).resolve_many((tampered,))

    assert reader.requested == []


def test_filter_capability_allows_score_updates_and_reordering_of_same_set() -> None:
    first = candidate(42)
    second = candidate(43)
    authority = snapshot(first, second)
    guard = StaticAuthorityGuard(authority)
    decision = CandidateFilter(guard).filter(
        scope(),
        (first, second),
        authority,
    )
    reranked = tuple(
        value.model_copy(update={"score": float(rank)})
        for rank, value in enumerate(reversed(decision.allowed), start=1)
    )
    reader = TrackingReader([])

    resolved = EvidenceResolver(guard, reader).resolve_many(reranked)

    assert tuple(item.candidate for item in resolved) == reranked
    assert reader.requested == [
        second.reference.object_id,
        first.reference.object_id,
    ]


@pytest.mark.parametrize(
    "reason",
    [
        "not_authorized",
        "tombstoned",
        "scope_denied",
        "use_denied",
        "review_not_approved",
        "not_yet_effective",
        "expired",
        "review_overdue",
        "sensitivity_denied",
        "source_client_excluded",
        "leave_one_out_ineligible",
    ],
)
def test_every_filter_gate_has_one_fixed_reason_and_no_body_read(reason: str) -> None:
    value = candidate(100)
    tombstoned = frozenset()
    if reason == "scope_denied":
        value = candidate(
            100,
            provenance=private_provenance(100, CLIENT_B),
            channel="profile",
        )
    elif reason == "use_denied":
        value = candidate(100, allowed_uses=frozenset({"continuity"}))
    elif reason == "review_not_approved":
        value = value.model_copy(
            update={
                "metadata": value.metadata.model_copy(
                    update={"review_status": "reviewed"}
                )
            }
        )
    elif reason == "not_yet_effective":
        value = value.model_copy(
            update={
                "metadata": value.metadata.model_copy(
                    update={"effective_from": NOW + timedelta(seconds=1)}
                )
            }
        )
    elif reason == "expired":
        value = value.model_copy(
            update={
                "metadata": value.metadata.model_copy(
                    update={"effective_to": NOW}
                )
            }
        )
    elif reason == "review_overdue":
        value = value.model_copy(
            update={
                "metadata": value.metadata.model_copy(
                    update={"review_due_at": NOW}
                )
            }
        )
    elif reason == "sensitivity_denied":
        value = value.model_copy(
            update={
                "metadata": value.metadata.model_copy(update={"sensitivity": 4})
            }
        )
    elif reason == "source_client_excluded":
        value = candidate(100, provenance=case_provenance(100, CLIENT_A))
    elif reason == "leave_one_out_ineligible":
        value = candidate(
            100,
            provenance=case_provenance(100, CLIENT_A, CLIENT_B),
        )
        variant_ref = reference("passage", 101)
        variant = LeaveOneOutVariant(
            reference=variant_ref,
            content_ref=variant_ref,
            object_type="passage",
            manifest_ref=reference("artifact_manifest", 401),
            review_status="approved",
            allowed_uses=frozenset({"answer_support"}),
            approved_at=NOW,
            sensitivity=1,
            source_grade="K3",
            source_count=1,
            provenance=case_provenance(101, CLIENT_B),
            location=value.location,
            freshness=value.freshness,
            media_type="text/plain",
            size_bytes=3,
        )
        value = value.model_copy(
            update={
                "metadata": value.metadata.model_copy(
                    update={
                        "leave_one_out": variant,
                        "minimum_leave_one_out_sources": 2,
                    }
                )
            }
        )
    authority = snapshot() if reason == "not_authorized" else snapshot(value)
    if reason == "tombstoned":
        tombstoned = frozenset({value.reference.object_id})
    guard = StaticAuthorityGuard(authority, tombstoned_ids=tombstoned)
    decision = CandidateFilter(guard).filter(scope(), (value,), authority)
    reader = TrackingReader([])

    assert EvidenceResolver(guard, reader).resolve_many(decision.allowed) == ()
    assert reader.requested == []
    assert decision.proof.reasons == {reason: 1}
    proof_json = decision.proof.model_dump_json()
    assert value.reference.object_id not in proof_json
    assert CLIENT_A not in proof_json
    assert CLIENT_B not in proof_json
