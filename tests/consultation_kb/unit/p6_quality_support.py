"""Synthetic P6 quality-test fixtures with no real client content."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.generation.contracts import (
    ConsistencySemanticAssessment,
    ReplyDraftSet,
)
from consultation_kb.knowledge._canonical import text_sha256
from consultation_kb.models.consistency import ConsistencySnapshot
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import (
    AuthoritySnapshotBinding,
    C1ApplicabilityDecision,
    EvidenceCandidate,
    EvidenceFreshnessSnapshot,
    EvidenceLocator,
    EvidencePack,
    EvidenceProvenanceView,
)
from consultation_kb.models.generation import GenerationStageEnvelope, GenerationStageName


NOW = datetime(2026, 7, 19, 2, 0, tzinfo=timezone.utc)


def sha(index: int) -> str:
    return f"{index:064x}"


def uuid7(index: int) -> str:
    return IdFactory(FixedClock(NOW), lambda: index).uuid7()


def object_id(kind: str, index: int) -> str:
    return IdFactory(FixedClock(NOW), lambda: index).object_id(kind)


def ref(kind: str, index: int, *, version: int = 1) -> VersionRef:
    return VersionRef(
        object_id=object_id(kind, index),
        version=version,
        content_sha256=sha(index + 1),
    )


def envelope(stage: GenerationStageName, index: int = 900) -> GenerationStageEnvelope:
    return GenerationStageEnvelope(
        stage=stage,
        turn_id=uuid7(index),
        run_id=uuid7(index + 1),
        parent_sha256s=(sha(index + 2),),
        created_at=NOW,
    )


def candidate(
    index: int,
    *,
    freshness: str = "current",
    contradicts: tuple[str, ...] = (),
) -> EvidenceCandidate:
    review_due_at = NOW + timedelta(days=30)
    if freshness == "stale":
        review_due_at = NOW - timedelta(days=1)
    return EvidenceCandidate(
        evidence_id=object_id("evidence", index),
        text_ref=ref("text", index),
        location=EvidenceLocator(
            locator_kind="source_line_span",
            anchor_refs=(ref("anchor", index + 100),),
            display_locator="lines:2-4",
            locator_policy_ref=ref("locator_policy", index + 200),
        ),
        freshness=EvidenceFreshnessSnapshot(
            status=freshness,
            evaluated_at=NOW,
            source_observed_at=NOW - timedelta(days=3),
            last_reviewed_at=NOW - timedelta(days=1),
            review_due_at=review_due_at,
            policy_ref=ref("freshness_policy", index + 300),
        ),
        channel="wiki",
        review_status="approved",
        source_grade="T1",
        framework_priority="normal",
        empirical_support="empirically_supported",
        provenance=EvidenceProvenanceView(
            provenance_ref=ref("provenance", index + 400),
            provenance_scope="global_source",
            source_count=1,
            passage_count=1,
            case_count=0,
            case_contributor_count=0,
            independent_source_count=1,
            client_exclusion_status="not_applicable",
            derivation_rule_ref=ref("derivation_rule", index + 500),
        ),
        supports_evidence_ids=(),
        contradicts_evidence_ids=contradicts,
        score=0.8,
    )


def pack(
    *,
    supporting: tuple[EvidenceCandidate, ...] | None = None,
    contradicting: tuple[EvidenceCandidate, ...] = (),
    c1_status: str = "applicable",
    effective_status: str = "active",
    missing_context_fields: tuple[str, ...] = (),
    c1_conflicts: tuple[str, ...] = (),
    empirical_support: str = "case_supported",
    temporary_fact_refs: tuple[VersionRef, ...] = (),
) -> EvidencePack:
    support = supporting if supporting is not None else (candidate(1),)
    run_id = uuid7(800)
    unavailable_without_revision = (
        c1_status == "unavailable" and effective_status == "none"
    )
    revision = None if unavailable_without_revision else ref("theory_revision", 700)
    matched = (
        ("relationship_context",)
        if c1_status in {"applicable", "not_applicable"}
        else ()
    )
    c1 = C1ApplicabilityDecision(
        status=c1_status,
        revision=revision,
        scope_policy_ref=ref("scope_policy", 701),
        matched_rule_ids=matched,
        missing_context_fields=missing_context_fields,
        effective_status=effective_status,
        empirical_support=("unassessed" if unavailable_without_revision else empirical_support),
        conflict_evidence_ids=c1_conflicts,
    )
    return EvidencePack(
        run_id=run_id,
        authority=AuthoritySnapshotBinding(
            snapshot_ref=ref("authority_snapshot", 801),
            run_id=run_id,
            global_runtime_epoch=3,
            client_runtime_epoch=4,
            tombstone_epoch=5,
            authorization_epoch=6,
            policy_ref=ref("authority_policy", 802),
            created_at=NOW,
        ),
        client_snapshot_ref=ref("profile_snapshot", 803),
        temporary_fact_refs=temporary_fact_refs,
        supporting=support,
        contradicting=contradicting,
        unresolved_conflict_refs=(),
        c1_applicability=c1,
        exclusion_proof_ref=ref("exclusion_proof", 804),
        wiki_manifest_ref=ref("wiki_manifest", 805),
        lexical_manifest_ref=ref("lexical_manifest", 806),
        vector_manifest_ref=ref("vector_manifest", 807),
        graph_manifest_ref=ref("graph_manifest", 808),
        reranker_descriptor_ref=ref("reranker_descriptor", 809),
    )


def current_consistency_assessments(
    replies: ReplyDraftSet,
    snapshots: tuple[ConsistencySnapshot, ...],
) -> tuple[ConsistencySemanticAssessment, ...]:
    """Build independent-critic-shaped fixtures over full candidate spans."""

    text_by_candidate = {
        candidate.candidate_id: candidate.text for candidate in replies.candidates
    }
    assessments: list[ConsistencySemanticAssessment] = []
    for snapshot in snapshots:
        text = text_by_candidate[snapshot.snapshot_key]
        axes = (
            *(("fact", item.fact_key, item.state) for item in snapshot.facts),
            *(
                ("core_position", item.position_key, item.stance)
                for item in snapshot.core_positions
            ),
            *(
                ("action_direction", item.action_key, item.disposition)
                for item in snapshot.action_directions
            ),
        )
        assessments.extend(
            ConsistencySemanticAssessment(
                snapshot_key=snapshot.snapshot_key,
                axis_kind=axis_kind,
                subject_key=subject_key,
                assessed_value=assessed_value,
                text_start_char=0,
                text_end_char=len(text),
                exact_excerpt=text,
                excerpt_sha256=text_sha256(text),
            )
            for axis_kind, subject_key, assessed_value in axes
        )
    return tuple(sorted(assessments, key=lambda item: item.assessment_key()))


__all__ = [
    "NOW",
    "candidate",
    "current_consistency_assessments",
    "envelope",
    "object_id",
    "pack",
    "ref",
    "sha",
    "uuid7",
]
