"""Worker-side authority for deterministic generation consistency results."""

from __future__ import annotations

from typing import Literal

from consultation_kb.generation.consistency import ConsistencyReviewer
from consultation_kb.generation.contracts import (
    ConsistencyFinding as StageConsistencyFinding,
    ConsistencyRiskReview,
    ReplyDraftSet,
)
from consultation_kb.generation.evidence_registry import (
    GenerationEvidenceBindingMismatch,
    GenerationEvidenceContextItem,
    validate_generation_evidence_context,
)
from consultation_kb.models.consistency import (
    ConsistencyFinding,
    ConsistencySnapshot,
)
from consultation_kb.models.evidence import EvidencePack


class GenerationConsistencyValidationError(RuntimeError):
    def __init__(self, code: str = "CONSISTENCY_RECOMPUTATION_MISMATCH") -> None:
        super().__init__(code)


def _snapshot_evidence(snapshot: ConsistencySnapshot) -> frozenset[str]:
    return frozenset(
        (*snapshot.conclusion_evidence_ids,)
        + tuple(
            evidence_id
            for fact in snapshot.facts
            for evidence_id in fact.evidence_ids
        )
    )


class GenerationConsistencyValidator:
    """Bind semantic snapshots to trusted artifacts, then recompute results."""

    def require_valid(
        self,
        submitted: ConsistencyRiskReview,
        *,
        reply_drafts: ReplyDraftSet,
        evidence_pack: EvidencePack,
        evidence_context: tuple[GenerationEvidenceContextItem, ...],
    ) -> None:
        review = ConsistencyRiskReview.model_validate(submitted, strict=True)
        replies = ReplyDraftSet.model_validate(reply_drafts, strict=True)
        pack = EvidencePack.model_validate(evidence_pack, strict=True)
        try:
            context = validate_generation_evidence_context(pack, evidence_context)
        except GenerationEvidenceBindingMismatch:
            raise GenerationConsistencyValidationError(
                "CONSISTENCY_EVIDENCE_CONTEXT_MISMATCH"
            ) from None
        self._validate_current_snapshots(review, replies)
        self._validate_historical_snapshots(review, pack)
        self._validate_semantic_assessments(review, replies, pack, context)

        result = ConsistencyReviewer().review(
            current_candidates=review.current_candidate_snapshots,
            session_earlier=review.session_earlier_snapshots,
            client_profiles=review.client_profile_snapshots,
            conclusion_changes=review.conclusion_changes,
            retry_count=review.retry_count,
        )
        snapshots = {
            item.snapshot_key: item
            for item in (
                *review.current_candidate_snapshots,
                *review.session_earlier_snapshots,
                *review.client_profile_snapshots,
            )
        }
        expected_findings = tuple(
            self._project_finding(index, finding, snapshots)
            for index, finding in enumerate(result.findings, start=1)
        )
        unresolved = self._unresolved_reasons(result.decision)
        if (
            review.consistency_findings != expected_findings
            or review.conclusion_changes != result.conclusion_changes
            or review.decision != result.decision
            or review.retry_count != result.retry_count
            or review.unresolved_reasons != unresolved
        ):
            raise GenerationConsistencyValidationError

    @staticmethod
    def _validate_current_snapshots(
        review: ConsistencyRiskReview,
        replies: ReplyDraftSet,
    ) -> None:
        snapshots = {
            item.snapshot_key: item for item in review.current_candidate_snapshots
        }
        drafts = {item.candidate_id: item for item in replies.candidates}
        if set(snapshots) != set(drafts):
            raise GenerationConsistencyValidationError(
                "CONSISTENCY_CURRENT_CANDIDATE_BINDING_MISMATCH"
            )
        for candidate_id, draft in drafts.items():
            snapshot = snapshots[candidate_id]
            fact_keys = {item.fact_key for item in snapshot.facts}
            position_keys = {item.position_key for item in snapshot.core_positions}
            action_keys = {item.action_key for item in snapshot.action_directions}
            declared_evidence = frozenset(draft.evidence_ids)
            if (
                snapshot.source != "current_candidate"
                or snapshot.conclusion != draft.text
                or fact_keys != set(draft.current_fact_ids)
                or position_keys != set(draft.core_positions)
                or action_keys != set(draft.action_directions)
                or frozenset(snapshot.conclusion_evidence_ids) != declared_evidence
                or not _snapshot_evidence(snapshot) <= declared_evidence
                or any(not fact.evidence_ids for fact in snapshot.facts)
            ):
                raise GenerationConsistencyValidationError(
                    "CONSISTENCY_CURRENT_CANDIDATE_BINDING_MISMATCH"
                )

    @staticmethod
    def _validate_historical_snapshots(
        review: ConsistencyRiskReview,
        pack: EvidencePack,
    ) -> None:
        expected_by_source = {
            "session_earlier": frozenset(
                item.evidence_id
                for item in (*pack.supporting, *pack.contradicting)
                if item.channel == "client_history"
            ),
            "client_profile": frozenset(
                item.evidence_id
                for item in (*pack.supporting, *pack.contradicting)
                if item.channel == "profile"
            ),
        }
        for source, snapshots in (
            ("session_earlier", review.session_earlier_snapshots),
            ("client_profile", review.client_profile_snapshots),
        ):
            actual = frozenset(
                evidence_id
                for snapshot in snapshots
                for evidence_id in _snapshot_evidence(snapshot)
            )
            if (
                actual != expected_by_source[source]
                or any(
                    snapshot.source != source
                    or not snapshot.conclusion_evidence_ids
                    or not _snapshot_evidence(snapshot)
                    or any(not fact.evidence_ids for fact in snapshot.facts)
                    for snapshot in snapshots
                )
            ):
                raise GenerationConsistencyValidationError(
                    "CONSISTENCY_HISTORICAL_EVIDENCE_MISMATCH"
                )

    @classmethod
    def _validate_semantic_assessments(
        cls,
        review: ConsistencyRiskReview,
        replies: ReplyDraftSet,
        pack: EvidencePack,
        context: tuple[GenerationEvidenceContextItem, ...],
    ) -> None:
        """Validate closure and projection, not semantic entailment.

        ``assessed_value`` remains an independent critic judgment.  This layer
        proves that there is exactly one judgment for every compared axis, that
        current judgments cover the full client-visible candidate, and that
        historical/profile judgments quote exact frozen evidence bytes.
        """

        assessments = {
            item.assessment_key(): item for item in review.semantic_assessments
        }
        snapshots = {
            item.snapshot_key: item
            for item in (
                *review.current_candidate_snapshots,
                *review.session_earlier_snapshots,
                *review.client_profile_snapshots,
            )
        }
        expected_values: dict[tuple[str, str, str, str], str] = {}
        for snapshot in snapshots.values():
            if snapshot.source == "current_candidate":
                expected_values.update(
                    {
                        (snapshot.snapshot_key, "fact", item.fact_key, ""): item.state
                        for item in snapshot.facts
                    }
                )
                expected_values.update(
                    {
                        (
                            snapshot.snapshot_key,
                            "core_position",
                            item.position_key,
                            "",
                        ): item.stance
                        for item in snapshot.core_positions
                    }
                )
                expected_values.update(
                    {
                        (
                            snapshot.snapshot_key,
                            "action_direction",
                            item.action_key,
                            "",
                        ): item.disposition
                        for item in snapshot.action_directions
                    }
                )
                continue

            expected_values.update(
                {
                    (
                        snapshot.snapshot_key,
                        "fact",
                        item.fact_key,
                        evidence_id,
                    ): item.state
                    for item in snapshot.facts
                    for evidence_id in item.evidence_ids
                }
            )
            expected_values.update(
                {
                    (
                        snapshot.snapshot_key,
                        "core_position",
                        item.position_key,
                        evidence_id,
                    ): item.stance
                    for item in snapshot.core_positions
                    for evidence_id in snapshot.conclusion_evidence_ids
                }
            )
            expected_values.update(
                {
                    (
                        snapshot.snapshot_key,
                        "action_direction",
                        item.action_key,
                        evidence_id,
                    ): item.disposition
                    for item in snapshot.action_directions
                    for evidence_id in snapshot.conclusion_evidence_ids
                }
            )
            expected_values.update(
                {
                    (
                        snapshot.snapshot_key,
                        "conclusion",
                        "conclusion",
                        evidence_id,
                    ): "supports_conclusion"
                    for evidence_id in snapshot.conclusion_evidence_ids
                }
            )
        if set(assessments) != set(expected_values):
            raise GenerationConsistencyValidationError(
                "CONSISTENCY_SEMANTIC_ASSESSMENT_SET_MISMATCH"
            )
        if any(
            assessments[key].assessed_value != expected_value
            for key, expected_value in expected_values.items()
        ):
            raise GenerationConsistencyValidationError(
                "CONSISTENCY_SEMANTIC_VALUE_MISMATCH"
            )

        drafts = {item.candidate_id: item for item in replies.candidates}
        selected = {
            item.evidence_id: item for item in (*pack.supporting, *pack.contradicting)
        }
        bodies = {item.evidence_id: item.body for item in context}
        expected_channel = {
            "session_earlier": "client_history",
            "client_profile": "profile",
        }
        for assessment in assessments.values():
            snapshot = snapshots[assessment.snapshot_key]
            if snapshot.source == "current_candidate":
                draft = drafts[snapshot.snapshot_key]
                if (
                    assessment.evidence_id is not None
                    or assessment.text_start_char != 0
                    or assessment.text_end_char != len(draft.text)
                    or assessment.exact_excerpt != draft.text
                ):
                    raise GenerationConsistencyValidationError(
                        "CONSISTENCY_CURRENT_SEMANTIC_SOURCE_MISMATCH"
                    )
                continue

            evidence_id = assessment.evidence_id
            candidate = None if evidence_id is None else selected.get(evidence_id)
            body = None if evidence_id is None else bodies.get(evidence_id)
            if (
                evidence_id is None
                or candidate is None
                or body is None
                or evidence_id not in _snapshot_evidence(snapshot)
                or candidate.channel != expected_channel[snapshot.source]
                or assessment.text_end_char > len(body)
                or body[
                    assessment.text_start_char : assessment.text_end_char
                ]
                != assessment.exact_excerpt
            ):
                raise GenerationConsistencyValidationError(
                    "CONSISTENCY_HISTORICAL_SOURCE_MISMATCH"
                )

    @staticmethod
    def _project_finding(
        index: int,
        finding: ConsistencyFinding,
        snapshots: dict[str, ConsistencySnapshot],
    ) -> StageConsistencyFinding:
        category: Literal[
            "fact_conflict",
            "core_position_conflict",
            "action_direction_conflict",
            "cross_turn_change",
            "expression_difference",
            "risk_review",
        ]
        category_by_code: dict[
            str,
            Literal[
                "fact_conflict",
                "core_position_conflict",
                "action_direction_conflict",
                "cross_turn_change",
                "expression_difference",
                "risk_review",
            ],
        ] = {
            "candidate_fact_conflict": "fact_conflict",
            "candidate_core_position_conflict": "core_position_conflict",
            "candidate_action_conflict": "action_direction_conflict",
            "historical_fact_conflict": "cross_turn_change",
            "unexplained_conclusion_change": "cross_turn_change",
        }
        category = category_by_code[finding.code]
        evidence_ids = tuple(
            sorted(
                {
                    evidence_id
                    for key in finding.source_snapshot_keys
                    for evidence_id in _snapshot_evidence(snapshots[key])
                }
            )
        )
        severity: Literal["allowed", "warning", "blocking"] = (
            "allowed" if finding.severity == "info" else finding.severity
        )
        return StageConsistencyFinding(
            finding_id=f"consistency_{index}",
            category=category,
            severity=severity,
            affected_candidate_ids=finding.source_snapshot_keys,
            evidence_ids=evidence_ids,
            description=(
                f"{finding.code}: {finding.subject_key} differs across "
                f"{', '.join(finding.source_snapshot_keys)}."
            ),
            correction=finding.correction,
        )

    @staticmethod
    def _unresolved_reasons(
        decision: str,
    ) -> tuple[str, ...]:
        if decision == "pass":
            return ()
        if decision == "rewrite":
            return ("unresolved_conflict",)
        if decision == "needs_counselor_judgment":
            return ("needs_counselor_judgment", "unresolved_conflict")
        raise GenerationConsistencyValidationError


__all__ = [
    "GenerationConsistencyValidationError",
    "GenerationConsistencyValidator",
]
