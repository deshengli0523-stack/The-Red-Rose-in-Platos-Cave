"""Deterministic multi-candidate and cross-turn consistency review."""

from __future__ import annotations

from itertools import combinations
from typing import Literal

from consultation_kb.models.consistency import (
    ConclusionChangeRecord,
    ConsistencyFinding,
    ConsistencyReviewResult,
    ConsistencySnapshot,
)


def _by_key(values: tuple[object, ...], attribute: str) -> dict[str, object]:
    return {str(getattr(item, attribute)): item for item in values}


def _fact_conflicts(left: str, right: str) -> bool:
    if left == right or "uncertain" in {left, right}:
        return False
    return True


class ConsistencyReviewer:
    """Compare structured assertions; prose similarity is intentionally unused."""

    def review(
        self,
        *,
        current_candidates: tuple[ConsistencySnapshot, ...],
        session_earlier: tuple[ConsistencySnapshot, ...] = (),
        client_profiles: tuple[ConsistencySnapshot, ...] = (),
        conclusion_changes: tuple[ConclusionChangeRecord, ...] = (),
        retry_count: int = 0,
    ) -> ConsistencyReviewResult:
        if type(retry_count) is not int or not 0 <= retry_count <= 2:
            raise ValueError("retry_count must be between zero and two")
        current = tuple(
            ConsistencySnapshot.model_validate(item) for item in current_candidates
        )
        earlier = tuple(
            ConsistencySnapshot.model_validate(item) for item in session_earlier
        )
        profiles = tuple(
            ConsistencySnapshot.model_validate(item) for item in client_profiles
        )
        changes = tuple(
            ConclusionChangeRecord.model_validate(item) for item in conclusion_changes
        )
        if not current:
            raise ValueError("consistency review requires a current candidate")
        if any(item.source != "current_candidate" for item in current):
            raise ValueError("current candidates require current_candidate source")
        if any(item.source != "session_earlier" for item in earlier):
            raise ValueError("session history requires session_earlier source")
        if any(item.source != "client_profile" for item in profiles):
            raise ValueError("profile history requires client_profile source")
        if len({item.snapshot_key for item in current + earlier + profiles}) != len(
            current + earlier + profiles
        ):
            raise ValueError("consistency snapshot keys must be unique")
        changes_by_subject = {item.subject_key: item for item in changes}
        if len(changes_by_subject) != len(changes):
            raise ValueError("conclusion changes must have unique subject keys")

        findings: list[ConsistencyFinding] = []
        for left, right in combinations(current, 2):
            findings.extend(self._compare_current_pair(left, right))

        representative = current[0]
        historical_evidence = {
            evidence_id
            for snapshot in earlier + profiles
            for evidence_id in self._snapshot_evidence(snapshot)
        }
        for historical in earlier + profiles:
            findings.extend(
                self._compare_history(
                    representative,
                    historical,
                    changes_by_subject,
                    historical_evidence,
                )
            )

        blocking = any(item.severity == "blocking" for item in findings)
        decision: Literal["pass", "rewrite", "needs_counselor_judgment"]
        if not blocking:
            decision = "pass"
        elif retry_count < 2:
            decision = "rewrite"
        else:
            decision = "needs_counselor_judgment"
        return ConsistencyReviewResult(
            findings=tuple(findings),
            conclusion_changes=changes,
            decision=decision,
            retry_count=retry_count,
        )

    @staticmethod
    def _compare_current_pair(
        left: ConsistencySnapshot,
        right: ConsistencySnapshot,
    ) -> list[ConsistencyFinding]:
        findings: list[ConsistencyFinding] = []
        sources = tuple(sorted((left.snapshot_key, right.snapshot_key)))

        left_facts = _by_key(left.facts, "fact_key")
        right_facts = _by_key(right.facts, "fact_key")
        for key in sorted(set(left_facts) | set(right_facts)):
            if key not in left_facts or key not in right_facts:
                findings.append(
                    ConsistencyFinding(
                        code="candidate_fact_conflict",
                        severity="blocking",
                        subject_key=key,
                        source_snapshot_keys=sources,
                        correction="Use the same current fact set across candidates.",
                    )
                )
                continue
            left_fact = left_facts[key]
            right_fact = right_facts[key]
            if _fact_conflicts(
                str(getattr(left_fact, "state")), str(getattr(right_fact, "state"))
            ):
                findings.append(
                    ConsistencyFinding(
                        code="candidate_fact_conflict",
                        severity="blocking",
                        subject_key=key,
                        source_snapshot_keys=sources,
                        correction="Align the candidates to one current fact state.",
                    )
                )

        left_positions = _by_key(left.core_positions, "position_key")
        right_positions = _by_key(right.core_positions, "position_key")
        for key in sorted(set(left_positions) | set(right_positions)):
            if key not in left_positions or key not in right_positions:
                findings.append(
                    ConsistencyFinding(
                        code="candidate_core_position_conflict",
                        severity="blocking",
                        subject_key=key,
                        source_snapshot_keys=sources,
                        correction="Use the same core-position axes across candidates.",
                    )
                )
                continue
            stances = {
                str(getattr(left_positions[key], "stance")),
                str(getattr(right_positions[key], "stance")),
            }
            if stances == {"support", "oppose"}:
                findings.append(
                    ConsistencyFinding(
                        code="candidate_core_position_conflict",
                        severity="blocking",
                        subject_key=key,
                        source_snapshot_keys=sources,
                        correction="Keep the same core position across reply styles.",
                    )
                )

        left_actions = _by_key(left.action_directions, "action_key")
        right_actions = _by_key(right.action_directions, "action_key")
        for key in sorted(set(left_actions) | set(right_actions)):
            if key not in left_actions or key not in right_actions:
                findings.append(
                    ConsistencyFinding(
                        code="candidate_action_conflict",
                        severity="blocking",
                        subject_key=key,
                        source_snapshot_keys=sources,
                        correction="Use the same action axes across candidates.",
                    )
                )
                continue
            dispositions = {
                str(getattr(left_actions[key], "disposition")),
                str(getattr(right_actions[key], "disposition")),
            }
            if dispositions == {"pursue", "avoid"}:
                findings.append(
                    ConsistencyFinding(
                        code="candidate_action_conflict",
                        severity="blocking",
                        subject_key=key,
                        source_snapshot_keys=sources,
                        correction="Keep action directions compatible across reply styles.",
                    )
                )
        return findings

    @staticmethod
    def _compare_history(
        current: ConsistencySnapshot,
        historical: ConsistencySnapshot,
        changes: dict[str, ConclusionChangeRecord],
        historical_evidence: set[str],
    ) -> list[ConsistencyFinding]:
        findings: list[ConsistencyFinding] = []
        sources = tuple(sorted((current.snapshot_key, historical.snapshot_key)))
        current_evidence = set(current.conclusion_evidence_ids)
        previous_evidence = set(historical_evidence)
        current_evidence.update(
            evidence_id for fact in current.facts for evidence_id in fact.evidence_ids
        )

        current_facts = _by_key(current.facts, "fact_key")
        historical_facts = _by_key(historical.facts, "fact_key")
        for key in sorted(set(current_facts) & set(historical_facts)):
            current_state = str(getattr(current_facts[key], "state"))
            prior_state = str(getattr(historical_facts[key], "state"))
            if current_state != prior_state and "uncertain" not in {
                current_state,
                prior_state,
            } and not ConsistencyReviewer._valid_change_record(
                changes.get(key), current_evidence, previous_evidence
            ):
                findings.append(
                    ConsistencyFinding(
                        code="historical_fact_conflict",
                        severity="blocking",
                        subject_key=key,
                        source_snapshot_keys=sources,
                        correction="Explain the fact change and its advice/profile impact.",
                    )
                )

        current_positions = _by_key(current.core_positions, "position_key")
        historical_positions = _by_key(historical.core_positions, "position_key")
        for key in sorted(set(current_positions) | set(historical_positions)):
            if key not in current_positions or key not in historical_positions:
                if not ConsistencyReviewer._valid_change_record(
                    changes.get(key), current_evidence, previous_evidence
                ):
                    findings.append(
                        ConsistencyFinding(
                            code="unexplained_conclusion_change",
                            severity="blocking",
                            subject_key=key,
                            source_snapshot_keys=sources,
                            correction="Explain why a core position was added or removed.",
                        )
                    )
                continue
            current_stance = str(getattr(current_positions[key], "stance"))
            prior_stance = str(getattr(historical_positions[key], "stance"))
            if current_stance != prior_stance and "uncertain" not in {
                current_stance,
                prior_stance,
            } and not ConsistencyReviewer._valid_change_record(
                changes.get(key), current_evidence, previous_evidence
            ):
                findings.append(
                    ConsistencyFinding(
                        code="unexplained_conclusion_change",
                        severity="blocking",
                        subject_key=key,
                        source_snapshot_keys=sources,
                        correction="Record why new information changed the conclusion.",
                    )
                )

        current_actions = _by_key(current.action_directions, "action_key")
        historical_actions = _by_key(historical.action_directions, "action_key")
        for key in sorted(set(current_actions) | set(historical_actions)):
            if key not in current_actions or key not in historical_actions:
                if not ConsistencyReviewer._valid_change_record(
                    changes.get(key), current_evidence, previous_evidence
                ):
                    findings.append(
                        ConsistencyFinding(
                            code="unexplained_conclusion_change",
                            severity="blocking",
                            subject_key=key,
                            source_snapshot_keys=sources,
                            correction="Explain why an action direction was added or removed.",
                        )
                    )
                continue
            current_direction = str(getattr(current_actions[key], "disposition"))
            prior_direction = str(getattr(historical_actions[key], "disposition"))
            if current_direction != prior_direction and not ConsistencyReviewer._valid_change_record(
                changes.get(key), current_evidence, previous_evidence
            ):
                findings.append(
                    ConsistencyFinding(
                        code="unexplained_conclusion_change",
                        severity="blocking",
                        subject_key=key,
                        source_snapshot_keys=sources,
                        correction="Record why new information changed the action direction.",
                    )
                )
        return findings

    @staticmethod
    def _snapshot_evidence(snapshot: ConsistencySnapshot) -> set[str]:
        evidence = set(snapshot.conclusion_evidence_ids)
        evidence.update(
            evidence_id for fact in snapshot.facts for evidence_id in fact.evidence_ids
        )
        return evidence

    @staticmethod
    def _valid_change_record(
        record: ConclusionChangeRecord | None,
        current_evidence: set[str],
        previous_evidence: set[str],
    ) -> bool:
        if record is None:
            return False
        return bool(record.current_evidence_ids) and set(
            record.current_evidence_ids
        ) <= current_evidence and set(record.previous_evidence_ids) <= previous_evidence


__all__ = ["ConsistencyReviewer"]
