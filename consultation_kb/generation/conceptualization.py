"""Deterministic validation for case conceptualization artifacts."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import model_validator

from consultation_kb.generation.contracts import Conceptualization
from consultation_kb.generation.evidence_scope import bound_evidence_ids
from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.common import NonEmptyStr, ObjectId, SafePolicyKey, StrictModel
from consultation_kb.models.evidence import EvidencePack


_AUTOMATIC_DIAGNOSIS_PATTERNS = (
    re.compile(r"(?:我|系统)(?:可以)?(?:断定|诊断)(?:你|来访者)"),
    re.compile(r"你(?:就是|患有|得了).{0,24}(?:人格障碍|精神障碍|心理疾病|抑郁症|焦虑症)"),
    re.compile(
        r"\b(?:i|we|the system)\s+(?:diagnose|conclude)\s+you\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\byou\s+(?:definitely\s+)?(?:have|are)\s+(?:a\s+)?(?:mental\s+)?disorder\b",
        re.IGNORECASE,
    ),
)


class ConceptualizationFinding(StrictModel):
    code: Literal[
        "evidence_pack_hash_mismatch",
        "unknown_evidence",
        "automatic_diagnosis",
        "suggestion_support_missing",
    ]
    severity: Literal["blocking"] = "blocking"
    item_id: SafePolicyKey | None
    evidence_ids: tuple[ObjectId, ...]
    correction: NonEmptyStr


class ConceptualizationValidationResult(StrictModel):
    accepted: bool
    findings: tuple[ConceptualizationFinding, ...]

    @model_validator(mode="after")
    def _accepted_matches_findings(self) -> "ConceptualizationValidationResult":
        if self.accepted == bool(self.findings):
            raise ValueError("accepted must be the inverse of blocking findings")
        return self


class ConceptualizationPolicyError(RuntimeError):
    def __init__(self, result: ConceptualizationValidationResult) -> None:
        self.result = result
        super().__init__("CONCEPTUALIZATION_POLICY_REJECTED")


class ConceptualizationValidator:
    """Validate evidence closure and cognitive-label discipline.

    The validator does not generate or rewrite prose.  It only checks the
    structured artifact against the frozen EvidencePack and deterministic
    professional-boundary rules.
    """

    def validate(
        self,
        artifact: Conceptualization,
        evidence_pack: EvidencePack,
    ) -> ConceptualizationValidationResult:
        value = Conceptualization.model_validate(artifact)
        pack = EvidencePack.model_validate(evidence_pack)
        findings: list[ConceptualizationFinding] = []

        expected_hash = canonical_sha256(pack.model_dump(mode="json"))
        if value.evidence_pack_sha256 != expected_hash:
            findings.append(
                ConceptualizationFinding(
                    code="evidence_pack_hash_mismatch",
                    item_id=None,
                    evidence_ids=(),
                    correction="Bind the conceptualization to the retrieved EvidencePack.",
                )
            )

        available = bound_evidence_ids(pack)
        item_types = {item.item_id: item.cognitive_type for item in value.items}
        for item in value.items:
            referenced = set(item.supporting_evidence_ids) | set(
                item.contradicting_evidence_ids
            )
            unknown = tuple(sorted(referenced - available))
            if unknown:
                findings.append(
                    ConceptualizationFinding(
                        code="unknown_evidence",
                        item_id=item.item_id,
                        evidence_ids=unknown,
                        correction="Use only evidence identifiers from the bound EvidencePack.",
                    )
                )

            if item.cognitive_type in {
                "counselor_observation",
                "hypothesis",
                "suggestion",
            } and any(pattern.search(item.statement) for pattern in _AUTOMATIC_DIAGNOSIS_PATTERNS):
                findings.append(
                    ConceptualizationFinding(
                        code="automatic_diagnosis",
                        item_id=item.item_id,
                        evidence_ids=tuple(sorted(referenced)),
                        correction="Reframe the statement as an observation or testable hypothesis.",
                    )
                )

            supporting_item_ids = tuple(
                getattr(item, "supporting_item_ids", ())
            )
            if item.cognitive_type == "suggestion":
                valid_support_types = {
                    "client_fact",
                    "client_reported",
                    "counselor_observation",
                    "hypothesis",
                }
                if not supporting_item_ids or any(
                    item_types.get(item_id) not in valid_support_types
                    for item_id in supporting_item_ids
                ):
                    findings.append(
                        ConceptualizationFinding(
                            code="suggestion_support_missing",
                            item_id=item.item_id,
                            evidence_ids=tuple(sorted(referenced)),
                            correction="Link the suggestion to a fact, report, observation, or hypothesis item.",
                        )
                    )

        result = ConceptualizationValidationResult(
            accepted=not findings,
            findings=tuple(findings),
        )
        return result

    def require_valid(
        self,
        artifact: Conceptualization,
        evidence_pack: EvidencePack,
    ) -> Conceptualization:
        value = Conceptualization.model_validate(artifact)
        result = self.validate(value, evidence_pack)
        if not result.accepted:
            raise ConceptualizationPolicyError(result)
        return value


__all__ = [
    "ConceptualizationFinding",
    "ConceptualizationPolicyError",
    "ConceptualizationValidationResult",
    "ConceptualizationValidator",
]
