"""Fail-closed validation for client-facing reply draft candidates."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import model_validator

from consultation_kb.generation.contracts import Conceptualization, ReplyDraftSet
from consultation_kb.generation.evidence_scope import bound_evidence_ids
from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.common import NonEmptyStr, ObjectId, SafePolicyKey, StrictModel
from consultation_kb.models.evidence import EvidencePack


BUILT_IN_REPLY_STRATEGIES = frozenset(
    {"gentle_empathy", "direct_clarification", "exploratory_guidance"}
)
_INTERNAL_JARGON = re.compile(
    r"(?:EvidencePack|evidence[_ -]?id|source[_ -]?grade|empirical[_ -]?support|"
    r"\bC1\b|\bC2\b|\bC3\b|内部风险|规则ID|系统告警)",
    re.IGNORECASE,
)
_CITATION_MARKER = re.compile(r"\[(?:\d{1,3}|[CTKL]\d|evidence[^\]]*)\]", re.IGNORECASE)

BoundaryPolicyCode = Literal[
    "automatic_diagnosis",
    "dangerous_advice",
    "victim_blaming",
    "guoxue_medicalization",
    "single_case_universalization",
    "client_agency_overridden",
]

_POLICY_PATTERNS: tuple[
    tuple[BoundaryPolicyCode, tuple[re.Pattern[str], ...], str], ...
] = (
    (
        "automatic_diagnosis",
        (
            re.compile(r"你(?:这就是|就是|患有|得了).{0,20}(?:抑郁症|焦虑症|人格障碍|精神障碍|心理疾病)"),
            re.compile(r"\byou\s+(?:definitely\s+)?have\s+.{0,20}(?:disorder|disease)\b", re.IGNORECASE),
        ),
        "Replace diagnosis with an observation, uncertainty, and a clarifying question.",
    ),
    (
        "dangerous_advice",
        (
            re.compile(r"(?:立即|马上)?停药"),
            re.compile(r"(?:不要|别)(?:报警|求助|就医)"),
            re.compile(r"(?:以暴制暴|跟踪对方|威胁对方)"),
            re.compile(r"\b(?:stop medication|do not seek help|retaliate violently)\b", re.IGNORECASE),
        ),
        "Remove dangerous instructions and preserve real-world support options.",
    ),
    (
        "victim_blaming",
        (
            re.compile(r"(?:都是|完全是)你的错"),
            re.compile(r"你(?:活该|自找的)"),
            re.compile(r"被(?:伤害|欺负|背叛).{0,12}是因为你"),
            re.compile(r"\byou (?:deserved|caused) (?:the abuse|being hurt)\b", re.IGNORECASE),
        ),
        "Remove blame and distinguish responsibility from the visitor's choices.",
    ),
    (
        "guoxue_medicalization",
        (
            re.compile(r"(?:易经|八字|风水|命理).{0,16}(?:治疗|治愈|替代就医).{0,10}(?:抑郁|焦虑|疾病|障碍)?"),
            re.compile(r"(?:抑郁|焦虑|疾病|障碍).{0,16}(?:用|靠)(?:易经|八字|风水|命理)(?:治疗|治愈)"),
        ),
        "Use traditional-cultural material as meaning-making, not medical treatment.",
    ),
    (
        "single_case_universalization",
        (
            re.compile(r"(?:这个|上个|某个)案例(?:已经)?证明.{0,20}(?:所有人|每个人|你一定)"),
            re.compile(r"别人这样(?:做)?成功.{0,12}(?:所以|说明)你一定"),
            re.compile(r"\bone case proves (?:everyone|you)\b", re.IGNORECASE),
        ),
        "Present a case only as a bounded analogy, never a universal rule.",
    ),
    (
        "client_agency_overridden",
        (
            re.compile(r"你必须立即"),
            re.compile(r"你只能(?:按|照|听)"),
            re.compile(r"照我说的做"),
            re.compile(r"\byou must immediately\b", re.IGNORECASE),
        ),
        "Offer choices and preserve the visitor's agency.",
    ),
)

_BREAKUP = re.compile(r"(?:立即|马上)?(?:分手|结束这段关系)|\bend (?:the )?relationship\b", re.IGNORECASE)
_NO_CHANGE = re.compile(r"关系无需改变|维持现状|不需要任何改变|\bstay as (?:it is|is)\b", re.IGNORECASE)


ReplyPolicyCode = Literal[
    "evidence_pack_hash_mismatch",
    "strategy_variation_missing",
    "current_fact_conflict",
    "current_fact_conceptualization_mismatch",
    "unknown_evidence",
    "candidate_evidence_closure",
    "unsupported_expression",
    "internal_jargon_or_citation",
    "candidate_semantic_conflict",
    "automatic_diagnosis",
    "dangerous_advice",
    "victim_blaming",
    "guoxue_medicalization",
    "single_case_universalization",
    "client_agency_overridden",
]


class ReplyPolicyFinding(StrictModel):
    code: ReplyPolicyCode
    severity: Literal["blocking"] = "blocking"
    candidate_id: SafePolicyKey | None
    claim_id: SafePolicyKey | None
    evidence_ids: tuple[ObjectId, ...]
    correction: NonEmptyStr


class ReplyValidationResult(StrictModel):
    accepted: bool
    findings: tuple[ReplyPolicyFinding, ...]

    @model_validator(mode="after")
    def _accepted_matches_findings(self) -> "ReplyValidationResult":
        if self.accepted == bool(self.findings):
            raise ValueError("accepted must be the inverse of blocking findings")
        return self


class ReplyPolicyError(RuntimeError):
    def __init__(self, result: ReplyValidationResult) -> None:
        self.result = result
        super().__init__("REPLY_POLICY_REJECTED")


class ReplyDraftValidator:
    """Check reply artifacts without regenerating or silently editing text."""

    def validate(
        self,
        artifact: ReplyDraftSet,
        evidence_pack: EvidencePack,
        conceptualization: Conceptualization,
    ) -> ReplyValidationResult:
        value = ReplyDraftSet.model_validate(artifact)
        pack = EvidencePack.model_validate(evidence_pack)
        concept = Conceptualization.model_validate(conceptualization)
        findings: list[ReplyPolicyFinding] = []
        available = bound_evidence_ids(pack)

        if value.evidence_pack_sha256 != canonical_sha256(
            pack.model_dump(mode="json")
        ):
            findings.append(
                ReplyPolicyFinding(
                    code="evidence_pack_hash_mismatch",
                    candidate_id=None,
                    claim_id=None,
                    evidence_ids=(),
                    correction="Bind reply drafts to the retrieved EvidencePack.",
                )
            )

        strategies = {candidate.strategy for candidate in value.candidates}
        if len(strategies) < 2:
            findings.append(
                ReplyPolicyFinding(
                    code="strategy_variation_missing",
                    candidate_id=None,
                    claim_id=None,
                    evidence_ids=(),
                    correction="Use at least two distinct reply strategies for the candidates.",
                )
            )

        fact_sets = {candidate.current_fact_ids for candidate in value.candidates}
        if len(fact_sets) != 1:
            findings.append(
                ReplyPolicyFinding(
                    code="current_fact_conflict",
                    candidate_id=None,
                    claim_id=None,
                    evidence_ids=(),
                    correction="All candidates must use the same current-fact snapshot.",
                )
            )

        expected_current_fact_ids = tuple(
            sorted(
                item.item_id
                for item in concept.items
                if item.cognitive_type
                in {"client_fact", "client_reported", "counselor_observation"}
            )
        )
        for candidate in value.candidates:
            if candidate.current_fact_ids != expected_current_fact_ids:
                findings.append(
                    ReplyPolicyFinding(
                        code="current_fact_conceptualization_mismatch",
                        candidate_id=candidate.candidate_id,
                        claim_id=None,
                        evidence_ids=(),
                        correction=(
                            "Use the exact canonical fact-like item identifiers from "
                            "the persisted conceptualization."
                        ),
                    )
                )

        breakup_candidates: list[str] = []
        no_change_candidates: list[str] = []
        for candidate in value.candidates:
            if _BREAKUP.search(candidate.text):
                breakup_candidates.append(candidate.candidate_id)
            if _NO_CHANGE.search(candidate.text):
                no_change_candidates.append(candidate.candidate_id)

            if _INTERNAL_JARGON.search(candidate.text) or _CITATION_MARKER.search(
                candidate.text
            ):
                findings.append(
                    ReplyPolicyFinding(
                        code="internal_jargon_or_citation",
                        candidate_id=candidate.candidate_id,
                        claim_id=None,
                        evidence_ids=candidate.evidence_ids,
                        correction="Keep client text natural and free of internal citations or labels.",
                    )
                )

            for code, patterns, correction in _POLICY_PATTERNS:
                if any(pattern.search(candidate.text) for pattern in patterns):
                    findings.append(
                        ReplyPolicyFinding(
                            code=code,
                            candidate_id=candidate.candidate_id,
                            claim_id=None,
                            evidence_ids=candidate.evidence_ids,
                            correction=correction,
                        )
                    )

            candidate_refs = set(candidate.evidence_ids)
            claim_refs = {
                evidence_id
                for claim in candidate.claims
                for evidence_id in claim.evidence_ids + claim.contradicting_evidence_ids
            }
            unknown = tuple(sorted((candidate_refs | claim_refs) - available))
            if unknown:
                findings.append(
                    ReplyPolicyFinding(
                        code="unknown_evidence",
                        candidate_id=candidate.candidate_id,
                        claim_id=None,
                        evidence_ids=unknown,
                        correction="Use only evidence identifiers from the bound EvidencePack.",
                    )
                )
            if not claim_refs <= candidate_refs:
                findings.append(
                    ReplyPolicyFinding(
                        code="candidate_evidence_closure",
                        candidate_id=candidate.candidate_id,
                        claim_id=None,
                        evidence_ids=tuple(sorted(claim_refs - candidate_refs)),
                        correction="Declare every claim evidence reference on its reply candidate.",
                    )
                )

            for claim in candidate.claims:
                if not claim.evidence_ids and claim.claim_type not in {
                    "open_question",
                    "uncertain_expression",
                }:
                    findings.append(
                        ReplyPolicyFinding(
                            code="unsupported_expression",
                            candidate_id=candidate.candidate_id,
                            claim_id=claim.claim_id,
                            evidence_ids=(),
                            correction="Make the expression an open question/uncertainty or add evidence.",
                        )
                    )

        if breakup_candidates and no_change_candidates:
            findings.append(
                ReplyPolicyFinding(
                    code="candidate_semantic_conflict",
                    candidate_id=None,
                    claim_id=None,
                    evidence_ids=(),
                    correction="Align the candidates' action direction before varying tone.",
                )
            )

        return ReplyValidationResult(accepted=not findings, findings=tuple(findings))

    def require_valid(
        self,
        artifact: ReplyDraftSet,
        evidence_pack: EvidencePack,
        conceptualization: Conceptualization,
    ) -> ReplyDraftSet:
        value = ReplyDraftSet.model_validate(artifact)
        result = self.validate(value, evidence_pack, conceptualization)
        if not result.accepted:
            raise ReplyPolicyError(result)
        return value


__all__ = [
    "BUILT_IN_REPLY_STRATEGIES",
    "ReplyDraftValidator",
    "ReplyPolicyCode",
    "ReplyPolicyError",
    "ReplyPolicyFinding",
    "ReplyValidationResult",
]
