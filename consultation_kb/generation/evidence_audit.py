"""Structured evidence audit for analysis and reply claims."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from consultation_kb.generation.contracts import (
    AuditFinding,
    Conceptualization,
    ConceptualizationItem,
    EvidenceAudit,
    EvidenceSemanticAssessment,
    ReplyClaim,
    ReplyDraftSet,
)
from consultation_kb.generation.evidence_registry import (
    GenerationEvidenceBindingMismatch,
    GenerationEvidenceContextItem,
    validate_generation_evidence_context,
)
from consultation_kb.generation.evidence_scope import bound_evidence_ids
from consultation_kb.models.common import (
    NonEmptyStr,
    ObjectId,
    SafePolicyKey,
    StrictModel,
)
from consultation_kb.models.evidence import EvidencePack


def _unique_sorted(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must not contain duplicates")
    return tuple(sorted(values))


ClaimType = Literal[
    "fact",
    "hypothesis",
    "important_conclusion",
    "suggestion",
    "open_question",
    "uncertain_expression",
]


class AuditableClaim(StrictModel):
    """Minimal shared claim contract consumed by the deterministic auditor."""

    claim_id: SafePolicyKey
    claim_type: ClaimType
    statement: Annotated[NonEmptyStr, Field(max_length=4_000)]
    evidence_ids: Annotated[
        tuple[ObjectId, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    contradicting_evidence_ids: Annotated[
        tuple[ObjectId, ...], Field(json_schema_extra={"uniqueItems": True})
    ] = ()
    evidence_fidelity: Literal["faithful", "interpretation", "not_applicable"]

    @field_validator("evidence_ids", "contradicting_evidence_ids")
    @classmethod
    def _canonical_evidence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted(value, "claim evidence IDs")

    @model_validator(mode="after")
    def _evidence_shape(self) -> "AuditableClaim":
        if set(self.evidence_ids) & set(self.contradicting_evidence_ids):
            raise ValueError("claim support and contradiction must be disjoint")
        if self.claim_type in {"fact", "important_conclusion", "suggestion"} and not self.evidence_ids:
            raise ValueError("fact, conclusion, and suggestion claims require evidence")
        if self.claim_type == "hypothesis" and self.evidence_fidelity == "faithful":
            raise ValueError("a hypothesis cannot claim direct evidence fidelity")
        if self.claim_type in {"open_question", "uncertain_expression"} and self.evidence_fidelity != "not_applicable":
            raise ValueError("open or uncertain expressions cannot claim evidence fidelity")
        return self

    @classmethod
    def from_conceptualization_item(
        cls,
        item: ConceptualizationItem,
    ) -> "AuditableClaim":
        value = ConceptualizationItem.model_validate(item)
        if value.cognitive_type in {"client_fact", "client_reported"}:
            claim_type: ClaimType = "fact"
            fidelity: Literal["faithful", "interpretation", "not_applicable"] = (
                "faithful"
            )
        elif value.cognitive_type in {"counselor_observation", "hypothesis"}:
            claim_type = "hypothesis"
            fidelity = "interpretation"
        else:
            claim_type = "suggestion"
            fidelity = "interpretation"
        return cls(
            claim_id=value.item_id,
            claim_type=claim_type,
            statement=value.statement,
            evidence_ids=value.supporting_evidence_ids,
            contradicting_evidence_ids=value.contradicting_evidence_ids,
            evidence_fidelity=fidelity,
        )


AuditCode = Literal[
    "unknown_evidence",
    "stale_or_tombstoned_evidence",
    "important_claim_unsupported",
    "unfaithful_paraphrase",
    "semantic_support_insufficient",
    "semantic_evidence_unfaithful",
    "semantic_evidence_conflict",
    "counterevidence_omitted",
    "hypothesis_promoted_to_fact",
    "semantic_claim_type_mismatch",
]


class EvidenceAuditFinding(StrictModel):
    code: AuditCode
    claim_id: SafePolicyKey
    evidence_ids: Annotated[
        tuple[ObjectId, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    ref_fidelity: Literal["faithful", "unsupported", "misrepresented", "stale"]
    conflict_status: Literal["none", "covered", "omitted"]
    severity: Literal["info", "warning", "blocking"]
    correction: NonEmptyStr

    @field_validator("evidence_ids")
    @classmethod
    def _canonical_evidence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted(value, "audit evidence IDs")


class EvidenceAuditResult(StrictModel):
    findings: tuple[EvidenceAuditFinding, ...]
    decision: Literal[
        "pass", "retrieve_more", "rewrite", "needs_counselor_judgment"
    ]
    retry_count: Annotated[int, Field(strict=True, ge=0, le=2)]
    unresolved_reasons: Annotated[
        tuple[
            Literal[
                "insufficient_evidence",
                "unresolved_conflict",
                "needs_counselor_judgment",
            ],
            ...,
        ],
        Field(json_schema_extra={"uniqueItems": True}),
    ]

    @field_validator("unresolved_reasons")
    @classmethod
    def _canonical_reasons(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted(value, "unresolved reasons")

    @model_validator(mode="after")
    def _decision_shape(self) -> "EvidenceAuditResult":
        blocking = any(item.severity == "blocking" for item in self.findings)
        if not blocking and (self.decision != "pass" or self.unresolved_reasons):
            raise ValueError("non-blocking evidence audit must pass")
        if blocking and self.retry_count < 2 and self.decision not in {
            "retrieve_more",
            "rewrite",
        }:
            raise ValueError("retryable evidence failure requires retrieve or rewrite")
        if blocking and self.retry_count == 2:
            if self.decision != "needs_counselor_judgment" or (
                "needs_counselor_judgment" not in self.unresolved_reasons
            ):
                raise ValueError("exhausted evidence audit requires counselor judgment")
        return self


class EvidenceAuditor:
    """Audit structured references; never infer support from citation-looking text."""

    def audit(
        self,
        *,
        evidence_pack: EvidencePack,
        analysis_claims: tuple[AuditableClaim | ReplyClaim, ...],
        reply_claims: tuple[AuditableClaim | ReplyClaim, ...],
        assessments: tuple[EvidenceSemanticAssessment, ...],
        retry_count: int = 0,
        tombstoned_evidence_ids: tuple[ObjectId, ...] = (),
    ) -> EvidenceAuditResult:
        if type(retry_count) is not int or not 0 <= retry_count <= 2:
            raise ValueError("retry_count must be between zero and two")
        pack = EvidencePack.model_validate(evidence_pack)
        analysis = self._deduplicate_claims(analysis_claims, "analysis")
        replies = self._deduplicate_claims(reply_claims, "reply")
        tombstoned = set(
            _unique_sorted(tombstoned_evidence_ids, "tombstoned evidence IDs")
        )

        candidates = {
            item.evidence_id: item for item in pack.supporting + pack.contradicting
        }
        available = set(bound_evidence_ids(pack))
        analysis_by_id = {item.claim_id: item for item in analysis}
        assessment_by_pair = self._assessment_pairs(
            assessments,
            analysis_claims=analysis,
            reply_claims=replies,
        )

        findings: list[EvidenceAuditFinding] = []
        requires_retrieval = False
        has_conflict = False
        for claim_scope, claim in (
            *(("analysis", item) for item in analysis),
            *(("reply", item) for item in replies),
        ):
            referenced = set(claim.evidence_ids) | set(
                claim.contradicting_evidence_ids
            )
            assessed_types = {
                assessment_by_pair[
                    (claim_scope, claim.claim_id, evidence_id, role)
                ].assessed_claim_type
                for role, evidence_ids in (
                    ("support", claim.evidence_ids),
                    ("contradict", claim.contradicting_evidence_ids),
                )
                for evidence_id in evidence_ids
            }
            if referenced and assessed_types != {claim.claim_type}:
                has_conflict = True
                findings.append(
                    EvidenceAuditFinding(
                        code="semantic_claim_type_mismatch",
                        claim_id=claim.claim_id,
                        evidence_ids=tuple(sorted(referenced)),
                        ref_fidelity="misrepresented",
                        conflict_status="none",
                        severity="blocking",
                        correction=(
                            "Rewrite the declared claim type to match the independent "
                            "semantic classification before applying claim-type gates."
                        ),
                    )
                )
            unknown = tuple(sorted(referenced - available))
            if unknown:
                requires_retrieval = True
                findings.append(
                    EvidenceAuditFinding(
                        code="unknown_evidence",
                        claim_id=claim.claim_id,
                        evidence_ids=unknown,
                        ref_fidelity="unsupported",
                        conflict_status="none",
                        severity="blocking",
                        correction="Retrieve valid evidence and bind the claim to the new pack.",
                    )
                )

            stale = tuple(
                sorted(
                    evidence_id
                    for evidence_id in referenced & available
                    if evidence_id in tombstoned
                    or (
                        evidence_id in candidates
                        and candidates[evidence_id].freshness.status == "stale"
                    )
                )
            )
            if stale:
                requires_retrieval = True
                findings.append(
                    EvidenceAuditFinding(
                        code="stale_or_tombstoned_evidence",
                        claim_id=claim.claim_id,
                        evidence_ids=stale,
                        ref_fidelity="stale",
                        conflict_status="none",
                        severity="blocking",
                        correction="Retrieve a current non-tombstoned evidence revision.",
                    )
                )

            if claim.claim_type in {"fact", "important_conclusion", "suggestion"} and not claim.evidence_ids:
                requires_retrieval = True
                findings.append(
                    EvidenceAuditFinding(
                        code="important_claim_unsupported",
                        claim_id=claim.claim_id,
                        evidence_ids=(),
                        ref_fidelity="unsupported",
                        conflict_status="none",
                        severity="blocking",
                        correction="Add pack evidence or express the content as uncertainty/question.",
                    )
                )

            if claim.claim_type in {"fact", "important_conclusion"} and (
                claim.evidence_fidelity != "faithful"
            ):
                findings.append(
                    EvidenceAuditFinding(
                        code="unfaithful_paraphrase",
                        claim_id=claim.claim_id,
                        evidence_ids=claim.evidence_ids,
                        ref_fidelity="misrepresented",
                        conflict_status="none",
                        severity="blocking",
                        correction=(
                            "Rewrite as a faithful paraphrase and retain exact semantic "
                            "assessments, or mark the proposition as a hypothesis."
                        ),
                    )
                )

            support_statuses = {
                evidence_id: assessment_by_pair[
                    (claim_scope, claim.claim_id, evidence_id, "support")
                ].semantic_status
                for evidence_id in claim.evidence_ids
            }
            contradiction_statuses = {
                evidence_id: assessment_by_pair[
                    (claim_scope, claim.claim_id, evidence_id, "contradict")
                ].semantic_status
                for evidence_id in claim.contradicting_evidence_ids
            }
            semantically_conflicting = tuple(
                sorted(
                    evidence_id
                    for evidence_id, status in support_statuses.items()
                    if status == "contradicts"
                )
            )
            if semantically_conflicting:
                has_conflict = True
                findings.append(
                    EvidenceAuditFinding(
                        code="semantic_evidence_conflict",
                        claim_id=claim.claim_id,
                        evidence_ids=semantically_conflicting,
                        ref_fidelity="misrepresented",
                        conflict_status="covered",
                        severity="blocking",
                        correction=(
                            "Do not present evidence that contradicts the claim as support; "
                            "preserve the conflict explicitly."
                        ),
                    )
                )

            insufficient = tuple(
                sorted(
                    evidence_id
                    for evidence_id, status in support_statuses.items()
                    if status == "ambiguous" and claim.claim_type != "hypothesis"
                )
            )
            insufficient += tuple(
                sorted(
                    evidence_id
                    for evidence_id, status in contradiction_statuses.items()
                    if status == "ambiguous"
                )
            )
            insufficient = tuple(sorted(set(insufficient)))
            if insufficient:
                requires_retrieval = True
                findings.append(
                    EvidenceAuditFinding(
                        code="semantic_support_insufficient",
                        claim_id=claim.claim_id,
                        evidence_ids=insufficient,
                        ref_fidelity="unsupported",
                        conflict_status="none",
                        severity="blocking",
                        correction=(
                            "Retrieve a source excerpt that bears on the claim or remove the "
                            "unsupported evidence reference."
                        ),
                    )
                )

            irrelevant = tuple(
                sorted(
                    evidence_id
                    for evidence_id, status in {
                        **support_statuses,
                        **contradiction_statuses,
                    }.items()
                    if status == "irrelevant"
                )
            )
            if irrelevant:
                findings.append(
                    EvidenceAuditFinding(
                        code="semantic_evidence_unfaithful",
                        claim_id=claim.claim_id,
                        evidence_ids=irrelevant,
                        ref_fidelity="misrepresented",
                        conflict_status="none",
                        severity="blocking",
                        correction=(
                            "Remove the irrelevant evidence reference or replace it with an "
                            "excerpt that bears on the claim."
                        ),
                    )
                )

            role_mismatch = tuple(
                sorted(
                    evidence_id
                    for evidence_id, status in contradiction_statuses.items()
                    if status == "supports"
                )
            )
            if role_mismatch:
                findings.append(
                    EvidenceAuditFinding(
                        code="semantic_evidence_unfaithful",
                        claim_id=claim.claim_id,
                        evidence_ids=role_mismatch,
                        ref_fidelity="misrepresented",
                        conflict_status="none",
                        severity="blocking",
                        correction=(
                            "Do not label evidence that supports the claim as contradicting "
                            "evidence."
                        ),
                    )
                )

            relevant_counterevidence: set[str] = set()
            support_ids = set(claim.evidence_ids) & available
            for evidence_id in support_ids & set(candidates):
                relevant_counterevidence.update(
                    target
                    for target in candidates[evidence_id].contradicts_evidence_ids
                    if target in available
                )
            relevant_counterevidence.update(
                candidate.evidence_id
                for candidate in pack.contradicting
                if set(candidate.contradicts_evidence_ids) & support_ids
            )
            omitted = tuple(
                sorted(relevant_counterevidence - set(claim.contradicting_evidence_ids))
            )
            if omitted:
                has_conflict = True
                findings.append(
                    EvidenceAuditFinding(
                        code="counterevidence_omitted",
                        claim_id=claim.claim_id,
                        evidence_ids=omitted,
                        ref_fidelity="faithful",
                        conflict_status="omitted",
                        severity="blocking",
                        correction="Associate the relevant counterevidence and preserve the conflict.",
                    )
                )

            prior = analysis_by_id.get(claim.claim_id)
            if (
                claim in replies
                and prior is not None
                and prior.claim_type == "hypothesis"
                and claim.claim_type == "fact"
            ):
                findings.append(
                    EvidenceAuditFinding(
                        code="hypothesis_promoted_to_fact",
                        claim_id=claim.claim_id,
                        evidence_ids=claim.evidence_ids,
                        ref_fidelity="misrepresented",
                        conflict_status="none",
                        severity="blocking",
                        correction="Keep the proposition explicitly hypothetical until clarified.",
                    )
                )

        blocking = any(item.severity == "blocking" for item in findings)
        if not blocking:
            decision: Literal[
                "pass", "retrieve_more", "rewrite", "needs_counselor_judgment"
            ] = "pass"
            unresolved: tuple[
                Literal[
                    "insufficient_evidence",
                    "unresolved_conflict",
                    "needs_counselor_judgment",
                ],
                ...,
            ] = ()
        elif retry_count == 2:
            decision = "needs_counselor_judgment"
            reasons: set[
                Literal[
                    "insufficient_evidence",
                    "unresolved_conflict",
                    "needs_counselor_judgment",
                ]
            ] = {"needs_counselor_judgment"}
            if requires_retrieval:
                reasons.add("insufficient_evidence")
            if has_conflict:
                reasons.add("unresolved_conflict")
            unresolved = tuple(sorted(reasons))
        else:
            decision = "retrieve_more" if requires_retrieval else "rewrite"
            reason_values: list[
                Literal["insufficient_evidence", "unresolved_conflict"]
            ] = []
            if requires_retrieval:
                reason_values.append("insufficient_evidence")
            if has_conflict:
                reason_values.append("unresolved_conflict")
            unresolved = tuple(sorted(reason_values))

        return EvidenceAuditResult(
            findings=tuple(findings),
            decision=decision,
            retry_count=retry_count,
            unresolved_reasons=unresolved,
        )

    def audit_artifacts(
        self,
        *,
        evidence_pack: EvidencePack,
        conceptualization: Conceptualization,
        reply_drafts: ReplyDraftSet,
        assessments: tuple[EvidenceSemanticAssessment, ...],
        retry_count: int = 0,
        tombstoned_evidence_ids: tuple[ObjectId, ...] = (),
    ) -> EvidenceAuditResult:
        """Adapt the frozen P6 stage contracts without inspecting prose markers."""

        analysis = Conceptualization.model_validate(conceptualization)
        replies = ReplyDraftSet.model_validate(reply_drafts)
        return self.audit(
            evidence_pack=evidence_pack,
            analysis_claims=tuple(
                AuditableClaim.from_conceptualization_item(item)
                for item in analysis.items
            ),
            reply_claims=tuple(
                claim for candidate in replies.candidates for claim in candidate.claims
            ),
            assessments=assessments,
            retry_count=retry_count,
            tombstoned_evidence_ids=tombstoned_evidence_ids,
        )

    def require_valid_artifact(
        self,
        submitted: EvidenceAudit,
        *,
        evidence_pack: EvidencePack,
        conceptualization: Conceptualization,
        reply_drafts: ReplyDraftSet,
        evidence_context: tuple[GenerationEvidenceContextItem, ...],
        tombstoned_evidence_ids: tuple[ObjectId, ...] = (),
    ) -> None:
        """Reject model-authored audit fields that differ from recomputation.

        ``rationale_summary`` remains model-authored explanatory text.  Every
        decision-bearing field is projected from the deterministic auditor.
        """

        exact = EvidenceAudit.model_validate(submitted, strict=True)
        self.require_exact_source_spans(
            evidence_pack=evidence_pack,
            evidence_context=evidence_context,
            assessments=exact.assessments,
        )
        result = self.audit_artifacts(
            evidence_pack=evidence_pack,
            conceptualization=conceptualization,
            reply_drafts=reply_drafts,
            assessments=exact.assessments,
            retry_count=exact.retry_count,
            tombstoned_evidence_ids=tombstoned_evidence_ids,
        )
        findings = tuple(self._contract_finding(item) for item in result.findings)
        if (
            exact.findings != findings
            or exact.decision != result.decision
            or exact.retry_count != result.retry_count
            or exact.unresolved_reasons != result.unresolved_reasons
        ):
            raise ValueError("EVIDENCE_AUDIT_RECOMPUTATION_MISMATCH")

    @staticmethod
    def require_exact_source_spans(
        *,
        evidence_pack: EvidencePack,
        evidence_context: tuple[GenerationEvidenceContextItem, ...],
        assessments: tuple[EvidenceSemanticAssessment, ...],
    ) -> None:
        """Close every model-selected Unicode span against frozen source bodies."""

        try:
            context = validate_generation_evidence_context(
                evidence_pack,
                evidence_context,
            )
        except GenerationEvidenceBindingMismatch:
            raise ValueError("EVIDENCE_ASSESSMENT_SOURCE_MISMATCH") from None
        bodies = {item.evidence_id: item.body for item in context}
        for assessment in assessments:
            body = bodies.get(assessment.evidence_id)
            if body is None or assessment.text_end_char > len(body):
                raise ValueError("EVIDENCE_ASSESSMENT_SOURCE_MISMATCH")
            exact = body[
                assessment.text_start_char : assessment.text_end_char
            ]
            if exact != assessment.exact_excerpt:
                raise ValueError("EVIDENCE_ASSESSMENT_SOURCE_MISMATCH")

    @staticmethod
    def _contract_finding(finding: EvidenceAuditFinding) -> AuditFinding:
        fidelity: Literal[
            "faithful", "unsupported", "misrepresented", "stale", "conflicted"
        ] = (
            "conflicted"
            if finding.conflict_status != "none"
            else finding.ref_fidelity
        )
        return AuditFinding(
            claim_id=finding.claim_id,
            evidence_ids=finding.evidence_ids,
            fidelity=fidelity,
            severity=finding.severity,
            correction=finding.correction,
        )

    @staticmethod
    def _deduplicate_claims(
        claims: tuple[AuditableClaim | ReplyClaim, ...],
        label: str,
    ) -> tuple[AuditableClaim, ...]:
        by_id: dict[str, AuditableClaim] = {}
        for raw in claims:
            claim = (
                AuditableClaim.model_validate(raw)
                if isinstance(raw, AuditableClaim)
                else AuditableClaim.model_validate(
                    raw.model_dump(
                        include={
                            "claim_id",
                            "claim_type",
                            "statement",
                            "evidence_ids",
                            "contradicting_evidence_ids",
                            "evidence_fidelity",
                        }
                    )
                )
            )
            existing = by_id.get(claim.claim_id)
            if existing is not None and existing != claim:
                raise ValueError(f"{label} claim ID copies must be identical")
            by_id[claim.claim_id] = claim
        return tuple(by_id[key] for key in sorted(by_id))

    @staticmethod
    def _assessment_pairs(
        assessments: tuple[EvidenceSemanticAssessment, ...],
        *,
        analysis_claims: tuple[AuditableClaim, ...],
        reply_claims: tuple[AuditableClaim, ...],
    ) -> dict[tuple[str, str, str, str], EvidenceSemanticAssessment]:
        if type(assessments) is not tuple:
            raise ValueError("EVIDENCE_ASSESSMENT_PAIR_MISMATCH")
        try:
            exact = tuple(
                EvidenceSemanticAssessment.model_validate(item, strict=True)
                for item in assessments
            )
        except (TypeError, ValueError):
            raise ValueError("EVIDENCE_ASSESSMENT_PAIR_MISMATCH") from None
        actual_keys = tuple(item.pair_key() for item in exact)
        if actual_keys != tuple(sorted(set(actual_keys))):
            raise ValueError("EVIDENCE_ASSESSMENT_PAIR_MISMATCH")

        expected: set[tuple[str, str, str, str]] = set()
        for scope, claims in (
            ("analysis", analysis_claims),
            ("reply", reply_claims),
        ):
            for claim in claims:
                expected.update(
                    (scope, claim.claim_id, evidence_id, "support")
                    for evidence_id in claim.evidence_ids
                )
                expected.update(
                    (scope, claim.claim_id, evidence_id, "contradict")
                    for evidence_id in claim.contradicting_evidence_ids
                )
        if set(actual_keys) != expected:
            raise ValueError("EVIDENCE_ASSESSMENT_PAIR_MISMATCH")
        return dict(zip(actual_keys, exact, strict=True))


__all__ = [
    "AuditCode",
    "AuditableClaim",
    "ClaimType",
    "EvidenceAuditFinding",
    "EvidenceAuditResult",
    "EvidenceAuditor",
]
