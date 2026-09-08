"""Strict, auditable contracts for the seven-stage generation pipeline.

The models intentionally capture conclusions, evidence bindings, uncertainty,
limits, and edit decisions.  They do not expose a place for free-form hidden
reasoning, scratchpads, or chain-of-thought.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Annotated, Any, Final, Literal, Mapping, TypeAlias

from pydantic import (
    Discriminator,
    Field,
    Tag,
    TypeAdapter,
    field_validator,
    model_validator,
)

from consultation_kb.models.common import (
    NonEmptyStr,
    NonNegativeInt,
    ObjectId,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
    VersionRef,
)
from consultation_kb.models.evidence import (
    EmpiricalSupport,
    EvidenceChannel,
    SourceGrade,
)
from consultation_kb.models.generation import GenerationStageEnvelope
from consultation_kb.models.consistency import (
    ConclusionChangeRecord,
    ConsistencySnapshot,
)
from consultation_kb.models.risk import InternalRiskObservation
from consultation_kb.knowledge._canonical import text_sha256


RationaleSummary: TypeAlias = Annotated[NonEmptyStr, Field(max_length=800)]
BoundedText: TypeAlias = Annotated[NonEmptyStr, Field(max_length=4_000)]
EvidenceIds: TypeAlias = Annotated[
    tuple[ObjectId, ...], Field(json_schema_extra={"uniqueItems": True})
]
PolicyKeys: TypeAlias = Annotated[
    tuple[SafePolicyKey, ...], Field(json_schema_extra={"uniqueItems": True})
]
NonEmptyPolicyKeys: TypeAlias = Annotated[
    tuple[SafePolicyKey, ...],
    Field(min_length=1, json_schema_extra={"uniqueItems": True}),
]
RequiredEvidenceType: TypeAlias = Literal[
    "temporal_graph_edge",
    "theory_applicability",
    "theory_boundary",
    "case_provenance",
    "contradicting_evidence",
    "risk_context",
]
RequiredEvidenceTypes: TypeAlias = Annotated[
    tuple[RequiredEvidenceType, ...],
    Field(json_schema_extra={"uniqueItems": True}),
]
GenerationDecision: TypeAlias = Literal[
    "pass", "retrieve_more", "rewrite", "needs_counselor_judgment"
]


def _unique_sorted(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")
    return tuple(sorted(values))


class RouteOmission(StrictModel):
    route: EvidenceChannel
    reason: Annotated[NonEmptyStr, Field(max_length=300)]


class QueryGuardrails(StrictModel):
    current_client_snapshot_validation: Literal[True] = True
    provenance_source_client_filter: Literal[True] = True
    tombstone_version_check: Literal[True] = True


SubqueryCategory: TypeAlias = Literal[
    "current_client_facts",
    "emotion_needs_relationship",
    "historical_change",
    "theory_method_boundary",
    "case_analogy",
    "counterevidence_conflict",
    "internal_risk",
]
SubqueryScope: TypeAlias = Literal[
    "client_private", "global_knowledge", "both", "internal_only"
]


class Subquery(StrictModel):
    subquery_id: SafePolicyKey
    category: SubqueryCategory
    question: Annotated[NonEmptyStr, Field(max_length=1_000)]
    routes: Annotated[
        tuple[EvidenceChannel, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    required_evidence_types: RequiredEvidenceTypes
    scope: SubqueryScope
    conflicts_target: PolicyKeys = ()

    @field_validator("routes", "required_evidence_types", "conflicts_target")
    @classmethod
    def _canonical_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted(value, "subquery values")

    @model_validator(mode="after")
    def _scope_closure(self) -> "Subquery":
        private = {"profile", "client_history"}
        global_routes = {"wiki", "lexical", "vector", "global_graph", "case"}
        routes = set(self.routes)
        if self.scope == "client_private" and routes - private:
            raise ValueError("client-private subquery cannot use global routes")
        if self.scope == "global_knowledge" and routes & private:
            raise ValueError("global subquery cannot use private routes")
        if self.scope == "internal_only" and routes:
            raise ValueError("internal-only subquery cannot retrieve content")
        if self.scope == "both" and not (routes & private and routes & global_routes):
            raise ValueError("both-scope subquery requires private and global routes")
        return self


class QueryPlan(StrictModel):
    envelope: GenerationStageEnvelope
    intent: Literal[
        "simple_empathic_clarification",
        "fact_change",
        "theory_guidance",
        "case_comparison",
        "mixed",
    ]
    client_snapshot_ref: VersionRef
    global_runtime_epoch: NonNegativeInt
    client_runtime_epoch: NonNegativeInt
    tombstone_epoch: NonNegativeInt
    authorization_epoch: NonNegativeInt
    guardrails: QueryGuardrails
    subqueries: Annotated[tuple[Subquery, ...], Field(min_length=1)]
    route_omissions: tuple[RouteOmission, ...]
    rationale_summary: RationaleSummary

    @model_validator(mode="after")
    def _query_plan_shape(self) -> "QueryPlan":
        if self.envelope.stage != "query_plan":
            raise ValueError("query plan envelope stage mismatch")
        identifiers = [item.subquery_id for item in self.subqueries]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("subquery identifiers must be unique")
        omissions = [item.route for item in self.route_omissions]
        if len(omissions) != len(set(omissions)):
            raise ValueError("route omissions must be unique")
        return self


CognitiveType: TypeAlias = Literal[
    "client_fact",
    "client_reported",
    "counselor_observation",
    "hypothesis",
    "suggestion",
]


class ConceptualizationItem(StrictModel):
    item_id: SafePolicyKey
    cognitive_type: CognitiveType
    statement: BoundedText
    supporting_evidence_ids: EvidenceIds = ()
    contradicting_evidence_ids: EvidenceIds = ()
    supporting_item_ids: PolicyKeys = ()
    uncertainty: Literal["low", "medium", "high"]
    clarification_question: BoundedText | None = None

    @field_validator(
        "supporting_evidence_ids", "contradicting_evidence_ids", "supporting_item_ids"
    )
    @classmethod
    def _canonical_evidence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted(value, "evidence identifiers")

    @model_validator(mode="after")
    def _hypothesis_shape(self) -> "ConceptualizationItem":
        if set(self.supporting_evidence_ids) & set(self.contradicting_evidence_ids):
            raise ValueError("supporting and contradicting evidence must be disjoint")
        if self.cognitive_type == "hypothesis" and (
            not self.supporting_evidence_ids or self.clarification_question is None
        ):
            raise ValueError("hypothesis requires support and a clarification question")
        if self.cognitive_type in {"client_fact", "client_reported", "counselor_observation"}:
            if not self.supporting_evidence_ids:
                raise ValueError("fact-like item requires supporting evidence")
        if self.cognitive_type == "suggestion" and not self.supporting_item_ids:
            raise ValueError("suggestion requires supporting fact or hypothesis items")
        if self.cognitive_type != "suggestion" and self.supporting_item_ids:
            raise ValueError("only suggestions may bind supporting conceptualization items")
        return self


class Conceptualization(StrictModel):
    envelope: GenerationStageEnvelope
    evidence_pack_sha256: Sha256Hex
    items: Annotated[tuple[ConceptualizationItem, ...], Field(min_length=1)]
    key_emotions: tuple[BoundedText, ...]
    key_needs: tuple[BoundedText, ...]
    alternative_explanations: tuple[BoundedText, ...]
    limitations: tuple[BoundedText, ...]
    rationale_summary: RationaleSummary

    @model_validator(mode="after")
    def _shape(self) -> "Conceptualization":
        if self.envelope.stage != "conceptualization":
            raise ValueError("conceptualization envelope stage mismatch")
        identifiers = [item.item_id for item in self.items]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("conceptualization item IDs must be unique")
        by_id = {item.item_id: item for item in self.items}
        for item in self.items:
            if not set(item.supporting_item_ids) <= set(by_id):
                raise ValueError("suggestion support items must resolve in conceptualization")
            if any(
                by_id[item_id].cognitive_type == "suggestion"
                for item_id in item.supporting_item_ids
            ):
                raise ValueError("suggestions must be supported by facts or hypotheses")
        return self


class TheorySelection(StrictModel):
    theory_ref: VersionRef
    role: Literal["primary_framework", "supporting", "alternative"]
    source_grade: SourceGrade
    empirical_support: EmpiricalSupport
    applicability: Literal[
        "applicable", "not_applicable", "insufficient_context", "unavailable"
    ]
    boundaries: tuple[BoundedText, ...]
    evidence_ids: EvidenceIds

    @field_validator("evidence_ids")
    @classmethod
    def _canonical_evidence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted(value, "theory evidence identifiers")


class TheoryComparison(StrictModel):
    envelope: GenerationStageEnvelope
    evidence_pack_sha256: Sha256Hex
    primary_framework: TheorySelection | None
    comparisons: tuple[TheorySelection, ...]
    conflicts: tuple[BoundedText, ...]
    clarification_questions: tuple[BoundedText, ...]
    rationale_summary: RationaleSummary

    @model_validator(mode="after")
    def _shape(self) -> "TheoryComparison":
        if self.envelope.stage != "theory_comparison":
            raise ValueError("theory comparison envelope stage mismatch")
        if self.primary_framework is not None and (
            self.primary_framework.role != "primary_framework"
            or self.primary_framework.applicability != "applicable"
        ):
            raise ValueError("primary framework must be applicable and have primary role")
        if any(item.role == "primary_framework" for item in self.comparisons):
            raise ValueError("comparisons cannot contain another primary framework")
        return self


ReplyStrategy: TypeAlias = Literal[
    "gentle_empathy", "direct_clarification", "exploratory_guidance", "custom"
]

SAFE_EVIDENCE_FREE_REPLY_TEMPLATES: Final[
    Mapping[SafePolicyKey, tuple[Literal["open_question", "uncertain_expression"], str]]
] = MappingProxyType(
    {
        "clarify_first_detail": ("open_question", "你现在最想先澄清哪一个细节？"),
        "clarify_first_need": ("open_question", "你现在最希望先被理解的是什么？"),
        "clarify_first_change": ("open_question", "你最想先核对哪一个变化？"),
        "clarify_first_timeline": ("open_question", "你想先从哪个时间点说起？"),
        "clarify_first_choice": ("open_question", "你想先比较哪两个选择？"),
        "clarify_observation": ("open_question", "你当时直接注意到了什么？"),
        "clarify_detail_en": (
            "open_question",
            "What detail would you like to clarify first?",
        ),
        "which_question_before_deciding": (
            "open_question",
            "Which one question must be answered before you decide?",
        ),
        "clarify_timeline_en": (
            "open_question",
            "Which point in the timeline would you like to clarify first?",
        ),
        "insufficient_for_conclusion": (
            "uncertain_expression",
            "目前的信息还不足以得出这个结论。",
        ),
        "multiple_explanations_remain": (
            "uncertain_expression",
            "这仍有多种可能，暂时不能确定。",
        ),
        "insufficient_for_conclusion_en": (
            "uncertain_expression",
            "The current information is not enough to support that conclusion.",
        ),
        "multiple_explanations_remain_en": (
            "uncertain_expression",
            "Several explanations remain possible, so this is still uncertain.",
        ),
    }
)


class ReplyClaim(StrictModel):
    claim_id: SafePolicyKey
    claim_type: Literal[
        "fact",
        "hypothesis",
        "important_conclusion",
        "suggestion",
        "open_question",
        "uncertain_expression",
    ]
    statement: BoundedText
    evidence_ids: EvidenceIds
    contradicting_evidence_ids: EvidenceIds = ()
    evidence_fidelity: Literal["faithful", "interpretation", "not_applicable"]
    text_start_char: NonNegativeInt
    text_end_char: Annotated[int, Field(strict=True, gt=0)]
    text_sha256: Sha256Hex
    safe_template_id: SafePolicyKey | None = None

    @field_validator("evidence_ids", "contradicting_evidence_ids")
    @classmethod
    def _canonical_evidence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted(value, "reply claim evidence identifiers")

    @model_validator(mode="after")
    def _evidence_shape(self) -> "ReplyClaim":
        if set(self.evidence_ids) & set(self.contradicting_evidence_ids):
            raise ValueError("claim support and contradiction must be disjoint")
        if self.claim_type in {"fact", "important_conclusion", "suggestion"} and not self.evidence_ids:
            raise ValueError("fact, conclusion, and suggestion claims require evidence")
        if self.claim_type == "hypothesis" and self.evidence_fidelity == "faithful":
            raise ValueError("a hypothesis cannot claim direct evidence fidelity")
        if self.claim_type in {"open_question", "uncertain_expression"}:
            if self.evidence_fidelity != "not_applicable":
                raise ValueError("open or uncertain expression has no evidence fidelity claim")
            if self.evidence_ids or self.contradicting_evidence_ids:
                raise ValueError("safe evidence-free expression cannot declare evidence")
            expected = (
                None
                if self.safe_template_id is None
                else SAFE_EVIDENCE_FREE_REPLY_TEMPLATES.get(self.safe_template_id)
            )
            if expected != (self.claim_type, self.statement):
                raise ValueError(
                    "evidence-free expression must use an exact approved safe template"
                )
        elif self.safe_template_id is not None:
            raise ValueError("only evidence-free expressions may use a safe template")
        return self


class ReplyDraft(StrictModel):
    candidate_id: SafePolicyKey
    strategy: ReplyStrategy
    text: BoundedText
    core_positions: NonEmptyPolicyKeys
    current_fact_ids: Annotated[
        tuple[NonEmptyStr, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    action_directions: NonEmptyPolicyKeys
    evidence_ids: EvidenceIds
    claims: Annotated[tuple[ReplyClaim, ...], Field(min_length=1)]

    @field_validator(
        "core_positions", "current_fact_ids", "action_directions", "evidence_ids"
    )
    @classmethod
    def _canonical_identifiers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted(value, "reply identifiers")

    @model_validator(mode="after")
    def _claim_span_closure(self) -> "ReplyDraft":
        """Require claims to partition the exact client-visible reply body.

        Character offsets use Python/Unicode code-point indexes and ``text_end_char``
        is exclusive.  No client-visible character may sit outside an auditable
        claim, and the claim statement is the exact covered substring rather than
        a loosely related summary.
        """

        claim_ids = tuple(claim.claim_id for claim in self.claims)
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("reply claim identifiers must be unique per candidate")

        ordered = tuple(
            sorted(
                self.claims,
                key=lambda claim: (
                    claim.text_start_char,
                    claim.text_end_char,
                    claim.claim_id,
                ),
            )
        )
        if self.claims != ordered:
            raise ValueError("reply claims must use canonical text-span order")

        cursor = 0
        for claim in ordered:
            if claim.text_start_char != cursor:
                raise ValueError(
                    "reply claim spans must cover the exact client text without gaps or overlaps"
                )
            if claim.text_end_char > len(self.text):
                raise ValueError("reply claim span exceeds the client text boundary")
            exact_text = self.text[claim.text_start_char : claim.text_end_char]
            if claim.statement != exact_text:
                raise ValueError("reply claim statement must equal its exact client-text span")
            if claim.text_sha256 != text_sha256(exact_text):
                raise ValueError("reply claim text hash does not match its exact client-text span")
            cursor = claim.text_end_char
        if cursor != len(self.text):
            raise ValueError(
                "reply claim spans must cover the exact client text without gaps or overlaps"
            )
        return self


class ReplyDraftSet(StrictModel):
    envelope: GenerationStageEnvelope
    evidence_pack_sha256: Sha256Hex
    candidates: Annotated[tuple[ReplyDraft, ...], Field(min_length=2, max_length=4)]
    shared_core_positions: NonEmptyPolicyKeys
    shared_action_directions: NonEmptyPolicyKeys
    rationale_summary: RationaleSummary

    @model_validator(mode="after")
    def _shape(self) -> "ReplyDraftSet":
        if self.envelope.stage != "reply_drafts":
            raise ValueError("reply draft envelope stage mismatch")
        identifiers = [candidate.candidate_id for candidate in self.candidates]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("reply candidate identifiers must be unique")
        required_positions = set(self.shared_core_positions)
        required_actions = set(self.shared_action_directions)
        if any(
            required_positions != set(candidate.core_positions)
            or required_actions != set(candidate.action_directions)
            for candidate in self.candidates
        ):
            raise ValueError("reply candidates must preserve shared positions and actions")
        return self


class AuditFinding(StrictModel):
    claim_id: SafePolicyKey
    evidence_ids: EvidenceIds
    fidelity: Literal[
        "faithful", "unsupported", "misrepresented", "stale", "conflicted"
    ]
    severity: Literal["info", "warning", "blocking"]
    correction: BoundedText | None = None

    @field_validator("evidence_ids")
    @classmethod
    def _canonical_evidence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted(value, "audit evidence identifiers")

    @model_validator(mode="after")
    def _correction_shape(self) -> "AuditFinding":
        if self.severity == "blocking" and self.correction is None:
            raise ValueError("blocking audit finding requires a correction")
        return self


class EvidenceSemanticAssessment(StrictModel):
    """One independent semantic judgment bound to an exact evidence excerpt.

    ``semantic_status`` and ``assessed_claim_type`` are authored by the
    independent audit pass.  The source span and digest are deterministic
    closure data and are revalidated against the frozen generation evidence
    context by the scoped worker.
    """

    claim_scope: Literal["analysis", "reply"]
    claim_id: SafePolicyKey
    assessed_claim_type: Literal[
        "fact",
        "hypothesis",
        "important_conclusion",
        "suggestion",
        "open_question",
        "uncertain_expression",
    ]
    evidence_id: ObjectId
    role: Literal["support", "contradict"]
    text_start_char: NonNegativeInt
    text_end_char: Annotated[int, Field(strict=True, gt=0)]
    exact_excerpt: Annotated[NonEmptyStr, Field(max_length=20_000)]
    excerpt_sha256: Sha256Hex
    semantic_status: Literal[
        "supports", "contradicts", "ambiguous", "irrelevant"
    ]

    @model_validator(mode="after")
    def _exact_excerpt(self) -> "EvidenceSemanticAssessment":
        if self.text_end_char <= self.text_start_char:
            raise ValueError("evidence assessment span must be non-empty")
        if self.text_end_char - self.text_start_char != len(self.exact_excerpt):
            raise ValueError("evidence assessment span length must equal excerpt length")
        if self.excerpt_sha256 != text_sha256(self.exact_excerpt):
            raise ValueError("evidence assessment excerpt hash mismatch")
        return self

    def pair_key(self) -> tuple[str, str, str, str]:
        return self.claim_scope, self.claim_id, self.evidence_id, self.role


class EvidenceAudit(StrictModel):
    envelope: GenerationStageEnvelope
    evidence_pack_sha256: Sha256Hex
    assessments: tuple[EvidenceSemanticAssessment, ...]
    findings: tuple[AuditFinding, ...]
    decision: GenerationDecision
    retry_count: Annotated[int, Field(strict=True, ge=0, le=2)] = 0
    unresolved_reasons: tuple[BoundedText, ...] = ()
    rationale_summary: RationaleSummary

    @model_validator(mode="after")
    def _shape(self) -> "EvidenceAudit":
        if self.envelope.stage != "evidence_audit":
            raise ValueError("evidence audit envelope stage mismatch")
        keys = tuple(item.pair_key() for item in self.assessments)
        if keys != tuple(sorted(set(keys))):
            raise ValueError(
                "evidence semantic assessments must be unique and canonical"
            )
        if self.decision == "pass" and any(
            finding.severity == "blocking" for finding in self.findings
        ):
            raise ValueError("evidence audit cannot pass with blocking findings")
        if self.decision != "pass" and not self.unresolved_reasons:
            raise ValueError("non-pass evidence audit requires unresolved reasons")
        return self


class ConsistencyFinding(StrictModel):
    finding_id: SafePolicyKey
    category: Literal[
        "fact_conflict",
        "core_position_conflict",
        "action_direction_conflict",
        "cross_turn_change",
        "expression_difference",
        "risk_review",
    ]
    severity: Literal["allowed", "warning", "blocking"]
    affected_candidate_ids: PolicyKeys
    evidence_ids: EvidenceIds = ()
    description: BoundedText
    correction: BoundedText | None = None

    @field_validator("affected_candidate_ids", "evidence_ids")
    @classmethod
    def _canonical_identifiers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted(value, "consistency identifiers")

    @model_validator(mode="after")
    def _blocking_shape(self) -> "ConsistencyFinding":
        if self.severity == "blocking" and self.correction is None:
            raise ValueError("blocking consistency finding requires correction")
        return self


class ConsistencySemanticAssessment(StrictModel):
    """Independent semantic projection bound to one exact visible/source span.

    The critic authors ``assessed_value``.  The remaining fields only let the
    worker prove that the judgment is complete, unique, and attached to bytes
    that were actually visible in the frozen generation run.
    """

    snapshot_key: SafePolicyKey
    axis_kind: Literal["fact", "core_position", "action_direction", "conclusion"]
    subject_key: SafePolicyKey
    assessed_value: Literal[
        "affirmed",
        "denied",
        "uncertain",
        "superseded",
        "support",
        "oppose",
        "pursue",
        "avoid",
        "explore",
        "defer",
        "supports_conclusion",
    ]
    evidence_id: ObjectId | None = None
    text_start_char: NonNegativeInt
    text_end_char: Annotated[int, Field(strict=True, gt=0)]
    exact_excerpt: Annotated[NonEmptyStr, Field(max_length=20_000)]
    excerpt_sha256: Sha256Hex

    @model_validator(mode="after")
    def _shape(self) -> "ConsistencySemanticAssessment":
        allowed_values = {
            "fact": {"affirmed", "denied", "uncertain", "superseded"},
            "core_position": {"support", "oppose", "uncertain"},
            "action_direction": {"pursue", "avoid", "explore", "defer"},
            "conclusion": {"supports_conclusion"},
        }
        if self.assessed_value not in allowed_values[self.axis_kind]:
            raise ValueError("consistency assessment value does not match its axis")
        if self.axis_kind == "conclusion" and self.subject_key != "conclusion":
            raise ValueError("conclusion assessment subject must be conclusion")
        if self.text_end_char <= self.text_start_char:
            raise ValueError("consistency assessment span must be non-empty")
        if self.text_end_char - self.text_start_char != len(self.exact_excerpt):
            raise ValueError("consistency assessment span length must equal excerpt length")
        if self.excerpt_sha256 != text_sha256(self.exact_excerpt):
            raise ValueError("consistency assessment excerpt hash mismatch")
        return self

    def assessment_key(self) -> tuple[str, str, str, str]:
        return (
            self.snapshot_key,
            self.axis_kind,
            self.subject_key,
            self.evidence_id or "",
        )


class ConsistencyRiskReview(StrictModel):
    envelope: GenerationStageEnvelope
    evidence_pack_sha256: Sha256Hex
    current_candidate_snapshots: Annotated[
        tuple[ConsistencySnapshot, ...], Field(min_length=1)
    ]
    session_earlier_snapshots: tuple[ConsistencySnapshot, ...] = ()
    client_profile_snapshots: tuple[ConsistencySnapshot, ...] = ()
    semantic_assessments: tuple[ConsistencySemanticAssessment, ...] = ()
    consistency_findings: tuple[ConsistencyFinding, ...]
    conclusion_changes: tuple[ConclusionChangeRecord, ...] = ()
    risk_observation_ids: Annotated[
        tuple[ObjectId, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    decision: GenerationDecision
    retry_count: Annotated[int, Field(strict=True, ge=0, le=2)] = 0
    unresolved_reasons: tuple[BoundedText, ...] = ()
    rationale_summary: RationaleSummary

    @field_validator("risk_observation_ids")
    @classmethod
    def _canonical_risk_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted(value, "risk observation identifiers")

    @model_validator(mode="after")
    def _shape(self) -> "ConsistencyRiskReview":
        if self.envelope.stage != "consistency_risk_review":
            raise ValueError("consistency review envelope stage mismatch")
        groups = (
            (self.current_candidate_snapshots, "current_candidate"),
            (self.session_earlier_snapshots, "session_earlier"),
            (self.client_profile_snapshots, "client_profile"),
        )
        if any(
            snapshot.source != source
            for snapshots, source in groups
            for snapshot in snapshots
        ):
            raise ValueError("consistency snapshot source mismatch")
        keys = tuple(
            snapshot.snapshot_key
            for snapshots, _source in groups
            for snapshot in snapshots
        )
        if len(keys) != len(set(keys)):
            raise ValueError("consistency snapshot keys must be unique")
        assessment_keys = tuple(
            assessment.assessment_key() for assessment in self.semantic_assessments
        )
        if assessment_keys != tuple(sorted(set(assessment_keys))):
            raise ValueError(
                "consistency semantic assessments must be unique and canonical"
            )
        if self.decision == "pass" and any(
            finding.severity == "blocking" for finding in self.consistency_findings
        ):
            raise ValueError("consistency review cannot pass with blocking findings")
        if self.decision != "pass" and not self.unresolved_reasons:
            raise ValueError("non-pass consistency review requires unresolved reasons")
        return self


class ClientReplyCandidate(StrictModel):
    """Client-safe physical sibling with no internal-risk fields."""

    candidate_id: SafePolicyKey
    label: Annotated[NonEmptyStr, Field(max_length=120)]
    strategy: ReplyStrategy
    text: BoundedText
    core_positions: PolicyKeys
    action_directions: PolicyKeys

    @field_validator("core_positions", "action_directions")
    @classmethod
    def _canonical_keys(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted(value, "client reply policy keys")


class CounselorInternalAnalysis(StrictModel):
    summary: BoundedText
    key_fact_ids: Annotated[
        tuple[NonEmptyStr, ...], Field(json_schema_extra={"uniqueItems": True})
    ]
    hypotheses: tuple[BoundedText, ...]
    conflicts: tuple[BoundedText, ...]
    uncertainty: tuple[BoundedText, ...]
    evidence_ids: EvidenceIds
    risk_observations: tuple[InternalRiskObservation, ...] = ()

    @field_validator("key_fact_ids", "evidence_ids")
    @classmethod
    def _canonical_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted(value, "internal analysis identifiers")


class FollowUpGuidance(StrictModel):
    suggested_questions: tuple[BoundedText, ...]
    optional_actions: tuple[BoundedText, ...]
    observation_focus: tuple[BoundedText, ...]
    next_steps: tuple[BoundedText, ...]


class EvidenceQualitySummary(StrictModel):
    status: Literal["sufficient", "limited", "conflicted", "needs_counselor_judgment"]
    evidence_ids: EvidenceIds
    unresolved_reasons: tuple[BoundedText, ...]
    retry_count: Annotated[int, Field(strict=True, ge=0, le=2)] = 0

    @field_validator("evidence_ids")
    @classmethod
    def _canonical_evidence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted(value, "quality evidence identifiers")

    @model_validator(mode="after")
    def _status_shape(self) -> "EvidenceQualitySummary":
        if (self.status == "sufficient") == bool(self.unresolved_reasons):
            raise ValueError("quality status and unresolved reasons do not match")
        return self


class FinalTurnBundle(StrictModel):
    envelope: GenerationStageEnvelope
    evidence_pack_sha256: Sha256Hex
    counselor_internal: CounselorInternalAnalysis
    client_reply_candidates: Annotated[
        tuple[ClientReplyCandidate, ...], Field(min_length=2, max_length=4)
    ]
    follow_up_guidance: FollowUpGuidance
    evidence_quality: EvidenceQualitySummary

    @model_validator(mode="after")
    def _shape(self) -> "FinalTurnBundle":
        if self.envelope.stage != "final_bundle":
            raise ValueError("final bundle envelope stage mismatch")
        identifiers = [item.candidate_id for item in self.client_reply_candidates]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("client reply candidate IDs must be unique")
        return self


def _stage_discriminator(value: Any) -> str | None:
    if isinstance(value, StrictModel):
        envelope = getattr(value, "envelope", None)
    elif isinstance(value, dict):
        envelope = value.get("envelope")
    else:
        return None
    if isinstance(envelope, GenerationStageEnvelope):
        return envelope.stage
    if isinstance(envelope, dict):
        stage = envelope.get("stage")
        return stage if isinstance(stage, str) else None
    return None


GenerationStagePayload: TypeAlias = Annotated[
    Annotated[QueryPlan, Tag("query_plan")]
    | Annotated[Conceptualization, Tag("conceptualization")]
    | Annotated[TheoryComparison, Tag("theory_comparison")]
    | Annotated[ReplyDraftSet, Tag("reply_drafts")]
    | Annotated[EvidenceAudit, Tag("evidence_audit")]
    | Annotated[ConsistencyRiskReview, Tag("consistency_risk_review")]
    | Annotated[FinalTurnBundle, Tag("final_bundle")],
    Discriminator(_stage_discriminator),
]

GENERATION_STAGE_ADAPTER: TypeAdapter[GenerationStagePayload] = TypeAdapter(
    GenerationStagePayload
)


def validate_generation_payload(value: object) -> GenerationStagePayload:
    return GENERATION_STAGE_ADAPTER.validate_python(value, strict=True)


def validate_generation_payload_json(value: str | bytes | bytearray) -> GenerationStagePayload:
    return GENERATION_STAGE_ADAPTER.validate_json(value, strict=True)


__all__ = [
    "AuditFinding",
    "BoundedText",
    "ClientReplyCandidate",
    "Conceptualization",
    "ConceptualizationItem",
    "ConsistencyFinding",
    "ConsistencyRiskReview",
    "ConsistencySemanticAssessment",
    "CounselorInternalAnalysis",
    "EvidenceAudit",
    "EvidenceSemanticAssessment",
    "EvidenceIds",
    "EvidenceQualitySummary",
    "FinalTurnBundle",
    "FollowUpGuidance",
    "GENERATION_STAGE_ADAPTER",
    "GenerationDecision",
    "GenerationStagePayload",
    "NonEmptyPolicyKeys",
    "PolicyKeys",
    "QueryGuardrails",
    "QueryPlan",
    "RationaleSummary",
    "ReplyDraft",
    "ReplyDraftSet",
    "ReplyClaim",
    "ReplyStrategy",
    "RouteOmission",
    "Subquery",
    "SubqueryCategory",
    "SubqueryScope",
    "TheoryComparison",
    "TheorySelection",
    "validate_generation_payload",
    "validate_generation_payload_json",
]
