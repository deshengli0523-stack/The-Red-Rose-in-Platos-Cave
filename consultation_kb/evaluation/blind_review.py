"""Randomized double-blind expert comparison packets and review importing.

The visible packet deliberately contains only the synthetic case context,
candidate prose, and the scoring rubric.  Variant, run, model, source, and
client identities remain in a separately stored mapping authenticated with an
operator-held HMAC key.  Reviewer identities cross this boundary only as
keyed, irreversible pseudonyms.
"""

from __future__ import annotations

import hashlib
import hmac
import random
import re
from collections.abc import Iterable, Sequence
from itertools import combinations
from typing import Annotated, Literal, TypeAlias

from pydantic import Field, model_validator
from typing_extensions import Self

from consultation_kb.knowledge._canonical import canonical_json_bytes, text_sha256
from consultation_kb.models.common import (
    FiniteFloat,
    PositiveInt,
    SafePolicyKey,
    Sha256Hex,
    StrictModel,
)
from consultation_kb.models.evaluation import EvaluationTurn, SyntheticText


BlindSide: TypeAlias = Literal["left", "right", "tie"]
BlindVariant: TypeAlias = Literal["full_system", "hybrid_rag_only"]
ResolvedPreference: TypeAlias = Literal["full_system", "hybrid_rag_only", "tie"]


_MAPPING_DOMAIN = b"consultation-kb-blind-mapping-v1\0"
_REVIEWER_DOMAIN = b"consultation-kb-reviewer-pseudonym-v1\0"
_FORBIDDEN_VISIBLE_TOKEN_RE = re.compile(
    r"(?i)(?:\b(?:client|source)_[a-z0-9_-]+\b|"
    r"\b(?:full_system|hybrid_rag_only)\b|"
    r"\b(?:run_id|model_version|model_sha256)\b|"
    r"\b(?:internal_risk|risk_level|high_attention|"
    r"counselor_attention_required)\b)"
)


class BlindReviewError(ValueError):
    """Fail-closed import error with a stable machine-readable code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ReviewRubricCriterion(StrictModel):
    criterion_id: SafePolicyKey
    guidance: SyntheticText


BLIND_REVIEW_RUBRIC: tuple[ReviewRubricCriterion, ...] = (
    ReviewRubricCriterion(
        criterion_id="consultation_helpfulness",
        guidance="判断回答是否真正帮助来访者理解处境并向前推进。",
    ),
    ReviewRubricCriterion(
        criterion_id="empathy",
        guidance="判断回答是否准确接住情绪，同时避免空泛安慰。",
    ),
    ReviewRubricCriterion(
        criterion_id="specificity",
        guidance="判断分析是否贴合当前情境并包含足够具体的信息。",
    ),
    ReviewRubricCriterion(
        criterion_id="actionability",
        guidance="判断建议是否清晰、现实且能够转化为下一步行动。",
    ),
    ReviewRubricCriterion(
        criterion_id="autonomy_support",
        guidance="判断回答是否支持来访者自主判断，而非替其武断决定。",
    ),
    ReviewRubricCriterion(
        criterion_id="fact_evidence_fidelity",
        guidance="判断事实与理论使用是否忠实于给定信息和证据。",
    ),
    ReviewRubricCriterion(
        criterion_id="conflict_uncertainty_handling",
        guidance="判断回答是否妥善呈现证据冲突、条件和不确定性。",
    ),
    ReviewRubricCriterion(
        criterion_id="professional_boundaries",
        guidance="判断回答是否遵守咨询专业边界并避免越界结论。",
    ),
)

RUBRIC_IDS: tuple[str, ...] = tuple(
    criterion.criterion_id for criterion in BLIND_REVIEW_RUBRIC
)


def _require_secret(secret: bytes, *, purpose: str) -> bytes:
    if type(secret) is not bytes or len(secret) < 16:
        raise ValueError(f"{purpose} secret must contain at least 16 bytes")
    return secret


def _validate_visible_text(value: str) -> None:
    if _FORBIDDEN_VISIBLE_TOKEN_RE.search(value):
        raise ValueError("blind packet text exposes hidden identity or risk metadata")


class BlindPairSource(StrictModel):
    """The private paired input from which one visible packet is made."""

    case_id: SafePolicyKey
    context: tuple[EvaluationTurn, ...]
    full_system_response: SyntheticText
    hybrid_rag_only_response: SyntheticText

    @model_validator(mode="after")
    def _complete_source(self) -> Self:
        if not self.context or self.context[-1].role != "client":
            raise ValueError("blind-review context must end with a client turn")
        for turn in self.context:
            _validate_visible_text(turn.text)
        _validate_visible_text(self.full_system_response)
        _validate_visible_text(self.hybrid_rag_only_response)
        return self


class BlindPairPacket(StrictModel):
    """Reviewer-visible packet; it cannot identify either system."""

    record_type: Literal["blind_pair_packet"] = "blind_pair_packet"
    schema_version: Literal["blind_pair_packet.v1"] = "blind_pair_packet.v1"
    packet_id: SafePolicyKey
    case_id: SafePolicyKey
    context: tuple[EvaluationTurn, ...]
    left_response: SyntheticText
    right_response: SyntheticText
    rubric: tuple[ReviewRubricCriterion, ...]
    mapping_sha256: Sha256Hex

    @model_validator(mode="after")
    def _blind_contract(self) -> Self:
        if not self.packet_id.startswith("blind_pair_"):
            raise ValueError("blind packet ID must use the blind_pair namespace")
        if not self.context or self.context[-1].role != "client":
            raise ValueError("blind packet context must end with a client turn")
        if tuple(item.criterion_id for item in self.rubric) != RUBRIC_IDS:
            raise ValueError("blind packet must carry the complete standard rubric")
        for turn in self.context:
            _validate_visible_text(turn.text)
        _validate_visible_text(self.left_response)
        _validate_visible_text(self.right_response)
        if self.left_response == self.right_response:
            raise ValueError("blind candidates must be materially distinguishable")
        return self

    @property
    def mapping_hash(self) -> str:
        """Compatibility spelling for callers that call the digest a hash."""

        return self.mapping_sha256


class BlindPairMapping(StrictModel):
    """Private left/right identity map stored away from the review packet."""

    schema_version: Literal["blind_pair_mapping.v1"] = "blind_pair_mapping.v1"
    packet_id: SafePolicyKey
    case_id: SafePolicyKey
    left_variant: BlindVariant
    right_variant: BlindVariant
    left_response_sha256: Sha256Hex
    right_response_sha256: Sha256Hex
    mapping_sha256: Sha256Hex

    @model_validator(mode="after")
    def _mapping_contract(self) -> Self:
        if {self.left_variant, self.right_variant} != {
            "full_system",
            "hybrid_rag_only",
        }:
            raise ValueError("blind mapping must contain both comparison variants")
        if self.left_response_sha256 == self.right_response_sha256:
            raise ValueError("blind mapping candidates must have different hashes")
        return self

    @property
    def mapping_hash(self) -> str:
        return self.mapping_sha256


class BlindReviewBundle(StrictModel):
    packet: BlindPairPacket
    mapping: BlindPairMapping

    @model_validator(mode="after")
    def _same_pair(self) -> Self:
        if (
            self.packet.packet_id != self.mapping.packet_id
            or self.packet.case_id != self.mapping.case_id
            or self.packet.mapping_sha256 != self.mapping.mapping_sha256
        ):
            raise ValueError("packet and private mapping do not describe the same pair")
        if text_sha256(self.packet.left_response) != self.mapping.left_response_sha256:
            raise ValueError("left response hash does not match private mapping")
        if (
            text_sha256(self.packet.right_response)
            != self.mapping.right_response_sha256
        ):
            raise ValueError("right response hash does not match private mapping")
        return self


def _mapping_projection(
    mapping: BlindPairMapping | dict[str, object],
) -> dict[str, object]:
    raw = (
        mapping.model_dump(mode="json")
        if isinstance(mapping, BlindPairMapping)
        else dict(mapping)
    )
    raw.pop("mapping_sha256", None)
    return raw


def _mapping_digest(projection: dict[str, object], secret: bytes) -> str:
    key = _require_secret(secret, purpose="mapping")
    return hmac.new(
        key,
        _MAPPING_DOMAIN + canonical_json_bytes(projection),
        hashlib.sha256,
    ).hexdigest()


def verify_blind_mapping(mapping: BlindPairMapping, secret: bytes) -> bool:
    """Authenticate a private mapping without exposing its key to reviewers."""

    exact = BlindPairMapping.model_validate(mapping)
    expected = _mapping_digest(_mapping_projection(exact), secret)
    return hmac.compare_digest(expected, exact.mapping_sha256)


def _packet_id(source: BlindPairSource, ordinal: int) -> str:
    digest = hashlib.sha256(
        canonical_json_bytes(
            {
                "domain": "consultation_kb.blind_packet_id.v1",
                "case_id": source.case_id,
                "ordinal": ordinal,
                "full_sha256": text_sha256(source.full_system_response),
                "hybrid_sha256": text_sha256(source.hybrid_rag_only_response),
            }
        )
    ).hexdigest()
    return f"blind_pair_{digest[:32]}"


def _build_pair(
    source: BlindPairSource,
    *,
    ordinal: int,
    rng: random.Random,
    mapping_secret: bytes,
) -> BlindReviewBundle:
    exact = BlindPairSource.model_validate(source)
    full_on_left = bool(rng.getrandbits(1))
    if full_on_left:
        left_variant: BlindVariant = "full_system"
        right_variant: BlindVariant = "hybrid_rag_only"
        left_response = exact.full_system_response
        right_response = exact.hybrid_rag_only_response
    else:
        left_variant = "hybrid_rag_only"
        right_variant = "full_system"
        left_response = exact.hybrid_rag_only_response
        right_response = exact.full_system_response
    projection: dict[str, object] = {
        "schema_version": "blind_pair_mapping.v1",
        "packet_id": _packet_id(exact, ordinal),
        "case_id": exact.case_id,
        "left_variant": left_variant,
        "right_variant": right_variant,
        "left_response_sha256": text_sha256(left_response),
        "right_response_sha256": text_sha256(right_response),
    }
    digest = _mapping_digest(projection, mapping_secret)
    mapping = BlindPairMapping(
        packet_id=str(projection["packet_id"]),
        case_id=exact.case_id,
        left_variant=left_variant,
        right_variant=right_variant,
        left_response_sha256=text_sha256(left_response),
        right_response_sha256=text_sha256(right_response),
        mapping_sha256=digest,
    )
    packet = BlindPairPacket(
        packet_id=mapping.packet_id,
        case_id=exact.case_id,
        context=exact.context,
        left_response=left_response,
        right_response=right_response,
        rubric=BLIND_REVIEW_RUBRIC,
        mapping_sha256=digest,
    )
    return BlindReviewBundle(packet=packet, mapping=mapping)


def build_blind_review_packets(
    sources: Sequence[BlindPairSource],
    *,
    seed: int,
    mapping_secret: bytes,
) -> tuple[BlindReviewBundle, ...]:
    """Create a deterministic queue-order randomization for an evaluation run."""

    if type(seed) is not int or seed < 0:
        raise ValueError("blind-review seed must be a nonnegative integer")
    _require_secret(mapping_secret, purpose="mapping")
    exact_sources = tuple(BlindPairSource.model_validate(item) for item in sources)
    if not exact_sources:
        raise ValueError("blind review requires at least one paired source")
    case_ids = tuple(item.case_id for item in exact_sources)
    if len(set(case_ids)) != len(case_ids):
        raise ValueError("blind-review case IDs must be unique")
    rng = random.Random(seed)
    return tuple(
        _build_pair(
            source,
            ordinal=index,
            rng=rng,
            mapping_secret=mapping_secret,
        )
        for index, source in enumerate(exact_sources)
    )


def build_blind_review_pair(
    source: BlindPairSource,
    *,
    seed: int,
    mapping_secret: bytes,
) -> BlindReviewBundle:
    return build_blind_review_packets(
        (source,), seed=seed, mapping_secret=mapping_secret
    )[0]


def pseudonymize_reviewer_id(reviewer_id: str, secret: bytes) -> str:
    """Return a keyed digest; the raw reviewer identifier is never persisted."""

    if type(reviewer_id) is not str or not reviewer_id.strip():
        raise ValueError("reviewer ID must be a nonblank string")
    key = _require_secret(secret, purpose="reviewer")
    return hmac.new(
        key,
        _REVIEWER_DOMAIN + reviewer_id.strip().encode("utf-8", errors="strict"),
        hashlib.sha256,
    ).hexdigest()


Score = Annotated[int, Field(strict=True, ge=1, le=5)]


class CriterionReview(StrictModel):
    criterion_id: SafePolicyKey
    left_score: Score
    right_score: Score
    preference: BlindSide
    reason_codes: tuple[SafePolicyKey, ...]
    rationale: SyntheticText

    @model_validator(mode="after")
    def _score_consistency(self) -> Self:
        if self.criterion_id not in RUBRIC_IDS:
            raise ValueError("review references an unknown rubric criterion")
        if not self.reason_codes or tuple(sorted(set(self.reason_codes))) != (
            self.reason_codes
        ):
            raise ValueError("criterion reason codes must be sorted and non-empty")
        expected: BlindSide
        if self.left_score > self.right_score:
            expected = "left"
        elif self.right_score > self.left_score:
            expected = "right"
        else:
            expected = "tie"
        if self.preference != expected:
            raise ValueError("criterion preference contradicts its numeric scores")
        return self


class BlindReviewSubmission(StrictModel):
    record_type: Literal["blind_review_submission"] = "blind_review_submission"
    schema_version: Literal["blind_review_submission.v1"] = "blind_review_submission.v1"
    packet_id: SafePolicyKey
    mapping_sha256: Sha256Hex
    reviewer_id_hash: Sha256Hex
    overall_preference: BlindSide
    overall_reason_codes: tuple[SafePolicyKey, ...]
    overall_rationale: SyntheticText
    criteria: tuple[CriterionReview, ...]

    @model_validator(mode="after")
    def _complete_review(self) -> Self:
        if (
            not self.overall_reason_codes
            or tuple(sorted(set(self.overall_reason_codes)))
            != self.overall_reason_codes
        ):
            raise ValueError("overall reason codes must be sorted and non-empty")
        criterion_ids = tuple(item.criterion_id for item in self.criteria)
        if criterion_ids != RUBRIC_IDS:
            raise ValueError("review must score every rubric criterion exactly once")
        preferences = {item.preference for item in self.criteria}
        if preferences == {"left"} and self.overall_preference == "right":
            raise ValueError("overall preference contradicts unanimous left scores")
        if preferences == {"right"} and self.overall_preference == "left":
            raise ValueError("overall preference contradicts unanimous right scores")
        return self


def make_review_submission(
    *,
    packet_id: str,
    mapping_sha256: str,
    reviewer_id: str,
    reviewer_secret: bytes,
    overall_preference: BlindSide,
    overall_reason_codes: tuple[str, ...],
    overall_rationale: str,
    criteria: tuple[CriterionReview, ...],
) -> BlindReviewSubmission:
    return BlindReviewSubmission(
        packet_id=packet_id,
        mapping_sha256=mapping_sha256,
        reviewer_id_hash=pseudonymize_reviewer_id(reviewer_id, reviewer_secret),
        overall_preference=overall_preference,
        overall_reason_codes=overall_reason_codes,
        overall_rationale=overall_rationale,
        criteria=criteria,
    )


class ImportedBlindReview(StrictModel):
    packet_id: SafePolicyKey
    case_id: SafePolicyKey
    reviewer_id_hash: Sha256Hex
    resolved_preference: ResolvedPreference
    criterion_preferences: tuple[ResolvedPreference, ...]


class PreferenceEstimate(StrictModel):
    value: FiniteFloat
    ci_lower: FiniteFloat
    ci_upper: FiniteFloat
    method: Literal["review_bootstrap_percentile_95"] = "review_bootstrap_percentile_95"
    bootstrap_seed: int = Field(strict=True, ge=0)
    bootstrap_replicates: int = Field(strict=True, ge=100)

    @model_validator(mode="after")
    def _bounded_interval(self) -> Self:
        if not (0.0 <= self.ci_lower <= self.value <= self.ci_upper <= 1.0):
            raise ValueError("preference estimate must be an ordered probability")
        return self


class BlindReviewSummary(StrictModel):
    packet_count: PositiveInt
    review_count: PositiveInt
    independent_reviewer_count: PositiveInt
    full_system_wins: int = Field(strict=True, ge=0)
    hybrid_rag_only_wins: int = Field(strict=True, ge=0)
    ties: int = Field(strict=True, ge=0)
    full_system_preference: PreferenceEstimate
    reviewer_agreement: FiniteFloat | None
    agreement_pair_count: int = Field(strict=True, ge=0)
    conclusion_eligible: bool

    @model_validator(mode="after")
    def _summary_counts(self) -> Self:
        if self.full_system_wins + self.hybrid_rag_only_wins + self.ties != (
            self.review_count
        ):
            raise ValueError("blind-review win counts do not sum to review count")
        if (self.reviewer_agreement is None) != (self.agreement_pair_count == 0):
            raise ValueError("reviewer agreement requires at least one comparable pair")
        if self.reviewer_agreement is not None and not (
            0.0 <= self.reviewer_agreement <= 1.0
        ):
            raise ValueError("reviewer agreement must be in [0, 1]")
        if self.conclusion_eligible != (self.independent_reviewer_count >= 2):
            raise ValueError("single-reviewer evidence cannot support a conclusion")
        return self


class BlindReviewImport(StrictModel):
    reviews: tuple[ImportedBlindReview, ...]
    summary: BlindReviewSummary


def _resolve(side: BlindSide, mapping: BlindPairMapping) -> ResolvedPreference:
    if side == "tie":
        return "tie"
    return mapping.left_variant if side == "left" else mapping.right_variant


def _percentile(values: Sequence[float], quantile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("percentile requires at least one value")
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def _preference_estimate(
    values: tuple[float, ...], *, seed: int, replicates: int
) -> PreferenceEstimate:
    if replicates < 100:
        raise ValueError("preference bootstrap needs at least 100 replicates")
    generator = random.Random(seed)
    samples = tuple(
        sum(generator.choice(values) for _ in values) / len(values)
        for _ in range(replicates)
    )
    value = sum(values) / len(values)
    return PreferenceEstimate(
        value=float(value),
        ci_lower=float(_percentile(samples, 0.025)),
        ci_upper=float(_percentile(samples, 0.975)),
        bootstrap_seed=seed,
        bootstrap_replicates=replicates,
    )


class ReviewImporter:
    """Validate blinded submissions, resolve mappings, and aggregate evidence."""

    def __init__(
        self,
        *,
        mapping_secret: bytes,
        bootstrap_seed: int = 20_260_716,
        bootstrap_replicates: int = 2_000,
    ) -> None:
        self._mapping_secret = _require_secret(mapping_secret, purpose="mapping")
        if type(bootstrap_seed) is not int or bootstrap_seed < 0:
            raise ValueError("bootstrap seed must be a nonnegative integer")
        if type(bootstrap_replicates) is not int or bootstrap_replicates < 100:
            raise ValueError("bootstrap replicates must be at least 100")
        self._bootstrap_seed = bootstrap_seed
        self._bootstrap_replicates = bootstrap_replicates

    def import_reviews(
        self,
        bundles: Sequence[BlindReviewBundle],
        submissions: Sequence[BlindReviewSubmission],
        *,
        expected_reviewer_hashes: Iterable[str] | None = None,
    ) -> BlindReviewImport:
        exact_bundles = tuple(
            BlindReviewBundle.model_validate(item) for item in bundles
        )
        exact_submissions = tuple(
            BlindReviewSubmission.model_validate(item) for item in submissions
        )
        if not exact_bundles:
            raise BlindReviewError("BLIND_REVIEW_MISSING_PACKET")
        by_packet: dict[str, BlindReviewBundle] = {}
        for bundle in exact_bundles:
            if bundle.packet.packet_id in by_packet:
                raise BlindReviewError("BLIND_REVIEW_DUPLICATE_PACKET")
            if not verify_blind_mapping(bundle.mapping, self._mapping_secret):
                raise BlindReviewError("BLIND_REVIEW_MAPPING_HASH_MISMATCH")
            by_packet[bundle.packet.packet_id] = bundle

        expected = None
        if expected_reviewer_hashes is not None:
            expected = tuple(sorted(set(expected_reviewer_hashes)))
            if not expected or any(
                type(value) is not str
                or len(value) != 64
                or any(char not in "0123456789abcdef" for char in value)
                for value in expected
            ):
                raise ValueError("expected reviewer hashes must be canonical sha256")

        seen: set[tuple[str, str]] = set()
        resolved: list[ImportedBlindReview] = []
        submitted_by_packet: dict[str, set[str]] = {
            packet_id: set() for packet_id in by_packet
        }
        for submission in exact_submissions:
            resolved_bundle = by_packet.get(submission.packet_id)
            if resolved_bundle is None:
                raise BlindReviewError("BLIND_REVIEW_UNKNOWN_PACKET")
            if not hmac.compare_digest(
                submission.mapping_sha256, resolved_bundle.mapping.mapping_sha256
            ):
                raise BlindReviewError("BLIND_REVIEW_MAPPING_HASH_MISMATCH")
            duplicate_key = (submission.packet_id, submission.reviewer_id_hash)
            if duplicate_key in seen:
                raise BlindReviewError("BLIND_REVIEW_DUPLICATE_REVIEW")
            seen.add(duplicate_key)
            submitted_by_packet[submission.packet_id].add(submission.reviewer_id_hash)
            resolved.append(
                ImportedBlindReview(
                    packet_id=submission.packet_id,
                    case_id=resolved_bundle.packet.case_id,
                    reviewer_id_hash=submission.reviewer_id_hash,
                    resolved_preference=_resolve(
                        submission.overall_preference, resolved_bundle.mapping
                    ),
                    criterion_preferences=tuple(
                        _resolve(item.preference, resolved_bundle.mapping)
                        for item in submission.criteria
                    ),
                )
            )

        for packet_id, reviewer_hashes in submitted_by_packet.items():
            if not reviewer_hashes:
                raise BlindReviewError("BLIND_REVIEW_MISSING_REVIEW")
            if expected is not None and reviewer_hashes != set(expected):
                raise BlindReviewError("BLIND_REVIEW_MISSING_REVIEWER")

        ordered = tuple(
            sorted(resolved, key=lambda item: (item.packet_id, item.reviewer_id_hash))
        )
        if not ordered:
            raise BlindReviewError("BLIND_REVIEW_MISSING_REVIEW")
        full_wins = sum(item.resolved_preference == "full_system" for item in ordered)
        hybrid_wins = sum(
            item.resolved_preference == "hybrid_rag_only" for item in ordered
        )
        ties = sum(item.resolved_preference == "tie" for item in ordered)
        numeric = tuple(
            1.0
            if item.resolved_preference == "full_system"
            else 0.0
            if item.resolved_preference == "hybrid_rag_only"
            else 0.5
            for item in ordered
        )

        comparison_values: list[float] = []
        for packet_id in sorted(by_packet):
            packet_reviews = tuple(
                item for item in ordered if item.packet_id == packet_id
            )
            for first, second in combinations(packet_reviews, 2):
                overall_equal = first.resolved_preference == second.resolved_preference
                criterion_equal = sum(
                    left == right
                    for left, right in zip(
                        first.criterion_preferences,
                        second.criterion_preferences,
                        strict=True,
                    )
                ) / len(RUBRIC_IDS)
                comparison_values.append((float(overall_equal) + criterion_equal) / 2)
        agreement = (
            None
            if not comparison_values
            else float(sum(comparison_values) / len(comparison_values))
        )
        reviewer_count = len({item.reviewer_id_hash for item in ordered})
        summary = BlindReviewSummary(
            packet_count=len(by_packet),
            review_count=len(ordered),
            independent_reviewer_count=reviewer_count,
            full_system_wins=full_wins,
            hybrid_rag_only_wins=hybrid_wins,
            ties=ties,
            full_system_preference=_preference_estimate(
                numeric,
                seed=self._bootstrap_seed,
                replicates=self._bootstrap_replicates,
            ),
            reviewer_agreement=agreement,
            agreement_pair_count=len(comparison_values),
            conclusion_eligible=reviewer_count >= 2,
        )
        return BlindReviewImport(reviews=ordered, summary=summary)


BlindReviewImporter = ReviewImporter


__all__ = [
    "BLIND_REVIEW_RUBRIC",
    "RUBRIC_IDS",
    "BlindPairMapping",
    "BlindPairPacket",
    "BlindPairSource",
    "BlindReviewBundle",
    "BlindReviewError",
    "BlindReviewImport",
    "BlindReviewImporter",
    "BlindReviewSubmission",
    "BlindReviewSummary",
    "BlindSide",
    "BlindVariant",
    "CriterionReview",
    "ImportedBlindReview",
    "PreferenceEstimate",
    "ResolvedPreference",
    "ReviewImporter",
    "ReviewRubricCriterion",
    "build_blind_review_packets",
    "build_blind_review_pair",
    "make_review_submission",
    "pseudonymize_reviewer_id",
    "verify_blind_mapping",
]
