from __future__ import annotations

import hashlib
import unicodedata
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

import pytest

from consultation_kb.core.config import AppConfig
from consultation_kb.generation.contracts import ClientReplyCandidate
from consultation_kb.models.common import VersionRef
from consultation_kb.models.risk import InternalRiskObservation
from consultation_kb.policy.loader import PolicyLoader
from consultation_kb.risk.output_guard import (
    ClientReplyLeakageError,
    ClientReplyOutputGuard,
)
from consultation_kb.risk.projection import RiskResponseProjector
from consultation_kb.risk.resources import (
    ApprovedRegionalResource,
    RegionalResource,
    RegionalResourceCatalog,
)


NOW = datetime(2026, 7, 19, 11, 0, tzinfo=timezone.utc)
TURN_ID = "018f0000-0000-7000-8000-000000000401"


def _ref(kind: str, suffix: int) -> VersionRef:
    return VersionRef(
        object_id=f"{kind}_018f0000-0000-7000-8000-{suffix:012x}",
        version=1,
        content_sha256=f"{suffix % 16:x}" * 64,
    )


def _observation(level: Literal["general", "high"]) -> InternalRiskObservation:
    suffix = 1 if level == "general" else 2
    return InternalRiskObservation(
        observation_id=f"risk_observation_018f0000-0000-7000-8000-{suffix:012x}",
        category=f"synthetic_{level}_observation",
        level=level,
        trigger_turn_ids=(TURN_ID,),
        rule_ref=_ref("risk_rule", suffix),
        detected_at=NOW,
        suggested_questions=(f"SYNTH-{level.upper()}-VERIFY",),
    )


def _candidate(text: str = "我想先确认一下：你现在是否安全？") -> ClientReplyCandidate:
    return ClientReplyCandidate(
        candidate_id="gentle_candidate",
        label="温和确认",
        strategy="gentle_empathy",
        text=text,
        core_positions=("respect_autonomy",),
        action_directions=("maintain_conversation",),
    )


def _normalized_fingerprint(value: str) -> tuple[int, str]:
    normalized = unicodedata.normalize("NFKD", value).casefold()
    searchable = "".join(
        char
        for char in normalized
        if unicodedata.category(char) != "Cf"
        and not unicodedata.category(char).startswith(("M", "P", "Z"))
        and not char.isspace()
    )
    return len(searchable), hashlib.sha256(searchable.encode("utf-8")).hexdigest()


def test_projection_is_an_allowlist_with_no_internal_labels_or_trigger_text() -> None:
    catalog = RegionalResourceCatalog(
        (
            RegionalResource(
                resource_id="regional_resource_018f0000-0000-7000-8000-000000000403",
                status="approved",
                regions=("cn_shanghai",),
                public_text_ref=_ref("public_resource_text", 3),
                source_ref=_ref("public_resource_source", 4),
                reviewed_at=NOW - timedelta(days=1),
                review_expires_at=NOW + timedelta(days=1),
            ),
        )
    )
    goals = RiskResponseProjector.to_client_goals(
        (_observation("general"), _observation("high")),
        resource_catalog=catalog,
        region="cn_shanghai",
        as_of=NOW,
    )
    assert goals.goals == (
        "maintain_conversation",
        "ask_clarifying_question",
        "check_immediate_safety",
        "invite_real_world_support",
        "offer_reviewed_resource",
    )
    serialized = goals.model_dump_json()
    for forbidden in (
        "category",
        "level",
        "rule",
        "alert",
        "trigger",
        "synthetic_high_observation",
    ):
        assert forbidden not in serialized.lower()


def test_output_guard_allows_natural_safety_question_and_returns_original_object() -> None:
    candidate = _candidate()
    assert ClientReplyOutputGuard().validate(candidate) == candidate
    from_json_shape = ClientReplyOutputGuard().validate(candidate.model_dump(mode="json"))
    assert from_json_shape == candidate


@pytest.mark.parametrize(
    "leak",
    [
        "系统告警：请注意",
        "内部风险观察已触发",
        "风险等级：高",
        "triggered risk_level high",
        "命中了风险规则",
        "高关注信号",
        "synthetic_high_observation",
        "SYNTH-RISK-HIGH-7D1A",
    ],
)
def test_output_guard_blocks_internal_phrases_without_word_deletion(leak: str) -> None:
    candidate = _candidate(leak)
    with pytest.raises(ClientReplyLeakageError, match="CLIENT_REPLY_RISK_LEAKAGE"):
        ClientReplyOutputGuard().validate(candidate)
    assert candidate.text == leak


@pytest.mark.parametrize(
    "leak",
    [
        "风\ufe0f险等级：高",
        "風\ufe0f險等級：高",
        "risk_lev\u0301el: high",
    ],
)
def test_output_guard_blocks_variation_selector_and_combining_mark_bypasses(
    leak: str,
) -> None:
    with pytest.raises(ClientReplyLeakageError, match="CLIENT_REPLY_RISK_LEAKAGE"):
        ClientReplyOutputGuard().validate(_candidate(leak))


def test_output_guard_blocks_private_canary_and_non_allowlisted_shape() -> None:
    guard = ClientReplyOutputGuard(internal_canaries=("PRIVATE-TRIGGER-QUOTE-9F31",))
    with pytest.raises(ClientReplyLeakageError, match="CLIENT_REPLY_INTERNAL_CANARY"):
        guard.validate(_candidate("private-trigger-quote-9f31"))
    with pytest.raises(
        ClientReplyLeakageError, match="CLIENT_REPLY_SCHEMA_NOT_ALLOWLISTED"
    ):
        guard.validate({**_candidate().model_dump(), "risk": _observation("high")})

    forged = ClientReplyCandidate.model_construct(
        **{**_candidate().model_dump(), "text": 123}
    )
    with pytest.raises(
        ClientReplyLeakageError, match="CLIENT_REPLY_SCHEMA_NOT_ALLOWLISTED"
    ):
        guard.validate(forged)


def test_output_guard_blocks_bound_category_rule_and_internal_question_text() -> None:
    rule_ref = _ref("risk_rule", 99)
    guard = ClientReplyOutputGuard(
        internal_canaries=(
            "suicide_intent",
            rule_ref.object_id,
            rule_ref.content_sha256,
            "INTERNAL-QUESTION-VERIFY-EXACT",
        )
    )

    for leak in (
        "suicide_intent",
        rule_ref.object_id,
        rule_ref.content_sha256,
        "INTERNAL-QUESTION-VERIFY-EXACT",
    ):
        with pytest.raises(
            ClientReplyLeakageError,
            match="CLIENT_REPLY_INTERNAL_CANARY",
        ):
            guard.validate(_candidate(leak))


def test_output_guard_blocks_safe_identifier_separator_variants_only() -> None:
    observation_id = (
        "risk_observation_018f0000-0000-7000-8000-000000000099"
    )
    rule_id = "risk_rule_018f0000-0000-7000-8000-000000000099"
    natural_question = "Could you tell me whether you feel safe right now?"
    guard = ClientReplyOutputGuard(
        internal_canaries=(
            "suicide_intent",
            observation_id,
            rule_id,
            natural_question,
        )
    )

    for leak in (
        "suicide-intent",
        "suicide intent",
        observation_id.replace("_", " ").replace("-", " "),
        rule_id.replace("_", "-").replace("-", " "),
    ):
        with pytest.raises(
            ClientReplyLeakageError,
            match="CLIENT_REPLY_INTERNAL_CANARY",
        ):
            guard.validate(_candidate(leak))

    # Natural prose is not compacted as an identifier canary. Only an exact
    # copy remains forbidden; an independently phrased safety check is valid.
    assert guard.validate(_candidate("Are you safe at this moment?"))


def test_output_guard_blocks_every_category_from_the_real_risk_policy(
    tmp_path: Path,
) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    vault = tmp_path / "vault"
    vault.mkdir()
    policy = PolicyLoader.from_config(
        AppConfig.from_values(repo_root, vault)
    ).load_all().risk_rules.document
    categories = tuple(sorted({rule.category for rule in policy.rules}))
    guard = ClientReplyOutputGuard(internal_canaries=categories)

    assert "suicide_intent" in categories
    for category in categories:
        with pytest.raises(
            ClientReplyLeakageError,
            match="CLIENT_REPLY_INTERNAL_CANARY",
        ):
            guard.validate(_candidate(category))


def test_output_guard_blocks_only_labelled_bound_level_and_preserves_natural_word() -> None:
    guard = ClientReplyOutputGuard(internal_levels=("high",))

    assert guard.validate(_candidate("Your stress feels high right now."))
    for leak in ("risk_level=high", "level: high", "风险等级：高"):
        with pytest.raises(ClientReplyLeakageError):
            guard.validate(_candidate(leak))


def test_output_guard_blocks_exact_trigger_quote_from_body_free_fingerprint() -> None:
    trigger = "I want to kill myself"
    guard = ClientReplyOutputGuard(
        internal_span_fingerprints=(_normalized_fingerprint(trigger),)
    )

    with pytest.raises(ClientReplyLeakageError, match="CLIENT_REPLY_TRIGGER_QUOTE"):
        guard.validate(_candidate(f"You said: {trigger}. Are you safe now?"))
    assert guard.validate(_candidate("Are you safe right now?"))


@pytest.mark.parametrize(
    ("trigger", "variants"),
    [
        (
            "I want to kill myself",
            (
                "I WANT TO KILL MYSELF",
                "Ｉ　ｗａｎｔ　ｔｏ　ｋｉｌｌ　ｍｙｓｅｌｆ",
                "I\u200b want to kill myself",
                "I\u0001 want to kill myself",
                "I/want.to:kill_myself",
            ),
        ),
        (
            "café suicide",
            (
                "CAFE\u0301/SUICIDE",
                "café:suicide",
            ),
        ),
    ],
)
def test_output_guard_blocks_normalized_trigger_variants_from_body_free_fingerprint(
    trigger: str,
    variants: tuple[str, ...],
) -> None:
    guard = ClientReplyOutputGuard(
        internal_span_fingerprints=(_normalized_fingerprint(trigger),)
    )

    for variant in variants:
        with pytest.raises(
            ClientReplyLeakageError,
            match="CLIENT_REPLY_TRIGGER_QUOTE",
        ):
            guard.validate(_candidate(f"You said {variant}."))

    assert guard.validate(_candidate("Are you safe right now?"))


def test_output_guard_blocks_dynamic_canary_punctuation_and_hash_grouping_variants() -> None:
    category = "suicide_intent"
    digest = "a1" * 32
    suggested_question = "Confirm current intent, plan, means, and timeframe."
    source_kind = "deterministic_rule"
    turn_id = "018f0000-0000-7000-8000-000000000401"
    guard = ClientReplyOutputGuard(
        internal_canaries=(
            category,
            digest,
            suggested_question,
            source_kind,
            turn_id,
        )
    )

    for leak in (
        "suicide/intent",
        "suicide.intent",
        "suicide:intent",
        "-".join(digest[index : index + 8] for index in range(0, len(digest), 8)),
        "Confirm/current:intent.plan/means:and timeframe",
        "deterministic/rule",
        turn_id.replace("-", ":"),
    ):
        with pytest.raises(
            ClientReplyLeakageError,
            match="CLIENT_REPLY_INTERNAL_CANARY",
        ):
            guard.validate(_candidate(leak))

    assert guard.validate(_candidate("Could you tell me whether you feel safe now?"))


@pytest.mark.parametrize(
    "leak",
    (
        "source/kind",
        "trigger.turn.ids",
        "start:offset",
        "end offset",
        "span-sha256",
    ),
)
def test_output_guard_blocks_internal_risk_field_name_variants(leak: str) -> None:
    with pytest.raises(ClientReplyLeakageError, match="CLIENT_REPLY_RISK_LEAKAGE"):
        ClientReplyOutputGuard().validate(_candidate(leak))


def test_projector_cannot_trust_a_constructed_approved_resource_dto() -> None:
    forged = ApprovedRegionalResource(
        resource_id="regional_resource_018f0000-0000-7000-8000-000000000499",
        public_text_ref=_ref("public_resource_text", 99),
    )
    with pytest.raises(TypeError, match="RESOURCE_CATALOG_REQUIRED"):
        RiskResponseProjector.to_client_goals(
            (_observation("high"),),
            resource_catalog=forged,  # type: ignore[arg-type]
            region="cn_shanghai",
            as_of=NOW,
        )
