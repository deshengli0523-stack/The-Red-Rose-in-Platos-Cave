from __future__ import annotations

import pytest

from consultation_kb.retrieval.normalization import (
    ApprovedAliasDictionary,
    ChineseTokenizer,
    NormalizationError,
    normalize_text,
)


def test_nfkc_and_boundaries_are_stable_without_script_rewriting() -> None:
    assert normalize_text("  ＡＢＣ　《中庸》\t至善！ ") == "ABC 中庸 至善"
    assert normalize_text("后 後") == "后 後"
    assert normalize_text("乾、坤；仁义") == "乾 坤 仁义"


def test_only_approved_aliases_expand_ancient_and_modern_forms() -> None:
    aliases = ApprovedAliasDictionary(
        {"心即理": ("心外无理",), "王守仁": ("王阳明",)}
    )
    tokenizer = ChineseTokenizer(aliases)

    assert aliases.expansions("王阳明主张心即理") == ("心外无理", "王守仁")
    assert "王守仁" in tokenizer.word_tokens("王阳明")
    assert ApprovedAliasDictionary().expansions("后與後") == ()


def test_alias_dictionary_rejects_nfkc_collisions() -> None:
    with pytest.raises(NormalizationError, match="NORMALIZATION_INPUT_INVALID"):
        ApprovedAliasDictionary({"Ａ": ("alpha",), "A": ("letter-a",)})


@pytest.mark.parametrize("value", ["", "\x00", "a\x01b", "x" * 16_385])
def test_normalization_rejects_empty_control_or_overlong_input(value: str) -> None:
    with pytest.raises(NormalizationError, match="NORMALIZATION_INPUT_INVALID"):
        normalize_text(value)
