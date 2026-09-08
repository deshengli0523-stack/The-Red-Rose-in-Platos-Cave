from __future__ import annotations

import pytest

from consultation_kb.archive.deidentification import Deidentifier
from consultation_kb.models.cases import assert_shared_text_safe


def _deidentifier() -> Deidentifier:
    return Deidentifier(span_hash_key=b"synthetic-test-key-32-bytes-long!!")


def test_scan_and_transform_remove_direct_and_third_party_identifiers() -> None:
    text = (
        "姓名：张三，电话13800138000，邮箱zhang@example.com，"
        "身份证110105199001011234，住址：上海市浦东新区丁香路88号，"
        "单位：星海科技有限公司，日期2026年7月16日，同事叫李四，"
        "内部会谈号019f55c5-5e2c-7e20-bfe3-65480ce3bb0d。"
    )
    service = _deidentifier()

    scan = service.scan(text)
    transformed = service.transform(text, scan)

    categories = {item.category for item in scan.findings}
    assert {
        "person_name",
        "phone",
        "email",
        "national_id",
        "exact_address",
        "organization",
        "exact_date",
        "third_party_person",
        "internal_identifier",
    }.issubset(categories)
    report_json = scan.model_dump_json()
    for private_value in (
        "张三",
        "13800138000",
        "zhang@example.com",
        "110105199001011234",
        "上海市浦东新区丁香路88号",
        "星海科技有限公司",
        "李四",
        "019f55c5-5e2c-7e20-bfe3-65480ce3bb0d",
    ):
        assert private_value not in report_json
        assert private_value not in transformed.output_text
    assert transformed.requires_human_review is True
    assert len(transformed.applied_finding_hashes) == len(scan.findings)


def test_rare_location_occupation_family_and_time_combination_is_quarantinable() -> None:
    text = (
        "来自青海省某偏远县，职业：特殊设备潜水员，属于单亲家庭，"
        "事件发生于2026年7月16日。"
    )
    service = _deidentifier()

    scan = service.scan(text)
    transformed = service.transform(text, scan)

    assert len(scan.rare_combinations) == 1
    assert scan.rare_combinations[0].categories == frozenset(
        {"rare_location", "occupation", "family_structure", "exact_date"}
    )
    assert transformed.unresolved_rare_combination_hashes == (
        scan.rare_combinations[0].combination_hmac_sha256,
    )
    assert "青海省某偏远县" not in transformed.output_text
    assert "特殊设备潜水员" not in transformed.output_text


def test_common_relationship_roles_and_intervention_sequence_are_preserved() -> None:
    text = "来访者先谈到男朋友，再讨论母亲；咨询师先澄清目标，再梳理边界。"
    service = _deidentifier()

    scan = service.scan(text)
    transformed = service.transform(text, scan)

    assert scan.findings == ()
    assert transformed.output_text == text
    assert "男朋友" in transformed.output_text
    assert "母亲" in transformed.output_text
    assert "先澄清目标，再梳理边界" in transformed.output_text


def test_transform_rejects_scan_for_different_text() -> None:
    service = _deidentifier()
    scan = service.scan("电话13800138000")

    with pytest.raises(ValueError, match="does not bind"):
        service.transform("电话13900139000", scan)


def test_transform_rejects_tampered_scan_that_omits_a_finding() -> None:
    service = _deidentifier()
    text = "姓名：张三，住址：上海市浦东新区丁香路88号。"
    scan = service.scan(text)
    tampered = scan.model_copy(update={"findings": ()})

    with pytest.raises(ValueError, match="authoritative rescan"):
        service.transform(text, tampered)


@pytest.mark.parametrize(
    ("text", "secret"),
    (
        (
            "住址：北京市朝阳区望京路13800138000号，其他信息已泛化。",
            "北京市朝阳区望京路13800138000号",
        ),
        (
            "单位：contact@example.com科技有限公司，其他信息已泛化。",
            "contact@example.com科技有限公司",
        ),
    ),
)
def test_overlapping_identifier_is_removed_with_the_broader_private_span(
    text: str,
    secret: str,
) -> None:
    service = _deidentifier()

    scan = service.scan(text)
    transformed = service.transform(text, scan)

    assert secret not in transformed.output_text
    assert all(
        current.start >= previous.end
        for previous, current in zip(scan.findings, scan.findings[1:], strict=False)
    )


@pytest.mark.parametrize(
    "text",
    (
        "内部编号client_\u200baaaaaaaaaaaa",
        "电话：１３８００１３８０００",
        "邮箱：ｔｅｓｔ＠ｅｘａｍｐｌｅ．ｃｏｍ",
    ),
)
def test_nfkc_and_format_control_obfuscation_is_still_removed(text: str) -> None:
    service = _deidentifier()

    scan = service.scan(text)
    transformed = service.transform(text, scan)

    assert scan.findings
    assert transformed.output_text != text
    assert "\u200b" not in transformed.output_text


def test_repeated_identifier_occurrences_have_distinct_report_hashes() -> None:
    service = _deidentifier()
    text = "第一次电话13800138000，第二次仍是13800138000。"

    scan = service.scan(text)
    transformed = service.transform(text, scan)

    assert len(scan.findings) == 2
    assert len(set(transformed.applied_finding_hashes)) == 2
    assert "13800138000" not in transformed.output_text


@pytest.mark.parametrize(
    "text",
    (
        "client_\u200baaaaaaaaaaaa",
        "ｃｌｉｅｎｔ＿ａａａａａａａａａａａａ",
        "电话１３８００１３８０００",
        "邮箱ｔｅｓｔ＠ｅｘａｍｐｌｅ．ｃｏｍ",
        "＂逐字引用＂",
    ),
)
def test_shared_text_guard_rejects_normalization_obfuscation(text: str) -> None:
    with pytest.raises(ValueError):
        assert_shared_text_safe(text)
