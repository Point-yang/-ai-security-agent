"""A local field gap must never become a claim about an entire source."""

from types import SimpleNamespace

import pytest

from zhidu.answers import source_constraints, structured_constraints


def enrichment(flags):
    return SimpleNamespace(
        schema_version="test-structured",
        quality_flags=flags,
        cvss={"selected": None, "entries": []},
        cpe_matches=[],
    )


@pytest.mark.parametrize(
    ("flag", "unsupported_statement", "protected_boundary"),
    [
        ("missing_affected_scope", "当前来源缺少", "版本是否受影响"),
        ("missing_cpe_scope", "当前 NVD 记录缺少", "产品或资产不受影响"),
        ("missing_cvss", "当前来源没有", "零分或无风险"),
        ("unknown_package_identity", "来源中的软件包身份未知", "真实组件名"),
        ("metadata_only", "论文记录只有元数据", "读取或验证论文全文"),
        ("catalog_scope_only", "不提供完整影响版本范围", "完整影响版本范围"),
    ],
)
def test_quality_flags_describe_conditional_local_boundaries(
    flag, unsupported_statement, protected_boundary
):
    rules = {rule["code"]: rule["rule"] for rule in structured_constraints(enrichment([flag]))}
    notice = rules[flag]
    assert notice.startswith("若本")
    assert unsupported_statement not in notice
    assert protected_boundary in notice
    assert "不能据此断言" in notice or "不能断言" in notice
    # The warning itself cannot be promoted to an uncited fact in limitations.
    assert "limitations" in rules["constraint_usage"]
    assert "未经引用支持的缺失事实" in rules["constraint_usage"]


def test_nvd_notice_does_not_assert_a_gap_when_fields_are_available():
    # Generic source notices are emitted even when this record has the fields.
    normalized = {
        "cvss": {"score": 9.8},
        "packages": [{"name": "vllm", "vulnerable_version_range": "< 0.8.5"}],
        "nvd": {"configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True}]}]}]},
    }
    rules = {
        rule["code"]: rule["rule"]
        for rule in source_constraints("nvd", "vulnerability", normalized)
    }
    assert "若 CPE 或版本范围缺失或未解析" in rules["nvd_unparsed_scope"]
    assert "不得据此推断产品或资产不受影响" in rules["nvd_unparsed_scope"]
    assert "CVSS 不能替代影响范围证据" in rules["nvd_unparsed_scope"]
    assert "missing_cvss" not in rules
    assert "missing_cpe_scope" not in rules


def test_missing_enrichment_does_not_mean_missing_source_data():
    rules = {rule["code"]: rule["rule"] for rule in structured_constraints(None)}
    notice = rules["structured_data_unavailable"]
    assert "本次未载入" in notice
    assert "本轮已读取并引用" in notice
    assert "这不表示来源缺少相应信息" in notice
    assert "constraint_usage" in rules


@pytest.mark.parametrize("source_id", ["crossref", "other-paper-provider"])
def test_paper_boundary_never_implies_full_text_was_read_or_unavailable(source_id):
    rules = {
        rule["code"]: rule["rule"]
        for rule in source_constraints(source_id, "paper", {"publication_precision": "month"})
    }
    notice = rules["metadata_only"]
    assert "若本轮证据仅包含论文元数据" in notice
    assert "不能声称已读取或验证论文全文" in notice
    assert "不能据此断言全文不存在或无法公开获取" in notice
    assert "month" in rules["publication_precision"]


def test_combined_notices_remain_valid_for_sources_with_different_field_coverage():
    # Consumers deduplicate constraints by code across retrieved sources. A gap
    # from one source therefore has to stay conditional when another has CVSS.
    missing = structured_constraints(enrichment(["missing_cvss"]))
    present = enrichment([])
    present.cvss = {"selected": {"score": 9.8}, "entries": [{"score": 9.8}]}
    merged = {rule["code"]: rule for rule in missing + structured_constraints(present)}
    assert merged["missing_cvss"]["rule"].startswith("若本次")
    assert "不能断言来源没有评分" in merged["missing_cvss"]["rule"]
    assert "selected_cvss_display_only" in merged
