"""Pattern-scope regression; actual claim entailment is reviewed separately."""

import pytest

from zhidu.agent_state import AgentAnswer
from zhidu.grounded_answer import (
    CONTRACT_VERSION,
    has_unquoted_source_absence,
    render_answer,
)

HANDLE = "a" * 24
EVIDENCE = {
    HANDLE: {"text": "This source recommends reading the scoped evidence.", "source_id": "nvd"}
}


def candidate(limitation):
    return AgentAnswer.model_validate(
        {
            "answer_class": "partial",
            "statements": [
                {
                    "text": "该片段建议阅读适用范围内的证据。",
                    "evidence": [{"evidence_id": HANDLE}],
                }
            ],
            "required_facts": ["来源声明", "问题要求的修复字段"],
            "missing_facts": ["本轮尚缺问题要求的修复字段证据"],
            "limitations": [limitation],
            "message": "",
        }
    )


@pytest.mark.parametrize(
    "limitation",
    [
        "NVD 来源片段仅含 CVE 编号与描述字段，未提供 affectedData 版本范围或首次修复版本字段。",
        "本轮返回的 NVD 片段没有 CPE 条件。",
        "NVD 来源摘录未包含 CVSS 字段。",
        "当前检索片段尚未提供修复字段。",
        "本轮返回的 NVD 字段未检索到 CVSS 评分。",
        "NVD 来源片段只覆盖编号，未返回 CVSS，也未返回 CPE。",
        "The retrieved source snippets contain no CVSS score.",
        "The source excerpts contain no CPE, and no CVSS.",
        "No CVSS score is available in the retrieved source snippets.",
        "No CPE condition was found in the current source excerpts.",
        "No CVSS score is available in the retrieved NVD source snippets.",
        "本轮检索片段未包含公开 PoC。",
        "本轮 NVD 片段只涉及版本 1.2.0，未返回修复字段。",
        "本轮提供的 NVD 片段仅含 affectedData 的 source、product 与 versions 字段，未包含 first_patched_version 字段。",
        "本轮提供的 GitHub 与 NVD 片段未包含凭据泄露或服务端请求（SSRF）相关限制的原文。",
        "本轮提供的 GitHub 与 NVD 片段未包含 load()/loads() 推荐信任与 allowlist 边界的明确原文表述。",
        "本轮 NVD 片段仅含来源、产品与版本字段，未包含修复字段。",
        "本轮提供的 NVD 片段仅含 source、product、versions 字段，未包含 CVSS 字段。",
        "本轮提供的 NVD 片段包含字段 source、product、versions，未包含 CPE。",
        "本轮 NVD 片段仅含 `source`、`product` 与 `versions` 字段，未包含修复字段。",
        "本轮 NVD 片段仅含 ‘source’、‘product’ 与 ‘versions’ 字段，未包含修复字段。",
        '本轮 NVD 片段仅含 "source"、"product" 与 "versions" 字段，未包含修复字段。',
        "本轮 NVD 片段仅含“来源”、“产品”与“版本”字段，未包含修复字段。",
        "本轮 NVD 片段仅含 `source`，未包含修复字段。",
        "The provided NVD snippets contain source, product and versions fields, no first_patched_version is available.",
        'The returned NVD snippets contain "source", "product" and "versions" keys, no CVSS score is available.',
        "The provided NVD snippets contain fields: source, product, versions, no CPE condition is available.",
        "The provided NVD snippets contain affectedData.source, no CVSS score is available.",
        "本轮提供的 NVD 片段未包含 first_patched_version 字段。",
        "本轮提供的 NVD 片段未提供 CVSS 字段。",
        "当前返回的 NVD 片段未包含 CPE 字段。",
        "The provided NVD source snippets contain no CVSS fields.",
        "The provided NVD snippets contain fields product and source, no CVSS is available.",
        "The provided NVD snippets contain product and source fields, no CVSS is available.",
    ],
)
def test_explicit_returned_excerpt_scope_is_allowed_without_editing_candidate(limitation):
    original = candidate(limitation)
    before = original.model_dump()
    rendered = render_answer(original, EVIDENCE)
    assert CONTRACT_VERSION == "source-answer-v10"
    assert has_unquoted_source_absence(limitation) is False
    assert rendered["answer_class"] == "partial"
    assert limitation in rendered["answer"]
    assert rendered["generated_claims"][0]["evidence"][0]["quote"] == EVIDENCE[HANDLE]["text"]
    assert len(rendered["generated_claims"]) == 1
    assert original.model_dump() == before


@pytest.mark.parametrize(
    "limitation",
    [
        "当前 NVD 记录缺少 CPE 条件。",
        "来源没有可用 CVSS。",
        "NVD 未发布 CVSS 评分。",
        "No CVSS score is available in the source.",
        "The sources have no CVSS score.",
        "来源没有 CVSS（本轮片段）。",
        "NVD 未提供 CPE，附注：仅讨论本轮片段。",
        "NVD 来源片段未含 CVSS，整个来源没有公开资料。",
        "本轮 NVD 片段未含 CPE，但 NVD 没有 CVSS。",
        "本轮返回片段没有 CVSS，因此不存在公开资料。",
        "NVD 来源片段未返回修复字段；NVD 未公布修复版本。",
        "NVD 来源片段没有 CPE。来源没有 CVSS。",
        "NVD 来源片段没有 CPE。不存在公开资料。",
        "NVD source snippets have no CPE; no public data is available.",
        "The current NVD excerpts contain no CPE. No CVSS is available in the source.",
        "The current NVD excerpts contain no CPE.No public information is available.",
        "NVD来源片段未返回CPE，来源没有CVSS和修复字段。",
        "NVD来源片段未返回CPE且整个来源没有CVSS。",
        "NVD 来源片段没有 CVSS 并且不存在公开资料。",
        "本轮 NVD 片段没有 CPE 以及没有公开资料。",
        "The source snippets have no CPE and no public information is available.",
        "No CVSS score is available in the source (current excerpt only).",
        "No CVSS score is available in the source (in current source excerpts).",
        "The NVD source lacks CVSS (in current source excerpts).",
        "NVD 来源没有 CVSS（本轮返回的来源片段）。",
        "来源没有公开资料。当前返回片段未提供CPE。",
        "不存在公开资料；本轮返回片段没有CPE。",
        "本轮 NVD 片段仅含 source、product 与 versions 字段，来源没有 CVSS。",
        "本轮 NVD 片段仅含 source、product 与 versions 字段，不存在公开资料。",
        "本轮 NVD 片段仅含 source、product 与 versions 字段；NVD 未发布 CVSS。",
        '本轮 NVD 片段仅含 "source"、"product" 字段，"source" 没有 CVSS。',
        "本轮 NVD 片段仅含 `source`、`product` 字段，`source` 缺少 CPE。",
        "本轮 NVD 片段仅含“来源”、“产品”字段，“来源”没有 CVSS。",
        "本轮 NVD 片段仅含 source、product字段，但整个来源没有公開数据和 CVSS。",
        "The provided NVD excerpts contain fields source, product, source has no CVSS score.",
        'The provided NVD excerpts contain "source" and "product" fields; "source" has no CVSS.',
        "The provided NVD excerpts contain `source` and `product` fields, no public data is available.",
        "The provided NVD excerpts contain affectedData.source; source has no CVSS.",
        "The source has no CVSS field.",
        'The "source" has no CVSS field.',
        '"source": "No CVSS is available."',
        "The NVD fields have no CVSS score.",
        "The source field has no CVSS score.",
        "NVD 来源片段只包含编号。NVD 字段没有 CVSS。",
        "本轮 NVD 片段只含 source、product字段，NVD字段没有 CVSS。",
    ],
)
def test_whole_source_or_unqualified_public_absence_cannot_borrow_excerpt_scope(limitation):
    original = candidate(limitation)
    before = original.model_dump()
    assert has_unquoted_source_absence(limitation) is True
    with pytest.raises(ValueError, match="unquoted_source_absence"):
        render_answer(original, EVIDENCE)
    assert original.model_dump() == before


def test_limitations_do_not_share_scope_between_list_items():
    original = candidate("本轮 NVD 返回片段没有 CPE。")
    original.limitations.append("No CVSS score is available in the source.")
    with pytest.raises(ValueError, match="unquoted_source_absence"):
        render_answer(original, EVIDENCE)
