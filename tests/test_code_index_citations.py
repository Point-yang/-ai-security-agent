"""Real indexed expressions are source facts, not model-authored citations."""

import pytest

from zhidu.agent_state import AgentAnswer
from zhidu.grounded_answer import contains_written_citation, evidence_id, render_answer


def candidate(text, handle):
    return AgentAnswer.model_validate(
        {
            "answer_class": "evidence",
            "statements": [{"text": text, "evidence": [{"evidence_id": handle}]}],
            "required_facts": ["索引缺少边界检查"],
            "missing_facts": [],
            "limitations": [],
            "message": "",
        }
    )


@pytest.mark.parametrize(
    "text",
    [
        "B_shape[1] 没有检查 rank。",
        "`B_shape[1]` 和 `A_shape[0]` 缺少 rank 检查。",
        "tensor[1][2] 访问存在边界条件。",
        "`[1]` 是输入数组，而不是来源编号。",
    ],
)
def test_code_indices_keep_their_verified_source_quote(text):
    citation = {
        "external_id": "example",
        "field": "description",
        "source_id": "github-advisories",
        "text": "The adapter accesses B_shape[1] and A_shape[0] without checking rank.",
    }
    handle = evidence_id(citation)
    result = render_answer(candidate(text, handle), {handle: citation})
    assert result["generated_claims"][0]["text"] == text
    assert result["generated_claims"][0]["evidence"][0]["quote"] == citation["text"]
    assert result["answer"].endswith("[1]")


@pytest.mark.parametrize(
    "text", ["源码指出缺少检查[1]。", "源码指出缺少检查 [2]。", "[1] 缺少检查。"]
)
def test_authored_reference_numbers_still_fail(text):
    citation = {
        "external_id": "example",
        "field": "description",
        "source_id": "github-advisories",
        "text": "The adapter accesses B_shape[1] without checking rank.",
    }
    handle = evidence_id(citation)
    with pytest.raises(ValueError, match="invalid_claim_text"):
        render_answer(candidate(text, handle), {handle: citation})


@pytest.mark.parametrize(
    "text",
    [
        "PoC 的输入 B 形状为 [28]（1 维），B_shape 只有 1 个元素，访问 B_shape[1] 会读取 std::vector<Dimension> 内部存储之后 16 字节的相邻堆内存；同样的未检查模式也适用于第 34、36 行的 A_shape[0] 和 A_shape[1]。",
        "输入 B 的形状是 [28]。",
        "输入B形状为[28]。",
        "B 的形状为：[28]（一维）。",
        "The input B shape is [28] and B_shape[1] accesses a second dimension.",
        "The shape = [28] represents one dimension.",
        "The shape: [28] represents one dimension.",
        "The shape is: [28] represents one dimension.",
        "B_shape = [28] describes a one-dimensional input.",
        "B.shape: [28] describes a one-dimensional input.",
        "shape = [ 28 ] and B_shape[ 1 ] are technical notation.",
        "shape = [-1] uses a symbolic dimension size.",
        "shape = [28]; A_shape = [1] are explicit assignments.",
        "shape = `[28]` is a code literal.",
    ],
)
def test_explicit_single_integer_shape_literal_preserves_candidate_and_quote(text):
    citation = {
        "external_id": "example",
        "field": "description",
        "source_id": "github-advisories",
        "text": "The input B has shape [28], and B_shape[1] is accessed without a rank check.",
    }
    handle = evidence_id(citation)
    original = candidate(text, handle)
    before = original.model_dump()
    assert contains_written_citation(text) is False
    result = render_answer(original, {handle: citation})
    assert original.model_dump() == before
    assert result["generated_claims"][0]["text"] == text
    assert result["generated_claims"][0]["evidence"][0]["quote"] == citation["text"]
    assert result["answer"].endswith(" [1]")


@pytest.mark.parametrize(
    "text",
    [
        "shape is [28]，来源说明越界 [1]。",
        "shape is [28][1]。",
        "形状为 [28]（一维），详见 [2]。",
        "形状为 [28]，参考来源[1]。",
        "shape = `[28]` [1]",
        "shape is `[28]`[1]",
        "PoC 的输入 B 为 [28]。",
        "输入数组为 [28]。",
        "[28] 是输入数组。",
        "数组 [ 28 ] 是一维输入。",
        "array = [-1] uses a symbolic dimension.",
        "shape_count = [28] is not a shape assignment.",
        "shape is unavailable; the source [1] describes it.",
        "shape= is not known, according to [1].",
        "The shape is discussed in the source [1].",
    ],
)
def test_shape_word_does_not_exempt_unrelated_or_bare_authored_marker(text):
    citation = {
        "external_id": "example",
        "field": "description",
        "source_id": "github-advisories",
        "text": "The input has shape [28].",
    }
    handle = evidence_id(citation)
    assert contains_written_citation(text) is True
    with pytest.raises(ValueError, match="invalid_claim_text"):
        render_answer(candidate(text, handle), {handle: citation})
