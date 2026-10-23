"""Exact question/prose binding and independent support/completeness acceptance."""

import copy

import pytest

from zhidu.agent_requirements import (
    coverage_ledger,
    normalize_plan,
    normalize_verification,
    reviewed_candidate,
    verifier_packet,
)
from zhidu.agent_state import AgentAnswer
from zhidu.agent_team_state import ResearchDecision, TaskPlan, VerifierOutput

GH, NVD = "a" * 24, "b" * 24
EVIDENCE = {
    GH: {
        "text": "Only applications accepting untrusted input and reviving trusted objects are exposed.",
        "source_id": "github-advisories",
    },
    NVD: {"text": "The description identifies this deserialization condition.", "source_id": "nvd"},
}


def task_plan(question, *, policy="any", elements=None):
    return TaskPlan.model_validate(
        {
            "tasks": [
                {
                    "task_id": "conditions",
                    "requirement": "应用暴露条件",
                    "source_ids": ["github-advisories", "nvd"],
                    "fields": ["description"],
                    "keywords": [],
                    "question_spans": [{"quote": question}],
                    "source_policy": policy,
                    "required_elements": elements or ["同时必要的暴露条件"],
                }
            ]
        }
    )


def answer(text="GitHub 公告的条件是接受不可信输入且复原可信对象。", refs=None):
    return AgentAnswer.model_validate(
        {
            "answer_class": "evidence",
            "statements": [
                {"text": text, "evidence": [{"evidence_id": handle} for handle in (refs or [GH])]}
            ],
            "required_facts": ["应用暴露条件"],
            "missing_facts": [],
            "limitations": [],
            "message": "",
        }
    )


def review(candidate, *, spans=True, elements=None):
    bindings = (
        [
            {"statement_index": index, "text": claim.text}
            for index, claim in enumerate(candidate.statements, 1)
        ]
        if spans
        else []
    )
    return VerifierOutput.model_validate(
        {
            "coverage": [
                {
                    "task_id": "conditions",
                    "status": "covered",
                    "statement_indices": [binding["statement_index"] for binding in bindings],
                    "answer_spans": bindings,
                    "element_coverage": [
                        {"element": element, "status": "covered", "answer_spans": bindings}
                        for element in (elements or ["同时必要的暴露条件"])
                    ],
                    "note": "AI判断正文表达且引文支持",
                }
            ],
            "claim_support": [
                {"statement_index": index, "status": "supported", "reason": "自身引文支持本句"}
                for index in range(1, len(candidate.statements) + 1)
            ],
            "unplanned_requirements": [],
            "gaps": [],
        }
    )


def test_question_span_is_bound_exactly_and_ambiguous_fragment_requires_offset():
    question = "比较条件，并说明条件。"
    plan = task_plan(question)
    normalized = normalize_plan(question, plan)
    assert normalized.tasks[0].question_spans[0].start == 0
    assert normalized.tasks[0].question_spans[0].end == len(question)
    payload = plan.model_dump()
    payload["tasks"][0]["question_spans"] = [{"quote": "条件"}]
    with pytest.raises(ValueError, match="invalid_task_question_span"):
        normalize_plan(question, TaskPlan.model_validate(payload))
    payload["tasks"][0]["question_spans"] = [{"quote": "条件", "start": 2, "end": 4}]
    assert (
        normalize_plan(question, TaskPlan.model_validate(payload)).tasks[0].question_spans[0].start
        == 2
    )


def test_plan_cannot_bind_a_requirement_to_invented_question_text():
    plan = task_plan("CVSS 评分")
    with pytest.raises(ValueError, match="invalid_task_question_span"):
        normalize_plan("说明应用暴露条件。", plan)


def test_oversized_offset_does_not_pass_python_slice_truncation():
    question = "说明条件"
    payload = task_plan(question).model_dump()
    payload["tasks"][0]["question_spans"] = [{"quote": question, "start": 0, "end": 999}]
    with pytest.raises(ValueError, match="invalid_task_question_span"):
        normalize_plan(question, TaskPlan.model_validate(payload))


def test_any_source_keeps_supported_github_claim_without_requiring_nvd_duplicate():
    question = "说明应用暴露必须同时满足的条件。"
    plan, candidate = task_plan(question), answer()
    verdict = normalize_verification(question, plan, candidate, review(candidate), EVIDENCE)
    approved = reviewed_candidate(plan, candidate, verdict, question=question, evidence=EVIDENCE)
    assert approved.answer_class == "evidence"
    assert approved.statements == candidate.statements
    assert verdict.unsupported == []
    assert verdict.coverage[0].answer_spans[0].start == 0


@pytest.mark.parametrize("source_id", [None, "", "   "])
def test_any_without_requested_source_ids_still_requires_real_source_metadata(source_id):
    question, candidate = "说明应用暴露条件。", answer()
    payload = task_plan(question).model_dump()
    payload["tasks"][0]["source_ids"] = []
    evidence = copy.deepcopy(EVIDENCE)
    evidence[GH]["source_id"] = source_id
    normalized = normalize_verification(
        question, TaskPlan.model_validate(payload), candidate, review(candidate), evidence
    )
    assert normalized.coverage[0].status == "partial"
    assert (
        reviewed_candidate(
            TaskPlan.model_validate(payload),
            candidate,
            normalized,
            question=question,
            evidence=evidence,
        ).statements
        == candidate.statements
    )


def test_each_source_missing_nvd_is_partial_not_an_unsupported_github_claim():
    question = "分别说明 GitHub 与 NVD 的应用暴露条件。"
    plan, candidate = task_plan(question, policy="each"), answer()
    verdict = normalize_verification(question, plan, candidate, review(candidate), EVIDENCE)
    approved = reviewed_candidate(plan, candidate, verdict, question=question, evidence=EVIDENCE)
    assert approved.answer_class == "partial"
    assert approved.statements == candidate.statements
    assert verdict.unsupported == [] and verdict.coverage[0].status == "partial"
    assert verdict.gaps[0].source_id == "nvd"


def test_quote_containing_untrusted_scope_does_not_replace_natural_language_answer():
    question = "说明应用暴露范围。"
    plan = task_plan(question, elements=["使用不可信输入的应用范围"])
    candidate = answer("公告描述一个复原入口。")
    verdict = review(candidate, spans=False, elements=["使用不可信输入的应用范围"])
    normalized = normalize_verification(question, plan, candidate, verdict, EVIDENCE)
    approved = reviewed_candidate(plan, candidate, normalized, question=question, evidence=EVIDENCE)
    assert normalized.coverage[0].status == "partial"
    assert approved.answer_class == "partial" and approved.statements == candidate.statements
    assert approved.missing_facts


def test_verifier_span_must_occur_in_candidate_not_only_its_quote():
    question = "说明应用暴露范围。"
    candidate = answer("公告描述一个复原入口。")
    payload = review(candidate).model_dump()
    fake = {"statement_index": 1, "text": "untrusted input"}
    payload["coverage"][0]["answer_spans"] = [fake]
    with pytest.raises(ValueError, match="invalid_verifier_answer_span"):
        normalize_verification(
            question,
            task_plan(question),
            candidate,
            VerifierOutput.model_validate(payload),
            EVIDENCE,
        )


def test_verifier_independently_reports_unanswered_original_requirement_omitted_by_plan():
    question = "说明应用暴露条件，并说明信任边界。"
    plan = task_plan("说明应用暴露条件")
    candidate = answer()
    payload = review(candidate).model_dump()
    payload["unplanned_requirements"] = [
        {
            "requirement": "说明信任边界",
            "question_span": {"quote": "说明信任边界"},
            "reason": "原问题明确要求但当前正文尚未回答",
        }
    ]
    verdict = VerifierOutput.model_validate(payload)
    approved = reviewed_candidate(plan, candidate, verdict, question=question, evidence=EVIDENCE)
    assert approved.answer_class == "partial" and approved.statements == candidate.statements
    assert "说明信任边界" in approved.required_facts and "说明信任边界" in approved.missing_facts
    ledger = coverage_ledger(plan, candidate, verdict, question=question, evidence=EVIDENCE)
    assert ledger["complete"] is False
    assert ledger["unplanned_requirements"][0]["question_span"]["start"] == question.index(
        "说明信任边界"
    )
    packet = verifier_packet(question, plan, candidate, EVIDENCE)
    assert packet["question"] == question
    assert packet["question_must_be_reviewed_independently_of_plan"] is True


def test_omission_cannot_invent_an_unasked_field():
    question, candidate = "说明应用暴露条件。", answer()
    payload = review(candidate).model_dump()
    payload["unplanned_requirements"] = [
        {"requirement": "CVSS", "question_span": {"quote": "CVSS"}, "reason": "编造要求"}
    ]
    with pytest.raises(ValueError, match="invalid_omitted_question_span"):
        normalize_verification(
            question,
            task_plan(question),
            candidate,
            VerifierOutput.model_validate(payload),
            EVIDENCE,
        )


def test_each_accepts_separate_source_answers_but_compare_needs_one_claim_quoting_both():
    question = "分别解释两个来源并对照差异。"
    candidate = answer()
    candidate.statements.append(answer("NVD 描述反序列化条件。", refs=[NVD]).statements[0])
    each = task_plan(question, policy="each")
    comparison = task_plan(question, policy="compare")
    assert (
        normalize_verification(question, each, candidate, review(candidate), EVIDENCE)
        .coverage[0]
        .status
        == "covered"
    )
    assert (
        normalize_verification(question, comparison, candidate, review(candidate), EVIDENCE)
        .coverage[0]
        .status
        == "partial"
    )
    cross = answer("GitHub 与 NVD 对条件采用不同表述。", refs=[GH, NVD])
    assert (
        normalize_verification(question, comparison, cross, review(cross), EVIDENCE)
        .coverage[0]
        .status
        == "covered"
    )


def test_final_statement_mapping_keeps_supported_claims_and_drops_only_unsupported():
    question = "说明应用暴露条件。"
    candidate = answer()
    candidate.statements.extend(
        [answer("错误结论").statements[0], answer("另一条正确结论").statements[0]]
    )
    payload = review(candidate).model_dump()
    payload["claim_support"][1].update(status="unsupported", reason="本句自己引文不支持")
    verdict = VerifierOutput.model_validate(payload)
    ledger = coverage_ledger(
        task_plan(question), candidate, verdict, question=question, evidence=EVIDENCE
    )
    assert ledger["final_statement_index_map"] == {"1": 1, "3": 2}
    assert ledger["tasks"][0]["final_statement_indices"] == [1, 2]
    approved = reviewed_candidate(
        task_plan(question), candidate, verdict, question=question, evidence=EVIDENCE
    )
    assert [claim.text for claim in approved.statements] == [
        candidate.statements[0].text,
        candidate.statements[2].text,
    ]


def test_bounded_answer_display_does_not_silently_drop_ninth_requirement():
    question = "一二三四五六七八九"
    candidate = answer()
    candidate.required_facts = [f"原需求{index}" for index in range(8)]
    payload = review(candidate).model_dump()
    payload["unplanned_requirements"] = [
        {"requirement": "第九个需求", "question_span": {"quote": "九"}, "reason": "未答"}
    ]
    approved = reviewed_candidate(
        task_plan(question),
        candidate,
        VerifierOutput.model_validate(payload),
        question=question,
        evidence=EVIDENCE,
    )
    assert len(approved.required_facts) == 8
    assert "第九个需求" in "；".join(approved.required_facts)


def test_batch_schema_is_bounded_and_cannot_mix_ready_or_single_calls():
    request = {"tool_name": "read_fields", "arguments": {"fields": ["description"]}, "task_ids": []}
    data = {
        "action": "batch",
        "requests": [request, copy.deepcopy(request)],
        "task_ids": [],
        "note": "定点补查",
    }
    assert len(ResearchDecision.model_validate(data).requests) == 2
    with pytest.raises(ValueError):
        ResearchDecision.model_validate({**data, "requests": [request] * 4})
    with pytest.raises(ValueError, match="ready_cannot_call_tool"):
        ResearchDecision.model_validate({**data, "action": "ready"})
    with pytest.raises(ValueError, match="single_tool_cannot_contain_batch"):
        ResearchDecision.model_validate({**data, "action": "tool", "tool_name": "read_fields"})


def test_compact_element_reference_expands_exact_task_prose_and_normalizes_twice():
    question, candidate = "说明应用暴露条件。", answer()
    payload = review(candidate).model_dump()
    element = payload["coverage"][0]["element_coverage"][0]
    element.pop("answer_spans")
    element["answer_span_indices"] = [1]
    compact = VerifierOutput.model_validate(payload)
    normalized = normalize_verification(question, task_plan(question), candidate, compact, EVIDENCE)
    expanded = normalized.coverage[0].element_coverage[0]
    assert expanded.answer_span_indices == []
    assert expanded.answer_spans[0] == normalized.coverage[0].answer_spans[0]
    assert expanded.answer_spans[0].text == candidate.statements[0].text
    assert expanded.answer_spans[0].start == 0
    assert (
        normalize_verification(question, task_plan(question), candidate, normalized, EVIDENCE)
        == normalized
    )
    ledger = coverage_ledger(
        task_plan(question), candidate, compact, question=question, evidence=EVIDENCE
    )
    assert (
        ledger["tasks"][0]["element_coverage"][0]["answer_spans"][0]["text"]
        == candidate.statements[0].text
    )
    assert ledger["complete"] is True


@pytest.mark.parametrize(
    "indices,error",
    [
        ([0], "invalid_verifier_span_reference"),
        ([-1], "invalid_verifier_span_reference"),
        ([2], "invalid_verifier_span_reference"),
        ([1, 1], "invalid_verifier_duplicate_span_reference"),
    ],
)
def test_compact_element_reference_rejects_out_of_bounds_or_repeated_indices(indices, error):
    question, candidate = "说明应用暴露条件。", answer()
    payload = review(candidate).model_dump()
    element = payload["coverage"][0]["element_coverage"][0]
    element["answer_spans"], element["answer_span_indices"] = [], indices
    with pytest.raises(ValueError, match=error):
        normalize_verification(
            question,
            task_plan(question),
            candidate,
            VerifierOutput.model_validate(payload),
            EVIDENCE,
        )


def test_compact_element_reference_rejects_dual_formats_instead_of_silently_picking_one():
    payload = review(answer()).model_dump()
    payload["coverage"][0]["element_coverage"][0]["answer_span_indices"] = [1]
    with pytest.raises(ValueError, match="element_cannot_mix_span_formats"):
        VerifierOutput.model_validate(payload)


def test_compact_element_reference_preserves_partial_and_final_index_remap_after_unsupported():
    question, candidate = "说明应用暴露条件。", answer()
    candidate.statements.extend(
        [answer("错误结论").statements[0], answer("另一条正确条件").statements[0]]
    )
    payload = review(candidate).model_dump()
    payload["claim_support"][1].update(status="unsupported", reason="自己的引文不支持")
    element = payload["coverage"][0]["element_coverage"][0]
    element["answer_spans"], element["answer_span_indices"] = [], [2, 3]
    verdict = VerifierOutput.model_validate(payload)
    normalized = normalize_verification(question, task_plan(question), candidate, verdict, EVIDENCE)
    assert normalized.coverage[0].element_coverage[0].status == "partial"
    assert [
        span.statement_index for span in normalized.coverage[0].element_coverage[0].answer_spans
    ] == [2, 3]
    ledger = coverage_ledger(
        task_plan(question), candidate, verdict, question=question, evidence=EVIDENCE
    )
    assert ledger["final_statement_index_map"] == {"1": 1, "3": 2}
    spans = ledger["tasks"][0]["element_coverage"][0]["answer_spans"]
    assert spans == [
        {"statement_index": 2, "text": "另一条正确条件", "start": 0, "end": len("另一条正确条件")}
    ]
    assert ledger["complete"] is False


def test_compact_element_reference_does_not_change_semantic_missing_verdict():
    question, candidate = "说明应用暴露条件。", answer()
    payload = review(candidate).model_dump()
    element = payload["coverage"][0]["element_coverage"][0]
    element.update(status="missing", answer_spans=[], answer_span_indices=[1])
    normalized = normalize_verification(
        question, task_plan(question), candidate, VerifierOutput.model_validate(payload), EVIDENCE
    )
    assert normalized.coverage[0].element_coverage[0].status == "missing"
    assert normalized.coverage[0].status == "partial"
