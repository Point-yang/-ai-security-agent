"""Subrequirement labels may outnumber claims without weakening review limits."""

import copy

import pytest
from pydantic import ValidationError

from zhidu.agent_requirements import coverage_ledger, reviewed_candidate
from zhidu.agent_state import AgentAnswer
from zhidu.agent_team_state import TaskPlan, VerifierOutput

HANDLE = "a" * 24
LABELS = [
    "触发 API",
    "opset 路径",
    "输入 rank",
    "未检查索引",
    "InferShapes 边界",
    "Release 表现",
    "ASan 表现",
    "可能泄露",
    "可能崩溃",
    "堆布局限制",
]
QUESTION = "说明" + "、".join(LABELS) + "，并说明不可信模型的来源条件。"
TEXTS = [
    "公告说明触发 API、opset 路径、输入 rank、未检查索引和 InferShapes 边界。",
    "公告区分 Release 和 ASan 表现，泄露与崩溃只是可能结果，受堆布局限制。",
]
EVIDENCE = {
    HANDLE: {
        "source_id": "github-advisories",
        "text": "The source states the trigger and boundary conditions; potential disclosure and crashes depend on the heap layout.",
    }
}


def payload():
    return {
        "answer_class": "evidence",
        "statements": [{"text": text, "evidence": [{"evidence_id": HANDLE}]} for text in TEXTS],
        "required_facts": list(LABELS),
        "missing_facts": [],
        "limitations": [],
        "message": "",
    }


def plan():
    return TaskPlan.model_validate(
        {
            "tasks": [
                {
                    "task_id": f"task-{index}",
                    "requirement": "；".join(LABELS[(index - 1) * 5 : index * 5]),
                    "source_ids": ["github-advisories"],
                    "fields": ["description"],
                    "keywords": [],
                    "question_spans": [{"quote": "、".join(LABELS[(index - 1) * 5 : index * 5])}],
                    "source_policy": "any",
                    "required_elements": LABELS[(index - 1) * 5 : index * 5],
                }
                for index in (1, 2)
            ]
        }
    )


def verdict():
    coverage = []
    for index in (1, 2):
        span = {"statement_index": index, "text": TEXTS[index - 1]}
        coverage.append(
            {
                "task_id": f"task-{index}",
                "status": "covered",
                "statement_indices": [index],
                "answer_spans": [span],
                "note": "AI逐项审查正文和自身引文",
                "element_coverage": [
                    {"element": label, "status": "covered", "answer_span_indices": [1]}
                    for label in LABELS[(index - 1) * 5 : index * 5]
                ],
            }
        )
    return {
        "coverage": coverage,
        "claim_support": [
            {"statement_index": index, "status": "supported", "reason": "本句自己的引文支持"}
            for index in (1, 2)
        ],
        "unplanned_requirements": [],
        "gaps": [],
    }


def test_ten_subrequirements_are_preserved_without_becoming_ten_claims():
    candidate = AgentAnswer.model_validate(payload())
    assert candidate.required_facts == LABELS
    assert len(candidate.statements) == 2
    approved = reviewed_candidate(
        plan(),
        candidate,
        VerifierOutput.model_validate(verdict()),
        question=QUESTION,
        evidence=EVIDENCE,
    )
    assert len(approved.required_facts) == 8  # existing display packing stays unchanged
    assert all(label in "；".join(approved.required_facts) for label in LABELS)
    ledger = coverage_ledger(
        plan(),
        candidate,
        VerifierOutput.model_validate(verdict()),
        question=QUESTION,
        evidence=EVIDENCE,
    )
    assert sum(len(item["required_elements"]) for item in ledger["tasks"]) == 10


def test_ten_missing_labels_are_preserved_on_input_and_remain_partial_after_review():
    data = payload()
    data.update(answer_class="partial", missing_facts=list(LABELS))
    candidate = AgentAnswer.model_validate(data)
    assert candidate.missing_facts == LABELS
    approved = reviewed_candidate(
        plan(),
        candidate,
        VerifierOutput.model_validate(verdict()),
        question=QUESTION,
        evidence=EVIDENCE,
    )
    assert approved.answer_class == "partial"
    assert all(label in "；".join(approved.missing_facts) for label in LABELS)


def test_larger_label_capacity_never_overrides_unsupported_or_omitted_requirement():
    candidate = AgentAnswer.model_validate(payload())
    data = verdict()
    data["claim_support"][1].update(status="unsupported", reason="本句引文未支持所述限制")
    data["unplanned_requirements"] = [
        {
            "requirement": "说明不可信模型的来源条件",
            "question_span": {"quote": "说明不可信模型的来源条件"},
            "reason": "原问题明确要求但计划与正文都未回答",
        }
    ]
    approved = reviewed_candidate(
        plan(), candidate, VerifierOutput.model_validate(data), question=QUESTION, evidence=EVIDENCE
    )
    assert approved.answer_class == "partial"
    assert [claim.text for claim in approved.statements] == [TEXTS[0]]
    assert "说明不可信模型的来源条件" in "；".join(approved.missing_facts)
    assert "本句引文未支持所述限制" in "；".join(approved.missing_facts)


@pytest.mark.parametrize("field", ["required_facts", "missing_facts"])
def test_sixty_five_labels_remain_rejected(field):
    data = payload()
    data[field] = [f"子需求 {index}" for index in range(65)]
    with pytest.raises(ValidationError, match="at most 64"):
        AgentAnswer.model_validate(data)


def test_nine_technical_claims_remain_rejected_even_with_valid_label_count():
    data = payload()
    data["statements"] = [copy.deepcopy(data["statements"][0]) for _ in range(9)]
    with pytest.raises(ValidationError, match="at most 8"):
        AgentAnswer.model_validate(data)


@pytest.mark.parametrize("field", ["required_facts", "missing_facts"])
@pytest.mark.parametrize("invalid", [1, False, {"requirement": "条件"}, None])
def test_requirement_labels_are_strict_strings(field, invalid):
    data = payload()
    data[field] = [invalid]
    with pytest.raises(ValidationError, match="valid string"):
        AgentAnswer.model_validate(data)


def test_claim_evidence_and_limitation_limits_are_unchanged():
    data = payload()
    data["statements"][0]["evidence"] *= 6
    with pytest.raises(ValidationError, match="at most 5"):
        AgentAnswer.model_validate(data)
    data = payload()
    data["limitations"] = ["本轮范围说明"] * 7
    with pytest.raises(ValidationError, match="at most 6"):
        AgentAnswer.model_validate(data)
