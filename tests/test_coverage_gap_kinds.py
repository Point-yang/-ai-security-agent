"""Separate prose, own-source and physical-context blockers without inference."""

import copy
import hashlib

import pytest

from zhidu.agent_requirements import coverage_ledger, normalize_verification, reviewed_candidate
from zhidu.agent_state import AgentAnswer
from zhidu.agent_team_state import (
    ResearchGap,
    ResearchGapDecision,
    TaskPlan,
    VerifierDecision,
    VerifierOutput,
)

HANDLE = "a" * 24
QUESTION = "列出全部必要条件。"


def fixture(*, complete=False, policy="any", context=True, missing=False, unsupported=False):
    field_text = "Condition one. Condition two."
    end = len(field_text) if complete else 14
    evidence = {
        HANDLE: {
            "source_id": "github-advisories",
            "field": "description",
            "json_pointer": "/description",
            "sha256": "a" * 64,
            "revision": 1,
            "start": 0,
            "end": end,
            "text": field_text[:end],
            "span_provenance": {
                "version": "source-context-span-v1",
                "source_field_chars": len(field_text),
                "source_field_sha256": hashlib.sha256(field_text.encode()).hexdigest(),
                "serialization": "string-verbatim",
                "offset_unit": "unicode_codepoint",
                "context": {
                    "kind": "field",
                    "start": 0,
                    "end": len(field_text),
                    "complete": complete,
                    "continuation_offset": None if complete else end,
                },
            },
        }
    }
    plan = TaskPlan.model_validate(
        {
            "tasks": [
                {
                    "task_id": "conditions",
                    "requirement": QUESTION,
                    "source_ids": ["github-advisories"]
                    if policy == "any"
                    else ["github-advisories", "nvd"],
                    "fields": ["description"],
                    "keywords": [],
                    "question_spans": [{"quote": QUESTION}],
                    "source_policy": policy,
                    "coverage_scope": "complete_context" if context else "facts",
                    "required_elements": ["必要条件"],
                }
            ]
        }
    )
    candidate = AgentAnswer.model_validate(
        {
            "answer_class": "evidence",
            "statements": [
                {"text": "必要条件已在这条正文中说明。", "evidence": [{"evidence_id": HANDLE}]}
            ],
            "required_facts": [QUESTION],
            "missing_facts": [],
            "limitations": [],
            "message": "",
        }
    )
    spans = [] if missing else [{"statement_index": 1, "text": candidate.statements[0].text}]
    review = VerifierOutput.model_validate(
        {
            "coverage": [
                {
                    "task_id": "conditions",
                    "status": "missing" if missing else "covered",
                    "statement_indices": [] if missing else [1],
                    "answer_spans": spans,
                    "note": "fixture AI semantics",
                    "element_coverage": [
                        {
                            "element": "必要条件",
                            "status": "missing" if missing else "covered",
                            "answer_spans": spans,
                        }
                    ],
                }
            ],
            "claim_support": [
                {
                    "statement_index": 1,
                    "status": "unsupported" if unsupported else "supported",
                    "reason": "fixture ownquotes",
                }
            ],
            "unplanned_requirements": [],
            "gaps": [],
        }
    )
    return plan, candidate, review, evidence


def normalized(parts):
    plan, candidate, review, evidence = parts
    return normalize_verification(QUESTION, plan, candidate, review, evidence)


def test_only_structure_proof_pending_does_not_label_condition_prose_unanswered():
    plan, candidate, review, evidence = fixture()
    result = normalized((plan, candidate, review, evidence))
    coverage = result.coverage[0]
    assert coverage.status == "partial" and coverage.semantic_status == "covered"
    assert coverage.coverage_blockers == ["context"]
    assert (
        coverage.element_coverage[0].semantic_status
        == coverage.element_coverage[0].status
        == "covered"
    )
    assert result.gaps[0].kind == "context" and result.gaps[0].context == "section"
    assert result.gaps[0].requirement.startswith("完整结构引用待补核：")
    approved = reviewed_candidate(plan, candidate, result, question=QUESTION, evidence=evidence)
    assert approved.answer_class == "partial" and approved.statements == candidate.statements
    assert approved.missing_facts == ["完整结构引用待补核：" + QUESTION]
    ledger = coverage_ledger(plan, candidate, result, question=QUESTION, evidence=evidence)
    assert ledger["tasks"][0]["context_only"] is True
    assert ledger["tasks"][0]["semantic_status"] == "covered" and ledger["complete"] is False


@pytest.mark.parametrize(
    "options",
    [
        {},
        {"missing": True},
        {"unsupported": True},
        {"complete": True, "policy": "each", "context": False},
    ],
)
def test_normalization_is_idempotent_for_each_blocker_kind(options):
    plan, candidate, review, evidence = fixture(**options)
    first = normalize_verification(QUESTION, plan, candidate, review, evidence)
    second = normalize_verification(QUESTION, plan, candidate, first, evidence)
    third = normalize_verification(QUESTION, plan, candidate, second, evidence)
    assert first.model_dump() == second.model_dump() == third.model_dump()


def test_true_missing_prose_stays_an_answer_gap_with_no_false_structure_only_flag():
    plan, candidate, review, evidence = fixture(missing=True)
    result = normalized((plan, candidate, review, evidence))
    assert result.coverage[0].semantic_status == result.coverage[0].status == "missing"
    assert result.coverage[0].coverage_blockers == ["answer"]
    assert result.gaps[0].kind == "answer" and result.gaps[0].requirement.startswith(
        "本轮正文尚需回答："
    )
    approved = reviewed_candidate(plan, candidate, result, question=QUESTION, evidence=evidence)
    assert approved.missing_facts == [QUESTION]
    assert approved.statements == candidate.statements
    assert (
        coverage_ledger(plan, candidate, result, question=QUESTION, evidence=evidence)["tasks"][0][
            "context_only"
        ]
        is False
    )


def test_unsupported_claim_is_source_support_failure_not_context_only():
    plan, candidate, review, evidence = fixture(unsupported=True)
    result = normalized((plan, candidate, review, evidence))
    assert result.coverage[0].semantic_status == "covered"
    assert result.coverage[0].coverage_blockers == ["unsupported"]
    assert result.gaps[0].kind == "source"
    assert result.coverage[0].element_coverage[0].semantic_status == "covered"
    assert result.coverage[0].element_coverage[0].status == "partial"
    approved = reviewed_candidate(plan, candidate, result, question=QUESTION, evidence=evidence)
    assert approved.answer_class == "refused" and approved.statements == []
    assert (
        coverage_ledger(plan, candidate, result, question=QUESTION, evidence=evidence)["tasks"][0][
            "context_only"
        ]
        is False
    )


def test_each_source_gap_preserves_supported_single_source_and_does_not_force_same_named_field():
    plan, candidate, review, evidence = fixture(complete=True, policy="each", context=False)
    result = normalized((plan, candidate, review, evidence))
    assert result.coverage[0].coverage_blockers == ["source"]
    assert result.gaps[0].kind == "source" and result.gaps[0].source_id == "nvd"
    assert result.gaps[0].field is None
    assert result.claim_support[0].status == "supported"
    approved = reviewed_candidate(plan, candidate, result, question=QUESTION, evidence=evidence)
    assert approved.statements == candidate.statements
    assert approved.missing_facts == ["来源引用待补核：" + QUESTION]


def test_existing_candidate_missing_labels_and_partial_are_never_automatically_cleared():
    plan, candidate, review, evidence = fixture()
    candidate.answer_class = "partial"
    candidate.missing_facts = ["原候选已记录的缺口"]
    approved = reviewed_candidate(plan, candidate, review, question=QUESTION, evidence=evidence)
    assert approved.answer_class == "partial"
    assert approved.missing_facts == ["原候选已记录的缺口", "完整结构引用待补核：" + QUESTION]
    assert candidate.missing_facts == ["原候选已记录的缺口"]
    assert candidate.answer_class == "partial"


def test_semantic_missing_does_not_become_covered_when_context_is_complete():
    plan, candidate, review, evidence = fixture(complete=True)
    data = review.model_dump()
    data["coverage"][0]["status"] = "partial"
    data["coverage"][0]["element_coverage"][0]["status"] = "partial"
    result = normalized((plan, candidate, VerifierOutput.model_validate(data), evidence))
    assert result.coverage[0].semantic_status == result.coverage[0].status == "partial"
    assert result.coverage[0].coverage_blockers == ["answer"]
    assert result.gaps[0].kind == "answer"


def test_semantic_and_structure_gaps_keep_both_blockers_without_losing_section_hint():
    plan, candidate, review, evidence = fixture()
    data = review.model_dump()
    data["coverage"][0]["status"] = "partial"
    data["coverage"][0]["element_coverage"][0]["status"] = "partial"
    result = normalized((plan, candidate, VerifierOutput.model_validate(data), evidence))
    assert result.coverage[0].coverage_blockers == ["answer", "context"]
    assert result.gaps[0].kind == "answer" and result.gaps[0].context == "section"


def test_legacy_gap_default_and_current_wire_have_no_new_required_internal_fields():
    assert ResearchGap(task_id="conditions", requirement="原缺口").kind == "answer"
    assert ResearchGapDecision(task_id="conditions", requirement="原缺口").kind == "answer"
    wire = VerifierDecision.model_json_schema()
    assert "semantic_status" not in wire["$defs"]["AnchorTaskCoverage"]["properties"]
    assert "semantic_status" not in wire["$defs"]["AnchorElementCoverage"]["properties"]
    assert "kind" not in wire["$defs"]["ResearchGapDecision"]["required"]


def test_ai_gap_conflicting_with_covered_task_is_visible_not_silently_dropped():
    plan, candidate, review, evidence = fixture(complete=True, context=False)
    data = review.model_dump()
    data["gaps"] = [{"task_id": "conditions", "requirement": "AI仍列出正文缺口"}]
    result = normalized((plan, candidate, VerifierOutput.model_validate(data), evidence))
    assert (
        result.coverage[0].semantic_status == "covered" and result.coverage[0].status == "partial"
    )
    assert result.coverage[0].coverage_blockers == ["answer"]
    assert result.gaps[0].kind == "answer"
    assert (
        normalize_verification(QUESTION, plan, candidate, result, evidence).model_dump()
        == result.model_dump()
    )


@pytest.mark.parametrize(
    "options,blockers",
    [
        ({}, ["answer", "context"]),
        ({"complete": True, "policy": "each", "context": False}, ["answer", "source"]),
        ({"unsupported": True}, ["answer", "unsupported"]),
    ],
)
def test_explicit_answer_gap_survives_physical_or_support_blockers_and_three_reentries(
    options, blockers
):
    plan, candidate, review, evidence = fixture(**options)
    review.gaps = [
        ResearchGap(
            task_id="conditions", requirement="正文遗漏一个用户明确要求的必要条件", kind="answer"
        )
    ]
    first = normalize_verification(QUESTION, plan, candidate, review, evidence)
    second = normalize_verification(QUESTION, plan, candidate, first, evidence)
    third = normalize_verification(QUESTION, plan, candidate, second, evidence)
    assert first.model_dump() == second.model_dump() == third.model_dump()
    assert (
        first.coverage[0].semantic_status == "covered"
    )  # Preserve the contradictory AI opinion too.
    assert first.coverage[0].coverage_blockers == blockers
    assert first.gaps[0].kind == "answer"
    assert first.gaps[0].requirement == review.gaps[0].requirement
    ledger = coverage_ledger(plan, candidate, first, question=QUESTION, evidence=evidence)
    assert ledger["tasks"][0]["context_only"] is False
    approved = reviewed_candidate(plan, candidate, first, question=QUESTION, evidence=evidence)
    assert QUESTION in approved.missing_facts
    assert not any(label.startswith("完整结构引用待补核：") for label in approved.missing_facts)


def test_automatically_generated_context_gap_never_becomes_answer_on_three_reentries():
    plan, candidate, review, evidence = fixture()
    first = normalize_verification(QUESTION, plan, candidate, review, evidence)
    second = normalize_verification(QUESTION, plan, candidate, first, evidence)
    third = normalize_verification(QUESTION, plan, candidate, second, evidence)
    assert first.model_dump() == second.model_dump() == third.model_dump()
    for result in (first, second, third):
        assert result.coverage[0].coverage_blockers == ["context"]
        assert result.gaps[0].kind == "context"
        assert (
            coverage_ledger(plan, candidate, result, question=QUESTION, evidence=evidence)["tasks"][
                0
            ]["context_only"]
            is True
        )


def test_explicit_source_and_context_gap_kinds_survive_without_physical_blockers():
    plan, candidate, review, evidence = fixture(complete=True, context=False)
    review.gaps = [
        ResearchGap(task_id="conditions", requirement="来源引用仍待核", kind="source"),
        ResearchGap(task_id="conditions", requirement="结构范围仍待核", kind="context"),
    ]
    first = normalize_verification(QUESTION, plan, candidate, review, evidence)
    second = normalize_verification(QUESTION, plan, candidate, first, evidence)
    third = normalize_verification(QUESTION, plan, candidate, second, evidence)
    assert first.model_dump() == second.model_dump() == third.model_dump()
    assert first.coverage[0].coverage_blockers == ["source", "context"]
    assert [gap.kind for gap in first.gaps] == ["source", "context"]
    assert first.coverage[0].semantic_status == "covered" and first.coverage[0].status == "partial"
    assert (
        coverage_ledger(plan, candidate, first, question=QUESTION, evidence=evidence)["tasks"][0][
            "context_only"
        ]
        is False
    )


def test_explicit_source_gap_is_not_hidden_by_physical_context_blocker():
    plan, candidate, review, evidence = fixture()
    review.gaps = [ResearchGap(task_id="conditions", requirement="本句来源仍待核", kind="source")]
    first = normalize_verification(QUESTION, plan, candidate, review, evidence)
    second = normalize_verification(QUESTION, plan, candidate, first, evidence)
    third = normalize_verification(QUESTION, plan, candidate, second, evidence)
    assert first.model_dump() == second.model_dump() == third.model_dump()
    assert first.coverage[0].coverage_blockers == ["context", "source"]
    assert first.gaps[0].kind == "source"
    assert (
        coverage_ledger(plan, candidate, first, question=QUESTION, evidence=evidence)["tasks"][0][
            "context_only"
        ]
        is False
    )


def test_inputs_and_original_ai_semantic_result_are_not_mutated():
    plan, candidate, review, evidence = fixture()
    before = copy.deepcopy(
        (plan.model_dump(), candidate.model_dump(), review.model_dump(), evidence)
    )
    normalized((plan, candidate, review, evidence))
    assert before == (plan.model_dump(), candidate.model_dump(), review.model_dump(), evidence)
