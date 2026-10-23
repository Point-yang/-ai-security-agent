import copy

import pytest
from pydantic import ValidationError

from zhidu.paired_evaluation import (
    DimensionObservation,
    judge_packet,
    paired_difference,
    score_answer,
    summarize,
    validate_verdict,
)


def sample():
    case = {
        "id": "case",
        "group_id": "group",
        "facts": [{"id": "range", "dimension": "affected_range"}],
    }
    result = {
        "generation": {"status": "completed"},
        "citations": [{"text": "affected < 2.0, patch 2.0"}],
        "generated_claims": [
            {
                "text": "受影响范围小于 2.0。",
                "evidence": [{"citation": 1, "quote": "affected < 2.0"}],
            }
        ],
    }
    verdict = {
        "facts": [
            {"fact_id": "range", "covered": True, "grounded": True, "reason": "原文范围明确"}
        ],
        "claims": [{"statement_index": 1, "supported": True, "reason": "结论未超过引文"}],
        "boundary_ok": True,
        "boundary_reason": "来源声明",
    }
    return case, result, verdict


def test_exact_irrelevant_quote_cannot_be_semantic_pass():
    case, result, verdict = sample()
    verdict["facts"][0]["grounded"] = False
    verdict["claims"][0]["supported"] = False
    score = score_answer(case, result, verdict)
    assert score["verbatim"]["exact"] == 1
    assert not score["strict_pass"]
    assert score["fact_recall"] == 0
    assert score["citation_entailment_precision"] == 0


def test_fallback_excerpts_never_count_as_semantic_answer():
    case, result, verdict = sample()
    result["generation"]["status"] = "fallback"
    score = score_answer(case, result, verdict)
    assert not score["strict_pass"]
    assert score["grounded_facts"] == 0


def test_missing_judge_kept_in_confirmed_accuracy_denominator():
    case, result, verdict = sample()
    rows = []
    for mode in ("rag", "workflow", "langchain"):
        for i in range(2):
            current = dict(case, id=f"case-{i}", group_id=f"group-{i}")
            row = score_answer(current, result, verdict if i == 0 else None)
            row.update(mode=mode, elapsed_ms=10, cost={"external_requests": 1, "billed_tokens": 30})
            rows.append(row)
    report = summarize(rows)
    assert report["modes"]["rag"]["confirmed_strict_accuracy_all_attempts"] == 0.5
    assert report["modes"]["rag"]["judge_coverage"] == 0.5
    assert not report["agent_gain_proven"]


@pytest.mark.parametrize("field", ["facts", "claims"])
def test_duplicate_or_omitted_judge_entries_rejected(field):
    case, result, verdict = sample()
    verdict[field].append(copy.deepcopy(verdict[field][0]))
    with pytest.raises(ValueError, match="set_mismatch"):
        validate_verdict(case, result, verdict)
    verdict[field] = []
    with pytest.raises(ValueError, match="set_mismatch"):
        validate_verdict(case, result, verdict)


def test_false_verbatim_blocks_positive_semantic_verdict():
    case, result, verdict = sample()
    result["generated_claims"][0]["evidence"][0]["quote"] = "fabricated patch"
    assert not score_answer(case, result, verdict)["strict_pass"]


def test_absence_cannot_be_promoted_to_no_public_data():
    with pytest.raises(ValidationError, match="positive_source_evidence_required"):
        DimensionObservation(
            dimension="poc", state="not_public", scope="local frozen corpus", conclusion="不存在"
        )
    for state in ("not_found_in_scope", "interface_error", "not_connected"):
        record = DimensionObservation(
            dimension="poc",
            state=state,
            scope="local frozen corpus",
            conclusion="不能判定公开数据存在性",
        )
        assert record.state == state


def test_cluster_pairing_does_not_count_questions_as_independent_groups():
    rows = []
    for i in range(4):
        for mode, passed in (("rag", False), ("langchain", True)):
            rows.append(
                {"case_id": str(i), "group_id": "one-cve", "mode": mode, "strict_pass": passed}
            )
    result = paired_difference(rows, "langchain", "rag", samples=100)
    assert result["groups"] == 1
    assert result["paired_wins"] == 4
    assert result["delta"] == 1


def test_judge_cannot_see_unquoted_context_or_gold_source_text():
    case, result, _ = sample()
    case["question"] = "范围是多少？"
    case["facts"][0].update(
        expected="小于 2.0", evidence=[{"text": "private-unquoted-gold-context"}]
    )
    result["answer"] = "受影响范围小于 2.0。"
    result["citations"][0]["text"] += " unquoted-source-context"
    packet = judge_packet(case, result, "anonymous-test")
    assert "unquoted-source-context" not in str(packet)
    assert "private-unquoted-gold-context" not in str(packet)
    assert packet["generated_claims"][0]["evidence"][0]["quote"] == "affected < 2.0"
