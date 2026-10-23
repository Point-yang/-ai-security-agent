"""Server-authored prose identity, independent semantics and final remapping."""

import copy
import json

import pytest
from test_agent_requirements import EVIDENCE, GH, NVD, answer, review, task_plan

from zhidu.agent_requirements import (
    coverage_ledger,
    expand_verifier_decision,
    normalize_verification,
    reviewed_candidate,
    verifier_packet,
)
from zhidu.agent_team_state import VerifierDecision
from zhidu.answer_anchors import build_answer_anchors

QUESTION = "说明应用暴露条件。"


def decision(packet, *, ids=None):
    ids = ids if ids is not None else [item["anchor_id"] for item in packet["answer_anchors"]]
    return VerifierDecision.model_validate(
        {
            "coverage": [
                {
                    "task_id": task["task_id"],
                    "status": "covered",
                    "anchor_ids": ids,
                    "note": "正文有回答且自身引文支持",
                    "element_coverage": [
                        {"element": element, "status": "covered", "anchor_ids": ids}
                        for element in task["required_elements"]
                    ],
                }
                for task in packet["tasks"]
            ],
            "claim_support": [
                {
                    "statement_index": item["statement_index"],
                    "status": "supported",
                    "reason": "自身引文支持",
                }
                for item in packet["statements"]
            ],
            "unplanned_requirements": [],
            "gaps": [],
        }
    )


def inputs(*, policy="any", scope=None, candidate=None):
    candidate = candidate or answer()
    plan = task_plan(QUESTION, policy=policy)
    return plan, candidate, verifier_packet(QUESTION, plan, candidate, EVIDENCE, scope=scope)


def test_server_whole_sentence_ids_are_stable_and_own_quote_tables_are_compact():
    plan, candidate, packet = inputs(scope="request-1")
    assert packet == verifier_packet(QUESTION, plan, candidate, EVIDENCE, scope="request-1")
    tables = build_answer_anchors(QUESTION, plan, candidate, EVIDENCE, scope="request-1")
    anchor = tables["answer_anchors"][0]
    assert anchor["text"] == candidate.statements[0].text
    assert (anchor["start"], anchor["end"]) == (0, len(anchor["text"]))
    assert anchor["anchor_id"].startswith("ans_")
    assert tables["source_quotes"][0]["quote_id"].startswith("src_")
    assert "text" not in packet["answer_anchors"][0] and "quote" not in packet["source_quotes"][0]
    encoded = json.dumps(packet, ensure_ascii=False)
    assert encoded.count(candidate.statements[0].text) == 1
    assert encoded.count(EVIDENCE[GH]["text"]) == 1
    assert EVIDENCE[NVD]["text"] not in encoded


def test_packet_does_not_export_unquoted_source_or_private_evidence_fields():
    plan, candidate, _ = inputs()
    evidence = copy.deepcopy(EVIDENCE)
    evidence[GH]["artifact"] = {"asset": "PRIVATE-ASSET-IDENTITY"}
    evidence[GH]["other_field"] = "UNREAD-SOURCE-CONTEXT"
    evidence[NVD]["text"] = "UNQUOTED-GOLD-ORACLE"
    encoded = json.dumps(verifier_packet(QUESTION, plan, candidate, evidence), ensure_ascii=False)
    assert all(
        secret not in encoded
        for secret in ["PRIVATE-ASSET-IDENTITY", "UNREAD-SOURCE-CONTEXT", "UNQUOTED-GOLD-ORACLE"]
    )


def test_id_selected_source_context_is_bound_to_body_anchor_and_cannot_be_replaced():
    plan, candidate, _ = inputs()
    evidence = copy.deepcopy(EVIDENCE)
    evidence[GH]["span_provenance"] = {
        "version": "source-context-span-v2",
        "context_id": "ctx_" + "a" * 64,
    }
    packet = verifier_packet(QUESTION, plan, candidate, evidence)
    original = decision(packet)
    changed = copy.deepcopy(evidence)
    changed[GH]["span_provenance"]["context_id"] = "ctx_" + "b" * 64
    with pytest.raises(ValueError, match="invalid_verifier_anchor_id"):
        expand_verifier_decision(QUESTION, plan, candidate, original, changed)


def test_valid_selection_expands_exact_prose_and_is_idempotent():
    plan, candidate, packet = inputs(scope="request-1")
    output = expand_verifier_decision(
        QUESTION, plan, candidate, decision(packet), EVIDENCE, scope="request-1"
    )
    span = output.coverage[0].answer_spans[0]
    assert span.model_dump() == {
        "statement_index": 1,
        "text": candidate.statements[0].text,
        "start": 0,
        "end": len(candidate.statements[0].text),
    }
    assert normalize_verification(QUESTION, plan, candidate, output, EVIDENCE) == output
    ledger = coverage_ledger(plan, candidate, output, question=QUESTION, evidence=EVIDENCE)
    assert ledger["tasks"][0]["answer_anchor_ids"] == decision(packet).coverage[0].anchor_ids
    assert ledger["complete"] is True


@pytest.mark.parametrize("kind", ["source", "unknown", "old_namespace"])
def test_source_or_unknown_ids_cannot_claim_body_coverage(kind):
    plan, candidate, packet = inputs()
    anchor = (
        packet["source_quotes"][0]["quote_id"]
        if kind == "source"
        else ("ans_0000000000000000_1" if kind == "unknown" else "statement_1")
    )
    with pytest.raises(ValueError, match="invalid_verifier_anchor_id"):
        expand_verifier_decision(
            QUESTION, plan, candidate, decision(packet, ids=[anchor]), EVIDENCE
        )


@pytest.mark.parametrize("level", ["task", "element"])
def test_duplicate_anchor_selection_rejected(level):
    plan, candidate, packet = inputs()
    payload = decision(packet).model_dump()
    row = payload["coverage"][0]
    target = row if level == "task" else row["element_coverage"][0]
    target["anchor_ids"] *= 2
    with pytest.raises(ValueError, match="invalid_verifier_duplicate_anchor"):
        expand_verifier_decision(
            QUESTION, plan, candidate, VerifierDecision.model_validate(payload), EVIDENCE
        )


@pytest.mark.parametrize("change", ["text", "labels", "quote", "provenance", "scope", "question"])
def test_ids_from_different_candidate_source_or_request_are_stale(change):
    plan, candidate, packet = inputs(scope="request-1")
    evidence, question, scope = copy.deepcopy(EVIDENCE), QUESTION, "request-1"
    if change == "text":
        candidate = answer("公告描述反序列化入口。")
    elif change == "labels":
        candidate = candidate.model_copy(update={"required_facts": ["更完整的问题要求"]})
    elif change == "quote":
        evidence[GH]["text"] += " Additional condition."
    elif change == "provenance":
        evidence[GH]["revision_id"] = "new-source-revision"
    elif change == "scope":
        scope = "request-2"
    else:
        question += "说明信任边界。"
    with pytest.raises(ValueError, match="invalid_verifier_anchor_id"):
        expand_verifier_decision(question, plan, candidate, decision(packet), evidence, scope=scope)


@pytest.mark.parametrize(
    "member,value",
    [
        ("text", "伪造正文"),
        ("start", 0),
        ("end", 1),
        ("statement_indices", [1]),
        ("answer_spans", []),
    ],
)
def test_wire_forbids_authored_body_locations(member, value):
    _, _, packet = inputs()
    payload = decision(packet).model_dump()
    payload["coverage"][0][member] = value
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        VerifierDecision.model_validate(payload)


def test_element_anchor_must_be_selected_by_parent_task():
    candidate = answer()
    candidate.statements.append(answer("另一条结论。", refs=[NVD]).statements[0])
    plan, candidate, packet = inputs(candidate=candidate)
    payload = decision(packet, ids=[packet["answer_anchors"][0]["anchor_id"]]).model_dump()
    payload["coverage"][0]["element_coverage"][0]["anchor_ids"] = [
        packet["answer_anchors"][1]["anchor_id"]
    ]
    with pytest.raises(ValueError, match="invalid_verifier_element_anchor"):
        expand_verifier_decision(
            QUESTION, plan, candidate, VerifierDecision.model_validate(payload), EVIDENCE
        )


def test_covered_without_body_anchor_is_partial_and_retains_supported_claim():
    plan, candidate, packet = inputs()
    output = expand_verifier_decision(QUESTION, plan, candidate, decision(packet, ids=[]), EVIDENCE)
    assert output.coverage[0].status == "partial" and output.unsupported == []
    approved = reviewed_candidate(plan, candidate, output, question=QUESTION, evidence=EVIDENCE)
    assert approved.answer_class == "partial" and approved.statements == candidate.statements


def test_quote_only_condition_cannot_turn_semantic_missing_into_covered():
    plan, candidate, packet = inputs(candidate=answer("公告描述一个复原入口。"))
    payload = decision(packet).model_dump()
    payload["coverage"][0]["element_coverage"][0].update(status="missing", anchor_ids=[])
    output = expand_verifier_decision(
        QUESTION, plan, candidate, VerifierDecision.model_validate(payload), EVIDENCE
    )
    assert "untrusted input" in packet["statements"][0]["quotes"][0]["quote"]
    assert output.coverage[0].element_coverage[0].status == "missing"
    assert output.coverage[0].status == "partial"


@pytest.mark.parametrize(
    "policy,expected", [("any", "covered"), ("each", "partial"), ("compare", "partial")]
)
def test_source_policy_is_independent_of_claim_support(policy, expected):
    plan, candidate, packet = inputs(policy=policy)
    output = expand_verifier_decision(QUESTION, plan, candidate, decision(packet), EVIDENCE)
    assert output.coverage[0].status == expected and output.unsupported == []
    assert (
        reviewed_candidate(plan, candidate, output, question=QUESTION, evidence=EVIDENCE).statements
        == candidate.statements
    )


def test_unsupported_pruning_preserves_original_anchor_identity_and_final_indices():
    candidate = answer()
    candidate.statements.extend(
        [
            answer("错误结论。", refs=[NVD]).statements[0],
            answer("另一条正确条件。", refs=[GH]).statements[0],
        ]
    )
    plan, candidate, packet = inputs(scope="request-1", candidate=candidate)
    payload = decision(packet).model_dump()
    payload["claim_support"][1].update(status="unsupported", reason="自身引文不支持")
    output = expand_verifier_decision(
        QUESTION,
        plan,
        candidate,
        VerifierDecision.model_validate(payload),
        EVIDENCE,
        scope="request-1",
    )
    ledger = coverage_ledger(
        plan, candidate, output, question=QUESTION, evidence=EVIDENCE, scope="request-1"
    )
    assert ledger["final_statement_index_map"] == {"1": 1, "3": 2}
    assert [item["final_statement_index"] for item in ledger["answer_anchor_statement_map"]] == [
        1,
        None,
        2,
    ]
    row = ledger["tasks"][0]
    assert row["answer_anchor_ids"] == [
        packet["answer_anchors"][index]["anchor_id"] for index in [0, 2]
    ]
    assert [span["statement_index"] for span in row["element_coverage"][0]["answer_spans"]] == [
        1,
        2,
    ]
    approved = reviewed_candidate(plan, candidate, output, question=QUESTION, evidence=EVIDENCE)
    assert [claim.text for claim in approved.statements] == [
        candidate.statements[0].text,
        candidate.statements[2].text,
    ]
    assert ledger["complete"] is False


def test_internal_binding_detects_candidate_edit_and_explicit_wrong_scope():
    plan, candidate, packet = inputs(scope="request-1")
    output = expand_verifier_decision(
        QUESTION, plan, candidate, decision(packet), EVIDENCE, scope="request-1"
    )
    with pytest.raises(ValueError, match="verifier_anchor_scope_mismatch"):
        coverage_ledger(
            plan, candidate, output, question=QUESTION, evidence=EVIDENCE, scope="request-2"
        )
    altered = candidate.model_copy(update={"missing_facts": ["原问题子要求"]})
    with pytest.raises(ValueError, match="invalid_verifier_anchor_binding"):
        normalize_verification(QUESTION, plan, altered, output, EVIDENCE)


def test_original_question_omission_is_bound_without_model_counting_offsets():
    question = QUESTION + "说明信任边界。"
    plan, candidate, _ = inputs()
    packet = verifier_packet(question, plan, candidate, EVIDENCE)
    payload = decision(packet).model_dump()
    payload["unplanned_requirements"] = [
        {"requirement": "说明信任边界", "question_quote": "说明信任边界", "reason": "正文尚未回答"}
    ]
    output = expand_verifier_decision(
        question, plan, candidate, VerifierDecision.model_validate(payload), EVIDENCE
    )
    assert output.unplanned_requirements[0].question_span.start == question.index("说明信任边界")
    assert (
        reviewed_candidate(
            plan, candidate, output, question=question, evidence=EVIDENCE
        ).answer_class
        == "partial"
    )


def test_legacy_internal_review_remains_valid_without_wire_ids():
    plan, candidate, _ = inputs()
    output = normalize_verification(QUESTION, plan, candidate, review(candidate), EVIDENCE)
    assert output.anchor_binding is None
    assert (
        coverage_ledger(plan, candidate, output, question=QUESTION, evidence=EVIDENCE)["complete"]
        is True
    )


def test_wire_gap_reason_is_audit_only_and_internal_gap_contract_remains_strict():
    from zhidu.agent_team_state import ResearchGap

    plan, candidate, packet = inputs()
    payload = decision(packet).model_dump()
    payload["gaps"] = [
        {"task_id": "conditions", "requirement": "补查必要条件", "reason": "当前正文缺少该条件"}
    ]
    wire = VerifierDecision.model_validate(payload)
    output = expand_verifier_decision(QUESTION, plan, candidate, wire, EVIDENCE)
    assert wire.model_dump()["gaps"][0]["reason"] == "当前正文缺少该条件"
    assert "reason" not in output.gaps[0].model_dump()
    assert output.gaps[0].requirement == "补查必要条件"
    assert output.coverage[0].status == "partial"
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        ResearchGap.model_validate(payload["gaps"][0])


@pytest.mark.parametrize("reason", [None, "说明" * 175])
def test_wire_gap_reason_is_optional_and_accepts_at_most_350_characters(reason):
    _, _, packet = inputs()
    payload = decision(packet).model_dump()
    payload["gaps"] = [{"task_id": "conditions", "requirement": "补查条件", "reason": reason}]
    assert VerifierDecision.model_validate(payload).gaps[0].reason == reason
    payload["gaps"][0].pop("reason")
    assert VerifierDecision.model_validate(payload).gaps[0].reason is None


@pytest.mark.parametrize(
    "extra", [{"reason": "x" * 351}, {"reason": 123}, {"permission": "new-tool"}]
)
def test_wire_gap_rejects_overlong_wrong_type_or_unknown_fields(extra):
    _, _, packet = inputs()
    payload = decision(packet).model_dump()
    payload["gaps"] = [{"task_id": "conditions", "requirement": "补查条件", **extra}]
    with pytest.raises(ValueError):
        VerifierDecision.model_validate(payload)
