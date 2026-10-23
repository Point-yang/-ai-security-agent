"""Complete-context requirements cannot borrow unread or unsupported evidence."""

import hashlib
from copy import deepcopy

from test_agent_requirements import GH, NVD, answer, review, task_plan

from zhidu.agent_requirements import coverage_ledger, normalize_verification, reviewed_candidate
from zhidu.agent_team_state import TaskPlan

QUESTION = "完整列出必须同时满足的条件。"
FIELD = "Background.\n\nAll conditions:\n\n1. A\n2. B\n3. C\n4. D\n\nOther information."
START, END = FIELD.index("All conditions:"), FIELD.index("\n\nOther")
MID = FIELD.index("3. C")


def citation(start, end, source="github-advisories"):
    return {
        "text": FIELD[start:end],
        "source_id": source,
        "field": "description",
        "revision": 1,
        "sha256": ("a" if source == "github-advisories" else "b") * 64,
        "json_pointer": "/description",
        "start": start,
        "end": end,
        "span_provenance": {
            "version": "source-context-span-v1",
            "source_field_chars": len(FIELD),
            "source_field_sha256": hashlib.sha256(FIELD.encode()).hexdigest(),
            "serialization": "string-verbatim",
            "offset_unit": "unicode_codepoint",
            "context": {
                "kind": "list_with_intro",
                "start": START,
                "end": END,
                "complete": start == START and end == END,
                "continuation_offset": end if end < END else None,
            },
        },
    }


def plan(policy="any", sources=None, scope="complete_context"):
    payload = task_plan(QUESTION, policy=policy).model_dump()
    payload["tasks"][0].update(
        coverage_scope=scope, source_ids=sources or ["github-advisories", "nvd"]
    )
    return TaskPlan.model_validate(payload)


def test_partial_source_context_downgrades_coverage_but_preserves_supported_fact():
    candidate = answer()
    evidence = {GH: citation(START, MID)}
    normalized = normalize_verification(QUESTION, plan(), candidate, review(candidate), evidence)
    assert normalized.coverage[0].status == "partial"
    assert normalized.unsupported == []
    assert normalized.gaps[0].context == "section"
    approved = reviewed_candidate(
        plan(), candidate, normalized, question=QUESTION, evidence=evidence
    )
    assert approved.answer_class == "partial" and approved.statements == candidate.statements


def test_unquoted_complete_context_cannot_fill_the_cited_partial_context():
    candidate = answer()
    evidence = {GH: citation(START, MID), NVD: citation(START, END)}
    ledger = coverage_ledger(
        plan(), candidate, review(candidate), question=QUESTION, evidence=evidence
    )
    assert ledger["tasks"][0]["context_check"]["sufficient"] is False
    assert ledger["complete"] is False


def test_two_actual_quoted_pages_can_cover_the_whole_same_context():
    candidate = answer(refs=[GH, NVD])
    evidence = {GH: citation(START, MID), NVD: citation(MID, END)}
    ledger = coverage_ledger(
        plan(), candidate, review(candidate), question=QUESTION, evidence=evidence
    )
    assert ledger["tasks"][0]["context_check"]["sufficient"] is True
    assert ledger["complete"] is True
    assert ledger["tasks"][0]["context_check"]["semantic_support_verified"] is False


def test_complete_context_from_a_different_requested_source_is_not_substitution():
    candidate = answer(refs=[GH, NVD])
    evidence = {GH: citation(START, MID), NVD: citation(START, END, source="nvd")}
    ledger = coverage_ledger(
        plan(sources=["github-advisories"]),
        candidate,
        review(candidate),
        question=QUESTION,
        evidence=evidence,
    )
    assert ledger["complete"] is False


def test_each_source_requires_its_own_complete_context():
    candidate = answer(refs=[GH, NVD])
    evidence = {GH: citation(START, END), NVD: citation(START, MID, source="nvd")}
    assert not coverage_ledger(
        plan("each"), candidate, review(candidate), question=QUESTION, evidence=evidence
    )["complete"]
    evidence[NVD] = citation(START, END, source="nvd")
    assert coverage_ledger(
        plan("each"), candidate, review(candidate), question=QUESTION, evidence=evidence
    )["complete"]


def test_unsupported_statement_cannot_supply_the_missing_source_page():
    candidate = answer()
    candidate.statements.append(answer("另一条未获支持的结论。", refs=[NVD]).statements[0])
    verdict = review(candidate)
    verdict.claim_support[1].status = "unsupported"
    evidence = {GH: citation(START, MID), NVD: citation(MID, END)}
    ledger = coverage_ledger(plan(), candidate, verdict, question=QUESTION, evidence=evidence)
    assert ledger["tasks"][0]["context_check"]["sufficient"] is False
    assert ledger["final_statement_index_map"] == {"1": 1}


def test_single_fact_does_not_require_exhaustive_context_or_nvd_duplication():
    candidate = answer()
    evidence = {GH: citation(START, MID)}
    ledger = coverage_ledger(
        plan(scope="facts"), candidate, review(candidate), question=QUESTION, evidence=evidence
    )
    assert ledger["tasks"][0]["context_check"]["required"] is False
    assert ledger["complete"] is True


def test_new_structural_proof_is_bound_to_answer_ids_but_unused_evidence_is_not():
    from zhidu.answer_anchors import build_answer_anchors

    candidate = answer()
    evidence = {GH: citation(START, END), NVD: citation(START, MID, source="nvd")}
    original = build_answer_anchors(QUESTION, plan(), candidate, evidence)
    changed = deepcopy(evidence)
    changed[GH]["span_provenance"]["context"]["kind"] = "section"
    assert (
        build_answer_anchors(QUESTION, plan(), candidate, changed)["candidate_digest"]
        != original["candidate_digest"]
    )
    unused = deepcopy(evidence)
    unused[NVD]["span_provenance"]["context"]["kind"] = "section"
    assert (
        build_answer_anchors(QUESTION, plan(), candidate, unused)["candidate_digest"]
        == original["candidate_digest"]
    )


def test_complete_other_block_does_not_hide_partial_condition_context():
    candidate = answer(refs=[GH, NVD])
    other = citation(START, END)
    other["json_pointer"] = "/another-field"
    evidence = {GH: citation(START, MID), NVD: other}
    ledger = coverage_ledger(
        plan(), candidate, review(candidate), question=QUESTION, evidence=evidence
    )
    assert ledger["tasks"][0]["context_check"]["coverage"]["complete_contexts"]
    assert ledger["tasks"][0]["context_check"]["sufficient"] is False
    assert ledger["complete"] is False
