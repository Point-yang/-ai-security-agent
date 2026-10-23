"""The actual framework compiles model-chosen task reads under shared limits."""

import copy

from test_agent_team import RoleScript
from test_context_navigation_tools import navigation_source, scoped
from test_member_a_rag_context import ingest

from zhidu.agent_research import (
    _admit,
    _research_engine,
    previously_observed_tasks,
    remaining_output_chars,
    research_evidence_map,
)
from zhidu.agent_team_state import ResearchDecision, TaskPlan
from zhidu.research_allocation import allocate_research_requests, build_allocation_state
from zhidu.source_spans import verify_source_span

QUESTION = "说明条件和信任边界"


def plan():
    return TaskPlan.model_validate(
        {
            "tasks": [
                {
                    "task_id": task,
                    "requirement": label,
                    "source_ids": ["github-advisories"],
                    "fields": ["description"],
                    "keywords": [],
                    "question_spans": [{"quote": QUESTION}],
                    "source_policy": "any",
                    "required_elements": [label],
                }
                for task, label in (("conditions", "条件"), ("trust", "信任边界"))
            ]
        }
    )


def run_fixture(database, store, settings, advisory, *, omit_task=False):
    ingest(database, store, navigation_source(advisory))
    with database() as session:
        tools = scoped(session, store, settings)
        event_id = next(iter(tools.events))

        def choose(payload):
            allocation = payload["allocation_state"]
            assert allocation["field_catalog"][event_id]["available_fields"]
            assert allocation["read_task_ids"] == []
            assert (
                payload["remaining_tool_output_chars"]
                == tools.runtime.max_output_chars - tools.runtime.output_chars
            )
            contexts = list(allocation["context_index"].values())
            condition = next(
                item["context_id"] for item in contexts if item["kind"] == "list_with_intro"
            )
            trust = next(item["context_id"] for item in contexts if "Guidance" in item["label"])
            rows = [{"task_id": "conditions", "context_ids": [condition]}]
            if not omit_task:
                rows.append({"task_id": "trust", "context_ids": [trust]})
            return {
                "action": "read_plan",
                "task_ids": [],
                "note": "逐任务选择实际返回的段落",
                "task_reads": rows,
            }

        runner = RoleScript(
            {
                "research:0:0": {
                    "action": "tool",
                    "tool_name": "read_fields",
                    "task_ids": [],
                    "arguments": {
                        "event_id": event_id,
                        "fields": ["description"],
                        "context": "outline",
                    },
                    "note": "导航",
                },
                "research:0:1": choose,
            },
            limit=7,
        )
        trace = []
        _research_engine(runner, tools, plan(), QUESTION, 0, [], trace)
        assert all(verify_source_span(session, store, item) for item in tools.evidence.values())
        return tools.snapshot(), trace, runner


def test_read_plan_merges_different_required_topics_without_treating_intent_as_support(
    database, store, settings, advisory
):
    snapshot, trace, runner = run_fixture(database, store, settings, advisory)
    assert len(runner.calls()) == 2 and snapshot["attempted_calls"] == 2
    assert len(snapshot["evidence"]) == 2
    admission = trace[1]["admission"]
    assert admission["feedback"] == [] and len(admission["admitted"]) == 1
    child = admission["admitted"][0]
    assert child["task_ids"] == ["conditions", "trust"]
    assert sorted(child["context_task_ids"].values()) == [["conditions"], ["trust"]]
    assert admission["task_reads_are_semantic_coverage"] is False
    assert previously_observed_tasks(trace) == ["conditions", "trust"]
    guide = research_evidence_map(trace, snapshot["evidence"])
    assert not guide["semantic_support_inferred"]
    rows = {row["task_id"]: row for row in guide["tasks"]}
    assert (
        len(rows["conditions"]["returned_evidence_ids"])
        == len(rows["trust"]["returned_evidence_ids"])
        == 1
    )
    condition_handle, trust_handle = (
        rows[task]["returned_evidence_ids"][0] for task in ("conditions", "trust")
    )
    assert condition_handle != trust_handle
    assert "Applications require" in snapshot["evidence"][condition_handle]["text"]
    assert "trusted manifests" in snapshot["evidence"][trust_handle]["text"]
    without_new_receipts = copy.deepcopy(trace)
    for entry in without_new_receipts:
        for receipt in entry["tool_observations"]:
            receipt.pop("returned_evidence_ids", None)
            receipt.pop("returned_context_ids", None)
    assert previously_observed_tasks(without_new_receipts) == []


def test_incomplete_read_plan_returns_feedback_without_partial_execution_or_invented_choice(
    database, store, settings, advisory
):
    snapshot, trace, runner = run_fixture(database, store, settings, advisory, omit_task=True)
    assert len(runner.calls()) == 2 and snapshot["attempted_calls"] == 1
    assert snapshot["evidence"] == {}
    assert trace[1]["admission"]["admitted"] == []
    assert any(
        item["code"] == "missing_task_ids" and item["ids"] == ["trust"]
        for item in trace[1]["admission"]["feedback"]
    )
    assert previously_observed_tasks(trace) == []


def test_frozen_observation_history_survives_new_cycle_and_prioritizes_unread_task():
    state = build_allocation_state(
        {"previously_observed_task_ids": ["conditions"], "evidence": []}, []
    )
    children = [
        {
            "child_id": f"r:tool:{index}",
            "tool": "read_fields",
            "arguments": {"event_id": "e", "fields": ["description"]},
            "task_ids": [task],
            "request_index": index,
        }
        for index, task in enumerate(("conditions", "trust"))
    ]
    allocated = allocate_research_requests(children, state, valid_request_indices=[0, 1])
    assert state["read_task_ids"] == ["conditions"]
    assert [row["task_ids"] for row in allocated["ordered"]] == [["trust"], ["conditions"]]
    assert allocated["semantic_coverage_inferred"] is False


def test_unknown_top_level_task_in_read_plan_is_feedback_without_execution():
    decision = ResearchDecision(action="read_plan", task_ids=["invented"], note="", task_reads=[])
    result = _admit(decision, {}, plan(), "r", 6, allocation_state={})
    assert result["admitted"] == []
    assert any(item["code"] == "unknown_task_ids" for item in result["feedback"])


def test_remaining_output_budget_counts_saved_tool_text_once_and_keeps_unknown_unknown():
    from langchain_core.messages import ToolMessage

    payload = {"tool_output_chars_at_start": 30, "tool_output_chars_limit": 100}
    message = ToolMessage(content="原文abc", tool_call_id="one")
    assert remaining_output_chars(payload, [message, message]) == 65
    assert (
        remaining_output_chars(
            payload, [message, ToolMessage(content="different", tool_call_id="one")]
        )
        is None
    )
    assert remaining_output_chars({}, [message]) is None
