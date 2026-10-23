"""Pure read-plan compilation, no source fetching or model calls."""

import copy
from types import SimpleNamespace

import pytest

from zhidu.agent_team_state import ResearchDecision, TaskPlan
from zhidu.research_plan import compile_read_plan


def plan(*ids):
    return TaskPlan.model_validate(
        {
            "tasks": [
                {
                    "task_id": identity,
                    "requirement": identity,
                    "source_ids": [],
                    "fields": [],
                    "keywords": [],
                    "question_spans": [{"quote": identity}],
                    "source_policy": "any",
                    "required_elements": [identity],
                }
                for identity in ids
            ]
        }
    )


def decision(*rows, action="read_plan"):
    return ResearchDecision.model_validate(
        {"action": action, "task_ids": [], "note": "intent only", "task_reads": list(rows)}
    )


def row(task, contexts=(), evidence=()):
    return {"task_id": task, "context_ids": list(contexts), "evidence_ids": list(evidence)}


def entry(event="event-one", field="description"):
    return {
        "event_id": event,
        "field": field,
        "start": 0,
        "end": 20,
        "kind": "section",
        "label": "source heading",
    }


def state(**contexts):
    return SimpleNamespace(context_index=contexts, evidence={"evidence-one": entry()})


def test_grouping_and_child_ids_are_stable_without_budget_or_priority():
    registry = state(
        c1=entry(), c2=entry(), c3=entry("event-one", "packages"), c4=entry("event-two")
    )
    result = compile_read_plan(
        decision(row("second", ["c4", "c2"]), row("first", ["c1", "c3"])),
        plan("first", "second"),
        registry,
        "research:0:1",
    )
    assert result["feedback"] == []
    assert [item["task_id"] for item in result["task_reads"]] == ["first", "second"]
    assert [child["arguments"] for child in result["children"]] == [
        {
            "event_id": "event-one",
            "fields": ["description"],
            "context": "section",
            "context_ids": ["c1", "c2"],
        },
        {
            "event_id": "event-one",
            "fields": ["packages"],
            "context": "section",
            "context_ids": ["c3"],
        },
        {
            "event_id": "event-two",
            "fields": ["description"],
            "context": "section",
            "context_ids": ["c4"],
        },
    ]
    assert [child["child_id"] for child in result["children"]] == [
        f"research:0:1:tool:{index}" for index in range(3)
    ]
    assert [child["request_index"] for child in result["children"]] == [0, 1, 2]
    assert result["children"][0]["task_ids"] == ["first", "second"]


def test_more_than_four_contexts_in_one_field_splits_without_dropping_any_selection():
    ids = [f"c{index}" for index in range(7)]
    registry = state(**{identity: entry() for identity in ids})
    result = compile_read_plan(decision(row("one", ids)), plan("one"), registry, "read")
    assert [child["arguments"]["context_ids"] for child in result["children"]] == [ids[:4], ids[4:]]
    assert all(
        child["tool"] == "read_fields" and len(child["arguments"]["fields"]) == 1
        for child in result["children"]
    )


def test_shared_context_across_tasks_is_fetched_once_with_full_task_mapping():
    registry = state(shared=entry(), other=entry())
    result = compile_read_plan(
        decision(row("b", ["shared"]), row("a", ["shared", "other"])),
        plan("a", "b"),
        registry,
        "parent",
    )
    assert len(result["children"]) == 1
    child = result["children"][0]
    assert child["arguments"]["context_ids"] == ["shared", "other"]
    assert child["task_ids"] == ["a", "b"]
    assert child["context_task_ids"] == {"shared": ["a", "b"], "other": ["a"]}


def test_evidence_only_task_is_valid_when_another_task_selects_a_context():
    result = compile_read_plan(
        decision(row("one", evidence=["evidence-one"]), row("two", ["c1"])),
        plan("one", "two"),
        state(c1=entry()),
        "parent",
    )
    assert result["feedback"] == []
    assert result["children"][0]["task_ids"] == ["two"]
    assert result["task_reads"][0]["evidence_ids"] == ["evidence-one"]


@pytest.mark.parametrize(
    "rows,code",
    [
        ([], "missing_task_ids"),
        ([row("one", ["c1"])], "missing_task_ids"),
        ([row("one", ["c1"]), row("one", ["c1"])], "duplicate_task_ids"),
        ([row("one", ["c1"]), row("two", ["c1"]), row("unknown", ["c1"])], "unknown_task_ids"),
        ([row("one", ["c1", "c1"]), row("two", ["c1"])], "duplicate_context_ids"),
        (
            [row("one", ["c1"], ["evidence-one", "evidence-one"]), row("two", ["c1"])],
            "duplicate_evidence_ids",
        ),
        ([row("one", ["not-issued"]), row("two", ["c1"])], "unknown_context_ids"),
        ([row("one", ["c1"], ["not-observed"]), row("two", ["c1"])], "unknown_evidence_ids"),
        ([row("one"), row("two", ["c1"])], "task_has_no_observed_or_selected_ids"),
        (
            [row("one", evidence=["evidence-one"]), row("two", evidence=["evidence-one"])],
            "no_context_selected",
        ),
    ],
)
def test_any_relationship_error_prevents_all_children_including_other_valid_tasks(rows, code):
    result = compile_read_plan(decision(*rows), plan("one", "two"), state(c1=entry()), "parent")
    assert result["children"] == []
    assert code in {feedback["code"] for feedback in result["feedback"]}
    assert all(isinstance(feedback["ids"], list) for feedback in result["feedback"])


@pytest.mark.parametrize(
    "registry,key,code",
    [
        ("context_index", "event_id", "unlocatable_context_ids"),
        ("context_index", "field", "unlocatable_context_ids"),
        ("evidence", "event_id", "unlocatable_evidence_ids"),
        ("evidence", "field", "unlocatable_evidence_ids"),
    ],
)
def test_existing_but_unlocatable_entries_are_feedback_not_guessed_targets(registry, key, code):
    current = state(c1=entry())
    target = (
        current.context_index["c1"]
        if registry == "context_index"
        else current.evidence["evidence-one"]
    )
    target.pop(key)
    result = compile_read_plan(
        decision(row("one", ["c1"], ["evidence-one"])), plan("one"), current, "parent"
    )
    assert result["children"] == [] and code in {item["code"] for item in result["feedback"]}


def test_duplicate_ids_across_tasks_are_allowed_for_both_reference_kinds():
    result = compile_read_plan(
        decision(row("one", ["c1"], ["evidence-one"]), row("two", ["c1"], ["evidence-one"])),
        plan("one", "two"),
        state(c1=entry()),
        "parent",
    )
    assert result["feedback"] == [] and len(result["children"]) == 1
    assert result["children"][0]["context_task_ids"]["c1"] == ["one", "two"]


def test_state_mapping_form_and_all_inputs_remain_unchanged_and_results_are_independent():
    current = {"context_index": {"c1": entry()}, "evidence": {"evidence-one": entry()}}
    selected, tasks = decision(row("one", ["c1"], ["evidence-one"])), plan("one")
    before = copy.deepcopy((selected.model_dump(), tasks.model_dump(), current))
    result = compile_read_plan(selected, tasks, current, "parent")
    assert before == (selected.model_dump(), tasks.model_dump(), current)
    result["children"][0]["arguments"]["context_ids"].append("not-an-input")
    result["children"][0]["context_task_ids"]["c1"].append("not-an-input")
    result["task_reads"][0]["evidence_ids"].append("not-an-input")
    assert before == (selected.model_dump(), tasks.model_dump(), current)
    assert "covered" not in json_keys(result)


def json_keys(value):
    if isinstance(value, dict):
        return set(value).union(*(json_keys(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(json_keys(child) for child in value))
    return set()


def test_unsupported_action_and_invalid_parent_id_cannot_emit_children():
    assert (
        compile_read_plan(decision(action="ready"), plan("one"), state(c1=entry()), "parent")[
            "children"
        ]
        == []
    )
    result = compile_read_plan(decision(row("one", ["c1"])), plan("one"), state(c1=entry()), "")
    assert result["children"] == [] and result["feedback"][0]["code"] == "invalid_parent_call_id"


@pytest.mark.parametrize(
    "task_ids,code", [(["unknown"], "unknown_task_ids"), (["one", "one"], "duplicate_task_ids")]
)
def test_optional_top_level_task_declarations_cannot_contain_invalid_ids(task_ids, code):
    selected = decision(row("one", ["c1"]))
    selected.task_ids = task_ids
    result = compile_read_plan(selected, plan("one"), state(c1=entry()), "parent")
    assert result["children"] == [] and code in {item["code"] for item in result["feedback"]}
