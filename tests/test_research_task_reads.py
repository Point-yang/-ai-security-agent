"""Bounded research intent syntax; relational failures are runtime feedback."""

import copy

import pytest
from pydantic import ValidationError

from zhidu.agent_team_state import ResearchDecision, ResearchTaskRead


def decision(action="ready", **values):
    return {"action": action, "task_ids": [], "note": "research intent", **values}


def mapping(**values):
    return {"task_id": "conditions", "evidence_ids": [], "context_ids": [], **values}


def test_legacy_decision_and_mapping_defaults_remain_compatible():
    ready = ResearchDecision.model_validate(decision())
    assert ready.task_reads == []
    item = ResearchTaskRead.model_validate({"task_id": "conditions"})
    assert item.evidence_ids == item.context_ids == [] and item.note == ""


def test_read_plan_keeps_per_task_existing_evidence_and_requested_contexts_without_coverage_status():
    raw = decision(
        "read_plan",
        task_reads=[
            mapping(evidence_ids=["a" * 24], note="已有该引用"),
            mapping(task_id="impact", context_ids=["ctx_opaque_1"], note="待读来源结构"),
        ],
    )
    before = copy.deepcopy(raw)
    parsed = ResearchDecision.model_validate(raw)
    assert parsed.model_dump()["task_reads"] == [
        {
            "task_id": "conditions",
            "evidence_ids": ["a" * 24],
            "context_ids": [],
            "note": "已有该引用",
        },
        {
            "task_id": "impact",
            "evidence_ids": [],
            "context_ids": ["ctx_opaque_1"],
            "note": "待读来源结构",
        },
    ]
    assert raw == before
    assert "status" not in ResearchTaskRead.model_json_schema()["properties"]
    assert "covered" not in ResearchTaskRead.model_json_schema()["properties"]


@pytest.mark.parametrize(
    "task_reads",
    [
        [],
        [mapping()],
        [mapping(evidence_ids=["known-evidence"])],
        [mapping(context_ids=["unknown-context"])],
        [mapping(), mapping()],
        [mapping(evidence_ids=["same", "same"], context_ids=["same-context", "same-context"])],
        [mapping(task_id="not-in-current-plan", context_ids=["not-issued"])],
    ],
)
def test_empty_unknown_or_duplicate_relations_stay_parseable_for_feedback(task_reads):
    value = ResearchDecision.model_validate(decision("read_plan", task_reads=task_reads))
    assert len(value.task_reads) == len(task_reads)
    assert value.tool_name is None and value.requests == [] and value.arguments == {}


@pytest.mark.parametrize(
    "extra",
    [
        {"tool_name": "read_fields"},
        {"arguments": {"fields": ["description"]}},
        {"requests": [{"tool_name": "read_fields", "arguments": {}, "task_ids": []}]},
    ],
)
def test_read_plan_cannot_smuggle_direct_or_batch_calls(extra):
    with pytest.raises(ValidationError, match="read_plan_cannot_mix_tool_calls"):
        ResearchDecision.model_validate(
            decision("read_plan", task_reads=[mapping(context_ids=["ctx_1"])], **extra)
        )


@pytest.mark.parametrize(
    "action,extra",
    [
        ("tool", {"tool_name": "read_fields", "arguments": {"event_id": "event"}}),
        ("batch", {"requests": [{"tool_name": "read_fields", "arguments": {}, "task_ids": []}]}),
        ("ready", {}),
    ],
)
def test_other_actions_may_annotate_research_intent_without_changing_execution_syntax(
    action, extra
):
    parsed = ResearchDecision.model_validate(
        decision(action, task_reads=[mapping(evidence_ids=["evidence-handle"])], **extra)
    )
    assert parsed.action == action and parsed.task_reads[0].evidence_ids == ["evidence-handle"]


@pytest.mark.parametrize(
    "action,extra,error",
    [
        (
            "tool",
            {
                "requests": [{"tool_name": "read_fields", "arguments": {}, "task_ids": []}],
                "tool_name": "read_fields",
            },
            "single_tool_cannot_contain_batch",
        ),
        ("batch", {"requests": []}, "batch_requires_requests_only"),
        ("ready", {"tool_name": "read_fields"}, "ready_cannot_call_tool"),
    ],
)
def test_legacy_action_rules_still_reject_invalid_mixtures(action, extra, error):
    with pytest.raises(ValidationError, match=error):
        ResearchDecision.model_validate(decision(action, **extra))


@pytest.mark.parametrize(
    "field,value",
    [
        ("task_id", "x" * 65),
        ("evidence_ids", ["x" * 65]),
        ("context_ids", ["x" * 129]),
        ("evidence_ids", ["x"] * 9),
        ("context_ids", ["x"] * 9),
        ("note", "x" * 121),
        ("task_id", ""),
        ("evidence_ids", [""]),
        ("context_ids", [""]),
        ("evidence_ids", [1]),
        ("context_ids", [None]),
    ],
)
def test_mapping_values_are_syntactically_bounded_without_interpreting_source_content(field, value):
    with pytest.raises(ValidationError):
        ResearchTaskRead.model_validate(mapping(**{field: value}))


def test_no_more_than_eight_task_rows_and_no_semantic_or_model_authored_event_fields():
    with pytest.raises(ValidationError):
        ResearchDecision.model_validate(decision("read_plan", task_reads=[mapping()] * 9))
    for extra in (
        {"status": "covered"},
        {"supported": True},
        {"event_id": "untrusted-event"},
        {"field": "description"},
    ):
        with pytest.raises(ValidationError):
            ResearchTaskRead.model_validate(mapping(**extra))


def test_task_reads_does_not_become_required_in_wire_schema():
    schema = ResearchDecision.model_json_schema()
    assert "task_reads" not in schema["required"]
    assert schema["properties"]["task_reads"]["maxItems"] == 8
    assert "read_plan" in schema["properties"]["action"]["enum"]
    assert schema["$defs"]["ResearchTaskRead"]["additionalProperties"] is False
