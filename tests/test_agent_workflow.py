"""Exercise preparation, conservative routing and the shared native budget."""

import json
from types import SimpleNamespace

import pytest
from test_member_a_rag_context import fixture_advisory, ingest

from zhidu.agent_workflow import _requirements, assess_coverage, run_workflow_agent
from zhidu.rag import RagRequest


def _body(advisory, question="受影响版本和首次修复版本是什么？", backend="auto", **kwargs):
    return RagRequest(
        question=question,
        query=advisory["ghsa_id"],
        generation="agent",
        agent_backend=backend,
        **kwargs,
    )


def _plain_final(messages):
    from langchain_core.messages import AIMessage, HumanMessage

    payload = json.loads(
        next(message.content for message in messages if isinstance(message, HumanMessage))
    )
    item = next(c for c in payload["prepared_evidence"] if c["field"] == "packages")
    return AIMessage(
        content=json.dumps(
            {
                "answer_class": "evidence",
                "statements": [
                    {
                        "text": "该公告首次修复版本为 1.2.0。",
                        "evidence": [{"evidence_id": item["evidence_id"]}],
                    }
                ],
                "required_facts": ["首次修复版本"],
                "missing_facts": [],
                "limitations": [],
                "message": "",
            }
        )
    )


@pytest.mark.parametrize("backend", ["workflow", "auto"])
def test_complete_structured_task_uses_one_final_model_call(
    database, store, settings, advisory, backend
):
    pytest.importorskip("langchain")
    from test_langchain_agent import ScriptedModel

    ingest(database, store, fixture_advisory(advisory))
    model = ScriptedModel(actions=[_plain_final])
    with database() as session:
        result = run_workflow_agent(
            session, store, settings, _body(advisory, backend=backend), None, model=model
        )
    assert result["generation"]["status"] == "completed", result
    assert result["answer_class"] == "evidence"
    assert model.position == 1
    assert result["routing"]["chosen_backend"] == "workflow"
    assert not result["routing"]["gaps"]
    assert result["routing"]["required_fields"] == ["packages"]
    assert result["agent"]["backend"] == "fixed_source_workflow"
    assert result["agent_backend"] == backend
    assert [step["tool"] for step in result["tools"]] == ["retrieve", "read_fields"]


def test_long_requested_prose_goes_directly_to_adaptive_loop(database, store, settings, advisory):
    pytest.importorskip("langchain")
    from langchain_core.messages import HumanMessage
    from test_langchain_agent import ScriptedModel, call, finish

    ingest(database, store, fixture_advisory(advisory))

    def read_late(messages):
        payload = json.loads(next(m.content for m in messages if isinstance(m, HumanMessage)))
        item = payload["prepared_evidence"][0]
        return call(
            "read_fields",
            {
                "event_id": item["event_id"],
                "fields": ["description"],
                "contains": "Patches",
                "limit": 1,
            },
        )

    model = ScriptedModel(actions=[read_late, finish])
    with database() as session:
        result = run_workflow_agent(
            session,
            store,
            settings,
            _body(advisory, question="来源的修复建议是什么？"),
            None,
            model=model,
        )
    assert result["generation"]["status"] == "completed", result
    assert model.position == 2
    assert result["routing"]["chosen_backend"] == "langchain"
    assert result["agent"]["backend"] == "auto_langchain"
    assert result["routing"]["gaps"][0]["code"] == "requested_field_coverage_incomplete"
    assert result["routing"]["prepared_tool_calls"] == 2
    assert len(result["tools"]) == 3
    assert result["tools"][-1]["input"]["contains"] == "Patches"
    assert any("Upgrade to 1.2.0" in citation["text"] for citation in result["citations"])


def test_adaptive_engine_receives_same_budget_start_and_all_call_options(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    settings = settings.model_copy(update={"agent_max_tool_calls": 3})
    tick = [100.0]
    observed = {}
    sentinels = {
        name: object() for name in ("model", "transport", "history", "conversation_context")
    }

    def engine(session, store, settings, body, encoder, **kwargs):
        tools = kwargs["prepared_tools"]
        observed.update(kwargs)
        assert tools.runtime.start == 100.0
        assert tools.attempted_calls == 2
        assert tools.runtime.max_calls == 3
        assert tools.runtime.deadline_seconds == settings.agent_deadline_seconds
        assert kwargs["final_only"] is False
        event_id = next(iter(tools.events))
        assert (
            tools.invoke(
                "read_fields",
                {
                    "event_id": event_id,
                    "fields": ["description"],
                    "contains": "Patches",
                    "limit": 1,
                },
            )[1]["status"]
            == "completed"
        )
        assert (
            tools.invoke("event_details", {"event_id": event_id})[1]["error"]
            == "call_budget_exceeded"
        )
        assert tools.runtime.start == 100.0
        return {"agent": {"backend": "langchain"}, "cost": {"external_requests": 0}}

    monkeypatch.setattr("zhidu.agent_workflow.run_langchain_agent", engine)
    with database() as session:
        result = run_workflow_agent(
            session,
            store,
            settings,
            _body(advisory, question="来源的修复建议是什么？"),
            None,
            clock=lambda: tick[0],
            checkpoint_key="workflow-test-001",
            checkpoint_resume_required=True,
            **sentinels,
        )
    assert result["routing"]["remaining_tool_calls"] == 1
    assert observed["checkpoint_key"] == "workflow-test-001"
    assert observed["checkpoint_resume_required"] is True
    assert all(observed[name] is value for name, value in sentinels.items())


def test_preflight_and_empty_evidence_make_no_model_request(
    database, store, settings, advisory, monkeypatch
):
    called = []

    def should_not_call(*args, **kwargs):
        called.append(kwargs)
        raise AssertionError("empty evidence must not reach final model engine")

    monkeypatch.setattr("zhidu.agent_workflow.run_langchain_agent", should_not_call)
    with database() as session:
        result = run_workflow_agent(
            session,
            store,
            settings,
            RagRequest(question="库中的一般信息", query="absent-query", agent_backend="auto"),
            None,
        )
    assert result["routing"]["chosen_backend"] == "no_evidence"
    assert result["answer_class"] == "refused"
    assert result["cost"]["external_requests"] == 0
    assert result["agent"]["tool_steps"] == result["tools"]
    assert result["agent"]["planner_usage"] == []
    assert result["agent"]["decisions"] == []
    assert result["agent"]["limits"]["tool_calls"] == settings.agent_max_tool_calls
    assert result["context"]["citations"] == 0
    assert not called


def test_missing_asset_preflight_has_product_trace(database, store, settings):
    pytest.importorskip("langchain")
    from test_langchain_agent import ScriptedModel

    model = ScriptedModel(actions=[])
    with database() as session:
        result = run_workflow_agent(
            session,
            store,
            settings,
            RagRequest(question="我的资产是否受影响？", agent_backend="auto"),
            None,
            model=model,
        )
    assert result["answer_class"] == "clarification"
    assert result["routing"]["chosen_backend"] == "preflight"
    assert result["agent"]["backend"] == "auto_preflight"
    assert result["context"]["citations"] == 0
    assert model.position == 0


def test_visible_coverage_does_not_infer_source_absence_or_unasked_fields():
    requirements = _requirements("只列受影响版本和首次修复版本")
    citation = {
        "event_id": "event",
        "source_id": "github-advisories",
        "field": "packages",
        "start": 0,
        "end": 80,
        "raw_document_id": "raw",
        "json_pointer": "/vulnerabilities",
        "span_provenance": {"boundary_complete": True, "source_field_chars": 80},
    }
    audit = assess_coverage(SimpleNamespace(evidence={"id": citation}), requirements)
    assert not audit["gaps"]
    assert audit["required_fields"] == ["packages"]
    assert audit["semantic_support_verified"] is False
    assert audit["source_absence_inferred"] is False
    citation["span_provenance"]["boundary_complete"] = False
    audit = assess_coverage(SimpleNamespace(evidence={"id": citation}), requirements)
    assert audit["gaps"] == [
        {"code": "requested_field_coverage_incomplete", "event_id": "event", "field": "packages"}
    ]
    assert "部分可引用片段" in audit["gap_descriptions"][0]


def test_cross_source_requirement_stays_visible_without_guessing_missing_source():
    requirements = _requirements("对照 GitHub 与 NVD 的受影响版本")
    citation = {
        "event_id": "event",
        "source_id": "github-advisories",
        "field": "packages",
        "start": 0,
        "end": 10,
        "raw_document_id": "raw",
        "json_pointer": "/vulnerabilities",
        "span_provenance": {"boundary_complete": True, "source_field_chars": 10},
    }
    audit = assess_coverage(SimpleNamespace(evidence={"id": citation}), requirements)
    assert {gap["code"] for gap in audit["gaps"]} == {
        "requested_source_count_not_returned",
        "requested_source_not_returned",
    }
    assert audit["source_absence_inferred"] is False
    scoped = _requirements("对照两个字段的受影响版本", event_scoped=True)
    assert scoped["minimum_events"] == 1


@pytest.mark.parametrize(
    "question",
    [
        "对照两份来源的原始范围，并说明触发机制",
        "列出受影响范围和修复版本，描述执行风险",
        "受影响版本以及默认加载路径有哪些边界？",
    ],
)
def test_chinese_mixed_version_and_narrative_requirements(question):
    assert _requirements(question)["fields"] == ["packages", "description"]


def test_score_coverage_uses_observed_normalized_name_without_guessing():
    requirements = _requirements("只列 CVSS 评分")
    citation = {
        "event_id": "event",
        "source_id": "github-advisories",
        "field": "cvss_v4",
        "start": 0,
        "end": 10,
        "raw_document_id": "raw",
        "json_pointer": "/cvss/v4",
        "span_provenance": {"boundary_complete": True, "source_field_chars": 10},
    }
    assert not assess_coverage(SimpleNamespace(evidence={"id": citation}), requirements)["gaps"]
    citation["field"] = "description"
    audit = assess_coverage(SimpleNamespace(evidence={"id": citation}), requirements)
    assert audit["gaps"][0]["field"] == "cvss"
    assert audit["source_absence_inferred"] is False
