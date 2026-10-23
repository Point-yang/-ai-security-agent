"""Real create_agent/ToolNode batches with local source and SDK fixtures only."""

import json
import threading
from typing import TypedDict

import httpx
import pytest
from sqlalchemy import select
from test_agent_team import RoleScript
from test_member_a_rag_context import fixture_advisory, ingest

pytest.importorskip("langchain")

from zhidu.agent_research import _research_engine, public_evidence
from zhidu.agent_roles import RoleRunner
from zhidu.agent_team_state import TaskPlan
from zhidu.langchain_tools import SourceRuntime, ToolSession
from zhidu.models import Asset, IntelEvent
from zhidu.rag import RagRequest

QUESTION = "读取后段信任边界和补丁覆盖"


def plan():
    return TaskPlan.model_validate(
        {
            "tasks": [
                {
                    "task_id": "conditions",
                    "requirement": QUESTION,
                    "source_ids": ["github-advisories"],
                    "fields": ["description"],
                    "contains": None,
                    "keywords": ["Trust boundary", "Patches"],
                    "question_spans": [{"quote": QUESTION}],
                    "source_policy": "any",
                    "required_elements": ["信任边界", "补丁覆盖"],
                }
            ]
        }
    )


def later_advisory(advisory):
    value = fixture_advisory(advisory)
    value["description"] = (
        "Initial background. " * 140
        + "\n\n## Trust boundary\nOnly trusted manifests may be deserialized.\n\n"
        + "Additional background. " * 140
        + "\n\n## Patches\nUpgrade to 1.2.0; dangerous opt-in remains an exception.\n"
    )
    return value


def setup_tools(session, store, settings, advisory, *, asset_id=None, max_calls=6):
    event = session.scalar(select(IntelEvent))
    body = RagRequest(
        question=QUESTION,
        query=advisory["ghsa_id"],
        mode="lexical",
        generation="agent",
        agent_backend="team",
        asset_id=asset_id,
    )
    runtime = SourceRuntime(session, store, settings, None, max_calls=max_calls, clock=lambda: 0)
    tools = ToolSession(runtime, body, asset_id)
    tools.invoke("retrieve", {"query": advisory["ghsa_id"], "mode": "lexical", "limit": 1})
    return tools, event.id


def child(event_id, contains, **arguments):
    return {
        "tool_name": "read_fields",
        "arguments": {
            "event_id": event_id,
            "fields": ["description"],
            "contains": contains,
            "limit": 1,
            **arguments,
        },
        "task_ids": ["conditions"],
    }


def batch(*requests):
    return {
        "action": "batch",
        "requests": list(requests),
        "task_ids": ["conditions"],
        "note": "同一研究决定读取两个后段",
    }


def ready():
    return {"action": "ready", "task_ids": ["conditions"], "note": "已有引文可交给正文修正"}


def test_one_real_research_decision_reads_two_later_sections_sequentially(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, later_advisory(advisory))
    with database() as session:
        tools, event_id = setup_tools(session, store, settings, advisory)
        script = RoleScript(
            {
                "research:0:0": batch(
                    child(event_id, "Trust boundary"), child(event_id, "Patches")
                ),
                "research:0:1": ready(),
            },
            limit=7,
        )
        active, maximum = 0, 0
        lock = threading.Lock()
        original = tools.invoke

        def sequential(*args, **kwargs):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            try:
                return original(*args, **kwargs)
            finally:
                with lock:
                    active -= 1

        monkeypatch.setattr(tools, "invoke", sequential)
        trace = []
        _research_engine(script, tools, plan(), QUESTION, 0, [], trace)
        assert maximum == 1
        assert [t["input"].get("contains") for t in tools.runtime.steps[1:]] == [
            "Trust boundary",
            "Patches",
        ]
        entry = trace[0]
        assert entry["action"] == "batch" and entry["decision_completed"]
        assert [x["child_id"] for x in entry["tool_observations"]] == [
            "research:0:0:tool:0",
            "research:0:0:tool:1",
        ]
        assert all(
            x["status"] == "completed" and x["novelty"]["new_source_chars"] > 0
            for x in entry["tool_observations"]
        )
        assert entry["novelty"]["new_source_chars"] > 0
        assert tools.attempted_calls == 3


def test_repeat_of_the_same_span_is_zero_without_forcing_a_new_source(
    database, store, settings, advisory
):
    ingest(database, store, later_advisory(advisory))
    with database() as session:
        tools, event_id = setup_tools(session, store, settings, advisory)
        tools.invoke("read_fields", child(event_id, "Patches")["arguments"])
        # The changed limit is a distinct admissible request, while the source
        # span remains identical. New handles/chunk IDs are not the metric.
        script = RoleScript(
            {
                "research:0:0": {
                    "action": "tool",
                    **child(event_id, "Patches", limit=2),
                    "note": "核查既有引文",
                },
                "research:0:1": ready(),
            },
            limit=7,
        )
        trace = []
        _research_engine(script, tools, plan(), QUESTION, 0, [], trace)
        assert trace[0]["novelty"]["new_source_chars"] == 0
        assert trace[0]["tool_observations"][0]["child_id"] == "research:0:0"
        assert trace[0]["tool_observations"][0]["status"] == "completed"
        assert trace[-1]["action"] == "ready"


def test_invalid_child_parameters_keep_valid_sibling_and_consume_tool_budget(
    database, store, settings, advisory
):
    ingest(database, store, later_advisory(advisory))
    with database() as session:
        tools, event_id = setup_tools(session, store, settings, advisory)
        script = RoleScript(
            {
                "research:0:0": batch(
                    child(event_id, "Trust boundary", limit=99), child(event_id, "Patches")
                ),
                "research:0:1": ready(),
            },
            limit=7,
        )
        trace = []
        _research_engine(script, tools, plan(), QUESTION, 0, [], trace)
        assert [x["status"] for x in trace[0]["tool_observations"]] == ["failed", "completed"]
        assert trace[0]["tool_observations"][0]["error"] == "invalid_arguments"
        assert trace[0]["tool_observations"][1]["novelty"]["new_source_chars"] > 0
        assert tools.attempted_calls == 3


def test_batch_admission_truncates_before_sending_tools_and_records_skipped_children(
    database, store, settings, advisory
):
    ingest(database, store, later_advisory(advisory))
    with database() as session:
        tools, event_id = setup_tools(session, store, settings, advisory, max_calls=2)
        script = RoleScript(
            {"research:0:0": batch(child(event_id, "Trust boundary"), child(event_id, "Patches"))},
            limit=7,
        )
        trace = []
        _research_engine(script, tools, plan(), QUESTION, 0, [], trace)
        assert len(trace[0]["admission"]["admitted"]) == 1
        assert trace[0]["admission"]["skipped"][0]["executed"] is False
        assert trace[0]["admission"]["skipped"][0]["child_id"] == "research:0:0:tool:1"
        assert tools.attempted_calls == 2
        assert len(script.calls()) == 1


def test_multiple_batches_cannot_exceed_six_tools_or_spend_first_cycle_model_reserve(
    database, store, settings, advisory
):
    ingest(database, store, later_advisory(advisory))
    with database() as session:
        tools, event_id = setup_tools(session, store, settings, advisory)
        script = RoleScript(
            {
                "research:0:0": batch(
                    child(event_id, "Trust boundary"),
                    child(event_id, "Patches"),
                    child(event_id, "Initial background"),
                ),
                "research:0:1": batch(
                    child(event_id, "Additional background"),
                    child(event_id, "missing"),
                    child(event_id, "extra missing"),
                ),
            },
            limit=7,
        )
        trace = []
        _research_engine(script, tools, plan(), QUESTION, 0, [], trace)
        assert tools.attempted_calls == 6
        assert len(script.calls()) == 2 and script.remaining_model_calls == 5
        assert len(trace[1]["admission"]["admitted"]) == 2
        assert len(trace[1]["admission"]["skipped"]) == 1
        assert all(x["actual_tool_attempts"] == 1 for t in trace for x in t["tool_observations"])


def test_unplanned_question_requirement_passes_unchanged_and_empty_task_ids_are_allowed(
    database, store, settings, advisory
):
    ingest(database, store, later_advisory(advisory))
    with database() as session:
        tools, event_id = setup_tools(session, store, settings, advisory)
        requested = child(event_id, "Trust boundary")
        requested["task_ids"] = []
        script = RoleScript({"research:0:0": batch(requested), "research:0:1": ready()}, limit=7)
        payload = frozen_input(script, tools)
        payload["unplanned_requirements"] = [{"requirement": "信任边界尚未进入计划"}]
        trace = []
        _research_engine(script, tools, plan(), QUESTION, 0, [], trace, payload)
        assert script.payloads[0][1]["unplanned_requirements"] == payload["unplanned_requirements"]
        assert trace[0]["tool_observations"][0]["status"] == "completed"


def frozen_input(runner, tools):
    return {
        "question": QUESTION,
        "plan": plan().model_dump(),
        "gaps": [],
        "evidence": public_evidence(tools),
        "constraints": [],
        "tools": {t.name: t.args_schema.model_json_schema() for t in tools.tools()},
        "mode": "lexical",
        "initial_query": tools.body.query,
        "selected_asset_available": bool(tools.selected_asset),
        "model_calls_at_start": runner.remaining_model_calls,
        "tool_calls_at_start": tools.attempted_calls,
    }


class ResearchSDK:
    def __init__(self, decision):
        self.decision, self.requests = decision, []

    def handle(self, request):
        value = json.loads(request.content)
        self.requests.append(value)
        return httpx.Response(
            200,
            json={
                "id": f"batch-sdk-{len(self.requests)}",
                "object": "chat.completion",
                "created": 1791806400,
                "model": value["model"],
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(self.decision, ensure_ascii=False),
                        },
                    }
                ],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 5,
                    "total_tokens": 15,
                    "prompt_cache_hit_tokens": 0,
                    "prompt_cache_miss_tokens": 10,
                },
            },
        )


def test_crash_between_batch_children_replays_paid_decision_and_first_tool_free(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, later_advisory(advisory))
    cloud = settings.model_copy(
        update={"deepseek_api_key": "mock-batch-sdk-key", "agent_max_model_calls": 3}
    )
    # model_copy does not validate SecretStr; use a fresh validated Settings.
    cloud = type(settings)(_env_file=None, **cloud.model_dump())
    with database() as session:
        tools, event_id = setup_tools(session, store, cloud, advisory)
        sdk = ResearchSDK(batch(child(event_id, "Trust boundary"), child(event_id, "Patches")))
        transport = httpx.MockTransport(sdk.handle)
        with RoleRunner(
            cloud,
            tools.runtime,
            tools,
            transport=transport,
            checkpoint_key="batch-child-crash",
            manifest={"test": "batch"},
        ) as runner:
            runner.recovery.save_context(tools.snapshot())
            payload = frozen_input(runner, tools)
            original = tools.invoke
            interrupted = False

            def crash(*args, **kwargs):
                nonlocal interrupted
                if interrupted:
                    raise RuntimeError("process_stopped_before_remaining_child")
                result = original(*args, **kwargs)
                if tools.call_context.identity == "research:1:0:tool:0":
                    interrupted = True
                    raise RuntimeError("process_stopped_after_first_child_receipt")
                return result

            monkeypatch.setattr(tools, "invoke", crash)
            with pytest.raises(RuntimeError):
                _research_engine(runner, tools, plan(), QUESTION, 1, [], [], payload)
            assert len(sdk.requests) == 1
            assert tools.attempted_calls == 2
    with database() as session:
        tools, _ = setup_tools(session, store, cloud, advisory)
        with RoleRunner(
            cloud,
            tools.runtime,
            tools,
            transport=transport,
            checkpoint_key="batch-child-crash",
            checkpoint_resume_required=True,
            manifest={"test": "batch"},
        ) as runner:
            trace = []
            _research_engine(runner, tools, plan(), QUESTION, 1, [], trace, payload)
            assert len(sdk.requests) == 1
            assert runner.current_attempt_external_requests == 0
            assert runner.recovery.replayed_models == 1
            assert tools.attempted_calls == 3
            observations = trace[0]["tool_observations"]
            assert observations[0]["replayed"] and observations[0]["actual_tool_attempts"] == 0
            assert observations[0]["current_attempt_novelty"]["new_source_chars"] == 0
            assert observations[1]["actual_tool_attempts"] == 1
            assert trace[0]["decision_completed"]
            assert len(trace[0]["admission"]["admitted"]) == 2
            assert [x["tool"] for x in tools.runtime.steps] == [
                "retrieve",
                "read_fields",
                "read_fields",
            ]
            assert len(trace) == 1


def test_asset_artifact_in_batch_never_enters_next_model_payload(
    database, store, settings, advisory
):
    ingest(database, store, later_advisory(advisory))
    with database.begin() as session:
        asset = Asset(
            name="private-batch-host",
            environment="internal",
            criticality="low",
            sbom_sha256="0" * 64,
        )
        session.add(asset)
        session.flush()
        asset_id = asset.id
    with database() as session:
        tools, event_id = setup_tools(session, store, settings, advisory, asset_id=asset_id)
        script = RoleScript(
            {
                "research:0:0": batch(
                    {
                        "tool_name": "asset_exposure",
                        "arguments": {"event_id": event_id},
                        "task_ids": [],
                    },
                    child(event_id, "Patches"),
                ),
                "research:0:1": ready(),
            },
            limit=7,
        )
        trace = []
        _research_engine(script, tools, plan(), QUESTION, 0, [], trace)
        outbound = json.dumps(script.payloads, ensure_ascii=False)
        assert asset_id not in outbound and "private-batch-host" not in outbound
        assert '"artifact"' not in outbound
        local = next(r["result"] for r in tools.results if r["tool"] == "asset_exposure")
        assert local["asset_id"] == asset_id and local["private_asset_data"]
        asset_observation = next(
            item for item in trace[0]["tool_observations"] if item["tool"] == "asset_exposure"
        )
        assert asset_observation["novelty"]["new_source_chars"] == 0


def test_unknown_plan_task_rejected_before_any_batch_tool_execution(
    database, store, settings, advisory
):
    ingest(database, store, later_advisory(advisory))
    with database() as session:
        tools, event_id = setup_tools(session, store, settings, advisory)
        bad = child(event_id, "Patches")
        bad["task_ids"] = ["invented-task"]
        script = RoleScript(
            {"research:0:0": batch(child(event_id, "Trust boundary"), bad)}, limit=7
        )
        with pytest.raises(ValueError, match="researcher_unknown_task"):
            _research_engine(script, tools, plan(), QUESTION, 0, [], [])
        assert tools.attempted_calls == 1


def test_unknown_ready_task_is_rejected_without_forcing_new_source_reads(
    database, store, settings, advisory
):
    ingest(database, store, later_advisory(advisory))
    with database() as session:
        tools, _ = setup_tools(session, store, settings, advisory)
        bad = ready()
        bad["task_ids"] = ["invented-task"]
        script = RoleScript({"research:0:0": bad}, limit=7)
        with pytest.raises(ValueError, match="researcher_unknown_task"):
            _research_engine(script, tools, plan(), QUESTION, 0, [], [])
        assert tools.attempted_calls == 1


def test_batch_cannot_read_an_undiscovered_event_but_valid_sibling_still_runs(
    database, store, settings, advisory
):
    ingest(database, store, later_advisory(advisory))
    foreign = later_advisory(advisory)
    foreign.update(ghsa_id="GHSA-dddd-eeee-ffff", cve_id="CVE-2099-7777")
    ingest(database, store, foreign)
    with database() as session:
        tools, event_id = setup_tools(session, store, settings, advisory)
        foreign_id = session.scalar(
            select(IntelEvent.id).where(IntelEvent.external_id == foreign["ghsa_id"])
        )
        assert foreign_id not in tools.events
        script = RoleScript(
            {
                "research:0:0": batch(child(foreign_id, "Patches"), child(event_id, "Patches")),
                "research:0:1": ready(),
            },
            limit=7,
        )
        trace = []
        _research_engine(script, tools, plan(), QUESTION, 0, [], trace)
        assert trace[0]["tool_observations"][0]["error"] == "target_not_in_current_retrieval"
        assert trace[0]["tool_observations"][1]["status"] == "completed"
        assert foreign_id not in {c["event_id"] for c in tools.evidence.values()}
        assert tools.attempted_calls == 3


def test_parent_graph_checkpoint_restores_batch_admission_and_observations(
    database, store, settings, advisory, monkeypatch
):
    import sqlite3

    from langgraph.checkpoint.sqlite import SqliteSaver
    from langgraph.graph import END, START, StateGraph

    class ResearchState(TypedDict, total=False):
        research_input: dict
        research_trace: list

    ingest(database, store, later_advisory(advisory))
    cloud = type(settings)(
        _env_file=None,
        **(
            settings.model_dump()
            | {
                "deepseek_api_key": "mock-nested-batch-key",
                "agent_max_model_calls": 3,
            }
        ),
    )
    sdk = None
    interruption = [False]
    graph_config = {"configurable": {"thread_id": "nested-batch-graph"}, "max_concurrency": 1}

    def graph_for(runner, tools, saver):
        def prepare(_state):
            return {"research_input": frozen_input(runner, tools), "research_trace": []}

        def research(state):
            trace = list(state.get("research_trace", []))
            _research_engine(runner, tools, plan(), QUESTION, 1, [], trace, state["research_input"])
            return {"research_trace": trace}

        graph = StateGraph(ResearchState)
        graph.add_node("prepare", prepare)
        graph.add_node("research", research)
        graph.add_edge(START, "prepare")
        graph.add_edge("prepare", "research")
        graph.add_edge("research", END)
        return graph.compile(checkpointer=saver)

    with database() as session:
        tools, event_id = setup_tools(session, store, cloud, advisory)
        sdk = ResearchSDK(batch(child(event_id, "Trust boundary"), child(event_id, "Patches")))
        with RoleRunner(
            cloud,
            tools.runtime,
            tools,
            transport=httpx.MockTransport(sdk.handle),
            checkpoint_key="nested-batch-roles",
            manifest={"test": "nested-batch"},
        ) as runner:
            runner.recovery.save_context(tools.snapshot())
            original = tools.invoke

            def crash(*args, **kwargs):
                if interruption[0]:
                    raise RuntimeError("process_stopped_before_remaining_child")
                result = original(*args, **kwargs)
                if tools.call_context.identity == "research:1:0:tool:0":
                    interruption[0] = True
                    raise RuntimeError("process_stopped_after_first_child_receipt")
                return result

            monkeypatch.setattr(tools, "invoke", crash)
            with sqlite3.connect(
                cloud.agent_checkpoint_path, check_same_thread=False
            ) as connection:
                graph = graph_for(runner, tools, SqliteSaver(connection))
                with pytest.raises(RuntimeError):
                    graph.invoke({}, graph_config, durability="sync")
        assert len(sdk.requests) == 1
    with database() as session:
        tools, _ = setup_tools(session, store, cloud, advisory)
        with RoleRunner(
            cloud,
            tools.runtime,
            tools,
            transport=httpx.MockTransport(sdk.handle),
            checkpoint_key="nested-batch-roles",
            checkpoint_resume_required=True,
            manifest={"test": "nested-batch"},
        ) as runner:
            with sqlite3.connect(
                cloud.agent_checkpoint_path, check_same_thread=False
            ) as connection:
                graph = graph_for(runner, tools, SqliteSaver(connection))
                result = graph.invoke(None, graph_config, durability="sync")
                again = graph.get_state(graph_config).values
            assert len(sdk.requests) == 1 and runner.current_attempt_external_requests == 0
            trace = result["research_trace"]
            assert len(trace) == 1 and trace[0]["decision_completed"]
            assert len(trace[0]["admission"]["admitted"]) == 2
            assert len(trace[0]["tool_observations"]) == 2
            assert trace[0]["novelty"]["new_source_chars"] > 0
            assert trace[0]["current_attempt_novelty"]["new_source_chars"] > 0
            assert sum(x["actual_tool_attempts"] for x in trace[0]["tool_observations"]) == 1
            assert tools.attempted_calls == 3
            assert again["research_trace"] == trace
