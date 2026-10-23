"""Prepared evidence uses one SDK JSON call and survives completed-reply crashes."""

import json

import httpx
import pytest
from test_agent_recovery import ProcessCrash
from test_langchain_agent import body
from test_member_a_rag_context import fixture_advisory, ingest

from zhidu.agent_checkpoint import RecoveryStore
from zhidu.langchain_agent import run_langchain_agent
from zhidu.langchain_tools import SourceRuntime, ToolSession
from zhidu.source_spans import verify_source_span

DESCRIPTION = (
    "Only a configured video backend accepts the large frame limit and can exhaust frontend memory. "
    "The source describes a possible effect under this configuration rather than guaranteed exhaustion."
)


@pytest.fixture
def prepared_advisory(database, store, advisory):
    data = fixture_advisory(advisory)
    data["description"] = DESCRIPTION
    ingest(database, store, data)
    return data


def options(settings):
    return settings.model_copy(
        update={
            "deepseek_api_key": type(settings.deepseek_api_key)("mock-provider-key"),
            "agent_max_model_calls": 3,
        }
    )


def prepare(session, store, settings, advisory):
    request = body(advisory).model_copy(update={"question": "来源中的触发条件及可能影响是什么？"})
    tools = ToolSession(SourceRuntime(session, store, settings, None), request, None)
    retrieved = json.loads(
        tools.invoke("retrieve", {"query": advisory["ghsa_id"], "mode": "lexical", "limit": 1})[0]
    )
    assert retrieved["status"] == "completed"
    event_id = retrieved["result"]["items"][0]["citation"]["event_id"]
    fields = json.loads(
        tools.invoke("read_fields", {"event_id": event_id, "fields": ["description"], "limit": 1})[
            0
        ]
    )
    assert fields["status"] == "completed"
    return request, tools


def candidate(evidence):
    item = next(item for item in evidence if item["field"] == "description")
    return {
        "answer_class": "evidence",
        "statements": [
            {
                "text": "只有启用指定视频后端时，大帧上限才可能耗尽前端内存。",
                "evidence": [{"evidence_id": item["evidence_id"]}],
            }
        ],
        "required_facts": ["触发条件", "可能影响"],
        "missing_facts": [],
        "limitations": [],
        "message": "",
    }


def sdk_transport(requests, mutate=None):
    def handle(request):
        payload = json.loads(request.content)
        requests.append(payload)
        assert not payload.get("tools")
        assert payload["response_format"] == {"type": "json_object"}
        task = json.loads(payload["messages"][-1]["content"])
        assert task["task_policy"] == "fixed_workflow_final_only"
        assert task["prepared_evidence"]
        answer = candidate(task["prepared_evidence"])
        if mutate:
            mutate(answer)
        return httpx.Response(
            200,
            json={
                "id": "prepared-final-test",
                "object": "chat.completion",
                "created": 1,
                "model": "mock-source-model",
                "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": json.dumps(answer)},
                    }
                ],
            },
        )

    return httpx.MockTransport(handle)


def execute(database, store, settings, advisory, transport, *, checkpoint_key=None):
    with database() as session:
        request, tools = prepare(session, store, settings, advisory)
        prepared_call_count = tools.attempted_calls
        result = run_langchain_agent(
            session,
            store,
            settings,
            request,
            None,
            prepared_tools=tools,
            final_only=True,
            transport=transport,
            checkpoint_key=checkpoint_key,
        )
        # Final-only generation may not append a hidden retrieval/tool phase.
        assert tools.attempted_calls == prepared_call_count
        return result


def test_prepared_sdk_final_only_has_one_json_call_and_server_owned_whole_span(
    database, store, settings, prepared_advisory
):
    requests = []
    result = execute(database, store, options(settings), prepared_advisory, sdk_transport(requests))
    assert result["generation"]["status"] == "completed", result
    assert len(requests) == result["cost"]["external_requests"] == 1
    assert result["cost"]["billed_tokens"] == 30
    assert [call["phase"] for call in result["agent"]["model_calls"]] == ["json_final"]
    assert [tool["tool"] for tool in result["tools"]] == ["retrieve", "read_fields"]
    citation = result["citations"][0]
    assert citation["text"] == DESCRIPTION
    assert result["generated_claims"][0]["evidence"][0]["quote"] == citation["text"]
    assert citation["span_provenance"]["boundary_complete"] is True
    with database() as session:
        assert verify_source_span(session, store, citation)


def test_prepared_completed_graph_replay_sends_zero_sdk_requests(
    database, store, settings, prepared_advisory
):
    requests = []
    opts = options(settings)
    first = execute(
        database,
        store,
        opts,
        prepared_advisory,
        sdk_transport(requests),
        checkpoint_key="prepared-completed",
    )
    assert first["generation"]["status"] == "completed", first

    def no_request(_request):
        pytest.fail("completed final-only graph must use its persisted answer")

    resumed = execute(
        database,
        store,
        opts,
        prepared_advisory,
        httpx.MockTransport(no_request),
        checkpoint_key="prepared-completed",
    )
    assert resumed["generation"]["status"] == "completed", resumed
    assert resumed["answer"] == first["answer"]
    assert resumed["agent"]["checkpoint_resumed"] is True
    assert resumed["cost"]["current_attempt_external_requests"] == 0
    assert resumed["cost"]["external_requests"] == len(requests) == 1
    assert resumed["cost"]["billed_tokens"] == 30


def test_prepared_completed_sdk_reply_replays_after_crash_before_graph_save(
    database, store, settings, prepared_advisory, monkeypatch
):
    requests = []
    opts = options(settings)
    original = RecoveryStore.save_model

    def crash_after_save(self, step, response, audit):
        original(self, step, response, audit)
        assert audit["phase"] == "json_final"
        raise ProcessCrash()

    monkeypatch.setattr(RecoveryStore, "save_model", crash_after_save)
    with pytest.raises(ProcessCrash):
        execute(
            database,
            store,
            opts,
            prepared_advisory,
            sdk_transport(requests),
            checkpoint_key="prepared-final-crash",
        )
    monkeypatch.setattr(RecoveryStore, "save_model", original)

    def no_request(_request):
        pytest.fail("saved SDK final response must not be billed again after a crash")

    resumed = execute(
        database,
        store,
        opts,
        prepared_advisory,
        httpx.MockTransport(no_request),
        checkpoint_key="prepared-final-crash",
    )
    assert resumed["generation"]["status"] == "completed", resumed
    assert resumed["agent"]["reply_replay"]["model_responses"] == 1
    assert resumed["cost"]["current_attempt_external_requests"] == 0
    assert resumed["cost"]["external_requests"] == len(requests) == 1
    assert resumed["cost"]["billed_tokens"] == 30


def test_prepared_nonzero_quote_index_is_rejected_without_silent_replacement(
    database, store, settings, prepared_advisory
):
    requests = []

    def invalid_index(answer):
        answer["statements"][0]["evidence"][0]["quote_index"] = 1

    result = execute(
        database,
        store,
        options(settings),
        prepared_advisory,
        sdk_transport(requests, invalid_index),
    )
    assert result["generation"]["status"] == "fallback", result
    assert result["generation"]["reason"] == "invalid_final_json"
    assert not result.get("generated_claims")
    assert len(requests) == 1


@pytest.mark.parametrize(
    "absence",
    [
        "当前 NVD 记录缺少 CPE 条件。",
        "来源没有可用 CVSS。",
        "NVD 未发布 CVSS 评分。",
        "No CVSS score is available in the source.",
    ],
)
def test_prepared_uncited_whole_source_absence_in_limitations_is_not_completed(
    database, store, settings, prepared_advisory, absence
):
    requests = []

    def unquoted_absence(answer):
        answer["limitations"] = [absence]

    result = execute(
        database,
        store,
        options(settings),
        prepared_advisory,
        sdk_transport(requests, unquoted_absence),
    )
    assert result["generation"]["status"] == "fallback", result
    assert result["generation"]["reason"] == "unquoted_source_absence"
    assert not result.get("generated_claims")
    assert absence not in result["answer"]
    assert len(requests) == 1
