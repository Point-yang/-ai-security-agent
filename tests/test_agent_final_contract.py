import json

import httpx
import pytest
from test_agent_recovery import ProcessCrash
from test_langchain_agent import ScriptedModel, body, call, retrieve
from test_member_a_rag_context import fixture_advisory, ingest

from zhidu.agent_checkpoint import RecoveryStore
from zhidu.generation import apply_generation
from zhidu.grounded_answer import CONTRACT_VERSION, quote_candidates
from zhidu.langchain_agent import run_langchain_agent
from zhidu.langchain_tools import SourceRuntime, ToolSession


def final_candidate(item):
    return {
        "answer_class": "evidence",
        "statements": [
            {
                "text": "该来源声明了当前事项。",
                "evidence": [{"evidence_id": item["evidence_id"], "quote_index": 0}],
            }
        ],
        "required_facts": ["来源声明"],
        "missing_facts": [],
        "limitations": [],
        "message": "",
    }


def reply(message, finish="stop"):
    return httpx.Response(
        200,
        json={
            "id": "contract-test",
            "object": "chat.completion",
            "created": 1,
            "model": "test-model",
            "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
            "choices": [
                {"index": 0, "finish_reason": finish, "message": {"role": "assistant", **message}}
            ],
        },
    )


def sdk_handler(advisory, requests, *, finish="stop"):
    def handle(request):
        payload = json.loads(request.content)
        requests.append(payload)
        if len(requests) == 1:
            return reply(
                {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "retrieve-1",
                            "type": "function",
                            "function": {
                                "name": "retrieve",
                                "arguments": json.dumps(
                                    {"query": advisory["ghsa_id"], "mode": "lexical", "limit": 2}
                                ),
                            },
                        }
                    ],
                },
                "tool_calls",
            )
        assert not payload.get("tools")
        assert payload["response_format"] == {"type": "json_object"}
        assert payload["temperature"] == 0
        observation = json.loads(
            next(m["content"] for m in reversed(payload["messages"]) if m["role"] == "tool")
        )
        item = observation["result"]["items"][0]
        return reply(
            {
                "content": json.dumps(final_candidate(item)),
                "reasoning_content": "hidden-test-reasoning",
            },
            finish,
        )

    return handle


def cloud(settings):
    return settings.model_copy(
        update={
            "deepseek_api_key": type(settings.deepseek_api_key)("test-sdk-key"),
            "agent_max_model_calls": 2,
        }
    )


def test_full_candidate_keeps_condition_sentence_after_old_cut():
    text = (
        "Introduction. " * 16
        + "Only a configured video backend accepts the large frame limit and can exhaust frontend memory."
    )
    assert len(text) > 160
    assert quote_candidates(text)[0] == text
    assert all(q in text for q in quote_candidates(text))


def test_real_sdk_last_allowed_call_is_json_without_business_tools(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    requests = []
    with database() as session:
        result = run_langchain_agent(
            session,
            store,
            cloud(settings),
            body(advisory),
            None,
            transport=httpx.MockTransport(sdk_handler(advisory, requests)),
        )
    assert result["generation"]["status"] == "completed", result
    assert len(requests) == result["cost"]["external_requests"] == 2
    assert result["generation"]["answer_contract"] == CONTRACT_VERSION
    assert result["agent"]["model_calls"][-1]["phase"] == "json_final"
    assert result["agent"]["model_calls"][-1]["finish_reason"] == "stop"
    assert "hidden-test-reasoning" not in json.dumps(result)


def test_truncated_sdk_final_is_failed_with_usage_and_no_retry(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    requests = []
    with database() as session:
        result = run_langchain_agent(
            session,
            store,
            cloud(settings),
            body(advisory),
            None,
            transport=httpx.MockTransport(sdk_handler(advisory, requests, finish="length")),
        )
    assert result["generation"]["reason"] == "incomplete_output"
    assert len(requests) == 2 and result["cost"]["billed_tokens"] == 60
    assert result["agent"]["model_calls"][-1]["finish_reason"] == "length"


def test_invalid_sdk_tool_args_are_diagnosed_without_echoing_raw_args(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    requests = []

    def handle(request):
        requests.append(1)
        return reply(
            {
                "content": None,
                "tool_calls": [
                    {
                        "id": "bad-call",
                        "type": "function",
                        "function": {"name": "retrieve", "arguments": '{"secret": "do-not-echo"'},
                    }
                ],
            },
            "tool_calls",
        )

    with database() as session:
        result = run_langchain_agent(
            session,
            store,
            cloud(settings),
            body(advisory),
            None,
            transport=httpx.MockTransport(handle),
        )
    assert len(requests) == 1
    assert result["generation"]["reason"] == "invalid_tool_arguments"
    assert result["cost"]["billed_tokens"] == 30
    assert result["agent"]["model_calls"][0]["invalid_tool_call_count"] == 1
    assert "do-not-echo" not in json.dumps(result)


def test_shared_rag_contract_resolves_same_server_quote_and_temperature(settings):
    packet = {
        "answer": "original",
        "answer_class": "evidence",
        "citations": [
            {
                "external_id": "GHSA-test",
                "text": "The configured decoder can exhaust frontend memory.",
            }
        ],
        "tools": [],
        "constraints": [],
        "claims": [],
        "cost": {"external_requests": 0},
    }
    options = settings.model_copy(
        update={
            "deepseek_api_key": type(settings.deepseek_api_key)("test-key"),
            "llm_temperature": 0.2,
        }
    )

    def handle(request):
        payload = json.loads(request.content)
        assert payload["temperature"] == 0.2
        source = json.loads(payload["messages"][-1]["content"])["sources"][0]
        return reply({"content": json.dumps(final_candidate(source))})

    apply_generation(options, "来源的条件是什么？", packet, transport=httpx.MockTransport(handle))
    assert packet["generation"]["status"] == "completed"
    assert packet["generation"]["answer_contract"] == CONTRACT_VERSION
    assert packet["generated_claims"][0]["evidence"][0]["quote"] == packet["citations"][0]["text"]


def test_two_unproductive_queries_force_final_before_five_calls(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))

    def missing(messages):
        observation = json.loads(next(m.content for m in reversed(messages) if m.type == "tool"))
        item = observation["result"]["items"][0]
        return call(
            "read_fields",
            {
                "event_id": item["citation"]["event_id"],
                "fields": ["description"],
                "contains": "never-found-marker",
            },
        )

    def stricter(messages):
        initial = json.loads(next(m.content for m in messages if m.type == "tool"))
        item = initial["result"]["items"][0]
        return call(
            "read_fields",
            {
                "event_id": item["citation"]["event_id"],
                "fields": ["description"],
                "contains": "never-found-marker-longer",
            },
        )

    def finish_json(messages):
        from langchain_core.messages import AIMessage

        initial = json.loads(next(m.content for m in messages if m.type == "tool"))
        return AIMessage(content=json.dumps(final_candidate(initial["result"]["items"][0])))

    model = ScriptedModel(actions=[retrieve(advisory), missing, stricter, finish_json])
    with database() as session:
        result = run_langchain_agent(session, store, settings, body(advisory), None, model=model)
    assert result["generation"]["status"] == "completed"
    assert model.position == 4
    assert result["agent"]["model_calls"][-1]["phase"] == "json_final"
    assert any(
        r["reason"] == "known_missing_field_query" for r in result["agent"]["policy_rejections"]
    )


def test_known_patch_field_stops_optional_patch_lookup(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        request = body(advisory).model_copy(update={"question": "受影响范围和修复字段是什么？"})
        scope = ToolSession(SourceRuntime(session, store, settings, None), request, None)
        scope.invoke("retrieve", {"query": advisory["ghsa_id"]})
        eid = next(iter(scope.events))
        scope.invoke("read_fields", {"event_id": eid, "fields": ["packages"], "limit": 1})
        failed = json.loads(
            scope.invoke(
                "read_fields", {"event_id": eid, "fields": ["description"], "contains": "Patches"}
            )[0]
        )
        assert failed["error"] == "optional_patch_lookup_not_required"
        assert len(scope.runtime.steps) == 2


def test_sdk_json_final_reply_replays_after_crash_before_graph_checkpoint(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    requests = []
    original = RecoveryStore.save_model

    def crash(self, step, response, audit):
        original(self, step, response, audit)
        if audit["phase"] == "json_final":
            raise ProcessCrash()

    monkeypatch.setattr(RecoveryStore, "save_model", crash)
    with database() as session, pytest.raises(ProcessCrash):
        run_langchain_agent(
            session,
            store,
            cloud(settings),
            body(advisory),
            None,
            checkpoint_key="sdk-json-crash",
            transport=httpx.MockTransport(sdk_handler(advisory, requests)),
        )
    monkeypatch.setattr(RecoveryStore, "save_model", original)

    def no_request(request):
        pytest.fail("completed provider response must be replayed locally")

    with database() as session:
        result = run_langchain_agent(
            session,
            store,
            cloud(settings),
            body(advisory),
            None,
            checkpoint_key="sdk-json-crash",
            transport=httpx.MockTransport(no_request),
        )
    assert result["generation"]["status"] == "completed", result
    assert len(requests) == 2 and result["cost"]["current_attempt_external_requests"] == 0
    assert result["cost"]["external_requests"] == 2


def test_invalid_completed_json_is_replayed_as_failure_without_new_request(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    opts = cloud(settings).model_copy(update={"agent_max_model_calls": 1})
    requests = []

    def handle(request):
        requests.append(1)
        return reply({"content": "not valid answer json"})

    for _ in range(2):
        with database() as session:
            result = run_langchain_agent(
                session,
                store,
                opts,
                body(advisory),
                None,
                checkpoint_key="invalid-json-reply",
                transport=httpx.MockTransport(handle),
            )
        assert result["generation"]["reason"] == "invalid_final_json"
    assert len(requests) == 1 and result["cost"]["current_attempt_external_requests"] == 0


def test_known_sdk_length_failure_replays_same_reason_and_usage(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    requests = []
    for _ in range(2):
        with database() as session:
            result = run_langchain_agent(
                session,
                store,
                cloud(settings),
                body(advisory),
                None,
                checkpoint_key="known-sdk-length",
                transport=httpx.MockTransport(sdk_handler(advisory, requests, finish="length")),
            )
        assert result["generation"]["reason"] == "incomplete_output"
        assert result["cost"]["billed_tokens"] == 60
    assert len(requests) == 2 and result["cost"]["current_attempt_external_requests"] == 0
