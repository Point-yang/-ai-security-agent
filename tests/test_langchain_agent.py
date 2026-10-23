"""Exercise the actual framework graph with scripted models and real source tools."""

import copy
import json
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import Field
from sqlalchemy import select
from test_member_a_rag_context import fixture_advisory, ingest

pytest.importorskip("langchain")
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from zhidu.api import create_app
from zhidu.langchain_agent import run_langchain_agent
from zhidu.langchain_tools import SourceRuntime, ToolSession
from zhidu.models import Asset, IntelEvent
from zhidu.rag import RagRequest


class ScriptedModel(BaseChatModel):
    actions: list[Any] = Field(exclude=True)
    position: int = 0
    seen: list[Any] = Field(default_factory=list, exclude=True)

    @property
    def _llm_type(self):
        return "scripted-framework-test"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        self.seen.append(messages)
        action = self.actions[min(self.position, len(self.actions) - 1)]
        self.position += 1
        message = action(messages) if callable(action) else action
        message.usage_metadata = {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}
        message.response_metadata = {"model_name": "scripted-model"}
        return ChatResult(generations=[ChatGeneration(message=message)])


def call(name, args, cid="tool-call"):
    return AIMessage(
        content="", tool_calls=[{"name": name, "args": args, "id": cid, "type": "tool_call"}]
    )


def observation(messages):
    return json.loads(next(m.content for m in reversed(messages) if isinstance(m, ToolMessage)))


def retrieve(advisory):
    return call("retrieve", {"query": advisory["ghsa_id"], "mode": "lexical", "limit": 2})


def read_patch(messages):
    item = observation(messages)["result"]["items"][0]
    return call(
        "read_fields",
        {
            "event_id": item["citation"]["event_id"],
            "fields": ["description"],
            "contains": "Patches",
            "limit": 1,
        },
        "read-patch",
    )


def finish(messages):
    result = observation(messages)["result"]
    item = result.get("fields", result.get("items"))[0]
    return call(
        "AgentAnswer",
        {
            "answer_class": "evidence",
            "statements": [
                {
                    "text": "该来源描述建议升级修复。",
                    "evidence": [{"evidence_id": item["evidence_id"], "quote_index": 0}],
                }
            ],
            "required_facts": ["来源修复建议"],
            "missing_facts": [],
            "limitations": ["未独立验证漏洞复现。"],
            "message": "",
        },
        "final-answer",
    )


def body(advisory, **kwargs):
    return RagRequest(
        question="来源的修复建议是什么？",
        query=advisory["ghsa_id"],
        mode="lexical",
        generation="agent",
        agent_backend="langchain",
        **kwargs,
    )


def test_dynamic_loop_reads_late_patch_and_fills_verbatim_quote(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    model = ScriptedModel(actions=[retrieve(advisory), read_patch, finish])
    with database() as session:
        result = run_langchain_agent(session, store, settings, body(advisory), None, model=model)
    assert result["generation"]["status"] == "completed", result
    assert result["answer_class"] == "evidence"
    assert model.position == 3
    assert [x["tool"] for x in result["tools"]] == ["retrieve", "read_fields"]
    assert "Upgrade to 1.2.0" in result["citations"][0]["text"]
    assert result["generated_claims"][0]["evidence"][0]["quote"] in result["citations"][0]["text"]
    assert result["cost"]["billed_tokens"] == 45
    assert result["cost"]["external_requests"] == 0
    assert result["agent"]["final_citation_check"]["verified"] == 1


def test_no_hardcoded_second_stage_and_lexical_recovery(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    failed = call("retrieve", {"query": advisory["ghsa_id"], "mode": "hybrid", "limit": 2})
    model = ScriptedModel(actions=[failed, retrieve(advisory), finish])
    with database() as session:
        result = run_langchain_agent(session, store, settings, body(advisory), None, model=model)
    assert result["generation"]["status"] == "completed", result
    assert result["tools"][0]["status"] == "failed"
    assert result["tools"][1]["input"]["mode"] == "lexical"
    assert not any(x["tool"] == "event_details" for x in result["tools"])


def test_unknown_evidence_cannot_be_promoted_to_a_fact(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))

    def invented(messages):
        message = finish(messages)
        message.tool_calls[0]["args"]["statements"][0]["evidence"][0]["evidence_id"] = "f" * 24
        return message

    model = ScriptedModel(actions=[retrieve(advisory), invented])
    with database() as session:
        result = run_langchain_agent(session, store, settings, body(advisory), None, model=model)
    assert result["generation"]["status"] == "fallback"
    assert result["generation"]["reason"] == "unknown_evidence_id"
    assert result["answer_class"] == "partial"
    assert "generated_claims" not in result


def test_model_call_budget_stops_repeated_tool_loop(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    settings = settings.model_copy(update={"agent_max_model_calls": 2})
    model = ScriptedModel(actions=[retrieve(advisory)])
    with database() as session:
        result = run_langchain_agent(session, store, settings, body(advisory), None, model=model)
    assert model.position == 2
    assert result["generation"]["status"] == "fallback"
    assert result["tool_calls"] <= 2


def test_scope_and_tool_budget_are_request_local(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    other = copy.deepcopy(fixture_advisory(advisory))
    other.update(ghsa_id="GHSA-dddd-eeee-ffff", cve_id="CVE-2099-7777")
    ingest(database, store, other)
    with database() as session:
        ids = session.scalars(select(IntelEvent.id).order_by(IntelEvent.external_id)).all()
        runtime = SourceRuntime(session, store, settings, None, max_calls=2)
        scoped = ToolSession(runtime, body(advisory, event_id=ids[0]), None)
        scoped.invoke("retrieve", {"query": advisory["ghsa_id"], "mode": "lexical"})
        failed = json.loads(
            scoped.invoke("read_fields", {"event_id": ids[1], "fields": ["packages"]})[0]
        )
        assert failed["error"] == "target_not_in_current_retrieval"
        failed = json.loads(scoped.invoke("retrieve", {"query": "anything"})[0])
        assert failed["error"] == "call_budget_exceeded"
        assert set(c["event_id"] for c in scoped.evidence.values()) <= {ids[0]}


def test_final_evidence_is_rechecked_after_model_returns(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))

    def corrupt(messages):
        message = finish(messages)
        item = observation(messages)["result"]["items"][0]
        path = store.path_for(item["citation"]["sha256"])
        path.write_bytes(b"corrupted")
        return message

    model = ScriptedModel(actions=[retrieve(advisory), corrupt])
    with database() as session:
        result = run_langchain_agent(session, store, settings, body(advisory), None, model=model)
    assert result["answer_class"] == "refused"
    assert not result["citations"]


def test_explicit_missing_asset_short_circuits_without_model(database, store, settings, advisory):
    model = ScriptedModel(actions=[])
    with database() as session:
        result = run_langchain_agent(
            session,
            store,
            settings,
            RagRequest(question="我的资产受到这个漏洞影响吗？", agent_backend="langchain"),
            None,
            model=model,
        )
    assert result["answer_class"] == "clarification"
    assert model.position == 0


def test_http_sdk_native_tool_calls_and_no_secret_in_trace(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    cloud = settings.model_copy(
        update={"deepseek_api_key": type(settings.deepseek_api_key)("sdk-test-secret")}
    )
    requests = []

    def handler(request):
        payload = json.loads(request.content)
        requests.append(payload)
        if len(requests) == 1:
            args = {"query": advisory["ghsa_id"], "mode": "lexical", "limit": 2}
            name = "retrieve"
        else:
            value = json.loads(
                next(m["content"] for m in reversed(payload["messages"]) if m["role"] == "tool")
            )
            item = value["result"]["items"][0]
            name = "AgentAnswer"
            args = {
                "answer_class": "evidence",
                "statements": [
                    {
                        "text": "来源报告了该问题。",
                        "evidence": [{"evidence_id": item["evidence_id"], "quote_index": 0}],
                    }
                ],
                "required_facts": ["来源声明"],
                "missing_facts": [],
                "limitations": [],
                "message": "",
            }
        return httpx.Response(
            200,
            json={
                "id": "mock-native",
                "object": "chat.completion",
                "created": 1,
                "model": "native-test",
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call-" + str(len(requests)),
                                    "type": "function",
                                    "function": {"name": name, "arguments": json.dumps(args)},
                                }
                            ],
                        },
                    }
                ],
            },
        )

    with database() as session:
        result = run_langchain_agent(
            session, store, cloud, body(advisory), None, transport=httpx.MockTransport(handler)
        )
    assert result["generation"]["status"] == "completed", result
    assert result["cost"]["external_requests"] == 2
    assert result["cost"]["billed_tokens"] == 30
    assert "sdk-test-secret" not in json.dumps(result)
    assert requests[0]["tools"] and requests[0]["parallel_tool_calls"] is False


def test_api_conversation_dispatch_and_repeat_request_is_free(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    calls = []
    original = run_langchain_agent

    def execute(*args, **kwargs):
        calls.append(1)
        return original(
            *args, **kwargs, model=ScriptedModel(actions=[retrieve(advisory), read_patch, finish])
        )

    monkeypatch.setattr("zhidu.langchain_agent.run_langchain_agent", execute)
    with TestClient(create_app(settings)) as client:
        headers = {"X-Admin-Key": "test-admin"}
        cid = client.post(
            "/api/v1/conversations", headers=headers, json={"title": "Framework test"}
        ).json()["id"]
        payload = {
            **body(advisory).model_dump(),
            "conversation_id": cid,
            "request_id": "framework-001",
        }
        first = client.post("/api/v1/rag/answers", headers=headers, json=payload)
        second = client.post("/api/v1/rag/answers", headers=headers, json=payload)
    assert first.status_code == second.status_code == 200
    assert first.json()["agent_backend"] == "langchain"
    assert second.json()["deduplicated"] is True
    assert len(calls) == 1


def test_final_schema_output_does_not_consume_business_tool_budget(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    settings = settings.model_copy(update={"agent_max_tool_calls": 1})
    with database() as session:
        result = run_langchain_agent(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=ScriptedModel(actions=[retrieve(advisory), finish]),
        )
    assert result["generation"]["status"] == "completed"
    assert result["tool_calls"] == 1


def test_same_verified_span_keeps_one_immutable_handle(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        runtime = SourceRuntime(session, store, settings, None)
        scope = ToolSession(runtime, body(advisory), None)
        scope.invoke("retrieve", {"query": advisory["ghsa_id"], "mode": "lexical"})
        eid = next(iter(scope.events))
        scope.invoke("event_details", {"event_id": eid})
        original_id, original = min(
            ((k, dict(v)) for k, v in scope.evidence.items() if v["field"] == "description"),
            key=lambda item: item[1]["start"],
        )
        original_quotes = scope.quotes(original)
        scope.invoke("read_fields", {"event_id": eid, "fields": ["description"], "limit": 1})
        assert scope.evidence[original_id] == original
        assert scope.quotes(scope.evidence[original_id]) == original_quotes
        assert (
            len({k for k, v in scope.evidence.items() if v["chunk_id"] == original["chunk_id"]})
            == 1
        )


def test_model_output_budget_includes_quote_candidates(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    monkeypatch.setattr("zhidu.langchain_tools.MAX_CALL_CHARS", 100)
    with database() as session:
        scope = ToolSession(SourceRuntime(session, store, settings, None), body(advisory), None)
        response = json.loads(
            scope.invoke("retrieve", {"query": advisory["ghsa_id"], "mode": "lexical"})[0]
        )
        assert response["error"] == "model_output_budget_exceeded"
        assert not scope.evidence
        assert not scope.events and not scope.cves


def test_private_asset_artifact_is_not_in_model_messages(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    with database.begin() as session:
        asset = Asset(
            name="private-project-host",
            environment="private",
            criticality="low",
            sbom_sha256="0" * 64,
        )
        session.add(asset)
        session.flush()
        asset_id = asset.id

    def asset_call(messages):
        item = observation(messages)["result"]["items"][0]
        return call("asset_exposure", {"event_id": item["citation"]["event_id"]}, "local-asset")

    def finish_public(messages):
        public = [
            m for m in messages if not isinstance(m, ToolMessage) or m.name != "asset_exposure"
        ]
        return finish(public)

    model = ScriptedModel(actions=[retrieve(advisory), asset_call, finish_public])
    with database() as session:
        result = run_langchain_agent(
            session, store, settings, body(advisory, asset_id=asset_id), None, model=model
        )
    assert result["generation"]["status"] == "completed"
    outbound = " ".join(str(m.content) for batch in model.seen for m in batch)
    assert asset_id not in outbound and "private-project-host" not in outbound
    local = next(
        x["result"] for x in result["agent"]["tool_results"] if x["tool"] == "asset_exposure"
    )
    assert local["asset_id"] == asset_id
