"""Switch standard interfaces without forwarding a different provider's credential."""

import json

import httpx
import pytest
from test_langchain_agent import body
from test_member_a_rag_context import fixture_advisory, ingest

from zhidu.generation import apply_generation
from zhidu.langchain_agent import run_langchain_agent
from zhidu.model_provider import ModelConfigurationError, model_profile
from zhidu.rag import run_rag


def compatible(settings, provider="openai_compatible"):
    return settings.model_copy(
        update={
            "agent_model_provider": provider,
            "agent_model_name": "compatible-tools-model",
            "agent_model_base_url": "https://gateway.example/v1"
            if provider != "ollama"
            else "http://127.0.0.1:11434/v1",
            "agent_model_api_key": type(settings.agent_model_api_key)("gateway-only-secret"),
            "deepseek_api_key": type(settings.deepseek_api_key)("never-send-deepseek-secret"),
        }
    )


@pytest.mark.parametrize("provider", ["openai_compatible", "ollama"])
def test_native_agent_standard_chat_interface(database, store, settings, advisory, provider):
    ingest(database, store, fixture_advisory(advisory))
    settings = compatible(settings, provider)
    requests = []

    def handler(request):
        assert request.headers["authorization"] == "Bearer gateway-only-secret"
        payload = json.loads(request.content)
        assert (
            "thinking" not in payload
            and "never-send-deepseek-secret" not in request.content.decode()
        )
        requests.append(payload)
        if len(requests) == 1:
            name, args = "retrieve", {"query": advisory["ghsa_id"], "mode": "lexical", "limit": 2}
        else:
            observation = json.loads(
                next(m["content"] for m in reversed(payload["messages"]) if m["role"] == "tool")
            )
            item = observation["result"]["items"][0]
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
                "id": "compatible",
                "object": "chat.completion",
                "created": 1,
                "model": "returned-compatible-model",
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
                                    "id": "compatible-" + str(len(requests)),
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
            session, store, settings, body(advisory), None, transport=httpx.MockTransport(handler)
        )
    assert result["generation"]["status"] == "completed", result
    assert result["generation"]["provider"] == provider
    assert result["generation_model"] == "returned-compatible-model"
    assert result["cost"]["external_requests"] == 2
    assert "secret" not in json.dumps(result)


def test_ordinary_rag_uses_same_configured_model_adapter(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    cloud = compatible(settings)

    def handler(request):
        payload = json.loads(request.content)
        assert payload["model"] == cloud.agent_model_name and "thinking" not in payload
        assert request.headers["authorization"] == "Bearer gateway-only-secret"
        source = json.loads(payload["messages"][-1]["content"])["sources"][0]
        return httpx.Response(
            200,
            json={
                "model": "ordinary-compatible",
                "usage": {"total_tokens": 17},
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": json.dumps(
                                {
                                    "statements": [
                                        {
                                            "text": "来源报告了该问题。",
                                            "evidence": [
                                                {
                                                    "citation": source["citation"],
                                                    "quote": source["text"][:30],
                                                }
                                            ],
                                        }
                                    ]
                                }
                            )
                        },
                    }
                ],
            },
        )

    with database() as session:
        request = body(advisory).model_copy(update={"generation": "extractive"})
        result = run_rag(session, store, settings, request, None)
        apply_generation(
            cloud,
            request.question,
            result,
            profile=model_profile(cloud),
            transport=httpx.MockTransport(handler),
        )
    assert result["generation"]["status"] == "completed"
    assert result["generation"]["provider"] == "openai_compatible"


def test_missing_dedicated_key_does_not_reuse_deepseek_key(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    settings = compatible(settings).model_copy(
        update={"agent_model_api_key": type(settings.agent_model_api_key)("")}
    )
    with database() as session:
        result = run_langchain_agent(session, store, settings, body(advisory), None)
    assert result["generation"]["reason"] == "missing_api_key"
    assert result["cost"]["external_requests"] == 0


@pytest.mark.parametrize(
    "base",
    [
        "https://name:password@gateway.example/v1",
        "file:///tmp/model",
        "https://gateway.example/v1?key=secret",
        "http://public.example/v1",
    ],
)
def test_provider_rejects_credential_urls_and_unsafe_endpoints(settings, base):
    with pytest.raises(ModelConfigurationError):
        model_profile(compatible(settings).model_copy(update={"agent_model_base_url": base}))
