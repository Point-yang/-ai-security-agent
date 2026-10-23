import copy
import json

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from zhidu.api import create_app
from zhidu.generation import apply_generation, generation_status
from zhidu.ingest import ingest_document
from zhidu.models import RagRun, now_utc
from zhidu.rag import RagRequest, run_rag
from zhidu.rag_metrics import score_response


@pytest.fixture
def cloud_settings(settings):
    return settings.model_copy(
        update={
            "llm_provider": "deepseek",
            "deepseek_api_key": type(settings.deepseek_api_key)("unit-test-secret"),
        }
    )


@pytest.fixture
def packet():
    return {
        "answer": "本地证据原文",
        "answer_class": "partial",
        "reason": "source_excerpts",
        "generation_model": "extractive-packet-v4",
        "tools": [],
        "constraints": [],
        "citations": [
            {
                "external_id": "GHSA-test",
                "text": "The decoder can exhaust memory when processing compressed audio.",
            }
        ],
        "claims": [],
        "cost": {"external_requests": 0, "billed_tokens": 0, "api_usd": 0},
        "asset_context": {"asset": {"name": "PRIVATE-ASSET-NAME"}},
    }


def completion(quote="decoder can exhaust memory", citation=1):
    return {
        "model": "deepseek-flash",
        "usage": {"prompt_tokens": 100, "completion_tokens": 40, "total_tokens": 140},
        "choices": [
            {
                "finish_reason": "stop",
                "message": {
                    "content": json.dumps(
                        {
                            "statements": [
                                {
                                    "text": "解码器可能耗尽内存。",
                                    "evidence": [{"citation": citation, "quote": quote}],
                                }
                            ]
                        }
                    ),
                    "reasoning_content": "hidden-not-for-storage",
                },
            }
        ],
    }


def test_valid_grounded_answer_and_minimal_disclosure(cloud_settings, packet):
    def handler(request):
        assert str(request.url) == "https://api.deepseek.com/chat/completions"
        assert request.headers["Authorization"] == "Bearer unit-test-secret"
        body = json.loads(request.content)
        assert body["model"] == "deepseek-v4-flash"
        assert body["thinking"] == {"type": "disabled"}
        assert body["response_format"] == {"type": "json_object"}
        assert "PRIVATE-ASSET-NAME" not in request.content.decode()
        assert "unit-test-secret" not in request.content.decode()
        sources = json.loads(body["messages"][-1]["content"])["sources"]
        assert sources[0]["evidence_id"]
        assert sources[0]["quote_policy"] == "server_fills_verified_span"
        assert "quote_candidates" not in sources[0]
        return httpx.Response(200, json=completion())

    apply_generation(cloud_settings, "发生什么？", packet, transport=httpx.MockTransport(handler))
    assert packet["generation"]["status"] == "completed"
    assert "解码器可能耗尽内存。 [1]" in packet["answer"]
    assert packet["extractive_answer"] == "本地证据原文"
    assert packet["generation_model"] == "deepseek-flash"
    assert packet["cost"]["billed_tokens"] == 140
    assert packet["cost"]["api_usd"] is None
    assert packet["generation"]["semantic_support_verified"] is False
    assert "hidden-not-for-storage" not in json.dumps(packet)


@pytest.mark.parametrize(
    "quote,citation", [("invented source quote", 1), ("decoder can exhaust memory", 2)]
)
def test_fabricated_attribution_falls_back(cloud_settings, packet, quote, citation):
    apply_generation(
        cloud_settings,
        "question",
        packet,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json=completion(quote, citation))
        ),
    )
    assert packet["generation"]["reason"] == "invalid_citation"
    assert packet["answer"] == "本地证据原文"
    assert "generated_claims" not in packet


@pytest.mark.parametrize(
    "status,reason",
    [
        (401, "authentication_failed"),
        (402, "insufficient_balance"),
        (429, "rate_limited"),
        (503, "upstream_error"),
        (302, "upstream_error"),
    ],
)
def test_http_failure_no_secret_or_retry(cloud_settings, packet, status, reason):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(
            status, text="unit-test-secret", headers={"Location": "https://example.com"}
        )

    apply_generation(cloud_settings, "question", packet, transport=httpx.MockTransport(handler))
    assert len(requests) == 1
    assert packet["generation"]["reason"] == reason
    assert packet["answer"] == "本地证据原文"
    assert "unit-test-secret" not in json.dumps(packet)


def test_timeout_retains_verified_answer(cloud_settings, packet):
    def handler(request):
        raise httpx.ReadTimeout("private upstream detail", request=request)

    apply_generation(cloud_settings, "question", packet, transport=httpx.MockTransport(handler))
    assert packet["generation"]["reason"] == "timeout"
    assert packet["answer"] == "本地证据原文"
    assert "private upstream" not in json.dumps(packet)


@pytest.mark.parametrize("kind", ["empty", "invalid_json", "truncated", "tool_call"])
def test_invalid_output_falls_back(cloud_settings, packet, kind):
    value = completion()
    choice = value["choices"][0]
    if kind == "empty":
        choice["message"]["content"] = '{"statements":[]}'
    elif kind == "invalid_json":
        choice["message"]["content"] = "not json"
    elif kind == "truncated":
        choice["finish_reason"] = "length"
    else:
        choice["message"]["tool_calls"] = [{"function": {"name": "execute"}}]
    apply_generation(
        cloud_settings,
        "question",
        packet,
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=value)),
    )
    assert packet["generation"]["status"] == "fallback"
    assert packet["answer"] == "本地证据原文"


def test_missing_key_and_wrong_host_never_make_request(settings, cloud_settings, packet):
    def unexpected(request):
        pytest.fail("credentials must not leave without valid configuration")

    apply_generation(settings, "q", packet, transport=httpx.MockTransport(unexpected))
    assert packet["generation"]["reason"] == "missing_api_key"
    assert packet["cost"]["external_requests"] == 0
    bad = cloud_settings.model_copy(
        update={"deepseek_base_url": "https://api.deepseek.com.evil.test"}
    )
    apply_generation(bad, "q", packet, transport=httpx.MockTransport(unexpected))
    assert packet["generation"]["reason"] == "invalid_endpoint"
    assert "unit-test-secret" not in json.dumps(generation_status(cloud_settings))


def test_no_evidence_no_cloud_call(database, store, cloud_settings, monkeypatch):
    monkeypatch.setattr(
        "zhidu.generation.apply_generation",
        lambda *a, **kw: pytest.fail("no evidence must not trigger generation"),
    )
    with database() as session:
        result = run_rag(
            session, store, cloud_settings, RagRequest(question="nothing", mode="lexical"), None
        )
    assert result["generation"]["status"] == "skipped"
    assert result["cost"]["external_requests"] == 0


def test_real_retrieval_api_and_persisted_generation(
    database, store, advisory, cloud_settings, monkeypatch
):
    item = copy.deepcopy(advisory)
    item["summary"] = "vLLM security input validation"
    item["description"] = "The decoder can exhaust memory when processing compressed audio."
    item["vulnerabilities"][0]["package"]["name"] = "vllm"
    with database.begin() as session:
        ingest_document(
            session,
            store,
            json.dumps(item).encode(),
            "offline://generation-test",
            now_utc(),
            "live",
        )

    def generated_response(req):
        sources = json.loads(json.loads(req.content)["messages"][1]["content"])["sources"]
        number = next(s["citation"] for s in sources if "decoder can exhaust memory" in s["text"])
        return httpx.Response(200, json=completion(citation=number))

    monkeypatch.setattr(
        "zhidu.generation.apply_generation",
        lambda s, q, r, **kwargs: apply_generation(
            s,
            q,
            r,
            transport=httpx.MockTransport(generated_response),
            **kwargs,
        ),
    )
    with TestClient(create_app(cloud_settings)) as client:
        response = client.post(
            "/api/v1/rag/answers",
            headers={"X-Admin-Key": "test-admin"},
            json={
                "question": "这条公告是什么问题？",
                "query": "GHSA-aaaa-bbbb-cccc",
                "mode": "lexical",
            },
        )
        assert response.status_code == 200
        result = response.json()
        assert result["generation"]["status"] == "completed"
        assert result["citations"][0]["sha256"]
        status = client.get("/api/v1/rag/status").json()
        assert status["generation"]["configured"] is True
        assert "unit-test-secret" not in json.dumps(status)
        local = client.post(
            "/api/v1/rag/answers",
            headers={"X-Admin-Key": "test-admin"},
            json={
                "question": "来源说明？",
                "query": "GHSA-aaaa-bbbb-cccc",
                "mode": "lexical",
                "generation": "extractive",
            },
        ).json()
        assert local["generation"]["status"] == "disabled"
    with database() as session:
        row = session.get(RagRun, result["id"])
        assert row.result["generated_claims"]
        assert "unit-test-secret" not in json.dumps(row.result)
        assert len(list(session.scalars(select(RagRun)))) == 2
    with pytest.raises(ValueError, match="semantic evaluation"):
        score_response({"expected_event_ids": []}, result)
