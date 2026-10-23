"""Product modes use the short transaction and durable request identity path."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient
from test_agent_final_contract import reply
from test_member_a_rag_context import fixture_advisory, ingest

from zhidu.agent_workflow import run_workflow_agent
from zhidu.api import create_app


@pytest.mark.parametrize("backend", ["workflow", "auto"])
def test_conversation_product_mode_persists_and_deduplicates_sdk_reply(
    database, store, settings, advisory, monkeypatch, backend
):
    ingest(database, store, fixture_advisory(advisory))
    options = settings.model_copy(
        update={"deepseek_api_key": type(settings.deepseek_api_key)("mock-sdk-key")}
    )
    calls = []

    def provider(request):
        payload = json.loads(request.content)
        calls.append(payload)
        assert not payload.get("tools")
        prepared = json.loads(payload["messages"][-1]["content"])["prepared_evidence"]
        source = next(c for c in prepared if c["field"] == "packages")
        return reply(
            {
                "content": json.dumps(
                    {
                        "answer_class": "evidence",
                        "statements": [
                            {
                                "text": "公告的首次修复版本为 1.2.0。",
                                "evidence": [{"evidence_id": source["evidence_id"]}],
                            }
                        ],
                        "required_facts": ["首次修复版本"],
                        "missing_facts": [],
                        "limitations": [],
                        "message": "",
                    }
                )
            }
        )

    def execute(*args, **kwargs):
        assert kwargs.get("checkpoint_key")
        return run_workflow_agent(*args, transport=httpx.MockTransport(provider), **kwargs)

    monkeypatch.setattr("zhidu.agent_workflow.run_workflow_agent", execute)
    headers = {"X-Admin-Key": "test-admin"}
    with TestClient(create_app(options)) as client:
        conversation = client.post(
            "/api/v1/conversations", headers=headers, json={"title": "product mode"}
        ).json()
        request = {
            "question": "首次修复版本是什么？",
            "query": advisory["ghsa_id"],
            "mode": "lexical",
            "generation": "agent",
            "agent_backend": backend,
            "conversation_id": conversation["id"],
            "request_id": f"{backend}-request",
        }
        first = client.post("/api/v1/rag/answers", headers=headers, json=request)
        assert first.status_code == 200, first.text
        assert first.json()["generation"]["status"] == "completed", first.json()
        assert first.json()["routing"]["chosen_backend"] == "workflow"
        second = client.post("/api/v1/rag/answers", headers=headers, json=request)
        assert second.status_code == 200, second.text
        assert second.json()["deduplicated"] is True
        assert first.json()["id"] == second.json()["id"]
    assert len(calls) == 1
