"""SDK acceptance for compact research messages, privacy and receipt replay."""

import json

import httpx
import pytest
from test_member_a_rag_context import fixture_advisory, ingest
from test_team_api_acceptance import TeamSDK

pytest.importorskip("langchain_deepseek")

from zhidu.agent_roles import RoleRunner, canonical_role_payload
from zhidu.agent_team import run_agent_team
from zhidu.langchain_tools import SourceRuntime, ToolSession
from zhidu.models import Asset
from zhidu.rag import RagRequest


def request_body(advisory, **kwargs):
    return RagRequest(
        question="该来源的受影响范围和首次修复版本字段是什么？",
        query=advisory["ghsa_id"],
        mode="lexical",
        generation="agent",
        agent_backend="team",
        **kwargs,
    )


def cloud_settings(settings):
    return type(settings)(
        _env_file=None,
        **(
            settings.model_dump()
            | {
                "deepseek_api_key": "mock-compact-sdk-secret",
                "llm_temperature": 0,
            }
        ),
    )


def envelope(request):
    body = json.loads(request.content)
    schema = json.loads(body["messages"][0]["content"].rsplit("schema:\n", 1)[1])
    return body, schema["title"], json.loads(body["messages"][-1]["content"])


class CompactSDK(TeamSDK):
    def __init__(self, advisory):
        super().__init__(advisory)
        self.research_payloads = []

    def handle(self, request):
        _, role, payload = envelope(request)
        if role == "ResearchDecision":
            self.research_payloads.append(payload)
            assert all(message["type"] in {"ai", "tool"} for message in payload["messages"])
            assert payload["question"] and payload["plan"] and payload["instructions"]
            assert payload["tools"]["read_fields"]["properties"]["fields"]["type"] == "array"
            if len(self.research_payloads) == 1:
                assert payload["messages"] == []
                assert payload["evidence"] == []
            else:
                assert [message["type"] for message in payload["messages"]] == ["ai", "tool"]
                previous = payload["messages"][0]["data"]
                assert previous["tool_calls"][0]["id"] == "research:0:0"
                assert previous["additional_kwargs"]["role_call_id"] == "research:0:0"
                observed = payload["messages"][1]["data"]
                assert "artifact" not in observed
                observation = json.loads(observed["content"])
                item = observation["result"]["items"][0]
                assert item["text"] == self.advisory["ghsa_id"]
                assert item["citation"]["source_id"] == "github-advisories"
                assert item["citation"]["json_pointer"] == "/ghsa_id"
                assert len(item["citation"]["sha256"]) == 64
                assert item["evidence_id"] and item["quote_policy"] == "server_fills_verified_span"
        return super().handle(request)


def test_compacted_sdk_payload_retains_tool_semantics_and_server_quote(
    database,
    store,
    settings,
    advisory,
):
    ingest(database, store, fixture_advisory(advisory))
    sdk = CompactSDK(advisory)
    with database() as session:
        result = run_agent_team(
            session,
            store,
            cloud_settings(settings),
            request_body(advisory),
            None,
            transport=httpx.MockTransport(sdk.handle),
        )
    assert result["generation"]["status"] == "completed", result["generation"]
    assert len(sdk.requests) == 5 and len(sdk.research_payloads) == 2
    assert [step["tool"] for step in result["tools"]] == ["retrieve", "read_fields"]
    assert result["tools"][1]["input"]["fields"] == ["packages"]
    quote = result["generated_claims"][0]["evidence"][0]["quote"]
    assert quote == result["citations"][0]["text"]
    assert '"first_patched_version": "1.2.0"' in quote
    assert result["agent"]["final_citation_check"]["verified"] == 1


class AssetCompactSDK(TeamSDK):
    def __init__(self, advisory):
        super().__init__(advisory)
        self.research_payloads = []

    def handle(self, request):
        body, role, payload = envelope(request)
        if role != "ResearchDecision":
            return super().handle(request)
        self.research_payloads.append(payload)
        self.research_calls += 1
        assert all(message["type"] in {"ai", "tool"} for message in payload["messages"])
        if self.research_calls == 1:
            assert payload["messages"] == []
            package = next(
                citation for citation in payload["evidence"] if citation["field"] == "packages"
            )
            assert json.loads(package["text"])[0]["first_patched_version"] == "1.2.0"
            assert package["span_provenance"]["boundary_complete"] is True
            result = {
                "action": "tool",
                "tool_name": "asset_exposure",
                "arguments": {"event_id": package["event_id"]},
                "task_ids": ["versions"],
                "note": "资产条件结果只保留本地",
            }
        else:
            tool = next(message for message in payload["messages"] if message["type"] == "tool")
            assert "artifact" not in tool["data"]
            public = json.loads(tool["data"]["content"])
            assert public["result"]["available_locally"] is True
            assert "exposures" not in public["result"] and "asset_id" not in public["result"]
            result = {
                "action": "ready",
                "arguments": {},
                "task_ids": ["versions"],
                "note": "按已有版本字段作答",
            }
        self.requests.append(body)
        self.roles.append(role)
        return httpx.Response(
            200,
            json={
                "id": f"asset-compact-sdk-{len(self.requests)}",
                "object": "chat.completion",
                "created": 1791806400,
                "model": body["model"],
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(result, ensure_ascii=False),
                        },
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            },
        )


def test_prepared_whole_spans_remain_once_and_asset_artifact_stays_local(
    database,
    store,
    settings,
    advisory,
):
    ingest(database, store, fixture_advisory(advisory))
    with database.begin() as session:
        asset = Asset(
            name="private-compaction-host",
            environment="internal",
            criticality="low",
            sbom_sha256="0" * 64,
        )
        session.add(asset)
        session.flush()
        asset_id = asset.id
    cloud = cloud_settings(settings)
    body = request_body(advisory, asset_id=asset_id)
    sdk = AssetCompactSDK(advisory)
    with database() as session:
        runtime = SourceRuntime(session, store, cloud, None)
        tools = ToolSession(runtime, body, asset_id)
        tools.invoke("retrieve", {"query": advisory["ghsa_id"], "mode": "lexical", "limit": 2})
        event_id = next(iter(tools.events))
        tools.invoke("read_fields", {"event_id": event_id, "fields": ["packages"], "limit": 1})
        result = run_agent_team(
            session,
            store,
            cloud,
            body,
            None,
            prepared_tools=tools,
            transport=httpx.MockTransport(sdk.handle),
        )
    assert result["generation"]["status"] == "completed", result["generation"]
    outbound = json.dumps(sdk.requests, ensure_ascii=False)
    assert asset_id not in outbound and "private-compaction-host" not in outbound
    assert "private_asset_data" not in outbound
    assert len(sdk.requests) == 5
    local = next(
        item["result"]
        for item in result["agent"]["tool_results"]
        if item["tool"] == "asset_exposure"
    )
    assert local["asset_id"] == asset_id and local["private_asset_data"] is True
    assert result["generated_claims"][0]["evidence"][0]["quote"] == result["citations"][0]["text"]


def test_compact_research_receipt_replays_with_stable_logical_json_and_zero_repayment(
    database,
    store,
    settings,
    advisory,
    monkeypatch,
):
    ingest(database, store, fixture_advisory(advisory))
    sdk = CompactSDK(advisory)
    cloud = cloud_settings(settings)
    original = RoleRunner.invoke
    requests, interrupted = {}, False

    def interrupt_after_known_reply(self, role, payload, schema, *, call_id):
        nonlocal interrupted
        requests.setdefault(call_id, []).append(canonical_role_payload(payload))
        response = original(self, role, payload, schema, call_id=call_id)
        if call_id == "research:0:1" and not interrupted:
            interrupted = True
            raise RuntimeError("test_interruption_after_compact_research_receipt")
        return response

    monkeypatch.setattr(RoleRunner, "invoke", interrupt_after_known_reply)
    transport = httpx.MockTransport(sdk.handle)
    with database() as session:
        first = run_agent_team(
            session,
            store,
            cloud,
            request_body(advisory),
            None,
            transport=transport,
            checkpoint_key="compact-team-crash",
        )
    assert first["generation"]["status"] == "fallback"
    assert len(sdk.requests) == 3
    with database() as session:
        second = run_agent_team(
            session,
            store,
            cloud,
            request_body(advisory),
            None,
            transport=transport,
            checkpoint_key="compact-team-crash",
            checkpoint_resume_required=True,
        )
    assert second["generation"]["status"] == "completed", second["generation"]
    assert len(sdk.requests) == 5  # only composer/verifier were newly billed
    assert second["cost"]["current_attempt_external_requests"] == 2
    assert second["cost"]["external_requests"] == 5
    assert requests["research:0:1"][0] == requests["research:0:1"][1]
    assert [entry["call_id"] for entry in second["agent"]["role_calls"]] == [
        "planner:0",
        "research:0:0",
        "research:0:1",
        "compose:0",
        "verify:0",
    ]
    assert second["agent"]["attempted_tool_calls"] == 2
    with database() as session:
        complete = run_agent_team(
            session,
            store,
            cloud,
            request_body(advisory),
            None,
            transport=transport,
            checkpoint_key="compact-team-crash",
            checkpoint_resume_required=True,
        )
    assert complete["answer"] == second["answer"]
    assert complete["cost"]["current_attempt_external_requests"] == 0
    assert len(sdk.requests) == 5
