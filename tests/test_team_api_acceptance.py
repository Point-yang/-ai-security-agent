"""API acceptance through actual LangChain SDK JSON roles and SQLite receipts."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from test_member_a_rag_context import fixture_advisory, ingest

pytest.importorskip("langchain_deepseek")

from zhidu.api import create_app
from zhidu.models import ConversationRagTurn, RagRun


class TeamSDK:
    """Deterministic provider fixtures; source facts come from the tool packet."""

    def __init__(self, advisory):
        self.advisory = advisory
        self.requests, self.roles = [], []
        self.research_calls = 0

    def handle(self, request):
        assert request.method == "POST"
        assert request.url.host == "api.deepseek.com"
        body = json.loads(request.content)
        self.requests.append(body)
        assert body["response_format"] == {"type": "json_object"}
        assert body["thinking"] == {"type": "disabled"}
        assert body["temperature"] == 0
        assert not body.get("tools")
        schema = json.loads(body["messages"][0]["content"].rsplit("schema:\n", 1)[1])
        payload = json.loads(body["messages"][-1]["content"])
        schema_name = schema["title"]
        self.roles.append(schema_name)
        if schema_name == "TaskPlan":
            result = {
                "tasks": [
                    {
                        "task_id": "versions",
                        "requirement": "受影响范围和首次修复版本字段",
                        "source_ids": ["github-advisories"],
                        "fields": ["packages"],
                        "contains": None,
                        "keywords": ["vulnerable_version_range", "first_patched_version"],
                        "question_spans": [{"quote": payload["question"]}],
                        "source_policy": "any",
                        "required_elements": ["受影响范围", "首次修复版本字段"],
                    }
                ]
            }
        elif schema_name == "ResearchDecision":
            self.research_calls += 1
            if self.research_calls == 1:
                result = {
                    "action": "tool",
                    "tool_name": "retrieve",
                    "arguments": {"query": self.advisory["ghsa_id"], "mode": "lexical", "limit": 2},
                    "task_ids": ["versions"],
                    "note": "发现公告",
                }
            else:
                tool_message = next(
                    message
                    for message in reversed(payload["messages"])
                    if message["type"] == "tool"
                )
                observation = json.loads(tool_message["data"]["content"])
                event_id = observation["result"]["items"][0]["citation"]["event_id"]
                assert payload["tools"]["read_fields"]["properties"]["fields"]["type"] == "array"
                assert "artifact" not in tool_message["data"]
                result = {
                    "action": "tool",
                    "tool_name": "read_fields",
                    "arguments": {"event_id": event_id, "fields": ["packages"], "limit": 1},
                    "task_ids": ["versions"],
                    "note": "读取版本字段",
                }
        elif schema_name == "AgentAnswer":
            citation = next(
                source for source in payload["sources"] if source["field"] == "packages"
            )
            package = json.loads(citation["text"])[0]
            result = {
                "answer_class": "evidence",
                "statements": [
                    {
                        "text": f"该来源的 vulnerable_version_range 为 {package['vulnerable_version_range']}，first_patched_version 为 {package['first_patched_version']}。",
                        "evidence": [{"evidence_id": citation["evidence_id"]}],
                    }
                ],
                "required_facts": ["受影响范围和首次修复版本字段"],
                "missing_facts": [],
                "limitations": [],
                "message": "",
            }
        elif schema_name == "VerifierDecision":
            assert payload["review_scope"] == "actual_attached_quotes_only"
            assert "sources" not in payload and "evidence" not in payload
            assert "first_patched_version" in payload["statements"][0]["quotes"][0]["quote"]
            anchor = payload["statements"][0]["answer_anchor_id"]
            assert anchor.startswith("ans_")
            assert payload["statements"][0]["quotes"][0]["quote_id"].startswith("src_")
            result = {
                "coverage": [
                    {
                        "task_id": "versions",
                        "status": "covered",
                        "anchor_ids": [anchor],
                        "note": "正文给出两个原始版本字段，引用支持",
                        "element_coverage": [
                            {"element": element, "status": "covered", "anchor_ids": [anchor]}
                            for element in ("受影响范围", "首次修复版本字段")
                        ],
                    }
                ],
                "claim_support": [
                    {
                        "statement_index": 1,
                        "status": "supported",
                        "reason": "自身packages引文支持两个字段",
                    }
                ],
                "unplanned_requirements": [],
                "gaps": [],
            }
        else:
            raise AssertionError(f"unexpected role schema {schema_name}")
        return self.response(body, result)

    def response(self, body, result):
        return httpx.Response(
            200,
            json={
                "id": f"team-sdk-{len(self.requests)}",
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
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 5,
                    "total_tokens": 15,
                    "prompt_cache_hit_tokens": 0,
                    "prompt_cache_miss_tokens": 10,
                },
            },
        )


def attach_transport(monkeypatch, transport):
    from zhidu.agent_team import run_agent_team

    def actual_team(*args, **kwargs):
        return run_agent_team(*args, **kwargs, transport=transport)

    monkeypatch.setattr("zhidu.agent_team.run_agent_team", actual_team)


def test_team_conversation_sdk_roles_and_duplicate_request_are_free(
    database,
    store,
    settings,
    advisory,
    monkeypatch,
):
    ingest(database, store, fixture_advisory(advisory))
    cloud = type(settings)(
        _env_file=None,
        **(
            settings.model_dump()
            | {
                "deepseek_api_key": "mock-team-sdk-secret",
                "llm_temperature": 0,
            }
        ),
    )
    sdk = TeamSDK(advisory)
    attach_transport(monkeypatch, httpx.MockTransport(sdk.handle))
    headers = {"X-Admin-Key": "test-admin"}
    with TestClient(create_app(cloud)) as client:
        cid = client.post(
            "/api/v1/conversations", headers=headers, json={"title": "Team SDK acceptance"}
        ).json()["id"]
        body = {
            "question": "该来源的受影响范围和首次修复版本字段是什么？",
            "query": advisory["ghsa_id"],
            "mode": "lexical",
            "generation": "agent",
            "agent_backend": "team",
            "conversation_id": cid,
            "request_id": "team-api-001",
        }
        first = client.post("/api/v1/rag/answers", headers=headers, json=body)
        repeated = client.post("/api/v1/rag/answers", headers=headers, json=body)
        conflict = client.post(
            "/api/v1/rag/answers",
            headers=headers,
            json={**body, "question": "同一请求编号的另一个问题"},
        )
        status = client.get(
            f"/api/v1/conversations/{cid}/rag-requests/team-api-001", headers=headers
        )
    assert first.status_code == repeated.status_code == 200
    initial, duplicate = first.json(), repeated.json()
    assert initial["generation"]["status"] == "completed", initial["generation"]
    assert initial["agent_backend"] == "team" and initial["answer_class"] == "evidence"
    assert sdk.roles == [
        "TaskPlan",
        "ResearchDecision",
        "ResearchDecision",
        "AgentAnswer",
        "VerifierDecision",
    ]
    assert len(sdk.requests) == 5
    assert initial["cost"]["external_requests"] == 5
    assert initial["cost"]["billed_tokens"] == 75
    assert duplicate["deduplicated"] is True and duplicate["id"] == initial["id"]
    assert duplicate["cost"]["current_attempt_external_requests"] == 0
    assert duplicate["cost"]["current_attempt_billed_tokens"] == 0
    assert conflict.status_code == 409
    assert status.json()["status"] == "completed"
    assert status.json()["generated_result_saved"] is True
    assert status.json()["resume_eligible"] is False
    assert [step["tool"] for step in initial["tools"]] == ["retrieve", "read_fields"]
    quote = initial["generated_claims"][0]["evidence"][0]["quote"]
    assert quote == initial["citations"][0]["text"]
    assert "mock-team-sdk-secret" not in json.dumps(initial)
    with database() as session:
        assert session.scalar(select(func.count()).select_from(ConversationRagTurn)) == 1
        assert session.scalar(select(func.count()).select_from(RagRun)) == 1


def test_team_api_authorization_and_missing_asset_preflight_send_no_sdk_request(
    database,
    store,
    settings,
    advisory,
    monkeypatch,
):
    ingest(database, store, fixture_advisory(advisory))
    sdk = TeamSDK(advisory)
    attach_transport(monkeypatch, httpx.MockTransport(sdk.handle))
    body = {
        "question": "我的资产是否受影响？",
        "query": advisory["ghsa_id"],
        "mode": "lexical",
        "generation": "agent",
        "agent_backend": "team",
    }
    with TestClient(create_app(settings)) as client:
        unauthorized = client.post("/api/v1/rag/answers", json=body)
        authorized = client.post(
            "/api/v1/rag/answers", json=body, headers={"X-Admin-Key": "test-admin"}
        )
    assert unauthorized.status_code == 401
    assert authorized.status_code == 200
    result = authorized.json()
    assert result["answer_class"] == "clarification"
    assert result["reason"] == "explicit_asset_required"
    assert result["context"]["citations"] == 0
    assert result["cost"]["external_requests"] == 0
    assert sdk.requests == []


def test_deadline_before_dispatch_has_no_inflight_paid_receipt_and_can_resume(
    database,
    store,
    settings,
    advisory,
):
    from zhidu.agent_roles import RoleError, RoleRunner
    from zhidu.agent_team_state import TaskPlan
    from zhidu.langchain_tools import SourceRuntime, ToolSession
    from zhidu.rag import RagRequest

    cloud = type(settings)(
        _env_file=None,
        **(
            settings.model_dump()
            | {
                "deepseek_api_key": "mock-team-sdk-secret",
                "llm_temperature": 0,
            }
        ),
    )
    sdk = TeamSDK(advisory)
    ticks = [0.0]
    body = RagRequest(
        question="受影响范围是什么？",
        query=advisory["ghsa_id"],
        mode="lexical",
        generation="agent",
        agent_backend="team",
    )
    with database() as session:
        runtime = SourceRuntime(session, store, cloud, None, clock=lambda: ticks[0])
        tools = ToolSession(runtime, body, None)
        ticks[0] = 100.0
        with RoleRunner(
            cloud, runtime, tools, model=object(), checkpoint_key="not-dispatched"
        ) as runner:
            with pytest.raises(RoleError, match="agent_deadline_exceeded"):
                runner.invoke("planner", {"question": body.question}, TaskPlan, call_id="planner:0")
            assert runner.calls() == []
            assert runner.external_requests == 0
            assert runner.has_reply("planner:0") is False
        ticks[0] = 0.0
        with RoleRunner(
            cloud,
            runtime,
            tools,
            transport=httpx.MockTransport(sdk.handle),
            checkpoint_key="not-dispatched",
            checkpoint_resume_required=True,
        ) as resumed:
            plan = resumed.invoke(
                "planner", {"question": body.question}, TaskPlan, call_id="planner:0"
            )
            assert plan.tasks[0].task_id == "versions"
            assert resumed.external_requests == 1
            assert resumed.current_attempt_external_requests == 1
            assert resumed.calls()[0]["status"] == "completed"
    assert len(sdk.requests) == 1


class RequirementSDK(TeamSDK):
    def __init__(self, advisory, *, source_policy="any", omission=False):
        super().__init__(advisory)
        self.source_policy, self.omission = source_policy, omission

    def handle(self, request):
        request_body = json.loads(request.content)
        schema = json.loads(request_body["messages"][0]["content"].rsplit("schema:\n", 1)[1])
        payload = json.loads(request_body["messages"][-1]["content"])
        response = super().handle(request)
        data = response.json()
        content = json.loads(data["choices"][0]["message"]["content"])
        if schema["title"] == "TaskPlan":
            content["tasks"][0]["source_policy"] = self.source_policy
            content["tasks"][0]["source_ids"] = ["github-advisories", "nvd"]
        if schema["title"] == "VerifierDecision":
            assert payload["question_must_be_reviewed_independently_of_plan"] is True
            if self.omission:
                content["unplanned_requirements"] = [
                    {
                        "requirement": "解释应用暴露的同时条件",
                        "question_quote": "解释应用暴露的同时条件",
                        "reason": "原问题另要求该条件；当前正文只给版本字段，尚未回答",
                    }
                ]
        data["choices"][0]["message"]["content"] = json.dumps(content, ensure_ascii=False)
        return httpx.Response(200, json=data)


@pytest.mark.parametrize("policy,expected", [("any", "evidence"), ("each", "partial")])
def test_sdk_source_policy_does_not_reclassify_supported_github_claim_as_unsupported(
    database,
    store,
    settings,
    advisory,
    policy,
    expected,
):
    from zhidu.agent_team import run_agent_team
    from zhidu.rag import RagRequest

    ingest(database, store, fixture_advisory(advisory))
    cloud = type(settings)(
        _env_file=None, **(settings.model_dump() | {"deepseek_api_key": "mock-team-sdk-secret"})
    )
    sdk = RequirementSDK(advisory, source_policy=policy)
    with database() as session:
        result = run_agent_team(
            session,
            store,
            cloud,
            RagRequest(
                question="分别给出 GitHub 和 NVD 的受影响范围与首次修复字段。"
                if policy == "each"
                else "给出公告受影响范围与首次修复字段。",
                query=advisory["ghsa_id"],
                mode="lexical",
                generation="agent",
                agent_backend="team",
            ),
            None,
            transport=httpx.MockTransport(sdk.handle),
        )
    assert result["generation"]["status"] == "completed", result["generation"]
    assert result["answer_class"] == expected
    assert len(result["generated_claims"]) == 1
    assert result["agent"]["verification"]["claim_support"][0]["status"] == "supported"
    assert result["claim_support"][0]["retained"] is True
    if policy == "each":
        assert result["requirement_ledger"]["tasks"][0]["status"] == "partial"
    assert len(sdk.requests) == 5


class WrongAnchorSDK(TeamSDK):
    def __init__(self, advisory, *, old_anchor=None, change_candidate=False):
        super().__init__(advisory)
        self.old_anchor, self.change_candidate = old_anchor, change_candidate
        self.current_anchor = None

    def handle(self, request):
        response = super().handle(request)
        value = response.json()
        result = json.loads(value["choices"][0]["message"]["content"])
        if self.roles[-1] == "AgentAnswer" and self.change_candidate:
            result["statements"][0]["text"] += "（该公告声明）"
        if self.roles[-1] == "VerifierDecision":
            payload = json.loads(self.requests[-1]["messages"][-1]["content"])
            self.current_anchor = payload["statements"][0]["answer_anchor_id"]
            wrong = self.old_anchor or payload["statements"][0]["quotes"][0]["quote_id"]
            result["coverage"][0]["anchor_ids"] = [wrong]
            for element in result["coverage"][0]["element_coverage"]:
                element["anchor_ids"] = [wrong]
        value["choices"][0]["message"]["content"] = json.dumps(result, ensure_ascii=False)
        return httpx.Response(200, json=value)


def test_sdk_source_quote_id_cannot_locate_prose_and_known_receipt_resume_is_free(
    database,
    store,
    settings,
    advisory,
):
    from zhidu.agent_team import run_agent_team
    from zhidu.rag import RagRequest

    ingest(database, store, fixture_advisory(advisory))
    cloud = type(settings)(
        _env_file=None, **(settings.model_dump() | {"deepseek_api_key": "mock-anchor-sdk-key"})
    )
    sdk = WrongAnchorSDK(advisory)
    transport = httpx.MockTransport(sdk.handle)
    body = RagRequest(
        question="受影响范围与首次修复字段是什么？",
        query=advisory["ghsa_id"],
        mode="lexical",
        generation="agent",
        agent_backend="team",
    )
    with database() as session:
        first = run_agent_team(
            session,
            store,
            cloud,
            body,
            None,
            transport=transport,
            checkpoint_key="wrong-anchor-sdk",
        )
    assert first["generation"]["reason"] == "invalid_verifier_anchor_id"
    assert first.get("generated_claims", []) == []
    assert len(sdk.requests) == 5
    assert first["agent"]["role_calls"][-1]["status"] == "completed"
    with database() as session:
        replay = run_agent_team(
            session,
            store,
            cloud,
            body,
            None,
            transport=transport,
            checkpoint_key="wrong-anchor-sdk",
            checkpoint_resume_required=True,
        )
    assert replay["generation"]["reason"] == "invalid_verifier_anchor_id"
    assert replay["cost"]["current_attempt_external_requests"] == 0
    assert len(sdk.requests) == 5


def test_sdk_anchor_from_previous_candidate_is_rejected_even_with_the_same_source_quote(
    database,
    store,
    settings,
    advisory,
):
    from zhidu.agent_team import run_agent_team
    from zhidu.rag import RagRequest

    ingest(database, store, fixture_advisory(advisory))
    cloud = type(settings)(
        _env_file=None, **(settings.model_dump() | {"deepseek_api_key": "mock-stale-anchor-key"})
    )
    first_sdk = TeamSDK(advisory)
    body = RagRequest(
        question="受影响范围与首次修复字段是什么？",
        query=advisory["ghsa_id"],
        mode="lexical",
        generation="agent",
        agent_backend="team",
    )
    with database() as session:
        first = run_agent_team(
            session, store, cloud, body, None, transport=httpx.MockTransport(first_sdk.handle)
        )
    assert first["generation"]["status"] == "completed"
    original = json.loads(first_sdk.requests[-1]["messages"][-1]["content"])
    old_anchor = original["statements"][0]["answer_anchor_id"]
    second_sdk = WrongAnchorSDK(advisory, old_anchor=old_anchor, change_candidate=True)
    with database() as session:
        second = run_agent_team(
            session, store, cloud, body, None, transport=httpx.MockTransport(second_sdk.handle)
        )
    current = json.loads(second_sdk.requests[-1]["messages"][-1]["content"])
    assert second_sdk.current_anchor != old_anchor
    assert (
        current["statements"][0]["quotes"][0]["quote"]
        == original["statements"][0]["quotes"][0]["quote"]
    )
    assert second["generation"]["reason"] == "invalid_verifier_anchor_id"
    assert second.get("generated_claims", []) == []


class CompactTenElementsSDK(TeamSDK):
    elements = [f"必要条件{index}" for index in range(1, 11)]

    def __init__(self, advisory):
        super().__init__(advisory)
        self.wire_response = None

    def handle(self, request):
        body = json.loads(request.content)
        schema = json.loads(body["messages"][0]["content"].rsplit("schema:\n", 1)[1])
        if schema["title"] == "VerifierDecision":
            self.requests.append(body)
            self.roles.append("VerifierDecision")
            payload = json.loads(body["messages"][-1]["content"])
            anchor = payload["statements"][0]["answer_anchor_id"]
            assert all(
                element in payload["statements"][0]["quotes"][0]["quote"]
                for element in self.elements
            )
            result = {
                "coverage": [
                    {
                        "task_id": task["task_id"],
                        "status": "covered",
                        "anchor_ids": [anchor],
                        "note": "正文列出必要条件",
                        "element_coverage": [
                            {"element": element, "status": "covered", "anchor_ids": [anchor]}
                            for element in task["required_elements"]
                        ],
                    }
                    for task in payload["tasks"]
                ],
                "claim_support": [
                    {
                        "statement_index": 1,
                        "status": "supported",
                        "reason": "自身description引文支持十项条件",
                    }
                ],
                "unplanned_requirements": [],
                "gaps": [],
            }
            self.wire_response = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
            assert body["max_tokens"] == 2400
            return self.response(body, result)
        response = super().handle(request)
        value = response.json()
        result = json.loads(value["choices"][0]["message"]["content"])
        payload = json.loads(self.requests[-1]["messages"][-1]["content"])
        if self.roles[-1] == "TaskPlan":
            task = result["tasks"][0]
            result["tasks"] = [
                {
                    **task,
                    "task_id": f"conditions-{index}",
                    "requirement": "说明必要条件",
                    "required_elements": self.elements[index * 5 : (index + 1) * 5],
                }
                for index in range(2)
            ]
        if self.roles[-1] == "ResearchDecision":
            result["task_ids"] = ["conditions-0", "conditions-1"]
        if self.roles[-1] == "AgentAnswer":
            citation = next(
                source for source in payload["sources"] if source["field"] == "description"
            )
            result["statements"] = [
                {
                    "text": "公告说明" + "、".join(self.elements) + "须同时满足。",
                    "evidence": [{"evidence_id": citation["evidence_id"]}],
                }
            ]
        value["choices"][0]["message"]["content"] = json.dumps(result, ensure_ascii=False)
        return httpx.Response(200, json=value)


def test_sdk_ten_element_review_uses_compact_ids_under_the_2400_output_budget(
    database,
    store,
    settings,
    advisory,
):
    from zhidu.agent_team import run_agent_team
    from zhidu.langchain_tools import SourceRuntime, ToolSession
    from zhidu.models import IntelEvent
    from zhidu.rag import RagRequest

    source = fixture_advisory(advisory)
    source["description"] = "公告说明" + "、".join(CompactTenElementsSDK.elements) + "须同时满足。"
    ingest(database, store, source)
    cloud = type(settings)(
        _env_file=None,
        **(
            settings.model_dump()
            | {
                "deepseek_api_key": "mock-compact-anchor-key",
                "deepseek_max_tokens": 2400,
            }
        ),
    )
    sdk = CompactTenElementsSDK(advisory)
    body = RagRequest(
        question="说明全部十项必要条件。",
        query=advisory["ghsa_id"],
        mode="lexical",
        generation="agent",
        agent_backend="team",
    )
    with database() as session:
        tools = ToolSession(SourceRuntime(session, store, cloud, None), body, None)
        tools.invoke("retrieve", {"query": advisory["ghsa_id"], "mode": "lexical", "limit": 1})
        event_id = session.scalar(select(IntelEvent.id))
        tools.invoke("read_fields", {"event_id": event_id, "fields": ["description"], "limit": 1})
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
    assert (
        sum(len(task["element_coverage"]) for task in result["requirement_ledger"]["tasks"]) == 10
    )
    # Conservative byte-bound plus the actual SDK request ceiling; no claim
    # that this fixture is a real model tokenization or semantic-quality run.
    assert len(sdk.wire_response.encode()) < 2400
    assert result["generated_claims"][0]["text"] not in sdk.wire_response
    assert all("answer_spans" not in row for row in json.loads(sdk.wire_response)["coverage"])
    assert result["claim_support"][0]["retained"] is True


def test_sdk_verifier_reports_question_condition_even_when_planner_omits_it(
    database,
    store,
    settings,
    advisory,
):
    from zhidu.agent_team import run_agent_team
    from zhidu.rag import RagRequest

    ingest(database, store, fixture_advisory(advisory))
    cloud = type(settings)(
        _env_file=None, **(settings.model_dump() | {"deepseek_api_key": "mock-team-sdk-secret"})
    )
    sdk = RequirementSDK(advisory, omission=True)
    with database() as session:
        result = run_agent_team(
            session,
            store,
            cloud,
            RagRequest(
                question="给出原始版本范围与首次修复字段，并解释应用暴露的同时条件。",
                query=advisory["ghsa_id"],
                mode="lexical",
                generation="agent",
                agent_backend="team",
            ),
            None,
            transport=httpx.MockTransport(sdk.handle),
        )
    assert result["generation"]["status"] == "completed", result["generation"]
    assert result["answer_class"] == "partial"
    assert len(result["generated_claims"]) == 1
    assert "解释应用暴露的同时条件" in result["answer"]
    assert (
        result["agent"]["verification"]["unplanned_requirements"][0]["question_span"]["start"] >= 0
    )
    assert len(sdk.requests) == 5
