"""Agent planning choices are observable, bounded, and source grounded."""

import json
from datetime import UTC, datetime

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from test_member_a_rag_context import fixture_advisory, ingest

from zhidu.agent_rag import Plan, plan_step, run_agent
from zhidu.api import create_app
from zhidu.models import RagRun
from zhidu.rag import RagRequest


def scripted(monkeypatch, calls):
    choices = []

    def planner(settings, question, tools, observations, *, phase, transport=None):
        assert phase in calls
        planned = calls[phase]
        choices.append((phase, list(tools), observations))
        return (
            Plan.model_validate(
                {"decision_summary": f"针对问题选择{phase}的当前证据工具。", "calls": planned}
            ),
            {"total_tokens": 11},
            "mock-planner",
        )

    def generator(settings, question, result, *, history=None, transport=None):
        assert result["citations"] and result["agent"]["final_citation_check"]["verified"] == len(
            result["citations"]
        )
        result["answer"] = "仅演示本轮引用。 [1]"
        result["generation_model"] = "mock-answer"
        result["generation"] = {
            "provider": "deepseek",
            "status": "completed",
            "usage": {"total_tokens": 42},
            "semantic_support_verified": False,
            "input_sha256": "mock-input",
        }

    monkeypatch.setattr("zhidu.agent_rag.plan_step", planner)
    monkeypatch.setattr("zhidu.agent_rag.apply_generation", generator)
    return choices


def first(query="GHSA-aaaa-bbbb-cccc", mode="lexical"):
    return [{"name": "retrieve", "arguments": {"query": query, "mode": mode, "limit": 3}}]


def test_model_selects_details_for_version_and_persists_trace(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    with database() as s:
        from zhidu.models import IntelEvent, SearchChunk

        eid = s.scalar(select(IntelEvent)).id
        cid = s.scalar(select(SearchChunk).where(SearchChunk.field == "packages")).id
    # Planner arguments are the only choices; use current IDs, never an invented source.
    scripted(
        monkeypatch,
        {
            "target_retrieval": first(),
            "evidence_analysis": [
                {"name": "event_details", "arguments": {"event_id": eid}},
                {"name": "verify_evidence", "arguments": {"chunk_id": cid}},
            ],
        },
    )
    with database() as s:
        r = run_agent(
            s,
            store,
            settings,
            RagRequest(
                question="首次修复版本是什么？",
                query=advisory["ghsa_id"],
                mode="lexical",
                generation="agent",
            ),
            None,
        )
    assert r["agent"]["status"] == "completed"
    assert [d["selected_tools"] for d in r["agent"]["decisions"]] == [
        ["retrieve"],
        ["event_details", "verify_evidence"],
    ]
    assert [x["tool"] for x in r["agent"]["tool_steps"]] == [
        "retrieve",
        "event_details",
        "verify_evidence",
    ]
    assert r["agent"]["final_citation_check"]["verified"] == len(r["citations"])
    assert r["cost"]["external_requests"] == 3 and r["cost"]["billed_tokens"] == 64
    assert r["generation"]["semantic_support_verified"] is False


def test_model_selects_comparison_and_keeps_source_disagreement(
    database, store, settings, advisory, monkeypatch
):
    a = fixture_advisory(advisory)
    ingest(database, store, a)
    b = fixture_advisory(advisory)
    b["vulnerabilities"][0]["first_patched_version"] = "1.3.0"
    ingest(database, store, b, source="vllm-vendor")
    scripted(
        monkeypatch,
        {
            "target_retrieval": first(),
            "evidence_analysis": [
                {"name": "compare_sources", "arguments": {"identifier": a["cve_id"]}},
            ],
        },
    )
    with database() as s:
        r = run_agent(
            s,
            store,
            settings,
            RagRequest(
                question="两个来源对首次修复版本的说法有什么不同？",
                query=a["ghsa_id"],
                mode="lexical",
                generation="agent",
            ),
            None,
        )
    assert r["agent"]["decisions"][1]["selected_tools"] == ["compare_sources"]
    assert {c["source_id"] for c in r["citations"]} == {"github-advisories", "vllm-vendor"}
    assert {c["source_id"] for c in r["citations"] if c["field"] == "packages"} == {
        "github-advisories",
        "vllm-vendor",
    }
    assert len(r["agent"]["policy_steps"]) == 2
    assert all(
        step["tool"] == "event_details" and not step["model_selected"]
        for step in r["agent"]["policy_steps"]
    )
    assert r["tool_calls"] <= 6
    assert any(x["code"] == "source_comparison_unresolved" for x in r["constraints"])
    assert r["agent"]["tool_results"][1]["result"]["items"]


def test_recovery_after_hybrid_failure_and_no_silent_mode_change(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    scripted(
        monkeypatch,
        {
            "target_retrieval": first(mode="hybrid"),
            "lexical_recovery": first(mode="hybrid"),
            "evidence_analysis": [
                {"name": "retrieve", "arguments": {"query": advisory["ghsa_id"], "mode": "lexical"}}
            ],
        },
    )
    with database() as s:
        r = run_agent(
            s,
            store,
            settings,
            RagRequest(
                question="有什么影响？",
                query=advisory["ghsa_id"],
                mode="hybrid",
                generation="agent",
            ),
            None,
        )
    assert [t["status"] for t in r["agent"]["tool_steps"][:2]] == ["failed", "completed"]
    assert r["agent"]["tool_steps"][0]["error"] == "model_unavailable"
    assert r["agent"]["tool_steps"][1]["input"]["mode"] == "lexical"
    assert r["agent"]["status"] == "completed"


def test_asset_requires_explicit_selection_and_stays_local(
    database, store, settings, advisory, monkeypatch
):
    from pathlib import Path

    from zhidu.asset_matching import import_cyclonedx
    from zhidu.models import IntelEvent

    ingest(database, store, fixture_advisory(advisory))
    with database.begin() as s:
        aid = import_cyclonedx(
            s,
            Path("examples/cyclonedx-vllm-demo.json").read_bytes(),
            asset_name="PRIVATE-ASSET",
            environment="test",
            criticality="low",
        )[0].id
    with database() as s:
        eid = s.scalar(select(IntelEvent)).id
    seen = []

    def planner(settings, question, tools, observations, *, phase, transport=None):
        assert "PRIVATE-ASSET" not in json.dumps(observations)
        assert aid not in json.dumps(observations)
        seen.append(phase)
        calls = (
            first()
            if phase == "target_retrieval"
            else [
                {
                    "name": "asset_exposure",
                    "arguments": {"asset_id": "<selected_asset>", "event_id": eid},
                }
            ]
        )
        return (
            Plan.model_validate(
                {"decision_summary": "针对问题选择当前资产条件证据。", "calls": calls}
            ),
            {"total_tokens": 10},
            "mock",
        )

    def generate(settings, question, result, *, history=None, transport=None):
        assert any(
            item["result"]["private_asset_data"] is True
            for item in result["agent"]["tool_results"]
            if item["tool"] == "asset_exposure" and item["status"] == "completed"
        )
        assert all("PRIVATE-ASSET" not in json.dumps(c) for c in result["citations"])
        result["generation"] = {
            "status": "completed",
            "usage": {"total_tokens": 20},
            "semantic_support_verified": False,
            "input_sha256": "mock",
        }
        result["generation_model"] = "mock"

    monkeypatch.setattr("zhidu.agent_rag.plan_step", planner)
    monkeypatch.setattr("zhidu.agent_rag.apply_generation", generate)
    with database() as s:
        missing = run_agent(
            s,
            store,
            settings,
            RagRequest(
                question="我的资产是否受影响？",
                query=advisory["ghsa_id"],
                mode="lexical",
                generation="agent",
            ),
            None,
        )
        chosen = run_agent(
            s,
            store,
            settings,
            RagRequest(
                question="我的资产是否受影响？",
                query=advisory["ghsa_id"],
                mode="lexical",
                generation="agent",
                asset_id=aid,
            ),
            None,
        )
    assert missing["answer_class"] == "clarification" and not missing["agent"]["decisions"]
    assert chosen["agent"]["private_asset_details_sent_to_model"] is False
    assert seen == ["target_retrieval", "evidence_analysis"]


def test_invalid_tool_and_limit_are_audited_without_execution(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    choices = []

    def planner(settings, question, tools, observations, *, phase, transport=None):
        choices.append(phase)
        if phase == "target_retrieval":
            return (
                Plan.model_validate({"decision_summary": "先检索当前公告原文。", "calls": first()}),
                {"total_tokens": 3},
                "mock",
            )
        # ToolCall schema rejects an arbitrary executable even if the model emits it.
        from zhidu.agent_rag import PlanningFailure

        raise PlanningFailure("tool_not_allowed")

    monkeypatch.setattr("zhidu.agent_rag.plan_step", planner)
    with database() as s:
        r = run_agent(
            s,
            store,
            settings,
            RagRequest(
                question="执行POC", query=advisory["ghsa_id"], mode="lexical", generation="agent"
            ),
            None,
        )
    assert r["agent"]["status"] == "fallback" and r["agent"]["reason"] == "tool_not_allowed"
    assert choices == ["target_retrieval", "evidence_analysis", "evidence_analysis"]
    assert not any(t["tool"] == "execute_poc" for t in r["agent"]["tool_steps"])
    assert r["answer"].startswith("Agent 工具规划或检索未完成")


def test_http_agent_turn_deduplicates_and_links_trace(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    with database() as s:
        from zhidu.models import IntelEvent

        eid = s.scalar(select(IntelEvent)).id
    choices = scripted(
        monkeypatch,
        {
            "target_retrieval": first(),
            "evidence_analysis": [{"name": "event_details", "arguments": {"event_id": eid}}],
        },
    )
    with TestClient(create_app(settings)) as client:
        cid = client.post(
            "/api/v1/conversations",
            headers={"X-Admin-Key": "test-admin"},
            json={"title": "Agent测试"},
        ).json()["id"]
        body = {
            "conversation_id": cid,
            "request_id": "agent-idempotent-1",
            "agent_backend": "legacy",
            "question": "这条漏洞如何修复？",
            "query": advisory["ghsa_id"],
            "mode": "lexical",
            "generation": "agent",
        }
        first_result = client.post(
            "/api/v1/rag/answers", headers={"X-Admin-Key": "test-admin"}, json=body
        )
        assert first_result.status_code == 200, first_result.text
        second = client.post(
            "/api/v1/rag/answers", headers={"X-Admin-Key": "test-admin"}, json=body
        ).json()
        assert second["deduplicated"] and second["id"] == first_result.json()["id"]
        assert len(choices) == 2
        replay = client.get(f"/api/v1/conversations/{cid}/replay").json()
        assert replay["messages"][-1]["hops"][-1]["output_data"]["agent"]["decisions"][1][
            "selected_tools"
        ] == ["event_details"]
    with database() as s:
        assert s.scalar(select(func.count()).select_from(RagRun)) == 1


def test_json_planner_discloses_no_asset_or_key_and_rejects_unlisted_tools(settings):
    cloud = settings.model_copy(
        update={"deepseek_api_key": type(settings.deepseek_api_key)("secret-test")}
    )

    def handler(request):
        body = json.loads(request.content)
        serialized = json.dumps(body)
        assert "PRIVATE-ASSET" not in serialized and "secret-test" not in serialized
        assert body["thinking"] == {"type": "disabled"}
        return httpx.Response(
            200,
            json={
                "model": "mock",
                "usage": {"total_tokens": 12},
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": json.dumps(
                                {"decision_summary": "根据公告编号查询当前证据。", "calls": first()}
                            )
                        },
                    }
                ],
            },
        )

    plan, usage, _ = plan_step(
        cloud,
        "查询公告",
        ["retrieve"],
        {"asset_selected": False},
        phase="target_retrieval",
        transport=httpx.MockTransport(handler),
    )
    assert plan.calls[0].name == "retrieve" and usage["total_tokens"] == 12

    def bad(request):
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": json.dumps(
                                {
                                    "decision_summary": "执行任意脚本。",
                                    "calls": [{"name": "run_shell", "arguments": {}}],
                                }
                            )
                        },
                    }
                ]
            },
        )

    from zhidu.agent_rag import PlanningFailure

    with pytest.raises(PlanningFailure) as exc:
        plan_step(
            cloud,
            "查询公告",
            ["retrieve"],
            {},
            phase="target_retrieval",
            transport=httpx.MockTransport(bad),
        )
    assert exc.value.reason == "invalid_plan"


def test_planner_normalizes_format_without_expanding_tool_whitelist():
    from pydantic import ValidationError

    from zhidu.agent_rag import _parse_plan

    fenced = (
        "```json\n"
        + json.dumps(
            {
                "decision_summary": "检索当前公开公告。",
                "calls": {
                    "tool": "retrieve",
                    "args": json.dumps({"query": "GHSA-aaaa-bbbb-cccc", "mode": "lexical"}),
                },
                "unused_comment": "never executed",
            }
        )
        + "\n```"
    )
    plan = _parse_plan(fenced)
    assert plan.calls[0].name == "retrieve"
    assert plan.calls[0].arguments["mode"] == "lexical"
    with pytest.raises(ValidationError):
        _parse_plan(
            json.dumps(
                {
                    "decision_summary": "执行未知命令。",
                    "calls": [{"name": "execute_poc", "arguments": {}}],
                }
            )
        )


def test_one_format_correction_is_audited_then_accepted(
    database, store, settings, advisory, monkeypatch
):
    from zhidu.agent_rag import PlanningFailure
    from zhidu.models import IntelEvent

    ingest(database, store, fixture_advisory(advisory))
    with database() as s:
        eid = s.scalar(select(IntelEvent)).id
    attempts = []

    def planner(settings, question, tools, observations, *, phase, transport=None):
        attempts.append((phase, observations))
        if phase == "target_retrieval":
            calls = first()
        elif sum(name == "evidence_analysis" for name, _ in attempts) == 1:
            raise PlanningFailure("invalid_plan", {"total_tokens": 8})
        else:
            assert observations["rejection_code"] == "invalid_plan"
            calls = [{"name": "event_details", "arguments": {"event_id": eid}}]
        return (
            Plan.model_validate(
                {"decision_summary": "选择白名单中的当前来源工具。", "calls": calls}
            ),
            {"total_tokens": 8},
            "mock",
        )

    def generator(settings, question, result, *, history=None, transport=None):
        result["generation"] = {
            "status": "completed",
            "usage": {"total_tokens": 16},
            "semantic_support_verified": False,
            "input_sha256": "mock",
        }
        result["generation_model"] = "mock"

    monkeypatch.setattr("zhidu.agent_rag.plan_step", planner)
    monkeypatch.setattr("zhidu.agent_rag.apply_generation", generator)
    with database() as s:
        result = run_agent(
            s,
            store,
            settings,
            RagRequest(
                question="公告版本范围是什么？",
                query=advisory["ghsa_id"],
                mode="lexical",
                generation="agent",
            ),
            None,
        )
    assert [d["status"] for d in result["agent"]["decisions"]] == [
        "completed",
        "failed",
        "completed",
    ]
    assert result["agent"]["decisions"][-1]["attempt"] == 2
    assert result["cost"]["external_requests"] == 4
    assert [t["tool"] for t in result["agent"]["tool_steps"]] == ["retrieve", "event_details"]


def test_unsupported_claim_and_missing_record_refuse_without_generated_fact(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    phases = scripted(
        monkeypatch,
        {
            "target_retrieval": first(query="zzzzmissingcomponent20999999"),
            "evidence_analysis": [
                {
                    "name": "retrieve",
                    "arguments": {"query": "zzzzmissingcomponent20999999", "mode": "lexical"},
                }
            ],
        },
    )
    with database() as s:
        unsafe = run_agent(
            s,
            store,
            settings,
            RagRequest(
                question="证明所有资产都安全",
                query=advisory["ghsa_id"],
                mode="lexical",
                generation="agent",
            ),
            None,
        )
        missing = run_agent(
            s,
            store,
            settings,
            RagRequest(
                question="zzzzmissingcomponent20999999",
                query="zzzzmissingcomponent20999999",
                mode="lexical",
                generation="agent",
            ),
            None,
        )
    assert unsafe["answer_class"] == "refused" and not unsafe["agent"]["decisions"]
    assert missing["answer_class"] == "refused" and not missing["citations"]
    assert not missing.get("generated_claims") and len(phases) == 2


def test_explicit_unknown_or_withdrawn_identifier_stops_before_cloud_plan(
    database, store, settings, advisory, monkeypatch
):
    from zhidu.models import IntelEvent

    ingest(database, store, fixture_advisory(advisory))
    attempts = []

    def unexpected(*args, **kwargs):
        attempts.append("cloud")
        raise AssertionError("cloud planner must not be called")

    monkeypatch.setattr("zhidu.agent_rag.plan_step", unexpected)
    with database() as session:
        missing = run_agent(
            session,
            store,
            settings,
            RagRequest(
                question="这条公告是什么？",
                query="GHSA-0000-xxxx-1234",
                mode="lexical",
                generation="agent",
            ),
            None,
        )
    with database.begin() as session:
        session.scalar(select(IntelEvent)).withdrawn_at = datetime.now(UTC)
    with database() as session:
        withdrawn = run_agent(
            session,
            store,
            settings,
            RagRequest(
                question="这条公告是什么？",
                query=advisory["ghsa_id"],
                mode="lexical",
                generation="agent",
            ),
            None,
        )
    assert not attempts
    assert missing["reason"] == withdrawn["reason"] == "explicit_identifier_not_current"
    assert missing["cost"]["external_requests"] == withdrawn["cost"]["external_requests"] == 0


def test_invalid_generated_quote_falls_back_with_tool_trace(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    with database() as s:
        from zhidu.models import IntelEvent

        eid = s.scalar(select(IntelEvent)).id
    scripted(
        monkeypatch,
        {
            "target_retrieval": first(),
            "evidence_analysis": [{"name": "event_details", "arguments": {"event_id": eid}}],
        },
    )
    monkeypatch.setattr(
        "zhidu.agent_rag.apply_generation",
        __import__("zhidu.generation", fromlist=["apply_generation"]).apply_generation,
    )
    cloud = settings.model_copy(
        update={"deepseek_api_key": type(settings.deepseek_api_key)("local-test-secret")}
    )

    def bogus(request):
        assert b"local-test-secret" not in request.content
        return httpx.Response(
            200,
            json={
                "model": "mock",
                "usage": {"total_tokens": 90},
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": json.dumps(
                                {
                                    "statements": [
                                        {
                                            "text": "凭空声称已修复",
                                            "evidence": [
                                                {"citation": 1, "quote": "invented-source-quote"}
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

    with database() as s:
        r = run_agent(
            s,
            store,
            cloud,
            RagRequest(
                question="首次修复版本？",
                query=advisory["ghsa_id"],
                mode="lexical",
                generation="agent",
            ),
            None,
            transport=httpx.MockTransport(bogus),
        )
    assert r["generation"]["status"] == "fallback"
    assert r["generation"]["reason"] == "invalid_citation"
    assert r["generation"]["validation_error"]["kind"] == "quote_not_verbatim"
    assert r["agent"]["status"] == "fallback"
    assert "凭空声称" not in r["answer"] and r["citations"]


def test_supplementary_retrieval_is_offered_only_for_sparse_results_and_runs_once(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    choices = scripted(
        monkeypatch,
        {
            "target_retrieval": [
                {
                    "name": "retrieve",
                    "arguments": {"query": advisory["ghsa_id"], "mode": "lexical", "limit": 1},
                }
            ],
            "evidence_analysis": [
                {
                    "name": "retrieve",
                    "arguments": {"query": advisory["ghsa_id"], "mode": "lexical", "limit": 1},
                }
                for _ in range(3)
            ],
        },
    )
    with database() as s:
        result = run_agent(
            s,
            store,
            settings,
            RagRequest(
                question="还缺什么证据？",
                query=advisory["ghsa_id"],
                mode="lexical",
                generation="agent",
            ),
            None,
        )
    assert "retrieve" in choices[-1][1]
    assert [r["status"] for r in result["agent"]["tool_results"]] == [
        "completed",
        "completed",
        "failed",
        "failed",
        "completed",
    ]
    assert len(result["agent"]["policy_rejections"]) == 2
    assert result["tool_calls"] == 5
    assert result["answer_class"] == "partial"


def test_planner_cannot_repeat_retrieval_when_current_evidence_is_sufficient(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    query = "vllm input validation"
    scripted(
        monkeypatch,
        {"target_retrieval": first(query=query), "evidence_analysis": first(query=query)},
    )
    with database() as s:
        result = run_agent(
            s,
            store,
            settings,
            RagRequest(
                question="公告版本是什么？",
                query=query,
                mode="lexical",
                generation="agent",
            ),
            None,
        )
    assert result["agent"]["status"] == "fallback"
    assert result["agent"]["reason"] == "tool_not_allowed"
    assert result["agent"]["decisions"][-1]["candidate_tools"] == [
        "event_details",
        "verify_evidence",
    ]
    assert len(result["agent"]["tool_steps"]) == 1
