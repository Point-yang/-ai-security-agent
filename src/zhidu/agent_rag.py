"""Model-chosen, bounded read-only tools; source bytes remain the answer boundary."""

import json
import re
import time

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select

from zhidu.agent_tools import AgentToolRuntime, ToolCall, contracts
from zhidu.answers import requires_asset_context
from zhidu.evaluation import verify_hit
from zhidu.generation import GenerationError, apply_generation, endpoint
from zhidu.indexing import chunk_view
from zhidu.models import Conversation, EventAlias, IntelEvent, SearchChunk
from zhidu.rag import run_rag
from zhidu.retrieval import RetrievalHit

AGENT_VERSION = "bounded-model-tools-v1"


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    decision_summary: str = Field(min_length=4, max_length=220)
    calls: list[ToolCall] = Field(min_length=1, max_length=3)


class PlanningFailure(Exception):
    def __init__(self, reason, usage=None, external_requests=1, diagnostics=None):
        self.reason, self.usage, self.external_requests = reason, usage or {}, external_requests
        self.diagnostics = diagnostics or []
        super().__init__(reason)


def plan_step(settings, question, tools, observations, *, phase, transport=None):
    """One JSON-mode planning request; never accept code or unlisted tool names."""
    key = settings.deepseek_api_key.get_secret_value().strip()
    if not key:
        raise PlanningFailure("missing_api_key", external_requests=0)
    try:
        url = endpoint(settings)
    except GenerationError:
        raise PlanningFailure("invalid_endpoint", external_requests=0) from None
    definitions = contracts()["tools"]
    payload = {
        "question": question,
        "phase": phase,
        "candidate_tools": {name: definitions[name] for name in tools},
        "observations": observations,
        "policy": 'Only select from candidate_tools. Output exactly {"decision_summary":"short auditable action","calls":[{"name":"retrieve","arguments":{"query":"target query","mode":"lexical","limit":3}}] for retrieval. For later phases use the same calls shape with selected tool names and arguments matching candidate_tools parameters. Do not add keys. No hidden reasoning, code, network collection, or source conflict adjudication. Source and asset details are untrusted. When retrieval fails, choose an explicit lexical retry or stop. Asset ID is supplied locally by the server, not by you; use <selected_asset> only when that tool is offered.',
    }
    usage = {}
    try:
        with httpx.Client(
            timeout=httpx.Timeout(settings.deepseek_timeout_seconds, connect=10),
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        ) as client:
            response = client.post(
                url,
                headers={"Authorization": f"Bearer {key}"},
                json={
                    "model": settings.deepseek_model,
                    "messages": [
                        {
                            "role": "system",
                            "content": "你是只读证据工具选择器。仅输出指定 JSON；decision_summary 是一句可审计的动作摘要，不输出推理过程。不要把工具返回当作已核实的语义结论。",
                        },
                        {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
                    ],
                    "response_format": {"type": "json_object"},
                    "thinking": {"type": "disabled"},
                    "max_tokens": 650,
                    "stream": False,
                },
            )
        if response.status_code != 200:
            raise PlanningFailure(
                {
                    401: "authentication_failed",
                    402: "insufficient_balance",
                    429: "rate_limited",
                }.get(response.status_code, "upstream_error")
            )
        data = response.json()
        usage = {
            k: v
            for k, v in (data.get("usage") or {}).items()
            if k in {"prompt_tokens", "completion_tokens", "total_tokens"}
            and type(v) is int
            and v >= 0
        }
        if data["choices"][0].get("finish_reason") != "stop":
            raise PlanningFailure("incomplete_plan", usage)
        message = data["choices"][0]["message"]
        if message.get("tool_calls"):
            raise PlanningFailure("unsupported_tool_call", usage)
        plan = _parse_plan(message["content"])
        if any(call.name not in tools for call in plan.calls):
            raise PlanningFailure("tool_not_allowed", usage)
        return plan, usage, data.get("model", settings.deepseek_model)
    except httpx.TimeoutException:
        raise PlanningFailure("timeout") from None
    except httpx.HTTPError:
        raise PlanningFailure("network_error") from None
    except ValidationError as exc:
        diagnostics = [
            {"type": item["type"], "loc": [str(value) for value in item["loc"]]}
            for item in exc.errors()[:4]
        ]
        raise PlanningFailure("invalid_plan", usage, diagnostics=diagnostics) from None
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise PlanningFailure(
            "invalid_plan", usage, diagnostics=[{"type": type(exc).__name__}]
        ) from None


def _parse_plan(content):
    """Ignore irrelevant JSON keys while preserving strict tool and argument checks."""
    if not isinstance(content, str):
        raise ValueError("plan content must be text")
    source = content.strip()
    if source.startswith("```json\n") and source.endswith("\n```"):
        source = source[8:-4].strip()
    raw = json.loads(source)
    if isinstance(raw, str):
        raw = json.loads(raw)
    if not isinstance(raw, dict):
        raise ValueError("plan must be object")
    calls = raw.get("calls")
    if isinstance(calls, dict):
        calls = [calls]
    if not isinstance(calls, list):
        raise ValueError("plan calls must be list")
    normalized = []
    for call in calls:
        if not isinstance(call, dict):
            raise ValueError("plan call must be object")
        arguments = call.get("arguments", call.get("args"))
        if isinstance(arguments, str):
            arguments = json.loads(arguments)
        normalized.append({"name": call.get("name", call.get("tool")), "arguments": arguments})
    return Plan.model_validate(
        {"decision_summary": raw.get("decision_summary"), "calls": normalized}
    )


def _summary(session, result):
    """Pass public identifiers and small excerpts to the next planner, never asset details."""
    if result["status"] != "completed":
        return {"status": "failed", "tool": result["tool"], "reason": result["error"]}
    if result["tool"] != "retrieve":
        return {"status": "completed", "tool": result["tool"]}
    items = []
    for row in result["result"]["items"][:5]:
        c = row["citation"]
        aliases = session.scalars(
            select(EventAlias.value).where(EventAlias.event_id == c["event_id"])
        ).all()
        items.append(
            {
                "chunk_id": c["chunk_id"],
                "event_id": c["event_id"],
                "external_id": c["external_id"],
                "cve_ids": [a for a in aliases if re.fullmatch(r"CVE-\d{4}-\d{4,}", a, re.I)][:3],
                "field": c["field"],
                "text_excerpt": row["text"][:200],
            }
        )
    return {"status": "completed", "tool": "retrieve", "items": items}


def _citation_items(session, response):
    if response["status"] != "completed":
        return []
    if response["tool"] == "retrieve":
        candidates = [(item["citation"], item["text"]) for item in response["result"]["items"]]
    elif response["tool"] == "event_details":
        candidates = [(item["citation"], item["text"]) for item in response["result"]["fields"]]
    else:
        return []
    items = []
    for citation, text in candidates:
        event = session.get(IntelEvent, citation["event_id"])
        items.append(
            {**citation, "text": text, "title": event.title, "source_url": event.source_url}
        )
    return items


def _local_two_source_version_answer(question, citations):
    """Render only literal current source fields when a cloud quote is invalid."""
    lower = question.casefold()
    if not any(term in lower for term in ("来源", "source")) or not any(
        term in lower for term in ("版本", "修复", "边界", "version", "patch")
    ):
        return None
    sources = {}
    for index, citation in enumerate(citations, 1):
        source = sources.setdefault(citation["source_id"], {})
        field = citation["field"]
        if field in {"title", "packages"} and field not in source:
            source[field] = (index, citation["text"])
        if field == "description" and "patch_link" not in source:
            match = re.search(
                r"(?:Patches|Fixes|Fix)\s*\n[\s\S]{0,100}?https://github\.com/[^\s)]+/pull/\d+",
                citation["text"],
                re.I,
            )
            if match:
                link = re.search(r"https://github\.com/[^\s)]+/pull/\d+", match.group())
                source["patch_link"] = (index, link.group())
    if len(sources) < 2 or any(
        "title" not in source or "packages" not in source for source in sources.values()
    ):
        return None
    if "依据" in lower and any("patch_link" not in source for source in sources.values()):
        return None
    lines = []
    for source_id, fields in sorted(sources.items()):
        try:
            packages = json.loads(fields["packages"][1])
        except (TypeError, ValueError):
            return None
        if (
            not isinstance(packages, list)
            or len(packages) != 1
            or not isinstance(packages[0], dict)
        ):
            return None
        entry = packages[0]
        vulnerable = entry.get("vulnerable_version_range")
        patched = [
            (name, entry[name])
            for name in ("first_patched_version", "patched_versions")
            if isinstance(entry.get(name), str) and entry[name]
        ]
        if not isinstance(vulnerable, str) or len(patched) != 1:
            return None
        title_index, title = fields["title"]
        package_index, _ = fields["packages"]
        patch_field, patch_value = patched[0]
        lines.append(
            f"{source_id}：标题为“{title}” [{title_index}]；packages 字段给出的受影响范围是“{vulnerable}”，"
            f"{patch_field} 为“{patch_value}” [{package_index}]。"
        )
        if "依据" in lower:
            patch_index, link = fields["patch_link"]
            lines.append(
                f"{source_id} 的描述片段列出修复 PR 链接 {link} [{patch_index}]；"
                "链接存在不等于已独立验证补丁代码。"
            )
    return "\n\n".join(lines)


def _base_result(body):
    return {
        "version": AGENT_VERSION,
        "mode": "agent",
        "answer_class": "refused",
        "answer": "本轮证据不足，不能作出事实结论。",
        "reason": "no_evidence",
        "citations": [],
        "claims": [],
        "constraints": [],
        "hops": [],
        "evidence_tasks": [],
        "asset_id": body.asset_id,
        "tools": [],
        "tool_calls": 0,
        "generation": {"provider": "deepseek", "status": "skipped", "reason": "evidence_not_ready"},
        "generation_model": "extractive-packet-v4",
        "context": {"sources": [], "relations": [], "truncated": False},
        "cost": {
            "external_requests": 0,
            "billed_tokens": 0,
            "api_usd": None,
            "local_compute_usd": None,
        },
        "independent_verification": False,
    }


def run_agent(
    session,
    store,
    settings,
    body,
    encoder,
    *,
    history=None,
    conversation_context=None,
    transport=None,
    clock=time.monotonic,
):
    started = clock()
    result = _base_result(body)
    selected_asset = body.asset_id
    if not selected_asset and body.conversation_id and not body.clear_asset:
        conversation = session.get(Conversation, body.conversation_id)
        selected_asset = conversation.active_asset_id if conversation else None
    result["asset_id"] = selected_asset
    if conversation_context is not None:
        result["conversation_context"] = conversation_context
        result["constraints"].extend(conversation_context.get("notices", []))
    trace = {
        "version": AGENT_VERSION,
        "decisions": [],
        "tool_steps": [],
        "tool_results": [],
        "status": "running",
        "planner_usage": [],
        "private_asset_details_sent_to_model": False,
        "candidate_tools": list(contracts()["tools"]),
        "source_scope": {"pool": body.pool, "origin": body.origin},
    }
    result["agent"] = trace
    explicit_ids = re.findall(
        r"CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}",
        body.query or body.question,
        re.I,
    )
    if explicit_ids:
        wanted = {value.casefold() for value in explicit_ids}
        matches = session.scalars(
            select(IntelEvent).where(IntelEvent.external_id.in_(explicit_ids))
        ).all()
        alias_rows = session.execute(select(EventAlias.event_id, EventAlias.value)).all()
        alias_ids = {event_id for event_id, value in alias_rows if value.casefold() in wanted}
        matches.extend(session.get(IntelEvent, eid) for eid in alias_ids)
        current = {event.id for event in matches if event and event.withdrawn_at is None}
        if not current:
            result.update(
                answer_class="refused",
                reason="explicit_identifier_not_current",
                answer="该明确编号在当前有效来源中无可引用证据；可能不存在或已撤回，不能沿用旧结论。",
            )
            trace["status"] = "refused"
            result["elapsed_ms"] = round((clock() - started) * 1000, 3)
            return result
    if any(
        term in body.question.casefold()
        for term in ("复现", "所有资产都安全", "已验证", "reproduced", "all assets are safe")
    ):
        result.update(
            answer_class="refused",
            reason="unsupported_verification_claim",
            answer="缺少独立复现或全量资产验证证据，不能据来源摘录作出该结论。",
        )
        trace["status"] = "refused"
        result["elapsed_ms"] = round((clock() - started) * 1000, 3)
        return result
    if requires_asset_context(body.question.casefold()) and not selected_asset:
        result.update(
            answer_class="clarification",
            reason="explicit_asset_required",
            answer="请先明确选择资产；没有资产 ID 不能判断该资产是否受影响。",
        )
        trace["status"] = "clarification"
        result["elapsed_ms"] = round((clock() - started) * 1000, 3)
        return result
    runtime = AgentToolRuntime(
        session, store, settings, encoder, pool=body.pool, origin=body.origin
    )
    planned = 0

    def choose(phase, allowed, observations, max_calls):
        nonlocal planned
        current_observations = observations
        for attempt in (1, 2):
            entry = {
                "phase": phase,
                "attempt": attempt,
                "question": body.question,
                "candidate_tools": allowed,
                "selected_tools": [],
                "decision_summary": "",
                "status": "failed",
            }
            trace["decisions"].append(entry)
            try:
                plan, usage, model = plan_step(
                    settings,
                    body.question,
                    allowed,
                    current_observations,
                    phase=phase,
                    transport=transport,
                )
                if len(plan.calls) > max_calls:
                    raise PlanningFailure("too_many_calls", usage)
                if any(call.name not in allowed for call in plan.calls):
                    raise PlanningFailure("tool_not_allowed", usage)
                planned += 1
                trace["planner_usage"].append(usage)
                entry.update(
                    status="completed",
                    selected_tools=[c.name for c in plan.calls],
                    decision_summary=plan.decision_summary,
                    returned_model=model,
                )
                return plan.calls
            except PlanningFailure as exc:
                planned += exc.external_requests
                if exc.usage:
                    trace["planner_usage"].append(exc.usage)
                entry.update(
                    error=exc.reason, decision_summary="规划失败，未接受未经核验的工具选择。"
                )
                if exc.diagnostics:
                    entry["diagnostics"] = exc.diagnostics
                if attempt == 1 and exc.reason in {
                    "invalid_plan",
                    "tool_not_allowed",
                    "too_many_calls",
                }:
                    current_observations = {
                        "original": observations,
                        "correction": "Previous format or selected tool was rejected. Choose only an offered tool; use exactly decision_summary and calls with schema-valid arguments.",
                        "rejection_code": exc.reason,
                        "permitted_tools": allowed,
                    }
                    continue
                return None
        return None

    def execute(call):
        arguments = dict(call.arguments)
        if call.name == "retrieve":
            if body.event_id:
                arguments["event_id"] = body.event_id
            if body.query and re.search(r"CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]{14,}", body.query, re.I):
                arguments["query"] = body.query
        if call.name == "asset_exposure":
            if not selected_asset or arguments.get("asset_id") != "<selected_asset>":
                arguments["asset_id"] = ""  # Runtime returns invalid_arguments.
            else:
                arguments["asset_id"] = selected_asset
        response = runtime.execute(call.name, arguments)
        trace["tool_steps"] = list(runtime.steps)
        trace["tool_results"].append(response)
        return response

    query = body.query or body.question
    first = choose(
        "target_retrieval",
        ["retrieve"],
        {
            "target_query": query,
            "mode": "lexical" if body.mode == "lexical" else "hybrid",
            "event_id": body.event_id,
            "scope_fixed_by_server": trace["source_scope"],
        },
        1,
    )
    if not first:
        return _fallback(
            session,
            store,
            settings,
            body,
            encoder,
            history,
            conversation_context,
            result,
            trace,
            planned,
            started,
            trace["decisions"][-1].get("error", "planner_failed"),
            clock,
        )
    response = execute(first[0])
    observations = [_summary(session, response)]
    if response["status"] != "completed" and response.get("error") == "model_unavailable":
        recovery = choose(
            "lexical_recovery",
            ["retrieve"],
            {
                "failure": observations[-1],
                "required_mode": "lexical",
                "target_query": query,
                "event_id": body.event_id,
            },
            1,
        )
        if recovery:
            recovery[0].arguments["mode"] = "lexical"
            response = execute(recovery[0])
            observations.append(_summary(session, response))
    if response["status"] != "completed":
        return _fallback(
            session,
            store,
            settings,
            body,
            encoder,
            history,
            conversation_context,
            result,
            trace,
            planned,
            started,
            response.get("error", "retrieve_failed"),
            clock,
        )
    retrieved_event_order = list(
        dict.fromkeys(i["citation"]["event_id"] for i in response["result"]["items"])
    )
    retrieved_events = set(retrieved_event_order)
    retrieved_chunks = {i["citation"]["chunk_id"] for i in response["result"]["items"]}
    allowed_cves = {
        alias.upper()
        for eid in retrieved_events
        for alias in session.scalars(select(EventAlias.value).where(EventAlias.event_id == eid))
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", alias, re.I)
    }
    candidates = ["event_details", "verify_evidence"] if retrieved_events else []
    if allowed_cves and any(
        term in body.question.casefold()
        for term in ("来源", "冲突", "不同", "比较", "source", "conflict", "compare", "difference")
    ):
        candidates.append("compare_sources")
    if len(response["result"]["items"]) < 2:
        candidates.append("retrieve")
    if selected_asset and requires_asset_context(body.question.casefold()):
        candidates.append("asset_exposure")
    analysis = choose(
        "evidence_analysis",
        candidates,
        {
            "retrieval": observations[-1],
            "selected_asset_available": bool(selected_asset),
            "asset_id_placeholder": "<selected_asset>" if selected_asset else None,
            "explicit_event_id": body.event_id,
        },
        3,
    )
    if analysis is None:
        return _fallback(
            session,
            store,
            settings,
            body,
            encoder,
            history,
            conversation_context,
            result,
            trace,
            planned,
            started,
            trace["decisions"][-1].get("error", "planner_failed"),
            clock,
        )
    responses = [response]
    supplementary_retrievals = 0
    for call in analysis:
        if call.name == "retrieve":
            supplementary_retrievals += 1
            if supplementary_retrievals > 1:
                rejected = dict(call.arguments)
                rejected["query"] = ""
                response = runtime.execute("retrieve", rejected)
                trace["tool_steps"] = list(runtime.steps)
                trace["tool_results"].append(response)
                trace.setdefault("policy_rejections", []).append(
                    {"tool": "retrieve", "reason": "supplement_limit_exceeded"}
                )
                responses.append(response)
                continue
        if (
            (
                call.name in {"event_details", "asset_exposure"}
                and call.arguments.get("event_id") not in retrieved_events
            )
            or (
                call.name == "compare_sources"
                and call.arguments.get("identifier", "").upper() not in allowed_cves
            )
            or (
                call.name == "verify_evidence"
                and call.arguments.get("chunk_id") not in retrieved_chunks
            )
        ):
            rejected = dict(call.arguments)
            rejected[
                {
                    "event_details": "event_id",
                    "asset_exposure": "event_id",
                    "compare_sources": "identifier",
                    "verify_evidence": "chunk_id",
                }[call.name]
            ] = ""
            response = runtime.execute(call.name, rejected)
            trace["tool_steps"] = list(runtime.steps)
            trace["tool_results"].append(response)
            trace.setdefault("policy_rejections", []).append(
                {"tool": call.name, "reason": "target_not_in_current_retrieval"}
            )
            responses.append(response)
            continue
        responses.append(execute(call))
    detailed = {
        item["result"]["event_id"]
        for item in responses
        if item["status"] == "completed" and item["tool"] == "event_details"
    }
    for event_id in retrieved_event_order[:2]:
        if event_id in detailed:
            continue
        if len(runtime.steps) >= runtime.max_calls:
            break
        trace.setdefault("policy_steps", []).append(
            {
                "tool": "event_details",
                "event_id": event_id,
                "reason": "current_source_text_required_before_generation",
                "model_selected": False,
            }
        )
        responses.append(runtime.execute("event_details", {"event_id": event_id}))
        trace["tool_steps"] = list(runtime.steps)
        trace["tool_results"].append(responses[-1])
        if responses[-1]["status"] == "completed":
            detailed.add(event_id)
    citations = {}
    for tool_result in responses:
        for citation in _citation_items(session, tool_result):
            citations[citation["chunk_id"]] = citation
        if tool_result["status"] == "completed" and tool_result["tool"] == "compare_sources":
            rows = tool_result["result"].get("items", [])
            if rows:
                result["constraints"].append(
                    {
                        "code": "source_comparison_unresolved",
                        "rule": "本轮跨来源字段观察："
                        + ", ".join(f"{r['field']}={r['status']}" for r in rows[:5])
                        + "。仅说明来源差异，不自动裁决。",
                    }
                )
        if tool_result["status"] == "completed" and tool_result["tool"] == "asset_exposure":
            result["constraints"].append(
                {
                    "code": "private_asset_local_only",
                    "rule": "资产条件仅在本地工具结果中查看；不向生成模型发送资产详情，匹配不代表漏洞复现。",
                }
            )
    result["citations"] = list(citations.values())[:24]
    result["context"] = {
        "sources": sorted({c["source_id"] for c in result["citations"]}),
        "relations": [],
        "citations": len(result["citations"]),
        "truncated": len(citations) > 24 or len(retrieved_event_order) > len(detailed),
        "note": "Only verified current excerpts, not complete documents.",
    }
    if len(retrieved_event_order) > len(detailed):
        result["constraints"].append(
            {
                "code": "source_detail_budget_limited",
                "rule": "至少一份当前来源详情未能在工具预算内获取，不能声称已完整比较全部来源。",
            }
        )
    if not result["citations"]:
        trace["status"] = "refused"
        result["reason"] = "no_verified_evidence"
        return _finish(result, runtime, trace, planned, started, clock)
    checked = []
    for citation in result["citations"]:
        row = session.get(SearchChunk, citation["chunk_id"])
        try:
            ok = bool(
                row
                and verify_hit(
                    session,
                    store,
                    RetrievalHit(**chunk_view(row).model_dump(), score=0, matched_terms=[]),
                )
            )
        except (OSError, ValueError):
            ok = False
        checked.append(ok)
    trace["final_citation_check"] = {
        "verified": sum(checked),
        "total": len(checked),
        "semantic_support_verified": False,
    }
    if not all(checked):
        result.update(
            answer_class="refused",
            reason="evidence_invalid",
            answer="本轮原文复验失败，不能引用作答。",
            citations=[],
        )
        trace["status"] = "refused"
        return _finish(result, runtime, trace, planned, started, clock)
    result["answer_class"] = (
        "partial" if any(r["status"] != "completed" for r in responses) else "evidence"
    )
    result["reason"] = "agent_verified_excerpts"
    result["claims"] = [
        {"citation_index": i, "quote": c["text"][:360]} for i, c in enumerate(result["citations"])
    ]
    result["answer"] = "以下是本轮已复验的来源片段：\n" + "\n".join(
        f"[{i + 1}] {c['external_id']}：{c['text'][:360]}"
        for i, c in enumerate(result["citations"])
    )
    if result["answer_class"] == "partial":
        result["answer"] += "\n部分工具失败，结论仍有缺口。"
    result["tools"] = list(runtime.steps)
    apply_generation(settings, body.question, result, history=history, transport=transport)
    if result["generation"]["status"] == "fallback" and result["generation"].get("reason") in {
        "invalid_citation",
        "invalid_response",
    }:
        local_answer = _local_two_source_version_answer(body.question, result["citations"])
        if local_answer is not None:
            result["extractive_answer"] = result["answer"]
            result["answer"] = local_answer
            result["answer_class"] = "evidence"
            result["reason"] = "verified_source_fields_local_fallback"
            result["generation"]["local_fallback"] = "two_source_version_fields_v1"
            trace["local_fallback"] = "two_source_version_fields_v1"
    trace["status"] = "completed" if result["generation"]["status"] == "completed" else "fallback"
    return _finish(result, runtime, trace, planned, started, clock)


def _finish(result, runtime, trace, planned, started, clock):
    trace["tool_steps"] = list(runtime.steps)
    result["tools"] = list(result["tools"] or runtime.steps)
    result["tool_calls"] = len(runtime.steps)
    result["cost"]["external_requests"] = planned + (
        1 if result["generation"].get("input_sha256") else 0
    )
    planner_tokens = sum(u.get("total_tokens", 0) for u in trace["planner_usage"])
    result["cost"]["billed_tokens"] = planner_tokens + (
        result["generation"].get("usage", {}).get("total_tokens") or 0
    )
    result["elapsed_ms"] = round((clock() - started) * 1000, 3)
    return result


def _fallback(
    session,
    store,
    settings,
    body,
    encoder,
    history,
    context,
    result,
    trace,
    planned,
    started,
    reason,
    clock,
):
    fallback = run_rag(
        session,
        store,
        settings,
        body.model_copy(update={"generation": "extractive", "mode": "lexical"}),
        encoder,
        history=history,
        conversation_context=context,
    )
    trace.update(status="fallback", reason=reason, fallback="local_lexical_extractive")
    fallback["agent"] = trace
    fallback["mode"] = "agent"
    fallback["answer"] = "Agent 工具规划或检索未完成，以下仅为本地词项摘录：\n" + fallback["answer"]
    fallback["generation"] = {
        "provider": "deepseek",
        "status": "fallback",
        "reason": reason,
        "semantic_support_verified": False,
    }
    fallback["cost"]["external_requests"] = planned
    fallback["cost"]["billed_tokens"] = sum(
        u.get("total_tokens", 0) for u in trace["planner_usage"]
    )
    fallback["cost"]["api_usd"] = None
    fallback["elapsed_ms"] = round((clock() - started) * 1000, 3)
    fallback["timing_scope"] = "agent_planning_tools_and_local_fallback"
    return fallback
