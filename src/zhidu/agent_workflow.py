"""Prepare evidence without a model; route only on visible source coverage.

The coverage gate is deliberately conservative. It records which requested
fields were actually returned, and whether their source intervals are complete;
it neither scores an answer nor infers that an entire source lacks information.
Preparation and a subsequent LangChain loop share one ToolSession and budget.
"""

import time

from zhidu.agent_rag import _base_result
from zhidu.langchain_agent import _preflight, run_langchain_agent
from zhidu.langchain_tools import SourceRuntime, ToolSession
from zhidu.models import Conversation

VERSION = "prepared-source-workflow-v1"


def _selected_asset(session, body):
    if body.asset_id or not body.conversation_id or body.clear_asset:
        return body.asset_id
    conversation = session.get(Conversation, body.conversation_id)
    return conversation.active_asset_id if conversation else None


def _requirements(question, *, event_scoped=False):
    question = question.casefold()
    version = any(
        term in question
        for term in (
            "受影响版本",
            "影响哪些版本",
            "受影响范围",
            "原始范围",
            "版本范围",
            "版本字段",
            "修复版本",
            "修复字段",
            "补丁字段",
            "补丁版本",
            "首次修复",
            "affected version",
            "vulnerable version",
            "patched version",
            "version range",
            "first patched",
        )
    )
    remediation = any(
        term in question
        for term in (
            "如何修复",
            "修复建议",
            "修复措施",
            "修复实现",
            "补丁实现",
            "补丁正文",
            "覆盖",
            "patches",
            "remediation",
            "mitigation",
            "patch implementation",
            "patch cover",
        )
    )
    references = any(
        term in question
        for term in (
            "参考链接",
            "参考文献",
            "引用链接",
            "reference",
            "来源链接",
        )
    )
    scores = any(term in question for term in ("cvss", "评分", "score"))
    # A request limited to structured versions does not also demand a narrative.
    detail_terms = (
        "触发",
        "条件",
        "危害",
        "能力",
        "根因",
        "认证",
        "是否",
        "争议",
        "路径",
        "默认",
        "影响行为",
        "代码执行",
        "风险",
        "说明",
        "机制",
        "描述",
        "执行",
        "影响及",
        "边界",
        "为何",
        "为什么",
        "授权",
        "impact",
        "condition",
        "authentication",
        "default",
        "execution",
        "cause",
        "dispute",
        "mechanism",
    )
    description = (
        remediation
        or any(term in question for term in detail_terms)
        or not (version or references or scores)
    )
    fields = []
    if version:
        fields.append("packages")
    if description:
        fields.append("description")
    if references:
        fields.append("references")
    if scores:
        fields.append("cvss")
    sources = []
    if "github" in question or "github 公告" in question:
        sources.append("github-advisories")
    if "nvd" in question:
        sources.append("nvd")
    cross_source = any(
        term in question
        for term in (
            "跨文档",
            "跨来源",
            "多个来源",
            "比较来源",
            "对照",
            "交叉",
            "cross-document",
            "cross-source",
        )
    )
    return {
        "fields": fields,
        "source_ids": sources,
        "minimum_events": 1 if event_scoped else max(len(sources), 2 if cross_source else 1),
        "remediation": remediation,
    }


def _field_complete(citations):
    """Check only source intervals already returned by the bounded tools."""
    if not citations:
        return False
    grouped = {}
    for citation in citations:
        provenance = citation.get("span_provenance", {})
        length = provenance.get("source_field_chars")
        if provenance.get("boundary_complete") is False:
            return False
        # Old bounded excerpts have no full-field length and cannot prove coverage.
        if type(length) is not int or length <= 0:
            continue
        key = (citation.get("raw_document_id"), citation.get("json_pointer"), length)
        grouped.setdefault(key, []).append((citation.get("start", -1), citation.get("end", -1)))
    if not grouped:
        return False
    for (_, _, length), intervals in grouped.items():
        reached = 0
        for start, end in sorted(intervals):
            if start > reached:
                break
            reached = max(reached, end)
        if reached < length:
            return False
    return True


def assess_coverage(tools, requirements):
    """Return auditable retrieval gaps, never semantic or whole-source findings."""
    by_event = {}
    for citation in tools.evidence.values():
        by_event.setdefault(citation["event_id"], []).append(citation)
    sources = {c.get("source_id") for c in tools.evidence.values()}
    gaps = []
    if not by_event:
        gaps.append({"code": "no_returned_evidence"})
    elif len(by_event) < requirements["minimum_events"]:
        gaps.append(
            {
                "code": "requested_source_count_not_returned",
                "required": requirements["minimum_events"],
            }
        )
    for source_id in requirements["source_ids"]:
        if source_id not in sources:
            gaps.append({"code": "requested_source_not_returned", "source_id": source_id})
    observed = []
    for event_id, citations in sorted(by_event.items()):
        fields = sorted({c["field"] for c in citations})
        observed.append(
            {"event_id": event_id, "source_id": citations[0].get("source_id"), "fields": fields}
        )
        for field in requirements["fields"]:
            candidates = [c for c in citations if c["field"] == field]
            if field == "packages" and citations[0].get("source_id") == "nvd":
                candidates = [
                    c
                    for c in citations
                    if c["field"].startswith("nvd_affected_data_") and "_version_" in c["field"]
                ]
            elif field == "cvss":
                candidates = [c for c in citations if c["field"].startswith("cvss")]
            if not candidates:
                gaps.append(
                    {"code": "requested_field_not_returned", "event_id": event_id, "field": field}
                )
            elif not _field_complete(candidates):
                gaps.append(
                    {
                        "code": "requested_field_coverage_incomplete",
                        "event_id": event_id,
                        "field": field,
                    }
                )
    return {
        "policy": "requested_fields_and_returned_source_intervals_only",
        "semantic_support_verified": False,
        "source_absence_inferred": False,
        "required_fields": requirements["fields"],
        "required_source_ids": requirements["source_ids"],
        "observed_fields": observed,
        "gaps": gaps,
        "gap_descriptions": [
            {
                "no_returned_evidence": "本轮工具没有返回可引用证据。",
                "requested_source_count_not_returned": "本轮返回的来源数量尚未覆盖问题要求。",
                "requested_source_not_returned": "本轮尚未返回问题指定的来源。",
                "requested_field_not_returned": "本轮尚未返回问题需要的字段。",
                "requested_field_coverage_incomplete": "问题需要的字段目前只有部分可引用片段。",
            }[gap["code"]]
            + (
                f"（{gap.get('source_id') or gap.get('field')}）"
                if gap.get("source_id") or gap.get("field")
                else ""
            )
            for gap in gaps
        ],
    }


def _prepare(tools, requirements, *, backend):
    tools.invoke(
        "retrieve",
        {"query": (tools.body.query or tools.body.question)[:200], "mode": "lexical", "limit": 3},
    )
    # Three source reads plus retrieval leave two of the six tool calls for
    # adaptive completion. A failure still consumes the same shared budget.
    event_ids = list(dict.fromkeys(c["event_id"] for c in tools.evidence.values()))[:3]
    for event_id in event_ids:
        if (
            tools.attempted_calls >= min(4, tools.runtime.max_calls)
            or tools.runtime.remaining() <= 0
        ):
            break
        fields = list(requirements["fields"])
        observed_version_fields = sorted(
            {
                c["field"]
                for c in tools.evidence.values()
                if c["event_id"] == event_id
                and c["field"].startswith("nvd_affected_data_")
                and "_version_" in c["field"]
            }
        )
        if observed_version_fields and "packages" in fields:
            fields.remove("packages")
            fields = (observed_version_fields + fields)[:4]
        if "cvss" in fields:
            fields.remove("cvss")
            # CVSS is a logical requirement, not an invented index field. The
            # current index may not expose score fields at all; only query the
            # actual names already observed in this request.
            fields += sorted(
                {
                    c["field"]
                    for c in tools.evidence.values()
                    if c["event_id"] == event_id and c["field"].startswith("cvss")
                }
            )
        if not fields:
            continue
        tools.invoke("read_fields", {"event_id": event_id, "fields": fields[:4], "limit": 3})
    # Explicit repair prose uses the same fixed late-section lookup as the
    # benchmark workflow. Auto leaves these calls to the evidence-gap planner.
    if backend == "workflow" and requirements["remediation"]:
        for event_id in event_ids[:2]:
            if tools.attempted_calls >= tools.runtime.max_calls or tools.runtime.remaining() <= 0:
                break
            descriptions = [
                c
                for c in tools.evidence.values()
                if c["event_id"] == event_id and c["field"] == "description"
            ]
            if not _field_complete(descriptions):
                tools.invoke(
                    "read_fields",
                    {
                        "event_id": event_id,
                        "fields": ["description"],
                        "contains": "Patches",
                        "limit": 1,
                    },
                )


def run_workflow_agent(
    session, store, settings, body, encoder, *, backend=None, clock=time.monotonic, **kwargs
):
    backend = backend or body.agent_backend or settings.agent_backend
    if backend not in {"workflow", "auto"}:
        raise ValueError("workflow backend must be workflow or auto")
    selected_asset = _selected_asset(session, body)
    if _preflight(session, body, selected_asset):
        result = run_langchain_agent(session, store, settings, body, encoder, clock=clock, **kwargs)
        result["agent_backend"] = backend
        result["agent"]["backend"] = (
            "fixed_source_workflow" if backend == "workflow" else "auto_preflight"
        )
        result["routing"] = {
            "version": VERSION,
            "chosen_backend": "preflight",
            "gaps": [],
            "gap_descriptions": [],
            "observed_fields": [],
            "model_planning": False,
        }
        result["context"].setdefault("citations", 0)
        return result
    runtime = SourceRuntime(
        session,
        store,
        settings,
        encoder,
        pool=body.pool,
        origin=body.origin,
        max_calls=settings.agent_max_tool_calls,
        clock=clock,
    )
    runtime.deadline_seconds = settings.agent_deadline_seconds
    tools = ToolSession(runtime, body, selected_asset)
    requirements = _requirements(body.question, event_scoped=bool(body.event_id))
    _prepare(tools, requirements, backend=backend)
    routing = assess_coverage(tools, requirements)
    route = "langchain" if backend == "auto" and routing["gaps"] else "workflow"
    routing.update(
        version=VERSION,
        chosen_backend=route,
        model_planning=route == "langchain",
        prepared_tool_calls=tools.attempted_calls,
        remaining_tool_calls=max(0, runtime.max_calls - tools.attempted_calls),
    )
    if not tools.evidence:
        result = _base_result(body)
        result.update(
            version=VERSION,
            asset_id=selected_asset,
            tools=list(runtime.steps),
            tool_calls=tools.attempted_calls,
            elapsed_ms=round((clock() - runtime.start) * 1000, 3),
        )
        result["agent"] = {
            "version": VERSION,
            "backend": "fixed_source_workflow",
            "status": "refused",
            "tool_steps": list(runtime.steps),
            "tool_results": tools.results,
            "policy_rejections": tools.rejections,
            "model_calls": [],
            "planner_usage": [],
            "decisions": [],
            "attempted_tool_calls": tools.attempted_calls,
            "private_asset_details_sent_to_model": False,
            "limits": {
                "model_calls": settings.agent_max_model_calls,
                "tool_calls": runtime.max_calls,
                "tool_output_chars": runtime.max_output_chars,
                "soft_deadline_seconds": settings.agent_deadline_seconds,
            },
        }
        result["context"]["citations"] = 0
        context = kwargs.get("conversation_context")
        if context is not None:
            result["conversation_context"] = context
            result["constraints"].extend(context.get("notices", []))
        routing.update(chosen_backend="no_evidence", model_planning=False)
    else:
        tools.constraints.append(
            {
                "code": "prepared_coverage_scope",
                "rule": "准备阶段只检查本轮返回片段的字段覆盖，不表示完整来源缺失。只在引用不能支持用户必答事实时列出 missing_facts；不得推断资料不存在。",
            }
        )
        result = run_langchain_agent(
            session,
            store,
            settings,
            body,
            encoder,
            prepared_tools=tools,
            final_only=route == "workflow",
            clock=clock,
            **kwargs,
        )
        result["agent"]["backend"] = (
            "fixed_source_workflow" if route == "workflow" else "auto_langchain"
        )
    result["agent_backend"] = backend
    result["routing"] = routing
    return result
