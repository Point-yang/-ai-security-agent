"""Budgeted evidence tools with optional, separately audited cloud generation."""

import json
import re
import time
from types import SimpleNamespace
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select

from zhidu.answers import (
    asset_constraints,
    asset_context_snapshot,
    citation_snapshot,
    requires_asset_context,
)
from zhidu.conversations import EXPLICIT_SWITCH_TERMS, build_hops, derive_evidence_tasks
from zhidu.evaluation import verify_hit
from zhidu.indexing import chunk_view
from zhidu.models import Asset, Conversation, EventAlias, IntelEvent, RagRun, SearchChunk
from zhidu.retrieval import RetrievalHit
from zhidu.semantic import ModelUnavailable, digest, retrieve


class RouterConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = "bounded-rag-v1"
    max_tools: int = Field(default=6, ge=1, le=10)
    timeout_ms: int = Field(default=15000, ge=1, le=60000)
    candidate_limit: int = Field(default=40, ge=1, le=100)
    semantic_min_score: float = Field(default=0.35, ge=0, le=1)
    supplement: bool = True
    trace: bool = True
    query_rewrite: bool = False
    relevance_gate: bool = False


class RagRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=1000)
    query: str | None = Field(default=None, min_length=1, max_length=200)
    mode: Literal["lexical", "hybrid", "agentic"] = "agentic"
    pool: Literal["formal", "candidate"] = "formal"
    origin: Literal["live", "replay"] = "live"
    event_id: str | None = Field(default=None, max_length=36)
    asset_id: str | None = Field(default=None, max_length=36)
    conversation_id: str | None = Field(default=None, max_length=36)
    request_id: str | None = Field(
        default=None, min_length=8, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$"
    )
    clear_asset: bool = False
    top_k: int = Field(default=5, ge=1, le=10)
    generation: Literal["configured", "extractive", "deepseek", "model", "agent"] = "configured"
    agent_backend: Literal["legacy", "langchain", "workflow", "auto", "team"] | None = None
    context_mode: Literal["expanded", "baseline"] = "expanded"

    @field_validator("question", "query")
    @classmethod
    def not_blank(cls, value):
        if value is not None and not value.strip():
            raise ValueError("text must not be blank")
        return value.strip() if value else value


class BudgetExceeded(RuntimeError):
    pass


class ToolBudget:
    def __init__(self, config, clock=time.monotonic):
        self.config, self.clock = config, clock
        self.start = clock()
        self.steps = []

    def remaining(self):
        return max(0, self.config.timeout_ms / 1000 - (self.clock() - self.start))

    def call(self, name, inputs, fn):
        if len(self.steps) >= self.config.max_tools:
            raise BudgetExceeded("tool_budget_exceeded")
        if self.remaining() <= 0:
            raise TimeoutError("deadline_exceeded")
        step = {"tool": name, "input": inputs, "status": "running"}
        self.steps.append(step)
        start = self.clock()
        try:
            result = fn()
            if self.remaining() <= 0:
                raise TimeoutError("deadline_exceeded")
            step["status"] = "completed"
            return result
        except Exception as exc:
            step["status"] = "failed"
            step["error"] = type(exc).__name__
            raise
        finally:
            step["elapsed_ms"] = round((self.clock() - start) * 1000, 3)


def _select(hits, top_k):
    selected, seen = [], set()
    for hit in hits:
        if hit.citation.event_id not in seen:
            seen.add(hit.citation.event_id)
            selected.append(hit)
            if len(selected) == top_k:
                break
    return selected


def run_rag(
    session,
    store,
    settings,
    request,
    encoder,
    config=None,
    *,
    clock=time.monotonic,
    history=None,
    conversation_context=None,
):
    from zhidu.generation import apply_generation

    started = clock()
    result = _run_evidence(session, store, settings, request, encoder, config, clock=clock)
    if conversation_context is not None:
        result["conversation_context"] = conversation_context
        result["constraints"].extend(conversation_context.get("notices", []))
        if any(w in request.question.casefold() for w in ("修复", "补丁", "fix", "patch")):
            sources = result.get("context", {}).get("sources", [])
            needs_version = any(
                w in request.question.casefold()
                for w in ("修复版本", "补丁版本", "first patched", "patched version")
            )
            if sources and not any(
                s["has_structured_patch_field"]
                or (needs_version and s.get("has_nvd_unaffected_version_status"))
                or (not needs_version and s["has_remediation_text_candidate"])
                for s in sources
            ):
                result.update(
                    answer_class="partial",
                    reason="repair_information_missing",
                    answer="本轮当前来源中没有可引用的修复信息，无法确认首次修复版本。请补充来源，不能从模型先验推断版本。",
                )
                result["constraints"].append(
                    {
                        "code": "repair_information_missing",
                        "rule": "未找到修复资料不表示不存在修复。",
                    }
                )
            elif needs_version and not any(s["has_structured_patch_field"] for s in sources):
                result["constraints"].append(
                    {
                        "code": "nvd_status_not_first_patched_version",
                        "rule": "NVD affectedData 可以声明某些版本为 affected/unaffected，但状态范围不自动等同于来源明确公布的首次修复版本；必须保留 versionType、边界和状态，不能声称独立确认了修复版本。",
                    }
                )
    provider = settings.llm_provider if request.generation == "configured" else request.generation
    result["generation"] = {"provider": provider, "status": "disabled"}
    if provider in {"deepseek", "model"}:
        if (
            result["answer_class"] in {"evidence", "partial"}
            and result["citations"]
            and result["reason"] != "repair_information_missing"
        ):
            if provider == "model":
                from zhidu.model_provider import model_profile

                apply_generation(
                    settings,
                    request.question,
                    result,
                    history=history,
                    profile=model_profile(settings),
                    session=session,
                    store=store,
                )
            elif history is None:
                apply_generation(settings, request.question, result, session=session, store=store)
            else:
                apply_generation(
                    settings,
                    request.question,
                    result,
                    history=history,
                    session=session,
                    store=store,
                )
        else:
            result["generation"].update(status="skipped", reason="evidence_not_ready")
    result["elapsed_ms"] = round((clock() - started) * 1000, 3)
    result["tool_calls"] = len(result["tools"])
    return result


def _run_evidence(session, store, settings, request, encoder, config=None, *, clock=time.monotonic):
    config = config or RouterConfig.model_validate_json(settings.rag_config.read_text())
    budget = ToolBudget(config, clock)
    query = request.query or request.question
    result = {
        "version": config.version,
        "router_sha256": digest(config.model_dump()),
        "mode": request.mode,
        "answer_class": "refused",
        "answer": "证据不足，不能作出事实结论。",
        "citations": [],
        "claims": [],
        "constraints": [],
        "hops": [],
        "evidence_tasks": [],
        "asset_id": request.asset_id,
        "tools": budget.steps,
        "retrieval": {},
        "generation_model": "extractive-packet-v4",
        "streaming": False,
        "ttft_ms": None,
        "cache": "no_answer_or_query_cache; reusable_model_process",
        "cost": {
            "external_requests": 0,
            "billed_tokens": 0,
            "api_usd": 0,
            "local_compute_usd": None,
        },
        "independent_verification": False,
    }
    asset_id = request.asset_id
    if asset_id and session.get(Asset, asset_id) is None:
        raise LookupError("asset not found")
    if request.event_id and session.get(IntelEvent, request.event_id) is None:
        raise LookupError("event not found")
    if request.conversation_id:
        conversation = session.get(Conversation, request.conversation_id)
        if conversation is None:
            raise LookupError("conversation not found")
        if not request.clear_asset:
            asset_id = asset_id or conversation.active_asset_id
    question = request.question.casefold()
    implicit_switch = (
        any(term in question for term in EXPLICIT_SWITCH_TERMS) and not request.asset_id
    )
    unsupported = any(
        term in question
        for term in ("复现", "所有资产都安全", "已验证", "reproduced", "all assets are safe")
    )
    context_missing = not asset_id and requires_asset_context(question)
    result["asset_id"] = asset_id
    result["context_policy"] = {
        "explicit_asset_id": request.asset_id,
        "conversation_id": request.conversation_id,
        "natural_language_asset_guessing": False,
    }
    try:
        if implicit_switch or unsupported or context_missing:
            result["reason"] = (
                "explicit_asset_required"
                if implicit_switch or context_missing
                else "unsupported_verification_claim"
            )
            result["answer"] = "缺少显式资产或独立验证证据，不能据此作答。"
            return result
        search_mode = "hybrid" if request.mode == "agentic" else request.mode

        def search(text):
            return retrieve(
                session,
                text,
                search_mode,
                settings,
                encoder,
                pool=request.pool,
                origin=request.origin,
                event_id=request.event_id,
                limit=config.candidate_limit,
                min_score=config.semantic_min_score,
                timeout=budget.remaining(),
                query_rewrite=config.query_rewrite,
                relevance_gate=config.relevance_gate,
            )

        hits, meta = budget.call(
            "retrieve", {"query": query, "mode": search_mode}, lambda: search(query)
        )
        result["retrieval"] = meta
        # An explicit identifier is a constraint, not just a token that may occur in another story.
        identifiers = re.findall(
            r"CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", query, re.I
        )
        allowed = None
        if identifiers:
            canonical = {x.casefold() for x in identifiers}
            allowed = {
                e.id
                for e in session.scalars(select(IntelEvent))
                if e.external_id.casefold() in canonical
            }
            allowed.update(
                eid
                for eid, alias in session.execute(select(EventAlias.event_id, EventAlias.value))
                if alias.casefold() in canonical
            )
            hits = [hit for hit in hits if hit.citation.event_id in allowed]
        selected = _select(hits, request.top_k)
        budget.steps[-1]["output"] = {"chunk_ids": [h.chunk_id for h in selected]}
        if not selected:
            result["reason"] = "no_evidence"
            return result

        def snapshots():
            citations, constraints = [], {}
            for rank, hit in enumerate(selected, 1):
                snapshot, rules = citation_snapshot(
                    session, session.get(SearchChunk, hit.chunk_id), hit.score, rank
                )
                citations.append(snapshot)
                constraints.update((r["code"], r) for r in rules)
            return citations, list(constraints.values())

        citations, constraints = snapshots()
        gaps = {flag for c in citations for flag in c.get("quality_flags", [])}
        if request.mode == "agentic" and config.supplement:
            # Bounded source lookup branch triggered by a gap or an explicit cross-source question.
            branch = bool(gaps) or any(
                s in question for s in ("冲突", "来源", "conflict", "source")
            )
            if branch:
                supplements, _ = budget.call(
                    "supplement",
                    {"external_id": selected[0].external_id},
                    lambda: search(selected[0].external_id),
                )
                if allowed is not None:
                    supplements = [h for h in supplements if h.citation.event_id in allowed]
                selected = _select(selected + supplements, request.top_k)
                citations, constraints = snapshots()
                budget.steps[-1]["output"] = {
                    "chunk_ids": [h.chunk_id for h in selected],
                    "network_collection": False,
                }

        if request.context_mode == "expanded":
            from zhidu.rag_context import expand_evidence_context

            selected, context = budget.call(
                "source_context",
                {"event_ids": [h.citation.event_id for h in selected]},
                lambda: expand_evidence_context(
                    session,
                    selected,
                    request.question,
                    pool=request.pool,
                    origin=request.origin,
                    event_id=request.event_id,
                ),
            )
            result["context"] = context
            budget.steps[-1]["output"] = context
            if not selected:
                result.update(reason="stale_context", answer="来源版本已失效，请重新检索当前资料。")
                return result
            citations, constraints = snapshots()
        elif any(h.field in {"external_id", "cve_id"} for h in selected):

            def expand_context():
                expanded = []
                for hit in selected:
                    if hit.field not in {"external_id", "cve_id"}:
                        expanded.append(hit)
                        continue
                    row = session.scalar(
                        select(SearchChunk)
                        .where(
                            SearchChunk.event_id == hit.citation.event_id,
                            SearchChunk.revision_id == hit.citation.revision_id,
                            SearchChunk.pool == request.pool,
                            SearchChunk.origin == request.origin,
                            SearchChunk.field == "description",
                        )
                        .order_by(SearchChunk.start, SearchChunk.id)
                    )
                    expanded.append(
                        RetrievalHit(
                            **chunk_view(row).model_dump(),
                            score=hit.score,
                            matched_terms=hit.matched_terms,
                        )
                        if row
                        else hit
                    )
                return expanded

            selected = budget.call(
                "source_context",
                {"event_ids": [h.citation.event_id for h in selected]},
                expand_context,
            )
            budget.steps[-1]["output"] = {"chunk_ids": [h.chunk_id for h in selected]}
            citations, constraints = snapshots()

        verified = budget.call(
            "citation_check",
            {"chunk_ids": [h.chunk_id for h in selected]},
            lambda: [verify_hit(session, store, h) for h in selected],
        )
        budget.steps[-1]["output"] = {"verified": sum(verified), "total": len(verified)}
        if not all(verified):
            result["reason"] = "evidence_missing"
            result["answer"] = "原文证据缺失或完整性校验失败，不能引用作答。"
            return result
        result["constraints"] = constraints
        if asset_id:
            context = asset_context_snapshot(
                session, asset_id, {h.citation.event_id for h in selected}
            )
            result["asset_context"] = context
            result["constraints"] += asset_constraints(context)
        if request.mode == "agentic" and config.trace:
            audit = SimpleNamespace(citations=citations)
            hops = budget.call(
                "evidence_path",
                {"event_ids": [h.citation.event_id for h in selected]},
                lambda: build_hops(session, store, audit, request.model_dump(), asset_id),
            )
            result["hops"] = hops
            result["evidence_tasks"] = derive_evidence_tasks(session, hops)
            budget.steps[-1]["output"] = {
                "hops": len(hops),
                "pending_tasks": len(result["evidence_tasks"]),
            }
        gaps = {flag for c in citations for flag in c.get("quality_flags", [])}
        if config.relevance_gate:
            # Missing unrelated CPE/CVSS fields do not invalidate a description-only answer.
            requested_version = any(
                w in question for w in ("版本", "影响范围", "version", "affected range")
            )
            requested_severity = any(
                w in question for w in ("严重", "评分", "cvss", "severity", "score")
            )
            is_partial = (
                requested_version
                and bool(gaps & {"unparsed_version_range", "missing_affected_scope"})
            ) or (
                requested_severity
                and (
                    "missing_cvss" in gaps
                    or any(
                        t["task_type"] == "cross_source_conflict" for t in result["evidence_tasks"]
                    )
                )
            )
        else:
            is_partial = bool(gaps) or bool(result["evidence_tasks"])
        if asset_id:
            exposures = result["asset_context"]["exposures"]
            is_partial |= not exposures or any(e["status"] == "unknown" for e in exposures)
        if result.get("context", {}).get("truncated"):
            is_partial = True
            result["constraints"].append(
                {
                    "code": "context_budget_limited",
                    "rule": "上下文达到片段或字符预算，未包含全部候选资料，不能声称已穷尽所有修复信息。",
                }
            )
        result["answer_class"] = "partial" if is_partial else "evidence"
        result["citations"] = citations
        # Only exact substrings are claims; metadata, flags and policy statements are separate.
        result["claims"] = [
            {"citation_index": i, "quote": h.text[:360]} for i, h in enumerate(selected)
        ]
        lines = ["以下是可复验的来源片段："]
        lines += [f"[{i + 1}] {h.external_id}：{h.text[:360]}" for i, h in enumerate(selected)]
        if is_partial:
            lines.append("证据仍有缺口或需要复核，不能外推为完整结论。")
        if asset_id:
            lines.append("资产上下文仅适用于本次选择的 SBOM；来源条件匹配不代表漏洞复现。")
        result["answer"] = "\n".join(lines)
        result["reason"] = "partial_source_evidence" if is_partial else "source_excerpts"
    except ModelUnavailable as exc:
        result.update(answer_class="unavailable", reason="model_unavailable", answer=str(exc))
    except (TimeoutError, BudgetExceeded) as exc:
        result.update(
            answer_class="refused",
            reason="timeout" if isinstance(exc, TimeoutError) else "tool_budget_exceeded",
            answer="本轮已到达工具预算或时间上限，未生成未经校验的结论。",
            citations=[],
            claims=[],
        )
    finally:
        if budget.remaining() <= 0:
            result.update(
                answer_class="refused",
                reason="timeout",
                citations=[],
                claims=[],
                answer="本轮已到达时间上限，不能输出未完成核验的结论。",
            )
        result["elapsed_ms"] = round((clock() - budget.start) * 1000, 3)
        result["tool_calls"] = len(budget.steps)
    return result


def save_run(session, request, result):
    row = RagRun(request=request.model_dump(), result=json.loads(json.dumps(result, default=str)))
    session.add(row)
    session.flush()
    return row
