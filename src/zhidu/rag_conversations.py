"""Persist generated turns without promoting historical answers to evidence."""

import hashlib
import json
import re
import time

from sqlalchemy import func, select, update

from zhidu.conversations import EXPLICIT_SWITCH_TERMS, conversation_context_status
from zhidu.models import (
    Asset,
    Conversation,
    ConversationHop,
    ConversationMessage,
    ConversationRagTurn,
    EventAlias,
    EvidenceTask,
    IntelEvent,
    RagRun,
    now_utc,
)
from zhidu.rag import run_rag, save_run

IDENTIFIER = re.compile(r"CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.I)
FOLLOWUP = re.compile(
    r"它|这个|这条|该公告|该漏洞|上述|前面|首次修复|影响哪些版本|如何修复|修复版本|版本范围|\b(it|this|that|affected versions|first patched|fix version)\b",
    re.I,
)


class TurnConflict(ValueError):
    pass


def safe(value):
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def resolve_context(session, conversation, body):
    messages = session.scalars(
        select(ConversationMessage)
        .where(ConversationMessage.conversation_id == conversation.id)
        .order_by(ConversationMessage.sequence)
    ).all()
    freshness = conversation_context_status(session, conversation)
    notices = [
        {
            "code": f"historical_source_{c['status']}",
            "rule": f"历史来源 {c['event_id']} 状态为 {c['status']}；旧回答保留，本轮仅使用重新核验的当前原文。",
        }
        for c in freshness["citations"]
        if not c["reusable_as_current"]
    ]
    context = {
        "history_policy": "reference_only_not_evidence",
        "notices": notices,
        "citation_status": freshness["citations"],
        "resolved_event_ids": [],
        "resolution": "explicit_query",
        "candidates": [],
    }
    history = [
        {"role": m.role, "content": m.content[:1500], "evidence_status": "historical_not_evidence"}
        for m in messages[-6:]
    ]
    changes = {"context_mode": "expanded"}
    if body.clear_asset and body.asset_id:
        raise TurnConflict("clear_asset and asset_id cannot be combined")
    if body.asset_id and session.get(Asset, body.asset_id) is None:
        raise LookupError("asset not found")
    if any(t in body.question.casefold() for t in EXPLICIT_SWITCH_TERMS) and not body.asset_id:
        context.update(
            resolution="clarification_required",
            clarification="请选择要切换的资产；本轮不会沿用旧资产或根据名称猜测。",
        )
        return changes, context, history
    explicit = body.query or IDENTIFIER.search(body.question)
    if body.event_id:
        event = session.get(IntelEvent, body.event_id)
        if event is None:
            raise LookupError("event not found")
        changes["query"] = body.query or event.external_id
        context["resolved_event_ids"] = [event.id]
        context["resolution"] = "explicit_event"
    elif explicit:
        changes["query"] = body.query or explicit.group(0)
    elif FOLLOWUP.search(body.question):
        # Last grounded turn defines the object; never silently fall back to an older topic.
        last = next((m for m in reversed(messages) if m.role == "assistant"), None)
        ids = sorted(last.selected_event_ids) if last else []
        events = [session.get(IntelEvent, eid) for eid in ids]
        context["candidates"] = [
            {
                "event_id": e.id,
                "external_id": e.external_id,
                "source_id": e.source_id,
                "title": e.title,
            }
            for e in events
            if e
        ]
        if len(ids) == 1 and events[0]:
            changes.update(event_id=ids[0], query=events[0].external_id)
        elif ids and all(events):
            identifiers = []
            for event in events:
                aliases = session.scalars(
                    select(EventAlias.value).where(EventAlias.event_id == event.id)
                ).all()
                identifiers.append({event.external_id.casefold(), *(a.casefold() for a in aliases)})
            common = set.intersection(*identifiers)
            if common:
                changes["query"] = sorted(common, key=lambda x: (not x.startswith("ghsa-"), x))[0]
            else:
                context.update(
                    resolution="clarification_required",
                    clarification="上一轮涉及多个不同公告，请选择一个来源事件或输入公告编号后继续。",
                )
        else:
            context.update(
                resolution="clarification_required",
                clarification="尚无可明确引用的公告对象，请输入公告编号或选择来源事件。",
            )
        if context["resolution"] != "clarification_required":
            context.update(resolution="confirmed_history_object", resolved_event_ids=ids)
    if body.event_id or changes.get("event_id"):
        event = session.get(IntelEvent, body.event_id or changes["event_id"])
        if event.withdrawn_at:
            context.update(
                resolution="source_withdrawn",
                clarification="所选公告已撤回，历史答案保留，但不能继续作为当前依据。请选择有效来源。",
            )
    if re.search(
        r"这个版本|该版本|\b(?:this|that) version\b", body.question, re.I
    ) and not re.search(r"\d+\.\d+", body.question):
        context.update(
            resolution="clarification_required",
            clarification="请明确具体版本号；公告中的影响范围和首次修复版本可能不同，不能静默猜选。",
        )
        return changes, context, history
    return changes, context, history


def generate_prepared_turn(
    session,
    store,
    settings,
    effective,
    encoder,
    context,
    history,
    *,
    checkpoint_key=None,
    checkpoint_resume_required=False,
):
    if context["resolution"] in {"clarification_required", "source_withdrawn"}:
        result = {
            "answer_class": "clarification"
            if context["resolution"] == "clarification_required"
            else "refused",
            "answer": context["clarification"],
            "reason": context["resolution"],
            "citations": [],
            "claims": [],
            "constraints": context["notices"],
            "tools": [],
            "hops": [],
            "evidence_tasks": [],
            "tool_calls": 0,
            "asset_id": None,
            "generation_model": "none",
            "generation": {"status": "skipped", "reason": context["resolution"]},
            "cost": {"external_requests": 0, "billed_tokens": 0, "api_usd": 0},
            "conversation_context": context,
        }
    else:
        if effective.generation == "agent":
            from zhidu.agent_dispatch import run_agent

            result = run_agent(
                session,
                store,
                settings,
                effective,
                encoder,
                history=history,
                conversation_context=context,
                **(
                    {
                        "checkpoint_key": checkpoint_key,
                        "checkpoint_resume_required": checkpoint_resume_required,
                    }
                    if checkpoint_key
                    and (effective.agent_backend or settings.agent_backend)
                    in {"langchain", "workflow", "auto", "team"}
                    else {}
                ),
            )
        else:
            result = run_rag(
                session,
                store,
                settings,
                effective,
                encoder,
                history=history,
                conversation_context=context,
            )
    return result


def submit_rag_turn(session, store, settings, body, encoder, *, prepared=None, generated=None):
    started = time.monotonic()
    if not body.request_id:
        raise TurnConflict("conversation requests require request_id")
    # Acquire a database row/write lock before reading sequence or checking deduplication.
    # SQLite serializes writers; PostgreSQL locks this conversation only. No automatic retry.
    locked = session.execute(
        update(Conversation)
        .where(Conversation.id == body.conversation_id)
        .values(state_version=Conversation.state_version)
    )
    if not locked.rowcount:
        raise LookupError("conversation not found")
    conversation = session.get(Conversation, body.conversation_id)
    fingerprint = hashlib.sha256(json.dumps(body.model_dump(), sort_keys=True).encode()).hexdigest()
    old = session.scalar(
        select(ConversationRagTurn).where(
            ConversationRagTurn.conversation_id == conversation.id,
            ConversationRagTurn.request_id == body.request_id,
        )
    )
    if old:
        if old.request_sha256 != fingerprint:
            raise TurnConflict("request_id already used for a different request")
        run = session.get(RagRun, old.rag_run_id)
        return {"id": run.id, **run.result, "deduplicated": True}
    if prepared is None:
        changes, context, history = resolve_context(session, conversation, body)
        effective = body.model_copy(update=changes)
    else:
        effective, context, history = prepared
    result = (
        generated
        if generated is not None
        else generate_prepared_turn(session, store, settings, effective, encoder, context, history)
    )
    requested_provider = (
        (effective.generation if effective.generation != "configured" else settings.llm_provider)
        if body.generation == "configured"
        else body.generation
    )
    result["requested_generation"] = {
        "provider": requested_provider,
        "model": settings.deepseek_model
        if requested_provider in {"deepseek", "agent"}
        else "extractive-packet-v4",
    }
    if result.get("generation", {}).get("requested_model"):
        result["requested_generation"]["model"] = result["generation"]["requested_model"]
    if body.clear_asset:
        conversation.active_asset_id = None
    elif body.asset_id:
        conversation.active_asset_id = body.asset_id
    sequence = (
        session.scalar(
            select(func.max(ConversationMessage.sequence)).where(
                ConversationMessage.conversation_id == conversation.id
            )
        )
        or 0
    ) + 1
    user = ConversationMessage(
        conversation_id=conversation.id,
        sequence=sequence,
        role="user",
        content=body.question,
        request=body.model_dump(),
        explicit_asset_id=body.asset_id,
        effective_asset_id=result["asset_id"],
        selected_event_ids=[],
        citations=[],
        constraints=[],
    )
    assistant = ConversationMessage(
        conversation_id=conversation.id,
        sequence=sequence + 1,
        role="assistant",
        content=result["answer"],
        request=None,
        answer_status=result["answer_class"],
        explicit_asset_id=body.asset_id,
        effective_asset_id=result["asset_id"],
        selected_event_ids=sorted({c["event_id"] for c in result["citations"]})
        or (context["resolved_event_ids"] if result["answer_class"] == "clarification" else []),
        citations=result["citations"],
        constraints=result["constraints"],
    )
    session.add_all([user, assistant])
    session.flush()
    for hop in result["hops"]:
        session.add(ConversationHop(assistant_message_id=assistant.id, **safe(hop)))
    for task in result["evidence_tasks"]:
        session.add(
            EvidenceTask(conversation_id=conversation.id, message_id=assistant.id, **safe(task))
        )
    conversation.state_version += 1
    conversation.updated_at = now_utc()
    result.update(
        conversation_id=conversation.id,
        request_id=body.request_id,
        user_message_id=user.id,
        assistant_message_id=assistant.id,
        state_version=conversation.state_version,
        resolved_request=effective.model_dump(),
    )
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    result["timing_scope"] = (
        "conversation_resolution_retrieval_verification_generation_and_message_flush; excludes_commit_and_network_delivery"
    )
    run = save_run(session, body, result)
    session.add(
        ConversationRagTurn(
            conversation_id=conversation.id,
            request_id=body.request_id,
            request_sha256=fingerprint,
            rag_run_id=run.id,
        )
    )
    # New hop stores all generation audit fields; no columns are added to old messages.
    session.add(
        ConversationHop(
            assistant_message_id=assistant.id,
            hop_order=max((h["hop_order"] for h in result["hops"]), default=0) + 1,
            hop_type="rag_generation",
            input_data={"rag_run_id": run.id, "request": body.model_dump()},
            output_data=safe(result),
            evidence_refs=safe(result["citations"]),
        )
    )
    session.flush()
    return {"id": run.id, **safe(result), "deduplicated": False}
