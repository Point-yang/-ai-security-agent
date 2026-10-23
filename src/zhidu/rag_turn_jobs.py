"""Reserve, generate and persist in separate transactions, with a per-turn lease."""

import hashlib
import json
import os
import time
from copy import deepcopy
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import select, update

from zhidu.models import Conversation, ConversationRagTurn, RagRun, RagTurnJob, now_utc
from zhidu.rag import RagRequest
from zhidu.rag_conversations import (
    TurnConflict,
    generate_prepared_turn,
    resolve_context,
    safe,
    submit_rag_turn,
)

WORKER_INSTANCE = str(uuid4())


def owner_alive(job):
    pid = job.payload.get("worker_pid")
    if pid is None:
        return True
    if pid == os.getpid():
        return job.payload.get("worker_instance") == WORKER_INSTANCE
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def fingerprint(body):
    return hashlib.sha256(json.dumps(body.model_dump(), sort_keys=True).encode()).hexdigest()


def _completed(session, body):
    turn = session.scalar(
        select(ConversationRagTurn).where(
            ConversationRagTurn.conversation_id == body.conversation_id,
            ConversationRagTurn.request_id == body.request_id,
        )
    )
    if not turn:
        return None
    run = session.get(RagRun, turn.rag_run_id)
    if RagRequest.model_validate(run.request).model_dump() != body.model_dump():
        raise TurnConflict("request_id already used for a different request")
    result = {"id": run.id, **deepcopy(run.result), "deduplicated": True}
    result["cost"] = {
        **result.get("cost", {}),
        "current_attempt_external_requests": 0,
        "current_attempt_billed_tokens": 0,
    }
    from zhidu.agent_research import replay_research_trace
    from zhidu.evidence_novelty import evidence_novelty

    agent = result.get("agent")
    if isinstance(agent, dict):
        for field in ("research_trace", "decisions"):
            if isinstance(agent.get(field), list):
                agent[field] = replay_research_trace(agent[field])
    batch = result.get("batch_tool_calls")
    if isinstance(batch, list):
        result["batch_tool_calls"] = replay_research_trace(batch)
    elif isinstance(batch, dict):
        for field in ("calls", "items"):
            if isinstance(batch.get(field), list):
                batch[field] = replay_research_trace(batch[field])
    novelty = result.get("evidence_novelty")
    if isinstance(novelty, dict):
        novelty["current_attempt"] = evidence_novelty({}, {})
        for decision in novelty.get("decisions", []):
            if isinstance(decision, dict):
                decision["current_attempt_novelty"] = evidence_novelty({}, {})
    return result


def _reserve(sessions, settings, body):
    if not body.request_id:
        raise TurnConflict("conversation requests require request_id")
    token, stamp = str(uuid4()), now_utc()
    with sessions.begin() as session:
        locked = session.execute(
            update(Conversation)
            .where(Conversation.id == body.conversation_id)
            .values(state_version=Conversation.state_version)
        )
        if not locked.rowcount:
            raise LookupError("conversation not found")
        existing = _completed(session, body)
        if existing:
            return "completed", existing
        conversation = session.get(Conversation, body.conversation_id)
        job = session.scalar(
            select(RagTurnJob).where(
                RagTurnJob.conversation_id == body.conversation_id,
                RagTurnJob.request_id == body.request_id,
            )
        )
        if job:
            if job.request_sha256 != fingerprint(body):
                raise TurnConflict("request_id already used for a different request")
            if job.status == "running" and job.lease_expires_at > stamp and owner_alive(job):
                return "wait", job.id
            if job.generated_result is None and not job.payload["native_agent"]:
                raise TurnConflict(
                    "previous_request_outcome_unknown; create a new request explicitly"
                )
            if conversation.state_version != job.base_state_version:
                raise TurnConflict("conversation_changed_since_interruption")
            job.owner_token, job.status = token, "running"
            job.lease_expires_at = stamp + timedelta(seconds=settings.rag_turn_lease_seconds)
            job.updated_at = stamp
            resuming = True
        else:
            active = session.scalar(
                select(RagTurnJob).where(
                    RagTurnJob.conversation_id == body.conversation_id,
                    RagTurnJob.status == "running",
                )
            )
            if active:
                raise TurnConflict(
                    "conversation_request_in_progress; retry the existing request first"
                )
            changes, context, history = resolve_context(session, conversation, body)
            effective = body.model_copy(update=changes)
            if effective.generation == "configured":
                effective = effective.model_copy(update={"generation": settings.llm_provider})
            if effective.generation == "agent" and effective.agent_backend is None:
                effective = effective.model_copy(update={"agent_backend": settings.agent_backend})
            if (
                not effective.asset_id
                and not effective.clear_asset
                and conversation.active_asset_id
            ):
                effective = effective.model_copy(update={"asset_id": conversation.active_asset_id})
            native = effective.generation == "agent" and (
                effective.agent_backend or settings.agent_backend
            ) in {"langchain", "workflow", "auto", "team"}
            job = RagTurnJob(
                conversation_id=body.conversation_id,
                request_id=body.request_id,
                request_sha256=fingerprint(body),
                status="running",
                owner_token=token,
                base_state_version=conversation.state_version,
                lease_expires_at=stamp + timedelta(seconds=settings.rag_turn_lease_seconds),
                payload={
                    "effective": effective.model_dump(),
                    "context": context,
                    "history": history,
                    "native_agent": native,
                },
            )
            session.add(job)
            resuming = False
        job.payload = {**job.payload, "worker_pid": os.getpid(), "worker_instance": WORKER_INSTANCE}
        session.flush()
        return "owned", {
            "id": job.id,
            "owner": token,
            "payload": safe(job.payload),
            "generated": safe(job.generated_result) if job.generated_result else None,
            "resuming": resuming,
        }


def submit_short_turn(sessions, store, settings, body, encoder):
    started = time.monotonic()
    deadline = started + settings.rag_turn_duplicate_wait_seconds
    while True:
        status, reservation = _reserve(sessions, settings, body)
        if status == "completed":
            return reservation
        if status == "owned":
            break
        if time.monotonic() >= deadline:
            raise TurnConflict("request_in_progress; retry with the same request_id")
        time.sleep(0.025)
    payload = reservation["payload"]
    effective = RagRequest.model_validate(payload["effective"])
    context, history = payload["context"], payload["history"]
    result = reservation["generated"]
    try:
        if result is None:
            # Read-only tool work. No primary-database write transaction spans the model call.
            with sessions() as session:
                result = generate_prepared_turn(
                    session,
                    store,
                    settings,
                    effective,
                    encoder,
                    context,
                    history,
                    checkpoint_key=reservation["id"] if payload["native_agent"] else None,
                    checkpoint_resume_required=reservation["resuming"],
                )
            with sessions.begin() as session:
                saved = session.execute(
                    update(RagTurnJob)
                    .where(
                        RagTurnJob.id == reservation["id"],
                        RagTurnJob.owner_token == reservation["owner"],
                    )
                    .values(generated_result=safe(result), updated_at=now_utc())
                )
                if not saved.rowcount:
                    raise TurnConflict("request_lease_lost")
        with sessions.begin() as session:
            job = session.get(RagTurnJob, reservation["id"])
            locked = session.execute(
                update(Conversation)
                .where(
                    Conversation.id == body.conversation_id,
                    Conversation.state_version == job.base_state_version,
                )
                .values(state_version=Conversation.state_version)
            )
            if not locked.rowcount or job.owner_token != reservation["owner"]:
                raise TurnConflict("conversation_changed_or_request_lease_lost")
            from zhidu.agent_result import verify_citations

            verification = verify_citations(session, store, result["citations"])
            if verification["verified"] != verification["total"]:
                raise TurnConflict("source_changed_after_generation; use a new request")
            result["turn_job_id"] = job.id
            answer = submit_rag_turn(
                session,
                store,
                settings,
                body,
                encoder,
                prepared=(effective, context, history),
                generated=result,
            )
            job.status, job.updated_at = "completed", now_utc()
            answer["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
            answer["timing_scope"] = (
                "reserve_generation_and_short_persist_transactions; excludes_network_delivery"
            )
            run = session.get(RagRun, answer["id"])
            run.result = {k: v for k, v in answer.items() if k not in {"id", "deduplicated"}}
            return answer
    except Exception as exc:
        with sessions.begin() as session:
            session.execute(
                update(RagTurnJob)
                .where(
                    RagTurnJob.id == reservation["id"],
                    RagTurnJob.owner_token == reservation["owner"],
                )
                .values(
                    status="interrupted",
                    error=type(exc).__name__,
                    lease_expires_at=now_utc(),
                    updated_at=now_utc(),
                )
            )
        raise
