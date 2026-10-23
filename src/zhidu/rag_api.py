"""Week-six routes share the app DB and authorization boundary."""

import json
from typing import Literal

from fastapi import Header, HTTPException, Query
from sqlalchemy import select

from zhidu.agent_tools import PreviewRequest, contracts, preview_tools
from zhidu.generation import generation_status
from zhidu.gold_review import reconcile
from zhidu.models import ChunkEmbedding, RagEvaluation, RagRun, RagTurnJob, SearchChunk, now_utc
from zhidu.rag import RagRequest, RouterConfig, run_rag, save_run
from zhidu.semantic import ModelUnavailable, content_digest, model_manifest, retrieve


def register_rag_routes(app, settings, sessions, store, encoder, require_admin):
    @app.get("/api/v1/agent/tools/contracts", tags=["智能体工具契约"])
    def agent_tool_contracts(x_admin_key: str | None = Header(default=None)):
        require_admin(x_admin_key)
        return contracts()

    @app.post("/api/v1/agent/tools/preview", tags=["智能体工具契约"])
    def agent_tool_preview(body: PreviewRequest, x_admin_key: str | None = Header(default=None)):
        require_admin(x_admin_key)
        with sessions() as session:
            return preview_tools(session, store, settings, encoder, body)

    @app.get("/api/v1/rag/human-review-status", tags=["成员 B RAG"])
    def human_review_status():
        try:
            inputs = [
                json.loads((settings.human_review_dir / name).read_text())
                for name in (
                    "source-packet.json",
                    "review-A.json",
                    "review-B.json",
                    "adjudications.json",
                )
            ]
            result = reconcile(*inputs)
            return {
                "status": result["status"],
                "tasks": result["tasks"],
                "completed": result["completed"],
                "pending": len(result["pending"]),
                "conflicts": len(result["conflicts"]),
                "official_scores": None,
            }
        except OSError:
            return {"status": "not_prepared", "official_scores": None}
        except (ValueError, KeyError, TypeError):
            return {"status": "invalid_review_files", "official_scores": None}

    @app.get("/api/v1/rag/search", tags=["成员 B RAG"])
    def rag_search(
        q: str = Query(min_length=1, max_length=200),
        mode: Literal["lexical", "hybrid"] = "hybrid",
        pool: Literal["formal", "candidate"] = "formal",
        origin: Literal["live", "replay"] = "live",
        event_id: str | None = None,
        limit: int = Query(10, ge=1, le=40),
    ):
        if not q.strip():
            raise HTTPException(422, "query must not be blank")
        config = RouterConfig.model_validate_json(settings.rag_config.read_text())
        with sessions() as session:
            try:
                hits, metadata = retrieve(
                    session,
                    q,
                    mode,
                    settings,
                    encoder,
                    pool=pool,
                    origin=origin,
                    event_id=event_id,
                    limit=limit,
                    min_score=config.semantic_min_score,
                    timeout=config.timeout_ms / 1000,
                    query_rewrite=config.query_rewrite,
                    relevance_gate=config.relevance_gate,
                )
            except ModelUnavailable as exc:
                raise HTTPException(
                    503, {"reason": "model_unavailable", "message": str(exc)}
                ) from None
            except TimeoutError:
                raise HTTPException(504, "embedding timeout") from None
            return {"items": [hit.model_dump() for hit in hits], "metadata": metadata}

    @app.get("/api/v1/rag/status", tags=["成员 B RAG"])
    def rag_status():
        from zhidu.langchain_agent import backend_status

        with sessions() as session:
            chunks = session.scalars(select(SearchChunk)).all()
            vectors = {r.chunk_id: r for r in session.scalars(select(ChunkEmbedding))}
            try:
                manifest = model_manifest(settings)
                ready = sum(
                    r.id in vectors
                    and vectors[r.id].model_key == manifest["digest"]
                    and vectors[r.id].content_sha256 == content_digest(r)
                    for r in chunks
                )
                status = "ready" if ready == len(chunks) else "index_incomplete"
                model = manifest["model"]
                key = manifest["digest"]
            except ModelUnavailable:
                ready, status, model, key = 0, "model_unavailable", settings.embedding_model, None
            # Availability is not inference success; failures are visible in each answer.
            return {
                "status": status,
                "model": model,
                "model_digest": key,
                "chunks": len(chunks),
                "current_vectors": ready,
                "streaming": False,
                "generation_model": generation_status(settings)["model"]
                if settings.llm_provider in {"deepseek", "model"}
                else "extractive-packet-v4",
                "generation": generation_status(settings),
                "agent": {
                    "configured_backend": settings.agent_backend,
                    "langchain": backend_status(),
                },
                "inference_checked": False,
            }

    @app.post("/api/v1/rag/answers", tags=["成员 B RAG"])
    def rag_answer(body: RagRequest, x_admin_key: str | None = Header(default=None)):
        from zhidu.agent_dispatch import run_agent
        from zhidu.rag_conversations import TurnConflict
        from zhidu.rag_turn_jobs import submit_short_turn

        require_admin(x_admin_key)
        try:
            if body.conversation_id:
                return submit_short_turn(sessions, store, settings, body, encoder)
            with sessions.begin() as session:
                result = (
                    run_agent(session, store, settings, body, encoder)
                    if body.generation == "agent"
                    else run_rag(session, store, settings, body, encoder)
                )
                run = save_run(session, body, result)
                return {"id": run.id, **result}
        except TurnConflict as exc:
            raise HTTPException(409, str(exc)) from None
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from None
        except (OSError, ValueError):
            raise HTTPException(503, "RAG configuration unavailable") from None

    @app.get(
        "/api/v1/conversations/{conversation_id}/rag-requests/{request_id}", tags=["成员 B RAG"]
    )
    def rag_request_status(
        conversation_id: str, request_id: str, x_admin_key: str | None = Header(default=None)
    ):
        from zhidu.rag_turn_jobs import owner_alive

        require_admin(x_admin_key)
        with sessions() as session:
            job = session.scalar(
                select(RagTurnJob).where(
                    RagTurnJob.conversation_id == conversation_id,
                    RagTurnJob.request_id == request_id,
                )
            )
            if job is None:
                raise HTTPException(404, "request job not found")
            active = (
                job.status == "running" and job.lease_expires_at > now_utc() and owner_alive(job)
            )
            return {
                "request_id": request_id,
                "status": job.status,
                "in_progress": active,
                "resume_eligible": not active
                and job.status != "completed"
                and (job.payload["native_agent"] or job.generated_result is not None),
                "generated_result_saved": job.generated_result is not None,
                "error": job.error,
                "lease_expires_at": job.lease_expires_at,
            }

    @app.post("/api/v1/rag/context", tags=["成员 B RAG"])
    def rag_context(body: RagRequest, x_admin_key: str | None = Header(default=None)):
        """Read-only context preview for conversation integration; never calls an LLM."""
        require_admin(x_admin_key)
        with sessions() as session:
            try:
                return run_rag(
                    session,
                    store,
                    settings,
                    body.model_copy(
                        update={"generation": "extractive", "context_mode": "expanded"}
                    ),
                    encoder,
                )
            except LookupError as exc:
                raise HTTPException(404, str(exc)) from None
            except (OSError, ValueError):
                raise HTTPException(503, "RAG configuration unavailable") from None

    @app.get("/api/v1/rag/runs", tags=["成员 B RAG"])
    def rag_runs(limit: int = Query(10, ge=1, le=50)):
        with sessions() as session:
            return [
                {"id": r.id, "created_at": r.created_at, "request": r.request, "result": r.result}
                for r in session.scalars(
                    select(RagRun).order_by(RagRun.created_at.desc()).limit(limit)
                )
            ]

    @app.get("/api/v1/rag/evaluations", tags=["成员 B RAG"])
    def rag_evaluations(limit: int = Query(5, ge=1, le=20)):
        with sessions() as session:
            return [
                {"id": r.id, "created_at": r.created_at, "report": r.report}
                for r in session.scalars(
                    select(RagEvaluation).order_by(RagEvaluation.created_at.desc()).limit(limit)
                )
            ]
