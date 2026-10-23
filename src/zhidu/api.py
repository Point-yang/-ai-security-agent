import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from zhidu.answers import (
    AnswerAuditCreate,
    ExtractiveAnswerRequest,
    audit_view,
    event_constraints,
    make_extractive_answer,
    save_audit,
)
from zhidu.asset_evaluation import asset_evaluation_view
from zhidu.asset_matching import (
    asset_report,
    asset_view,
    exposure_view,
    import_cyclonedx,
    scan_assets,
)
from zhidu.catalog import catalog_associations, catalog_item_view
from zhidu.comparisons import comparison_view, sync_comparisons
from zhidu.config import Settings
from zhidu.conversations import (
    asset_recommendations,
    comparison_review_context,
    conversation_context_status,
    conversation_view,
    create_conversation,
    replay_conversation,
    submit_turn,
    task_view,
)
from zhidu.db import make_engine, make_sessions
from zhidu.enrichment import enrichment_status, enrichment_view
from zhidu.enrichment_evaluation import enrichment_evaluation_view
from zhidu.evaluation import evaluation_view
from zhidu.evidence import asset_evidence_graph, event_trace
from zhidu.indexing import chunk_view, index_status, search_index
from zhidu.models import (
    AffectedPackage,
    AnswerAudit,
    Asset,
    AssetEvaluation,
    AssetExposure,
    CatalogItem,
    CatalogRevision,
    CollectionRun,
    ComparisonReviewChange,
    Conversation,
    ConversationEvaluation,
    EnrichmentEvaluation,
    EventAlias,
    EventChange,
    EventEnrichment,
    EventRevision,
    EventTriage,
    EvidenceTask,
    IntelEvent,
    IntelligenceComparison,
    MonitorState,
    OperationalEvaluation,
    RawDocument,
    RecoveryAction,
    RetrievalEvaluation,
    SearchChunk,
    Source,
    SyncState,
    now_utc,
)
from zhidu.monitor import load_targets
from zhidu.monitoring_experiment import window_report
from zhidu.observability import RequestMetrics, configure_logging, log_event
from zhidu.operations import (
    collection_snapshot,
    enrichment_snapshot,
    operational_evaluation_view,
    operational_snapshot,
)
from zhidu.rag_api import register_rag_routes
from zhidu.retrieval import RetrievalChunk, RetrievalResult
from zhidu.schemas import (
    AnnotationPatch,
    ComparisonReviewPatch,
    ConversationCreate,
    ConversationTurnCreate,
    CycloneDXImport,
    EventDetail,
    EventList,
    RevisionView,
)
from zhidu.semantic import LocalEncoder
from zhidu.sources import SOURCES
from zhidu.storage import BlobStore
from zhidu.worker_health import worker_snapshot


def create_app(settings: Settings | None = None) -> FastAPI:
    configure_logging()
    settings = settings or Settings()
    engine = make_engine(settings.database_url)
    sessions = make_sessions(engine)
    store = BlobStore(settings.raw_dir)
    encoder = LocalEncoder(settings)

    @asynccontextmanager
    async def lifespan(app):
        yield
        encoder.close()
        engine.dispose()

    app = FastAPI(
        title="知盾 · 情报与检索接口",
        version="0.12.0",
        lifespan=lifespan,
        description="多源监测、可追溯证据、结构化富化、资产匹配与审计检索。",
    )
    app.state.engine = engine
    request_metrics = RequestMetrics()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "PATCH", "POST"],
        allow_headers=["Content-Type", "X-Admin-Key"],
    )

    @app.middleware("http")
    async def response_headers(request, call_next):
        started = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
        finally:
            route = getattr(request.scope.get("route"), "path", "unmatched")
            duration = time.perf_counter() - started
            request_metrics.observe(route, status_code, duration)
            if route not in {"/metrics", "/health", "/health/live", "/health/ready", "/static"}:
                log_event(
                    "http_request", route=route, status=status_code, seconds=round(duration, 6)
                )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def db():
        with sessions() as session:
            yield session

    Db = Annotated[Session, Depends(db)]

    def get_event(session, event_id):
        event = session.get(IntelEvent, event_id)
        if event is None:
            raise HTTPException(404, "event not found")
        return event

    def require_admin(x_admin_key):
        key = settings.admin_key.get_secret_value()
        if not key:
            raise HTTPException(503, "HTTP writes disabled; configure ZHIDU_ADMIN_KEY")
        if not x_admin_key or not secrets.compare_digest(x_admin_key, key):
            raise HTTPException(401, "invalid admin key")

    register_rag_routes(app, settings, sessions, store, encoder, require_admin)

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request, exc):
        return JSONResponse(
            status_code=503,
            content={"detail": "database unavailable; run init-db and check configuration"},
        )

    @app.get("/api/v1/release/evidence", tags=["发布与评测"])
    def release_evidence():
        from zhidu.release_evidence import public_release_evidence

        return public_release_evidence(settings.submission_evidence_path)

    @app.get("/health", tags=["运行状态"])
    def health(session: Db):
        count = session.scalar(select(func.count()).select_from(IntelEvent))
        return {
            "status": "ok",
            "events": count,
            "version": "0.12.0",
            "http_writes_enabled": bool(settings.admin_key.get_secret_value()),
        }

    @app.get("/health/live", tags=["运行状态"])
    def liveness():
        return {"status": "alive", "version": "0.12.0"}

    @app.get("/health/ready", tags=["运行状态"])
    def readiness(session: Db):
        # A reachable DB on an old schema is not ready to serve current handlers.
        session.execute(select(MonitorState.heartbeat_at).limit(1)).all()
        session.execute(select(OperationalEvaluation.id).limit(1)).all()
        session.execute(select(IntelligenceComparison.is_active).limit(1)).all()
        checks = {
            "database": session.scalar(select(1)) == 1,
            "monitor_config": True,
            "raw_storage": settings.raw_dir.exists()
            and os.access(settings.raw_dir, os.R_OK | os.W_OK),
        }
        try:
            load_targets(settings.monitor_config)
        except (OSError, ValueError):
            checks["monitor_config"] = False
        ready = all(checks.values())
        return JSONResponse(
            status_code=200 if ready else 503,
            content={"status": "ready" if ready else "not_ready", "checks": checks},
        )

    @app.get("/metrics", include_in_schema=False)
    def prometheus_metrics(session: Db):
        try:
            targets = load_targets(settings.monitor_config)
        except (OSError, ValueError):
            raise HTTPException(503, "monitor configuration unavailable") from None
        collection = collection_snapshot(session, targets)
        enrichment = enrichment_snapshot(session)
        lines = [
            "# HELP zhidu_events_total Stored intelligence events.",
            "# TYPE zhidu_events_total gauge",
            f"zhidu_events_total {enrichment['events']}",
            "# HELP zhidu_enrichment_coverage Fraction of events with current enrichment.",
            "# TYPE zhidu_enrichment_coverage gauge",
            f"zhidu_enrichment_coverage {enrichment['coverage']}",
            "# HELP zhidu_monitor_targets_failed Enabled monitor targets in failed state.",
            "# TYPE zhidu_monitor_targets_failed gauge",
            f"zhidu_monitor_targets_failed {collection['targets_failed']}",
            "# HELP zhidu_monitor_targets_fresh Targets successful within two configured intervals.",
            "# TYPE zhidu_monitor_targets_fresh gauge",
            f"zhidu_monitor_targets_fresh {collection['targets_fresh']}",
            "# TYPE zhidu_monitor_targets_enabled gauge",
            f"zhidu_monitor_targets_enabled {collection['configured_targets']}",
        ]
        for target in collection["targets"]:
            labels = f'target="{target["id"]}",source="{target["source_id"]}"'
            lines.append(
                f"zhidu_monitor_consecutive_failures{{{labels}}} {target['consecutive_failures']}"
            )
            if target["seconds_since_success"] is not None:
                lines.append(
                    f"zhidu_monitor_seconds_since_success{{{labels}}} {target['seconds_since_success']}"
                )
        lines.extend(request_metrics.render())
        return Response("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")

    @app.get("/api/v1/events", response_model=EventList, tags=["情报"])
    def list_events(
        session: Db,
        q: str | None = Query(default=None, max_length=200),
        source_id: str | None = None,
        kind: str | None = None,
        ai_label: str | None = None,
        alias: str | None = None,
        package: str | None = None,
        severity: Literal["unknown", "low", "medium", "high", "critical"] | None = None,
        include_withdrawn: bool = True,
        updated_since: datetime | None = None,
        limit: int = Query(20, ge=1, le=100),
        offset: int = Query(0, ge=0),
    ):
        stmt = select(IntelEvent)
        if source_id:
            stmt = stmt.where(IntelEvent.source_id == source_id)
        if kind:
            stmt = stmt.where(IntelEvent.kind == kind)
        if ai_label:
            stmt = stmt.where(
                IntelEvent.id.in_(select(EventTriage.event_id).where(EventTriage.label == ai_label))
            )
        if q:
            stmt = stmt.where(
                or_(
                    IntelEvent.title.icontains(q, autoescape=True),
                    IntelEvent.external_id.icontains(q, autoescape=True),
                )
            )
        if alias:
            stmt = stmt.where(
                IntelEvent.id.in_(select(EventAlias.event_id).where(EventAlias.value == alias))
            )
        if package:
            stmt = stmt.where(
                IntelEvent.id.in_(
                    select(AffectedPackage.event_id).where(AffectedPackage.name == package)
                )
            )
        if severity:
            stmt = stmt.where(IntelEvent.severity == severity)
        if not include_withdrawn:
            stmt = stmt.where(IntelEvent.withdrawn_at.is_(None))
        if updated_since:
            if updated_since.tzinfo is None:
                raise HTTPException(422, "updated_since requires timezone")
            stmt = stmt.where(IntelEvent.source_updated_at >= updated_since)
        total = session.scalar(select(func.count()).select_from(stmt.subquery()))
        events = session.scalars(
            stmt.order_by(IntelEvent.source_updated_at.desc(), IntelEvent.id)
            .offset(offset)
            .limit(limit)
        ).all()
        return {"total": total, "items": events, "limit": limit, "offset": offset}

    @app.get("/api/v1/events/{event_id}", response_model=EventDetail, tags=["情报"])
    def event_detail(event_id: str, session: Db):
        event = get_event(session, event_id)
        revision = session.scalar(
            select(EventRevision).where(
                EventRevision.event_id == event_id,
                EventRevision.number == event.revision,
            )
        )
        aliases = session.scalars(
            select(EventAlias.value)
            .where(EventAlias.event_id == event_id)
            .order_by(EventAlias.value)
        ).all()
        return {
            **{c.name: getattr(event, c.name) for c in IntelEvent.__table__.columns},
            "aliases": aliases,
            "packages": revision.normalized["packages"],
            "current_revision": revision,
            "triage": triage_data(session.get(EventTriage, event_id)),
            "enrichment": (
                enrichment_view(row) if (row := session.get(EventEnrichment, event_id)) else None
            ),
        }

    @app.get("/api/v1/events/{event_id}/history", response_model=list[RevisionView], tags=["证据"])
    def event_history(event_id: str, session: Db):
        get_event(session, event_id)
        return session.scalars(
            select(EventRevision)
            .where(EventRevision.event_id == event_id)
            .order_by(EventRevision.number.desc())
        ).all()

    @app.get("/api/v1/events/{event_id}/evidence", tags=["证据"])
    def event_evidence(event_id: str, session: Db, revision: int | None = Query(None, ge=1)):
        event = get_event(session, event_id)
        result = session.scalar(
            select(EventRevision).where(
                EventRevision.event_id == event_id,
                EventRevision.number == (revision or event.revision),
            )
        )
        if result is None:
            raise HTTPException(404, "revision not found")
        return {"event_id": event_id, "revision": result.number, "items": result.evidence}

    @app.get("/api/v1/events/{event_id}/trace", tags=["证据"])
    def trace_event(event_id: str, session: Db):
        """Verify field pointers and return the full observation timeline."""
        return event_trace(session, store, get_event(session, event_id))

    @app.get("/api/v1/events/{event_id}/audit", tags=["情报"])
    def event_audit(event_id: str, session: Db):
        get_event(session, event_id)
        rows = session.scalars(
            select(EventChange)
            .where(EventChange.event_id == event_id)
            .order_by(EventChange.sequence)
        ).all()
        return [
            {
                "sequence": row.sequence,
                "change_type": row.change_type,
                "occurred_at": row.occurred_at,
                "detail": row.detail,
            }
            for row in rows
        ]

    @app.get("/api/v1/events/{event_id}/enrichment", tags=["结构化富化"])
    def event_enrichment(event_id: str, session: Db):
        get_event(session, event_id)
        row = session.get(EventEnrichment, event_id)
        if row is None:
            raise HTTPException(404, "event enrichment not built; run zhidu enrich")
        return enrichment_view(row)

    @app.get("/api/v1/enrichment/status", tags=["结构化富化"])
    def enrichment_summary(session: Db):
        return enrichment_status(session)

    @app.get("/api/v1/review-queue", tags=["人工核验"])
    def review_queue(
        session: Db,
        quality_flag: str | None = Query(default=None, max_length=100),
        source_id: str | None = None,
        limit: int = Query(50, ge=1, le=200),
    ):
        stmt = (
            select(IntelEvent, EventTriage, EventEnrichment)
            .join(EventTriage, EventTriage.event_id == IntelEvent.id)
            .join(EventEnrichment, EventEnrichment.event_id == IntelEvent.id)
            .where(IntelEvent.review_status.in_(["unreviewed", "needs_evidence"]))
        )
        if source_id:
            stmt = stmt.where(IntelEvent.source_id == source_id)
        rows = session.execute(stmt).all()
        if quality_flag:
            rows = [row for row in rows if quality_flag in row[2].quality_flags]

        def priority(row):
            event, triage, enrichment = row
            return (
                (30 if event.kind == "exploitation_alert" else 0)
                + (
                    20
                    if triage.label == "relevant"
                    else 10
                    if triage.label == "needs_review"
                    else 0
                )
                + ({"critical": 20, "high": 15, "medium": 8}.get(event.severity, 0))
                + min(len(enrichment.quality_flags), 5)
                + (5 if event.review_status == "needs_evidence" else 0)
            )

        ranked = sorted(rows, key=lambda row: (-priority(row), row[0].source_updated_at, row[0].id))
        return {
            "total": len(ranked),
            "priority_is_workflow_score_not_risk_probability": True,
            "items": [
                {
                    "event_id": event.id,
                    "source_id": event.source_id,
                    "external_id": event.external_id,
                    "title": event.title,
                    "kind": event.kind,
                    "severity": event.severity,
                    "ai_label": triage.label,
                    "review_status": event.review_status,
                    "priority": priority((event, triage, enrichment)),
                    "quality_flags": enrichment.quality_flags,
                    "selected_cvss": enrichment.cvss.get("selected"),
                }
                for event, triage, enrichment in ranked[:limit]
            ],
        }

    @app.get("/api/v1/assets", tags=["资产与 SBOM"])
    def assets(session: Db):
        rows = session.scalars(select(Asset).order_by(Asset.name)).all()
        return [asset_view(session, row) for row in rows]

    @app.get("/api/v1/assets/{asset_id}", tags=["资产与 SBOM"])
    def asset_detail(asset_id: str, session: Db):
        asset = session.get(Asset, asset_id)
        if asset is None:
            raise HTTPException(404, "asset not found")
        return asset_view(session, asset)

    @app.get("/api/v1/assets/{asset_id}/report", tags=["资产与 SBOM"])
    def reproducible_asset_report(asset_id: str, session: Db):
        try:
            return asset_report(session, asset_id)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from None

    @app.get("/api/v1/assets/{asset_id}/evidence-graph", tags=["资产与 SBOM"])
    def asset_trace(asset_id: str, session: Db):
        asset = session.get(Asset, asset_id)
        if asset is None:
            raise HTTPException(404, "asset not found")
        return asset_evidence_graph(session, store, asset)

    @app.get("/api/v1/assets/{asset_id}/recommendations", tags=["资产与 SBOM"])
    def asset_priority_recommendations(
        asset_id: str, session: Db, limit: int = Query(20, ge=1, le=100)
    ):
        asset = session.get(Asset, asset_id)
        if asset is None:
            raise HTTPException(404, "asset not found")
        return asset_recommendations(session, asset, limit)

    @app.get("/api/v1/asset-evaluations", tags=["资产与 SBOM"])
    def asset_evaluations(session: Db, limit: int = Query(20, ge=1, le=100)):
        rows = session.scalars(
            select(AssetEvaluation).order_by(AssetEvaluation.run_at.desc()).limit(limit)
        ).all()
        return [asset_evaluation_view(row) for row in rows]

    @app.get("/api/v1/conversation-evaluations", tags=["成员 B 多轮问答"])
    def conversation_evaluations(session: Db, limit: int = Query(20, ge=1, le=100)):
        rows = session.scalars(
            select(ConversationEvaluation)
            .order_by(ConversationEvaluation.run_at.desc())
            .limit(limit)
        ).all()
        return [
            {column.name: getattr(row, column.name) for column in row.__table__.columns}
            for row in rows
        ]

    @app.post("/api/v1/assets/import-cyclonedx", tags=["资产与 SBOM"])
    def import_asset(
        body: CycloneDXImport,
        session: Db,
        x_admin_key: Annotated[str | None, Header()] = None,
    ):
        require_admin(x_admin_key)
        content = json.dumps(
            body.sbom, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
        try:
            asset, result = import_cyclonedx(
                session,
                content,
                asset_name=body.asset_name,
                environment=body.environment,
                criticality=body.criticality,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(422, str(exc)) from None
        session.commit()
        return {"asset": asset_view(session, asset), "result": result}

    @app.get("/api/v1/assets/{asset_id}/exposures", tags=["资产与 SBOM"])
    def asset_exposures(
        asset_id: str,
        session: Db,
        status: Literal["affected", "not_affected", "unknown"] | None = None,
        limit: int = Query(100, ge=1, le=500),
    ):
        if session.get(Asset, asset_id) is None:
            raise HTTPException(404, "asset not found")
        stmt = select(AssetExposure).where(AssetExposure.asset_id == asset_id)
        if status:
            stmt = stmt.where(AssetExposure.status == status)
        total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        rows = session.scalars(
            stmt.order_by(AssetExposure.status, AssetExposure.id).limit(limit)
        ).all()
        return {
            "asset_id": asset_id,
            "total": total,
            "source_asserted_comparison_not_independent_verification": True,
            "items": [exposure_view(session, row) for row in rows],
        }

    @app.post("/api/v1/assets/{asset_id}/scan", tags=["资产与 SBOM"])
    def scan_asset(
        asset_id: str,
        session: Db,
        x_admin_key: Annotated[str | None, Header()] = None,
    ):
        require_admin(x_admin_key)
        if session.get(Asset, asset_id) is None:
            raise HTTPException(404, "asset not found")
        result = scan_assets(session, asset_id)
        session.commit()
        return result

    @app.get("/api/v1/comparisons", tags=["跨来源比较"])
    def comparisons(
        session: Db,
        identifier: str | None = Query(default=None, max_length=100),
        status: Literal["agreement", "variation", "conflict"] | None = None,
        review_status: Literal["unreviewed", "acknowledged", "needs_evidence"] | None = None,
        include_inactive: bool = False,
        limit: int = Query(100, ge=1, le=500),
    ):
        stmt = select(IntelligenceComparison)
        if not include_inactive:
            stmt = stmt.where(IntelligenceComparison.is_active.is_(True))
        if identifier:
            stmt = stmt.where(IntelligenceComparison.identifier == identifier.upper())
        if status:
            stmt = stmt.where(IntelligenceComparison.status == status)
        if review_status:
            stmt = stmt.where(IntelligenceComparison.review_status == review_status)
        total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        rows = session.scalars(
            stmt.order_by(IntelligenceComparison.identifier, IntelligenceComparison.field).limit(
                limit
            )
        ).all()
        return {
            "total": total,
            "automatic_resolution": False,
            "items": [comparison_view(row) for row in rows],
        }

    @app.patch("/api/v1/comparisons/{comparison_id}/review", tags=["跨来源比较"])
    def review_comparison(
        comparison_id: str,
        body: ComparisonReviewPatch,
        session: Db,
        x_admin_key: Annotated[str | None, Header()] = None,
    ):
        require_admin(x_admin_key)
        row = session.get(IntelligenceComparison, comparison_id)
        if row is None:
            raise HTTPException(404, "comparison not found")
        if not row.is_active:
            raise HTTPException(409, "comparison is inactive; reload current source evidence")
        if row.status != "conflict" or row.field != "severity":
            raise HTTPException(422, "manual review is limited to severity conflicts")
        result = session.execute(
            update(IntelligenceComparison)
            .where(
                IntelligenceComparison.id == comparison_id,
                IntelligenceComparison.annotation_version == body.expected_version,
                IntelligenceComparison.is_active.is_(True),
            )
            .values(
                review_status=body.review_status,
                analyst_note=body.analyst_note,
                annotation_version=body.expected_version + 1,
                reviewed_at=now_utc(),
            )
        )
        if result.rowcount != 1:
            session.rollback()
            raise HTTPException(409, "comparison review changed; reload before retrying")
        session.add(
            ComparisonReviewChange(
                comparison_id=comparison_id,
                previous_version=body.expected_version,
                annotation_version=body.expected_version + 1,
                review_status=body.review_status,
                analyst_note=body.analyst_note,
                observations=row.observations,
                change_kind="manual_review",
            )
        )
        session.commit()
        return comparison_view(session.get(IntelligenceComparison, comparison_id))

    @app.get("/api/v1/comparisons/{comparison_id}/reviews", tags=["跨来源比较"])
    def comparison_reviews(comparison_id: str, session: Db):
        if session.get(IntelligenceComparison, comparison_id) is None:
            raise HTTPException(404, "comparison not found")
        rows = session.scalars(
            select(ComparisonReviewChange)
            .where(ComparisonReviewChange.comparison_id == comparison_id)
            .order_by(ComparisonReviewChange.created_at, ComparisonReviewChange.id)
        ).all()
        return [
            {column.name: getattr(row, column.name) for column in row.__table__.columns}
            for row in rows
        ]

    @app.get("/api/v1/comparisons/{comparison_id}/review-context", tags=["跨来源比较"])
    def comparison_evidence_context(comparison_id: str, session: Db):
        row = session.get(IntelligenceComparison, comparison_id)
        if row is None:
            raise HTTPException(404, "comparison not found")
        return comparison_review_context(session, store, row)

    @app.post("/api/v1/comparisons/rebuild", tags=["跨来源比较"])
    def rebuild_comparisons(
        session: Db,
        x_admin_key: Annotated[str | None, Header()] = None,
    ):
        require_admin(x_admin_key)
        result = sync_comparisons(session)
        session.commit()
        return result

    def retrieval_rows(
        session,
        *,
        event_id=None,
        package=None,
        severity=None,
        origin="live",
        include_withdrawn=False,
        ai_label=None,
    ):
        stmt = (
            select(IntelEvent, EventRevision, RawDocument)
            .join(
                EventRevision,
                (EventRevision.event_id == IntelEvent.id)
                & (EventRevision.number == IntelEvent.revision),
            )
            .join(RawDocument, RawDocument.id == EventRevision.raw_document_id)
            .where(EventRevision.disposition == "current")
        )
        if ai_label:
            stmt = stmt.where(
                IntelEvent.id.in_(select(EventTriage.event_id).where(EventTriage.label == ai_label))
            )
        if event_id:
            stmt = stmt.where(IntelEvent.id == event_id)
        if origin:
            stmt = stmt.where(RawDocument.origin == origin)
        if not include_withdrawn:
            stmt = stmt.where(IntelEvent.withdrawn_at.is_(None))
        if severity:
            stmt = stmt.where(IntelEvent.severity == severity)
        if package:
            stmt = stmt.where(
                IntelEvent.id.in_(
                    select(AffectedPackage.event_id).where(AffectedPackage.name == package)
                )
            )
        return session.execute(stmt).all()

    @app.get("/api/v1/retrieval/search", response_model=RetrievalResult, tags=["成员 B 检索"])
    def retrieve(
        session: Db,
        q: str = Query(min_length=1, max_length=200),
        package: str | None = None,
        severity: Literal["unknown", "low", "medium", "high", "critical"] | None = None,
        origin: Literal["live", "replay"] = "live",
        ai_label: Literal["relevant", "needs_review", "unrelated"] | None = None,
        pool: Literal["formal", "candidate", "excluded"] | None = None,
        source_id: str | None = None,
        kind: str | None = None,
        entity_type: Literal["cve", "ghsa", "doi", "package", "vendor", "product"] | None = None,
        entity_value: str | None = Query(default=None, max_length=300),
        cpe: str | None = Query(default=None, max_length=500),
        quality_flag: str | None = Query(default=None, max_length=100),
        include_withdrawn: bool = False,
        limit: int = Query(20, ge=1, le=100),
        offset: int = Query(0, ge=0),
    ):
        if not q.strip():
            raise HTTPException(422, "q must contain non-whitespace characters")
        if pool and ai_label:
            expected = {"relevant": "formal", "needs_review": "candidate", "unrelated": "excluded"}
            if expected[ai_label] != pool:
                raise HTTPException(422, "pool and ai_label select different index sets")
        if bool(entity_type) != bool(entity_value):
            raise HTTPException(422, "entity_type and entity_value must be provided together")
        hits, scanned_events = search_index(
            session,
            q.strip(),
            pool=pool,
            package=package,
            severity=severity,
            origin=origin,
            source_id=source_id,
            kind=kind,
            entity_type=entity_type,
            entity_value=entity_value,
            cpe=cpe,
            quality_flag=quality_flag,
            ai_label=ai_label,
            include_withdrawn=include_withdrawn,
        )
        return {
            "query": q.strip(),
            "total": len(hits),
            "scanned_events": scanned_events,
            "items": hits[offset : offset + limit],
        }

    @app.get(
        "/api/v1/retrieval/events/{event_id}",
        response_model=list[RetrievalChunk],
        tags=["成员 B 检索"],
    )
    def retrieval_input(event_id: str, session: Db):
        get_event(session, event_id)
        rows = session.scalars(
            select(SearchChunk).where(SearchChunk.event_id == event_id).order_by(SearchChunk.id)
        ).all()
        return [chunk_view(row) for row in rows]

    @app.get("/api/v1/retrieval/index", tags=["成员 B 检索"])
    def retrieval_index_status(session: Db):
        return index_status(session)

    @app.get("/api/v1/retrieval/evaluations", tags=["成员 B 检索"])
    def retrieval_evaluations(session: Db, limit: int = Query(20, ge=1, le=100)):
        rows = session.scalars(
            select(RetrievalEvaluation).order_by(RetrievalEvaluation.run_at.desc()).limit(limit)
        ).all()
        return [evaluation_view(row) for row in rows]

    @app.get("/api/v1/answer-constraints/{event_id}", tags=["成员 B 问答"])
    def answer_constraints(event_id: str, session: Db):
        event = get_event(session, event_id)
        revision = session.scalar(
            select(EventRevision).where(
                EventRevision.event_id == event.id,
                EventRevision.number == event.revision,
            )
        )
        enrichment = session.get(EventEnrichment, event_id)
        return {
            "event_id": event.id,
            "revision_id": revision.id,
            "source_id": event.source_id,
            "kind": event.kind,
            "enrichment_schema_version": enrichment.schema_version if enrichment else None,
            "quality_flags": enrichment.quality_flags if enrichment else [],
            "constraints": event_constraints(session, event_id, revision),
        }

    @app.post("/api/v1/answers/extractive", tags=["成员 B 问答"])
    def extractive_answer(
        session: Db,
        body: ExtractiveAnswerRequest,
        x_admin_key: Annotated[str | None, Header()] = None,
    ):
        require_admin(x_admin_key)
        try:
            audit = make_extractive_answer(session, body)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from None
        session.commit()
        return audit_view(audit)

    @app.get("/api/v1/conversations", tags=["成员 B 多轮问答"])
    def conversations(session: Db, limit: int = Query(50, ge=1, le=200)):
        rows = session.scalars(
            select(Conversation).order_by(Conversation.updated_at.desc()).limit(limit)
        ).all()
        return [conversation_view(session, row) for row in rows]

    @app.post("/api/v1/conversations", tags=["成员 B 多轮问答"])
    def start_conversation(
        body: ConversationCreate,
        session: Db,
        x_admin_key: Annotated[str | None, Header()] = None,
    ):
        require_admin(x_admin_key)
        try:
            row = create_conversation(session, body.title, body.asset_id)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from None
        session.commit()
        return conversation_view(session, row)

    @app.get("/api/v1/conversations/{conversation_id}", tags=["成员 B 多轮问答"])
    def conversation_detail(conversation_id: str, session: Db):
        row = session.get(Conversation, conversation_id)
        if row is None:
            raise HTTPException(404, "conversation not found")
        return replay_conversation(session, row)

    @app.get("/api/v1/conversations/{conversation_id}/replay", tags=["成员 B 多轮问答"])
    def conversation_replay(conversation_id: str, session: Db):
        row = session.get(Conversation, conversation_id)
        if row is None:
            raise HTTPException(404, "conversation not found")
        return replay_conversation(session, row)

    @app.get("/api/v1/conversations/{conversation_id}/context-status", tags=["成员 B 多轮问答"])
    def current_conversation_context(conversation_id: str, session: Db):
        row = session.get(Conversation, conversation_id)
        if row is None:
            raise HTTPException(404, "conversation not found")
        return conversation_context_status(session, row)

    @app.post("/api/v1/conversations/{conversation_id}/turns", tags=["成员 B 多轮问答"])
    def conversation_turn(
        conversation_id: str,
        body: ConversationTurnCreate,
        session: Db,
        x_admin_key: Annotated[str | None, Header()] = None,
    ):
        require_admin(x_admin_key)
        row = session.get(Conversation, conversation_id)
        if row is None:
            raise HTTPException(404, "conversation not found")
        try:
            result = submit_turn(session, store, row, body)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from None
        session.commit()
        return result

    @app.get(
        "/api/v1/conversations/{conversation_id}/evidence-tasks",
        tags=["成员 B 多轮问答"],
    )
    def conversation_evidence_tasks(
        conversation_id: str,
        session: Db,
        status: Literal["pending", "completed", "cancelled"] | None = None,
    ):
        if session.get(Conversation, conversation_id) is None:
            raise HTTPException(404, "conversation not found")
        stmt = select(EvidenceTask).where(EvidenceTask.conversation_id == conversation_id)
        if status:
            stmt = stmt.where(EvidenceTask.status == status)
        rows = session.scalars(stmt.order_by(EvidenceTask.created_at, EvidenceTask.id)).all()
        return {
            "conversation_id": conversation_id,
            "network_collection_executed": False,
            "items": [task_view(row) for row in rows],
        }

    @app.get(
        "/api/v1/conversations/{conversation_id}/recommendations",
        tags=["成员 B 多轮问答"],
    )
    def conversation_recommendations(
        conversation_id: str, session: Db, limit: int = Query(20, ge=1, le=100)
    ):
        row = session.get(Conversation, conversation_id)
        if row is None:
            raise HTTPException(404, "conversation not found")
        if row.active_asset_id is None:
            raise HTTPException(409, "conversation has no explicitly selected asset")
        return asset_recommendations(session, session.get(Asset, row.active_asset_id), limit)

    @app.post("/api/v1/answer-audits", tags=["成员 B 问答"])
    def create_answer_audit(
        session: Db,
        body: AnswerAuditCreate,
        x_admin_key: Annotated[str | None, Header()] = None,
    ):
        require_admin(x_admin_key)
        try:
            audit = save_audit(session, body)
        except LookupError as exc:
            raise HTTPException(409, str(exc)) from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        session.commit()
        return audit_view(audit)

    @app.get("/api/v1/answer-audits", tags=["成员 B 问答"])
    def answer_audits(session: Db, limit: int = Query(20, ge=1, le=100)):
        rows = session.scalars(
            select(AnswerAudit).order_by(AnswerAudit.created_at.desc()).limit(limit)
        ).all()
        return [audit_view(row) for row in rows]

    @app.patch("/api/v1/events/{event_id}/annotation", tags=["人工核验"])
    def annotate(
        event_id: str,
        body: AnnotationPatch,
        session: Db,
        x_admin_key: Annotated[str | None, Header()] = None,
    ):
        require_admin(x_admin_key)
        get_event(session, event_id)
        result = session.execute(
            update(IntelEvent)
            .where(
                IntelEvent.id == event_id,
                IntelEvent.annotation_version == body.expected_version,
            )
            .values(
                review_status=body.review_status,
                analyst_note=body.analyst_note,
                annotation_version=body.expected_version + 1,
            )
        )
        if result.rowcount != 1:
            session.rollback()
            raise HTTPException(409, "annotation changed; reload before retrying")
        session.add(
            EventChange(event_id=event_id, change_type="annotation", detail=body.model_dump())
        )
        session.commit()
        return {
            "event_id": event_id,
            "annotation_version": body.expected_version + 1,
            "review_status": body.review_status,
            "analyst_note": body.analyst_note,
        }

    @app.get("/api/v1/raw-documents/{document_id}", tags=["证据"])
    def raw_metadata(document_id: str, session: Db):
        doc = session.get(RawDocument, document_id)
        if doc is None:
            raise HTTPException(404, "raw document not found")
        return {
            **{c.name: getattr(doc, c.name) for c in RawDocument.__table__.columns},
            "content_url": f"/api/v1/raw-documents/{doc.id}/content",
        }

    @app.get("/api/v1/raw-documents/{document_id}/content", tags=["证据"])
    def raw_content(document_id: str, session: Db):
        doc = session.get(RawDocument, document_id)
        if doc is None:
            raise HTTPException(404, "raw document not found")
        try:
            content = store.read(doc.sha256)
        except (OSError, ValueError):
            raise HTTPException(503, "raw document missing or integrity check failed") from None
        return Response(
            content=content,
            media_type=doc.media_type,
            headers={"ETag": f'"{doc.sha256}"', "Cache-Control": "no-cache"},
        )

    @app.get("/api/v1/sources", tags=["运行状态"])
    def sources(session: Db):
        rows = session.scalars(select(Source).order_by(Source.id)).all()
        return [
            {"id": s.id, "name": s.name, "category": s.category, "base_url": s.base_url}
            for s in rows
        ]

    @app.get("/api/v1/collection-runs", tags=["运行状态"])
    def runs(session: Db, limit: int = Query(20, ge=1, le=100)):
        rows = session.scalars(
            select(CollectionRun).order_by(CollectionRun.started_at.desc()).limit(limit)
        ).all()
        return [
            {c.name: getattr(row, c.name) for c in CollectionRun.__table__.columns} for row in rows
        ]

    def triage_data(row):
        if row is None:
            return None
        return {
            "label": row.label,
            "category": row.category,
            "rule_version": row.rule_version,
            "matches": row.matches,
            "method": "deterministic_rules",
        }

    @app.get("/api/v1/events/{event_id}/related", tags=["情报"])
    def related(event_id: str, session: Db):
        event = get_event(session, event_id)
        current = session.scalar(
            select(EventRevision).where(
                EventRevision.event_id == event_id, EventRevision.number == event.revision
            )
        )
        origin = session.get(RawDocument, current.raw_document_id).origin
        aliases = session.scalars(
            select(EventAlias.value).where(EventAlias.event_id == event_id)
        ).all()
        stmt = (
            select(IntelEvent, EventAlias.value)
            .join(EventAlias, EventAlias.event_id == IntelEvent.id)
            .join(
                EventRevision,
                (EventRevision.event_id == IntelEvent.id)
                & (EventRevision.number == IntelEvent.revision),
            )
            .join(RawDocument, RawDocument.id == EventRevision.raw_document_id)
            .where(
                EventAlias.value.in_(aliases),
                IntelEvent.id != event_id,
                RawDocument.origin == origin,
            )
            .order_by(IntelEvent.id, EventAlias.value)
            .limit(101)
        )
        rows = session.execute(stmt).all()
        items = {}
        for other, alias in rows[:100]:
            item = items.setdefault(
                other.id,
                {
                    "event_id": other.id,
                    "source_id": other.source_id,
                    "external_id": other.external_id,
                    "title": other.title,
                    "shared_identifiers": [],
                    "relation": "shared_identifier",
                    "independent_confirmation": False,
                },
            )
            item["shared_identifiers"].append(alias)
        return {
            "items": list(items.values()),
            "truncated": len(rows) > 100,
            "note": "Identifier association only; source records and original evidence remain separate.",
        }

    @app.get("/api/v1/monitoring", tags=["运行状态"])
    def monitoring(session: Db):
        try:
            targets = load_targets(settings.monitor_config)
        except (OSError, ValueError):
            raise HTTPException(503, "monitor configuration unavailable") from None
        items = []
        for target in targets:
            state = session.get(MonitorState, target.id)
            run = (
                session.get(CollectionRun, state.last_run_id)
                if state and state.last_run_id
                else None
            )
            spec = SOURCES[target.source]
            items.append(
                {
                    "id": target.id,
                    "source_id": target.source,
                    "source_name": spec.name,
                    "category": spec.category,
                    "enabled": target.enabled,
                    "interval_seconds": target.interval_seconds,
                    "status": state.status if state else "not_started",
                    "config_current": state.config_hash == target.fingerprint if state else False,
                    "next_run_at": state.next_run_at if state else None,
                    "last_success_at": state.last_success_at if state else None,
                    "consecutive_failures": state.failures if state else 0,
                    "has_pending_pages": bool(state.continuation) if state else False,
                    "stats": run.stats if run else {},
                    "error": run.error if run else None,
                }
            )
        return {
            "targets": items,
            "configured_sources": len({t.source for t in targets if t.enabled}),
            "configured_categories": len(
                {SOURCES[t.source].category for t in targets if t.enabled}
            ),
            "note": "Configuration counts are not proven source coverage or real-time SLA.",
        }

    @app.get("/api/v1/monitoring/window", tags=["运行状态"])
    def monitoring_window(session: Db, hours: int = Query(24, ge=1, le=168)):
        """Retrospective successful-poll coverage; never a publication-latency SLA."""
        try:
            targets = load_targets(settings.monitor_config)
        except (OSError, ValueError):
            raise HTTPException(503, "monitor configuration unavailable") from None
        return window_report(session, targets, hours=hours)

    @app.get("/api/v1/monitoring/worker", tags=["运行状态"])
    def monitoring_worker():
        return worker_snapshot(settings.raw_dir.parent / "collector.heartbeat")

    @app.get("/api/v1/operations/status", tags=["运行状态"])
    def operations_status(session: Db):
        try:
            targets = load_targets(settings.monitor_config)
        except (OSError, ValueError):
            raise HTTPException(503, "monitor configuration unavailable") from None
        return operational_snapshot(
            session,
            store,
            targets,
            verify_raw=False,
        )

    @app.get("/api/v1/catalog/items", tags=["元数据目录"])
    def catalog_items(
        session: Db,
        source_id: str | None = None,
        kind: str | None = None,
        external_id: str | None = None,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
    ):
        stmt = select(CatalogItem)
        if source_id:
            stmt = stmt.where(CatalogItem.source_id == source_id)
        if kind:
            stmt = stmt.where(CatalogItem.kind == kind)
        if external_id:
            stmt = stmt.where(CatalogItem.external_id == external_id)
        total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        rows = session.scalars(
            stmt.order_by(CatalogItem.last_seen_at.desc(), CatalogItem.id)
            .offset(offset)
            .limit(limit)
        ).all()
        return {
            "total": total,
            "items": [catalog_item_view(session, row) for row in rows],
            "scope": "source_metadata_only_no_poc_execution",
        }

    @app.get("/api/v1/catalog/items/{item_id}/history", tags=["元数据目录"])
    def catalog_history(item_id: str, session: Db):
        if session.get(CatalogItem, item_id) is None:
            raise HTTPException(404, "catalog item not found")
        rows = session.scalars(
            select(CatalogRevision)
            .where(CatalogRevision.item_id == item_id)
            .order_by(CatalogRevision.number.desc())
        ).all()
        return [
            {
                "number": row.number,
                "raw_document_id": row.raw_document_id,
                "evidence_locator": row.evidence_locator,
                "fingerprint": row.fingerprint,
                "collected_at": row.collected_at,
            }
            for row in rows
        ]

    @app.get("/api/v1/catalog/items/{item_id}/associations", tags=["元数据目录"])
    def catalog_association_candidates(item_id: str, session: Db):
        row = session.get(CatalogItem, item_id)
        if row is None:
            raise HTTPException(404, "catalog item not found")
        return catalog_associations(session, row)

    @app.get("/api/v1/operations/evaluations", tags=["运行状态"])
    def operations_evaluations(session: Db, limit: int = Query(20, ge=1, le=100)):
        rows = session.scalars(
            select(OperationalEvaluation).order_by(OperationalEvaluation.run_at.desc()).limit(limit)
        ).all()
        return [operational_evaluation_view(row) for row in rows]

    @app.get("/api/v1/enrichment/evaluations", tags=["结构化富化"])
    def enrichment_evaluations(session: Db, limit: int = Query(20, ge=1, le=100)):
        rows = session.scalars(
            select(EnrichmentEvaluation).order_by(EnrichmentEvaluation.run_at.desc()).limit(limit)
        ).all()
        return [enrichment_evaluation_view(row) for row in rows]

    @app.get("/api/v1/operations/recovery-actions", tags=["运行状态"])
    def recovery_actions(session: Db, limit: int = Query(50, ge=1, le=200)):
        rows = session.scalars(
            select(RecoveryAction).order_by(RecoveryAction.occurred_at.desc()).limit(limit)
        ).all()
        return [
            {column.name: getattr(row, column.name) for column in RecoveryAction.__table__.columns}
            for row in rows
        ]

    @app.get("/api/v1/sync-states", tags=["运行状态"])
    def sync_states(session: Db):
        return [
            {"scope": s.scope, "watermark": s.watermark}
            for s in session.scalars(select(SyncState).order_by(SyncState.scope)).all()
        ]

    static = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(static / "index.html")

    @app.get("/workspace", include_in_schema=False)
    def member_b_workspace():
        return FileResponse(static / "workspace.html")

    @app.get("/assets", include_in_schema=False)
    def asset_workspace():
        return FileResponse(static / "assets.html")

    @app.get("/catalog", include_in_schema=False)
    def catalog_workspace():
        return FileResponse(static / "catalog.html")

    return app
