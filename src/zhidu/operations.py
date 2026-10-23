"""Operational metrics, honest quality gates and audited recovery actions."""

import hashlib
import json
import math
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import func, select

from zhidu.models import (
    AssetExposure,
    CollectionRun,
    EnrichmentState,
    EventEnrichment,
    EventRevision,
    IntelEvent,
    IntelligenceComparison,
    MonitorState,
    OperationalEvaluation,
    RawDocument,
    RecoveryAction,
    SearchChunk,
    SearchIndexState,
    now_utc,
)
from zhidu.sources import SOURCES

OPERATIONS_SCHEMA_VERSION = "operations-v1"


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(fraction * len(ordered)) - 1)
    return round(ordered[index], 6)


def _distribution(values: list[float], unit: str) -> dict:
    return {
        "samples": len(values),
        "min": round(min(values), 6) if values else None,
        "p50": _percentile(values, 0.5),
        "p95": _percentile(values, 0.95),
        "max": round(max(values), 6) if values else None,
        "unit": unit,
    }


def raw_integrity(session, store) -> dict:
    documents = session.scalars(select(RawDocument).order_by(RawDocument.id)).all()
    verified = 0
    failures = []
    for document in documents:
        try:
            content = store.read(document.sha256)
            if hashlib.sha256(content).hexdigest() != document.sha256:
                raise ValueError("digest mismatch")
            if len(content) != document.size_bytes:
                raise ValueError("size mismatch")
            verified += 1
        except (OSError, ValueError) as exc:
            failures.append(
                {
                    "raw_document_id": document.id,
                    "sha256": document.sha256,
                    "error": type(exc).__name__,
                }
            )
    return {
        "raw_documents": len(documents),
        "verified": verified,
        "failed": len(failures),
        "failure_samples": failures[:20],
    }


def collection_snapshot(session, targets, *, clock=now_utc) -> dict:
    now = clock()
    target_rows = []
    for target in targets:
        state = session.get(MonitorState, target.id)
        run = session.get(CollectionRun, state.last_run_id) if state and state.last_run_id else None
        freshness = (
            max(0.0, (now - state.last_success_at).total_seconds())
            if state and state.last_success_at
            else None
        )
        stale_after = max(target.interval_seconds * 2, 600)
        target_rows.append(
            {
                "id": target.id,
                "source_id": target.source,
                "category": SOURCES[target.source].category,
                "enabled": target.enabled,
                "interval_seconds": target.interval_seconds,
                "status": state.status if state else "not_started",
                "config_current": bool(state and state.config_hash == target.fingerprint),
                "consecutive_failures": state.failures if state else 0,
                "has_pending_pages": bool(state and state.continuation),
                "last_success_at": state.last_success_at if state else None,
                "heartbeat_at": state.heartbeat_at if state else None,
                "seconds_since_success": round(freshness, 3) if freshness is not None else None,
                "fresh_within_two_intervals": freshness is not None and freshness <= stale_after,
                "last_run_status": run.status if run else None,
            }
        )

    # Attribute the initial observation to its immutable first revision. Replay
    # fixtures and non-timestamp publication dates must not improve live latency.
    observations = session.execute(
        select(IntelEvent, EventRevision, RawDocument)
        .join(
            EventRevision, (EventRevision.event_id == IntelEvent.id) & (EventRevision.number == 1)
        )
        .join(RawDocument, RawDocument.id == EventRevision.raw_document_id)
    ).all()
    live_delays = []
    exclusions = Counter()
    for event, revision, document in observations:
        if document.origin != "live":
            exclusions["replay"] += 1
        elif event.kind != "vulnerability":
            exclusions["non_vulnerability_publication_semantics"] += 1
        else:
            published = revision.normalized.get("published_at")
            delay = (event.first_seen_at - datetime.fromisoformat(published)).total_seconds()
            if delay < 0:
                exclusions["negative_delay"] += 1
            else:
                live_delays.append(delay / 3600)
    runs = session.scalars(
        select(CollectionRun).where(CollectionRun.finished_at.is_not(None))
    ).all()
    run_durations = [max(0.0, (run.finished_at - run.started_at).total_seconds()) for run in runs]
    run_statuses = Counter(run.status for run in session.scalars(select(CollectionRun)))
    enabled = [row for row in target_rows if row["enabled"]]
    return {
        "configured_targets": len(enabled),
        "configured_sources": len({row["source_id"] for row in enabled}),
        "configured_categories": len({row["category"] for row in enabled}),
        "targets": target_rows,
        "targets_current": sum(row["config_current"] for row in enabled),
        "targets_fresh": sum(row["fresh_within_two_intervals"] for row in enabled),
        "targets_failed": sum(row["status"] == "failed" for row in enabled),
        "targets_with_pending_pages": sum(row["has_pending_pages"] for row in enabled),
        "run_status_counts": dict(sorted(run_statuses.items())),
        "run_duration": _distribution(run_durations, "seconds"),
        "observed_publication_to_first_seen": _distribution(live_delays, "hours"),
        "delay_exclusions": dict(exclusions),
        "observation_delay_is_sla_evidence": False,
        "observation_delay_note": (
            "Includes historical backfill and proves only database observation delay; "
            "continuous daemon uptime is required before claiming a monitoring SLA."
        ),
    }


def enrichment_snapshot(session) -> dict:
    event_count = session.scalar(select(func.count()).select_from(IntelEvent)) or 0
    rows = session.scalars(select(EventEnrichment)).all()
    flags = Counter(flag for row in rows for flag in row.quality_flags)
    exposure_counts = Counter(row.status for row in session.scalars(select(AssetExposure)))
    comparison_counts = Counter(
        row.status
        for row in session.scalars(
            select(IntelligenceComparison).where(IntelligenceComparison.is_active.is_(True))
        )
    )
    return {
        "events": event_count,
        "enriched_events": len(rows),
        "coverage": round(len(rows) / event_count, 6) if event_count else 1.0,
        "with_entities": sum(bool(row.entities) for row in rows),
        "with_cvss": sum(bool(row.cvss.get("entries")) for row in rows),
        "with_version_scope": sum(bool(row.version_ranges) for row in rows),
        "with_cpe_scope": sum(bool(row.cpe_matches) for row in rows),
        "quality_flag_counts": dict(sorted(flags.items())),
        "asset_exposure_counts": dict(sorted(exposure_counts.items())),
        "comparison_counts": dict(sorted(comparison_counts.items())),
        "coverage_is_accuracy": False,
        "accuracy_note": "Coverage metrics do not establish correctness; use a labeled suite.",
    }


def operational_snapshot(session, store, targets, *, verify_raw=True, clock=now_utc) -> dict:
    collection = collection_snapshot(session, targets, clock=clock)
    enrichment = enrichment_snapshot(session)
    integrity = raw_integrity(session, store) if verify_raw else {"status": "not_checked"}
    index_state = session.get(SearchIndexState, "lexical")
    chunk_count = session.scalar(select(func.count()).select_from(SearchChunk)) or 0
    enrichment_state = session.get(EnrichmentState, "structured")
    checks = [
        {
            "id": "raw_integrity",
            "passed": integrity.get("failed", 0) == 0 if verify_raw else None,
            "required": verify_raw,
        },
        {
            "id": "enrichment_coverage",
            "passed": enrichment["coverage"] == 1.0,
            "required": True,
        },
        {
            "id": "index_event_count",
            "passed": bool(index_state and index_state.event_count == enrichment["events"]),
            "required": True,
        },
        {
            "id": "index_chunk_count",
            "passed": bool(index_state and index_state.chunk_count == chunk_count),
            "required": True,
        },
        {
            "id": "enrichment_state_count",
            "passed": bool(
                enrichment_state
                and enrichment_state.event_count == enrichment["events"]
                and enrichment_state.enriched_count == enrichment["enriched_events"]
            ),
            "required": True,
        },
        {
            "id": "monitor_configs_current",
            "passed": collection["targets_current"] == collection["configured_targets"],
            "required": True,
        },
        {
            "id": "monitor_freshness",
            "passed": collection["targets_fresh"] == collection["configured_targets"],
            "required": True,
        },
        {
            "id": "no_failed_targets",
            "passed": collection["targets_failed"] == 0,
            "required": True,
        },
    ]
    required = [item for item in checks if item["required"]]
    if any(item["passed"] is False for item in required):
        status = "failed" if integrity.get("failed", 0) else "degraded"
    else:
        status = "passed"
    return {
        "schema_version": OPERATIONS_SCHEMA_VERSION,
        "run_at": clock(),
        "status": status,
        "collection": collection,
        "enrichment": enrichment,
        "integrity": integrity,
        "checks": checks,
        "limitations": [
            "Historical publication-to-first-seen delay is not a continuous-monitoring SLA.",
            "Enrichment coverage is not enrichment accuracy or recall.",
            "A passed integrity check validates stored bytes and references, not upstream truth.",
        ],
    }


def save_operational_evaluation(session, snapshot: dict) -> OperationalEvaluation:
    def safe(value):
        return json.loads(json.dumps(value, default=lambda item: item.isoformat()))

    row = OperationalEvaluation(
        schema_version=snapshot["schema_version"],
        run_at=snapshot["run_at"],
        status=snapshot["status"],
        collection=safe(snapshot["collection"]),
        enrichment=snapshot["enrichment"],
        integrity=snapshot["integrity"],
        checks=snapshot["checks"],
        limitations=snapshot["limitations"],
    )
    session.add(row)
    session.flush()
    return row


def operational_evaluation_view(row: OperationalEvaluation) -> dict:
    return {column.name: getattr(row, column.name) for column in row.__table__.columns}


def doctor(session, store, targets, *, repair=False, clock=now_utc) -> dict:
    """Repair callers must hold the database writer lock for the entire transaction."""
    now = clock()
    target_map = {target.id: target for target in targets}
    planned = []
    running = session.scalars(select(CollectionRun).where(CollectionRun.status == "running")).all()
    for run in running:
        target_id = next(
            (
                state.target_id
                for state in session.scalars(select(MonitorState))
                if state.last_run_id == run.id
            ),
            None,
        )
        state = session.get(MonitorState, target_id) if target_id else None
        last_progress = (state.heartbeat_at if state else None) or run.started_at
        if now - last_progress <= timedelta(minutes=10):
            continue
        planned.append(
            {
                "action_type": "recover_interrupted_collection",
                "target_id": target_id,
                "run_id": run.id,
                "age_seconds": round((now - run.started_at).total_seconds(), 3),
            }
        )
        if repair:
            run.status = "interrupted"
            run.finished_at = now
            run.error = "doctor recovered a stale running collection"
            if target_id and (state := session.get(MonitorState, target_id)):
                state.status = "failed"
                state.failures += 1
                state.next_run_at = now
                state.heartbeat_at = now

    for state in session.scalars(select(MonitorState)):
        target = target_map.get(state.target_id)
        if not target or state.status != "running" or not state.heartbeat_at:
            continue
        stale_after = timedelta(seconds=max(target.interval_seconds * 2, 600))
        if now - state.heartbeat_at <= stale_after:
            continue
        if not any(item["target_id"] == state.target_id for item in planned):
            planned.append(
                {
                    "action_type": "recover_stale_monitor_state",
                    "target_id": state.target_id,
                    "age_seconds": round((now - state.heartbeat_at).total_seconds(), 3),
                }
            )
            if repair:
                state.status = "failed"
                state.failures += 1
                state.next_run_at = now
                state.heartbeat_at = now

    integrity = raw_integrity(session, store)
    derived = {"status": "not_run"}
    if repair and not integrity["failed"]:
        from zhidu.asset_matching import scan_assets
        from zhidu.comparisons import sync_comparisons
        from zhidu.enrichment import sync_enrichments
        from zhidu.indexing import sync_index

        derived = {
            "index": sync_index(session),
            "enrichment": sync_enrichments(session, store),
            "assets": scan_assets(session),
            "comparisons": sync_comparisons(session),
        }
        planned.append(
            {
                "action_type": "reconcile_derived_state",
                "target_id": None,
                "result": derived,
            }
        )
    elif repair:
        derived = {"status": "blocked", "reason": "raw_integrity_failed"}
        planned.append(
            {"action_type": "reconcile_derived_state", "target_id": None, "result": derived}
        )
    if repair:
        for action in planned:
            session.add(
                RecoveryAction(
                    action_type=action["action_type"],
                    target_id=action.get("target_id"),
                    status="blocked"
                    if action.get("result", {}).get("status") == "blocked"
                    else "completed",
                    detail=action,
                    occurred_at=now,
                )
            )
    return {
        "schema_version": "doctor-v1",
        "checked_at": now,
        "mode": "repair" if repair else "inspect",
        "status": "failed"
        if integrity["failed"]
        else ("degraded" if planned and not repair else "passed"),
        "raw_integrity": integrity,
        "planned_or_completed_actions": planned,
        "derived_reconciliation": derived,
        "unrecoverable_automatically": integrity["failure_samples"],
        "note": "Doctor only repairs scheduler state and rebuildable derivatives; it never invents source evidence.",
    }
