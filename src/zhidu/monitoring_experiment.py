"""Retrospective source-freshness coverage from persisted runs, not process uptime."""

from datetime import timedelta

from sqlalchemy import select

from zhidu.models import CollectionRun, now_utc


def window_report(session, targets, *, hours=24, clock=now_utc):
    if not 1 <= hours <= 168:
        raise ValueError("hours must be between 1 and 168")
    end = clock()
    start = end - timedelta(hours=hours)
    items = []
    for target in targets:
        if not target.enabled:
            continue
        scope = f"monitor:{target.id}:{target.fingerprint[:16]}"
        horizon = max(target.interval_seconds * 2, 600)
        runs = session.scalars(
            select(CollectionRun)
            .where(
                CollectionRun.scope == scope,
                CollectionRun.started_at <= end,
                CollectionRun.started_at >= start - timedelta(seconds=horizon),
            )
            .order_by(CollectionRun.started_at)
        ).all()
        successful = [
            r for r in runs if r.status == "completed" and r.finished_at and r.finished_at <= end
        ]
        intervals = []
        for run in sorted(successful, key=lambda r: r.finished_at):
            left, right = (
                max(start, run.finished_at),
                min(end, run.finished_at + timedelta(seconds=horizon)),
            )
            if right <= left:
                continue
            if intervals and left <= intervals[-1][1]:
                intervals[-1][1] = max(right, intervals[-1][1])
            else:
                intervals.append([left, right])
        covered = sum((right - left).total_seconds() for left, right in intervals)
        items.append(
            {
                "target_id": target.id,
                "config_hash": target.fingerprint,
                "success_runs": len(successful),
                "failed_runs": sum(r.status in {"failed", "interrupted"} for r in runs),
                "freshness_horizon_seconds": horizon,
                "freshness_covered_seconds": round(covered, 3),
                "freshness_coverage": round(covered / (hours * 3600), 6),
                "intervals": [
                    {"from": left.isoformat(), "to": right.isoformat()} for left, right in intervals
                ],
            }
        )
    return {
        "schema_version": "monitoring-window-v1",
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "hours": hours,
        "targets": items,
        "status": "observed_window_covered"
        if items and all(r["freshness_coverage"] == 1 for r in items)
        else "insufficient_coverage",
        "process_uptime_measured": False,
        "publication_latency_sla_proven": False,
        "note": "Coverage uses successful polls and two configured intervals. It is not worker uptime, source availability or a <=6h publication SLA.",
    }
