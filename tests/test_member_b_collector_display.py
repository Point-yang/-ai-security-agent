"""Independent pulse checks and failure/recovery boundaries for B's status UI."""

import os
import time
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select
from test_member_a_collector_recovery import OfflinePages
from test_week2 import Pages, fixtures

from zhidu.api import create_app
from zhidu.models import MonitorState, now_utc
from zhidu.monitor import Target, sync_target
from zhidu.worker_health import worker_snapshot


def test_worker_snapshot_never_uses_target_progress_or_exposes_process_id(tmp_path, monkeypatch):
    path = tmp_path / "collector.heartbeat"
    assert worker_snapshot(path)["status"] == "not_started"
    path.write_text("42")
    monkeypatch.setattr("zhidu.worker_health.os.kill", lambda *_: None)
    result = worker_snapshot(path)
    assert result["status"] == "healthy"
    assert result["target_progress_heartbeat_used"] is False
    assert "pid" not in result and "path" not in result
    os.utime(path, (time.time() - 60, time.time() - 60))
    assert worker_snapshot(path)["status"] == "stale"

    def denied(*_):
        raise PermissionError

    monkeypatch.setattr("zhidu.worker_health.os.kill", denied)
    assert worker_snapshot(path)["status"] == "unverified"


def test_api_ready_with_missing_worker_and_stale_source_then_recovery(
    database, settings, advisory, tmp_path
):
    import json

    config = tmp_path / "targets.json"
    target = Target(id="b-failure-demo", source="cisa-kev", interval_seconds=60)
    config.write_text(json.dumps({"targets": [target.model_dump()]}))
    settings.monitor_config = config
    settings.raw_dir.mkdir(parents=True, exist_ok=True)
    now = now_utc()
    for _ in range(2):
        failure = sync_target(
            database, settings, target, transport=OfflinePages(), clock=lambda: now
        )
        assert failure["status"] == "failed"
    with database.begin() as session:
        session.get(MonitorState, target.id).last_success_at = now - timedelta(days=2)
    with TestClient(create_app(settings)) as client:
        assert client.get("/health/ready").status_code == 200
        assert client.get("/api/v1/monitoring/worker").json()["status"] == "not_started"
        job = client.get("/api/v1/monitoring").json()["targets"][0]
        assert job["status"] == "failed" and job["consecutive_failures"] == 2
        collection = client.get("/api/v1/operations/status").json()["collection"]
        assert collection["targets_fresh"] == 0 and collection["targets_failed"] == 1
        content = json.dumps(fixtures(advisory)["cisa-kev"]).encode()
        sync_target(database, settings, target, transport=Pages(content), clock=lambda: now)
        job = client.get("/api/v1/monitoring").json()["targets"][0]
        assert job["status"] == "completed" and job["consecutive_failures"] == 0
        collection = client.get("/api/v1/operations/status").json()["collection"]
        assert collection["targets_fresh"] == 1 and collection["targets_failed"] == 0
        for hours in (24, 168):
            report = client.get(f"/api/v1/monitoring/window?hours={hours}").json()
            assert report["status"] == "insufficient_coverage"
            assert not report["publication_latency_sla_proven"]
            assert not report["process_uptime_measured"]
    with database() as session:
        assert len(session.scalars(select(MonitorState)).all()) == 1
