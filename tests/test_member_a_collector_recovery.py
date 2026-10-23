"""Transport outages are diagnosable and recover without rewinding source state."""

import json
from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from test_week2 import NOW, Pages, fixtures

from zhidu.api import create_app
from zhidu.collector import CollectionError, GitHubCollector
from zhidu.models import MonitorState, SyncState
from zhidu.monitor import SourceHTTP, Target, failure_retry_seconds, sync_target
from zhidu.sources import SOURCES


class OfflinePages:
    def pages(self, target, start, end, validators):
        raise CollectionError(f"{target.source}: network failure after 3 attempts (ConnectTimeout)")
        yield  # pragma: no cover


def test_transport_error_uses_bounded_retry_but_http_limit_keeps_existing_backoff():
    target = Target(id="retry", source="nvd", interval_seconds=21600)
    assert failure_retry_seconds(target, 1, "nvd: network failure after 3 attempts") == 120
    assert failure_retry_seconds(target, 10, "nvd: network failure after 3 attempts") == 1800
    assert failure_retry_seconds(target, 10, "nvd: HTTP 429 after retries") == 21600


def test_failure_then_success_resets_state_without_advancing_failed_watermark(
    database, settings, advisory
):
    target = Target(id="kev-retry", source="cisa-kev", interval_seconds=3600)
    failed = sync_target(database, settings, target, transport=OfflinePages(), clock=lambda: NOW)
    assert failed["status"] == "failed"
    with database() as session:
        state = session.get(MonitorState, target.id)
        assert state.failures == 1
        assert state.next_run_at == NOW + timedelta(seconds=120)
        assert session.get(SyncState, f"monitor:{target.id}:{target.fingerprint[:16]}") is None
    content = json.dumps(fixtures(advisory)["cisa-kev"]).encode()
    succeeded = sync_target(
        database,
        settings,
        target,
        transport=Pages(content),
        clock=lambda: NOW + timedelta(seconds=120),
    )
    assert succeeded["status"] == "completed"
    with database() as session:
        state = session.get(MonitorState, target.id)
        assert state.failures == 0
        assert state.last_success_at == NOW + timedelta(seconds=120)


def test_sanitized_transport_diagnostics_omit_exception_details(settings):
    def fail(request):
        raise httpx.ConnectTimeout("private upstream URL and token", request=request)

    with httpx.Client(transport=httpx.MockTransport(fail)) as client:
        source = SourceHTTP(settings, client, sleeper=lambda _: None)
        with pytest.raises(CollectionError) as exc:
            source.request(client, "nvd", SOURCES["nvd"].base_url)
        assert "ConnectTimeout" in str(exc.value)
        assert "private" not in str(exc.value)
        github = GitHubCollector(settings, client=client, sleeper=lambda _: None)
        with pytest.raises(CollectionError) as exc:
            list(github.pages("vllm", "pip", NOW - timedelta(days=1), NOW, 1))
        assert "ConnectTimeout" in str(exc.value)
        assert "private" not in str(exc.value)


def test_monitoring_window_api_is_readonly_and_preserves_sla_boundary(database, settings):
    with TestClient(create_app(settings)) as client:
        response = client.get("/api/v1/monitoring/window?hours=24")
        assert response.status_code == 200
        report = response.json()
        assert report["status"] == "insufficient_coverage"
        assert report["publication_latency_sla_proven"] is False
        assert report["process_uptime_measured"] is False
        assert client.get("/api/v1/monitoring/window?hours=169").status_code == 422
