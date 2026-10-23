import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from zhidu.api import create_app
from zhidu.ingest import ingest_document
from zhidu.models import IntelEvent, RawDocument, now_utc


@pytest.fixture
def api(settings, database, store, advisory):
    with database.begin() as session:
        ingest_document(
            session, store, json.dumps(advisory).encode(), "offline://test", now_utc(), "replay"
        )
    with TestClient(create_app(settings)) as client:
        yield client


def test_list_detail_history_evidence_roundtrip(api):
    assert api.get("/health").json()["events"] == 1
    items = api.get("/api/v1/events").json()
    assert items["total"] == 1
    event_id = items["items"][0]["id"]
    detail = api.get(f"/api/v1/events/{event_id}").json()
    assert "CVE-2099-0001" in detail["aliases"]
    assert detail["packages"][0]["fixed_version"] is None
    history = api.get(f"/api/v1/events/{event_id}/history").json()
    assert len(history) == 1
    evidence = api.get(f"/api/v1/events/{event_id}/evidence").json()
    assert evidence["items"]
    raw_id = history[0]["raw_document_id"]
    assert api.get(f"/api/v1/raw-documents/{raw_id}").json()["origin"] == "replay"
    assert (
        api.get(f"/api/v1/raw-documents/{raw_id}/content").json()["ghsa_id"]
        == "GHSA-aaaa-bbbb-cccc"
    )


def test_search_filters_and_limits(api):
    assert api.get("/api/v1/events", params={"alias": "CVE-2099-0001"}).json()["total"] == 1
    assert api.get("/api/v1/events", params={"package": "example-ai-demo"}).json()["total"] == 1
    assert api.get("/api/v1/events", params={"severity": "low"}).json()["total"] == 0
    assert api.get("/api/v1/events", params={"q": "%"}).json()["total"] == 0
    assert api.get("/api/v1/events?limit=101").status_code == 422
    assert api.get("/api/v1/events?updated_since=2026-01-01T00:00:00").status_code == 422


def test_not_found(api):
    assert api.get("/api/v1/events/missing").status_code == 404
    assert api.get("/api/v1/raw-documents/missing/content").status_code == 404


def test_annotation_auth_audit_and_optimistic_lock(api):
    event_id = api.get("/api/v1/events").json()["items"][0]["id"]
    path = f"/api/v1/events/{event_id}/annotation"
    body = {"expected_version": 0, "review_status": "in_review", "analyst_note": "核对版本中"}
    assert api.patch(path, json=body).status_code == 401
    assert api.patch(path, json=body, headers={"X-Admin-Key": "wrong"}).status_code == 401
    result = api.patch(path, json=body, headers={"X-Admin-Key": "test-admin"})
    assert result.status_code == 200 and result.json()["annotation_version"] == 1
    assert api.patch(path, json=body, headers={"X-Admin-Key": "test-admin"}).status_code == 409
    assert api.get(f"/api/v1/events/{event_id}/audit").json()[-1]["change_type"] == "annotation"


def test_writes_disabled_without_key(settings, database, api):
    settings.admin_key = ""
    # SecretStr coercion happens during settings construction, not attribute assignment.
    settings = settings.model_validate(settings.model_dump())
    event_id = api.get("/api/v1/events").json()["items"][0]["id"]
    with TestClient(create_app(settings)) as client:
        response = client.patch(
            f"/api/v1/events/{event_id}/annotation",
            json={
                "expected_version": 0,
                "review_status": "verified",
                "analyst_note": "",
            },
        )
        assert response.status_code == 503


def test_corrupt_raw_document_detected(api, database, store):
    with database() as session:
        doc = session.scalar(select(RawDocument))
        raw_id, digest = doc.id, doc.sha256
    store.path_for(digest).write_bytes(b"tampered")
    response = api.get(f"/api/v1/raw-documents/{raw_id}/content")
    assert response.status_code == 503


def test_source_update_preserves_analyst_note(api, database, store, advisory):
    event_id = api.get("/api/v1/events").json()["items"][0]["id"]
    api.patch(
        f"/api/v1/events/{event_id}/annotation",
        json={
            "expected_version": 0,
            "review_status": "in_review",
            "analyst_note": "retain this",
        },
        headers={"X-Admin-Key": "test-admin"},
    )
    advisory["updated_at"] = "2026-01-02T08:00:00Z"
    with database.begin() as session:
        ingest_document(
            session, store, json.dumps(advisory).encode(), "offline://test", now_utc(), "replay"
        )
    with database() as session:
        assert session.get(IntelEvent, event_id).analyst_note == "retain this"


def test_ui_and_openapi(api):
    assert api.get("/").status_code == 200
    assert api.get("/static/app.js").status_code == 200
    spec = api.get("/openapi.json").json()
    assert "EventDetail" in spec["components"]["schemas"]
    assert "/api/v1/events/{event_id}/annotation" in spec["paths"]
