import copy
import json

from fastapi.testclient import TestClient
from sqlalchemy import select

from zhidu.api import create_app
from zhidu.asset_matching import import_cyclonedx
from zhidu.evidence import asset_evidence_graph, event_trace, verify_revision_evidence
from zhidu.ingest import ingest_document
from zhidu.models import EventRevision, IntelEvent, now_utc


def ingest(database, store, payload, fetched_at=None):
    with database.begin() as session:
        return ingest_document(
            session,
            store,
            json.dumps(payload).encode(),
            "offline://member-a-week5",
            fetched_at or now_utc(),
            "replay",
        )


def test_revision_evidence_is_verified_against_exact_raw(database, store, advisory):
    ingest(database, store, advisory)
    with database() as session:
        revision = session.scalar(select(EventRevision))
        result = verify_revision_evidence(session, store, revision)
        assert result["summary"]["failed"] == 0
        assert result["summary"]["verified"] == len(revision.evidence)
        assert all(
            item["expected_value_sha256"] == item["resolved_value_sha256"]
            for item in result["items"]
        )


def test_trace_shows_field_delta_and_current_lineage(database, store, advisory):
    ingest(database, store, advisory)
    changed = copy.deepcopy(advisory)
    changed["updated_at"] = "2026-01-02T08:00:00Z"
    changed["severity"] = "critical"
    changed["vulnerabilities"][0]["first_patched_version"] = "1.2.0"
    ingest(database, store, changed)
    with database() as session:
        event = session.scalar(select(IntelEvent))
        result = event_trace(session, store, event)
        assert result["summary"]["revisions"] == 2
        assert result["summary"]["field_evidence_failed"] == 0
        fields = {
            item["field"] for item in result["timeline"][1]["delta_from_previous_observation"]
        }
        assert {"severity", "packages", "source_updated_at"} <= fields
        assert result["timeline"][1]["is_effective_current"] is True
        assert [row["change_type"] for row in result["audit"][:2]] == ["created", "updated"]


def test_asset_graph_connects_component_event_revision_and_raw(database, store, advisory):
    ingest(database, store, advisory)
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "library",
                "name": "example-ai-demo",
                "version": "1.0.0",
                "purl": "pkg:pypi/example-ai-demo@1.0.0",
            }
        ],
    }
    with database.begin() as session:
        asset, _ = import_cyclonedx(session, json.dumps(sbom).encode(), asset_name="week5-demo")
        asset_id = asset.id
    with database() as session:
        asset = session.get(type(asset), asset_id)
        result = asset_evidence_graph(session, store, asset)
        assert result["summary"]["chains"] == 1
        assert (
            result["summary"]["field_evidence_total"]
            == result["summary"]["field_evidence_verified"]
        )
        chain = result["chains"][0]
        assert chain["component"]["name"] == "example-ai-demo"
        assert chain["event"]["external_id"] == advisory["ghsa_id"]
        assert chain["revision"]["id"]
        assert chain["raw_document"]["sha256"]


def test_week5_trace_api_and_asset_page(database, store, settings, advisory):
    ingest(database, store, advisory)
    with database() as session:
        event_id = session.scalar(select(IntelEvent.id))
    with TestClient(create_app(settings)) as client:
        trace = client.get(f"/api/v1/events/{event_id}/trace")
        assert trace.status_code == 200
        assert trace.json()["summary"]["field_evidence_failed"] == 0
        assert client.get("/api/v1/events/missing/trace").status_code == 404
        page = client.get("/assets")
        assert page.status_code == 200
        assert "证据追溯" in page.text
