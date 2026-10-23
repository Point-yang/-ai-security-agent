import copy
import json
from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy import select

from zhidu.api import create_app
from zhidu.asset_matching import (
    evaluate_cpe,
    evaluate_range,
    import_cyclonedx,
    parse_purl,
    scan_assets,
)
from zhidu.comparisons import sync_comparisons
from zhidu.ingest import ingest_document
from zhidu.models import AssetExposure, IntelligenceComparison, now_utc
from zhidu.sources import SOURCES


def ingest(database, store, payload, source="github-advisories"):
    with database.begin() as session:
        return ingest_document(
            session,
            store,
            json.dumps(payload).encode(),
            f"offline://member-a-week4/{source}",
            now_utc(),
            "replay",
            spec=SOURCES[source],
        )


def sbom(version="1.1.0", cpe=None):
    component = {
        "type": "library",
        "name": "vllm",
        "version": version,
        "purl": f"pkg:pypi/vllm@{version}",
        "bom-ref": "vllm-component",
    }
    if cpe:
        component["cpe"] = cpe
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:test",
        "components": [component],
    }


def relevant(advisory, severity="high"):
    data = copy.deepcopy(advisory)
    data["summary"] = "vLLM security vulnerability"
    data["description"] = "vLLM security vulnerability in request processing"
    data["severity"] = severity
    data["vulnerabilities"][0]["package"]["name"] = "vllm"
    data["vulnerabilities"][0]["vulnerable_version_range"] = ">= 1.0.0, < 2.0.0"
    return data


def test_purl_and_version_evaluation_are_bounded():
    assert parse_purl("pkg:pypi/vLLM@1.2.0") == {
        "ecosystem": "pip",
        "name": "vllm",
        "version": "1.2.0",
    }
    assert parse_purl("pkg:npm/%40team/core@2.0.0")["name"] == "@team/core"
    parsed = {
        "status": "parsed",
        "clauses": [
            {"operator": ">=", "version": "1.0.0"},
            {"operator": "<", "version": "2.0.0"},
        ],
    }
    assert evaluate_range("1.5.0", parsed)[0] == "affected"
    assert evaluate_range("2.1.0", parsed)[0] == "not_affected"
    assert evaluate_range("release-next", parsed)[0] == "unknown"
    assert evaluate_range("1.5.0", {"status": "opaque", "clauses": []})[0] == "unknown"
    assert evaluate_range("1.5.0", {"status": "parsed", "clauses": []})[0] == "unknown"


def test_cyclonedx_import_scans_and_replaces_asset_components(database, store, advisory):
    ingest(database, store, relevant(advisory))
    first = json.dumps(sbom("1.1.0")).encode()
    with database.begin() as session:
        asset, result = import_cyclonedx(session, first, asset_name="demo-service")
        assert result["scan"]["status_counts"]["affected"] == 1
        asset_id = asset.id
    with database() as session:
        row = session.scalar(select(AssetExposure))
        assert row.status == "affected"
        assert row.evidence[0]["verification"] == "source_asserted_asset_comparison"

    second = json.dumps(sbom("2.1.0")).encode()
    with database.begin() as session:
        asset, result = import_cyclonedx(session, second, asset_name="demo-service")
        assert asset.id == asset_id
        assert result["created"] is False
        assert result["scan"]["status_counts"]["not_affected"] == 1
        assert scan_assets(session, asset_id)["unchanged"] == 1


def test_cpe_evaluation_requires_identity_and_comparable_version():
    component = SimpleNamespace(
        cpe="cpe:2.3:a:vllm_project:vllm:1.5.0:*:*:*:*:*:*:*", version="1.5.0"
    )
    match = {
        "criteria": "cpe:2.3:a:vllm_project:vllm:*:*:*:*:*:*:*:*",
        "vulnerable": True,
        "version_start_including": "1.0.0",
        "version_end_excluding": "2.0.0",
    }
    assert evaluate_cpe(component, match)[0] == "affected"
    component.cpe = "cpe:2.3:a:other:product:1.5.0:*:*:*:*:*:*:*"
    assert evaluate_cpe(component, match) is None


def test_shared_cve_comparison_marks_severity_conflict_without_resolving(database, store, advisory):
    ghsa = relevant(advisory, "high")
    vendor = relevant(advisory, "critical")
    ingest(database, store, ghsa, "github-advisories")
    ingest(database, store, vendor, "vllm-vendor")
    with database.begin() as session:
        result = sync_comparisons(session)
        assert result["status_counts"]["conflict"] == 1
        row = session.scalar(
            select(IntelligenceComparison).where(IntelligenceComparison.field == "severity")
        )
        assert row.status == "conflict"
        assert {item["value"] for item in row.observations} == {"high", "critical"}
        assert result["automatic_resolution"] is False


def test_asset_and_comparison_api(database, store, settings, advisory):
    ingest(database, store, relevant(advisory))
    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/api/v1/assets/import-cyclonedx",
            json={"asset_name": "api-service", "criticality": "high", "sbom": sbom()},
            headers={"X-Admin-Key": "test-admin"},
        )
        assert response.status_code == 200
        asset = response.json()["asset"]
        assert asset["component_count"] == 1
        assert asset["exposure_counts"]["affected"] == 1
        exposures = client.get(f"/api/v1/assets/{asset['id']}/exposures").json()
        assert exposures["items"][0]["independent_verification"] is False
        assert client.get("/api/v1/assets").json()[0]["name"] == "api-service"
        assert client.get("/api/v1/comparisons").status_code == 200
