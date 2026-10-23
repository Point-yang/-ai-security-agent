import copy
import json

from fastapi.testclient import TestClient
from sqlalchemy import select

from zhidu.api import create_app
from zhidu.asset_evaluation import AssetEvaluationSuite, evaluate_assets
from zhidu.asset_matching import asset_report, import_cyclonedx
from zhidu.comparisons import sync_comparisons
from zhidu.enrichment import ENRICHMENT_SCHEMA_VERSION
from zhidu.ingest import ingest_document
from zhidu.models import AssetExposure, IntelligenceComparison, now_utc
from zhidu.sources import SOURCES


def ingest(database, store, data, source="github-advisories"):
    with database.begin() as session:
        return ingest_document(
            session,
            store,
            json.dumps(data).encode(),
            f"offline://member-b-week4/{source}",
            now_utc(),
            "live",
            spec=SOURCES[source],
        )


def advisory_case(base, ghsa, cve, package, version_range, severity="high"):
    data = copy.deepcopy(base)
    data.update(
        ghsa_id=ghsa,
        cve_id=cve,
        summary=f"vLLM security case {ghsa}",
        description=f"vLLM security authentication bypass {ghsa}",
        severity=severity,
    )
    data["vulnerabilities"][0]["package"]["name"] = package
    data["vulnerabilities"][0]["vulnerable_version_range"] = version_range
    return data


def sbom(version="0.6.2"):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:member-b-week4",
        "components": [
            {
                "type": "library",
                "name": "vllm",
                "version": version,
                "purl": f"pkg:pypi/vllm@{version}",
                "bom-ref": "vllm-demo",
            }
        ],
    }


def prepare_cases(database, store, advisory):
    rows = [
        advisory_case(
            advisory,
            "GHSA-aaaa-bbbb-cccc",
            "CVE-2099-0001",
            "vllm",
            ">= 0.5.0, < 1.0.0",
        ),
        advisory_case(
            advisory,
            "GHSA-dddd-eeee-ffff",
            "CVE-2099-0002",
            "vllm",
            ">= 1.0.0, < 2.0.0",
        ),
        advisory_case(
            advisory,
            "GHSA-1111-2222-3333",
            "CVE-2099-0003",
            "vllm",
            "1.0 || 2.0",
        ),
        advisory_case(
            advisory,
            "GHSA-4444-5555-6666",
            "CVE-2099-0004",
            "other-package",
            ">= 0.1.0",
        ),
    ]
    for row in rows:
        ingest(database, store, row)
    vendor = advisory_case(
        advisory,
        "GHSA-7777-8888-9999",
        "CVE-2099-0001",
        "vllm",
        ">= 0.5.0, < 1.0.0",
        severity="critical",
    )
    vendor["vulnerabilities"][0]["patched_versions"] = ">= 1.0.0"
    ingest(database, store, vendor, "vllm-vendor")
    with database.begin() as session:
        asset, _ = import_cyclonedx(
            session,
            json.dumps(sbom()).encode(),
            asset_name="week4-demo-asset",
            environment="demo",
            criticality="high",
        )
        sync_comparisons(session)
        return asset.id


def test_asset_context_is_explicit_and_snapshotted(database, store, settings, advisory):
    asset_id = prepare_cases(database, store, advisory)
    with database.begin() as session:
        target_event_id = session.scalar(
            select(AssetExposure.event_id).where(
                AssetExposure.asset_id == asset_id,
                AssetExposure.status == "affected",
            )
        )
    with TestClient(create_app(settings)) as client:
        denied = client.post(
            "/api/v1/answers/extractive",
            json={
                "question": "我的资产是否受影响？",
                "query": "authentication bypass GHSA-aaaa-bbbb-cccc",
            },
            headers={"X-Admin-Key": "test-admin"},
        ).json()
        assert denied["status"] == "asset_context_required"
        assert denied["citations"] == []

        answer = client.post(
            "/api/v1/answers/extractive",
            json={
                "question": "我的资产是否受影响？",
                "query": "GHSA-aaaa-bbbb-cccc",
                "asset_id": asset_id,
                "event_id": target_event_id,
                "limit": 1,
            },
            headers={"X-Admin-Key": "test-admin"},
        )
        assert answer.status_code == 200
        audit = answer.json()
        assert audit["prompt_version"] == "evidence-packet-v3"
        assert audit["asset_id"] == asset_id
        assert audit["asset_context"]["asset"]["sbom_sha256"]
        assert audit["asset_context"]["exposures"][0]["status"] == "affected"
        assert audit["citations"][0]["event_id"] == target_event_id
        assert "affected_is_source_condition_match" in {
            item["code"] for item in audit["constraints"]
        }
        assert "no_asset_match" not in {item["code"] for item in audit["constraints"]}
        assert "不代表漏洞已复现" in audit["answer"]

        missing = client.post(
            "/api/v1/answers/extractive",
            json={"question": "我的资产是否受影响？", "asset_id": "missing"},
            headers={"X-Admin-Key": "test-admin"},
        )
        assert missing.status_code == 404

        missing_event = client.post(
            "/api/v1/answers/extractive",
            json={
                "question": "该资产是否受影响？",
                "asset_id": asset_id,
                "event_id": "missing",
            },
            headers={"X-Admin-Key": "test-admin"},
        )
        assert missing_event.status_code == 404


def test_asset_fixed_suite_covers_three_states_absence_and_conflict(database, store, advisory):
    asset_id = prepare_cases(database, store, advisory)
    suite = AssetEvaluationSuite.model_validate(
        {
            "version": "week4-test-v1",
            "asset_name": "week4-demo-asset",
            "cases": [
                {
                    "id": "affected",
                    "kind": "exposure",
                    "component_name": "vllm",
                    "component_version": "0.6.2",
                    "external_id": "GHSA-aaaa-bbbb-cccc",
                    "expected_status": "affected",
                },
                {
                    "id": "not-affected",
                    "kind": "exposure",
                    "component_name": "vllm",
                    "component_version": "0.6.2",
                    "external_id": "GHSA-dddd-eeee-ffff",
                    "expected_status": "not_affected",
                },
                {
                    "id": "unknown",
                    "kind": "exposure",
                    "component_name": "vllm",
                    "component_version": "0.6.2",
                    "external_id": "GHSA-1111-2222-3333",
                    "expected_status": "unknown",
                },
                {
                    "id": "no-identity",
                    "kind": "no_identity",
                    "component_name": "vllm",
                    "component_version": "0.6.2",
                    "external_id": "GHSA-4444-5555-6666",
                    "expected_status": "absent",
                },
                {
                    "id": "severity-conflict",
                    "kind": "comparison",
                    "identifier": "CVE-2099-0001",
                    "field": "severity",
                    "expected_status": "conflict",
                },
            ],
        }
    )
    with database.begin() as session:
        result = evaluate_assets(session, store, suite)
        assert result.asset_id == asset_id
        assert result.status_accuracy == 1
        assert result.evidence_verifiable_rate == 1
        assert result.boundary_pass_rate == 1


def test_conflict_review_is_optimistic_locked_and_survives_rebuild(
    database, store, settings, advisory
):
    prepare_cases(database, store, advisory)
    with database() as session:
        conflict = session.scalar(
            select(IntelligenceComparison).where(
                IntelligenceComparison.identifier == "CVE-2099-0001",
                IntelligenceComparison.field == "severity",
            )
        )
        comparison_id = conflict.id
    with TestClient(create_app(settings)) as client:
        reviewed = client.patch(
            f"/api/v1/comparisons/{comparison_id}/review",
            json={
                "expected_version": 0,
                "review_status": "acknowledged",
                "analyst_note": "两个来源评分不同，保留双方观察，不选择胜方。",
            },
            headers={"X-Admin-Key": "test-admin"},
        )
        assert reviewed.status_code == 200
        assert reviewed.json()["annotation_version"] == 1
        stale = client.patch(
            f"/api/v1/comparisons/{comparison_id}/review",
            json={
                "expected_version": 0,
                "review_status": "needs_evidence",
                "analyst_note": "stale",
            },
            headers={"X-Admin-Key": "test-admin"},
        )
        assert stale.status_code == 409
        assert len(client.get(f"/api/v1/comparisons/{comparison_id}/reviews").json()) == 1

    with database.begin() as session:
        sync_comparisons(session)
        row = session.get(IntelligenceComparison, comparison_id)
        assert row.review_status == "acknowledged"
        assert row.analyst_note.startswith("两个来源")


def test_reproducible_asset_report_has_hash_schema_time_and_limits(
    database, store, settings, advisory
):
    asset_id = prepare_cases(database, store, advisory)
    with database() as session:
        report = asset_report(session, asset_id)
        assert report["report_version"] == "asset-report-v1"
        assert len(report["sbom_sha256"]) == 64
        assert report["enrichment_schema_versions"] == [ENRICHMENT_SCHEMA_VERSION]
        assert report["scan_time"] is not None
        assert report["limitations"]
        assert report["exposures"]
        assert all(item["revision_id"] for item in report["exposures"])

    with TestClient(create_app(settings)) as client:
        response = client.get(f"/api/v1/assets/{asset_id}/report")
        assert response.status_code == 200
        assert response.json()["sbom_sha256"] == report["sbom_sha256"]
