import copy
import json

from fastapi.testclient import TestClient
from sqlalchemy import select

from zhidu.api import create_app
from zhidu.enrichment import ENRICHMENT_SCHEMA_VERSION, parse_version_range, sync_enrichments
from zhidu.ingest import ingest_document
from zhidu.models import EventEnrichment, IntelEvent, now_utc
from zhidu.sources import SOURCES


def ingest(database, store, payload, *, source="github-advisories"):
    content = json.dumps(payload).encode()
    with database.begin() as session:
        return ingest_document(
            session,
            store,
            content,
            f"offline://week3/{source}",
            now_utc(),
            "replay",
            spec=SOURCES[source],
        )


def test_version_range_parser_is_conservative():
    parsed = parse_version_range(">= 1.0.0, < 1.2.0")
    assert parsed == {
        "raw": ">= 1.0.0, < 1.2.0",
        "status": "parsed",
        "clauses": [
            {"operator": ">=", "version": "1.0.0"},
            {"operator": "<", "version": "1.2.0"},
        ],
    }
    assert parse_version_range("1.0 || 2.0")["status"] == "opaque"
    assert parse_version_range("unknown")["status"] == "unknown"


def test_github_enrichment_preserves_scope_cvss_and_provenance(database, store, advisory):
    data = copy.deepcopy(advisory)
    data["summary"] = "vLLM security vulnerability"
    data["description"] = "vLLM security input validation vulnerability"
    data["vulnerabilities"][0]["package"]["name"] = "vllm"
    data["cvss"] = {
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
    }
    ingest(database, store, data)
    with database() as session:
        event = session.scalar(select(IntelEvent))
        row = session.get(EventEnrichment, event.id)
        assert row.schema_version == ENRICHMENT_SCHEMA_VERSION
        assert row.revision_id
        assert {item["value"] for item in row.entities} >= {
            "CVE-2099-0001",
            "GHSA-aaaa-bbbb-cccc",
            "vllm",
        }
        assert row.version_ranges[0]["vulnerable"]["status"] == "parsed"
        assert row.cvss["selected"]["score"] == 9.8
        assert any(item["field"] == "packages" for item in row.provenance)


def test_nvd_enrichment_extracts_cpe_and_prefers_primary_cvss(database, store):
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-12345",
                    "published": "2026-01-01T00:00:00.000Z",
                    "lastModified": "2026-01-02T00:00:00.000Z",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "vLLM security vulnerability"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                },
                            }
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vllm_project:vllm:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "test-match",
                                            "versionEndExcluding": "0.8.5",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "references": [],
                }
            }
        ]
    }
    ingest(database, store, payload, source="nvd")
    with database() as session:
        event = session.scalar(select(IntelEvent))
        row = session.get(EventEnrichment, event.id)
        assert row.cvss["selected"]["authority"] == "primary"
        assert row.cpe_matches[0]["version_end_excluding"] == "0.8.5"
        assert row.cpe_matches[0]["json_pointer"].endswith("/cpeMatch/0")
        assert {item["value"] for item in row.entities} >= {"vllm_project", "vllm"}
        assert "missing_cpe_scope" not in row.quality_flags


def test_enrichment_reconciles_current_revision_and_exposes_review_queue(
    database, store, settings, advisory
):
    data = copy.deepcopy(advisory)
    data["summary"] = "vLLM security vulnerability"
    data["description"] = "vLLM security authentication bypass"
    data["vulnerabilities"][0]["package"]["name"] = "vllm"
    ingest(database, store, data)
    with database() as session:
        event = session.scalar(select(IntelEvent))
        first_revision = session.get(EventEnrichment, event.id).revision_id

    data["updated_at"] = "2026-01-03T08:00:00Z"
    data["description"] = "vLLM security authentication bypass updated"
    ingest(database, store, data)
    with database.begin() as session:
        event = session.scalar(select(IntelEvent))
        row = session.get(EventEnrichment, event.id)
        assert row.revision_id != first_revision
        result = sync_enrichments(session, store)
        assert result["changed_events"] == 0
        assert result["coverage"] == 1

    with TestClient(create_app(settings)) as client:
        status = client.get("/api/v1/enrichment/status").json()
        assert status["enriched"] == status["events"] == 1
        detail = client.get(f"/api/v1/events/{event.id}").json()
        assert detail["enrichment"]["revision_id"] == row.revision_id
        queue = client.get("/api/v1/review-queue").json()
        assert queue["total"] == 1
        assert queue["items"][0]["ai_label"] == "relevant"
        assert queue["priority_is_workflow_score_not_risk_probability"] is True
