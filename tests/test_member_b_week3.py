import copy
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from zhidu.answers import structured_constraints
from zhidu.api import create_app
from zhidu.enrichment import ENRICHMENT_SCHEMA_VERSION
from zhidu.evaluation import EvaluationSuite, evaluate
from zhidu.ingest import ingest_document
from zhidu.models import now_utc
from zhidu.sources import SOURCES


def relevant(advisory):
    data = copy.deepcopy(advisory)
    data["summary"] = "vLLM security vulnerability and authentication bypass"
    data["description"] = "vLLM has an authentication bypass security vulnerability."
    data["vulnerabilities"][0]["package"]["name"] = "vllm"
    return data


def ingest(database, store, data, source="github-advisories"):
    with database.begin() as session:
        return ingest_document(
            session,
            store,
            json.dumps(data).encode(),
            f"offline://member-b-week3/{source}",
            now_utc(),
            "live",
            spec=SOURCES[source],
        )


@pytest.fixture
def api(settings, database):
    with TestClient(create_app(settings)) as client:
        yield client


def test_structured_entity_and_quality_filters_are_exact(api, database, store, advisory):
    data = relevant(advisory)
    data["vulnerabilities"][0]["vulnerable_version_range"] = "1.0 || 2.0"
    ingest(database, store, data)

    response = api.get(
        "/api/v1/retrieval/search",
        params={
            "q": "authentication",
            "pool": "formal",
            "entity_type": "cve",
            "entity_value": data["cve_id"].lower(),
            "quality_flag": "unparsed_version_range",
        },
    )
    assert response.status_code == 200
    result = response.json()
    assert result["total"] > 0
    assert result["method"] == "lexical-v3-structured"
    assert {item["external_id"] for item in result["items"]} == {data["ghsa_id"]}

    missing = api.get(
        "/api/v1/retrieval/search",
        params={
            "q": "authentication",
            "entity_type": "cve",
            "entity_value": "CVE-2000-0000",
        },
    )
    assert missing.json()["total"] == 0
    assert (
        api.get(
            "/api/v1/retrieval/search", params={"q": "authentication", "entity_type": "cve"}
        ).status_code
        == 422
    )


def test_quality_flags_force_uncertainty_and_are_snapshotted(api, database, store, advisory):
    data = relevant(advisory)
    data["vulnerabilities"][0]["vulnerable_version_range"] = "=< 1.0.0"
    ingest(database, store, data)
    headers = {"X-Admin-Key": "test-admin"}
    audit = api.post(
        "/api/v1/answers/extractive",
        json={"question": "哪些版本受影响？", "query": "authentication bypass"},
        headers=headers,
    ).json()
    codes = {item["code"] for item in audit["constraints"]}
    assert "unparsed_version_range" in codes
    assert "不确定性说明" in audit["answer"]
    assert "unparsed_version_range" in audit["citations"][0]["quality_flags"]
    assert audit["citations"][0]["enrichment_schema_version"] == ENRICHMENT_SCHEMA_VERSION

    event_id = audit["citations"][0]["event_id"]
    constraints = api.get(f"/api/v1/answer-constraints/{event_id}").json()
    assert "unparsed_version_range" in constraints["quality_flags"]
    assert constraints["enrichment_schema_version"] == ENRICHMENT_SCHEMA_VERSION


def test_no_evidence_question_is_refused_and_audited(api):
    response = api.post(
        "/api/v1/answers/extractive",
        json={"question": "不存在的记录是什么？", "query": "zzzznosuchrecord20999999"},
        headers={"X-Admin-Key": "test-admin"},
    )
    assert response.status_code == 200
    audit = response.json()
    assert audit["status"] == "no_evidence"
    assert audit["prompt_version"] == "evidence-packet-v3"
    assert audit["citations"] == []
    assert audit["constraints"][0]["code"] == "insufficient_evidence"
    assert "不能据此作答" in audit["answer"]


def test_cvss_conflict_and_cpe_condition_have_mandatory_boundaries():
    enrichment = SimpleNamespace(
        schema_version="structured-v1",
        quality_flags=[],
        cvss={
            "selected": {"score": 8.3},
            "entries": [{"score": 6.5}, {"score": 8.3}],
        },
        cpe_matches=[{"criteria": "cpe:2.3:a:vllm:vllm:*:*:*:*:*:*:*:*"}],
    )
    codes = {item["code"] for item in structured_constraints(enrichment)}
    assert codes >= {
        "selected_cvss_display_only",
        "cvss_multiple_scores",
        "cpe_condition_not_asset_match",
    }


def test_week3_evaluation_measures_answerability_and_constraints(database, store, advisory):
    data = relevant(advisory)
    data["vulnerabilities"][0]["vulnerable_version_range"] = "1.0 || 2.0"
    ingest(database, store, data)
    suite = EvaluationSuite.model_validate(
        {
            "version": "week3-test-v1",
            "cases": [
                {
                    "id": "opaque",
                    "question": "哪些版本受影响？",
                    "query": "authentication bypass",
                    "pool": "formal",
                    "expected_external_ids": [data["ghsa_id"]],
                    "expected_constraint_codes": ["unparsed_version_range"],
                    "quality_flag": "unparsed_version_range",
                },
                {
                    "id": "no-answer",
                    "question": "不存在的记录是什么？",
                    "query": "zzzznosuchrecord20999999",
                    "pool": "formal",
                    "expected_status": "no_evidence",
                    "expected_constraint_codes": ["insufficient_evidence"],
                },
            ],
        }
    )
    with database.begin() as session:
        result = evaluate(session, store, suite)
        assert result.hit_rate_at_k == 1
        assert result.answerability_accuracy == 1
        assert result.constraint_pass_rate == 1
        assert result.citation_verifiable_rate == 1
        assert result.hallucination_rate == 0
