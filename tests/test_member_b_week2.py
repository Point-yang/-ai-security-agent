import copy
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from zhidu.answers import source_constraints
from zhidu.api import create_app
from zhidu.evaluation import EvaluationSuite, evaluate
from zhidu.indexing import INDEX_SCHEMA_VERSION, sync_index
from zhidu.ingest import ingest_document
from zhidu.models import (
    AnswerAudit,
    EventTriage,
    IntelEvent,
    SearchChunk,
    SearchIndexState,
    now_utc,
)


def ingest(database, store, advisory, origin="live"):
    with database.begin() as session:
        return ingest_document(
            session,
            store,
            json.dumps(advisory).encode(),
            "offline://member-b-week2",
            now_utc(),
            origin,
        )


def relevant(advisory):
    data = copy.deepcopy(advisory)
    data["summary"] = "vLLM security vulnerability and authentication bypass"
    data["description"] = "vLLM has an authentication bypass security vulnerability."
    data["vulnerabilities"][0]["package"]["name"] = "vllm"
    return data


@pytest.fixture
def api(settings, database):
    with TestClient(create_app(settings)) as client:
        yield client


def test_ingest_persists_pool_version_and_index_state(database, store, advisory):
    data = relevant(advisory)
    ingest(database, store, data)
    with database() as session:
        chunks = session.scalars(select(SearchChunk)).all()
        event = session.scalar(select(IntelEvent))
        state = session.get(SearchIndexState, "lexical")
        assert chunks and state.schema_version == INDEX_SCHEMA_VERSION
        assert state.event_count == 1 and state.chunk_count == len(chunks)
        assert all(
            chunk.pool == "formal"
            and chunk.ai_label == "relevant"
            and chunk.event_id == event.id
            and chunk.revision_number == 1
            and chunk.revision_id
            and chunk.raw_document_id
            and chunk.sha256
            and chunk.json_pointer
            for chunk in chunks
        )


def test_revision_and_withdrawal_replace_index_without_time_cursor(api, database, store, advisory):
    data = relevant(advisory)
    data["description"] = "vLLM oldunique authentication bypass marker."
    ingest(database, store, data)
    with database() as session:
        old_revision_id = session.scalar(select(SearchChunk.revision_id))

    data["updated_at"] = "2026-01-03T08:00:00Z"
    data["description"] = "vLLM newunique authentication bypass marker."
    ingest(database, store, data)
    with database.begin() as session:
        rows = session.scalars(select(SearchChunk)).all()
        assert rows and all(row.revision_number == 2 for row in rows)
        assert all(row.revision_id != old_revision_id for row in rows)
        result = sync_index(session)
        assert result["changed_events"] == 0 and result["unchanged_events"] == 1
    assert api.get("/api/v1/retrieval/search", params={"q": "oldunique"}).json()["total"] == 0
    assert api.get("/api/v1/retrieval/search", params={"q": "newunique"}).json()["total"] > 0

    data["updated_at"] = "2026-01-04T08:00:00Z"
    data["withdrawn_at"] = "2026-01-04T08:00:00Z"
    ingest(database, store, data)
    assert api.get("/api/v1/retrieval/search", params={"q": "newunique"}).json()["total"] == 0
    included = api.get(
        "/api/v1/retrieval/search",
        params={"q": "newunique", "include_withdrawn": True},
    ).json()
    assert included["total"] > 0 and all(item["withdrawn"] for item in included["items"])


def test_reclassification_moves_pools_and_reconciliation_removes_unclassified(
    api, database, store, advisory
):
    data = relevant(advisory)
    ingest(database, store, data)
    event_id = api.get("/api/v1/events").json()["items"][0]["id"]
    with database.begin() as session:
        triage = session.get(EventTriage, event_id)
        triage.label = "needs_review"
        triage.rule_version = "manual-test"
        sync_index(session)
    assert (
        api.get(
            "/api/v1/retrieval/search", params={"q": "authentication", "pool": "formal"}
        ).json()["total"]
        == 0
    )
    assert (
        api.get(
            "/api/v1/retrieval/search", params={"q": "authentication", "pool": "candidate"}
        ).json()["total"]
        > 0
    )
    with database.begin() as session:
        session.delete(session.get(EventTriage, event_id))
        result = sync_index(session)
        assert result["removed_orphan_chunks"] > 0
        assert session.scalar(select(func.count()).select_from(SearchChunk)) == 0


def test_extractive_answer_and_external_audit_keep_immutable_citation_snapshot(
    api, database, store, advisory
):
    data = relevant(advisory)
    ingest(database, store, data)
    headers = {"X-Admin-Key": "test-admin"}
    response = api.post(
        "/api/v1/answers/extractive",
        json={"question": "vLLM 有认证绕过风险吗？", "query": "authentication bypass"},
        headers=headers,
    )
    assert response.status_code == 200
    audit = response.json()
    assert audit["status"] == "completed"
    assert audit["model"] == "extractive-template-v1"
    assert audit["prompt_version"] == "evidence-packet-v3"
    assert audit["citations"][0]["revision_id"]
    assert audit["citations"][0]["retrieval_score"] > 0
    old_revision_id = audit["citations"][0]["revision_id"]

    data["updated_at"] = "2026-01-03T08:00:00Z"
    data["description"] = "vLLM updated authentication bypass security vulnerability."
    ingest(database, store, data)
    saved = api.get("/api/v1/answer-audits").json()[0]
    assert saved["citations"][0]["revision_id"] == old_revision_id
    with database() as session:
        assert session.get(SearchChunk, saved["citations"][0]["chunk_id"]) is None
        assert session.scalar(select(func.count()).select_from(AnswerAudit)) == 1

    missing = api.post(
        "/api/v1/answer-audits",
        json={
            "question": "q",
            "answer": "a",
            "retrieval_query": "q",
            "pool": "formal",
            "model": "external-model",
            "prompt_version": "prompt-v1",
            "citations": [{"chunk_id": "missing", "retrieval_score": 1, "rank": 1}],
        },
        headers=headers,
    )
    assert missing.status_code == 409


def test_fixed_suite_measures_retrieval_citations_and_extractive_grounding(
    database, store, advisory
):
    data = relevant(advisory)
    ingest(database, store, data)
    suite = EvaluationSuite.model_validate(
        {
            "version": "test-v1",
            "cases": [
                {
                    "id": "auth",
                    "question": "Is there an auth bypass?",
                    "query": "authentication bypass",
                    "pool": "formal",
                    "top_k": 5,
                    "expected_external_ids": [data["ghsa_id"]],
                }
            ],
        }
    )
    with database.begin() as session:
        result = evaluate(session, store, suite)
        assert result.hit_rate_at_k == 1
        assert result.citation_verifiable_rate == 1
        assert result.hallucination_rate == 0
        assert result.details[0]["verified_citations"] > 0


@pytest.mark.parametrize(
    ("source_id", "kind", "normalized", "code"),
    [
        ("vllm-vendor", "vulnerability", {}, "vendor_patched_range"),
        ("nvd", "vulnerability", {}, "nvd_unparsed_scope"),
        ("cisa-kev", "exploitation_alert", {}, "kev_date_semantics"),
        ("crossref", "paper", {"publication_precision": "month"}, "publication_precision"),
    ],
)
def test_source_specific_answer_constraints(source_id, kind, normalized, code):
    assert code in {item["code"] for item in source_constraints(source_id, kind, normalized)}
