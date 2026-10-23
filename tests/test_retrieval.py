import json

import pytest
from fastapi.testclient import TestClient

from zhidu.api import create_app
from zhidu.ingest import ingest_document
from zhidu.models import now_utc
from zhidu.retrieval import terms


@pytest.fixture
def api(settings, database):
    with TestClient(create_app(settings)) as client:
        yield client


def ingest(database, store, advisory, origin="live", as_list=False):
    with database.begin() as session:
        return ingest_document(
            session,
            store,
            json.dumps([advisory] if as_list else advisory).encode(),
            "offline://retrieval-test",
            now_utc(),
            origin,
        )


def search(api, query, **params):
    response = api.get("/api/v1/retrieval/search", params={"q": query, **params})
    assert response.status_code == 200
    return response.json()


def test_description_chunks_resolve_to_raw_fields(api, database, store, advisory):
    advisory["description"] = "a " * 900 + "unique evidence retrieval needle" + " z" * 600
    ingest(database, store, advisory, as_list=True)
    result = search(api, "needle")
    assert result["total"] > 0
    assert result["scanned_events"] == 1
    assert result["method"] == "lexical-v3-structured"
    hit = result["items"][0]
    assert hit["field"] == "description"
    citation = hit["citation"]
    assert citation["json_pointer"] == "/0/description"
    raw = api.get(f"/api/v1/raw-documents/{citation['raw_document_id']}/content")
    assert raw.headers["etag"] == f'"{citation["sha256"]}"'
    assert raw.json()[0]["description"][hit["start"] : hit["end"]] == hit["text"]
    assert citation["revision"] == 1
    assert citation["verification"] == "source_asserted"
    assert search(api, "needle")["items"] == result["items"]


def test_current_revision_only_and_old_citation_survives(api, database, store, advisory):
    advisory["description"] = "oldneedle"
    ingest(database, store, advisory)
    old = search(api, "oldneedle")["items"][0]["citation"]
    advisory["description"] = "newneedle"
    advisory["updated_at"] = "2026-01-03T08:00:00Z"
    ingest(database, store, advisory)
    advisory["description"] = "conflictneedle"
    ingest(database, store, advisory)
    advisory["description"] = "staleneedle"
    advisory["updated_at"] = "2026-01-02T08:00:00Z"
    ingest(database, store, advisory)
    for query in ["oldneedle", "conflictneedle", "staleneedle"]:
        assert search(api, query)["total"] == 0
    assert search(api, "newneedle")["items"][0]["citation"]["revision"] == 2
    assert (
        api.get(f"/api/v1/raw-documents/{old['raw_document_id']}/content").json()["description"]
        == "oldneedle"
    )
    chunks = api.get(f"/api/v1/retrieval/events/{old['event_id']}").json()
    assert {chunk["citation"]["revision"] for chunk in chunks} == {2}


def test_replay_and_withdrawn_are_explicit(api, database, store, advisory):
    advisory["description"] = "isolatedneedle"
    ingest(database, store, advisory, origin="replay")
    assert search(api, "isolatedneedle")["total"] == 0
    assert search(api, "isolatedneedle", origin="replay")["total"] == 1
    advisory["updated_at"] = "2026-01-03T08:00:00Z"
    advisory["withdrawn_at"] = "2026-01-03T08:00:00Z"
    ingest(database, store, advisory, origin="replay")
    assert search(api, "isolatedneedle", origin="replay")["total"] == 0
    result = search(api, "isolatedneedle", origin="replay", include_withdrawn=True)
    assert result["items"][0]["withdrawn"] is True


def test_filters_ids_packages_chinese_and_pagination(api, database, store, advisory):
    advisory["description"] = "模型存在提示注入风险。安全审查需要证据。"
    ingest(database, store, advisory)
    assert search(api, "提示注入")["items"][0]["field"] == "description"
    assert search(api, "CVE-2099-0001")["items"][0]["field"] == "cve_id"
    assert search(api, "example-ai-demo")["items"][0]["field"] == "packages"
    assert search(api, "提示注入", package="nonexistent")["total"] == 0
    assert search(api, "提示注入", severity="low")["total"] == 0
    result = search(api, "example-ai-demo 提示注入", limit=1)
    assert result["total"] >= 2 and len(result["items"]) == 1
    second = search(api, "example-ai-demo 提示注入", limit=1, offset=1)
    assert second["items"][0]["chunk_id"] != result["items"][0]["chunk_id"]
    assert search(api, "totallyabsent")["total"] == 0
    assert search(api, "%")["total"] == 0


def test_empty_database_validation_and_workspace(api):
    assert search(api, "vllm")["scanned_events"] == 0
    for params in [{}, {"q": " "}, {"q": "x", "limit": 101}, {"q": "x", "origin": "all"}]:
        assert api.get("/api/v1/retrieval/search", params=params).status_code == 422
    assert api.get("/api/v1/retrieval/events/missing").status_code == 404
    assert api.get("/workspace").status_code == 200
    assert api.get("/static/workspace.js").status_code == 200
    assert "/api/v1/retrieval/search" in api.get("/openapi.json").json()["paths"]


def test_compound_words_match_components_but_identifiers_remain_precise(
    api, database, store, advisory
):
    advisory["description"] = "Audio decompression-bomb through load_audio."
    ingest(database, store, advisory)
    for query in ["decompression", "bomb", "load", "audio"]:
        assert any(hit["field"] == "description" for hit in search(api, query)["items"])
    assert search(api, "CVE-2099-9999")["total"] == 0
    assert terms("CVE-2099-0001") == {"cve-2099-0001"}
