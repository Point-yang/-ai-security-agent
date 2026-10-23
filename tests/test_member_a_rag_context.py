import copy
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from zhidu.api import create_app
from zhidu.evaluation import verify_hit
from zhidu.indexing import chunk_view, search_index, sync_index
from zhidu.ingest import ingest_document
from zhidu.models import ChunkEmbedding, IntelEvent, RagRun, SearchChunk, now_utc
from zhidu.rag import RagRequest, run_rag
from zhidu.rag_context import citation_freshness, expand_evidence_context
from zhidu.retrieval import RetrievalHit
from zhidu.sources import SOURCES


def ingest(database, store, item, source="github-advisories", origin="live"):
    with database.begin() as s:
        ingest_document(
            s,
            store,
            json.dumps(item).encode(),
            "offline://context-test",
            now_utc(),
            origin,
            spec=SOURCES[source],
        )


def fixture_advisory(advisory):
    item = copy.deepcopy(advisory)
    item["summary"] = "vLLM security input validation"
    item["description"] = (
        "vLLM input validation. "
        + "Background information. " * 130
        + "\n## Patches\nUpgrade to 1.2.0 to fix this vulnerability.\n"
    )
    item["vulnerabilities"][0]["package"]["name"] = "vllm"
    item["vulnerabilities"][0]["first_patched_version"] = "1.2.0"
    item["references"] = ["https://example.org/security/patch-123"]
    return item


def answer(session, store, settings, **kwargs):
    return run_rag(
        session,
        store,
        settings,
        RagRequest(
            question="影响哪些版本，如何修复？",
            query="GHSA-aaaa-bbbb-cccc",
            mode="lexical",
            generation="extractive",
            **kwargs,
        ),
        None,
    )


def test_context_contains_late_repair_package_reference_and_verifiable_spans(
    database, store, advisory, settings
):
    ingest(database, store, fixture_advisory(advisory))
    with database() as s:
        baseline = answer(s, store, settings, context_mode="baseline")
        result = answer(s, store, settings)
        assert "Upgrade to 1.2.0" not in " ".join(c["text"] for c in baseline["citations"])
        by_field = {c["field"] for c in result["citations"]}
        assert {"title", "description", "packages", "references"} <= by_field
        assert any("Upgrade to 1.2.0" in c["text"] for c in result["citations"])
        assert result["context"]["sources"][0]["has_structured_patch_field"]
        assert len({c["chunk_id"] for c in result["citations"]}) == len(result["citations"])
        for c in result["citations"]:
            row = s.get(SearchChunk, c["chunk_id"])
            assert verify_hit(
                s, store, RetrievalHit(**chunk_view(row).model_dump(), score=0, matched_terms=[])
            )


def test_related_source_conflict_preserved_and_explicit_event_scoped(
    database, store, advisory, settings
):
    first = fixture_advisory(advisory)
    ingest(database, store, first)
    second = copy.deepcopy(first)
    second["vulnerabilities"][0]["first_patched_version"] = "1.3.0"
    ingest(database, store, second, source="vllm-vendor")
    unrelated = copy.deepcopy(first)
    unrelated.update(ghsa_id="GHSA-dddd-eeee-ffff", cve_id="CVE-2099-7777")
    ingest(database, store, unrelated)
    with database() as s:
        result = answer(s, store, settings, top_k=1)
        assert len(result["context"]["sources"]) == 2
        assert len(result["context"]["relations"]) == 1
        assert result["context"]["source_conflicts_auto_resolved"] is False
        texts = [c["text"] for c in result["citations"] if c["field"] == "packages"]
        assert any("1.2.0" in t for t in texts) and any("1.3.0" in t for t in texts)
        eid = result["context"]["sources"][0]["event_id"]
        scoped = answer(s, store, settings, event_id=eid)
        assert {c["event_id"] for c in scoped["citations"]} == {eid}
        assert scoped["context"]["relations"] == []


def test_revision_update_removes_old_vectors_and_stale_context(database, store, advisory, settings):
    item = fixture_advisory(advisory)
    ingest(database, store, item)
    with database.begin() as s:
        old = answer(s, store, settings)
        first = s.scalar(select(SearchChunk).where(SearchChunk.field == "description"))
        seed = RetrievalHit(**chunk_view(first).model_dump(), score=1, matched_terms=[])
        s.add(
            ChunkEmbedding(
                chunk_id=first.id, model_key="fixture", content_sha256="fixture", vector=[1]
            )
        )
    updated = copy.deepcopy(item)
    updated.update(updated_at="2026-01-04T00:00:00Z", description="The current fix is 1.4.0.")
    updated["vulnerabilities"][0]["first_patched_version"] = "1.4.0"
    ingest(database, store, updated)
    with database() as s:
        assert s.get(ChunkEmbedding, seed.chunk_id) is None
        stale, _ = expand_evidence_context(s, [seed], "修复", pool="formal", origin="live")
        assert stale == []
        assert {v["status"] for v in citation_freshness(s, old["citations"])} == {"superseded"}
        current = answer(s, store, settings)
        assert {c["revision"] for c in current["citations"]} == {2}
        assert all(
            "1.2.0" not in c["text"] for c in current["citations"] if c["field"] == "description"
        )


def test_tampered_index_rebuilt_even_when_ids_unchanged(database, store, advisory, settings):
    ingest(database, store, fixture_advisory(advisory))
    with database.begin() as s:
        row = s.scalar(select(SearchChunk).where(SearchChunk.field == "description"))
        original = row.text
        row.text = "tampered"
        s.flush()
        result = sync_index(s)
        assert result["changed_events"] == 1
        s.expire_all()
        assert s.get(SearchChunk, row.id).text == original
        assert sync_index(s)["changed_events"] == 0


def test_withdrawn_never_returned_even_with_stale_chunk_flag(database, store, advisory, settings):
    item = fixture_advisory(advisory)
    ingest(database, store, item)
    with database.begin() as s:
        old = answer(s, store, settings)
        s.scalar(select(IntelEvent)).withdrawn_at = now_utc()
    with database() as s:
        assert search_index(s, "vllm")[0] == []
        assert answer(s, store, settings)["citations"] == []
        assert citation_freshness(s, old["citations"])[0]["status"] == "withdrawn"


def test_context_preview_never_calls_cloud_or_persists_run(
    database, store, advisory, settings, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    monkeypatch.setattr(
        "zhidu.generation.apply_generation",
        lambda *a, **kw: pytest.fail("read-only preview must not call model"),
    )
    settings.llm_provider = "deepseek"
    with TestClient(create_app(settings)) as client:
        body = {
            "question": "修复版本？",
            "query": "GHSA-aaaa-bbbb-cccc",
            "mode": "lexical",
            "generation": "deepseek",
        }
        assert client.post("/api/v1/rag/context", json=body).status_code == 401
        r = client.post("/api/v1/rag/context", json=body, headers={"X-Admin-Key": "test-admin"})
        assert r.status_code == 200
        assert r.json()["context"]["sources"]
        assert r.json()["cost"]["external_requests"] == 0
    with database() as s:
        assert s.scalar(select(func.count()).select_from(RagRun)) == 0


def test_raw_corruption_blocks_expanded_context(database, store, advisory, settings):
    ingest(database, store, fixture_advisory(advisory))
    with database() as s:
        row = s.scalar(select(SearchChunk))
        store.path_for(row.sha256).write_bytes(b"corrupted")
        result = answer(s, store, settings)
        assert result["reason"] == "evidence_missing"
        assert not result["citations"]


def test_context_budgets_and_candidate_isolation(database, store, advisory, settings, monkeypatch):
    item = fixture_advisory(advisory)
    ingest(database, store, item)
    clone = copy.deepcopy(item)
    ingest(database, store, clone, source="vllm-vendor", origin="replay")
    monkeypatch.setattr("zhidu.rag_context.MAX_CITATIONS", 2)
    monkeypatch.setattr("zhidu.rag_context.MAX_CONTEXT_CHARS", 1000)
    with database() as s:
        r = answer(s, store, settings, top_k=1)
        assert r["context"]["citations"] <= 2 and r["context"]["text_chars"] <= 1000
        assert r["context"]["truncated"] is True
        assert all(c["origin"] == "live" for c in r["citations"])
        assert len(r["context"]["sources"]) == 1


def test_conversation_freshness_does_not_rewrite_history(database, store, advisory, settings):
    item = fixture_advisory(advisory)
    ingest(database, store, item)
    headers = {"X-Admin-Key": "test-admin"}
    with TestClient(create_app(settings)) as client:
        cid = client.post(
            "/api/v1/conversations", headers=headers, json={"title": "context freshness"}
        ).json()["id"]
        turn = client.post(
            f"/api/v1/conversations/{cid}/turns",
            headers=headers,
            json={"question": "来源说明？", "query": "GHSA-aaaa-bbbb-cccc", "origin": "live"},
        )
        assert turn.status_code == 200
        before = client.get(f"/api/v1/conversations/{cid}/replay").json()
        status = client.get(f"/api/v1/conversations/{cid}/context-status").json()
        assert status["citations"] and all(c["reusable_as_current"] for c in status["citations"])
        item.update(
            updated_at="2026-01-06T00:00:00Z",
            description="New revision describes a different patch.",
        )
        ingest(database, store, item)
        status = client.get(f"/api/v1/conversations/{cid}/context-status").json()
        assert all(c["status"] == "superseded" for c in status["citations"])
        after = client.get(f"/api/v1/conversations/{cid}/replay").json()
        assert before["replay_sha256"] == after["replay_sha256"]
