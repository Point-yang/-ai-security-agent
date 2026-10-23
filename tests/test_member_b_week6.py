import copy
import json
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from zhidu.api import create_app
from zhidu.asset_matching import import_cyclonedx
from zhidu.conversations import create_conversation
from zhidu.ingest import ingest_document
from zhidu.models import ChunkEmbedding, IntelEvent, RagRun, RawDocument, SearchChunk, now_utc
from zhidu.rag import RagRequest, RouterConfig, ToolBudget, run_rag
from zhidu.rag_dataset import alias_groups, freeze_dataset, load_frozen
from zhidu.semantic import LocalEncoder, ModelUnavailable, retrieve, sync_embeddings


class FakeEncoder:
    """Test vectors only; never included in measured semantic benchmark."""

    def encode(self, texts, timeout=15):
        return [[1.0, 0.0] for _ in texts]


@pytest.fixture
def corpus(database, store, advisory, monkeypatch):
    advisory["summary"] = "vLLM security input validation"
    advisory["vulnerabilities"][0]["package"]["name"] = "vllm"
    with database.begin() as session:
        ingest_document(
            session, store, json.dumps(advisory).encode(), "offline://week6", now_utc(), "live"
        )
        event = session.scalar(select(IntelEvent))
        eid = event.id
    monkeypatch.setattr(
        "zhidu.semantic.model_manifest",
        lambda *a, **kw: {"digest": "test-only", "dimension": 2, "model": "test-only", "files": {}},
    )
    return eid


def test_embedding_is_removed_in_same_revision_transaction(
    database, store, advisory, settings, corpus
):
    with database.begin() as session:
        sync_embeddings(session, settings, FakeEncoder())
        old = set(session.scalars(select(ChunkEmbedding.chunk_id)))
        changed = copy.deepcopy(advisory)
        changed["updated_at"] = "2026-01-03T08:00:00Z"
        changed["description"] += " changed source"
        ingest_document(
            session, store, json.dumps(changed).encode(), "offline://week6", now_utc(), "live"
        )
        assert not old & set(session.scalars(select(ChunkEmbedding.chunk_id)))
        with pytest.raises(ModelUnavailable, match="索引未覆盖"):
            retrieve(session, "security", "hybrid", settings, FakeEncoder())
        sync_embeddings(session, settings, FakeEncoder())
        hits, _ = retrieve(session, "security", "hybrid", settings, FakeEncoder())
        assert hits and all(h.citation.revision == 2 for h in hits)


def test_wrong_content_or_model_never_served(database, settings, corpus):
    with database.begin() as session:
        sync_embeddings(session, settings, FakeEncoder())
        session.scalar(select(ChunkEmbedding)).content_sha256 = "changed"
        session.flush()
        with pytest.raises(ModelUnavailable):
            retrieve(session, "test", "hybrid", settings, FakeEncoder())


def test_agent_budget_timeout_and_model_unavailable(database, settings, store, corpus):
    with database.begin() as session:
        request = RagRequest(question="来源说明什么？", query="GHSA-aaaa-bbbb-cccc", mode="agentic")
        sync_embeddings(session, settings, FakeEncoder())
        result = run_rag(
            session, store, settings, request, FakeEncoder(), RouterConfig(max_tools=1)
        )
        assert result["reason"] == "tool_budget_exceeded"
        assert result["citations"] == []

        class Unavailable(FakeEncoder):
            def encode(self, texts, timeout=15):
                raise ModelUnavailable("offline")

        result = run_rag(session, store, settings, request, Unavailable(), RouterConfig())
        assert result["answer_class"] == "unavailable"
        assert result["reason"] == "model_unavailable"

        class Slow(FakeEncoder):
            def encode(self, texts, timeout=15):
                raise TimeoutError("hard inference limit")

        result = run_rag(session, store, settings, request, Slow(), RouterConfig())
        assert result["reason"] == "timeout" and not result["citations"]


def test_deadline_checked_after_tool():
    ticks = [0.0]
    budget = ToolBudget(RouterConfig(timeout_ms=10), clock=lambda: ticks[0])

    def work():
        ticks[0] = 1

    with pytest.raises(TimeoutError):
        budget.call("tool", {}, work)
    assert budget.steps[0]["status"] == "failed"


def test_raw_corruption_is_distinct_from_model_unavailable(database, settings, store, corpus):
    with database() as session:
        document = session.scalar(select(RawDocument))
        store.path_for(document.sha256).write_text("{}")
        result = run_rag(
            session,
            store,
            settings,
            RagRequest(question="来源", query="GHSA-aaaa-bbbb-cccc", mode="lexical"),
            FakeEncoder(),
            RouterConfig(),
        )
        assert result["reason"] == "evidence_missing" and not result["citations"]


def test_supplement_path_and_citation_contract(database, settings, store, corpus):
    with database.begin() as session:
        sync_embeddings(session, settings, FakeEncoder())
        result = run_rag(
            session,
            store,
            settings,
            RagRequest(question="来源证据？", query="GHSA-aaaa-bbbb-cccc"),
            FakeEncoder(),
            RouterConfig(),
        )
        assert "supplement" in [x["tool"] for x in result["tools"]]
        assert len(result["hops"]) == 5
        for citation in result["citations"]:
            assert all(
                key in citation
                for key in (
                    "event_id",
                    "revision_id",
                    "raw_document_id",
                    "json_pointer",
                    "start",
                    "end",
                    "sha256",
                )
            )
        assert all(
            t["network_verification_status"] == "not_started" for t in result["evidence_tasks"]
        )


def test_explicit_asset_and_conversation_isolation(database, settings, store, corpus):
    with database.begin() as session:
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
        a, _ = import_cyclonedx(session, json.dumps(sbom).encode(), asset_name="asset-a")
        b, _ = import_cyclonedx(session, json.dumps(sbom).encode(), asset_name="asset-b")
        conversation = create_conversation(session, "isolated", a.id)
        base = {
            "question": "我的资产是否受影响？",
            "query": "GHSA-aaaa-bbbb-cccc",
            "mode": "lexical",
        }
        refused = run_rag(
            session, store, settings, RagRequest(**base), FakeEncoder(), RouterConfig()
        )
        assert refused["reason"] == "explicit_asset_required"
        inherited = run_rag(
            session,
            store,
            settings,
            RagRequest(**base, conversation_id=conversation.id),
            FakeEncoder(),
            RouterConfig(),
        )
        assert inherited["asset_context"]["asset"]["id"] == a.id
        switched = run_rag(
            session,
            store,
            settings,
            RagRequest(**base, conversation_id=conversation.id, asset_id=b.id),
            FakeEncoder(),
            RouterConfig(),
        )
        assert switched["asset_context"]["asset"]["id"] == b.id
        assert (
            conversation.active_asset_id == a.id
        )  # RAG audit does not mutate the session context.
        base["question"] = "另一个资产是否受影响？"
        denied = run_rag(
            session,
            store,
            settings,
            RagRequest(**base, conversation_id=conversation.id),
            FakeEncoder(),
            RouterConfig(),
        )
        assert denied["reason"] == "explicit_asset_required"


def test_group_freeze_rejects_mutation(database, store, advisory, corpus, tmp_path):
    from zhidu.models import EventAlias

    with database.begin() as session:
        second = copy.deepcopy(advisory)
        second["ghsa_id"] = "GHSA-1111-2222-3333"
        second["cve_id"] = "CVE-2099-0002"
        ingest_document(
            session, store, json.dumps(second).encode(), "offline://second", now_utc(), "live"
        )
        other = session.scalar(select(IntelEvent).where(IntelEvent.id != corpus))
        session.add(EventAlias(event_id=other.id, value=advisory["cve_id"]))
        session.flush()
        groups = alias_groups(session)
        assert groups[corpus]["group_id"] == groups[other.id]["group_id"]
        assert groups[corpus]["split"] == groups[other.id]["split"]
        data = freeze_dataset(session, {"records": []})
        file = tmp_path / "frozen.json"
        file.write_text(json.dumps(data))
        assert load_frozen(file, session)["official_scores"] is None
        data["version"] = "tampered"
        file.write_text(json.dumps(data))
        with pytest.raises(ValueError, match="modified"):
            load_frozen(file, session)


def test_api_auth_and_durable_audit(database, store, settings, corpus):
    with TestClient(create_app(settings)) as client:
        request = {"question": "我的资产是否受影响？", "mode": "lexical"}
        assert client.post("/api/v1/rag/answers", json=request).status_code == 401
        response = client.post(
            "/api/v1/rag/answers", json=request, headers={"X-Admin-Key": "test-admin"}
        )
        assert response.status_code == 200
        assert response.json()["answer_class"] == "refused"
    with database() as session:
        audit = session.get(RagRun, response.json()["id"])
        assert audit.result["answer_class"] == "refused"


def test_encoder_queue_timeout_is_bounded(settings):
    encoder = LocalEncoder(settings)
    encoder.lock.acquire()
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            encoder.encode(["test"], timeout=0.01)
    finally:
        encoder.lock.release()
    assert time.monotonic() - started < 0.5


def sleeping_worker(pipe, manifest):
    time.sleep(10)


def test_encoder_timeout_terminates_child(settings, monkeypatch):
    monkeypatch.setattr("zhidu.semantic.model_manifest", lambda *a, **kw: {"digest": "test"})
    monkeypatch.setattr("zhidu.semantic._worker", sleeping_worker)
    encoder = LocalEncoder(settings)
    with pytest.raises(TimeoutError):
        encoder.encode(["test"], timeout=0.02)
    assert encoder.process is None and encoder.pipe is None


def test_route_switches_and_pool_isolation(database, settings, store, corpus):
    with database.begin() as session:
        sync_embeddings(session, settings, FakeEncoder())
        request = RagRequest(
            question="来源证据？", query="GHSA-aaaa-bbbb-cccc", context_mode="baseline"
        )
        result = run_rag(
            session,
            store,
            settings,
            request,
            FakeEncoder(),
            RouterConfig(supplement=False, trace=False),
        )
        assert [t["tool"] for t in result["tools"]] == [
            "retrieve",
            "source_context",
            "citation_check",
        ]
        assert all(c["field"] == "description" for c in result["citations"])
        assert result["hops"] == []
        for chunk in session.scalars(select(SearchChunk)):
            chunk.pool = "candidate"
        session.flush()
        assert (
            retrieve(session, request.query, "lexical", settings, FakeEncoder(), pool="formal")[0]
            == []
        )
        hits, _ = retrieve(
            session, request.query, "hybrid", settings, FakeEncoder(), pool="candidate"
        )
        assert hits and all(h.pool == "candidate" for h in hits)
