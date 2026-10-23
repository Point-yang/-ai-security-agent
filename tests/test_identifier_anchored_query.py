"""A current identifier scopes retrieval; topic words do not erase its sources."""

import copy

from sqlalchemy import select
from test_member_a_rag_context import fixture_advisory, ingest
from test_member_b_week6 import FakeEncoder

from zhidu.models import ChunkEmbedding, SearchChunk
from zhidu.query_policy import plan_query
from zhidu.semantic import retrieve, sync_embeddings


def test_current_cve_with_technical_query_keeps_only_linked_events(
    database, store, settings, advisory
):
    first = fixture_advisory(advisory)
    ingest(database, store, first)
    other = copy.deepcopy(first)
    other["ghsa_id"], other["cve_id"] = "GHSA-xxxx-yyyy-zzzz", "CVE-2099-9999"
    other["identifiers"] = [{"type": "CVE", "value": other["cve_id"]}]
    ingest(database, store, other)
    with database() as session:
        query = f"{advisory['cve_id']} 对照 GitHub NVD pip preprocess() FileExplorer resolved path"
        plan = plan_query(session, query)
        assert plan.unresolved and plan.anchored_event_ids
        hits, meta = retrieve(
            session, query, "lexical", settings, None, query_rewrite=True, relevance_gate=True
        )
        assert hits and meta["query_policy"]["identifier_anchored"]
        assert {hit.external_id for hit in hits} == {advisory["ghsa_id"]}


def test_unknown_identifier_and_unscoped_unknown_product_do_not_pass(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        for query in ("CVE-2099-999999 对照 GitHub NVD pip", "unknownproductz technical API safe"):
            hits, _ = retrieve(
                session, query, "lexical", settings, None, query_rewrite=True, relevance_gate=True
            )
            assert not hits


def test_unrelated_dense_top_hit_cannot_displace_current_identifier(
    database, store, settings, advisory, monkeypatch
):
    first = fixture_advisory(advisory)
    ingest(database, store, first)
    other = copy.deepcopy(first)
    other["ghsa_id"], other["cve_id"] = "GHSA-xxxx-yyyy-zzzz", "CVE-2099-9999"
    other["identifiers"] = [{"type": "CVE", "value": other["cve_id"]}]
    ingest(database, store, other)
    monkeypatch.setattr(
        "zhidu.semantic.model_manifest",
        lambda *a, **k: {"digest": "test-only", "dimension": 2, "model": "test-only", "files": {}},
    )
    with database.begin() as session:
        sync_embeddings(session, settings, FakeEncoder())
        rows = {row.id: row for row in session.scalars(select(SearchChunk))}
        for vector in session.scalars(select(ChunkEmbedding)):
            vector.vector = (
                [0.0, 1.0]
                if rows[vector.chunk_id].external_id == advisory["ghsa_id"]
                else [1.0, 0.0]
            )
        session.flush()
        hits, meta = retrieve(
            session,
            advisory["ghsa_id"],
            "hybrid",
            settings,
            FakeEncoder(),
            limit=1,
            relevance_gate=True,
        )
        assert len(hits) == 1 and hits[0].external_id == advisory["ghsa_id"]
        assert meta["scanned_chunks"] == sum(
            row.external_id == advisory["ghsa_id"] for row in rows.values()
        )
