"""Generation budgets whole verified source spans, then rechecks source freshness."""

import copy
import json

import httpx
from sqlalchemy import select
from test_member_a_rag_context import fixture_advisory, ingest

from zhidu.agent_result import verify_citations
from zhidu.generation import apply_generation
from zhidu.models import SearchChunk

DESCRIPTION = ("A configured vLLM backend may exhaust memory. " * 30)[:1199] + "."


def cloud(settings):
    return settings.model_copy(
        update={"deepseek_api_key": type(settings.deepseek_api_key)("mock-provider-key")}
    )


def packet_for_rows(rows):
    return {
        "answer_class": "evidence",
        "answer": "原抽取式证据回答。",
        "citations": [
            {"chunk_id": row.id, "external_id": row.external_id, "text": row.text} for row in rows
        ],
        "constraints": [],
        "tools": [],
        "claims": [],
        "cost": {"external_requests": 0},
    }


def sdk_reply(source):
    candidate = {
        "answer_class": "evidence",
        "statements": [
            {
                "text": "来源说明配置相应后端时可能耗尽内存。",
                "evidence": [{"evidence_id": source["evidence_id"]}],
            }
        ],
        "required_facts": ["可能影响"],
        "missing_facts": [],
        "limitations": [],
        "message": "",
    }
    return httpx.Response(
        200,
        json={
            "model": "mock-source-model",
            "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
            "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(candidate)}}],
        },
    )


def test_total_generation_budget_keeps_whole_spans_and_last_reference_verifies(
    database, store, settings, advisory
):
    # Twenty 900-character retrieval chunks fit the existing 18,000-character
    # retrieval context. Expanding each to its complete 1,200-character field
    # exceeds generation's 20,000-character budget and must omit entire spans.
    for index in range(20):
        item = fixture_advisory(advisory)
        item.update(
            ghsa_id=f"GHSA-{index:04x}-bbbb-cccc",
            cve_id=f"CVE-2099-{index + 1000}",
            description=DESCRIPTION,
        )
        ingest(database, store, item)
    requests = []

    def handle(request):
        task = json.loads(json.loads(request.content)["messages"][-1]["content"])
        sources = task["sources"]
        requests.append(sources)
        assert len(sources) == 16
        assert sum(len(source["text"]) for source in sources) == 19200
        assert all(source["text"] == DESCRIPTION for source in sources)
        assert all(source["span_provenance"]["boundary_complete"] is True for source in sources)
        assert all(source["span_provenance"]["selection_kind"] == "field" for source in sources)
        assert all(source["span_provenance"]["source_field_chars"] == 1200 for source in sources)
        return sdk_reply(sources[-1])

    with database() as session:
        rows = list(
            session.scalars(
                select(SearchChunk).where(
                    SearchChunk.field == "description", SearchChunk.start == 0
                )
            )
        )
        assert len(rows) == 20
        assert sum(len(row.text) for row in rows) == 18000
        packet = packet_for_rows(rows)
        apply_generation(
            cloud(settings),
            "来源说明什么可能影响？",
            packet,
            session=session,
            store=store,
            transport=httpx.MockTransport(handle),
        )
        assert packet["generation"]["status"] == "completed", packet
        assert packet["generated_claims"][0]["evidence"][0]["quote"] == DESCRIPTION
        assert len(packet["citations"]) == 1
        assert verify_citations(session, store, packet["citations"])["verified"] == 1
    assert len(requests) == packet["cost"]["external_requests"] == 1
    assert packet["cost"]["billed_tokens"] == 30


def test_source_update_during_provider_call_rejects_generation_and_keeps_original_fallback(
    database, store, settings, advisory
):
    item = fixture_advisory(advisory)
    item["description"] = DESCRIPTION
    ingest(database, store, item)
    requests = []

    def handle(request):
        task = json.loads(json.loads(request.content)["messages"][-1]["content"])
        requests.append(task)
        updated = copy.deepcopy(item)
        updated.update(
            updated_at="2026-10-13T12:00:00Z",
            description="The current source now describes a different issue and condition.",
        )
        ingest(database, store, updated)
        return sdk_reply(task["sources"][-1])

    with database() as session:
        row = session.scalar(
            select(SearchChunk).where(SearchChunk.field == "description", SearchChunk.start == 0)
        )
        packet = packet_for_rows([row])
        original_answer = packet["answer"]
        original_citations = copy.deepcopy(packet["citations"])
        apply_generation(
            cloud(settings),
            "来源说明什么可能影响？",
            packet,
            session=session,
            store=store,
            transport=httpx.MockTransport(handle),
        )
    assert packet["generation"]["status"] == "fallback", packet
    assert packet["generation"]["reason"] == "evidence_invalid"
    assert packet["answer"] == original_answer
    assert packet["citations"] == original_citations
    assert not packet.get("generated_claims")
    assert len(requests) == packet["cost"]["external_requests"] == 1
    assert packet["cost"]["billed_tokens"] == 30
