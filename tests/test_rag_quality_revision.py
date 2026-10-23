import copy
import json

import pytest
from sqlalchemy import select

from zhidu.gold_review import freeze_release, reconcile, review_template, seal
from zhidu.indexing import chunk_view
from zhidu.ingest import ingest_document
from zhidu.models import SearchChunk, now_utc
from zhidu.query_policy import plan_query, relevant_hits
from zhidu.rag_metrics import score_response, summarize
from zhidu.retrieval import RetrievalHit


def test_no_answer_quote_is_verbatim_but_never_relevant():
    case = {"expected_event_ids": [], "expected_class": "refused"}
    result = {
        "answer_class": "partial",
        "citations": [{"event_id": "other", "text": "a real excerpt"}],
        "claims": [{"citation_index": 0, "quote": "real excerpt"}],
    }
    score = score_response(case, result)
    assert score["supported_claims"] == 0
    assert score["verbatim_claims"] == 1
    assert score["class_correct"] is False


def test_support_requires_both_quote_and_expected_event():
    result = {
        "answer_class": "evidence",
        "citations": [{"event_id": "right", "text": "actual"}],
        "claims": [
            {"citation_index": 0, "quote": "invented"},
            {"citation_index": -1, "quote": "actual"},
        ],
    }
    assert (
        score_response({"expected_event_ids": ["right"], "expected_class": "evidence"}, result)[
            "supported_claims"
        ]
        == 0
    )


def test_no_claims_is_not_vacuous_full_support():
    row = {
        "case_id": "refusal",
        "answer_class": "refused",
        "expected_class": "refused",
        "class_correct": True,
        "recall_at_k": None,
        "claims": 0,
        "supported_claims": 0,
        "verbatim_claims": 0,
    }
    assert summarize([row])["citation_support_rate"] is None


@pytest.fixture
def topic_corpus(database, store, advisory):
    with database.begin() as session:
        for index, (title, description, package) in enumerate(
            [
                (
                    "vLLM authentication bypass",
                    "vLLM auth bypass permits unauthorized access.",
                    "vllm",
                ),
                (
                    "vLLM memory issue",
                    "References a different auth bypass advisory as background.",
                    "vllm",
                ),
                (
                    "PyTorch authentication bypass",
                    "PyTorch auth bypass in a separate product.",
                    "pytorch",
                ),
            ]
        ):
            data = copy.deepcopy(advisory)
            data.update(
                ghsa_id=f"GHSA-aaaa-bbbb-ccc{index}", summary=title, description=description
            )
            data["vulnerabilities"][0]["package"]["name"] = package
            ingest_document(
                session,
                store,
                json.dumps(data).encode(),
                f"offline://quality/{index}",
                now_utc(),
                "live",
            )
    return database


def test_chinese_rewrite_preserves_product_and_security_facets(topic_corpus):
    with topic_corpus() as session:
        plan = plan_query(session, "PyTorch 的认证绕过问题有哪些证据？")
        assert plan.search_text == "pytorch authentication bypass"
        rows = session.scalars(select(SearchChunk)).all()
        hits = [
            RetrievalHit(**chunk_view(row).model_dump(), score=1, matched_terms=[]) for row in rows
        ]
        accepted = relevant_hits(session, hits, plan)
        assert accepted and all(h.external_id.endswith("ccc2") for h in accepted)
        accepted = relevant_hits(session, hits, plan_query(session, "vllm 认证绕过"))
        assert accepted and all(h.external_id.endswith("ccc0") for h in accepted)


@pytest.mark.parametrize(
    "query",
    [
        "ZenithCalc authentication bypass",
        "novazet2029",
        "QuasarWare 认证绕过",
        "CVE-2099-9876543",
        "这条公告的版本范围是什么？",
        "what is the weather",
    ],
)
def test_unseen_entities_missing_context_and_low_relevance_refuse(topic_corpus, query):
    with topic_corpus() as session:
        hits = [
            RetrievalHit(**chunk_view(row).model_dump(), score=0.99, matched_terms=[])
            for row in session.scalars(select(SearchChunk))
        ]
        assert relevant_hits(session, hits, plan_query(session, query)) == []


def packet_fixture():
    return seal(
        {
            "version": "test-only",
            "corpus_sha256": "test-corpus",
            "parent_freeze_sha256": "test-freeze",
            "tasks": [
                {"id": "source1", "group_id": "g", "split": "test", "question": "What is stated?"}
            ],
            "records": [
                {
                    "event_id": "source1",
                    "group_id": "g",
                    "raw_record": {"description": "Source reports denial of service."},
                }
            ],
        }
    )


def completed_review(packet, slot):
    doc = review_template(packet, slot)
    doc.update(reviewer_id=f"test-only-reviewer-{slot}", independent_review_attested=True)
    doc["reviews"][0].update(
        reviewed_at="2026-09-24T00:00:00Z",
        answer_class="evidence",
        complete_answer="The source reports denial of service; no exploit was reproduced.",
        supported_fields=["description"],
        citations=[
            {"record_id": "source1", "pointer": "/description", "quote": "denial of service"}
        ],
    )
    return doc


def test_gold_cannot_be_released_without_two_actual_submissions():
    packet = packet_fixture()
    a, b = review_template(packet, "A"), review_template(packet, "B")
    assert reconcile(packet, a, b)["completed"] == 0
    with pytest.raises(ValueError, match="missing independent"):
        freeze_release(packet, a, b)
    a = completed_review(packet, "A")
    with pytest.raises(ValueError):
        freeze_release(packet, a, b)


def test_gold_rejects_same_reviewer_bad_quote_and_unattested_review():
    packet = packet_fixture()
    a, b = completed_review(packet, "A"), completed_review(packet, "B")
    b["reviewer_id"] = a["reviewer_id"]
    with pytest.raises(ValueError, match="distinct"):
        freeze_release(packet, a, b)
    b = completed_review(packet, "B")
    b["reviews"][0]["citations"][0]["quote"] = "fabricated quote"
    with pytest.raises(ValueError, match="quote"):
        freeze_release(packet, a, b)
    b = completed_review(packet, "B")
    b["independent_review_attested"] = False
    with pytest.raises(ValueError, match="attestation"):
        freeze_release(packet, a, b)


def test_gold_disagreement_requires_audited_independent_adjudication():
    packet = packet_fixture()
    a, b = completed_review(packet, "A"), completed_review(packet, "B")
    b["reviews"][0]["complete_answer"] = "Another wording requiring adjudication."
    assert reconcile(packet, a, b)["conflicts"] == ["source1"]
    decision = {
        "task_id": "source1",
        "adjudicator_id": "test-only-adjudicator",
        "reason": "Both source quotes support the final wording.",
        "review_method": "human",
        "reviewed_at": "2026-09-24T01:00:00Z",
        "answer": a["reviews"][0],
    }
    release = freeze_release(
        packet, a, b, {"packet_sha256": packet["sha256"], "decisions": [decision]}
    )
    assert release["status"] == "human_gold_frozen"
    assert release["labels"][0]["resolution"] == "adjudicated"
    assert release["official_answer_scores"] is None
