import copy
import json
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from test_member_a_rag_context import fixture_advisory, ingest

from zhidu.api import create_app
from zhidu.asset_matching import import_cyclonedx
from zhidu.generation import apply_generation
from zhidu.models import ConversationMessage, RagRun

HEADERS = {"X-Admin-Key": "test-admin"}


def start(client):
    return client.post("/api/v1/conversations", json={"title": "连续问答"}, headers=HEADERS).json()[
        "id"
    ]


def turn(client, cid, rid, question="这条漏洞是什么？", **kw):
    return client.post(
        "/api/v1/rag/answers",
        headers=HEADERS,
        json={
            "conversation_id": cid,
            "request_id": rid,
            "question": question,
            "mode": "lexical",
            "generation": "extractive",
            **kw,
        },
    )


def mock_cloud(monkeypatch, settings, status=200):
    payloads = []
    cloud = settings.model_copy(
        update={"deepseek_api_key": type(settings.deepseek_api_key)("test-secret")}
    )

    def handler(request):
        payload = json.loads(json.loads(request.content)["messages"][-1]["content"])
        payloads.append(payload)
        if status == "timeout":
            raise httpx.ReadTimeout("private detail", request=request)
        if status != 200:
            return httpx.Response(status, text="private detail test-secret")
        source = next(s for s in payload["sources"] if s.get("field") == "packages")
        return httpx.Response(
            200,
            json={
                "model": "mock-actual-model",
                "usage": {"total_tokens": 101, "prompt_tokens": 80, "completion_tokens": 21},
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": json.dumps(
                                {
                                    "statements": [
                                        {
                                            "text": "请按来源字段核对版本条件。",
                                            "evidence": [
                                                {
                                                    "citation": source["citation"],
                                                    "quote": source["text"][:40],
                                                }
                                            ],
                                        }
                                    ]
                                }
                            )
                        },
                    }
                ],
            },
        )

    def generate(settings, question, result, *, history=None, **kwargs):
        time.sleep(0.01)
        apply_generation(
            cloud,
            question,
            result,
            history=history,
            transport=httpx.MockTransport(handler),
            **kwargs,
        )

    monkeypatch.setattr("zhidu.generation.apply_generation", generate)
    return payloads


def test_three_generated_turns_resolve_object_and_persist_full_audit(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    payloads = mock_cloud(monkeypatch, settings)
    with TestClient(create_app(settings)) as client:
        cid = start(client)
        results = []
        for i, q in enumerate(["这条漏洞是什么？", "影响哪些版本？", "首次修复版本是什么？"]):
            r = turn(
                client,
                cid,
                f"three-{i:04}",
                q,
                generation="deepseek",
                **({"query": "GHSA-aaaa-bbbb-cccc"} if i == 0 else {}),
            )
            assert r.status_code == 200, r.text
            results.append(r.json())
        assert [len(p["history"]) for p in payloads] == [0, 2, 4]
        assert payloads[-1]["history_policy"] == "historical_reference_only_not_evidence"
        assert all(r["generation"]["status"] == "completed" for r in results)
        assert all(r["generation_model"] == "mock-actual-model" for r in results)
        assert results[-1]["conversation_context"]["resolution"] == "confirmed_history_object"
        assert all(
            r["cost"]["billed_tokens"] == 101 and r["elapsed_ms"] >= r["generation"]["elapsed_ms"]
            for r in results
        )
        replay = client.get(f"/api/v1/conversations/{cid}/replay").json()
        assert len(replay["messages"]) == 6
        assert (
            replay["messages"][-1]["hops"][-1]["output_data"]["generation"]["usage"]["total_tokens"]
            == 101
        )
        assert replay["messages"][-1]["hops"][-1]["input_data"]["rag_run_id"] == results[-1]["id"]
        assert not results[-1]["generation"]["semantic_support_verified"]
    with database() as s:
        assert s.scalar(select(func.count()).select_from(RagRun)) == 3


def test_revision_refresh_and_withdrawal_do_not_rewrite_history(
    database, store, settings, advisory
):
    item = fixture_advisory(advisory)
    ingest(database, store, item)
    with TestClient(create_app(settings)) as client:
        cid = start(client)
        first = turn(client, cid, "first-0001", query=item["ghsa_id"]).json()
        before = client.get(f"/api/v1/conversations/{cid}/replay").json()
        changed = copy.deepcopy(item)
        changed.update(
            updated_at="2026-01-05T00:00:00Z", description="Upgrade to 1.4.0 for the current fix."
        )
        changed["vulnerabilities"][0]["first_patched_version"] = "1.4.0"
        ingest(database, store, changed)
        assert client.get(f"/api/v1/conversations/{cid}/replay").json() == before
        second = turn(client, cid, "second-0002", "首次修复版本是什么？").json()
        assert {c["revision"] for c in second["citations"]} == {2}
        assert any(c["code"] == "historical_source_superseded" for c in second["constraints"])
        assert "1.4.0" in second["answer"]
        replay = client.get(f"/api/v1/conversations/{cid}/replay").json()
        assert replay["messages"][:2] == before["messages"]
        changed.update(updated_at="2026-01-06T00:00:00Z", withdrawn_at="2026-01-06T00:00:00Z")
        ingest(database, store, changed)
        assert client.get(f"/api/v1/conversations/{cid}/replay").json() == replay
        third = turn(client, cid, "third-0003", "它影响哪些版本？").json()
        assert third["reason"] == "source_withdrawn" and third["citations"] == []
        assert first["citations"][0]["revision"] == 1


def test_multiple_events_require_clarification_but_related_sources_stay_separate(
    database, store, settings, advisory
):
    item = fixture_advisory(advisory)
    ingest(database, store, item)
    other = copy.deepcopy(item)
    other.update(ghsa_id="GHSA-dddd-eeee-ffff", cve_id="CVE-2099-7777")
    ingest(database, store, other)
    with TestClient(create_app(settings)) as client:
        cid = start(client)
        broad = turn(client, cid, "broad-0001", "概述公告", query="vllm security").json()
        assert len({c["event_id"] for c in broad["citations"]}) == 2
        clarify = turn(client, cid, "broad-0002", "它影响哪些版本？").json()
        assert (
            clarify["answer_class"] == "clarification"
            and len(clarify["conversation_context"]["candidates"]) == 2
        )
        chosen = clarify["conversation_context"]["candidates"][0]["event_id"]
        resolved = turn(client, cid, "broad-0003", "它影响哪些版本？", event_id=chosen).json()
        assert {c["event_id"] for c in resolved["citations"]} == {chosen}
        vendor = copy.deepcopy(item)
        vendor["vulnerabilities"][0]["first_patched_version"] = "1.3.0"
        ingest(database, store, vendor, source="vllm-vendor")
        paired = start(client)
        turn(client, paired, "paired-0001", query=item["ghsa_id"])
        follow = turn(client, paired, "paired-0002", "首次修复版本是什么？").json()
        assert follow["answer_class"] != "clarification"
        assert {c["source_id"] for c in follow["citations"]} == {"github-advisories", "vllm-vendor"}
        assert "1.2.0" in follow["answer"] and "1.3.0" in follow["answer"]


@pytest.mark.parametrize(
    "failure,reason", [(429, "rate_limited"), (402, "insufficient_balance"), ("timeout", "timeout")]
)
def test_failed_generation_kept_and_retry_is_idempotent(
    database, store, settings, advisory, monkeypatch, failure, reason
):
    ingest(database, store, fixture_advisory(advisory))
    payloads = mock_cloud(monkeypatch, settings, failure)
    with TestClient(create_app(settings)) as client:
        cid = start(client)
        one = turn(
            client, cid, "retry-0001", query=advisory["ghsa_id"], generation="deepseek"
        ).json()
        two = turn(
            client, cid, "retry-0001", query=advisory["ghsa_id"], generation="deepseek"
        ).json()
        assert one["id"] == two["id"] and two["deduplicated"]
        assert len(payloads) == 1 and one["generation"]["reason"] == reason
        assert "test-secret" not in json.dumps(one) and "private detail" not in json.dumps(one)
        assert turn(client, cid, "retry-0001", "different").status_code == 409
        assert len(client.get(f"/api/v1/conversations/{cid}/replay").json()["messages"]) == 2
        three = turn(
            client, cid, "retry-0002", query=advisory["ghsa_id"], generation="deepseek"
        ).json()
        assert three["id"] != one["id"] and len(payloads) == 2


def test_simultaneous_duplicate_runs_once(database, store, settings, advisory, monkeypatch):
    ingest(database, store, fixture_advisory(advisory))
    payloads = mock_cloud(monkeypatch, settings)
    with TestClient(create_app(settings)) as client:
        cid = start(client)
        with ThreadPoolExecutor(2) as executor:
            results = list(
                executor.map(
                    lambda _: turn(
                        client,
                        cid,
                        "parallel-0001",
                        query=advisory["ghsa_id"],
                        generation="deepseek",
                    ),
                    range(2),
                )
            )
        assert all(r.status_code == 200 for r in results)
        assert len({r.json()["id"] for r in results}) == 1 and len(payloads) == 1


def test_missing_patch_and_damaged_raw_do_not_call_model(
    database, store, settings, advisory, monkeypatch
):
    item = fixture_advisory(advisory)
    item["description"] = "vLLM input validation vulnerability."
    item["vulnerabilities"][0]["first_patched_version"] = None
    item["references"] = []
    ingest(database, store, item)
    payloads = mock_cloud(monkeypatch, settings)
    with TestClient(create_app(settings)) as client:
        cid = start(client)
        missing = turn(
            client,
            cid,
            "missing-0001",
            "首次修复版本是什么？",
            query=item["ghsa_id"],
            generation="deepseek",
        ).json()
        assert missing["reason"] == "repair_information_missing" and not payloads
        # Corrupt the saved raw bytes, not just a mock verification result.
        blobs = [p for p in settings.raw_dir.rglob("*") if p.is_file()]
        assert blobs
        blobs[0].write_bytes(b"broken")
        damaged = turn(client, cid, "damaged-0001", "它是什么？", generation="deepseek").json()
        assert (
            damaged["reason"] == "evidence_missing" and damaged["citations"] == [] and not payloads
        )


def test_assets_are_explicit_switchable_and_clearable(database, store, settings, advisory):
    from pathlib import Path

    ingest(database, store, fixture_advisory(advisory))
    with database.begin() as s:
        ids = [
            import_cyclonedx(
                s,
                Path("examples/cyclonedx-vllm-demo.json").read_bytes(),
                asset_name=name,
                environment="test",
                criticality="low",
            )[0].id
            for name in ["A", "B"]
        ]
    with TestClient(create_app(settings)) as client:
        cid = start(client)
        one = turn(client, cid, "asset-0001", query=advisory["ghsa_id"], asset_id=ids[0]).json()
        two = turn(client, cid, "asset-0002", "它影响哪些版本？").json()
        assert one["asset_id"] == two["asset_id"] == ids[0]
        uncertain = turn(client, cid, "asset-0003", "切换资产看看它").json()
        assert uncertain["answer_class"] == "clarification" and uncertain["asset_id"] is None
        selected = turn(
            client, cid, "asset-0004", "切换资产", asset_id=ids[1], query=advisory["ghsa_id"]
        ).json()
        assert selected["asset_id"] == ids[1]
        clear = turn(client, cid, "asset-0005", "它是什么？", clear_asset=True).json()
        assert clear["asset_id"] is None
        assert (
            client.get(f"/api/v1/conversations/{cid}").json()["conversation"]["active_asset"]
            is None
        )


def test_unknown_topic_and_ambiguous_version_never_reuse_older_object(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    with TestClient(create_app(settings)) as client:
        cid = start(client)
        turn(client, cid, "topic-0001", query=advisory["ghsa_id"])
        ambiguous = turn(client, cid, "topic-0002", "这个版本是否受影响？").json()
        assert ambiguous["answer_class"] == "clarification"
        turn(client, cid, "topic-0003", "不存在的公告", query="GHSA-zzzz-zzzz-zzzz")
        follow = turn(client, cid, "topic-0004", "它影响哪些版本？").json()
        assert follow["answer_class"] == "clarification" and not follow["citations"]


def test_preview_is_readonly_and_ids_required_for_persistence(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    with TestClient(create_app(settings)) as client:
        cid = start(client)
        body = {
            "conversation_id": cid,
            "question": "版本信息",
            "query": advisory["ghsa_id"],
            "mode": "lexical",
            "generation": "deepseek",
        }
        assert client.post("/api/v1/rag/context", headers=HEADERS, json=body).status_code == 200
        assert client.post("/api/v1/rag/answers", headers=HEADERS, json=body).status_code == 409
        assert (
            client.post("/api/v1/rag/answers", json={**body, "request_id": "auth-0001"}).status_code
            == 401
        )
    with database() as s:
        assert s.scalar(select(func.count()).select_from(ConversationMessage)) == 0
        assert s.scalar(select(func.count()).select_from(RagRun)) == 0
