import copy

from fastapi.testclient import TestClient
from test_member_a_week7 import ingest, pair

from zhidu.api import create_app


def test_retired_comparison_preserves_replay_and_marks_live_context(
    database, store, settings, advisory
):
    comparison_id = pair(database, store, advisory)
    headers = {"X-Admin-Key": "test-admin"}
    with TestClient(create_app(settings)) as client:
        conversation_id = client.post(
            "/api/v1/conversations", json={"title": "archive regression"}, headers=headers
        ).json()["id"]
        response = client.post(
            f"/api/v1/conversations/{conversation_id}/turns",
            json={"question": "比较来源声明", "query": "vllm security", "origin": "replay"},
            headers=headers,
        )
        assert response.status_code == 200
        replay = client.get(f"/api/v1/conversations/{conversation_id}/replay").json()
        assert replay["messages"][-1]["evidence_tasks"]
        changed = copy.deepcopy(advisory)
        changed.update(
            summary="vLLM security",
            severity="critical",
            updated_at="2026-01-03T08:00:00Z",
            withdrawn_at="2026-01-03T08:00:00Z",
        )
        ingest(database, store, changed, "vllm-vendor")
        after = client.get(f"/api/v1/conversations/{conversation_id}/replay").json()
        assert after["replay_sha256"] == replay["replay_sha256"]
        status = client.get(f"/api/v1/conversations/{conversation_id}/context-status").json()
        retired = next(c for c in status["comparisons"] if c["id"] == comparison_id)
        assert retired["is_active"] is False and retired["stale"] is True
        current = client.post(
            f"/api/v1/conversations/{conversation_id}/turns",
            json={"question": "比较当前来源", "query": "vllm security", "origin": "replay"},
            headers=headers,
        ).json()
        comparison_hop = next(
            h
            for h in current["assistant_message"]["hops"]
            if h["hop_type"] == "cross_source_comparison"
        )
        assert not comparison_hop["output_data"]["comparisons"]
        context = client.get(f"/api/v1/comparisons/{comparison_id}/review-context").json()
        assert context["comparison"]["is_active"] is False
        assert context["review_transitions"][-1]["change_kind"] == "retired"
        assert context["review_transitions"][-1]["observations"]
        assert client.get("/api/v1/conversations/missing/context-status").status_code == 404
