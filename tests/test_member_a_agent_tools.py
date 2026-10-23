"""Tool contracts, source boundaries, failure isolation and budgets."""

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from test_member_a_rag_context import fixture_advisory, ingest
from test_member_a_week7 import pair

from zhidu.agent_tools import AgentToolRuntime
from zhidu.api import create_app
from zhidu.models import (
    Asset,
    AssetComponent,
    AssetExposure,
    Conversation,
    EventRevision,
    IntelEvent,
    RagRun,
    SearchChunk,
)


def seeded(database, store, advisory):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        event = session.scalar(select(IntelEvent))
        chunk = session.scalar(select(SearchChunk).where(SearchChunk.field == "packages"))
        return event.id, chunk.id


def runtime(database, store, settings, **kwargs):
    return AgentToolRuntime(database(), store, settings, None, **kwargs)


def test_contracts_are_typed_and_http_requires_admin(database, store, settings):
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/v1/agent/tools/contracts").status_code == 401
        response = client.get(
            "/api/v1/agent/tools/contracts", headers={"X-Admin-Key": "test-admin"}
        )
        assert response.status_code == 200
        data = response.json()
        assert set(data["tools"]) == {
            "retrieve",
            "event_details",
            "compare_sources",
            "asset_exposure",
            "verify_evidence",
        }
        assert data["limits"]["max_calls"] == 6
        assert data["tools"]["asset_exposure"]["parameters"]["required"] == ["asset_id", "event_id"]
        assert "run_shell" not in str(data)


def test_retrieval_detail_and_verify_are_current_and_source_bound(
    database, store, settings, advisory
):
    event_id, chunk_id = seeded(database, store, advisory)
    with database() as session:
        run = AgentToolRuntime(session, store, settings, None)
        hit = run.execute("retrieve", {"query": "GHSA-aaaa-bbbb-cccc", "limit": 2})
        assert hit["status"] == "completed" and hit["result"]["items"]
        assert all(item["citation"]["event_id"] == event_id for item in hit["result"]["items"])
        assert all(item["citation"]["origin"] == "live" for item in hit["result"]["items"])
        detail = run.execute("event_details", {"event_id": event_id})
        assert detail["status"] == "completed"
        assert {item["citation"]["field"] for item in detail["result"]["fields"]} >= {
            "packages",
            "description",
        }
        assert run.execute("verify_evidence", {"chunk_id": chunk_id})["result"]["verified"]
        assert run.steps[-1]["input"] == {"chunk_id": chunk_id}
        assert all(step["elapsed_ms"] >= 0 for step in run.steps)
        assert run.execute("event_details", {"event_id": "0" * 36})["error"] == "not_found"


def test_readonly_http_batch_and_scope(database, store, settings, advisory):
    event_id, _ = seeded(database, store, advisory)
    with database() as session:
        before = session.scalar(select(func.count()).select_from(RagRun))
        chunk_count = session.scalar(select(func.count()).select_from(SearchChunk))
    request = {
        "calls": [
            {"name": "retrieve", "arguments": {"query": "GHSA-aaaa-bbbb-cccc"}},
            {"name": "event_details", "arguments": {"event_id": event_id}},
        ]
    }
    with TestClient(create_app(settings)) as client:
        assert client.post("/api/v1/agent/tools/preview", json=request).status_code == 401
        response = client.post(
            "/api/v1/agent/tools/preview",
            json=request,
            headers={"X-Admin-Key": "test-admin"},
        )
        assert response.status_code == 200
        data = response.json()
        assert [item["status"] for item in data["results"]] == ["completed", "completed"]
        assert data["policy"]["no_database_write"] and data["policy"]["no_model_call"]
        replay = client.post(
            "/api/v1/agent/tools/preview",
            json={**request, "origin": "replay"},
            headers={"X-Admin-Key": "test-admin"},
        ).json()
        assert replay["results"][0]["result"]["items"] == []
        assert replay["results"][1]["error"] == "not_found"
    with database() as session:
        assert session.scalar(select(func.count()).select_from(RagRun)) == before
        assert session.scalar(select(func.count()).select_from(Conversation)) == 0
        assert session.scalar(select(func.count()).select_from(SearchChunk)) == chunk_count


def test_invalid_parameters_and_forbidden_tool_are_closed(database, store, settings):
    with database() as session:
        run = AgentToolRuntime(session, store, settings, None)
        bad = run.execute("retrieve", {"query": "x", "limit": 100, "origin": "replay"})
        assert bad == {"status": "failed", "tool": "retrieve", "error": "invalid_arguments"}
        assert run.execute("asset_exposure", {"asset_id": "a" * 36})["error"] == "invalid_arguments"
        assert run.execute("execute_poc", {"command": "rm -rf /"})["error"] == "tool_not_allowed"
        assert "rm -rf" not in str(run.steps)
    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/api/v1/agent/tools/preview",
            headers={"X-Admin-Key": "test-admin"},
            json={"calls": [{"name": "execute_poc", "arguments": {}}]},
        )
        assert response.status_code == 422


def test_hybrid_failure_needs_explicit_lexical_retry(database, store, settings, advisory):
    seeded(database, store, advisory)
    with database() as session:
        run = AgentToolRuntime(session, store, settings, None)
        unavailable = run.execute("retrieve", {"query": "vllm", "mode": "hybrid"})
        assert unavailable["error"] == "model_unavailable"
        local = run.execute("retrieve", {"query": "GHSA-aaaa-bbbb-cccc", "mode": "lexical"})
        assert local["status"] == "completed"
        assert run.steps[0]["status"] == "failed" and run.steps[1]["status"] == "completed"


def test_budgets_stop_output_and_deadline(database, store, settings, advisory, monkeypatch):
    seeded(database, store, advisory)
    with database() as session:
        run = AgentToolRuntime(session, store, settings, None, max_calls=1)
        assert run.execute("retrieve", {"query": "GHSA-aaaa-bbbb-cccc"})["status"] == "completed"
        assert run.execute("retrieve", {"query": "another"})["error"] == "call_budget_exceeded"
        assert len(run.steps) == 1
        monkeypatch.setattr("zhidu.agent_tools.MAX_CALL_CHARS", 1)
        capped = AgentToolRuntime(session, store, settings, None)
        assert (
            capped.execute("retrieve", {"query": "GHSA-aaaa-bbbb-cccc"})["error"]
            == "output_budget_exceeded"
        )
        assert capped.output_chars == 0
        ticks = [0.0]
        timed = AgentToolRuntime(
            session, store, settings, None, deadline_seconds=1, clock=lambda: ticks[0]
        )

        def slow(_):
            ticks[0] = 2
            return {"items": []}

        monkeypatch.setattr(timed, "_retrieve", slow)
        assert timed.execute("retrieve", {"query": "x"})["error"] == "deadline_exceeded"


def test_corrupted_raw_never_leaks_excerpt(database, store, settings, advisory):
    event_id, chunk_id = seeded(database, store, advisory)
    with database() as session:
        row = session.get(SearchChunk, chunk_id)
        store.path_for(row.sha256).write_text("corrupt")
        run = AgentToolRuntime(session, store, settings, None)
        assert run.execute("verify_evidence", {"chunk_id": chunk_id})["error"] == "evidence_invalid"
        detail = run.execute("event_details", {"event_id": event_id})
        assert detail["status"] == "failed" and "result" not in detail


def test_comparison_filters_superseded_and_retired(database, store, settings, advisory):
    comparison_id = pair(database, store, advisory)
    with database() as session:
        from zhidu.models import IntelligenceComparison

        row = session.get(IntelligenceComparison, comparison_id)
        active = AgentToolRuntime(session, store, settings, None, origin="replay")
        result = active.execute("compare_sources", {"identifier": row.identifier})
        assert result["status"] == "completed"
        assert result["result"]["items"]
        assert all(len(item["observations"]) >= 2 for item in result["result"]["items"])
        assert not result["result"]["items"][0]["automatic_resolution"]
        live = AgentToolRuntime(session, store, settings, None, origin="live")
        assert (
            live.execute("compare_sources", {"identifier": row.identifier})["result"]["items"] == []
        )
    with database.begin() as session:
        session.get(IntelligenceComparison, comparison_id).is_active = False
    with database() as session:
        run = AgentToolRuntime(session, store, settings, None, origin="replay")
        items = run.execute("compare_sources", {"identifier": row.identifier})["result"]["items"]
        assert comparison_id not in {item["comparison_id"] for item in items}


def test_asset_requires_explicit_ids_and_current_revision(database, store, settings, advisory):
    event_id, _ = seeded(database, store, advisory)
    with database.begin() as session:
        asset = Asset(
            name="fictional fixture asset",
            environment="test",
            criticality="low",
            sbom_sha256="0" * 64,
        )
        session.add(asset)
        session.flush()
        component = AssetComponent(asset_id=asset.id, ecosystem="pip", name="vllm", version="1.0.0")
        session.add(component)
        session.flush()
        revision = session.scalar(select(EventRevision).where(EventRevision.event_id == event_id))
        session.add(
            AssetExposure(
                asset_id=asset.id,
                component_id=component.id,
                event_id=event_id,
                revision_id=revision.id,
                enrichment_schema_version="test",
                status="affected",
                match_method="package",
                reason="fixture source range",
                evidence=[],
            )
        )
        aid = asset.id
    with database() as session:
        run = AgentToolRuntime(session, store, settings, None)
        result = run.execute("asset_exposure", {"asset_id": aid, "event_id": event_id})
        assert (
            result["status"] == "completed"
            and result["result"]["exposures"][0]["status"] == "affected"
        )
        assert result["result"]["private_asset_data"] is True
        no_match = run.execute("asset_exposure", {"asset_id": aid, "event_id": "0" * 36})
        assert no_match["error"] == "not_found"
        assert run.execute("asset_exposure", {"asset_id": aid})["error"] == "invalid_arguments"
    with database.begin() as session:
        session.get(IntelEvent, event_id).revision = 2
    with database() as session:
        run = AgentToolRuntime(session, store, settings, None)
        result = run.execute("asset_exposure", {"asset_id": aid, "event_id": event_id})
        assert result["error"] == "not_found"
