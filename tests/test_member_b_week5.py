import copy
import json

from fastapi.testclient import TestClient
from sqlalchemy import select

from zhidu.api import create_app
from zhidu.asset_matching import import_cyclonedx
from zhidu.comparisons import sync_comparisons
from zhidu.conversation_evaluation import (
    ConversationEvaluationSuite,
    evaluate_conversations,
)
from zhidu.conversations import (
    create_conversation,
    replay_conversation,
    submit_turn,
)
from zhidu.ingest import ingest_document
from zhidu.models import AssetExposure, IntelEvent, IntelligenceComparison, now_utc
from zhidu.schemas import ConversationTurnCreate
from zhidu.sources import SOURCES


def ingest(database, store, data, source="github-advisories"):
    with database.begin() as session:
        return ingest_document(
            session,
            store,
            json.dumps(data).encode(),
            f"offline://member-b-week5/{source}",
            now_utc(),
            "live",
            spec=SOURCES[source],
        )


def advisory_case(base, ghsa, cve, version_range, severity="high"):
    data = copy.deepcopy(base)
    data.update(
        ghsa_id=ghsa,
        cve_id=cve,
        summary=f"vLLM week5 case {ghsa}",
        description=f"vLLM week5 security evidence {ghsa}",
        severity=severity,
    )
    data["vulnerabilities"][0]["package"]["name"] = "vllm"
    data["vulnerabilities"][0]["vulnerable_version_range"] = version_range
    return data


def sbom(serial):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "components": [
            {
                "type": "library",
                "name": "vllm",
                "version": "0.6.2",
                "purl": "pkg:pypi/vllm@0.6.2",
                "bom-ref": "vllm-week5",
            }
        ],
    }


def prepare_week5(database, store, advisory):
    affected = advisory_case(
        advisory,
        "GHSA-aaaa-bbbb-cccc",
        "CVE-2099-0001",
        ">= 0.5.0, < 1.0.0",
        "high",
    )
    ingest(database, store, affected)
    vendor = advisory_case(
        advisory,
        "GHSA-7777-8888-9999",
        "CVE-2099-0001",
        ">= 0.5.0, < 1.0.0",
        "critical",
    )
    vendor["vulnerabilities"][0]["patched_versions"] = ">= 1.0.0"
    ingest(database, store, vendor, "vllm-vendor")
    unknown = advisory_case(
        advisory,
        "GHSA-1111-2222-3333",
        "CVE-2099-0003",
        "1.0 || 2.0",
    )
    ingest(database, store, unknown)
    with database.begin() as session:
        first, _ = import_cyclonedx(
            session,
            json.dumps(sbom("urn:uuid:week5-first")).encode(),
            asset_name="week5-production",
            environment="production",
            criticality="critical",
        )
        second, _ = import_cyclonedx(
            session,
            json.dumps(sbom("urn:uuid:week5-second")).encode(),
            asset_name="week5-staging",
            environment="staging",
            criticality="high",
        )
        sync_comparisons(session)
        affected_event = session.scalar(
            select(IntelEvent).where(IntelEvent.external_id == "GHSA-aaaa-bbbb-cccc")
        )
        unknown_event = session.scalar(
            select(IntelEvent).where(IntelEvent.external_id == "GHSA-1111-2222-3333")
        )
        return {
            "asset_a": first.id,
            "asset_b": second.id,
            "affected_event": affected_event.id,
            "unknown_event": unknown_event.id,
        }


def make_turn(question, event_id=None, asset_id=None):
    return ConversationTurnCreate(
        question=question,
        query=("GHSA-aaaa-bbbb-cccc" if event_id else "vllm"),
        asset_id=asset_id,
        event_id=event_id,
        origin="live",
        limit=1,
    )


def test_three_multiturn_asset_context_cases(database, store, advisory):
    data = prepare_week5(database, store, advisory)
    with database.begin() as session:
        conversation = create_conversation(session, "week5", data["asset_a"])
        inherited = submit_turn(
            session,
            store,
            conversation,
            make_turn("它对当前资产有什么影响？", data["affected_event"]),
        )
        assert inherited["context_policy"]["asset_inherited"] is True
        assert inherited["assistant_message"]["effective_asset_id"] == data["asset_a"]

        switched = submit_turn(
            session,
            store,
            conversation,
            make_turn(
                "切换资产后再检查这条公告。",
                data["affected_event"],
                data["asset_b"],
            ),
        )
        assert switched["conversation"]["active_asset"]["id"] == data["asset_b"]
        assert switched["assistant_message"]["explicit_asset_id"] == data["asset_b"]

        assetless = create_conversation(session, "assetless")
        refused = submit_turn(
            session,
            store,
            assetless,
            make_turn("另一个资产是否受影响？", data["affected_event"]),
        )
        assert refused["assistant_message"]["answer_status"] == "asset_context_required"
        assert refused["assistant_message"]["citations"] == []
        assert refused["context_policy"]["natural_language_asset_guessing"] is False


def test_multihop_trace_tasks_recommendations_and_replay(database, store, advisory):
    data = prepare_week5(database, store, advisory)
    with database.begin() as session:
        conversation = create_conversation(session, "full-chain", data["asset_a"])
        result = submit_turn(
            session,
            store,
            conversation,
            make_turn("沿证据链核对这条公告。", data["affected_event"]),
        )
        hops = result["assistant_message"]["hops"]
        assert [item["hop_type"] for item in hops] == [
            "event_selection",
            "cross_source_comparison",
            "asset_exposure",
            "event_trace",
            "raw_evidence",
        ]
        assert all(item["evidence_refs"] for item in hops)
        assert all(
            {"event_id", "revision_id", "raw_document_id", "json_pointer"} <= set(ref)
            for item in hops
            for ref in item["evidence_refs"]
        )
        assert any(
            task["task_type"] == "cross_source_conflict"
            and task["network_verification_status"] == "not_started"
            for task in result["assistant_message"]["evidence_tasks"]
        )
        assert result["recommendations"]["ranking_is_probability"] is False
        assert result["recommendations"]["selected_asset"]["id"] == data["asset_a"]

        first = replay_conversation(session, conversation)
        second = replay_conversation(session, conversation)
        assert first["replay_sha256"] == second["replay_sha256"]

        unknown = submit_turn(
            session,
            store,
            conversation,
            ConversationTurnCreate(
                question="这条 unknown 记录需要补什么证据？",
                query="GHSA-1111-2222-3333",
                event_id=data["unknown_event"],
                origin="live",
                limit=1,
            ),
        )
        assert any(
            task["task_type"] == "unknown_asset_condition" and task["status"] == "pending"
            for task in unknown["assistant_message"]["evidence_tasks"]
        )


def test_week5_api_replay_conflict_context_and_boundaries(database, store, settings, advisory):
    data = prepare_week5(database, store, advisory)
    with database() as session:
        conflict = session.scalar(
            select(IntelligenceComparison).where(
                IntelligenceComparison.identifier == "CVE-2099-0001",
                IntelligenceComparison.field == "severity",
            )
        )
    with TestClient(create_app(settings)) as client:
        created = client.post(
            "/api/v1/conversations",
            json={"title": "api-session", "asset_id": data["asset_a"]},
            headers={"X-Admin-Key": "test-admin"},
        )
        assert created.status_code == 200
        conversation_id = created.json()["id"]
        turn = client.post(
            f"/api/v1/conversations/{conversation_id}/turns",
            json={
                "question": "完整核验这条公告。",
                "query": "GHSA-aaaa-bbbb-cccc",
                "event_id": data["affected_event"],
                "origin": "live",
                "limit": 1,
            },
            headers={"X-Admin-Key": "test-admin"},
        )
        assert turn.status_code == 200
        replay = client.get(f"/api/v1/conversations/{conversation_id}/replay")
        assert replay.status_code == 200
        assert len(replay.json()["messages"]) == 2
        tasks = client.get(f"/api/v1/conversations/{conversation_id}/evidence-tasks")
        assert tasks.json()["network_collection_executed"] is False
        recommendation = client.get(
            f"/api/v1/conversations/{conversation_id}/recommendations"
        ).json()
        assert recommendation["selected_asset"]["id"] == data["asset_a"]
        assert recommendation["ranking_is_probability"] is False

        reviewed = client.patch(
            f"/api/v1/comparisons/{conflict.id}/review",
            json={
                "expected_version": 0,
                "review_status": "needs_evidence",
                "analyst_note": "核对两个来源的评分版本与适用范围。",
            },
            headers={"X-Admin-Key": "test-admin"},
        )
        assert reviewed.status_code == 200
        context = client.get(f"/api/v1/comparisons/{conflict.id}/review-context")
        assert context.status_code == 200
        payload = context.json()
        assert len(payload["source_traces"]) == 2
        assert all(item["evidence_refs"] for item in payload["source_traces"])
        assert payload["automatic_resolution"] is False
        transition = payload["review_transitions"][0]
        assert transition["before"] == {
            "version": 0,
            "review_status": "unreviewed",
            "analyst_note": "",
        }
        assert transition["after"]["version"] == 1
        assert transition["after"]["review_status"] == "needs_evidence"
        assert transition["after"]["analyst_note"].startswith("核对两个来源")

        no_asset = client.post(
            "/api/v1/conversations",
            json={"title": "no-asset"},
            headers={"X-Admin-Key": "test-admin"},
        ).json()
        assert (
            client.get(f"/api/v1/conversations/{no_asset['id']}/recommendations").status_code == 409
        )

    with database() as session:
        assert session.scalar(
            select(AssetExposure).where(
                AssetExposure.asset_id == data["asset_a"],
                AssetExposure.event_id == data["unknown_event"],
                AssetExposure.status == "unknown",
            )
        )


def test_fixed_six_case_conversation_evaluation(database, store, advisory):
    prepare_week5(database, store, advisory)
    suite = ConversationEvaluationSuite(
        version="week5-test-v1",
        primary_asset_name="week5-production",
        secondary_asset_name="week5-staging",
        conflict_external_id="GHSA-aaaa-bbbb-cccc",
        conflict_source_id="github-advisories",
        unknown_external_id="GHSA-1111-2222-3333",
        unknown_source_id="github-advisories",
    )
    with database.begin() as session:
        result = evaluate_conversations(session, store, suite)
        assert result.case_count == 6
        assert result.conversation_pass_rate == 1
        assert result.hop_evidence_rate == 1
        assert result.replay_determinism_rate == 1
        assert result.task_boundary_rate == 1
        assert result.recommendation_boundary_rate == 1
