import copy
import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.exc import OperationalError

from zhidu.api import create_app
from zhidu.enrichment_evaluation import EnrichmentSuite, evaluate_enrichment
from zhidu.ingest import ingest_document
from zhidu.models import (
    CollectionRun,
    MonitorState,
    OperationalEvaluation,
    RawDocument,
    RecoveryAction,
    SearchChunk,
    now_utc,
)
from zhidu.monitor import Target, resilient_cycle
from zhidu.operations import (
    doctor,
    operational_snapshot,
    save_operational_evaluation,
)

NOW = datetime(2026, 9, 22, 8, tzinfo=UTC)


def ingest(database, store, advisory):
    with database.begin() as session:
        ingest_document(
            session,
            store,
            json.dumps(advisory).encode(),
            "offline://member-a-week6",
            now_utc(),
            "replay",
        )


def test_operational_snapshot_separates_coverage_from_accuracy(database, store, advisory):
    ingest(database, store, advisory)
    target = Target(id="serialize-time", source="github-advisories")
    with database.begin() as session:
        session.add(
            MonitorState(
                target_id=target.id,
                config_hash=target.fingerprint,
                status="completed",
                next_run_at=NOW,
                last_success_at=NOW,
                heartbeat_at=NOW,
            )
        )
        snapshot = operational_snapshot(
            session,
            store,
            [target],
            verify_raw=True,
            clock=lambda: NOW,
        )
        row = save_operational_evaluation(session, snapshot)
        assert row.status == "passed"
        assert snapshot["enrichment"]["coverage"] == 1
        assert snapshot["enrichment"]["coverage_is_accuracy"] is False
        assert snapshot["collection"]["observation_delay_is_sla_evidence"] is False
        assert snapshot["collection"]["observed_publication_to_first_seen"]["samples"] == 0
    with database() as session:
        saved = session.scalar(select(OperationalEvaluation))
        assert saved.schema_version == "operations-v1"
        assert saved.collection["targets"][0]["last_success_at"] == NOW.isoformat()


def test_doctor_recovers_stale_collection_and_audits_action(database, store, advisory):
    ingest(database, store, advisory)
    target = Target(id="week6", source="github-advisories", interval_seconds=300)
    with database.begin() as session:
        run = CollectionRun(
            source_id="github-advisories",
            scope="monitor:week6:test",
            status="running",
            started_at=NOW - timedelta(hours=1),
        )
        session.add(run)
        session.flush()
        session.add(
            MonitorState(
                target_id=target.id,
                config_hash=target.fingerprint,
                status="running",
                failures=0,
                next_run_at=NOW + timedelta(hours=1),
                last_run_id=run.id,
                heartbeat_at=NOW - timedelta(hours=1),
            )
        )
        run_id = run.id

    with database.begin() as session:
        result = doctor(session, store, [target], repair=True, clock=lambda: NOW)
        assert result["status"] == "passed"
        assert any(
            item["action_type"] == "recover_interrupted_collection"
            for item in result["planned_or_completed_actions"]
        )

    with database() as session:
        run = session.get(CollectionRun, run_id)
        state = session.get(MonitorState, target.id)
        assert run.status == "interrupted"
        assert state.status == "failed"
        assert state.next_run_at == NOW
        assert session.scalar(select(RecoveryAction)) is not None


def test_health_metrics_and_operations_api(database, store, settings, advisory):
    ingest(database, store, advisory)
    with TestClient(create_app(settings)) as client:
        assert client.get("/health/live").json()["status"] == "alive"
        ready = client.get("/health/ready")
        assert ready.status_code == 200
        assert ready.json()["status"] == "ready"
        metrics = client.get("/metrics")
        assert metrics.status_code == 200
        assert "zhidu_events_total 1" in metrics.text
        assert "zhidu_enrichment_coverage 1.0" in metrics.text
        status = client.get("/api/v1/operations/status")
        assert status.status_code == 200
        assert status.json()["enrichment"]["coverage_is_accuracy"] is False


def test_doctor_inspection_does_not_mutate(database, store, advisory):
    ingest(database, store, advisory)
    with database() as session:
        result = doctor(session, store, [], repair=False, clock=lambda: NOW)
        assert result["mode"] == "inspect"
        assert result["derived_reconciliation"] == {"status": "not_run"}
    with database() as session:
        assert session.scalar(select(RecoveryAction)) is None


def test_labeled_enrichment_suite_scores_assertions_and_evidence(database, store, advisory):
    ingest(database, store, advisory)
    suite = EnrichmentSuite.model_validate(
        {
            "version": "week6-test-v1",
            "labeled_at": "2026-09-22",
            "cases": [
                {
                    "id": "ghsa-demo",
                    "source_id": "github-advisories",
                    "external_id": advisory["ghsa_id"],
                    "kind": "vulnerability",
                    "severity": advisory["severity"],
                    "quality_flags": ["missing_cvss"],
                    "entities": [
                        {"type": "cve", "value": advisory["cve_id"]},
                        {
                            "type": "package",
                            "value": "example-ai-demo",
                            "ecosystem": "pip",
                        },
                    ],
                    "packages": [
                        {
                            "ecosystem": "pip",
                            "name": "example-ai-demo",
                            "vulnerable_raw": ">= 1.0.0, < 1.2.0",
                        }
                    ],
                    "has_cvss": False,
                    "has_cpe": False,
                    "has_version_scope": True,
                }
            ],
        }
    )
    with database.begin() as session:
        result = evaluate_enrichment(session, store, suite)
        assert result.assertion_accuracy == 1
        assert result.expected_fact_recall == 1
        assert result.evidence_verifiable_rate == 1
        missing = copy.deepcopy(suite)
        missing.cases[0].external_id = "GHSA-missing"
        absent = evaluate_enrichment(session, store, missing)
        assert absent.assertion_count == result.assertion_count
        assert absent.assertion_accuracy == 0
        assert absent.expected_fact_recall == 0
        assert absent.evidence_verifiable_rate == 0


def test_corrupt_raw_blocks_rebuild_but_preserves_failure_audit(database, store, advisory):
    ingest(database, store, advisory)
    with database() as session:
        digest = session.scalar(select(RawDocument.sha256))
    store.path_for(digest).write_bytes(b"tampered")
    with database.begin() as session:
        result = doctor(session, store, [], repair=True)
        assert result["status"] == "failed"
        assert result["derived_reconciliation"]["status"] == "blocked"
    with database() as session:
        assert session.scalar(select(RecoveryAction)).status == "blocked"
    assert store.path_for(digest).read_bytes() == b"tampered"


def test_doctor_repairs_missing_index_then_is_idempotent(database, store, advisory):
    ingest(database, store, advisory)
    with database.begin() as session:
        session.execute(delete(SearchChunk))
    with database.begin() as session:
        before = operational_snapshot(session, store, [])
        assert before["status"] == "degraded"
        first = doctor(session, store, [], repair=True)
        assert first["derived_reconciliation"]["index"]["changed_events"] == 1
        assert operational_snapshot(session, store, [])["status"] == "passed"
        second = doctor(session, store, [], repair=True)
        assert second["derived_reconciliation"]["index"]["changed_events"] == 0


def test_monitor_resumes_after_database_outage_without_leaking_secrets(monkeypatch):
    calls = []

    def failing_once(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise OperationalError("secret query", {}, RuntimeError("private-password"))
        return [{"target": "one", "status": "completed"}]

    monkeypatch.setattr("zhidu.monitor.run_due", failing_once)
    failed = resilient_cycle(None, None, [])
    assert failed == [{"target": "scheduler", "status": "failed", "error": "OperationalError"}]
    assert resilient_cycle(None, None, [])[0]["status"] == "completed"
