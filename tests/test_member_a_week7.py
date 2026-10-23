import copy
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from zhidu.api import create_app
from zhidu.asset_matching import evaluate_component, evaluate_cpe, parse_cyclonedx
from zhidu.comparisons import sync_comparisons
from zhidu.enrichment import _cpe_matches, parse_version_range
from zhidu.ingest import ingest_document
from zhidu.models import (
    ComparisonReviewChange,
    Conversation,
    ConversationMessage,
    EvidenceTask,
    IntelligenceComparison,
    now_utc,
)
from zhidu.sources import SOURCES


def test_single_monitor_lease_and_clean_shutdown(tmp_path):
    from zhidu.locking import WriterBusy
    from zhidu.worker_health import healthy, worker_pulse

    path = tmp_path / "collector.heartbeat"
    with worker_pulse(path):
        assert healthy(path)
        with pytest.raises(WriterBusy), worker_pulse(path):
            pass
        assert healthy(path)
    assert not path.exists()
    with worker_pulse(path):
        assert healthy(path)


def test_monitoring_window_preserves_gaps(database, store, advisory):
    from datetime import UTC, datetime, timedelta

    from zhidu.models import CollectionRun
    from zhidu.monitor import Target
    from zhidu.monitoring_experiment import window_report

    ingest(database, store, advisory, "github-advisories")
    target = Target(id="window", source="github-advisories", interval_seconds=600)
    end = datetime(2026, 9, 24, tzinfo=UTC)
    with database.begin() as session:
        for minute in (60, 20):
            stamp = end - timedelta(minutes=minute)
            session.add(
                CollectionRun(
                    source_id=target.source,
                    scope=f"monitor:{target.id}:{target.fingerprint[:16]}",
                    status="completed",
                    started_at=stamp,
                    finished_at=stamp,
                )
            )
        report = window_report(session, [target], hours=1, clock=lambda: end)
        assert report["targets"][0]["freshness_coverage"] == pytest.approx(2 / 3, abs=1e-6)
        assert report["status"] == "insufficient_coverage"
        assert report["publication_latency_sla_proven"] is False


def test_reactivation_keeps_id_and_old_review_history(database, store, advisory):
    cid = pair(database, store, advisory)
    updated = copy.deepcopy(advisory)
    updated.update(
        summary="vLLM security",
        severity="critical",
        updated_at="2026-01-03T08:00:00Z",
        withdrawn_at="2026-01-03T08:00:00Z",
    )
    ingest(database, store, updated, "vllm-vendor")
    updated.update(updated_at="2026-01-04T08:00:00Z", withdrawn_at=None)
    ingest(database, store, updated, "vllm-vendor")
    with database() as session:
        row = session.get(IntelligenceComparison, cid)
        assert row.is_active and row.retired_at is None
        assert row.annotation_version == 2 and row.review_status == "needs_evidence"
        changes = session.scalars(
            select(ComparisonReviewChange)
            .where(ComparisonReviewChange.comparison_id == cid)
            .order_by(ComparisonReviewChange.annotation_version)
        ).all()
        assert [c.change_kind for c in changes] == ["retired", "reactivated"]


def test_semantic_failure_is_separate_from_committed_collection(
    database, store, settings, advisory, monkeypatch
):
    from zhidu.models import IntelEvent
    from zhidu.semantic import ModelUnavailable
    from zhidu.semantic_maintenance import maintain_semantics

    ingest(database, store, advisory, "github-advisories")

    def unavailable(*args, **kwargs):
        raise ModelUnavailable("fixture")

    monkeypatch.setattr("zhidu.semantic.sync_embeddings", unavailable)
    report = maintain_semantics(database, settings, encoder=object())
    assert report == {"status": "failed", "error_type": "ModelUnavailable"}
    with database() as session:
        assert session.scalar(select(IntelEvent.id)) is not None


def test_monitor_maintenance_refills_vectors_after_source_update(
    database, store, settings, advisory, monkeypatch
):
    from zhidu.models import ChunkEmbedding
    from zhidu.semantic_maintenance import maintain_semantics

    class Encoder:
        def encode(self, texts, timeout=120):
            return [[1.0, 0.0] for _ in texts]

    monkeypatch.setattr(
        "zhidu.semantic.model_manifest",
        lambda *args, **kwargs: {"digest": "test-only", "dimension": 2, "model": "test-only"},
    )
    ingest(database, store, advisory, "github-advisories")
    assert maintain_semantics(database, settings, encoder=Encoder())["changed"] > 0
    with database() as session:
        old = set(session.scalars(select(ChunkEmbedding.chunk_id)))
    changed = copy.deepcopy(advisory)
    changed.update(updated_at="2026-01-07T08:00:00Z", description="vLLM corrected source")
    ingest(database, store, changed, "github-advisories")
    with database() as session:
        assert not old.intersection(session.scalars(select(ChunkEmbedding.chunk_id)))
    assert maintain_semantics(database, settings, encoder=Encoder())["changed"] > 0
    assert maintain_semantics(database, settings, encoder=Encoder())["changed"] == 0


def ingest(database, store, payload, source):
    with database.begin() as session:
        ingest_document(
            session,
            store,
            json.dumps(payload).encode(),
            f"offline://week7/{source}",
            now_utc(),
            "replay",
            spec=SOURCES[source],
        )


def pair(database, store, advisory):
    for source, severity in (("github-advisories", "high"), ("vllm-vendor", "critical")):
        data = copy.deepcopy(advisory)
        data.update(summary="vLLM security", severity=severity)
        ingest(database, store, data, source)
    with database() as session:
        return session.scalar(
            select(IntelligenceComparison.id).where(IntelligenceComparison.field == "severity")
        )


def test_withdrawal_preserves_review_and_pending_task(database, store, settings, advisory):
    cid = pair(database, store, advisory)
    with TestClient(create_app(settings)) as client:
        response = client.patch(
            f"/api/v1/comparisons/{cid}/review",
            headers={"X-Admin-Key": "test-admin"},
            json={
                "expected_version": 0,
                "review_status": "acknowledged",
                "analyst_note": "retain note",
            },
        )
        assert response.status_code == 200
    with database.begin() as session:
        conversation = Conversation(title="fixture", state_version=0)
        session.add(conversation)
        session.flush()
        message = ConversationMessage(
            conversation_id=conversation.id, sequence=1, role="assistant", content="snapshot"
        )
        session.add(message)
        session.flush()
        task = EvidenceTask(
            conversation_id=conversation.id,
            message_id=message.id,
            comparison_id=cid,
            task_type="cross_source_conflict",
            missing_fields=[],
            target_sources=[],
            completion_conditions=[],
            evidence_refs=[],
        )
        session.add(task)
        session.flush()
        tid = task.id
    withdrawn = copy.deepcopy(advisory)
    withdrawn.update(
        summary="vLLM security",
        severity="critical",
        updated_at="2026-01-03T08:00:00Z",
        withdrawn_at="2026-01-03T08:00:00Z",
    )
    ingest(database, store, withdrawn, "vllm-vendor")
    with database.begin() as session:
        row = session.get(IntelligenceComparison, cid)
        assert not row.is_active and row.retired_at
        assert row.analyst_note == "retain note"
        assert session.get(EvidenceTask, tid).comparison_id == cid
        assert session.get(EvidenceTask, tid).status == "pending"
        history = session.scalars(
            select(ComparisonReviewChange)
            .where(ComparisonReviewChange.comparison_id == cid)
            .order_by(ComparisonReviewChange.annotation_version)
        ).all()
        assert [h.change_kind for h in history] == ["manual_review", "retired"]
        assert history[0].observations == history[1].observations
        assert sync_comparisons(session)["retired"] == 0
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/v1/comparisons").json()["total"] == 0
        assert client.get("/api/v1/comparisons?include_inactive=true").json()["total"] > 0
        assert (
            client.patch(
                f"/api/v1/comparisons/{cid}/review",
                headers={"X-Admin-Key": "test-admin"},
                json={
                    "expected_version": 2,
                    "review_status": "acknowledged",
                    "analyst_note": "stale",
                },
            ).status_code
            == 409
        )


def test_source_update_invalidates_stale_review(database, store, settings, advisory):
    cid = pair(database, store, advisory)
    updated = copy.deepcopy(advisory)
    updated.update(summary="vLLM security", severity="medium", updated_at="2026-01-04T08:00:00Z")
    ingest(database, store, updated, "vllm-vendor")
    with database() as session:
        row = session.get(IntelligenceComparison, cid)
        assert row.annotation_version == 1
        assert row.review_status == "needs_evidence"
        change = session.scalar(
            select(ComparisonReviewChange).where(ComparisonReviewChange.comparison_id == cid)
        )
        assert {o["value"] for o in change.observations} == {"high", "critical"}
        assert {o["value"] for o in row.observations} == {"high", "medium"}


def evaluate(ranges, ecosystem="pip"):
    component = SimpleNamespace(ecosystem=ecosystem, name="vllm", version="1.5.0", cpe=None)
    enrichment = SimpleNamespace(
        revision_id="rev",
        cpe_matches=[],
        version_ranges=[
            {
                "ecosystem": ecosystem,
                "package": "vllm",
                "source_kind": "affected_package",
                "vulnerable": parse_version_range(value),
            }
            for value in ranges
        ],
    )
    return evaluate_component(
        component, SimpleNamespace(id="event", source_id="source", external_id="id"), enrichment
    )


def test_alternative_ranges_use_union_and_unknown_prevents_exclusion():
    assert evaluate([">=1.0, <2.0", ">=3.0, <4.0"])["status"] == "affected"
    assert evaluate([">=3.0, <4.0", "unparseable"])["status"] == "unknown"
    assert evaluate([">=3.0, <4.0", ">=5.0"])["status"] == "not_affected"
    assert evaluate([">=1.0, <2.0"], "npm")["status"] == "unknown"


def test_environment_cpe_is_not_a_negative_vulnerability_assertion():
    component = SimpleNamespace(cpe="cpe:2.3:a:vllm:vllm:1.5.0:*:*:*:*:*:*:*", version="1.5.0")
    match = {"criteria": "cpe:2.3:a:vllm:vllm:*:*:*:*:*:*:*:*", "vulnerable": False}
    assert evaluate_cpe(component, match)[0] == "unknown"
    raw = {
        "configurations": [{"operator": "AND", "nodes": [{"operator": "OR", "cpeMatch": [match]}]}]
    }
    assert _cpe_matches(raw, "")[0]["requires_configuration_evaluation"] is True
    raw["configurations"][0]["operator"] = "OR"
    assert _cpe_matches(raw, "")[0]["requires_configuration_evaluation"] is False


@pytest.mark.parametrize(
    "data",
    [
        [],
        {"bomFormat": "CycloneDX"},
        {"bomFormat": "CycloneDX", "components": [{"purl": 123}]},
        {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:pypi/vllm@1.0", "version": "2.0"}]},
    ],
)
def test_invalid_sbom_fails_validation(data):
    with pytest.raises(ValueError):
        parse_cyclonedx(json.dumps(data).encode())
