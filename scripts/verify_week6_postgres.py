"""Offline fixture checks against a dedicated PostgreSQL acceptance database.

Refuses normal database names. No real source collection is performed.
"""

import argparse
import json
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.engine import make_url

from zhidu.api import create_app
from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.ingest import ingest_document
from zhidu.locking import writer_lock
from zhidu.models import IntelEvent, SearchChunk, now_utc
from zhidu.operations import doctor, operational_snapshot, save_operational_evaluation
from zhidu.storage import BlobStore


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--after-restart", action="store_true")
    args = parser.parse_args()
    settings = Settings()
    url = make_url(settings.database_url)
    if url.get_backend_name() != "postgresql" or not url.database.startswith("zhidu_acceptance_"):
        raise SystemExit("Requires an isolated PostgreSQL database named zhidu_acceptance_*")
    checks = {}
    migration = Config("alembic.ini")
    command.upgrade(migration, "head")
    command.check(migration)
    checks["migration_matches_models"] = True
    engine = make_engine(settings.database_url)
    sessions = make_sessions(engine)
    store = BlobStore(settings.raw_dir)
    content = Path("examples/ghsa-demo-v1.json").read_bytes()
    with writer_lock(settings.database_url), sessions.begin() as session:
        if args.after_restart:
            checks["fixture_survived_restart"] = session.scalar(select(IntelEvent.id)) is not None
        result = ingest_document(
            session, store, content, "offline://postgres-week6", now_utc(), "replay"
        )
        checks["idempotent_ingestion"] = (
            result["unchanged"] == 1
            if args.after_restart
            else result["created"] + result["unchanged"] == 1
        )
        session.execute(delete(SearchChunk))
        checks["missing_index_detected"] = (
            operational_snapshot(session, store, [])["status"] == "degraded"
        )
        repair = doctor(session, store, [], repair=True)
        checks["index_rebuilt"] = repair["derived_reconciliation"]["index"]["changed_events"] == 1
        snapshot = operational_snapshot(session, store, [])
        save_operational_evaluation(session, snapshot)
        checks["snapshot_persisted"] = snapshot["status"] == "passed"
        checks["repeat_repair_unchanged"] = (
            doctor(session, store, [], repair=True)["derived_reconciliation"]["index"][
                "changed_events"
            ]
            == 0
        )
    with TestClient(create_app(settings)) as client:
        checks["readiness"] = client.get("/health/ready").status_code == 200
        checks["metrics"] = "zhidu_events_total 1" in client.get("/metrics").text
        checks["report_api"] = (
            client.get("/api/v1/operations/evaluations").json()[0]["status"] == "passed"
        )
    engine.dispose()
    report = {
        "checked_at": now_utc().isoformat(),
        "status": "passed" if all(checks.values()) else "failed",
        "database": url.database,
        "dialect": "postgresql",
        "after_container_restart": args.after_restart,
        "checks": checks,
        "scope": "host Python API against container PostgreSQL; synthetic replay fixture, no live collection",
        "api_container_build_verified": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    raise SystemExit(0 if all(checks.values()) else 1)


if __name__ == "__main__":
    main()
