"""Read-only functional drill on a restored bundle, with offline model inference."""

import argparse
import json
import time
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

import zhidu.api
from zhidu.api import create_app
from zhidu.backup import restored_settings
from zhidu.catalog import audit_catalog
from zhidu.db import make_engine, make_sessions
from zhidu.evidence import audit_all_evidence
from zhidu.models import IntelEvent, now_utc
from zhidu.storage import BlobStore


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.directory.resolve()
    settings = restored_settings(root)
    checks = {}
    checks["bundled_code_loaded"] = (
        Path(zhidu.api.__file__).resolve().is_relative_to(root / "code/src")
    )
    started = time.perf_counter()
    engine = make_engine(settings.database_url)
    with make_sessions(engine)() as session:
        evidence = audit_all_evidence(session, BlobStore(settings.raw_dir))
        catalog = audit_catalog(session, BlobStore(settings.raw_dir))
        first = session.scalar(select(IntelEvent.id))
    engine.dispose()
    checks["field_evidence"] = evidence["status"] == "passed"
    checks["catalog_evidence"] = catalog["status"] == "passed"
    with TestClient(create_app(settings)) as client:
        checks["readiness"] = client.get("/health/ready").status_code == 200
        checks["credential_isolation"] = (
            client.get("/health").json()["http_writes_enabled"] is False
        )
        checks["main_pages"] = all(
            client.get(path).status_code == 200
            for path in ["/", "/workspace", "/assets", "/catalog"]
        )
        trace = client.get(f"/api/v1/events/{first}/trace")
        checks["event_trace"] = (
            trace.status_code == 200 and trace.json()["summary"]["field_evidence_failed"] == 0
        )
        status = client.get("/api/v1/rag/status").json()
        checks["semantic_ready"] = status["status"] == "ready"
        retrieval_start = time.perf_counter()
        response = client.get(
            "/api/v1/rag/search",
            params={"q": "vllm audio decompression bomb", "mode": "hybrid", "limit": 3},
        )
        retrieval_ms = round((time.perf_counter() - retrieval_start) * 1000, 3)
        checks["offline_embedding_query"] = response.status_code == 200 and bool(
            response.json().get("items")
        )
    report = {
        "checked_at": now_utc().isoformat(),
        "status": "passed" if all(checks.values()) else "failed",
        "restored_directory": str(root),
        "checks": checks,
        "evidence": evidence,
        "catalog": catalog,
        "semantic_status": status,
        "embedding_request_ms": retrieval_ms,
        "total_drill_seconds": round(time.perf_counter() - started, 3),
        "scope": "restored code/database/raw/model; local TestClient; no upstream source collection; not a fresh-machine installation benchmark",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(
        json.dumps(
            {"status": report["status"], "checks": checks, "embedding_request_ms": retrieval_ms},
            ensure_ascii=False,
        )
    )
    raise SystemExit(0 if all(checks.values()) else 1)


if __name__ == "__main__":
    main()
