"""Read-only release evidence bundle; never fabricate human labels or uptime."""

import argparse
import hashlib
import json
from pathlib import Path

from sqlalchemy import func, select

from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.evidence import audit_all_evidence
from zhidu.models import (
    ChunkEmbedding,
    ComparisonReviewChange,
    EventRevision,
    IntelEvent,
    IntelligenceComparison,
    SearchChunk,
    now_utc,
)
from zhidu.monitor import load_targets
from zhidu.monitoring_experiment import window_report
from zhidu.operations import operational_snapshot
from zhidu.semantic import ModelUnavailable, content_digest, model_manifest
from zhidu.storage import BlobStore


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    settings = Settings()
    engine = make_engine(settings.database_url)
    store = BlobStore(settings.raw_dir)
    with make_sessions(engine)() as session:
        ops = operational_snapshot(session, store, load_targets(settings.monitor_config))
        evidence = audit_all_evidence(session, store)
        window = window_report(session, load_targets(settings.monitor_config), hours=24)
        chunks = session.scalars(select(SearchChunk)).all()
        vectors = {v.chunk_id: v for v in session.scalars(select(ChunkEmbedding))}
        try:
            manifest = model_manifest(settings, verify=True)
            valid = sum(
                c.id in vectors
                and vectors[c.id].model_key == manifest["digest"]
                and vectors[c.id].content_sha256 == content_digest(c)
                and len(vectors[c.id].vector) == manifest["dimension"]
                for c in chunks
            )
            semantic = {
                "status": "ready" if valid == len(chunks) else "incomplete",
                "valid": valid,
                "chunks": len(chunks),
                "model_digest": manifest["digest"],
            }
        except ModelUnavailable:
            semantic = {"status": "model_unavailable", "valid": None, "chunks": len(chunks)}
        counts = {
            m.__tablename__: session.scalar(select(func.count()).select_from(m))
            for m in (IntelEvent, EventRevision, ComparisonReviewChange)
        }
        counts["active_comparisons"] = session.scalar(
            select(func.count())
            .select_from(IntelligenceComparison)
            .where(IntelligenceComparison.is_active.is_(True))
        )
        counts["inactive_comparisons"] = session.scalar(
            select(func.count())
            .select_from(IntelligenceComparison)
            .where(IntelligenceComparison.is_active.is_(False))
        )
    engine.dispose()
    code_paths = sorted(
        [
            *Path("src").rglob("*.py"),
            *Path("migrations").rglob("*.py"),
            *Path("tests").glob("test_member_a_week7.py"),
        ]
    )
    digests = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in code_paths}
    checks = {
        "raw_integrity": ops["integrity"]["failed"] == 0,
        "field_evidence": evidence["status"] == "passed",
        "operational_health": ops["status"] == "passed",
        "semantic_completeness": semantic["status"] == "ready",
    }
    report = {
        "checked_at": now_utc().isoformat(),
        "schema_version": "week7-release-evidence-v1",
        "engineering_checks": checks,
        "engineering_status": "passed" if all(checks.values()) else "attention_required",
        "release_ready": False,
        "release_gaps": [
            "independent_human_gold_pending",
            "B_answer_quality_reacceptance_pending",
            "continuous_monitoring_SLA_unproven",
            "blog_standard_policy_POC_sources_pending",
        ],
        "counts": counts,
        "evidence": evidence,
        "operations": ops,
        "semantic": semantic,
        "monitoring_window": window,
        "code_sha256": hashlib.sha256(json.dumps(digests, sort_keys=True).encode()).hexdigest(),
        "files": digests,
        "note": "Read-only engineering evidence; not permission to freeze or a competition score.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n")
    print(
        json.dumps(
            {"output": str(args.output), "engineering_checks": checks, "release_ready": False},
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
