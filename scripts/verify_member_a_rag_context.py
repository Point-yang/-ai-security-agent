"""Read-only real-corpus context audit; no model API call or gold accuracy claim."""

import argparse
import json
from pathlib import Path

from sqlalchemy import func, select

from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.evidence import audit_all_evidence
from zhidu.models import ChunkEmbedding, SearchChunk, now_utc
from zhidu.rag import RagRequest, run_rag
from zhidu.semantic import content_digest, model_manifest
from zhidu.storage import BlobStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    settings = Settings()
    engine = make_engine(settings.database_url)
    store = BlobStore(settings.raw_dir)
    try:
        with make_sessions(engine)() as session:
            audit = audit_all_evidence(session, store)
            rows = session.scalars(select(SearchChunk)).all()
            vectors = {v.chunk_id: v for v in session.scalars(select(ChunkEmbedding))}
            model = model_manifest(settings)
            valid = sum(
                r.id in vectors
                and vectors[r.id].model_key == model["digest"]
                and vectors[r.id].content_sha256 == content_digest(r)
                for r in rows
            )
            cases = []
            for query in ["GHSA-2pc9-4j83-qjmr", "GHSA-6pr9-rp53-2pmc"]:
                request = RagRequest(
                    question="该公告影响哪些版本，有什么修复依据？",
                    query=query,
                    mode="lexical",
                    generation="extractive",
                )
                old = run_rag(
                    session,
                    store,
                    settings,
                    request.model_copy(update={"context_mode": "baseline"}),
                    None,
                )
                expanded = run_rag(session, store, settings, request, None)
                cases.append(
                    {
                        "query": query,
                        "baseline_fields": sorted({c["field"] for c in old["citations"]}),
                        "baseline_citations": len(old["citations"]),
                        "expanded_fields": sorted({c["field"] for c in expanded["citations"]}),
                        "context": expanded.get("context"),
                        "answer_class": expanded["answer_class"],
                        "reason": expanded.get("reason"),
                        "external_requests": expanded["cost"]["external_requests"],
                        "citations": [
                            {
                                "field": c["field"],
                                "source_id": c["source_id"],
                                "revision": c["revision"],
                                "json_pointer": c["json_pointer"],
                                "sha256": c["sha256"],
                            }
                            for c in expanded["citations"]
                        ],
                    }
                )
            checks = {
                "raw_field_evidence": audit["status"] == "passed",
                "vectors_current": valid == len(rows),
                "context_sources_available": all(
                    c["context"] and c["context"]["sources"] for c in cases
                ),
                "package_context_present": all("packages" in c["expanded_fields"] for c in cases),
                "no_cloud_requests": all(c["external_requests"] == 0 for c in cases),
            }
            report = {
                "checked_at": now_utc().isoformat(),
                "status": "passed" if all(checks.values()) else "failed",
                "checks": checks,
                "chunks": len(rows),
                "valid_vectors": valid,
                "fields": dict(
                    session.execute(
                        select(SearchChunk.field, func.count()).group_by(SearchChunk.field)
                    ).all()
                ),
                "evidence_audit": audit,
                "cases": cases,
                "scope": "Two known-source engineering cases; no independent gold correctness score.",
            }
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(
            json.dumps(
                {k: report[k] for k in ("status", "checks", "chunks", "valid_vectors")},
                ensure_ascii=False,
            )
        )
        raise SystemExit(0 if all(checks.values()) else 1)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
