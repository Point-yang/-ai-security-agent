"""Read-only live-corpus check of the current hybrid RAG path."""

import argparse
import json

from sqlalchemy import func, select

from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.models import ChunkEmbedding, SearchChunk
from zhidu.rag import RagRequest, run_rag
from zhidu.semantic import LocalEncoder
from zhidu.storage import BlobStore


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--query", default="CVE-2025-30202")
    parser.add_argument("--question", default="CVE-2025-30202 的修复版本是什么？")
    args = parser.parse_args()
    settings = Settings()
    engine = make_engine(settings.database_url)
    sessions = make_sessions(engine)
    encoder = LocalEncoder(settings)
    try:
        with sessions() as session:
            chunks = session.scalar(select(func.count()).select_from(SearchChunk)) or 0
            vectors = session.scalar(select(func.count()).select_from(ChunkEmbedding)) or 0
            result = run_rag(
                session,
                BlobStore(settings.raw_dir),
                settings,
                RagRequest(
                    question=args.question,
                    query=args.query,
                    mode="hybrid",
                    generation="extractive",
                ),
                encoder,
            )
        report = {
            "read_only": True,
            "cloud_generation_requested": False,
            "chunks": chunks,
            "vectors": vectors,
            "mode": result["mode"],
            "retrieval_mode": result.get("retrieval", {}).get("mode"),
            "answer_class": result["answer_class"],
            "reason": result.get("reason"),
            "citations": len(result["citations"]),
            "elapsed_ms": result.get("elapsed_ms"),
        }
        print(json.dumps(report, ensure_ascii=False))
        if report["answer_class"] not in {"evidence", "partial"} or not report["citations"]:
            raise SystemExit(1)
    finally:
        encoder.close()
        engine.dispose()


if __name__ == "__main__":
    main()
