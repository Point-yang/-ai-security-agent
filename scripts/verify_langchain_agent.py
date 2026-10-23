"""Bounded live compatibility smoke on a SQLite backup, never a holdout score."""

import argparse
import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.engine import make_url

from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.langchain_agent import backend_status, run_langchain_agent
from zhidu.models import IntelEvent
from zhidu.rag import RagRequest
from zhidu.storage import BlobStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Allow a bounded real model request")
    parser.add_argument("--cases", type=int, choices=[1, 2], default=1)
    parser.add_argument("--output", type=Path, required=True, help="New directory; never overwrite")
    args = parser.parse_args()
    settings = Settings()
    if not args.live:
        print(json.dumps(backend_status()))
        return
    if not settings.deepseek_api_key.get_secret_value():
        raise SystemExit("DeepSeek key is not configured")
    url = make_url(settings.database_url)
    if url.get_backend_name() != "sqlite":
        raise SystemExit("This smoke script requires a SQLite backup")
    args.output.mkdir(parents=True, exist_ok=False)
    snapshot = args.output / "evaluation.db"
    with (
        sqlite3.connect(f"file:{Path(url.database).resolve()}?mode=ro", uri=True) as source,
        sqlite3.connect(snapshot) as target,
    ):
        source.backup(target)
        if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise SystemExit("Backup integrity check failed")
    snapshot_sha = hashlib.sha256(snapshot.read_bytes()).hexdigest()
    frozen = settings.model_copy(
        update={"database_url": f"sqlite:///{snapshot}", "agent_deadline_seconds": 30}
    )
    engine = make_engine(frozen.database_url)
    sessions = make_sessions(engine)
    rows = []
    with sessions() as session:
        identifiers = session.scalars(
            select(IntelEvent.external_id)
            .where(
                IntelEvent.source_id == "github-advisories",
                IntelEvent.withdrawn_at.is_(None),
                IntelEvent.title.ilike("%vllm%"),
            )
            .order_by(IntelEvent.published_at.desc())
            .limit(args.cases)
        ).all()
    if len(identifiers) != args.cases:
        raise SystemExit("Not enough current public records for smoke")
    for identifier in identifiers:
        request = RagRequest(
            question=f"依据当前来源，{identifier} 的受影响范围与修复字段分别是什么？请保留原始范围并说明证据边界。",
            query=identifier,
            mode="lexical",
            generation="agent",
            agent_backend="langchain",
        )
        with sessions() as session:
            result = run_langchain_agent(
                session, BlobStore(settings.raw_dir), frozen, request, None
            )
        rows.append({"request": request.model_dump(), "result": result})
    engine.dispose()
    if hashlib.sha256(snapshot.read_bytes()).hexdigest() != snapshot_sha:
        raise SystemExit("The read-only smoke changed its database snapshot")
    report = {
        "version": "langchain-native-tool-smoke-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "scope": "known current public-source compatibility smoke; not a holdout or accuracy result",
        "backend": backend_status(),
        "snapshot_sha256": snapshot_sha,
        "snapshot_unchanged": True,
        "rows": rows,
        "completed": sum(r["result"]["generation"]["status"] == "completed" for r in rows),
        "external_requests": sum(r["result"]["cost"]["external_requests"] for r in rows),
    }
    with (args.output / "live-smoke.json").open("x") as f:
        f.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(
        json.dumps(
            {
                "output": str(args.output / "live-smoke.json"),
                "completed": report["completed"],
                "cases": len(rows),
                "external_requests": report["external_requests"],
            }
        )
    )


if __name__ == "__main__":
    main()
