"""Explicit semantic maintenance and frozen evaluation commands."""

import argparse
import json
from pathlib import Path

from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.locking import writer_lock
from zhidu.semantic import LocalEncoder, sync_embeddings
from zhidu.storage import BlobStore


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["semantic-sync", "benchmark"])
    parser.add_argument(
        "--dataset", type=Path, default=Path("config/member-b-week6-frozen-qa.json")
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, choices=range(1, 11), default=2)
    parser.add_argument("--concurrency", type=int, choices=[1, 2, 4], default=1)
    args = parser.parse_args()
    settings = Settings()
    engine = make_engine(settings.database_url)
    sessions = make_sessions(engine)
    encoder = LocalEncoder(settings)
    try:
        if args.command == "semantic-sync":
            with writer_lock(settings.database_url), sessions.begin() as session:
                report = sync_embeddings(session, settings, encoder)
        else:
            from zhidu.rag_benchmark import benchmark

            report = benchmark(
                sessions,
                BlobStore(settings.raw_dir),
                settings,
                args.dataset,
                repeats=args.repeats,
                concurrency=args.concurrency,
            )
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n")
        print(json.dumps({"output": str(args.output), "status": "completed"}))
    finally:
        encoder.close()
        engine.dispose()


if __name__ == "__main__":
    main()
