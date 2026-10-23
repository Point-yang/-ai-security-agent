"""Loopback-only isolated page fixture; never reads or mutates the main DB."""

import argparse
import hashlib
import json
from datetime import timedelta
from pathlib import Path

import httpx
import uvicorn
from sqlalchemy import delete

import zhidu.api as api_module
from zhidu.catalog import ingest_catalog
from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.ingest import ensure_source, ingest_document
from zhidu.locking import writer_lock
from zhidu.models import Base, ChunkEmbedding, CollectionRun, MonitorState, now_utc
from zhidu.monitor import SourceHTTP, load_targets, sync_target
from zhidu.semantic import digest, sync_embeddings
from zhidu.sources import SOURCES
from zhidu.storage import BlobStore


class FixtureEncoder:
    def __init__(self, *_):
        pass

    def encode(self, texts, **_):
        return [[1.0, 0.0] for _ in texts]

    def close(self):
        pass


def build_app(root):
    root.mkdir(parents=True, exist_ok=True)
    database = root / "isolated.db"
    if database.exists():
        raise ValueError("isolated fixture exists; choose a new --directory")
    model = root / "model"
    model.mkdir()
    model.joinpath("fixture.bin").write_text("fixture-only-no-model-inference")
    files = {"fixture.bin": hashlib.sha256(model.joinpath("fixture.bin").read_bytes()).hexdigest()}
    manifest = root / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "model": "sentence-transformers/all-MiniLM-L6-v2",
                "path": str(model.resolve()),
                "files": files,
                "digest": digest(files),
                "dimension": 2,
            }
        )
    )
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite:///{database.resolve()}",
        raw_dir=root / "raw",
        embedding_manifest=manifest,
        monitor_config=Path("config/sources.json"),
        llm_provider="extractive",
        admin_key="isolated-review-key",
        github_token="",
        deepseek_api_key="",
    )
    engine = make_engine(settings.database_url)
    Base.metadata.create_all(engine)
    sessions = make_sessions(engine)
    targets = load_targets(settings.monitor_config)
    advisory = json.loads(Path("examples/ghsa-demo-v1.json").read_text())
    advisory.update(
        summary="隔离测试 vLLM input validation",
        description="Isolated test vLLM input validation; no real vulnerability finding.",
    )
    advisory["vulnerabilities"][0]["package"]["name"] = "vllm"
    content = json.dumps([advisory]).encode()
    with sessions.begin() as session:
        ingest_document(
            session,
            BlobStore(settings.raw_dir),
            content,
            "offline://isolated-page-test",
            now_utc(),
            "live",
        )
        for target in targets:
            ensure_source(session, SOURCES[target.source])
            run = CollectionRun(
                source_id=target.source,
                scope=f"monitor:{target.id}:{target.fingerprint[:16]}",
                status="completed",
                started_at=now_utc() - timedelta(hours=6),
                finished_at=now_utc() - timedelta(hours=6),
                stats={},
            )
            session.add(run)
            session.flush()
            session.add(
                MonitorState(
                    target_id=target.id,
                    config_hash=target.fingerprint,
                    status="completed",
                    last_run_id=run.id,
                    last_success_at=now_utc(),
                    heartbeat_at=now_utc(),
                    next_run_at=now_utc() + timedelta(seconds=target.interval_seconds),
                )
            )
        sync_embeddings(session, settings, FixtureEncoder())
        for origin in ("live", "replay"):
            blog = {
                "allBlogs": [
                    {
                        "_id": f"fixture-{origin}",
                        "title": f"AI security fixture {origin}",
                        "url": f"/blog/fixture-{origin}",
                        "publishedAt": now_utc().isoformat(),
                    }
                ]
            }
            ingest_catalog(
                session,
                BlobStore(settings.raw_dir),
                json.dumps(blog).encode(),
                source_id="hf-blog",
                url="offline://isolated-catalog-test",
                fetched_at=now_utc(),
                origin=origin,
            )
    api_module.LocalEncoder = FixtureEncoder
    scenario = {"value": "recovered"}
    api_module.worker_snapshot = lambda _: {
        "status": "healthy",
        "check_method": "isolated_fixture_controlled_pulse",
        "fixture_controlled": True,
        "target_progress_heartbeat_used": False,
        "process_uptime_measured": False,
    }
    app = api_module.create_app(settings)

    @app.post("/__fixture/scenario/{name}")
    def set_scenario(name: str):
        if name not in {"failure", "recovered", "stale", "incomplete"}:
            return {"error": "unknown fixture"}
        scenario["value"] = name
        with writer_lock(settings.database_url), sessions.begin() as session:
            for target in targets:
                state = session.get(MonitorState, target.id)
                state.status, state.failures = "completed", 0
                state.last_success_at = now_utc() - (
                    timedelta(days=3) if name == "stale" else timedelta()
                )
                state.next_run_at = now_utc() + timedelta(seconds=target.interval_seconds)
            if name == "incomplete":
                session.execute(delete(ChunkEmbedding))
            else:
                sync_embeddings(session, settings, FixtureEncoder())
        if name in {"failure", "recovered"}:

            def response(request):
                if name == "failure":
                    raise httpx.ConnectTimeout(
                        "private proxy and token must never display", request=request
                    )
                return httpx.Response(200, content=content)

            with httpx.Client(transport=httpx.MockTransport(response)) as client:
                transport = SourceHTTP(settings, client, sleeper=lambda _: None)
                with writer_lock(settings.database_url):
                    for _ in range(2 if name == "failure" else 1):
                        sync_target(sessions, settings, targets[0], transport=transport)
            if name == "failure":
                with sessions.begin() as session:
                    session.get(MonitorState, targets[0].id).last_success_at = (
                        now_utc() - timedelta(days=3)
                    )
        return {
            "scenario": name,
            "isolated": True,
            "cloud_generation": False,
            "real_embedding_inference": False,
        }

    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8036)
    args = parser.parse_args()
    uvicorn.run(build_app(args.directory), host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
