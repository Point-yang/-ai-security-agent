"""Verify the portable release in an isolated database without cloud model calls."""

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    sys.path.insert(0, str(root / "src"))
    if not (root / "data/SNAPSHOT.json").is_file():
        raise SystemExit("Run this verifier inside the exported submission directory.")
    from fastapi.testclient import TestClient

    from zhidu.api import create_app
    from zhidu.config import Settings
    from zhidu.semantic import model_manifest

    checks = {}
    manifest = root / "MANIFEST.json"
    if manifest.is_file():
        entries = json.loads(manifest.read_text())["files"]
        for name, digest in entries.items():
            with (root / name).open("rb") as stream:
                assert hashlib.file_digest(stream, "sha256").hexdigest() == digest, name
        checks["file_hashes_verified"] = len(entries)
    snapshot = json.loads((root / "data/SNAPSHOT.json").read_text())
    with sqlite3.connect((root / "data/zhidu.db").as_uri() + "?mode=ro", uri=True) as db:
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert not db.execute("PRAGMA foreign_key_check").fetchall()
        for table in snapshot["private_tables_cleared"]:
            assert db.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0] == 0, table
        for digest, size in db.execute("SELECT DISTINCT sha256,size_bytes FROM raw_documents"):
            blob = root / "data/raw" / digest[:2] / f"{digest}.json"
            assert blob.stat().st_size == size
            assert hashlib.sha256(blob.read_bytes()).hexdigest() == digest
        checks["database_integrity"] = "passed"
        checks["private_tables_empty"] = len(snapshot["private_tables_cleared"])
        checks["raw_files_verified"] = snapshot["raw_file_count"]
    with tempfile.TemporaryDirectory(prefix="zhidu-submission-check-") as temp:
        scratch = Path(temp)
        shutil.copyfile(root / "data/zhidu.db", scratch / "check.sqlite")
        settings = Settings(
            _env_file=None,
            database_url=f"sqlite:///{scratch / 'check.sqlite'}",
            raw_dir=root / "data/raw",
            embedding_manifest=root / "data/models/manifest.json",
            embedding_cache=scratch / "models",
            monitor_config=root / "config/sources.json",
            rag_config=root / "config/member-b-week6-router-v2.json",
            agent_checkpoint_path=scratch / "checkpoints.sqlite",
            human_review_dir=scratch / "reviews",
            llm_provider="extractive",
            deepseek_api_key="",
            agent_model_api_key="",
            github_token="",
            admin_key="",
        )
        model_manifest(settings, verify=True)
        checks["portable_model_hashes"] = "passed"
        with TestClient(create_app(settings)) as client:
            for endpoint in (
                "/health/ready",
                "/workspace",
                "/assets",
                "/catalog",
                "/api/v1/rag/status",
                "/api/v1/release/evidence",
            ):
                assert client.get(endpoint).status_code == 200, endpoint
            evidence = client.get("/api/v1/release/evidence").json()
            assert evidence["status"] == "available"
            assert evidence["gold"]["method"] == "project_ai_review"
            for item in evidence["sources"]:
                source = root / item["file"]
                assert hashlib.sha256(source.read_bytes()).hexdigest() == item["sha256"]
            checks["published_evidence_sources_verified"] = len(evidence["sources"])
            for html in (root / "src/zhidu/static").glob("*.html"):
                for url in re.findall(
                    r'(?:src|href)=["\'](/static/[^"\']+)["\']', html.read_text()
                ):
                    assert client.get(url).status_code == 200, url
            events = client.get("/api/v1/events", params={"alias": "CVE-2026-73557"}).json()
            assert events["total"] >= 3
            checks["demo_case_source_count"] = events["total"]
            for event in events["items"]:
                for suffix in ("history", "evidence", "enrichment"):
                    assert client.get(f"/api/v1/events/{event['id']}/{suffix}").status_code == 200
            comparison = client.get(
                "/api/v1/comparisons", params={"identifier": "CVE-2026-73557"}
            ).json()
            assert comparison["total"] > 0
            checks["comparison_fields"] = comparison["total"]
            for mode in ("lexical", "hybrid"):
                response = client.get(
                    "/api/v1/rag/search", params={"q": "CVE-2026-73557", "mode": mode}
                )
                assert response.status_code == 200, (mode, response.status_code)
                assert response.json()["items"], mode
                checks[f"{mode}_retrieval"] = "passed"
    result = {"status": "passed", "cloud_model_calls": 0, "checks": checks}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
