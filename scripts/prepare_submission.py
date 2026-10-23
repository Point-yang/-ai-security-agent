"""Build a new, portable submission from explicit source/evidence allowlists.

Never copies .env, private conversations, operational logs, checkpoints or backups.
The live SQLite source is opened read-only and exported through SQLite backup.
"""

import argparse
import hashlib
import json
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

ROOT_FILES = (
    "README.md",
    "pyproject.toml",
    "requirements.lock",
    "requirements-semantic.lock",
    "requirements-agent.lock",
    "alembic.ini",
    "Dockerfile",
    "compose.yaml",
    ".dockerignore",
    ".gitignore",
    ".env.example",
)
CODE_DIRS = ("src", "tests", "scripts", "migrations", "config", "examples", ".github")
PUBLIC_TABLES = {
    "alembic_version",
    "sources",
    "raw_documents",
    "events",
    "affected_packages",
    "event_aliases",
    "event_revisions",
    "event_changes",
    "event_triage",
    "search_chunks",
    "search_index_states",
    "event_enrichments",
    "enrichment_states",
    "chunk_embeddings",
    "catalog_items",
    "catalog_revisions",
    "intelligence_comparisons",
}
EVIDENCE = {
    "agent-stage6-release-20261013": (
        "report.json",
        "execution-audit.json",
        "adjudications.json",
        "gold-specs.json",
    ),
    "member-a-monitoring-enrichment-evaluation-20261009": (
        "frozen-enrichment.json",
        "difference-review.json",
        "verification.json",
        "manifest.json",
        "monitoring-evaluation.json",
        "current-source-conformity.json",
    ),
    "agent-allocation-development-20261015": (
        "engineering-audit.json",
        "execution-audit.json",
        "development-quote-review.json",
        "stopped.json",
        "tests.xml",
        "node-tests.txt",
    ),
    "agent-navigation-development-v2-20261015": (
        "summary.json",
        "execution-audit.json",
        "development-quote-review.json",
    ),
}
IGNORE_NAMES = {"__pycache__", ".pytest_cache", ".ruff_cache", ".DS_Store"}


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def build(root, destination):
    from zhidu.config import Settings
    from zhidu.semantic import model_manifest

    settings = Settings()
    if not settings.database_url.startswith("sqlite:///"):
        raise ValueError("Submission exporter currently requires SQLite")
    if destination.exists():
        raise FileExistsError("Choose a new destination; existing releases are never overwritten")
    if destination.is_relative_to(root / "data"):
        raise ValueError("Release destination cannot be inside the live data directory")
    destination.mkdir(parents=True)

    def copy(source, relative):
        source = Path(source)
        if source.is_symlink():
            raise ValueError(f"Symlink input is not accepted: {source.name}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)

    for name in ROOT_FILES:
        copy(root / name, name)
    for folder in CODE_DIRS:
        for source in sorted((root / folder).rglob("*")):
            if (
                source.is_file()
                and not any(p in IGNORE_NAMES or p.endswith(".egg-info") for p in source.parts)
                and source.suffix not in {".pyc", ".pyo"}
            ):
                copy(source, source.relative_to(root))
    for source in sorted((root / "docs/submission").rglob("*")):
        if source.is_file():
            copy(source, source.relative_to(root))
    # Small frozen reports referenced by historical contract tests, not obsolete runtimes.
    for name in (
        "member-b-agent-paired-v3-evaluation.json",
        "member-b-agent-paired-v4-evaluation.json",
    ):
        copy(root / "docs" / name, Path("docs") / name)
    evidence_index = []
    for folder, names in EVIDENCE.items():
        for name in names:
            source = root / "output" / folder / name
            if not source.is_file():
                raise FileNotFoundError(source)
            copy(source, Path("evidence") / folder / name)
            evidence_index.append(
                {
                    "file": f"evidence/{folder}/{name}",
                    "sha256": sha(source),
                    "kind": "unchanged_historical_evidence",
                }
            )
    write_json(destination / "evidence/index.json", evidence_index)

    db = destination / "data/zhidu.db"
    db.parent.mkdir(parents=True)
    original = Path(settings.database_url.removeprefix("sqlite:///")).resolve()
    with sqlite3.connect(original.as_uri() + "?mode=ro", uri=True) as source:
        with sqlite3.connect(db) as target:
            source.backup(target)
    with sqlite3.connect(db) as target:
        tables = {
            r[0]
            for r in target.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        assert PUBLIC_TABLES.issubset(tables)
        target.execute("PRAGMA secure_delete=ON")
        for table in tables - PUBLIC_TABLES:
            target.execute(f'DELETE FROM "{table}"')
        # Preserve public ingestion history, while excluding analyst annotations.
        target.execute("DELETE FROM event_changes WHERE change_type NOT IN ('created','updated')")
        for sequence, detail in target.execute("SELECT sequence,detail FROM event_changes"):
            source_change = json.loads(detail)
            public_change = {
                key: source_change[key]
                for key in ("revision", "disposition", "origin")
                if key in source_change
            }
            target.execute(
                "UPDATE event_changes SET detail=? WHERE sequence=?",
                (json.dumps(public_change), sequence),
            )
        target.execute(
            "UPDATE events SET analyst_note='', review_status='unreviewed', annotation_version=0"
        )
        target.execute(
            "UPDATE intelligence_comparisons SET analyst_note='', review_status='unreviewed', annotation_version=0, reviewed_at=NULL"
        )
        target.execute("""DELETE FROM raw_documents WHERE id NOT IN (
            SELECT raw_document_id FROM event_revisions UNION SELECT raw_document_id FROM catalog_items
            UNION SELECT raw_document_id FROM catalog_revisions UNION SELECT raw_document_id FROM search_chunks
        )""")
        target.commit()
        # VACUUM removes deleted private rows from free pages before distributing the database.
        target.execute("VACUUM")
        assert target.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert not target.execute("PRAGMA foreign_key_check").fetchall()
        documents = target.execute(
            "SELECT DISTINCT sha256,size_bytes FROM raw_documents"
        ).fetchall()
        counts = {
            table: target.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            for table in sorted(tables)
        }
        assert all(counts[t] == 0 for t in tables - PUBLIC_TABLES)
    for digest, size in documents:
        source = settings.raw_dir / digest[:2] / f"{digest}.json"
        assert source.stat().st_size == size and sha(source) == digest
        copy(source, f"data/raw/{digest[:2]}/{digest}.json")
    model = model_manifest(settings, verify=True)
    for name in model["files"]:
        copy(Path(model["path"]) / name, Path("data/models/files") / name)
    # Relative path makes the existing model digest usable on another machine.
    write_json(destination / "data/models/manifest.json", {**model, "path": "data/models/files"})
    write_json(
        destination / "data/SNAPSHOT.json",
        {
            "created_at": datetime.now(UTC).isoformat(),
            "kind": "sanitized_public_intelligence_snapshot",
            "historical_collection_origin_preserved": True,
            "live_collector_state_included": False,
            "personal_sessions_and_assets_included": False,
            "private_tables_cleared": sorted(tables - PUBLIC_TABLES),
            "counts": counts,
            "raw_file_count": len(documents),
            "raw_bytes": sum(row[1] for row in documents),
            "model_digest": model["digest"],
        },
    )
    print(
        json.dumps(
            {
                "destination": str(destination),
                "events": counts["events"],
                "raw_files": len(documents),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(Path.cwd().resolve(), args.output.resolve())
