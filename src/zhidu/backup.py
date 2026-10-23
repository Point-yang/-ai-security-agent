"""Local SQLite recovery bundles. Never overwrite live data or include .env secrets."""

import argparse
import hashlib
import json
import platform
import shutil
import sqlite3
import sys
from pathlib import Path, PurePosixPath

from sqlalchemy.engine import make_url

from zhidu.config import Settings
from zhidu.locking import writer_lock
from zhidu.models import now_utc
from zhidu.storage import BlobStore

FORMAT = "zhidu-recovery-v1"
ROOT_FILES = (
    "README.md",
    "pyproject.toml",
    "requirements.lock",
    "requirements-agent.lock",
    "requirements-semantic.lock",
    "alembic.ini",
    "Dockerfile",
    "compose.yaml",
    ".dockerignore",
    ".gitignore",
    ".env.example",
)
SOURCE_DIRS = ("src", "migrations", "config", "scripts", "examples", "tests", "docs", ".github")
SUFFIXES = {".py", ".json", ".html", ".css", ".js", ".mjs", ".md", ".yaml", ".yml", ".sh"}


def file_hash(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def canonical_hash(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()


def safe_path(root, relative):
    path = PurePosixPath(relative)
    if not path.parts or path.is_absolute() or ".." in path.parts or "\\" in relative:
        raise ValueError("invalid path in recovery manifest")
    candidate = root.joinpath(*path.parts)
    if not candidate.resolve().is_relative_to(root.resolve()):
        raise ValueError("recovery path escapes its directory")
    if any(p.is_symlink() for p in (candidate, *candidate.parents) if p != root.parent):
        raise ValueError("symlinks are not accepted in recovery files")
    return candidate


def read_snapshot(path):
    with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as connection:
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("SQLite integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone():
            raise ValueError("SQLite foreign key check failed")
        tables = {
            r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "raw_documents" not in tables:
            raise ValueError("database is not a zhidu snapshot")
        documents = connection.execute("SELECT sha256,size_bytes FROM raw_documents").fetchall()
        counts = {
            name: connection.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
            for name in (
                "events",
                "event_revisions",
                "raw_documents",
                "search_chunks",
                "chunk_embeddings",
                "catalog_items",
                "rag_runs",
            )
            if name in tables
        }
        schema = (
            connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
            if "alembic_version" in tables
            else "unversioned"
        )
    return {"schema": schema, "counts": counts, "documents": documents}


def create_backup(settings, output, *, project_root=None, include_model=False):
    output = Path(output).resolve()
    root = Path(project_root or Path.cwd()).resolve()
    url = make_url(settings.database_url)
    if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
        raise ValueError("this bundle command requires SQLite; use pg_dump for PostgreSQL")
    database = Path(url.database).resolve()
    if not database.is_file():
        raise ValueError("source database does not exist")
    # A new directory only. A failed/incomplete creation has no final manifest.
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    entries = {}

    def add(source, relative):
        source = Path(source)
        if source.is_symlink():
            raise ValueError("refuse symlink backup input")
        destination = safe_path(output, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.resolve() != destination.resolve():
            shutil.copyfile(source, destination)
        entries[relative] = {"sha256": file_hash(destination), "bytes": destination.stat().st_size}

    snapshot = output / "data/zhidu.db"
    snapshot.parent.mkdir(parents=True)
    with writer_lock(settings.database_url):
        with sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True) as source:
            with sqlite3.connect(snapshot) as destination:
                source.backup(destination)
    snapshot_info = read_snapshot(snapshot)
    add(snapshot, "data/zhidu.db")
    store = BlobStore(settings.raw_dir)
    for digest, size in set(snapshot_info["documents"]):
        source = store.path_for(digest)
        if file_hash(source) != digest or source.stat().st_size != size:
            raise ValueError("raw evidence mismatch; backup aborted")
        add(source, f"data/raw/{digest[:2]}/{digest}.json")

    # Enumerated project files, never whole-workspace copying (no .env, .git,
    # virtualenv, raw work directories, credentials or unrelated app caches).
    code_files = [root / name for name in ROOT_FILES if (root / name).is_file()]
    for directory in SOURCE_DIRS:
        code_files.extend(
            p
            for p in (root / directory).rglob("*")
            if p.is_file() and p.suffix in SUFFIXES and "__pycache__" not in p.parts
        )
    for file in sorted(set(code_files)):
        if file.is_relative_to(output):
            continue
        add(file, "code/" + file.relative_to(root).as_posix())
    # Capture the actual selected non-secret runtime policies even if custom.
    for source, name in (
        (settings.monitor_config, "monitor.json"),
        (settings.rag_config, "rag.json"),
    ):
        json.loads(Path(source).read_text())
        add(source, "runtime/" + name)
    reviews = []
    if settings.human_review_dir.is_dir():
        for file in sorted(settings.human_review_dir.glob("*.json")):
            add(file, "data/human-review/" + file.name)
            reviews.append(file.name)

    model_data = None
    if include_model:
        from zhidu.semantic import model_manifest

        model_data = model_manifest(settings, verify=True)
        for name in model_data["files"]:
            source = safe_path(Path(model_data["path"]).resolve(), name)
            add(source, "data/model/files/" + name)
        # Relocatable in the bundle; restore rewrites only this path.
        portable_model = {**model_data, "path": "data/model/files"}
        model_path = output / "data/model/manifest.json"
        model_path.write_text(json.dumps(portable_model, indent=2) + "\n")
        add(model_path, "data/model/manifest.json")
    manifest = {
        "format": FORMAT,
        "created_at": now_utc().isoformat(),
        "schema": snapshot_info["schema"],
        "counts": snapshot_info["counts"],
        "python": platform.python_version(),
        "platform": platform.platform(),
        "files": entries,
        "model_included": include_model,
        "model_digest": model_data["digest"] if model_data else None,
        "human_review_files": reviews,
        "credentials_included": False,
        "dependency_runtime_included": False,
        "scope": "local private recovery bundle; dependency installation and credentials are separate",
    }
    manifest["manifest_sha256"] = canonical_hash(manifest)
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    return verify_backup(output)


def verify_backup(bundle):
    bundle = Path(bundle).resolve()
    manifest = json.loads((bundle / "manifest.json").read_text())
    claimed = manifest.pop("manifest_sha256")
    if manifest.get("format") != FORMAT or canonical_hash(manifest) != claimed:
        raise ValueError("invalid or modified recovery manifest")
    files = manifest["files"]
    if "data/zhidu.db" not in files:
        raise ValueError("snapshot is missing from the manifest")
    for name, entry in files.items():
        file = safe_path(bundle, name)
        if file.name == ".env":
            raise ValueError("credential files cannot be restored from this bundle")
        if file.stat().st_size != entry["bytes"] or file_hash(file) != entry["sha256"]:
            raise ValueError(f"recovery file checksum mismatch: {name}")
    info = read_snapshot(bundle / "data/zhidu.db")
    for digest, size in info["documents"]:
        relative = f"data/raw/{digest[:2]}/{digest}.json"
        if (
            relative not in files
            or files[relative]["sha256"] != digest
            or files[relative]["bytes"] != size
        ):
            raise ValueError("snapshot references missing or inconsistent raw evidence")
    if info["schema"] != manifest["schema"] or info["counts"] != manifest["counts"]:
        raise ValueError("snapshot metadata differs from manifest")
    if manifest["model_included"]:
        model = json.loads(safe_path(bundle, "data/model/manifest.json").read_text())
        for name, digest in model["files"].items():
            relative = "data/model/files/" + name
            safe_path(bundle, relative)
            if relative not in files or files[relative]["sha256"] != digest:
                raise ValueError("model files differ from the runtime manifest")
        if (
            model["digest"] != manifest["model_digest"]
            or canonical_hash(model["files"]) != model["digest"]
        ):
            raise ValueError("model digest differs from backup")
    return {
        "status": "passed",
        "bundle": str(bundle),
        "manifest_sha256": claimed,
        "files_verified": len(files),
        "bytes_verified": sum(v["bytes"] for v in files.values()),
        "counts": info["counts"],
        "schema": info["schema"],
        "model_included": manifest["model_included"],
        "credentials_included": False,
        "note": "Checksums detect corruption; they are not a trusted digital signature.",
    }


def restore_backup(bundle, destination):
    bundle, destination = Path(bundle).resolve(), Path(destination).resolve()
    verification = verify_backup(bundle)
    manifest = json.loads((bundle / "manifest.json").read_text())
    # This is intentionally never an in-place database replacement.
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    for name in manifest["files"]:
        source, target = safe_path(bundle, name), safe_path(destination, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if file_hash(target) != manifest["files"][name]["sha256"]:
            raise ValueError("restored file checksum mismatch")
    if manifest["model_included"]:
        model_path = destination / "data/model/manifest.json"
        model = json.loads(model_path.read_text())
        model["path"] = str(destination / "data/model/files")
        model_path.write_text(json.dumps(model, indent=2) + "\n")
    result = {
        "status": "restored",
        "destination": str(destination),
        "backup_manifest_sha256": verification["manifest_sha256"],
        "counts": verification["counts"],
        "restored_files_verified": verification["files_verified"],
        "model_path_relocated": manifest["model_included"],
        "credentials_restored": False,
    }
    (destination / "restore-report.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def restored_settings(directory):
    root = Path(directory).resolve()
    report = json.loads((root / "restore-report.json").read_text())
    if report.get("status") != "restored":
        raise ValueError("incomplete restoration")
    model_path = root / "data/model/manifest.json"
    model_name = (
        json.loads(model_path.read_text())["model"]
        if model_path.is_file()
        else "sentence-transformers/all-MiniLM-L6-v2"
    )
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{root / 'data/zhidu.db'}",
        raw_dir=root / "data/raw",
        monitor_config=root / "runtime/monitor.json",
        rag_config=root / "runtime/rag.json",
        embedding_cache=root / "data/model",
        embedding_manifest=model_path,
        embedding_model=model_name,
        human_review_dir=root / "data/human-review",
        github_token="",
        admin_key="",
        llm_provider="extractive",
        deepseek_api_key="",
    )


def main():
    parser = argparse.ArgumentParser(
        description="SQLite backup, verify and non-destructive restore"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--include-model", action="store_true")
    verify = sub.add_parser("verify")
    verify.add_argument("bundle", type=Path)
    restore = sub.add_parser("restore")
    restore.add_argument("bundle", type=Path)
    restore.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "create":
            result = create_backup(Settings(), args.output, include_model=args.include_model)
        elif args.command == "verify":
            result = verify_backup(args.bundle)
        else:
            result = restore_backup(args.bundle, args.destination)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, sqlite3.Error) as exc:
        print(
            json.dumps(
                {"status": "failed", "error_type": type(exc).__name__, "detail": str(exc)},
                ensure_ascii=False,
            )
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
