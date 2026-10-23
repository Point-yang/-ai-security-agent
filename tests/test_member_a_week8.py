import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from zhidu.api import create_app
from zhidu.backup import (
    canonical_hash,
    create_backup,
    restore_backup,
    restored_settings,
    verify_backup,
)
from zhidu.ingest import ingest_document
from zhidu.models import now_utc


def seed(database, store, advisory):
    with database.begin() as session:
        ingest_document(
            session,
            store,
            json.dumps(advisory).encode(),
            "offline://backup-test",
            now_utc(),
            "replay",
        )


def minimal_root(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "src/example.py").write_text("# fixture\n")
    (root / ".env").write_text("PRIVATE_SECRET=do-not-copy\n")
    return root


def test_backup_restore_keeps_evidence_and_uses_new_database(
    database, store, settings, advisory, tmp_path, monkeypatch
):
    seed(database, store, advisory)
    bundle = tmp_path / "bundle"
    create_backup(settings, bundle, project_root=minimal_root(tmp_path))
    assert not (bundle / "code/.env").exists()
    assert verify_backup(bundle)["counts"]["events"] == 1
    destination = tmp_path / "restored"
    restore_backup(bundle, destination)
    monkeypatch.setenv("ZHIDU_LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("ZHIDU_DEEPSEEK_API_KEY", "must-not-inherit")
    restored = restored_settings(destination)
    assert restored.database_url != settings.database_url
    assert not restored.admin_key.get_secret_value()
    assert restored.llm_provider == "extractive"
    assert not restored.deepseek_api_key.get_secret_value()
    with TestClient(create_app(restored)) as client:
        assert client.get("/health/ready").status_code == 200
        event = client.get("/api/v1/events").json()["items"][0]
        trace = client.get(f"/api/v1/events/{event['id']}/trace").json()
        assert trace["summary"]["field_evidence_failed"] == 0
        assert trace["summary"]["field_evidence_verified"] > 0


def test_corruption_fails_before_restore_creates_destination(
    database, store, settings, advisory, tmp_path
):
    seed(database, store, advisory)
    bundle = tmp_path / "bundle"
    create_backup(settings, bundle, project_root=minimal_root(tmp_path))
    next((bundle / "data/raw").rglob("*.json")).write_text("corrupt")
    with pytest.raises(ValueError, match="checksum"):
        restore_backup(bundle, tmp_path / "should-not-exist")
    assert not (tmp_path / "should-not-exist").exists()


def test_existing_destination_is_never_overwritten(database, store, settings, advisory, tmp_path):
    seed(database, store, advisory)
    bundle = tmp_path / "bundle"
    create_backup(settings, bundle, project_root=minimal_root(tmp_path))
    destination = tmp_path / "existing"
    destination.mkdir()
    sentinel = destination / "keep.txt"
    sentinel.write_text("keep")
    with pytest.raises(FileExistsError):
        restore_backup(bundle, destination)
    assert sentinel.read_text() == "keep"
    with pytest.raises(FileExistsError):
        create_backup(settings, bundle, project_root=tmp_path)


def test_manifest_cannot_escape_directory(database, store, settings, advisory, tmp_path):
    seed(database, store, advisory)
    bundle = tmp_path / "bundle"
    create_backup(settings, bundle, project_root=minimal_root(tmp_path))
    path = bundle / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest.pop("manifest_sha256")
    manifest["files"]["../../outside"] = {"sha256": "0" * 64, "bytes": 0}
    manifest["manifest_sha256"] = canonical_hash(manifest)
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="invalid path"):
        verify_backup(bundle)


def test_model_manifest_is_relocated_without_changing_digest(
    database, store, settings, advisory, tmp_path
):
    seed(database, store, advisory)
    root = tmp_path / "model"
    root.mkdir()
    (root / "model.onnx").write_bytes(b"fake-test-model-not-for-inference")
    from zhidu.backup import file_hash

    files = {"model.onnx": file_hash(root / "model.onnx")}
    settings.embedding_manifest = tmp_path / "model-manifest.json"
    settings.embedding_manifest.write_text(
        json.dumps(
            {
                "model": settings.embedding_model,
                "path": str(root),
                "files": files,
                "digest": canonical_hash(files),
                "dimension": 2,
            }
        )
    )
    bundle = tmp_path / "bundle"
    create_backup(settings, bundle, project_root=minimal_root(tmp_path), include_model=True)
    destination = tmp_path / "restored"
    restore_backup(bundle, destination)
    restored = restored_settings(destination)
    from zhidu.semantic import model_manifest

    manifest = model_manifest(restored, verify=True)
    assert Path(manifest["path"]) == destination / "data/model/files"
    assert manifest["digest"] == canonical_hash(files)
