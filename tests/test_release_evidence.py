import json
from pathlib import Path

from fastapi.testclient import TestClient

from zhidu.api import create_app
from zhidu.release_evidence import public_release_evidence


def load_reference():
    return json.loads(Path("config/submission-evidence.json").read_text())


def test_public_summary_preserves_review_method_and_unknown_usage(tmp_path):
    path = tmp_path / "summary.json"
    path.write_text(json.dumps(load_reference()))
    result = public_release_evidence(path)
    assert result["status"] == "available"
    assert result["gold"]["human_review"] is False
    assert result["gold"]["independent"] is False
    assert result["complex_qa"]["agent_gain_proven"] is False
    assert result["latest_trial"]["total_tokens"] is None
    assert result["latest_trial"]["total_cost"] is None
    assert all(not Path(row["file"]).is_absolute() for row in result["sources"])


def test_summary_unavailable_instead_of_invented_scores(tmp_path):
    path = tmp_path / "absent.json"
    assert public_release_evidence(path) == {"status": "unavailable", "reason": "missing"}
    path.write_text('{"schema_version":"unknown"}')
    assert public_release_evidence(path) == {"status": "unavailable", "reason": "invalid"}


def test_summary_rejects_inconsistent_comparison_denominators(tmp_path):
    summary = load_reference()
    summary["complex_qa"]["modes"][0]["strict_accuracy"] = 1.0
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(summary))
    assert public_release_evidence(path)["status"] == "unavailable"


def test_summary_rejects_private_or_traversing_source_paths(tmp_path):
    summary = load_reference()
    summary["sources"][0]["file"] = "evidence/../../.env"
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(summary))
    assert public_release_evidence(path)["status"] == "unavailable"


def test_release_summary_is_read_only_and_needs_no_admin_key(settings, tmp_path):
    path = tmp_path / "summary.json"
    path.write_text(json.dumps(load_reference()))
    settings = settings.model_copy(update={"submission_evidence_path": path})
    with TestClient(create_app(settings)) as client:
        response = client.get("/api/v1/release/evidence")
        assert response.status_code == 200
        assert response.json()["status"] == "available"
        assert response.json()["gold"]["method"] == "project_ai_review"
        assert not (tmp_path / "test.db").exists()
