"""Scoring safety checks: no missing-case exclusion or artificial human release."""

import importlib.util
from pathlib import Path

import pytest

from zhidu.gold_review import freeze_release, review_template, seal, validate_answer

spec = importlib.util.spec_from_file_location(
    "source_review", Path(__file__).parents[1] / "scripts/review_week6_sources.py"
)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


def packet():
    record = {
        "event_id": "a",
        "group_id": "g",
        "split": "test",
        "source_id": "crossref",
        "external_id": "10.test/a",
        "revision_id": "r",
        "sha256": "raw",
        "raw_record": {"DOI": "10.test/a", "title": ["Example"]},
    }
    return seal({"tasks": [{"id": "a", "group_id": "g", "split": "test"}], "records": [record]})


def test_missing_prediction_keeps_all_expected_facts():
    result = review.score_sets([["entity:cve", "cve-1"]], review.prediction_facts(None))
    assert (result["tp"], result["fp"], result["fn"]) == (0, 0, 1)
    assert review.aggregate([result])["fact_recall"] == 0
    assert review.aggregate([result])["fact_precision"] is None


def test_unsupported_and_wrong_values_are_penalized():
    result = review.score_sets([["entity:cve", "a"]], [["entity:cve", "b"], ["entity:cve", "b"]])
    assert (result["tp"], result["fp"], result["fn"]) == (0, 1, 1)


def test_ranges_do_not_gain_an_invented_upper_bound():
    assert review.range_text(">= 0.1.0") != review.range_text(">= 0.1.0, < 0.9.0")
    assert review.range_text(">= 0.1.0, < 0.9.0") == review.range_text(">=0.1.0,<0.9.0")
    assert review.range_text("0.9.0") != review.range_text(">=0.9.0")


def test_ai_draft_has_valid_quotes_but_cannot_be_human_gold():
    p = packet()
    answer = review.source_answer(p["records"][0])
    validate_answer(p, p["tasks"][0], answer)
    a, b = review_template(p, "A"), review_template(p, "B")
    a.update(review_method="ai_assisted", reviews=[answer])
    b.update(review_method="ai_assisted", reviews=[answer])
    with pytest.raises(ValueError, match="Human independent"):
        freeze_release(p, a, b)


def test_nvd_versions_retain_unaffected_status_and_authority():
    record = {
        "event_id": "a",
        "source_id": "nvd",
        "raw_record": {
            "id": "CVE-X",
            "affected": [
                {
                    "source": "publisher",
                    "affectedData": [
                        {
                            "vendor": "vendor",
                            "product": "product",
                            "defaultStatus": "unaffected",
                            "versions": [{"version": "1.0", "status": "unaffected"}],
                        }
                    ],
                }
            ],
        },
    }
    facts = [x["fact"] for x in review.source_facts(record)]
    version = next(x for x in facts if x[0] == "nvd_affected_version")
    assert version[1] == "publisher"
    assert version[-1]["status"] == "unaffected"


@pytest.mark.parametrize(
    "case", ["omitted", "duplicate", "wrong_revision", "wrong_packet", "tampered"]
)
def test_score_rejects_untrustworthy_manifest(tmp_path, case):
    p = packet()
    review.draft(p, tmp_path)
    prediction = {"task_id": "a", "revision_id": "r", "source_sha256": "raw", "prediction": None}
    rows = (
        []
        if case == "omitted"
        else [prediction, prediction]
        if case == "duplicate"
        else [prediction]
    )
    if case == "wrong_revision":
        prediction["revision_id"] = "other"
    manifest = seal(
        {"packet_sha256": "wrong" if case == "wrong_packet" else p["sha256"], "predictions": rows}
    )
    if case == "tampered":
        manifest["predictions"] = []
    review.save(tmp_path / "test-predictions.json", manifest)
    with pytest.raises(ValueError):
        review.score(p, tmp_path)


def test_existing_artifact_is_never_overwritten(tmp_path):
    path = tmp_path / "frozen.json"
    review.save(path, {"original": True})
    with pytest.raises(FileExistsError):
        review.save(path, {"original": False})
    assert review.read(path) == {"original": True}
