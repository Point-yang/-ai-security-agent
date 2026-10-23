"""AI adoption keeps honest provenance, source limits and frozen test identity."""

import importlib.util
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from zhidu.gold_review import seal

SCRIPTS = Path(__file__).parents[1] / "scripts"
spec = importlib.util.spec_from_file_location(
    "review_week6_sources", SCRIPTS / "review_week6_sources.py"
)
helpers = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = helpers
spec.loader.exec_module(helpers)
spec = importlib.util.spec_from_file_location("release_ai", SCRIPTS / "release_week6_ai_gold.py")
release_ai = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_ai)


def fixture_data():
    record = {
        "event_id": "a",
        "source_id": "crossref",
        "group_id": "g",
        "split": "test",
        "external_id": "10.test/a",
        "revision_id": "r",
        "sha256": "raw",
        "raw_record": {"DOI": "10.test/a", "title": ["Example"]},
    }
    task = {"id": "a", "group_id": "g", "split": "test", "record_ids": ["a"]}
    packet = seal({"tasks": [task], "records": [record]})
    answer = helpers.source_answer(record)
    status, rationale, issues = release_ai.classify(record)
    label = {
        **answer,
        **task,
        "answer_class": status,
        "class_rationale": rationale,
        "source_issues": issues,
        "review_method": "ai",
        "reviewed_at": helpers.now(),
        "refusal_reason": None,
    }
    release = seal(
        {
            "status": "project_ai_gold_frozen",
            "review_method": "ai",
            "human_reviewed": False,
            "authorization": {"allows_ai_substitution": True},
            "packet_sha256": packet["sha256"],
            "class_counts": {"evidence": 1},
            "labels": [label],
        }
    )
    predictions = seal(
        {
            "packet_sha256": packet["sha256"],
            "predictions": [
                {"task_id": "a", "revision_id": "r", "source_sha256": "raw", "prediction": None}
            ],
        }
    )
    return packet, release, predictions


def test_metadata_answer_does_not_require_full_text():
    packet, release, _ = fixture_data()
    release_ai.validate_release(packet, release)
    assert release["labels"][0]["answer_class"] == "evidence"


@pytest.mark.parametrize(
    ("vulnerable", "fixed", "expected"),
    [
        (">=0.1.0", "0.19.0", "0.19.0"),
        ("<=0.7.0", "v0.7.0", "0.7.0"),
        (">=0.22.1,<=0.28.0", ">=0.28.0", "0.28.0"),
        (">=0.1.0,<0.19.0", "0.19.0", None),
        ("<=0.20.1", ">=0.26.0", None),
    ],
)
def test_overlap_never_fills_an_upper_bound(vulnerable, fixed, expected):
    assert release_ai.range_overlap(vulnerable, fixed) == expected


def test_explicit_dispute_is_partial_and_cited():
    record = {
        "event_id": "a",
        "source_id": "nvd",
        "raw_record": {
            "id": "CVE-X",
            "descriptions": [
                {"value": "The existence of this vulnerability is still disputed at present."}
            ],
        },
    }
    status, _, issues = release_ai.classify(record)
    assert status == "partial"
    assert issues[0]["citations"][0]["pointer"] == "/descriptions/0/value"


def test_missing_prediction_is_not_dropped_or_called_class_accuracy():
    packet, release, predictions = fixture_data()
    result = release_ai.evaluate(packet, release, predictions)
    assert result["metrics"]["fn"] == 1
    assert result["metrics"]["record_exact_accuracy"] == 0
    assert result["answer_class_accuracy"] is None


@pytest.mark.parametrize("change", ["human", "authorization", "split", "duplicate", "quote"])
def test_release_rejects_provenance_and_label_corruption(change):
    packet, release, _ = fixture_data()
    release = deepcopy(release)
    if change == "human":
        release["human_reviewed"] = True
    elif change == "authorization":
        release["authorization"]["allows_ai_substitution"] = False
    elif change == "split":
        release["labels"][0]["split"] = "train"
    elif change == "duplicate":
        release["labels"] *= 2
    else:
        release["labels"][0]["citations"][0]["quote"] = "invented quote"
    release.pop("sha256")
    with pytest.raises(ValueError):
        release_ai.validate_release(packet, seal(release))


def test_score_rejects_test_omission():
    packet, release, _ = fixture_data()
    predictions = seal({"packet_sha256": packet["sha256"], "predictions": []})
    with pytest.raises(ValueError, match="All test predictions"):
        release_ai.evaluate(packet, release, predictions)
