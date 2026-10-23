"""A/B labels must be real, typed, independent and manually adjudicated."""

import json

import pytest

from zhidu.agent_review import freeze, reconcile, sha


def write(path, payload):
    path.write_text(json.dumps(payload, ensure_ascii=False) + "\n")


def test_blind_review_requires_two_complete_labels_and_manual_adjudication(tmp_path):
    packet = {
        "source_report_sha256": "fixed-report",
        "items": [
            {"item_id": "cited", "citations": [{"text": "evidence"}], "answer_class": "evidence"},
            {"item_id": "refused", "citations": [], "answer_class": "refused"},
        ],
    }
    write(tmp_path / "source-packet.json", packet)
    packet_hash = sha(tmp_path / "source-packet.json")
    mapping = tmp_path / "private-map.json"
    write(
        mapping,
        {
            "source_report_sha256": "fixed-report",
            "item_to_mode": {
                "cited": {"mode": "bounded_agent"},
                "refused": {"mode": "ordinary_deepseek"},
            },
        },
    )
    reviews = {}
    for reviewer in ("A", "B"):
        reviews[reviewer] = {
            "reviewer": reviewer,
            "packet_sha256": packet_hash,
            "annotations": [
                {
                    "item_id": "cited",
                    "answer_correct": None,
                    "semantic_citation_support": None,
                    "complete": None,
                    "refusal_appropriate": None,
                    "reviewed_at": None,
                },
                {
                    "item_id": "refused",
                    "answer_correct": None,
                    "semantic_citation_support": None,
                    "complete": None,
                    "refusal_appropriate": None,
                    "reviewed_at": None,
                },
            ],
        }
        write(tmp_path / f"review-{reviewer}.json", reviews[reviewer])
    decisions = {"packet_sha256": packet_hash, "decisions": []}
    write(tmp_path / "adjudications.json", decisions)
    state = reconcile(tmp_path, mapping)
    assert state["status"] == "pending_human_review" and len(state["pending"]) == 4
    with pytest.raises(ValueError, match="incomplete"):
        freeze(state)

    for review in reviews.values():
        cited, refused = review["annotations"]
        cited.update(
            answer_correct=True,
            semantic_citation_support=True,
            complete=True,
            refusal_appropriate="not_applicable",
            reviewed_at="2026-09-29T10:00:00Z",
        )
        refused.update(
            answer_correct=True,
            semantic_citation_support="not_applicable",
            complete=False,
            refusal_appropriate=True,
            reviewed_at="2026-09-29T10:00:00Z",
            notes="拒答没有覆盖该问题要求的版本条件。",
        )
    reviews["B"]["annotations"][0]["answer_correct"] = False
    reviews["B"]["annotations"][0]["notes"] = "引文不能支撑该结论。"
    for reviewer in ("A", "B"):
        write(tmp_path / f"review-{reviewer}.json", reviews[reviewer])
    state = reconcile(tmp_path, mapping)
    assert state["status"] == "pending_human_review"
    assert state["conflicts"] == [{"item_id": "cited", "field": "answer_correct"}]
    decisions["decisions"] = [
        {
            "item_id": "cited",
            "field": "answer_correct",
            "value": False,
            "adjudicator": "third-reviewer",
            "reason": "unsupported conclusion",
            "reviewed_at": "2026-09-29T12:00:00Z",
        }
    ]
    write(tmp_path / "adjudications.json", decisions)
    frozen = freeze(reconcile(tmp_path, mapping))
    assert frozen["status"] == "frozen_human_review"
    assert frozen["scores"]["bounded_agent"]["answer_correct"] == 0
    assert frozen["scores"]["ordinary_deepseek"]["refusal_appropriate"] == 1
