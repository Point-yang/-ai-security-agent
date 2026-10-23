"""New comparison protocol is frozen, disjoint and isolated from the main DB."""

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest


@pytest.mark.historic_snapshot
def test_new_paired_protocol_excludes_old_cases_and_contains_copy_only_withdrawal(
    require_historic_files,
):
    manifest = json.loads(Path("config/member-b-agent-paired-v2.json").read_text())
    old = json.loads(Path("config/member-b-week6-frozen-qa.json").read_text())
    copy = Path(manifest["evaluation_database"])
    require_historic_files(copy, Path("data/zhidu.db"))
    assert hashlib.sha256(copy.read_bytes()).hexdigest() == manifest["evaluation_database_sha256"]
    assert manifest["status"] == "frozen_before_model_runs"
    assert len(manifest["cases"]) == len({case["id"] for case in manifest["cases"]}) == 8
    prior = {event_id for case in old["cases"] for event_id in case["expected_event_ids"]}
    positive = [case for case in manifest["cases"] if case["expected_event_ids"]]
    assert len(positive) == 4
    assert all(len(case["expected_event_ids"]) == 2 for case in positive)
    assert not prior.intersection(
        event_id for case in positive for event_id in case["expected_event_ids"]
    )
    assert all(case["label_status"] != "independent_human_gold" for case in manifest["cases"])
    withdrawn = manifest["withdrawal_fixture"]["event_ids"]
    with sqlite3.connect("file:data/zhidu.db?mode=ro", uri=True) as main:
        assert (
            main.execute(
                "SELECT COUNT(*) FROM events WHERE id IN (?,?) AND withdrawn_at IS NOT NULL",
                withdrawn,
            ).fetchone()[0]
            == 0
        )
    with sqlite3.connect(f"file:{copy}?mode=ro", uri=True) as evaluation:
        assert (
            evaluation.execute(
                "SELECT COUNT(*) FROM events WHERE id IN (?,?) AND withdrawn_at IS NOT NULL",
                withdrawn,
            ).fetchone()[0]
            == 2
        )
        assert evaluation.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
