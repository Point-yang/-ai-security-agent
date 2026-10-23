"""The new paired cohort and report remain bound to one frozen corpus copy."""

import hashlib
import json
from pathlib import Path

import pytest


@pytest.mark.historic_snapshot
def test_v4_protocol_and_report_are_disjoint_and_immutable(require_historic_files):
    protocol_path = Path("config/member-b-agent-paired-v4.json")
    report_path = Path("docs/member-b-agent-paired-v4-evaluation.json")
    protocol = json.loads(protocol_path.read_text())
    report = json.loads(report_path.read_text())
    database = Path(protocol["evaluation_database"])
    require_historic_files(database)
    assert protocol["status"] == "frozen_before_model_runs"
    assert (
        hashlib.sha256(database.read_bytes()).hexdigest() == protocol["evaluation_database_sha256"]
    )
    assert report["protocol_sha256"] == hashlib.sha256(protocol_path.read_bytes()).hexdigest()
    assert report["evaluation_database_sha256"] == protocol["evaluation_database_sha256"]
    assert len(protocol["cases"]) == 7 and len(report["rows"]) == 21
    assert report["external_requests_reported"] <= report["external_request_cap"]
    older = set()
    for name in (
        "config/member-b-week6-frozen-qa.json",
        "config/member-b-agent-paired-v2.json",
        "config/member-b-agent-paired-v3.json",
    ):
        older.update(
            event_id
            for case in json.loads(Path(name).read_text())["cases"]
            for event_id in case.get("expected_event_ids", [])
        )
    current = {event_id for case in protocol["cases"] for event_id in case["expected_event_ids"]}
    assert current and current.isdisjoint(older)
    assert all(row["correctness"] is None for row in report["rows"])
