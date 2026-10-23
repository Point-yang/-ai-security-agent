"""Final paired evidence stays disjoint from prior tuning and copied withdrawals."""

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from zhidu.agent_rag import Plan, _local_two_source_version_answer, run_agent
from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.rag import RagRequest
from zhidu.storage import BlobStore


@pytest.mark.historic_snapshot
def test_v3_is_frozen_disjoint_and_only_copy_has_withdrawal(require_historic_files):
    v3 = json.loads(Path("config/member-b-agent-paired-v3.json").read_text())
    v2 = json.loads(Path("config/member-b-agent-paired-v2.json").read_text())
    old = json.loads(Path("config/member-b-week6-frozen-qa.json").read_text())
    report = json.loads(Path("docs/member-b-agent-paired-v3-evaluation.json").read_text())
    database = Path(v3["evaluation_database"])
    require_historic_files(database, Path("data/zhidu.db"))
    assert v3["status"] == "frozen_before_model_runs"
    assert hashlib.sha256(database.read_bytes()).hexdigest() == v3["evaluation_database_sha256"]
    assert (
        report["protocol_sha256"]
        == hashlib.sha256(Path("config/member-b-agent-paired-v3.json").read_bytes()).hexdigest()
    )
    assert len(v3["cases"]) == 7 and len(report["rows"]) == 21
    known = {
        eid
        for source in (old, v2)
        for case in source["cases"]
        for eid in case["expected_event_ids"]
    }
    known.update(v2["withdrawal_fixture"]["event_ids"])
    assert not known.intersection(eid for case in v3["cases"] for eid in case["expected_event_ids"])
    ids = v3["withdrawal_fixture"]["event_ids"]
    with sqlite3.connect("file:data/zhidu.db?mode=ro", uri=True) as main:
        assert (
            main.execute(
                "SELECT COUNT(*) FROM events WHERE id IN (?,?) AND withdrawn_at IS NOT NULL", ids
            ).fetchone()[0]
            == 0
        )
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as copy:
        assert (
            copy.execute(
                "SELECT COUNT(*) FROM events WHERE id IN (?,?) AND withdrawn_at IS NOT NULL", ids
            ).fetchone()[0]
            == 2
        )
    assert all(
        row["correctness"] is None and row["semantic_citation_support"] is None
        for row in report["rows"]
    )


@pytest.mark.historic_snapshot
def test_agent_can_read_both_current_patch_sources_within_tool_budget(
    monkeypatch,
    require_historic_files,
):
    """The former failure had two hits, but the second detail exceeded 9k chars."""
    db = Path("data/member-b-agent-paired-v3.db").resolve()
    require_historic_files(db)
    settings = Settings(database_url=f"sqlite:///{db}")
    protocol = json.loads(Path("config/member-b-agent-paired-v3.json").read_text())
    case = next(row for row in protocol["cases"] if row["id"] == "fresh-patch-30202")
    with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as snapshot:
        digests = snapshot.execute(
            "SELECT DISTINCT d.sha256 FROM raw_documents d "
            "JOIN event_revisions r ON r.raw_document_id = d.id "
            "JOIN events e ON e.id = r.event_id AND e.revision = r.number "
            "WHERE e.id IN (?,?)",
            case["expected_event_ids"],
        ).fetchall()
    require_historic_files(*(BlobStore(settings.raw_dir).path_for(row[0]) for row in digests))
    engine = make_engine(settings.database_url)
    captured = {}

    def planner(settings, question, tools, observations, *, phase, transport=None):
        if phase == "target_retrieval":
            calls = [
                {
                    "name": "retrieve",
                    "arguments": {"query": "CVE-2025-30202", "mode": "lexical", "limit": 3},
                }
            ]
        else:
            calls = [{"name": "compare_sources", "arguments": {"identifier": "CVE-2025-30202"}}]
        return (
            Plan.model_validate(
                {"decision_summary": "读取两个当前来源的修复依据。", "calls": calls}
            ),
            {},
            "mock",
        )

    def generator(settings, question, result, *, history=None, transport=None):
        captured["citations"] = result["citations"]
        result["generation"] = {
            "status": "fallback",
            "reason": "invalid_citation",
            "usage": {},
            "input_sha256": "mock",
        }

    monkeypatch.setattr("zhidu.agent_rag.plan_step", planner)
    monkeypatch.setattr("zhidu.agent_rag.apply_generation", generator)
    try:
        with make_sessions(engine)() as session:
            result = run_agent(
                session,
                BlobStore(settings.raw_dir),
                settings,
                RagRequest(
                    question="CVE-2025-30202 的来源分别给出了什么首个修复版本及依据？",
                    query="CVE-2025-30202",
                    mode="lexical",
                    generation="agent",
                ),
                None,
            )
    finally:
        engine.dispose()

    assert result["tool_calls"] <= 6
    assert [row["status"] for row in result["agent"]["tool_results"]] == [
        "completed",
        "completed",
        "completed",
        "completed",
    ]
    packages = {
        row["source_id"]: row["text"] for row in captured["citations"] if row["field"] == "packages"
    }
    assert "patched_versions" in packages["vllm-vendor"]
    assert "first_patched_version" in packages["github-advisories"]
    assert {row["source_id"] for row in captured["citations"] if "17197" in row["text"]} == {
        "vllm-vendor",
        "github-advisories",
    }
    assert result["generation"]["local_fallback"] == "two_source_version_fields_v1"
    assert result["answer_class"] == "evidence"
    assert "first_patched_version" in result["answer"]
    assert "patched_versions" in result["answer"]
    assert result["answer"].count("17197") == 2


def test_original_fifteenth_citation_is_present_and_supports_timing_claim():
    report = json.loads(Path("docs/member-b-agent-paired-v3-evaluation.json").read_text())
    row = next(
        item
        for item in report["rows"]
        if item["case_id"] == "fresh-summary-46570" and item["mode"] == "bounded_agent"
    )
    assert row["generation_status"] == "completed"
    assert row["generation_citation_checks_passed"]
    assert len(row["citations"]) == 15
    assert "[15]" in row["answer"]
    assert "prefix caching mechanism" in row["citations"][14]["text"]
    assert "TTFT" in row["citations"][14]["text"]
    local = _local_two_source_version_answer(row["question"], row["citations"])
    assert local is not None
    assert "github-advisories" in local and "vllm-vendor" in local
    assert "first_patched_version" in local and "patched_versions" in local
