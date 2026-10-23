import copy
import importlib.util
import json

import pytest
from test_member_a_rag_context import fixture_advisory, ingest

from zhidu.indexing import chunk_view
from zhidu.langchain_tools import SourceRuntime
from zhidu.paired_evaluation import digest
from zhidu.retrieval import RetrievalHit
from zhidu.semantic import active_chunks

spec = importlib.util.spec_from_file_location(
    "paired_pilot_runner", "scripts/run_agent_paired_pilot.py"
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_completed_answer_tamper_invalidates_judge_binding(tmp_path):
    path = tmp_path / "answer.json"
    row = {"status": "completed", "result": {"answer": "来源声明"}}
    row["row_sha256"] = digest(row)
    path.write_text(json.dumps(row))
    assert runner.load_answer(path)["result"]["answer"] == "来源声明"
    row["result"]["answer"] = "已在用户环境复现"
    path.write_text(json.dumps(row))
    with pytest.raises(ValueError, match="answer_artifact_changed"):
        runner.load_answer(path)


def test_source_slots_not_exhausted_by_one_document_fields(
    database,
    settings,
    store,
    advisory,
    monkeypatch,
):
    first = fixture_advisory(advisory)
    second = copy.deepcopy(first)
    second["ghsa_id"] = "GHSA-dddd-eeee-ffff"
    ingest(database, store, first)
    ingest(database, store, second)
    with database() as session:
        chunks = active_chunks(session)
        event_ids = sorted({c.event_id for c in chunks})
        first_chunks = [c for c in chunks if c.event_id == event_ids[0]][:4]
        second_chunk = next(c for c in chunks if c.event_id == event_ids[1])
        ranked = first_chunks + [second_chunk]
        hits = [
            RetrievalHit(**chunk_view(c).model_dump(), score=1, matched_terms=[]) for c in ranked
        ]

        def mock_retrieve(*args, **kwargs):
            # Model tool asks for two snippets. Ranking puts four fields of one
            # source before the other source, reproducing the loss of a document.
            return hits[: kwargs["limit"]], {"mock": True}

        monkeypatch.setattr("zhidu.agent_tools.retrieve", mock_retrieve)
        runtime = SourceRuntime(session, store, settings, None)
        result = runtime.execute("retrieve", {"query": "shared identifier", "limit": 2})
        assert result["status"] == "completed"
        assert {i["citation"]["event_id"] for i in result["result"]["items"]} == set(event_ids)


def test_started_attempt_is_not_resubmitted_after_unknown_outcome(tmp_path, settings, monkeypatch):
    output = tmp_path / "experiment"
    output.mkdir()
    case = {"id": "fixture-case", "question": "依据来源说明范围", "query": "fixture"}
    protocol = {"cases": [case], "budget": {"max_generation_requests": 20}}
    calls = []

    def interrupted(*args, **kwargs):
        calls.append("unknown")
        raise RuntimeError("process terminated after provider may have accepted")

    for name in ("run_rag", "fixed_workflow", "run_langchain_agent"):
        monkeypatch.setattr(runner, name, interrupted)
    with pytest.raises(RuntimeError):
        runner.generate(output, protocol, settings)
    started = list((output / "answers").glob("*.json"))
    assert len(started) == 1 and json.loads(started[0].read_text())["status"] == "started"
    uncertain_mode = json.loads(started[0].read_text())["mode"]

    def safe_mock(*args, **kwargs):
        calls.append("mock")
        return {"generation": {"status": "completed"}, "cost": {"external_requests": 0}}

    for name in ("run_rag", "fixed_workflow", "run_langchain_agent"):
        monkeypatch.setattr(runner, name, safe_mock)
    # The local test DB differs from corpus.sqlite; isolate just the mutation
    # assertion, which is covered by the real offline snapshot audit.
    monkeypatch.setattr(runner, "sha", lambda path: "unchanged")
    protocol["corpus_sha256"] = "unchanged"
    runner.generate(output, protocol, settings)
    assert calls == ["unknown", "mock", "mock"]
    assert (
        json.loads((output / "answers" / f"fixture-case-{uncertain_mode}.json").read_text())[
            "status"
        ]
        == "started"
    )
