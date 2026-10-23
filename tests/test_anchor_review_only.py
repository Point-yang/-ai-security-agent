"""Local fixture and MockTransport checks; never freeze real paid output."""

import importlib.util
import json
import sqlite3

import httpx
import pytest
from sqlalchemy import select
from test_member_a_rag_context import fixture_advisory, ingest

from zhidu.agent_state import AgentAnswer
from zhidu.indexing import sync_index
from zhidu.model_provider import model_profile
from zhidu.models import SearchChunk
from zhidu.paired_evaluation import digest
from zhidu.source_spans import source_span


@pytest.fixture
def runner():
    spec = importlib.util.spec_from_file_location(
        "anchor_review_only", "scripts/run_agent_anchor_review_only.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False))


@pytest.fixture
def paid_source(database, store, settings, advisory, tmp_path, runner):
    """Synthetic failed pipeline, with completed paid plan/candidate receipts."""
    ingest(database, store, fixture_advisory(advisory))
    with database.begin() as session:
        sync_index(session)
        row = session.scalar(select(SearchChunk).where(SearchChunk.field == "packages"))
        citation = source_span(session, store, row)
        unused = source_span(
            session,
            store,
            session.scalar(select(SearchChunk).where(SearchChunk.field == "description")),
        )
    source = tmp_path / "old-v3"
    source.mkdir()
    import shutil

    shutil.copyfile(tmp_path / "test.db", source / "corpus.sqlite")
    shutil.copytree(store.root, source / "raw")
    handle = "a" * 24
    question = "给出原始受影响范围和首次修复字段。"
    plan = {
        "tasks": [
            {
                "task_id": "versions",
                "requirement": question,
                "source_ids": ["github-advisories"],
                "fields": ["packages"],
                "keywords": [],
                "question_spans": [{"quote": question}],
                "source_policy": "any",
                "required_elements": ["受影响范围", "首次修复字段"],
            }
        ]
    }
    candidate = {
        "answer_class": "evidence",
        "statements": [
            {
                "text": "GitHub 版本范围为 >= 1.0.0, < 1.2.0，首次修复版本为1.2.0。",
                "evidence": [{"evidence_id": handle}],
            }
        ],
        "required_facts": [f"原标签{index}" for index in range(10)],
        "missing_facts": [],
        "limitations": [],
        "message": "",
    }
    assert AgentAnswer.model_validate(candidate)
    snapshot = {
        "events": [row.event_id],
        "cves": [advisory["cve_id"]],
        "evidence": {handle: citation, "b" * 24: unused},
        "results": [],
        "rejections": [],
        "constraints": [],
        "attempted_calls": 6,
        "steps": [],
        "output_chars": 1000,
        "seen_calls": [],
        "missing_queries": [],
        "no_progress_calls": 0,
    }
    thread = "stage8:original-paid-fixture:core"
    with sqlite3.connect(source / "stage8-role-receipts.sqlite") as db:
        db.execute(
            "CREATE TABLE agent_context(thread_id TEXT PRIMARY KEY,manifest_hash TEXT,snapshot TEXT)"
        )
        db.execute("CREATE TABLE agent_role_steps(thread_id TEXT,call_id TEXT,step INTEGER)")
        db.execute(
            "CREATE TABLE agent_model_replies(thread_id TEXT,step INTEGER,input_hash TEXT,status TEXT,response TEXT,audit TEXT,http_requests INTEGER)"
        )
        db.execute(
            "INSERT INTO agent_context VALUES(?,?,?)",
            (thread, "original-binding", json.dumps(snapshot)),
        )
        for step, call_id, answer in ((1, "planner:0", plan), (4, "compose:0", candidate)):
            response = {"answer": answer, "messages": []}
            audit = {"call_id": call_id, "finish_reason": "stop", "status": "completed"}
            db.execute("INSERT INTO agent_role_steps VALUES(?,?,?)", (thread, call_id, step))
            db.execute(
                "INSERT INTO agent_model_replies VALUES(?,?,?,?,?,?,?)",
                (
                    thread,
                    step,
                    "original-input",
                    "completed",
                    json.dumps(response),
                    json.dumps(audit),
                    1,
                ),
            )
    write(
        source / "answers/stage6-langchain-core-team_hybrid.json",
        {
            "case_id": "stage6-langchain-core",
            "request_id": thread,
            "status": "completed",
            "mode": "team_hybrid",
            "result": {
                "generation": {"status": "fallback", "reason": "invalid_verifier_answer_span"},
                "asset_id": None,
            },
        },
    )
    write(
        source / "initial-packets/stage6-langchain-core.json",
        {"scope": {"pool": "formal", "origin": "live", "event_id": None}, "snapshot": snapshot},
    )
    write(source / "gold-specs.json", {"gold": "GOLD_NOT_MODEL_INPUT"})
    write(source / "encoder-manifest.json", {"digest": "original-encoder-fixture"})
    shutil.copyfile("config/model-pricing.json", source / "model-pricing.json")
    write(source / "summary.json", {"old_failure": "unchanged"})
    data = {
        name: runner.sha(source / name)
        for name in (
            "corpus.sqlite",
            "gold-specs.json",
            "encoder-manifest.json",
            "model-pricing.json",
        )
    }
    protocol = {
        "version": "agent-stage8-p0-development-v1",
        "cases": [
            {
                "id": "stage6-langchain-core",
                "package": "langchain-core",
                "question": question,
                "query": advisory["ghsa_id"],
                "facts": [{"id": "gold", "expected": "GOLD_NOT_MODEL_INPUT"}],
            }
        ],
        "corpus_sha256": runner.sha(source / "corpus.sqlite"),
        "data_artifact_sha256": data,
        "initial_artifact_sha256": {
            "initial-packets/stage6-langchain-core.json": runner.sha(
                source / "initial-packets/stage6-langchain-core.json"
            )
        },
        "raw_sha256": [path.stem for path in (source / "raw").rglob("*.json")],
        "implementation_sha256": {},
        "legacy_artifact_sha256": {},
        "matching": {"model_profile": model_profile(settings).public()},
    }
    protocol["freeze_sha256"] = digest(protocol)
    write(source / "protocol.json", protocol)
    return source


def test_offline_freeze_preserves_old_bytes_labels_and_only_ownquote_packet(
    runner, paid_source, tmp_path
):
    before = {
        str(path.relative_to(paid_source)): path.read_bytes()
        for path in paid_source.rglob("*")
        if path.is_file()
    }
    output = tmp_path / "anchor-review"
    protocol = runner.freeze(paid_source, output)
    assert protocol["budget"] == runner.BUDGET and protocol["budget"]["new_model_calls"] == 1
    assert protocol["model_input_gold"] is False and protocol["full_agent_success"] is False
    inputs = json.loads((output / "review-inputs.json").read_text())
    assert len(inputs["candidate"]["required_facts"]) == 10
    packet = json.loads((output / "verifier-packet.json").read_text())
    serialized = json.dumps(packet, ensure_ascii=False)
    assert "GOLD_NOT_MODEL_INPUT" not in serialized
    assert "old_failure" not in serialized and "invalid_verifier_answer_span" not in serialized
    assert "Background information" not in serialized and len(packet["source_quotes"]) == 1
    assert packet["answer_anchors"][0]["anchor_id"].startswith("ans_")
    assert packet["source_quotes"][0]["quote_id"].startswith("src_")
    assert packet["statements"][0]["text"] == inputs["candidate"]["statements"][0]["text"]
    assert {
        str(path.relative_to(paid_source)): path.read_bytes()
        for path in paid_source.rglob("*")
        if path.is_file()
    } == before
    assert runner.load_protocol(output)["scope_id"] == protocol["scope_id"]


def test_paid_extraction_reads_wal_copy_without_opening_original_database(runner, paid_source):
    path = paid_source / "stage8-role-receipts.sqlite"
    db = sqlite3.connect(path)
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("UPDATE agent_context SET manifest_hash='latest-in-wal'")
        db.commit()
        wal = path.with_name(path.name + "-wal")
        assert wal.exists()
        before = (path.read_bytes(), wal.read_bytes())
        protocol = json.loads((paid_source / "protocol.json").read_text())
        inputs = runner.paid_inputs(paid_source, protocol)
        assert inputs["source_thread_id"].startswith("stage8:")
        assert before == (path.read_bytes(), wal.read_bytes())
    finally:
        db.close()


def test_private_asset_scope_is_rejected_before_new_output(runner, paid_source, tmp_path):
    path = paid_source / "answers/stage6-langchain-core-team_hybrid.json"
    attempt = json.loads(path.read_text())
    attempt["result"]["asset_id"] = "private-fixture-host"
    write(path, attempt)
    with pytest.raises(ValueError, match="public_evaluation_scope"):
        runner.freeze(paid_source, tmp_path / "anchor-review")
    assert not (tmp_path / "anchor-review").exists()


def test_old_failed_attempt_and_archived_source_tampering_stop_validation(
    runner, paid_source, tmp_path
):
    output = tmp_path / "anchor-review"
    runner.freeze(paid_source, output)
    path = paid_source / "answers/stage6-langchain-core-team_hybrid.json"
    original = path.read_bytes()
    path.write_bytes(original + b" ")
    with pytest.raises(ValueError, match="original_artifact_changed"):
        runner.load_protocol(output)
    path.write_bytes(original)
    (output / "source/protocol.json").write_text("{}")
    with pytest.raises(ValueError, match="frozen_source_copy_changed"):
        runner.load_protocol(output)


def test_new_request_identity_cannot_reuse_old_paid_role_thread(runner):
    identity = runner.request_identity(
        {"experiment_id": "review-fixture", "freeze_sha256": "new-scope"}
    )
    assert identity == "anchor-review:review-fixture:new-scope:anchor-verify:0"
    assert not identity.startswith("stage8:")


def test_unknown_request_is_reserved_once_and_never_reissued(runner, paid_source, tmp_path):
    output = tmp_path / "anchor-review"
    protocol = runner.freeze(paid_source, output)
    dispatched = []

    def unknown():
        dispatched.append(1)
        raise RuntimeError("provider outcome unknown fixture")

    runner.generate(output, protocol, None, run_review=unknown)
    runner.generate(output, protocol, None, run_review=unknown)
    assert dispatched == [1]
    assert runner.summary(output, protocol)["requests_reserved_or_receipted"] == 1
    assert json.loads((output / "stopped.json").read_text())["automatic_retry"] is False


def test_invalid_saved_reply_stops_without_calling_again(runner, paid_source, tmp_path):
    output = tmp_path / "anchor-review"
    protocol = runner.freeze(paid_source, output)
    dispatched = []

    def invalid():
        dispatched.append(1)
        return {
            "generation": {"status": "failed", "reason": "invalid_answer_anchor"},
            "cost": {"external_requests": 1},
            "new_business_tool_calls": 0,
        }

    runner.generate(output, protocol, None, run_review=invalid)
    runner.generate(output, protocol, None, run_review=invalid)
    assert dispatched == [1]
    assert (output / "stopped.json").exists()


class AnchorSDK:
    def __init__(self, *, forged=False, partial=False):
        self.requests, self.forged, self.partial = [], forged, partial

    def handle(self, request):
        body = json.loads(request.content)
        self.requests.append(body)
        assert body["max_tokens"] == 2400 and body["response_format"] == {"type": "json_object"}
        assert not body.get("tools")
        payload = json.loads(body["messages"][-1]["content"])
        assert "GOLD_NOT_MODEL_INPUT" not in json.dumps(payload)
        schema = json.loads(body["messages"][0]["content"].rsplit("schema:\n", 1)[1])
        assert schema["title"] == "VerifierDecision"
        anchor = (
            payload["source_quotes"][0]["quote_id"]
            if self.forged
            else payload["answer_anchors"][0]["anchor_id"]
        )
        task = payload["tasks"][0]
        value = {
            "coverage": [
                {
                    "task_id": task["task_id"],
                    "status": "partial" if self.partial else "covered",
                    "anchor_ids": [anchor],
                    "note": "fixture AI ownquotes",
                    "element_coverage": [
                        {
                            "element": element,
                            "status": "partial" if self.partial else "covered",
                            "anchor_ids": [anchor],
                        }
                        for element in task["required_elements"]
                    ],
                }
            ],
            "claim_support": [
                {"statement_index": 1, "status": "supported", "reason": "自身引文支持"}
            ],
            "unplanned_requirements": [],
            "gaps": [],
        }
        return httpx.Response(
            200,
            json={
                "id": "anchor-sdk-1",
                "object": "chat.completion",
                "created": 1791949735,
                "model": body["model"],
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(value, ensure_ascii=False),
                        },
                    }
                ],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 5,
                    "total_tokens": 15,
                    "prompt_cache_hit_tokens": 0,
                    "prompt_cache_miss_tokens": 10,
                },
            },
        )


@pytest.mark.parametrize("partial,answer_class", [(False, "evidence"), (True, "partial")])
def test_one_real_sdk_verifier_no_planning_research_composition_or_business_tools(
    runner,
    paid_source,
    tmp_path,
    settings,
    monkeypatch,
    partial,
    answer_class,
):
    from zhidu.langchain_tools import ToolSession

    output = tmp_path / "anchor-review"
    protocol = runner.freeze(paid_source, output)
    cloud = type(settings)(
        _env_file=None, **(settings.model_dump() | {"deepseek_api_key": "mock-anchor-sdk-secret"})
    )
    cloud = runner.experiment_settings(output, protocol, settings=cloud)
    assert cloud.agent_max_model_calls == 1 and cloud.agent_deadline_seconds == 60
    assert cloud.agent_checkpoint_path == output / "anchor-role-receipts.sqlite"
    monkeypatch.setattr(
        ToolSession,
        "invoke",
        lambda *args, **kwargs: pytest.fail("review cannot invoke business tools"),
    )
    sdk = AnchorSDK(partial=partial)
    transport = httpx.MockTransport(sdk.handle)
    row = runner.generate(output, protocol, cloud, transport=transport)
    assert row["result"]["generation"]["status"] == "completed", row
    assert row["result"]["answer_class"] == answer_class
    assert len(sdk.requests) == 1
    assert [call["role"] for call in row["result"]["role_calls"]] == ["verifier"]
    assert [call["call_id"] for call in row["result"]["role_calls"]] == ["anchor-verify:0"]
    assert row["result"]["new_business_tool_calls"] == 0
    inputs = json.loads((output / "review-inputs.json").read_text())
    assert row["result"]["original_candidate_sha256"] == digest(inputs["candidate"])
    assert len(inputs["candidate"]["required_facts"]) == 10
    assert (
        row["result"]["literal_source_check"]["verified"]
        == row["result"]["literal_source_check"]["total"]
        == 1
    )
    assert runner.generate(output, protocol, cloud, transport=transport) == row
    assert len(sdk.requests) == 1
    summary = runner.summary(output, protocol)
    assert summary["full_agent_success"] is False and summary["official_accuracy"] is None
    assert summary["cost"]["external_requests"] == 1


def test_source_quote_id_cannot_be_used_as_body_anchor_and_receipt_is_not_retried(
    runner, paid_source, tmp_path, settings
):
    output = tmp_path / "anchor-review"
    protocol = runner.freeze(paid_source, output)
    cloud = type(settings)(
        _env_file=None, **(settings.model_dump() | {"deepseek_api_key": "mock-anchor-sdk-secret"})
    )
    cloud = runner.experiment_settings(output, protocol, settings=cloud)
    sdk = AnchorSDK(forged=True)
    transport = httpx.MockTransport(sdk.handle)
    row = runner.generate(output, protocol, cloud, transport=transport)
    assert row["result"]["generation"]["status"] == "failed", row
    assert row["result"]["structural_acceptance"] is False
    runner.generate(output, protocol, cloud, transport=transport)
    assert len(sdk.requests) == 1 and (output / "stopped.json").exists()


def test_packet_of_another_frozen_scope_has_different_answer_ids(runner, paid_source, tmp_path):
    first = tmp_path / "review-one"
    second = tmp_path / "review-two"
    runner.freeze(paid_source, first)
    runner.freeze(paid_source, second)
    first_packet = json.loads((first / "verifier-packet.json").read_text())
    second_packet = json.loads((second / "verifier-packet.json").read_text())
    assert (
        first_packet["answer_anchors"][0]["anchor_id"]
        != second_packet["answer_anchors"][0]["anchor_id"]
    )


def test_unknown_or_unattempted_summary_never_becomes_accuracy(runner, paid_source, tmp_path):
    output = tmp_path / "anchor-review"
    protocol = runner.freeze(paid_source, output)
    value = runner.summary(output, protocol)
    assert (
        value["requests_reserved_or_receipted"] == 0 and value["attempt_status"] == "not_attempted"
    )
    assert value["official_accuracy"] is None and value["semantic_support_verified"] is False
    assert value["old_scores_combined"] is False and value["quality_gain_proven"] is False
