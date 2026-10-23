"""Stored result replay preserves logical history and incurs no new P0 work."""

from copy import deepcopy

from sqlalchemy import select

from zhidu.agent_research import replay_research_trace
from zhidu.agent_team import research_progress
from zhidu.evidence_novelty import evidence_novelty
from zhidu.models import Conversation, ConversationRagTurn, RagRun
from zhidu.rag import RagRequest
from zhidu.rag_turn_jobs import _completed, fingerprint


def original_trace():
    novelty = {
        "status": "known",
        "new_source_chars": 153,
        "known_new_source_chars": 153,
        "new_source_spans": [{"sha256": "a" * 64, "start": 0, "end": 153}],
    }
    return [
        {
            "cycle": 0,
            "call_id": "research:0:0",
            "action": "batch",
            "model_decision_replayed": False,
            "decision_completed": True,
            "admission": {
                "requested": 2,
                "admitted": [
                    {"child_id": "research:0:0:tool:0"},
                    {"child_id": "research:0:0:tool:1"},
                ],
                "skipped": [],
            },
            "novelty": deepcopy(novelty),
            "current_attempt_novelty": deepcopy(novelty),
            "tool_observations": [
                {
                    "child_id": f"research:0:0:tool:{index}",
                    "tool": "read_fields",
                    "status": "completed",
                    "error": None,
                    "replayed": False,
                    "actual_tool_attempts": 1,
                    "novelty": deepcopy(novelty),
                    "current_attempt_novelty": deepcopy(novelty),
                }
                for index in range(2)
            ],
        }
    ]


def test_replay_copy_keeps_logical_intervals_but_sets_every_current_counter_to_zero():
    original = original_trace()
    snapshot = deepcopy(original)
    replayed = replay_research_trace(original)
    assert original == snapshot
    assert replayed[0]["novelty"] == original[0]["novelty"]
    assert replayed[0]["admission"] == original[0]["admission"]
    assert replayed[0]["model_decision_replayed"] is True
    assert replayed[0]["current_attempt_novelty"]["new_source_chars"] == 0
    for index, child in enumerate(replayed[0]["tool_observations"]):
        assert child["replayed"] is True and child["actual_tool_attempts"] == 0
        assert child["current_attempt_novelty"] == evidence_novelty({}, {})
        assert child["novelty"] == original[0]["tool_observations"][index]["novelty"]
    replayed[0]["novelty"]["new_source_spans"][0]["start"] = 99
    assert original == snapshot


def test_replay_is_idempotent_and_does_not_turn_unknown_history_into_known_gain():
    original = original_trace()
    original[0]["novelty"] = {
        "status": "unknown",
        "new_source_chars": None,
        "known_new_source_chars": 153,
    }
    once = replay_research_trace(original)
    assert replay_research_trace(once) == once
    progress = research_progress(once)
    assert (
        progress["logical"]["status"] == "unknown"
        and progress["logical"]["new_source_chars"] is None
    )
    assert (
        progress["current_attempt"]["status"] == "known"
        and progress["current_attempt"]["new_source_chars"] == 0
    )


def seed_result(database, *, batch_wrapper=False):
    trace = original_trace()
    result = {
        "agent_backend": "team",
        "answer_class": "evidence",
        "answer": "original answer",
        "cost": {
            "external_requests": 5,
            "billed_tokens": 100,
            "current_attempt_external_requests": 5,
            "current_attempt_billed_tokens": 100,
            "monetary": {"status": "unknown", "unknown_calls": 1},
        },
        "agent": {"research_trace": deepcopy(trace), "decisions": deepcopy(trace)},
        "batch_tool_calls": {"calls": deepcopy(trace)} if batch_wrapper else deepcopy(trace),
        "evidence_novelty": research_progress(trace),
        "citations": [{"text": "original source quote", "sha256": "a" * 64}],
    }
    with database.begin() as session:
        conversation = Conversation(title="P0 replay fixture")
        session.add(conversation)
        session.flush()
        body = RagRequest(
            question="原问题",
            conversation_id=conversation.id,
            request_id="p0-replay-001",
            generation="agent",
            agent_backend="team",
        )
        run = RagRun(request=body.model_dump(), result=deepcopy(result))
        session.add(run)
        session.flush()
        session.add(
            ConversationRagTurn(
                conversation_id=conversation.id,
                request_id=body.request_id,
                request_sha256=fingerprint(body),
                rag_run_id=run.id,
            )
        )
        run_id = run.id
    return body, run_id, result


def test_completed_api_duplicate_has_zero_current_work_and_leaves_persisted_run_unchanged(database):
    body, run_id, original = seed_result(database)
    with database() as session:
        duplicate = _completed(session, body)
        assert duplicate["deduplicated"] is True
        assert duplicate["cost"]["current_attempt_external_requests"] == 0
        assert duplicate["cost"]["current_attempt_billed_tokens"] == 0
        assert duplicate["cost"]["external_requests"] == 5
        assert duplicate["cost"]["billed_tokens"] == 100
        assert duplicate["cost"]["monetary"]["status"] == "unknown"
        assert duplicate["evidence_novelty"]["logical"] == original["evidence_novelty"]["logical"]
        assert duplicate["evidence_novelty"]["current_attempt"]["new_source_chars"] == 0
        assert (
            duplicate["evidence_novelty"]["decisions"][0]["current_attempt_novelty"][
                "new_source_chars"
            ]
            == 0
        )
        for field in (
            duplicate["batch_tool_calls"],
            duplicate["agent"]["research_trace"],
            duplicate["agent"]["decisions"],
        ):
            assert all(
                child["actual_tool_attempts"] == 0 and child["replayed"]
                for entry in field
                for child in entry["tool_observations"]
            )
        duplicate["citations"][0]["text"] = "mutated response copy"
        assert session.get(RagRun, run_id).result == original
        assert _completed(session, body)["citations"][0]["text"] == "original source quote"
    with database() as session:
        assert session.scalar(select(RagRun).where(RagRun.id == run_id)).result == original


def test_wrapped_batch_receipts_are_also_reset_without_changing_original(database):
    body, run_id, original = seed_result(database, batch_wrapper=True)
    with database() as session:
        duplicate = _completed(session, body)
        assert (
            duplicate["batch_tool_calls"]["calls"][0]["tool_observations"][0][
                "actual_tool_attempts"
            ]
            == 0
        )
        assert session.get(RagRun, run_id).result == original


def test_response_without_p0_fields_retains_legacy_shape(database):
    body, run_id, _ = seed_result(database)
    with database.begin() as session:
        session.get(RagRun, run_id).result = {
            "cost": {"external_requests": 0},
            "answer": "legacy original",
        }
    with database() as session:
        duplicate = _completed(session, body)
        assert "agent" not in duplicate and "evidence_novelty" not in duplicate
        assert duplicate["cost"]["current_attempt_external_requests"] == 0
        assert duplicate["answer"] == "legacy original"
