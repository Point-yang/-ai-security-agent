"""Known provider failures and graph tool replay keep their distinct identities."""

import json
import sqlite3

import httpx
import pytest
from test_agent_final_contract import cloud, final_candidate, reply
from test_agent_recovery import ProcessCrash
from test_langchain_agent import body
from test_member_a_rag_context import fixture_advisory, ingest

from zhidu.agent_checkpoint import RecoveryStore
from zhidu.langchain_agent import run_langchain_agent


def test_invalid_native_answer_receipt_replays_same_failure_and_usage(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    options = cloud(settings)
    requests = []
    hidden = "private-reasoning-must-not-survive-invalid-structured-output"

    def invalid_answer(request):
        payload = json.loads(request.content)
        requests.append(payload)
        assert payload.get("tools"), "This must exercise the native ToolStrategy phase."
        return reply(
            {
                "content": None,
                "reasoning_content": hidden,
                "tool_calls": [
                    {
                        "id": "invalid-agent-answer",
                        "type": "function",
                        "function": {
                            "name": "AgentAnswer",
                            "arguments": json.dumps({"answer_class": "evidence"}),
                        },
                    }
                ],
            },
            "tool_calls",
        )

    key = "invalid-native-answer-receipt"
    with database() as session:
        first = run_langchain_agent(
            session,
            store,
            options,
            body(advisory),
            None,
            checkpoint_key=key,
            transport=httpx.MockTransport(invalid_answer),
        )
    assert first["generation"]["reason"] == "invalid_structured_answer", first
    assert first["agent"]["model_calls"][0]["phase"] == "native_tool_loop"
    assert first["cost"]["external_requests"] == len(requests) == 1
    assert first["cost"]["billed_tokens"] == 30
    with sqlite3.connect(options.agent_checkpoint_path) as conn:
        status, saved_response, saved_audit = conn.execute(
            "SELECT status,response,audit FROM agent_model_replies WHERE thread_id=? AND step=1",
            (key,),
        ).fetchone()
    assert status == "completed", "A received invalid answer is a known outcome."
    assert saved_response and hidden not in saved_response + saved_audit
    assert hidden not in json.dumps(first)

    def no_request(_request):
        pytest.fail("A received invalid provider response must not be requested again.")

    with database() as session:
        resumed = run_langchain_agent(
            session,
            store,
            options,
            body(advisory),
            None,
            checkpoint_key=key,
            transport=httpx.MockTransport(no_request),
        )
    assert resumed["generation"]["reason"] == "invalid_structured_answer", resumed
    assert resumed["cost"]["current_attempt_external_requests"] == 0
    assert resumed["cost"]["external_requests"] == 1
    assert resumed["cost"]["billed_tokens"] == 30
    assert hidden not in json.dumps(resumed)


def duplicate_retrieve_handler(advisory, requests):
    """Reuse a tool ID in a new model step to catch argument-only replay keys."""
    arguments = {"query": advisory["ghsa_id"], "mode": "lexical", "limit": 2}

    def handle(request):
        payload = json.loads(request.content)
        requests.append(payload)
        if len(requests) <= 2:
            return reply(
                {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "same-provider-tool-id",
                            "type": "function",
                            "function": {
                                "name": "retrieve",
                                "arguments": json.dumps(arguments),
                            },
                        }
                    ],
                },
                "tool_calls",
            )
        assert len(requests) == 3
        observations = [
            json.loads(m["content"]) for m in payload["messages"] if m["role"] == "tool"
        ]
        assert observations[-1]["error"] == "duplicate_tool_request"
        item = observations[0]["result"]["items"][0]
        return reply({"content": json.dumps(final_candidate(item))})

    return handle


def assert_duplicate_accounting(result):
    assert result["generation"]["status"] == "completed", result
    assert result["agent"]["attempted_tool_calls"] == 2
    assert len(result["agent"]["tool_steps"]) == 1
    assert [r["reason"] for r in result["agent"]["policy_rejections"]] == ["duplicate_tool_request"]
    assert result["cost"]["external_requests"] == 3
    assert result["cost"]["billed_tokens"] == 90


def test_new_model_step_same_tool_arguments_is_a_duplicate_not_a_replay(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    options = cloud(settings).model_copy(update={"agent_max_model_calls": 3})
    requests = []
    with database() as session:
        result = run_langchain_agent(
            session,
            store,
            options,
            body(advisory),
            None,
            checkpoint_key="new-step-duplicate-tool",
            transport=httpx.MockTransport(duplicate_retrieve_handler(advisory, requests)),
        )
    assert len(requests) == 3
    assert_duplicate_accounting(result)
    assert result["agent"]["reply_replay"]["tool_responses"] == 0


def test_tool_receipt_crash_replays_original_call_but_rejects_new_step(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    options = cloud(settings).model_copy(update={"agent_max_model_calls": 3})
    requests = []
    handler = duplicate_retrieve_handler(advisory, requests)
    original_save = RecoveryStore.save_tool

    def crash_after_tool_receipt(self, *args, **kwargs):
        original_save(self, *args, **kwargs)
        raise ProcessCrash()

    monkeypatch.setattr(RecoveryStore, "save_tool", crash_after_tool_receipt)
    with database() as session, pytest.raises(ProcessCrash):
        run_langchain_agent(
            session,
            store,
            options,
            body(advisory),
            None,
            checkpoint_key="tool-receipt-crash",
            transport=httpx.MockTransport(handler),
        )
    assert len(requests) == 1
    monkeypatch.setattr(RecoveryStore, "save_tool", original_save)
    with database() as session:
        resumed = run_langchain_agent(
            session,
            store,
            options,
            body(advisory),
            None,
            checkpoint_key="tool-receipt-crash",
            transport=httpx.MockTransport(handler),
        )
    assert_duplicate_accounting(resumed)
    assert resumed["agent"]["checkpoint_resumed"] is True
    assert resumed["agent"]["reply_replay"]["tool_responses"] == 1
    assert resumed["cost"]["current_attempt_external_requests"] == 2
    assert len(requests) == 3
