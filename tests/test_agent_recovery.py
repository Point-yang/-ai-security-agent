"""Completed replies survive restart; uncertain requests are never blindly resent."""

import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Event

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from test_langchain_agent import ScriptedModel, body, finish, retrieve
from test_member_a_rag_context import fixture_advisory, ingest

from zhidu.agent_checkpoint import RecoveryStore
from zhidu.api import create_app
from zhidu.langchain_agent import run_langchain_agent
from zhidu.models import Conversation, ConversationMessage, RagRun, RagTurnJob, now_utc
from zhidu.rag_turn_jobs import submit_short_turn


class ProcessCrash(BaseException):
    pass


def test_completed_graph_reopens_without_any_model_request(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    model = ScriptedModel(actions=[retrieve(advisory), finish])
    with database() as session:
        first = run_langchain_agent(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=model,
            checkpoint_key="completed-case",
        )
    assert first["generation"]["status"] == "completed", first
    resumed_model = ScriptedModel(actions=[])
    with database() as session:
        resumed = run_langchain_agent(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=resumed_model,
            checkpoint_key="completed-case",
        )
    assert resumed["generation"]["status"] == "completed", resumed
    assert resumed_model.position == 0
    assert resumed["answer"] == first["answer"]
    assert resumed["agent"]["checkpoint_resumed"] is True
    assert resumed["cost"]["current_attempt_external_requests"] == 0
    assert resumed["cost"]["billed_tokens"] == first["cost"]["billed_tokens"]


def test_reply_cached_before_graph_checkpoint_is_replayed(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    original = RecoveryStore.save_model

    def crash_after_save(self, step, response, audit):
        original(self, step, response, audit)
        raise ProcessCrash()

    monkeypatch.setattr(RecoveryStore, "save_model", crash_after_save)
    first_model = ScriptedModel(actions=[retrieve(advisory)])
    with database() as session, pytest.raises(ProcessCrash):
        run_langchain_agent(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=first_model,
            checkpoint_key="cached-before-crash",
        )
    monkeypatch.setattr(RecoveryStore, "save_model", original)
    resumed_model = ScriptedModel(actions=[finish])
    with database() as session:
        resumed = run_langchain_agent(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=resumed_model,
            checkpoint_key="cached-before-crash",
        )
    assert resumed["generation"]["status"] == "completed", resumed
    assert first_model.position == resumed_model.position == 1
    assert resumed["agent"]["reply_replay"]["model_responses"] == 1
    assert resumed["cost"]["billed_tokens"] == 30


def test_unknown_inflight_outcome_blocks_model_retry(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))

    def crash(_messages):
        raise ProcessCrash()

    with database() as session, pytest.raises(ProcessCrash):
        run_langchain_agent(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=ScriptedModel(actions=[crash]),
            checkpoint_key="uncertain-case",
        )
    resumed_model = ScriptedModel(actions=[])
    with database() as session:
        result = run_langchain_agent(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=resumed_model,
            checkpoint_key="uncertain-case",
        )
    assert result["generation"]["reason"] == "model_request_outcome_unknown", result
    assert resumed_model.position == 0
    assert result["cost"]["billed_tokens"] is None


def test_checkpoint_source_revision_is_revalidated(database, store, settings, advisory):
    original = fixture_advisory(advisory)
    ingest(database, store, original)
    with database() as session:
        first = run_langchain_agent(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=ScriptedModel(actions=[retrieve(advisory), finish]),
            checkpoint_key="stale-source",
        )
    assert first["generation"]["status"] == "completed"
    updated = copy.deepcopy(original)
    updated.update(
        updated_at="2026-10-13T00:00:00Z",
        description="The new source description has different evidence.",
    )
    ingest(database, store, updated)
    model = ScriptedModel(actions=[])
    with database() as session:
        result = run_langchain_agent(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=model,
            checkpoint_key="stale-source",
        )
    assert result["generation"]["reason"] == "checkpoint_evidence_stale"
    assert not result["citations"] and model.position == 0


def test_primary_database_writer_is_free_while_model_waits(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    entered, release = Event(), Event()
    from zhidu.rag_conversations import run_rag

    def delayed(*args, **kwargs):
        result = run_rag(*args, **kwargs)
        entered.set()
        assert release.wait(5)
        return result

    monkeypatch.setattr("zhidu.rag_conversations.run_rag", delayed)
    with TestClient(create_app(settings)) as client:
        headers = {"X-Admin-Key": "test-admin"}
        cid = client.post(
            "/api/v1/conversations", headers=headers, json={"title": "waiting"}
        ).json()["id"]
        payload = {
            **body(advisory).model_dump(),
            "generation": "extractive",
            "conversation_id": cid,
            "request_id": "write-free-001",
        }

        def write_other():
            with database.begin() as session:
                session.add(Conversation(title="unrelated writer", state_version=0))
            return True

        with ThreadPoolExecutor(2) as pool:
            pending = pool.submit(client.post, "/api/v1/rag/answers", headers=headers, json=payload)
            assert entered.wait(3)
            try:
                assert pool.submit(write_other).result(timeout=2)
            finally:
                release.set()
            assert pending.result(timeout=3).status_code == 200


def test_persisted_generation_recovers_without_regeneration(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    with database.begin() as session:
        conversation = Conversation(title="recover persist", state_version=0)
        session.add(conversation)
        session.flush()
        cid = conversation.id
    request = body(advisory).model_copy(
        update={
            "generation": "extractive",
            "conversation_id": cid,
            "request_id": "persist-crash-001",
        }
    )
    from zhidu.rag_turn_jobs import generate_prepared_turn, submit_rag_turn

    generated = []

    def count(*args, **kwargs):
        generated.append(1)
        return generate_prepared_turn(*args, **kwargs)

    def crash(*args, **kwargs):
        raise ProcessCrash()

    monkeypatch.setattr("zhidu.rag_turn_jobs.generate_prepared_turn", count)
    monkeypatch.setattr("zhidu.rag_turn_jobs.submit_rag_turn", crash)
    with pytest.raises(ProcessCrash):
        submit_short_turn(database, store, settings, request, None)
    with database.begin() as session:
        job = session.scalar(select(RagTurnJob))
        assert job.generated_result is not None
        job.lease_expires_at = now_utc() - timedelta(seconds=1)
    monkeypatch.setattr("zhidu.rag_turn_jobs.submit_rag_turn", submit_rag_turn)
    result = submit_short_turn(database, store, settings, request, None)
    assert len(generated) == 1 and result["answer_class"] == "evidence"
    with database() as session:
        assert session.scalar(select(func.count()).select_from(ConversationMessage)) == 2
        assert session.scalar(select(func.count()).select_from(RagRun)) == 1


def test_required_checkpoint_loss_does_not_start_a_fresh_model_run(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    model = ScriptedModel(actions=[])
    with database() as session:
        result = run_langchain_agent(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=model,
            checkpoint_key="lost-checkpoint",
            checkpoint_resume_required=True,
        )
    assert result["generation"]["reason"] == "checkpoint_missing"
    assert model.position == 0


def test_provider_or_prompt_change_blocks_checkpoint_reuse(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        result = run_langchain_agent(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=ScriptedModel(actions=[retrieve(advisory), finish]),
            checkpoint_key="configuration-guard",
        )
    assert result["generation"]["status"] == "completed"
    model = ScriptedModel(actions=[])
    changed = settings.model_copy(update={"agent_model_name": "different-model"})
    with database() as session:
        result = run_langchain_agent(
            session,
            store,
            changed,
            body(advisory),
            None,
            model=model,
            checkpoint_key="configuration-guard",
            checkpoint_resume_required=True,
        )
    assert result["generation"]["reason"] == "checkpoint_configuration_changed"
    assert model.position == 0
