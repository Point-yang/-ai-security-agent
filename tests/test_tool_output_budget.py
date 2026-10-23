"""Public packing, failure admission and recovery share one hard output budget."""

import copy
import json
from contextlib import closing

import pytest
from test_member_a_rag_context import fixture_advisory, ingest
from test_read_fields_pagination import scoped_tools

from zhidu.agent_checkpoint import RecoveryStore
from zhidu.langchain_tools import ReadFieldsArgs, ToolOutputLimit, public_tool_content
from zhidu.source_spans import verify_source_span


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def test_model_observation_keeps_full_quote_and_identity_while_audit_stays_local(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        scope = scoped_tools(session, store, settings)
        text, artifact = scope.invoke(
            "read_fields", {"event_id": next(iter(scope.events)), "fields": ["packages"]}
        )
        public = json.loads(text)["result"]["fields"][0]
        local = artifact["result"]["fields"][0]
        assert public["text"] == local["text"]
        for field in ("event_id", "source_id", "external_id", "field", "sha256", "json_pointer"):
            assert public["citation"][field] == local["citation"][field]
        assert "source_field_sha256" in local["citation"]["span_provenance"]
        assert "source_field_sha256" not in public["citation"]["span_provenance"]
        assert len(text) < len(encode(artifact))
        assert verify_source_span(session, store, {**local["citation"], "text": local["text"]})
        assert scope.runtime.output_chars == len(text)


def test_large_raw_result_is_packed_before_public_budget_admission(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        control = scoped_tools(session, store, settings)
        args = {"event_id": next(iter(control.events)), "fields": ["description"], "limit": 4}
        _, full = control.invoke("read_fields", args)
        first = copy.deepcopy(full)
        first["result"]["fields"] = first["result"]["fields"][:1]
        cap = len(encode(public_tool_content(first))) + 200
        raw = control.runtime._read_fields(ReadFieldsArgs.model_validate(args))
        assert len(json.dumps(raw, ensure_ascii=False)) > cap
        bounded = settings.model_copy(update={"agent_max_output_chars": cap})
        direct = scoped_tools(session, store, bounded)
        assert direct.runtime.execute("read_fields", args)["error"] == "output_budget_exceeded"
        scope = scoped_tools(session, store, bounded)
        text, result = scope.invoke("read_fields", args)
        assert result["status"] == "completed"
        fields = result["result"]["fields"]
        assert 0 < len(fields) < len(full["result"]["fields"])
        assert result["result"]["more_available"] is True
        assert len(text) == scope.runtime.output_chars <= cap
        assert all(
            verify_source_span(session, store, {**item["citation"], "text": item["text"]})
            for item in fields
        )


def test_too_small_remaining_budget_emits_no_oversized_failure(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        scope = scoped_tools(session, store, settings)
        scope.runtime.output_chars = scope.runtime.max_output_chars - 5
        before = scope.runtime.output_chars
        with pytest.raises(ToolOutputLimit):
            scope.invoke("read_fields", {"event_id": "x" * 36, "fields": ["packages"]})
        assert scope.runtime.output_chars == before
        assert scope.results[-1]["error"] == "model_output_budget_exceeded"
        assert scope.evidence == {}


def test_invalid_schema_responses_share_call_and_character_budgets(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        scope = scoped_tools(session, store, settings)
        tool = next(tool for tool in scope.tools() if tool.name == "read_fields")
        total = 0
        for index in range(7):
            text = tool.invoke({"event_id": next(iter(scope.events)), "fields": "packages"})
            row = json.loads(text)
            assert row["error"] == ("invalid_arguments" if index < 6 else "call_budget_exceeded")
            assert "packages" not in text  # raw invalid inputs stay out of diagnostics
            total += len(text)
        assert scope.runtime.output_chars == total <= scope.runtime.max_output_chars
        assert scope.runtime.steps == [] and scope.evidence == {}
        exhausted = scoped_tools(session, store, settings)
        exhausted.runtime.output_chars = exhausted.runtime.max_output_chars - 5
        tool = next(tool for tool in exhausted.tools() if tool.name == "read_fields")
        with pytest.raises(ToolOutputLimit):
            tool.invoke({"event_id": next(iter(exhausted.events)), "fields": "packages"})
        assert exhausted.runtime.output_chars <= exhausted.runtime.max_output_chars


def test_blocked_output_receipt_stays_blocked_on_free_tool_replay(
    database, store, settings, advisory, tmp_path
):
    ingest(database, store, fixture_advisory(advisory))
    with (
        database() as session,
        closing(RecoveryStore(tmp_path / "output-receipts.sqlite", "output-limit", {})) as recovery,
    ):
        scope = scoped_tools(session, store, settings)
        scope.recovery = recovery
        scope.runtime.output_chars = scope.runtime.max_output_chars - 5
        scope.call_context.identity = "paid-step:tool-1"
        args = {"event_id": "x" * 36, "fields": ["packages"]}
        with pytest.raises(ToolOutputLimit):
            scope.invoke("read_fields", args)
        calls = scope.attempted_calls
        with pytest.raises(ToolOutputLimit):
            scope.invoke("read_fields", args)
        assert scope.attempted_calls == calls
        assert scope.runtime.output_chars <= scope.runtime.max_output_chars
