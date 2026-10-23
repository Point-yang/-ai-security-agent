"""Only actually returned local field catalogs guide later tool admission."""

import copy

import pytest
from test_context_navigation_tools import find_entry, invoke, navigation_source, scoped
from test_member_a_rag_context import ingest

from zhidu.agent_checkpoint import RecoveryStore
from zhidu.evidence_novelty import evidence_novelty


@pytest.mark.parametrize("mode", ["excerpt", "section", "outline", "ids"])
def test_every_executed_read_mode_returns_and_records_current_field_catalog(
    database, store, settings, advisory, mode
):
    ingest(database, store, navigation_source(advisory))
    with database() as session:
        tools = scoped(session, store, settings)
        ids = None
        if mode == "ids":
            _, outline = invoke(tools)
            ids = [find_entry(outline, "Guidance")["context_id"]]
        before = tools.runtime.output_chars
        text, result = invoke(
            tools,
            context="section" if mode == "ids" else mode,
            ids=ids,
            contains="Guidance" if mode in {"excerpt", "section"} else None,
        )
        assert result["status"] == "completed", result
        value = result["result"]
        catalog = value["available_fields"]
        assert catalog == sorted(set(catalog))
        assert {"description", "packages", "title"} <= set(catalog)
        assert tools.field_catalog == {value["event_id"]: catalog}
        assert tools.runtime.output_chars - before == len(text)
        if mode == "outline":
            assert not tools.evidence
            assert evidence_novelty({}, tools.evidence)["new_source_chars"] == 0


def test_known_missing_request_is_still_executed_and_paid_without_becoming_source_absence(
    database, store, settings, advisory
):
    ingest(database, store, navigation_source(advisory))
    with database() as session:
        tools = scoped(session, store, settings)
        text, result = invoke(tools, context="section", fields=["not_in_this_index"])
        assert result["status"] == "completed"
        value = result["result"]
        assert value["fields"] == [] and value["missing_requested_fields"] == ["not_in_this_index"]
        assert tools.field_catalog[value["event_id"]] == value["available_fields"]
        assert tools.attempted_calls == len(tools.runtime.steps) == 1
        assert tools.runtime.output_chars == len(text) and not tools.evidence
        assert tools.no_progress_calls == 0  # New navigation, zero source novelty.
        first_catalog = copy.deepcopy(tools.field_catalog)
        _, second = invoke(tools, fields=["also_not_in_this_index"])
        assert second["status"] == "completed"
        assert tools.attempted_calls == len(tools.runtime.steps) == 2
        assert tools.field_catalog == first_catalog and tools.no_progress_calls == 1
        assert not tools.evidence
        assert evidence_novelty({}, tools.evidence)["new_source_chars"] == 0


def test_catalog_never_reads_an_unknown_event(database, store, settings, advisory, monkeypatch):
    ingest(database, store, navigation_source(advisory))
    with database() as session:
        tools = scoped(session, store, settings)

        def forbidden_lookup(*args, **kwargs):
            raise AssertionError("unknown event must be rejected before active_chunks")

        monkeypatch.setattr("zhidu.langchain_tools.active_chunks", forbidden_lookup)
        _, result = invoke(tools, event_id="f" * 36)
        assert result["error"] == "target_not_in_current_retrieval"
        assert tools.field_catalog == {} and not tools.evidence
        assert tools.attempted_calls == 1 and tools.runtime.steps == []


def test_catalog_survives_snapshot_and_cached_reply_adds_zero_calls_or_chars(
    database, store, settings, advisory
):
    ingest(database, store, navigation_source(advisory))
    with database() as session:
        tools = scoped(session, store, settings)
        recovery = RecoveryStore(
            settings.agent_checkpoint_path, "field-catalog", {"test": "field-catalog"}
        )
        try:
            tools.recovery = recovery
            tools.call_context.identity = "catalog:0"
            reply = invoke(tools, fields=["not_in_this_index"])
            restored = scoped(session, store, settings)
            restored.restore(recovery.context())
            restored.recovery = recovery
            restored.call_context.identity = "catalog:0"
            before = (restored.attempted_calls, restored.runtime.output_chars)
            assert invoke(restored, fields=["not_in_this_index"]) == reply
            assert (restored.attempted_calls, restored.runtime.output_chars) == before
            assert restored.field_catalog == tools.field_catalog and not restored.evidence
            assert recovery.replayed_tools == 1
        finally:
            recovery.close()


def test_legacy_frozen_snapshot_does_not_acquire_a_free_catalog(
    database, store, settings, advisory
):
    ingest(database, store, navigation_source(advisory))
    with database() as session:
        tools = scoped(session, store, settings)
        snapshot = tools.snapshot()
        snapshot.pop("field_catalog")
        before = copy.deepcopy(snapshot)
        restored = scoped(session, store, settings)
        restored.restore(snapshot)
        assert restored.field_catalog == {} and restored.runtime.output_chars == 0
        assert snapshot == before


def test_field_catalog_metadata_cannot_bypass_the_remaining_total_output_budget(
    database, store, settings, advisory
):
    ingest(database, store, navigation_source(advisory))
    with database() as session:
        tools = scoped(session, store, settings)
        tools.runtime.output_chars = tools.runtime.max_output_chars - 100
        before = tools.runtime.output_chars
        text, result = invoke(tools)
        assert result["error"] == "model_output_budget_exceeded"
        assert "available_fields" not in result.get("result", {})
        assert tools.field_catalog == {} and tools.context_index == {} and not tools.evidence
        assert tools.runtime.output_chars == before + len(text) <= tools.runtime.max_output_chars
        assert tools.attempted_calls == 1 and tools.no_progress_calls == 1


def test_catalog_is_still_real_output_when_all_quote_spans_are_omitted(
    database, store, settings, advisory
):
    ingest(database, store, navigation_source(advisory, count=1, body_chars=2000))
    with database() as session:
        tools = scoped(session, store, settings)
        tools.runtime.output_chars = tools.runtime.max_output_chars - 800
        before = tools.runtime.output_chars
        text, result = invoke(tools, context="section", contains="Context 1")
        assert result["status"] == "completed", result
        value = result["result"]
        assert value["fields"] == [] and value["whole_spans_omitted_by_budget"] == 1
        assert tools.field_catalog[value["event_id"]] == value["available_fields"]
        assert not tools.evidence and tools.no_progress_calls == 0
        assert tools.runtime.output_chars == before + len(text) <= tools.runtime.max_output_chars
