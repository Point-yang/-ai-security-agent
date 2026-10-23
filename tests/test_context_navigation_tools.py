"""Paid, bounded source navigation remains separate from literal evidence."""

import copy
import json

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from test_member_a_rag_context import fixture_advisory, ingest

from zhidu.agent_checkpoint import RecoveryStore
from zhidu.evidence_novelty import evidence_novelty
from zhidu.langchain_tools import ReadFieldsArgs, SourceRuntime, ToolSession, public_tool_content
from zhidu.models import IntelEvent
from zhidu.rag import RagRequest
from zhidu.source_spans import verify_source_span


def navigation_source(advisory, *, count=4, body_chars=300):
    item = fixture_advisory(advisory)
    item["description"] = (
        "Older runtime uses allowed_objects=all.\n\n"
        "Applications require all following conditions:\n\n"
        "1. Untrusted input is accepted.\n2. Input is not made inert.\n"
        "3. Nested data is preserved.\n4. An affected loader path is used.\n\n"
        "## Guidance\n\nUse narrow allowed_objects with trusted manifests only.\n"
        "UNQUOTED-BODY-MARKER belongs to the original guidance body.\n\n"
        + "".join(
            f"## Context {index}\n\nContext_{index} original body. "
            + "retained restriction " * (body_chars // 21)
            + "\n\n"
            for index in range(1, count + 1)
        )
    )
    return item


def scoped(session, store, settings, *, event_id=None):
    event_id = event_id or session.scalar(select(IntelEvent.id))
    body = RagRequest(question="列出完整条件、guidance和原文范围", event_id=event_id)
    return ToolSession(SourceRuntime(session, store, settings, None, clock=lambda: 0), body, None)


def invoke(
    tools, *, context="outline", fields=None, ids=None, contains=None, after=None, event_id=None
):
    args = {
        "event_id": event_id or next(iter(tools.events)),
        "fields": fields or ["description"],
        "context": context,
    }
    if ids is not None:
        args["context_ids"] = ids
    if contains is not None:
        args["contains"] = contains
    if after is not None:
        args["after_offset"] = after
    text, artifact = tools.invoke("read_fields", args)
    assert json.loads(text) == public_tool_content(artifact)
    return text, artifact


def find_entry(result, label):
    return next(entry for entry in result["result"]["context_index"] if label in entry["label"])


def citations(result):
    return [{**item["citation"], "text": item["text"]} for item in result["result"]["fields"]]


def test_outline_is_paid_navigation_and_contains_no_body_or_evidence(
    database, store, settings, advisory
):
    ingest(database, store, navigation_source(advisory))
    with database() as session:
        tools = scoped(session, store, settings)
        before = copy.deepcopy(tools.evidence)
        text, result = invoke(tools)
        assert result["status"] == "completed", result
        entries = result["result"]["context_index"]
        assert 1 <= len(entries) <= 12
        assert "UNQUOTED-BODY-MARKER" not in text
        assert result["result"]["fields"] == []
        assert tools.attempted_calls == len(tools.runtime.steps) == 1
        assert tools.runtime.output_chars == len(text) > 0
        assert tools.evidence == before == {}
        assert set(tools.context_index) == {entry["context_id"] for entry in entries}
        assert tools.no_progress_calls == 0
        assert evidence_novelty(before, tools.evidence)["new_source_chars"] == 0


def test_ids_select_guidance_without_paging_unheaded_field_and_preserve_raw_proof(
    database, store, settings, advisory
):
    ingest(database, store, navigation_source(advisory))
    with database() as session:
        tools = scoped(session, store, settings)
        _, outline = invoke(tools)
        entry = find_entry(outline, "Guidance")
        _, result = invoke(tools, context="section", ids=[entry["context_id"]])
        assert result["status"] == "completed", result
        citation = citations(result)[0]
        assert citation["start"] == entry["start"] and citation["end"] == entry["end"]
        assert citation["text"].startswith("## Guidance")
        assert "UNQUOTED-BODY-MARKER" in citation["text"]
        assert "Older runtime" not in citation["text"]
        assert citation["span_provenance"]["context"]["complete"]
        assert verify_source_span(session, store, citation)
        assert len(tools.evidence) == 1 and tools.attempted_calls == 2


def test_four_ids_are_all_read_despite_legacy_default_limit_three(
    database, store, settings, advisory
):
    ingest(database, store, navigation_source(advisory, count=4, body_chars=200))
    with database() as session:
        tools = scoped(session, store, settings)
        _, outline = invoke(tools)
        ids = [find_entry(outline, f"Context {index}")["context_id"] for index in range(1, 5)]
        _, result = invoke(tools, context="section", ids=ids)
        assert result["status"] == "completed", result
        spans = citations(result)
        assert len(spans) == 4
        assert all(verify_source_span(session, store, citation) for citation in spans)
        assert result["result"]["omitted_context_ids"] == []
        assert result["result"]["pending_context_ids"] == []
        assert result["result"]["next_offsets"] == {}


@pytest.mark.parametrize(
    "change",
    [
        {"context": "excerpt"},
        {"context": "outline"},
        {"fields": ["description", "packages"]},
        {"contains": "Guidance"},
        {"context_ids": ["context-id", "context-id"]},
        {"context_ids": ["context-a", "context-b"], "after_offset": 0},
        {"context_ids": [f"context-{index}" for index in range(5)]},
    ],
)
def test_context_id_parameter_combinations_are_strict(change):
    args = {
        "event_id": "a" * 36,
        "fields": ["description"],
        "context": "section",
        "context_ids": ["context-id"],
    }
    with pytest.raises(ValidationError):
        ReadFieldsArgs.model_validate(args | change)


def test_unissued_id_wrong_field_and_undiscovered_event_cannot_expand_scope(
    database, store, settings, advisory
):
    first = navigation_source(advisory)
    second = copy.deepcopy(first)
    second.update(ghsa_id="GHSA-dddd-eeee-ffff", cve_id="CVE-2099-7777")
    ingest(database, store, first)
    ingest(database, store, second)
    with database() as session:
        events = {event.external_id: event.id for event in session.scalars(select(IntelEvent))}
        tools = scoped(session, store, settings, event_id=events[first["ghsa_id"]])
        _, outline = invoke(tools)
        context_id = find_entry(outline, "Guidance")["context_id"]
        unissued = scoped(session, store, settings, event_id=events[first["ghsa_id"]])
        assert (
            invoke(unissued, context="section", ids=[context_id])[1]["error"]
            == "context_id_not_in_current_navigation"
        )
        assert (
            invoke(tools, context="section", ids=[context_id], fields=["packages"])[1]["error"]
            == "context_id_not_in_current_navigation"
        )
        assert (
            invoke(tools, context="section", ids=[context_id], event_id=events[second["ghsa_id"]])[
                1
            ]["error"]
            == "target_not_in_current_retrieval"
        )
        assert not tools.evidence and tools.events == {events[first["ghsa_id"]]}


def test_long_id_context_continues_same_structure_in_exact_adjacent_pages(
    database, store, settings, advisory
):
    item = navigation_source(advisory, count=1, body_chars=2600)
    ingest(database, store, item)
    with database() as session:
        tools = scoped(session, store, settings)
        _, outline = invoke(tools)
        entry = find_entry(outline, "Context 1")
        cursor, spans = None, []
        for _ in range(4):
            _, result = invoke(tools, context="section", ids=[entry["context_id"]], after=cursor)
            assert result["status"] == "completed", result
            citation = citations(result)[0]
            assert citation["start"] == (entry["start"] if cursor is None else cursor)
            assert citation["end"] <= entry["end"]
            assert len(citation["text"]) <= 1200 and verify_source_span(session, store, citation)
            spans.append(citation)
            cursor = citation["span_provenance"]["context"]["continuation_offset"]
            if cursor is None:
                assert result["result"]["pending_context_ids"] == []
                break
            assert result["result"]["pending_context_ids"] == [entry["context_id"]]
            assert result["result"]["next_offsets"]["description"] == cursor
        else:
            pytest.fail("long fixture must finish within six total calls")
        assert (
            "".join(c["text"] for c in spans) == item["description"][entry["start"] : entry["end"]]
        )
        assert tools.attempted_calls <= 6


def test_outline_label_miss_does_not_block_a_body_match_in_section_mode(
    database, store, settings, advisory
):
    ingest(database, store, navigation_source(advisory))
    with database() as session:
        tools = scoped(session, store, settings)
        assert invoke(tools, contains="UNQUOTED-BODY-MARKER")[1]["error"] == "not_found"
        _, result = invoke(tools, context="section", contains="UNQUOTED-BODY-MARKER")
        assert result["status"] == "completed", result
        assert verify_source_span(session, store, citations(result)[0])


def test_outline_and_id_reply_cache_restore_issued_navigation_without_new_attempts(
    database, store, settings, advisory
):
    ingest(database, store, navigation_source(advisory))
    with database() as session:
        tools = scoped(session, store, settings)
        recovery = RecoveryStore(
            settings.agent_checkpoint_path, "nav-replay", {"test": "nav-replay"}
        )
        try:
            tools.recovery = recovery
            tools.call_context.identity = "outline:0"
            first_text, first = invoke(tools)
            context_id = find_entry(first, "Guidance")["context_id"]
            restored = scoped(session, store, settings)
            restored.restore(recovery.context())
            restored.recovery = recovery
            restored.call_context.identity = "outline:0"
            before = (restored.attempted_calls, restored.runtime.output_chars)
            assert invoke(restored) == (first_text, first)
            assert (restored.attempted_calls, restored.runtime.output_chars) == before
            assert restored.context_index == tools.context_index and not restored.evidence
            restored.call_context.identity = "section:0"
            section_reply = invoke(restored, context="section", ids=[context_id])
            resumed = scoped(session, store, settings)
            resumed.restore(recovery.context())
            resumed.recovery = recovery
            resumed.call_context.identity = "section:0"
            before = (resumed.attempted_calls, resumed.runtime.output_chars)
            assert invoke(resumed, context="section", ids=[context_id]) == section_reply
            assert (resumed.attempted_calls, resumed.runtime.output_chars) == before
            assert recovery.replayed_tools == 2
        finally:
            recovery.close()


def test_navigation_ids_are_revalidated_after_source_revision_change(
    database, store, settings, advisory
):
    item = navigation_source(advisory)
    ingest(database, store, item)
    with database() as session:
        tools = scoped(session, store, settings)
        _, outline = invoke(tools)
        context_id = find_entry(outline, "Guidance")["context_id"]
        snapshot = copy.deepcopy(tools.snapshot())
    changed = copy.deepcopy(item)
    changed.update(
        updated_at="2026-10-15T00:00:00Z",
        description=item["description"] + "\nCurrent new bytes.\n",
    )
    ingest(database, store, changed)
    with database() as session:
        tools = scoped(session, store, settings)
        tools.restore(snapshot)
        _, result = invoke(tools, context="section", ids=[context_id])
        assert result["status"] == "failed" and not tools.evidence
        assert tools.attempted_calls == snapshot["attempted_calls"] + 1


def test_old_snapshot_has_no_free_navigation_and_failures_use_six_call_budget(
    database, store, settings, advisory
):
    ingest(database, store, navigation_source(advisory))
    with database() as session:
        tools = scoped(session, store, settings)
        snapshot = tools.snapshot()
        snapshot.pop("context_index")
        tools.restore(snapshot)
        assert tools.context_index == {} and tools.runtime.output_chars == 0
        for index in range(6):
            assert (
                invoke(tools, context="section", ids=[f"unissued-{index}"])[1]["error"]
                == "context_id_not_in_current_navigation"
            )
        assert invoke(tools)[1]["error"] == "call_budget_exceeded"
        assert not tools.context_index and not tools.evidence


def test_outline_pages_are_bounded_monotonic_and_never_skip_an_index_entry(
    database, store, settings, advisory
):
    ingest(database, store, navigation_source(advisory, count=20, body_chars=100))
    with database() as session:
        tools = scoped(session, store, settings)
        cursor, returned = None, []
        for _ in range(4):
            _, result = invoke(tools, after=cursor)
            assert result["status"] == "completed", result
            value = result["result"]
            assert 1 <= len(value["context_index"]) <= 12
            ids = [entry["context_id"] for entry in value["context_index"]]
            assert not set(ids) & {entry["context_id"] for entry in returned}
            returned.extend(value["context_index"])
            next_cursor = value["next_offsets"]["description"]
            assert next_cursor > (cursor or 0)
            cursor = next_cursor
            if not value["more_available"]:
                break
        else:
            pytest.fail("twenty headings must fit the bounded navigation pages")
        assert all(
            any(f"Context {index}" in entry["label"] for entry in returned)
            for index in range(1, 21)
        )
        assert set(tools.context_index) == {entry["context_id"] for entry in returned}
        assert not tools.evidence and tools.runtime.output_chars <= tools.runtime.max_output_chars


def test_budget_dropped_navigation_is_not_issued_and_cursor_returns_first_omitted_start(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, navigation_source(advisory, count=10))
    with database() as session:
        _, control = invoke(scoped(session, store, settings))
        entries = control["result"]["context_index"]
        assert len(entries) > 2
        first = copy.deepcopy(control)
        first["result"].update(
            context_index=entries[:1],
            more_available=True,
            whole_index_entries_omitted_by_budget=len(entries) - 1,
            next_offsets={"description": entries[1]["start"]},
        )
        cap = (
            len(json.dumps(public_tool_content(first), ensure_ascii=False, separators=(",", ":")))
            + 150
        )
        monkeypatch.setattr("zhidu.langchain_tools.MAX_CALL_CHARS", cap)
        tools = scoped(session, store, settings)
        text, bounded = invoke(tools)
        assert bounded["status"] == "completed", bounded
        assert bounded["result"]["context_index"] == entries[:1]
        assert bounded["result"]["next_offsets"]["description"] == entries[1]["start"]
        assert set(tools.context_index) == {entries[0]["context_id"]}
        assert len(text) <= cap and not tools.evidence
        # A budget-omitted ID must not be usable as if its metadata had appeared.
        assert (
            invoke(tools, context="section", ids=[entries[1]["context_id"]])[1]["error"]
            == "context_id_not_in_current_navigation"
        )
        _, page = invoke(tools, after=entries[1]["start"])
        assert page["status"] == "completed", page
        assert page["result"]["context_index"][0]["context_id"] == entries[1]["context_id"]


def test_multi_id_budget_omission_is_explicit_and_does_not_grant_evidence(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, navigation_source(advisory, count=4, body_chars=700))
    with database() as session:
        control_tools = scoped(session, store, settings)
        _, outline = invoke(control_tools)
        ids = [find_entry(outline, f"Context {index}")["context_id"] for index in range(1, 5)]
        _, control = invoke(control_tools, context="section", ids=ids)
        assert len(control["result"]["fields"]) == 4
        first = copy.deepcopy(control)
        first["result"].update(
            fields=control["result"]["fields"][:1],
            more_available=True,
            omitted_context_ids=ids[1:],
            pending_context_ids=ids[1:],
            whole_spans_omitted_by_budget=3,
        )
        cap = (
            len(json.dumps(public_tool_content(first), ensure_ascii=False, separators=(",", ":")))
            + 150
        )
        tools = scoped(session, store, settings)
        invoke(tools)
        monkeypatch.setattr("zhidu.langchain_tools.MAX_CALL_CHARS", cap)
        text, partial = invoke(tools, context="section", ids=ids)
        assert partial["status"] == "completed", partial
        value = partial["result"]
        assert len(value["fields"]) == 1
        assert value["omitted_context_ids"] == value["pending_context_ids"] == ids[1:]
        assert value["next_offsets"] == {} and value["more_available"]
        assert len(tools.evidence) == 1 and len(text) <= cap
        assert verify_source_span(session, store, citations(partial)[0])
        _, next_read = invoke(tools, context="section", ids=[ids[1]])
        assert next_read["status"] == "completed", next_read
        assert "Context_2 original body" in citations(next_read)[0]["text"]


def test_global_character_budget_cannot_publish_unpaid_navigation_or_new_evidence(
    database, store, settings, advisory
):
    ingest(database, store, navigation_source(advisory))
    with database() as session:
        tools = scoped(session, store, settings)
        # The initial frozen packet may already have consumed most of the cap.
        tools.runtime.output_chars = tools.runtime.max_output_chars - 600
        before = tools.runtime.output_chars
        text, result = invoke(tools)
        assert result["status"] == "completed", result
        assert result["result"]["context_index"] == []
        assert result["result"]["next_offsets"] == {}
        assert result["result"]["whole_index_entries_omitted_by_budget"] > 0
        assert not tools.context_index and not tools.evidence
        assert tools.field_catalog == {
            result["result"]["event_id"]: result["result"]["available_fields"]
        }
        assert tools.no_progress_calls == 0  # The paid field table is navigation progress.
        assert evidence_novelty({}, tools.evidence)["new_source_chars"] == 0
        assert tools.runtime.output_chars == before + len(text) <= tools.runtime.max_output_chars


def test_id_read_rejects_tampered_raw_even_after_valid_navigation(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, navigation_source(advisory))
    with database() as session:
        tools = scoped(session, store, settings)
        _, outline = invoke(tools)
        context_id = find_entry(outline, "Guidance")["context_id"]
        actual_read = store.read
        monkeypatch.setattr(store, "read", lambda sha: actual_read(sha) + b" ")
        _, result = invoke(tools, context="section", ids=[context_id])
        assert result["error"] == "evidence_invalid"
        assert not tools.evidence and tools.attempted_calls == 2
