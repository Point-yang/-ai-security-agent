"""Pagination keeps source fields, provenance, budget gaps and miss scope intact."""

import copy
import hashlib
import json

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from test_member_a_rag_context import fixture_advisory, ingest

from zhidu.langchain_tools import ReadFieldsArgs, SourceRuntime, ToolSession, public_tool_content
from zhidu.models import IntelEvent
from zhidu.rag import RagRequest
from zhidu.source_spans import canonical_field, verify_source_span
from zhidu.sources import resolve_pointer


def scoped_tools(session, store, settings, *, event_id=None):
    event_id = event_id or session.scalar(select(IntelEvent.id))
    body = RagRequest(question="说明公告原始字段与条件", event_id=event_id)
    runtime = SourceRuntime(session, store, settings, None, clock=lambda: 0)
    return ToolSession(runtime, body, None)


def read(tools, fields=None, *, offset=None, contains=None, limit=1, event_id=None):
    args = {
        "event_id": event_id or next(iter(tools.events)),
        "fields": fields or ["description"],
        "limit": limit,
    }
    if offset is not None:
        args["after_offset"] = offset
    if contains is not None:
        args["contains"] = contains
    model_text, artifact = tools.invoke("read_fields", args)
    assert json.loads(model_text) == public_tool_content(artifact)
    return artifact


def assert_source_packet(session, store, fields):
    for item in fields:
        citation = {**item["citation"], "text": item["text"]}
        assert verify_source_span(session, store, citation)
        raw = store.read(citation["sha256"])
        assert hashlib.sha256(raw).hexdigest() == citation["sha256"]
        text = canonical_field(resolve_pointer(json.loads(raw), citation["json_pointer"]))
        assert text[citation["start"] : citation["end"]] == item["text"]
        assert (
            citation["span_provenance"]["source_field_sha256"]
            == hashlib.sha256(text.encode()).hexdigest()
        )


@pytest.mark.parametrize("offset", [-1, True, 1.1, "900"])
def test_after_offset_is_strict_nonnegative_integer(offset):
    with pytest.raises(ValidationError):
        ReadFieldsArgs(event_id="a" * 36, fields=["description"], after_offset=offset)


def test_first_chunk_of_each_field_precedes_extra_description_chunks(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        tools = scoped_tools(session, store, settings)
        result = read(tools, ["description", "packages"], limit=2)
        assert result["status"] == "completed"
        fields = result["result"]["fields"]
        assert [item["citation"]["field"] for item in fields] == ["description", "packages"]
        assert result["result"]["more_available"] is True
        assert set(result["result"]["next_offsets"]) == {"description", "packages"}
        assert_source_packet(session, store, fields)


def test_returned_cursor_advances_over_original_chunks_without_restarting(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        tools = scoped_tools(session, store, settings)
        cursor, seen_chunks = 0, set()
        for _ in range(6):
            result = read(tools, offset=cursor)
            assert result["status"] == "completed", result
            value = result["result"]
            assert_source_packet(session, store, value["fields"])
            chunk_ids = {item["citation"]["chunk_id"] for item in value["fields"]}
            assert not chunk_ids & seen_chunks
            seen_chunks |= chunk_ids
            next_cursor = value["next_offsets"]["description"]
            assert next_cursor > cursor
            assert next_cursor == max(
                item["citation"]["span_provenance"]["base_end"] for item in value["fields"]
            )
            cursor = next_cursor
            if not value["more_available"]:
                break
        else:
            pytest.fail("fixture description must finish within the shared six-call budget")
        assert len(seen_chunks) > 2
        assert "Upgrade to 1.2.0" in " ".join(c["text"] for c in tools.evidence.values())
        assert tools.attempted_calls <= 6


def test_new_offsets_do_not_reset_the_six_call_budget(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        tools = scoped_tools(session, store, settings)
        for offset in range(6):
            assert read(tools, offset=offset)["status"] == "completed"
        seventh = read(tools, offset=6)
        assert seventh["error"] == "call_budget_exceeded"
        assert tools.attempted_calls == 7
        assert len(tools.runtime.steps) == 6


def test_cursor_cannot_read_a_valid_but_undiscovered_event(database, store, settings, advisory):
    first = fixture_advisory(advisory)
    second = copy.deepcopy(first)
    second.update(ghsa_id="GHSA-dddd-eeee-ffff", cve_id="CVE-2099-7777")
    ingest(database, store, first)
    ingest(database, store, second)
    with database() as session:
        events = {event.external_id: event.id for event in session.scalars(select(IntelEvent))}
        tools = scoped_tools(session, store, settings, event_id=events[first["ghsa_id"]])
        result = read(tools, offset=0, event_id=events[second["ghsa_id"]])
        assert result["error"] == "target_not_in_current_retrieval"
        assert not tools.evidence
        assert tools.events == {events[first["ghsa_id"]]}


def test_late_page_miss_does_not_block_the_same_query_on_earlier_page(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        tools = scoped_tools(session, store, settings)
        miss = read(tools, offset=3000, contains="vLLM input")
        assert miss["error"] == "not_found"
        assert tools.missing_queries[-1][-1] == 3000
        earlier = read(tools, offset=0, contains="vLLM input")
        assert earlier["status"] == "completed", earlier
        assert any("vLLM input" in item["text"] for item in earlier["result"]["fields"])
        assert_source_packet(session, store, earlier["result"]["fields"])


def test_late_page_miss_does_not_block_wider_earlier_query(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        tools = scoped_tools(session, store, settings)
        assert read(tools, offset=3000, contains="vLLM input validation")["error"] == "not_found"
        earlier = read(tools, offset=0, contains="vLLM input")
        assert earlier["status"] == "completed"


def test_whole_field_miss_blocks_more_specific_query_in_same_or_later_scope(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        tools = scoped_tools(session, store, settings)
        assert read(tools, offset=0, contains="does-not-exist")["error"] == "not_found"
        for offset in (0, 2000):
            narrower = read(tools, offset=offset, contains="does-not-exist-specific")
            assert narrower["error"] == "known_missing_field_query"


def test_legacy_three_part_miss_snapshot_has_whole_field_scope(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        tools = scoped_tools(session, store, settings)
        event_id = next(iter(tools.events))
        snapshot = tools.snapshot()
        snapshot["missing_queries"] = [[event_id, ["description"], "does-not-exist"]]
        restored = scoped_tools(session, store, settings)
        restored.restore(snapshot)
        assert (
            read(restored, offset=900, contains="does-not-exist-specific")["error"]
            == "known_missing_field_query"
        )


def test_miss_in_one_field_does_not_block_another_field(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        tools = scoped_tools(session, store, settings)
        assert (
            read(tools, ["description"], offset=0, contains="first_patched_version")["error"]
            == "not_found"
        )
        package = read(tools, ["packages"], offset=0, contains="first_patched_version")
        assert package["status"] == "completed"
        assert_source_packet(session, store, package["result"]["fields"])


def test_pagination_rechecks_current_revision_and_rejects_tampered_raw(
    database, store, settings, advisory, monkeypatch
):
    original = fixture_advisory(advisory)
    ingest(database, store, original)
    with database() as session:
        tools = scoped_tools(session, store, settings)
        first = read(tools)
        prior = {
            **first["result"]["fields"][0]["citation"],
            "text": first["result"]["fields"][0]["text"],
        }
        assert verify_source_span(session, store, prior)
    changed = copy.deepcopy(original)
    changed.update(
        updated_at="2026-10-13T00:00:00Z",
        description=original["description"] + "\nCurrent revision only.\n",
    )
    ingest(database, store, changed)
    with database() as session:
        assert not verify_source_span(session, store, prior)
        tools = scoped_tools(session, store, settings)
        current = read(tools, offset=900)
        assert current["status"] == "completed"
        assert {item["citation"]["revision"] for item in current["result"]["fields"]} == {2}
        assert_source_packet(session, store, current["result"]["fields"])
        actual_read = store.read
        monkeypatch.setattr(store, "read", lambda sha: actual_read(sha) + b" ")
        rejected = read(tools, offset=1800)
        assert rejected["error"] == "evidence_invalid"


def test_budget_cursor_does_not_jump_past_an_omitted_middle_span(
    database, store, settings, advisory, monkeypatch
):
    item = fixture_advisory(advisory)
    # Four indexed windows produce complete source spans of differing sizes.
    # A larger middle span is dropped while a smaller later span could fit.
    item["description"] = "\n\n".join(
        (
            "alpha " * 135 + ".",
            "bravo " * 183 + ".",
            "charlie " * 25 + ".",
            "delta " * 138 + ".",
        )
    )
    ingest(database, store, item)
    with database() as session:
        full_tools = scoped_tools(session, store, settings)
        full = read(full_tools, limit=4)
        assert full["status"] == "completed"
        items = full["result"]["fields"]
        assert len(items) == 4
        assert all(i["citation"]["span_provenance"]["boundary_complete"] for i in items)
        two_small = copy.deepcopy(full)
        two_small["result"]["fields"] = [items[0], items[-1]]
        cap = (
            len(
                json.dumps(
                    public_tool_content(two_small), ensure_ascii=False, separators=(",", ":")
                )
            )
            + 100
        )
        assert len(items[1]["text"]) > len(items[-1]["text"])
        monkeypatch.setattr("zhidu.langchain_tools.MAX_CALL_CHARS", cap)
        bounded_tools = scoped_tools(session, store, settings)
        bounded = read(bounded_tools, limit=4)
        assert bounded["status"] == "completed", bounded
        value = bounded["result"]
        assert value["whole_spans_omitted_by_budget"] > 0
        assert value["more_available"] is True
        # Continuing from this cursor must still make the dropped second row
        # eligible, even if the packer also retained a later small span.
        first_base_end = items[0]["citation"]["span_provenance"]["base_end"]
        assert value["next_offsets"]["description"] == first_base_end
        assert_source_packet(session, store, value["fields"])
        next_page = read(bounded_tools, offset=first_base_end, limit=1)
        assert next_page["status"] == "completed"
        assert (
            next_page["result"]["fields"][0]["citation"]["chunk_id"]
            == items[1]["citation"]["chunk_id"]
        )


def test_budget_omitted_field_has_no_cursor_and_can_be_read_later(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        control = read(scoped_tools(session, store, settings), ["description", "packages"], limit=2)
        first_only = copy.deepcopy(control)
        first_only["result"]["fields"] = [control["result"]["fields"][0]]
        cap = (
            len(
                json.dumps(
                    public_tool_content(first_only), ensure_ascii=False, separators=(",", ":")
                )
            )
            + 150
        )
        monkeypatch.setattr("zhidu.langchain_tools.MAX_CALL_CHARS", cap)
        tools = scoped_tools(session, store, settings)
        partial = read(tools, ["description", "packages"], limit=2)
        assert partial["status"] == "completed"
        value = partial["result"]
        assert [i["citation"]["field"] for i in value["fields"]] == ["description"]
        assert "packages" not in value["next_offsets"]
        assert value["more_available"] is True
        package = read(tools, ["packages"], offset=0, limit=1)
        assert package["status"] == "completed"
        assert package["result"]["fields"][0]["citation"]["field"] == "packages"
        assert_source_packet(session, store, package["result"]["fields"])
