"""Structured source reads preserve raw text, paging, scope and shared limits."""

import copy
import json

import pytest
from sqlalchemy import select
from test_member_a_rag_context import fixture_advisory, ingest

from zhidu.agent_checkpoint import RecoveryStore
from zhidu.evidence_novelty import evidence_novelty
from zhidu.langchain_tools import ReadFieldsArgs, SourceRuntime, ToolSession, public_tool_content
from zhidu.models import Asset, IntelEvent
from zhidu.rag import RagRequest
from zhidu.source_spans import verify_source_span


def source(advisory, description):
    item = fixture_advisory(advisory)
    item["description"] = description
    return item


def tools_for(session, store, settings, *, asset_id=None, event_id=None):
    event_id = event_id or session.scalar(select(IntelEvent.id))
    body = RagRequest(
        question="说明完整条件和guidance信任边界", event_id=event_id, asset_id=asset_id
    )
    return ToolSession(
        SourceRuntime(session, store, settings, None, clock=lambda: 0), body, asset_id
    )


def read(tools, *, contains=None, after=None, limit=4, context="section", fields=None):
    args = {
        "event_id": next(iter(tools.events)),
        "fields": fields or ["description"],
        "limit": limit,
    }
    if context is not None:
        args["context"] = context
    if contains is not None:
        args["contains"] = contains
    if after is not None:
        args["after_offset"] = after
    text, result = tools.invoke("read_fields", args)
    assert json.loads(text) == public_tool_content(result)
    return result


def quoted(result):
    return [{**item["citation"], "text": item["text"]} for item in result["result"]["fields"]]


def test_section_read_covers_intro_and_four_conditions_across_original_chunks(
    database, store, settings, advisory
):
    conditions = [
        f"{i}. Condition_{i}: " + "required application boundary " * 5 + "." for i in range(1, 5)
    ]
    intro = "Applications are exposed only when all of the following are true:\n\n"
    block = intro + "\n".join(conditions) + "\n"
    description = "Background. " * 30 + "\n\n" + block + "\n## Other\nUnasked material.\n"
    ingest(database, store, source(advisory, description))
    with database() as session:
        tools = tools_for(session, store, settings)
        result = read(tools, contains="Applications are exposed")
        assert result["status"] == "completed", result
        citations = quoted(result)
        assert len(citations) == 1  # One structure, even if several chunks match.
        citation = citations[0]
        assert intro.strip() in citation["text"]
        assert all(condition in citation["text"] for condition in conditions)
        assert citation["span_provenance"]["context"]["kind"] == "list_with_intro"
        assert citation["span_provenance"]["context"]["complete"]
        assert citation["end"] > citation["span_provenance"]["base_end"]
        assert verify_source_span(session, store, citation)
        assert description[citation["start"] : citation["end"]] == citation["text"]


def test_guidance_section_keeps_trust_allowlist_and_roundtrip_boundaries(
    database, store, settings, advisory
):
    guidance = (
        "## Guidance for load() and loads()\n\n"
        "Use only trusted manifests or serialized objects from trusted storage.\n\n"
        "Do not pass user-controlled requests or tool inputs to these loaders.\n\n"
        "Pass a narrow allowed_objects; avoid the broad all allowlist.\n\n"
        "Secret-marker validation also applies during dumps() -> loads() round trips.\n\n"
    )
    description = "Prior background. " * 70 + "\n\n" + guidance + "## Credits\nUnasked credits.\n"
    ingest(database, store, source(advisory, description))
    with database() as session:
        result = read(tools_for(session, store, settings), contains="Guidance for load")
        assert result["status"] == "completed"
        citation = quoted(result)[0]
        assert citation["text"] == guidance
        assert "Unasked credits" not in citation["text"]
        assert verify_source_span(session, store, citation)


def test_long_context_pages_keep_original_keyword_anchor_and_never_skip_later_text(
    database, store, settings, advisory
):
    description = "## Guidance\n\n" + "Trusted loader restrictions remain mandatory. " * 70
    ingest(database, store, source(advisory, description))
    with database() as session:
        tools = tools_for(session, store, settings)
        cursor, citations = None, []
        for _ in range(4):
            result = read(tools, contains="Guidance", after=cursor, limit=4)
            assert result["status"] == "completed", result
            page = quoted(result)
            assert len(page) == 1
            citation = page[0]
            assert verify_source_span(session, store, citation)
            assert citation["start"] == (cursor or 0)
            assert len(citation["text"]) <= 1200
            assert result["result"]["next_offsets"]["description"] == citation["end"]
            citations.append(citation)
            cursor = citation["span_provenance"]["context"]["continuation_offset"]
            if cursor is None:
                assert result["result"]["more_available"] is False
                break
        else:
            pytest.fail("fixture must finish in at most four shared-budget pages")
        assert "".join(c["text"] for c in citations) == description
        assert len({c["chunk_id"] for c in citations}) == 1
        assert citations[1]["start"] > citations[1]["span_provenance"]["base_end"]
        assert tools.attempted_calls == len(citations)


def context_lists():
    return [
        f"## Group {index}\n\nApplications require all following conditions:\n\n"
        + "\n".join(
            f"{number}. Group_{index}_condition_{number}: " + "required boundary " * 3 + "."
            for number in range(1, 5)
        )
        + "\n\n"
        for index in range(1, 4)
    ]


def test_complete_context_paging_crosses_blank_heading_gaps_without_repeating_old_list(
    database, store, settings, advisory
):
    description = "".join(context_lists())
    ingest(database, store, source(advisory, description))
    with database() as session:
        tools = tools_for(session, store, settings)
        cursor, seen = None, []
        for index in range(1, 4):
            result = read(tools, contains="Applications require", after=cursor, limit=1)
            assert result["status"] == "completed", result
            citation = quoted(result)[0]
            assert f"Group_{index}_condition_4" in citation["text"]
            assert citation["span_provenance"]["context"]["complete"]
            assert verify_source_span(session, store, citation)
            seen.append(citation["start"])
            cursor = result["result"]["next_offsets"]["description"]
            if index < 3:
                assert cursor > citation["end"]
                assert result["result"]["more_available"]
            else:
                assert not result["result"]["more_available"]
        assert len(set(seen)) == 3


def test_budget_dropped_middle_context_cursor_points_to_its_start_not_later_context(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, source(advisory, "".join(context_lists())))
    with database() as session:
        control = read(
            tools_for(session, store, settings), contains="Applications require", limit=3
        )
        all_fields = control["result"]["fields"]
        assert len(all_fields) == 3
        first_only = copy.deepcopy(control)
        first_only["result"]["fields"] = all_fields[:1]
        cap = (
            len(
                json.dumps(
                    public_tool_content(first_only), ensure_ascii=False, separators=(",", ":")
                )
            )
            + 150
        )
        monkeypatch.setattr("zhidu.langchain_tools.MAX_CALL_CHARS", cap)
        tools = tools_for(session, store, settings)
        bounded = read(tools, contains="Applications require", limit=3)
        assert len(bounded["result"]["fields"]) == 1
        second_start = all_fields[1]["citation"]["span_provenance"]["context"]["start"]
        assert bounded["result"]["next_offsets"]["description"] == second_start
        next_page = read(tools, contains="Applications require", after=second_start, limit=1)
        assert next_page["status"] == "completed", next_page
        assert "Group_2_condition_4" in quoted(next_page)[0]["text"]


def test_budget_omission_has_no_cursor_and_cannot_count_discarded_context_proof_as_progress(
    database, store, settings, advisory, monkeypatch
):
    ingest(database, store, source(advisory, "## Guidance\n\n" + "Trusted restriction. " * 50))
    with database() as session:
        tools = tools_for(session, store, settings)
        prior = read(tools, contains="Guidance", context="excerpt", limit=1)
        assert prior["status"] == "completed"
        before = copy.deepcopy(tools.evidence)
        monkeypatch.setattr("zhidu.langchain_tools.MAX_CALL_CHARS", 700)
        result = read(tools, contains="Guidance", context="section", limit=1)
        assert result["status"] == "completed"
        assert result["result"]["fields"] == []
        assert result["result"]["next_offsets"] == {}
        assert result["result"]["whole_spans_omitted_by_budget"] == 1
        assert tools.evidence == before
        assert tools.no_progress_calls == 1
        assert tools.runtime.output_chars <= tools.runtime.max_output_chars


def test_retained_context_metadata_update_is_progress_without_new_raw_characters(
    database, store, settings, advisory
):
    ingest(database, store, source(advisory, "## Guidance\nUse trusted sources only.\n"))
    with database() as session:
        tools = tools_for(session, store, settings)
        assert read(tools, contains="Guidance", context="excerpt")["status"] == "completed"
        before = copy.deepcopy(tools.evidence)
        tools.no_progress_calls = 1
        result = read(tools, contains="Guidance", context="section")
        assert result["status"] == "completed"
        assert set(before) == set(tools.evidence)
        assert tools.no_progress_calls == 0
        assert evidence_novelty(before, tools.evidence)["new_source_chars"] == 0
        assert (
            next(iter(tools.evidence.values()))["span_provenance"]["version"]
            == "source-context-span-v1"
        )


def test_excerpt_miss_cache_cannot_block_structural_context_read(
    database, store, settings, advisory
):
    ingest(database, store, source(advisory, "## Guidance\n" + "Trusted restrictions. " * 100))
    with database() as session:
        tools = tools_for(session, store, settings)
        assert (
            read(tools, contains="Guidance", after=1200, context="excerpt")["error"] == "not_found"
        )
        result = read(tools, contains="Guidance", after=1200, context="section")
        assert result["status"] == "completed", result
        assert quoted(result)[0]["start"] == 1200


def test_structural_miss_is_cached_only_for_that_mode_and_invalid_cursor_is_not_a_miss(
    database, store, settings, advisory
):
    ingest(database, store, source(advisory, "Preamble.\n\n## Guidance\nUse trusted inputs.\n"))
    with database() as session:
        tools = tools_for(session, store, settings)
        assert read(tools, contains="no-such-phrase")["error"] == "not_found"
        assert (
            read(tools, contains="no-such-phrase-specific")["error"] == "known_missing_field_query"
        )
        assert read(tools, contains="Guidance", after=10_000)["error"] == "invalid_arguments"
        assert read(tools, contains="Guidance")["status"] == "completed"
        assert tools.attempted_calls == 4


def test_legacy_default_is_identical_to_explicit_excerpt(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    assert ReadFieldsArgs(event_id="a" * 36, fields=["description"]).context == "excerpt"
    with database() as session:
        default = read(
            tools_for(session, store, settings), contains="Patches", context=None, limit=1
        )
        explicit = read(
            tools_for(session, store, settings), contains="Patches", context="excerpt", limit=1
        )
        assert default == explicit
        assert quoted(default)[0]["span_provenance"]["version"] == "source-span-v1"


def test_section_multiple_fields_are_fair_and_deduplicate_the_same_structure(
    database, store, settings, advisory
):
    ingest(database, store, source(advisory, "## Guidance\n" + "Trusted restrictions. " * 80))
    with database() as session:
        result = read(
            tools_for(session, store, settings), fields=["description", "packages"], limit=4
        )
        assert result["status"] == "completed"
        assert [c["field"] for c in quoted(result)] == ["description", "packages"]
        assert all(verify_source_span(session, store, c) for c in quoted(result))


def test_undiscovered_event_and_invalid_parameters_keep_the_same_six_attempt_budget(
    database, store, settings, advisory
):
    ingest(database, store, source(advisory, "## Guidance\nUse trusted inputs.\n"))
    with database() as session:
        tools = tools_for(session, store, settings)
        args = {"event_id": "a" * 36, "fields": ["description"], "context": "section"}
        assert tools.invoke("read_fields", args)[1]["error"] == "target_not_in_current_retrieval"
        event_id = next(iter(tools.events))
        for index in range(5):
            result = tools.invoke(
                "read_fields",
                {
                    "event_id": event_id,
                    "fields": ["description"],
                    "context": "invalid",
                    "limit": index,
                },
            )[1]
            assert result["error"] == "invalid_arguments"
        assert read(tools, contains="Guidance")["error"] == "call_budget_exceeded"
        assert tools.attempted_calls == 7 and not tools.evidence


def test_context_cache_replay_reuses_exact_span_with_zero_new_attempts(
    database, store, settings, advisory
):
    ingest(database, store, source(advisory, "## Guidance\nUse trusted inputs.\n"))
    with database() as session:
        tools = tools_for(session, store, settings)
        recovery = RecoveryStore(
            settings.agent_checkpoint_path, "context-cache", {"test": "context"}
        )
        try:
            tools.recovery = recovery
            tools.call_context.identity = "context:0"
            first = read(tools, contains="Guidance")
            assert first["status"] == "completed"
            restored = tools_for(session, store, settings)
            restored.restore(recovery.context())
            restored.recovery = recovery
            restored.call_context.identity = "context:0"
            before = restored.attempted_calls
            assert read(restored, contains="Guidance") == first
            assert restored.attempted_calls == before == 1
            assert len(restored.runtime.steps) == 1
            assert recovery.replayed_tools == 1
        finally:
            recovery.close()


def test_public_context_metadata_has_no_unread_body_or_private_asset_artifact(
    database, store, settings, advisory
):
    description = (
        "## Guidance\n"
        + "Trusted sources required. " * 70
        + "\n## Secret future section\nUNREAD-SOURCE-MARKER\n"
    )
    ingest(database, store, source(advisory, description))
    with database.begin() as session:
        asset = Asset(
            name="private-context-host",
            environment="internal",
            criticality="low",
            sbom_sha256="0" * 64,
        )
        session.add(asset)
        session.flush()
        asset_id = asset.id
    with database() as session:
        tools = tools_for(session, store, settings, asset_id=asset_id)
        text, result = tools.invoke(
            "read_fields",
            {
                "event_id": next(iter(tools.events)),
                "fields": ["description"],
                "context": "section",
                "contains": "Guidance",
            },
        )
        assert result["status"] == "completed"
        assert "UNREAD-SOURCE-MARKER" not in text
        assert asset_id not in text and "private-context-host" not in text
        metadata = json.loads(text)["result"]["fields"][0]["citation"]["span_provenance"]["context"]
        assert set(metadata) == {"kind", "start", "end", "complete", "continuation_offset"}
