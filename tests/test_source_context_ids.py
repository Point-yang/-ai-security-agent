"""Bounded source navigation IDs, exact reads and compatible provenance."""

import copy
import hashlib
import json

import pytest
from sqlalchemy import select
from test_member_a_rag_context import ingest
from test_source_spans import _advisory, _row

from zhidu.models import IntelEvent, SearchChunk
from zhidu.source_context import context_ranges, navigation_contexts
from zhidu.source_spans import (
    source_context_index,
    source_context_span,
    source_context_spans_by_ids,
    source_span,
    verify_source_context_span,
    verify_source_span,
)


def document():
    return (
        "Generic loader wording in the first unstructured paragraph. " * 25 + "\n\n"
        "## Conditions\n\nApplications must meet all of these gates:\n\n"
        "1. First necessary gate.\n2. Second necessary gate.\n3. Third necessary gate.\n4. Fourth necessary gate.\n\n"
        "## Guidance\n\nUse trusted inputs and a narrow allowlist; retain the round-trip boundary.\n\n"
        "## Appendix\n\nUNREAD-BODY-MARKER.\n"
    )


def test_outline_contains_only_navigation_labels_and_can_locate_the_full_list(
    database, store, advisory
):
    text = document()
    ingest(database, store, _advisory(advisory, text))
    with database() as session:
        row = _row(session)
        index = source_context_index(session, store, row)
        assert index["more_available"] is False and index["next_offset"] is None
        encoded = json.dumps(index, ensure_ascii=False)
        assert "Generic loader wording" not in encoded
        assert "First necessary gate" not in encoded and "UNREAD-BODY-MARKER" not in encoded
        assert all(
            set(item)
            == {
                "context_id",
                "kind",
                "label",
                "start",
                "end",
                "field",
                "event_id",
                "source_binding",
            }
            and item["context_id"].startswith("ctx_")
            and len(item["label"]) <= 120
            for item in index["items"]
        )
        entry = next(item for item in index["items"] if item["kind"] == "list_with_intro")
        citation = source_context_spans_by_ids(session, store, row, [entry["context_id"]])[0]
        assert citation["text"] == text[entry["start"] : entry["end"]]
        assert (
            "all of these gates" in citation["text"] and "Fourth necessary gate" in citation["text"]
        )
        assert "UNREAD-BODY-MARKER" not in citation["text"]
        proof = citation["span_provenance"]
        assert (
            proof["version"] == "source-context-span-v2"
            and proof["context_id"] == entry["context_id"]
        )
        assert proof["context"]["complete"] and verify_source_context_span(session, store, citation)
        assert verify_source_span(session, store, citation)


def test_directory_binding_is_shared_across_ranges_without_changing_existing_id_hash(
    database, store, advisory
):
    text = document()
    ingest(database, store, _advisory(advisory, text))
    with database() as session:
        row = _row(session)
        entries = source_context_index(session, store, row)["items"]
        identity = {
            key: getattr(row, key)
            for key in (
                "event_id",
                "revision_id",
                "revision_number",
                "raw_document_id",
                "sha256",
                "source_id",
                "external_id",
                "origin",
                "json_pointer",
                "field",
            )
        }
        identity.update(
            version="source-context-index-v1",
            source_field_sha256=hashlib.sha256(text.encode()).hexdigest(),
        )

        def digest(value):
            return hashlib.sha256(
                json.dumps(
                    value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
                ).encode()
            ).hexdigest()

        assert {entry["source_binding"] for entry in entries} == {digest(identity)}
        for entry in entries:
            old_id_input = {**identity, **{key: entry[key] for key in ("kind", "start", "end")}}
            assert entry["context_id"] == "ctx_" + digest(old_id_input)[:24]


def test_outline_filter_matches_labels_not_unread_body_and_plain_fields_have_safe_labels(
    database, store, advisory
):
    text = "Plain confidential source body; UNSHARED-MARKER."
    ingest(database, store, _advisory(advisory, text))
    with database() as session:
        row = _row(session)
        index = source_context_index(session, store, row)
        assert index["items"][0]["label"] == "description" and index["items"][0]["kind"] == "field"
        assert "UNSHARED-MARKER" not in json.dumps(index)
        assert source_context_index(session, store, row, contains="UNSHARED-MARKER")["items"] == []
        assert (
            source_context_index(session, store, row, contains="DESCRIPTION")["items"]
            == index["items"]
        )


def test_bounded_outline_pages_never_repeat_or_skip_a_start(database, store, advisory):
    text = "".join(f"## Topic {index}\n\nBody {index}.\n\n" for index in range(25))
    ingest(database, store, _advisory(advisory, text))
    with database() as session:
        row, cursor, entries = _row(session), None, []
        while True:
            index = source_context_index(session, store, row, after_offset=cursor, limit=12)
            assert 0 < len(index["items"]) <= 12
            entries.extend(index["items"])
            cursor = index["next_offset"]
            if not index["more_available"]:
                assert cursor is None
                break
        assert len(entries) == 25
        assert len({item["start"] for item in entries}) == len(entries)
        assert [item["label"] for item in entries] == [f"## Topic {index}" for index in range(25)]
        assert len({item["context_id"] for item in entries}) == 25
        assert source_context_index(session, store, row, after_offset=len(text))["items"] == []


def test_no_intro_list_label_is_its_heading_not_an_item_body():
    text = "## Requirements\n\n- BODY-SECRET-FIRST\n- BODY-SECRET-SECOND\n"
    entries = navigation_contexts(text, "description")
    entry = next(item for item in entries if item["kind"] == "list_with_intro")
    assert entry["label"] == "## Requirements"
    assert "BODY-SECRET" not in json.dumps(entries)
    bare = navigation_contexts("- BODY-SECRET-FIRST\n- BODY-SECRET-SECOND\n", "description")
    assert bare[0]["label"] == "description" and len(bare) == 1


def test_long_labels_are_bounded_source_prefixes_and_fenced_pseudo_headings_are_not_indexed():
    title = "## " + "Long title " * 20
    text = title + "\n\n```markdown\n## Fake heading\n- Fake item\n```\n\nActual body.\n"
    entries = navigation_contexts(text, "description")
    assert len(entries) == 1 and entries[0]["label"] == title[:120]
    assert "Fake heading" not in json.dumps(entries)


def test_v2_multiple_ids_load_and_parse_once_even_with_many_repeated_words(
    database, store, advisory, monkeypatch
):
    import zhidu.source_context as parser
    import zhidu.source_spans as reader

    text = "".join(f"## Topic {index}\n\n" + "repeated " * 300 + "\n\n" for index in range(4))
    ingest(database, store, _advisory(advisory, text))
    with database() as session:
        row = _row(session)
        ids = [item["context_id"] for item in source_context_index(session, store, row)["items"]]
        original_load, original_lines = reader._load_field, parser._lines
        calls = {"load": 0, "parse": 0}

        def load(*args):
            calls["load"] += 1
            return original_load(*args)

        def lines(*args):
            calls["parse"] += 1
            return original_lines(*args)

        monkeypatch.setattr(reader, "_load_field", load)
        monkeypatch.setattr(parser, "_lines", lines)
        citations = source_context_spans_by_ids(session, store, row, ids)
        assert calls == {"load": 1, "parse": 1}
        assert len(citations) == 4 and all(len(citation["text"]) == 1200 for citation in citations)
        assert all(not citation["span_provenance"]["context"]["complete"] for citation in citations)


def test_v2_same_context_pages_exactly_with_no_joining_or_false_complete(database, store, advisory):
    text = "## Guidance\n\n" + "Trust boundary🙂 remains mandatory. " * 100
    ingest(database, store, _advisory(advisory, text))
    with database() as session:
        row = _row(session)
        context_id = source_context_index(session, store, row)["items"][0]["context_id"]
        cursor, pages = None, []
        while True:
            citation = source_context_spans_by_ids(
                session, store, row, [context_id], after_offset=cursor
            )[0]
            context = citation["span_provenance"]["context"]
            assert not context["complete"] and verify_source_span(session, store, citation)
            if pages:
                assert pages[-1]["end"] == citation["start"]
            pages.append(citation)
            cursor = context["continuation_offset"]
            if cursor is None:
                break
        assert "".join(citation["text"] for citation in pages) == text


def test_context_ids_bind_the_current_field_and_unknown_namespace_is_rejected(
    database, store, advisory
):
    ingest(database, store, _advisory(advisory, document()))
    with database() as session:
        row = _row(session)
        package_row = _row(session, field="packages")
        context_id = source_context_index(session, store, row)["items"][0]["context_id"]
        for wrong_row, wrong_id in [
            (package_row, context_id),
            (row, "ans_0000000000000000_1"),
            (row, "ctx_" + "0" * 24),
        ]:
            with pytest.raises(ValueError, match="source_context_invalid_id"):
                source_context_spans_by_ids(session, store, wrong_row, [wrong_id])


def test_changed_source_revision_rejects_old_ids(database, store, advisory):
    original = _advisory(advisory, document())
    ingest(database, store, original)
    with database() as session:
        context_id = source_context_index(session, store, _row(session))["items"][0]["context_id"]
    changed = copy.deepcopy(original)
    changed["description"] += "\nAdditional source detail.\n"
    changed["updated_at"] = "2099-01-03T00:00:00Z"
    ingest(database, store, changed)
    with database() as session:
        event = session.scalar(select(IntelEvent))
        row = session.scalar(
            select(SearchChunk).where(
                SearchChunk.field == "description",
                SearchChunk.start == 0,
                SearchChunk.revision_number == event.revision,
            )
        )
        assert source_context_index(session, store, row)["items"][0]["context_id"] != context_id
        with pytest.raises(ValueError, match="source_context_invalid_id"):
            source_context_spans_by_ids(session, store, row, [context_id])


@pytest.mark.parametrize("change", ["context_id", "complete", "source_id", "text", "after_offset"])
def test_v2_citation_proof_tampering_fails_current_source_verification(
    database, store, advisory, change
):
    ingest(database, store, _advisory(advisory, document()))
    with database() as session:
        row = _row(session)
        ids = [item["context_id"] for item in source_context_index(session, store, row)["items"]]
        citation = source_context_spans_by_ids(session, store, row, [ids[0]])[0]
        if change == "context_id":
            citation["span_provenance"]["context_id"] = ids[-1]
        elif change == "complete":
            citation["span_provenance"]["context"]["complete"] = False
        elif change == "after_offset":
            citation["span_provenance"]["after_offset"] = citation["end"]
        else:
            citation[change] = "forged"
        assert not verify_source_context_span(session, store, citation) and not verify_source_span(
            session, store, citation
        )


def test_old_source_and_context_v1_are_byte_stable_after_new_navigation_reads(
    database, store, advisory
):
    text = document()
    ingest(database, store, _advisory(advisory, text))
    with database() as session:
        row = _row(session)
        source_before = source_span(session, store, row, contains="Generic loader")
        context_before = source_context_span(session, store, row, contains="Applications must")
        old_bytes = [
            json.dumps(item, sort_keys=True, ensure_ascii=False)
            for item in [source_before, context_before]
        ]
        index = source_context_index(session, store, row)
        source_context_spans_by_ids(session, store, row, [index["items"][0]["context_id"]])
        assert old_bytes == [
            json.dumps(item, sort_keys=True, ensure_ascii=False)
            for item in [
                source_span(session, store, row, contains="Generic loader"),
                source_context_span(session, store, row, contains="Applications must"),
            ]
        ]
        assert verify_source_span(session, store, source_before) and verify_source_span(
            session, store, context_before
        )


@pytest.mark.parametrize(
    "arguments", [{"limit": 13}, {"limit": True}, {"contains": ""}, {"after_offset": True}]
)
def test_outline_bounds_and_types_remain_strict(database, store, advisory, arguments):
    ingest(database, store, _advisory(advisory, document()))
    with database() as session, pytest.raises(ValueError):
        source_context_index(session, store, _row(session), **arguments)


@pytest.mark.parametrize(
    "case", ["duplicate", "five_ids", "multi_offset", "invalid_offset", "invalid_limit", "bad_type"]
)
def test_id_batches_and_page_parameters_are_strict(database, store, advisory, case):
    ingest(database, store, _advisory(advisory, document()))
    with database() as session:
        row = _row(session)
        ids = [item["context_id"] for item in source_context_index(session, store, row)["items"]]
        arguments = {"context_ids": [ids[0]]}
        if case == "duplicate":
            arguments["context_ids"] *= 2
        elif case == "five_ids":
            arguments["context_ids"] = ids[:1] * 5
        elif case == "multi_offset":
            arguments.update(context_ids=ids[:2], after_offset=0)
        elif case == "invalid_offset":
            arguments["after_offset"] = True
        elif case == "invalid_limit":
            arguments["max_chars"] = 1201
        else:
            arguments["context_ids"] = [123]
        with pytest.raises(ValueError):
            source_context_spans_by_ids(session, store, row, **arguments)


def test_many_headings_keep_v1_equal_or_higher_section_boundaries():
    text = "".join(f"{'#' * (index % 6 + 1)} Topic {index}\nBody.\n" for index in range(2000))
    ranges = [item for item in context_ranges(text) if item["kind"] == "section"]
    assert len(ranges) == 2000
    for index in [0, 1, 1001, 1998, 1999]:
        level = index % 6 + 1
        following = next(
            (other for other in range(index + 1, 2000) if other % 6 + 1 <= level), None
        )
        expected_end = (
            text.index(f"{'#' * (following % 6 + 1)} Topic {following}\n")
            if following is not None
            else len(text)
        )
        assert ranges[index]["end"] == expected_end
