"""Source spans are continuous, bounded, revision-bound, and literally verifiable."""

import copy
import json

import pytest
from sqlalchemy import select
from test_member_a_rag_context import ingest

from zhidu.models import IntelEvent, SearchChunk
from zhidu.source_spans import canonical_field, source_span, verify_source_span


def _advisory(advisory, description):
    item = copy.deepcopy(advisory)
    item["summary"] = "vLLM source span regression"
    item["description"] = description
    item["vulnerabilities"][0]["package"]["name"] = "vllm"
    return item


def _row(session, field="description", start=0):
    return session.scalar(
        select(SearchChunk).where(
            SearchChunk.field == field,
            SearchChunk.start == start,
        )
    )


def test_paragraph_expands_beyond_900_without_mutating_index(database, store, advisory):
    text = "A vulnerable component permits " + "untrusted input " * 67 + "to execute."
    assert 900 < len(text) <= 1200
    ingest(database, store, _advisory(advisory, text))
    with database() as session:
        row = _row(session)
        before = (row.id, row.text, row.start, row.end)
        citation = source_span(session, store, row)
        assert citation["text"] == text
        assert citation["end"] > row.end
        assert citation["span_provenance"]["boundary_complete"]
        assert verify_source_span(session, store, citation)
        assert (row.id, row.text, row.start, row.end) == before


def test_middle_chunk_anchor_selects_a_complete_sentence(database, store, advisory):
    first = "Background " + "a" * 480 + "."
    target = "Target condition: " + "b" * 570 + " applies."
    third = "Other condition " + "c" * 890 + "."
    text = first + " " + target + " " + third
    ingest(database, store, _advisory(advisory, text))
    with database() as session:
        row = _row(session, start=780)
        citation = source_span(session, store, row, contains="Target condition")
        assert citation["text"] == target
        assert citation["start"] < row.start
        assert citation["end"] < row.end
        assert citation["span_provenance"]["selection_kind"] == "sentences"
        assert text[citation["start"] : citation["end"]] == citation["text"]
        assert verify_source_span(session, store, citation)


def test_chinese_offsets_preserve_original_whitespace_and_characters(database, store, advisory):
    text = (
        "标题\n\n"
        + "条件成立时，"
        + "用户内容" * 250
        + "可造成拒绝服务。\n\n"
        + "其他背景" * 500
        + "。"
    )
    ingest(database, store, _advisory(advisory, text))
    with database() as session:
        citation = source_span(session, store, _row(session, start=780))
        assert citation["text"].endswith("可造成拒绝服务。")
        assert citation["text"].startswith("条件成立时，")
        assert citation["span_provenance"]["offset_unit"] == "unicode_codepoint"
        assert text[citation["start"] : citation["end"]] == citation["text"]
        assert verify_source_span(session, store, citation)


def test_short_json_matches_index_default_serialization(database, store, advisory):
    item = _advisory(advisory, "Short complete source assertion.")
    ingest(database, store, item)
    expected = json.dumps(item["vulnerabilities"], ensure_ascii=False, sort_keys=True)
    assert canonical_field(item["vulnerabilities"]) == expected
    assert ": " in expected and ", " in expected
    with database() as session:
        citation = source_span(session, store, _row(session, field="packages"))
        assert citation["text"] == expected
        assert citation["span_provenance"]["serialization"] == "json-sorted-default-v1"
        assert verify_source_span(session, store, citation)


def test_large_json_uses_complete_contiguous_member_or_value(database, store, advisory):
    item = _advisory(advisory, "A complete source assertion.")
    item["vulnerabilities"] = [
        {
            "package": {"ecosystem": "pip", "name": f"vllm-{n}"},
            "vulnerable_version_range": "a" * 460,
            "first_patched_version": "1.2.0",
        }
        for n in range(4)
    ]
    ingest(database, store, item)
    full = canonical_field(item["vulnerabilities"])
    with database() as session:
        citation = source_span(session, store, _row(session, field="packages", start=780))
        assert 0 < len(citation["text"]) <= 1200
        assert citation["span_provenance"]["selection_kind"] in {"json_member", "json_value"}
        assert citation["span_provenance"]["boundary_complete"]
        assert full[citation["start"] : citation["end"]] == citation["text"]
        assert verify_source_span(session, store, citation)


def test_oversized_sentence_is_explicit_incomplete_original_fragment(database, store, advisory):
    text = "Oversized condition " + "x" * 2000 + "."
    ingest(database, store, _advisory(advisory, text))
    with database() as session:
        row = _row(session)
        citation = source_span(session, store, row)
        assert citation["text"] == row.text
        assert citation["start"] == row.start and citation["end"] == row.end
        assert citation["span_provenance"]["selection_kind"] == "bounded_fragment"
        assert not citation["span_provenance"]["boundary_complete"]
        assert verify_source_span(session, store, citation)
        altered = copy.deepcopy(citation)
        altered["span_provenance"]["boundary_complete"] = True
        assert not verify_source_span(session, store, altered)


@pytest.mark.parametrize(
    "key,value",
    [
        ("text", "Invented quote."),
        ("start", 1),
        ("json_pointer", "/summary"),
        ("sha256", "0" * 64),
        ("revision_id", "0" * 36),
        ("external_id", "GHSA-forged"),
    ],
)
def test_modified_source_identity_offsets_and_text_fail(database, store, advisory, key, value):
    ingest(database, store, _advisory(advisory, "One complete source condition."))
    with database() as session:
        citation = source_span(session, store, _row(session))
        citation[key] = value
        assert not verify_source_span(session, store, citation)


def test_provenance_hash_tampering_and_missing_raw_fail(database, store, advisory):
    ingest(database, store, _advisory(advisory, "One complete source condition."))
    with database() as session:
        citation = source_span(session, store, _row(session))
        altered = copy.deepcopy(citation)
        altered["span_provenance"]["source_field_sha256"] = "0" * 64
        assert not verify_source_span(session, store, altered)
        store.path_for(citation["sha256"]).write_bytes(b"{}")
        assert not verify_source_span(session, store, citation)


def test_citation_rechecks_current_revision_and_withdrawal(database, store, advisory):
    ingest(database, store, _advisory(advisory, "One complete source condition."))
    with database.begin() as session:
        citation = source_span(session, store, _row(session))
    with database.begin() as session:
        event = session.get(IntelEvent, citation["event_id"])
        event.revision += 1
    with database() as session:
        assert not verify_source_span(session, store, citation)


@pytest.mark.parametrize("limit", [7, 1201, True])
def test_rejects_invalid_bounds(database, store, advisory, limit):
    ingest(database, store, _advisory(advisory, "One complete source condition."))
    with database() as session, pytest.raises(ValueError, match="invalid_span_limit"):
        source_span(session, store, _row(session), max_chars=limit)
