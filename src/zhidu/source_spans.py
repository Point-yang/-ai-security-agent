"""Read-only, contiguous source spans anchored to immutable retrieval chunks.

Offsets refer to Unicode code points in the same field serialization used by
``build_chunks``. Verification proves source identity and literal provenance;
it does not establish that a quotation supports a model's claim semantically.
"""

import hashlib
import json
import re

from zhidu.models import EventRevision, IntelEvent, RawDocument, SearchChunk
from zhidu.source_context import VERSION as CONTEXT_SPAN_VERSION
from zhidu.source_context import context_ranges, navigation_contexts, select_context
from zhidu.sources import resolve_pointer

SPAN_VERSION = "source-span-v1"
CONTEXT_ID_SPAN_VERSION = "source-context-span-v2"
CONTEXT_INDEX_VERSION = "source-context-index-v1"
MAX_SPAN_CHARS = 1200
_ABBREVIATIONS = {"e.g.", "i.e.", "etc.", "mr.", "mrs.", "dr.", "vs.", "fig."}
_CLOSERS = "\"'”’)]}*`"


def canonical_field(value):
    """Match indexing exactly, including default JSON separator spaces."""
    return (
        value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
    )


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _trim(text, start, end):
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end


def _prose_units(text):
    """Return complete blank-line paragraphs and sentence ranges, never joins."""
    paragraphs, sentences = [], []
    previous = 0
    separators = list(re.finditer(r"\n[ \t\r]*\n(?:[ \t\r]*\n)*", text))
    for end, following in [(m.start(), m.end()) for m in separators] + [(len(text), len(text))]:
        start, end = _trim(text, previous, end)
        previous = following
        if start == end:
            continue
        paragraphs.append((start, end, "paragraph"))
        cursor, pos = start, start
        while pos < end:
            char = text[pos]
            if char not in ".!?。！？":
                pos += 1
                continue
            after = pos + 1
            while after < end and text[after] in ".!?。！？":
                after += 1
            while after < end and text[after] in _CLOSERS:
                after += 1
            if char in ".!?" and after < end and not text[after].isspace():
                pos += 1
                continue
            token = re.search(r"[A-Za-z.]+$", text[cursor : pos + 1])
            if char == "." and token and token.group(0).casefold() in _ABBREVIATIONS:
                pos += 1
                continue
            unit_start, unit_end = _trim(text, cursor, after)
            if unit_start < unit_end:
                sentences.append((unit_start, unit_end, "sentences"))
            cursor, pos = after, after
        if cursor < end:
            unit_start, unit_end = _trim(text, cursor, end)
            if unit_start < unit_end:
                # A paragraph's end is a valid boundary even without punctuation.
                sentences.append((unit_start, unit_end, "sentences"))
    return paragraphs, sentences


def _json_units(value, start=0):
    """Offsets of complete values/members in the canonical JSON serialization."""
    text = canonical_field(value)
    result = [(start, start + len(text), "json_value")]
    if isinstance(value, list):
        cursor = 1
        for child in value:
            encoded = json.dumps(child, ensure_ascii=False, sort_keys=True)
            result.extend(_json_units_serialized(child, start + cursor))
            cursor += len(encoded) + 2  # Default separator is comma plus space.
    elif isinstance(value, dict):
        cursor = 1
        for key in sorted(value):
            prefix = json.dumps(key, ensure_ascii=False) + ": "
            encoded = json.dumps(value[key], ensure_ascii=False, sort_keys=True)
            result.append(
                (start + cursor, start + cursor + len(prefix) + len(encoded), "json_member")
            )
            result.extend(_json_units_serialized(value[key], start + cursor + len(prefix)))
            cursor += len(prefix) + len(encoded) + 2
    return result


def _json_units_serialized(value, start):
    # Nested strings include quotes/escaping; top-level indexed strings do not.
    if isinstance(value, str):
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True)
        return [(start, start + len(encoded), "json_value")]
    return _json_units(value, start)


def _select(text, value, base_start, base_end, max_chars, contains):
    if len(text) <= max_chars:
        return 0, len(text), "field", True
    anchors = list(re.finditer(re.escape(contains), text, re.IGNORECASE)) if contains else []

    def eligible(start, end):
        return (
            0 < end - start <= max_chars
            and min(end, base_end) > max(start, base_start)
            and (not contains or any(start <= m.start() and m.end() <= end for m in anchors))
        )

    if isinstance(value, str):
        paragraphs, sentences = _prose_units(text)
        candidates = [unit for unit in paragraphs if eligible(unit[0], unit[1])]
        # Combine adjacent complete sentences by selecting a single original
        # source interval; whitespace and intervening text remain untouched.
        nearby = [
            s for s in sentences if base_start - max_chars < s[1] and s[0] < base_end + max_chars
        ]
        for index, first in enumerate(nearby):
            for last in nearby[index:]:
                if last[1] - first[0] > max_chars:
                    break
                if eligible(first[0], last[1]):
                    candidates.append((first[0], last[1], "sentences"))
    else:
        candidates = [unit for unit in _json_units(value) if eligible(unit[0], unit[1])]
    if candidates:
        # Preserve as much of the retrieved context as possible; prefer less
        # expansion on ties, and retain complete paragraphs over sentence runs.
        start, end, kind = max(
            candidates,
            key=lambda s: (
                min(s[1], base_end) - max(s[0], base_start),
                -(s[1] - s[0]),
                s[2] == "paragraph",
                -s[0],
            ),
        )
        return start, end, kind, True
    # A sentence/JSON member can exceed the bound. Keep only the original
    # continuous anchor and explicitly report that its boundary is incomplete.
    return base_start, min(base_end, base_start + max_chars), "bounded_fragment", False


def _load_field(session, store, row):
    event = session.get(IntelEvent, row.event_id, populate_existing=True)
    revision = session.get(EventRevision, row.revision_id, populate_existing=True)
    document = session.get(RawDocument, row.raw_document_id, populate_existing=True)
    if not (
        event
        and revision
        and document
        and not event.withdrawn_at
        and not row.withdrawn
        and row.pool in {"formal", "candidate"}
        and event.revision == row.revision_number == revision.number
        and revision.event_id == event.id
        and revision.disposition == "current"
        and revision.raw_document_id == document.id
        and event.source_id == row.source_id == document.source_id
        and event.external_id == row.external_id
        and document.sha256 == row.sha256
        and document.origin == row.origin
        and row.verification == "source_asserted"
    ):
        raise ValueError("evidence_invalid")
    content = store.read(document.sha256)
    if hashlib.sha256(content).hexdigest() != document.sha256:
        raise ValueError("evidence_invalid")
    value = resolve_pointer(json.loads(content), row.json_pointer)
    text = canonical_field(value)
    if not (0 <= row.start < row.end <= len(text) and text[row.start : row.end] == row.text):
        raise ValueError("evidence_invalid")
    return event, value, text


def source_span(session, store, row, max_chars=MAX_SPAN_CHARS, contains=None):
    """Return a citation with exact source offsets; never alter the index row.

    ``contains`` can anchor a field lookup to a later source phrase. The returned
    ``span_provenance.boundary_complete`` must be shown to the generator: False
    means that no complete intersecting unit met the size/anchor constraints.
    """
    if type(max_chars) is not int or not 8 <= max_chars <= MAX_SPAN_CHARS:
        raise ValueError("invalid_span_limit")
    if contains is not None and (not isinstance(contains, str) or not 1 <= len(contains) <= 120):
        raise ValueError("invalid_span_anchor")
    if not row or not isinstance(row, SearchChunk):
        raise ValueError("evidence_invalid")
    with session.no_autoflush:
        event, value, text = _load_field(session, store, row)
    start, end, kind, complete = _select(text, value, row.start, row.end, max_chars, contains)
    citation = {
        "chunk_id": row.id,
        "event_id": row.event_id,
        "revision_id": row.revision_id,
        "revision": row.revision_number,
        "raw_document_id": row.raw_document_id,
        "json_pointer": row.json_pointer,
        "sha256": row.sha256,
        "field": row.field,
        "start": start,
        "end": end,
        "external_id": row.external_id,
        "source_id": row.source_id,
        "origin": row.origin,
        "title": event.title,
        "source_url": event.source_url,
        "text": text[start:end],
        "span_provenance": {
            "version": SPAN_VERSION,
            "base_chunk_id": row.id,
            "base_start": row.start,
            "base_end": row.end,
            "source_field_sha256": _digest(text),
            "source_field_chars": len(text),
            "serialization": "string-verbatim"
            if isinstance(value, str)
            else "json-sorted-default-v1",
            "offset_unit": "unicode_codepoint",
            "selection_kind": kind,
            "boundary_complete": complete,
            "max_chars": max_chars,
            "contains": contains,
        },
    }
    return citation


def source_context_anchor_offsets(session, store, row, contains=None):
    """Enumerate trusted canonical positions; no raw body is returned.

    Literal occurrences use the same matching rules as selection. Without a
    query, include the base anchor and structural starts for context traversal.
    This is a server-only helper, not a model-authored offset capability.
    """
    if contains is not None and (not isinstance(contains, str) or not 1 <= len(contains) <= 120):
        raise ValueError("invalid_span_anchor")
    if not row or not isinstance(row, SearchChunk):
        raise ValueError("evidence_invalid")
    with session.no_autoflush:
        _, _, text = _load_field(session, store, row)
    if contains is not None:
        return [match.start() for match in re.finditer(re.escape(contains), text, re.IGNORECASE)]
    return sorted({row.start, *(item["start"] for item in context_ranges(text))})


def _context_catalog(row, text):
    field_sha = _digest(text)
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
    identity.update(version=CONTEXT_INDEX_VERSION, source_field_sha256=field_sha)
    source_binding = _digest(
        json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    )
    items = []
    for context in navigation_contexts(text, row.field):
        binding = {**identity, **{key: context[key] for key in ("kind", "start", "end")}}
        context_id = (
            "ctx_"
            + _digest(
                json.dumps(binding, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            )[:24]
        )
        items.append(
            {
                **context,
                "context_id": context_id,
                "field": row.field,
                "event_id": row.event_id,
                "source_binding": source_binding,
            }
        )
    return items, field_sha


def source_context_index(session, store, row, contains=None, after_offset=None, limit=12):
    """Return verified, bounded navigation metadata without quotation bodies."""
    if type(limit) is not int or not 1 <= limit <= 12:
        raise ValueError("invalid_context_index_limit")
    if contains is not None and (not isinstance(contains, str) or not 1 <= len(contains) <= 120):
        raise ValueError("invalid_span_anchor")
    if after_offset is not None and (type(after_offset) is not int or after_offset < 0):
        raise ValueError("source_context_invalid_offset")
    if not row or not isinstance(row, SearchChunk):
        raise ValueError("evidence_invalid")
    with session.no_autoflush:
        _, _, text = _load_field(session, store, row)
    items, _ = _context_catalog(row, text)
    selected = [
        item
        for item in items
        if (after_offset is None or item["start"] >= after_offset)
        and (contains is None or contains.casefold() in item["label"].casefold())
    ]
    return {
        "items": selected[:limit],
        "more_available": len(selected) > limit,
        "next_offset": selected[limit]["start"] if len(selected) > limit else None,
    }


def source_context_spans_by_ids(
    session, store, row, context_ids, after_offset=None, max_chars=MAX_SPAN_CHARS
):
    """Load/parse once for a bounded batch of current, field-bound IDs."""
    if (
        not isinstance(context_ids, list)
        or not 1 <= len(context_ids) <= 4
        or any(not isinstance(value, str) for value in context_ids)
    ):
        raise ValueError("source_context_invalid_id")
    if len(set(context_ids)) != len(context_ids):
        raise ValueError("duplicate_context_ids")
    if after_offset is not None and len(context_ids) != 1:
        raise ValueError("source_context_multiple_ids_with_offset")
    if type(max_chars) is not int or not 8 <= max_chars <= MAX_SPAN_CHARS:
        raise ValueError("invalid_span_limit")
    if after_offset is not None and (type(after_offset) is not int or after_offset < 0):
        raise ValueError("source_context_invalid_offset")
    if not row or not isinstance(row, SearchChunk):
        raise ValueError("evidence_invalid")
    with session.no_autoflush:
        event, value, text = _load_field(session, store, row)
    items, field_sha = _context_catalog(row, text)
    catalog = {item["context_id"]: item for item in items}
    if any(context_id not in catalog for context_id in context_ids):
        raise ValueError("source_context_invalid_id")
    citations = []
    for context_id in context_ids:
        context = catalog[context_id]
        start = context["start"] if after_offset is None else after_offset
        if not context["start"] <= start < context["end"]:
            raise ValueError("source_context_invalid_offset")
        end = min(context["end"], start + max_chars)
        complete = start == context["start"] and end == context["end"]
        citations.append(
            {
                "chunk_id": row.id,
                "event_id": row.event_id,
                "revision_id": row.revision_id,
                "revision": row.revision_number,
                "raw_document_id": row.raw_document_id,
                "json_pointer": row.json_pointer,
                "sha256": row.sha256,
                "field": row.field,
                "start": start,
                "end": end,
                "external_id": row.external_id,
                "source_id": row.source_id,
                "origin": row.origin,
                "title": event.title,
                "source_url": event.source_url,
                "text": text[start:end],
                "span_provenance": {
                    "version": CONTEXT_ID_SPAN_VERSION,
                    "base_chunk_id": row.id,
                    "base_start": row.start,
                    "base_end": row.end,
                    "source_field_sha256": field_sha,
                    "source_field_chars": len(text),
                    "serialization": "string-verbatim"
                    if isinstance(value, str)
                    else "json-sorted-default-v1",
                    "offset_unit": "unicode_codepoint",
                    "selection_kind": context["kind"],
                    "boundary_complete": complete,
                    "max_chars": max_chars,
                    "contains": None,
                    "after_offset": after_offset,
                    "context_id": context_id,
                    "context": {
                        "kind": context["kind"],
                        "start": context["start"],
                        "end": context["end"],
                        "complete": complete,
                        "continuation_offset": end if end < context["end"] else None,
                    },
                },
            }
        )
    return citations


def source_context_span(
    session,
    store,
    row,
    max_chars=MAX_SPAN_CHARS,
    contains=None,
    after_offset=None,
    anchor_offset=None,
):
    """Return a structural context page without changing legacy span selection."""
    if not row or not isinstance(row, SearchChunk):
        raise ValueError("evidence_invalid")
    with session.no_autoflush:
        event, value, text = _load_field(session, store, row)
    selected = select_context(
        text,
        base_start=row.start,
        base_end=row.end,
        max_chars=max_chars,
        contains=contains,
        after_offset=after_offset,
        anchor_offset=anchor_offset,
    )
    start, end = selected["start"], selected["end"]
    return {
        "chunk_id": row.id,
        "event_id": row.event_id,
        "revision_id": row.revision_id,
        "revision": row.revision_number,
        "raw_document_id": row.raw_document_id,
        "json_pointer": row.json_pointer,
        "sha256": row.sha256,
        "field": row.field,
        "start": start,
        "end": end,
        "external_id": row.external_id,
        "source_id": row.source_id,
        "origin": row.origin,
        "title": event.title,
        "source_url": event.source_url,
        "text": text[start:end],
        "span_provenance": {
            "version": CONTEXT_SPAN_VERSION,
            "base_chunk_id": row.id,
            "base_start": row.start,
            "base_end": row.end,
            "source_field_sha256": _digest(text),
            "source_field_chars": len(text),
            "serialization": "string-verbatim"
            if isinstance(value, str)
            else "json-sorted-default-v1",
            "offset_unit": "unicode_codepoint",
            "selection_kind": selected["selection_kind"],
            "boundary_complete": selected["context_complete"],
            "max_chars": max_chars,
            "contains": contains,
            "after_offset": after_offset,
            "anchor_offset": anchor_offset,
            "context": {
                "kind": selected["selection_kind"],
                "start": selected["context_start"],
                "end": selected["context_end"],
                "complete": selected["context_complete"],
                "continuation_offset": selected["continuation_offset"],
            },
        },
    }


def verify_source_context_span(session, store, citation):
    """Recompute structure, lookup occurrence and exact page from current raw."""
    try:
        provenance = citation["span_provenance"]
        if not isinstance(provenance, dict) or provenance.get("version") not in {
            CONTEXT_SPAN_VERSION,
            CONTEXT_ID_SPAN_VERSION,
        }:
            return False
        context = provenance.get("context")
        if (
            not isinstance(context, dict)
            or type(context.get("complete")) is not bool
            or any(type(context.get(key)) is not int for key in ("start", "end"))
            or (
                context.get("continuation_offset") is not None
                and type(context["continuation_offset"]) is not int
            )
        ):
            return False
        if (
            type(provenance.get("boundary_complete")) is not bool
            or any(type(citation.get(key)) is not int for key in ("start", "end", "revision"))
            or any(
                type(provenance.get(key)) is not int
                for key in ("base_start", "base_end", "source_field_chars", "max_chars")
            )
        ):
            return False
        with session.no_autoflush:
            row = session.get(SearchChunk, citation["chunk_id"], populate_existing=True)
        if provenance["version"] == CONTEXT_ID_SPAN_VERSION:
            expected = source_context_spans_by_ids(
                session,
                store,
                row,
                [provenance["context_id"]],
                max_chars=provenance["max_chars"],
                after_offset=provenance.get("after_offset"),
            )[0]
        else:
            expected = source_context_span(
                session,
                store,
                row,
                max_chars=provenance["max_chars"],
                contains=provenance.get("contains"),
                after_offset=provenance.get("after_offset"),
                anchor_offset=provenance.get("anchor_offset"),
            )
        keys = {
            "chunk_id",
            "event_id",
            "revision_id",
            "revision",
            "raw_document_id",
            "json_pointer",
            "sha256",
            "field",
            "start",
            "end",
            "external_id",
            "source_id",
            "origin",
            "text",
            "span_provenance",
        }
        return all(citation.get(key) == expected[key] for key in keys)
    except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError):
        return False


def verify_source_span(session, store, citation):
    """Check current source identity, literal interval and deterministic provenance."""
    try:
        provenance = citation["span_provenance"]
        if isinstance(provenance, dict) and provenance.get("version") in {
            CONTEXT_SPAN_VERSION,
            CONTEXT_ID_SPAN_VERSION,
        }:
            return verify_source_context_span(session, store, citation)
        if not isinstance(provenance, dict) or provenance.get("version") != SPAN_VERSION:
            return False
        if (
            type(provenance.get("boundary_complete")) is not bool
            or any(type(citation.get(key)) is not int for key in ("start", "end", "revision"))
            or any(
                type(provenance.get(key)) is not int
                for key in ("base_start", "base_end", "source_field_chars", "max_chars")
            )
        ):
            return False
        with session.no_autoflush:
            row = session.get(SearchChunk, citation["chunk_id"], populate_existing=True)
        expected = source_span(
            session,
            store,
            row,
            max_chars=provenance["max_chars"],
            contains=provenance.get("contains"),
        )
        # Ignore presentation additions, but no source identity, offsets, text or
        # provenance may drift. Recomputing also checks the completeness marker.
        keys = {
            "chunk_id",
            "event_id",
            "revision_id",
            "revision",
            "raw_document_id",
            "json_pointer",
            "sha256",
            "field",
            "start",
            "end",
            "external_id",
            "source_id",
            "origin",
            "text",
            "span_provenance",
        }
        return all(citation.get(key) == expected[key] for key in keys)
    except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError):
        return False
