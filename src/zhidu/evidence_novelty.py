"""Compare verified source coordinates, never retrieval IDs or semantic quality.

Callers provide the source-span ledger already checked by ToolSession. This
module does not fetch sources or establish that a quotation entails a claim.
Unknown provenance prevents a confirmed total; known-coordinate deltas remain
available separately for diagnostics.
"""

import re
from collections.abc import Mapping

_SHA = re.compile(r"^[a-f0-9]{64}$")


def _values(evidence):
    return list(evidence.values()) if isinstance(evidence, Mapping) else list(evidence)


def _merge(intervals):
    merged = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _collect(evidence):
    groups, unknown = {}, []
    for index, citation in enumerate(_values(evidence)):
        reason = None
        if not isinstance(citation, Mapping) or not isinstance(
            citation.get("span_provenance"), Mapping
        ):
            reason = "missing_source_span_provenance"
        else:
            provenance = citation["span_provenance"]
            if (
                not _SHA.fullmatch(str(citation.get("sha256", "")))
                or not isinstance(citation.get("json_pointer"), str)
                or not citation["json_pointer"].startswith("/")
                or type(citation.get("revision")) is not int
                or citation["revision"] < 1
                or not isinstance(citation.get("field"), str)
                or not citation["field"]
                or not _SHA.fullmatch(str(provenance.get("source_field_sha256", "")))
                or provenance.get("offset_unit") != "unicode_codepoint"
                or provenance.get("serialization")
                not in {"string-verbatim", "json-sorted-default-v1"}
            ):
                reason = "invalid_canonical_source_identity"
            elif (
                type(citation.get("start")) is not int
                or type(citation.get("end")) is not int
                or type(provenance.get("source_field_chars")) is not int
                or not 0 <= citation["start"] < citation["end"] <= provenance["source_field_chars"]
                or not isinstance(citation.get("text"), str)
                or len(citation["text"]) != citation["end"] - citation["start"]
            ):
                reason = "invalid_canonical_source_interval"
        if reason:
            unknown.append({"index": index, "reason": reason})
            continue
        key = (
            citation["sha256"],
            citation["json_pointer"],
            citation["revision"],
            citation["field"],
            provenance["source_field_sha256"],
        )
        groups.setdefault(key, []).append((citation["start"], citation["end"]))
    return {key: _merge(value) for key, value in groups.items()}, unknown


def _spans(groups):
    return [
        {
            "sha256": key[0],
            "json_pointer": key[1],
            "revision": key[2],
            "field": key[3],
            "source_field_sha256": key[4],
            "start": start,
            "end": end,
        }
        for key, intervals in sorted(groups.items())
        for start, end in intervals
    ]


def _subtract(intervals, covered):
    result = []
    for start, end in intervals:
        cursor = start
        for old_start, old_end in covered:
            if old_end <= cursor:
                continue
            if old_start >= end:
                break
            if cursor < old_start:
                result.append((cursor, min(old_start, end)))
            cursor = max(cursor, old_end)
            if cursor >= end:
                break
        if cursor < end:
            result.append((cursor, end))
    return result


def evidence_novelty(before, after):
    """Return an interval-union delta with explicit unknown-provenance handling.

    A new chunk/evidence ID anchored to the same original coordinates adds zero
    characters. Different offsets measure literal source coverage, even when
    wording repeats; that is explicitly not a semantic or accuracy gain.
    """
    old, unknown_before = _collect(before)
    current, unknown_after = _collect(after)
    added = {key: _subtract(intervals, old.get(key, [])) for key, intervals in current.items()}
    known = sum(end - start for intervals in added.values() for start, end in intervals)
    complete = not unknown_before and not unknown_after
    return {
        "status": "known" if complete else "unknown",
        "new_source_chars": known if complete else None,
        "known_new_source_chars": known,
        "new_source_spans": _spans(added),
        "before_source_spans": _spans(old),
        "after_source_spans": _spans(current),
        "unknown_before": unknown_before,
        "unknown_after": unknown_after,
        "unit": "canonical_source_unicode_codepoint_interval_union",
        "semantic_support_verified": False,
        "quality_gain_proven": False,
    }
