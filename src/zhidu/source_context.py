"""Deterministic Markdown structure intervals, never semantic completeness.

All ranges and pages are slices of the original Unicode string. Fence contents
are data and cannot introduce headings or list items. A structure larger than
the page bound stays one interval and is read in consecutive pages.
"""

import re

VERSION = "source-context-span-v1"
MAX_CONTEXT_CHARS = 1200
_FENCE = re.compile(r"^[ \t]*(`{3,}|~{3,})")
_HEADING = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+|$)")
_SETEXT = re.compile(r"^ {0,3}(=+|-+)[ \t]*$")
_ITEM = re.compile(r"^([ \t]*)(?:[-+*]|[0-9]{1,9}[.)])(?:[ \t]+|$)")


def _lines(text):
    lines, offset, fence, group = [], 0, None, 0
    for raw in text.splitlines(keepends=True):
        body = raw.rstrip("\r\n")
        marker = _FENCE.match(body)
        code_group = None
        if fence:
            code_group = group
            if re.fullmatch(
                r"[ \t]*" + re.escape(fence[0]) + "{" + str(fence[1]) + r",}[ \t]*", body
            ):
                fence = None
        elif marker:
            fence = (marker.group(1)[0], len(marker.group(1)))
            group += 1
            code_group = group
        heading = _HEADING.match(body) if code_group is None else None
        item = _ITEM.match(body) if code_group is None else None
        lines.append(
            {
                "start": offset,
                "end": offset + len(raw),
                "body": body,
                "blank": not body.strip(),
                "code": code_group,
                "heading": len(heading.group(1)) if heading else None,
                "heading_tail": False,
                "item": len(item.group(1).expandtabs(4)) if item else None,
                "indent": len(body[: len(body) - len(body.lstrip(" \t"))].expandtabs(4)),
            }
        )
        offset += len(raw)
    # Setext headings belong to their preceding ordinary text line.
    for index in range(1, len(lines)):
        underline, previous = lines[index], lines[index - 1]
        match = _SETEXT.match(underline["body"]) if underline["code"] is None else None
        if (
            match
            and previous["code"] is None
            and not previous["blank"]
            and previous["item"] is None
            and not previous["heading"]
        ):
            previous["heading"] = 1 if match.group(1)[0] == "=" else 2
            underline["heading_tail"] = True
    return lines


def context_ranges(text):
    """Return structural intervals; overlapping sections intentionally coexist.

    Lists include the immediately preceding prose paragraph as an intro,
    continuation lines and internal blank lines. Sections end at the next
    heading of equal or higher rank. The field is a fallback interval.
    """
    if not isinstance(text, str) or not text:
        raise ValueError("invalid_source_context_text")
    lines = _lines(text)
    return _context_ranges(text, lines)


def _context_ranges(text, lines):
    ranges = []
    headings = [line for line in lines if line["heading"]]
    # Same equal/higher heading boundary as v1, without quadratic list slices.
    open_sections = []
    for heading in headings:
        while open_sections and open_sections[-1][0] >= heading["heading"]:
            ranges[open_sections.pop()[1]]["end"] = heading["start"]
        open_sections.append((heading["heading"], len(ranges)))
        ranges.append({"start": heading["start"], "end": len(text), "kind": "section"})
    index = 0
    while index < len(lines):
        first = lines[index]
        if first["item"] is None:
            index += 1
            continue
        indent, last, cursor, blank, code_groups = first["item"], index, index + 1, False, set()
        while cursor < len(lines):
            line = lines[cursor]
            if line["heading"] and line["indent"] <= indent:
                break
            if line["code"] is not None:
                if line["code"] not in code_groups and blank and line["indent"] <= indent:
                    break
                code_groups.add(line["code"])
                last, blank = cursor, False
            elif line["blank"]:
                blank = True
            elif line["item"] is not None:
                if line["item"] < indent:
                    break
                last, blank = cursor, False
            elif line["indent"] > indent or not blank:
                # Markdown permits lazy continuation before a blank line.
                last, blank = cursor, False
            else:
                break
            cursor += 1
        intro = index - 1
        while intro >= 0 and lines[intro]["blank"] and lines[intro]["code"] is None:
            intro -= 1
        start = first["start"]
        if (
            intro >= 0
            and not lines[intro]["heading"]
            and not lines[intro]["heading_tail"]
            and lines[intro]["item"] is None
            and lines[intro]["code"] is None
        ):
            while intro > 0:
                previous = lines[intro - 1]
                if (
                    previous["blank"]
                    or previous["heading"]
                    or previous["heading_tail"]
                    or previous["item"] is not None
                    or previous["code"] is not None
                ):
                    break
                intro -= 1
            start = lines[intro]["start"]
        ranges.append({"start": start, "end": lines[last]["end"], "kind": "list_with_intro"})
        index = cursor
    ranges.append({"start": 0, "end": len(text), "kind": "field"})
    return sorted(ranges, key=lambda item: (item["start"], item["end"], item["kind"]))


def navigation_contexts(text, field):
    """Boundable navigation descriptors, not new body evidence.

    Labels contain only a heading line, a list intro line, or the field name.
    At each source start keep the most specific recommended structure, so a
    start-offset cursor can never split a group or repeat half of one.
    """
    if not isinstance(text, str) or not text:
        raise ValueError("invalid_source_context_text")
    lines = _lines(text)
    ranges = _context_ranges(text, lines)
    structured = [item for item in ranges if item["kind"] != "field"]
    eligible = structured or ranges
    line_by_start, heading_labels, heading = {}, {}, None
    for line in lines:
        if line["heading"]:
            heading = line["body"]
        line_by_start[line["start"]] = line
        heading_labels[line["start"]] = heading
    recommended = {}
    rank = {"list_with_intro": 0, "section": 1, "field": 2}
    for item in eligible:
        previous = recommended.get(item["start"])
        if previous and (rank[previous["kind"]], previous["end"] - previous["start"]) <= (
            rank[item["kind"]],
            item["end"] - item["start"],
        ):
            continue
        line = line_by_start[item["start"]]
        if item["kind"] == "field":
            label = field
        elif item["kind"] == "list_with_intro" and line["item"] is not None:
            label = heading_labels[item["start"]] or field
        else:
            label = line["body"]
        recommended[item["start"]] = {**item, "label": label[:120]}
    return [recommended[start] for start in sorted(recommended)]


def select_context(
    text,
    *,
    base_start=0,
    base_end=None,
    max_chars=MAX_CONTEXT_CHARS,
    contains=None,
    after_offset=None,
    anchor_offset=None,
):
    """Locate a stable context and return one contiguous bounded page.

    Repeated literal anchors prefer an occurrence intersecting the base chunk,
    then the nearest occurrence, then the earliest. Paging never changes that
    occurrence. Unknown anchors and offsets are explicit lookup failures.
    """
    if type(max_chars) is not int or not 8 <= max_chars <= MAX_CONTEXT_CHARS:
        raise ValueError("invalid_span_limit")
    if contains is not None and (not isinstance(contains, str) or not 1 <= len(contains) <= 120):
        raise ValueError("invalid_span_anchor")
    if after_offset is not None and (type(after_offset) is not int or after_offset < 0):
        raise ValueError("source_context_invalid_offset")
    ranges = context_ranges(text)
    base_end = len(text) if base_end is None else base_end
    if (
        type(base_start) is not int
        or type(base_end) is not int
        or not 0 <= base_start < base_end <= len(text)
    ):
        raise ValueError("invalid_source_context_base")
    if anchor_offset is not None and (
        type(anchor_offset) is not int or not 0 <= anchor_offset < len(text)
    ):
        raise ValueError("source_context_invalid_anchor_offset")
    if contains:
        matches = list(re.finditer(re.escape(contains), text, re.IGNORECASE))
        if not matches:
            raise ValueError("source_context_anchor_not_found")

        def priority(match):
            overlap = min(match.end(), base_end) > max(match.start(), base_start)
            distance = max(base_start - match.end(), match.start() - base_end, 0)
            return not overlap, distance, match.start()

        if anchor_offset is not None:
            match = next((match for match in matches if match.start() == anchor_offset), None)
            if match is None:
                raise ValueError("source_context_invalid_anchor_offset")
        else:
            match = min(matches, key=priority)
        anchor_start, anchor_end = match.span()
    else:
        anchor_start = base_start if anchor_offset is None else anchor_offset
        anchor_end = anchor_start + 1
    eligible = [
        item for item in ranges if item["start"] <= anchor_start and anchor_end <= item["end"]
    ]
    rank = {"list_with_intro": 0, "section": 1, "field": 2}
    context = min(
        eligible, key=lambda item: (rank[item["kind"]], item["end"] - item["start"], item["start"])
    )
    start = context["start"] if after_offset is None else after_offset
    if not context["start"] <= start < context["end"]:
        raise ValueError("source_context_invalid_offset")
    end = min(context["end"], start + max_chars)
    return {
        "start": start,
        "end": end,
        "context_start": context["start"],
        "context_end": context["end"],
        "context_complete": start == context["start"] and end == context["end"],
        "continuation_offset": end if end < context["end"] else None,
        "selection_kind": context["kind"],
        "contains_matched": contains is not None,
    }
