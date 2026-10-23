"""Pure, replayable scheduling of requests the research model already chose.

Navigation and interval arithmetic guide allocation, never claim support or
question coverage. No tools, IDs, tasks or source text are invented here.
Only schema-validated requests may be narrowed or skipped; tool validation and
the shared execution budget remain the caller's responsibility.
"""

import json
import re
from copy import deepcopy

VERSION = "research-allocation-v1"
_CONTEXT_VERSIONS = {"source-context-span-v1", "source-context-span-v2"}
_CITATION_KEYS = (
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
    "title",
    "source_url",
    "span_provenance",
    "text",
)


def _strings(value):
    return (
        sorted({item for item in value if isinstance(item, str) and item})
        if isinstance(value, list)
        else []
    )


def _message(message):
    if isinstance(message, dict):
        data = message.get("data", message)
        return message.get("type", message.get("role")), data if isinstance(data, dict) else {}
    return getattr(message, "type", None), {
        key: getattr(message, key, None)
        for key in ("content", "artifact", "tool_call_id", "additional_kwargs")
    }


def _artifact(data):
    if isinstance(data.get("artifact"), dict):
        return data["artifact"]
    content = data.get("content")
    if isinstance(content, dict):
        return content
    try:
        parsed = json.loads(content)
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, ValueError):
        return {}


def _context(entry):
    if not isinstance(entry, dict) or any(
        not isinstance(entry.get(key), str) or not entry[key]
        for key in ("context_id", "event_id", "field")
    ):
        return None
    if (
        type(entry.get("start")) is not int
        or type(entry.get("end")) is not int
        or not 0 <= entry["start"] < entry["end"]
    ):
        return None
    source_binding = entry.get("source_binding")
    source_binding = (
        source_binding
        if isinstance(source_binding, str) and re.fullmatch(r"[a-f0-9]{64}", source_binding)
        else None
    )
    return {
        **{
            key: entry.get(key)
            for key in ("context_id", "event_id", "field", "start", "end", "kind")
        },
        "source_binding": source_binding,
        "label": entry.get("label", "")[:120] if isinstance(entry.get("label", ""), str) else "",
    }


def _add_contexts(directory, entries):
    entries = list(entries.values()) if isinstance(entries, dict) else entries
    for entry in entries if isinstance(entries, list) else []:
        normalized = _context(entry)
        if normalized:
            directory[normalized["context_id"]] = normalized


def _catalog(catalog, event_id, value):
    if isinstance(value, list):
        value = {"available_fields": value}
    if not isinstance(event_id, str) or not event_id or not isinstance(value, dict):
        return
    available = value.get("available_fields")
    missing = value.get("missing_requested_fields")
    if not isinstance(available, list) and not isinstance(missing, list):
        return
    existing = catalog.setdefault(
        event_id, {"available_fields": None, "missing_requested_fields": []}
    )
    if isinstance(available, list):
        existing["available_fields"] = _strings(available)
    missing = set(existing["missing_requested_fields"]) | set(_strings(missing))
    if existing["available_fields"] is not None:
        missing -= set(existing["available_fields"])
    existing["missing_requested_fields"] = sorted(missing)


def _add_quote(intervals, citation, text):
    if not isinstance(citation, dict) or not isinstance(text, str) or not text.strip():
        return False
    event_id, field = citation.get("event_id"), citation.get("field")
    start, end = citation.get("start"), citation.get("end")
    if (
        isinstance(event_id, str)
        and event_id
        and isinstance(field, str)
        and field
        and type(start) is int
        and type(end) is int
        and 0 <= start < end
        and end - start == len(text)
    ):
        provenance = citation.get("span_provenance", {})
        provenance = provenance if isinstance(provenance, dict) else {}
        context = provenance.get("context", {})
        context = context if isinstance(context, dict) else {}
        structure = (
            provenance.get("version") in _CONTEXT_VERSIONS or provenance.get("version") is None
        ) and (
            context.get("kind") in {"field", "section", "list_with_intro"}
            and type(context.get("start")) is int
            and type(context.get("end")) is int
            and 0 <= context["start"] <= start < end <= context["end"]
            and type(context.get("complete")) is bool
        )
        intervals.append(
            {
                "event_id": event_id,
                "field": field,
                "start": start,
                "end": end,
                "context_id": provenance.get("context_id"),
                "structure_provenance_observed": bool(structure),
                "context_kind": context.get("kind"),
                "context_start": context.get("start"),
                "context_end": context.get("end"),
            }
        )
    return True


def build_allocation_state(payload, messages):
    """Fold frozen input and prior AI/ToolMessages, without live runtime state.

    ``read_task_ids`` means an assigned request once returned body text. It is
    explicitly neither semantic support nor completion of the assigned task.
    """
    directory, intervals, catalog, read_tasks, assignments, evidence = {}, [], {}, set(), {}, {}
    read_tasks.update(_strings(payload.get("previously_observed_task_ids")))
    _add_contexts(directory, payload.get("context_index", []))
    initial = payload.get("evidence", [])
    initial = (
        list(initial.items())
        if isinstance(initial, dict)
        else [(None, item) for item in initial]
        if isinstance(initial, list)
        else []
    )
    for handle, citation in initial:
        if isinstance(citation, dict):
            _add_quote(intervals, citation, citation.get("text"))
            handle = citation.get("evidence_id") or handle
            if isinstance(handle, str) and isinstance(citation.get("text"), str):
                evidence[handle] = {
                    key: deepcopy(citation[key]) for key in _CITATION_KEYS if key in citation
                }
    initial_catalog = payload.get("field_catalog", {})
    if isinstance(initial_catalog, dict):
        for event_id, value in initial_catalog.items():
            _catalog(catalog, event_id, value)
    elif isinstance(initial_catalog, list):
        for value in initial_catalog:
            if isinstance(value, dict):
                _catalog(catalog, value.get("event_id"), value)
    for message in messages:
        kind, data = _message(message)
        if kind in {"ai", "assistant"}:
            extra = data.get("additional_kwargs") or {}
            admission = extra.get("research_admission", {}) if isinstance(extra, dict) else {}
            for child in admission.get("admitted", []) if isinstance(admission, dict) else []:
                if isinstance(child, dict) and isinstance(child.get("child_id"), str):
                    assignments[child["child_id"]] = {
                        "task_ids": _strings(child.get("task_ids")),
                        "context_task_ids": deepcopy(child.get("context_task_ids")),
                    }
        elif kind == "tool":
            artifact = _artifact(data)
            value = artifact.get("result")
            if artifact.get("status") != "completed" or not isinstance(value, dict):
                continue
            _add_contexts(directory, value.get("context_index", []))
            _catalog(catalog, value.get("event_id"), value)
            assigned = assignments.get(data.get("tool_call_id"), {})
            if not value.get("navigation_only"):
                for name in ("items", "fields"):
                    for item in value.get(name, []) if isinstance(value.get(name), list) else []:
                        if isinstance(item, dict):
                            if _add_quote(intervals, item.get("citation"), item.get("text")):
                                handle = item.get("evidence_id")
                                if isinstance(handle, str) and handle:
                                    citation = {**item["citation"], "text": item["text"]}
                                    evidence[handle] = {
                                        key: deepcopy(citation[key])
                                        for key in _CITATION_KEYS
                                        if key in citation
                                    }
                                mapping = assigned.get("context_task_ids")
                                if isinstance(mapping, dict):
                                    proof = item.get("citation", {}).get("span_provenance", {})
                                    read_tasks.update(
                                        _strings(mapping.get(proof.get("context_id")))
                                    )
                                else:
                                    read_tasks.update(assigned.get("task_ids", []))
    unique_intervals = {
        json.dumps(value, sort_keys=True, ensure_ascii=False): value for value in intervals
    }
    return {
        "version": VERSION,
        "context_index": {key: directory[key] for key in sorted(directory)},
        "evidence": {key: evidence[key] for key in sorted(evidence)},
        "read_intervals": [unique_intervals[key] for key in sorted(unique_intervals)],
        "field_catalog": {key: catalog[key] for key in sorted(catalog)},
        "read_task_ids": sorted(read_tasks),
        "read_tasks_mean_previously_observed_not_covered": True,
    }


def _covered(start, end, intervals):
    cursor = start
    for left, right in sorted(intervals):
        if left > cursor:
            return False
        cursor = max(cursor, right)
        if cursor >= end:
            return True
    return False


def _target(child, state):
    args = child.get("arguments", {})
    ids = args.get("context_ids")
    if child.get("tool") != "read_fields" or not isinstance(ids, list) or not ids:
        return None
    if (
        args.get("context") != "section"
        or not isinstance(args.get("fields"), list)
        or len(args["fields"]) != 1
    ):
        return None
    directory = state.get("context_index", {})
    if any(
        not isinstance(context_id, str)
        or context_id not in directory
        or directory[context_id].get("event_id") != args.get("event_id")
        or directory[context_id].get("field") != args["fields"][0]
        for context_id in ids
    ):
        return None
    return [directory[context_id] for context_id in ids]


def _page(entry, child):
    offset = child["arguments"].get("after_offset")
    start = entry["start"] if offset is None else offset
    if type(start) is not int or not entry["start"] <= start < entry["end"]:
        return None
    return start, min(entry["end"], start + 1200)


def _read_intervals(state, entry, *, structure=False):
    matching = []
    for interval in state.get("read_intervals", []):
        if interval.get("event_id") != entry["event_id"] or interval.get("field") != entry["field"]:
            continue
        # Coordinates alone cannot bind an old revision or a legacy proof to
        # a current issued ID. Preserve the stronger proof acquisition.
        if structure and not (
            interval.get("structure_provenance_observed")
            and interval.get("context_id") == entry["context_id"]
        ):
            continue
        matching.append((interval["start"], interval["end"]))
    return matching


def _context_tasks(child, context_id):
    mapping = child.get("context_task_ids")
    return (
        _strings(mapping.get(context_id))
        if isinstance(mapping, dict)
        else _strings(child.get("task_ids"))
    )


def _retain_ids(child, retained):
    child["arguments"]["context_ids"] = retained
    if isinstance(child.get("context_task_ids"), dict):
        child["context_task_ids"] = {
            context_id: deepcopy(child["context_task_ids"][context_id])
            for context_id in retained
            if context_id in child["context_task_ids"]
        }
        child["task_ids"] = sorted(
            {task for context_id in retained for task in _context_tasks(child, context_id)}
        )


def allocate_research_requests(children, state, *, valid_request_indices=None):
    """Prioritize already-chosen requests and audit every deterministic tradeoff.

    Caller-supplied schema validation gates all parameter changes and skips.
    Without it, children pass through unchanged. Stable child/request identities
    survive reordering and are never reassigned from execution order.
    """
    originals, active, skipped, audit = deepcopy(children), [], [], []
    valid = set(valid_request_indices) if valid_request_indices is not None else set()

    def skip(child, reason):
        skipped.append({**deepcopy(child), "reason": reason, "executed": False})
        audit.append(
            {"action": "skipped", "request_index": child["request_index"], "reason": reason}
        )

    for child in originals:
        if child["request_index"] not in valid:
            active.append(deepcopy(child))
            continue
        work, args = deepcopy(child), child.get("arguments", {})
        # Unknown/cross-scope IDs must reach the existing tool error path.
        targets = _target(child, state)
        if args.get("context_ids") and targets is None:
            active.append(work)
            continue
        if child.get("tool") == "read_fields" and isinstance(args.get("fields"), list):
            catalog = state.get("field_catalog", {}).get(args.get("event_id"), {})
            available, missing = (
                catalog.get("available_fields"),
                set(catalog.get("missing_requested_fields", [])),
            )
            fields = [
                field
                for field in args["fields"]
                if field not in missing and (available is None or field in available)
            ]
            if not fields:
                skip(child, "all_requested_fields_known_missing")
                continue
            if fields != args["fields"]:
                work["arguments"]["fields"] = fields
                audit.append(
                    {
                        "action": "narrowed_fields",
                        "request_index": child["request_index"],
                        "original_fields": args["fields"],
                        "selected_fields": fields,
                        "reason": "explicit_current_field_catalog",
                    }
                )
        if targets and all(_page(entry, work) is not None for entry in targets):
            retained = [
                entry["context_id"]
                for entry in targets
                if not _covered(*_page(entry, work), _read_intervals(state, entry, structure=True))
            ]
            if not retained:
                skip(child, "requested_context_pages_already_observed")
                continue
            if retained != work["arguments"]["context_ids"]:
                audit.append(
                    {
                        "action": "narrowed_context_ids",
                        "request_index": child["request_index"],
                        "original_context_ids": work["arguments"]["context_ids"],
                        "selected_context_ids": retained,
                        "reason": "matching_structure_pages_already_observed",
                    }
                )
                _retain_ids(work, retained)
        active.append(work)

    # A smaller complete structure is a scheduling choice, not a declaration
    # that its containing section has been read or all task facts are answered.
    candidates = []
    for position, child in enumerate(active):
        if (
            child["request_index"] not in valid
            or child["arguments"].get("after_offset") is not None
        ):
            continue
        for ordinal, entry in enumerate(_target(child, state) or []):
            tasks = tuple(_context_tasks(child, entry["context_id"]))
            if tasks:
                candidates.append((position, ordinal, entry, tasks))
    removed = {}
    for position, ordinal, outer, tasks in candidates:
        smaller = [
            (other_position, other_ordinal, inner)
            for other_position, other_ordinal, inner, other_tasks in candidates
            if tasks == other_tasks
            and inner["event_id"] == outer["event_id"]
            and inner["field"] == outer["field"]
            and (
                inner["context_id"] == outer["context_id"]
                or (
                    outer.get("source_binding") is not None
                    and inner.get("source_binding") == outer["source_binding"]
                )
            )
            and outer["start"] <= inner["start"]
            and inner["end"] <= outer["end"]
            and inner["end"] - inner["start"] <= 1200
            and (inner["end"] - inner["start"], other_position, other_ordinal)
            < (outer["end"] - outer["start"], position, ordinal)
        ]
        if smaller:
            other_position, _, inner = min(
                smaller, key=lambda item: (item[2]["end"] - item[2]["start"], item[0], item[1])
            )
            removed.setdefault(position, set()).add(outer["context_id"])
            audit.append(
                {
                    "action": "deferred_containing_context",
                    "request_index": active[position]["request_index"],
                    "context_id": outer["context_id"],
                    "selected_smaller_context_id": inner["context_id"],
                    "retained_request_index": active[other_position]["request_index"],
                    "task_ids": list(tasks),
                    "reason": "model_selected_complete_smaller_structure_for_same_task_mapping",
                    "outer_marked_read": False,
                    "semantic_coverage_inferred": False,
                }
            )
    narrowed = []
    for position, child in enumerate(active):
        if position in removed:
            _retain_ids(
                child,
                [
                    context_id
                    for context_id in child["arguments"]["context_ids"]
                    if context_id not in removed[position]
                ],
            )
            if not child["arguments"]["context_ids"]:
                skip(
                    originals[
                        next(
                            index
                            for index, value in enumerate(originals)
                            if value["request_index"] == child["request_index"]
                        )
                    ],
                    "containing_context_deferred_for_selected_smaller_structure",
                )
                continue
        narrowed.append(child)
    # Reserve invalid children in their original slots so schema failures still
    # use the established attempt/error path rather than becoming free skips.
    pending = [child for child in narrowed if child["request_index"] in valid]
    ordered, scheduled_tasks = [], set(state.get("read_task_ids", []))
    for child in narrowed:
        if child["request_index"] not in valid:
            ordered.append(child)
            continue

        def priority(candidate):
            unseen = set(candidate.get("task_ids", [])) - scheduled_tasks
            targets = _target(candidate, state)
            pages = [_page(entry, candidate) for entry in targets] if targets else []
            overlap = bool(
                targets
                and all(
                    page is not None and _covered(*page, _read_intervals(state, entry))
                    for entry, page in zip(targets, pages, strict=True)
                )
            )
            return -len(unseen), overlap, candidate["request_index"]

        selected = min(pending, key=priority)
        pending.remove(selected)
        ordered.append(selected)
        scheduled_tasks.update(selected.get("task_ids", []))
    previous_order = [child["request_index"] for child in narrowed]
    final_order = [child["request_index"] for child in ordered]
    if final_order != previous_order:
        audit.append(
            {
                "action": "reordered",
                "original_order": previous_order,
                "selected_order": final_order,
                "reason": "different_previously_unobserved_task_mappings_then_literal_overlap",
            }
        )
    return {
        "version": VERSION,
        "ordered": ordered,
        "skipped": skipped,
        "audit": audit,
        "semantic_coverage_inferred": False,
    }
