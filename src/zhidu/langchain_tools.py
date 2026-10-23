"""LangChain adapter over the existing source runtime, with sequential execution."""

import json
import threading
from typing import Annotated, Literal

from pydantic import Field, ValidationError, model_validator
from sqlalchemy import select

from zhidu.agent_tools import (
    MAX_CALL_CHARS,
    MAX_OUTPUT_CHARS,
    SCHEMAS,
    AgentToolRuntime,
    EventArgs,
    StrictArgs,
    _citation,
    _verified_row,
    contracts,
)
from zhidu.grounded_answer import evidence_id as source_handle
from zhidu.grounded_answer import quote_candidates
from zhidu.models import EventAlias, IntelEvent, SearchChunk
from zhidu.semantic import active_chunks


class ReadFieldsArgs(StrictArgs):
    event_id: str = Field(min_length=36, max_length=36)
    fields: list[str] = Field(min_length=1, max_length=4)
    contains: str | None = Field(default=None, min_length=1, max_length=120)
    after_offset: int | None = Field(default=None, ge=0)
    context: Literal["excerpt", "section", "outline"] = "excerpt"
    context_ids: list[Annotated[str, Field(min_length=8, max_length=160)]] = Field(
        default_factory=list, max_length=4
    )
    limit: int = Field(default=3, ge=1, le=4)

    @model_validator(mode="after")
    def context_id_scope(self):
        if self.context_ids:
            if self.context != "section" or len(self.fields) != 1 or self.contains is not None:
                raise ValueError("context_ids_require_one_section_field_without_contains")
            if len(set(self.context_ids)) != len(self.context_ids):
                raise ValueError("duplicate_context_ids")
            if len(self.context_ids) > 1 and self.after_offset is not None:
                raise ValueError("context_cursor_requires_single_id")
        return self


class ToolOutputLimit(RuntimeError):
    """Stop before another model call when even a failure packet cannot fit."""


class SourceRuntime(AgentToolRuntime):
    schemas = {**SCHEMAS, "read_fields": ReadFieldsArgs}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # New role backends share the configured per-answer deadline; the
        # legacy runtime's 15-second default must not shorten only baselines.
        requested = kwargs.get("deadline_seconds", self.settings.agent_deadline_seconds)
        self.deadline_seconds = min(float(requested), self.settings.agent_deadline_seconds, 60)

    def execute_for_packing(self, name, arguments):
        # Only ToolSession uses this path. Its final public packet owns the
        # character budget; large local provenance/private artifacts must not
        # reject a smaller packet before whole-span packing can run.
        return self._execute(name, arguments, defer_output_budget=True)

    def _event_details(self, args):
        rows = active_chunks(
            self.session, pool=self.pool, origin=self.origin, event_id=args.event_id
        )
        if not rows:
            raise LookupError("event not found in current scope")
        priority = {
            "title": 0,
            "packages": 1,
            "required_action": 2,
            "description": 4,
            "references": 5,
        }
        rows = sorted(
            rows,
            key=lambda r: (
                3 if r.field.startswith("nvd_affected_data_") else priority.get(r.field, 6),
                r.start,
                r.id,
            ),
        )
        fields = []
        for row in rows[:4]:
            _verified_row(self.session, self.store, row)
            fields.append(
                {
                    "citation": _citation(row),
                    "text": row.text[:700],
                    "text_truncated": len(row.text) > 700,
                }
            )
        return {
            "event_id": args.event_id,
            "fields": fields,
            "more_available": len(rows) > 4,
            "fields_are_excerpts": True,
            "source_asserted_not_independent_verified": True,
            "read_fields_hint": "Use read_fields with packages, description, title, references; contains locates later sections.",
        }

    def _read_fields(self, args):
        rows = active_chunks(
            self.session, pool=self.pool, origin=self.origin, event_id=args.event_id
        )
        available_fields = sorted({row.field for row in rows})
        missing_fields = [field for field in args.fields if field not in available_fields]
        rows = [r for r in rows if r.field in args.fields]
        if missing_fields and not rows:
            value = {
                "event_id": args.event_id,
                "fields": [],
                "matching_chunks": 0,
                "more_available": False,
                "available_fields": available_fields,
                "missing_requested_fields": missing_fields,
                "fields_are_excerpts": True,
                "source_asserted_not_independent_verified": True,
            }
            if args.context == "outline":
                value.update(
                    context_index=[], context_mode="outline", next_offsets={}, navigation_only=True
                )
            return value
        if args.context == "outline":
            value = self._read_outline_fields(args, rows, available_fields, missing_fields)
            value["available_fields"] = available_fields
            return value
        if args.context_ids:
            value = self._read_context_ids(args, rows)
            value["available_fields"] = available_fields
            return value
        if args.context == "section":
            value = self._read_context_fields(args, rows, available_fields, missing_fields)
            value["available_fields"] = available_fields
            return value
        if args.contains:
            rows = [r for r in rows if args.contains.casefold() in r.text.casefold()]
        if args.after_offset is not None:
            rows = [r for r in rows if r.end > args.after_offset]
        rows.sort(key=lambda r: (args.fields.index(r.field), r.start))
        if not rows:
            raise LookupError("no matching current field excerpt")
        fields = []
        first, remainder, seen = [], [], set()
        for row in rows:
            (remainder if row.field in seen else first).append(row)
            seen.add(row.field)
        for row in (first + remainder)[: args.limit]:
            _verified_row(self.session, self.store, row)
            fields.append({"citation": _citation(row), "text": row.text, "text_truncated": False})
        value = {
            "event_id": args.event_id,
            "fields": fields,
            "matching_chunks": len(rows),
            "more_available": len(rows) > len(fields),
            "next_offsets": {
                field: max(
                    item["citation"]["end"] for item in fields if item["citation"]["field"] == field
                )
                for field in {item["citation"]["field"] for item in fields}
            },
            "fields_are_excerpts": True,
            "source_asserted_not_independent_verified": True,
            "available_fields": available_fields,
        }
        if missing_fields:
            value.update(available_fields=available_fields, missing_requested_fields=missing_fields)
        return value

    def _read_outline_fields(self, args, rows, available_fields, missing_fields):
        from zhidu.source_spans import source_context_index

        rows.sort(key=lambda row: (args.fields.index(row.field), row.start, row.id))
        first_rows, seen_fields = [], set()
        for row in rows:
            if row.field not in seen_fields:
                first_rows.append(row)
            seen_fields.add(row.field)
        first_groups, other_groups, source_offsets = [], [], {}
        source_more = False
        for row in first_rows:
            _verified_row(self.session, self.store, row)
            index = source_context_index(
                self.session,
                self.store,
                row,
                contains=args.contains,
                after_offset=args.after_offset,
                limit=12,
            )
            source_more = source_more or index["more_available"]
            source_offsets[row.field] = index["next_offset"]
            groups = {}
            for entry in index["items"]:
                groups.setdefault(entry["start"], []).append(entry)
            for position, group in enumerate(groups.values()):
                (first_groups if position == 0 else other_groups).append(group)
        entries, lookahead = [], {}
        for group in first_groups + other_groups:
            field = group[0]["field"]
            if field in lookahead or len(entries) + len(group) > 12:
                lookahead.setdefault(field, group[0]["start"])
                continue
            entries.extend(group)
        if not entries:
            raise LookupError("no matching current source context label")
        value = {
            "event_id": args.event_id,
            "fields": [],
            "context_mode": "outline",
            "context_index": entries,
            "navigation_only": True,
            "source_index_is_not_evidence": True,
            "more_available": source_more or bool(lookahead),
            "next_offsets": {
                field: lookahead.get(field, source_offsets.get(field))
                if lookahead.get(field, source_offsets.get(field)) is not None
                else max(entry["end"] for entry in entries if entry["field"] == field)
                for field in {entry["field"] for entry in entries}
            },
            "source_asserted_not_independent_verified": True,
        }
        if missing_fields:
            value.update(available_fields=available_fields, missing_requested_fields=missing_fields)
        return value

    def _read_context_ids(self, args, rows):
        from zhidu.source_spans import source_context_spans_by_ids

        if not rows:
            raise LookupError("no matching current source field")
        row = min(rows, key=lambda row: (row.start, row.id))
        _verified_row(self.session, self.store, row)
        citations = source_context_spans_by_ids(
            self.session, self.store, row, args.context_ids, after_offset=args.after_offset
        )
        fields = [
            {
                "citation": {key: value for key, value in citation.items() if key != "text"},
                "text": citation["text"],
                "text_truncated": not citation["span_provenance"]["context"]["complete"],
            }
            for citation in citations
        ]
        pending = [
            citation["span_provenance"]["context_id"]
            for citation in citations
            if citation["span_provenance"]["context"]["continuation_offset"] is not None
        ]
        return {
            "event_id": args.event_id,
            "fields": fields,
            "context_mode": "section",
            "selected_context_ids": args.context_ids,
            "pending_context_ids": pending,
            "omitted_context_ids": [],
            "more_available": bool(pending),
            "next_offsets": {args.fields[0]: citations[0]["end"]}
            if len(args.context_ids) == 1
            else {},
            "fields_are_excerpts": True,
            "source_asserted_not_independent_verified": True,
        }

    def _read_context_fields(self, args, rows, available_fields, missing_fields):
        from zhidu.source_spans import source_context_anchor_offsets, source_context_span

        # Keep the original contains anchor when continuing its context. The
        # quoted next page can legitimately start beyond the anchor chunk.
        # Enumerate verified canonical occurrences, including several contexts
        # inside one chunk, rather than inferring matches from chunk excerpts.
        rows.sort(key=lambda row: (args.fields.index(row.field), row.start, row.id))
        first_rows, seen_fields = [], set()
        for row in rows:
            if row.field not in seen_fields:
                first_rows.append(row)
            seen_fields.add(row.field)
        candidates, contexts = [], set()
        invalid_offset = False
        for row in first_rows:
            _verified_row(self.session, self.store, row)
            anchors = source_context_anchor_offsets(self.session, self.store, row, args.contains)
            for anchor_offset in anchors:
                try:
                    citation = source_context_span(
                        self.session,
                        self.store,
                        row,
                        contains=args.contains,
                        anchor_offset=anchor_offset,
                    )
                    context = citation["span_provenance"]["context"]
                    if args.after_offset is not None:
                        if args.after_offset >= context["end"]:
                            invalid_offset = True
                            continue
                        # A completed context may be followed by a heading or
                        # blank gap. Advance only to the verified next context
                        # start; never select a page outside that context.
                        page_start = max(args.after_offset, context["start"])
                        citation = source_context_span(
                            self.session,
                            self.store,
                            row,
                            contains=args.contains,
                            after_offset=page_start,
                            anchor_offset=anchor_offset,
                        )
                except ValueError as exc:
                    if str(exc) == "source_context_anchor_not_found":
                        continue
                    if str(exc) == "source_context_invalid_offset":
                        invalid_offset = True
                        continue
                    raise
                context = citation["span_provenance"]["context"]
                key = (citation["field"], context["start"], context["end"])
                if key in contexts:
                    continue
                contexts.add(key)
                candidates.append(citation)
        first, remainder, seen_fields = [], [], set()
        for citation in candidates:
            (remainder if citation["field"] in seen_fields else first).append(citation)
            seen_fields.add(citation["field"])
        fields, pending_fields = [], set()
        exhausted, lookahead = False, {}
        for citation in first + remainder:
            context = citation["span_provenance"]["context"]
            if citation["field"] in pending_fields:
                continue
            if len(fields) >= args.limit:
                exhausted = True
                lookahead.setdefault(citation["field"], context["start"])
                continue
            fields.append(
                {
                    "citation": {key: value for key, value in citation.items() if key != "text"},
                    "text": citation["text"],
                    "text_truncated": not context["complete"],
                }
            )
            if context["continuation_offset"] is not None:
                pending_fields.add(citation["field"])
        if not fields:
            if invalid_offset:
                raise ValueError("source_context_invalid_offset")
            raise LookupError("no matching current source context")
        continuation = any(
            item["citation"]["span_provenance"]["context"]["continuation_offset"] is not None
            for item in fields
        )
        value = {
            "event_id": args.event_id,
            "fields": fields,
            "context_mode": "section",
            "matching_chunks": len(rows),
            "more_available": exhausted or continuation,
            "next_offsets": {
                field: max(
                    item["citation"]["span_provenance"]["context"]["continuation_offset"]
                    or lookahead.get(field, item["citation"]["end"])
                    for item in fields
                    if item["citation"]["field"] == field
                )
                for field in {item["citation"]["field"] for item in fields}
            },
            "fields_are_excerpts": True,
            "source_asserted_not_independent_verified": True,
        }
        if missing_fields:
            value.update(available_fields=available_fields, missing_requested_fields=missing_fields)
        return value


def public_tool_content(result):
    """Keep citation semantics in model observations; audit metadata stays local."""
    if result.get("status") != "completed" or not isinstance(result.get("result"), dict):
        return result
    content = {**result, "result": dict(result["result"])}
    citation_keys = (
        "chunk_id",
        "event_id",
        "source_id",
        "external_id",
        "field",
        "revision_id",
        "json_pointer",
        "sha256",
        "start",
        "end",
    )
    for key in ("items", "fields"):
        if key not in content["result"]:
            continue
        items = []
        for item in content["result"][key]:
            if not isinstance(item, dict) or "citation" not in item:
                items.append(item)
                continue
            citation = item["citation"]
            public = {name: citation[name] for name in citation_keys if name in citation}
            if "span_provenance" in citation:
                public["span_provenance"] = {
                    name: citation["span_provenance"][name]
                    for name in ("boundary_complete", "base_start", "base_end", "context_id")
                    if name in citation["span_provenance"]
                }
                if "context" in citation["span_provenance"]:
                    public["span_provenance"]["context"] = {
                        name: citation["span_provenance"]["context"][name]
                        for name in ("kind", "start", "end", "complete", "continuation_offset")
                        if name in citation["span_provenance"]["context"]
                    }
            items.append({**item, "citation": public})
        content["result"][key] = items
    return content


class ToolSession:
    """Per-request state; framework tool workers cannot share a session concurrently."""

    def __init__(self, runtime, body, selected_asset):
        self.runtime, self.body, self.selected_asset = runtime, body, selected_asset
        self.lock = threading.RLock()
        self.events = {body.event_id} if body.event_id else set()
        self.cves, self.evidence = set(), {}
        self.results, self.rejections = [], []
        self.attempted_calls = 0
        self.constraints = []
        self.recovery = None
        self.seen_calls = set()
        self.missing_queries = []
        self.no_progress_calls = 0
        self.call_context = threading.local()
        # Navigation metadata is paid tool output, never evidence. Six bounded
        # outline calls can publish at most 72 IDs during one request.
        self.context_index = {}
        # Observed local index fields are navigation, not source facts. A
        # complete catalog is saved only after its paid response is emitted.
        self.field_catalog = {}

    def snapshot(self):
        return {
            "events": sorted(self.events),
            "cves": sorted(self.cves),
            "evidence": self.evidence,
            "results": self.results,
            "rejections": self.rejections,
            "constraints": self.constraints,
            "attempted_calls": self.attempted_calls,
            "steps": self.runtime.steps,
            "output_chars": self.runtime.output_chars,
            "seen_calls": sorted(self.seen_calls),
            "missing_queries": self.missing_queries,
            "no_progress_calls": self.no_progress_calls,
            "context_index": self.context_index,
            "field_catalog": self.field_catalog,
        }

    def restore(self, snapshot):
        self.events, self.cves = set(snapshot["events"]), set(snapshot["cves"])
        for field in ("evidence", "results", "rejections", "constraints", "attempted_calls"):
            setattr(self, field, snapshot[field])
        self.runtime.steps, self.runtime.output_chars = snapshot["steps"], snapshot["output_chars"]
        self.seen_calls = set(snapshot.get("seen_calls", []))
        self.missing_queries = snapshot.get("missing_queries", [])
        self.no_progress_calls = snapshot.get("no_progress_calls", 0)
        self.context_index = dict(list(snapshot.get("context_index", {}).items())[:72])
        self.field_catalog = {
            event_id: list(fields) for event_id, fields in snapshot.get("field_catalog", {}).items()
        }

    @staticmethod
    def _id_read_status(value, requested_ids, retained):
        returned = {item["citation"]["span_provenance"]["context_id"]: item for item in retained}
        omitted = [context_id for context_id in requested_ids if context_id not in returned]
        pending = [
            context_id
            for context_id in requested_ids
            if context_id not in returned
            or returned[context_id]["citation"]["span_provenance"]["context"]["continuation_offset"]
            is not None
        ]
        value.update(
            omitted_context_ids=omitted, pending_context_ids=pending, more_available=bool(pending)
        )

    def _pack_context_index(self, result, previous_output):
        """Publish whole tied-start groups; discarded navigation grants no IDs."""
        value = result["result"]
        original = list(value["context_index"])
        runtime_offsets = dict(value.get("next_offsets", {}))
        original_more = value.get("more_available", False)
        groups = {}
        for entry in original:
            groups.setdefault((entry["field"], entry["start"]), []).append(entry)
        accepted, blocked_fields = [], set()

        def assign(entries):
            retained_ids = {entry["context_id"] for entry in entries}
            offsets = {}
            for field in {entry["field"] for entry in entries}:
                omitted = [
                    entry["start"]
                    for entry in original
                    if entry["field"] == field and entry["context_id"] not in retained_ids
                ]
                offsets[field] = (
                    min(omitted)
                    if omitted
                    else runtime_offsets.get(
                        field, max(entry["end"] for entry in entries if entry["field"] == field)
                    )
                )
            value.update(
                context_index=entries,
                next_offsets=offsets,
                whole_index_entries_omitted_by_budget=len(original) - len(entries),
                more_available=original_more or len(entries) < len(original),
            )

        for (field, _), group in groups.items():
            if field in blocked_fields:
                continue
            assign(accepted + group)
            chars = len(
                json.dumps(public_tool_content(result), ensure_ascii=False, separators=(",", ":"))
            )
            if chars > min(MAX_CALL_CHARS, self.runtime.max_output_chars - previous_output) - 100:
                blocked_fields.add(field)
                continue
            accepted.extend(group)
        assign(accepted)

    def invoke(self, name, arguments, *, _failure_override=None, _diagnostics=None):
        with self.lock:
            identity = getattr(self.call_context, "identity", None)
            if self.recovery and identity is not None:
                cached = self.recovery.tool_reply(name, arguments, identity)
                if cached:
                    if not cached[0] and cached[1].get("error") == "model_output_budget_exceeded":
                        raise ToolOutputLimit("agent_output_budget_exceeded")
                    return cached
            previous_output = self.runtime.output_chars
            previous_step_count = len(self.runtime.steps)
            previous_evidence = dict(self.evidence)
            previous_constraints = len(self.constraints)
            previous_events, previous_cves = set(self.events), set(self.cves)
            previous_context_index = dict(self.context_index)
            previous_field_catalog = dict(self.field_catalog)
            self.attempted_calls += 1
            args = dict(arguments)
            rejection = None
            key = json.dumps([name, args], sort_keys=True, ensure_ascii=False)
            if self.attempted_calls > self.runtime.max_calls:
                rejection = "call_budget_exceeded"
            elif _failure_override:
                rejection = _failure_override
            elif name == "retrieve":
                if self.body.event_id:
                    args["event_id"] = self.body.event_id
                elif args.get("event_id") and args["event_id"] not in self.events:
                    rejection = "target_not_in_current_retrieval"
            elif name in {"event_details", "read_fields", "asset_exposure"}:
                if args.get("event_id") not in self.events:
                    rejection = "target_not_in_current_retrieval"
                if name == "asset_exposure":
                    if not self.selected_asset:
                        rejection = "explicit_asset_required"
                    args["asset_id"] = self.selected_asset
            elif name == "verify_evidence" and args.get("chunk_id") not in {
                c["chunk_id"] for c in self.evidence.values()
            }:
                rejection = "target_not_in_current_retrieval"
            elif name == "compare_sources":
                if self.body.event_id or args.get("identifier", "").upper() not in self.cves:
                    rejection = "target_not_in_current_retrieval"
            if rejection is None and key in self.seen_calls:
                rejection = "duplicate_tool_request"
            if rejection is None and name == "read_fields" and args.get("context_ids"):
                try:
                    id_args = ReadFieldsArgs.model_validate(args)
                except ValidationError:
                    pass  # The runtime records the normal invalid-arguments receipt.
                else:
                    if any(
                        context_id not in self.context_index
                        or self.context_index[context_id].get("event_id") != id_args.event_id
                        or self.context_index[context_id].get("field") != id_args.fields[0]
                        for context_id in id_args.context_ids
                    ):
                        rejection = "context_id_not_in_current_navigation"
            if (
                rejection is None
                and name == "read_fields"
                and isinstance(args.get("contains"), str)
            ):
                needle = args["contains"].casefold()
                fields = args.get("fields", [])
                if any(
                    old[0] == args.get("event_id")
                    and old[1] == fields
                    and old[2] in needle
                    and (args.get("after_offset") or 0) >= (old[3] if len(old) > 3 else 0)
                    and args.get("context", "excerpt") == (old[4] if len(old) > 4 else "excerpt")
                    for old in self.missing_queries
                ):
                    rejection = "known_missing_field_query"
                question = self.body.question.casefold()
                package_known = any(
                    c["event_id"] == args.get("event_id")
                    and c["field"] == "packages"
                    and (
                        '"first_patched_version": "' in c["text"]
                        or '"patched_versions": "' in c["text"]
                    )
                    for c in self.evidence.values()
                )
                if (
                    needle in {"patch", "patches"}
                    and package_known
                    and any(
                        term in question for term in ("修复字段", "修复版本", "patched version")
                    )
                    and not any(
                        term in question
                        for term in (
                            "修复建议",
                            "补丁正文",
                            "修复实现",
                            "修复措施",
                            "覆盖",
                            "patch implementation",
                            "patches section",
                            "patch cover",
                        )
                    )
                ):
                    rejection = "optional_patch_lookup_not_required"
            self.seen_calls.add(key)
            if rejection:
                result = {"status": "failed", "tool": name, "error": rejection}
                if _diagnostics and rejection == "invalid_arguments":
                    result["diagnostics"] = _diagnostics
                self.rejections.append({"tool": name, "reason": rejection})
            else:
                result = self.runtime.execute_for_packing(name, args)
            self.results.append(result)
            if (
                name == "read_fields"
                and result.get("error") == "not_found"
                and isinstance(args.get("contains"), str)
            ):
                missing = [
                    args.get("event_id"),
                    args.get("fields", []),
                    args["contains"].casefold(),
                    args.get("after_offset") or 0,
                ]
                if args.get("context", "excerpt") != "excerpt":
                    missing.append(args["context"])
                self.missing_queries.append(missing)
            if result["status"] == "completed":
                value = result["result"]
                items = value.get("items", []) if name == "retrieve" else value.get("fields", [])
                runtime_offsets = dict(value.get("next_offsets", {}))
                if name == "read_fields" and args.get("context") == "outline":
                    self._pack_context_index(result, previous_output)
                for item in items:
                    from zhidu.source_spans import source_span

                    row = self.runtime.session.get(SearchChunk, item["citation"]["chunk_id"])
                    if name == "read_fields" and args.get("context", "excerpt") == "section":
                        from zhidu.source_spans import verify_source_context_span

                        c = {**item["citation"], "text": item["text"]}
                        if not verify_source_context_span(
                            self.runtime.session, self.runtime.store, c
                        ):
                            raise ValueError("evidence_invalid")
                    else:
                        c = source_span(
                            self.runtime.session,
                            self.runtime.store,
                            row,
                            contains=args.get("contains") if name == "read_fields" else None,
                        )
                    event = self.runtime.session.get(IntelEvent, c["event_id"])
                    c.update(title=event.title, source_url=event.source_url)
                    complete = (
                        c["span_provenance"]
                        .get("context", {})
                        .get("complete", c["span_provenance"]["boundary_complete"])
                    )
                    item.update(
                        citation={k: v for k, v in c.items() if k != "text"},
                        text=c["text"],
                        text_truncated=not complete,
                    )
                    evidence_id = source_handle(c)
                    self.evidence[evidence_id] = c
                    self.events.add(c["event_id"])
                    aliases = self.runtime.session.scalars(
                        select(EventAlias.value).where(EventAlias.event_id == c["event_id"])
                    ).all()
                    self.cves.update(a.upper() for a in aliases if a.upper().startswith("CVE-"))
                    # Model selects handles; the server owns the verified source span.
                    item["evidence_id"] = evidence_id
                    item["quote_policy"] = "server_fills_verified_span"
                # Pack whole spans before exposing them. Expanded paragraphs
                # and provenance must not make a five-hit retrieval lose all
                # evidence to the single-response budget.
                accepted, blocked_fields = [], set()
                for item in items:
                    field_key = (item["citation"]["event_id"], item["citation"]["field"])
                    value["items" if name == "retrieve" else "fields"] = accepted + [item]
                    if name == "read_fields" and args.get("context_ids"):
                        self._id_read_status(value, args["context_ids"], accepted + [item])
                    trial_chars = len(
                        json.dumps(
                            public_tool_content(result), ensure_ascii=False, separators=(",", ":")
                        )
                    )
                    if (
                        field_key in blocked_fields
                        or trial_chars
                        > min(MAX_CALL_CHARS, self.runtime.max_output_chars - previous_output) - 100
                    ):
                        blocked_fields.add(field_key)
                        if item["evidence_id"] in previous_evidence:
                            self.evidence[item["evidence_id"]] = previous_evidence[
                                item["evidence_id"]
                            ]
                        else:
                            self.evidence.pop(item["evidence_id"], None)
                        continue
                    accepted.append(item)
                if items:
                    value["items" if name == "retrieve" else "fields"] = accepted
                    value["whole_spans_omitted_by_budget"] = len(items) - len(accepted)
                    if len(accepted) < len(items):
                        value["more_available"] = True
                    allowed_events = previous_events | {
                        c["event_id"] for c in self.evidence.values()
                    }
                    self.events.intersection_update(allowed_events)
                    retained_aliases = self.runtime.session.scalars(
                        select(EventAlias.value).where(EventAlias.event_id.in_(allowed_events))
                    ).all()
                    self.cves = previous_cves | {
                        alias.upper()
                        for alias in retained_aliases
                        if alias.upper().startswith("CVE-")
                    }
                    if name == "read_fields":
                        offsets = {}
                        for field in {item["citation"]["field"] for item in accepted}:
                            retained = [
                                item for item in accepted if item["citation"]["field"] == field
                            ]
                            if "context" not in retained[0]["citation"]["span_provenance"]:
                                offsets[field] = max(
                                    item["citation"]["span_provenance"]["base_end"]
                                    for item in retained
                                )
                                continue
                            continuation = [
                                item["citation"]["span_provenance"]["context"][
                                    "continuation_offset"
                                ]
                                for item in retained
                                if item["citation"]["span_provenance"]["context"][
                                    "continuation_offset"
                                ]
                                is not None
                            ]
                            omitted = [
                                item["citation"]["span_provenance"]["context"]["start"]
                                for item in items
                                if item["citation"]["field"] == field and item not in accepted
                            ]
                            offsets[field] = (
                                min(continuation)
                                if continuation
                                else min(omitted)
                                if omitted
                                else runtime_offsets.get(
                                    field, max(item["citation"]["end"] for item in retained)
                                )
                            )
                        value["next_offsets"] = offsets
                        if args.get("context_ids"):
                            self._id_read_status(value, args["context_ids"], accepted)
                            if len(args["context_ids"]) > 1:
                                value["next_offsets"] = {}
                if name == "compare_sources" and any(
                    r.get("status") in {"variation", "conflict"} for r in value.get("items", [])
                ):
                    self.constraints.append(
                        {
                            "code": "source_comparison_unresolved",
                            "rule": "保留各来源声明与差异，不能自动选定正确来源。",
                        }
                    )
            content = public_tool_content(result)
            if name == "asset_exposure" and result["status"] == "completed":
                content = {
                    "status": "completed",
                    "tool": name,
                    "result": {
                        "available_locally": True,
                        "note": "资产条件结果仅在本地展示；不能据公告断言资产已验证或安全。",
                    },
                }
                self.constraints.append(
                    {"code": "private_asset_local_only", "rule": content["result"]["note"]}
                )
            model_text = json.dumps(content, ensure_ascii=False, separators=(",", ":"))
            if len(model_text) > MAX_CALL_CHARS or previous_output + len(model_text) > min(
                MAX_OUTPUT_CHARS, self.runtime.max_output_chars
            ):
                self.evidence = previous_evidence
                self.events, self.cves = previous_events, previous_cves
                self.constraints = self.constraints[:previous_constraints]
                result = {"status": "failed", "tool": name, "error": "model_output_budget_exceeded"}
                self.results[-1] = result
                model_text = json.dumps(result)
                if len(self.runtime.steps) > previous_step_count:
                    self.runtime.steps[-1].update(status="failed", error=result["error"])
            cannot_emit = (
                previous_output + len(model_text) > self.runtime.max_output_chars
                or len(model_text) > MAX_CALL_CHARS
            )
            if cannot_emit:
                # Failed packets use the same hard budget as successful ones.
                # Preserve the local receipt, but emit no oversized tool text
                # and stop this graph (also on a later checkpoint replay).
                model_text = ""
            if result["status"] == "completed" and name == "read_fields":
                for entry in result["result"].get("context_index", []):
                    if entry["context_id"] in self.context_index or len(self.context_index) < 72:
                        self.context_index[entry["context_id"]] = dict(entry)
                if model_text and "available_fields" in result["result"]:
                    self.field_catalog[result["result"]["event_id"]] = list(
                        result["result"]["available_fields"]
                    )
            self.runtime.output_chars = previous_output + len(model_text)
            if len(self.runtime.steps) > previous_step_count:
                self.runtime.steps[-1]["result_chars"] = len(model_text)
            progress = (
                any(
                    previous_evidence.get(handle) != citation
                    for handle, citation in self.evidence.items()
                )
                or self.context_index != previous_context_index
                or self.field_catalog != previous_field_catalog
                or len(self.constraints) > previous_constraints
            )
            self.no_progress_calls = 0 if progress else self.no_progress_calls + 1
            if self.recovery:
                self.recovery.save_tool(
                    name, arguments, model_text, result, self.snapshot(), identity
                )
            if cannot_emit:
                raise ToolOutputLimit("agent_output_budget_exceeded")
            return model_text, result

    @staticmethod
    def quotes(citation):
        return quote_candidates(citation["text"])

    def tools(self):
        from langchain_core.tools import StructuredTool

        descriptions = contracts()["tools"]
        schemas = {**SCHEMAS, "read_fields": ReadFieldsArgs}
        schemas["asset_exposure"] = EventArgs  # Asset scope comes exclusively from the server.
        available = [name for name in schemas if name != "asset_exposure" or self.selected_asset]
        result = []
        for name in available:

            def execute(_name=name, **arguments):
                return self.invoke(_name, arguments)

            description = descriptions.get(name, {}).get("description") or (
                "Read selected normalized fields of a discovered event: packages, description, title, references, "
                "or an exact nvd_affected_data_* field name. Pass fields as a JSON array, not a string. "
                "Use contains to locate later sections "
                "such as Patches or Impact, or pass next_offsets[field] as after_offset to page that field. "
                "Use context='section' for an intact introductory condition list or guidance section. "
                "Its continuation_offset pages the same context even when the keyword appears only in its introduction. "
                "Use context='outline' to inspect up to 12 source headings/list introductions without reading their bodies; "
                "it consumes one tool call and returns navigation IDs, not evidence. Read selected returned context_ids "
                "with context='section', one field and at most four distinct IDs; omit contains. All selected IDs are read "
                "regardless of the legacy limit. Pass after_offset only with a single ID, using that span's continuation_offset. "
                "Check pending_context_ids/omitted_context_ids for unfinished reads. "
                "Each successful read returns available_fields for this event's current local index; "
                "a field missing from that catalog does not prove the original source lacks the fact. "
                "One chunk per requested field is returned before additional chunks. "
                "Excerpts are current verified source text, not full documents."
            )

            def invalid_arguments(exc, _name=name):
                errors = [
                    {"field": list(e["loc"]), "type": e["type"]}
                    for e in exc.errors(include_input=False, include_url=False)[:4]
                ]
                cache_args = {"errors": exc.errors(include_input=True, include_url=False)}
                return self.invoke(
                    _name, cache_args, _failure_override="invalid_arguments", _diagnostics=errors
                )[0]

            result.append(
                StructuredTool.from_function(
                    execute,
                    name=name,
                    description=description,
                    args_schema=schemas[name],
                    response_format="content_and_artifact",
                    handle_validation_error=invalid_arguments,
                )
            )
        return result
