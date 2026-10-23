"""Read-only, bounded source tools for a future model-controlled planner.

This module makes no model call and never writes to the database. A tool result
is evidence or a comparison of source assertions, not an independent finding.
"""

import json
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select

from zhidu.evaluation import verify_hit
from zhidu.evidence import _verify_source_pointer
from zhidu.indexing import chunk_view
from zhidu.models import (
    Asset,
    AssetExposure,
    IntelEvent,
    IntelligenceComparison,
    RawDocument,
    SearchChunk,
)
from zhidu.retrieval import RetrievalHit
from zhidu.semantic import ModelUnavailable, active_chunks, retrieve

TOOL_VERSION = "agent-source-tools-v1"
MAX_CALLS = 6
MAX_OUTPUT_CHARS = 24000
MAX_CALL_CHARS = 9000
MAX_DETAIL_EXCERPT_CHARS = 700
DEADLINE_SECONDS = 15
TOOL_NAMES = ("retrieve", "event_details", "compare_sources", "asset_exposure", "verify_evidence")


class StrictArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RetrieveArgs(StrictArgs):
    query: str = Field(min_length=1, max_length=200)
    mode: Literal["lexical", "hybrid"] = "lexical"
    limit: int = Field(default=3, ge=1, le=5)
    event_id: str | None = Field(default=None, min_length=36, max_length=36)


class EventArgs(StrictArgs):
    event_id: str = Field(min_length=36, max_length=36)


class CompareArgs(StrictArgs):
    identifier: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$", max_length=50)


class AssetArgs(StrictArgs):
    asset_id: str = Field(min_length=36, max_length=36)
    event_id: str = Field(min_length=36, max_length=36)


class VerifyArgs(StrictArgs):
    chunk_id: str = Field(min_length=24, max_length=64)


SCHEMAS = {
    "retrieve": RetrieveArgs,
    "event_details": EventArgs,
    "compare_sources": CompareArgs,
    "asset_exposure": AssetArgs,
    "verify_evidence": VerifyArgs,
}


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: Literal[
        "retrieve", "event_details", "compare_sources", "asset_exposure", "verify_evidence"
    ]
    arguments: dict


class PreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    pool: Literal["formal", "candidate"] = "formal"
    origin: Literal["live", "replay"] = "live"
    calls: list[ToolCall] = Field(min_length=1, max_length=MAX_CALLS)


def contracts():
    return {
        "version": TOOL_VERSION,
        "tools": {
            name: {
                "description": {
                    "retrieve": "Find current, cited source snippets; lexical or local hybrid only.",
                    "event_details": "Read current source fields for an explicit event ID.",
                    "compare_sources": "Inspect active observations for an explicit CVE; never adjudicate.",
                    "asset_exposure": "Read bounded exposure records for explicit asset AND event IDs.",
                    "verify_evidence": "Recheck current chunk against raw bytes, hash and JSON pointer.",
                }[name],
                "parameters": model.model_json_schema(),
            }
            for name, model in SCHEMAS.items()
        },
        "limits": {
            "max_calls": MAX_CALLS,
            "deadline_seconds": DEADLINE_SECONDS,
            "max_call_chars": MAX_CALL_CHARS,
            "max_output_chars": MAX_OUTPUT_CHARS,
        },
        "policy": "read_only; no shell, POC execution, network collection, model call or automatic conflict resolution",
    }


def _citation(row):
    return {
        "chunk_id": row.id,
        "event_id": row.event_id,
        "revision_id": row.revision_id,
        "revision": row.revision_number,
        "raw_document_id": row.raw_document_id,
        "json_pointer": row.json_pointer,
        "sha256": row.sha256,
        "field": row.field,
        "start": row.start,
        "end": row.end,
        "external_id": row.external_id,
        "source_id": row.source_id,
        "origin": row.origin,
    }


def _verified_row(session, store, row):
    hit = RetrievalHit(**chunk_view(row).model_dump(), score=0, matched_terms=[])
    if not verify_hit(session, store, hit):
        raise ValueError("evidence_invalid")


class AgentToolRuntime:
    """One user-request scope. Reuse this object for every proposed model tool call."""

    schemas = SCHEMAS

    def __init__(
        self,
        session,
        store,
        settings,
        encoder,
        *,
        pool="formal",
        origin="live",
        max_calls=MAX_CALLS,
        deadline_seconds=DEADLINE_SECONDS,
        clock=time.monotonic,
    ):
        if pool not in {"formal", "candidate"} or origin not in {"live", "replay"}:
            raise ValueError("invalid source scope")
        self.session, self.store, self.settings, self.encoder = session, store, settings, encoder
        self.pool, self.origin = pool, origin
        self.max_calls = min(max_calls, MAX_CALLS)
        self.deadline_seconds = min(deadline_seconds, DEADLINE_SECONDS)
        self.clock, self.start = clock, clock()
        self.steps = []
        self.output_chars = 0
        self.max_output_chars = min(settings.agent_max_output_chars, MAX_OUTPUT_CHARS)

    def remaining(self):
        return max(0.0, self.deadline_seconds - (self.clock() - self.start))

    def execute(self, name, arguments):
        return self._execute(name, arguments)

    def _execute(self, name, arguments, *, defer_output_budget=False):
        started = self.clock()
        step = {"tool": name, "status": "failed", "error": None, "elapsed_ms": 0.0}
        if len(self.steps) >= self.max_calls:
            return {"status": "failed", "error": "call_budget_exceeded", "tool": name}
        self.steps.append(step)
        try:
            if self.remaining() <= 0:
                raise TimeoutError("deadline_exceeded")
            if name not in self.schemas:
                raise LookupError("tool_not_allowed")
            args = self.schemas[name].model_validate(arguments)
            step["input"] = args.model_dump()
            result = getattr(self, "_" + name)(args)
            if self.remaining() <= 0:
                raise TimeoutError("deadline_exceeded")
            length = len(json.dumps(result, ensure_ascii=False, default=str))
            if not defer_output_budget and (
                length > MAX_CALL_CHARS or self.output_chars + length > self.max_output_chars
            ):
                raise OverflowError("output_budget_exceeded")
            if not defer_output_budget:
                self.output_chars += length
            step.update(status="completed", error=None, result_chars=length)
            return {"status": "completed", "tool": name, "result": result}
        except ValidationError:
            reason = "invalid_arguments"
        except LookupError as exc:
            reason = str(exc) if str(exc) == "tool_not_allowed" else "not_found"
        except ModelUnavailable:
            reason = "model_unavailable"
        except TimeoutError:
            reason = "deadline_exceeded"
        except OverflowError:
            reason = "output_budget_exceeded"
        except ValueError as exc:
            reason = str(exc) if str(exc) == "evidence_invalid" else "invalid_arguments"
        except Exception:
            reason = "tool_unavailable"
        finally:
            step["elapsed_ms"] = round((self.clock() - started) * 1000, 3)
        step["error"] = reason
        return {"status": "failed", "tool": name, "error": reason}

    # Exceptions are mapped to small codes; raw upstream details never enter the trace.
    def _retrieve(self, args):
        hits, meta = retrieve(
            self.session,
            args.query,
            args.mode,
            self.settings,
            self.encoder,
            pool=self.pool,
            origin=self.origin,
            event_id=args.event_id,
            # An unscoped identifier query must not spend every result slot on
            # different fields of one document, hiding other matching sources.
            limit=args.limit if args.event_id else min(50, args.limit * 10),
            timeout=self.remaining(),
            query_rewrite=True,
            relevance_gate=True,
        )
        if not args.event_id:
            distinct, repeated, seen = [], [], set()
            for hit in hits:
                if hit.citation.event_id in seen:
                    repeated.append(hit)
                else:
                    seen.add(hit.citation.event_id)
                    distinct.append(hit)
            hits = distinct + repeated
        selected = []
        for hit in hits[: args.limit]:
            row = self.session.get(SearchChunk, hit.chunk_id)
            _verified_row(self.session, self.store, row)
            selected.append(
                {
                    "citation": _citation(row),
                    "title": row.title,
                    "text": row.text[:750],
                    "text_truncated": len(row.text) > 750,
                    "rank_score_not_confidence": hit.score,
                }
            )
        return {
            "items": selected,
            "mode": args.mode,
            "scope": {"pool": self.pool, "origin": self.origin},
            "retrieval": meta,
            "independent_verification": False,
        }

    def _event_details(self, args):
        rows = active_chunks(
            self.session, pool=self.pool, origin=self.origin, event_id=args.event_id
        )
        if not rows:
            raise LookupError("event not found in current scope")
        event = self.session.get(IntelEvent, args.event_id)
        ordered = []
        for field in ("title", "packages", "required_action"):
            ordered.extend(r for r in rows if r.field == field)
        ordered.extend(
            sorted(
                (r for r in rows if r.field.startswith("nvd_affected_data_")),
                key=lambda r: ("_version_" not in r.field, r.field, r.start),
            )[:8]
        )
        ordered.extend(r for r in rows if r.field == "description")
        ordered.extend(r for r in rows if r.field == "references")
        fields, seen = [], set()
        for row in ordered:
            if row.id in seen or len(fields) >= 8:
                continue
            seen.add(row.id)
            _verified_row(self.session, self.store, row)
            fields.append(
                {
                    "citation": _citation(row),
                    "text": row.text[:MAX_DETAIL_EXCERPT_CHARS],
                    "text_truncated": len(row.text) > MAX_DETAIL_EXCERPT_CHARS,
                }
            )
        return {
            "event_id": event.id,
            "source_id": event.source_id,
            "external_id": event.external_id,
            "source_url": event.source_url,
            "revision": event.revision,
            "fields": fields,
            "fields_are_excerpts": True,
            "source_asserted_not_independent_verified": True,
        }

    def _compare_sources(self, args):
        allowed = {
            r.event_id for r in active_chunks(self.session, pool=self.pool, origin=self.origin)
        }
        rows = self.session.scalars(
            select(IntelligenceComparison)
            .where(
                IntelligenceComparison.identifier == args.identifier,
                IntelligenceComparison.is_active.is_(True),
            )
            .order_by(IntelligenceComparison.field)
            .limit(5)
        ).all()
        items = []
        for row in rows:
            observations = []
            for o in row.observations[:4]:
                event = self.session.get(IntelEvent, o["event_id"])
                if (
                    not event
                    or event.withdrawn_at
                    or event.id not in allowed
                    or o["revision_id"] != self._current_revision_id(event)
                ):
                    continue
                document = self.session.get(RawDocument, o.get("raw_document_id"))
                if not document:
                    raise ValueError("evidence_invalid")
                try:
                    self.store.read(document.sha256)
                except (OSError, ValueError) as exc:
                    raise ValueError("evidence_invalid") from exc
                verification = _verify_source_pointer(self.store, document, o.get("json_pointer"))
                if verification["status"] == "failed":
                    raise ValueError("evidence_invalid")
                value = json.dumps(o.get("value"), ensure_ascii=False)
                observations.append(
                    {
                        "event_id": event.id,
                        "source_id": o["source_id"],
                        "revision_id": o["revision_id"],
                        "value": value[:1200],
                        "value_truncated": len(value) > 1200,
                        "json_pointer": o.get("json_pointer"),
                        "raw_document_id": o.get("raw_document_id"),
                        "verification": verification["status"],
                        "raw_sha256": document.sha256,
                        "comparison_value_is_derived": True,
                    }
                )
            if len(observations) < 2:
                continue
            items.append(
                {
                    "comparison_id": row.id,
                    "field": row.field,
                    "status": row.status,
                    "annotation_version": row.annotation_version,
                    "review_status": row.review_status,
                    "observations": observations,
                    "automatic_resolution": False,
                }
            )
        return {
            "identifier": args.identifier,
            "items": items,
            "active_only": True,
            "note": "Source observations may differ. A verified pointer confirms raw bytes and location, not the derived comparison value. Missing pointers are not verified; inspect event_details for raw version evidence. No automatic winner.",
        }

    def _asset_exposure(self, args):
        asset = self.session.get(Asset, args.asset_id)
        event = self.session.get(IntelEvent, args.event_id)
        if not asset or not event or event.withdrawn_at:
            raise LookupError("asset or current event not found")
        if not active_chunks(self.session, pool=self.pool, origin=self.origin, event_id=event.id):
            raise LookupError("event not found in current scope")
        rows = self.session.scalars(
            select(AssetExposure)
            .where(AssetExposure.asset_id == args.asset_id, AssetExposure.event_id == args.event_id)
            .limit(8)
        ).all()
        exposures = []
        for row in rows:
            if row.revision_id != self._current_revision_id(event):
                continue
            exposures.append(
                {
                    "status": row.status,
                    "reason": row.reason[:1000],
                    "match_method": row.match_method,
                    "revision_id": row.revision_id,
                    "component_id": row.component_id,
                }
            )
        return {
            "asset_id": asset.id,
            "event_id": event.id,
            "exposures": exposures,
            "no_match_is_not_not_affected": True,
            "private_asset_data": True,
            "interpretation": "Only source-condition matches for this explicitly selected asset; not exploit verification.",
        }

    def _verify_evidence(self, args):
        row = next(
            (
                r
                for r in active_chunks(self.session, pool=self.pool, origin=self.origin)
                if r.id == args.chunk_id
            ),
            None,
        )
        if row is None:
            raise LookupError("current chunk not found")
        _verified_row(self.session, self.store, row)
        return {
            "verified": True,
            "citation": _citation(row),
            "checks": "raw_sha256_json_pointer_span_value",
            "semantic_support_verified": False,
        }

    def _current_revision_id(self, event):
        from zhidu.models import EventRevision

        return self.session.scalar(
            select(EventRevision.id).where(
                EventRevision.event_id == event.id,
                EventRevision.number == event.revision,
                EventRevision.disposition == "current",
            )
        )


def preview_tools(session, store, settings, encoder, request):
    runtime = AgentToolRuntime(
        session, store, settings, encoder, pool=request.pool, origin=request.origin
    )
    results = [runtime.execute(call.name, call.arguments) for call in request.calls]
    return {
        "version": TOOL_VERSION,
        "results": results,
        "steps": runtime.steps,
        "tool_calls": len(runtime.steps),
        "output_chars": runtime.output_chars,
        "policy": {
            "pool": request.pool,
            "origin": request.origin,
            "no_model_call": True,
            "no_network_collection": True,
            "no_database_write": True,
        },
    }
