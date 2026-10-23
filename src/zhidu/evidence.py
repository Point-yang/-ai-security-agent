"""Deterministic evidence verification, revision timelines and asset trace chains."""

import hashlib
import json

from sqlalchemy import select

from zhidu.models import (
    Asset,
    AssetComponent,
    AssetExposure,
    EventChange,
    EventRevision,
    IntelEvent,
    RawDocument,
)
from zhidu.sources import resolve_pointer


def _digest(value) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _load_document(store, document: RawDocument) -> tuple[object | None, str | None]:
    try:
        return json.loads(store.read(document.sha256)), None
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return None, type(exc).__name__


def verify_revision_evidence(session, store, revision: EventRevision) -> dict:
    document = session.get(RawDocument, revision.raw_document_id)
    if document is None:
        return {
            "revision_id": revision.id,
            "revision": revision.number,
            "summary": {
                "total": len(revision.evidence),
                "verified": 0,
                "failed": len(revision.evidence),
            },
            "items": [],
            "document_error": "raw_document_missing",
        }
    raw, document_error = _load_document(store, document)
    items = []
    for evidence in revision.evidence:
        pointer = evidence.get("json_pointer")
        status = "verified"
        error = None
        actual = None
        if evidence.get("raw_document_id") != document.id:
            status, error = "failed", "evidence_document_does_not_match_revision"
        elif document_error:
            status, error = "failed", f"raw_document_{document_error}"
        elif not pointer:
            status, error = "failed", "json_pointer_missing"
        else:
            try:
                actual = resolve_pointer(raw, pointer)
            except (KeyError, IndexError, TypeError, ValueError):
                status, error = "failed", "json_pointer_unresolvable"
            else:
                if actual != evidence.get("value"):
                    status, error = "failed", "stored_value_mismatch"
        item = {
            "field": evidence.get("field"),
            "raw_document_id": evidence.get("raw_document_id"),
            "json_pointer": pointer,
            "verification": evidence.get("verification"),
            "status": status,
            "error": error,
            "expected_value_sha256": _digest(evidence.get("value")),
            "resolved_value_sha256": _digest(actual) if status == "verified" else None,
        }
        items.append(item)
    verified = sum(item["status"] == "verified" for item in items)
    return {
        "revision_id": revision.id,
        "revision": revision.number,
        "disposition": revision.disposition,
        "raw_document": {
            "id": document.id,
            "sha256": document.sha256,
            "source_id": document.source_id,
            "url": document.url,
            "origin": document.origin,
            "size_bytes": document.size_bytes,
        },
        "summary": {"total": len(items), "verified": verified, "failed": len(items) - verified},
        "items": items,
        "document_error": document_error,
    }


def _field_changes(before: dict | None, after: dict) -> list[dict]:
    before = before or {}
    changes = []
    for field in sorted(set(before) | set(after)):
        old, new = before.get(field), after.get(field)
        if old == new:
            continue
        changes.append(
            {
                "field": field,
                "before": old,
                "after": new,
                "before_sha256": _digest(old),
                "after_sha256": _digest(new),
            }
        )
    return changes


def event_trace(session, store, event: IntelEvent) -> dict:
    revisions = session.scalars(
        select(EventRevision)
        .where(EventRevision.event_id == event.id)
        .order_by(EventRevision.number)
    ).all()
    previous = None
    timeline = []
    for revision in revisions:
        verification = verify_revision_evidence(session, store, revision)
        timeline.append(
            {
                "revision_id": revision.id,
                "number": revision.number,
                "disposition": revision.disposition,
                "is_effective_current": revision.number == event.revision,
                "source_updated_at": revision.source_updated_at,
                "collected_at": revision.collected_at,
                "raw_document": verification.get("raw_document"),
                "delta_from_previous_observation": _field_changes(previous, revision.normalized),
                "evidence_verification": verification,
            }
        )
        previous = revision.normalized
    audit = session.scalars(
        select(EventChange).where(EventChange.event_id == event.id).order_by(EventChange.sequence)
    ).all()
    verified = sum(item["evidence_verification"]["summary"]["verified"] for item in timeline)
    total = sum(item["evidence_verification"]["summary"]["total"] for item in timeline)
    return {
        "schema_version": "evidence-trace-v1",
        "event": {
            "id": event.id,
            "source_id": event.source_id,
            "external_id": event.external_id,
            "title": event.title,
            "current_revision": event.revision,
        },
        "summary": {
            "revisions": len(timeline),
            "field_evidence_total": total,
            "field_evidence_verified": verified,
            "field_evidence_failed": total - verified,
        },
        "timeline": timeline,
        "audit": [
            {
                "sequence": row.sequence,
                "change_type": row.change_type,
                "occurred_at": row.occurred_at,
                "detail": row.detail,
            }
            for row in audit
        ],
        "note": "Deltas compare observations in arrival order; stale/conflict revisions never become current automatically.",
    }


def audit_all_evidence(session, store) -> dict:
    revisions = session.scalars(
        select(EventRevision).order_by(EventRevision.event_id, EventRevision.number)
    ).all()
    event_ids = set()
    documents = set()
    verified = failed = 0
    failures = []
    dispositions = {}
    for revision in revisions:
        event_ids.add(revision.event_id)
        dispositions[revision.disposition] = dispositions.get(revision.disposition, 0) + 1
        result = verify_revision_evidence(session, store, revision)
        if result.get("raw_document"):
            documents.add(result["raw_document"]["id"])
        verified += result["summary"]["verified"]
        failed += result["summary"]["failed"]
        for item in result["items"]:
            if item["status"] != "verified" and len(failures) < 20:
                failures.append(
                    {
                        "event_id": revision.event_id,
                        "revision_id": revision.id,
                        "revision": revision.number,
                        "field": item["field"],
                        "error": item["error"],
                    }
                )
    return {
        "schema_version": "evidence-audit-v1",
        "status": "passed" if failed == 0 else "failed",
        "events": len(event_ids),
        "revisions": len(revisions),
        "raw_documents": len(documents),
        "field_evidence_total": verified + failed,
        "field_evidence_verified": verified,
        "field_evidence_failed": failed,
        "dispositions": dispositions,
        "failure_samples": failures,
        "scope": "stored raw bytes, SHA-256, JSON Pointer and captured field value equality",
    }


def _verify_source_pointer(store, document: RawDocument, pointer: str | None) -> dict:
    if not pointer:
        return {"json_pointer": pointer, "status": "not_available"}
    raw, error = _load_document(store, document)
    if error:
        return {"json_pointer": pointer, "status": "failed", "error": error}
    try:
        value = resolve_pointer(raw, pointer)
    except (KeyError, IndexError, TypeError, ValueError):
        return {"json_pointer": pointer, "status": "failed", "error": "unresolvable"}
    return {
        "json_pointer": pointer,
        "status": "verified",
        "resolved_value_sha256": _digest(value),
    }


def asset_evidence_graph(session, store, asset: Asset) -> dict:
    rows = session.scalars(
        select(AssetExposure)
        .where(AssetExposure.asset_id == asset.id)
        .order_by(AssetExposure.status, AssetExposure.event_id, AssetExposure.component_id)
    ).all()
    chains = []
    pointer_verified = pointer_total = 0
    revision_verified = revision_total = 0
    for exposure in rows:
        component = session.get(AssetComponent, exposure.component_id)
        event = session.get(IntelEvent, exposure.event_id)
        revision = session.get(EventRevision, exposure.revision_id)
        document = session.get(RawDocument, revision.raw_document_id)
        verification = verify_revision_evidence(session, store, revision)
        assertions = []
        for item in exposure.evidence:
            source = item.get("source") or {}
            result = _verify_source_pointer(store, document, source.get("json_pointer"))
            pointer_total += result["status"] != "not_available"
            pointer_verified += result["status"] == "verified"
            assertions.append(
                {
                    "method": item.get("method"),
                    "status": item.get("status"),
                    "reason": item.get("reason"),
                    "verification": item.get("verification"),
                    "pointer_check": result,
                }
            )
        revision_total += verification["summary"]["total"]
        revision_verified += verification["summary"]["verified"]
        chains.append(
            {
                "exposure_id": exposure.id,
                "status": exposure.status,
                "reason": exposure.reason,
                "match_method": exposure.match_method,
                "component": {
                    "id": component.id,
                    "ecosystem": component.ecosystem,
                    "name": component.name,
                    "version": component.version,
                    "purl": component.purl,
                    "cpe": component.cpe,
                },
                "event": {
                    "id": event.id,
                    "source_id": event.source_id,
                    "external_id": event.external_id,
                    "title": event.title,
                },
                "revision": {
                    "id": revision.id,
                    "number": revision.number,
                    "disposition": revision.disposition,
                    "enrichment_schema_version": exposure.enrichment_schema_version,
                },
                "raw_document": verification["raw_document"],
                "source_assertions": assertions,
                "field_evidence": verification["summary"],
            }
        )
    return {
        "schema_version": "asset-evidence-graph-v1",
        "asset": {
            "id": asset.id,
            "name": asset.name,
            "environment": asset.environment,
            "criticality": asset.criticality,
            "sbom_sha256": asset.sbom_sha256,
            "imported_at": asset.imported_at,
        },
        "summary": {
            "chains": len(chains),
            "source_pointers_total": pointer_total,
            "source_pointers_verified": pointer_verified,
            "field_evidence_total": revision_total,
            "field_evidence_verified": revision_verified,
        },
        "chains": chains,
        "independent_verification": False,
        "note": "The graph verifies evidence integrity and provenance, not exploitability.",
    }
