import hashlib
import json
from datetime import datetime

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from zhidu.classification import classify
from zhidu.indexing import refresh_index_state, sync_event_index
from zhidu.models import (
    AffectedPackage,
    EventAlias,
    EventChange,
    EventRevision,
    EventTriage,
    IntelEvent,
    RawDocument,
    Source,
)
from zhidu.schemas import AdvisoryInput
from zhidu.sources import SOURCES, PreparedRecord, SourceSpec, resolve_pointer
from zhidu.storage import BlobStore

SOURCE_ID = "github-advisories"
MAX_DOCUMENT_BYTES = 15 * 1024 * 1024


def ensure_source(session: Session, spec: SourceSpec = SOURCES[SOURCE_ID]):
    if session.get(Source, spec.id) is None:
        session.add(
            Source(id=spec.id, name=spec.name, category=spec.category, base_url=spec.base_url)
        )
        session.flush()


def normalize(advisory: AdvisoryInput) -> dict:
    return {
        "external_id": advisory.ghsa_id,
        "aliases": sorted({advisory.ghsa_id, *([advisory.cve_id] if advisory.cve_id else [])}),
        "kind": "vulnerability",
        "title": advisory.summary,
        "description": advisory.description or "",
        "severity": advisory.severity,
        "source_url": str(advisory.html_url),
        "published_at": advisory.published_at.isoformat(),
        "source_updated_at": advisory.updated_at.isoformat(),
        "withdrawn_at": advisory.withdrawn_at.isoformat() if advisory.withdrawn_at else None,
        "packages": [
            {
                "ecosystem": v.package.ecosystem,
                "name": v.package.name,
                "vulnerable_range": v.vulnerable_version_range,
                "fixed_version": v.first_patched_version,
            }
            for v in advisory.vulnerabilities
        ],
        "cvss": advisory.cvss_severities or advisory.cvss,
        "cwes": advisory.cwes,
        "references": advisory.references,
        "verification": "source_asserted",
    }


def make_evidence(raw: dict, pointer: str, document_id: str) -> list[dict]:
    mapping = {
        "external_id": "ghsa_id",
        "cve_id": "cve_id",
        "title": "summary",
        "description": "description",
        "severity": "severity",
        "packages": "vulnerabilities",
        "published_at": "published_at",
        "source_updated_at": "updated_at",
        "withdrawn_at": "withdrawn_at",
        "references": "references",
        "cwes": "cwes",
        "cvss": "cvss_severities" if raw.get("cvss_severities") else "cvss",
    }
    return [
        {
            "field": field,
            "raw_document_id": document_id,
            "json_pointer": f"{pointer}/{key}",
            "value": raw[key],
            "verification": "source_asserted",
        }
        for field, key in mapping.items()
        if key in raw
    ]


def ingest_document(
    session: Session,
    store: BlobStore,
    content: bytes,
    url: str,
    fetched_at: datetime,
    origin: str,
    spec: SourceSpec = SOURCES[SOURCE_ID],
    prepared: list[PreparedRecord] | None = None,
) -> dict:
    """Caller commits a whole page or rolls it back; validation precedes all DB writes."""
    if origin not in {"live", "replay"}:
        raise ValueError("origin must be live or replay")
    if len(content) > MAX_DOCUMENT_BYTES:
        raise ValueError("document exceeds 15 MiB limit")
    parsed = json.loads(content)
    if prepared is None:
        from zhidu.sources import prepare

        prepared, _ = prepare(spec.id, content)
    if len(prepared) > 10000:
        raise ValueError("too many records in one document")
    ensure_source(session, spec)
    digest = store.put(content)
    doc = session.scalar(
        select(RawDocument).where(
            RawDocument.source_id == spec.id,
            RawDocument.url == url,
            RawDocument.sha256 == digest,
            RawDocument.origin == origin,
        )
    )
    if doc is None:
        doc = RawDocument(
            source_id=spec.id,
            url=url,
            sha256=digest,
            size_bytes=len(content),
            origin=origin,
            first_fetched_at=fetched_at,
            last_fetched_at=fetched_at,
        )
        session.add(doc)
        session.flush()
    else:
        doc.last_fetched_at = max(doc.last_fetched_at, fetched_at)

    stats = dict(created=0, updated=0, unchanged=0, stale=0, conflict=0)
    for item in prepared:
        pointer = item.pointer
        normalized = item.normalized
        published_at = datetime.fromisoformat(normalized["published_at"])
        updated_at = datetime.fromisoformat(normalized["source_updated_at"])
        withdrawn_at = (
            datetime.fromisoformat(normalized["withdrawn_at"])
            if normalized["withdrawn_at"]
            else None
        )
        evidence = [
            {
                "field": field,
                "raw_document_id": doc.id,
                "json_pointer": path,
                "value": resolve_pointer(parsed, path),
                "verification": "source_asserted",
            }
            for field, path in item.fields.items()
        ]
        fingerprint = hashlib.sha256(
            json.dumps(
                normalized,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        event = session.scalar(
            select(IntelEvent)
            .where(
                IntelEvent.source_id == spec.id,
                IntelEvent.external_id == normalized["external_id"],
            )
            .with_for_update()
        )
        created = event is None
        if created:
            event = IntelEvent(
                source_id=spec.id,
                external_id=normalized["external_id"],
                first_seen_at=fetched_at,
                last_seen_at=fetched_at,
                current_fingerprint=fingerprint,
            )
            # Required fields are populated below before the first flush.
        else:
            event.last_seen_at = max(event.last_seen_at, fetched_at)
            previous = session.scalar(
                select(EventRevision.id).where(
                    EventRevision.event_id == event.id,
                    EventRevision.fingerprint == fingerprint,
                )
            )
            if previous is not None:
                if event.current_fingerprint == fingerprint:
                    from zhidu.enrichment import sync_event_enrichment

                    triage = save_triage(session, event.id, normalized)
                    current = session.scalar(
                        select(EventRevision).where(
                            EventRevision.event_id == event.id,
                            EventRevision.number == event.revision,
                        )
                    )
                    current_doc = session.get(RawDocument, current.raw_document_id)
                    current_raw = json.loads(store.read(current_doc.sha256))
                    sync_event_enrichment(
                        session,
                        event,
                        current,
                        current_doc,
                        resolve_pointer(current_raw, current.record_pointer),
                    )
                    sync_event_index(session, event, current, current_doc, triage)
                stats["unchanged"] += 1
                continue

        disposition = "current"
        action = "created" if created else "updated"
        if not created and updated_at < event.source_updated_at:
            disposition, action = "stale", "stale"
        elif not created and updated_at == event.source_updated_at:
            disposition, action = "conflict", "conflict"

        if disposition == "current":
            for key in ("title", "description", "severity", "source_url", "kind"):
                setattr(event, key, normalized[key])
            event.published_at = published_at
            event.source_updated_at = updated_at
            event.withdrawn_at = withdrawn_at
            event.current_fingerprint = fingerprint
            if not created:
                session.execute(
                    update(EventRevision)
                    .where(
                        EventRevision.event_id == event.id,
                        EventRevision.disposition == "current",
                    )
                    .values(disposition="superseded")
                )
                if event.review_status == "verified":
                    event.review_status = "needs_evidence"
                    event.annotation_version += 1
        if created:
            session.add(event)
            session.flush()

        latest_number = (
            session.scalar(
                select(EventRevision.number)
                .where(
                    EventRevision.event_id == event.id,
                )
                .order_by(EventRevision.number.desc())
                .limit(1)
            )
            or 0
        )
        number = latest_number + 1
        triage = None
        if disposition == "current":
            triage = save_triage(session, event.id, normalized)
            event.revision = number
            session.execute(delete(EventAlias).where(EventAlias.event_id == event.id))
            session.execute(delete(AffectedPackage).where(AffectedPackage.event_id == event.id))
            session.add_all(EventAlias(event_id=event.id, value=a) for a in normalized["aliases"])
            session.add_all(AffectedPackage(event_id=event.id, **p) for p in normalized["packages"])
        revision = EventRevision(
            event_id=event.id,
            number=number,
            raw_document_id=doc.id,
            record_pointer=pointer,
            fingerprint=fingerprint,
            disposition=disposition,
            collected_at=fetched_at,
            source_updated_at=updated_at,
            normalized=normalized,
            evidence=evidence,
        )
        session.add(revision)
        session.add(
            EventChange(
                event_id=event.id,
                change_type=action,
                occurred_at=fetched_at,
                detail={"revision": number, "disposition": disposition, "origin": origin},
            )
        )
        session.flush()
        if disposition == "current":
            from zhidu.enrichment import sync_event_enrichment

            sync_event_enrichment(
                session, event, revision, doc, resolve_pointer(parsed, revision.record_pointer)
            )
            sync_event_index(session, event, revision, doc, triage)
        stats[action] += 1
    from zhidu.asset_matching import scan_assets
    from zhidu.comparisons import sync_comparisons
    from zhidu.enrichment import refresh_enrichment_state

    refresh_index_state(session)
    refresh_enrichment_state(session)
    asset_scan = scan_assets(session)
    comparisons = sync_comparisons(session)
    return {
        **stats,
        "records": len(prepared),
        "raw_document_id": doc.id,
        "asset_scan": asset_scan,
        "comparisons": comparisons,
    }


def save_triage(session, event_id, normalized):
    result = classify(normalized)
    row = session.get(EventTriage, event_id)
    if row is None:
        row = EventTriage(event_id=event_id)
        session.add(row)
    row.label = result["label"]
    row.category = result["category"]
    row.rule_version = result["rule_version"]
    row.matches = result["matches"]
    return row
