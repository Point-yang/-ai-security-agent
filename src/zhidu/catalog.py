"""Bounded source metadata collection with exact JSON/NDJSON byte provenance."""

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse

from sqlalchemy import select

from zhidu.ingest import ensure_source
from zhidu.models import CatalogItem, CatalogRevision, EventAlias, IntelEvent, RawDocument
from zhidu.sources import SOURCES, resolve_pointer

CATALOG_SOURCES = {"hf-blog", "nist-ai-rmf", "federal-register-ai", "nuclei-cves"}
MAX_BYTES = 15 * 1024 * 1024
POC_PRODUCTS = re.compile(r"\b(vllm|ollama|langflow|langchain|litellm|huggingface|pytorch)\b", re.I)
AI_SECURITY_BLOG = re.compile(
    r"\b(security|safety|secure|vulnerability|prompt injection|jailbreak|red[ -]?team|"
    r"privacy|source-aware verification|trustworthy|adversarial)\b",
    re.I,
)
AI_POLICY = re.compile(
    r"\b(artificial intelligence|machine learning|large language model|llm|AI safety|AI security)\b",
    re.I,
)
AI_POLICY_CONTEXT = re.compile(
    r"\b(vulnerability|security|risk|safety|accuracy|governance|cyber|accountability|transparency)\b",
    re.I,
)
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CVE_IN_TEXT = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


@dataclass(frozen=True)
class CatalogRecord:
    data: dict
    locator: str


def _date(value):
    if not value:
        return None
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp.astimezone(UTC)


def _fields(source, external, title, description, url, raw, *, published=None, updated=None):
    if not external or not title or not url:
        raise ValueError("catalog metadata requires identifier, title and URL")
    return {
        "source_id": source,
        "external_id": str(external)[:200],
        "kind": {
            "hf-blog": "blog",
            "nist-ai-rmf": "standard_metadata",
            "federal-register-ai": "policy_metadata",
            "nuclei-cves": "poc_template_metadata",
        }[source],
        "title": str(title)[:5000],
        "description": str(description or "")[:50000],
        "source_url": str(url)[:2000],
        "published_at": published,
        "source_updated_at": updated,
        "assertion_scope": "source_metadata_only",
        "payload_executed": False,
        "metadata": raw,
    }


def parse_catalog(source: str, content: bytes) -> list[CatalogRecord]:
    if source not in CATALOG_SOURCES or not content or len(content) > MAX_BYTES:
        raise ValueError("unsupported or oversized catalog response")
    if source == "nuclei-cves":
        records = []
        offset = 0
        for number, line in enumerate(content.splitlines(keepends=True)):
            if number >= 10000 or len(line) > 100000:
                raise ValueError("catalog has too many or oversized lines")
            raw = json.loads(line)
            info = raw.get("Info") or {}
            external, path = raw.get("ID"), raw.get("file_path")
            if (
                isinstance(external, str)
                and CVE.fullmatch(external)
                and isinstance(path, str)
                and re.fullmatch(r"http/cves/\d{4}/CVE-\d{4}-\d{4,}\.yaml", path)
                and POC_PRODUCTS.search(f"{info.get('Name', '')} {info.get('Description', '')}")
            ):
                data = _fields(
                    source,
                    external,
                    info.get("Name"),
                    info.get("Description"),
                    f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{path}",
                    {
                        "file_path": path,
                        "template_severity": info.get("Severity"),
                        "template_info_only": True,
                        "template_executed": False,
                        "publication_date_known": False,
                    },
                )
                records.append(
                    CatalogRecord(
                        data, f"byte:{offset}:{offset + len(line.rstrip(bytes([10, 13])))}"
                    )
                )
            offset += len(line)
        return records

    payload = json.loads(content)
    if source == "hf-blog":
        if not isinstance(payload, dict) or not isinstance(payload.get("allBlogs"), list):
            raise ValueError("invalid Hugging Face blog index")
        records = []
        for index, row in enumerate(payload["allBlogs"][:100]):
            path = row.get("url")
            if (
                not isinstance(path, str)
                or not path.startswith("/blog/")
                or ".." in path
                or not AI_SECURITY_BLOG.search(str(row.get("title") or ""))
            ):
                continue
            data = _fields(
                source,
                row.get("_id"),
                row.get("title"),
                "",
                "https://huggingface.co" + path,
                {"blog_index_only": True, "body_available": False, "slug": row.get("slug")},
                published=_date(row.get("publishedAt")),
                updated=_date(row.get("editedAt") or row.get("publishedAt")),
            )
            records.append(CatalogRecord(data, f"/allBlogs/{index}"))
        return records
    if source == "nist-ai-rmf":
        raw = payload["message"]
        doi = str(raw["DOI"]).lower()
        if doi != "10.6028/nist.ai.100-1" or "National Institute of Standards" not in raw.get(
            "publisher", ""
        ):
            raise ValueError("NIST document identity is not verified")
        date_parts = (raw.get("published") or {}).get("date-parts", [[]])[0]
        publication = datetime(*(date_parts + [1, 1])[:3], tzinfo=UTC) if date_parts else None
        return [
            CatalogRecord(
                _fields(
                    source,
                    doi,
                    raw["title"][0],
                    raw.get("abstract", ""),
                    "https://doi.org/" + doi,
                    {
                        "publisher": raw["publisher"],
                        "metadata_only": True,
                        "publication_precision": {1: "year", 2: "month", 3: "day"}.get(
                            len(date_parts), "unknown"
                        ),
                        "doi_registration_date": raw.get("created", {}).get("date-time"),
                        "full_text_collected": False,
                    },
                    published=publication,
                    updated=_date(raw.get("indexed", {}).get("date-time")),
                ),
                "/message",
            )
        ]
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("invalid Federal Register index")
    records = []
    for index, raw in enumerate(payload["results"][:100]):
        title = str(raw.get("title") or "")
        if not AI_POLICY.search(title) or not AI_POLICY_CONTEXT.search(title):
            continue
        url = raw.get("html_url")
        if not isinstance(url, str) or urlparse(url).netloc != "www.federalregister.gov":
            continue
        number = raw.get("document_number")
        data = _fields(
            source,
            number,
            title,
            raw.get("abstract"),
            url,
            {
                "document_type": raw.get("type"),
                "agencies": [a.get("name") for a in raw.get("agencies", [])],
                "metadata_only": True,
                "legal_status_not_inferred": True,
            },
            published=_date(raw.get("publication_date")),
        )
        records.append(CatalogRecord(data, f"/results/{index}"))
    return records


def resolve_catalog_locator(content: bytes, locator: str):
    if locator.startswith("byte:"):
        _, start, end = locator.split(":")
        return json.loads(content[int(start) : int(end)])
    return resolve_pointer(json.loads(content), locator)


def ingest_catalog(session, store, content, *, source_id, url, fetched_at, origin):
    if source_id not in CATALOG_SOURCES or origin not in {"live", "replay"}:
        raise ValueError("invalid catalog source or origin")
    parsed = parse_catalog(source_id, content)
    ensure_source(session, SOURCES[source_id])
    digest = store.put(content)
    document = session.scalar(
        select(RawDocument).where(
            RawDocument.source_id == source_id,
            RawDocument.url == url,
            RawDocument.sha256 == digest,
            RawDocument.origin == origin,
        )
    )
    if document is None:
        document = RawDocument(
            source_id=source_id,
            url=url,
            sha256=digest,
            media_type="application/x-ndjson" if source_id == "nuclei-cves" else "application/json",
            size_bytes=len(content),
            origin=origin,
            first_fetched_at=fetched_at,
            last_fetched_at=fetched_at,
        )
        session.add(document)
        session.flush()
    else:
        document.last_fetched_at = max(document.last_fetched_at, fetched_at)
    counts = {"created": 0, "updated": 0, "unchanged": 0}
    for row in parsed:
        data = row.data
        # Fetched time is never substituted for an unknown source publication date.
        stable = {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in data.items()}
        fingerprint = hashlib.sha256(
            json.dumps(stable, ensure_ascii=False, sort_keys=True).encode()
        ).hexdigest()
        current = session.scalar(
            select(CatalogItem).where(
                CatalogItem.source_id == source_id, CatalogItem.external_id == data["external_id"]
            )
        )
        if current:
            previous_document = session.get(RawDocument, current.raw_document_id)
            if previous_document.origin == "live" and origin == "replay":
                # A later fixture must never replace the current live lineage.
                counts["unchanged"] += 1
                continue
            if current.fingerprint == fingerprint and previous_document.origin == origin:
                current.last_seen_at = max(current.last_seen_at, fetched_at)
                counts["unchanged"] += 1
                continue
        if current is None:
            current = CatalogItem(
                source_id=source_id,
                external_id=data["external_id"],
                kind=data["kind"],
                title=data["title"],
                description=data["description"],
                source_url=data["source_url"],
                published_at=data["published_at"],
                source_updated_at=data["source_updated_at"],
                first_seen_at=fetched_at,
                last_seen_at=fetched_at,
                raw_document_id=document.id,
                evidence_locator=row.locator,
                normalized=stable,
                fingerprint=fingerprint,
                revision=1,
            )
            session.add(current)
            session.flush()
            counts["created"] += 1
        else:
            current.revision += 1
            counts["updated"] += 1
        for key in (
            "kind",
            "title",
            "description",
            "source_url",
            "published_at",
            "source_updated_at",
        ):
            setattr(current, key, data[key])
        current.raw_document_id = document.id
        current.evidence_locator = row.locator
        current.normalized = stable
        current.fingerprint = fingerprint
        current.last_seen_at = fetched_at
        session.add(
            CatalogRevision(
                item_id=current.id,
                number=current.revision,
                raw_document_id=document.id,
                evidence_locator=row.locator,
                normalized=stable,
                fingerprint=fingerprint,
                collected_at=fetched_at,
            )
        )
    session.flush()
    return {
        "source_id": source_id,
        "raw_document_id": document.id,
        "observed": len(parsed),
        **counts,
        "scope": "source_metadata_only_no_poc_execution",
    }


def catalog_item_view(session, row):
    document = session.get(RawDocument, row.raw_document_id)
    return {
        "id": row.id,
        "source_id": row.source_id,
        "external_id": row.external_id,
        "kind": row.kind,
        "title": row.title,
        "description": row.description,
        "source_url": row.source_url,
        "published_at": row.published_at,
        "source_updated_at": row.source_updated_at,
        "first_seen_at": row.first_seen_at,
        "last_seen_at": row.last_seen_at,
        "revision": row.revision,
        "raw_document_id": document.id,
        "raw_sha256": document.sha256,
        "origin": document.origin,
        "media_type": document.media_type,
        "evidence_locator": row.evidence_locator,
        "metadata": row.normalized["metadata"],
        "source_metadata_only": True,
        "payload_executed": False,
    }


def catalog_associations(session, row):
    """Return exact-identifier event candidates without asserting semantic truth."""
    text = " ".join((row.external_id, row.title, row.description, row.source_url))
    identifiers = sorted({value.upper() for value in CVE_IN_TEXT.findall(text)})
    candidates = []
    seen = set()
    for identifier in identifiers:
        events = session.scalars(
            select(IntelEvent).where(IntelEvent.external_id == identifier)
        ).all()
        alias_event_ids = session.scalars(
            select(EventAlias.event_id).where(EventAlias.value == identifier)
        ).all()
        events.extend(
            session.scalars(select(IntelEvent).where(IntelEvent.id.in_(alias_event_ids))).all()
        )
        for event in events:
            if event.id in seen:
                continue
            seen.add(event.id)
            candidates.append(
                {
                    "catalog_item_id": row.id,
                    "catalog_source_id": row.source_id,
                    "catalog_external_id": row.external_id,
                    "catalog_raw_document_id": row.raw_document_id,
                    "catalog_evidence_locator": row.evidence_locator,
                    "identifier": identifier,
                    "event_id": event.id,
                    "event_source_id": event.source_id,
                    "event_external_id": event.external_id,
                    "event_title": event.title,
                    "event_revision": event.revision,
                    "event_withdrawn": event.withdrawn_at is not None,
                    "match_type": "exact_cve_identifier",
                    "confidence": 1.0,
                    "review_status": "candidate_requires_human_review",
                    "source_metadata_only": True,
                    "does_not_prove_vulnerability": True,
                }
            )
    return {
        "catalog_item_id": row.id,
        "candidates": candidates,
        "identifiers_found": identifiers,
        "association_policy": "Exact CVE strings only; no automatic merge, asset impact, or vulnerability validity claim.",
    }


def audit_catalog(session, store):
    rows = session.execute(
        select(CatalogRevision, CatalogItem, RawDocument)
        .join(CatalogItem, CatalogItem.id == CatalogRevision.item_id)
        .join(RawDocument, RawDocument.id == CatalogRevision.raw_document_id)
    ).all()
    verified = 0
    failures = []
    originals = {}
    for revision, item, document in rows:
        try:
            if document.sha256 not in originals:
                content = store.read(document.sha256)
                if len(content) != document.size_bytes:
                    raise ValueError("source byte count differs")
                originals[document.sha256] = content
            resolved = resolve_catalog_locator(
                originals[document.sha256], revision.evidence_locator
            )
            if item.source_id == "nuclei-cves":
                title = resolved["Info"]["Name"]
            elif item.source_id == "nist-ai-rmf":
                title = resolved["title"][0]
            else:
                title = resolved["title"]
            if revision.normalized["title"] != str(title)[:5000]:
                raise ValueError("title does not resolve to the source record")
            serialized = json.dumps(
                revision.normalized, ensure_ascii=False, sort_keys=True
            ).encode()
            if hashlib.sha256(serialized).hexdigest() != revision.fingerprint:
                raise ValueError("normalized metadata fingerprint differs")
            verified += 1
        except (KeyError, TypeError, ValueError, OSError, IndexError, json.JSONDecodeError) as exc:
            failures.append(
                {"item_id": item.id, "revision": revision.number, "error": type(exc).__name__}
            )
    return {
        "status": "passed" if not failures else "failed",
        "revisions": len(rows),
        "verified": verified,
        "failed": len(failures),
        "raw_documents": len(originals),
        "failure_samples": failures[:20],
        "scope": "source metadata integrity, not payload execution or validity of upstream claims",
    }
