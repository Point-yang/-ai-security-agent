"""Deterministic, rebuildable enrichment with source-level provenance."""

import json
import re
from collections import Counter

from sqlalchemy import delete, select

from zhidu.models import (
    EnrichmentState,
    EventEnrichment,
    EventRevision,
    IntelEvent,
    RawDocument,
    now_utc,
)
from zhidu.sources import resolve_pointer

ENRICHMENT_NAME = "structured"
ENRICHMENT_SCHEMA_VERSION = "structured-v5-nvd-authority"
VERSION_CLAUSE = re.compile(r"^(<=|>=|<|>|=|==|~=|\^|~)?\s*([0-9][0-9A-Za-z.+_-]*)$")


def _pointer(base: str, suffix: str) -> str:
    return f"{base}/{suffix}" if base else f"/{suffix}"


def _evidence_pointer(revision, field: str) -> str | None:
    item = next((row for row in revision.evidence if row.get("field") == field), None)
    return item.get("json_pointer") if item else None


def _unique(items: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for item in items:
        key = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if key not in seen:
            result.append(item)
            seen.add(key)
    return result


def parse_version_range(raw: str | None) -> dict:
    """Parse only transparent comparator lists; retain every unsupported expression verbatim."""
    value = (raw or "").strip()
    if not value or value.casefold() == "unknown":
        return {"raw": value or None, "status": "unknown", "clauses": []}
    pieces = [
        piece.strip() for piece in re.split(r",|\s+and\s+", value, flags=re.I) if piece.strip()
    ]
    clauses = []
    for piece in pieces:
        match = VERSION_CLAUSE.fullmatch(piece)
        if not match:
            return {"raw": value, "status": "opaque", "clauses": []}
        clauses.append({"operator": match.group(1) or "=", "version": match.group(2)})
    return {"raw": value, "status": "parsed", "clauses": clauses}


def _cvss_entries(normalized: dict, revision) -> list[dict]:
    raw = normalized.get("cvss")
    base = _evidence_pointer(revision, "cvss")
    if not isinstance(raw, dict):
        return []
    entries = []
    if any(str(key).startswith("cvssMetric") for key in raw):
        for metric_name, values in raw.items():
            if not str(metric_name).startswith("cvssMetric") or not isinstance(values, list):
                continue
            for index, metric in enumerate(values):
                data = metric.get("cvssData", {}) if isinstance(metric, dict) else {}
                vector, score = data.get("vectorString"), data.get("baseScore")
                if not vector or not isinstance(score, int | float) or not 0 <= score <= 10:
                    continue
                entries.append(
                    {
                        "version": str(data.get("version") or "unknown"),
                        "vector": vector,
                        "score": float(score),
                        "severity": str(data.get("baseSeverity") or "unknown").lower(),
                        "source": metric.get("source"),
                        "authority": str(metric.get("type") or "unknown").lower(),
                        "json_pointer": (
                            f"{base}/{metric_name}/{index}/cvssData" if base else None
                        ),
                    }
                )
    elif raw.get("vector_string") or raw.get("vectorString"):
        vector = raw.get("vector_string") or raw.get("vectorString")
        score = raw.get("score") if "score" in raw else raw.get("baseScore")
        if isinstance(score, int | float) and 0 <= score <= 10:
            version_match = re.match(r"CVSS:([0-9.]+)", vector)
            entries.append(
                {
                    "version": version_match.group(1) if version_match else "unknown",
                    "vector": vector,
                    "score": float(score),
                    "severity": str(raw.get("baseSeverity") or "unknown").lower(),
                    "source": None,
                    "authority": "source",
                    "json_pointer": base,
                }
            )
    else:
        for metric_name, data in raw.items():
            if not isinstance(data, dict):
                continue
            vector = data.get("vector_string") or data.get("vectorString")
            score = data.get("score") if "score" in data else data.get("baseScore")
            if not vector or not isinstance(score, int | float) or not 0 <= score <= 10:
                continue
            version_match = re.match(r"CVSS:([0-9.]+)", vector)
            entries.append(
                {
                    "version": version_match.group(1) if version_match else metric_name,
                    "vector": vector,
                    "score": float(score),
                    "severity": "unknown",
                    "source": None,
                    "authority": "source",
                    "json_pointer": f"{base}/{metric_name}" if base else None,
                }
            )
    return _unique(entries)


def _selected_cvss(entries: list[dict]) -> dict | None:
    if not entries:
        return None

    def version(value):
        try:
            return tuple(int(part) for part in value.split("."))
        except ValueError:
            return (0,)

    ordered = sorted(
        entries,
        key=lambda item: (
            item["authority"] == "primary",
            version(item["version"]),
            item["score"],
        ),
        reverse=True,
    )
    return ordered[0]


def _cpe_matches(raw_record: dict, record_pointer: str) -> list[dict]:
    results = []

    def walk(value, path, complex_configuration=False):
        if isinstance(value, dict):
            complex_configuration = (
                complex_configuration
                or bool(value.get("negate"))
                or value.get("operator", "OR") != "OR"
            )
            for key, child in value.items():
                next_path = _pointer(path, str(key).replace("~", "~0").replace("/", "~1"))
                if key == "cpeMatch" and isinstance(child, list):
                    for index, match in enumerate(child):
                        if not isinstance(match, dict) or not match.get("criteria"):
                            continue
                        item = {
                            "criteria": match["criteria"],
                            "vulnerable": bool(match.get("vulnerable")),
                            "match_criteria_id": match.get("matchCriteriaId"),
                            "version_start_including": match.get("versionStartIncluding"),
                            "version_start_excluding": match.get("versionStartExcluding"),
                            "version_end_including": match.get("versionEndIncluding"),
                            "version_end_excluding": match.get("versionEndExcluding"),
                            "json_pointer": _pointer(next_path, str(index)),
                            "requires_configuration_evaluation": complex_configuration,
                        }
                        results.append(item)
                else:
                    walk(child, next_path, complex_configuration)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, _pointer(path, str(index)), complex_configuration)

    if isinstance(raw_record, dict) and "configurations" in raw_record:
        walk(raw_record["configurations"], _pointer(record_pointer, "configurations"))
    return _unique(results)


def _cpe_entity(criteria: str) -> list[dict]:
    parts = criteria.split(":")
    if len(parts) < 6 or parts[:2] != ["cpe", "2.3"]:
        return []
    kind = {"a": "application", "o": "operating_system", "h": "hardware"}.get(parts[2], parts[2])
    return [
        {"type": "vendor", "value": parts[3], "source": "cpe"},
        {"type": "product", "value": parts[4], "source": "cpe", "part": kind},
    ]


def build_enrichment(event, revision, document, raw_record: dict) -> dict:
    normalized = revision.normalized
    entities = []
    for alias in normalized.get("aliases", []):
        upper = alias.upper()
        kind = "cve" if upper.startswith("CVE-") else "ghsa" if upper.startswith("GHSA-") else "doi"
        entities.append({"type": kind, "value": alias, "source": "alias"})

    package_pointer = _evidence_pointer(revision, "packages")
    version_ranges = []
    provenance = [
        {
            "field": item["field"],
            "raw_document_id": document.id,
            "json_pointer": item["json_pointer"],
            "verification": item.get("verification", "source_asserted"),
        }
        for item in revision.evidence
    ]
    for index, package in enumerate(normalized.get("packages", [])):
        identity = {
            "type": "package",
            "ecosystem": str(package.get("ecosystem") or "unknown").lower(),
            "value": str(package.get("name") or "unknown").lower(),
            "source": "package_scope",
        }
        entities.append(identity)
        vulnerable = parse_version_range(package.get("vulnerable_range"))
        fixed = parse_version_range(package.get("fixed_version"))
        version_ranges.append(
            {
                "ecosystem": identity["ecosystem"],
                "package": identity["value"],
                "vulnerable": vulnerable,
                "fixed": fixed,
                "source_kind": "affected_package",
                "json_pointer": _pointer(package_pointer, str(index)) if package_pointer else None,
            }
        )

    vendor_ranges = normalized.get("vendor_patched_ranges", [])
    for index, value in enumerate(vendor_ranges if isinstance(vendor_ranges, list) else []):
        if not value:
            continue
        package = normalized.get("packages", [{}])[index] if normalized.get("packages") else {}
        version_ranges.append(
            {
                "ecosystem": str(package.get("ecosystem") or "unknown").lower(),
                "package": str(package.get("name") or "unknown").lower(),
                "vulnerable": None,
                "fixed": parse_version_range(value),
                "source_kind": "vendor_patched_range",
                "json_pointer": _pointer(
                    revision.record_pointer, f"vulnerabilities/{index}/patched_versions"
                ),
            }
        )

    # NVD's current 2.0 record can carry CNA statements under
    # affected[].affectedData[]. Preserve the publisher's exact version object,
    # status, defaultStatus and pointer; versionType semantics are not parsed or
    # converted into a package vulnerability interval here.
    if event.source_id == "nvd" and isinstance(raw_record, dict):
        for authority_index, authority in enumerate(raw_record.get("affected", [])):
            if not isinstance(authority, dict):
                continue
            publisher = authority.get("source")
            if publisher is not None:
                provenance.append(
                    {
                        "field": "nvd_affected_data_fact",
                        "index_field": f"nvd_affected_data_{authority_index}_source",
                        "authority": publisher,
                        "value": publisher,
                        "raw_document_id": document.id,
                        "json_pointer": _pointer(
                            revision.record_pointer, f"affected/{authority_index}/source"
                        ),
                        "verification": "source_asserted",
                    }
                )
            products = authority.get("affectedData", [])
            if not isinstance(products, list):
                continue
            for product_index, product in enumerate(products):
                if not isinstance(product, dict):
                    continue
                product_pointer = _pointer(
                    revision.record_pointer,
                    f"affected/{authority_index}/affectedData/{product_index}",
                )
                identity = {
                    key: product.get(key)
                    for key in ("vendor", "product", "packageName", "packageURL", "defaultStatus")
                }
                for kind in ("vendor", "product"):
                    value = product.get(kind)
                    if value and str(value).strip().casefold() not in {
                        "n/a",
                        "unknown",
                        "not applicable",
                        "*",
                    }:
                        entities.append(
                            {
                                "type": kind,
                                "value": str(value).strip(),
                                "source": "nvd_affected_data",
                                "authority": publisher,
                                "json_pointer": _pointer(product_pointer, kind),
                            }
                        )
                # The publisher is a distinct authority even when several CNAs
                # report the same product and version facts.
                for key in (
                    "vendor",
                    "product",
                    "collectionURL",
                    "packageName",
                    "packageURL",
                    "defaultStatus",
                    "cpes",
                ):
                    value = product.get(key)
                    if value is None:
                        continue
                    field = f"nvd_affected_data_{authority_index}_{product_index}_{key}"
                    provenance.append(
                        {
                            "field": "nvd_affected_data_fact",
                            "index_field": field,
                            "authority": publisher,
                            "value": value,
                            "raw_document_id": document.id,
                            "json_pointer": _pointer(product_pointer, key),
                            "verification": "source_asserted",
                        }
                    )
                versions = product.get("versions", [])
                if not isinstance(versions, list):
                    continue
                for version_index, version in enumerate(versions):
                    if not isinstance(version, dict):
                        continue
                    version_pointer = _pointer(product_pointer, f"versions/{version_index}")
                    version_ranges.append(
                        {
                            "source_kind": "nvd_affected_data",
                            "authority": publisher,
                            "index_field": f"nvd_affected_data_{authority_index}_{product_index}_version_{version_index}",
                            **identity,
                            "version_status": dict(version),
                            "json_pointer": version_pointer,
                            "product_json_pointer": product_pointer,
                            "raw_document_id": document.id,
                        }
                    )
                    provenance.append(
                        {
                            "field": "nvd_affected_data_fact",
                            "index_field": f"nvd_affected_data_{authority_index}_{product_index}_version_{version_index}",
                            "authority": publisher,
                            "value": version,
                            "raw_document_id": document.id,
                            "json_pointer": version_pointer,
                            "verification": "source_asserted",
                        }
                    )

    if event.source_id == "cisa-kev" and isinstance(raw_record, dict):
        if raw_record.get("vendorProject"):
            entities.append(
                {"type": "vendor", "value": raw_record["vendorProject"], "source": "kev"}
            )
        if raw_record.get("product"):
            entities.append({"type": "product", "value": raw_record["product"], "source": "kev"})

    cpe_matches = _cpe_matches(raw_record, revision.record_pointer)
    for match in cpe_matches:
        entities.extend(_cpe_entity(match["criteria"]))

    cvss_entries = _cvss_entries(normalized, revision)
    provenance.extend(
        {
            "field": "cpe_match",
            "raw_document_id": document.id,
            "json_pointer": item["json_pointer"],
            "verification": "source_asserted",
        }
        for item in cpe_matches
    )

    flags = []
    if normalized.get("metadata_only"):
        flags.append("metadata_only")
    if event.kind == "vulnerability":
        if not cvss_entries:
            flags.append("missing_cvss")
        if not version_ranges and not cpe_matches:
            flags.append("missing_affected_scope")
        if event.source_id == "nvd" and not cpe_matches:
            flags.append("missing_cpe_scope")
    if event.kind == "exploitation_alert":
        flags.append("catalog_scope_only")
    if any(item.get("value") == "unknown" for item in entities if item["type"] == "package"):
        flags.append("unknown_package_identity")
    if any(
        value and value.get("status") == "opaque"
        for row in version_ranges
        for value in (row.get("vulnerable"), row.get("fixed"))
    ):
        flags.append("unparsed_version_range")

    return {
        "entities": _unique(entities),
        "version_ranges": _unique(version_ranges),
        "cvss": {"selected": _selected_cvss(cvss_entries), "entries": cvss_entries},
        "cpe_matches": cpe_matches,
        "quality_flags": sorted(set(flags)),
        "provenance": _unique(provenance),
    }


def sync_event_enrichment(session, event, revision, document, raw_record) -> bool:
    data = build_enrichment(event, revision, document, raw_record)
    row = session.get(EventEnrichment, event.id)
    values = {
        "revision_id": revision.id,
        "schema_version": ENRICHMENT_SCHEMA_VERSION,
        **data,
    }
    if row is not None and all(getattr(row, key) == value for key, value in values.items()):
        return False
    if row is None:
        row = EventEnrichment(event_id=event.id, **values)
        session.add(row)
    else:
        for key, value in values.items():
            setattr(row, key, value)
        row.enriched_at = now_utc()
    return True


def enrichment_stats(rows: list[EventEnrichment], event_count: int) -> dict:
    flags = Counter(flag for row in rows for flag in row.quality_flags)
    return {
        "coverage": round(len(rows) / event_count, 6) if event_count else 1.0,
        "with_cvss": sum(bool(row.cvss.get("entries")) for row in rows),
        "with_version_scope": sum(bool(row.version_ranges) for row in rows),
        "with_cpe_scope": sum(bool(row.cpe_matches) for row in rows),
        "entities": sum(len(row.entities) for row in rows),
        "quality_flag_counts": dict(sorted(flags.items())),
    }


def refresh_enrichment_state(session) -> EnrichmentState:
    rows = session.scalars(select(EventEnrichment)).all()
    event_count = len(session.scalars(select(IntelEvent.id)).all())
    stats = enrichment_stats(rows, event_count)
    state = session.get(EnrichmentState, ENRICHMENT_NAME)
    if state is None:
        state = EnrichmentState(name=ENRICHMENT_NAME)
        session.add(state)
    state.schema_version = ENRICHMENT_SCHEMA_VERSION
    state.synced_at = now_utc()
    state.event_count = event_count
    state.enriched_count = len(rows)
    state.stats = stats
    return state


def sync_enrichments(session, store) -> dict:
    records = session.execute(
        select(IntelEvent, EventRevision, RawDocument)
        .join(
            EventRevision,
            (EventRevision.event_id == IntelEvent.id)
            & (EventRevision.number == IntelEvent.revision),
        )
        .join(RawDocument, RawDocument.id == EventRevision.raw_document_id)
        .where(EventRevision.disposition == "current")
    ).all()
    active_ids = {event.id for event, _, _ in records}
    existing_ids = set(session.scalars(select(EventEnrichment.event_id)).all())
    removed = 0
    if orphan_ids := existing_ids - active_ids:
        removed = session.execute(
            delete(EventEnrichment).where(EventEnrichment.event_id.in_(orphan_ids))
        ).rowcount

    cache = {}
    changed = 0
    for event, revision, document in records:
        if document.sha256 not in cache:
            cache[document.sha256] = json.loads(store.read(document.sha256))
        raw_record = resolve_pointer(cache[document.sha256], revision.record_pointer)
        changed += sync_event_enrichment(session, event, revision, document, raw_record)
    session.flush()
    state = refresh_enrichment_state(session)
    from zhidu.comparisons import sync_comparisons
    from zhidu.indexing import sync_index

    index = sync_index(session)
    comparisons = sync_comparisons(session)
    return {
        "schema_version": ENRICHMENT_SCHEMA_VERSION,
        "events": len(records),
        "changed_events": changed,
        "unchanged_events": len(records) - changed,
        "removed_orphans": removed,
        "index": index,
        "comparisons": comparisons,
        **state.stats,
    }


def enrichment_view(row: EventEnrichment) -> dict:
    return {
        "event_id": row.event_id,
        "revision_id": row.revision_id,
        "schema_version": row.schema_version,
        "enriched_at": row.enriched_at,
        "entities": row.entities,
        "version_ranges": row.version_ranges,
        "cvss": row.cvss,
        "cpe_matches": row.cpe_matches,
        "quality_flags": row.quality_flags,
        "provenance": row.provenance,
    }


def enrichment_status(session) -> dict:
    rows = session.scalars(select(EventEnrichment)).all()
    event_count = len(session.scalars(select(IntelEvent.id)).all())
    state = session.get(EnrichmentState, ENRICHMENT_NAME)
    return {
        "name": ENRICHMENT_NAME,
        "schema_version": ENRICHMENT_SCHEMA_VERSION,
        "synced_at": state.synced_at if state else None,
        "events": event_count,
        "enriched": len(rows),
        "derived_not_source_fact": True,
        **enrichment_stats(rows, event_count),
    }
