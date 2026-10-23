"""Cross-source comparison without silently resolving source disagreements."""

import hashlib
import json

from sqlalchemy import select

from zhidu.models import (
    ComparisonReviewChange,
    EventAlias,
    EventEnrichment,
    IntelEvent,
    IntelligenceComparison,
    now_utc,
)


def _id(identifier: str, field: str) -> str:
    value = hashlib.sha256(f"{identifier}:{field}".encode()).hexdigest()
    return f"{value[:8]}-{value[8:12]}-{value[12:16]}-{value[16:20]}-{value[20:32]}"


def _source_pointer(enrichment, field):
    return next(
        (item.get("json_pointer") for item in enrichment.provenance if item.get("field") == field),
        None,
    )


def _observation(event, enrichment, value, pointer=None):
    return {
        "event_id": event.id,
        "revision_id": enrichment.revision_id,
        "source_id": event.source_id,
        "external_id": event.external_id,
        "value": value,
        "raw_document_id": next(
            (
                item.get("raw_document_id")
                for item in enrichment.provenance
                if item.get("raw_document_id")
            ),
            None,
        ),
        "json_pointer": pointer,
        "verification": "source_asserted",
    }


def _field_observations(field, rows):
    observations = []
    for event, enrichment in rows:
        if field == "severity":
            if event.severity == "unknown":
                continue
            observations.append(
                _observation(
                    event, enrichment, event.severity, _source_pointer(enrichment, "severity")
                )
            )
        elif field == "cvss_score":
            selected = enrichment.cvss.get("selected")
            if not selected:
                continue
            value = {
                "score": selected.get("score"),
                "version": selected.get("version"),
                "source": selected.get("source"),
            }
            observations.append(
                _observation(event, enrichment, value, selected.get("json_pointer"))
            )
        elif field == "affected_scope":
            nvd_affected = [
                {
                    key: item.get(key)
                    for key in (
                        "authority",
                        "vendor",
                        "product",
                        "packageName",
                        "packageURL",
                        "defaultStatus",
                        "version_status",
                        "json_pointer",
                    )
                }
                for item in enrichment.version_ranges
                if item.get("source_kind") == "nvd_affected_data"
            ]
            value = {
                "packages": [
                    {
                        "ecosystem": item.get("ecosystem"),
                        "package": item.get("package"),
                        "vulnerable": (item.get("vulnerable") or {}).get("raw"),
                    }
                    for item in enrichment.version_ranges
                    if item.get("source_kind") == "affected_package"
                ],
                "cpe": [item.get("criteria") for item in enrichment.cpe_matches],
                "nvd_affected_data": nvd_affected,
            }
            if not value["packages"] and not value["cpe"] and not nvd_affected:
                continue
            observations.append(
                _observation(
                    event, enrichment, value, _source_pointer(enrichment, "nvd_affected_data_fact")
                )
            )
    return sorted(
        observations,
        key=lambda item: (item["source_id"], item["event_id"], _canonical(item["value"])),
    )


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def invalidate_review(session, row, reason):
    """Preserve the prior evidence, note and version; invalidate stale UI edits too."""
    old_version = row.annotation_version
    row.annotation_version += 1
    row.review_status = "needs_evidence"
    session.add(
        ComparisonReviewChange(
            comparison_id=row.id,
            previous_version=old_version,
            annotation_version=row.annotation_version,
            review_status=row.review_status,
            analyst_note=row.analyst_note,
            observations=row.observations,
            change_kind=reason,
        )
    )


def sync_comparisons(session) -> dict:
    alias_rows = session.execute(
        select(EventAlias.value, IntelEvent, EventEnrichment)
        .join(IntelEvent, IntelEvent.id == EventAlias.event_id)
        .join(EventEnrichment, EventEnrichment.event_id == IntelEvent.id)
        .where(EventAlias.value.like("CVE-%"), IntelEvent.withdrawn_at.is_(None))
    ).all()
    groups = {}
    for identifier, event, enrichment in alias_rows:
        groups.setdefault(identifier.upper(), {})[event.id] = (event, enrichment)

    desired = {}
    for identifier, event_map in groups.items():
        rows = list(event_map.values())
        if len({event.source_id for event, _ in rows}) < 2:
            continue
        for field in ("severity", "cvss_score", "affected_scope"):
            observations = _field_observations(field, rows)
            if len({item["source_id"] for item in observations}) < 2:
                continue
            distinct = {_canonical(item["value"]) for item in observations}
            if len(distinct) == 1:
                status = "agreement"
            elif field == "severity":
                status = "conflict"
            else:
                status = "variation"
            desired[(identifier, field)] = {
                "id": _id(identifier, field),
                "identifier": identifier,
                "field": field,
                "status": status,
                "observations": observations,
            }

    existing = {
        (row.identifier, row.field): row for row in session.scalars(select(IntelligenceComparison))
    }
    created = updated = unchanged = reactivated = 0
    for key, values in desired.items():
        row = existing.get(key)
        if row is None:
            session.add(IntelligenceComparison(**values))
            created += 1
        elif row.is_active and all(getattr(row, field) == value for field, value in values.items()):
            unchanged += 1
        else:
            reactivated += not row.is_active
            invalidate_review(session, row, "source_updated" if row.is_active else "reactivated")
            row.is_active = True
            row.retired_at = None
            row.status = values["status"]
            row.observations = values["observations"]
            row.evaluated_at = now_utc()
            updated += 1
    stale = [existing[key] for key in set(existing) - set(desired) if existing[key].is_active]
    for row in stale:
        invalidate_review(session, row, "retired")
        row.is_active = False
        row.retired_at = now_utc()
    session.flush()
    counts = {"agreement": 0, "variation": 0, "conflict": 0}
    for row in session.scalars(
        select(IntelligenceComparison).where(IntelligenceComparison.is_active.is_(True))
    ):
        counts[row.status] = counts.get(row.status, 0) + 1
    return {
        "identifiers_compared": len({identifier for identifier, _ in desired}),
        "created": created,
        "updated": updated,
        "unchanged": unchanged,
        "removed": 0,
        "retired": len(stale),
        "reactivated": reactivated,
        "status_counts": counts,
        "automatic_resolution": False,
    }


def comparison_view(row: IntelligenceComparison) -> dict:
    return {
        "id": row.id,
        "identifier": row.identifier,
        "field": row.field,
        "status": row.status,
        "is_active": row.is_active,
        "retired_at": row.retired_at,
        "observations": row.observations,
        "review_status": row.review_status,
        "analyst_note": row.analyst_note,
        "annotation_version": row.annotation_version,
        "reviewed_at": row.reviewed_at,
        "evaluated_at": row.evaluated_at,
        "automatic_resolution": False,
    }
