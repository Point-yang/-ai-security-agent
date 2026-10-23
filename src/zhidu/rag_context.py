"""Bounded current-revision context, preserving individual source evidence spans."""

import json
import re
from collections import defaultdict

from sqlalchemy import select

from zhidu.indexing import chunk_view
from zhidu.models import EventAlias, EventRevision, IntelEvent
from zhidu.retrieval import RetrievalHit, rank_chunks
from zhidu.semantic import active_chunks

CONTEXT_VERSION = "evidence-context-v2-nvd-affected"
MAX_CITATIONS = 24
MAX_CONTEXT_CHARS = 18000
FIX_TERMS = re.compile(
    r"\b(patch(?:ed|es)?|fix(?:ed|es)?|mitigat\w*|workaround|upgrade|remediat\w*)\b|修复|缓解|升级",
    re.I,
)


def expand_evidence_context(session, seeds, question, *, pool, origin, event_id=None):
    rows = active_chunks(session, pool=pool, origin=origin, event_id=event_id)
    by_event = defaultdict(list)
    by_id = {r.id: r for r in rows}
    for row in rows:
        by_event[row.event_id].append(row)
    # A seed from an outdated index/revision is never promoted into current evidence.
    seeds = [
        s
        for s in seeds
        if s.chunk_id in by_id and s.citation.revision_id == by_id[s.chunk_id].revision_id
    ]
    ids = list(dict.fromkeys(s.citation.event_id for s in seeds))
    events = {
        r.id: r for r in session.scalars(select(IntelEvent).where(IntelEvent.id.in_(by_event)))
    }
    aliases = defaultdict(set)
    for eid, value in session.execute(select(EventAlias.event_id, EventAlias.value)):
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", value, re.I):
            aliases[eid].add(value.upper())
    relations = []
    # At most two additional sources, direct identifier links only (not fuzzy title matches).
    if not event_id:
        for other in sorted(set(by_event) - set(ids)):
            for seed_id in list(ids):
                shared = sorted(aliases[seed_id] & aliases[other])
                same = events[seed_id].external_id == events[other].external_id
                if same or shared:
                    relations.append(
                        {
                            "from_event_id": seed_id,
                            "to_event_id": other,
                            "type": "same_identifier" if same else "shared_cve",
                            "identifiers": shared or [events[other].external_id],
                        }
                    )
                    break
            if len(relations) == 2:
                break
        ids += [r["to_event_id"] for r in relations]
    seed_map = {s.citation.event_id: s for s in seeds}
    queues = {}
    for eid in ids:
        chunks = sorted(by_event[eid], key=lambda r: (r.start, r.id))
        fields = defaultdict(list)
        for row in chunks:
            fields[row.field].append(row)
        ranked = rank_chunks([chunk_view(r) for r in fields["description"]], question)
        descriptions = {r.id: r for r in fields["description"]}
        nvd_affected = [
            row
            for field, field_rows in fields.items()
            if field.startswith("nvd_affected_data_")
            for row in field_rows
        ]
        nvd_ranked = rank_chunks([chunk_view(r) for r in nvd_affected], question)
        fixes = sorted(
            fields["description"], key=lambda r: (-len(FIX_TERMS.findall(r.text)), r.start)
        )
        fixes = [r for r in fixes if FIX_TERMS.search(r.text)][:3]
        seed = seed_map.get(eid)
        seed_row = by_id.get(seed.chunk_id) if seed else None
        preferred = (
            fields["title"][:1]
            + fields["packages"][:3]
            + [next(r for r in nvd_affected if r.id == hit.chunk_id) for hit in nvd_ranked[:3]]
            + fields["required_action"][:2]
            + fixes
            + ([seed_row] if seed_row and seed_row.field == "description" else [])
            + [descriptions[h.chunk_id] for h in ranked[:2]]
            + fields["description"][:1]
            + fields["references"][:2]
        )
        # Include neighbors where chunk boundaries may split a repair explanation.
        for fix in fixes[:1]:
            preferred += [
                r
                for r in fields["description"]
                if r.start == fix.start + 780 or r.start == fix.start - 780
            ]
        preferred += [seed_row] if seed_row else []
        unique, seen = [], set()
        for row in preferred:
            # Do not deduplicate across sources: differences must remain inspectable.
            identity = (row.raw_document_id, row.json_pointer, row.start, row.end)
            if identity not in seen:
                seen.add(identity)
                unique.append(row)
        queues[eid] = unique
    selected, chars, clipped = [], 0, False
    while any(queues.values()):
        for eid in ids:
            if not queues[eid]:
                continue
            row = queues[eid].pop(0)
            if len(selected) >= MAX_CITATIONS or chars + len(row.text) > MAX_CONTEXT_CHARS:
                clipped = True
                continue
            seed = seed_map.get(eid)
            selected.append(
                RetrievalHit(
                    **chunk_view(row).model_dump(),
                    score=seed.score if seed else 0.0,
                    matched_terms=seed.matched_terms if seed else [],
                )
            )
            chars += len(row.text)
    source_summary = []
    for eid in ids:
        included = [h for h in selected if h.citation.event_id == eid]
        if not included:
            continue
        event = events[eid]
        included_fields = sorted({h.field for h in included})
        packages = [h.text for h in included if h.field == "packages"]
        nvd_facts = [h.text for h in included if h.field.startswith("nvd_affected_data_")]
        nvd_unaffected_status = False
        for hit in included:
            if not hit.field.startswith("nvd_affected_data_") or "_version_" not in hit.field:
                continue
            try:
                status_fact = json.loads(hit.text)
            except (TypeError, ValueError):
                continue
            nvd_unaffected_status |= status_fact.get("status") == "unaffected" or any(
                change.get("status") == "unaffected"
                for change in status_fact.get("changes", [])
                if isinstance(change, dict)
            )
        nvd_unaffected_status |= any(
            r.text.strip('"') == "unaffected"
            for r in included
            if r.field.startswith("nvd_affected_data_") and "_defaultStatus" in r.field
        )
        patch_field = any(
            re.search(r'"(?:first_patched_version|patched_versions)"\s*:\s*(?!null)["\[{]', p)
            for p in packages
        )
        source_summary.append(
            {
                "event_id": eid,
                "external_id": event.external_id,
                "source_id": event.source_id,
                "source_url": event.source_url,
                "title": event.title,
                "revision_id": included[0].citation.revision_id,
                "revision": event.revision,
                "fields": included_fields,
                "available_field_chunk_counts": {
                    field: sum(r.field == field for r in by_event[eid])
                    for field in sorted({r.field for r in by_event[eid]})
                },
                "included_field_chunk_counts": {
                    field: sum(h.field == field for h in included) for field in included_fields
                },
                "full_document_included": False,
                "citation_numbers": [
                    i for i, h in enumerate(selected, 1) if h.citation.event_id == eid
                ],
                "has_package_evidence": "packages" in included_fields,
                "has_nvd_affected_data": bool(nvd_facts),
                "has_nvd_unaffected_version_status": nvd_unaffected_status,
                "has_structured_patch_field": patch_field,
                "has_remediation_text_candidate": any(
                    FIX_TERMS.search(h.text)
                    for h in included
                    if h.field in {"description", "required_action"}
                ),
                "note": "Field presence and keyword candidates do not prove a fix is available; cite the actual source text.",
            }
        )
    return selected, {
        "version": CONTEXT_VERSION,
        "sources": source_summary,
        "relations": relations,
        "citations": len(selected),
        "text_chars": chars,
        "truncated": clipped,
        "max_citations": MAX_CITATIONS,
        "max_text_chars": MAX_CONTEXT_CHARS,
        "source_conflicts_auto_resolved": False,
    }


def citation_freshness(session, citations):
    """Live overlay only; never rewrite historical message citations or replay hashes."""
    results, seen = [], set()
    for c in citations:
        key = (c.get("event_id"), c.get("revision_id"))
        if key in seen:
            continue
        seen.add(key)
        event = session.get(IntelEvent, key[0]) if key[0] else None
        revision = session.get(EventRevision, key[1]) if key[1] else None
        if not event or not revision or revision.event_id != event.id:
            state = "missing"
        elif event.withdrawn_at is not None:
            state = "withdrawn"
        elif revision.disposition != "current" or revision.number != event.revision:
            state = "superseded"
        else:
            state = "current"
        results.append(
            {
                "event_id": key[0],
                "snapshot_revision_id": key[1],
                "current_revision": event.revision if event else None,
                "status": state,
                "reusable_as_current": state == "current",
            }
        )
    return results
