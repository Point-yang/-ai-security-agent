"""Persistent lexical index reconciled from current source revisions."""

import hashlib
import json

from sqlalchemy import delete, func, select

from zhidu.models import (
    AffectedPackage,
    EventEnrichment,
    EventRevision,
    EventTriage,
    IntelEvent,
    RawDocument,
    SearchChunk,
    SearchIndexState,
    now_utc,
)
from zhidu.retrieval import RetrievalChunk, build_chunks, rank_chunks, terms

INDEX_NAME = "lexical"
INDEX_SCHEMA_VERSION = "lexical-v8-nvd-authority"


def structured_event_ids(
    session,
    *,
    entity_type=None,
    entity_value=None,
    cpe=None,
    quality_flag=None,
) -> set[str] | None:
    """Return exact structured-filter matches without treating derived data as evidence."""
    if not any((entity_type, entity_value, cpe, quality_flag)):
        return None
    rows = session.scalars(select(EventEnrichment)).all()
    expected = entity_value.casefold() if entity_value else None
    expected_cpe = cpe.casefold() if cpe else None
    matched = set()
    for row in rows:
        if entity_type and not any(
            item.get("type") == entity_type and str(item.get("value", "")).casefold() == expected
            for item in row.entities
        ):
            continue
        if expected_cpe and not any(
            str(item.get("criteria", "")).casefold() == expected_cpe for item in row.cpe_matches
        ):
            continue
        if quality_flag and quality_flag not in row.quality_flags:
            continue
        matched.add(row.event_id)
    return matched


def _stored(chunk: RetrievalChunk, rule_version: str) -> SearchChunk:
    citation = chunk.citation
    return SearchChunk(
        id=chunk.chunk_id,
        event_id=citation.event_id,
        revision_id=citation.revision_id,
        revision_number=citation.revision,
        raw_document_id=citation.raw_document_id,
        source_id=chunk.source_id,
        kind=chunk.kind,
        external_id=chunk.external_id,
        title=chunk.title,
        field=chunk.field,
        text=chunk.text,
        start=chunk.start,
        end=chunk.end,
        json_pointer=citation.json_pointer,
        sha256=citation.sha256,
        origin=citation.origin,
        verification=citation.verification,
        pool=chunk.pool,
        ai_label=chunk.ai_label,
        triage_rule_version=rule_version,
        severity=chunk.severity,
        withdrawn=chunk.withdrawn,
        term_list=sorted(terms(chunk.text, expand_compounds=True)),
    )


def chunk_view(row: SearchChunk) -> RetrievalChunk:
    return RetrievalChunk(
        chunk_id=row.id,
        external_id=row.external_id,
        title=row.title,
        field=row.field,
        text=row.text,
        start=row.start,
        end=row.end,
        withdrawn=row.withdrawn,
        source_id=row.source_id,
        kind=row.kind,
        severity=row.severity,
        ai_label=row.ai_label,
        pool=row.pool,
        citation={
            "event_id": row.event_id,
            "revision_id": row.revision_id,
            "revision": row.revision_number,
            "raw_document_id": row.raw_document_id,
            "json_pointer": row.json_pointer,
            "sha256": row.sha256,
            "origin": row.origin,
            "verification": row.verification,
        },
    )


def sync_event_index(session, event, revision, document, triage) -> dict:
    desired = build_chunks(event, revision, document, triage)
    enrichment = session.get(EventEnrichment, event.id)
    if enrichment is not None and enrichment.revision_id == revision.id:
        for fact in enrichment.provenance:
            if fact.get("field") != "nvd_affected_data_fact" or not fact.get("index_field"):
                continue
            value = fact.get("value")
            text = (
                value
                if isinstance(value, str)
                else json.dumps(value, ensure_ascii=False, sort_keys=True)
            )
            field = fact["index_field"]
            for start in range(0, len(text), 780):
                end = min(start + 900, len(text))
                identity = f"{event.id}:{revision.number}:{field}:{start}:{end}"
                citation = RetrievalChunk(
                    chunk_id=hashlib.sha256(identity.encode()).hexdigest()[:24],
                    external_id=event.external_id,
                    title=event.title,
                    field=field,
                    text=text[start:end],
                    start=start,
                    end=end,
                    withdrawn=bool(event.withdrawn_at),
                    source_id=event.source_id,
                    kind=event.kind,
                    severity=event.severity,
                    ai_label=triage.label,
                    pool={"relevant": "formal", "needs_review": "candidate"}.get(
                        triage.label, "excluded"
                    ),
                    citation={
                        "event_id": event.id,
                        "revision_id": revision.id,
                        "revision": revision.number,
                        "raw_document_id": fact["raw_document_id"],
                        "json_pointer": fact["json_pointer"],
                        "sha256": document.sha256,
                        "origin": document.origin,
                    },
                )
                desired.append(citation)
                if end == len(text):
                    break
    # New source revisions may already expose these exact fields through
    # EventRevision.evidence. Rebuild/backfill uses the enrichment projection
    # to add them without mutating the immutable historical revision evidence.
    desired = list({chunk.chunk_id: chunk for chunk in desired}.values())
    existing = session.scalars(select(SearchChunk).where(SearchChunk.event_id == event.id)).all()
    desired_ids = {chunk.chunk_id for chunk in desired}
    desired_rows = {c.chunk_id: _stored(c, triage.rule_version) for c in desired}
    compared_fields = (
        "revision_id",
        "raw_document_id",
        "source_id",
        "kind",
        "title",
        "severity",
        "text",
        "json_pointer",
        "sha256",
        "start",
        "end",
        "field",
        "pool",
        "origin",
        "ai_label",
        "withdrawn",
        "term_list",
        "triage_rule_version",
    )
    unchanged = (
        {row.id for row in existing} == desired_ids
        and all(
            all(getattr(row, f) == getattr(desired_rows[row.id], f) for f in compared_fields)
            for row in existing
        )
        if desired
        else not existing
    )
    if unchanged:
        return {"changed": False, "removed": 0, "created": 0}
    removed = len(existing)
    session.execute(delete(SearchChunk).where(SearchChunk.event_id == event.id))
    session.add_all(_stored(chunk, triage.rule_version) for chunk in desired)
    return {"changed": True, "removed": removed, "created": len(desired)}


def sync_index(session) -> dict:
    rows = session.execute(
        select(IntelEvent, EventRevision, RawDocument, EventTriage)
        .join(
            EventRevision,
            (EventRevision.event_id == IntelEvent.id)
            & (EventRevision.number == IntelEvent.revision),
        )
        .join(RawDocument, RawDocument.id == EventRevision.raw_document_id)
        .join(EventTriage, EventTriage.event_id == IntelEvent.id)
        .where(EventRevision.disposition == "current")
    ).all()
    active_ids = {event.id for event, *_ in rows}
    indexed_ids = set(session.scalars(select(SearchChunk.event_id).distinct()).all())
    removed_orphans = 0
    if orphan_ids := indexed_ids - active_ids:
        removed_orphans = session.execute(
            delete(SearchChunk).where(SearchChunk.event_id.in_(orphan_ids))
        ).rowcount
    changed_events = created_chunks = replaced_chunks = unchanged_events = 0
    for event, revision, document, triage in rows:
        result = sync_event_index(session, event, revision, document, triage)
        if result["changed"]:
            changed_events += 1
            created_chunks += result["created"]
            replaced_chunks += result["removed"]
        else:
            unchanged_events += 1
    session.flush()
    pool_counts = dict(
        session.execute(select(SearchChunk.pool, func.count()).group_by(SearchChunk.pool)).all()
    )
    chunk_count = session.scalar(select(func.count()).select_from(SearchChunk)) or 0
    state = session.get(SearchIndexState, INDEX_NAME)
    if state is None:
        state = SearchIndexState(
            name=INDEX_NAME,
            schema_version=INDEX_SCHEMA_VERSION,
            synced_at=now_utc(),
            event_count=len(rows),
            chunk_count=chunk_count,
            pool_counts=pool_counts,
        )
        session.add(state)
    else:
        state.schema_version = INDEX_SCHEMA_VERSION
        state.synced_at = now_utc()
        state.event_count = len(rows)
        state.chunk_count = chunk_count
        state.pool_counts = pool_counts
    return {
        "schema_version": INDEX_SCHEMA_VERSION,
        "events": len(rows),
        "changed_events": changed_events,
        "unchanged_events": unchanged_events,
        "created_chunks": created_chunks,
        "replaced_chunks": replaced_chunks,
        "removed_orphan_chunks": removed_orphans,
        "chunks": state.chunk_count,
        "pools": pool_counts,
    }


def refresh_index_state(session):
    event_count = session.scalar(select(func.count(SearchChunk.event_id.distinct()))) or 0
    chunk_count = session.scalar(select(func.count()).select_from(SearchChunk)) or 0
    pool_counts = dict(
        session.execute(select(SearchChunk.pool, func.count()).group_by(SearchChunk.pool)).all()
    )
    state = session.get(SearchIndexState, INDEX_NAME)
    if state is None:
        state = SearchIndexState(
            name=INDEX_NAME,
            schema_version=INDEX_SCHEMA_VERSION,
            synced_at=now_utc(),
            event_count=event_count,
            chunk_count=chunk_count,
            pool_counts=pool_counts,
        )
        session.add(state)
    else:
        state.schema_version = INDEX_SCHEMA_VERSION
        state.event_count = event_count
        state.chunk_count = chunk_count
        state.pool_counts = pool_counts
        state.synced_at = now_utc()
    return state


def index_status(session) -> dict:
    state = session.get(SearchIndexState, INDEX_NAME)
    counts = dict(
        session.execute(select(SearchChunk.pool, func.count()).group_by(SearchChunk.pool)).all()
    )
    return {
        "name": INDEX_NAME,
        "schema_version": state.schema_version if state else INDEX_SCHEMA_VERSION,
        "synced_at": state.synced_at if state else None,
        "events": session.scalar(select(func.count(SearchChunk.event_id.distinct()))) or 0,
        "chunks": session.scalar(select(func.count()).select_from(SearchChunk)) or 0,
        "pools": counts,
        "durable": True,
        "sync_method": "current_revision_reconciliation",
    }


def search_index(
    session,
    query,
    *,
    event_id=None,
    pool=None,
    ai_label=None,
    origin="live",
    source_id=None,
    kind=None,
    package=None,
    entity_type=None,
    entity_value=None,
    cpe=None,
    quality_flag=None,
    severity=None,
    include_withdrawn=False,
):
    stmt = (
        select(SearchChunk)
        .join(IntelEvent, IntelEvent.id == SearchChunk.event_id)
        .join(EventRevision, EventRevision.id == SearchChunk.revision_id)
        .where(
            IntelEvent.revision == SearchChunk.revision_number,
            EventRevision.disposition == "current",
            EventRevision.event_id == IntelEvent.id,
            EventRevision.number == SearchChunk.revision_number,
        )
    )
    if event_id:
        stmt = stmt.where(SearchChunk.event_id == event_id)
    if pool:
        stmt = stmt.where(SearchChunk.pool == pool)
    if ai_label:
        stmt = stmt.where(SearchChunk.ai_label == ai_label)
    if origin:
        stmt = stmt.where(SearchChunk.origin == origin)
    if source_id:
        stmt = stmt.where(SearchChunk.source_id == source_id)
    if kind:
        stmt = stmt.where(SearchChunk.kind == kind)
    if package:
        stmt = stmt.where(
            SearchChunk.event_id.in_(
                select(AffectedPackage.event_id).where(AffectedPackage.name == package)
            )
        )
    structured_ids = structured_event_ids(
        session,
        entity_type=entity_type,
        entity_value=entity_value,
        cpe=cpe,
        quality_flag=quality_flag,
    )
    if structured_ids is not None:
        stmt = stmt.where(SearchChunk.event_id.in_(structured_ids))
    if severity:
        stmt = stmt.where(SearchChunk.severity == severity)
    if not include_withdrawn:
        stmt = stmt.where(SearchChunk.withdrawn.is_(False), IntelEvent.withdrawn_at.is_(None))
    rows = session.scalars(stmt).all()
    hits = rank_chunks([chunk_view(row) for row in rows], query)
    return hits, len({row.event_id for row in rows})
