"""Member B's small-corpus lexical retrieval, with immutable source citations."""

import hashlib
import json
import re
from typing import Literal

from pydantic import BaseModel


class Citation(BaseModel):
    event_id: str
    revision_id: str
    revision: int
    raw_document_id: str
    json_pointer: str
    sha256: str
    origin: Literal["live", "replay"]
    verification: Literal["source_asserted"] = "source_asserted"


class RetrievalChunk(BaseModel):
    chunk_id: str
    external_id: str
    title: str
    field: str
    text: str
    start: int
    end: int
    withdrawn: bool
    source_id: str
    kind: str
    severity: str
    ai_label: Literal["relevant", "needs_review", "unrelated"]
    pool: Literal["formal", "candidate", "excluded"]
    citation: Citation


class RetrievalHit(RetrievalChunk):
    score: float
    matched_terms: list[str]


class RetrievalResult(BaseModel):
    query: str
    method: str = "lexical-v3-structured"
    total: int
    scanned_events: int
    items: list[RetrievalHit]


def build_chunks(event, revision, document, triage=None) -> list[RetrievalChunk]:
    """Offsets refer to the string value or canonical JSON serialization of the field."""
    chunks = []
    fields = {
        "title",
        "description",
        "packages",
        "external_id",
        "cve_id",
        "references",
        "required_action",
    }
    ai_label = triage.label if triage else "unrelated"
    pool = {"relevant": "formal", "needs_review": "candidate"}.get(ai_label, "excluded")
    for evidence in revision.evidence:
        if (
            evidence["field"] not in fields
            and not evidence["field"].startswith("nvd_affected_data_")
        ) or evidence["value"] is None:
            continue
        value = evidence["value"]
        text = (
            value
            if isinstance(value, str)
            else json.dumps(value, ensure_ascii=False, sort_keys=True)
        )
        for start in range(0, len(text), 780):
            end = min(start + 900, len(text))
            identity = f"{event.id}:{revision.number}:{evidence['field']}:{start}:{end}"
            chunks.append(
                RetrievalChunk(
                    chunk_id=hashlib.sha256(identity.encode()).hexdigest()[:24],
                    external_id=event.external_id,
                    title=revision.normalized["title"],
                    field=evidence["field"],
                    text=text[start:end],
                    start=start,
                    end=end,
                    withdrawn=bool(revision.normalized.get("withdrawn_at")),
                    source_id=event.source_id,
                    kind=event.kind,
                    severity=event.severity,
                    ai_label=ai_label,
                    pool=pool,
                    citation=Citation(
                        event_id=event.id,
                        revision_id=revision.id,
                        revision=revision.number,
                        raw_document_id=document.id,
                        json_pointer=evidence["json_pointer"],
                        sha256=document.sha256,
                        origin=document.origin,
                    ),
                )
            )
            if end == len(text):
                break
    return chunks


def terms(text: str, *, expand_compounds: bool = False) -> set[str]:
    result = set()
    for token in re.findall(r"[a-z0-9]+(?:[_.-][a-z0-9]+)*|[\u4e00-\u9fff]+", text.casefold()):
        if "\u4e00" <= token[0] <= "\u9fff" and len(token) > 1:
            result.update(token[i : i + 2] for i in range(len(token) - 1))
        else:
            result.add(token)
            if expand_compounds:
                result.update(re.split(r"[_.-]", token))
    return result


def rank_chunks(chunks: list[RetrievalChunk], query: str) -> list[RetrievalHit]:
    query_terms = terms(query)
    if not query_terms:
        return []
    hits = []
    for chunk in chunks:
        text_terms = terms(chunk.text, expand_compounds=True)
        title_terms = terms(chunk.title, expand_compounds=True)
        matched = sorted(query_terms & (text_terms | title_terms))
        if not matched:
            continue
        # Transparent relevance score, never a confidence or verification probability.
        score = len(query_terms & text_terms) / len(query_terms)
        score += 0.25 * len(query_terms & title_terms) / len(query_terms)
        if query.casefold() in chunk.text.casefold():
            score += 1
        elif query.casefold() in chunk.title.casefold():
            score += 1
        hits.append(
            RetrievalHit(**chunk.model_dump(), score=round(score, 4), matched_terms=matched)
        )
    return sorted(hits, key=lambda hit: (-hit.score, hit.citation.event_id, hit.field, hit.start))
