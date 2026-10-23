"""Deterministic retrieval and citation evaluation for a fixed question suite."""

import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from zhidu.answers import event_constraints
from zhidu.indexing import INDEX_SCHEMA_VERSION, search_index
from zhidu.models import RawDocument, RetrievalEvaluation
from zhidu.sources import resolve_pointer


class EvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=100)
    question: str = Field(min_length=1, max_length=1000)
    query: str = Field(min_length=1, max_length=200)
    pool: str = "formal"
    top_k: int = Field(default=10, ge=1, le=100)
    expected_external_ids: list[str] = Field(default_factory=list)
    expected_status: Literal["evidence", "no_evidence"] = "evidence"
    expected_constraint_codes: list[str] = Field(default_factory=list)
    entity_type: Literal["cve", "ghsa", "doi", "package", "vendor", "product"] | None = None
    entity_value: str | None = None
    cpe: str | None = None
    quality_flag: str | None = None


class EvaluationSuite(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = Field(min_length=1, max_length=100)
    cases: list[EvaluationCase] = Field(min_length=1)


def load_suite(path: Path) -> EvaluationSuite:
    return EvaluationSuite.model_validate(json.loads(path.read_text()))


def verify_hit(session, store, hit) -> bool:
    document = session.get(RawDocument, hit.citation.raw_document_id)
    if document is None or document.sha256 != hit.citation.sha256:
        return False
    try:
        content = store.read(document.sha256)
        raw = json.loads(content)
        value = resolve_pointer(raw, hit.citation.json_pointer)
    except (OSError, ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError):
        return False
    text = (
        value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
    )
    return (
        hashlib.sha256(content).hexdigest() == hit.citation.sha256
        and text[hit.start : hit.end] == hit.text
    )


def evaluate(session, store, suite: EvaluationSuite) -> RetrievalEvaluation:
    details = []
    total_citations = verified_citations = supported_lines = total_lines = 0
    hits = retrieval_cases = answerable = constraint_passes = constraint_cases = 0
    for case in suite.cases:
        ranked, scanned_events = search_index(
            session,
            case.query,
            pool=case.pool,
            origin="live",
            include_withdrawn=False,
            entity_type=case.entity_type,
            entity_value=case.entity_value,
            cpe=case.cpe,
            quality_flag=case.quality_flag,
        )
        selected, seen_events = [], set()
        for hit in ranked:
            if hit.citation.event_id in seen_events:
                continue
            selected.append(hit)
            seen_events.add(hit.citation.event_id)
            if len(selected) == case.top_k:
                break
        external_ids = {hit.external_id for hit in selected}
        case_hit = (
            bool(external_ids & set(case.expected_external_ids))
            if case.expected_external_ids
            else True
        )
        if case.expected_external_ids:
            retrieval_cases += 1
            hits += case_hit
        answerability_pass = bool(selected) == (case.expected_status == "evidence")
        answerable += answerability_pass
        returned_constraint_codes = set()
        for event_id in seen_events:
            returned_constraint_codes.update(
                rule["code"] for rule in event_constraints(session, event_id)
            )
        if not selected:
            returned_constraint_codes.add("insufficient_evidence")
        constraint_pass = set(case.expected_constraint_codes).issubset(returned_constraint_codes)
        if case.expected_constraint_codes:
            constraint_cases += 1
            constraint_passes += constraint_pass
        verified = [verify_hit(session, store, hit) for hit in selected]
        total_citations += len(verified)
        verified_citations += sum(verified)
        # The evaluated answer is an extractive evidence packet: every output line maps 1:1
        # to a selected chunk. A failed source verification makes that line unsupported.
        total_lines += len(selected)
        supported_lines += sum(verified)
        details.append(
            {
                "id": case.id,
                "question": case.question,
                "query": case.query,
                "pool": case.pool,
                "top_k": case.top_k,
                "hit": case_hit,
                "answerability_pass": answerability_pass,
                "expected_status": case.expected_status,
                "constraint_pass": constraint_pass,
                "expected_constraint_codes": case.expected_constraint_codes,
                "returned_constraint_codes": sorted(returned_constraint_codes),
                "expected_external_ids": case.expected_external_ids,
                "returned_external_ids": [hit.external_id for hit in selected],
                "scanned_events": scanned_events,
                "citations": len(selected),
                "verified_citations": sum(verified),
                "unsupported_answer_lines": len(selected) - sum(verified),
            }
        )

    def rate(numerator, denominator):
        return round(numerator / denominator if denominator else 1, 4)

    row = RetrievalEvaluation(
        suite_version=suite.version,
        index_schema_version=INDEX_SCHEMA_VERSION,
        case_count=len(suite.cases),
        hit_rate_at_k=rate(hits, retrieval_cases),
        citation_verifiable_rate=rate(verified_citations, total_citations),
        hallucination_rate=rate(total_lines - supported_lines, total_lines),
        answerability_accuracy=rate(answerable, len(suite.cases)),
        constraint_pass_rate=rate(constraint_passes, constraint_cases),
        details=details,
    )
    session.add(row)
    session.flush()
    return row


def evaluation_view(row: RetrievalEvaluation) -> dict:
    return {
        **{
            column.name: getattr(row, column.name)
            for column in RetrievalEvaluation.__table__.columns
        },
        "metric_scope": (
            "fixed-suite retrieval, answerability, policy constraints and extractive evidence "
            "packets; not free-form LLM answers"
        ),
    }
