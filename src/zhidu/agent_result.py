"""Validate model-selected evidence IDs and fill exact source quotations locally."""

from zhidu.evaluation import verify_hit
from zhidu.grounded_answer import render_answer
from zhidu.indexing import chunk_view
from zhidu.models import SearchChunk
from zhidu.retrieval import RetrievalHit


def verify_citations(session, store, citations):
    session.expire_all()
    checks = []
    for c in citations:
        if "span_provenance" in c:
            from zhidu.source_spans import verify_source_span

            checks.append(verify_source_span(session, store, c))
            continue
        row = session.get(SearchChunk, c["chunk_id"])
        try:
            valid = bool(
                row
                and c["text"] in row.text
                and verify_hit(
                    session,
                    store,
                    RetrievalHit(**chunk_view(row).model_dump(), score=0, matched_terms=[]),
                )
            )
        except (OSError, ValueError):
            valid = False
        checks.append(valid)
    return {"verified": sum(checks), "total": len(checks), "semantic_support_verified": False}


def finalize_answer(session, store, result, candidate, evidence):
    rendered = render_answer(candidate, evidence)
    checks = verify_citations(session, store, rendered["citations"])
    result["agent"]["final_citation_check"] = checks
    if checks["verified"] != checks["total"]:
        raise ValueError("evidence_invalid")
    partial = rendered["answer_class"] == "partial"
    for constraint in result["constraints"]:
        rendered["answer"] += "\n\n" + constraint["rule"]
        partial |= constraint["code"] == "source_comparison_unresolved"
    if rendered["answer_class"] in {"evidence", "partial"} and partial:
        rendered["answer_class"] = "partial"
    result.update(rendered, reason="langchain_grounded_generation")


def excerpt_fallback(session, store, result, evidence, reason):
    citations = list(evidence.values())[:24]
    checks = verify_citations(session, store, citations)
    result["agent"]["final_citation_check"] = checks
    result["generation"].update(status="fallback", reason=reason, citation_checks_passed=False)
    if not citations or checks["verified"] != checks["total"]:
        result.update(
            answer_class="refused",
            answer="本轮没有通过复验的可引用证据，不能作出事实结论。",
            reason="evidence_invalid" if citations else "no_verified_evidence",
            citations=[],
            claims=[],
        )
    else:
        result.update(
            answer_class="partial",
            reason="langchain_extractive_fallback",
            citations=citations,
            answer="Agent 未完成可靠生成，以下仅为本轮已复验的来源片段：\n"
            + "\n".join(
                f"[{i}] {c['external_id']}：{c['text'][:360]}" for i, c in enumerate(citations, 1)
            ),
            claims=[
                {"citation_index": i, "quote": c["text"][:360]} for i, c in enumerate(citations)
            ],
        )
    result["generation_model"] = "extractive-packet-v4"
