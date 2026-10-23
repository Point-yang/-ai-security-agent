"""Do not confuse a verbatim excerpt with evidence relevant to a question."""

from collections import Counter


def rate(numerator, denominator):
    return numerator / denominator if denominator else None


def score_response(case, result):
    if result.get("generation", {}).get("status") == "completed":
        raise ValueError(
            "generated answers require semantic evaluation; extractive metrics are not applicable"
        )
    expected = set(case["expected_event_ids"])
    citations = result["citations"]
    returned = {c["event_id"] for c in citations}
    exact = relevant = 0
    for claim in result["claims"]:
        index = claim.get("citation_index")
        if not isinstance(index, int) or not 0 <= index < len(citations):
            continue
        citation = citations[index]
        quote = claim.get("quote")
        consistent = bool(isinstance(quote, str) and quote and quote in citation.get("text", ""))
        exact += consistent
        # Empty expected sets never support a factual output, even if it is a real quote.
        relevant += consistent and citation["event_id"] in expected
    return {
        "class_correct": result["answer_class"] == case["expected_class"],
        "recall_at_k": rate(len(expected & returned), len(expected)),
        "claims": len(result["claims"]),
        "verbatim_claims": exact,
        "supported_claims": relevant,
        "expected_event_ids": sorted(expected),
        "returned_event_ids": sorted(returned),
    }


def summarize(records):
    refusals = [r for r in records if r["expected_class"] == "refused"]
    positive = [r for r in records if r["expected_class"] != "refused"]
    recall = [r["recall_at_k"] for r in records if r["recall_at_k"] is not None]
    claims = sum(r["claims"] for r in records)
    return {
        "requests": len(records),
        "unique_cases": len({r["case_id"] for r in records}),
        "class_accuracy": rate(sum(r["class_correct"] for r in records), len(records)),
        "refusal_correctness": rate(sum(r["class_correct"] for r in refusals), len(refusals)),
        "refusal_cases": len(refusals),
        "positive_cases": len(positive),
        "positive_class_accuracy": rate(sum(r["class_correct"] for r in positive), len(positive)),
        "verbatim_consistency_rate": rate(sum(r["verbatim_claims"] for r in records), claims),
        "citation_support_rate": rate(sum(r["supported_claims"] for r in records), claims),
        "claim_count": claims,
        "supported_claims": sum(r["supported_claims"] for r in records),
        "recall_at_5": rate(sum(recall), len(recall)),
        "classes": dict(Counter(r["answer_class"] for r in records)),
    }


def stratified(records):
    return {
        field: {
            key: summarize([r for r in records if r[field] == key])
            for key in sorted({r[field] for r in records})
        }
        for field in ("split", "language")
    }


def query_language(case):
    return "zh" if any("\u4e00" <= char <= "\u9fff" for char in case["query"]) else "en"
