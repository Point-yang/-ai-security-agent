"""Correct metric denominators and prepare blank blind human review packets."""

import hashlib
import json
from collections import Counter
from pathlib import Path

from evaluate_member_b_agent import summary

FULL = Path("docs/member-b-agent-comparison-full.json")
RECHECK = Path("docs/member-b-agent-comparison-recheck.json")
ANALYSIS = Path("docs/member-b-agent-comparison-analysis.json")
ROOT = Path("data/member-b-agent-review")
PRIVATE_MAP = Path("tmp/member-b-agent/review-item-map.json")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def corrected_rows(rows):
    normalized = json.loads(json.dumps(rows, ensure_ascii=False))
    for row in normalized:
        # The original writer counted a safe local lexical fallback with citations
        # as unverified merely because it had no Agent final_citation_check field.
        if (
            row["mode"] == "bounded_agent"
            and row["citations"]
            and row["reason"] in {"source_excerpts", "partial_source_evidence"}
        ):
            row["citation_byte_verified"] = True
    return normalized


def run():
    for path in (
        ANALYSIS,
        ROOT / "source-packet.json",
        ROOT / "review-A.json",
        ROOT / "review-B.json",
        ROOT / "adjudications.json",
        PRIVATE_MAP,
    ):
        if path.exists():
            raise SystemExit(f"refusing overwrite: {path}")
    full, recheck = json.loads(FULL.read_text()), json.loads(RECHECK.read_text())
    assert recheck["post_hoc_recheck"] and recheck["parent_report_sha256"] == sha256(FULL)
    modes = ("extractive", "ordinary_deepseek", "bounded_agent")
    cohorts = {}
    for name, report in (("original_fixed_12", full), ("post_hoc_selected_7", recheck)):
        rows = corrected_rows(report["rows"])
        cohorts[name] = {
            "case_count": report["case_count"],
            "metrics": {mode: summary([r for r in rows if r["mode"] == mode]) for mode in modes},
            "agent_generation_failures": dict(
                Counter(
                    r["generation_reason"] or "none"
                    for r in rows
                    if r["mode"] == "bounded_agent" and r["generation_status"] == "fallback"
                )
            ),
            "source_report_sha256": sha256(FULL if name == "original_fixed_12" else RECHECK),
        }
    analysis = {
        "version": "member-b-agent-analysis-v1",
        "date": "2026-09-29",
        "evaluation_copy_sha256": full["database_sha256"],
        "cohorts": cohorts,
        "first_run_unchanged": True,
        "metric_correction": "For Agent local-lexical fallback with citations, the original writer treated the absent Agent final_citation_check as a failed byte check. Existing RAG verified those citations. Corrected cited-case denominator and rate appear here; original rows remain unchanged.",
        "interpretation": "No demonstrated quality gain: model generation completed in fewer positive cases for Agent, with extra planning requests. Post-hoc seven-case recheck is diagnostic, not a fresh holdout score.",
        "semantic_answer_correctness": None,
        "semantic_citation_support": None,
        "human_gold_completed": 0,
        "api_usd": None,
        "external_request_budget": {
            "approved_approximate_max": 60,
            "original_pair": 25,
            "single_case_diagnostic": 4,
            "post_hoc_recheck": 20,
            "total_reported": 49,
        },
    }
    ANALYSIS.write_text(json.dumps(analysis, ensure_ascii=False, indent=2) + "\n")

    source_digest = sha256(FULL)
    submissions, lookup = [], {}
    for row in full["rows"]:
        identity = f"{row['case_id']}|{row['mode']}|{source_digest}".encode()
        item_id = hashlib.sha256(identity).hexdigest()[:16]
        lookup[item_id] = {"case_id": row["case_id"], "mode": row["mode"]}
        submissions.append(
            {
                "item_id": item_id,
                "question": row["question"],
                "answer": row["answer"],
                "citations": row["citations"],
                "answer_class": row["answer_class"],
                "generation_status": row["generation_status"],
                "instruction": "Judge the answer against current cited raw source meaning. Quote containment alone is insufficient; distinguish refusal, source disagreement, and absent information.",
            }
        )
    submissions.sort(key=lambda item: item["item_id"])
    ROOT.mkdir(parents=True, exist_ok=True)
    PRIVATE_MAP.parent.mkdir(parents=True, exist_ok=True)
    packet = {
        "status": "prepared_not_reviewed",
        "source_report_sha256": source_digest,
        "system_labels_hidden": True,
        "items": submissions,
    }
    (ROOT / "source-packet.json").write_text(
        json.dumps(packet, ensure_ascii=False, indent=2) + "\n"
    )
    packet_digest = sha256(ROOT / "source-packet.json")
    for reviewer in ("A", "B"):
        records = [
            {
                "item_id": item["item_id"],
                "answer_correct": None,
                "semantic_citation_support": None,
                "complete": None,
                "refusal_appropriate": None,
                "notes": None,
                "reviewed_at": None,
            }
            for item in submissions
        ]
        if reviewer == "B":
            records.reverse()
        template = {
            "status": "pending_human_review",
            "reviewer": reviewer,
            "packet_sha256": packet_digest,
            "annotations": records,
        }
        (ROOT / f"review-{reviewer}.json").write_text(
            json.dumps(template, ensure_ascii=False, indent=2) + "\n"
        )
    (ROOT / "adjudications.json").write_text(
        json.dumps(
            {"status": "pending_human_review", "packet_sha256": packet_digest, "decisions": []},
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )
    PRIVATE_MAP.write_text(
        json.dumps(
            {"source_report_sha256": source_digest, "item_to_mode": lookup},
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )
    print(
        json.dumps(
            {
                "analysis": str(ANALYSIS),
                "human_packet": str(ROOT),
                "items": len(submissions),
                "completed_reviews": 0,
                "reported_external_requests": 49,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    run()
