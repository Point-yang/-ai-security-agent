"""Fixed 12-question paired evaluation; external calls require explicit approval."""

import argparse
import hashlib
import json
import time
from pathlib import Path

from zhidu.agent_rag import run_agent
from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.rag import RagRequest, run_rag
from zhidu.semantic import LocalEncoder
from zhidu.storage import BlobStore

DATASET = Path("config/member-b-week6-frozen-qa.json")
DEFAULT_DB = Path("data/member-b-agent-eval-20260929.db")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def quantile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    index = (len(ordered) - 1) * fraction
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    return round(ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower), 3)


def summary(rows):
    wall = [r["wall_ms"] for r in rows]
    complete = [r for r in rows if r["generation_status"] == "completed"]
    positive = [r for r in rows if r["expected_class"] != "refused"]
    tools = [r["tool_success"] for r in rows if r["tool_success"] is not None]
    decisions = [d for r in rows for d in r["decisions"]]
    cited = [r for r in rows if r["citations"]]
    pairs = [r for r in rows if r["expected_class"] != "refused"]
    refusals = [r for r in rows if r["expected_class"] == "refused"]
    return {
        "cases": len(rows),
        "completed_generation": len(complete),
        "completed_generation_on_positive": sum(
            r["generation_status"] == "completed" for r in positive
        ),
        "positive_generation_cases": len(positive),
        "safe_abstentions_on_refusal_cases": sum(
            r["answer_class"] in {"refused", "clarification"} for r in refusals
        ),
        "refusal_cases": len(refusals),
        "positive_cases_with_expected_event": sum(
            bool(set(r["expected_event_ids"]) & set(r["returned_event_ids"])) for r in pairs
        ),
        "positive_cases": len(pairs),
        "tool_success_rate_among_executed": sum(tools) / len(tools) if tools else None,
        "planner_decision_completion_rate": sum(d["status"] == "completed" for d in decisions)
        / len(decisions)
        if decisions
        else None,
        "planner_decisions": len(decisions),
        "multi_tool_cases": sum(r["multi_tool"] for r in rows),
        "citation_byte_check_rate_among_cited": sum(r["citation_byte_verified"] for r in cited)
        / len(cited)
        if cited
        else None,
        "cited_cases": len(cited),
        "generated_quote_check_passed": sum(r["generation_citation_checks_passed"] for r in rows),
        "p50_wall_ms": quantile(wall, 0.5),
        "p95_wall_ms": quantile(wall, 0.95),
        "p50_completed_generation_ms": quantile([r["wall_ms"] for r in complete], 0.5),
        "p95_completed_generation_ms": quantile([r["wall_ms"] for r in complete], 0.95),
        "billed_tokens_reported": sum(r["billed_tokens"] or 0 for r in rows),
        "billed_tokens_per_completed_generation": round(
            sum(r["billed_tokens"] or 0 for r in rows) / len(complete), 1
        )
        if complete
        else None,
        "external_requests_reported": sum(r["external_requests"] or 0 for r in rows),
        "api_usd": None,
        "answer_correctness": None,
        "semantic_citation_support": None,
        "completeness": None,
        "quality_note": "Development labels and byte-level quote checks are not independent human correctness or semantic support scores.",
    }


def one(session, store, settings, encoder, case, mode):
    generation = {
        "extractive": "extractive",
        "ordinary_deepseek": "deepseek",
        "bounded_agent": "agent",
    }[mode]
    request = RagRequest(
        question=case["question"],
        query=case["query"],
        mode="lexical" if mode == "extractive" else "hybrid",
        generation=generation,
        pool="formal",
        origin="live",
        top_k=5,
    )
    start = time.monotonic()
    if mode == "bounded_agent":
        result = run_agent(session, store, settings, request, encoder)
    else:
        result = run_rag(session, store, settings, request, encoder)
    wall = round((time.monotonic() - start) * 1000, 3)
    decisions = result.get("agent", {}).get("decisions", [])
    tool_results = result.get("agent", {}).get("tool_results", [])
    check = result.get("agent", {}).get("final_citation_check")
    return {
        "case_id": case["id"],
        "mode": mode,
        "split": case["split"],
        "question": case["question"],
        "query": case["query"],
        "expected_class": case["expected_class"],
        "expected_event_ids": case["expected_event_ids"],
        "answer_class": result["answer_class"],
        "reason": result.get("reason"),
        "answer": result["answer"],
        "citations": result["citations"],
        "returned_event_ids": sorted({c["event_id"] for c in result["citations"]}),
        "generation_status": result.get("generation", {}).get("status"),
        "generation_reason": result.get("generation", {}).get("reason"),
        "generation_model": result.get("generation_model"),
        "generation_citation_checks_passed": result.get("generation", {}).get(
            "citation_checks_passed"
        )
        is True,
        "semantic_support_verified": result.get("generation", {}).get("semantic_support_verified")
        is True,
        "citation_byte_verified": check["verified"] == check["total"]
        if check is not None
        else bool(result["citations"]),
        "tool_success": (sum(t["status"] == "completed" for t in tool_results) / len(tool_results))
        if tool_results
        else None,
        "multi_tool": len({t["tool"] for t in tool_results if t["status"] == "completed"}) > 1,
        "decisions": decisions,
        "tool_results": tool_results,
        "wall_ms": wall,
        "server_elapsed_ms": result.get("elapsed_ms"),
        "billed_tokens": result.get("cost", {}).get("billed_tokens"),
        "external_requests": result.get("cost", {}).get("external_requests"),
        "api_usd": result.get("cost", {}).get("api_usd"),
        "correctness": None,
        "semantic_citation_support": None,
        "completeness": None,
        "human_review_status": "pending",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, default=DEFAULT_DB)
    parser.add_argument(
        "--mode", choices=["preflight", "full", "agent_recheck"], default="preflight"
    )
    parser.add_argument(
        "--case-ids", help="comma-separated development IDs for post-hoc Agent recheck"
    )
    parser.add_argument("--external-model-approved", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.mode in {"full", "agent_recheck"} and not args.external_model_approved:
        parser.error(
            "full mode sends public questions and verified source excerpts to the configured DeepSeek API; obtain explicit approval first"
        )
    if (
        args.mode in {"full", "agent_recheck"}
        and not Settings().deepseek_api_key.get_secret_value().strip()
    ):
        parser.error("DeepSeek API key is not configured")
    dataset = json.loads(DATASET.read_text())
    cases = [c for c in dataset["cases"] if c["split"] == "development"]
    assert len(cases) == 12
    parent_report = None
    if args.mode == "agent_recheck":
        if not args.case_ids:
            parser.error("agent_recheck requires --case-ids")
        chosen = args.case_ids.split(",")
        if not 1 <= len(chosen) <= 7 or len(chosen) != len(set(chosen)):
            parser.error("choose 1–7 distinct development case IDs")
        cases = [c for c in cases if c["id"] in chosen]
        if len(cases) != len(chosen):
            parser.error("case IDs must exist in the fixed development set")
        parent_path = Path("docs/member-b-agent-comparison-full.json")
        if not parent_path.is_file():
            parser.error("original full report is required")
        parent_report = json.loads(parent_path.read_text())
    db = args.database.resolve()
    if not db.is_file():
        parser.error("evaluation database copy not found")
    if parent_report and parent_report["database_sha256"] != digest(db):
        parser.error("evaluation database differs from original paired run")
    settings = Settings(database_url=f"sqlite:///{db}")
    engine = make_engine(settings.database_url)
    encoder = LocalEncoder(settings)
    rows = []
    try:
        for case in cases:
            for mode in (
                ["extractive"]
                if args.mode == "preflight"
                else ["bounded_agent"]
                if args.mode == "agent_recheck"
                else ["extractive", "ordinary_deepseek", "bounded_agent"]
            ):
                with make_sessions(engine)() as session:
                    row = one(session, BlobStore(settings.raw_dir), settings, encoder, case, mode)
                rows.append(row)
                print(
                    json.dumps(
                        {
                            "case": case["id"],
                            "mode": mode,
                            "generation": row["generation_status"],
                            "wall_ms": row["wall_ms"],
                        },
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
    finally:
        encoder.close()
        engine.dispose()
    if parent_report:
        selected_ids = {c["id"] for c in cases}
        rows = [
            r
            for r in parent_report["rows"]
            if r["case_id"] in selected_ids and r["mode"] in {"extractive", "ordinary_deepseek"}
        ] + rows
    groups = {
        mode: summary([r for r in rows if r["mode"] == mode])
        for mode in sorted({r["mode"] for r in rows})
    }
    report = {
        "version": "member-b-agent-comparison-v1",
        "mode": args.mode,
        "date": "2026-09-29",
        "dataset": str(DATASET),
        "dataset_sha256": digest(DATASET),
        "database_copy": str(args.database),
        "database_sha256": digest(db),
        "split": "development",
        "case_count": len(cases),
        "corpus_note": "Current 3214-chunk corpus copy; older frozen corpus hash is not reused as if identical.",
        "independent_human_gold": False,
        "post_hoc_recheck": args.mode == "agent_recheck",
        "parent_report_sha256": digest(Path("docs/member-b-agent-comparison-full.json"))
        if parent_report
        else None,
        "all_semantic_scores_pending": True,
        "modes": groups,
        "rows": rows,
    }
    output = args.output or Path(
        {
            "preflight": "docs/member-b-agent-comparison-preflight.json",
            "full": "docs/member-b-agent-comparison-full.json",
            "agent_recheck": "docs/member-b-agent-comparison-recheck.json",
        }[args.mode]
    )
    if output.exists():
        parser.error(f"refusing to overwrite {output}")
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n")
    print(json.dumps({"output": str(output), "modes": groups}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
