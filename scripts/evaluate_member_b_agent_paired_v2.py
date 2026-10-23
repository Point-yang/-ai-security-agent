"""Run the pre-frozen new 8-case comparison with resumable billable-call tracking."""

import argparse
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from evaluate_member_b_agent import one, summary

from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.semantic import LocalEncoder
from zhidu.storage import BlobStore

DATASET = Path("config/member-b-agent-paired-v2.json")
CHECKPOINT = Path("tmp/member-b-agent-paired-v2-progress.json")
OUTPUT = Path("docs/member-b-agent-paired-v2-evaluation.json")
MODES = ("extractive", "ordinary_deepseek", "bounded_agent")
MAX_REQUESTS = 60


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save_atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n")
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=DATASET)
    parser.add_argument("--checkpoint", type=Path, default=CHECKPOINT)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--external-model-approved", action="store_true")
    args = parser.parse_args()
    if not args.external_model_approved:
        parser.error(
            "this run sends fixed public-security questions and verified excerpts to the configured official DeepSeek API; obtain approval first"
        )
    if args.output.exists():
        parser.error(f"refusing overwrite {args.output}")
    manifest = json.loads(args.dataset.read_text())
    cases = manifest["cases"]
    if manifest["status"] != "frozen_before_model_runs" or not 1 <= len(cases) <= 12:
        parser.error("paired protocol is not frozen")
    db = Path(manifest["evaluation_database"])
    if digest(db) != manifest["evaluation_database_sha256"]:
        parser.error("evaluation database changed after the protocol was frozen")
    implementation = hashlib.sha256(
        Path("src/zhidu/agent_rag.py").read_bytes() + Path("src/zhidu/generation.py").read_bytes()
    ).hexdigest()
    protocol_hash = digest(args.dataset)
    if args.checkpoint.exists():
        state = json.loads(args.checkpoint.read_text())
        if (
            state["protocol_sha256"] != protocol_hash
            or state["implementation_sha256"] != implementation
        ):
            parser.error("checkpoint belongs to a different protocol or implementation")
        if state["in_flight"] is not None:
            parser.error(
                "an external request may have been billed before interruption; inspect it manually before any retry"
            )
    else:
        state = {
            "protocol_sha256": protocol_hash,
            "implementation_sha256": implementation,
            "rows": [],
            "in_flight": None,
            "external_requests_reported": 0,
        }
        save_atomic(args.checkpoint, state)
    settings = Settings(database_url=f"sqlite:///{db.resolve()}")
    if not settings.deepseek_api_key.get_secret_value().strip():
        parser.error("official DeepSeek API key is not configured")
    engine = make_engine(settings.database_url)
    encoder = LocalEncoder(settings)
    completed = {(r["case_id"], r["mode"]) for r in state["rows"]}
    try:
        for case in cases:
            for mode in MODES:
                key = (case["id"], mode)
                if key in completed:
                    continue
                possible = 0 if mode == "extractive" else 1 if mode == "ordinary_deepseek" else 7
                if state["external_requests_reported"] + possible > MAX_REQUESTS:
                    parser.error(
                        "request cap reached before completing the paired cohort; no further external calls made"
                    )
                state["in_flight"] = {
                    "case_id": case["id"],
                    "mode": mode,
                    "started_at": datetime.now(UTC).isoformat(),
                }
                save_atomic(args.checkpoint, state)
                with make_sessions(engine)() as session:
                    result = one(
                        session, BlobStore(settings.raw_dir), settings, encoder, case, mode
                    )
                state["rows"].append(result)
                state["external_requests_reported"] += result["external_requests"] or 0
                state["in_flight"] = None
                save_atomic(args.checkpoint, state)
                print(
                    json.dumps(
                        {
                            "case": case["id"],
                            "mode": mode,
                            "generation": result["generation_status"],
                            "reason": result["generation_reason"],
                            "external_requests_so_far": state["external_requests_reported"],
                        },
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
    finally:
        encoder.close()
        engine.dispose()
    rows = state["rows"]
    if len(rows) != len(cases) * len(MODES):
        parser.error("paired cohort is incomplete")
    report = {
        "version": manifest["version"],
        "dataset": str(args.dataset),
        "created_at": datetime.now(UTC).isoformat(),
        "protocol_sha256": protocol_hash,
        "implementation_sha256": implementation,
        "evaluation_database_sha256": manifest["evaluation_database_sha256"],
        "synthetic_withdrawal_only_in_copy": bool(
            manifest.get("withdrawal_fixture", {}).get("only_in_evaluation_copy")
        ),
        "scope": manifest["scope"],
        "new_case_count": len(cases),
        "paired_modes": list(MODES),
        "external_request_cap": MAX_REQUESTS,
        "external_requests_reported": state["external_requests_reported"],
        "development_history_overlaps": False,
        "independent_human_gold": False,
        "semantic_scores_pending": True,
        "metrics": {mode: summary([r for r in rows if r["mode"] == mode]) for mode in MODES},
        "rows": rows,
    }
    with args.output.open("x") as file:
        file.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "external_requests": report["external_requests_reported"],
                "generation_completed": {
                    m: report["metrics"][m]["completed_generation"] for m in MODES
                },
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
