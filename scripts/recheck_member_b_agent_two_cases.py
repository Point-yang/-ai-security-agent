"""Post-hoc Agent diagnosis on the two known v3 cases; never overwrite v3."""

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

DATASET = Path("config/member-b-agent-paired-v3.json")
OUTPUT = Path("docs/member-b-agent-two-case-posthoc-20260929.json")
CHECKPOINT = Path("tmp/member-b-agent-two-case-posthoc-progress.json")
CASE_IDS = ("fresh-patch-30202", "fresh-summary-46570")
MAX_EXTERNAL_REQUESTS = 14


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save_atomic(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n")
    os.replace(temporary, path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--external-model-approved", action="store_true")
    parser.add_argument("--case-id", choices=CASE_IDS, action="append")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--checkpoint", type=Path, default=CHECKPOINT)
    args = parser.parse_args()
    if not args.external_model_approved:
        parser.error(
            "this recheck sends public questions and verified excerpts to official DeepSeek"
        )
    if args.output.exists():
        parser.error(f"refusing to overwrite {args.output}")
    protocol = json.loads(DATASET.read_text())
    database = Path(protocol["evaluation_database"])
    if digest(database) != protocol["evaluation_database_sha256"]:
        parser.error("evaluation database changed")
    selected_ids = tuple(dict.fromkeys(args.case_id or CASE_IDS))
    cases = [case for case in protocol["cases"] if case["id"] in selected_ids]
    if {case["id"] for case in cases} != set(selected_ids):
        parser.error("post-hoc case IDs missing")
    implementation = hashlib.sha256(
        b"".join(
            Path(name).read_bytes()
            for name in (
                "src/zhidu/agent_tools.py",
                "src/zhidu/agent_rag.py",
                "src/zhidu/generation.py",
            )
        )
    ).hexdigest()
    if args.checkpoint.exists():
        progress = json.loads(args.checkpoint.read_text())
        if (
            progress["implementation_sha256"] != implementation
            or progress["protocol_sha256"] != digest(DATASET)
            or progress["selected_case_ids"] != list(selected_ids)
        ):
            parser.error("checkpoint belongs to another protocol, case set, or implementation")
        if progress["in_flight"] is not None:
            parser.error("a request may have been billed; inspect checkpoint before retry")
    else:
        progress = {
            "implementation_sha256": implementation,
            "protocol_sha256": digest(DATASET),
            "selected_case_ids": list(selected_ids),
            "rows": [],
            "in_flight": None,
            "external_requests_reported": 0,
        }
        save_atomic(args.checkpoint, progress)
    settings = Settings(database_url=f"sqlite:///{database.resolve()}")
    if not settings.deepseek_api_key.get_secret_value().strip():
        parser.error("official DeepSeek key is not configured")
    engine = make_engine(settings.database_url)
    encoder = LocalEncoder(settings)
    try:
        completed = {row["case_id"] for row in progress["rows"]}
        for case in cases:
            if case["id"] in completed:
                continue
            if progress["external_requests_reported"] + 7 > MAX_EXTERNAL_REQUESTS:
                parser.error("request cap reached")
            progress["in_flight"] = {
                "case_id": case["id"],
                "started_at": datetime.now(UTC).isoformat(),
            }
            save_atomic(args.checkpoint, progress)
            with make_sessions(engine)() as session:
                row = one(
                    session, BlobStore(settings.raw_dir), settings, encoder, case, "bounded_agent"
                )
            progress["rows"].append(row)
            progress["external_requests_reported"] += row["external_requests"] or 0
            progress["in_flight"] = None
            save_atomic(args.checkpoint, progress)
            print(
                json.dumps(
                    {
                        "case_id": case["id"],
                        "generation_status": row["generation_status"],
                        "generation_reason": row["generation_reason"],
                        "external_requests_reported": progress["external_requests_reported"],
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
    finally:
        encoder.close()
        engine.dispose()
    rows = progress["rows"]
    if len(rows) != len(selected_ids):
        parser.error("two-case post-hoc run incomplete")
    report = {
        "version": "member-b-agent-two-case-posthoc-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "known_cases_after_tuning": True,
        "new_holdout": False,
        "independent_human_score": False,
        "original_v3_report_sha256": digest(Path("docs/member-b-agent-paired-v3-evaluation.json")),
        "protocol_sha256": digest(DATASET),
        "evaluation_database_sha256": digest(database),
        "implementation_sha256": implementation,
        "external_request_cap": MAX_EXTERNAL_REQUESTS,
        "external_requests_reported": progress["external_requests_reported"],
        "metrics": summary(rows),
        "rows": rows,
    }
    with args.output.open("x") as file:
        file.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(str(args.output))


if __name__ == "__main__":
    main()
