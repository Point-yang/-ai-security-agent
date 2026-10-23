"""One post-hoc public case checks source-detail grounding after a fix."""

import json
from pathlib import Path

from zhidu.agent_rag import run_agent
from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.rag import RagRequest
from zhidu.semantic import LocalEncoder
from zhidu.storage import BlobStore

OUT = Path("docs/member-b-agent-v2-mooncake-diagnostic.json")


def main():
    if OUT.exists():
        raise SystemExit("refusing overwrite")
    frozen = json.loads(Path("config/member-b-agent-paired-v2.json").read_text())
    case = next(c for c in frozen["cases"] if c["id"] == "new-compare-mooncake")
    settings = Settings(database_url=f"sqlite:///{Path(frozen['evaluation_database']).resolve()}")
    engine = make_engine(settings.database_url)
    encoder = LocalEncoder(settings)
    try:
        with make_sessions(engine)() as session:
            result = run_agent(
                session,
                BlobStore(settings.raw_dir),
                settings,
                RagRequest(
                    question=case["question"],
                    query=case["query"],
                    mode="hybrid",
                    generation="agent",
                    pool="formal",
                    origin="live",
                ),
                encoder,
            )
    finally:
        encoder.close()
        engine.dispose()
    audit = {
        "case_id": case["id"],
        "post_hoc_diagnostic": True,
        "not_fresh_holdout": True,
        "model_completed": result["generation"]["status"] == "completed",
        "generation_reason": result["generation"].get("reason"),
        "citation_fields": [
            {"source": c["source_id"], "field": c["field"]} for c in result["citations"]
        ],
        "policy_steps": result["agent"].get("policy_steps", []),
        "decisions": [
            {
                "phase": d["phase"],
                "attempt": d["attempt"],
                "status": d["status"],
                "selected_tools": d["selected_tools"],
                "error": d.get("error"),
            }
            for d in result["agent"]["decisions"]
        ],
        "tool_calls": result["tool_calls"],
        "external_requests": result["cost"]["external_requests"],
        "reported_tokens": result["cost"]["billed_tokens"],
        "elapsed_ms": result["elapsed_ms"],
        "semantic_support_verified": False,
    }
    OUT.write_text(json.dumps(audit, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(audit, ensure_ascii=False))


if __name__ == "__main__":
    main()
