"""Read-only tool-contract drill on the current local corpus; no external calls."""

import json
from pathlib import Path

from sqlalchemy import func, select

from zhidu.agent_tools import AgentToolRuntime, contracts
from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.models import Conversation, IntelEvent, RagRun
from zhidu.storage import BlobStore


def main():
    settings = Settings()
    engine = make_engine(settings.database_url)
    try:
        with make_sessions(engine)() as session:
            before = {
                "events": session.scalar(select(func.count()).select_from(IntelEvent)),
                "rag_runs": session.scalar(select(func.count()).select_from(RagRun)),
                "conversations": session.scalar(select(func.count()).select_from(Conversation)),
            }
            event = session.scalar(
                select(IntelEvent).where(
                    IntelEvent.external_id == "GHSA-2pc9-4j83-qjmr",
                    IntelEvent.source_id == "github-advisories",
                )
            )
            if event is None:
                raise RuntimeError("real corpus case is absent")
            runtime = AgentToolRuntime(session, BlobStore(settings.raw_dir), settings, None)
            search = runtime.execute("retrieve", {"query": event.external_id, "limit": 2})
            detail = runtime.execute("event_details", {"event_id": event.id})
            chunk = (
                search.get("result", {}).get("items", [{}])[0].get("citation", {}).get("chunk_id")
            )
            verification = runtime.execute("verify_evidence", {"chunk_id": chunk}) if chunk else {}
            comparison = runtime.execute("compare_sources", {"identifier": "CVE-2025-32444"})
            missing_asset = runtime.execute(
                "asset_exposure", {"asset_id": "0" * 36, "event_id": event.id}
            )
            forbidden = runtime.execute("execute_poc", {"command": "ignored"})
            after = {
                "events": session.scalar(select(func.count()).select_from(IntelEvent)),
                "rag_runs": session.scalar(select(func.count()).select_from(RagRun)),
                "conversations": session.scalar(select(func.count()).select_from(Conversation)),
            }
            checks = {
                "source_search": search["status"] == "completed"
                and bool(search["result"]["items"]),
                "current_detail": detail["status"] == "completed"
                and bool(detail["result"]["fields"]),
                "raw_evidence": verification.get("status") == "completed",
                "active_comparison": comparison["status"] == "completed"
                and bool(comparison["result"]["items"]),
                "explicit_asset_required": missing_asset.get("error") == "not_found",
                "forbidden_tool": forbidden.get("error") == "tool_not_allowed",
                "no_database_write": before == after,
                "bounded_calls": len(runtime.steps) == contracts()["limits"]["max_calls"],
            }
            report = {
                "status": "passed" if all(checks.values()) else "failed",
                "checks": checks,
                "tool_version": contracts()["version"],
                "scope": {"pool": runtime.pool, "origin": runtime.origin},
                "database_counts_before_after_equal": before == after,
                "tool_calls": len(runtime.steps),
                "output_chars": runtime.output_chars,
                "comparison_fields": [
                    item["field"] for item in comparison.get("result", {}).get("items", [])
                ],
                "note": "Current-source engineering drill; not model tool-selection or answer accuracy proof.",
            }
        output = Path("docs/member-a-agent-tools-real-audit.json")
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(report, ensure_ascii=False))
        raise SystemExit(0 if all(checks.values()) else 1)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
