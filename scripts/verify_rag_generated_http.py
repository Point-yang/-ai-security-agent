"""One bounded public-question HTTP generation check against the local service."""

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx

from zhidu.config import Settings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8010")
    parser.add_argument("--external-model-approved", action="store_true")
    parser.add_argument(
        "--output", type=Path, default=Path("docs/member-b-rag-live-generation-20261001.json")
    )
    args = parser.parse_args()
    if not args.external_model_approved:
        parser.error(
            "this check makes one potentially billable DeepSeek request; pass --external-model-approved"
        )
    if args.output.exists():
        parser.error(f"refusing to overwrite {args.output}")
    settings = Settings()
    key = settings.admin_key.get_secret_value().strip()
    if not key:
        parser.error("local HTTP write key is not configured")
    request = {
        "question": "CVE-2025-30202 的两个来源分别写了什么首个修复版本？",
        "query": "CVE-2025-30202",
        "mode": "hybrid",
        "generation": "deepseek",
        "top_k": 5,
    }
    with httpx.Client(timeout=60, trust_env=False, follow_redirects=False) as client:
        response = client.post(
            args.base_url.rstrip("/") + "/api/v1/rag/answers",
            headers={"X-Admin-Key": key},
            json=request,
        )
    result = response.json()
    generation = result.get("generation") or {}
    report = {
        "version": "member-b-rag-live-http-check-v1",
        "checked_at": datetime.now(UTC).isoformat(),
        "request": request,
        "http_status": response.status_code,
        "run_id": result.get("id"),
        "answer_class": result.get("answer_class"),
        "reason": result.get("reason"),
        "answer": result.get("answer"),
        "generation_status": generation.get("status"),
        "generation_reason": generation.get("reason"),
        "generation_model": result.get("generation_model"),
        "citation_checks_passed": generation.get("citation_checks_passed"),
        "citations": result.get("citations") or [],
        "elapsed_ms": result.get("elapsed_ms"),
        "external_requests": (result.get("cost") or {}).get("external_requests"),
        "billed_tokens": (result.get("cost") or {}).get("billed_tokens"),
        "scope": "one public advisory question; not accuracy or P95 proof",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as file:
        file.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(
        json.dumps(
            {
                "http_status": report["http_status"],
                "generation_status": report["generation_status"],
                "generation_reason": report["generation_reason"],
                "citations": len(report["citations"]),
                "output": str(args.output),
            },
            ensure_ascii=False,
        )
    )
    if response.status_code != 200 or generation.get("status") != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
