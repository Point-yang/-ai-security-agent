"""Read-only dated evidence for B's collector display acceptance."""

import argparse
import json
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import httpx


def redact(value):
    if isinstance(value, dict):
        return {
            key: error_type(item) if key == "error" and item else redact(item)
            for key, item in value.items()
            if key not in {"api_key", "authorization", "headers", "proxy", "pid"}
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def error_type(value):
    match = re.search(
        r"\b(ConnectTimeout|ReadTimeout|WriteTimeout|PoolTimeout|ConnectError|ReadError|"
        r"RemoteProtocolError|ProxyError)\b|HTTP\s+\d{3}",
        str(value),
    )
    return match.group(0) if match else "source_processing_failure_redacted"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8010")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    endpoints = {
        "api": "/health/ready",
        "worker": "/api/v1/monitoring/worker",
        "monitoring": "/api/v1/monitoring",
        "operations": "/api/v1/operations/status",
        "rag": "/api/v1/rag/status",
        "window_24h": "/api/v1/monitoring/window?hours=24",
        "window_168h": "/api/v1/monitoring/window?hours=168",
        "events": "/api/v1/events?limit=1",
        "catalog": "/api/v1/catalog/items?limit=100",
    }
    results = {}
    with httpx.Client(base_url=args.base_url, trust_env=False, timeout=30) as client:
        for name, endpoint in endpoints.items():
            response = client.get(endpoint)
            response.raise_for_status()
            results[name] = redact(response.json())
    jobs = [item for item in results["monitoring"]["targets"] if item["enabled"]]
    progress = results["operations"]["collection"]["targets"]
    catalog = results["catalog"]["items"]
    summary = {
        "targets": len(jobs),
        "successful": sum(row["status"] == "completed" for row in jobs),
        "failed": sum(row["status"] == "failed" for row in jobs),
        "stale": sum(not row["fresh_within_two_intervals"] for row in progress),
        "events": results["events"]["total"],
        "chunks": results["rag"]["chunks"],
        "current_vectors": results["rag"]["current_vectors"],
        "catalog_rows": len(catalog),
        "catalog_by_origin": dict(Counter(item["origin"] for item in catalog)),
        "catalog_by_origin_source": dict(
            Counter(f"{item['origin']}:{item['source_id']}" for item in catalog)
        ),
    }
    report = {
        "checked_at": datetime.now(UTC).isoformat(),
        "method": "sequential_read_only_http_snapshot",
        "atomic_snapshot": False,
        "main_database_mutated": False,
        "cloud_generation": False,
        "error_details_redacted": True,
        "endpoints": endpoints,
        "summary": summary,
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
