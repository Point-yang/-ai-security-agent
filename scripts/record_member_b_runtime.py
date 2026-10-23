"""Record a seven-day local runtime window for the member-B service.

The recorder is intentionally independent of the application database. It
samples the public read-only health/operations endpoints, records request
latency and compact operational counters, and appends each observation with
fsync so an interrupted window remains auditable.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

DEFAULT_BASE_URL = "http://127.0.0.1:8010"
DEFAULT_OUTPUT = Path("output/member-b-runtime/runtime.jsonl")
DEFAULT_INTERVAL = 300
DEFAULT_DURATION_HOURS = 168


def iso_now() -> str:
    return datetime.now(UTC).isoformat()


def request(base_url: str, path: str, timeout: float) -> dict:
    started = time.perf_counter()
    url = base_url.rstrip("/") + path
    req = urllib.request.Request(url, headers={"Accept": "application/json,text/plain"})
    try:
        # A localhost observation must never inherit a user or system HTTP proxy.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=timeout) as response:
            body = response.read()
            content_type = response.headers.get("Content-Type", "")
            try:
                decoded = body.decode("utf-8") if body else ""
            except UnicodeDecodeError:
                decoded = ""
            try:
                payload = json.loads(decoded) if decoded else None
            except json.JSONDecodeError:
                payload = None
            return {
                "path": path,
                "status_code": response.status,
                "latency_ms": round((time.perf_counter() - started) * 1000, 3),
                "content_type": content_type,
                "payload": payload,
                "raw_text": decoded if payload is None else None,
                "bytes": len(body),
            }
    except urllib.error.HTTPError as exc:
        body = exc.read()
        return {
            "path": path,
            "status_code": exc.code,
            "latency_ms": round((time.perf_counter() - started) * 1000, 3),
            "error": f"http_{exc.code}",
            "bytes": len(body),
        }
    except (OSError, TimeoutError) as exc:
        return {
            "path": path,
            "status_code": None,
            "latency_ms": round((time.perf_counter() - started) * 1000, 3),
            "error": type(exc).__name__,
        }


def compact_operations(payload: dict | None) -> dict:
    if not isinstance(payload, dict):
        return {}
    collection = payload.get("collection") or {}
    return {
        "status": payload.get("status"),
        "configured_targets": collection.get("configured_targets"),
        "targets_current": collection.get("targets_current"),
        "targets_fresh": collection.get("targets_fresh"),
        "targets_failed": collection.get("targets_failed"),
        "targets_with_pending_pages": collection.get("targets_with_pending_pages"),
        "targets": [
            {
                key: target.get(key)
                for key in (
                    "id",
                    "source_id",
                    "status",
                    "config_current",
                    "consecutive_failures",
                    "last_success_at",
                    "seconds_since_success",
                    "fresh_within_two_intervals",
                    "last_run_status",
                )
            }
            for target in collection.get("targets", [])
        ],
        "run_status_counts": collection.get("run_status_counts"),
        "run_duration": collection.get("run_duration"),
        "observed_publication_to_first_seen": collection.get("observed_publication_to_first_seen"),
        "enrichment_coverage": (payload.get("enrichment") or {}).get("coverage"),
        "integrity": payload.get("integrity"),
        "checks": payload.get("checks"),
    }


def parse_metrics(payload: str | None) -> dict:
    if not isinstance(payload, str):
        return {}
    values = {}
    pattern = re.compile(r"^(zhidu_[a-zA-Z0-9_]+)(?:\{[^}]*\})?\s+([-+0-9.eE]+)$")
    for line in payload.splitlines():
        match = pattern.match(line.strip())
        if match:
            name, value = match.groups()
            try:
                values[name] = float(value)
            except ValueError:
                continue
    return values


def sample(base_url: str, timeout: float) -> dict:
    paths = (
        "/health/live",
        "/health/ready",
        "/api/v1/operations/status",
        "/api/v1/monitoring",
        "/metrics",
    )
    responses = [request(base_url, path, timeout) for path in paths]
    by_path = {row["path"]: row for row in responses}
    ops = by_path.get("/api/v1/operations/status", {})
    metrics_response = by_path.get("/metrics", {})
    return {
        "type": "sample",
        "sampled_at": iso_now(),
        "base_url": base_url,
        "requests": [
            {key: value for key, value in row.items() if key not in {"payload", "raw_text"}}
            for row in responses
        ],
        "health": (by_path.get("/health/ready") or {}).get("payload"),
        "operations": compact_operations(ops.get("payload")),
        "metrics": parse_metrics(metrics_response.get("raw_text")),
    }


def append_jsonl(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def run(args: argparse.Namespace) -> None:
    output = args.output
    lock_path = output.with_suffix(output.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit(f"another runtime recorder owns {lock_path}") from None

        started = datetime.now(UTC)
        planned_end = started + timedelta(hours=args.duration_hours)
        append_jsonl(
            output,
            {
                "type": "run_started",
                "started_at": started.isoformat(),
                "planned_end_at": planned_end.isoformat(),
                "duration_hours": args.duration_hours,
                "interval_seconds": args.interval_seconds,
                "timeout_seconds": args.timeout_seconds,
                "base_url": args.base_url,
                "schema_version": "member-b-runtime-v1",
            },
        )
        sample_count = 0
        while True:
            now = datetime.now(UTC)
            if sample_count and now >= planned_end:
                break
            observation = sample(args.base_url, args.timeout_seconds)
            append_jsonl(output, observation)
            sample_count += 1
            if args.once or now >= planned_end:
                break
            time.sleep(max(1, args.interval_seconds))
        append_jsonl(
            output,
            {
                "type": "run_finished",
                "finished_at": iso_now(),
                "samples_written": sample_count,
                "planned_end_at": planned_end.isoformat(),
            },
        )
        print(json.dumps({"output": str(output), "samples_written": sample_count}))
        if os.environ.get("XPC_SERVICE_NAME") == "com.zhidu.member-b-runtime-v2":
            # launchctl submit infers KeepAlive. Remove this job after the fixed
            # seven-day window so it cannot silently start a second window.
            subprocess.run(
                ["launchctl", "remove", "com.zhidu.member-b-runtime-v2"],
                capture_output=True,
                check=False,
                timeout=5,
            )


def summary(path: Path) -> dict:
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    samples = [row for row in records if row.get("type") == "sample"]
    latency = {}
    status_counts = {}
    for row in samples:
        for req in row.get("requests", []):
            path_name = req["path"]
            latency.setdefault(path_name, []).append(req["latency_ms"])
            status_counts.setdefault(path_name, {})
            key = str(req.get("status_code") or req.get("error") or "unknown")
            status_counts[path_name][key] = status_counts[path_name].get(key, 0) + 1
    distributions = {}
    for path_name, values in latency.items():
        ordered = sorted(values)
        distributions[path_name] = {
            "samples": len(values),
            "min_ms": min(values),
            "max_ms": max(values),
            "p50_ms": ordered[(len(ordered) - 1) // 2],
            "p95_ms": ordered[max(0, int(len(ordered) * 0.95) - 1)],
            "status_counts": status_counts[path_name],
        }
    result = {
        "schema_version": "member-b-runtime-summary-v1",
        "source": str(path),
        "records": len(records),
        "samples": len(samples),
        "started_at": next(
            (r.get("started_at") for r in records if r.get("type") == "run_started"), None
        ),
        "finished_at": next(
            (r.get("finished_at") for r in reversed(records) if r.get("type") == "run_finished"),
            None,
        ),
        "request_latency": distributions,
        "latest_operations": samples[-1].get("operations") if samples else None,
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--interval-seconds", type=int, default=DEFAULT_INTERVAL)
    parser.add_argument("--duration-hours", type=float, default=DEFAULT_DURATION_HOURS)
    parser.add_argument("--timeout-seconds", type=float, default=15)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()
    if args.summary:
        print(json.dumps(summary(args.output), ensure_ascii=False, indent=2))
        return
    run(args)


if __name__ == "__main__":
    main()
