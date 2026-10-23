"""Read-only operational audit and current-code source-fact regression evaluation."""

import argparse
import hashlib
import importlib.util
import json
import math
import sqlite3
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from zoneinfo import ZoneInfo

from zhidu.enrichment import ENRICHMENT_SCHEMA_VERSION, build_enrichment
from zhidu.gold_review import validate_seal
from zhidu.monitor import load_targets
from zhidu.sources import resolve_pointer

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "source_fact_protocol", ROOT / "scripts/review_week6_sources.py"
)
facts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(facts)
TZ = ZoneInfo("Asia/Shanghai")
CORE_SOURCES = {"cisa-kev", "crossref", "github-advisories", "nvd", "vllm-vendor"}


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dt(value):
    if not value:
        return None
    result = datetime.fromisoformat(value)
    return result.replace(tzinfo=UTC) if result.tzinfo is None else result.astimezone(UTC)


def distribution(values):
    ordered = sorted(values)
    if not ordered:
        return {"samples": 0, "p50": None, "p95": None, "max": None}
    return {
        "samples": len(ordered),
        "min": ordered[0],
        "p50": ordered[math.ceil(len(ordered) * 0.50) - 1],
        "p95": ordered[math.ceil(len(ordered) * 0.95) - 1],
        "max": ordered[-1],
    }


def summarize(rows):
    result = facts.aggregate(rows)
    groups = {r["group_id"] for r in rows if r.get("group_id")}
    recalls = [
        facts.aggregate([r for r in rows if r.get("group_id") == group])["fact_recall"]
        for group in groups
    ]
    result["group_macro_recall"] = (
        sum(v for v in recalls if v is not None) / len(recalls) if recalls else None
    )
    result["by_source"] = {
        source: facts.aggregate([r for r in rows if r["source_id"] == source])
        for source in sorted({r["source_id"] for r in rows})
    }
    result["non_paper_source_facts"] = facts.aggregate(
        [r for r in rows if r["source_id"] != "crossref"]
    )
    return result


class SourceStore:
    def __init__(self, connection):
        self.connection = connection
        self.cache = {}

    def record(self, revision):
        document = self.connection.execute(
            "SELECT * FROM raw_documents WHERE id=?", (revision["raw_document_id"],)
        ).fetchone()
        digest = document["sha256"]
        if digest not in self.cache:
            path = ROOT / "data/raw" / digest[:2] / (digest + ".json")
            if sha(path) != digest:
                raise ValueError("Raw file checksum mismatch: " + digest)
            self.cache[digest] = read(path)
        return document, resolve_pointer(self.cache[digest], revision["record_pointer"])


def frozen_enrichment(connection, store, packet, gold):
    labels = {r["task_id"]: r for r in gold["labels"]}
    tasks = {r["id"]: r for r in packet["tasks"]}
    rows, predictions = [], []
    for record in packet["records"]:
        revision = connection.execute(
            "SELECT * FROM event_revisions WHERE id=?", (record["revision_id"],)
        ).fetchone()
        if not revision or revision["event_id"] != record["event_id"]:
            raise ValueError("Missing/wrong frozen revision: " + record["event_id"])
        document, raw = store.record(revision)
        if (
            document["sha256"] != record["sha256"]
            or document["id"] != record["raw_document_id"]
            or revision["record_pointer"] != record["record_pointer"]
            or raw != record["raw_record"]
        ):
            raise ValueError("Frozen input changed: " + record["event_id"])
        label = labels[record["event_id"]]
        for citation in label["citations"]:
            value = resolve_pointer(raw, citation["pointer"])
            text = value if isinstance(value, str) else facts.encoded(value)
            if text != citation["quote"]:
                raise ValueError("Frozen reference quote mismatch")
        normalized = json.loads(revision["normalized"])
        prediction = build_enrichment(
            SimpleNamespace(source_id=record["source_id"], kind=normalized["kind"]),
            SimpleNamespace(
                normalized=normalized,
                evidence=json.loads(revision["evidence"]),
                record_pointer=revision["record_pointer"],
            ),
            SimpleNamespace(id=document["id"]),
            raw,
        )
        expected = [v["fact"] for v in label["enrichment_facts"]]
        actual = facts.prediction_facts(prediction)
        task = tasks[record["event_id"]]
        rows.append(
            {
                "task_id": record["event_id"],
                "source_id": record["source_id"],
                "external_id": record["external_id"],
                "split": task["split"],
                "group_id": task["group_id"],
                "revision_id": revision["id"],
                "source_sha256": document["sha256"],
                **facts.score_sets(expected, actual),
            }
        )
        predictions.append({"task_id": record["event_id"], "prediction": prediction})
    return {
        "schema_version": ENRICHMENT_SCHEMA_VERSION,
        "method": "current_enrichment_code_on_immutable_frozen_inputs",
        "reference_method": gold["review_method"],
        "reference_independent": gold["independent_review_attested"],
        "test": summarize([r for r in rows if r["split"] == "test"]),
        "all_splits_diagnostic": summarize(rows),
        "rows": rows,
        "limitations": [
            "This is regression on previously observed examples, not a new blind test.",
            "AI reference adopted by the project; not independent human review.",
            "Evaluates source-asserted structured facts; not full-answer meaning, vulnerability truth, version comparison or paper/POC relevance.",
            "Crossref scores only DOI; non-paper metrics are also reported.",
        ],
    }, predictions


def current_enrichment(connection, store):
    rows = []
    for event in connection.execute("SELECT * FROM events ORDER BY id").fetchall():
        if event["source_id"] not in CORE_SOURCES:
            continue
        revision = connection.execute(
            "SELECT * FROM event_revisions WHERE event_id=? AND number=?",
            (event["id"], event["revision"]),
        ).fetchone()
        document, raw = store.record(revision)
        enrichment = connection.execute(
            "SELECT * FROM event_enrichments WHERE event_id=?", (event["id"],)
        ).fetchone()
        stale = bool(enrichment and enrichment["revision_id"] != revision["id"])
        prediction = (
            {
                k: json.loads(enrichment[k])
                for k in ("entities", "version_ranges", "cvss", "cpe_matches")
            }
            if enrichment and not stale
            else None
        )
        expected = [
            v["fact"]
            for v in facts.source_facts(
                {"event_id": event["id"], "source_id": event["source_id"], "raw_record": raw}
            )
        ]
        rows.append(
            {
                "event_id": event["id"],
                "source_id": event["source_id"],
                "external_id": event["external_id"],
                "revision_id": revision["id"],
                "source_sha256": document["sha256"],
                "origin": document["origin"],
                "missing_prediction": prediction is None,
                "stale_prediction": stale,
                **facts.score_sets(expected, facts.prediction_facts(prediction)),
            }
        )
    return {
        "method": "current_database_against_separate_source_fact_reader",
        "metrics": summarize(rows),
        "live_only": summarize([r for r in rows if r["origin"] == "live"]),
        "rows": rows,
        "limitations": [
            "Automated source conformity check, not independent gold or semantic accuracy.",
            "Reference reader has known scope limits; set differences require source inspection.",
            "Catalog metadata, semantic paper/POC links, asset matching and parsed version logic are not scored.",
        ],
    }


def latency_summary(rows):
    eligible = [r for r in rows if r["classification"] == "new_publication"]
    values = [r["delay_hours"] for r in eligible]
    return {
        **distribution(values),
        "unit": "hours",
        "within_6h": sum(v <= 6 for v in values),
        "within_12h": sum(v <= 12 for v in values),
        "within_24h": sum(v <= 24 for v in values),
        "over_24h": sum(v > 24 for v in values),
        "first_seen_after_window_end": sum(r["seen_after_window_end"] for r in eligible),
        "classifications": dict(Counter(r["classification"] for r in rows)),
    }


def monitoring(connection, store, runtime, config):
    records = [json.loads(line) for line in runtime.read_text().splitlines() if line]
    start = next(r for r in records if r["type"] == "run_started")
    finish = next((r for r in reversed(records) if r["type"] == "run_finished"), None)
    begin, end = dt(start["started_at"]), dt(start["planned_end_at"])
    samples = [r for r in records if r["type"] == "sample"]
    times = [dt(r["sampled_at"]) for r in samples]
    gaps = [
        {
            "from": a.astimezone(TZ).isoformat(),
            "to": b.astimezone(TZ).isoformat(),
            "hours": (b - a).total_seconds() / 3600,
        }
        for a, b in zip(times, times[1:], strict=False)
        if (b - a).total_seconds() > start["interval_seconds"] * 2
    ]
    requests = {}
    for path in sorted({v["path"] for r in samples for v in r["requests"]}):
        request_rows = [v for r in samples for v in r["requests"] if v["path"] == path]
        requests[path] = {
            "statuses": dict(
                Counter(str(v.get("status_code") or v.get("error")) for v in request_rows)
            ),
            "latency_ms": distribution([v["latency_ms"] for v in request_rows]),
        }
    runs = [
        dict(r)
        for r in connection.execute("SELECT * FROM collection_runs WHERE scope LIKE 'monitor:%'")
    ]
    window_runs = [r for r in runs if begin <= dt(r["started_at"]) < end]
    for run in window_runs:
        run["status_at_window_end"] = (
            run["status"]
            if run["finished_at"] and dt(run["finished_at"]) <= end
            else "unfinished_at_window_end"
        )
    targets = []
    for target in load_targets(config):
        target_runs = [r for r in runs if r["scope"].split(":")[1] == target.id]
        selected = [r for r in window_runs if r["scope"].split(":")[1] == target.id]
        horizon = max(target.interval_seconds * 2, 600)
        spans = []
        for run in sorted(
            (r for r in target_runs if r["status"] == "completed" and r["finished_at"]),
            key=lambda r: dt(r["finished_at"]),
        ):
            left, right = (
                max(begin, dt(run["finished_at"])),
                min(end, dt(run["finished_at"]) + timedelta(seconds=horizon)),
            )
            if right <= left:
                continue
            if spans and left <= spans[-1][1]:
                spans[-1][1] = max(right, spans[-1][1])
            else:
                spans.append([left, right])
        covered = sum((b - a).total_seconds() for a, b in spans)
        targets.append(
            {
                "target_id": target.id,
                "status_counts": dict(Counter(r["status_at_window_end"] for r in selected)),
                "freshness_coverage": covered / (end - begin).total_seconds(),
                "horizon_seconds_from_current_config": horizon,
                "config_hashes_seen": sorted({r["scope"].split(":")[2] for r in selected}),
            }
        )
    delay_rows = []
    for event in connection.execute("SELECT * FROM events ORDER BY id").fetchall():
        revision = connection.execute(
            "SELECT * FROM event_revisions WHERE event_id=? ORDER BY number LIMIT 1", (event["id"],)
        ).fetchone()
        document, _ = store.record(revision)
        normalized = json.loads(revision["normalized"])
        published = dt(normalized.get("published_at"))
        seen = dt(event["first_seen_at"])
        if not (begin <= seen < end or published and begin <= published < end):
            continue
        if document["origin"] != "live":
            classification = "replay"
        elif not published:
            classification = "missing_publication_time"
        elif published > seen:
            classification = "publication_after_observation"
        elif published < begin:
            classification = "historical_backfill"
        elif published >= end:
            classification = "outside_publication_window"
        else:
            classification = "new_publication"
        delay_rows.append(
            {
                "event_id": event["id"],
                "source_id": event["source_id"],
                "external_id": event["external_id"],
                "kind": event["kind"],
                "source_url": event["source_url"],
                "raw_sha256": document["sha256"],
                "published_at_first_revision": published.isoformat() if published else None,
                "first_seen_at": seen.isoformat(),
                "classification": classification,
                "seen_after_window_end": seen >= end,
                "delay_hours": (seen - published).total_seconds() / 3600
                if classification == "new_publication"
                else None,
            }
        )
    vulnerability_rows = [
        r for r in delay_rows if r["kind"] in {"vulnerability", "exploitation_alert"}
    ]
    return {
        "window_start_beijing": begin.astimezone(TZ).isoformat(),
        "window_end_beijing": end.astimezone(TZ).isoformat(),
        "recorder_finished": finish is not None,
        "runtime_sha256": sha(runtime),
        "samples": len(samples),
        "expected_nominal_samples": math.ceil(
            (end - begin).total_seconds() / start["interval_seconds"]
        ),
        "gaps_over_two_intervals": len(gaps),
        "largest_gaps": sorted(gaps, key=lambda r: -r["hours"])[:10],
        "requests": requests,
        "operational_status_samples": dict(
            Counter((r.get("operations") or {}).get("status", "missing") for r in samples)
        ),
        "poll_status_counts": dict(Counter(r["status_at_window_end"] for r in window_runs)),
        "poll_errors": dict(Counter(r["error"] for r in window_runs if r["error"])),
        "targets": targets,
        "discovery_delay": {
            "all_event_sources": latency_summary(delay_rows),
            "vulnerability_and_kev": latency_summary(vulnerability_rows),
            "by_source": {
                s: latency_summary([r for r in delay_rows if r["source_id"] == s])
                for s in sorted({r["source_id"] for r in delay_rows})
            },
        },
        "delay_rows": delay_rows,
        "runs": window_runs,
        "acceptance_status": "not_accepted",
        "limitations": [
            "Discovery delay includes only records eventually observed by this database; unobserved upstream publications are unknown, so collection recall cannot be calculated.",
            "Latency uses the provider publication timestamp stored in the first source revision; provider indexing lag and original vendor publication time are not independently verified.",
            "Source-record counts retain mirrors/duplicates; they are not unique vulnerability counts.",
            "Paper dates may have day/month granularity and are separately reported.",
            "Poll coverage reconstruction uses current configured horizons and merges known historical scopes; target configuration changed during the window.",
            "Missing samples are unknown intervals, not measured downtime; observed HTTP success is not continuous uptime.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=ROOT / "data/zhidu.db")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    snapshot = args.output / "evaluation-snapshot.sqlite"
    source = sqlite3.connect(f"file:{args.database.resolve()}?mode=ro", uri=True)
    destination = sqlite3.connect(snapshot)
    source.backup(destination)
    destination.close()
    source.close()
    connection = sqlite3.connect(f"file:{snapshot.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise ValueError("Snapshot integrity failed")
    store = SourceStore(connection)
    packet = read(ROOT / "data/week6-human-review/source-packet.json")
    gold = read(ROOT / "data/week6-ai-gold/project-gold-v1.json")
    validate_seal(packet)
    validate_seal(gold)
    if packet["sha256"] != gold["packet_sha256"]:
        raise ValueError("Gold packet mismatch")
    frozen, predictions = frozen_enrichment(connection, store, packet, gold)
    current = current_enrichment(connection, store)
    monitor = monitoring(
        connection,
        store,
        ROOT / "output/member-b-runtime/runtime-7day.jsonl",
        ROOT / "config/sources.json",
    )
    connection.close()
    write(args.output / "frozen-enrichment.json", frozen)
    write(args.output / "frozen-predictions.json", predictions)
    write(args.output / "current-source-conformity.json", current)
    write(args.output / "monitoring-evaluation.json", monitor)
    write(
        args.output / "manifest.json",
        {
            "checked_at_beijing": datetime.now(TZ).isoformat(),
            "schema_version": ENRICHMENT_SCHEMA_VERSION,
            "snapshot_sha256": sha(snapshot),
            "packet_sha256": packet["sha256"],
            "reference_sha256": gold["sha256"],
            "evaluator_sha256": sha(Path(__file__)),
            "fact_protocol_sha256": sha(ROOT / "scripts/review_week6_sources.py"),
            "raw_documents_verified": len(store.cache),
            "production_database_modified": False,
        },
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "frozen_test": frozen["test"],
                "all_frozen": frozen["all_splits_diagnostic"],
                "current": current["metrics"],
                "discovery_delay": monitor["discovery_delay"],
                "poll_status_counts": monitor["poll_status_counts"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
