"""Collect a fixed, fresh public advisory group without touching the main corpus.

Four preselected packages, at most eight anonymous GETs, no retries or redirects.
The output is a source intake packet, not a question set or an answer gold set.
"""

import argparse
import hashlib
import json
import re
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

PACKAGES = ("torch", "transformers", "ray", "mlflow")
IDENTIFIER = re.compile(r"CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.I)
TEXT_SUFFIXES = {".json", ".jsonl", ".md", ".py", ".csv", ".txt"}
GITHUB_URL = "https://api.github.com/advisories"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def utc_now():
    return datetime.now(UTC).isoformat()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def freeze_exclusions(project, database, output):
    """Read existing identifiers before any public collection or output exists."""
    identifiers = set()
    with sqlite3.connect(f"file:{database.resolve()}?mode=ro", uri=True) as connection:
        connection.execute("begin")
        for table, column in (("events", "external_id"), ("event_aliases", "value")):
            identifiers.update(
                match.casefold()
                for (value,) in connection.execute(f"select {column} from {table}")
                for match in IDENTIFIER.findall(value or "")
            )
        counts = {
            table: connection.execute(f"select count(*) from {table}").fetchone()[0]
            for table in ("events", "event_aliases")
        }
        connection.rollback()
    db_identifiers = sorted(identifiers)
    files = []
    for root in ("config", "docs", "tests", "scripts", "output", "data/week6-ai-gold"):
        for path in sorted((project / root).rglob("*")):
            if not path.is_file() or path.suffix not in TEXT_SUFFIXES:
                continue
            if (
                path.resolve() == Path(__file__).resolve()
                or output.resolve() in path.resolve().parents
            ):
                continue
            body = path.read_bytes()
            matches = {
                value.casefold() for value in IDENTIFIER.findall(body.decode(errors="ignore"))
            }
            identifiers.update(matches)
            files.append(
                {
                    "path": str(path.relative_to(project)),
                    "sha256": sha256(body),
                    "identifiers": sorted(matches),
                }
            )
    exclusions = {
        "frozen_at": utc_now(),
        "database_path": str(database.resolve()),
        "database_counts": counts,
        "database_identifiers": db_identifiers,
        "identifiers": sorted(identifiers),
        "history_files": files,
        "scope": "all main event external IDs and aliases, plus prior project text; public CVE/GHSA only",
    }
    write_json(output / "exclusions.json", exclusions)
    return identifiers, sha256((output / "exclusions.json").read_bytes())


def advisory_identifiers(advisory):
    values = {advisory.get("ghsa_id"), advisory.get("cve_id")}
    values.update(item.get("value") for item in advisory.get("identifiers", []))
    return sorted(value.casefold() for value in values if value and IDENTIFIER.fullmatch(value))


def select_advisory(response, package, exclusions):
    assessments = []
    chosen = None
    for rank, advisory in enumerate(response, start=1):
        reasons = []
        identifiers = advisory_identifiers(advisory)
        if advisory.get("withdrawn_at"):
            reasons.append("withdrawn")
        if not advisory.get("cve_id") or not re.fullmatch(
            r"CVE-\d{4}-\d{4,}", advisory["cve_id"], re.I
        ):
            reasons.append("no_valid_cve")
        prior = sorted(set(identifiers) & exclusions)
        if prior:
            reasons.append("already_in_main_or_project_history")
        matching = [
            item
            for item in advisory.get("vulnerabilities", [])
            if item.get("package", {}).get("ecosystem") == "pip"
            and item.get("package", {}).get("name", "").casefold() == package.casefold()
        ]
        if not matching:
            reasons.append("no_exact_requested_pip_package")
        selected = not reasons and chosen is None
        assessments.append(
            {
                "response_rank": rank,
                "ghsa_id": advisory.get("ghsa_id"),
                "cve_id": advisory.get("cve_id"),
                "identifiers": identifiers,
                "published_at": advisory.get("published_at"),
                "withdrawn_at": advisory.get("withdrawn_at"),
                "excluded_identifiers": prior,
                "rejection_reasons": reasons,
                "selected": selected,
                "decision": "first_eligible_in_published_descending_response"
                if selected
                else "rejected"
                if reasons
                else "later_eligible_not_selected",
            }
        )
        if selected:
            chosen = advisory
    return chosen, assessments


def fetch(client, url, params, output, name, attempts):
    if len(attempts) >= 8:
        raise RuntimeError("public_request_limit_exceeded")
    request = client.build_request("GET", url, params=params)
    record = {
        "attempt": len(attempts) + 1,
        "method": "GET",
        "url": str(request.url),
        "started_at": utc_now(),
        "automatic_retries": 0,
        "follow_redirects": False,
    }
    attempts.append(record)
    started = time.monotonic()
    parsed = None
    try:
        response = client.send(request)
        # Content is the exact decoded HTTP response entity, before JSON parsing.
        body = response.content
        raw_path = output / "raw" / (name + ".json")
        raw_path.write_bytes(body)
        record.update(
            {
                "http_status": response.status_code,
                "raw_path": str(raw_path.relative_to(output)),
                "sha256": sha256(body),
                "bytes": len(body),
                "content_type": response.headers.get("content-type"),
                "response_date": response.headers.get("date"),
                "github_rate_limit_remaining": response.headers.get("x-ratelimit-remaining"),
            }
        )
        if response.status_code != 200:
            record["state"] = "interface_error"
            record["error"] = f"http_{response.status_code}"
        else:
            try:
                parsed = response.json()
                record["state"] = "response_received"
            except ValueError:
                record["state"] = "invalid_response"
                record["error"] = "invalid_json"
    except httpx.HTTPError as error:
        record.update(
            {"state": "interface_error", "http_status": None, "error": type(error).__name__}
        )
    record.update(
        {"finished_at": utc_now(), "elapsed_seconds": round(time.monotonic() - started, 3)}
    )
    return parsed, record


def collect(project, database, output):
    output.mkdir(parents=True, exist_ok=False)
    (output / "raw").mkdir()
    exclusions, exclusion_sha = freeze_exclusions(project, database, output)
    manifest = {
        "schema_version": "fresh-public-source-intake-v1",
        "created_at": utc_now(),
        "packages_preselected": list(PACKAGES),
        "exclusions_sha256": exclusion_sha,
        "policy": {
            "maximum_anonymous_gets": 8,
            "automatic_retries": 0,
            "domains": ["api.github.com", "services.nvd.nist.gov"],
            "nvd_minimum_start_interval_seconds": 7,
            "github_page_size": 5,
            "github_sort": "published desc",
            "credentials_sent": False,
            "main_database_modified": False,
            "model_calls": 0,
            "poc_execution": False,
            "selection": "first unwithdrawn exact pip package with CVE and no identifier in exclusions",
            "insufficient_second_source": "intake status only; never equated with no public data",
        },
        "requests": [],
        "groups": [],
    }
    write_json(output / "manifest.json", manifest)
    with httpx.Client(
        timeout=30,
        follow_redirects=False,
        trust_env=False,
        headers={
            "Accept": "application/json",
            "User-Agent": "zhidu-public-source-intake/1.0",
            "Accept-Encoding": "identity",
        },
    ) as client:
        selected = []
        for package in PACKAGES:
            response, record = fetch(
                client,
                GITHUB_URL,
                {
                    "ecosystem": "pip",
                    "affects": package,
                    "sort": "published",
                    "direction": "desc",
                    "per_page": 5,
                },
                output,
                "github-" + package,
                manifest["requests"],
            )
            group = {
                "package": package,
                "github_request_attempt": record["attempt"],
                "github_raw_path": record.get("raw_path"),
                "github_sha256": record.get("sha256"),
                "second_source_state": "not_attempted",
                "two_public_sources_available": False,
            }
            if isinstance(response, list) and all(isinstance(item, dict) for item in response):
                chosen, assessments = select_advisory(response, package, exclusions)
                group["candidate_assessments"] = assessments
                if chosen:
                    group.update(
                        {
                            "selection_state": "selected",
                            "cve_id": chosen["cve_id"],
                            "ghsa_id": chosen["ghsa_id"],
                            "github_response_pointer": "/"
                            + str(next(i for i, item in enumerate(response) if item is chosen)),
                            "selection_reason": "first eligible record in the fixed latest-five response; no complexity-based replacement",
                        }
                    )
                    selected.append(group)
                else:
                    group["selection_state"] = "no_eligible_record_within_latest_five"
            else:
                group["selection_state"] = (
                    record["state"] if response is None else "invalid_response_shape"
                )
            manifest["groups"].append(group)
            write_json(output / "manifest.json", manifest)
        previous_nvd_start = None
        for group in selected:
            if previous_nvd_start is not None:
                time.sleep(max(0, 7 - (time.monotonic() - previous_nvd_start)))
            previous_nvd_start = time.monotonic()
            response, record = fetch(
                client,
                NVD_URL,
                {"cveId": group["cve_id"]},
                output,
                "nvd-" + group["package"],
                manifest["requests"],
            )
            group.update(
                {
                    "nvd_request_attempt": record["attempt"],
                    "nvd_raw_path": record.get("raw_path"),
                    "nvd_sha256": record.get("sha256"),
                }
            )
            if isinstance(response, dict) and isinstance(response.get("vulnerabilities"), list):
                matches = [
                    (i, item["cve"])
                    for i, item in enumerate(response["vulnerabilities"])
                    if isinstance(item, dict)
                    and isinstance(item.get("cve"), dict)
                    and item["cve"].get("id", "").casefold() == group["cve_id"].casefold()
                ]
                if len(matches) == 1:
                    index, cve = matches[0]
                    group.update(
                        {
                            "second_source_state": "source_received",
                            "two_public_sources_available": True,
                            "nvd_response_pointer": f"/vulnerabilities/{index}/cve",
                            "nvd_vulnerability_status": cve.get("vulnStatus"),
                        }
                    )
                else:
                    group["second_source_state"] = (
                        "requested_identifier_not_uniquely_present_in_response"
                    )
            else:
                group["second_source_state"] = (
                    record["state"] if response is None else "invalid_response_shape"
                )
            write_json(output / "manifest.json", manifest)
    manifest.update(
        {
            "finished_at": utc_now(),
            "request_count": len(manifest["requests"]),
            "selected_groups": len(selected),
            "groups_with_two_sources": sum(
                group["two_public_sources_available"] for group in manifest["groups"]
            ),
            "gold_authored": False,
            "agent_run": False,
        }
    )
    write_json(output / "manifest.json", manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--database", type=Path, default=Path("data/zhidu.db"))
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="new directory; existing output is never overwritten",
    )
    args = parser.parse_args()
    project = args.project.resolve()
    database = args.database if args.database.is_absolute() else project / args.database
    output = args.output if args.output.is_absolute() else project / args.output
    manifest = collect(project, database, output)
    print(
        json.dumps(
            {
                key: manifest[key]
                for key in ("request_count", "selected_groups", "groups_with_two_sources")
            },
            ensure_ascii=False,
        )
    )
    for group in manifest["groups"]:
        print(
            json.dumps(
                {
                    key: group.get(key)
                    for key in (
                        "package",
                        "selection_state",
                        "cve_id",
                        "ghsa_id",
                        "second_source_state",
                    )
                },
                ensure_ascii=False,
            )
        )


if __name__ == "__main__":
    main()
