"""Bounded, read-only live probe of the four catalog source contracts."""

import argparse
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from zhidu.catalog import parse_catalog
from zhidu.config import Settings
from zhidu.monitor import SourceHTTP, load_targets


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("config/catalog-sources-staging.json"))
    parser.add_argument(
        "--output", type=Path, default=Path("docs/member-a-catalog-live-probe-20260930.json")
    )
    parser.add_argument("--federal-page-size", type=int, default=20)
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"refusing to overwrite {args.output}")
    settings = Settings()
    now = datetime.now(UTC)
    results = []
    for target in load_targets(args.config):
        if target.source == "federal-register-ai":
            target = target.model_copy(update={"page_size": args.federal_page_size})
        row = {"target": target.id, "source": target.source, "status": "failed"}
        try:
            page = next(SourceHTTP(settings).pages(target, now - timedelta(days=7), now, {}))
            url, content, has_next, _headers, not_modified, *_ = page
            records = parse_catalog(target.source, content)
            row.update(
                status="parsed",
                source_url=url,
                response_sha256=hashlib.sha256(content).hexdigest(),
                response_bytes=len(content),
                parsed_records=len(records),
                has_next=has_next,
                not_modified=not_modified,
                first_records=[
                    {
                        "external_id": item.data["external_id"],
                        "title": item.data["title"][:180],
                        "locator": item.locator,
                    }
                    for item in records[:30]
                ],
            )
        except Exception as exc:
            row["error_type"] = type(exc).__name__
            row["error"] = str(exc)[:300]
        results.append(row)
        print(json.dumps({k: row[k] for k in ("target", "status")}, ensure_ascii=False), flush=True)
    report = {
        "version": "catalog-live-probe-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "read_only": True,
        "database_mutated": False,
        "sources": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as file:
        file.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(str(args.output))


if __name__ == "__main__":
    main()
