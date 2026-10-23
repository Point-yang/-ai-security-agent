"""Build a read-only report of catalog-to-event candidate associations."""

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from zhidu.catalog import catalog_associations
from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.models import CatalogItem, RawDocument


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/member-a-catalog-association-report-20260930.json"),
    )
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"refusing to overwrite {args.output}")
    settings = Settings()
    engine = make_engine(settings.database_url)
    try:
        with make_sessions(engine)() as session:
            rows = (
                session.execute(
                    select(CatalogItem)
                    .join(RawDocument, RawDocument.id == CatalogItem.raw_document_id)
                    .where(RawDocument.origin == "live")
                    .order_by(CatalogItem.source_id, CatalogItem.external_id)
                )
                .scalars()
                .all()
            )
            items = [catalog_associations(session, row) for row in rows]
    finally:
        engine.dispose()
    report = {
        "version": "catalog-event-associations-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "source_metadata_only": True,
        "automatic_merge": False,
        "candidate_requires_human_review": True,
        "live_catalog_items": len(items),
        "items_with_candidates": sum(bool(item["candidates"]) for item in items),
        "candidate_associations": sum(len(item["candidates"]) for item in items),
        "items": items,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as file:
        file.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(
        json.dumps(
            {
                k: report[k]
                for k in ("live_catalog_items", "items_with_candidates", "candidate_associations")
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
