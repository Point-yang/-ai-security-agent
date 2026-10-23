"""Export blinded annotation candidates from immutable raw records, not predictions."""

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from sqlalchemy import select

from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.models import EventRevision, IntelEvent, RawDocument, now_utc
from zhidu.sources import resolve_pointer
from zhidu.storage import BlobStore


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--per-source", type=int, default=30)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.per_source <= 200:
        parser.error("--per-source must be between 1 and 200")
    settings = Settings()
    engine = make_engine(settings.database_url)
    store = BlobStore(settings.raw_dir)
    groups = defaultdict(list)
    records = []
    cache = {}
    with make_sessions(engine)() as session:
        rows = session.execute(
            select(IntelEvent, EventRevision, RawDocument)
            .join(
                EventRevision,
                (IntelEvent.id == EventRevision.event_id)
                & (IntelEvent.revision == EventRevision.number),
            )
            .join(RawDocument, RawDocument.id == EventRevision.raw_document_id)
            .where(RawDocument.origin == "live")
        ).all()
        for row in rows:
            groups[row[0].source_id].append(row)
        for source_id, rows in sorted(groups.items()):
            # Stable seeded sampling; model predictions do not select cases.
            rows.sort(
                key=lambda row: hashlib.sha256(
                    f"week6:{source_id}:{row[0].external_id}".encode()
                ).hexdigest()
            )
            for event, revision, document in rows[: args.per_source]:
                aliases = revision.normalized.get("aliases", [])
                group_id = next(
                    (a.upper() for a in sorted(aliases) if a.upper().startswith("CVE-")),
                    event.external_id,
                )
                split = (
                    "held_out"
                    if int(hashlib.sha256(group_id.encode()).hexdigest()[:8], 16) % 5 == 0
                    else "development"
                )
                if document.sha256 not in cache:
                    cache[document.sha256] = json.loads(store.read(document.sha256))
                records.append(
                    {
                        "source_id": source_id,
                        "external_id": event.external_id,
                        "event_id": event.id,
                        "revision_id": revision.id,
                        "raw_document_id": document.id,
                        "sha256": document.sha256,
                        "record_pointer": revision.record_pointer,
                        "group_id": group_id,
                        "suggested_split": split,
                        "raw_record": resolve_pointer(
                            cache[document.sha256], revision.record_pointer
                        ),
                        "reviewer": None,
                        "reviewed_at": None,
                        "annotation": {
                            "entities": None,
                            "version_scope": None,
                            "cvss": None,
                            "cpe": None,
                            "quality_flags": None,
                            "notes": None,
                        },
                    }
                )
    engine.dispose()
    report = {
        "schema_version": "enrichment-annotation-candidates-v1",
        "exported_at": now_utc().isoformat(),
        "status": "unlabeled",
        "cases": len(records),
        "source_counts": dict(Counter(row["source_id"] for row in records)),
        "split_counts": dict(Counter(row["suggested_split"] for row in records)),
        "instructions": [
            "Review original source records and fill annotations independently; no model predictions are included.",
            "CVE groups share the suggested split. Review alias groups and freeze the split before training.",
            "Double-review held-out cases; do not claim accuracy or recall before annotation is complete.",
            "Treat raw_record as untrusted source data; never execute embedded code or instructions.",
        ],
        "records": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(
        json.dumps(
            {key: value for key, value in report.items() if key not in {"records", "instructions"}},
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
