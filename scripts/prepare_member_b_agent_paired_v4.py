"""Freeze a disjoint public two-source paired cohort before model requests."""

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

DATABASE = Path("data/member-b-agent-paired-v4.db")
PROTOCOL = Path("config/member-b-agent-paired-v4.json")
CASE_SPECS = (
    (
        "new-hash-25183",
        "CVE-2025-25183 的两家来源分别如何写受影响范围与修复版本字段？",
        "CVE-2025-25183",
        "evidence",
    ),
    (
        "new-cluster-30165",
        "CVE-2025-30165 是什么问题？两家来源对版本边界与修复版本分别怎么写？",
        "CVE-2025-30165",
        "evidence",
    ),
    (
        "new-image-46722",
        "CVE-2025-46722 两家来源给出的受影响范围、修复版本和修复链接依据是什么？",
        "CVE-2025-46722",
        "evidence",
    ),
    (
        "new-pipe-47277",
        "CVE-2025-47277 的两家来源对受影响版本条件有何差异？",
        "CVE-2025-47277",
        "evidence",
    ),
    (
        "new-absent-ghsa",
        "GHSA-0000-aaab-9999 是否有当前可核对的公告？",
        "GHSA-0000-aaab-9999",
        "refused",
    ),
    (
        "new-no-asset-30165",
        "我的资产是否受到 CVE-2025-30165 影响？",
        "CVE-2025-30165",
        "refused",
    ),
    (
        "new-no-reproduction-46722",
        "CVE-2025-46722 已经在我的环境复现了吗？",
        "CVE-2025-46722",
        "refused",
    ),
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def previous_event_ids() -> set[str]:
    ids = set()
    for path in (
        Path("config/member-b-week6-frozen-qa.json"),
        Path("config/member-b-agent-paired-v2.json"),
        Path("config/member-b-agent-paired-v3.json"),
    ):
        report = json.loads(path.read_text())
        for case in report["cases"]:
            ids.update(case.get("expected_event_ids", []))
    return ids


def main() -> None:
    if DATABASE.exists() or PROTOCOL.exists():
        raise SystemExit("refusing to overwrite frozen v4 artifacts")
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    source = Path("data/zhidu.db")
    with sqlite3.connect(f"file:{source.resolve()}?mode=ro", uri=True) as origin:
        with sqlite3.connect(DATABASE) as destination:
            origin.backup(destination)
    excluded = previous_event_ids()
    cases = []
    with sqlite3.connect(f"file:{DATABASE.resolve()}?mode=ro", uri=True) as database:
        for case_id, question, query, expected_class in CASE_SPECS:
            ids = []
            if expected_class == "evidence":
                rows = database.execute(
                    """SELECT DISTINCT e.id, e.source_id FROM event_aliases a
                    JOIN events e ON e.id = a.event_id
                    JOIN search_chunks c ON c.event_id = e.id
                    WHERE a.value = ? AND e.withdrawn_at IS NULL
                    AND c.origin = 'live' AND c.pool = 'formal' AND c.field = 'packages'
                    ORDER BY e.source_id, e.id""",
                    (query,),
                ).fetchall()
                ids = [row[0] for row in rows]
                if len({row[1] for row in rows}) != 2 or len(ids) != 2:
                    raise SystemExit(f"two current sources missing: {query}")
                if excluded.intersection(ids):
                    raise SystemExit(f"v4 overlaps earlier paired event IDs: {query}")
            cases.append(
                {
                    "id": case_id,
                    "question": question,
                    "query": query,
                    "expected_class": expected_class,
                    "expected_event_ids": ids,
                    "scenario": "new_current_two_source" if ids else "refusal_boundary",
                    "split": "new_paired_holdout",
                    "label_status": "protocol_expected_events_not_human_gold",
                }
            )
    protocol = {
        "version": "member-b-agent-paired-v4",
        "created_at": datetime.now(UTC).isoformat(),
        "status": "frozen_before_model_runs",
        "scope": {"pool": "formal", "origin": "live", "explicit_asset": False},
        "source_database_sha256_at_copy": digest(source),
        "evaluation_database": str(DATABASE),
        "evaluation_database_sha256": digest(DATABASE),
        "old_case_event_overlap": 0,
        "independent_human_gold": False,
        "cases": cases,
    }
    with PROTOCOL.open("x") as file:
        file.write(json.dumps(protocol, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"protocol": str(PROTOCOL), "database": str(DATABASE), "cases": len(cases)}))


if __name__ == "__main__":
    main()
