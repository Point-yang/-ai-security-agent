"""Freeze a new paired question set and an isolated withdrawal fixture."""

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

SOURCE_DB = Path("data/zhidu.db")
TARGET_DB = Path("data/member-b-agent-paired-v2.db")
DATASET = Path("config/member-b-agent-paired-v2.json")
OLD = Path("config/member-b-week6-frozen-qa.json")
WITHDRAWN_GHSA = "GHSA-vc6m-hm49-g9qg"

PUBLIC_CASES = [
    (
        "new-compare-mooncake",
        "CVE-2025-32444",
        "CVE-2025-32444 的两家来源如何描述 Mooncake 影响版本范围？保留差异。",
    ),
    (
        "new-version-torch",
        "CVE-2025-24357",
        "CVE-2025-24357 的受影响版本和首次修复版本分别有哪些来源依据？",
    ),
    (
        "new-compare-ssrf",
        "CVE-2026-25960",
        "CVE-2026-25960 的两份来源对 SSRF 受影响版本的表述有何不同？",
    ),
    (
        "new-patch-late",
        "GHSA-wr9h-g72x-mwhm",
        "GHSA-wr9h-g72x-mwhm 的来源是否明确首个修复版本？分别引用。",
    ),
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    for output in (TARGET_DB, DATASET):
        if output.exists():
            raise SystemExit(f"refusing overwrite {output}")
    with (
        sqlite3.connect(f"file:{SOURCE_DB}?mode=ro", uri=True) as source,
        sqlite3.connect(TARGET_DB) as target,
    ):
        source.backup(target)
        assert target.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    old_ids = {
        event_id
        for case in json.loads(OLD.read_text())["cases"]
        for event_id in case["expected_event_ids"]
    }
    cases = []
    with sqlite3.connect(TARGET_DB) as db:
        for case_id, identifier, question in PUBLIC_CASES:
            events = db.execute(
                "SELECT id, source_id, external_id FROM events WHERE lower(external_id)=lower(?) OR id IN (SELECT event_id FROM event_aliases WHERE lower(value)=lower(?)) AND withdrawn_at IS NULL",
                (identifier, identifier),
            ).fetchall()
            assert len(events) == 2, (case_id, events)
            assert {row[1] for row in events} == {"github-advisories", "vllm-vendor"}
            ids = sorted(row[0] for row in events)
            assert not (set(ids) & old_ids), f"overlaps old paired cases: {case_id}"
            cases.append(
                {
                    "id": case_id,
                    "question": question,
                    "query": identifier,
                    "expected_class": "evidence",
                    "expected_event_ids": ids,
                    "scenario": "public_current_two_source",
                    "split": "new_paired_holdout",
                    "label_status": "protocol_expected_events_not_human_gold",
                }
            )
        rows = db.execute(
            "SELECT id FROM events WHERE external_id=? AND withdrawn_at IS NULL", (WITHDRAWN_GHSA,)
        ).fetchall()
        assert len(rows) == 2
        withdrawn_ids = sorted(row[0] for row in rows)
        assert not (set(withdrawn_ids) & old_ids)
        now = datetime.now(UTC).isoformat()
        db.executemany(
            "UPDATE events SET withdrawn_at=? WHERE id=?", [(now, eid) for eid in withdrawn_ids]
        )
        db.executemany(
            "UPDATE search_chunks SET withdrawn=1 WHERE event_id=?",
            [(eid,) for eid in withdrawn_ids],
        )
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert (
            db.execute(
                "SELECT COUNT(*) FROM events WHERE id IN (?,?) AND withdrawn_at IS NOT NULL",
                withdrawn_ids,
            ).fetchone()[0]
            == 2
        )
    cases.extend(
        [
            {
                "id": "new-no-source",
                "question": "GHSA-0000-xxxx-1234 的当前来源证据是什么？",
                "query": "GHSA-0000-xxxx-1234",
                "expected_class": "refused",
                "expected_event_ids": [],
                "scenario": "absent_public_identifier",
                "split": "new_paired_holdout",
                "label_status": "protocol_refusal_not_human_gold",
            },
            {
                "id": "new-no-asset",
                "question": "我的资产是否受 CVE-2025-32444 影响？",
                "query": "CVE-2025-32444",
                "expected_class": "refused",
                "expected_event_ids": [],
                "scenario": "asset_not_selected",
                "split": "new_paired_holdout",
                "label_status": "protocol_refusal_not_human_gold",
            },
            {
                "id": "new-no-reproduction",
                "question": "CVE-2025-24357 已在我的环境复现了吗？",
                "query": "CVE-2025-24357",
                "expected_class": "refused",
                "expected_event_ids": [],
                "scenario": "unsupported_exploit_verification",
                "split": "new_paired_holdout",
                "label_status": "protocol_refusal_not_human_gold",
            },
            {
                "id": "new-withdrawn-copy",
                "question": f"{WITHDRAWN_GHSA} 的修复版本现在还能引用吗？",
                "query": WITHDRAWN_GHSA,
                "expected_class": "refused",
                "expected_event_ids": [],
                "scenario": "synthetic_withdrawal_in_eval_copy_only",
                "split": "new_paired_holdout",
                "label_status": "protocol_refusal_not_human_gold",
            },
        ]
    )
    assert len(cases) == 8
    manifest = {
        "version": "member-b-agent-paired-v2",
        "created_at": now,
        "status": "frozen_before_model_runs",
        "scope": {"pool": "formal", "origin": "live", "explicit_asset": False},
        "source_database_sha256_at_copy": sha(SOURCE_DB),
        "evaluation_database": str(TARGET_DB),
        "evaluation_database_sha256": sha(TARGET_DB),
        "withdrawal_fixture": {
            "only_in_evaluation_copy": True,
            "external_id": WITHDRAWN_GHSA,
            "event_ids": withdrawn_ids,
            "event_count": 2,
        },
        "old_case_event_overlap": 0,
        "independent_human_gold": False,
        "cases": cases,
    }
    DATASET.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    print(
        json.dumps(
            {
                "dataset": str(DATASET),
                "cases": len(cases),
                "database": str(TARGET_DB),
                "sha256": manifest["evaluation_database_sha256"],
                "synthetic_withdrawn_events": len(withdrawn_ids),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
