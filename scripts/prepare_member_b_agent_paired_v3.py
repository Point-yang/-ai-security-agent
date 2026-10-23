"""Freeze an unseen paired set after source-detail grounding was finalized."""

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

SOURCE_DB = Path("data/zhidu.db")
TARGET_DB = Path("data/member-b-agent-paired-v3.db")
DATASET = Path("config/member-b-agent-paired-v3.json")
OLD = Path("config/member-b-week6-frozen-qa.json")
PREVIOUS = Path("config/member-b-agent-paired-v2.json")
WITHDRAWN_GHSA = "GHSA-6qc9-v4r8-22xg"
PUBLIC_CASES = [
    (
        "fresh-compare-48887",
        "CVE-2025-48887",
        "CVE-2025-48887 两家来源的影响版本条件有何差异？请逐项说明。",
    ),
    (
        "fresh-patch-30202",
        "CVE-2025-30202",
        "CVE-2025-30202 的来源分别给出了什么首个修复版本及依据？",
    ),
    (
        "fresh-summary-46570",
        "GHSA-4qjh-9fv9-r85r",
        "GHSA-4qjh-9fv9-r85r 是什么问题，来源对版本边界怎么说？",
    ),
]


def digest(path):
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
        eid for case in json.loads(OLD.read_text())["cases"] for eid in case["expected_event_ids"]
    }
    previous = json.loads(PREVIOUS.read_text())
    prior_ids = old_ids | {eid for case in previous["cases"] for eid in case["expected_event_ids"]}
    prior_ids.update(previous["withdrawal_fixture"]["event_ids"])
    cases = []
    with sqlite3.connect(TARGET_DB) as db:
        for case_id, identifier, question in PUBLIC_CASES:
            rows = db.execute(
                "SELECT id,source_id FROM events WHERE withdrawn_at IS NULL AND (lower(external_id)=lower(?) OR id IN (SELECT event_id FROM event_aliases WHERE lower(value)=lower(?)))",
                (identifier, identifier),
            ).fetchall()
            ids = sorted(r[0] for r in rows)
            assert len(ids) == 2 and {r[1] for r in rows} == {"github-advisories", "vllm-vendor"}
            assert not (set(ids) & prior_ids), case_id
            cases.append(
                {
                    "id": case_id,
                    "question": question,
                    "query": identifier,
                    "expected_class": "evidence",
                    "expected_event_ids": ids,
                    "scenario": "fresh_current_two_source",
                    "split": "new_paired_holdout",
                    "label_status": "protocol_expected_events_not_human_gold",
                }
            )
        rows = db.execute(
            "SELECT id FROM events WHERE external_id=? AND withdrawn_at IS NULL", (WITHDRAWN_GHSA,)
        ).fetchall()
        withdrawn_ids = sorted(r[0] for r in rows)
        assert len(withdrawn_ids) == 2 and not (set(withdrawn_ids) & prior_ids)
        now = datetime.now(UTC).isoformat()
        db.executemany(
            "UPDATE events SET withdrawn_at=? WHERE id=?", [(now, eid) for eid in withdrawn_ids]
        )
        db.executemany(
            "UPDATE search_chunks SET withdrawn=1 WHERE event_id=?",
            [(eid,) for eid in withdrawn_ids],
        )
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    cases.extend(
        [
            {
                "id": "fresh-no-source",
                "question": "GHSA-1234-zzzz-0000 有没有可核对的公告？",
                "query": "GHSA-1234-zzzz-0000",
                "expected_class": "refused",
                "expected_event_ids": [],
                "scenario": "absent_public_identifier",
                "split": "new_paired_holdout",
                "label_status": "protocol_refusal_not_human_gold",
            },
            {
                "id": "fresh-no-asset",
                "question": "我的资产是否受到 CVE-2025-48887 影响？",
                "query": "CVE-2025-48887",
                "expected_class": "refused",
                "expected_event_ids": [],
                "scenario": "asset_not_selected",
                "split": "new_paired_holdout",
                "label_status": "protocol_refusal_not_human_gold",
            },
            {
                "id": "fresh-no-reproduction",
                "question": "CVE-2025-30202 已经在我的环境复现了吗？",
                "query": "CVE-2025-30202",
                "expected_class": "refused",
                "expected_event_ids": [],
                "scenario": "unsupported_exploit_verification",
                "split": "new_paired_holdout",
                "label_status": "protocol_refusal_not_human_gold",
            },
            {
                "id": "fresh-withdrawn-copy",
                "question": f"{WITHDRAWN_GHSA} 的旧版本条件还能当作当前证据吗？",
                "query": WITHDRAWN_GHSA,
                "expected_class": "refused",
                "expected_event_ids": [],
                "scenario": "synthetic_withdrawal_in_eval_copy_only",
                "split": "new_paired_holdout",
                "label_status": "protocol_refusal_not_human_gold",
            },
        ]
    )
    assert len(cases) == 7
    DATASET.write_text(
        json.dumps(
            {
                "version": "member-b-agent-paired-v3",
                "created_at": now,
                "status": "frozen_before_model_runs",
                "scope": {"pool": "formal", "origin": "live", "explicit_asset": False},
                "source_database_sha256_at_copy": digest(SOURCE_DB),
                "evaluation_database": str(TARGET_DB),
                "evaluation_database_sha256": digest(TARGET_DB),
                "withdrawal_fixture": {
                    "only_in_evaluation_copy": True,
                    "external_id": WITHDRAWN_GHSA,
                    "event_ids": withdrawn_ids,
                    "event_count": 2,
                },
                "old_case_event_overlap": 0,
                "independent_human_gold": False,
                "cases": cases,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )
    print(
        json.dumps(
            {
                "dataset": str(DATASET),
                "cases": len(cases),
                "database": str(TARGET_DB),
                "sha256": digest(TARGET_DB),
                "synthetic_withdrawn_events": len(withdrawn_ids),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
