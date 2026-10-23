"""Prepare blinded A/B review for the final untouched paired v3 report."""

import hashlib
import json
from pathlib import Path

REPORT = Path("docs/member-b-agent-paired-v3-evaluation.json")
ROOT = Path("data/member-b-agent-paired-v3-review")
MAPPING = Path("tmp/member-b-agent/paired-v3-review-item-map.json")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_new(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as file:
        file.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def main():
    report = json.loads(REPORT.read_text())
    if report["version"] != "member-b-agent-paired-v3" or len(report["rows"]) != 21:
        raise SystemExit("final paired report is incomplete")
    source_hash = digest(REPORT)
    items, mapping = [], {}
    for row in report["rows"]:
        item_id = hashlib.sha256(
            f"{row['case_id']}|{row['mode']}|{source_hash}".encode()
        ).hexdigest()[:16]
        mapping[item_id] = {"case_id": row["case_id"], "mode": row["mode"]}
        items.append(
            {
                "item_id": item_id,
                "question": row["question"],
                "answer": row["answer"],
                "citations": row["citations"],
                "answer_class": row["answer_class"],
                "instruction": "Judge correctness, semantic support and completeness against each current raw source. Model/tool success or quote containment alone is not correctness.",
            }
        )
    items.sort(key=lambda item: item["item_id"])
    packet = {
        "status": "prepared_not_reviewed",
        "source_report_sha256": source_hash,
        "system_labels_hidden": True,
        "items": items,
    }
    write_new(ROOT / "source-packet.json", packet)
    packet_hash = digest(ROOT / "source-packet.json")
    for reviewer in ("A", "B"):
        records = [
            {
                "item_id": item["item_id"],
                "answer_correct": None,
                "semantic_citation_support": None,
                "complete": None,
                "refusal_appropriate": None,
                "notes": None,
                "reviewed_at": None,
            }
            for item in items
        ]
        if reviewer == "B":
            records.reverse()
        write_new(
            ROOT / f"review-{reviewer}.json",
            {
                "status": "pending_human_review",
                "reviewer": reviewer,
                "packet_sha256": packet_hash,
                "annotations": records,
            },
        )
    write_new(
        ROOT / "adjudications.json",
        {"status": "pending_human_review", "packet_sha256": packet_hash, "decisions": []},
    )
    write_new(MAPPING, {"source_report_sha256": source_hash, "item_to_mode": mapping})
    print(
        json.dumps(
            {
                "packet": str(ROOT / "source-packet.json"),
                "items": len(items),
                "reviewers": 2,
                "completed": 0,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
