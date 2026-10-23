"""Export blinded templates, inspect progress, and freeze only completed human gold."""

import argparse
import json
from pathlib import Path

from zhidu.gold_review import freeze_release, make_packet, reconcile, review_template


def save_new(path, data):
    with path.open("x") as f:
        f.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["prepare", "show", "status", "freeze"])
    parser.add_argument("--directory", type=Path, default=Path("data/week6-human-review"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--index", type=int, default=1, help="show: one-based task number")
    parser.add_argument(
        "--detailed", action="store_true", help="status: list pending and conflict IDs"
    )
    args = parser.parse_args()
    root = args.directory
    if args.command == "prepare":
        root.mkdir(parents=True, exist_ok=True)
        packet = make_packet(json.loads(Path("config/member-b-week6-frozen-qa.json").read_text()))
        save_new(root / "source-packet.json", packet)
        save_new(root / "review-A.json", review_template(packet, "A"))
        save_new(root / "review-B.json", review_template(packet, "B"))
        save_new(root / "adjudications.json", {"packet_sha256": packet["sha256"], "decisions": []})
        print(
            json.dumps(
                {
                    "status": "prepared_not_annotated",
                    "tasks": len(packet["tasks"]),
                    "directory": str(root),
                }
            )
        )
        return
    if args.command == "show":
        packet = json.loads((root / "source-packet.json").read_text())
        if not 1 <= args.index <= len(packet["tasks"]):
            parser.error(f"--index must be between 1 and {len(packet['tasks'])}")
        task = packet["tasks"][args.index - 1]
        records = [
            record for record in packet["records"] if record["event_id"] in task["record_ids"]
        ]
        print(
            json.dumps(
                {"index": args.index, "task": task, "records": records},
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    inputs = [
        json.loads((root / name).read_text())
        for name in ("source-packet.json", "review-A.json", "review-B.json", "adjudications.json")
    ]
    result = reconcile(*inputs) if args.command == "status" else freeze_release(*inputs)
    if args.output:
        save_new(args.output, result)
    output = {key: result[key] for key in ("status", "tasks", "completed")}
    if args.command == "status":
        output["reviewer_progress"] = {
            slot: sum(row.get("answer_class") is not None for row in review["reviews"])
            for slot, review in zip(("A", "B"), inputs[1:3], strict=True)
        }
        output["pending_count"] = len(result["pending"])
        output["conflict_count"] = len(result["conflicts"])
        if args.detailed:
            output["pending_task_ids"] = result["pending"]
            output["conflict_task_ids"] = result["conflicts"]
    print(json.dumps(output, ensure_ascii=False))


if __name__ == "__main__":
    main()
