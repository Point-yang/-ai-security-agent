"""Validate two independent answer reviews; freeze only with human adjudication."""

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path("data/member-b-agent-review")
PRIVATE_MAP = Path("tmp/member-b-agent/review-item-map.json")
FIELDS = ("answer_correct", "semantic_citation_support", "complete", "refusal_appropriate")


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def valid(field, value, item):
    if field in {"answer_correct", "complete"}:
        return isinstance(value, bool)
    if field == "semantic_citation_support":
        return isinstance(value, bool) if item["citations"] else value == "not_applicable"
    if field == "refusal_appropriate":
        return (
            isinstance(value, bool)
            if item["answer_class"] in {"refused", "clarification"}
            else value == "not_applicable"
        )
    return False


def reconcile(root=ROOT, mapping=PRIVATE_MAP):
    packet_path = root / "source-packet.json"
    packet = read(packet_path)
    packet_hash = sha(packet_path)
    reviews = [read(root / f"review-{reviewer}.json") for reviewer in ("A", "B")]
    decisions = read(root / "adjudications.json")
    ids = [item["item_id"] for item in packet["items"]]
    items = {item["item_id"]: item for item in packet["items"]}
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate packet item")
    if any(record.get("packet_sha256") != packet_hash for record in [*reviews, decisions]):
        raise ValueError("packet digest mismatch")
    if [review.get("reviewer") for review in reviews] != ["A", "B"]:
        raise ValueError("reviewer identities must remain distinct")
    indexed = []
    pending = []
    for review in reviews:
        rows = review["annotations"]
        if len(rows) != len(ids) or {row["item_id"] for row in rows} != set(ids):
            raise ValueError("review items mismatch")
        if len({row["item_id"] for row in rows}) != len(rows):
            raise ValueError("duplicate review item")
        indexed.append({row["item_id"]: row for row in rows})
        for row in rows:
            if (
                not row.get("reviewed_at")
                or any(not valid(field, row.get(field), items[row["item_id"]]) for field in FIELDS)
                or (any(row.get(field) is False for field in FIELDS) and not row.get("notes"))
            ):
                pending.append({"reviewer": review["reviewer"], "item_id": row["item_id"]})
    lookup = read(mapping)
    if lookup["source_report_sha256"] != packet["source_report_sha256"]:
        raise ValueError("mode mapping does not match source report")
    if set(lookup["item_to_mode"]) != set(ids):
        raise ValueError("mode mapping items mismatch")
    adjudications = decisions["decisions"]
    keys = [(d.get("item_id"), d.get("field")) for d in adjudications]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate adjudication")
    decision_map = {key: d for key, d in zip(keys, adjudications, strict=True)}
    conflicts = []
    resolved = []
    for item_id in ids:
        combined = {}
        for field in FIELDS:
            first, second = (review[item_id][field] for review in indexed)
            if first == second and valid(field, first, items[item_id]):
                combined[field] = first
            elif valid(field, first, items[item_id]) and valid(field, second, items[item_id]):
                choice = decision_map.get((item_id, field))
                if (
                    choice is None
                    or not valid(field, choice.get("value"), items[item_id])
                    or not choice.get("adjudicator")
                    or choice.get("adjudicator") in {"A", "B"}
                    or not choice.get("reason")
                    or not choice.get("reviewed_at")
                ):
                    conflicts.append({"item_id": item_id, "field": field})
                else:
                    combined[field] = choice["value"]
        if len(combined) == len(FIELDS):
            resolved.append({"item_id": item_id, **combined})
    status = (
        "ready_to_freeze"
        if not pending and not conflicts and len(resolved) == len(ids)
        else "pending_human_review"
    )
    return {
        "status": status,
        "items": len(ids),
        "completed_items": len(resolved),
        "pending": pending,
        "conflicts": conflicts,
        "resolved": resolved,
        "source_report_sha256": packet["source_report_sha256"],
        "mode_map": lookup["item_to_mode"],
    }


def freeze(result):
    if result["status"] != "ready_to_freeze":
        raise ValueError("independent reviews or adjudications are incomplete")
    groups = defaultdict(list)
    for row in result["resolved"]:
        info = result["mode_map"][row["item_id"]]
        groups[info["mode"]].append(row)
    scores = {}
    for mode, rows in groups.items():
        scores[mode] = {"reviewed": len(rows)}
        for field in FIELDS:
            applicable = [r[field] for r in rows if isinstance(r[field], bool)]
            scores[mode][field] = sum(applicable) / len(applicable) if applicable else None
            scores[mode][field + "_n"] = len(applicable)
    return {
        "status": "frozen_human_review",
        "source_report_sha256": result["source_report_sha256"],
        "items": result["items"],
        "reviewers": ["A", "B"],
        "scores": scores,
        "manual_adjudication_required_for_disagreements": True,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["status", "freeze"])
    parser.add_argument("--directory", type=Path, default=ROOT)
    parser.add_argument("--mapping", type=Path, default=PRIVATE_MAP)
    parser.add_argument(
        "--output", type=Path, default=Path("docs/member-b-agent-human-review-scores.json")
    )
    args = parser.parse_args()
    state = reconcile(args.directory, args.mapping)
    if args.command == "status":
        compact = {k: state[k] for k in ("status", "items", "completed_items")}
        compact["pending_reviews"] = len(state["pending"])
        compact["unresolved_fields"] = len(state["conflicts"])
        print(
            json.dumps(
                compact,
                ensure_ascii=False,
            )
        )
        return
    report = freeze(state)
    with args.output.open("x") as f:
        f.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(str(args.output))


if __name__ == "__main__":
    main()
