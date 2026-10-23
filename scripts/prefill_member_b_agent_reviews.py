"""Prefill the v3 A/B review templates from the AI candidate scoring.

This is deliberately a prefill operation: the files remain pending_human_review,
and uncertain fields are split between A and B so that a later adjudicator must
resolve them. It must never be used as a human-gold shortcut.
"""

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

FIELDS = (
    "answer_correct",
    "semantic_citation_support",
    "complete",
    "refusal_appropriate",
)
DIRECT_PASS_MARKERS = ("PR/复杂度", "Patches 片段的具体 PR")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def candidate_value(value: str):
    if value == "likely_true":
        return True
    if value == "likely_false":
        return False
    if value == "not_applicable":
        return "not_applicable"
    if value == "human_required":
        return None
    raise ValueError(f"unsupported AI candidate value: {value}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path("data/member-b-agent-paired-v3-review"),
    )
    parser.add_argument(
        "--scoring",
        type=Path,
        default=Path("docs/member-b-agent-paired-v3-ai-scoring.json"),
    )
    parser.add_argument("--timestamp", help="ISO timestamp for the AI prefill")
    args = parser.parse_args()

    scoring = json.loads(args.scoring.read_text())
    rows = {row["item_id"]: row for row in scoring["rows"]}
    timestamp = args.timestamp or datetime.now(UTC).astimezone().isoformat()
    direct_pass = []
    split = []

    for reviewer in ("A", "B"):
        path = args.directory / f"review-{reviewer}.json"
        payload = json.loads(path.read_text())
        annotations = []
        for annotation in payload["annotations"]:
            item_id = annotation["item_id"]
            row = rows[item_id]
            rationale = row.get("rationale", "")
            direct = any(marker in rationale for marker in DIRECT_PASS_MARKERS)
            values = {}
            notes = []
            for field in FIELDS:
                candidate = row["candidate"][field]
                value = candidate_value(candidate)
                if value is None:
                    if direct and field == "answer_correct":
                        value = True
                        direct_pass.append((item_id, field))
                    else:
                        value = reviewer == "A"
                        split.append((item_id, field))
                        notes.append(
                            f"{field}: AI 候选不确定；按委托规则 A=true、B=false，待人工核对后由第三人裁决。"
                        )
                values[field] = value

            notes.insert(0, "AI 预审候选预填，非人工签名，仍保持 pending_human_review。")
            if direct:
                notes.append(
                    "PR/补丁表述按委托规则先直接通过；人工仍需确认对应片段完全支持该结论。"
                )
            elif row.get("human_required"):
                notes.append("该条含语义核对要求；请人工检查答案是否超出引用片段。")
            for field in FIELDS:
                if values[field] is False:
                    notes.append(f"{field}=false 的具体依据：{rationale}")
                    break
            annotations.append(
                {
                    "item_id": item_id,
                    **values,
                    "notes": " ".join(notes),
                    "reviewed_at": timestamp,
                }
            )

        payload["status"] = "pending_human_review"
        payload["prefill"] = {
            "source": str(args.scoring),
            "source_sha256": sha256(args.scoring),
            "generated_at": timestamp,
            "policy": "likely values copied; human_required split A=true/B=false; PR/complexity candidate pass prefilled true",
            "direct_pass_fields": sorted({f"{item}:{field}" for item, field in direct_pass}),
            "split_fields": sorted({f"{item}:{field}" for item, field in split}),
            "human_gold": False,
        }
        payload["annotations"] = annotations
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")

    print(
        json.dumps(
            {
                "timestamp": timestamp,
                "direct_pass": len(set(direct_pass)),
                "split": len(set(split)),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
