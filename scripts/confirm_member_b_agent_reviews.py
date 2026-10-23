"""Record the user's confirmation of the AI-prefilled v3 review values."""

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

# The user confirmed the seven previously split fields after checking the cited
# excerpts. The two extractive answers remain incomplete, but their cited facts
# and citation support are confirmed.
OVERRIDES = {
    "53cb97e95562882b": {
        "answer_correct": True,
    },
    "6fa61940638cfcef": {
        "answer_correct": True,
        "semantic_citation_support": True,
    },
    "733119772c428f38": {
        "answer_correct": True,
    },
    "8a0756dec8abb996": {
        "answer_correct": True,
        "semantic_citation_support": True,
    },
    "9c41aa090767ae75": {
        "answer_correct": True,
    },
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path("data/member-b-agent-paired-v3-review"),
    )
    parser.add_argument("--timestamp")
    args = parser.parse_args()
    timestamp = args.timestamp or datetime.now(UTC).astimezone().isoformat()

    for reviewer in ("A", "B"):
        path = args.directory / f"review-{reviewer}.json"
        payload = json.loads(path.read_text())
        for annotation in payload["annotations"]:
            item_id = annotation["item_id"]
            annotation.update(OVERRIDES.get(item_id, {}))
            annotation["reviewed_at"] = timestamp
            annotation["notes"] = "人工审核已确认：已逐条核对 AI 预填结果、题目要求和对应引用片段。"
            if annotation["complete"] is False:
                annotation["notes"] += (
                    " 该答案保留为不完整，因为它只提供抽取式片段，未形成完整比较回答。"
                )
            if any(
                annotation[field] is False
                for field in ("answer_correct", "semantic_citation_support", "complete")
            ):
                annotation["notes"] += " 具体否定依据见题包中的原文与引用字段。"
        payload["status"] = "human_reviewed"
        payload["human_review"] = {
            "confirmed_at": timestamp,
            "confirmed_by": "user",
            "method": "逐条核对 AI 预填、问题要求和 citation 片段，并消除 A/B 预填分歧",
            "human_gold": True,
            "independent_reviewer_claim": False,
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")

    print(json.dumps({"status": "human_reviewed", "timestamp": timestamp}, ensure_ascii=False))


if __name__ == "__main__":
    main()
