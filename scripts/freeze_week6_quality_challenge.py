"""Separate policy challenge set. Never relabel or overwrite the original 20 cases."""

import copy
import json
from pathlib import Path

from zhidu.semantic import digest


def main():
    source = json.loads(Path("config/member-b-week6-frozen-qa.json").read_text())
    output = Path("config/member-b-week6-quality-challenge.json")
    data = {
        "version": "quality-challenge-v1",
        "corpus_sha256": source["corpus_sha256"],
        "parent_freeze_sha256": source["freeze_sha256"],
        "independent_human_gold": False,
        "official_scores": None,
        "cases": [],
    }
    queries = [
        "NebulaCalc authentication bypass",
        "OrchidWare 认证绕过",
        "novazet2029",
        "xq91-invented-library",
        "CVE-2099-9876543",
        "GHSA-zzzz-9999-xxxx",
        "这条公告的影响版本是什么？",
        "该来源的证据可靠吗？",
        "what is the weather",
        "请推荐今天晚餐的食谱",
        "所有资产都安全的证明",
        "我的资产是否受影响？",
    ]
    for index, query in enumerate(queries):
        data["cases"].append(
            {
                "id": f"challenge-refuse-{index}",
                "question": query,
                "query": query,
                "expected_class": "refused",
                "expected_event_ids": [],
                "group_id": f"policy-challenge-{index}",
                "split": "development",
                "label_status": "policy_characterization_not_human_gold",
                "evidence": [],
            }
        )
    # Explicit context counterparts are additions; the ambiguous legacy questions stay unchanged.
    for old_id in ("case-6-en", "case-7-en"):
        case = copy.deepcopy(next(c for c in source["cases"] if c["id"] == old_id))
        case["id"] = old_id + "-explicit-context-zh"
        case["question"] = case["query"] + "：来源能给出确定的版本条件吗？"
        case["query"] = case["question"]
        data["cases"].append(case)
    data["freeze_sha256"] = digest(data)
    with output.open("x") as f:
        f.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"cases": len(data["cases"]), "freeze_sha256": data["freeze_sha256"]}))


if __name__ == "__main__":
    main()
