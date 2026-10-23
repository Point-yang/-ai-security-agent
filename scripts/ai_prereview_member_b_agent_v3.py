"""AI-assisted pre-review; never writes A/B labels or freezes human gold."""

import hashlib
import json
import re
from pathlib import Path

PACKET = Path("data/member-b-agent-paired-v3-review/source-packet.json")
RAW = Path("data/raw")
OUTPUT = Path("docs/member-b-agent-paired-v3-ai-prereview.json")
SUMMARY = Path("docs/member-b-agent-paired-v3-ai-prereview.md")


def pointer_value(value, pointer):
    if pointer in ("", "/"):
        return value
    current = value
    for token in pointer.lstrip("/").split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(token)]
        else:
            current = current[token]
    return current


def raw_check(citation):
    digest = citation.get("sha256", "")
    path = RAW / digest[:2] / f"{digest}.json"
    result = {
        "raw_path": str(path),
        "sha256_ok": False,
        "pointer_ok": False,
        "pointer_value": None,
        "error": None,
    }
    if not path.is_file():
        result["error"] = "raw_file_missing"
        return result
    content = path.read_bytes()
    result["sha256_ok"] = hashlib.sha256(content).hexdigest() == digest
    try:
        document = json.loads(content)
        value = pointer_value(document, citation["json_pointer"])
        result["pointer_value"] = value
        result["pointer_ok"] = True
        result["value_in_excerpt"] = str(value) in citation.get("text", "") or citation.get(
            "text", ""
        ) in json.dumps(value, ensure_ascii=False)
    except Exception as exc:
        result["error"] = type(exc).__name__
    return result


def citation_markers(answer):
    return sorted({int(value) for value in re.findall(r"\[(\d+)\]", answer)})


def prereview(item):
    answer = item["answer"]
    citations = item["citations"]
    checks = [raw_check(citation) for citation in citations]
    markers = citation_markers(answer)
    valid_markers = bool(markers) and max(markers, default=0) <= len(citations)
    cited_raw_ok = (
        all(check["sha256_ok"] and check["pointer_ok"] for check in checks) if citations else True
    )
    refusal = item["answer_class"] in {"refused", "clarification"}
    question = item["question"]
    missing_context = any(
        term in question for term in ("我的资产", "复现", "所有资产", "有没有可核对", "旧版本条件")
    )
    if refusal:
        refusal_candidate = bool(missing_context or not citations)
        return {
            "item_id": item["item_id"],
            "question": question,
            "answer_class": item["answer_class"],
            "ai_candidate": {
                "answer_correct": "likely_true" if refusal_candidate else "human_required",
                "semantic_citation_support": "not_applicable"
                if not citations
                else "human_required",
                "complete": "likely_true" if answer.strip() else "likely_false",
                "refusal_appropriate": "likely_true" if refusal_candidate else "human_required",
            },
            "evidence_checks": checks,
            "citation_markers": markers,
            "human_review_required": not refusal_candidate,
            "rationale": "无引用的拒答符合当前资料缺口/资产/复现限制。"
            if refusal_candidate
            else "拒答对象需要审核者核对题目语义。",
        }
    likely_complete = (
        item["answer_class"] != "partial" and "部分工具失败" not in answer and "缺口" not in answer
    )
    return {
        "item_id": item["item_id"],
        "question": question,
        "answer_class": item["answer_class"],
        "ai_candidate": {
            "answer_correct": "human_required",
            "semantic_citation_support": "likely_true"
            if cited_raw_ok and valid_markers
            else "likely_false",
            "complete": "likely_true" if likely_complete else "likely_false",
            "refusal_appropriate": "not_applicable",
        },
        "evidence_checks": checks,
        "citation_markers": markers,
        "human_review_required": True,
        "rationale": "逐字引用和原文指针可复验，但中文概括的语义正确性必须由审核者判断。",
    }


def main():
    if OUTPUT.exists() or SUMMARY.exists():
        raise SystemExit("refusing overwrite")
    packet = json.loads(PACKET.read_text())
    rows = [prereview(item) for item in packet["items"]]
    counts = {
        "items": len(rows),
        "likely_refusal_appropriate": sum(
            r["ai_candidate"]["refusal_appropriate"] == "likely_true" for r in rows
        ),
        "likely_citation_chain_ok": sum(
            r["ai_candidate"]["semantic_citation_support"] == "likely_true" for r in rows
        ),
        "likely_incomplete": sum(r["ai_candidate"]["complete"] == "likely_false" for r in rows),
        "human_answer_correctness_required": sum(
            r["ai_candidate"]["answer_correct"] == "human_required" for r in rows
        ),
        "raw_sha256_failures": sum(not c["sha256_ok"] for r in rows for c in r["evidence_checks"]),
        "pointer_failures": sum(not c["pointer_ok"] for r in rows for c in r["evidence_checks"]),
    }
    report = {
        "version": "ai-prereview-v1",
        "status": "ai_assisted_not_human_gold",
        "source_packet_sha256": hashlib.sha256(PACKET.read_bytes()).hexdigest(),
        "counts": counts,
        "rows": rows,
        "warning": "候选标签由程序辅助检查生成；没有填写 A/B 标注文件，也不能作为比赛正式准确率。",
    }
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    lines = [
        "# v3 Agent 21 条答案 AI 预审",
        "",
        "状态：AI 辅助预审，不是人工金标，也未修改 A/B 标注文件。",
        "",
        f"共 {counts['items']} 条；建议人工核对答案正确性 {counts['human_answer_correctness_required']} 条；"
        f"原文哈希失败 {counts['raw_sha256_failures']}，字段定位失败 {counts['pointer_failures']}。",
        "",
    ]
    for row in rows:
        c = row["ai_candidate"]
        lines.append(
            f"- `{row['item_id']}`：answer_correct={c['answer_correct']}；semantic_support={c['semantic_citation_support']}；complete={c['complete']}；refusal={c['refusal_appropriate']}。{row['rationale']}"
        )
    lines += [
        "",
        "下一步：两名审核者分别打开 source-packet.json 和各自 review-A/B.json，独立填写；AI 预审只能作为核查索引。",
    ]
    SUMMARY.write_text("\n".join(lines) + "\n")
    print(
        json.dumps(
            {"output": str(OUTPUT), "summary": str(SUMMARY), "counts": counts}, ensure_ascii=False
        )
    )


if __name__ == "__main__":
    main()
