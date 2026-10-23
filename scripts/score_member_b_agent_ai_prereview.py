"""Apply a transparent AI candidate rubric to the v3 pre-review; never freeze gold."""

import json
from pathlib import Path

PRE = Path("docs/member-b-agent-paired-v3-ai-prereview.json")
OUT = Path("docs/member-b-agent-paired-v3-ai-scoring.json")
MD = Path("docs/member-b-agent-paired-v3-ai-scoring.md")

# Human review remains required for semantic meaning. These are issue flags,
# not official truth labels and do not modify review-A/B.json.
OVERRIDES = {
    "0eedb26a72807dd3": (
        "likely_false",
        "likely_false",
        "likely_true",
        "只引用 vllm-vendor 的 packages，未回答 GitHub 来源分别给出的修复依据；虽标 partial，但题目要求两来源，建议判不完整。",
    ),
    "2ed9d1a748db0f4d": (
        "human_required",
        "likely_true",
        "likely_true",
        "两来源 packages、标题和描述均有引用；需人工确认 PR/复杂度表述是否完全由对应片段支持。",
    ),
    "53cb97e95562882b": (
        "human_required",
        "likely_true",
        "likely_true",
        "问题、版本边界和描述均有来源字段；需人工核对测试环境与攻击结论是否超出原文。",
    ),
    "5ee4256f4e979036": (
        "human_required",
        "likely_true",
        "likely_true",
        "两来源首个修复字段和补丁链接均被覆盖；需人工核对 Patches 片段的具体 PR 是否与来源一致。",
    ),
    "6c71044f0fd1876f": (
        "likely_false",
        "likely_false",
        "likely_false",
        "答案引用了 [15]，但该条目只有 14 个 citations；存在越界引用，不能作为完整正确答案。",
    ),
    "6fa61940638cfcef": (
        "human_required",
        "likely_false",
        "human_required",
        "这是本地抽取式证据包，包含两来源 packages，但没有形成完整的自然语言回答；题目要求首个修复版本及依据，建议人工判完整性。",
    ),
    "733119772c428f38": (
        "human_required",
        "likely_true",
        "likely_true",
        "两来源版本字段、描述和引用差异均有候选依据；需人工核对每个描述结论是否支撑。",
    ),
    "8a0756dec8abb996": (
        "human_required",
        "likely_false",
        "human_required",
        "这是本地原文摘录而非整理后的比较答案；有完整候选证据，但没有直接回答两来源差异，建议人工判完整性。",
    ),
    "9c41aa090767ae75": (
        "human_required",
        "likely_true",
        "likely_true",
        "问题、漏洞机制、版本边界和测试条件均有引用；需人工核对 AUC、环境和修复表述是否逐项对应。",
    ),
}


def main():
    refresh = "--refresh" in __import__("sys").argv
    if (OUT.exists() or MD.exists()) and not refresh:
        raise SystemExit("refusing overwrite")
    source = json.loads(PRE.read_text())
    rows = []
    for row in source["rows"]:
        candidate = row["ai_candidate"].copy()
        rationale = row["rationale"]
        if row["item_id"] in OVERRIDES:
            correct, complete, support, rationale = OVERRIDES[row["item_id"]]
            candidate.update(
                answer_correct=correct, complete=complete, semantic_citation_support=support
            )
        rows.append(
            {
                "item_id": row["item_id"],
                "question": row["question"],
                "answer_class": row["answer_class"],
                "candidate": candidate,
                "rationale": rationale,
                "human_required": True,
                "source_checks": row["evidence_checks"],
            }
        )
    summary = {
        "items": len(rows),
        "candidate_likely_correct_or_refusal": sum(
            r["candidate"]["answer_correct"] == "likely_true" for r in rows
        ),
        "candidate_likely_false": sum(
            r["candidate"]["answer_correct"] == "likely_false" for r in rows
        ),
        "semantic_support_likely_true": sum(
            r["candidate"]["semantic_citation_support"] == "likely_true" for r in rows
        ),
        "complete_likely_true": sum(r["candidate"]["complete"] == "likely_true" for r in rows),
        "human_answer_correctness_required": sum(
            r["candidate"]["answer_correct"] == "human_required" for r in rows
        ),
        "human_gold": False,
    }
    report = {
        "version": "ai-prereview-scoring-v1",
        "status": "candidate_only_not_human_gold",
        "source_prereview_sha256": __import__("hashlib").sha256(PRE.read_bytes()).hexdigest(),
        "summary": summary,
        "rows": rows,
        "warning": "这些是 AI 候选判断；未写入 A/B 审核文件，也不能作为比赛正式准确率。",
    }
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    lines = [
        "# v3 Agent AI 候选评分",
        "",
        "状态：候选评分，不是人工金标。A/B 文件保持空白。",
        "",
        f"共 {summary['items']} 条；候选支持引用 {summary['semantic_support_likely_true']} 条；"
        f"候选完整回答 {summary['complete_likely_true']} 条；答案语义仍需人工判断 {summary['human_answer_correctness_required']} 条。",
        "",
    ]
    for row in rows:
        c = row["candidate"]
        lines.append(
            f"- `{row['item_id']}`：correct={c['answer_correct']}；support={c['semantic_citation_support']}；complete={c['complete']}；{row['rationale']}"
        )
    lines += [
        "",
        "下一步：A/B 独立复核 21 条，尤其先看 likely_false 和 human_required 项；完成后运行 reconcile，再裁决分歧。",
    ]
    MD.write_text("\n".join(lines) + "\n")
    print(json.dumps({"output": str(OUT), "summary": summary}, ensure_ascii=False))


if __name__ == "__main__":
    main()
