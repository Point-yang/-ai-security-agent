"""Project-authorized AI gold, separate from the unchanged human release gate."""

import argparse
import hashlib
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from review_week6_sources import (
    aggregate,
    citation,
    encoded,
    now,
    prediction_facts,
    read,
    save,
    score_sets,
)

from zhidu.gold_review import seal, validate_answer, validate_seal
from zhidu.sources import resolve_pointer

PACKET = Path("data/week6-human-review/source-packet.json")
DRAFT = Path("output/week6-source-review-v2/source-review-ai.json")
PREDICTIONS = Path("output/week6-source-review-v2/test-predictions.json")
RELEASE = Path("data/week6-ai-gold/project-gold-v1.json")
EVALUATION = Path("docs/member-b-week6-ai-gold-evaluation.json")
AUTHORIZATION = "如果能通过，请直接作为正式类别金标，允许替代人工"
RUBRIC = {
    "version": "source-attributed-answer-class-v1",
    "scope": "原题要求确认来源结论及证据不足的边界，评价来源归属的可回答性，不要求独立复现现实漏洞。",
    "evidence": "原记录能支持有来源归属的答案；全文、现实复现或本地资产证据缺失本身不降级。撤回公告可支持其历史内容与撤回状态。",
    "partial": "原记录能支持部分结论，但明确争议、正文与范围字段冲突、或受影响与修复范围重叠，使核心影响/版本结论不能无歧义确认。分别保留原始声明，不补齐范围。",
    "refused": "该题不存在可支持来源结论的可用原文；不得因仅缺论文全文或存在证据边界而整体拒答。",
    "cross_source": "来源间差异按来源分别保留，不因冻结别名分组而认定同一漏洞，不自动把一个来源的结论覆盖另一来源。",
    "version_gaps": "仅有受影响终点到修复起点的空档不等于矛盾，不推断空档安全；实际交叠或正文冲突才触发 partial。",
}


def range_overlap(vulnerable, fixed):
    """Return a concrete common version, never infer an absent upper bound."""
    if not vulnerable or not fixed:
        return None
    match = re.fullmatch(r"\s*(?:>=|==|=)?\s*v?(\d[\w.+-]*)\s*", fixed)
    if not match:
        return None
    candidate = match.group(1)
    try:
        clauses = []
        for clause in vulnerable.split(","):
            clause = re.sub(r"\s+", "", clause)
            if re.match(r"^v?\d", clause):
                clause = "==" + clause.removeprefix("v")
            elif clause.startswith("=") and not clause.startswith("=="):
                clause = "=" + clause
            clauses.append(clause)
        if Version(candidate) in SpecifierSet(",".join(clauses)):
            return candidate
    except (InvalidVersion, InvalidSpecifier):
        return None
    return None


def classify(record):
    raw, source = record["raw_record"], record["source_id"]
    issues = []
    if source == "nvd":
        for i, description in enumerate(raw.get("descriptions", [])):
            if "still disputed" in description.get("value", "").lower():
                issues.append(
                    {
                        "reason": "原文明示漏洞存在性仍有争议，并给出正常行为的替代解释；只能确认争议与报告内容。",
                        "citations": [citation(record, f"/descriptions/{i}/value")],
                    }
                )
    if raw.get("ghsa_id") == "GHSA-7m6h-x95x-82q5":
        issues.append(
            {
                "reason": "结构化受影响范围 < 0.21.0，但正文 Versions 段涉及 <= 0.21.0 及之后代码路径，修复为 >= 0.27.0；无法确认统一受影响边界。",
                "citations": [
                    citation(record, "/description"),
                    citation(record, "/vulnerabilities/0"),
                ],
            }
        )
    for i, scope in enumerate(raw.get("vulnerabilities", [])):
        for fixed_key in ("first_patched_version", "patched_versions"):
            overlap = range_overlap(scope.get("vulnerable_version_range"), scope.get(fixed_key))
            if overlap:
                issues.append(
                    {
                        "reason": f"受影响字段 {scope['vulnerable_version_range']} 与修复字段 {scope[fixed_key]} 在 {overlap} 重叠；不把缺失上界自动补齐，不能无条件判定该版本安全。",
                        "citations": [
                            citation(record, f"/vulnerabilities/{i}/vulnerable_version_range"),
                            citation(record, f"/vulnerabilities/{i}/{fixed_key}"),
                        ],
                    }
                )
    if issues:
        return "partial", " ".join(i["reason"] for i in issues), issues
    if source == "crossref":
        title = "；".join(raw.get("title", []))
        reason = (
            f"DOI {raw.get('DOI')} 及题名《{title}》可直接核验。"
            + (
                "记录含摘要，可归属为作者陈述。"
                if raw.get("abstract")
                else "记录不含摘要，只确认书目信息。"
            )
            + "题目未要求全文实验结论，明确这项边界即可回答。"
        )
    elif source == "cisa-kev":
        reason = f"{raw.get('cveID')} 的目录收录、产品 {raw.get('product')}、描述与行动字段可以直接支持来源归属的答案；不外推本地资产命中。"
    elif source == "nvd":
        reason = f"{raw.get('id')} 的 descriptions、metrics 及可用 affected/configurations 支持来源陈述；保留发布方、版本状态和不同表示，不把缺 CPE 当成无版本证据。"
    elif raw.get("withdrawn_at"):
        reason = f"{raw.get('ghsa_id')} 于 {raw['withdrawn_at']} 撤回，正文说明重复公告；可确认历史声明与撤回状态，不能计为新的独立漏洞。"
    else:
        reason = f"{raw.get('ghsa_id')} 的标题“{raw.get('summary')}”、正文及包范围可支持按来源归属的答案；部署前提、空字段和未说明的版本区间保持为边界，不推断实际复现或安全性。"
    return "evidence", reason, []


def validate_release(packet, release):
    validate_seal(packet)
    validate_seal(release)
    if (
        release.get("status") != "project_ai_gold_frozen"
        or release.get("review_method") != "ai"
        or release.get("human_reviewed") is not False
        or release.get("packet_sha256") != packet["sha256"]
        or not release.get("authorization", {}).get("allows_ai_substitution")
    ):
        raise ValueError("Invalid project AI release provenance")
    tasks = {t["id"]: t for t in packet["tasks"]}
    labels = release["labels"]
    if not tasks or len(labels) != len(tasks) or {r["task_id"] for r in labels} != set(tasks):
        raise ValueError("Every task must have exactly one reviewed label")
    if release["class_counts"] != dict(Counter(r["answer_class"] for r in labels)):
        raise ValueError("Class counts do not match labels")
    for label in labels:
        task = tasks[label["task_id"]]
        if label["split"] != task["split"] or label["group_id"] != task["group_id"]:
            raise ValueError("Frozen split/group cannot change")
        if not label.get("class_rationale") or label.get("review_method") != "ai":
            raise ValueError("AI decision and rationale required")
        if datetime.fromisoformat(label["reviewed_at"]).tzinfo is None:
            raise ValueError("AI review timestamp requires timezone")
        if any(c["record_id"] not in task["record_ids"] for c in label["citations"]):
            raise ValueError("AI release must cite the question's own source")
        validate_answer(packet, task, label)
        for issue in label["source_issues"]:
            validate_answer(
                packet,
                task,
                {
                    "answer_class": "evidence",
                    "complete_answer": issue["reason"],
                    "supported_fields": [c["pointer"] for c in issue["citations"]],
                    "citations": issue["citations"],
                },
            )
        for item in label["enrichment_facts"]:
            validate_answer(
                packet,
                task,
                {
                    "answer_class": "evidence",
                    "complete_answer": encoded(item["fact"]),
                    "supported_fields": [c["pointer"] for c in item["citations"]],
                    "citations": item["citations"],
                },
            )


def freeze(packet, draft):
    validate_seal(packet)
    validate_seal(draft)
    if draft["packet_sha256"] != packet["sha256"]:
        raise ValueError("Draft belongs to another packet")
    source = {r["event_id"]: r for r in packet["records"]}
    answers = {r["task_id"]: r for r in draft["reviews"]}
    if len(answers) != len(draft["reviews"]) or set(answers) != {t["id"] for t in packet["tasks"]}:
        raise ValueError("Draft task coverage mismatch")
    labels = []
    for task in packet["tasks"]:
        record = source[task["id"]]
        raw = (Path("data/raw") / record["sha256"][:2] / (record["sha256"] + ".json")).read_bytes()
        if (
            hashlib.sha256(raw).hexdigest() != record["sha256"]
            or resolve_pointer(json.loads(raw), record["record_pointer"]) != record["raw_record"]
        ):
            raise ValueError("Source record is not byte-verifiable")
        answer = answers[task["id"]]
        status, reason, issues = classify(record)
        limitation = answer["refusal_reason"]
        labels.append(
            {
                **answer,
                **task,
                "source_id": record["source_id"],
                "external_id": record["external_id"],
                "answer_class": status,
                "refusal_reason": reason if status != "evidence" else None,
                "evidence_limitations": limitation,
                "class_rationale": reason,
                "complete_answer": "类别复核结论：" + reason + "\n\n" + answer["complete_answer"],
                "source_issues": issues,
                "review_method": "ai",
                "reviewer_id": "codex-ai",
                "reviewed_at": now(),
                "resolution": "source_attribution_with_explicit_limits",
            }
        )
    release = seal(
        {
            "version": "project-ai-gold-v1",
            "status": "project_ai_gold_frozen",
            "released_at": now(),
            "review_method": "ai",
            "human_reviewed": False,
            "independent_review_attested": False,
            "adoption_scope": "user_authorized_project_official_not_organizer_certification",
            "authorization": {
                "date": "2026-10-04",
                "timezone": "Asia/Shanghai",
                "user_message": AUTHORIZATION,
                "allows_ai_substitution": True,
            },
            "packet_sha256": packet["sha256"],
            "corpus_sha256": packet["corpus_sha256"],
            "parent_freeze_sha256": packet["parent_freeze_sha256"],
            "draft_sha256": draft["sha256"],
            "rubric": RUBRIC,
            "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "tasks": len(labels),
            "completed": len(labels),
            "class_counts": dict(Counter(r["answer_class"] for r in labels)),
            "split_counts": dict(Counter(r["split"] for r in labels)),
            "labels": labels,
            "source_scope_comparisons": draft["source_scope_comparisons"],
            "limitations": [
                "单个 AI 与规则复核，未经过双人人工或独立盲审。",
                "已见过旧测试结果，类别规则是事后明确，不得宣称新的盲测。",
                "类别冻结不产生模型类别准确率，必须有对应问题的模型类别预测才能计分。",
            ],
        }
    )
    validate_release(packet, release)
    return release


def evaluate(packet, release, predictions):
    validate_release(packet, release)
    validate_seal(predictions)
    if predictions["packet_sha256"] != packet["sha256"]:
        raise ValueError("Wrong prediction packet")
    tasks = {t["id"]: t for t in packet["tasks"] if t["split"] == "test"}
    actual = {p["task_id"]: p for p in predictions["predictions"]}
    if len(actual) != len(predictions["predictions"]) or set(actual) != set(tasks):
        raise ValueError("All test predictions required exactly once")
    source = {r["event_id"]: r for r in packet["records"]}
    rows = []
    for label in release["labels"]:
        if label["task_id"] not in tasks:
            continue
        task_id = label["task_id"]
        p = actual[task_id]
        r = source[task_id]
        if p["revision_id"] != r["revision_id"] or p["source_sha256"] != r["sha256"]:
            raise ValueError("Test source revision mismatch")
        if p["prediction"] and (
            p["prediction"]["event_id"] != task_id
            or p["prediction"]["revision_id"] != r["revision_id"]
        ):
            raise ValueError("Nested prediction identity mismatch")
        expected = [f["fact"] for f in label["enrichment_facts"]]
        predicted = prediction_facts(p["prediction"])
        rows.append(
            {
                "task_id": task_id,
                "source_id": r["source_id"],
                "external_id": r["external_id"],
                "group_id": label["group_id"],
                "missing_prediction": p["prediction"] is None,
                **score_sets(expected, predicted),
                "expected_facts": expected,
                "predicted_facts": predicted,
            }
        )
    return seal(
        {
            "version": "project-ai-gold-evaluation-v1",
            "status": "project_official_ai_reference_evaluation",
            "created_at": now(),
            "gold_sha256": release["sha256"],
            "predictions_sha256": predictions["sha256"],
            "packet_sha256": packet["sha256"],
            "split": "test",
            "metrics": aggregate(rows),
            "by_source": {
                s: aggregate([r for r in rows if r["source_id"] == s])
                for s in sorted({r["source_id"] for r in rows})
            },
            "answer_class_accuracy": None,
            "answer_class_accuracy_reason": "冻结预测仅含结构化富化字段，没有与这 24 道问题对应的模型 answer_class；不能把金标类别与自身比较。",
            "scope": "沿用旧报告的结构化来源事实口径；不评价全文语义、版本解析、CPE 布尔逻辑或现实漏洞真伪。",
            "model_version": "stored structured-v1 enrichment snapshot",
            "human_gold": False,
            "evaluator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "rows": rows,
        }
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["freeze", "evaluate", "status"])
    parser.add_argument("--release", type=Path, default=RELEASE)
    parser.add_argument("--output", type=Path, default=EVALUATION)
    args = parser.parse_args()
    packet = read(PACKET)
    if args.command == "freeze":
        release = freeze(packet, read(DRAFT))
        save(args.release, release)
    else:
        release = read(args.release)
        validate_release(packet, release)
        if args.command == "evaluate":
            save(args.output, evaluate(packet, release, read(PREDICTIONS)))
    print(
        encoded(
            {
                "status": release["status"],
                "tasks": release["tasks"],
                "class_counts": release["class_counts"],
                "sha256": release["sha256"],
            }
        )
    )


if __name__ == "__main__":
    main()
