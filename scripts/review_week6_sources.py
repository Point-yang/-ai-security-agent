"""Source-only AI draft and reproducible provisional enrichment scoring.

Never writes human review slots or creates a human gold release. The draft is
an auditable extraction aid, not an independent human semantic annotation.
"""

import argparse
import hashlib
import json
import re
import sqlite3
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from zhidu.gold_review import seal, validate_answer, validate_seal
from zhidu.sources import resolve_pointer

ROOT = Path("data/week6-human-review")
OUT = Path("output/week6-source-review-v2")
BOUNDS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)
SNAKE_BOUNDS = (
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
)


def now():
    return datetime.now(UTC).isoformat()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as f:
        f.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def read(path):
    return json.loads(path.read_text())


def canonical(value):
    return str(value or "unknown").strip().casefold()


def range_text(value):
    # Whitespace only: never infer a missing upper bound or change operators.
    return re.sub(r"\s+", "", value)


def fact(kind, *values):
    return [kind, *values]


def citation(record, pointer):
    value = resolve_pointer(record["raw_record"], pointer)
    return {
        "record_id": record["event_id"],
        "pointer": pointer,
        "quote": value if isinstance(value, str) else encoded(value),
    }


def cpe_nodes(value, path="/configurations"):
    if isinstance(value, dict):
        if value.get("criteria"):
            yield path, value
        for k, v in value.items():
            yield from cpe_nodes(v, path + "/" + k)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from cpe_nodes(v, path + "/" + str(i))


def source_facts(record):
    """Direct structured source assertions; no production extractor is called."""
    a, source = record["raw_record"], record["source_id"]
    result = {}

    def add(kind, values, *pointers):
        item = fact(kind, *values)
        result[encoded(item)] = {"fact": item, "citations": [citation(record, p) for p in pointers]}

    for field, kind in (("cveID", "cve"), ("cve_id", "cve"), ("ghsa_id", "ghsa"), ("DOI", "doi")):
        if a.get(field):
            add("entity:" + kind, [canonical(a[field])], "/" + field)
    if source == "nvd":
        add("entity:cve", [canonical(a["id"])], "/id")
    if source == "cisa-kev":
        for field, kind in (("vendorProject", "vendor"), ("product", "product")):
            if a.get(field):
                add("entity:" + kind, [canonical(a[field])], "/" + field)
    for i, v in enumerate(a.get("vulnerabilities", [])):
        base = f"/vulnerabilities/{i}"
        package = v.get("package") or {}
        identity = [canonical(package.get("ecosystem")), canonical(package.get("name"))]
        add("entity:package", identity, base + "/package")
        for field, kind in (
            ("vulnerable_version_range", "vulnerable_range"),
            ("first_patched_version", "fixed_range"),
            ("patched_versions", "fixed_range"),
        ):
            if v.get(field):
                add(kind, [*identity, range_text(v[field])], base + "/package", base + "/" + field)
    for name, v in (a.get("cvss_severities") or {}).items():
        if v.get("vector_string") and isinstance(v.get("score"), (int, float)):
            vector = v["vector_string"]
            version = vector.split("/")[0].removeprefix("CVSS:")
            add("cvss", [version, vector, float(v["score"]), None], "/cvss_severities/" + name)
    for name, metrics in (a.get("metrics") or {}).items():
        if not name.startswith("cvssMetric"):
            continue
        for i, m in enumerate(metrics):
            v = m.get("cvssData") or {}
            if v.get("vectorString") and isinstance(v.get("baseScore"), (int, float)):
                add(
                    "cvss",
                    [v["version"], v["vectorString"], float(v["baseScore"]), m.get("source")],
                    f"/metrics/{name}/{i}",
                )
    for path, v in cpe_nodes(a.get("configurations", [])):
        add(
            "cpe_match",
            [v["criteria"], bool(v.get("vulnerable")), *[v.get(k) for k in BOUNDS]],
            path,
        )
        parts = v["criteria"].split(":")
        if parts[:2] == ["cpe", "2.3"] and len(parts) >= 5:
            for kind, value in zip(("vendor", "product"), parts[3:5], strict=True):
                add("entity:" + kind, [canonical(value)], path + "/criteria")
    # Newer NVD affectedData is source evidence even when the old extractor
    # only reads configurations. Preserve publisher, product and version status.
    for i, authority in enumerate(a.get("affected", [])):
        for j, product in enumerate(authority.get("affectedData", [])):
            base = f"/affected/{i}/affectedData/{j}"
            for kind in ("vendor", "product"):
                if product.get(kind) and canonical(product[kind]) not in {"n/a", "unknown"}:
                    add("entity:" + kind, [canonical(product[kind])], base + "/" + kind)
            for version in product.get("versions", []):
                if canonical(version.get("version")) in {"n/a", "unknown"}:
                    continue
                identity = {
                    key: product.get(key)
                    for key in ("vendor", "product", "packageName", "packageURL", "defaultStatus")
                }
                add(
                    "nvd_affected_version",
                    [authority.get("source"), identity, version],
                    f"/affected/{i}/source",
                    base,
                )
    return list(result.values())


def source_answer(record):
    a, source = record["raw_record"], record["source_id"]
    citations, parts = {}, []

    def include(pointer, label):
        value = resolve_pointer(a, pointer)
        if value is None or value == "" or value == [] or value == {}:
            return
        citations[pointer] = citation(record, pointer)
        parts.append(label + "：" + (value if isinstance(value, str) else encoded(value)) + "。")

    if source == "cisa-kev":
        for field, label in (
            ("cveID", "CISA KEV 收录编号"),
            ("vendorProject", "来源所列厂商"),
            ("product", "产品"),
            ("dateAdded", "收录日"),
            ("shortDescription", "来源描述"),
            ("requiredAction", "来源要求的行动"),
            ("dueDate", "来源所列截止日"),
            ("knownRansomwareCampaignUse", "勒索软件活动使用状态"),
        ):
            include("/" + field, label)
        limitation = "此题包证明的是 KEV 目录声明，不能确认具体本地资产命中、漏洞复现或修复版本；Unknown 不等于未被勒索软件利用。法规与行动要求仅转述冻结条目，未核验外链正文。"
    elif source == "crossref":
        for field, label in (
            ("DOI", "DOI"),
            ("title", "题名"),
            ("type", "文献类型"),
            ("publisher", "出版者"),
            ("author", "作者元数据"),
            ("published", "出版日期元数据"),
            ("abstract", "所存摘要的作者陈述"),
        ):
            if field in a:
                include("/" + field, label)
        limitation = (
            "只能确认所存书目信息"
            + ("和摘要中的作者陈述" if a.get("abstract") else "；此记录未存摘要")
            + "。未阅读论文全文，不能把标题、DOI、引用数量或下载链接当作实验有效性、安全改进或结果复现的证据。"
        )
    elif source == "nvd":
        for field, label in (
            ("id", "NVD 编号"),
            ("vulnStatus", "记录状态"),
            ("descriptions", "来源描述（保留语言与限定）"),
            ("affected", "各发布方的产品及版本声明"),
            ("metrics", "来源评分（保留评分版本和发布方）"),
            ("configurations", "CPE 配置条件"),
        ):
            if field in a:
                include("/" + field, label)
        limitation = "描述、affectedData 和 CPE 配置属于不同来源表示；缺少 configurations 不等于没有版本证据。不能由 CVSS、公开 PoC 或引用链接推断本地资产命中及实际在野利用，未核验外链正文。"
        description = encoded(a.get("descriptions", []))
        if "disputed" in description.casefold():
            limitation += "原文明示漏洞存在争议且提出替代解释，因此不确认争议指控为已验证事实。"
    else:
        for field, label in (
            ("ghsa_id", "公告编号"),
            ("cve_id", "关联 CVE"),
            ("summary", "来源标题"),
            ("description", "来源正文（包含触发条件、影响及保留意见）"),
            ("severity", "来源评级"),
            ("vulnerabilities", "逐包受影响与修复声明"),
            ("cvss_severities", "来源评分"),
            ("withdrawn_at", "撤回时间"),
        ):
            if field in a:
                include("/" + field, label)
        limitation = "以上是公告在冻结时的声明；仅适用于正文限定的部署和触发条件，不能推断所有部署均受影响或已在本地复现。受影响范围与修复字段分别保留，不擅自补齐上界；空 ecosystem 仅标为 unknown，不能推定 pip。未核验外链正文。"
        if a.get("withdrawn_at"):
            limitation += (
                "公告已作为重复条目撤回，应保留撤回状态和原始描述，不能将其计作新的独立漏洞。"
            )
        special_notes = {
            "GHSA-7m6h-x95x-82q5": "结构化字段写 < 0.21.0，但正文 Versions 段也描述 0.21.0 之后的代码路径，且修复字段为 >= 0.27.0；不能把 0.21.0 至 0.27.0 之间判为安全。",
            "GHSA-wv77-2vpf-vmmg": "受影响字段上界为 0.11.1，修复字段为 0.14.0，中间区间的状态不能仅由这两个字段确定。",
            "GHSA-rh4j-5rhw-hr54": "受影响字段 <= 0.7.0 与修复字段 v0.7.0 在 0.7.0 边界存在重叠；保留矛盾，不确认该边界版本安全。",
            "GHSA-hhv2-872h-628q": "受影响字段 >= 0.22.1, <= 0.28.0 与修复字段 >= 0.28.0 在 0.28.0 重叠；保留矛盾，不确认该边界版本安全。",
        }
        if a.get("ghsa_id") in special_notes:
            limitation += special_notes[a["ghsa_id"]]
    parts.append("证据边界：" + limitation)
    return {
        "task_id": record["event_id"],
        "drafted_at": now(),
        "reviewed_at": None,
        "answer_class": "partial",
        "complete_answer": "\n\n".join(parts),
        "supported_fields": list(citations),
        "citations": list(citations.values()),
        "refusal_reason": limitation,
        "enrichment_facts": source_facts(record),
    }


def differences(packet):
    """Source discrepancies, not invented A/B reviewer disagreements."""
    groups = defaultdict(list)
    for r in packet["records"]:
        groups[r["group_id"]].append(r)
    result = []
    for group, records in groups.items():
        entries = []
        for r in records:
            a = r["raw_record"]
            for i, v in enumerate(a.get("vulnerabilities", [])):
                entries.append(
                    {
                        "task_id": r["event_id"],
                        "source_id": r["source_id"],
                        "scope": v,
                        "citation": citation(r, f"/vulnerabilities/{i}"),
                    }
                )
            for i, authority in enumerate(a.get("affected", [])):
                for j, v in enumerate(authority.get("affectedData", [])):
                    if canonical(v.get("product")) == "vllm":
                        entries.append(
                            {
                                "task_id": r["event_id"],
                                "source_id": r["source_id"],
                                "scope": v,
                                "citation": citation(r, f"/affected/{i}/affectedData/{j}"),
                            }
                        )
        if len({x["task_id"] for x in entries}) > 1:
            result.append(
                {
                    "group_id": group,
                    "entries": entries,
                    "resolution": "retain_source_scopes_separately",
                    "reason": "各来源的原始范围、包标识与修复字段分别保留。字符串/表示差异不自动等于事实冲突，也不以多数票合并为统一受影响范围；统一结论证据不足。",
                    "review_method": "ai_assisted",
                    "human_adjudicated": False,
                }
            )
    return result


def draft(packet, out):
    answers = []
    records = {r["event_id"]: r for r in packet["records"]}
    for task in packet["tasks"]:
        answer = source_answer(records[task["id"]])
        validate_answer(packet, task, answer)
        for item in answer["enrichment_facts"]:
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
        answers.append(answer)
    save(
        out / "source-review-ai.json",
        seal(
            {
                "version": "source-review-ai-v1",
                "packet_sha256": packet["sha256"],
                "created_at": now(),
                "review_method": "ai_assisted_source_extraction",
                "reviewer_id": "codex-ai",
                "independent_review_attested": False,
                "human_review_completed": False,
                "status": "draft_pending_human_review",
                "answer_class_policy": "partial 表示可转述来源声明，但未验证现实有效性；不是模型拒答评分标签。",
                "reviews": answers,
                "source_scope_comparisons": differences(packet),
                "human_reviewer_disagreements": {
                    "status": "not_available",
                    "reason": "A/B 均未提交，不能裁决不存在的审核分歧",
                },
            }
        ),
    )


def snapshot(packet, database, out):
    records = {r["event_id"]: r for r in packet["records"]}
    rows = []
    connection = sqlite3.connect(f"file:{database.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("BEGIN")
    try:
        for task in packet["tasks"]:
            if task["split"] != "test":
                continue
            r = records[task["id"]]
            revision = connection.execute(
                "SELECT r.*, d.sha256 FROM event_revisions r JOIN raw_documents d ON d.id=r.raw_document_id WHERE r.id=?",
                (r["revision_id"],),
            ).fetchone()
            if not revision or any(
                revision[k] != r[k]
                for k in ("event_id", "raw_document_id", "record_pointer", "sha256")
            ):
                raise ValueError("Frozen revision/raw document mismatch: " + task["id"])
            # Verify original file bytes and the relative frozen record.
            raw_path = Path("data/raw") / r["sha256"][:2] / (r["sha256"] + ".json")
            raw_bytes = raw_path.read_bytes()
            if (
                hashlib.sha256(raw_bytes).hexdigest() != r["sha256"]
                or resolve_pointer(json.loads(raw_bytes), r["record_pointer"]) != r["raw_record"]
            ):
                raise ValueError("Frozen source bytes mismatch: " + task["id"])
            row = connection.execute(
                "SELECT * FROM event_enrichments WHERE event_id=?", (task["id"],)
            ).fetchone()
            value = dict(row) if row else None
            if value:
                if value["revision_id"] != r["revision_id"]:
                    raise ValueError("Prediction uses another source revision: " + task["id"])
                for key in (
                    "entities",
                    "version_ranges",
                    "cvss",
                    "cpe_matches",
                    "quality_flags",
                    "provenance",
                ):
                    value[key] = json.loads(value[key])
            rows.append(
                {
                    "task_id": task["id"],
                    "revision_id": r["revision_id"],
                    "source_sha256": r["sha256"],
                    "prediction": value,
                }
            )
    finally:
        connection.close()
    save(
        out / "test-predictions.json",
        seal(
            {
                "version": "frozen-test-predictions-v1",
                "packet_sha256": packet["sha256"],
                "database": str(database),
                "exported_at": now(),
                "predictions": rows,
            }
        ),
    )


def prediction_facts(p):
    if p is None:
        return []
    result = []
    for entity in p["entities"]:
        if entity["type"] == "package":
            result.append(
                fact(
                    "entity:package", canonical(entity.get("ecosystem")), canonical(entity["value"])
                )
            )
        else:
            result.append(fact("entity:" + entity["type"], canonical(entity["value"])))
    for v in p["version_ranges"]:
        if v.get("source_kind") == "nvd_affected_data":
            identity = {
                key: v.get(key)
                for key in ("vendor", "product", "packageName", "packageURL", "defaultStatus")
            }
            result.append(
                fact("nvd_affected_version", v.get("authority"), identity, v.get("version_status"))
            )
            continue
        identity = [canonical(v.get("ecosystem")), canonical(v.get("package"))]
        for field, kind in (("vulnerable", "vulnerable_range"), ("fixed", "fixed_range")):
            if (v.get(field) or {}).get("raw"):
                result.append(fact(kind, *identity, range_text(v[field]["raw"])))
    for v in p["cvss"].get("entries", []):
        result.append(
            fact("cvss", v.get("version"), v.get("vector"), v.get("score"), v.get("source"))
        )
    for v in p["cpe_matches"]:
        result.append(
            fact(
                "cpe_match",
                v["criteria"],
                bool(v.get("vulnerable")),
                *[v.get(k) for k in SNAKE_BOUNDS],
            )
        )
    return result


def score_sets(expected, actual):
    expected, actual = set(map(encoded, expected)), set(map(encoded, actual))
    tp, fp, fn = expected & actual, actual - expected, expected - actual
    return {
        "tp": len(tp),
        "fp": len(fp),
        "fn": len(fn),
        "missing": [json.loads(x) for x in sorted(fn)],
        "unsupported": [json.loads(x) for x in sorted(fp)],
    }


def aggregate(rows):
    tp, fp, fn = (sum(r[k] for r in rows) for k in ("tp", "fp", "fn"))
    exact = sum(r["fp"] == r["fn"] == 0 and not r.get("missing_prediction", False) for r in rows)
    return {
        "records": len(rows),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "fact_precision": tp / (tp + fp) if tp + fp else None,
        "fact_recall": tp / (tp + fn) if tp + fn else None,
        "exact_records": exact,
        "record_exact_accuracy": exact / len(rows) if rows else None,
    }


def score(packet, out):
    review, predictions = read(out / "source-review-ai.json"), read(out / "test-predictions.json")
    for artifact in (review, predictions):
        validate_seal(artifact)
        if artifact["packet_sha256"] != packet["sha256"]:
            raise ValueError("Wrong packet")
    expected = {r["task_id"]: r for r in review["reviews"]}
    actual = {r["task_id"]: r for r in predictions["predictions"]}
    tasks = [t for t in packet["tasks"] if t["split"] == "test"]
    if len(actual) != len(predictions["predictions"]) or set(actual) != {t["id"] for t in tasks}:
        raise ValueError("Prediction manifest must include every test task exactly once")
    records = {r["event_id"]: r for r in packet["records"]}
    rows = []
    for task in tasks:
        r = records[task["id"]]
        a = actual[task["id"]]
        if a["revision_id"] != r["revision_id"] or a["source_sha256"] != r["sha256"]:
            raise ValueError("Prediction identity mismatch")
        gold = [x["fact"] for x in expected[task["id"]]["enrichment_facts"]]
        pred = prediction_facts(a["prediction"])
        rows.append(
            {
                "task_id": task["id"],
                "source_id": r["source_id"],
                "external_id": r["external_id"],
                "group_id": task["group_id"],
                "missing_prediction": a["prediction"] is None,
                **score_sets(gold, pred),
                "expected_facts": gold,
                "predicted_facts": pred,
            }
        )
    sources = {
        s: aggregate([r for r in rows if r["source_id"] == s])
        for s in sorted({r["source_id"] for r in rows})
    }
    groups = {
        g: aggregate([r for r in rows if r["group_id"] == g])
        for g in sorted({r["group_id"] for r in rows})
    }
    categories = {}
    for kind in sorted({f[0] for r in rows for f in r["expected_facts"] + r["predicted_facts"]}):
        category_rows = [
            score_sets(
                [f for f in r["expected_facts"] if f[0] == kind],
                [f for f in r["predicted_facts"] if f[0] == kind],
            )
            for r in rows
        ]
        metrics = aggregate(category_rows)
        categories[kind] = {
            k: metrics[k] for k in ("tp", "fp", "fn", "fact_precision", "fact_recall")
        }
    save(
        out / "test-enrichment-evaluation.json",
        seal(
            {
                "version": "provisional-source-fact-evaluation-v1",
                "created_at": now(),
                "status": "provisional_not_human_gold",
                "packet_sha256": packet["sha256"],
                "review_sha256": review["sha256"],
                "predictions_sha256": predictions["sha256"],
                "evaluator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "official_scores": None,
                "split": "test",
                "metrics": aggregate(rows),
                "by_source": sources,
                "by_fact_category": categories,
                "groups": len(groups),
                "group_macro_recall": sum(g["fact_recall"] for g in groups.values()) / len(groups),
                "fully_correct_groups": sum(
                    g["exact_records"] == g["records"] for g in groups.values()
                ),
                "scope": "Source-asserted structured facts only: identifiers, vendor/product/package entities, advisory raw version ranges, CVSS version/vector/score/publisher, CPE leaf criteria/bounds, and NVD affectedData version objects with publisher/product/status. Not full-answer semantic accuracy, field provenance entailment, version parser correctness, CPE boolean semantics, selected CVSS policy, quality flags, or real-world vulnerability verification.",
                "normalization": "Casefold entity identifiers; empty ecosystem=unknown; remove version-range whitespace only. Deduplicate within task, never across sources. No TN definition, so do not call precision binary accuracy. Missing predictions remain FN.",
                "rows": rows,
            }
        ),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["draft", "snapshot", "score"])
    parser.add_argument("--output", type=Path, default=OUT)
    parser.add_argument("--database", type=Path, default=Path("data/member-b-week6-eval.db"))
    args = parser.parse_args()
    packet = read(ROOT / "source-packet.json")
    validate_seal(packet)
    if args.command == "draft":
        draft(packet, args.output)
    elif args.command == "snapshot":
        snapshot(packet, args.database, args.output)
    else:
        score(packet, args.output)
    print(
        json.dumps(
            {
                "command": args.command,
                "output": str(args.output),
                "status": "complete_provisional_only",
            }
        )
    )


if __name__ == "__main__":
    main()
