"""Freeze new questions and AI source gold before any benchmark output exists."""

import argparse
import hashlib
import json
import re
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.engine import make_url

from zhidu.agent_tools import _verified_row
from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.models import EventAlias, IntelEvent
from zhidu.paired_evaluation import DimensionObservation, EvidenceField, digest
from zhidu.semantic import active_chunks
from zhidu.storage import BlobStore

CONDITIONS = {
    "105752": (
        "cache_salt",
        "GPT-OSS Harmony /v1/responses 的工具续轮丢失 cache_salt；另一租户猜测工具后历史可利用未加盐缓存做提示成员侧信道；不能泛化为所有部署。",
    ),
    "105754": (
        "kwargs_data",
        "分离式 scale-out /inference/v1/generate 信任请求 features 中张量、缓存标识和占位范围，可能终止共享 EngineCore，或在知道/诱导受害者内容哈希时污染跨请求缓存。",
    ),
    "105755": (
        "X-Request-Id",
        "启用 flash late interaction 的 /score 或 /rerank 使用调用者 X-Request-Id 作为查询缓存键；并发复用受害者标识可覆盖查询嵌入、污染评分或引发缓存错误，需要受害者标识和并发条件。",
    ),
    "105756": (
        "LMCache",
        "使用 LMCache-MP 的部署未严格校验 cache_salt；恶意请求可沿异常传播终止共享 EngineCore，是有部署前提的拒绝服务。",
    ),
    "105757": (
        "structured",
        "特定结构化输出请求触发的后端/响应处理异常越过请求边界并终止共享服务；是共享服务拒绝服务，不能把配置条件省略。",
    ),
    "105758": (
        "Qwen",
        "服务 Qwen2-VL 或 Qwen3-VL 模型时，请求 media_io_kwargs.video.max_frames 与 fps 缺少服务器上限，未认证远程输入可耗尽 API-server 内存。",
    ),
    "105759": (
        "Rust",
        "Rust frontend 的 HTTP 指标中间件把调用者可控 HTTP method 原样作为 Prometheus label，独特方法值导致无界基数和内存耗尽；不能泛化为默认 Python frontend。",
    ),
    "105760": (
        "GLMGA",
        "请求 media_io_kwargs 选择 GLMGA 视频采样器并设大 fps/max_frames，采样器在去重前构造大索引列表，造成 CPU/内存耗尽；需保留视频后端条件。",
    ),
}


def file_sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def old_identifiers(supersedes=None):
    identifiers, files = set(), []
    paths = []
    for root in ("config", "docs", "tests", "scripts"):
        paths.extend(p for p in Path(root).rglob("*") if p.suffix in {".json", ".md", ".py"})
    paths += list(Path("data").glob("*review/*.json"))
    paths += list(Path("data/week6-ai-gold").glob("*.json"))
    paths += [
        p
        for p in Path("output").rglob("*.json")
        if any(token in str(p).lower() for token in ("paired", "smoke", "prereview", "gold"))
    ]
    for path in sorted(set(paths)):
        if path.resolve() == Path(__file__).resolve():
            continue
        if supersedes and supersedes.resolve() in path.resolve().parents:
            continue
        text = path.read_text(errors="ignore")
        identifiers.update(
            re.findall(r"CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", text, re.I)
        )
        files.append({"path": str(path), "sha256": file_sha(path)})
    return {s.casefold() for s in identifiers}, files


def evidence(row, quote=None):
    return EvidenceField(
        source_id=row.source_id,
        event_id=row.event_id,
        chunk_id=row.id,
        json_pointer=row.json_pointer,
        sha256=row.sha256,
        text=row.text,
        quote=quote or row.text,
    ).model_dump()


def freeze(output, supersedes=None):
    settings = Settings()
    output.mkdir(parents=True, exist_ok=False)
    prior, exclusion_files = old_identifiers(supersedes)
    if supersedes:
        if list((supersedes / "answers").glob("*.json")) or list(
            (supersedes / "judgments").glob("*.json")
        ):
            raise ValueError("cannot_supersede_after_model_outputs")
    source_db = Path(make_url(settings.database_url).database).resolve()
    snapshot = output / "corpus.sqlite"
    with sqlite3.connect(f"file:{source_db}?mode=ro", uri=True) as origin:
        with sqlite3.connect(snapshot) as target:
            origin.backup(target)
            assert target.execute("pragma integrity_check").fetchone()[0] == "ok"
    engine = make_engine(f"sqlite:///{snapshot}")
    sessions = make_sessions(engine)
    original_store = BlobStore(settings.raw_dir)
    corpus_store = BlobStore(output / "raw")
    cases = []
    with sessions() as session:
        rows = active_chunks(session)
        by_event = {}
        for row in rows:
            by_event.setdefault(row.event_id, []).append(row)
        events = {e.id: e for e in session.scalars(select(IntelEvent))}
        groups = {}
        for eid, alias in session.execute(select(EventAlias.event_id, EventAlias.value)):
            if alias.startswith("CVE-") and eid in by_event:
                groups.setdefault(alias, set()).add(eid)
        raw_hashes = sorted({r.sha256 for r in rows})
        for sha in raw_hashes:
            original_store.read(sha)
            dst = corpus_store.path_for(sha)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original_store.path_for(sha), dst)
        for identifier, ids in sorted(groups.items()):
            if identifier.split("-")[-1] not in CONDITIONS:
                continue
            if {identifier.casefold(), *(events[e].external_id.casefold() for e in ids)} & prior:
                continue
            sources = {events[e].source_id: e for e in ids}
            wanted = (
                ["github-advisories", "vllm-vendor"]
                if "github-advisories" in sources
                else ["vllm-vendor", "nvd"]
            )
            if any(s not in sources for s in wanted):
                continue
            facts = []
            ranges, repairs = {}, {}
            packet = []
            for source in wanted:
                eid = sources[source]
                fields = sorted(by_event[eid], key=lambda r: (r.field, r.start, r.id))
                package = next((r for r in fields if r.field == "packages"), None)
                if package:
                    value = json.loads(package.text)[0]
                    version_range = value["vulnerable_version_range"]
                    repair_name = (
                        "first_patched_version"
                        if "first_patched_version" in value
                        else "patched_versions"
                    )
                    repair = value.get(repair_name)
                    version_evidence = [evidence(package)]
                    repair_evidence = version_evidence
                else:
                    affected = next(r for r in fields if r.field.endswith("_version_0"))
                    value = json.loads(affected.text)
                    version_range = value["version"]
                    version_evidence = [evidence(affected)]
                    fixed = next(
                        r
                        for r in fields
                        if r.field == "description" and "fixed in version" in r.text
                    )
                    repair = (
                        re.search(r"fixed in version ([\w.]+)", fixed.text).group(1).rstrip(".")
                    )
                    repair_name = "description_fixed_in_version"
                    repair_evidence = [evidence(fixed)]
                ranges[source], repairs[source] = version_range, {repair_name: repair}
                facts += [
                    {
                        "id": f"{source}-range",
                        "dimension": "affected_range",
                        "expected": f"{source} 原始范围 {version_range}；不得自行补边界或修正疑似笔误。",
                        "evidence": version_evidence,
                    },
                    {
                        "id": f"{source}-repair",
                        "dimension": "remediation",
                        "expected": f"{source} 的 {repair_name} = {repair}；保留字段语义，不把补丁范围等同于首次修复字段。",
                        "evidence": repair_evidence,
                    },
                ]
                keyword, expected = CONDITIONS[identifier.split("-")[-1]]
                descriptions = [r for r in fields if r.field == "description"]
                selected = [r for r in descriptions if keyword.casefold() in r.text.casefold()][:3]
                packet += [evidence(r) for r in selected]
            facts.append(
                {
                    "id": "conditions",
                    "dimension": "conditions",
                    "expected": expected,
                    "evidence": packet,
                }
            )
            difference = f"分别保留范围 {ranges} 和修复字段 {repairs}。"
            if len(set(ranges.values())) > 1 or any("30.0.0" in str(v) for v in repairs.values()):
                difference += "明确提示原始范围/修复字段存在差异，不能静默修正或选定唯一权威结论。"
            else:
                difference += (
                    "两个来源结构化范围未显示差异；有首次修复和修补范围两种表达时应说明语义不同。"
                )
            facts.append(
                {
                    "id": "difference",
                    "dimension": "source_difference",
                    "expected": difference,
                    "evidence": [e for f in facts[:4] for e in f["evidence"]],
                }
            )
            for fact in facts:
                if not fact["evidence"]:
                    raise ValueError("gold_fact_without_source")
                for item in fact["evidence"]:
                    row = next(r for r in rows if r.id == item["chunk_id"])
                    _verified_row(session, corpus_store, row)
            dimensions = []
            for dimension in ("affected_range", "remediation", "conditions", "source_difference"):
                selected_facts = [f for f in facts if f["dimension"] == dimension]
                dimensions.append(
                    DimensionObservation(
                        dimension=dimension,
                        state="partial"
                        if dimension == "source_difference" and "存在差异" in difference
                        else "found",
                        scope=f"frozen formal/live source fields for {identifier}",
                        conclusion="；".join(f["expected"] for f in selected_facts),
                        evidence=[
                            EvidenceField.model_validate(e)
                            for f in selected_facts
                            for e in f["evidence"]
                        ],
                    ).model_dump()
                )
            cases.append(
                {
                    "id": f"pilot-{identifier}",
                    "group_id": identifier,
                    "split": "pilot",
                    "question": f"对照 {wanted[0]} 与 {wanted[1]} 对 {identifier} 的当前资料，分别给出原始受影响版本范围和修复字段（保留首次修复版本与修补范围的语义），说明触发配置/输入条件及影响；指出字段差异或一致之处。保留来源声明的证据边界，若有疑似笔误保留原文并标记待核。",
                    "query": identifier,
                    "source_ids": wanted,
                    "facts": facts,
                    "dimension_gold": dimensions,
                    "history": "new QA task; source previously in structured enrichment conformity audit",
                }
            )
    engine.dispose()
    if len(cases) != 8:
        raise ValueError(f"expected predeclared eight eligible groups, got {len(cases)}")
    implementation = {
        str(p): file_sha(p)
        for p in [
            *sorted(Path("src/zhidu").glob("*.py")),
            Path(__file__),
            Path("scripts/run_agent_paired_pilot.py"),
        ]
    }
    protocol = {
        "version": "agent-paired-pilot-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "scope": "new_question_pretest_not_untouched_source_holdout",
        "gold_review": {
            "method": "AI_source_review",
            "human_reviewed": False,
            "adoption": "user_authorized_project_gold_only",
            "frozen_before_outputs": True,
        },
        "organizer_scoring_rules": {
            "dimension_separation": "user_supplied_FAQ",
            "no_data_api_errors_partial_citation_rules": "unanswered_FAQ_rows_10_11; project rubric below is not organizer certification",
        },
        "budget": {
            "model_calls_per_answer": 5,
            "tool_calls_per_answer": 6,
            "completion_tokens_per_call": 1800,
            "soft_deadline_seconds": 30,
            "tool_output_chars": 18000,
            "max_generation_requests": 56,
            "max_judge_requests": 24,
            "max_total_requests": 80,
        },
        "matching": {
            "corpus": "identical frozen formal/live corpus + raw bytes",
            "model": "same configured model/profile",
            "retrieval": "lexical for all initial queries; native agent has same tool set",
            "rag": "one retrieval + existing production source context expansion + one generation",
            "workflow": "fixed retrieve -> ordered read_fields(packages,description) -> up to two Patches reads -> one generation",
            "langchain": "native adaptive framework tool selection",
            "prompt": "existing strategy-specific production prompts; same source-boundary rules, NOT identical prompts",
            "context": "common 18000 character evidence ceiling; metadata and repeated history tokens audited; native tool metadata also consumes ceiling",
        },
        "rubric": {
            "strict": "completed generation + every frozen fact covered and semantically grounded + all generated statements entailed by THEIR cited quotes + verbatim quotes + evidence boundary respected",
            "denominator": "all frozen cases, failed attempts included; absent judge is unknown, never silently excluded from confirmed strict rate",
            "fact_recall": "grounded required facts / required facts in judged answers",
            "precision": "semantically supported generated statements / generated statements in judged answers",
            "missing_data": "not_found_in_scope is not not_public; interface_error and not_connected never assert absent real-world data",
            "class_accuracy": "not scored: source-level classes and task semantic completion are separate",
            "judge": "single anonymous AI review with rationale; same provider bias remains; no human identity or independent human attestation",
            "statistics": "identifier-group paired bootstrap; exploratory small single-component pilot",
            "gain_gate": "no population claim from this pilot; future isolated multi-component holdout required",
        },
        "corpus_sha256": file_sha(snapshot),
        "raw_sha256": raw_hashes,
        "prior_QA_exclusions": exclusion_files,
        "source_history_audits": [
            {"path": str(p), "sha256": file_sha(p)}
            for p in (
                Path(
                    "output/member-a-monitoring-enrichment-evaluation-20261009/current-source-conformity.json"
                ),
                Path(
                    "output/member-a-monitoring-enrichment-evaluation-20261009/monitoring-evaluation.json"
                ),
            )
        ],
        "implementation_sha256": implementation,
        "cases": cases,
        "supersedes_pre_inference": {
            "path": str(supersedes),
            "protocol_sha256": file_sha(supersedes / "protocol.json"),
            "reason": "offline-only diagnosis: negative disclaimer triggered legacy RAG guard; diversified source-tool retrieval before any live output",
        }
        if supersedes
        else None,
    }
    protocol["freeze_sha256"] = digest(protocol)
    (output / "protocol.json").write_text(json.dumps(protocol, ensure_ascii=False, indent=2) + "\n")
    print(
        json.dumps(
            {
                "output": str(output),
                "groups": len(cases),
                "scope": protocol["scope"],
                "sha256": protocol["freeze_sha256"],
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--supersedes", type=Path)
    args = parser.parse_args()
    freeze(args.output, args.supersedes)
