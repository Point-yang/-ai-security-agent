"""Freeze four new identifier groups and atomic AI source gold before model output."""

import argparse
import hashlib
import json
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.engine import make_url

from zhidu.agent_tools import _verified_row
from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.indexing import sync_index
from zhidu.ingest import ingest_document
from zhidu.model_provider import model_profile
from zhidu.models import EventAlias, EventTriage
from zhidu.paired_evaluation import DimensionObservation, EvidenceField, digest
from zhidu.semantic import active_chunks
from zhidu.sources import SOURCES, prepare
from zhidu.storage import BlobStore

# Source review authored before predictions. A needle identifies exact primary
# text and serves only to find its provenance chunk, never to score an answer.
SPECS = {
    "torch": {
        "question": "分别保留 GitHub 的原始受影响范围和首次修复字段，以及 NVD 描述中的版本断言。NVD 对 ctc_loss 的攻击接近方式、影响及漏洞真实性有什么限定？不要把单个版本观察扩成完整范围。",
        "facts": [
            (
                "nvd-version",
                "affected_range",
                "nvd",
                "PyTorch 2.6.0",
                "NVD 称问题在 PyTorch 2.6.0 中发现；这是描述中的版本观察，不自动等于整个受影响范围。",
            ),
            (
                "target-function",
                "conditions",
                "nvd",
                "torch.nn.functional.ctc_loss",
                "NVD 指向 torch.nn.functional.ctc_loss 函数。",
            ),
            (
                "attack-condition",
                "conditions",
                "nvd",
                "approached locally",
                "NVD 声明攻击需要本地接近，不能说成无条件远程攻击。",
            ),
            ("impact", "conditions", "nvd", "denial of service", "NVD 声明影响为拒绝服务。"),
            (
                "dispute",
                "source_difference",
                "nvd",
                "real existence",
                "NVD 明确说漏洞真实存在性仍受到怀疑；保留这一限定，不宣称已经裁定存在或已验证。",
            ),
        ],
    },
    "transformers": {
        "question": "分别给出 GitHub 版本范围、首次修复字段与 NVD 的原始版本描述，比较两者。load_custom_generate 的信任检查与写文件的先后是什么？拒绝信任后能否据来源说成立即执行远程代码？说明已声明的影响边界。",
        "facts": [
            (
                "nvd-version",
                "affected_range",
                "nvd",
                "4.57.0 to 5.16.1",
                "NVD 的原始版本描述为 4.57.0 to 5.16.1。",
            ),
            (
                "range-difference",
                "source_difference",
                "github-advisories",
                "4.49.0",
                "GitHub 结构化范围 >= 4.49.0, <= 5.8.1 与 NVD 描述 4.57.0 to 5.16.1 不同，分别归属，不自动选定或改写一个范围。",
            ),
            (
                "ordering",
                "conditions",
                "nvd",
                "before performing",
                "load_custom_generate 在 trust_remote_code 同意检查之前抓取并缓存远程模块文件。",
            ),
            (
                "unauthorized-write",
                "conditions",
                "nvd",
                "declines the trust prompt",
                "即使用户拒绝信任，攻击者控制的 Python 文件仍被写入本地缓存，写入可跨会话持久存在。",
            ),
            (
                "execution-boundary",
                "conditions",
                "nvd",
                "execution is correctly gated",
                "来源明确执行仍受信任检查控制；不能把未授权写文件等同于拒绝信任后立即执行。",
            ),
        ],
    },
    "ray": {
        "question": "给出 GitHub 的原始受影响范围和首次修复字段。依据 NVD 说明 read_webdataset 的攻击输入、两个默认解码分支及影响；依据 GitHub 说明 decoder 默认和 PyTorch 的 weights_only 安全默认是否阻止该路径，以及 Parquet 的 2.55.0 补丁是否覆盖此处。",
        "facts": [
            (
                "tar-input",
                "conditions",
                "nvd",
                "malicious tar archive",
                "攻击者提供恶意 TAR 给 read_webdataset；这是来源声明的攻击输入条件。",
            ),
            (
                "pickle-branch",
                "conditions",
                "nvd",
                "pickle.loads()",
                ".pkl/.pickle 条目走 pickle.loads() 不安全反序列化。",
            ),
            (
                "torch-branch",
                "conditions",
                "nvd",
                "weights_only=False",
                ".pt/.pth 条目走 torch.load(weights_only=False)，不能当作使用安全默认。",
            ),
            (
                "impact",
                "conditions",
                "nvd",
                "remote workers",
                "NVD 声明可在处理该恶意归档的 Ray remote workers 上执行任意代码。",
            ),
            (
                "decoder-default",
                "conditions",
                "github-advisories",
                "default `decoder=True`",
                "GitHub 声明默认 decoder=True 触发解码，无需额外 opt-in。",
            ),
            (
                "pytorch-default",
                "source_difference",
                "github-advisories",
                "PyTorch 2.6 changed",
                "GitHub 说明该路径显式 weights_only=False 覆盖 PyTorch 2.6 的较安全默认，不可因上游默认改变判定这条路径安全。",
            ),
            (
                "parquet-fix-boundary",
                "source_difference",
                "github-advisories",
                "different code site",
                "GitHub 说明 Parquet 2.55.0 补丁修的是不同位置，没有覆盖 WebDataset 路径。",
            ),
        ],
    },
    "mlflow": {
        "question": "给出 GitHub 的原始范围与首次修复字段。分别引用 NVD 的 api_base/proxy 机制、GitHub 的调用身份与 SSRF 守卫条件；CVE-2026-4035 的 api_key 修复是否覆盖这个 api_base 问题？不要从较短的 NVD 描述推断无需认证。",
        "facts": [
            (
                "destination-validation",
                "conditions",
                "nvd",
                "no validation of scheme",
                "创建 gateway secret 时接受并原样保存 api_base，没有校验 scheme、host 或 IP 范围。",
            ),
            (
                "proxy-effect",
                "conditions",
                "nvd",
                "returns the full response body",
                "proxy 使用已保存的 api_base 加调用者路径发出 HTTP 请求并返回完整响应体。",
            ),
            (
                "auth-condition",
                "conditions",
                "github-advisories",
                "read-only accounts",
                "GitHub 声明只需 basic authentication，包含只读账户在内的已认证用户可创建相关 secret；不是无条件未认证访问。",
            ),
            (
                "ssrf-guard",
                "conditions",
                "github-advisories",
                "_validate_webhook_url",
                "GitHub 声明现有 SSRF 守卫 _validate_webhook_url 未在该 gateway secret/proxy 路径调用。",
            ),
            (
                "fix-boundary",
                "source_difference",
                "github-advisories",
                "unaffected by that fix",
                "GitHub 明确 api_base 目的地址缺校验独立于 CVE-2026-4035 的 api_key 环境变量解析机制，未被那个修复覆盖。",
            ),
        ],
    },
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def field_evidence(row):
    return EvidenceField(
        source_id=row.source_id,
        event_id=row.event_id,
        chunk_id=row.id,
        json_pointer=row.json_pointer,
        sha256=row.sha256,
        text=row.text,
        quote=row.text,
    ).model_dump()


def freeze(intake, output, supersedes=None):
    manifest = json.loads((intake / "manifest.json").read_text())
    excluded = json.loads((intake / "exclusions.json").read_text())
    groups = manifest["groups"]
    if supersedes and (
        list((supersedes / "answers").glob("*.json"))
        or list((supersedes / "judgments").glob("*.json"))
    ):
        raise ValueError("cannot_supersede_after_any_model_output")
    if len(groups) != 4 or any(not g["two_public_sources_available"] for g in groups):
        raise ValueError("preselected_source_pairs_incomplete")
    settings = Settings()
    output.mkdir(parents=True, exist_ok=False)
    main_db = Path(make_url(settings.database_url).database).resolve()
    snapshot = output / "corpus.sqlite"
    with (
        sqlite3.connect(f"file:{main_db}?mode=ro", uri=True) as original,
        sqlite3.connect(snapshot) as target,
    ):
        current = {
            r[0]
            for r in original.execute(
                "select value from event_aliases union select external_id from events"
            )
        }
        if any({g["cve_id"], g["ghsa_id"]} & current for g in groups):
            raise ValueError("identifier_no_longer_new")
        original.backup(target)
    store = BlobStore(output / "raw")
    engine = make_engine(f"sqlite:///{snapshot}")
    sessions = make_sessions(engine)
    old_store = BlobStore(settings.raw_dir)
    cases = []
    with sessions.begin() as session:
        for g in groups:
            for source, name in (("github-advisories", "github"), ("nvd", "nvd")):
                path = intake / g[f"{name}_raw_path"]
                if sha(path) != g[f"{name}_sha256"]:
                    raise ValueError("intake_source_bytes_changed")
                raw = path.read_bytes()
                prepared, _ = prepare(source, raw)
                selected = [
                    p
                    for p in prepared
                    if p.normalized["external_id"]
                    == (g["ghsa_id"] if name == "github" else g["cve_id"])
                ]
                if len(selected) != 1:
                    raise ValueError("source_identifier_not_unique")
                url = next(
                    r["url"]
                    for r in manifest["requests"]
                    if r["attempt"] == g[f"{name}_request_attempt"]
                )
                ingest_document(
                    session,
                    store,
                    raw,
                    url,
                    datetime.now(UTC),
                    "live",
                    spec=SOURCES[source],
                    prepared=selected,
                )
            # Keep exact CVE-linked NVD observations in the AI source pool even
            # where a short NVD description omits generic AI classifier keywords.
            for eid in session.scalars(
                select(EventAlias.event_id).where(EventAlias.value == g["cve_id"])
            ):
                triage = session.get(EventTriage, eid)
                if triage.label != "relevant":
                    triage.label = "relevant"
                    triage.rule_version = "fresh-cve-linked-relevance-v1"
                    triage.matches = {
                        **triage.matches,
                        "exact_cve_link": g["cve_id"],
                        "public_ai_package": g["package"],
                    }
        sync_index(session)
    with sessions() as session:
        rows = active_chunks(session)
        raw_hashes = sorted({r.sha256 for r in rows})
        for raw_sha in raw_hashes:
            if not store.path_for(raw_sha).exists():
                old_store.read(raw_sha)
                target = store.path_for(raw_sha)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(old_store.path_for(raw_sha), target)
        for g in groups:
            ids = set(
                session.scalars(select(EventAlias.event_id).where(EventAlias.value == g["cve_id"]))
            )
            scoped = [r for r in rows if r.event_id in ids]
            facts = []
            package_row = next(
                r for r in scoped if r.source_id == "github-advisories" and r.field == "packages"
            )
            package = next(
                v for v in json.loads(package_row.text) if v["package"]["name"] == g["package"]
            )
            facts += [
                {
                    "id": "github-range",
                    "dimension": "affected_range",
                    "expected": f"GitHub 的原始 {g['package']} 范围为 {package['vulnerable_version_range']}，不改写边界。",
                    "evidence": [field_evidence(package_row)],
                },
                {
                    "id": "github-repair",
                    "dimension": "remediation",
                    "expected": f"GitHub first_patched_version = {package.get('first_patched_version')!r}。"
                    + (
                        "null 仅是当前字段为空，不证明无修复或无公开数据。"
                        if package.get("first_patched_version") is None
                        else "保留首次修复点语义。"
                    ),
                    "evidence": [field_evidence(package_row)],
                },
            ]
            for fid, dimension, source, needle, expected in SPECS[g["package"]]["facts"]:
                matching = [
                    r
                    for r in scoped
                    if r.source_id == source and r.field == "description" and needle in r.text
                ]
                if not matching:
                    raise ValueError(f"gold_quote_not_in_source_chunk: {g['package']} {fid}")
                ev = [field_evidence(matching[0])]
                if fid == "range-difference":
                    ev += [
                        field_evidence(package_row),
                        field_evidence(
                            next(
                                r
                                for r in scoped
                                if r.source_id == "nvd"
                                and r.field == "description"
                                and "4.57.0 to 5.16.1" in r.text
                            )
                        ),
                    ]
                facts.append(
                    {"id": fid, "dimension": dimension, "expected": expected, "evidence": ev}
                )
            for fact in facts:
                for e in fact["evidence"]:
                    _verified_row(session, store, next(r for r in scoped if r.id == e["chunk_id"]))
            dimensions = []
            for dimension in ("affected_range", "remediation", "conditions", "source_difference"):
                relevant = [f for f in facts if f["dimension"] == dimension]
                dimensions.append(
                    DimensionObservation(
                        dimension=dimension,
                        state="partial"
                        if (
                            dimension == "remediation"
                            and package.get("first_patched_version") is None
                        )
                        or (
                            dimension == "source_difference"
                            and g["package"] in {"torch", "transformers"}
                        )
                        else "found",
                        scope=f"frozen GitHub/NVD fields for {g['cve_id']}",
                        conclusion="；".join(f["expected"] for f in relevant),
                        evidence=[
                            EvidenceField.model_validate(e) for f in relevant for e in f["evidence"]
                        ],
                    ).model_dump()
                )
            cases.append(
                {
                    "id": f"fresh-{g['package']}",
                    "group_id": g["cve_id"],
                    "package": g["package"],
                    "query": g["cve_id"],
                    "question": f"对照 github-advisories 与 nvd 对 {g['cve_id']} 的来源声明："
                    + SPECS[g["package"]]["question"],
                    "split": "fresh_group_holdout",
                    "source_ids": ["github-advisories", "nvd"],
                    "event_ids": sorted(ids),
                    "facts": facts,
                    "dimension_gold": dimensions,
                    "history": "identifiers absent from pre-intake main/history exclusions; no generation inspected before source gold freeze",
                }
            )
    engine.dispose()
    protocol = {
        "version": "agent-fresh-holdout-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "scope": "fresh_identifier_group_holdout_four_components_small_pilot",
        "gold_review": {
            "method": "AI_source_review",
            "human_reviewed": False,
            "independent_human_attestation": False,
            "frozen_before_outputs": True,
            "adoption": "user_authorized_project_gold_not_organizer_certification",
        },
        "selection": {
            "preselected_packages": manifest["packages_preselected"],
            "method": "first eligible from fixed latest-five response; history/main exclusion before intake; no complexity replacement",
            "intake_manifest_sha256": sha(intake / "manifest.json"),
            "exclusions_sha256": sha(intake / "exclusions.json"),
            "exclusions_identifier_count": excluded.get(
                "identifiers_count", len(excluded.get("identifiers", []))
            ),
            "main_modified": False,
        },
        "budget": {
            "model_calls_per_answer": 5,
            "tool_calls_per_answer": 6,
            "completion_tokens_per_call": 1800,
            "soft_deadline_seconds": 30,
            "final_reserve_seconds": 8,
            "tool_output_chars": 18000,
            "max_generation_requests": 28,
            "max_judge_requests": 12,
            "max_total_requests": 40,
        },
        "matching": {
            "model_profile": model_profile(settings).public(),
            "temperature": 0,
            "answer_contract": "source-answer-v3",
            "quote_policy": "server-owned complete excerpts, identical resolver for all modes",
            "rag": "production lexical retrieval plus source context expansion, one generation",
            "workflow": "same fixed source-field workflow, one generation",
            "langchain": "adaptive native framework loop, at most five generation calls including JSON final",
            "source_pool": "same corpus; fresh NVD AI relevance by exact CVE association only in isolated copy",
        },
        "rubric": {
            "strict": "completed generation; all atomic required facts grounded; every generated statement entailed by its own quote; boundary respected",
            "semantic_judge": "anonymous AI receives only actual quoted spans and target facts, never unquoted citation text or gold source text",
            "source_scope": "source assertions only; no real-world exploitation/asset/patch execution claim",
            "failures": "all attempts retained; no automatic retry of uncertain outcome",
            "missing_fields": "null/absent local field is not not_public; interface_error and not_connected remain distinct",
            "statistics": "paired by whole CVE group; four convenience-selected components, exploratory only",
        },
        "limitations": [
            "4 identifier groups and one case per component; independently isolated from project history but too small for population or organizer accuracy claims",
            "GitHub and NVD can repeat the same upstream report; distinct records are not independent real-world corroboration",
            "gold review and anonymous semantic judging are AI, not human; same-provider judging bias remains and verdicts require review",
            "same model/temperature/final schema/evidence ceilings; strategy prompts and actual input token counts differ",
            "soft deadline/backend duration excludes HTTP UI/TTFT; API USD unknown",
            "FAQ rows 10/11 official treatment of failures/partial/no public data remains unknown",
            "real asset discovery, POC execution, task class accuracy and multi-role ablation not measured",
        ],
        "corpus_sha256": sha(snapshot),
        "raw_sha256": raw_hashes,
        "implementation_sha256": {
            str(p): sha(p)
            for p in [
                *sorted(Path("src/zhidu").glob("*.py")),
                Path(__file__),
                Path("scripts/run_agent_paired_pilot.py"),
            ]
        },
        "cases": cases,
        "supersedes_pre_inference": {
            "path": str(supersedes),
            "protocol_sha256": sha(supersedes / "protocol.json"),
            "reason": "known SDK length failure receipt, execution parameter binding and rejected-delivery scope rollback fixed before any prediction; source facts and selection unchanged",
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
                "atomic_facts": sum(len(c["facts"]) for c in cases),
                "sha256": protocol["freeze_sha256"],
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intake", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--supersedes", type=Path)
    args = parser.parse_args()
    freeze(args.intake, args.output, args.supersedes)
