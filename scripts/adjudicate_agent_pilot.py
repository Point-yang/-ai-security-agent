"""Apply the Codex AI's direct-quote review, preserving the anonymous first review."""

import argparse
import copy
import json
from datetime import UTC, datetime
from pathlib import Path

from run_agent_paired_pilot import answer_path, load_answer, load_protocol, save, sha

from zhidu.paired_evaluation import digest, score_answer, summarize

# Each completed generated answer was read against its own quotations. Event,
# source and field identifiers may use verified provenance metadata; technical
# properties such as ecosystem, deployment conditions and numeric measurements
# still require quotation support. True entries have complete substantive support.
CLAIMS = {
    ("105752", "workflow"): {
        1: True,
        2: True,
        3: True,
        4: True,
        5: True,
        6: "引文在 multi-turn lo 截断，未引用首轮盐、tokens_input 重提交或缺盐机制。",
        7: "引文只到第二租户开头，未包含猜测历史、cached-token 计数或成员推断操作。",
        8: "CWE 和 vendor Affected/Summary 复述等断言未在所引片段中出现。",
    },
    ("105754", "workflow"): {
        1: "引文只有版本和修复键，没有 pip 包生态。",
        2: True,
        3: "引文未包含下界早于 0.25.1 或维护者确认回溯范围。",
        4: "引文只到 kwargs_data，不含 mm_hashes、mm_placeholders、处理器或重绑定。",
        5: "所引文本不含跨请求缓存投毒/检索和稀疏掩码影响。",
        6: True,
        7: "引用在 CUDA illegal-memory-access 和 cache-key not b 截断，不含 ValueError、assert、掩码完整性等全部断言。",
        8: "CWE 引文只含 CWE-20 与 CWE-1284，不含所列其他分类。",
    },
    ("105755", "workflow"): {
        1: "引文只有版本与修复键，没有 pip 包生态。",
        2: True,
        3: "vendor 的下界与 packages 范围断言使用 github 的下界引文，未提供相应 vendor 引文。",
        4: True,
        5: "无需更多前提未被引文支持，且后续还声明需受害者标识和并发条件。",
        6: "数据并行路由把缓存键固定到同一引擎不在这条结论的引文中。",
        7: "引文未包括共享计数器错误、Moderate 或 CWE-639 等全部断言。",
        8: "引文仅是 vLLM 的介绍，不证明来源没有补丁正文或复现步骤。",
    },
    ("105756", "workflow"): {
        1: True,
        2: "跨源比较提到 github 的首次修复点，但本条引用仅有 vendor 字段。",
        3: True,
        4: "与 github 一致的跨源断言本条仅引用 vendor，没有 github 引文。",
        5: "引文只说接受 cache_salt，没有仅限非空字符串及无字符/长度限制。",
        6: "逐步调度缓存查找和关键字参数传递未被所引截断片段完整覆盖。",
        7: True,
        8: "CVSS/CWE 引文没有 Severity: Moderate 字段。",
    },
    ("105758", "workflow"): {
        1: "引文只有版本与修复键，没有 pip 包生态。",
        2: True,
        3: True,
        4: True,
        5: "内存与 RSS 数据有引文，但提高 max_frames 与 fps 的字段在引文中被截断。",
        6: True,
        7: "引用不含 GHSA-vxqj/PR #51969 的标识或无 max_frames 上限等完整断言。",
        8: "引文截断，不含 MediaConnector.load_from_url 在大小逻辑前分派的断言。",
    },
    ("105759", "workflow"): {
        1: "引用仅到 track_http_metri，不含方法标签、攻击路由、标签持久化、内存影响或修复句。",
        2: "NVD 描述说 fixed in version，不能擅自升级为 first patched 字段。",
        3: "引文仅含 Rust 前端启用方式，不含中间件标签及三个缺失限制。",
        4: "引用只说可发任意方法令牌，不含路由示例、405、axum 或永久插入。",
        5: "引文在 permanently insertin 截断，不含两个指标族、OOM 或抓取成本。",
        6: "引文在 registered path 相关内容前后截断，不含 Router::layer、文件行号及三个标签值。",
        7: "本条引文不含两来源受影响范围，且 NVD fixed 描述不是首次修复版本字段。",
    },
    ("105760", "workflow"): {
        1: "引文在 request-level m 截断，不能支持 GLMGA、fps/max_frames 和 CPU/内存影响。",
        2: True,
        3: True,
        4: "引用从 del 开始、在 request valu 截断，未完整覆盖视频模型/chat endpoint 与 loader 映射。",
        5: "引文没有 video_backend 或 fps/max_frames=500000 的选项内容。",
        6: "引文在 enabled, an 截断，未提供持有效 key 的调用者可达结论。",
        7: True,
        8: "引用中的两个 packages 都在 vulnerable 字段前截断，不能支持所述共同范围。",
    },
    ("105752", "rag"): {
        1: True,
        2: "所引用 packages 在 vulnerable_version_range 值之前截断。",
        3: "范围值和不存在 first_patched_version 的断言没有完整引文支撑。",
        4: "结论归属 vendor，但实际引用 github；下界和字段差异也没有完整引文。",
        5: "两条引文都未涵盖首轮盐、tokens_input 和全局未加盐缓存机制。",
        6: "引文仅说续轮泄漏共享缓存，不含前序 CVE、PR-17045、精确计数或 TTFT 比较。",
        7: "CVSS 引文不能支撑全部严重性、CWE 与可猜历史前提。",
        8: "HarmonyContext 携带原始 request 的断言不在实际引文中。",
    },
    ("105757", "rag"): {
        1: True,
        2: True,
        3: True,
        4: "引文不含下界早于 0.25.1 的句子。",
        5: "引文不含下界与维护者确认范围的句子。",
        6: "仅引用异常边界的主题句和一段配置，不含全部异常传播与致命错误机制。",
        7: "引用缺少站点1及 Rust 前端等全部三站点配置和哨兵细节。",
        8: "本条实际引文没有 CWE-755/248/20 或 Moderate 等全部断言。",
    },
    ("105758", "rag"): {
        1: True,
        2: "所引版本对象仅有 status/version，未包含 vllm 产品字段。",
        3: True,
        4: True,
        5: "引文在请求参数处截断，未包含 Qwen 模型配置与完整 max_frames/fps 字段。",
        6: "引文没有 Qwen 不读取 num_frames 的完整说明。",
        7: "表格行只有当前 2994 MiB，未引用 706 MiB 对照或 #51969 的结论依据。",
        8: "references 引文截断，不含所列 PR 56729、commit 与 release 链接。",
    },
    ("105759", "rag"): {
        1: True,
        2: True,
        3: True,
        4: True,
        5: "引文仅含 Rust 启用方式，没有 Prometheus 方法标签、白名单或基数限制。",
        6: True,
        7: "引文只涵盖 api-key 不缓解，不含 GUARDED_PREFIXES 数组及机密性/完整性影响。",
        8: "本条没有 vendor 受影响范围引文；版本对象缺字段也不能证明其他位置没有 CPE 条件。",
    },
    ("105760", "rag"): {
        1: "引文在 request-level m 截断，不支持 GLMGA 参数和 CPU/内存影响。",
        2: True,
        3: "引文没有 pip 包生态。",
        4: "引文没有 pip 包生态。",
        5: "本条引用只有修复键，没有所述两来源的共同受影响范围。",
        6: "引文在 The model 截断，没有无需默认使用 GLMGA 的说明。",
        7: "参数选择和共享加载执行器等机制未在实际引用中完整出现。",
        8: True,
    },
    ("105760", "langchain"): {
        1: "引文仅含版本与修复键，没有 pip 包生态。",
        2: "引文仅含版本与修复键，没有 pip 包生态。",
        3: "本条未引用两个范围，且把首次修复点与修补范围称为语义等价。",
        4: "引文没有两帧 PoC、OpenCV 解码器或无需 GPU/外部媒体的断言。",
        5: "引文只是选项的引导句，没有 JSON 选项值及 500000 数值。",
        6: "引用在 enabled, an 截断，没有持有效 key 的调用者可达断言。",
        7: "引文没有 GLMGA 索引构建/去重、CPU/内存与共享执行器机制。",
    },
}

CONDITION_GROUNDED = {
    ("105755", "workflow"),
    ("105756", "workflow"),
    ("105758", "workflow"),
    ("105757", "rag"),
}


def adjudicate(output):
    protocol = load_protocol(output)
    cases = {c["id"]: c for c in protocol["cases"]}
    mapping = json.loads((output / "blind-map.json").read_text())
    records, reviews = [], []
    raw = json.loads((output / "report.json").read_text())
    for blind_id, entry in mapping.items():
        case = cases[entry["case_id"]]
        source = answer_path(output, case, entry["mode"])
        answer = load_answer(source)
        result = answer["result"]
        initial = json.loads((output / "judgments" / f"{blind_id}.json").read_text())
        assert initial["status"] == "completed" and initial["answer_sha256"] == sha(source)
        verdict = copy.deepcopy(initial["verdict"])
        key = (case["group_id"].split("-")[-1], entry["mode"])
        if result["generation"]["status"] == "completed":
            manual = CLAIMS[key]
            assert set(manual) == set(range(1, len(result["generated_claims"]) + 1))
            for claim in verdict["claims"]:
                checked = manual[claim["statement_index"]]
                claim.update(
                    supported=checked is True,
                    reason="逐字引文覆盖完整实质断言。" if checked is True else checked,
                )
            for fact in verdict["facts"]:
                if fact["fact_id"] == "conditions" and key not in CONDITION_GROUNDED:
                    fact.update(
                        grounded=False,
                        reason="实际所引片段未完整覆盖冻结条件事实中的配置、输入或影响；不能使用 citation.text 未引用部分补足。",
                    )
                    if key == ("105760", "workflow"):
                        fact.update(
                            covered=False,
                            reason="答案未说明冻结事实要求的 GLMGA 先构造索引再去重机制，引用也没有支撑该机制。",
                        )
                if key == ("105752", "rag") and fact["fact_id"].endswith("-range"):
                    fact.update(grounded=False, reason="所引用 packages 在范围字段值前截断。")
                if fact["fact_id"] == "difference" and key in {
                    ("105752", "rag"),
                    ("105759", "workflow"),
                    ("105760", "langchain"),
                }:
                    fact.update(
                        grounded=False,
                        reason="范围对照未获得实际引文支持，或把 NVD fixed 描述/首次修复点/修补范围的不同语义混同。",
                    )
            if key == ("105755", "workflow"):
                verdict.update(
                    boundary_ok=False,
                    boundary_reason="无证据地声称来源未提供复现步骤或补丁正文；局部未读到不能推断来源不存在。",
                )
        else:
            for fact in verdict["facts"]:
                fact.update(
                    covered=False,
                    grounded=False,
                    reason="生成失败，原文摘录降级不是完成的语义答案。",
                )
        differences = {
            "claims": [
                c["statement_index"]
                for c, before in zip(verdict["claims"], initial["verdict"]["claims"], strict=True)
                if c["supported"] != before["supported"]
            ],
            "facts": [
                f["fact_id"]
                for f, before in zip(verdict["facts"], initial["verdict"]["facts"], strict=True)
                if (f["covered"], f["grounded"]) != (before["covered"], before["grounded"])
            ],
        }
        reviews.append(
            {
                "anonymous_id": blind_id,
                "case_id": case["id"],
                "mode": entry["mode"],
                "answer_sha256": sha(source),
                "initial_judgment_sha256": sha(output / "judgments" / f"{blind_id}.json"),
                "changes": differences,
                "verdict": verdict,
            }
        )
        record = score_answer(case, result, verdict)
        record.update(
            mode=entry["mode"],
            elapsed_ms=answer["elapsed_ms"],
            cost=result["cost"],
            generation_reason=result["generation"].get("reason"),
            anonymous_id=blind_id,
        )
        records.append(record)
    provenance = {
        "method": "Codex_AI_direct_quote_adjudication",
        "human_reviewed": False,
        "reviewer_identity": "AI",
        "blinded": False,
        "external_requests": 0,
        "rubric_changed": False,
        "scope": "same frozen quote-only semantic rubric; stricter check of compound assertions; single AI adjudicator, not organizer certification",
    }
    artifact = {
        "version": "agent-pilot-adjudications-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "protocol_sha256": protocol["freeze_sha256"],
        "review": provenance,
        "records": reviews,
    }
    artifact["sha256"] = digest(artifact)
    save(output / "adjudications.json", artifact)
    report = summarize(records)
    report.update(
        version="agent-paired-pilot-adjudicated-v1",
        protocol_sha256=protocol["freeze_sha256"],
        review=provenance,
        records=records,
        judge_cost=raw["judge_cost"],
        limitations=raw["limitations"]
        + [
            "anonymous initial judge often used unquoted surrounding text; retained separately as non-final first review",
            "direct-quote adjudication was performed by Codex AI with method labels visible; possible adjudicator bias remains",
            "condition gold facts combine several clauses; future holdout should split them into atomic facts",
            "ordinary generation omits temperature, native agent sets temperature=0; configuration differences limit causal attribution",
        ],
        raw_initial_review_sha256=sha(output / "report.json"),
        adjudications_sha256=artifact["sha256"],
    )
    save(output / "adjudicated-report.json", report)
    print(
        json.dumps(
            {
                "output": str(output / "adjudicated-report.json"),
                "strict_passes": {
                    m: v["confirmed_strict_passes"] for m, v in report["modes"].items()
                },
                "claim_disagreements": sum(len(r["changes"]["claims"]) for r in reviews),
                "agent_gain_proven": False,
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    adjudicate(parser.parse_args().output)
