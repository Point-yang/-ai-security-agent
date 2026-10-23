"""Apply recorded AI disagreement decisions without changing original reviews."""

import argparse
import copy
import json
from datetime import UTC, datetime
from pathlib import Path

from run_agent_paired_pilot import answer_path, load_answer, load_protocol, save, sha

from zhidu.paired_evaluation import digest, judge_packet, score_answer, summarize, validate_verdict


def adjudicate(output):
    protocol = load_protocol(output)
    mapping = json.loads((output / "blind-map.json").read_text())
    review = json.loads((output / "blind-review.json").read_text())
    assert review["human_reviewed"] is False and review["mapping_read"] is False
    assert set(review["results"]) == set(mapping)
    cases = {case["id"]: case for case in protocol["cases"]}
    original_report = json.loads((output / "report.json").read_text())
    decisions, records = [], []
    for blind_id, identity in mapping.items():
        case = cases[identity["case_id"]]
        path = answer_path(output, case, identity["mode"])
        result = load_answer(path)["result"]
        primary = json.loads((output / "judgments" / f"{blind_id}.json").read_text())
        assert primary["answer_sha256"] == sha(path)
        packet_path = output / "blind-review-packets" / f"{blind_id}.json"
        assert digest(json.loads(packet_path.read_text())) == digest(
            judge_packet(case, result, blind_id)
        )
        first = validate_verdict(case, result, primary["verdict"]).model_dump()
        second = validate_verdict(case, result, review["results"][blind_id]["verdict"]).model_dump()
        resolved = copy.deepcopy(first)
        for section, id_key, fields in (
            ("facts", "fact_id", ("covered", "grounded")),
            ("claims", "statement_index", ("supported",)),
        ):
            by_id = {item[id_key]: item for item in second[section]}
            for index, item in enumerate(first[section]):
                other = by_id[item[id_key]]
                if not any(item[field] != other[field] for field in fields):
                    continue
                if blind_id in {"anonymous-003", "anonymous-007", "anonymous-008"}:
                    reason = "未完成生成，仅返回原始片段且 generated_claims 为空；冻结规则不将片段堆砌计为自然语言必答事实覆盖。"
                elif blind_id == "anonymous-001" and item[id_key] == "pytorch-default":
                    reason = "实际引文和回答没有 PyTorch 2.6 安全默认及该路径覆盖关系，显式 weights_only=False 不能替代这一必答关系。"
                elif blind_id == "anonymous-005" and section == "claims" and item[id_key] == 1:
                    reason = "本句引用 packages，支持 pip/torch/范围；其 GHSA 元数据未给出 CVE 映射，不能从问题或另一条 NVD 引用替本句补证。"
                elif blind_id == "anonymous-006" and (
                    item[id_key] == "range-difference" or item[id_key] == 4
                ):
                    reason = "本句 GitHub description 引文为 versions 4.49.0, <= 5.8.1，不能静默补为从 4.49.0 至 5.8.1；其它 statement 的 packages 引文不能代替本句支撑。"
                else:
                    raise ValueError("unrecorded_adjudication_required")
                resolved[section][index] = {**other, "reason": reason}
                decisions.append(
                    {
                        "anonymous_id": blind_id,
                        "identity": identity,
                        "section": section,
                        "id": item[id_key],
                        "first": item,
                        "second": other,
                        "resolved": resolved[section][index],
                        "reason": reason,
                        "packet_sha256": sha(packet_path),
                    }
                )
        assert first["boundary_ok"] == second["boundary_ok"], "new_boundary_adjudication_required"
        record = score_answer(case, result, resolved)
        old_record = next(
            row for row in original_report["records"] if row["anonymous_id"] == blind_id
        )
        record.update(
            {
                key: old_record[key]
                for key in ("mode", "elapsed_ms", "cost", "generation_reason", "anonymous_id")
            }
        )
        records.append(record)
    adjudications = {
        "method": "AI_quote_only_disagreement_adjudication",
        "human_reviewed": False,
        "organizer_certified": False,
        "adjudicator_blinded": False,
        "rubric_changed": False,
        "original_reviews_preserved": True,
        "disagreements": len(decisions),
        "decisions": decisions,
        "blind_review_sha256": sha(output / "blind-review.json"),
        "first_report_sha256": sha(output / "report.json"),
    }
    final = summarize(records, modes=protocol["modes"], challenger=protocol["challenger"])
    final.update(
        version="agent-stage5-adjudicated-development-report-v1",
        created_at=datetime.now(UTC).isoformat(),
        records=records,
        judge_cost=original_report["judge_cost"],
        limitations=protocol["limitations"],
        development_regression=True,
        held_out=False,
        human_reviewed=False,
        protocol_sha256=protocol["freeze_sha256"],
        corpus_unchanged=original_report["corpus_unchanged"],
        adjudication_method=adjudications["method"],
        disagreements_resolved=len(decisions),
    )
    save(output / "adjudications.json", adjudications, new=True)
    save(output / "adjudicated-report.json", final, new=True)
    print(
        json.dumps(
            {
                "disagreements": len(decisions),
                "modes": {
                    key: {
                        name: value[name]
                        for name in (
                            "confirmed_strict_passes",
                            "fact_recall_judged",
                            "citation_entailment_precision_judged",
                        )
                    }
                    for key, value in final["modes"].items()
                },
                "agent_gain_proven": False,
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    adjudicate(parser.parse_args().output)
