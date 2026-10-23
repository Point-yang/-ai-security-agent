"""Independent offline contracts; no real freeze, network or billed inference."""

import copy
import importlib.util
import json

import pytest
import test_stage7_development as stage7_tests

from zhidu.paired_evaluation import digest

legacy_fixture = stage7_tests.legacy


@pytest.fixture
def runner():
    spec = importlib.util.spec_from_file_location(
        "stage8_p0", "scripts/run_agent_stage8_p0_development.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def legacy(legacy_fixture):
    """Rename only synthetic temporary fixture data; original fixtures stay intact."""
    source = legacy_fixture
    protocol_path = source / "protocol.json"
    protocol = json.loads(protocol_path.read_text())
    packages = ["gradio", "langchain", "langchain-core", "llama-index", "onnx", "keras"]
    for case, package in zip(protocol["cases"], packages, strict=True):
        old_id = case["id"]
        case.update(id=f"stage6-{package}", package=package)
        initial = source / "initial-packets" / f"{old_id}.json"
        initial.rename(initial.with_name(f"{case['id']}.json"))
        for mode in ("rag_hybrid", "workflow_hybrid", "team_hybrid"):
            path = source / "answers" / f"{old_id}-{mode}.json"
            row = json.loads(path.read_text())
            row.pop("row_sha256", None)
            row["case_id"] = case["id"]
            row["row_sha256"] = digest(row)
            path.unlink()
            path.with_name(f"{case['id']}-{mode}.json").write_text(json.dumps(row))
    protocol.pop("freeze_sha256")
    protocol["freeze_sha256"] = digest(protocol)
    protocol_path.write_text(json.dumps(protocol))
    (source / "gold-specs.json").write_text(json.dumps({"cases": protocol["cases"]}))
    return source


def test_fixed_selection_budget_and_original_bytes_are_preserved(runner, legacy, tmp_path):
    before = {str(p.relative_to(legacy)): p.read_bytes() for p in legacy.rglob("*") if p.is_file()}
    output = tmp_path / "stage8"
    protocol = runner.freeze(legacy, output, prior_developments=[])
    assert [c["package"] for c in protocol["cases"]] == ["langchain-core", "onnx"]
    assert protocol["selection"]["selected_before_generation"] is True
    assert protocol["budget"]["max_generation_requests"] == 16
    assert protocol["budget"]["model_calls_per_answer"] == 8
    assert protocol["budget"]["tool_calls_per_answer"] == 6
    assert protocol["budget"]["soft_deadline_seconds"] == 60
    assert protocol["budget"]["tool_output_chars"] == 18000
    assert protocol["budget"]["max_judge_requests"] == 0
    assert protocol["new_holdout"] is False and protocol["quality_gain_proven"] is False
    for name in ("corpus.sqlite", "gold-specs.json", "encoder-manifest.json", "model-pricing.json"):
        assert (output / name).read_bytes() == before[name]
    assert len(list((output / "initial-packets").glob("*.json"))) == 6
    assert (
        output / "legacy" / "answers" / "stage6-langchain-workflow_hybrid.json"
    ).read_bytes() == before["answers/stage6-langchain-workflow_hybrid.json"]
    assert before == {
        str(p.relative_to(legacy)): p.read_bytes() for p in legacy.rglob("*") if p.is_file()
    }
    assert runner.load_protocol(output)["cases"] == protocol["cases"]


def test_archive_contains_nested_source_css_and_public_json_but_never_credentials(runner, tmp_path):
    paths = [
        "src/zhidu/new_p0/module.py",
        "src/zhidu/static/console.css",
        "src/zhidu/static/console.js",
        "src/zhidu/static/console-receipt-demo.json",
        "tests/nested/test_p0.py",
        "tests/boundary.test.mjs",
    ]
    for name in paths:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}" if path.suffix == ".json" else "fixture")
    (tmp_path / ".env").write_text("ADMIN_KEY=private-fixture")
    (tmp_path / "src/zhidu/static/private.json").write_text('{"admin_key":"private-fixture"}')
    found = {str(p.relative_to(tmp_path)) for p in runner.archive_paths(tmp_path)}
    assert set(paths) <= found
    assert ".env" not in found and "src/zhidu/static/private.json" not in found


def test_public_demo_with_private_key_is_not_archived(runner, tmp_path):
    path = tmp_path / "src/zhidu/static/console-receipt-demo.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"api_key":"private-fixture"}')
    with pytest.raises(ValueError, match="public_demo_contains_private_data"):
        runner.archive_paths(tmp_path)


def test_old_failed_development_attempt_is_bound_and_never_changed(runner, legacy, tmp_path):
    prior = tmp_path / "old-development"
    (prior / "answers").mkdir(parents=True)
    row = {"case_id": "stage6-onnx", "status": "unknown_outcome", "request_ceiling": 8}
    (prior / "answers/failed.json").write_text(json.dumps(row))
    old = {
        "original_stage6": {
            "freeze_sha256": json.loads((legacy / "protocol.json").read_text())["freeze_sha256"]
        }
    }
    (prior / "protocol.json").write_text(json.dumps(old))
    output = tmp_path / "stage8"
    runner.freeze(legacy, output, prior_developments=[prior])
    assert (prior / "answers/failed.json").read_text() == json.dumps(row)
    (prior / "answers/failed.json").write_text('{"status":"changed"}')
    with pytest.raises(ValueError, match="prior_development_artifact_changed"):
        runner.load_protocol(output)


def test_original_gold_or_initial_mutation_is_detected_even_with_clean_copy(
    runner, legacy, tmp_path
):
    output = tmp_path / "stage8"
    runner.freeze(legacy, output, prior_developments=[])
    path = legacy / "initial-packets" / "stage6-onnx.json"
    original = path.read_bytes()
    path.write_bytes(original + b" ")
    with pytest.raises(ValueError, match="original_stage6_data_or_initial_changed"):
        runner.load_protocol(output)
    path.write_bytes(original)
    (legacy / "gold-specs.json").write_text('{"changed":true}')
    with pytest.raises(ValueError, match="original_stage6_data_or_initial_changed"):
        runner.load_protocol(output)


def test_new_identity_never_reuses_stage6_or_stage7(runner):
    protocol = {"experiment_id": "stage8-fixture", "freeze_sha256": "frozen"}
    identity = runner.request_identity(protocol, {"id": "stage6-onnx"})
    assert identity.startswith("stage8:") and "stage8-fixture" in identity


def test_unknown_attempt_reserves_eight_and_is_not_reissued(runner, tmp_path):
    calls = []

    def unknown(case):
        calls.append(case["id"])
        raise RuntimeError("outcome uncertain")

    protocol = {
        "experiment_id": "stage8-fixture",
        "freeze_sha256": "frozen",
        "budget": {"max_generation_requests": 16},
        "cases": [{"id": "core"}, {"id": "onnx"}],
    }
    runner.run_schedule(tmp_path, protocol, unknown)
    runner.run_schedule(tmp_path, protocol, unknown)
    assert calls == ["core"]
    assert runner.generation_requests(tmp_path) == 8
    assert json.loads((tmp_path / "stopped.json").read_text())["automatic_retry"] is False


def p0_result(*, policy="any", sources=("github-advisories",), anchored=True, plan_omission=False):
    text = "GitHub 声明仅处理不可信模型的转换应用满足条件。"
    citations = [
        {"source_id": source, "text": "Only converters of untrusted models are affected."}
        for source in sources
    ]
    spans = [{"statement_index": 1, "start": 0, "end": len(text), "text": text}] if anchored else []
    ledger = [
        {
            "task_id": "untrusted",
            "requirement": "不可信模型条件",
            "source_policy": policy,
            "source_ids": ["github-advisories", "nvd"],
            "status": "covered",
            "statement_indices": [1],
            "answer_spans": spans,
            "required_elements": ["不可信模型"],
            "element_coverage": [
                {"element": "不可信模型", "status": "covered", "answer_spans": copy.deepcopy(spans)}
            ],
        }
    ]
    return {
        "generation": {"status": "completed"},
        "answer_class": "evidence",
        "citations": citations,
        "generated_claims": [
            {
                "text": text if anchored else "已读取来源片段。",
                "evidence": [
                    {"citation": i + 1, "quote": c["text"]} for i, c in enumerate(citations)
                ],
            }
        ],
        "requirement_ledger": ledger,
        "question_coverage": {
            "method": "AI original-question+anchored-task review",
            "complete": True,
            "missing_task_ids": [],
            "unanswered_question_requirements": ["部署条件"] if plan_omission else [],
        },
        "claim_support": {
            "method": "internal_AI_ownquotes",
            "claims": [{"final_statement_index": 1, "supported": True}],
        },
        "evidence_novelty": {
            "status": "complete",
            "new_source_chars": 0,
            "known_new_source_chars": 0,
            "new_source_spans": [],
        },
        "batch_tool_calls": [],
        "cost": {"external_requests": 5, "billed_tokens": 100},
    }


def test_quote_contains_condition_but_body_has_no_anchor_is_not_complete(runner):
    result = p0_result(anchored=False)
    audit = runner.acceptance_contract_audit(result)
    assert audit["contract_ok"] is False
    assert "covered_task_without_final_answer_span" in audit["issues"]
    assert audit["independent_semantic_score"] is False


def test_plan_omits_a_user_condition_cannot_claim_complete(runner):
    audit = runner.acceptance_contract_audit(p0_result(plan_omission=True))
    assert audit["contract_ok"] is False
    assert "complete_with_unanswered_question_requirements" in audit["issues"]


def test_source_policy_any_accepts_one_correct_source_but_compare_needs_both(runner):
    assert runner.acceptance_contract_audit(p0_result(policy="any"))["contract_ok"] is True
    missing = runner.acceptance_contract_audit(p0_result(policy="compare"))
    assert "covered_task_missing_required_sources" in missing["issues"]
    both = p0_result(policy="compare", sources=("github-advisories", "nvd"))
    assert runner.acceptance_contract_audit(both)["contract_ok"] is True


def test_cross_source_comparison_cannot_borrow_a_different_statements_quote(runner):
    result = p0_result(policy="compare", sources=("github-advisories", "nvd"))
    second = copy.deepcopy(result["generated_claims"][0])
    result["generated_claims"][0]["evidence"] = [
        {"citation": 1, "quote": result["citations"][0]["text"]}
    ]
    second["evidence"] = [{"citation": 2, "quote": result["citations"][1]["text"]}]
    result["generated_claims"].append(second)
    task = result["requirement_ledger"][0]
    task["statement_indices"] = [1, 2]
    task["answer_spans"].append({**task["answer_spans"][0], "statement_index": 2})
    task["element_coverage"][0]["answer_spans"] = copy.deepcopy(task["answer_spans"])
    audit = runner.acceptance_contract_audit(result)
    assert "covered_task_missing_required_sources" in audit["issues"]
    task["source_policy"] = "each"
    assert runner.acceptance_contract_audit(result)["contract_ok"] is True


def test_every_required_element_needs_its_own_final_prose_anchor(runner):
    result = p0_result()
    result["requirement_ledger"][0]["required_elements"].append("转换应用")
    audit = runner.acceptance_contract_audit(result)
    assert "covered_task_element_coverage_unrecorded" in audit["issues"]


def test_answer_span_must_match_retained_statement_not_quote(runner):
    result = p0_result()
    result["requirement_ledger"][0]["answer_spans"][0]["text"] = result["citations"][0]["text"]
    audit = runner.acceptance_contract_audit(result)
    assert "answer_span_not_in_final_statement" in audit["issues"]


def test_summary_marks_missing_fields_unrecorded_and_does_not_score_gold(runner, tmp_path):
    output = tmp_path
    (output / "answers").mkdir()
    protocol = {
        "experiment_id": "stage8-fixture",
        "freeze_sha256": "frozen",
        "cases": [{"id": "core", "facts": [{"id": "gold-condition"}]}],
        "legacy_artifact_sha256": {},
        "prior_development_artifacts": {},
        "original_stage6": {"path": str(output)},
        "data_artifact_sha256": {},
        "initial_artifact_sha256": {},
        "raw_sha256": [],
        "matching": {"model_profile": {"provider": "deepseek", "model": "fixture"}},
    }
    runner.execute_once(
        output / "answers/core-team_hybrid.json",
        {"mode": "team_hybrid"},
        lambda: {"generation": {"status": "completed"}, "cost": {"external_requests": 0}},
    )
    summary = runner.summary(output, protocol)
    case = summary["cases"][0]
    assert case["question_coverage"]["availability"] == "unrecorded"
    assert summary["new_holdout"] is False and summary["quality_gain_proven"] is False
    assert summary["official_accuracy"] is None and summary["judge_api_calls"] == 0


def test_novelty_is_interval_based_not_new_chunk_id():
    from zhidu.evidence_novelty import evidence_novelty

    original = {
        "chunk_id": "one",
        "event_id": "event",
        "revision_id": "revision",
        "revision": 1,
        "field": "description",
        "sha256": "a" * 64,
        "json_pointer": "/description",
        "start": 0,
        "end": 5,
        "text": "hello",
        "span_provenance": {
            "source_field_sha256": "b" * 64,
            "source_field_chars": 10,
            "offset_unit": "unicode_codepoint",
            "serialization": "string-verbatim",
        },
    }
    repeat = copy.deepcopy(original)
    repeat["chunk_id"] = "different-chunk"
    assert (
        evidence_novelty({"one": original}, {"one": original, "two": repeat})["new_source_chars"]
        == 0
    )


def test_batch_replay_summary_separates_logical_from_current_attempt_novelty(runner):
    result = p0_result()
    result["batch_tool_calls"] = [
        {
            "call_id": "research:0:0",
            "action": "batch",
            "tool_observations": [
                {
                    "child_id": "research:0:0:tool:0",
                    "tool": "read_fields",
                    "replayed": True,
                    "actual_tool_attempts": 0,
                    "novelty": {"new_source_chars": 5},
                    "current_attempt_novelty": {"new_source_chars": 0},
                },
            ],
        }
    ]
    progress = runner.progress_summary(result)
    assert progress["batch"]["replayed_children"] == 1
    assert progress["batch"]["actual_children"] == 0
    assert progress["batch"]["current_attempt_known_new_chars"] == 0


def test_actual_child_count_never_assumes_one_attempt_and_unknown_novelty_is_not_new(runner):
    result = p0_result()
    result["batch_tool_calls"] = [
        {
            "action": "batch",
            "tool_observations": [
                {
                    "replayed": False,
                    "actual_tool_attempts": 0,
                    "novelty": {"status": "known", "new_source_chars": 0},
                },
                {
                    "replayed": False,
                    "actual_tool_attempts": 1,
                    "novelty": {
                        "status": "unknown",
                        "new_source_chars": None,
                        "known_new_source_chars": 9,
                    },
                },
                {"replayed": False, "novelty": {"status": "unknown", "known_new_source_chars": 9}},
            ],
        }
    ]
    batch = runner.progress_summary(result)["batch"]
    assert batch["actual_children"] == batch["actual_tool_attempts"] == 1
    assert batch["unrecorded_child_attempts"] == 1
    assert batch["logical_known_new_chars"] == 0
    assert batch["unknown_child_novelties"] == 2


def test_completed_format_failure_stops_without_launching_second_case(runner, tmp_path):
    calls = []

    def malformed(case):
        calls.append(case["id"])
        return {"generation": {"status": "completed"}, "cost": {"external_requests": 1}}

    protocol = {
        "experiment_id": "stage8-fixture",
        "freeze_sha256": "frozen",
        "budget": {"max_generation_requests": 16},
        "cases": [{"id": "core"}, {"id": "onnx"}],
    }
    stopped = runner.run_schedule(tmp_path, protocol, malformed)
    assert stopped["reason"] == "p0_acceptance_contract_unrecorded"
    assert calls == ["core"]
    runner.run_schedule(tmp_path, protocol, malformed)
    assert calls == ["core"]


def test_existing_attempt_identity_and_concurrent_runner_block_new_model_work(runner, tmp_path):
    protocol = {
        "experiment_id": "stage8-fixture",
        "freeze_sha256": "frozen",
        "budget": {"max_generation_requests": 16},
        "cases": [{"id": "core"}],
    }
    (tmp_path / "answers").mkdir()
    runner.save(
        tmp_path / "answers/core-team_hybrid.json",
        {"request_id": "stage7:old-paid", "status": "started", "mode": "team_hybrid"},
    )
    calls = []
    with pytest.raises(ValueError, match="attempt_request_identity_changed"):
        runner.run_schedule(tmp_path, protocol, lambda case: calls.append(case))
    assert calls == []
    with runner._single_runner(tmp_path):
        with pytest.raises(RuntimeError, match="stage8_runner_already_active"):
            runner.run_schedule(tmp_path, protocol, lambda case: calls.append(case))
    assert calls == []


def test_actual_requirement_normalizer_preserves_supported_claim_and_reports_partial():
    from zhidu.agent_requirements import coverage_ledger, reviewed_candidate
    from zhidu.agent_state import AgentAnswer
    from zhidu.agent_team_state import TaskPlan, VerifierOutput

    question = "说明转换应用与不可信模型条件，并解释部署限制。"
    handle = "a" * 24
    evidence = {
        handle: {
            "source_id": "github-advisories",
            "text": "Only converters accepting untrusted models are affected.",
        }
    }
    plan = TaskPlan.model_validate(
        {
            "tasks": [
                {
                    "task_id": "conversion",
                    "requirement": "说明转换应用条件",
                    "source_ids": ["github-advisories", "nvd"],
                    "fields": ["description"],
                    "keywords": [],
                    "question_spans": [{"quote": "转换应用与不可信模型条件"}],
                    "source_policy": "any",
                    "required_elements": ["转换应用", "不可信模型"],
                }
            ]
        }
    )
    candidate = AgentAnswer.model_validate(
        {
            "answer_class": "evidence",
            "statements": [
                {
                    "text": "GitHub 公告将受影响范围限于转换应用。",
                    "evidence": [{"evidence_id": handle}],
                }
            ],
            "required_facts": ["说明转换应用条件"],
            "missing_facts": [],
            "limitations": [],
            "message": "",
        }
    )
    prose = {"statement_index": 1, "text": candidate.statements[0].text}
    verdict = VerifierOutput.model_validate(
        {
            "coverage": [
                {
                    "task_id": "conversion",
                    "status": "covered",
                    "statement_indices": [1],
                    "note": "引文有条件但正文漏不可信限定",
                    "answer_spans": [prose],
                    "element_coverage": [
                        {"element": "转换应用", "status": "covered", "answer_spans": [prose]},
                        {"element": "不可信模型", "status": "partial", "answer_spans": []},
                    ],
                }
            ],
            "claim_support": [
                {"statement_index": 1, "status": "supported", "reason": "本句仅说明正确范围部分"}
            ],
            "unplanned_requirements": [
                {
                    "requirement": "部署限制",
                    "question_span": {"quote": "部署限制"},
                    "reason": "原问题有要求而计划未列且正文未答",
                }
            ],
            "gaps": [],
        }
    )
    final = reviewed_candidate(plan, candidate, verdict, question=question, evidence=evidence)
    ledger = coverage_ledger(plan, candidate, verdict, question=question, evidence=evidence)
    assert final.answer_class == "partial" and final.statements == candidate.statements
    assert ledger["tasks"][0]["status"] == "partial" and ledger["complete"] is False
    assert ledger["tasks"][0]["source_check"]["sufficient"] is True
    assert ledger["unplanned_requirements"][0]["question_span"]["start"] == question.index(
        "部署限制"
    )


def test_actual_ledger_final_spans_remap_after_unsupported_claim_removal(runner):
    from zhidu.agent_requirements import coverage_ledger, reviewed_candidate
    from zhidu.agent_state import AgentAnswer
    from zhidu.agent_team_state import TaskPlan, VerifierOutput
    from zhidu.grounded_answer import render_answer

    question, handle = "说明条件。", "a" * 24
    evidence = {
        handle: {
            "source_id": "github-advisories",
            "text": "Only converters accepting untrusted models are affected.",
        }
    }
    plan = TaskPlan.model_validate(
        {
            "tasks": [
                {
                    "task_id": "conversion",
                    "requirement": question,
                    "source_ids": ["github-advisories"],
                    "fields": ["description"],
                    "keywords": [],
                    "question_spans": [{"quote": question}],
                    "source_policy": "any",
                    "required_elements": ["条件"],
                }
            ]
        }
    )
    candidate = AgentAnswer.model_validate(
        {
            "answer_class": "evidence",
            "statements": [
                {"text": text, "evidence": [{"evidence_id": handle}]}
                for text in (
                    "GitHub 说明转换应用条件。",
                    "错误的额外结论。",
                    "GitHub 限定不可信模型输入。",
                )
            ],
            "required_facts": [question],
            "missing_facts": [],
            "limitations": [],
            "message": "",
        }
    )
    spans = [{"statement_index": i, "text": candidate.statements[i - 1].text} for i in (1, 3)]
    verdict = VerifierOutput.model_validate(
        {
            "coverage": [
                {
                    "task_id": "conversion",
                    "status": "covered",
                    "statement_indices": [1, 3],
                    "answer_spans": spans,
                    "element_coverage": [
                        {"element": "条件", "status": "covered", "answer_spans": spans}
                    ],
                    "note": "正文涵盖",
                }
            ],
            "claim_support": [
                {
                    "statement_index": i,
                    "status": "unsupported" if i == 2 else "supported",
                    "reason": "自身引文审核",
                }
                for i in (1, 2, 3)
            ],
            "unplanned_requirements": [],
            "gaps": [],
        }
    )
    final = reviewed_candidate(plan, candidate, verdict, question=question, evidence=evidence)
    ledger = coverage_ledger(plan, candidate, verdict, question=question, evidence=evidence)
    result = render_answer(final, evidence)
    result.update(
        requirement_ledger=ledger,
        question_coverage={
            "complete": False,
            "missing_task_ids": [],
            "unanswered_question_requirements": [],
        },
    )
    task = ledger["tasks"][0]
    assert task["final_statement_indices"] == [1, 2]
    assert [span["statement_index"] for span in task["answer_spans"]] == [1, 2]
    assert [span["statement_index"] for span in task["candidate_answer_spans"]] == [1, 3]
    assert runner.acceptance_contract_audit(result)["contract_ok"] is True
