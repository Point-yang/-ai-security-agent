"""Offline contract tests for the new holdout; no real intake or model execution."""

import copy
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest


def script(name):
    spec = importlib.util.spec_from_file_location(name, Path("scripts") / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def collector():
    return script("collect_agent_stage6_sources")


@pytest.fixture
def freezer():
    return script("freeze_agent_stage6_holdout")


@pytest.fixture
def runner():
    return script("run_agent_stage6_evaluation")


def advisory(package, index):
    return {
        "ghsa_id": f"GHSA-aaaa-bbbb-{index:04d}",
        "cve_id": f"CVE-2026-{10000 + index}",
        "vulnerabilities": [{"package": {"ecosystem": "pip", "name": package}}],
        "withdrawn_at": None,
    }


def test_preselection_and_first_eligible_are_fixed(collector):
    assert collector.PACKAGES == (
        "gradio",
        "langchain",
        "langchain-core",
        "llama-index",
        "vllm",
        "onnx",
        "onnxruntime",
        "keras",
    )
    candidates = [advisory("gradio", i) for i in range(1, 6)]
    candidates[1]["cve_id"] = None
    selected, audit = collector.select_advisory(
        candidates, "gradio", {candidates[0]["cve_id"].casefold()}
    )
    assert selected == candidates[2]
    assert len(audit) == 5
    assert [row["selected"] for row in audit] == [False, False, True, False, False]


def test_collect_keeps_failures_no_retry_redirect_or_package_replacement(
    collector,
    tmp_path,
    monkeypatch,
):
    requests = []
    clock = [0.0]
    monkeypatch.setattr(collector, "freeze_exclusions", lambda *args: (set(), "excluded"))

    def mock(request):
        requests.append(request)
        assert request.method == "GET"
        assert "authorization" not in request.headers
        if request.url.host == "api.github.com":
            assert request.url.params["type"] == "reviewed"
            assert request.url.params["per_page"] == "5"
            package = request.url.params["affects"]
            if package == "gradio":
                return httpx.Response(302, headers={"location": "https://example.org"})
            if package == "keras":
                return httpx.Response(200, json=[])
            return httpx.Response(200, json=[advisory(package, len(requests))])
        return httpx.Response(503, json={"error": "fixture failure"})

    with httpx.Client(transport=httpx.MockTransport(mock), follow_redirects=False) as client:
        manifest = collector.collect(
            tmp_path,
            tmp_path / "main.db",
            tmp_path / "intake",
            client=client,
            clock=lambda: clock[0],
            sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        )
    assert len(requests) == 14
    assert len(manifest["groups"]) == 8
    assert manifest["groups"][0]["selection_state"] == "interface_error"
    assert manifest["groups"][-1]["selection_state"] == "no_eligible_record_within_latest_five"
    assert sum(g["two_public_sources_available"] for g in manifest["groups"]) == 0
    starts = [r["monotonic_started"] for r in manifest["requests"] if r["service"] == "nvd"]
    assert all(b - a >= 7 for a, b in zip(starts, starts[1:], strict=False))
    assert manifest["policy"]["maximum_anonymous_gets"] == 16


def test_source_gold_uses_full_scope_and_exact_pointer_not_expected(freezer):
    raw = {"description": "Only an authenticated caller may access the endpoint."}
    evidence = freezer.validate_source_evidence(
        raw,
        {"source_id": "nvd", "json_pointer": "/description", "quote": "authenticated caller"},
        source_id="nvd",
        external_id="CVE-2026-12345",
        sha256="a" * 64,
        record_pointer="",
    )
    assert evidence["scope"]["text"] == raw["description"]
    assert evidence["scope"]["complete"] is True
    assert evidence["sha256"] == "a" * 64
    with pytest.raises(ValueError, match="gold_quote_not_verbatim"):
        freezer.validate_source_evidence(
            raw,
            {"source_id": "nvd", "json_pointer": "/description", "quote": "unauthenticated caller"},
            source_id="nvd",
            external_id="CVE-2026-12345",
            sha256="a" * 64,
            record_pointer="",
        )
    with pytest.raises(ValueError, match="gold_pointer_outside_selected_record"):
        freezer.validate_source_evidence(
            raw,
            {"source_id": "nvd", "json_pointer": "/description", "quote": "authenticated caller"},
            source_id="nvd",
            external_id="CVE-2026-12345",
            sha256="a" * 64,
            record_pointer="/another-record",
        )


def test_freeze_refuses_post_prediction_gold(freezer):
    with pytest.raises(ValueError, match="predictions_forbidden_before_freeze"):
        freezer.reject_predictions({"cases": [{"answer": "already inspected"}]})
    freezer.reject_predictions({"cases": [{"question": "fixture", "facts": []}]})


class FakeRuntime:
    def __init__(self, *args, **kwargs):
        self.steps = []
        self.output_chars = 0
        self.max_calls = kwargs.get("max_calls", 6)


class FakeTools:
    retrieves = 0

    def __init__(self, runtime, body, selected):
        self.runtime = runtime
        self.body = body
        self.events = {"event-one"}
        self.evidence = {
            "handle": {
                "event_id": "event-one",
                "text": "same exact quote",
                "field": "description",
                "source_id": "nvd",
            }
        }
        self.results = []
        self.constraints = []
        self.attempted_calls = 0

    def invoke(self, name, args):
        self.attempted_calls += 1
        self.runtime.steps.append({"tool": name, "args": copy.deepcopy(args)})
        if name == "retrieve":
            type(self).retrieves += 1
        result = {"status": "completed", "tool": name, "result": {"items": []}}
        self.results.append(result)
        return json.dumps(result), result

    def snapshot(self):
        return {
            "events": sorted(self.events),
            "evidence": self.evidence,
            "results": self.results,
            "constraints": self.constraints,
            "attempted_calls": self.attempted_calls,
            "steps": self.runtime.steps,
            "output_chars": 0,
        }

    def restore(self, snapshot):
        self.events = set(snapshot["events"])
        for key in ("evidence", "results", "constraints", "attempted_calls"):
            setattr(self, key, snapshot[key])
        self.runtime.steps = snapshot["steps"]


def test_fair_initial_packet_one_retrieval_identical_deep_restores(
    runner,
    settings,
    monkeypatch,
):
    from zhidu.rag import RagRequest

    FakeTools.retrieves = 0
    monkeypatch.setattr(runner, "SourceRuntime", FakeRuntime)
    monkeypatch.setattr(runner, "ToolSession", FakeTools)
    body = RagRequest(question="fixture", query="CVE-2026-12345", mode="hybrid")
    packet = runner.fair_initial_packet(None, None, settings, body, None)
    assert packet["retrieve_arguments"] == {
        "query": "CVE-2026-12345",
        "mode": "hybrid",
        "limit": 5,
    }
    restores = [
        runner.restore_initial_packet(packet, None, None, settings, body, None)
        for _ in runner.MODES
    ]
    assert FakeTools.retrieves == 1
    assert all(t.evidence == packet["snapshot"]["evidence"] for t in restores)
    restores[0].evidence["handle"]["text"] = "mutated"
    assert restores[1].evidence["handle"]["text"] == "same exact quote"
    assert packet["snapshot"]["evidence"]["handle"]["text"] == "same exact quote"
    damaged = copy.deepcopy(packet)
    damaged["snapshot"]["evidence"]["handle"]["text"] = "tampered"
    with pytest.raises(ValueError, match="initial_packet_changed"):
        runner.restore_initial_packet(damaged, None, None, settings, body, None)


def test_mode_ceilings_and_unknown_started_reserve_all_calls(runner, tmp_path):
    assert runner.MODE_CEILINGS == {"rag_hybrid": 1, "workflow_hybrid": 1, "team_hybrid": 8}
    answers = tmp_path / "answers"
    answers.mkdir()
    (answers / "fixture.json").write_text(json.dumps({"status": "started", "mode": "team_hybrid"}))
    protocol = {
        "budget": {
            "max_generation_requests": 80,
            "max_judge_requests": 24,
            "max_total_requests": 104,
        }
    }
    assert runner.generation_requests(tmp_path, protocol) == 8
    with pytest.raises(ValueError, match="global_generation_budget_exhausted"):
        runner.check_request_budget(protocol, 81, 0)


def test_experiment_configuration_enforces_six_tool_hard_limit(
    runner, settings, tmp_path, monkeypatch
):
    from pydantic import ValidationError

    values = settings.model_dump()

    class FixtureSettings(type(settings)):
        def __init__(self, **kwargs):
            super().__init__(_env_file=None, **(values | kwargs))

    monkeypatch.setattr(runner, "Settings", FixtureSettings)
    monkeypatch.setattr(runner, "model_manifest", lambda *args, **kwargs: {"digest": "fixture"})
    protocol = {
        "freeze_sha256": "fixture",
        "matching": {"encoder_digest": "fixture"},
        "budget": {
            "tool_calls_per_answer": 6,
            "tool_output_chars": 18000,
            "soft_deadline_seconds": 60,
            "completion_tokens_per_call": 2400,
            "final_reserve_seconds": 12,
        },
    }
    configured = runner.experiment_settings(tmp_path, protocol)
    assert configured.agent_max_tool_calls == 6
    assert configured.deepseek_max_tokens == 2400
    assert configured.agent_max_model_calls == 8
    protocol["budget"]["tool_calls_per_answer"] = 9
    with pytest.raises(ValidationError):
        runner.experiment_settings(tmp_path, protocol)


def test_started_generation_is_never_resubmitted(runner, tmp_path):
    calls = []
    path = tmp_path / "attempt.json"

    def unknown():
        calls.append(1)
        raise RuntimeError("provider might have accepted")

    runner.execute_once(path, {"mode": "team_hybrid"}, unknown)
    runner.execute_once(path, {"mode": "team_hybrid"}, unknown)
    assert calls == [1]
    saved = json.loads(path.read_text())
    assert saved["status"] == "unknown_outcome"
    assert saved["request_ceiling"] == 8


def test_quote_only_packet_never_exposes_gold_scope_or_full_citation(runner):
    case = {
        "id": "case",
        "group_id": "CVE-2026-12345",
        "question": "fixture",
        "facts": [
            {
                "id": "f",
                "dimension": "conditions",
                "expected": "target",
                "evidence": [{"text": "UNQUOTED GOLD SECRET"}],
            }
        ],
    }
    result = {
        "answer": "fixture",
        "citations": [{"source_id": "nvd", "text": "UNQUOTED SOURCE SECRET"}],
        "generated_claims": [
            {"text": "fixture", "evidence": [{"citation": 1, "quote": "actual quote"}]}
        ],
    }
    packet = runner.anonymous_packet(case, result, "anonymous-001")
    text = json.dumps(packet)
    assert "UNQUOTED" not in text
    assert "actual quote" in text
    assert "mode" not in packet and "group_id" not in packet


def test_report_rejects_incomplete_pairs_and_small_cohort_cannot_prove_gain(runner):
    with pytest.raises(ValueError, match="incomplete_frozen_pair"):
        runner.paired_summary([], expected_cases=["case"], minimum_groups=8)


def test_all_modes_receive_same_packet_before_any_strategy_work(runner, settings, monkeypatch):
    from zhidu.rag import RagRequest

    monkeypatch.setattr(runner, "SourceRuntime", FakeRuntime)
    monkeypatch.setattr(runner, "ToolSession", FakeTools)
    body = RagRequest(question="fixture", query="CVE-2026-12345 fixture", mode="hybrid")
    packet = runner.fair_initial_packet(None, None, settings, body, None)
    seen = []

    def compose(session, store, mode_settings, request, tools, **kwargs):
        seen.append(copy.deepcopy(tools.evidence))
        return {"generation": {"status": "completed"}, "cost": {"external_requests": 0}}

    def team(session, store, mode_settings, request, encoder, *, prepared_tools, **kwargs):
        assert mode_settings.agent_max_model_calls == 8
        seen.append(copy.deepcopy(prepared_tools.evidence))
        return {"generation": {"status": "completed"}, "cost": {"external_requests": 0}}

    monkeypatch.setattr(runner, "compose_once", compose)
    monkeypatch.setitem(sys.modules, "zhidu.agent_team", SimpleNamespace(run_agent_team=team))
    results = [
        runner.run_mode(
            mode, packet, None, None, settings, body, None, checkpoint_key="fixture:" + mode
        )
        for mode in runner.MODES
    ]
    assert all(evidence == packet["snapshot"]["evidence"] for evidence in seen)
    assert {r["fair_initial_packet_sha256"] for r in results} == {packet["packet_sha256"]}
    assert results[0]["actual_additional_tool_attempts"] == 0
    assert results[1]["actual_additional_tool_attempts"] == 2


def scored_rows(runner, count, *, equal_correct=False):
    rows = []
    for i in range(count):
        for mode in runner.MODES:
            passed = equal_correct or mode == "team_hybrid"
            rows.append(
                {
                    "case_id": f"case-{i}",
                    "group_id": f"CVE-2026-{10000 + i}",
                    "mode": mode,
                    "strict_pass": passed,
                    "judge_available": True,
                    "generation_completed": True,
                    "grounded_facts": int(passed),
                    "required_facts": 1,
                    "claims": 1,
                    "supported_claims": int(passed),
                    "dimensions": {},
                    "elapsed_ms": 100 if mode == "team_hybrid" else 200,
                    "cost": {"external_requests": 1, "billed_tokens": 10},
                }
            )
    return rows


def test_quality_and_efficiency_require_their_own_group_ci_and_sample_size(runner):
    small = runner.paired_summary(scored_rows(runner, 2), expected_cases=["case-0", "case-1"])
    assert small["agent_gain_proven"] is False
    rows = scored_rows(runner, 8, equal_correct=True)
    summary = runner.paired_summary(rows, expected_cases=[f"case-{i}" for i in range(8)])
    for pair in summary["paired"].values():
        assert pair["quality_gain_proven"] is False
        assert pair["group_bootstrap_95_ci"] == [0, 0]
        assert pair["efficiency"]["efficiency_gain_proven"] is True
        assert pair["efficiency"]["group_bootstrap_95_ci_ms"][1] < 0


def test_precision_recall_improvement_alone_does_not_prove_gain(runner):
    rows = scored_rows(runner, 8)
    for row in rows:
        row.update(
            strict_pass=False,
            required_facts=10,
            claims=10,
            grounded_facts=8 if row["mode"] == "team_hybrid" else 2,
            supported_claims=9 if row["mode"] == "team_hybrid" else 3,
        )
    summary = runner.paired_summary(rows, expected_cases=[f"case-{i}" for i in range(8)])
    assert summary["agent_gain_proven"] is False
    for pair in summary["paired"].values():
        for metric in pair["quality_metrics"].values():
            assert metric["group_bootstrap_95_ci"][0] > 0
        assert pair["quality_metrics_are_diagnostic_not_proof"] is True


def test_cost_pairing_stays_in_original_currency_and_requires_exact_amount(runner):
    rows = scored_rows(runner, 8, equal_correct=True)
    for row in rows:
        row["elapsed_ms"] = 200
        row["cost"]["pricing"] = {
            "currency_totals": {
                "CNY": {
                    "complete": True,
                    "amount": 0.8 if row["mode"] == "team_hybrid" else 1.0,
                }
            }
        }
    summary = runner.paired_summary(rows, expected_cases=[f"case-{i}" for i in range(8)])
    assert summary["agent_gain_proven"] is True
    for pair in summary["paired"].values():
        currency = pair["efficiency"]["same_currency_cost"]["CNY"]
        assert currency["cost_gain_proven"] is True
        assert currency["exchange_rate_applied"] is False
        assert currency["group_bootstrap_95_ci"][1] < 0
    for row in rows:
        if row["mode"] == "team_hybrid":
            row["cost"]["pricing"]["currency_totals"] = {"USD": {"complete": True, "amount": 0.01}}
    summary = runner.paired_summary(rows, expected_cases=[f"case-{i}" for i in range(8)])
    assert summary["agent_gain_proven"] is False
    for pair in summary["paired"].values():
        assert all(
            cost["groups"] == 0 and cost["cost_gain_proven"] is False
            for cost in pair["efficiency"]["same_currency_cost"].values()
        )


def test_efficiency_excludes_whole_group_if_one_frozen_case_is_incorrect(runner):
    rows = scored_rows(runner, 9, equal_correct=True)
    for row in rows:
        if row["case_id"] == "case-8":
            row["group_id"] = "CVE-2026-10000"
        if row["case_id"] == "case-0" and row["mode"] != "team_hybrid":
            row["strict_pass"] = False
    summary = runner.paired_summary(rows, expected_cases=[f"case-{i}" for i in range(9)])
    for pair in summary["paired"].values():
        assert pair["efficiency"]["groups"] == 7
        assert "CVE-2026-10000" in pair["efficiency"]["excluded_groups"]
        assert pair["efficiency"]["efficiency_gain_proven"] is False


def test_missing_gold_for_complete_pair_is_not_silently_dropped(freezer, tmp_path):
    groups = [
        {"package": package, "two_public_sources_available": package == "gradio"}
        for package in freezer.PACKAGES
    ]
    exclusion_path = tmp_path / "exclusions.json"
    exclusion_path.write_text(json.dumps({"identifiers": []}))
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "agent-stage6-source-intake-v1",
                "packages_preselected": list(freezer.PACKAGES),
                "groups": groups,
                "exclusions_sha256": freezer.sha(exclusion_path),
            }
        )
    )
    specs = tmp_path / "specs.json"
    specs.write_text(json.dumps({"cases": []}))
    with pytest.raises(ValueError, match="gold_must_cover_all_and_only_complete_selected_pairs"):
        freezer.validate_inputs(tmp_path, specs)


def test_review_disagreements_require_bound_explicit_adjudication(runner, tmp_path):
    case = {
        "id": "case",
        "group_id": "CVE-2026-12345",
        "question": "fixture",
        "facts": [{"id": "f", "dimension": "conditions", "expected": "target"}],
    }
    result = {
        "answer": "fixture",
        "generation": {"status": "completed"},
        "citations": [],
        "generated_claims": [],
    }
    verdict = {
        "facts": [{"fact_id": "f", "covered": True, "grounded": False, "reason": "fixture"}],
        "claims": [],
        "boundary_ok": True,
        "boundary_reason": "fixture",
    }
    protocol = {"cases": [case]}
    (tmp_path / "answers").mkdir()
    (tmp_path / "judgments").mkdir()
    mapping = runner.blind_map(tmp_path, protocol)
    second_results = {}
    for anonymous_id, entry in mapping.items():
        source = tmp_path / "answers" / f"case-{entry['mode']}.json"
        runner.execute_once(source, {"mode": entry["mode"]}, lambda: result)
        runner.execute_once(
            tmp_path / "judgments" / f"{anonymous_id}.json",
            {"answer_sha256": runner.sha(source)},
            lambda: {"verdict": verdict},
        )
        disagrees = copy.deepcopy(verdict)
        disagrees["facts"][0]["covered"] = False
        second_results[anonymous_id] = {"verdict": disagrees}
    second_path = tmp_path / "second-review.json"
    second_path.write_text(
        json.dumps(
            {
                "method": "AI_quote_only_anonymous_review",
                "human_reviewed": False,
                "mapping_read": False,
                "results": second_results,
            }
        )
    )
    reconciled = runner.reconcile_reviews(tmp_path, protocol, second_path)
    assert all(r["verdict"] is None for r in reconciled["results"].values())
    assert all(r["first"] == verdict for r in reconciled["results"].values())
