"""Offline Stage 7 fixtures only; no real release freeze or provider request."""

import copy
import importlib.util
import json

import pytest

from zhidu.paired_evaluation import digest


@pytest.fixture
def runner():
    spec = importlib.util.spec_from_file_location(
        "stage7_development", "scripts/run_agent_stage7_development.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False))


@pytest.fixture
def legacy(tmp_path):
    source = tmp_path / "stage6"
    source.mkdir()
    (source / "corpus.sqlite").write_bytes(b"fixture isolated corpus; never queried")
    cases = []
    for i, fact_count in enumerate([7, 8, 8, 7, 8, 8]):
        case = {
            "id": f"case-{i}",
            "group_id": f"CVE-2026-{10000 + i}",
            "question": "fixture original question",
            "query": f"CVE-2026-{10000 + i} fixture",
            "facts": [
                {
                    "id": f"fact-{j}",
                    "dimension": "conditions",
                    "expected": "unchanged source target",
                }
                for j in range(fact_count)
            ],
        }
        cases.append(case)
        packet = {
            "version": "stage6-fair-initial-packet-v1",
            "retrieve_arguments": {"query": case["query"], "mode": "hybrid", "limit": 5},
            "scope": {"pool": "formal", "origin": "live", "event_id": None},
            "snapshot": {"evidence": {}, "steps": [], "attempted_calls": 1, "output_chars": 321},
            "elapsed_ms": 1.0,
            "reply": {"status": "completed"},
        }
        packet["packet_sha256"] = digest(packet)
        save(source / "initial-packets" / f"{case['id']}.json", packet)
        for mode in ("rag_hybrid", "workflow_hybrid", "team_hybrid"):
            row = {
                "case_id": case["id"],
                "mode": mode,
                "initial_packet_sha256": packet["packet_sha256"],
                "status": "completed",
                "result": {"generation": {"status": "completed"}, "cost": {"external_requests": 1}},
            }
            if mode == "workflow_hybrid" and i == 1:
                row = {
                    "case_id": case["id"],
                    "mode": mode,
                    "status": "unknown_outcome",
                    "request_ceiling": 1,
                }
            row["row_sha256"] = digest(row)
            save(source / "answers" / f"{case['id']}-{mode}.json", row)
    import hashlib

    encoder = {"model": "fixture", "digest": "fixture", "files": {}}
    save(source / "encoder-manifest.json", encoder)
    save(source / "model-pricing.json", {"fixture": "immutable price artifact"})
    save(source / "gold-specs.json", {"cases": cases})
    save(
        source / "report.json", {"version": "old immutable statistics", "agent_gain_proven": False}
    )
    body = b"fixture raw source bytes"
    raw_sha = hashlib.sha256(body).hexdigest()
    raw_path = source / "raw" / raw_sha[:2] / f"{raw_sha}.json"
    raw_path.parent.mkdir(parents=True)
    raw_path.write_bytes(body)

    def hashfile(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    protocol = {
        "version": "agent-stage6-holdout-v1",
        "cases": cases,
        "corpus_sha256": hashfile(source / "corpus.sqlite"),
        "raw_sha256": [raw_sha],
        "implementation_sha256": {},
        "matching": {
            "model_profile": {"provider": "deepseek", "model": "fixture-model"},
            "encoder_digest": "fixture",
            "encoder_manifest_sha256": hashfile(source / "encoder-manifest.json"),
            "model_pricing_sha256": hashfile(source / "model-pricing.json"),
        },
    }
    protocol["freeze_sha256"] = digest(protocol)
    save(source / "protocol.json", protocol)
    return source


def test_fixture_freeze_preserves_source_gold_initial_and_unknown_old_attempt(
    runner, legacy, tmp_path
):
    old_bytes = {
        str(path.relative_to(legacy)): path.read_bytes()
        for path in legacy.rglob("*")
        if path.is_file()
    }
    output = tmp_path / "stage7"
    protocol = runner.freeze(legacy, output)
    assert protocol["scope"] == "seen_corpus_development_regression"
    assert protocol["new_holdout"] is False and protocol["quality_gain_proven"] is False
    assert protocol["modes"] == ["team_hybrid"]
    assert protocol["budget"]["max_generation_requests"] == 48
    assert protocol["budget"]["max_judge_requests"] == 0
    assert protocol["budget"]["tool_calls_per_answer"] == 6
    assert protocol["budget"]["completion_tokens_per_call"] == 2400
    assert protocol["cases"] == json.loads((legacy / "protocol.json").read_text())["cases"]
    for name in ("corpus.sqlite", "gold-specs.json", "encoder-manifest.json", "model-pricing.json"):
        assert (output / name).read_bytes() == old_bytes[name]
    for path, body in old_bytes.items():
        assert (legacy / path).read_bytes() == body
    unknown = output / "legacy" / "answers" / "case-1-workflow_hybrid.json"
    assert unknown.read_bytes() == old_bytes["answers/case-1-workflow_hybrid.json"]
    assert all(
        (output / "initial-packets" / f"case-{i}.json").read_bytes()
        == old_bytes[f"initial-packets/case-{i}.json"]
        for i in range(6)
    )


def test_old_team_must_have_known_completed_attempt(runner, legacy, tmp_path):
    path = legacy / "answers" / "case-0-team_hybrid.json"
    row = {"status": "started", "mode": "team_hybrid", "case_id": "case-0"}
    save(path, row)
    with pytest.raises(ValueError, match="original_team_attempt_not_completed"):
        runner.freeze(legacy, tmp_path / "stage7")


def test_tail_selection_is_frozen_with_reduced_budget_and_unchanged_questions(
    runner, legacy, tmp_path
):
    original = json.loads((legacy / "protocol.json").read_text())
    output = tmp_path / "selected-stage7"
    protocol = runner.freeze(legacy, output, case_ids=["case-5", "case-4"])
    assert protocol["cases"] == original["cases"][4:]
    assert (
        protocol["budget"]["max_generation_requests"]
        == protocol["budget"]["max_total_requests"]
        == 16
    )
    assert protocol["selection"]["case_ids"] == ["case-4", "case-5"]
    assert protocol["selection"]["policy"].endswith("no combined score with earlier attempts")
    assert (output / "gold-specs.json").read_bytes() == (legacy / "gold-specs.json").read_bytes()
    assert runner.load_protocol(output)["cases"] == protocol["cases"]


@pytest.mark.parametrize("case_ids", [[], ["case-4", "case-4"], ["unknown-case"]])
def test_selection_cannot_drop_into_an_empty_duplicate_or_unknown_cohort(
    runner, legacy, tmp_path, case_ids
):
    output = tmp_path / "invalid-selection"
    with pytest.raises(ValueError, match="invalid_development_case_selection"):
        runner.freeze(legacy, output, case_ids=case_ids)
    assert not output.exists()


def test_initial_packet_hash_and_scope_cannot_change(runner, legacy):
    case = json.loads((legacy / "protocol.json").read_text())["cases"][0]
    packet = json.loads((legacy / "initial-packets" / "case-0.json").read_text())
    runner.validate_initial_packet(packet, case)
    changed = copy.deepcopy(packet)
    changed["snapshot"]["output_chars"] = 999
    with pytest.raises(ValueError, match="initial_packet_changed"):
        runner.validate_initial_packet(changed, case)
    changed = copy.deepcopy(packet)
    changed["retrieve_arguments"]["limit"] = 3
    changed.pop("packet_sha256")
    changed["packet_sha256"] = digest(changed)
    with pytest.raises(ValueError, match="initial_query_or_scope_changed"):
        runner.validate_initial_packet(changed, case)


def test_new_identity_is_distinct_from_every_stage6_request(runner):
    protocol = {"experiment_id": "stage7-development-fixture", "freeze_sha256": "fixture-hash"}
    identity = runner.request_identity(protocol, {"id": "case-0"})
    assert identity.startswith("stage7:")
    assert "stage7-development-fixture" in identity and "case-0:team_hybrid" in identity


def test_unknown_attempt_is_reserved_and_never_resubmitted(runner, tmp_path):
    calls = []

    def interrupted():
        calls.append(1)
        raise RuntimeError("accepted outcome unknown")

    path = tmp_path / "answers" / "case-team_hybrid.json"
    path.parent.mkdir()
    runner.execute_once(path, {"mode": "team_hybrid", "request_id": "stage7:fixture"}, interrupted)
    runner.execute_once(path, {"mode": "team_hybrid", "request_id": "stage7:fixture"}, interrupted)
    assert calls == [1]
    assert runner.generation_requests(tmp_path) == 8
    assert runner.stop_reason(json.loads(path.read_text())) == "unknown_provider_outcome"


def test_budget_or_format_failure_is_retained_and_stops_schedule(runner, tmp_path):
    calls = []
    cases = [{"id": f"case-{i}"} for i in range(6)]

    def failed(case):
        calls.append(case["id"])
        return {
            "generation": {"status": "fallback", "reason": "invalid_claim_text"},
            "cost": {"external_requests": 3, "billed_tokens": 20},
        }

    protocol = {
        "experiment_id": "stage7-development-fixture",
        "freeze_sha256": "fixture",
        "cases": cases,
        "budget": {"max_generation_requests": 48},
    }
    runner.run_schedule(tmp_path, protocol, failed)
    assert calls == ["case-0"]
    row = json.loads((tmp_path / "answers" / "case-0-team_hybrid.json").read_text())
    assert row["result"]["generation"]["reason"] == "invalid_claim_text"
    runner.run_schedule(tmp_path, protocol, failed)
    assert calls == ["case-0"]


def test_summary_keeps_unattempted_cases_and_never_claims_holdout_gain(runner, tmp_path):
    protocol = {
        "experiment_id": "stage7-development-fixture",
        "freeze_sha256": "fixture",
        "cases": [{"id": "case-0", "facts": []}, {"id": "case-1", "facts": []}],
        "legacy_artifact_sha256": {},
        "matching": {"model_profile": {"provider": "deepseek", "model": "fixture-model"}},
    }
    (tmp_path / "answers").mkdir()
    runner.execute_once(
        tmp_path / "answers" / "case-0-team_hybrid.json",
        {"mode": "team_hybrid"},
        lambda: {
            "generation": {"status": "completed"},
            "agent": {
                "role_calls": [
                    {"role": "composer", "call_id": "compose:0", "usage": {"total_tokens": 10}}
                ]
            },
            "tools": [
                {
                    "tool": "read_fields",
                    "args": {"fields": ["packages", "description"], "after_offset": 700},
                }
            ],
            "cost": {"external_requests": 1, "billed_tokens": 10},
            "observed_evidence_gaps": {"gaps": []},
            "citations": [],
        },
    )
    summary = runner.summary(tmp_path, protocol)
    assert summary["new_holdout"] is False and summary["quality_gain_proven"] is False
    assert len(summary["cases"]) == 2 and summary["cases"][1]["status"] == "not_attempted"
    assert summary["cases"][0]["actual_role_calls"][0]["role"] == "composer"


def test_technical_index_renderer_acceptance_is_local_and_citation_forgery_rejected(runner):
    probes = runner.renderer_acceptance()
    assert probes["network_or_model_calls"] == 0
    assert probes["technical_indices_accepted"] is True
    assert probes["authored_citation_rejected"] is True
    assert probes["semantic_support_verified"] is False
