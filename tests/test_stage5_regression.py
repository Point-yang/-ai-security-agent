"""Regression freezing/routing/budgets, without provider calls or real snapshots."""

import importlib.util
import json

import pytest
from pydantic import SecretStr
from test_paired_evaluation import sample

from zhidu.paired_evaluation import digest, score_answer, summarize
from zhidu.storage import BlobStore


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = _module("stage5_runner", "scripts/run_agent_paired_pilot.py")
freezer = _module("stage5_freezer", "scripts/freeze_agent_stage5_regression.py")


def test_freeze_preserves_seen_gold_source_bytes_and_never_overwrites(
    tmp_path, settings, monkeypatch
):
    source = tmp_path / "stage4"
    source.mkdir()
    (source / "corpus.sqlite").write_bytes(b"immutable-test-snapshot")
    store = BlobStore(source / "raw")
    raw_sha = store.put(b'{"literal": "preserve spaces and source bytes"}')
    cases = [
        {
            "id": f"case-{i}",
            "group_id": f"group-{i}",
            "facts": [
                {"id": str(n), "expected": "frozen original source fact"} for n in range(count)
            ],
        }
        for i, count in enumerate((7, 7, 9, 7))
    ]
    original = {
        "cases": cases,
        "gold_review": {"human_reviewed": False},
        "corpus_sha256": freezer.sha(source / "corpus.sqlite"),
        "raw_sha256": [raw_sha],
        "rubric": {"strict": "all required facts grounded"},
    }
    original["freeze_sha256"] = digest(original)
    (source / "protocol.json").write_text(json.dumps(original))
    source_hash = freezer.sha(source / "protocol.json")
    monkeypatch.setattr(freezer, "STAGE4_SOURCE", source)
    monkeypatch.setattr(freezer, "ROOT", tmp_path)
    monkeypatch.setattr(freezer, "CONTRACT_VERSION", "source-answer-v4")
    monkeypatch.setattr(
        freezer,
        "Settings",
        lambda: settings.model_copy(
            update={
                "deepseek_api_key": SecretStr("never-publish-this-test-secret"),
            }
        ),
    )
    monkeypatch.setattr(freezer, "implementation_hashes", lambda: {"fixture.py": "0" * 64})
    output = tmp_path / "stage5"
    protocol = freezer.freeze(output)
    assert protocol["cases"] == cases
    assert protocol["development_history"]["all_groups_seen"]
    assert protocol["development_history"]["all_facts_seen"]
    assert protocol["development_history"]["atomic_facts"] == 30
    assert protocol["gold_review"]["human_reviewed"] is False
    assert protocol["held_out"] is False and protocol["effective_split"] == "development_regression"
    assert freezer.sha(output / "corpus.sqlite") == original["corpus_sha256"]
    assert BlobStore(output / "raw").read(raw_sha) == store.read(raw_sha)
    assert freezer.sha(source / "protocol.json") == source_hash
    assert "never-publish-this-test-secret" not in (output / "protocol.json").read_text()
    with pytest.raises(FileExistsError, match="already_exists"):
        freezer.freeze(output)


def test_three_new_modes_use_product_workflow_and_per_mode_ceilings(
    tmp_path, settings, monkeypatch
):
    calls = []

    def mock_product(session, store, current_settings, body, encoder, *args):
        calls.append((body.agent_backend, current_settings.agent_max_model_calls))
        return {"generation": {"status": "completed"}, "cost": {"external_requests": 1}}

    def old_helper(*args, **kwargs):
        raise AssertionError("new protocol must use product workflow")

    monkeypatch.setattr(runner, "run_rag", mock_product)
    monkeypatch.setattr(runner, "run_workflow_agent", mock_product)
    monkeypatch.setattr(runner, "fixed_workflow", old_helper)
    monkeypatch.setattr(runner, "sha", lambda path: "unchanged")
    protocol = {
        "cases": [{"id": "case", "question": "来源版本范围是什么", "query": "fixture"}],
        "modes": ["rag", "workflow", "auto"],
        "matching": {"workflow_execution": "production_workflow_agent"},
        "budget": {
            "max_generation_requests": 28,
            "max_judge_requests": 12,
            "max_total_requests": 40,
        },
        "corpus_sha256": "unchanged",
    }
    runner.generate(tmp_path, protocol, settings)
    assert set(calls) == {(None, 1), ("workflow", 1), ("auto", 5)}
    assert len(list((tmp_path / "answers").glob("*.json"))) == 3
    assert {row["mode"] for row in runner.blind_map(tmp_path, protocol).values()} == {
        "rag",
        "workflow",
        "auto",
    }


def test_started_requests_reserve_the_correct_mode_ceiling(tmp_path):
    (tmp_path / "answers").mkdir()
    for mode in ("rag", "workflow", "auto"):
        runner.save(
            tmp_path / "answers" / f"{mode}.json", {"status": "started", "mode": mode}, new=True
        )
    assert runner.generation_requests(tmp_path, {"budget": {}}) == 7


def test_judge_global_ceiling_is_checked_before_http(tmp_path, settings, monkeypatch):
    case = {
        "id": "case",
        "question": "来源事实是什么",
        "facts": [{"id": "f", "dimension": "conditions", "expected": "来源事实"}],
    }
    protocol = {
        "cases": [case],
        "modes": ["rag", "workflow", "auto"],
        "budget": {
            "max_generation_requests": 28,
            "max_judge_requests": 0,
            "max_total_requests": 40,
        },
    }
    (tmp_path / "answers").mkdir()
    answer = {
        "case_id": "case",
        "mode": "rag",
        "status": "completed",
        "result": {
            "answer": "来源声明",
            "cost": {"external_requests": 0},
            "citations": [],
            "generated_claims": [],
        },
    }
    answer["row_sha256"] = digest(answer)
    runner.save(runner.answer_path(tmp_path, case, "rag"), answer, new=True)
    runner.save(
        tmp_path / "blind-map.json", {"anonymous-001": {"case_id": "case", "mode": "rag"}}, new=True
    )

    def forbidden_http(*args, **kwargs):
        raise AssertionError("budget-exhausted judge must not call provider")

    monkeypatch.setattr(runner.httpx, "Client", forbidden_http)
    monkeypatch.setattr(
        runner, "generation_target", lambda *args: ("https://fixture.invalid", "test-only")
    )
    with pytest.raises(ValueError, match="global_judge_budget_exhausted"):
        runner.judge(tmp_path, protocol, settings)
    assert not list((tmp_path / "judgments").glob("*.json"))


def test_total_budget_includes_generation_and_unknown_judge_receipts(tmp_path):
    (tmp_path / "judgments").mkdir()
    runner.save(
        tmp_path / "judgments" / "unknown.json",
        {"status": "started", "external_requests": 1},
        new=True,
    )
    assert runner.judge_requests(tmp_path) == 1
    protocol = {
        "budget": {"max_generation_requests": 28, "max_judge_requests": 12, "max_total_requests": 1}
    }
    with pytest.raises(ValueError, match="global_total_budget_exhausted"):
        runner.check_request_budget(protocol, generation=1, judging=runner.judge_requests(tmp_path))


def test_auto_can_be_the_paired_challenger_without_changing_old_default():
    case, result, verdict = sample()
    records = []
    for mode in ("rag", "workflow", "auto"):
        row = score_answer(case, result, verdict)
        row.update(mode=mode, elapsed_ms=1, cost={"external_requests": 1, "billed_tokens": 10})
        records.append(row)
    report = summarize(records, modes=("rag", "workflow", "auto"), challenger="auto")
    assert set(report["modes"]) == {"rag", "workflow", "auto"}
    assert set(report["paired"]) == {"rag", "workflow"}
    assert report["paired"]["workflow"]["delta"] == 0
    assert not report["agent_gain_proven"]
