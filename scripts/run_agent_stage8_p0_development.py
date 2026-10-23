"""P0 requirement-ledger/batch-research development on two already seen cases.

Freeze original bytes and prior outcomes, never infer a fresh holdout or combine
old scores. Generation is explicit and never retries a paid uncertain outcome.
Summary separates internal AI judgments, literal checks, interval novelty and
actual child receipts; no extra judge API exists.
"""

import argparse
import copy
import fcntl
import importlib.util
import json
import shutil
from contextlib import contextmanager
from functools import partial
from pathlib import Path

from zhidu.agent_result import verify_citations
from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.model_provider import model_profile
from zhidu.paired_evaluation import digest, quote_check
from zhidu.semantic import LocalEncoder, model_manifest
from zhidu.storage import BlobStore

_spec = importlib.util.spec_from_file_location(
    "stage8_shared_stage7", Path(__file__).with_name("run_agent_stage7_development.py")
)
_stage7 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_stage7)
save, sha, execute_once, load_attempt = (
    _stage7.save,
    _stage7.sha,
    _stage7.execute_once,
    _stage7.load_attempt,
)
MODE = "team_hybrid"
VERSION = "agent-stage8-p0-development-v1"
SELECTED_PACKAGES = ("langchain-core", "onnx")
BUDGET = {**_stage7.BUDGET, "max_generation_requests": 16, "max_total_requests": 16}
FIELDS = (
    "requirement_ledger",
    "question_coverage",
    "claim_support",
    "evidence_novelty",
    "batch_tool_calls",
)
TEXT_SUFFIXES = {
    ".py",
    ".pyi",
    ".js",
    ".mjs",
    ".cjs",
    ".css",
    ".scss",
    ".html",
    ".svg",
    ".md",
    ".txt",
}
PUBLIC_STATIC_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".ico",
}


def _reject_private_demo(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key.casefold() in {
                "api_key",
                "admin_key",
                "authorization",
                "password",
                "access_token",
                "refresh_token",
                "asset_id",
                "component_id",
            } and child not in (None, "", False):
                raise ValueError("public_demo_contains_private_data")
            if key.casefold() == "private_asset_data" and child is True:
                raise ValueError("public_demo_contains_private_data")
            _reject_private_demo(child)
    elif isinstance(value, list):
        for child in value:
            _reject_private_demo(child)


def archive_paths(project):
    """All current source/tests/static code; JSON only from public demo allowlist."""
    project = Path(project).resolve()
    selected = set()
    for directory in (project / "src", project / "tests"):
        for path in directory.rglob("*"):
            if (
                not path.is_file()
                or path.is_symlink()
                or any(
                    part in {"__pycache__", ".pytest_cache", ".ruff_cache"} for part in path.parts
                )
                or path.name.startswith(".env")
            ):
                continue
            static = project / "src" / "zhidu" / "static" in path.parents
            if path.suffix in TEXT_SUFFIXES or static and path.suffix in PUBLIC_STATIC_SUFFIXES:
                selected.add(path)
            elif static and path.suffix == ".json" and path.name.startswith("console-receipt-"):
                _reject_private_demo(json.loads(path.read_text()))
                selected.add(path)
    for name in (
        "scripts/run_agent_stage6_evaluation.py",
        "scripts/run_agent_stage7_development.py",
        "scripts/run_agent_stage8_p0_development.py",
        "pyproject.toml",
        "requirements.lock",
        "requirements-agent.lock",
        "requirements-semantic.lock",
    ):
        path = project / name
        if path.is_file():
            selected.add(path)
    return sorted(selected)


def _prior_paths(directory):
    names = {
        "protocol.json",
        "report.json",
        "stopped.json",
        "summary.json",
        "execution-audit.json",
        "cycle-budget-audit.json",
        "development-quote-review.json",
        "service-check.json",
    }
    selected = [
        p
        for p in directory.iterdir()
        if p.is_file()
        and (
            p.name in names
            or p.name.startswith("zero-call-")
            and p.suffix == ".json"
            or p.suffix == ".sqlite"
        )
    ]
    selected.extend(p for p in (directory / "answers").glob("*.json") if p.is_file())
    return sorted(selected)


def freeze(stage6, output, *, prior_developments=None):
    stage6, output = Path(stage6).resolve(), Path(output).resolve()
    old = _stage7._legacy_protocol(stage6)
    selected = []
    for package in SELECTED_PACKAGES:
        matches = [c for c in old["cases"] if c.get("package") == package]
        if len(matches) != 1:
            raise ValueError("p0_preselected_package_not_unique")
        selected.append(matches[0])
    if prior_developments is None:
        prior_developments = [
            p
            for p in sorted(stage6.parent.glob("agent-stage7-development*"))
            if (p / "protocol.json").is_file()
        ]
    prior_developments = [Path(p).resolve() for p in prior_developments]
    for directory in prior_developments:
        source = json.loads((directory / "protocol.json").read_text())
        if source.get("original_stage6", {}).get("freeze_sha256") != old["freeze_sha256"]:
            raise ValueError("prior_development_has_different_source_data")
    project = Path(__file__).resolve().parents[1]
    paths = archive_paths(project)
    protocol = _stage7.freeze(stage6, output, case_ids=[c["id"] for c in selected])
    code = output / "code"
    shutil.rmtree(code)
    hashes = {}
    for path in paths:
        relative = path.relative_to(project)
        before = sha(path)
        target = code / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        if sha(path) != before or sha(target) != before:
            raise ValueError("implementation_changed_during_freeze")
        hashes[str(relative)] = before
    preserved = {}
    for index, directory in enumerate(prior_developments):
        records = {}
        destination = output / "prior-development" / f"{index:02d}-{directory.name}"
        for path in _prior_paths(directory):
            relative = path.relative_to(directory)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            records[str(relative)] = {
                "sha256": sha(path),
                "copied_path": str(target.relative_to(output)),
            }
            if sha(target) != records[str(relative)]["sha256"]:
                raise ValueError("prior_artifact_changed_during_freeze")
        preserved[str(directory)] = records
    protocol.pop("freeze_sha256")
    protocol.update(
        version=VERSION,
        budget=copy.deepcopy(BUDGET),
        cases=copy.deepcopy(selected),
        scope="seen_corpus_p0_development_only",
        implementation_sha256=hashes,
        prior_development_artifacts=preserved,
        acceptance_fields=list(FIELDS),
    )
    protocol["selection"] = {
        "packages": list(SELECTED_PACKAGES),
        "case_ids": [c["id"] for c in selected],
        "selected_before_generation": True,
        "policy": "fixed P0 development cases; never combined with old scores",
    }
    protocol["statistics"] = {
        "official_or_holdout_accuracy": False,
        "semantic_scoring_api_calls": 0,
        "coverage_source": "internal AI original-question/anchored-task review, not independently proven semantics",
        "novelty_basis": "canonical raw-source field interval union; unknown spans never become known-new",
        "new_holdout": False,
        "quality_gain_proven": False,
    }
    protocol["freeze_sha256"] = digest(protocol)
    save(output / "protocol.json", protocol)
    return protocol


def _verify_preserved(output, protocol):
    original = Path(protocol["original_stage6"]["path"])
    for name, expected in (
        protocol["data_artifact_sha256"] | protocol["initial_artifact_sha256"]
    ).items():
        if sha(original / name) != expected:
            raise ValueError("original_stage6_data_or_initial_changed")
    for raw_sha in protocol["raw_sha256"]:
        BlobStore(original / "raw").read(raw_sha)
    for name, expected in protocol["legacy_artifact_sha256"].items():
        if sha(output / "legacy" / name) != expected or sha(original / name) != expected:
            raise ValueError("legacy_statistics_or_attempt_changed")
    for directory, records in protocol["prior_development_artifacts"].items():
        for relative, binding in records.items():
            if (
                sha(Path(directory) / relative) != binding["sha256"]
                or sha(output / binding["copied_path"]) != binding["sha256"]
            ):
                raise ValueError("prior_development_artifact_changed")


def load_protocol(output):
    output = Path(output).resolve()
    protocol = json.loads((output / "protocol.json").read_text())
    frozen = dict(protocol)
    expected = frozen.pop("freeze_sha256")
    if protocol.get("version") != VERSION or digest(frozen) != expected:
        raise ValueError("stage8_protocol_changed")
    if (
        tuple(c["package"] for c in protocol["cases"]) != SELECTED_PACKAGES
        or protocol["budget"] != BUDGET
        or protocol["modes"] != [MODE]
        or protocol["new_holdout"] is not False
    ):
        raise ValueError("stage8_policy_or_selection_changed")
    for name, expected in (
        protocol["data_artifact_sha256"] | protocol["initial_artifact_sha256"]
    ).items():
        if sha(output / name) != expected:
            raise ValueError("stage8_frozen_data_changed")
    _verify_preserved(output, protocol)
    project = Path(__file__).resolve().parents[1]
    if {str(p.relative_to(project)) for p in archive_paths(project)} != set(
        protocol["implementation_sha256"]
    ):
        raise ValueError("stage8_implementation_footprint_changed")
    for name, expected in protocol["implementation_sha256"].items():
        if sha(project / name) != expected or sha(output / "code" / name) != expected:
            raise ValueError("stage8_implementation_changed")
    for raw_sha in protocol["raw_sha256"]:
        BlobStore(output / "raw").read(raw_sha)
    return protocol


def experiment_settings(output, protocol):
    settings = Settings()
    values = settings.model_dump() | {
        "database_url": f"sqlite:///{Path(output) / 'corpus.sqlite'}",
        "raw_dir": Path(output) / "raw",
        "embedding_manifest": Path(output) / "encoder-manifest.json",
        "model_pricing_path": Path(output) / "model-pricing.json",
        "agent_checkpoint_path": Path(output) / "stage8-role-receipts.sqlite",
        "agent_max_model_calls": 8,
        "agent_max_tool_calls": 6,
        "agent_deadline_seconds": 60,
        "deepseek_timeout_seconds": 60,
        "deepseek_max_tokens": 2400,
        "agent_max_output_chars": 18000,
        "agent_final_reserve_seconds": 12,
        "llm_temperature": 0,
    }
    settings = Settings.model_validate(values)
    if model_profile(settings).public() != protocol["matching"]["model_profile"]:
        raise ValueError("original_model_profile_changed")
    if model_manifest(settings, verify=True)["digest"] != protocol["matching"]["encoder_digest"]:
        raise ValueError("original_encoder_digest_changed")
    return settings


def _field(result, name):
    value = result.get(name)
    return value if value is not None else result.get("agent", {}).get(name)


def _tasks(value):
    return (
        value
        if isinstance(value, list)
        else value.get("tasks", value.get("items", []))
        if isinstance(value, dict)
        else []
    )


def acceptance_contract_audit(result):
    """Structural consistency only. Anchored text is not semantic entailment."""
    issues = []
    ledger, coverage = _field(result, "requirement_ledger"), _field(result, "question_coverage")
    if ledger is None or not _tasks(ledger) or not isinstance(coverage, dict):
        issues.append("p0_coverage_fields_unrecorded")
    coverage = coverage if isinstance(coverage, dict) else {}
    if coverage.get("complete") is True:
        if coverage.get("missing_task_ids"):
            issues.append("complete_with_missing_tasks")
        if coverage.get("unanswered_question_requirements"):
            issues.append("complete_with_unanswered_question_requirements")
    elif result.get("answer_class") == "evidence":
        issues.append("incomplete_question_answer_must_not_be_evidence")
    claims, citations = result.get("generated_claims", []), result.get("citations", [])
    literal = quote_check(result)
    if claims and literal["total"] != literal["exact"]:
        issues.append("invalid_actual_quote_reference")
    for task in _tasks(ledger):
        if coverage.get("complete") is True and task.get("status") != "covered":
            issues.append("complete_with_incomplete_ledger_task")
        if task.get("status") != "covered":
            continue
        indices = task.get("final_statement_indices", task.get("statement_indices", []))
        if not indices or any(type(i) is not int or not 1 <= i <= len(claims) for i in indices):
            issues.append("covered_task_without_valid_final_statement")
            continue
        spans = task.get("answer_spans", [])
        if not spans:
            issues.append("covered_task_without_final_answer_span")

        def bound_span(span, retained_indices=indices):
            index = span.get("final_statement_index", span.get("statement_index"))
            if index not in retained_indices:
                issues.append("answer_span_not_in_final_statement")
                return
            text = claims[index - 1]["text"]
            selected = span.get("text")
            start, end = span.get("start"), span.get("end")
            if (
                not isinstance(selected, str)
                or not selected
                or selected not in text
                or (start is not None or end is not None)
                and (
                    type(start) is not int
                    or type(end) is not int
                    or not 0 <= start < end <= len(text)
                    or text[start:end] != selected
                )
            ):
                issues.append("answer_span_not_in_final_statement")

        for span in spans:
            bound_span(span)
        required_elements = task.get("required_elements", [])
        elements = task.get("element_coverage", [])
        if (
            not required_elements
            or {e.get("element") for e in elements} != set(required_elements)
            or len(elements) != len(required_elements)
        ):
            issues.append("covered_task_element_coverage_unrecorded")
        for element in elements:
            if element.get("status") != "covered" or not element.get("answer_spans"):
                issues.append("covered_task_with_incomplete_element")
            for span in element.get("answer_spans", []):
                bound_span(span)
        per_statement_sources = []
        for index in indices:
            sources = set()
            for ref in claims[index - 1].get("evidence", []):
                citation = ref.get("citation")
                if type(citation) is int and 1 <= citation <= len(citations):
                    source = citations[citation - 1].get("source_id")
                    if source:
                        sources.add(source)
            per_statement_sources.append(sources)
        sources = set().union(*per_statement_sources)
        required = set(task.get("source_ids", []))
        policy = task.get("source_policy", "any")
        if policy == "compare" and (
            len(required) < 2 or not any(required <= observed for observed in per_statement_sources)
        ):
            issues.append("covered_task_missing_required_sources")
        elif policy == "each" and (not required or not required <= sources):
            issues.append("covered_task_missing_required_sources")
        elif policy == "any" and (not required & sources if required else not sources):
            issues.append("covered_task_missing_required_sources")
        elif policy not in {"any", "each", "compare"}:
            issues.append("invalid_source_policy")
    return {
        "method": "offline_structural_P0_contract_audit",
        "contract_ok": not issues,
        "issues": list(dict.fromkeys(issues)),
        "literal_quote_check": literal,
        "independent_semantic_score": False,
        "semantic_support_verified": False,
    }


def _items(value):
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return value.get("items", value.get("claims", value.get("calls", [])))
    return []


def _known_chars(value):
    if not isinstance(value, dict):
        return 0
    # Unknown before/after intervals cannot establish that known coordinates
    # are actually new. Keep the diagnostic residual in the raw field only.
    if value.get("status") == "unknown":
        return 0
    chars = value.get("new_source_chars")
    return chars if type(chars) is int and chars >= 0 else 0


def progress_summary(result):
    fields = {
        name: {
            "availability": "recorded" if _field(result, name) is not None else "unrecorded",
            "value": copy.deepcopy(_field(result, name)),
        }
        for name in FIELDS
    }
    batch = {
        "availability": fields["batch_tool_calls"]["availability"],
        "parent_calls": 0,
        "actual_children": 0,
        "actual_tool_attempts": 0,
        "unrecorded_child_attempts": 0,
        "replayed_children": 0,
        "logical_known_new_chars": 0,
        "current_attempt_known_new_chars": 0,
        "unknown_child_novelties": 0,
        "novelty_is_semantic_gain": False,
    }
    for entry in _items(_field(result, "batch_tool_calls")):
        batch["parent_calls"] += entry.get("action") in {"batch", "read_plan"}
        for child in entry.get("tool_observations", entry.get("children", [])):
            replayed = child.get("replayed") is True
            batch["replayed_children"] += replayed
            attempts = child.get("actual_tool_attempts")
            if type(attempts) is int and attempts >= 0:
                batch["actual_children"] += attempts > 0
                batch["actual_tool_attempts"] += attempts
            elif not replayed:
                batch["unrecorded_child_attempts"] += 1
            batch["unknown_child_novelties"] += child.get("novelty", {}).get("status") == "unknown"
            batch["logical_known_new_chars"] += _known_chars(child.get("novelty"))
            batch["current_attempt_known_new_chars"] += (
                0 if replayed else _known_chars(child.get("current_attempt_novelty"))
            )
    return {
        **fields,
        "batch": batch,
        "contract_audit": acceptance_contract_audit(result),
        "semantic_support_verified": False,
        "official_accuracy": None,
    }


def request_identity(protocol, case):
    return f"stage8:{protocol['experiment_id']}:{protocol['freeze_sha256']}:{case['id']}:{MODE}"


def generation_requests(output):
    return _stage7.generation_requests(output)


def stop_reason(row):
    reason = _stage7.stop_reason(row)
    if reason:
        return reason
    audit = row.get("result", {}).get("stage8_acceptance", {}).get("contract_audit")
    if not isinstance(audit, dict):
        return "p0_acceptance_contract_unrecorded"
    return "p0_acceptance_contract_failed" if audit.get("contract_ok") is not True else None


@contextmanager
def _single_runner(output):
    with (output / "generation.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("stage8_runner_already_active") from None
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def run_schedule(output, protocol, run_case):
    output = Path(output)
    (output / "answers").mkdir(exist_ok=True)
    with _single_runner(output):
        stop_path = output / "stopped.json"
        if stop_path.exists():
            return json.loads(stop_path.read_text())
        for case in protocol["cases"]:
            path = output / "answers" / f"{case['id']}-{MODE}.json"
            identity = request_identity(protocol, case)
            if path.exists():
                row = load_attempt(path)
                if row.get("request_id") != identity:
                    raise ValueError("attempt_request_identity_changed")
            else:
                if generation_requests(output) + 8 > protocol["budget"]["max_generation_requests"]:
                    value = {
                        "case_id": case["id"],
                        "reason": "global_request_budget_exhausted",
                        "automatic_retry": False,
                    }
                    save(stop_path, value, new=True)
                    return value
                metadata = {
                    "case_id": case["id"],
                    "mode": MODE,
                    "request_id": identity,
                    "experimental_id": protocol["experiment_id"],
                    "protocol_sha256": protocol["freeze_sha256"],
                    "request_ceiling": 8,
                }
                row = execute_once(path, metadata, partial(run_case, case))
            reason = stop_reason(row)
            if reason:
                value = {
                    "case_id": case["id"],
                    "reason": reason,
                    "request_id": identity,
                    "attempt_retained": True,
                    "automatic_retry": False,
                }
                save(stop_path, value, new=True)
                return value
        return {
            "status": "completed",
            "cases": len(protocol["cases"]),
            "requests": generation_requests(output),
        }


def generate(output, protocol, settings):
    output = Path(output)
    engine = make_engine(settings.database_url)
    sessions, store, encoder = (
        make_sessions(engine),
        BlobStore(settings.raw_dir),
        LocalEncoder(settings),
    )

    def run_case(case):
        packet = json.loads((output / "initial-packets" / f"{case['id']}.json").read_text())
        body = _stage7.validate_initial_packet(packet, case)
        with sessions() as session:
            tools = _stage7._shared.restore_initial_packet(
                packet, session, store, settings, body, encoder
            )
            checks = verify_citations(session, store, list(tools.evidence.values()))
            if (
                checks["verified"] != checks["total"]
                or tools.evidence != packet["snapshot"]["evidence"]
                or tools.runtime.output_chars != packet["snapshot"]["output_chars"]
            ):
                raise ValueError("original_initial_scope_invalid")
            result = _stage7._shared.run_mode(
                MODE,
                packet,
                session,
                store,
                settings,
                body,
                encoder,
                checkpoint_key=request_identity(protocol, case),
            )
            result["stage8_acceptance"] = {
                "seen_development": True,
                "initial_packet_sha256": packet["packet_sha256"],
                "source_binding": checks,
                "contract_audit": acceptance_contract_audit(result),
                "independent_semantic_score": False,
            }
            return result

    try:
        value = run_schedule(output, protocol, run_case)
    finally:
        encoder.close()
        engine.dispose()
    if sha(output / "corpus.sqlite") != protocol["corpus_sha256"]:
        raise ValueError("development_mutated_frozen_corpus")
    return value


def summary(output, protocol):
    output = Path(output)
    _verify_preserved(output, protocol)
    value = _stage7.summary(output, protocol)
    for row in value["cases"]:
        path = output / "answers" / f"{row['case_id']}-{MODE}.json"
        result = load_attempt(path).get("result", {}) if path.exists() else {}
        progress = progress_summary(result)
        row.update(progress)
        cost = result.get("cost", {})
        row["cost_receipt"] = copy.deepcopy(cost)
        row["monetary"] = copy.deepcopy(cost.get("pricing", cost.get("monetary")))
        row["acceptance"] = result.get("stage8_acceptance")
        models, tools = (
            cost.get("external_requests"),
            result.get("agent", {}).get("attempted_tool_calls"),
        )
        row["budget_observation"] = {
            "model_calls_limit": 8,
            "tool_calls_limit_including_initial": 6,
            "model_calls": models,
            "current_attempt_model_calls": cost.get("current_attempt_external_requests"),
            "tool_calls_including_initial": tools,
            "additional_tool_attempts": result.get("actual_additional_tool_attempts"),
            "model_limit_observed": models <= 8 if type(models) is int and models >= 0 else None,
            "tool_limit_observed": tools <= 6 if type(tools) is int and tools >= 0 else None,
            "soft_deadline_seconds": 60,
            "elapsed_ms": row.get("elapsed_ms"),
            "completion_tokens_per_call": 2400,
            "tool_output_chars_limit": 18000,
            "tool_output_chars": result.get("agent", {}).get("tool_output_chars"),
        }
        case = next(c for c in protocol["cases"] if c["id"] == row["case_id"])
        row["frozen_target_fact_ids"] = [f["id"] for f in case["facts"]]
        row["gold_fact_score"] = None
    value.update(
        version="stage8-p0-development-summary-v1",
        scope="seen_corpus_p0_development_only",
        selected_packages=list(SELECTED_PACKAGES),
        judge_api_calls=0,
        semantic_support_verified=False,
        old_scores_combined=False,
        official_accuracy=None,
        quality_gain_proven=False,
        new_holdout=False,
        budget=copy.deepcopy(protocol.get("budget", BUDGET)),
    )
    save(output / "summary.json", value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--action", choices=("freeze", "validate", "generate", "summary"), default="validate"
    )
    parser.add_argument("--stage6", type=Path)
    parser.add_argument("--prior-development", action="append", type=Path)
    args = parser.parse_args()
    if args.action == "freeze":
        if args.stage6 is None:
            parser.error("--stage6 required for freeze")
        value = freeze(args.stage6, args.output, prior_developments=args.prior_development)
        print(
            json.dumps(
                {"frozen": True, "new_holdout": False, "cases": [c["id"] for c in value["cases"]]}
            )
        )
        return
    if args.stage6 is not None or args.prior_development is not None:
        parser.error("source/selection options are only accepted before freeze")
    protocol = load_protocol(args.output)
    if args.action == "generate":
        value = generate(args.output, protocol, experiment_settings(args.output, protocol))
    elif args.action == "summary":
        value = summary(args.output, protocol)
    else:
        value = {
            "validated": True,
            "new_holdout": False,
            "cases": [c["id"] for c in protocol["cases"]],
        }
    print(json.dumps(value, ensure_ascii=False))


if __name__ == "__main__":
    main()
