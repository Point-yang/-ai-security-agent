"""One new verifier of an immutable, previously paid development candidate.

Freeze/validate are offline. Generation never repeats planning, research,
composition or an uncertain request. It does not change the original failure
or establish complete Agent success, holdout accuracy or independent semantics.
"""

import argparse
import copy
import fcntl
import importlib.util
import json
import shutil
import sqlite3
import tempfile
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from zhidu.agent_result import verify_citations
from zhidu.agent_state import AgentAnswer
from zhidu.agent_team_state import TaskPlan
from zhidu.config import Settings
from zhidu.grounded_answer import render_answer
from zhidu.model_costs import cost_for_calls
from zhidu.model_provider import model_profile
from zhidu.paired_evaluation import digest, quote_check
from zhidu.storage import BlobStore

_spec = importlib.util.spec_from_file_location(
    "anchor_shared_stage8", Path(__file__).with_name("run_agent_stage8_p0_development.py")
)
_stage8 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_stage8)
save, sha, execute_once, load_attempt = (
    _stage8.save,
    _stage8.sha,
    _stage8.execute_once,
    _stage8.load_attempt,
)
VERSION = "agent-body-anchor-review-only-v1"
CASE_ID = "stage6-langchain-core"
ROLE_CALL_ID = "anchor-verify:0"
BUDGET = {
    "new_model_calls": 1,
    "new_business_tool_calls": 0,
    "completion_tokens": 2400,
    "soft_deadline_seconds": 60,
    "automatic_retry": False,
}


def _relative(root, name):
    path = Path(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("invalid_artifact_path")
    selected = root / path
    if selected.is_symlink() or root.resolve() not in selected.resolve().parents:
        raise ValueError("invalid_artifact_path")
    return selected


def _public_only(value):
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = key.casefold().replace("_", "").replace("-", "")
            if normalized in {
                "assetid",
                "selectedasset",
                "componentid",
                "sbomsha256",
                "privateassetdata",
            } and item not in (None, "", False, [], {}):
                raise ValueError("review_requires_public_evaluation_scope")
            if key == "code" and item == "private_asset_local_only":
                raise ValueError("review_requires_public_evaluation_scope")
            _public_only(item)
    elif isinstance(value, list):
        for item in value:
            _public_only(item)


def _source_protocol(source):
    protocol = json.loads((source / "protocol.json").read_text())
    frozen = dict(protocol)
    expected = frozen.pop("freeze_sha256")
    if protocol.get("version") != "agent-stage8-p0-development-v1" or digest(frozen) != expected:
        raise ValueError("original_protocol_changed")
    bindings = {"protocol.json": sha(source / "protocol.json")}
    for name, expected_sha in (
        protocol["data_artifact_sha256"] | protocol["initial_artifact_sha256"]
    ).items():
        if sha(_relative(source, name)) != expected_sha:
            raise ValueError("original_data_or_initial_changed")
        bindings[name] = expected_sha
    if sha(source / "corpus.sqlite") != protocol["corpus_sha256"]:
        raise ValueError("original_corpus_changed")
    for name, expected_sha in protocol["implementation_sha256"].items():
        relative = "code/" + name
        if sha(_relative(source, relative)) != expected_sha:
            raise ValueError("original_code_archive_changed")
        bindings[relative] = expected_sha
    for name, expected_sha in protocol.get("legacy_artifact_sha256", {}).items():
        relative = "legacy/" + name
        if sha(_relative(source, relative)) != expected_sha:
            raise ValueError("original_legacy_artifact_changed")
        bindings[relative] = expected_sha
    store = BlobStore(source / "raw")
    for raw_sha in protocol["raw_sha256"]:
        store.read(raw_sha)  # Literal integrity only, never model input.
    return protocol, bindings


def _source_files(source):
    names = [
        "protocol.json",
        "corpus.sqlite",
        "gold-specs.json",
        "model-pricing.json",
        "encoder-manifest.json",
        "stage8-role-receipts.sqlite",
        "stage8-role-receipts.sqlite-wal",
        "corpus.sqlite-wal",
        "stopped.json",
        "summary.json",
    ]
    paths = [source / name for name in names if (source / name).is_file()]
    for name in ("raw", "initial-packets", "answers"):
        paths.extend(path for path in (source / name).rglob("*.json") if path.is_file())
    if any(path.is_symlink() for path in paths):
        raise ValueError("invalid_artifact_path")
    return sorted(set(paths))


def _sqlite_copy(original, destination):
    shutil.copyfile(original, destination)
    wal = original.with_name(original.name + "-wal")
    if wal.is_file():
        shutil.copyfile(wal, destination.with_name(destination.name + "-wal"))


def paid_inputs(source, protocol):
    """Read main+WAL copies in a temporary directory, never open the old DB."""
    selected = [
        case
        for case in protocol["cases"]
        if case["id"] == CASE_ID and case["package"] == "langchain-core"
    ]
    if len(selected) != 1:
        raise ValueError("fixed_original_core_case_required")
    case = {key: selected[0][key] for key in ("id", "package", "question", "query")}
    attempt = load_attempt(source / "answers" / f"{CASE_ID}-team_hybrid.json")
    _public_only(attempt)
    thread = attempt.get("request_id")
    if not isinstance(thread, str) or not thread.startswith("stage8:"):
        raise ValueError("original_paid_thread_missing")
    if attempt.get("result", {}).get("generation", {}).get("status") == "completed":
        raise ValueError("original_failed_candidate_required")
    receipts = {}
    with tempfile.TemporaryDirectory(prefix="anchor-paid-read-") as temporary:
        path = Path(temporary) / "receipts.sqlite"
        _sqlite_copy(source / "stage8-role-receipts.sqlite", path)
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as database:
            for call_id in ("planner:0", "compose:0"):
                row = database.execute(
                    "SELECT r.step,r.status,r.response,r.audit FROM agent_role_steps s JOIN agent_model_replies r ON r.thread_id=s.thread_id AND r.step=s.step WHERE s.thread_id=? AND s.call_id=?",
                    (thread, call_id),
                ).fetchone()
                if row is None or row[1] != "completed":
                    raise ValueError("original_paid_reply_not_completed")
                response, audit = json.loads(row[2]), json.loads(row[3])
                if (
                    audit.get("error")
                    or audit.get("finish_reason") != "stop"
                    or not isinstance(response.get("answer"), dict)
                ):
                    raise ValueError("original_typed_plan_and_candidate_required")
                receipts[call_id] = {
                    "step": row[0],
                    "answer": response["answer"],
                    "response_sha256": digest(response),
                    "audit_sha256": digest(audit),
                }
            row = database.execute(
                "SELECT snapshot FROM agent_context WHERE thread_id=?", (thread,)
            ).fetchone()
            if row is None or row[0] is None:
                raise ValueError("original_context_missing")
            snapshot = json.loads(row[0])
    _public_only(snapshot)
    initial = json.loads((source / "initial-packets" / f"{CASE_ID}.json").read_text())
    _public_only(initial)
    if initial.get("scope") != {"pool": "formal", "origin": "live", "event_id": None}:
        raise ValueError("review_requires_public_evaluation_scope")
    plan = TaskPlan.model_validate(receipts["planner:0"]["answer"])
    candidate = AgentAnswer.model_validate(receipts["compose:0"]["answer"])
    render_answer(candidate, snapshot["evidence"])
    return {
        "case": case,
        "source_thread_id": thread,
        "plan": plan.model_dump(exclude_unset=True),
        "candidate": candidate.model_dump(exclude_unset=True),
        "snapshot": snapshot,
        "paid_reply_bindings": {
            key: {k: v for k, v in value.items() if k != "answer"}
            for key, value in receipts.items()
        },
    }


def _verify_frozen_citations(output, inputs):
    with tempfile.TemporaryDirectory(prefix="anchor-corpus-read-") as temporary:
        path = Path(temporary) / "corpus.sqlite"
        _sqlite_copy(output / "source" / "corpus.sqlite", path)
        engine = create_engine(
            "sqlite://", creator=lambda: sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        )
        try:
            with Session(engine, autoflush=False) as session:
                checks = verify_citations(
                    session,
                    BlobStore(output / "source" / "raw"),
                    list(inputs["snapshot"]["evidence"].values()),
                )
        finally:
            engine.dispose()
    if checks["verified"] != checks["total"] or not checks["total"]:
        raise ValueError("original_source_scope_invalid")
    return checks


def archive_paths(project):
    paths = set(_stage8.archive_paths(project))
    paths.add(project / "scripts" / "run_agent_anchor_review_only.py")
    return sorted(paths)


def _anchor_api():
    from zhidu.agent_requirements import expand_verifier_decision, verifier_packet
    from zhidu.agent_team_state import VerifierDecision

    return VerifierDecision, verifier_packet, expand_verifier_decision


def review_packet(protocol, inputs):
    _, packet_builder, _ = _anchor_api()
    return packet_builder(
        inputs["case"]["question"],
        TaskPlan.model_validate(inputs["plan"]),
        AgentAnswer.model_validate(inputs["candidate"]),
        inputs["snapshot"]["evidence"],
        scope=protocol["scope_id"],
    )


def freeze(source, output):
    source, output = Path(source).resolve(), Path(output).resolve()
    if output.exists() or source == output or source in output.parents:
        raise ValueError("new_separate_review_directory_required")
    old, protections = _source_protocol(source)
    files = _source_files(source)
    source_hashes = {str(path.relative_to(source)): sha(path) for path in files}
    protections.update(source_hashes)
    inputs = paid_inputs(source, old)
    project = Path(__file__).resolve().parents[1]
    implementations = {str(path.relative_to(project)): sha(path) for path in archive_paths(project)}
    output.mkdir(parents=True)
    for path in files:
        target = output / "source" / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    for name, expected in implementations.items():
        target = output / "code" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(project / name, target)
        if sha(target) != expected or sha(project / name) != expected:
            raise ValueError("implementation_changed_during_freeze")
    source_checks = _verify_frozen_citations(output, inputs)
    save(output / "review-inputs.json", inputs, new=True)
    scope_id = (
        "anchor-review:"
        + output.name
        + ":"
        + digest({"inputs": inputs, "implementation": implementations})
    )
    protocol = {
        "version": VERSION,
        "experiment_id": output.name,
        "scope_id": scope_id,
        "scope": "seen_paid_candidate_verifier_only_development",
        "new_holdout": False,
        "official_accuracy": None,
        "semantic_support_verified": False,
        "quality_gain_proven": False,
        "budget": copy.deepcopy(BUDGET),
        "case": inputs["case"],
        "original": {
            "path": str(source),
            "freeze_sha256": old["freeze_sha256"],
            "protected_sha256": protections,
            "original_failure_retained": True,
            "original_requests_reissued": False,
        },
        "matching": {
            "model_profile": old["matching"]["model_profile"],
            "temperature": 0,
            "model_pricing_sha256": source_hashes["model-pricing.json"],
            "encoder_manifest_sha256": source_hashes["encoder-manifest.json"],
        },
        "source_copy_sha256": source_hashes,
        "inputs_sha256": sha(output / "review-inputs.json"),
        "implementation_sha256": implementations,
        "literal_source_checks": source_checks,
        "full_agent_success": False,
        "automatic_retry": False,
        "model_input_gold": False,
    }
    packet = review_packet(protocol, inputs)
    save(output / "verifier-packet.json", packet, new=True)
    protocol["packet_sha256"] = sha(output / "verifier-packet.json")
    protocol["freeze_sha256"] = digest(protocol)
    save(output / "protocol.json", protocol, new=True)
    if any(sha(_relative(source, name)) != expected for name, expected in protections.items()):
        raise ValueError("original_artifact_changed_during_freeze")
    return protocol


def _protected(output, protocol):
    original = Path(protocol["original"]["path"])
    for name, expected in protocol["original"]["protected_sha256"].items():
        if sha(_relative(original, name)) != expected:
            raise ValueError("original_artifact_changed")
    for name, expected in protocol["source_copy_sha256"].items():
        if sha(_relative(output / "source", name)) != expected:
            raise ValueError("frozen_source_copy_changed")


def load_protocol(output):
    output = Path(output).resolve()
    protocol = json.loads((output / "protocol.json").read_text())
    frozen = dict(protocol)
    expected = frozen.pop("freeze_sha256")
    if (
        protocol.get("version") != VERSION
        or digest(frozen) != expected
        or protocol["budget"] != BUDGET
    ):
        raise ValueError("review_protocol_changed")
    _protected(output, protocol)
    if (
        sha(output / "review-inputs.json") != protocol["inputs_sha256"]
        or sha(output / "verifier-packet.json") != protocol["packet_sha256"]
    ):
        raise ValueError("review_input_or_packet_changed")
    project = Path(__file__).resolve().parents[1]
    if {str(path.relative_to(project)) for path in archive_paths(project)} != set(
        protocol["implementation_sha256"]
    ):
        raise ValueError("review_implementation_footprint_changed")
    for name, expected_sha in protocol["implementation_sha256"].items():
        if sha(project / name) != expected_sha or sha(output / "code" / name) != expected_sha:
            raise ValueError("review_implementation_changed")
    inputs = json.loads((output / "review-inputs.json").read_text())
    _public_only(inputs)
    if review_packet(protocol, inputs) != json.loads((output / "verifier-packet.json").read_text()):
        raise ValueError("review_packet_binding_changed")
    _verify_frozen_citations(output, inputs)
    return protocol


def experiment_settings(output, protocol, *, settings=None):
    settings = settings or Settings()
    settings = Settings.model_validate(
        settings.model_dump()
        | {
            "agent_checkpoint_path": Path(output) / "anchor-role-receipts.sqlite",
            "model_pricing_path": Path(output) / "source" / "model-pricing.json",
            "agent_max_model_calls": 1,
            "deepseek_max_tokens": 2400,
            "agent_deadline_seconds": 60,
            "deepseek_timeout_seconds": 60,
            "agent_max_output_chars": 18000,
            "llm_temperature": 0,
        }
    )
    if model_profile(settings).public() != protocol["matching"]["model_profile"]:
        raise ValueError("original_model_profile_changed")
    return settings


def request_identity(protocol):
    return f"anchor-review:{protocol['experiment_id']}:{protocol['freeze_sha256']}:{ROLE_CALL_ID}"


def _review_once(output, protocol, settings, *, transport=None):
    from zhidu.agent_requirements import coverage_ledger, reviewed_candidate
    from zhidu.agent_roles import RoleRunner
    from zhidu.agent_team import VERIFY_RULES
    from zhidu.langchain_tools import SourceRuntime, ToolSession
    from zhidu.rag import RagRequest

    Decision, _, expand = _anchor_api()
    inputs = json.loads((output / "review-inputs.json").read_text())
    plan, candidate = (
        TaskPlan.model_validate(inputs["plan"]),
        AgentAnswer.model_validate(inputs["candidate"]),
    )
    payload = {
        "instructions": VERIFY_RULES,
        **json.loads((output / "verifier-packet.json").read_text()),
    }
    result = {
        "generation": {"status": "failed"},
        "new_business_tool_calls": 0,
        "original_candidate_sha256": digest(inputs["candidate"]),
        "original_failure_retained": True,
        "full_agent_success": False,
        "semantic_support_verified": False,
        "official_accuracy": None,
    }
    calls, external, current, active = [], None, None, None
    with tempfile.TemporaryDirectory(prefix="anchor-review-corpus-") as temporary:
        path = Path(temporary) / "corpus.sqlite"
        _sqlite_copy(output / "source" / "corpus.sqlite", path)
        engine = create_engine(
            "sqlite://", creator=lambda: sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        )
        try:
            with Session(engine, autoflush=False) as session:
                body = RagRequest(
                    question=inputs["case"]["question"],
                    query=inputs["case"]["query"],
                    mode="hybrid",
                    generation="agent",
                    agent_backend="team",
                )
                runtime = SourceRuntime(
                    session, BlobStore(output / "source" / "raw"), settings, None
                )
                tools = ToolSession(runtime, body, None)
                tools.restore(copy.deepcopy(inputs["snapshot"]))
                prior_calls = tools.attempted_calls
                try:
                    with RoleRunner(
                        settings,
                        runtime,
                        tools,
                        transport=transport,
                        checkpoint_key=request_identity(protocol),
                        manifest={
                            "version": VERSION,
                            "protocol": protocol["freeze_sha256"],
                            "scope": protocol["scope_id"],
                            "packet_sha256": protocol["packet_sha256"],
                        },
                    ) as active:
                        decision = active.invoke(
                            "verifier", payload, Decision, call_id=ROLE_CALL_ID
                        )
                        verification = expand(
                            inputs["case"]["question"],
                            plan,
                            candidate,
                            decision,
                            tools.evidence,
                            scope=protocol["scope_id"],
                        )
                        approved = reviewed_candidate(
                            plan,
                            candidate,
                            verification,
                            question=inputs["case"]["question"],
                            evidence=tools.evidence,
                        )
                        ledger = coverage_ledger(
                            plan,
                            candidate,
                            verification,
                            question=inputs["case"]["question"],
                            evidence=tools.evidence,
                        )
                        rendered = render_answer(approved, tools.evidence)
                        checks = verify_citations(session, runtime.store, rendered["citations"])
                        if checks["verified"] != checks["total"]:
                            raise ValueError("review_final_source_invalid")
                        result.update(
                            rendered,
                            decision=decision.model_dump(),
                            verification=verification.model_dump(),
                            requirement_ledger=ledger,
                            literal_source_check=checks,
                            literal_quote_check=quote_check(rendered),
                            structural_acceptance=True,
                            generation={"status": "completed", "semantic_support_verified": False},
                        )
                except Exception as error:
                    result["generation"] = {
                        "status": "failed",
                        "reason": str(error)[:100]
                        if isinstance(error, ValueError)
                        else type(error).__name__,
                        "error_type": type(error).__name__,
                    }
                    result["structural_acceptance"] = False
                finally:
                    if active is not None:
                        calls, external = active.calls(), active.external_requests
                        current = active.current_attempt_external_requests
                    if tools.attempted_calls != prior_calls:
                        raise ValueError("review_attempted_business_tool")
        finally:
            engine.dispose()
    profile = protocol["matching"]["model_profile"]
    result["role_calls"] = calls
    result["cost"] = {
        "external_requests": external,
        "current_attempt_external_requests": current,
        "model_calls_attempted": len(calls),
        "billed_tokens": sum(call["usage"]["total_tokens"] for call in calls)
        if calls and all(type(call.get("usage", {}).get("total_tokens")) is int for call in calls)
        else None,
        "pricing": cost_for_calls(
            calls
            or (
                [{"usage": None, "billing_id": request_identity(protocol)}]
                if external is None
                else []
            ),
            profile["provider"],
            profile["model"],
            settings.model_pricing_path,
        ),
    }
    return result


def generate(output, protocol, settings, *, transport=None, run_review=None):
    """A persistent one-request reservation. Any saved outcome blocks resend."""
    output = Path(output).resolve()
    if load_protocol(output) != protocol:
        raise ValueError("review_protocol_argument_changed")
    if run_review is None or settings is not None:
        settings = experiment_settings(output, protocol, settings=settings)
    path = output / "review-attempt.json"
    identity = request_identity(protocol)
    with (output / "generation.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("review_runner_already_active") from None
        try:
            if path.exists():
                row = load_attempt(path)
                if row.get("request_id") != identity:
                    raise ValueError("review_request_identity_changed")
            else:
                call = run_review or (
                    lambda: _review_once(output, protocol, settings, transport=transport)
                )
                row = execute_once(
                    path,
                    {
                        "request_id": identity,
                        "request_ceiling": 1,
                        "protocol_sha256": protocol["freeze_sha256"],
                        "mode": "verifier_only",
                    },
                    call,
                )
            result = row.get("result", {})
            requests = result.get("cost", {}).get("external_requests")
            failed = (
                row["status"] != "completed"
                or result.get("generation", {}).get("status") != "completed"
            )
            invalid = (
                type(requests) is not int
                or not 0 <= requests <= 1
                or result.get("new_business_tool_calls") != 0
            )
            if (failed or invalid) and not (output / "stopped.json").exists():
                save(
                    output / "stopped.json",
                    {
                        "reason": "unknown_or_invalid_review_retained",
                        "request_id": identity,
                        "automatic_retry": False,
                    },
                    new=True,
                )
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
    _protected(output, protocol)
    return row


def summary(output, protocol):
    output = Path(output).resolve()
    _protected(output, protocol)
    path = output / "review-attempt.json"
    attempt = load_attempt(path) if path.exists() else None
    result = attempt.get("result", {}) if attempt else {}
    actual = result.get("cost", {}).get("external_requests")
    requests = (
        0
        if attempt is None
        else actual
        if type(actual) is int and actual >= 0 and attempt["status"] == "completed"
        else 1
    )
    value = {
        "version": VERSION + "-summary",
        "scope": "seen_paid_candidate_verifier_only_development",
        "protocol_sha256": protocol["freeze_sha256"],
        "request_id": request_identity(protocol),
        "budget": BUDGET,
        "attempt_status": attempt["status"] if attempt else "not_attempted",
        "generation": result.get("generation"),
        "requests_reserved_or_receipted": requests,
        "new_business_tool_calls": result.get("new_business_tool_calls"),
        "request_budget_observed": requests <= 1,
        "role_calls": result.get("role_calls", []),
        "cost": result.get("cost"),
        "answer_class": result.get("answer_class"),
        "structural_acceptance": result.get("structural_acceptance"),
        "requirement_ledger": result.get("requirement_ledger"),
        "original_candidate_sha256": result.get("original_candidate_sha256"),
        "original_failure_retained": True,
        "full_agent_success": False,
        "semantic_support_verified": False,
        "official_accuracy": None,
        "quality_gain_proven": False,
        "new_holdout": False,
        "old_scores_combined": False,
    }
    save(output / "summary.json", value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--action", choices=("freeze", "validate", "generate", "summary"), default="validate"
    )
    parser.add_argument("--source", type=Path)
    args = parser.parse_args()
    if args.action == "freeze":
        if args.source is None:
            parser.error("--source required before freeze")
        value = freeze(args.source, args.output)
        print(json.dumps({"frozen": True, "scope": value["scope"], "new_model_calls_limit": 1}))
        return
    if args.source is not None:
        parser.error("--source is only accepted before freeze")
    protocol = load_protocol(args.output)
    if args.action == "generate":
        value = generate(args.output, protocol, experiment_settings(args.output, protocol))
    elif args.action == "summary":
        value = summary(args.output, protocol)
    else:
        value = {"validated": True, "new_model_calls": 0, "full_agent_success": False}
    print(json.dumps(value, ensure_ascii=False))


if __name__ == "__main__":
    main()
