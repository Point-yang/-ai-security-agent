"""Seen-corpus team development regression, never a new holdout.

The original Stage 6 data, gold, cases, initial scopes and attempts stay
immutable. Only a new Stage 7 team request identity can spend model calls.
Freeze and summary are offline; generation is an explicit separate action.
No scoring API is included. Local renderer/provenance checks are not semantics.
"""

import argparse
import copy
import importlib.util
import json
import re
import shutil
from datetime import UTC, datetime
from functools import partial
from pathlib import Path

from zhidu.agent_result import verify_citations
from zhidu.agent_state import AgentAnswer
from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.grounded_answer import evidence_id, render_answer
from zhidu.model_costs import cost_for_calls
from zhidu.model_provider import model_profile
from zhidu.paired_evaluation import digest
from zhidu.rag import RagRequest
from zhidu.semantic import LocalEncoder, model_manifest
from zhidu.storage import BlobStore

_spec = importlib.util.spec_from_file_location(
    "stage7_shared_stage6", Path(__file__).with_name("run_agent_stage6_evaluation.py")
)
_shared = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_shared)
save, sha, load_attempt, execute_once = (
    _shared.save,
    _shared.sha,
    _shared.load_attempt,
    _shared.execute_once,
)
MODE = "team_hybrid"
VERSION = "agent-stage7-development-v1"
BUDGET = {
    "model_calls_per_answer": 8,
    "max_generation_requests": 48,
    "max_judge_requests": 0,
    "max_total_requests": 48,
    "tool_calls_per_answer": 6,
    "completion_tokens_per_call": 2400,
    "soft_deadline_seconds": 60,
    "final_reserve_seconds": 12,
    "tool_output_chars": 18000,
}


def renderer_acceptance():
    """Synthetic syntax probes; no real source assertion or semantic scoring."""
    text = "The adapter accesses B_shape[1], A_shape[0], and A_shape[1] without checking rank."
    citation = {
        "chunk_id": "stage7-renderer-synthetic",
        "source_id": "synthetic-local-probe",
        "text": text,
    }
    handle = evidence_id(citation)
    value = {
        "answer_class": "evidence",
        "statements": [
            {
                "text": "源码访问 B_shape[1]、A_shape[0] 和 A_shape[1]。",
                "evidence": [{"evidence_id": handle}],
            }
        ],
        "required_facts": ["technical index syntax"],
        "missing_facts": [],
        "limitations": [],
        "message": "",
    }
    acceptance = {
        "network_or_model_calls": 0,
        "semantic_support_verified": False,
        "scope": "synthetic_renderer_contract_only",
        "technical_indices_accepted": False,
        "authored_citation_rejected": False,
    }
    try:
        rendered = render_answer(AgentAnswer.model_validate(value), {handle: citation})
        acceptance["technical_indices_accepted"] = bool(
            rendered["generated_claims"][0]["text"] == value["statements"][0]["text"]
            and rendered["generated_claims"][0]["evidence"][0]["quote"] == text
        )
    except ValueError as error:
        acceptance["technical_index_error"] = type(error).__name__
    forged = copy.deepcopy(value)
    forged["statements"][0]["text"] = "来源结论 [1]"
    try:
        render_answer(AgentAnswer.model_validate(forged), {handle: citation})
    except ValueError:
        acceptance["authored_citation_rejected"] = True
    return acceptance


def validate_initial_packet(packet, case):
    frozen = dict(packet)
    expected = frozen.pop("packet_sha256")
    if digest(frozen) != expected:
        raise ValueError("initial_packet_changed")
    body = RagRequest(
        question=case["question"], query=case["query"], mode="hybrid", generation="agent"
    )
    if packet["retrieve_arguments"] != {
        "query": body.query,
        "mode": "hybrid",
        "limit": 5,
    } or packet["scope"] != {"pool": body.pool, "origin": body.origin, "event_id": body.event_id}:
        raise ValueError("initial_query_or_scope_changed")
    if packet["snapshot"].get("attempted_calls") != 1:
        raise ValueError("initial_packet_has_additional_tools")
    return body


def _legacy_protocol(source):
    source = Path(source)
    protocol = json.loads((source / "protocol.json").read_text())
    frozen = dict(protocol)
    expected = frozen.pop("freeze_sha256")
    if protocol.get("version") != "agent-stage6-holdout-v1" or digest(frozen) != expected:
        raise ValueError("original_stage6_protocol_changed")
    if len(protocol["cases"]) != 6 or sum(len(c["facts"]) for c in protocol["cases"]) != 46:
        raise ValueError("original_six_group_46_fact_cohort_required")
    if sha(source / "corpus.sqlite") != protocol["corpus_sha256"]:
        raise ValueError("original_corpus_changed")
    for filename, expected_sha in protocol["implementation_sha256"].items():
        # Live code is intentionally newer. Verify the old immutable archive.
        if sha(source / "code" / filename) != expected_sha:
            raise ValueError("original_code_archive_changed")
    matching = protocol["matching"]
    if sha(source / "encoder-manifest.json") != matching["encoder_manifest_sha256"]:
        raise ValueError("original_encoder_changed")
    if (
        matching.get("model_pricing_sha256")
        and sha(source / "model-pricing.json") != matching["model_pricing_sha256"]
    ):
        raise ValueError("original_price_catalog_changed")
    store = BlobStore(source / "raw")
    for raw_sha in protocol["raw_sha256"]:
        store.read(raw_sha)
    for case in protocol["cases"]:
        packet = json.loads((source / "initial-packets" / f"{case['id']}.json").read_text())
        validate_initial_packet(packet, case)
        original = load_attempt(source / "answers" / f"{case['id']}-{MODE}.json")
        if original["status"] != "completed":
            raise ValueError("original_team_attempt_not_completed")
        if original.get("initial_packet_sha256") != packet["packet_sha256"]:
            raise ValueError("original_team_initial_binding_changed")
    return protocol


def experiment_budget(cases):
    ceiling = min(BUDGET["max_generation_requests"], len(cases) * BUDGET["model_calls_per_answer"])
    return {**BUDGET, "max_generation_requests": ceiling, "max_total_requests": ceiling}


def freeze(stage6, output, *, case_ids=None):
    """Byte-copy an immutable seen data set; never infer or rewrite gold/answers."""
    stage6, output = Path(stage6).resolve(), Path(output).resolve()
    if output.exists():
        raise ValueError("new_stage7_directory_required")
    old = _legacy_protocol(stage6)
    cases = old["cases"]
    if case_ids is not None:
        requested = set(case_ids)
        if (
            not requested
            or len(requested) != len(case_ids)
            or not requested <= {case["id"] for case in cases}
        ):
            raise ValueError("invalid_development_case_selection")
        cases = [case for case in cases if case["id"] in requested]
    acceptance = renderer_acceptance()
    if not acceptance["technical_indices_accepted"] or not acceptance["authored_citation_rejected"]:
        raise ValueError("renderer_contract_acceptance_failed")
    output.mkdir(parents=True)
    for name in ("corpus.sqlite", "gold-specs.json", "encoder-manifest.json", "model-pricing.json"):
        shutil.copyfile(stage6 / name, output / name)
    for name in ("raw", "initial-packets"):
        shutil.copytree(stage6 / name, output / name)
    legacy = output / "legacy"
    legacy.mkdir()
    shutil.copytree(stage6 / "answers", legacy / "answers")
    for name in (
        "protocol.json",
        "report.json",
        "reconciled-reviews.json",
        "execution-manifest.json",
        "blind-review.json",
    ):
        if (stage6 / name).is_file():
            shutil.copyfile(stage6 / name, legacy / name)
    legacy_hashes = {
        str(path.relative_to(legacy)): sha(path)
        for path in sorted(legacy.rglob("*"))
        if path.is_file()
    }
    data_hashes = {
        name: sha(output / name)
        for name in (
            "corpus.sqlite",
            "gold-specs.json",
            "encoder-manifest.json",
            "model-pricing.json",
        )
    }
    initial_hashes = {
        str(path.relative_to(output)): sha(path)
        for path in sorted((output / "initial-packets").glob("*.json"))
    }
    source_files = [
        *sorted(Path("src/zhidu").glob("*.py")),
        *sorted(Path("src/zhidu/static").glob("*.js")),
        *sorted(Path("src/zhidu/static").glob("*.html")),
        *sorted(Path("tests").glob("*.py")),
        *sorted(Path("tests").glob("*.mjs")),
        Path("scripts/run_agent_stage6_evaluation.py"),
        Path(__file__).relative_to(Path.cwd()),
        Path("pyproject.toml"),
        Path("requirements.lock"),
        Path("requirements-agent.lock"),
        Path("requirements-semantic.lock"),
    ]
    archive_hashes = {}
    for path in source_files:
        archived = output / "code" / path
        archived.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, archived)
        archive_hashes[str(path)] = sha(path)
    protocol = {
        "version": VERSION,
        "created_at": datetime.now(UTC).isoformat(),
        "experiment_id": output.name,
        "scope": "seen_corpus_development_regression",
        "new_holdout": False,
        "quality_gain_proven": False,
        "modes": [MODE],
        "cases": copy.deepcopy(cases),
        "budget": experiment_budget(cases),
        "selection": {
            "case_ids": [case["id"] for case in cases],
            "policy": "frozen_before_new_model_requests; development_only; no combined score with earlier attempts",
        },
        "original_stage6": {
            "path": str(stage6),
            "protocol_sha256": sha(stage6 / "protocol.json"),
            "freeze_sha256": old["freeze_sha256"],
            "cases_sha256": digest(old["cases"]),
            "previous_outputs_seen": True,
            "unknown_previous_attempts_retained": True,
            "previous_requests_reissued": False,
        },
        "matching": {
            "model_profile": old["matching"]["model_profile"],
            "temperature": 0,
            "encoder_digest": old["matching"]["encoder_digest"],
            "initial_packet_policy": "byte-identical original Stage 6 packets/evidence/snapshots; no new initial retrieval",
            "source_and_gold_unchanged": True,
        },
        "corpus_sha256": old["corpus_sha256"],
        "raw_sha256": old["raw_sha256"],
        "data_artifact_sha256": data_hashes,
        "initial_artifact_sha256": initial_hashes,
        "legacy_artifact_sha256": legacy_hashes,
        "implementation_sha256": archive_hashes,
        "renderer_acceptance": acceptance,
        "stop_policy": "retain and stop on unknown outcome or any generation/format/budget failure; existing attempts never reissued",
        "statistics": {
            "official_or_holdout_accuracy": False,
            "semantic_scoring_api_calls": 0,
            "acceptance": "runtime/renderer/provenance only; any later Codex quote-only review is AI development acceptance",
        },
    }
    protocol["freeze_sha256"] = digest(protocol)
    save(output / "protocol.json", protocol, new=True)
    return protocol


def load_protocol(output):
    output = Path(output)
    protocol = json.loads((output / "protocol.json").read_text())
    frozen = dict(protocol)
    expected = frozen.pop("freeze_sha256")
    if protocol.get("version") != VERSION or digest(frozen) != expected:
        raise ValueError("stage7_protocol_changed")
    if (
        protocol["modes"] != [MODE]
        or protocol["budget"] != experiment_budget(protocol["cases"])
        or protocol["new_holdout"] is not False
    ):
        raise ValueError("stage7_development_policy_changed")
    for name, expected_sha in (
        protocol["data_artifact_sha256"] | protocol["initial_artifact_sha256"]
    ).items():
        if sha(output / name) != expected_sha:
            raise ValueError("stage7_frozen_data_changed")
    for name, expected_sha in protocol["legacy_artifact_sha256"].items():
        if (
            sha(output / "legacy" / name) != expected_sha
            or sha(Path(protocol["original_stage6"]["path"]) / name) != expected_sha
        ):
            raise ValueError("legacy_statistics_or_attempt_changed")
    for name, expected_sha in protocol["implementation_sha256"].items():
        if sha(name) != expected_sha or sha(output / "code" / name) != expected_sha:
            raise ValueError("stage7_implementation_changed")
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
        "agent_checkpoint_path": Path(output) / "stage7-role-receipts.sqlite",
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


def request_identity(protocol, case):
    return f"stage7:{protocol['experiment_id']}:{protocol['freeze_sha256']}:{case['id']}:{MODE}"


def generation_requests(output):
    total = 0
    for path in (Path(output) / "answers").glob("*.json"):
        row = load_attempt(path)
        if row.get("mode") != MODE:
            raise ValueError("stage7_team_only")
        calls = row.get("result", {}).get("cost", {}).get("external_requests")
        if row["status"] != "completed" or calls is None:
            calls = 8
        if type(calls) is not int or not 0 <= calls <= 8:
            raise ValueError("invalid_team_request_receipt")
        total += calls
    return total


def stop_reason(row):
    if row["status"] != "completed":
        return "unknown_provider_outcome"
    generation = row.get("result", {}).get("generation", {})
    if generation.get("status") != "completed":
        return generation.get("reason", "generation_not_completed")
    calls = row.get("result", {}).get("cost", {}).get("external_requests")
    if calls is None:
        return "unknown_request_receipt"
    if type(calls) is not int or not 0 <= calls <= 8:
        return "invalid_model_budget_receipt"
    return None


def run_schedule(output, protocol, run_case):
    """Conservative sequential schedule; a failed first case cannot launch case 2."""
    output = Path(output)
    (output / "answers").mkdir(exist_ok=True)
    stop_path = output / "stopped.json"
    if stop_path.exists():
        return json.loads(stop_path.read_text())
    for case in protocol["cases"]:
        path = output / "answers" / f"{case['id']}-{MODE}.json"
        if path.exists():
            row = load_attempt(path)
        else:
            if generation_requests(output) + 8 > protocol["budget"]["max_generation_requests"]:
                value = {
                    "case_id": case["id"],
                    "reason": "global_request_budget_exhausted",
                    "request_id": request_identity(protocol, case),
                }
                save(stop_path, value, new=True)
                return value
            metadata = {
                "case_id": case["id"],
                "mode": MODE,
                "request_id": request_identity(protocol, case),
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
                "request_id": row.get("request_id"),
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
        body = validate_initial_packet(packet, case)
        with sessions() as session:
            # Reuse verified source handles and byte-exact budget scope. Never
            # invoke an initial retrieval under the updated ranking/field code.
            tools = _shared.restore_initial_packet(packet, session, store, settings, body, encoder)
            check = verify_citations(session, store, list(tools.evidence.values()))
            if check["verified"] != check["total"]:
                raise ValueError("original_initial_source_binding_invalid")
            if (
                tools.evidence != packet["snapshot"]["evidence"]
                or tools.runtime.output_chars != packet["snapshot"]["output_chars"]
            ):
                raise ValueError("original_initial_budget_scope_changed")
            result = _shared.run_mode(
                MODE,
                packet,
                session,
                store,
                settings,
                body,
                encoder,
                checkpoint_key=request_identity(protocol, case),
            )
            result["stage7_acceptance"] = {
                "original_initial_packet_sha256": packet["packet_sha256"],
                "original_source_binding": check,
                "development_regression": True,
                "semantic_support_verified": False,
                "renderer": renderer_acceptance(),
            }
            return result

    try:
        result = run_schedule(output, protocol, run_case)
    finally:
        encoder.close()
        engine.dispose()
    if sha(output / "corpus.sqlite") != protocol["corpus_sha256"]:
        raise ValueError("development_run_mutated_original_corpus")
    return result


def summary(output, protocol):
    output = Path(output)
    for name, expected_sha in protocol["legacy_artifact_sha256"].items():
        if sha(output / "legacy" / name) != expected_sha:
            raise ValueError("legacy_statistics_or_attempt_changed")
    rows, receipts = [], []
    for case in protocol["cases"]:
        path = output / "answers" / f"{case['id']}-{MODE}.json"
        if not path.exists():
            rows.append({"case_id": case["id"], "status": "not_attempted", "requests": 0})
            continue
        attempt = load_attempt(path)
        result = attempt.get("result", {})
        calls = result.get("agent", {}).get("role_calls", [])
        actual_tools = result.get("actual_additional_tools", result.get("tools", []))
        count = result.get("cost", {}).get("external_requests")
        count = 8 if attempt["status"] != "completed" or count is None else count
        receipts.extend(
            {
                **call,
                "billing_id": call.get("provider_response_id")
                or f"{case['id']}:{call.get('call_id', index)}",
            }
            for index, call in enumerate(calls)
        )
        if not calls and count:
            receipts.append({"billing_id": case["id"] + ":unknown", "usage": None})
        rows.append(
            {
                "case_id": case["id"],
                "status": attempt["status"],
                "request_id": attempt.get("request_id"),
                "generation": result.get("generation"),
                "requests": count,
                "billed_tokens": result.get("cost", {}).get("billed_tokens"),
                "elapsed_ms": attempt.get("elapsed_ms"),
                "actual_role_calls": calls,
                "actual_additional_tools": actual_tools,
                "actual_tool_results": result.get("agent", {}).get("tool_results", []),
                "actual_tool_attempts": result.get("actual_additional_tool_attempts"),
                "field_coverage": result.get("observed_evidence_gaps"),
                "returned_source_fields": sorted(
                    {c.get("field", "unknown") for c in result.get("citations", [])}
                ),
                "team_quote_review": result.get("agent", {}).get("verification"),
                "actual_technical_index_statements": [
                    {
                        "statement_index": index,
                        "text": claim["text"],
                        "evidence": claim.get("evidence", []),
                    }
                    for index, claim in enumerate(result.get("generated_claims", []), 1)
                    if re.search(r"\b[A-Za-z_]\w*\[\d+\]", claim["text"])
                ],
                "acceptance": result.get("stage7_acceptance"),
                "monetary": result.get("cost", {}).get("pricing"),
                "semantic_or_official_score": None,
            }
        )
    profile = protocol["matching"]["model_profile"]
    value = {
        "version": "stage7-development-summary-v1",
        "scope": "seen_corpus_development_regression",
        "experiment_id": protocol["experiment_id"],
        "new_holdout": False,
        "quality_gain_proven": False,
        "official_accuracy": None,
        "semantic_scoring_api_calls": 0,
        "cases": rows,
        "requests_reserved_or_receipted": generation_requests(output),
        "pricing": cost_for_calls(
            receipts, profile["provider"], profile["model"], output / "model-pricing.json"
        ),
        "renderer_acceptance": renderer_acceptance(),
        "old_statistics_immutable": True,
        "legacy_artifact_sha256": protocol["legacy_artifact_sha256"],
        "protocol_sha256": protocol["freeze_sha256"],
    }
    save(output / "summary.json", value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--action", choices=("freeze", "validate", "generate", "summary"), default="validate"
    )
    parser.add_argument("--stage6", type=Path)
    parser.add_argument(
        "--case-id",
        action="append",
        help="Freeze only these known development cases; repeat for several cases.",
    )
    args = parser.parse_args()
    if args.action == "freeze":
        if args.stage6 is None:
            parser.error("--stage6 is required for freeze")
        protocol = freeze(args.stage6, args.output, case_ids=args.case_id)
        print(
            json.dumps({"frozen": True, "development_only": True, "cases": len(protocol["cases"])})
        )
        return
    if args.case_id is not None:
        parser.error("--case-id is allowed only during freeze, not after results")
    protocol = load_protocol(args.output)
    if args.action == "generate":
        value = generate(args.output, protocol, experiment_settings(args.output, protocol))
    elif args.action == "summary":
        value = summary(args.output, protocol)
    else:
        value = {"validated": True, "development_only": True, "cases": len(protocol["cases"])}
    print(json.dumps(value, ensure_ascii=False))


if __name__ == "__main__":
    main()
