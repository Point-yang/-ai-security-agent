"""Freeze a preselected intake and externally authored atomic source gold.

No predictions are permitted before this operation. Only selected source pairs
enter the isolated corpus. Semantic embeddings use a verified local FastEmbed
manifest; this script never prepares/downloads an encoder or runs a generator.
"""

import argparse
import hashlib
import json
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.indexing import sync_index
from zhidu.ingest import ingest_document
from zhidu.model_provider import model_profile
from zhidu.models import Base, EventAlias, EventTriage, IntelEvent
from zhidu.paired_evaluation import DIMENSIONS, digest
from zhidu.semantic import LocalEncoder, active_chunks, model_manifest, sync_embeddings
from zhidu.source_spans import canonical_field, source_span
from zhidu.sources import SOURCES, prepare, resolve_pointer
from zhidu.storage import BlobStore

PACKAGES = (
    "gradio",
    "langchain",
    "langchain-core",
    "llama-index",
    "vllm",
    "onnx",
    "onnxruntime",
    "keras",
)
MODES = ("rag_hybrid", "workflow_hybrid", "team_hybrid")
FORBIDDEN_PREDICTION_KEYS = {
    "answer",
    "answers",
    "prediction",
    "predictions",
    "generated_claims",
    "verdict",
    "judgments",
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n")


def reject_predictions(value):
    if isinstance(value, dict):
        if FORBIDDEN_PREDICTION_KEYS & value.keys():
            raise ValueError("predictions_forbidden_before_freeze")
        for child in value.values():
            reject_predictions(child)
    elif isinstance(value, list):
        for child in value:
            reject_predictions(child)


def validate_source_evidence(raw, evidence, *, source_id, external_id, sha256, record_pointer):
    pointer, quote = evidence.get("json_pointer"), evidence.get("quote")
    if evidence.get("source_id") != source_id:
        raise ValueError("gold_source_mismatch")
    if not isinstance(pointer, str) or not (
        pointer == record_pointer or pointer.startswith(record_pointer + "/")
    ):
        raise ValueError("gold_pointer_outside_selected_record")
    if not isinstance(quote, str) or len(quote.strip()) < 8:
        raise ValueError("gold_quote_not_verbatim")
    text = canonical_field(resolve_pointer(raw, pointer))
    if quote not in text:
        raise ValueError("gold_quote_not_verbatim")
    if "start" in evidence:
        start = evidence["start"]
        if type(start) is not int or text[start : start + len(quote)] != quote:
            raise ValueError("gold_quote_offset_mismatch")
    else:
        start = text.find(quote)
        if text.find(quote, start + 1) != -1:
            raise ValueError("gold_quote_not_unique_supply_start")
    return {
        "source_id": source_id,
        "external_id": external_id,
        "json_pointer": pointer,
        "sha256": sha256,
        "quote": quote,
        "quote_start": start,
        "quote_end": start + len(quote),
        "scope": {
            "kind": "complete_source_field",
            "text": text,
            "complete": True,
            "chars": len(text),
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
            "record_pointer": record_pointer,
        },
    }


def validate_inputs(intake, gold_specs):
    manifest = json.loads((intake / "manifest.json").read_text())
    exclusions = json.loads((intake / "exclusions.json").read_text())
    specs = json.loads(Path(gold_specs).read_text())
    reject_predictions(specs)
    if manifest.get("schema_version") != "agent-stage6-source-intake-v1":
        raise ValueError("wrong_intake_version")
    if manifest["packages_preselected"] != list(PACKAGES) or [
        g["package"] for g in manifest["groups"]
    ] != list(PACKAGES):
        raise ValueError("preselected_packages_changed")
    if sha(intake / "exclusions.json") != manifest["exclusions_sha256"]:
        raise ValueError("exclusion_manifest_changed")
    if manifest.get("agent_run") or manifest.get("model_calls", 0):
        raise ValueError("predictions_forbidden_before_freeze")
    for name in ("answers", "judgments", "blind-review-packets"):
        if (intake / name).exists() and any((intake / name).rglob("*")):
            raise ValueError("predictions_forbidden_before_freeze")
    groups = [g for g in manifest["groups"] if g.get("two_public_sources_available")]
    by_package = {c["package"]: c for c in specs["cases"]}
    if len(by_package) != len(specs["cases"]) or set(by_package) != {g["package"] for g in groups}:
        raise ValueError("gold_must_cover_all_and_only_complete_selected_pairs")
    excluded = {v.casefold() for v in exclusions["identifiers"]}
    validated = {}
    for group in groups:
        if {group["cve_id"].casefold(), group["ghsa_id"].casefold()} & excluded:
            raise ValueError("selected_identifier_in_history")
        sources = {}
        for source_id, prefix, identifier in (
            ("github-advisories", "github", group["ghsa_id"]),
            ("nvd", "nvd", group["cve_id"]),
        ):
            path = (intake / group[f"{prefix}_raw_path"]).resolve()
            if intake.resolve() not in path.parents or sha(path) != group[f"{prefix}_sha256"]:
                raise ValueError("intake_source_bytes_changed")
            raw = json.loads(path.read_text())
            pointer = group[f"{prefix}_response_pointer"]
            record = resolve_pointer(raw, pointer)
            actual_id = record.get("ghsa_id") if prefix == "github" else record.get("id")
            if actual_id != identifier:
                raise ValueError("selected_source_identifier_changed")
            sources[source_id] = {
                "raw": raw,
                "path": path,
                "pointer": pointer,
                "external_id": identifier,
                "sha256": group[f"{prefix}_sha256"],
            }
        spec = by_package[group["package"]]
        if (
            not isinstance(spec.get("question"), str)
            or not spec["question"].strip()
            or not spec.get("facts")
        ):
            raise ValueError("atomic_gold_question_and_facts_required")
        ids = [f["id"] for f in spec["facts"]]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate_atomic_fact_id")
        facts = []
        for fact in spec["facts"]:
            if (
                fact["dimension"] not in DIMENSIONS
                or not isinstance(fact.get("expected"), str)
                or not fact["expected"].strip()
                or not fact.get("evidence")
            ):
                raise ValueError("invalid_atomic_gold_fact")
            evidence = []
            for item in fact["evidence"]:
                source = sources[item["source_id"]]
                evidence.append(
                    validate_source_evidence(
                        source["raw"],
                        item,
                        source_id=item["source_id"],
                        external_id=source["external_id"],
                        sha256=source["sha256"],
                        record_pointer=source["pointer"],
                    )
                )
            facts.append(
                {k: fact[k] for k in ("id", "dimension", "expected")} | {"evidence": evidence}
            )
        validated[group["package"]] = {"spec": spec, "sources": sources, "facts": facts}
    return manifest, exclusions, validated


def check_current_main(database, groups):
    if database is None:
        return
    with sqlite3.connect(f"file:{Path(database).resolve()}?mode=ro", uri=True) as connection:
        identifiers = {
            r[0].casefold()
            for r in connection.execute(
                "select value from event_aliases union select external_id from events"
            )
        }
    if any({g["cve_id"].casefold(), g["ghsa_id"].casefold()} & identifiers for g in groups):
        raise ValueError("identifier_no_longer_new_in_main")


def freeze(intake, gold_specs, output, *, settings=None, encoder=None, main_database=None):
    intake, output = Path(intake).resolve(), Path(output).resolve()
    if output.exists():
        raise ValueError("new_stage6_directory_required")
    manifest, exclusions, validated = validate_inputs(intake, gold_specs)
    groups = [g for g in manifest["groups"] if g.get("two_public_sources_available")]
    check_current_main(main_database or exclusions.get("database_path"), groups)
    settings = settings or Settings()
    encoder_binding = model_manifest(settings, verify=True)
    output.mkdir(parents=True)
    save(output / "encoder-manifest.json", encoder_binding)
    price_sha = None
    if settings.model_pricing_path.is_file():
        shutil.copyfile(settings.model_pricing_path, output / "model-pricing.json")
        price_sha = sha(output / "model-pricing.json")
    corpus = output / "corpus.sqlite"
    scoped_settings = settings.model_copy(
        update={
            "database_url": f"sqlite:///{corpus}",
            "raw_dir": output / "raw",
            "embedding_manifest": output / "encoder-manifest.json",
        }
    )
    engine = make_engine(scoped_settings.database_url)
    Base.metadata.create_all(engine)
    sessions, store = make_sessions(engine), BlobStore(scoped_settings.raw_dir)
    cases = []
    own_encoder = encoder is None
    encoder = encoder or LocalEncoder(scoped_settings)
    try:
        with sessions.begin() as session:
            for group in groups:
                for source_id, source in validated[group["package"]]["sources"].items():
                    raw = source["path"].read_bytes()
                    prepared, _ = prepare(source_id, raw)
                    selected = [
                        p for p in prepared if p.normalized["external_id"] == source["external_id"]
                    ]
                    if len(selected) != 1:
                        raise ValueError("selected_source_identifier_not_unique")
                    prefix = "github" if source_id == "github-advisories" else "nvd"
                    request = next(
                        r
                        for r in manifest["requests"]
                        if r["attempt"] == group[f"{prefix}_request_attempt"]
                    )
                    ingest_document(
                        session,
                        store,
                        raw,
                        request["url"],
                        datetime.now(UTC),
                        "live",
                        spec=SOURCES[source_id],
                        prepared=selected,
                    )
                    event = session.scalar(
                        select(IntelEvent).where(
                            IntelEvent.source_id == source_id,
                            IntelEvent.external_id == source["external_id"],
                        )
                    )
                    triage = session.get(EventTriage, event.id)
                    triage.label = "relevant"
                    triage.rule_version = "stage6-preselected-exact-ai-package-v1"
                    triage.matches = {
                        **triage.matches,
                        "preselected_ai_package": group["package"],
                        "exact_cve_link": group["cve_id"],
                    }
            sync_index(session)
            semantic = sync_embeddings(session, scoped_settings, encoder)
        with sessions() as session:
            rows = active_chunks(session)
            for group in groups:
                ids = set(
                    session.scalars(
                        select(EventAlias.event_id).where(EventAlias.value == group["cve_id"])
                    )
                )
                scoped = [r for r in rows if r.event_id in ids]
                value = validated[group["package"]]
                for fact in value["facts"]:
                    for evidence in fact["evidence"]:
                        candidates = [
                            r
                            for r in scoped
                            if r.source_id == evidence["source_id"]
                            and r.json_pointer == evidence["json_pointer"]
                            and r.start < evidence["quote_end"]
                            and evidence["quote_start"] < r.end
                        ]
                        bound = None
                        for row in candidates:
                            span = source_span(
                                session, store, row, contains=evidence["quote"][:120]
                            )
                            if evidence["quote"] in span["text"]:
                                bound = span
                                break
                        if bound is None:
                            raise ValueError("gold_quote_not_in_retrievable_source_span")
                        evidence.update(
                            event_id=bound["event_id"],
                            chunk_id=bound["chunk_id"],
                            revision_id=bound["revision_id"],
                            revision=bound["revision"],
                            source_span=bound,
                            text=evidence["scope"]["text"],
                        )
                query = (group["cve_id"] + " " + value["spec"]["question"])[:200]
                cases.append(
                    {
                        "id": f"stage6-{group['package']}",
                        "group_id": group["cve_id"],
                        "package": group["package"],
                        "query": query,
                        "question": value["spec"]["question"],
                        "facts": value["facts"],
                        "event_ids": sorted(ids),
                        "source_ids": ["github-advisories", "nvd"],
                        "split": "unseen_identifier_group_holdout",
                    }
                )
            raw_hashes = sorted({r.sha256 for r in rows})
            actual = {(e.source_id, e.external_id) for e in session.scalars(select(IntelEvent))}
            wanted = {
                (sid, identifier)
                for g in groups
                for sid, identifier in (("github-advisories", g["ghsa_id"]), ("nvd", g["cve_id"]))
            }
            if actual != wanted:
                raise ValueError("isolated_corpus_contains_unselected_events")
    finally:
        if own_encoder:
            encoder.close()
        engine.dispose()
    code = output / "code"
    code.mkdir()
    source_files = [
        *sorted(Path("src/zhidu").glob("*.py")),
        *sorted(Path("scripts").glob("*agent_stage6*.py")),
        Path("tests/test_agent_stage6_evaluation.py"),
        Path("pyproject.toml"),
    ]
    implementation = {}
    for path in source_files:
        target = code / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        implementation[str(path)] = sha(path)
    save(output / "intake-manifest.json", manifest)
    save(output / "gold-specs.json", json.loads(Path(gold_specs).read_text()))
    count = len(cases)
    protocol = {
        "version": "agent-stage6-holdout-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "modes": list(MODES),
        "challenger": "team_hybrid",
        "cases": cases,
        "intake_groups": manifest["groups"],
        "preselected_packages": list(PACKAGES),
        "gold_review": {
            "method": "AI_source_review",
            "human_reviewed": False,
            "frozen_before_outputs": True,
        },
        "selection": {
            "intake_sha256": sha(intake / "manifest.json"),
            "gold_specs_sha256": sha(gold_specs),
            "exclusions_sha256": sha(intake / "exclusions.json"),
            "excluded_identifiers": exclusions["identifiers"],
            "all_failures_retained": True,
            "replacement_allowed": False,
        },
        "budget": {
            "model_calls_per_mode": {"rag_hybrid": 1, "workflow_hybrid": 1, "team_hybrid": 8},
            "max_generation_requests": count * 10,
            "max_judge_requests": count * 3,
            "max_total_requests": count * 13,
            "workflow_additional_read_fields": 4,
            "tool_calls_per_answer": 6,
            "completion_tokens_per_call": 2400,
            "soft_deadline_seconds": 60,
            "final_reserve_seconds": 12,
            "tool_output_chars": 18000,
        },
        "matching": {
            "retrieval_mode": "hybrid",
            "initial_limit": 5,
            "query_policy": "CVE plus original question prefix, at most 200 chars; identical in all modes",
            "initial_packet": "one ToolSession.retrieve snapshot, identically restored for all modes",
            "model_profile": model_profile(settings).public(),
            "temperature": 0,
            "source_pool": "selected GitHub/NVD pairs only",
            "encoder_manifest_sha256": sha(output / "encoder-manifest.json"),
            "encoder_digest": encoder_binding["digest"],
            "semantic_sync": semantic,
            "model_pricing_sha256": price_sha,
        },
        "statistics": {
            "unit": "whole frozen identifier group",
            "minimum_groups_for_gain_claim": 8,
            "quality_and_efficiency_separate": True,
            "quality_metrics": ["strict_pass", "fact_recall", "citation_entailment_precision"],
            "proof_metrics": [
                "strict_pass",
                "common_all_strict_correct_latency",
                "common_all_strict_correct_same_currency_cost",
            ],
            "quality_rate_basis": "macro paired-case rates with whole identifier-group bootstrap; unavailable metric removes the entire group only from that diagnostic",
            "ci_containing_zero_is_not_proof": True,
        },
        "corpus_sha256": sha(corpus),
        "raw_sha256": raw_hashes,
        "implementation_sha256": implementation,
        "review": {
            "rounds": 2,
            "api_judge_rounds": 1,
            "second_review": "Codex read-only anonymous packets; no second API call",
            "packet": "quote_only_anonymous",
            "adjudication": "explicit disagreement interface; never silently replace a review",
            "human_reviewed": False,
        },
        "limitations": [
            "eight preselected components at most; failed/missing pairs remain in intake and are never replaced",
            "source assertions and AI-authored gold are not independent human certification or exploitation/asset validation",
            "GitHub/NVD may repeat upstream claims; two records are not independent real-world confirmation",
            "quality and efficiency gain claims require complete group pairs and their respective confidence intervals",
        ],
    }
    protocol["freeze_sha256"] = digest(protocol)
    save(output / "protocol.json", protocol)
    return protocol


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intake", type=Path, required=True)
    parser.add_argument("--gold-specs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--main-database", type=Path)
    args = parser.parse_args()
    protocol = freeze(args.intake, args.gold_specs, args.output, main_database=args.main_database)
    print(json.dumps({"groups": len(protocol["cases"]), "sha256": protocol["freeze_sha256"]}))


if __name__ == "__main__":
    main()
