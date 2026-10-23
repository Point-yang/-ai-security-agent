"""Measured complete backend answers, frozen cases, explicit non-gold metrics."""

import hashlib
import json
import os
import platform
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from importlib.metadata import version
from pathlib import Path

from sqlalchemy import func, select

from zhidu.models import EventRevision, IntelEvent, RagEvaluation, SearchChunk
from zhidu.operations import _distribution
from zhidu.rag import RagRequest, RouterConfig, run_rag, save_run
from zhidu.rag_dataset import load_frozen
from zhidu.rag_metrics import query_language, score_response, stratified, summarize
from zhidu.semantic import LocalEncoder, digest, model_manifest


def benchmark(sessions, store, settings, dataset_path, *, repeats=2, concurrency=1):
    with sessions() as session:
        data = load_frozen(dataset_path, session)
        counts = {
            model.__tablename__: session.scalar(select(func.count()).select_from(model))
            for model in (IntelEvent, SearchChunk, EventRevision)
        }
    config = RouterConfig.model_validate_json(settings.rag_config.read_text())
    try:
        manifest = model_manifest(settings)
    except RuntimeError:
        manifest = None
    report = {
        "implementation_sha256": digest(
            {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(Path(__file__).parent.glob("*.py"))
            }
        ),
        "version": "rag-benchmark-v2",
        "dataset_sha256": data["freeze_sha256"],
        "dataset_version": data["version"],
        "unique_case_counts_by_split": dict(Counter(c["split"] for c in data["cases"])),
        "unique_case_counts_by_language": dict(Counter(query_language(c) for c in data["cases"])),
        "corpus_sha256": data["corpus_sha256"],
        "router": config.model_dump(),
        "official_human_gold_scores": None,
        "human_gold_status": "pending_independent_review",
        "scope": "train_development_characterization_not_human_gold_or_test_score",
        "hardware": {
            "os": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "logical_cpus": os.cpu_count(),
        },
        "data_scale": counts,
        "concurrency": concurrency,
        "repeats": repeats,
        "models": {
            "generation": "extractive-packet-v4",
            "embedding": manifest["model"] if manifest else settings.embedding_model,
            "embedding_digest": manifest["digest"] if manifest else None,
            "reranker": "rrf60-cosine-v1",
            "fastembed": version("fastembed"),
        },
        "ttft_ms": None,
        "streaming": False,
        "latency_scope": "complete backend answer + citation checks + DB commit + JSON serialization; excludes HTTP transport",
        "cache": "cold first request separated; warm model process, OS cache uncontrolled; no query/answer cache",
        "modes": {},
    }

    def rate(n, d):
        return n / d if d else None

    for mode in ("lexical", "hybrid", "agentic"):
        encoder = LocalEncoder(settings)

        def execute(case, mode=mode, encoder=encoder):
            start = time.perf_counter()
            # This historical benchmark measures excerpts, not generated semantic correctness.
            request = RagRequest(
                question=case["question"],
                query=case["query"],
                mode=mode,
                generation="extractive",
                context_mode="baseline",
            )
            with sessions.begin() as session:
                result = run_rag(session, store, settings, request, encoder, config)
                row = save_run(session, request, result)
                run_id = row.id
            # Serialization and commit are included, unlike the HTTP middleware timer.
            json.dumps(result, default=str)
            elapsed = (time.perf_counter() - start) * 1000
            return {
                "case_id": case["id"],
                "split": case["split"],
                "language": query_language(case),
                "run_id": run_id,
                "expected_class": case["expected_class"],
                "answer_class": result["answer_class"],
                "reason": result.get("reason"),
                "elapsed_ms": elapsed,
                **score_response(case, result),
                "tool_calls": result["tool_calls"],
                "cost": result["cost"],
            }

        try:
            cold = execute(data["cases"][0])
            work = data["cases"] * repeats
            if concurrency == 1:
                records = [execute(case) for case in work]
            else:
                with ThreadPoolExecutor(max_workers=concurrency) as executor:
                    records = list(executor.map(execute, work))
        finally:
            encoder.close()
        refusals = [r for r in records if r["expected_class"] == "refused"]
        recalls = [r["recall_at_k"] for r in records if r["recall_at_k"] is not None]
        report["modes"][mode] = {
            **summarize(records),
            "strata": stratified(records),
            "cold_first_request": cold,
            "complete_answer_latency_ms": _distribution([r["elapsed_ms"] for r in records], "ms"),
            "non_refusal_latency_ms": _distribution(
                [r["elapsed_ms"] for r in records if r["answer_class"] in {"evidence", "partial"}],
                "ms",
            ),
            "class_accuracy": rate(sum(r["class_correct"] for r in records), len(records)),
            "refusal_correctness": rate(sum(r["class_correct"] for r in refusals), len(refusals)),
            "citation_support_rate": rate(
                sum(r["supported_claims"] for r in records), sum(r["claims"] for r in records)
            ),
            "citation_support_definition": "exact source excerpt AND frozen expected event; not free-form entailment",
            "recall_at_5": rate(sum(recalls), len(recalls)),
            "unavailable_requests": sum(r["answer_class"] == "unavailable" for r in records),
            "request_api_cost_usd": 0,
            "local_compute_cost_usd": None,
            "records": records,
        }
    report["report_sha256"] = digest(report)
    with sessions.begin() as session:
        session.add(RagEvaluation(report=report))
    return report
