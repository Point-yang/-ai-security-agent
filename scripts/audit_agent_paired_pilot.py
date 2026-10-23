"""No model requests: recheck frozen bytes and actual baseline evidence delivery."""

import argparse
import json
from collections import Counter
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from run_agent_paired_pilot import fixed_workflow, load_protocol, save

from zhidu.agent_tools import _verified_row
from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.models import SearchChunk
from zhidu.paired_evaluation import digest
from zhidu.rag import RagRequest, RouterConfig, run_rag
from zhidu.semantic import active_chunks
from zhidu.storage import BlobStore


def audit(output):
    protocol = load_protocol(output)
    settings = Settings().model_copy(
        update={
            "database_url": f"sqlite:///{output / 'corpus.sqlite'}",
            "raw_dir": output / "raw",
            "agent_max_output_chars": 18000,
        }
    )
    store = BlobStore(settings.raw_dir)
    engine = make_engine(settings.database_url)
    sessions = make_sessions(engine)
    rows, checks = [], 0
    # Short local demo passphrases can also be ordinary words in public text;
    # substring matching cannot establish credential export for those values.
    secret_values = [
        s.get_secret_value()
        for s in (
            settings.admin_key,
            settings.deepseek_api_key,
            settings.agent_model_api_key,
            settings.github_token,
        )
        if len(s.get_secret_value()) >= 12
    ]
    public_hosts, source_counts = Counter(), Counter()
    with sessions() as session:
        corpus = active_chunks(session)
        # Public source fields are the only discoverable records; private asset tools
        # are not registered by the native agent when no asset has been selected.
        for chunk in corpus:
            source_counts[chunk.source_id] += 1
            if any(secret in chunk.text for secret in secret_values):
                raise ValueError("configured_secret_in_source_text")
        for case in protocol["cases"]:
            for fact in case["facts"]:
                for item in fact["evidence"]:
                    row = session.get(SearchChunk, item["chunk_id"])
                    assert row is not None and row.text == item["text"]
                    assert item["quote"] in row.text
                    _verified_row(session, store, row)
                    checks += 1
            body = RagRequest(
                question=case["question"],
                query=case["query"],
                mode="lexical",
                generation="extractive",
                context_mode="expanded",
            )
            rag = run_rag(
                session,
                store,
                settings,
                body,
                None,
                RouterConfig(
                    max_tools=6,
                    timeout_ms=30000,
                    query_rewrite=True,
                    relevance_gate=True,
                    supplement=False,
                    trace=False,
                ),
            )
            with patch("run_agent_paired_pilot.apply_generation"):
                workflow = fixed_workflow(session, store, settings, body)
            for name, result in (("rag", rag), ("workflow", workflow)):
                delivered = {c["source_id"] for c in result["citations"]}
                chars = sum(len(c["text"]) for c in result["citations"])
                for c in result["citations"]:
                    host = urlsplit(c.get("source_url", "")).hostname
                    public_hosts[host or "unknown"] += 1
                assert chars <= 18000
                assert result["cost"]["external_requests"] == 0
                rows.append(
                    {
                        "case_id": case["id"],
                        "mode": name,
                        "wanted_source_ids": case["source_ids"],
                        "delivered_source_ids": sorted(delivered),
                        "source_delivery_complete": set(case["source_ids"]).issubset(delivered),
                        "evidence_chars": chars,
                        "citations": len(result["citations"]),
                        "tools": result["tool_calls"],
                        "tool_errors": [
                            s.get("error") for s in result["tools"] if s["status"] == "failed"
                        ],
                    }
                )
    engine.dispose()
    result = {
        "version": "agent-paired-pilot-offline-audit-v1",
        "protocol_sha256": protocol["freeze_sha256"],
        "model_calls": 0,
        "external_requests": 0,
        "semantic_accuracy": None,
        "gold_facts": sum(len(c["facts"]) for c in protocol["cases"]),
        "raw_quote_pointer_checks": checks,
        "frozen_raw_blobs": len(protocol["raw_sha256"]),
        "long_configured_secret_matches_in_source_text": 0,
        "credential_check_scope": "configured values of at least 12 characters; short ordinary-word coincidences are not classified as credential disclosure; settings objects never enter model payloads",
        "retrievable_source_counts": dict(source_counts),
        "delivered_source_hosts": dict(public_hosts),
        "outbound_scope_if_authorized": "questions and public source excerpts; judging additionally sends anonymous generated answers and pre-frozen source gold; no database file, credentials, SBOM or selected asset details",
        "qa_source_disjointness": "new QA tasks; known prior structured enrichment audit use disclosed",
        "records": rows,
    }
    result["sha256"] = digest(result)
    save(output / "offline-audit.json", result)
    print(
        json.dumps(
            {
                "output": str(output / "offline-audit.json"),
                "gold_facts": result["gold_facts"],
                "raw_checks": checks,
                "source_delivery": {
                    m: sum(r["source_delivery_complete"] for r in rows if r["mode"] == m)
                    for m in ("rag", "workflow")
                },
                "external_requests": 0,
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    audit(parser.parse_args().output)
