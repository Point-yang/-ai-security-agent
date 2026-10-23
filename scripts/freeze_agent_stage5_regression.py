"""Freeze seen stage4 cases for development regression, never a new holdout.

This command only reads the fixed stage4 release and local implementation.
It copies existing corpus/source bytes unchanged, makes no provider request,
and refuses to overwrite any output directory.
"""

import argparse
import copy
import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

from zhidu.config import Settings
from zhidu.grounded_answer import CONTRACT_VERSION
from zhidu.model_provider import model_profile
from zhidu.paired_evaluation import digest
from zhidu.storage import BlobStore

ROOT = Path(__file__).resolve().parents[1]
STAGE4_SOURCE = ROOT / "output/agent-stage4-release-20261012"
DEFAULT_OUTPUT = ROOT / "output/agent-stage5-regression-20261013"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def implementation_hashes():
    paths = [
        *sorted((ROOT / "src/zhidu").glob("*.py")),
        ROOT / "scripts/run_agent_paired_pilot.py",
        Path(__file__).resolve(),
        ROOT / "pyproject.toml",
        ROOT / "requirements-agent.lock",
    ]
    return {str(path.relative_to(ROOT)): sha(path) for path in paths}


def freeze(output=DEFAULT_OUTPUT):
    output = Path(output)
    if output.exists():
        raise FileExistsError("regression_output_already_exists")
    source = STAGE4_SOURCE
    original = json.loads((source / "protocol.json").read_text())
    unsigned = dict(original)
    original_freeze = unsigned.pop("freeze_sha256")
    if digest(unsigned) != original_freeze:
        raise ValueError("stage4_protocol_changed")
    if sha(source / "corpus.sqlite") != original["corpus_sha256"]:
        raise ValueError("stage4_corpus_changed")
    cases = copy.deepcopy(original["cases"])
    groups = {case["group_id"] for case in cases}
    facts = sum(len(case["facts"]) for case in cases)
    if len(cases) != 4 or len(groups) != 4 or facts != 30:
        raise ValueError("fixed_stage4_regression_cohort_changed")
    if original["gold_review"].get("human_reviewed") is not False:
        raise ValueError("stage4_gold_review_identity_changed")
    old_store = BlobStore(source / "raw")
    for raw_sha in original["raw_sha256"]:
        old_store.read(raw_sha)
    if CONTRACT_VERSION != "source-answer-v4":
        raise ValueError("stage5_implementation_not_ready")
    # Only the model's public profile is retained. Settings/model API keys and
    # arbitrary environment values never enter this protocol or any artifact.
    profile = model_profile(Settings()).public()
    hashes = implementation_hashes()
    protocol = {
        "version": "agent-stage5-development-regression-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "scope": "seen_stage4_four_group_development_regression",
        "effective_split": "development_regression",
        "held_out": False,
        "modes": ["rag", "workflow", "auto"],
        "challenger": "auto",
        "gold_review": {
            "method": "AI_source_review_reused_unchanged",
            "human_reviewed": False,
            "independent_human_attestation": False,
            "frozen_before_stage5_outputs": True,
            "original_frozen_before_stage4_outputs": True,
            "adoption": "user_authorized_project_gold_not_organizer_certification",
        },
        "development_history": {
            "all_groups_seen": True,
            "all_facts_seen": True,
            "groups": len(groups),
            "atomic_facts": facts,
            "prior_answers_used_for_bugfix": True,
            "case_history_is_stage4_historical_only": True,
            "interpretation": "development regression only; neither independent holdout accuracy nor general Agent gain proof",
        },
        "selection": {
            "method": "reuse every fixed stage4 group and fact without replacement",
            "seen_case_ids": [case["id"] for case in cases],
            "main_modified": False,
        },
        "budget": {
            "model_calls_per_answer": 5,
            "model_calls_per_mode": {"rag": 1, "workflow": 1, "auto": 5},
            "tool_calls_per_answer": 6,
            "completion_tokens_per_call": 1800,
            "soft_deadline_seconds": 30,
            "final_reserve_seconds": 8,
            "tool_output_chars": 18000,
            "max_generation_requests": 28,
            "max_judge_requests": 12,
            "max_total_requests": 40,
        },
        "matching": {
            "model_profile": profile,
            "temperature": 0,
            "answer_contract": CONTRACT_VERSION,
            "quote_policy": "same current raw hash/pointer verified contiguous spans and server-owned quote resolver",
            "rag": "production lexical retrieval plus context expansion; one generation",
            "workflow": "production prepared evidence workflow; one generation",
            "workflow_execution": "production_workflow_agent",
            "auto": "same production workflow; evidence coverage gate alone may route to LangChain; five generation calls total",
            "source_pool": "unchanged stage4 frozen corpus and raw byte snapshots",
        },
        "rubric": {
            **copy.deepcopy(original["rubric"]),
            "statistics": "paired by whole CVE group; seen development cases, exploratory regression only",
        },
        "limitations": [
            "All 4 groups/30 required facts and prior stage4 outputs have been seen and used for bug fixes; this is development regression, not a new holdout",
            "AI source gold is reused unchanged; no human review or organizer certification is claimed",
            "Anonymous single same-provider AI judgment can be biased and requires review; judging is separate from source-byte verification",
            "Same model/temperature/final schema/call ceilings; prompts and actual input token counts differ",
            "Soft deadline/backend duration excludes HTTP/UI transport and TTFT; API USD unknown",
            "Repeated source reports are not independent real-world corroboration; no asset/POC/patch execution verification",
            "FAQ rows 10/11 official failure/partial/no-public-data scoring remains unknown",
        ],
        "corpus_sha256": original["corpus_sha256"],
        "raw_sha256": list(original["raw_sha256"]),
        "implementation_sha256": hashes,
        "cases": cases,
        "source_release": {
            "path": str(source.relative_to(ROOT)),
            "protocol_file_sha256": sha(source / "protocol.json"),
            "protocol_freeze_sha256": original_freeze,
            "cases_sha256": digest(cases),
            "copied_without_source_or_gold_modification": True,
            "prior_release_untouched": True,
        },
    }
    protocol["freeze_sha256"] = digest(protocol)
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(source / "corpus.sqlite", output / "corpus.sqlite")
    new_store = BlobStore(output / "raw")
    for raw_sha in original["raw_sha256"]:
        if new_store.put(old_store.read(raw_sha)) != raw_sha:
            raise ValueError("raw_copy_integrity_failed")
    if sha(output / "corpus.sqlite") != original["corpus_sha256"]:
        raise ValueError("corpus_copy_integrity_failed")
    with (output / "protocol.json").open("x") as file:
        file.write(json.dumps(protocol, ensure_ascii=False, indent=2) + "\n")
    print(
        json.dumps(
            {
                "output": str(output),
                "groups": len(groups),
                "atomic_facts": facts,
                "development_regression": True,
                "sha256": protocol["freeze_sha256"],
            }
        )
    )
    return protocol


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    freeze(args.output)
