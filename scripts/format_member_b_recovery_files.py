"""Formatting-only batch required by B handoff; verify identical Python ASTs."""

import ast
import hashlib
import json
import subprocess
from pathlib import Path

FILES = (
    "scripts/confirm_member_b_agent_reviews.py",
    "scripts/prefill_member_b_agent_reviews.py",
    "scripts/probe_catalog_live_sources.py",
    "scripts/recheck_member_b_agent_two_cases.py",
    "scripts/record_member_b_runtime.py",
    "scripts/release_week6_ai_gold.py",
    "scripts/report_catalog_associations.py",
    "scripts/review_week6_sources.py",
    "scripts/serve_member_b_recovery_fixture.py",
    "scripts/verify_rag_generated_http.py",
    "scripts/week6_gold_review.py",
    "src/zhidu/agent_rag.py",
    "src/zhidu/catalog.py",
    "tests/test_member_a_catalog.py",
    "tests/test_member_b_agent_paired_v3.py",
    "tests/test_member_b_agent_paired_v4.py",
    "tests/test_member_b_collector_display.py",
    "tests/test_week6_ai_gold_release.py",
    "tests/test_week6_source_review.py",
)


def main():
    before = {name: Path(name).read_bytes() for name in FILES}
    trees = {
        name: ast.dump(ast.parse(data), include_attributes=False) for name, data in before.items()
    }
    subprocess.run([".venv/bin/ruff", "format", *FILES], check=True)
    rows = []
    for name in FILES:
        current = Path(name).read_bytes()
        unchanged = trees[name] == ast.dump(ast.parse(current), include_attributes=False)
        if not unchanged:
            raise ValueError(f"semantic AST changed: {name}")
        rows.append(
            {
                "path": name,
                "before_sha256": hashlib.sha256(before[name]).hexdigest(),
                "after_sha256": hashlib.sha256(current).hexdigest(),
                "ast_unchanged": unchanged,
            }
        )
    Path("docs/member-b-recovery-formatting-20261007.json").write_text(
        json.dumps(
            {
                "scope": "formatting_only_separate_from_model_quality_experiments",
                "historical_experiment_hashes_not_rewritten": True,
                "files": rows,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
