"""Correct historical metrics from saved output; do not replace historical timing evidence."""

import json
from pathlib import Path

from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.models import RagRun
from zhidu.rag_dataset import load_frozen
from zhidu.rag_metrics import query_language, score_response, stratified, summarize
from zhidu.semantic import digest


def main():
    engine = make_engine(Settings().database_url)
    with make_sessions(engine)() as session:
        data = load_frozen(Path("config/member-b-week6-frozen-qa.json"), session)
        cases = {c["id"]: c for c in data["cases"]}
        for suffix in ("evaluation", "concurrency2"):
            original = Path(f"docs/member-b-week6-rag-{suffix}.json")
            output = original.with_name(original.stem + "-corrected.json")
            if output.exists():
                raise ValueError("Refusing to overwrite a corrected report")
            report = json.loads(original.read_text())
            old_digest = report.pop("report_sha256")
            assert digest(report) == old_digest
            report["supersedes_report_sha256"] = old_digest
            report["version"] = "rag-rescore-v2"
            report["correction"] = (
                "Empty expected event sets cannot support factual claims; timing retained from original run."
            )
            report["scope"] = "train_development_characterization_not_human_gold_or_test_score"
            for mode, section in report["modes"].items():
                for row in [section["cold_first_request"], *section["records"]]:
                    run = session.get(RagRun, row["run_id"])
                    if run is None:
                        raise ValueError("Saved answer unavailable: cannot independently rescore")
                    row.update(score_response(cases[row["case_id"]], run.result))
                    row["language"] = query_language(cases[row["case_id"]])
                section.update(summarize(section["records"]))
                section["strata"] = stratified(section["records"])
                print(
                    suffix,
                    mode,
                    section["supported_claims"],
                    section["claim_count"],
                    section["citation_support_rate"],
                )
            report["report_sha256"] = digest(report)
            output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
