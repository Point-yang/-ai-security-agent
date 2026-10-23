"""Create once; never overwrite a frozen evaluation manifest."""

import json
from pathlib import Path

from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.rag_dataset import freeze_dataset

if __name__ == "__main__":
    output = Path("config/member-b-week6-frozen-qa.json")
    if output.exists():
        raise SystemExit("Already frozen; refusing overwrite")
    engine = make_engine(Settings().database_url)
    with make_sessions(engine)() as session:
        data = freeze_dataset(
            session, json.loads(Path("docs/member-a-week6-annotation-pack.json").read_text())
        )
    output.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str) + "\n")
    print(
        json.dumps(
            {
                "file": str(output),
                "freeze_sha256": data["freeze_sha256"],
                "cases": len(data["cases"]),
                "human_pending": len(data["human_annotation_records"]),
            }
        )
    )
