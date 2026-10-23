"""Create an isolated demonstration copy with an explicitly fictional SBOM."""

import json
import sqlite3
from pathlib import Path

from sqlalchemy import select

from zhidu.asset_matching import import_cyclonedx
from zhidu.config import Settings
from zhidu.conversations import create_conversation, submit_turn
from zhidu.db import make_engine, make_sessions
from zhidu.models import IntelEvent
from zhidu.schemas import ConversationTurnCreate
from zhidu.storage import BlobStore


def main():
    target = Path("data/member-b-delivery-demo.db")
    if target.exists():
        raise SystemExit("Demo already exists; refusing overwrite")
    with (
        sqlite3.connect("file:data/zhidu.db?mode=ro", uri=True) as source,
        sqlite3.connect(target) as destination,
    ):
        source.backup(destination)
    engine = make_engine(f"sqlite:///{target}")
    with make_sessions(engine).begin() as session:
        asset, details = import_cyclonedx(
            session,
            Path("examples/cyclonedx-vllm-demo.json").read_bytes(),
            asset_name="虚构演示资产 vLLM",
            environment="demo",
            criticality="high",
        )
        event = session.scalar(
            select(IntelEvent).where(
                IntelEvent.external_id == "GHSA-pmqf-x6x8-p7qw",
                IntelEvent.source_id == "github-advisories",
            )
        )
        conversation = create_conversation(session, "演示会话 来源条件与补证", asset.id)
        result = submit_turn(
            session,
            BlobStore(Settings().raw_dir),
            conversation,
            ConversationTurnCreate(
                question="我的演示资产与这条来源条件如何比较？",
                query=event.external_id,
                event_id=event.id,
                limit=1,
            ),
        )
        report = {
            "database": str(target),
            "fictional_asset": True,
            "asset_id": asset.id,
            "conversation_id": conversation.id,
            "event_id": event.id,
            "asset_scan": details,
            "message_count": result["conversation"]["message_count"],
        }
    report_path = Path("tmp/member-b-delivery/demo-state.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    print(json.dumps(report, ensure_ascii=False, default=str))
    engine.dispose()


if __name__ == "__main__":
    main()
