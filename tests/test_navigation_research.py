"""Real LangChain research consumes returned navigation IDs, never invented IDs."""

import copy
import json

from test_agent_research_batch import QUESTION, plan
from test_agent_team import RoleScript
from test_context_navigation_tools import navigation_source, scoped
from test_member_a_rag_context import ingest

from zhidu.agent_research import _research_engine
from zhidu.source_spans import verify_source_span


def test_research_reads_ids_from_paid_outline_and_restores_navigation_without_new_source_reads(
    database, store, settings, advisory
):
    ingest(database, store, navigation_source(advisory))
    with database() as session:
        tools = scoped(session, store, settings)
        event_id = next(iter(tools.events))

        def choose_returned_ids(payload):
            messages = [row for row in payload["messages"] if row["type"] == "tool"]
            assert len(messages) == 1
            content = messages[0]["data"]["content"]
            assert "UNQUOTED-BODY-MARKER" not in content
            outline = json.loads(content)["result"]["context_index"]
            ids = [
                row["context_id"]
                for row in outline
                if "Guidance" in row["label"] or row["kind"] == "list_with_intro"
            ]
            assert len(ids) == 2
            return {
                "action": "tool",
                "tool_name": "read_fields",
                "task_ids": ["conditions"],
                "arguments": {
                    "event_id": event_id,
                    "fields": ["description"],
                    "context": "section",
                    "context_ids": ids,
                },
                "note": "使用刚返回的目录定位所需段落",
            }

        script = RoleScript(
            {
                "research:0:0": {
                    "action": "tool",
                    "tool_name": "read_fields",
                    "task_ids": ["conditions"],
                    "arguments": {
                        "event_id": event_id,
                        "fields": ["description"],
                        "context": "outline",
                    },
                    "note": "先导航",
                },
                "research:0:1": choose_returned_ids,
            },
            limit=7,
        )
        trace = []
        _research_engine(script, tools, plan(), QUESTION, 0, [], trace)
        assert len(script.calls()) == 2 and tools.attempted_calls == 2
        assert trace[0]["novelty"]["new_source_chars"] == 0
        assert trace[1]["novelty"]["new_source_chars"] > 0
        assert len(tools.evidence) == 2
        assert all(
            verify_source_span(session, store, citation) for citation in tools.evidence.values()
        )
        assert any(
            "UNQUOTED-BODY-MARKER" in citation["text"] for citation in tools.evidence.values()
        )

        restored = scoped(session, store, settings)
        restored.restore(copy.deepcopy(tools.snapshot()))
        resumed = RoleScript(
            {"research:1:0": {"action": "ready", "task_ids": ["conditions"], "note": "已有正文"}},
            limit=3,
        )
        _research_engine(resumed, restored, plan(), QUESTION, 1, [], [])
        request = resumed.payloads[0][1]
        assert request["context_index"] == list(tools.context_index.values())
        assert request["context_index_is_navigation_not_evidence"] is True
        assert restored.attempted_calls == tools.attempted_calls
        assert restored.runtime.output_chars == tools.runtime.output_chars
