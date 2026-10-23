"""Exercise the product StateGraph and its real LangChain research tool loop."""

import json
from copy import deepcopy

import pytest
from test_member_a_rag_context import fixture_advisory, ingest

pytest.importorskip("langchain")

from zhidu.agent_state import AgentAnswer
from zhidu.agent_team import build_team_graph, run_agent_team, verifier_packet
from zhidu.agent_team_state import TaskPlan, VerifierOutput
from zhidu.langchain_tools import SourceRuntime, ToolSession
from zhidu.rag import RagRequest


class RoleScript:
    def __init__(self, actions, limit=8):
        self.actions, self.limit = actions, limit
        self.entries, self.payloads, self.responses = [], [], {}
        self.external_requests = self.current_attempt_external_requests = 0

    @property
    def remaining_model_calls(self):
        return self.limit - len(self.entries)

    def has_reply(self, call_id):
        return call_id in self.responses

    def invoke(self, role, payload, schema, *, call_id):
        if call_id in self.responses:
            return self.responses[call_id]
        if self.remaining_model_calls <= 0:
            raise ValueError("model_call_budget_exceeded")
        self.payloads.append((role, payload))
        action = self.actions[call_id]
        value = action(payload) if callable(action) else action
        if schema.__name__ == "VerifierDecision":
            value = wire_verdict_fixture(value, payload)
        response = schema.model_validate(value)
        self.responses[call_id] = response
        self.entries.append(
            {"role": role, "call_id": call_id, "usage": {"total_tokens": 15}, "http_requests": 0}
        )
        return response

    def calls(self):
        return self.entries


def wire_verdict_fixture(value, payload):
    """Only the test fixture boundary translates old internal verdict samples.

    Production accepts the wire schema exclusively. Never invent an anchor or
    copy a source quote into an answer span; every ID comes from the packet.
    Already-wire samples pass through unchanged, including intentionally bad IDs.
    """
    value = deepcopy(value.model_dump() if hasattr(value, "model_dump") else value)
    if any("anchor_ids" in item for item in value.get("coverage", [])):
        return value
    by_index = {item["statement_index"]: item for item in payload["statements"]}

    def anchors(spans, fallback=()):
        indices = [span["statement_index"] for span in spans] if spans else list(fallback)
        for span in spans:
            assert span["text"] in by_index[span["statement_index"]]["text"], (
                "fixture answer span must use candidate prose"
            )
        return list(dict.fromkeys(by_index[index]["answer_anchor_id"] for index in indices))

    rows = []
    for row in value.get("coverage", []):
        rows.append(
            {
                "task_id": row["task_id"],
                "status": row["status"],
                "note": row["note"],
                "anchor_ids": anchors(
                    row.get("answer_spans", []), row.get("statement_indices", [])
                ),
                "element_coverage": [
                    {
                        "element": item["element"],
                        "status": item["status"],
                        "anchor_ids": anchors(item.get("answer_spans", [])),
                    }
                    for item in row["element_coverage"]
                ],
            }
        )
    return {
        "coverage": rows,
        "claim_support": value["claim_support"],
        "unplanned_requirements": [
            {
                "requirement": item["requirement"],
                "question_quote": item["question_span"]["quote"],
                "reason": item["reason"],
            }
            for item in value["unplanned_requirements"]
        ],
        "gaps": value["gaps"],
    }


def plan(question="来源的修复建议是什么？"):
    return {
        "tasks": [
            {
                "task_id": "patch",
                "requirement": "公告明确的修复建议",
                "source_ids": ["github-advisories"],
                "fields": ["description"],
                "contains": "Patches",
                "keywords": ["upgrade"],
                "question_spans": [{"quote": question}],
                "source_policy": "any",
                "required_elements": ["公告明确的修复建议"],
            }
        ]
    }


def retrieve(advisory):
    return {
        "action": "tool",
        "tool_name": "retrieve",
        "arguments": {"query": advisory["ghsa_id"], "mode": "lexical", "limit": 2},
        "task_ids": ["patch"],
        "note": "先找当前公告",
    }


def ready():
    return {"action": "ready", "arguments": {}, "task_ids": ["patch"], "note": "提交现有证据"}


def candidate(payload, *, choose_patch=False):
    citations = payload["sources"]
    source = (
        next(
            (citation for citation in citations if "Upgrade to 1.2.0" in citation["text"]),
            citations[0],
        )
        if choose_patch
        else citations[0]
    )
    return {
        "answer_class": "evidence",
        "statements": [
            {
                "text": "该公告建议升级至1.2.0。",
                "evidence": [{"evidence_id": source["evidence_id"]}],
            }
        ],
        "required_facts": ["公告明确的修复建议"],
        "missing_facts": [],
        "limitations": [],
        "message": "",
    }


def covered(text="该公告建议升级至1.2.0。"):
    span = {"statement_index": 1, "text": text}
    return {
        "coverage": [
            {
                "task_id": "patch",
                "status": "covered",
                "statement_indices": [1],
                "note": "正文陈述修复建议且自身引文支持",
                "answer_spans": [span],
                "element_coverage": [
                    {"element": "公告明确的修复建议", "status": "covered", "answer_spans": [span]}
                ],
            }
        ],
        "claim_support": [
            {"statement_index": 1, "status": "supported", "reason": "自身引文支持该结论"}
        ],
        "unplanned_requirements": [],
        "gaps": [],
    }


def missing():
    return {
        "coverage": [
            {
                "task_id": "patch",
                "status": "missing",
                "statement_indices": [],
                "note": "当前实际引用未包含修复正文",
                "answer_spans": [],
                "element_coverage": [
                    {"element": "公告明确的修复建议", "status": "missing", "answer_spans": []}
                ],
            }
        ],
        "claim_support": [
            {
                "statement_index": 1,
                "status": "unsupported",
                "reason": "当前实际引用没有升级1.2.0的声明",
            }
        ],
        "unplanned_requirements": [],
        "gaps": [
            {
                "task_id": "patch",
                "requirement": "补读公告Patches修复正文",
                "source_id": "github-advisories",
                "field": "description",
                "contains": "Patches",
            }
        ],
    }


def body(advisory, **kwargs):
    return RagRequest(
        question="来源的修复建议是什么？",
        query=advisory["ghsa_id"],
        mode="lexical",
        generation="agent",
        agent_backend="langchain",
        **kwargs,
    )


def test_product_graph_has_separate_planner_research_composer_and_quote_verifier(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    script = RoleScript(
        {
            "planner:0": plan(),
            "research:0:0": retrieve(advisory),
            "research:0:1": ready(),
            "compose:0": lambda p: candidate(p, choose_patch=True),
            "verify:0": covered(),
        },
        limit=5,
    )
    with database() as session:
        result = run_agent_team(session, store, settings, body(advisory), None, runner=script)
    assert result["generation"]["status"] == "completed", result
    assert result["agent"]["roles"] == ["planner", "researcher", "composer", "verifier"]
    assert [entry["role"] for entry in script.calls()] == [
        "planner",
        "researcher",
        "researcher",
        "composer",
        "verifier",
    ]
    assert result["tool_calls"] == 1
    assert result["cost"]["billed_tokens"] == 75
    assert result["agent"]["tool_steps"] == result["tools"]
    assert len(result["agent"]["planner_usage"]) == 5
    assert result["agent"]["decisions"] == result["agent"]["research_trace"]
    assert (
        result["cost"]["monetary"]["status"] == "unknown"
    )  # total-only script usage is not billable detail
    packet = next(payload for role, payload in script.payloads if role == "verifier")
    assert packet["review_scope"] == "actual_attached_quotes_only"
    assert "sources" not in packet and "evidence" not in packet
    assert "quote" in packet["statements"][0]["quotes"][0]
    assert result["agent"]["ai_quote_review"]["human_review"] is False
    research = next(payload for role, payload in script.payloads if role == "researcher")
    assert research["tools"]["read_fields"]["properties"]["fields"]["type"] == "array"


def test_verifier_concrete_gap_causes_actual_second_tool_read(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    settings = settings.model_copy(update={"agent_max_model_calls": 8})

    def read_patch(payload):
        assert payload["gaps"][0]["contains"] == "Patches"
        event_id = payload["evidence"][0]["event_id"]
        return {
            "action": "tool",
            "tool_name": "read_fields",
            "arguments": {
                "event_id": event_id,
                "fields": ["description"],
                "contains": "Patches",
                "limit": 1,
            },
            "task_ids": ["patch"],
            "note": "依据核查缺口实际补读Patches",
        }

    script = RoleScript(
        {
            "planner:0": plan(),
            "research:0:0": retrieve(advisory),
            "research:0:1": ready(),
            "compose:0": candidate,
            "verify:0": missing(),
            "research:1:0": read_patch,
            "compose:1": lambda p: candidate(p, choose_patch=True),
            "verify:1": covered(),
        }
    )
    with database() as session:
        result = run_agent_team(session, store, settings, body(advisory), None, runner=script)
    assert result["generation"]["status"] == "completed", result
    assert result["answer_class"] == "evidence"
    assert [step["tool"] for step in result["tools"]] == ["retrieve", "read_fields"]
    assert result["tools"][1]["input"]["contains"] == "Patches"
    assert result["agent"]["supplement_cycles"] == 1
    assert len(script.calls()) == 8
    assert "Upgrade to 1.2.0" in result["generated_claims"][0]["evidence"][0]["quote"]
    assert result["agent"]["final_citation_check"]["verified"] == 1


def test_budget_exhaustion_does_not_publish_unsupported_statement(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    script = RoleScript(
        {
            "planner:0": plan(),
            "research:0:0": retrieve(advisory),
            "research:0:1": ready(),
            "compose:0": candidate,
            "verify:0": missing(),
        },
        limit=5,
    )
    with database() as session:
        result = run_agent_team(session, store, settings, body(advisory), None, runner=script)
    assert result["answer_class"] == "refused", result
    assert result["generated_claims"] == []
    assert result["agent"]["supplement_cycles"] == 0
    assert len(script.calls()) == 5
    assert "1.2.0" not in result["answer"]


def test_greedy_first_researcher_cannot_spend_the_targeted_gap_cycle(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    settings = settings.model_copy(update={"agent_max_model_calls": 8})

    def read_title(payload):
        observation = json.loads(payload["messages"][-1]["data"]["content"])
        event_id = observation["result"]["items"][0]["citation"]["event_id"]
        return {
            "action": "tool",
            "tool_name": "read_fields",
            "arguments": {"event_id": event_id, "fields": ["title"]},
            "task_ids": ["patch"],
            "note": "首轮选择另一次读取，没有主动ready",
        }

    def read_patch(payload):
        assert payload["gaps"][0]["contains"] == "Patches"
        assert payload["model_calls_before_composition"] == 1
        return {
            "action": "tool",
            "tool_name": "read_fields",
            "arguments": {
                "event_id": payload["evidence"][0]["event_id"],
                "fields": ["description"],
                "contains": "Patches",
                "limit": 1,
            },
            "task_ids": ["patch"],
            "note": "按核查角色缺口定位修复正文",
        }

    script = RoleScript(
        {
            "planner:0": plan(),
            "research:0:0": retrieve(advisory),
            "research:0:1": read_title,
            "compose:0": candidate,
            "verify:0": missing(),
            "research:1:0": read_patch,
            "compose:1": lambda p: candidate(p, choose_patch=True),
            "verify:1": covered(),
        }
    )
    with database() as session:
        result = run_agent_team(session, store, settings, body(advisory), None, runner=script)
    assert result["generation"]["status"] == "completed", result
    assert result["agent"]["supplement_cycles"] == 1
    assert len(script.calls()) == 8
    assert "research:0:2" not in script.responses
    assert [step["tool"] for step in result["tools"]] == ["retrieve", "read_fields", "read_fields"]
    assert "Upgrade to 1.2.0" in result["generated_claims"][0]["evidence"][0]["quote"]
    assert result["agent"]["final_citation_check"]["verified"] == 1


def test_unknown_evidence_rejected_before_quote_verifier(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))

    def forged(payload):
        answer = candidate(payload)
        answer["statements"][0]["evidence"][0]["evidence_id"] = "x" * 24
        return answer

    script = RoleScript(
        {
            "planner:0": plan(),
            "research:0:0": retrieve(advisory),
            "research:0:1": ready(),
            "compose:0": forged,
        },
        limit=5,
    )
    with database() as session:
        result = run_agent_team(session, store, settings, body(advisory), None, runner=script)
    assert result["generation"]["reason"] == "unknown_evidence_id"
    assert not any(entry["role"] == "verifier" for entry in script.calls())
    assert result["answer_class"] == "partial"


def test_missing_required_task_in_verifier_is_fail_closed(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    bad = covered()
    bad["coverage"][0]["task_id"] = "invented"
    script = RoleScript(
        {
            "planner:0": plan(),
            "research:0:0": retrieve(advisory),
            "research:0:1": ready(),
            "compose:0": candidate,
            "verify:0": bad,
        },
        limit=5,
    )
    with database() as session:
        result = run_agent_team(session, store, settings, body(advisory), None, runner=script)
    assert result["generation"]["reason"] == "invalid_verifier_task_coverage"
    assert result["answer_class"] == "partial"


def test_selected_asset_preflight_needs_no_role_call(database, store, settings, advisory):
    script = RoleScript({})
    request = body(advisory).model_copy(update={"question": "我的资产是否受影响？"})
    with database() as session:
        result = run_agent_team(session, store, settings, request, None, runner=script)
    assert result["answer_class"] == "clarification"
    assert script.calls() == []
    assert result["context"]["citations"] == 0


def test_reviewer_cannot_observe_unquoted_extra_source():
    p = TaskPlan.model_validate(plan(question="修复建议"))
    evidence = {
        "a" * 24: {"text": "Upgrade to 1.2.0", "source_id": "github-advisories"},
        "b" * 24: {"text": "SECRET UNQUOTED CONTEXT", "source_id": "nvd"},
    }
    c = AgentAnswer.model_validate(
        {
            "answer_class": "evidence",
            "statements": [
                {"text": "来源建议升级至1.2.0", "evidence": [{"evidence_id": "a" * 24}]}
            ],
            "required_facts": ["修复建议"],
            "missing_facts": [],
            "limitations": [],
            "message": "",
        }
    )
    packet = verifier_packet("修复建议", p, c, evidence)
    assert "SECRET UNQUOTED CONTEXT" not in json.dumps(packet)
    assert "nvd" not in json.dumps(packet)


def test_graph_contains_actual_role_nodes(database, store, settings, advisory):
    request = body(advisory)
    with database() as session:
        tools = ToolSession(SourceRuntime(session, store, settings, None), request, None)
        graph = build_team_graph(RoleScript({}), tools, request.question)
    assert {"planner", "researcher", "composer", "verifier", "supplement"} <= set(
        graph.get_graph().nodes
    )


def test_duplicate_atomic_tasks_rejected():
    payload = plan()
    payload["tasks"] *= 2
    with pytest.raises(ValueError, match="duplicate_task_id"):
        TaskPlan.model_validate(payload)


def test_unsupported_claim_forces_coverage_partial_without_publishing_fact():
    from zhidu.agent_team import validate_verification

    p = TaskPlan.model_validate(plan())
    c = AgentAnswer.model_validate(
        {
            "answer_class": "evidence",
            "statements": [{"text": "来源升级建议", "evidence": [{"evidence_id": "a" * 24}]}],
            "required_facts": ["修复建议"],
            "missing_facts": [],
            "limitations": [],
            "message": "",
        }
    )
    verdict = covered(text="来源升级建议")
    verdict["claim_support"] = [
        {"statement_index": 1, "status": "unsupported", "reason": "引用不支持"}
    ]
    ledger = validate_verification(p, c, VerifierOutput.model_validate(verdict))
    assert ledger["tasks"][0]["status"] == "partial"
    assert ledger["unsupported_statement_indices"] == [1]


def test_local_asset_tool_artifact_never_reaches_any_role(database, store, settings, advisory):
    from zhidu.models import Asset

    ingest(database, store, fixture_advisory(advisory))
    settings = settings.model_copy(update={"agent_max_model_calls": 6})
    with database.begin() as session:
        asset = Asset(
            name="private-project-host",
            environment="private",
            criticality="low",
            sbom_sha256="0" * 64,
        )
        session.add(asset)
        session.flush()
        asset_id = asset.id

    def select_asset(payload):
        messages = payload["messages"]
        tool = next(message for message in reversed(messages) if message["type"] == "tool")
        event_id = json.loads(tool["data"]["content"])["result"]["items"][0]["citation"]["event_id"]
        return {
            "action": "tool",
            "tool_name": "asset_exposure",
            "arguments": {"event_id": event_id},
            "task_ids": ["patch"],
            "note": "仅本地展示所选资产条件匹配",
        }

    script = RoleScript(
        {
            "planner:0": plan(),
            "research:0:0": retrieve(advisory),
            "research:0:1": select_asset,
            "research:0:2": ready(),
            "compose:0": candidate,
            "verify:0": covered(),
        },
        limit=6,
    )
    with database() as session:
        result = run_agent_team(
            session, store, settings, body(advisory, asset_id=asset_id), None, runner=script
        )
    assert result["generation"]["status"] == "completed", result
    outbound = json.dumps(script.payloads, ensure_ascii=False)
    assert asset_id not in outbound and "private-project-host" not in outbound
    assert "private_asset_data" not in outbound
    local = next(
        tool["result"]
        for tool in result["agent"]["tool_results"]
        if tool["tool"] == "asset_exposure"
    )
    assert local["asset_id"] == asset_id


def role_model(actions):
    from langchain_core.messages import AIMessage
    from test_langchain_agent import ScriptedModel

    wrapped = []
    for action in actions:

        def complete(messages, _action=action):
            payload = json.loads(messages[-1].content)
            value = _action(payload) if callable(_action) else deepcopy(_action)
            schema = json.loads(messages[0].content.rsplit("schema:\n", 1)[1])
            if schema["title"] == "VerifierDecision":
                value = wire_verdict_fixture(value, payload)
            return AIMessage(content=json.dumps(value, ensure_ascii=False))

        wrapped.append(complete)
    return ScriptedModel(actions=wrapped)


def test_completed_sqlite_team_checkpoint_replays_without_role_generation(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    first_model = role_model([plan(), retrieve(advisory), ready(), candidate, covered()])
    with database() as session:
        first = run_agent_team(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=first_model,
            checkpoint_key="completed-team",
        )
    assert first["generation"]["status"] == "completed", first
    assert first_model.position == 5
    second_model = role_model([])
    with database() as session:
        second = run_agent_team(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=second_model,
            checkpoint_key="completed-team",
            checkpoint_resume_required=True,
        )
    assert second["generation"]["status"] == "completed", second
    assert second_model.position == 0
    assert second["answer"] == first["answer"]
    assert second["agent"]["checkpoint_resumed"] is True
    assert second["agent"]["attempted_tool_calls"] == 1
    assert len(second["agent"]["role_calls"]) == 5


def test_research_receipt_before_graph_checkpoint_is_free_on_resume(
    database, store, settings, advisory, monkeypatch
):
    from zhidu.agent_roles import RoleRunner

    ingest(database, store, fixture_advisory(advisory))
    original = RoleRunner.invoke
    interrupted = False

    def crash_after_receipt(self, role, payload, schema, *, call_id):
        nonlocal interrupted
        response = original(self, role, payload, schema, call_id=call_id)
        if call_id == "research:0:1" and not interrupted:
            interrupted = True
            raise RuntimeError("simulated_graph_interruption_after_durable_research_receipt")
        return response

    monkeypatch.setattr(RoleRunner, "invoke", crash_after_receipt)
    first_model = role_model([plan(), retrieve(advisory), ready()])
    with database() as session:
        first = run_agent_team(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=first_model,
            checkpoint_key="interrupted-team",
        )
    assert first["generation"]["status"] == "fallback"
    assert first_model.position == 3
    second_model = role_model([candidate, covered()])
    with database() as session:
        second = run_agent_team(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=second_model,
            checkpoint_key="interrupted-team",
            checkpoint_resume_required=True,
        )
    assert second["generation"]["status"] == "completed", (
        second["generation"].get("reason"),
        second["generation"].get("error_type"),
    )
    assert second_model.position == 2
    assert len(second["agent"]["role_calls"]) == 5
    assert second["agent"]["attempted_tool_calls"] == 1
    assert second["tool_calls"] == 1


def test_stale_source_blocks_checkpoint_without_new_model_request(
    database, store, settings, advisory
):
    from zhidu.models import SearchChunk

    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        first = run_agent_team(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=role_model([plan(), retrieve(advisory), ready(), candidate, covered()]),
            checkpoint_key="stale-team",
        )
    assert first["generation"]["status"] == "completed", first
    chunk_id = first["citations"][0]["chunk_id"]
    with database.begin() as session:
        row = session.get(SearchChunk, chunk_id)
        row.text += "tampered"
    second_model = role_model([])
    with database() as session:
        second = run_agent_team(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=second_model,
            checkpoint_key="stale-team",
            checkpoint_resume_required=True,
        )
    assert second["generation"]["reason"] == "checkpoint_evidence_stale", second
    assert second_model.position == 0


def test_unknown_research_receipt_is_blocked_without_blind_retry(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))

    def unknown(_payload):
        raise TimeoutError("simulated_provider_outcome_unknown")

    first_model = role_model([plan(), retrieve(advisory), unknown])
    with database() as session:
        first = run_agent_team(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=first_model,
            checkpoint_key="unknown-team",
        )
    assert first["generation"]["status"] == "fallback"
    assert first_model.position == 3
    second_model = role_model([])
    with database() as session:
        second = run_agent_team(
            session,
            store,
            settings,
            body(advisory),
            None,
            model=second_model,
            checkpoint_key="unknown-team",
            checkpoint_resume_required=True,
        )
    assert second["generation"]["reason"] == "model_request_outcome_unknown", second["generation"]
    assert second_model.position == 0
