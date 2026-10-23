"""Public P0 receipts through the actual product graph and checkpoint replay."""

from test_agent_team import body, candidate, covered, plan, ready, role_model
from test_member_a_rag_context import fixture_advisory, ingest

from zhidu.agent_team import research_progress, run_agent_team
from zhidu.langchain_tools import SourceRuntime, ToolSession


def test_product_batch_receipt_has_question_and_final_prose_anchors(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    settings = settings.model_copy(update={"agent_max_model_calls": 8})
    request = body(advisory)
    with database() as session:
        tools = ToolSession(SourceRuntime(session, store, settings, None), request, None)
        _, initial = tools.invoke(
            "retrieve", {"query": advisory["ghsa_id"], "mode": "lexical", "limit": 1}
        )
        event_id = initial["result"]["items"][0]["citation"]["event_id"]
        batch = {
            "action": "batch",
            "task_ids": ["patch"],
            "note": "分读修复正文和版本字段",
            "requests": [
                {
                    "tool_name": "read_fields",
                    "arguments": {
                        "event_id": event_id,
                        "fields": ["description"],
                        "contains": "Patches",
                    },
                    "task_ids": ["patch"],
                },
                {
                    "tool_name": "read_fields",
                    "arguments": {"event_id": event_id, "fields": ["packages"]},
                    "task_ids": ["patch"],
                },
            ],
        }
        result = run_agent_team(
            session,
            store,
            settings,
            request,
            None,
            prepared_tools=tools,
            model=role_model(
                [plan(), batch, ready(), lambda p: candidate(p, choose_patch=True), covered()]
            ),
        )
    assert result["generation"]["status"] == "completed", (
        result["generation"].get("reason"),
        result["generation"].get("error_type"),
    )
    assert result["question_coverage"]["complete"] is True
    ledger = result["requirement_ledger"]
    task = ledger["tasks"][0]
    assert task["question_spans"][0]["quote"] == request.question
    span = task["answer_spans"][0]
    text = result["generated_claims"][span["statement_index"] - 1]["text"]
    assert text[span["start"] : span["end"]] == span["text"]
    assert result["claim_support"][0]["retained"] is True
    receipt = result["batch_tool_calls"][0]
    assert receipt["action"] == "batch" and receipt["decision_completed"] is True
    assert len(receipt["admission"]["admitted"]) == 2
    assert [child["actual_tool_attempts"] for child in receipt["tool_observations"]] == [1, 1]
    assert result["agent"]["attempted_tool_calls"] == 3
    assert result["agent"]["tool_output_chars"] <= settings.agent_max_output_chars
    assert result["evidence_novelty"]["semantic_support_verified"] is False
    assert result["evidence_novelty"]["quality_gain_proven"] is False


def test_completed_graph_replay_preserves_logical_gain_but_has_zero_new_work(
    database, store, settings, advisory
):
    from test_agent_team import retrieve

    ingest(database, store, fixture_advisory(advisory))
    request = body(advisory)
    with database() as session:
        first = run_agent_team(
            session,
            store,
            settings,
            request,
            None,
            model=role_model([plan(), retrieve(advisory), ready(), candidate, covered()]),
            checkpoint_key="p0-completed-graph",
        )
    with database() as session:
        replay = run_agent_team(
            session,
            store,
            settings,
            request,
            None,
            model=role_model([]),
            checkpoint_key="p0-completed-graph",
            checkpoint_resume_required=True,
        )
    assert first["generation"]["status"] == replay["generation"]["status"] == "completed"
    assert replay["requirement_ledger"] == first["requirement_ledger"]
    assert replay["evidence_novelty"]["logical"] == first["evidence_novelty"]["logical"]
    assert replay["evidence_novelty"]["current_attempt"]["new_source_chars"] == 0
    children = [
        child for entry in replay["batch_tool_calls"] for child in entry["tool_observations"]
    ]
    assert children and all(
        child["replayed"] and child["actual_tool_attempts"] == 0 for child in children
    )


def test_unknown_or_unrecorded_novelty_is_never_reported_as_confirmed_zero():
    assert research_progress([])["logical"] == {"status": "unrecorded", "new_source_chars": None}
    result = research_progress(
        [
            {
                "call_id": "x",
                "novelty": {
                    "status": "unknown",
                    "new_source_chars": None,
                    "known_new_source_chars": 23,
                },
            }
        ]
    )
    assert result["logical"] == {
        "status": "unknown",
        "new_source_chars": None,
        "known_new_source_chars": 23,
    }
    assert result["current_attempt"]["status"] == "unrecorded"


def test_resume_after_compose_receipt_does_not_count_completed_research_again(
    database, store, settings, advisory, monkeypatch
):
    from test_agent_team import retrieve

    from zhidu.agent_roles import RoleRunner

    ingest(database, store, fixture_advisory(advisory))
    original = RoleRunner.invoke
    interrupted = False

    def crash_after_composition(self, role, payload, schema, *, call_id):
        nonlocal interrupted
        response = original(self, role, payload, schema, call_id=call_id)
        if call_id == "compose:0" and not interrupted:
            interrupted = True
            raise RuntimeError("known_composition_receipt_before_checkpoint")
        return response

    monkeypatch.setattr(RoleRunner, "invoke", crash_after_composition)
    request = body(advisory)
    with database() as session:
        first = run_agent_team(
            session,
            store,
            settings,
            request,
            None,
            model=role_model([plan(), retrieve(advisory), ready(), candidate]),
            checkpoint_key="p0-compose-interruption",
        )
    assert first["generation"]["status"] == "fallback"
    assert first["batch_tool_calls"][0]["tool_observations"][0]["actual_tool_attempts"] == 1
    model = role_model([covered()])
    with database() as session:
        resumed = run_agent_team(
            session,
            store,
            settings,
            request,
            None,
            model=model,
            checkpoint_key="p0-compose-interruption",
            checkpoint_resume_required=True,
        )
    assert resumed["generation"]["status"] == "completed", resumed["generation"]
    assert model.position == 1
    assert resumed["evidence_novelty"]["current_attempt"]["new_source_chars"] == 0
    children = [
        child for entry in resumed["batch_tool_calls"] for child in entry["tool_observations"]
    ]
    assert children and all(
        child["replayed"] and child["actual_tool_attempts"] == 0 for child in children
    )


def test_full_tool_budget_still_allows_missing_prose_to_be_rewritten(
    database, store, settings, advisory
):
    from sqlalchemy import select
    from test_agent_team import missing

    from zhidu.models import IntelEvent

    ingest(database, store, fixture_advisory(advisory))
    settings = settings.model_copy(update={"agent_max_model_calls": 8})
    request = body(advisory)
    with database() as session:
        event_id = session.scalar(select(IntelEvent.id))
        tools = ToolSession(
            SourceRuntime(session, store, settings, None, max_calls=2), request, None
        )
        tools.invoke("retrieve", {"query": advisory["ghsa_id"], "mode": "lexical", "limit": 1})
        tools.invoke(
            "read_fields", {"event_id": event_id, "fields": ["description"], "contains": "Patches"}
        )

        def incomplete(payload):
            answer = candidate(payload, choose_patch=True)
            answer["statements"][0]["text"] = "公告给出了修复建议。"
            return answer

        review = missing()
        review["claim_support"][0].update(
            status="supported", reason="自身引文支持有修复建议，但正文尚未给版本"
        )
        model = role_model(
            [plan(), incomplete, review, lambda p: candidate(p, choose_patch=True), covered()]
        )
        result = run_agent_team(
            session, store, settings, request, None, prepared_tools=tools, model=model
        )
    assert result["generation"]["status"] == "completed", result["generation"]
    assert result["answer_class"] == "evidence"
    assert result["agent"]["attempted_tool_calls"] == 2
    assert result["agent"]["supplement_cycles"] == 1
    assert [call["role"] for call in result["agent"]["role_calls"]] == [
        "planner",
        "composer",
        "verifier",
        "composer",
        "verifier",
    ]
    assert result["evidence_novelty"]["logical"]["status"] == "unrecorded"


def test_quote_reviewer_knows_field_boundary_without_receiving_unquoted_body():
    from test_agent_requirements import EVIDENCE, answer, task_plan

    from zhidu.agent_team import verifier_packet

    evidence = {key: dict(value) for key, value in EVIDENCE.items()}
    candidate = answer()
    handle = candidate.statements[0].evidence[0].evidence_id
    evidence[handle].update(
        start=0,
        end=len(evidence[handle]["text"]),
        span_provenance={"source_field_chars": len(evidence[handle]["text"]) + 300},
    )
    packet = verifier_packet(
        "说明应用暴露条件。", task_plan("说明应用暴露条件。"), candidate, evidence
    )
    quote = packet["statements"][0]["quotes"][0]
    assert quote["quote_covers_entire_field"] is False
    assert quote["source_field_chars"] == quote["end"] + 300
    assert quote["quote"] == evidence[handle]["text"]
