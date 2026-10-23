"""Descriptive task identities survive plan/review/gap round trips unchanged."""

import json

import httpx
import pytest
from pydantic import ValidationError

from zhidu.agent_team_state import AtomicTask, ResearchGap, TaskCoverage, TaskPlan


@pytest.mark.parametrize(
    "task_id", ["arbitrary_deserialization", "credential_ssrf_boundary_conditions", "a" * 64]
)
def test_descriptive_task_identity_is_identical_across_roles(task_id):
    task = AtomicTask(
        task_id=task_id,
        requirement="问题要求的来源边界",
        source_ids=["nvd"],
        fields=["description"],
        keywords=[],
        question_spans=[{"quote": "问题要求的来源边界"}],
        source_policy="any",
        required_elements=["来源边界"],
    )
    plan = TaskPlan.model_validate({"tasks": [task.model_dump()]})
    coverage = TaskCoverage(
        task_id=task_id,
        status="missing",
        statement_indices=[],
        note="本轮尚缺证据",
        answer_spans=[],
        element_coverage=[{"element": "来源边界", "status": "missing", "answer_spans": []}],
    )
    gap = ResearchGap(task_id=task_id, requirement=task.requirement)
    assert plan.tasks[0].task_id == coverage.task_id == gap.task_id == task_id
    assert TaskPlan.model_validate_json(plan.model_dump_json()).tasks[0].task_id == task_id


@pytest.mark.parametrize("task_id", ["", "a" * 65, "task with spaces", "中文任务", "../../task"])
def test_identity_length_and_identifier_syntax_remain_bounded(task_id):
    with pytest.raises(ValidationError):
        AtomicTask(
            task_id=task_id,
            requirement="来源事实",
            source_ids=[],
            fields=[],
            keywords=[],
            question_spans=[{"quote": "来源事实"}],
            source_policy="any",
            required_elements=["来源事实"],
        )


def test_descriptive_identifiers_cannot_bypass_duplicate_task_check():
    task = {
        "task_id": "arbitrary_deserialization",
        "requirement": "来源事实",
        "source_ids": [],
        "fields": [],
        "keywords": [],
        "question_spans": [{"quote": "来源事实"}],
        "source_policy": "any",
        "required_elements": ["来源事实"],
    }
    with pytest.raises(ValidationError, match="duplicate_task_id"):
        TaskPlan.model_validate({"tasks": [task, task]})


def test_invalid_role_receipt_records_only_diagnostic_type_and_location(
    database, store, settings, tmp_path
):
    pytest.importorskip("langchain_deepseek")
    from zhidu.agent_roles import RoleError, RoleRunner
    from zhidu.langchain_tools import SourceRuntime, ToolSession
    from zhidu.rag import RagRequest

    requests = []
    marker = "private-invalid-value-must-not-be-in-audit"

    def handle(request):
        requests.append(1)
        task = {
            "task_id": marker + "x" * 65,
            "requirement": "来源事实",
            "source_ids": [],
            "fields": [],
            "keywords": [],
            "question_spans": [{"quote": "来源事实"}],
            "source_policy": "any",
            "required_elements": ["来源事实"],
        }
        return httpx.Response(
            200,
            json={
                "id": "invalid-role-sdk",
                "object": "chat.completion",
                "created": 1791806400,
                "model": "deepseek-flash",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": json.dumps({"tasks": [task]})},
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            },
        )

    cloud = type(settings)(
        _env_file=None,
        **(
            settings.model_dump()
            | {
                "deepseek_api_key": "mock-role-diagnostic-secret",
                "agent_checkpoint_path": tmp_path / "diagnostic.sqlite",
            }
        ),
    )
    with database() as session:
        runtime = SourceRuntime(session, store, cloud, None)
        tools = ToolSession(runtime, RagRequest(question="来源事实"), None)
        with RoleRunner(
            cloud,
            runtime,
            tools,
            transport=httpx.MockTransport(handle),
            checkpoint_key="diagnostic",
        ) as runner:
            for _ in range(2):
                with pytest.raises(RoleError, match="invalid_role_response"):
                    runner.invoke(
                        "planner", {"question": "来源事实"}, TaskPlan, call_id="planner:0"
                    )
            receipt = runner.calls()[0]
            assert receipt["validation_errors"] == [
                {"type": "string_too_long", "location": ["tasks", 0, "task_id"]}
            ]
            assert marker not in json.dumps(receipt)
            assert runner.external_requests == 1
    assert requests == [1]
