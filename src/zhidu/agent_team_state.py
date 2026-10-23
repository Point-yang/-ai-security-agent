"""JSON-only plans, tool decisions and quote-only review for the role graph."""

from typing import Annotated, Literal, TypedDict

from pydantic import BaseModel, ConfigDict, Field, model_validator

TASK_ID_MAX_LENGTH = 64


class StrictRoleOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class QuestionSpan(StrictRoleOutput):
    quote: str = Field(min_length=1, max_length=1000)
    start: int | None = Field(default=None, ge=0)
    end: int | None = Field(default=None, ge=1)


class AtomicTask(StrictRoleOutput):
    task_id: str = Field(min_length=1, max_length=TASK_ID_MAX_LENGTH, pattern=r"^[a-zA-Z0-9_-]+$")
    requirement: str = Field(min_length=1, max_length=350)
    source_ids: list[str] = Field(max_length=4)
    fields: list[str] = Field(max_length=4)
    contains: str | None = Field(default=None, max_length=120)
    keywords: list[str] = Field(max_length=6)
    question_spans: list[QuestionSpan] = Field(min_length=1, max_length=4)
    source_policy: Literal["any", "each", "compare"]
    coverage_scope: Literal["facts", "complete_context"] = Field(
        default="facts",
        description="Use complete_context when the question requires a complete condition list or exhaustive enumeration; physical context coverage is checked separately from semantic correctness.",
    )
    required_elements: list[Annotated[str, Field(min_length=1, max_length=350)]] = Field(
        min_length=1, max_length=8
    )


class TaskPlan(StrictRoleOutput):
    tasks: list[AtomicTask] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def unique_tasks(self):
        ids = [task.task_id for task in self.tasks]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate_task_id")
        return self


class ResearchRequest(StrictRoleOutput):
    tool_name: Literal[
        "retrieve",
        "event_details",
        "read_fields",
        "compare_sources",
        "asset_exposure",
        "verify_evidence",
    ]
    arguments: dict
    task_ids: list[str] = Field(max_length=8)


class ResearchTaskRead(StrictRoleOutput):
    """Research intent only; referenced IDs do not prove semantic coverage."""

    task_id: str = Field(min_length=1, max_length=TASK_ID_MAX_LENGTH)
    evidence_ids: list[Annotated[str, Field(min_length=1, max_length=64)]] = Field(
        default_factory=list, max_length=8
    )
    context_ids: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(
        default_factory=list, max_length=8
    )
    note: str = Field(default="", max_length=120)


class ResearchDecision(StrictRoleOutput):
    action: Literal["tool", "batch", "ready", "read_plan"]
    tool_name: (
        Literal[
            "retrieve",
            "event_details",
            "read_fields",
            "compare_sources",
            "asset_exposure",
            "verify_evidence",
        ]
        | None
    ) = None
    arguments: dict = Field(default_factory=dict)
    task_ids: list[str] = Field(max_length=8)
    note: str = Field(max_length=350)
    requests: list[ResearchRequest] = Field(default_factory=list, max_length=3)
    task_reads: list[ResearchTaskRead] = Field(
        default_factory=list,
        max_length=8,
        description="Per-task research intent using current evidence/context IDs. Server validates membership, duplicates and full plan mapping before execution; this is not semantic coverage.",
    )

    @model_validator(mode="after")
    def valid_action(self):
        if self.action == "tool" and self.tool_name is None:
            raise ValueError("tool_name_required")
        if self.action == "tool" and self.requests:
            raise ValueError("single_tool_cannot_contain_batch")
        if self.action == "batch" and (
            not self.requests or self.tool_name is not None or self.arguments
        ):
            raise ValueError("batch_requires_requests_only")
        if self.action == "ready" and (
            self.tool_name is not None or self.arguments or self.requests
        ):
            raise ValueError("ready_cannot_call_tool")
        if self.action == "read_plan" and (
            self.tool_name is not None or self.arguments or self.requests
        ):
            raise ValueError("read_plan_cannot_mix_tool_calls")
        return self


class AnswerSpan(StrictRoleOutput):
    statement_index: int = Field(ge=1, le=8)
    text: str = Field(min_length=1, max_length=1400)
    start: int | None = Field(default=None, ge=0)
    end: int | None = Field(default=None, ge=1)


class ElementCoverage(StrictRoleOutput):
    element: str = Field(min_length=1, max_length=350)
    status: Literal["covered", "partial", "missing"]
    answer_spans: list[AnswerSpan] = Field(default_factory=list, max_length=8)
    answer_span_indices: list[int] = Field(default_factory=list, max_length=8)
    semantic_status: Literal["covered", "partial", "missing"] | None = None

    @model_validator(mode="after")
    def unique_span_format(self):
        if self.answer_spans and self.answer_span_indices:
            raise ValueError("element_cannot_mix_span_formats")
        return self


class TaskCoverage(StrictRoleOutput):
    task_id: str = Field(min_length=1, max_length=TASK_ID_MAX_LENGTH)
    status: Literal["covered", "partial", "missing"]
    statement_indices: list[int] = Field(max_length=8)
    note: str = Field(max_length=350)
    answer_spans: list[AnswerSpan] = Field(max_length=8)
    element_coverage: list[ElementCoverage] = Field(min_length=1, max_length=8)
    semantic_status: Literal["covered", "partial", "missing"] | None = None
    coverage_blockers: list[Literal["answer", "source", "context", "unsupported"]] = Field(
        default_factory=list, max_length=4
    )


class UnsupportedStatement(StrictRoleOutput):
    statement_index: int = Field(ge=1, le=8)
    reason: str = Field(min_length=1, max_length=350)


class ClaimSupport(StrictRoleOutput):
    statement_index: int = Field(ge=1, le=8)
    status: Literal["supported", "unsupported"]
    reason: str = Field(min_length=1, max_length=350)


class UnplannedRequirement(StrictRoleOutput):
    requirement: str = Field(min_length=1, max_length=350)
    question_span: QuestionSpan
    reason: str = Field(min_length=1, max_length=350)


class ResearchGap(StrictRoleOutput):
    task_id: str = Field(min_length=1, max_length=TASK_ID_MAX_LENGTH)
    requirement: str = Field(min_length=1, max_length=350)
    source_id: str | None = Field(default=None, max_length=80)
    event_id: str | None = Field(default=None, min_length=36, max_length=36)
    field: str | None = Field(default=None, max_length=100)
    contains: str | None = Field(default=None, max_length=120)
    query: str | None = Field(default=None, max_length=200)
    context: Literal["excerpt", "section"] | None = None
    kind: Literal["answer", "source", "context"] = "answer"


class ResearchGapDecision(ResearchGap):
    """Optional review explanation stays in the wire audit, never tool input."""

    reason: str | None = Field(default=None, max_length=350)


class VerifierOutput(StrictRoleOutput):
    coverage: list[TaskCoverage] = Field(min_length=1, max_length=8)
    claim_support: list[ClaimSupport] = Field(max_length=8)
    unplanned_requirements: list[UnplannedRequirement] = Field(max_length=8)
    gaps: list[ResearchGap] = Field(max_length=8)
    anchor_binding: "AnswerAnchorBinding | None" = None

    @property
    def unsupported(self):
        """Internal compatibility view; task incompleteness never creates it."""
        return [
            UnsupportedStatement(statement_index=item.statement_index, reason=item.reason)
            for item in self.claim_support
            if item.status == "unsupported"
        ]


class AnswerAnchorBinding(StrictRoleOutput):
    question_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    scope_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    statement_anchor_ids: dict[str, str]


class AnchorElementCoverage(StrictRoleOutput):
    element: str = Field(min_length=1, max_length=350)
    status: Literal["covered", "partial", "missing"]
    anchor_ids: list[str] = Field(max_length=8)


class AnchorTaskCoverage(StrictRoleOutput):
    task_id: str = Field(min_length=1, max_length=TASK_ID_MAX_LENGTH)
    status: Literal["covered", "partial", "missing"]
    anchor_ids: list[str] = Field(max_length=8)
    note: str = Field(max_length=350)
    element_coverage: list[AnchorElementCoverage] = Field(min_length=1, max_length=8)


class UnplannedRequirementDecision(StrictRoleOutput):
    requirement: str = Field(min_length=1, max_length=350)
    question_quote: str = Field(min_length=1, max_length=1000)
    reason: str = Field(min_length=1, max_length=350)


class VerifierDecision(StrictRoleOutput):
    """Only server anchor IDs may locate candidate prose in model output."""

    coverage: list[AnchorTaskCoverage] = Field(min_length=1, max_length=8)
    claim_support: list[ClaimSupport] = Field(max_length=8)
    unplanned_requirements: list[UnplannedRequirementDecision] = Field(max_length=8)
    gaps: list[ResearchGapDecision] = Field(max_length=8)


VerifierOutput.model_rebuild()


class TeamState(TypedDict, total=False):
    plan: dict
    candidate: dict
    verification: dict
    verification_decision: dict
    cycle: int
    research_trace: list[dict]
    research_input: dict
    tools_scope: dict
    status: str
