"""Source-bound candidate answers; source excerpts are never model-authored."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.json_schema import SkipJsonSchema


class EvidenceRef(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    evidence_id: str = Field(min_length=24, max_length=64)
    # Older clients may still send zero. New model schemas expose only the
    # evidence handle; the server supplies the whole verified source span.
    quote_index: SkipJsonSchema[Literal[0]] = 0


class AgentClaim(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: str = Field(min_length=1, max_length=1400)
    evidence: list[EvidenceRef] = Field(min_length=1, max_length=5)


class AgentAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    answer_class: Literal["evidence", "partial", "refused", "clarification"]
    statements: list[AgentClaim] = Field(max_length=8)
    required_facts: list[str] = Field(
        min_length=1,
        max_length=64,
        description="Labels for the user's task subrequirements, up to 8 tasks × 8 elements. These are requirement labels, not additional technical conclusions; statements remain limited to 8.",
    )
    missing_facts: list[str] = Field(
        max_length=64,
        description="Labels for still-unanswered user subrequirements, not additional factual claims. Up to 8 tasks × 8 elements; missing labels do not turn absent evidence into a source-absence fact.",
    )
    limitations: list[str] = Field(max_length=6)
    message: str = Field(max_length=800)
