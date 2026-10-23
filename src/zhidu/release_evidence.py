"""Public, dated evaluation summaries shipped with the project release."""

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


class EvidenceSource(BaseModel):
    file: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def relative_public_path(self):
        path = Path(self.file)
        if path.is_absolute() or ".." in path.parts or not self.file.startswith("evidence/"):
            raise ValueError("Evidence references must be relative release paths")
        return self


class GoldMethod(BaseModel):
    method: Literal["project_ai_review"]
    records: int = Field(ge=0)
    independent: Literal[False]
    human_review: Literal[False]


class EnrichmentResult(BaseModel):
    evaluated_on: str
    records: int = Field(ge=1)
    facts: int = Field(ge=1)
    precision: float = Field(ge=0, le=1, allow_inf_nan=False)
    recall: float = Field(ge=0, le=1, allow_inf_nan=False)
    independent: Literal[False]
    scope: Literal["frozen_source_fact_regression"]


class ComparisonMode(BaseModel):
    key: str
    label: str
    strict_passes: int = Field(ge=0)
    strict_accuracy: float = Field(ge=0, le=1, allow_inf_nan=False)
    fact_recall: float = Field(ge=0, le=1, allow_inf_nan=False)
    mean_elapsed_ms: float = Field(ge=0, allow_inf_nan=False)


class ComplexQA(BaseModel):
    evaluated_on: str
    cases: int = Field(ge=1)
    modes: list[ComparisonMode] = Field(min_length=1)
    agent_gain_proven: Literal[False]

    @model_validator(mode="after")
    def check_denominators(self):
        keys = [mode.key for mode in self.modes]
        if len(set(keys)) != len(keys):
            raise ValueError("Duplicate comparison modes")
        for mode in self.modes:
            if (
                mode.strict_passes > self.cases
                or abs(mode.strict_accuracy - mode.strict_passes / self.cases) > 1e-9
            ):
                raise ValueError("Inconsistent strict accuracy denominator")
        return self


class LatestTrial(BaseModel):
    evaluated_on: str
    status: Literal["planner_timeout"]
    unknown_calls: int = Field(ge=1)
    new_answers: Literal[0]
    total_tokens: None
    total_cost: None


class SubmissionEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["submission-evidence-v1"]
    release: str
    as_of: str
    gold: GoldMethod
    enrichment: EnrichmentResult
    complex_qa: ComplexQA
    latest_trial: LatestTrial
    sources: list[EvidenceSource] = Field(min_length=1)


def public_release_evidence(path: Path) -> dict:
    try:
        content = path.read_bytes()
        if len(content) > 100_000:
            raise ValueError("Oversized evidence summary")
        evidence = SubmissionEvidence.model_validate_json(content)
        return {"status": "available", **evidence.model_dump()}
    except FileNotFoundError:
        return {"status": "unavailable", "reason": "missing"}
    except (OSError, ValueError, ValidationError, json.JSONDecodeError):
        return {"status": "unavailable", "reason": "invalid"}
