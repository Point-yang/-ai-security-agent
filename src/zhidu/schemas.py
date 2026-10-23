from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator


class PackageInput(BaseModel):
    ecosystem: str = Field(min_length=1, max_length=50)
    name: str = Field(min_length=1, max_length=500)


class VulnerabilityInput(BaseModel):
    package: PackageInput
    vulnerable_version_range: str = Field(min_length=1, max_length=5000)
    first_patched_version: str | None = Field(default=None, max_length=200)


class AdvisoryInput(BaseModel):
    model_config = ConfigDict(extra="ignore")
    ghsa_id: str = Field(pattern=r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
    cve_id: str | None = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,}$")
    summary: str = Field(min_length=1, max_length=5000)
    description: str | None = Field(default=None, max_length=500000)
    html_url: HttpUrl
    severity: Literal["unknown", "low", "medium", "high", "critical"] = "unknown"
    published_at: datetime
    updated_at: datetime
    withdrawn_at: datetime | None = None
    vulnerabilities: list[VulnerabilityInput] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    cvss: dict | None = None
    cvss_severities: dict | None = None
    cwes: list[dict] = Field(default_factory=list)

    @field_validator("published_at", "updated_at", "withdrawn_at")
    @classmethod
    def require_timezone(cls, value):
        if value is not None:
            if value.tzinfo is None:
                raise ValueError("timezone is required")
            return value.astimezone(UTC)
        return value


class AnnotationPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: int = Field(ge=0)
    review_status: Literal["unreviewed", "in_review", "verified", "needs_evidence"]
    analyst_note: str = Field(max_length=10000)


class CycloneDXImport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_name: str = Field(min_length=1, max_length=300)
    environment: str = Field(default="unknown", min_length=1, max_length=50)
    criticality: Literal["low", "medium", "high", "critical"] = "medium"
    sbom: dict


class ComparisonReviewPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: int = Field(ge=0)
    review_status: Literal["unreviewed", "acknowledged", "needs_evidence"]
    analyst_note: str = Field(max_length=10000)


class ConversationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(default="安全情报研究会话", min_length=1, max_length=300)
    asset_id: str | None = Field(default=None, max_length=36)

    @field_validator("title")
    @classmethod
    def title_not_blank(cls, value):
        if not value.strip():
            raise ValueError("title must contain non-whitespace characters")
        return value.strip()


class ConversationTurnCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=1000)
    query: str | None = Field(default=None, max_length=200)
    pool: Literal["formal", "candidate"] = "formal"
    origin: Literal["live", "replay"] = "live"
    asset_id: str | None = Field(default=None, max_length=36)
    event_id: str | None = Field(default=None, max_length=36)
    limit: int = Field(default=5, ge=1, le=10)

    @field_validator("question")
    @classmethod
    def conversation_question_not_blank(cls, value):
        if not value.strip():
            raise ValueError("question must contain non-whitespace characters")
        return value.strip()

    @field_validator("query")
    @classmethod
    def conversation_query_not_blank(cls, value):
        if value is not None and not value.strip():
            raise ValueError("query must contain non-whitespace characters")
        return value.strip() if value else value


class EventSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    source_id: str
    external_id: str
    kind: str
    title: str
    severity: str
    published_at: datetime
    source_updated_at: datetime
    withdrawn_at: datetime | None
    first_seen_at: datetime
    last_seen_at: datetime
    revision: int
    review_status: str
    annotation_version: int


class EventList(BaseModel):
    total: int
    items: list[EventSummary]
    limit: int
    offset: int


class RevisionView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    event_id: str
    number: int
    raw_document_id: str
    record_pointer: str
    fingerprint: str
    disposition: str
    collected_at: datetime
    source_updated_at: datetime
    normalized: dict
    evidence: list[dict]


class EventDetail(EventSummary):
    triage: dict | None = None
    enrichment: dict | None = None
    description: str
    source_url: str
    analyst_note: str
    aliases: list[str]
    packages: list[dict]
    current_revision: RevisionView
