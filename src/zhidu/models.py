from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


def now_utc():
    return datetime.now(UTC)


def new_id():
    return str(uuid4())


class UTCDateTime(TypeDecorator):
    """SQLite and PostgreSQL return the same timezone-aware API timestamps."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            if value.tzinfo is None:
                raise ValueError("timestamp must include timezone")
            return value.astimezone(UTC)
        return None

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class Base(DeclarativeBase):
    pass


class Source(Base):
    __tablename__ = "sources"
    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(50))
    base_url: Mapped[str] = mapped_column(String(500))


class RawDocument(Base):
    __tablename__ = "raw_documents"
    __table_args__ = (UniqueConstraint("source_id", "url", "sha256", "origin"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.id"))
    url: Mapped[str] = mapped_column(String(2000))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    media_type: Mapped[str] = mapped_column(String(100), default="application/json")
    origin: Mapped[str] = mapped_column(String(20))  # live / replay
    first_fetched_at: Mapped[datetime] = mapped_column(UTCDateTime())
    last_fetched_at: Mapped[datetime] = mapped_column(UTCDateTime())


class CatalogItem(Base):
    __tablename__ = "catalog_items"
    __table_args__ = (UniqueConstraint("source_id", "external_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.id"), index=True)
    external_id: Mapped[str] = mapped_column(String(200), index=True)
    kind: Mapped[str] = mapped_column(String(40))
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    source_url: Mapped[str] = mapped_column(String(2000))
    published_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    source_updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime())
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime())
    raw_document_id: Mapped[str] = mapped_column(ForeignKey("raw_documents.id"))
    evidence_locator: Mapped[str] = mapped_column(Text)
    normalized: Mapped[dict] = mapped_column(JSON)
    fingerprint: Mapped[str] = mapped_column(String(64))
    revision: Mapped[int] = mapped_column(Integer, default=1)


class CatalogRevision(Base):
    __tablename__ = "catalog_revisions"
    __table_args__ = (UniqueConstraint("item_id", "number"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    item_id: Mapped[str] = mapped_column(ForeignKey("catalog_items.id"), index=True)
    number: Mapped[int] = mapped_column(Integer)
    raw_document_id: Mapped[str] = mapped_column(ForeignKey("raw_documents.id"))
    evidence_locator: Mapped[str] = mapped_column(Text)
    normalized: Mapped[dict] = mapped_column(JSON)
    fingerprint: Mapped[str] = mapped_column(String(64))
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime())


class IntelEvent(Base):
    __tablename__ = "events"
    __table_args__ = (UniqueConstraint("source_id", "external_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.id"))
    external_id: Mapped[str] = mapped_column(String(100), index=True)
    kind: Mapped[str] = mapped_column(String(30), default="vulnerability")
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20))
    source_url: Mapped[str] = mapped_column(String(2000))
    published_at: Mapped[datetime] = mapped_column(UTCDateTime())
    source_updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    withdrawn_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime())
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime())
    revision: Mapped[int] = mapped_column(Integer, default=1)
    current_fingerprint: Mapped[str] = mapped_column(String(64))
    review_status: Mapped[str] = mapped_column(String(30), default="unreviewed")
    analyst_note: Mapped[str] = mapped_column(Text, default="")
    annotation_version: Mapped[int] = mapped_column(Integer, default=0)


class EventAlias(Base):
    __tablename__ = "event_aliases"
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id"), primary_key=True)
    value: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)


class AffectedPackage(Base):
    __tablename__ = "affected_packages"
    __table_args__ = (Index("ix_package_lookup", "ecosystem", "name"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id"), index=True)
    ecosystem: Mapped[str] = mapped_column(String(50))
    name: Mapped[str] = mapped_column(String(500))
    vulnerable_range: Mapped[str] = mapped_column(Text)
    fixed_version: Mapped[str | None] = mapped_column(String(200))


class EventRevision(Base):
    __tablename__ = "event_revisions"
    __table_args__ = (UniqueConstraint("event_id", "number"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id"), index=True)
    number: Mapped[int] = mapped_column(Integer)
    raw_document_id: Mapped[str] = mapped_column(ForeignKey("raw_documents.id"))
    record_pointer: Mapped[str] = mapped_column(String(100))
    fingerprint: Mapped[str] = mapped_column(String(64))
    disposition: Mapped[str] = mapped_column(String(30))  # current / superseded / stale / conflict
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime())
    source_updated_at: Mapped[datetime] = mapped_column(UTCDateTime())
    normalized: Mapped[dict] = mapped_column(JSON)
    evidence: Mapped[list] = mapped_column(JSON)


class EventChange(Base):
    __tablename__ = "event_changes"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id"), index=True)
    change_type: Mapped[str] = mapped_column(String(30))
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)
    detail: Mapped[dict] = mapped_column(JSON)


class CollectionRun(Base):
    __tablename__ = "collection_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.id"))
    scope: Mapped[str] = mapped_column(String(600))
    status: Mapped[str] = mapped_column(String(30), default="running")
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)


class SyncState(Base):
    __tablename__ = "sync_states"
    scope: Mapped[str] = mapped_column(String(600), primary_key=True)
    watermark: Mapped[datetime] = mapped_column(UTCDateTime())


class EventTriage(Base):
    __tablename__ = "event_triage"
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id"), primary_key=True)
    label: Mapped[str] = mapped_column(String(30))
    category: Mapped[str] = mapped_column(String(50))
    rule_version: Mapped[str] = mapped_column(String(30))
    matches: Mapped[dict] = mapped_column(JSON)


class MonitorState(Base):
    __tablename__ = "monitor_states"
    target_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    config_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(30), default="pending")
    failures: Mapped[int] = mapped_column(Integer, default=0)
    next_run_at: Mapped[datetime] = mapped_column(UTCDateTime())
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    heartbeat_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), index=True)
    last_run_id: Mapped[str | None] = mapped_column(ForeignKey("collection_runs.id"))
    etag: Mapped[str | None] = mapped_column(Text)
    last_modified: Mapped[str | None] = mapped_column(Text)
    continuation: Mapped[dict | None] = mapped_column(JSON)


class SearchChunk(Base):
    __tablename__ = "search_chunks"
    __table_args__ = (
        Index("ix_search_chunk_pool", "pool", "origin", "withdrawn"),
        Index("ix_search_chunk_event_revision", "event_id", "revision_id"),
        Index("ix_search_chunk_filters", "source_id", "kind", "severity"),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id"), index=True)
    revision_id: Mapped[str] = mapped_column(ForeignKey("event_revisions.id"))
    revision_number: Mapped[int] = mapped_column(Integer)
    raw_document_id: Mapped[str] = mapped_column(ForeignKey("raw_documents.id"))
    source_id: Mapped[str] = mapped_column(String(50))
    kind: Mapped[str] = mapped_column(String(30))
    external_id: Mapped[str] = mapped_column(String(100))
    title: Mapped[str] = mapped_column(Text)
    field: Mapped[str] = mapped_column(String(50))
    text: Mapped[str] = mapped_column(Text)
    start: Mapped[int] = mapped_column(Integer)
    end: Mapped[int] = mapped_column(Integer)
    json_pointer: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    origin: Mapped[str] = mapped_column(String(20))
    verification: Mapped[str] = mapped_column(String(30), default="source_asserted")
    pool: Mapped[str] = mapped_column(String(30))
    ai_label: Mapped[str] = mapped_column(String(30))
    triage_rule_version: Mapped[str] = mapped_column(String(30))
    severity: Mapped[str] = mapped_column(String(20))
    withdrawn: Mapped[bool] = mapped_column(Boolean, default=False)
    term_list: Mapped[list] = mapped_column(JSON)
    indexed_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)


class SearchIndexState(Base):
    __tablename__ = "search_index_states"
    name: Mapped[str] = mapped_column(String(50), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(30))
    synced_at: Mapped[datetime] = mapped_column(UTCDateTime())
    event_count: Mapped[int] = mapped_column(Integer)
    chunk_count: Mapped[int] = mapped_column(Integer)
    pool_counts: Mapped[dict] = mapped_column(JSON)


class AnswerAudit(Base):
    __tablename__ = "answer_audits"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    question: Mapped[str] = mapped_column(Text)
    answer: Mapped[str] = mapped_column(Text)
    retrieval_query: Mapped[str] = mapped_column(Text)
    pool: Mapped[str] = mapped_column(String(30))
    model: Mapped[str] = mapped_column(String(100))
    prompt_version: Mapped[str] = mapped_column(String(100))
    policy_version: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(30))
    citations: Mapped[list] = mapped_column(JSON)
    constraints: Mapped[list] = mapped_column(JSON)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"))
    asset_context: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc, index=True)


class RetrievalEvaluation(Base):
    __tablename__ = "retrieval_evaluations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    suite_version: Mapped[str] = mapped_column(String(100))
    index_schema_version: Mapped[str] = mapped_column(String(30))
    run_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc, index=True)
    case_count: Mapped[int] = mapped_column(Integer)
    hit_rate_at_k: Mapped[float] = mapped_column(Float)
    citation_verifiable_rate: Mapped[float] = mapped_column(Float)
    hallucination_rate: Mapped[float] = mapped_column(Float)
    answerability_accuracy: Mapped[float | None] = mapped_column(Float)
    constraint_pass_rate: Mapped[float | None] = mapped_column(Float)
    details: Mapped[list] = mapped_column(JSON)


class EventEnrichment(Base):
    """Rebuildable structured facts derived from one immutable current revision."""

    __tablename__ = "event_enrichments"
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id"), primary_key=True)
    revision_id: Mapped[str] = mapped_column(ForeignKey("event_revisions.id"), index=True)
    schema_version: Mapped[str] = mapped_column(String(30))
    enriched_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)
    entities: Mapped[list] = mapped_column(JSON)
    version_ranges: Mapped[list] = mapped_column(JSON)
    cvss: Mapped[dict] = mapped_column(JSON)
    cpe_matches: Mapped[list] = mapped_column(JSON)
    quality_flags: Mapped[list] = mapped_column(JSON)
    provenance: Mapped[list] = mapped_column(JSON)


class EnrichmentState(Base):
    __tablename__ = "enrichment_states"
    name: Mapped[str] = mapped_column(String(50), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(30))
    synced_at: Mapped[datetime] = mapped_column(UTCDateTime())
    event_count: Mapped[int] = mapped_column(Integer)
    enriched_count: Mapped[int] = mapped_column(Integer)
    stats: Mapped[dict] = mapped_column(JSON)


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(300), unique=True)
    environment: Mapped[str] = mapped_column(String(50), default="unknown")
    criticality: Mapped[str] = mapped_column(String(30), default="medium")
    sbom_format: Mapped[str] = mapped_column(String(50), default="CycloneDX")
    sbom_version: Mapped[str | None] = mapped_column(String(30))
    sbom_sha256: Mapped[str] = mapped_column(String(64))
    imported_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)


class AssetComponent(Base):
    __tablename__ = "asset_components"
    __table_args__ = (Index("ix_asset_component_identity", "ecosystem", "name", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    ecosystem: Mapped[str] = mapped_column(String(50))
    name: Mapped[str] = mapped_column(String(500))
    version: Mapped[str] = mapped_column(String(200))
    purl: Mapped[str | None] = mapped_column(String(1000))
    cpe: Mapped[str | None] = mapped_column(String(1000))
    bom_ref: Mapped[str | None] = mapped_column(String(500))
    component_type: Mapped[str] = mapped_column(String(50), default="library")


class AssetExposure(Base):
    __tablename__ = "asset_exposures"
    __table_args__ = (
        UniqueConstraint("component_id", "event_id"),
        Index("ix_asset_exposure_status", "asset_id", "status"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    component_id: Mapped[str] = mapped_column(ForeignKey("asset_components.id"), index=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id"), index=True)
    revision_id: Mapped[str] = mapped_column(ForeignKey("event_revisions.id"))
    enrichment_schema_version: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30))
    match_method: Mapped[str] = mapped_column(String(50))
    reason: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list] = mapped_column(JSON)
    evaluated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)


class IntelligenceComparison(Base):
    __tablename__ = "intelligence_comparisons"
    __table_args__ = (UniqueConstraint("identifier", "field"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    identifier: Mapped[str] = mapped_column(String(100), index=True)
    field: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(30), index=True)
    observations: Mapped[list] = mapped_column(JSON)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    retired_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    review_status: Mapped[str] = mapped_column(String(30), default="unreviewed")
    analyst_note: Mapped[str] = mapped_column(Text, default="")
    annotation_version: Mapped[int] = mapped_column(Integer, default=0)
    reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    evaluated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)


class ComparisonReviewChange(Base):
    __tablename__ = "comparison_review_changes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    comparison_id: Mapped[str] = mapped_column(
        ForeignKey("intelligence_comparisons.id"), index=True
    )
    previous_version: Mapped[int] = mapped_column(Integer)
    annotation_version: Mapped[int] = mapped_column(Integer)
    review_status: Mapped[str] = mapped_column(String(30))
    analyst_note: Mapped[str] = mapped_column(Text)
    change_kind: Mapped[str] = mapped_column(String(40), default="manual_review")
    observations: Mapped[list | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)


class AssetEvaluation(Base):
    __tablename__ = "asset_evaluations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    suite_version: Mapped[str] = mapped_column(String(100))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    run_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc, index=True)
    case_count: Mapped[int] = mapped_column(Integer)
    status_accuracy: Mapped[float] = mapped_column(Float)
    evidence_verifiable_rate: Mapped[float] = mapped_column(Float)
    boundary_pass_rate: Mapped[float] = mapped_column(Float)
    details: Mapped[list] = mapped_column(JSON)


class Conversation(Base):
    __tablename__ = "conversations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(String(300))
    active_asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), index=True)
    state_version: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc, index=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc, index=True)


class ConversationMessage(Base):
    __tablename__ = "conversation_messages"
    __table_args__ = (UniqueConstraint("conversation_id", "sequence"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    conversation_id: Mapped[str] = mapped_column(ForeignKey("conversations.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    role: Mapped[str] = mapped_column(String(20))
    content: Mapped[str] = mapped_column(Text)
    request: Mapped[dict | None] = mapped_column(JSON)
    answer_status: Mapped[str | None] = mapped_column(String(30))
    explicit_asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"))
    effective_asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"))
    selected_event_ids: Mapped[list] = mapped_column(JSON, default=list)
    citations: Mapped[list] = mapped_column(JSON, default=list)
    constraints: Mapped[list] = mapped_column(JSON, default=list)
    answer_audit_id: Mapped[str | None] = mapped_column(ForeignKey("answer_audits.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc, index=True)


class ConversationHop(Base):
    __tablename__ = "conversation_hops"
    __table_args__ = (UniqueConstraint("assistant_message_id", "hop_order"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assistant_message_id: Mapped[str] = mapped_column(
        ForeignKey("conversation_messages.id"), index=True
    )
    hop_order: Mapped[int] = mapped_column(Integer)
    hop_type: Mapped[str] = mapped_column(String(50))
    input_data: Mapped[dict] = mapped_column(JSON)
    output_data: Mapped[dict] = mapped_column(JSON)
    evidence_refs: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)


class EvidenceTask(Base):
    __tablename__ = "evidence_tasks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    conversation_id: Mapped[str] = mapped_column(ForeignKey("conversations.id"), index=True)
    message_id: Mapped[str] = mapped_column(ForeignKey("conversation_messages.id"), index=True)
    comparison_id: Mapped[str | None] = mapped_column(
        ForeignKey("intelligence_comparisons.id"), index=True
    )
    task_type: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    missing_fields: Mapped[list] = mapped_column(JSON)
    target_sources: Mapped[list] = mapped_column(JSON)
    completion_conditions: Mapped[list] = mapped_column(JSON)
    evidence_refs: Mapped[list] = mapped_column(JSON)
    network_verification_status: Mapped[str] = mapped_column(String(30), default="not_started")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc, index=True)


class ConversationEvaluation(Base):
    __tablename__ = "conversation_evaluations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    suite_version: Mapped[str] = mapped_column(String(100))
    run_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc, index=True)
    case_count: Mapped[int] = mapped_column(Integer)
    conversation_pass_rate: Mapped[float] = mapped_column(Float)
    hop_evidence_rate: Mapped[float] = mapped_column(Float)
    replay_determinism_rate: Mapped[float] = mapped_column(Float)
    task_boundary_rate: Mapped[float] = mapped_column(Float)
    recommendation_boundary_rate: Mapped[float] = mapped_column(Float)
    details: Mapped[list] = mapped_column(JSON)


class OperationalEvaluation(Base):
    __tablename__ = "operational_evaluations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    schema_version: Mapped[str] = mapped_column(String(50))
    run_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc, index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    collection: Mapped[dict] = mapped_column(JSON)
    enrichment: Mapped[dict] = mapped_column(JSON)
    integrity: Mapped[dict] = mapped_column(JSON)
    checks: Mapped[list] = mapped_column(JSON)
    limitations: Mapped[list] = mapped_column(JSON)


class EnrichmentEvaluation(Base):
    __tablename__ = "enrichment_evaluations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    suite_version: Mapped[str] = mapped_column(String(100))
    run_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc, index=True)
    case_count: Mapped[int] = mapped_column(Integer)
    assertion_count: Mapped[int] = mapped_column(Integer)
    assertion_accuracy: Mapped[float] = mapped_column(Float)
    expected_fact_recall: Mapped[float] = mapped_column(Float)
    evidence_verifiable_rate: Mapped[float] = mapped_column(Float)
    details: Mapped[list] = mapped_column(JSON)


class RecoveryAction(Base):
    __tablename__ = "recovery_actions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    action_type: Mapped[str] = mapped_column(String(60), index=True)
    target_id: Mapped[str | None] = mapped_column(String(100), index=True)
    status: Mapped[str] = mapped_column(String(30))
    detail: Mapped[dict] = mapped_column(JSON)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc, index=True)


class ChunkEmbedding(Base):
    __tablename__ = "chunk_embeddings"
    chunk_id: Mapped[str] = mapped_column(
        ForeignKey("search_chunks.id", ondelete="CASCADE"), primary_key=True
    )
    model_key: Mapped[str] = mapped_column(String(200), index=True)
    content_sha256: Mapped[str] = mapped_column(String(64))
    vector: Mapped[list] = mapped_column(JSON)


class RagRun(Base):
    __tablename__ = "rag_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc, index=True)
    request: Mapped[dict] = mapped_column(JSON)
    result: Mapped[dict] = mapped_column(JSON)


class RagEvaluation(Base):
    __tablename__ = "rag_evaluations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc, index=True)
    report: Mapped[dict] = mapped_column(JSON)


class ConversationRagTurn(Base):
    __tablename__ = "conversation_rag_turns"
    __table_args__ = (UniqueConstraint("conversation_id", "request_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    conversation_id: Mapped[str] = mapped_column(ForeignKey("conversations.id"), index=True)
    request_id: Mapped[str] = mapped_column(String(64))
    request_sha256: Mapped[str] = mapped_column(String(64))
    rag_run_id: Mapped[str] = mapped_column(ForeignKey("rag_runs.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)


class RagTurnJob(Base):
    __tablename__ = "rag_turn_jobs"
    __table_args__ = (UniqueConstraint("conversation_id", "request_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    conversation_id: Mapped[str] = mapped_column(ForeignKey("conversations.id"), index=True)
    request_id: Mapped[str] = mapped_column(String(64))
    request_sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(30), index=True)
    owner_token: Mapped[str] = mapped_column(String(36))
    base_state_version: Mapped[int] = mapped_column(Integer)
    lease_expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    payload: Mapped[dict] = mapped_column(JSON)
    generated_result: Mapped[dict | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)
