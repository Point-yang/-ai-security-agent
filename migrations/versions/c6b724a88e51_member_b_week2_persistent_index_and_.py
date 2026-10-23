"""member B week2 persistent index and answer audit

Revision ID: c6b724a88e51
Revises: 5e755300bd0b
"""

import sqlalchemy as sa
from alembic import op

revision = "c6b724a88e51"
down_revision = "5e755300bd0b"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "answer_audits",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("question", sa.Text(), nullable=False),
        sa.Column("answer", sa.Text(), nullable=False),
        sa.Column("retrieval_query", sa.Text(), nullable=False),
        sa.Column("pool", sa.String(length=30), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=False),
        sa.Column("prompt_version", sa.String(length=100), nullable=False),
        sa.Column("policy_version", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("citations", sa.JSON(), nullable=False),
        sa.Column("constraints", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_answer_audits_created_at", "answer_audits", ["created_at"])
    op.create_table(
        "retrieval_evaluations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("suite_version", sa.String(length=100), nullable=False),
        sa.Column("index_schema_version", sa.String(length=30), nullable=False),
        sa.Column("run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("case_count", sa.Integer(), nullable=False),
        sa.Column("hit_rate_at_k", sa.Float(), nullable=False),
        sa.Column("citation_verifiable_rate", sa.Float(), nullable=False),
        sa.Column("hallucination_rate", sa.Float(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_retrieval_evaluations_run_at", "retrieval_evaluations", ["run_at"])
    op.create_table(
        "search_index_states",
        sa.Column("name", sa.String(length=50), nullable=False),
        sa.Column("schema_version", sa.String(length=30), nullable=False),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("chunk_count", sa.Integer(), nullable=False),
        sa.Column("pool_counts", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("name"),
    )
    op.create_table(
        "search_chunks",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("revision_id", sa.String(length=36), nullable=False),
        sa.Column("revision_number", sa.Integer(), nullable=False),
        sa.Column("raw_document_id", sa.String(length=36), nullable=False),
        sa.Column("source_id", sa.String(length=50), nullable=False),
        sa.Column("kind", sa.String(length=30), nullable=False),
        sa.Column("external_id", sa.String(length=100), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("field", sa.String(length=50), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("start", sa.Integer(), nullable=False),
        sa.Column("end", sa.Integer(), nullable=False),
        sa.Column("json_pointer", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("origin", sa.String(length=20), nullable=False),
        sa.Column("verification", sa.String(length=30), nullable=False),
        sa.Column("pool", sa.String(length=30), nullable=False),
        sa.Column("ai_label", sa.String(length=30), nullable=False),
        sa.Column("triage_rule_version", sa.String(length=30), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("withdrawn", sa.Boolean(), nullable=False),
        sa.Column("term_list", sa.JSON(), nullable=False),
        sa.Column("indexed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"]),
        sa.ForeignKeyConstraint(["raw_document_id"], ["raw_documents.id"]),
        sa.ForeignKeyConstraint(["revision_id"], ["event_revisions.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_search_chunks_event_id", "search_chunks", ["event_id"])
    op.create_index("ix_search_chunk_pool", "search_chunks", ["pool", "origin", "withdrawn"])
    op.create_index("ix_search_chunk_event_revision", "search_chunks", ["event_id", "revision_id"])
    op.create_index("ix_search_chunk_filters", "search_chunks", ["source_id", "kind", "severity"])


def downgrade():
    op.drop_index("ix_search_chunk_filters", table_name="search_chunks")
    op.drop_index("ix_search_chunk_event_revision", table_name="search_chunks")
    op.drop_index("ix_search_chunk_pool", table_name="search_chunks")
    op.drop_index("ix_search_chunks_event_id", table_name="search_chunks")
    op.drop_table("search_chunks")
    op.drop_table("search_index_states")
    op.drop_index("ix_retrieval_evaluations_run_at", table_name="retrieval_evaluations")
    op.drop_table("retrieval_evaluations")
    op.drop_index("ix_answer_audits_created_at", table_name="answer_audits")
    op.drop_table("answer_audits")
