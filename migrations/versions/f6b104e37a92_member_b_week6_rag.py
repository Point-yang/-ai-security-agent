"""Versioned semantic index and bounded RAG audit.

Revision ID: f6b104e37a92
Revises: e82a91c640d7
"""

import sqlalchemy as sa
from alembic import op

revision = "f6b104e37a92"
down_revision = "e82a91c640d7"
branch_labels = depends_on = None


def upgrade():
    op.create_table(
        "chunk_embeddings",
        sa.Column(
            "chunk_id",
            sa.String(64),
            sa.ForeignKey("search_chunks.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("model_key", sa.String(200), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("vector", sa.JSON(), nullable=False),
    )
    op.create_index("ix_chunk_embeddings_model_key", "chunk_embeddings", ["model_key"])
    op.create_table(
        "rag_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request", sa.JSON(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
    )
    op.create_index("ix_rag_runs_created_at", "rag_runs", ["created_at"])
    op.create_table(
        "rag_evaluations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("report", sa.JSON(), nullable=False),
    )
    op.create_index("ix_rag_evaluations_created_at", "rag_evaluations", ["created_at"])


def downgrade():
    op.drop_table("rag_evaluations")
    op.drop_table("rag_runs")
    op.drop_table("chunk_embeddings")
