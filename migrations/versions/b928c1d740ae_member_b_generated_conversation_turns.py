"""Idempotent generated turns linked to immutable RAG runs."""

import sqlalchemy as sa
from alembic import op

revision = "b928c1d740ae"
down_revision = "c61e40a782fb"
branch_labels = depends_on = None


def upgrade():
    op.create_table(
        "conversation_rag_turns",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "conversation_id", sa.String(36), sa.ForeignKey("conversations.id"), nullable=False
        ),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("rag_run_id", sa.String(36), sa.ForeignKey("rag_runs.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("conversation_id", "request_id"),
    )
    op.create_index(
        "ix_conversation_rag_turns_conversation_id", "conversation_rag_turns", ["conversation_id"]
    )


def downgrade():
    op.drop_index("ix_conversation_rag_turns_conversation_id", table_name="conversation_rag_turns")
    op.drop_table("conversation_rag_turns")
