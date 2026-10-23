"""Reserve model work without holding a conversation write transaction."""

import sqlalchemy as sa
from alembic import op

revision = "e194af81b723"
down_revision = "b928c1d740ae"
branch_labels = depends_on = None


def upgrade():
    op.create_table(
        "rag_turn_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "conversation_id", sa.String(36), sa.ForeignKey("conversations.id"), nullable=False
        ),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("owner_token", sa.String(36), nullable=False),
        sa.Column("base_state_version", sa.Integer, nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
        sa.Column("generated_result", sa.JSON),
        sa.Column("error", sa.String(100)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("conversation_id", "request_id"),
    )
    op.create_index("ix_rag_turn_jobs_conversation_id", "rag_turn_jobs", ["conversation_id"])
    op.create_index("ix_rag_turn_jobs_status", "rag_turn_jobs", ["status"])


def downgrade():
    op.drop_table("rag_turn_jobs")
