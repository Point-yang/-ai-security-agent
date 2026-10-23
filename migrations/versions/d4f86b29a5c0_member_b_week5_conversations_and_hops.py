"""member B week5 conversations and deterministic hops

Revision ID: d4f86b29a5c0
Revises: b7c94e6a0d31
Create Date: 2026-09-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d4f86b29a5c0"
down_revision: str | None = "b7c94e6a0d31"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "conversations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("active_asset_id", sa.String(36), sa.ForeignKey("assets.id")),
        sa.Column("state_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_conversations_active_asset_id", "conversations", ["active_asset_id"])
    op.create_index("ix_conversations_created_at", "conversations", ["created_at"])
    op.create_index("ix_conversations_updated_at", "conversations", ["updated_at"])
    op.create_table(
        "conversation_messages",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "conversation_id", sa.String(36), sa.ForeignKey("conversations.id"), nullable=False
        ),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("request", sa.JSON()),
        sa.Column("answer_status", sa.String(30)),
        sa.Column("explicit_asset_id", sa.String(36), sa.ForeignKey("assets.id")),
        sa.Column("effective_asset_id", sa.String(36), sa.ForeignKey("assets.id")),
        sa.Column("selected_event_ids", sa.JSON(), nullable=False),
        sa.Column("citations", sa.JSON(), nullable=False),
        sa.Column("constraints", sa.JSON(), nullable=False),
        sa.Column("answer_audit_id", sa.String(36), sa.ForeignKey("answer_audits.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("conversation_id", "sequence"),
    )
    op.create_index(
        "ix_conversation_messages_conversation_id", "conversation_messages", ["conversation_id"]
    )
    op.create_index("ix_conversation_messages_created_at", "conversation_messages", ["created_at"])
    op.create_table(
        "conversation_hops",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "assistant_message_id",
            sa.String(36),
            sa.ForeignKey("conversation_messages.id"),
            nullable=False,
        ),
        sa.Column("hop_order", sa.Integer(), nullable=False),
        sa.Column("hop_type", sa.String(50), nullable=False),
        sa.Column("input_data", sa.JSON(), nullable=False),
        sa.Column("output_data", sa.JSON(), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("assistant_message_id", "hop_order"),
    )
    op.create_index(
        "ix_conversation_hops_assistant_message_id",
        "conversation_hops",
        ["assistant_message_id"],
    )
    op.create_table(
        "evidence_tasks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "conversation_id", sa.String(36), sa.ForeignKey("conversations.id"), nullable=False
        ),
        sa.Column(
            "message_id", sa.String(36), sa.ForeignKey("conversation_messages.id"), nullable=False
        ),
        sa.Column(
            "comparison_id",
            sa.String(36),
            sa.ForeignKey("intelligence_comparisons.id"),
        ),
        sa.Column("task_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("missing_fields", sa.JSON(), nullable=False),
        sa.Column("target_sources", sa.JSON(), nullable=False),
        sa.Column("completion_conditions", sa.JSON(), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
        sa.Column("network_verification_status", sa.String(30), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_evidence_tasks_conversation_id", "evidence_tasks", ["conversation_id"])
    op.create_index("ix_evidence_tasks_message_id", "evidence_tasks", ["message_id"])
    op.create_index("ix_evidence_tasks_comparison_id", "evidence_tasks", ["comparison_id"])
    op.create_index("ix_evidence_tasks_status", "evidence_tasks", ["status"])
    op.create_index("ix_evidence_tasks_created_at", "evidence_tasks", ["created_at"])
    op.create_table(
        "conversation_evaluations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("suite_version", sa.String(100), nullable=False),
        sa.Column("run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("case_count", sa.Integer(), nullable=False),
        sa.Column("conversation_pass_rate", sa.Float(), nullable=False),
        sa.Column("hop_evidence_rate", sa.Float(), nullable=False),
        sa.Column("replay_determinism_rate", sa.Float(), nullable=False),
        sa.Column("task_boundary_rate", sa.Float(), nullable=False),
        sa.Column("recommendation_boundary_rate", sa.Float(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
    )
    op.create_index("ix_conversation_evaluations_run_at", "conversation_evaluations", ["run_at"])


def downgrade() -> None:
    op.drop_index("ix_conversation_evaluations_run_at", table_name="conversation_evaluations")
    op.drop_table("conversation_evaluations")
    op.drop_index("ix_evidence_tasks_created_at", table_name="evidence_tasks")
    op.drop_index("ix_evidence_tasks_status", table_name="evidence_tasks")
    op.drop_index("ix_evidence_tasks_comparison_id", table_name="evidence_tasks")
    op.drop_index("ix_evidence_tasks_message_id", table_name="evidence_tasks")
    op.drop_index("ix_evidence_tasks_conversation_id", table_name="evidence_tasks")
    op.drop_table("evidence_tasks")
    op.drop_index("ix_conversation_hops_assistant_message_id", table_name="conversation_hops")
    op.drop_table("conversation_hops")
    op.drop_index("ix_conversation_messages_created_at", table_name="conversation_messages")
    op.drop_index("ix_conversation_messages_conversation_id", table_name="conversation_messages")
    op.drop_table("conversation_messages")
    op.drop_index("ix_conversations_updated_at", table_name="conversations")
    op.drop_index("ix_conversations_created_at", table_name="conversations")
    op.drop_index("ix_conversations_active_asset_id", table_name="conversations")
    op.drop_table("conversations")
