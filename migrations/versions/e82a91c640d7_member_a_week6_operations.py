"""member A week6 operations evaluation and recovery audit

Revision ID: e82a91c640d7
Revises: d4f86b29a5c0
Create Date: 2026-09-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e82a91c640d7"
down_revision: str | None = "d4f86b29a5c0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("monitor_states") as batch_op:
        batch_op.add_column(sa.Column("heartbeat_at", sa.DateTime(timezone=True)))
        batch_op.create_index("ix_monitor_states_heartbeat_at", ["heartbeat_at"])

    op.create_table(
        "operational_evaluations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("schema_version", sa.String(50), nullable=False),
        sa.Column("run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("collection", sa.JSON(), nullable=False),
        sa.Column("enrichment", sa.JSON(), nullable=False),
        sa.Column("integrity", sa.JSON(), nullable=False),
        sa.Column("checks", sa.JSON(), nullable=False),
        sa.Column("limitations", sa.JSON(), nullable=False),
    )
    op.create_index("ix_operational_evaluations_run_at", "operational_evaluations", ["run_at"])
    op.create_index("ix_operational_evaluations_status", "operational_evaluations", ["status"])

    op.create_table(
        "enrichment_evaluations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("suite_version", sa.String(100), nullable=False),
        sa.Column("run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("case_count", sa.Integer(), nullable=False),
        sa.Column("assertion_count", sa.Integer(), nullable=False),
        sa.Column("assertion_accuracy", sa.Float(), nullable=False),
        sa.Column("expected_fact_recall", sa.Float(), nullable=False),
        sa.Column("evidence_verifiable_rate", sa.Float(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
    )
    op.create_index("ix_enrichment_evaluations_run_at", "enrichment_evaluations", ["run_at"])

    op.create_table(
        "recovery_actions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("action_type", sa.String(60), nullable=False),
        sa.Column("target_id", sa.String(100)),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_recovery_actions_action_type", "recovery_actions", ["action_type"])
    op.create_index("ix_recovery_actions_target_id", "recovery_actions", ["target_id"])
    op.create_index("ix_recovery_actions_occurred_at", "recovery_actions", ["occurred_at"])


def downgrade() -> None:
    op.drop_index("ix_recovery_actions_occurred_at", table_name="recovery_actions")
    op.drop_index("ix_recovery_actions_target_id", table_name="recovery_actions")
    op.drop_index("ix_recovery_actions_action_type", table_name="recovery_actions")
    op.drop_table("recovery_actions")
    op.drop_index("ix_enrichment_evaluations_run_at", table_name="enrichment_evaluations")
    op.drop_table("enrichment_evaluations")
    op.drop_index("ix_operational_evaluations_status", table_name="operational_evaluations")
    op.drop_index("ix_operational_evaluations_run_at", table_name="operational_evaluations")
    op.drop_table("operational_evaluations")
    with op.batch_alter_table("monitor_states") as batch_op:
        batch_op.drop_index("ix_monitor_states_heartbeat_at")
        batch_op.drop_column("heartbeat_at")
