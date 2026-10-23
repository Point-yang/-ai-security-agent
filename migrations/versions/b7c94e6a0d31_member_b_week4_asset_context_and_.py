"""member B week4 asset context and comparison review

Revision ID: b7c94e6a0d31
Revises: a41c27d0e944
"""

import sqlalchemy as sa
from alembic import op

revision = "b7c94e6a0d31"
down_revision = "a41c27d0e944"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("answer_audits", schema=None) as batch_op:
        batch_op.add_column(sa.Column("asset_id", sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column("asset_context", sa.JSON(), nullable=True))
        batch_op.create_foreign_key(
            "fk_answer_audits_asset_id_assets", "assets", ["asset_id"], ["id"]
        )

    with op.batch_alter_table("intelligence_comparisons", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "review_status",
                sa.String(length=30),
                nullable=False,
                server_default="unreviewed",
            )
        )
        batch_op.add_column(sa.Column("analyst_note", sa.Text(), nullable=False, server_default=""))
        batch_op.add_column(
            sa.Column("annotation_version", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "asset_evaluations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("suite_version", sa.String(length=100), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("case_count", sa.Integer(), nullable=False),
        sa.Column("status_accuracy", sa.Float(), nullable=False),
        sa.Column("evidence_verifiable_rate", sa.Float(), nullable=False),
        sa.Column("boundary_pass_rate", sa.Float(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_asset_evaluations_asset_id", "asset_evaluations", ["asset_id"])
    op.create_index("ix_asset_evaluations_run_at", "asset_evaluations", ["run_at"])

    op.create_table(
        "comparison_review_changes",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("comparison_id", sa.String(length=36), nullable=False),
        sa.Column("previous_version", sa.Integer(), nullable=False),
        sa.Column("annotation_version", sa.Integer(), nullable=False),
        sa.Column("review_status", sa.String(length=30), nullable=False),
        sa.Column("analyst_note", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["comparison_id"], ["intelligence_comparisons.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_comparison_review_changes_comparison_id",
        "comparison_review_changes",
        ["comparison_id"],
    )


def downgrade():
    op.drop_index(
        "ix_comparison_review_changes_comparison_id",
        table_name="comparison_review_changes",
    )
    op.drop_table("comparison_review_changes")
    op.drop_index("ix_asset_evaluations_run_at", table_name="asset_evaluations")
    op.drop_index("ix_asset_evaluations_asset_id", table_name="asset_evaluations")
    op.drop_table("asset_evaluations")
    with op.batch_alter_table("intelligence_comparisons", schema=None) as batch_op:
        batch_op.drop_column("reviewed_at")
        batch_op.drop_column("annotation_version")
        batch_op.drop_column("analyst_note")
        batch_op.drop_column("review_status")
    with op.batch_alter_table("answer_audits", schema=None) as batch_op:
        batch_op.drop_constraint("fk_answer_audits_asset_id_assets", type_="foreignkey")
        batch_op.drop_column("asset_context")
        batch_op.drop_column("asset_id")
