"""Retain inactive comparisons and bind review changes to observation snapshots."""

import sqlalchemy as sa
from alembic import op

revision = "a730cf924be1"
down_revision = "f6b104e37a92"
branch_labels = depends_on = None


def upgrade():
    with op.batch_alter_table("intelligence_comparisons") as batch:
        batch.add_column(
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true())
        )
        batch.add_column(sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_index("ix_intelligence_comparisons_is_active", ["is_active"])
    with op.batch_alter_table("comparison_review_changes") as batch:
        batch.add_column(
            sa.Column("change_kind", sa.String(40), nullable=False, server_default="manual_review")
        )
        batch.add_column(sa.Column("observations", sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table("comparison_review_changes") as batch:
        batch.drop_column("observations")
        batch.drop_column("change_kind")
    with op.batch_alter_table("intelligence_comparisons") as batch:
        batch.drop_index("ix_intelligence_comparisons_is_active")
        batch.drop_column("retired_at")
        batch.drop_column("is_active")
