"""member A week3 structured enrichment

Revision ID: ea1a2de37f80
Revises: c6b724a88e51
"""

import sqlalchemy as sa
from alembic import op

revision = "ea1a2de37f80"
down_revision = "c6b724a88e51"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "enrichment_states",
        sa.Column("name", sa.String(length=50), nullable=False),
        sa.Column("schema_version", sa.String(length=30), nullable=False),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("enriched_count", sa.Integer(), nullable=False),
        sa.Column("stats", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("name"),
    )
    op.create_table(
        "event_enrichments",
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("revision_id", sa.String(length=36), nullable=False),
        sa.Column("schema_version", sa.String(length=30), nullable=False),
        sa.Column("enriched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("entities", sa.JSON(), nullable=False),
        sa.Column("version_ranges", sa.JSON(), nullable=False),
        sa.Column("cvss", sa.JSON(), nullable=False),
        sa.Column("cpe_matches", sa.JSON(), nullable=False),
        sa.Column("quality_flags", sa.JSON(), nullable=False),
        sa.Column("provenance", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"]),
        sa.ForeignKeyConstraint(["revision_id"], ["event_revisions.id"]),
        sa.PrimaryKeyConstraint("event_id"),
    )
    op.create_index(
        "ix_event_enrichments_revision_id", "event_enrichments", ["revision_id"], unique=False
    )


def downgrade():
    op.drop_index("ix_event_enrichments_revision_id", table_name="event_enrichments")
    op.drop_table("event_enrichments")
    op.drop_table("enrichment_states")
