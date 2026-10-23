"""member A week4 assets and source comparisons

Revision ID: a41c27d0e944
Revises: f3a91c024b17
"""

import sqlalchemy as sa
from alembic import op

revision = "a41c27d0e944"
down_revision = "f3a91c024b17"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "assets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("environment", sa.String(length=50), nullable=False),
        sa.Column("criticality", sa.String(length=30), nullable=False),
        sa.Column("sbom_format", sa.String(length=50), nullable=False),
        sa.Column("sbom_version", sa.String(length=30), nullable=True),
        sa.Column("sbom_sha256", sa.String(length=64), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "asset_components",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("ecosystem", sa.String(length=50), nullable=False),
        sa.Column("name", sa.String(length=500), nullable=False),
        sa.Column("version", sa.String(length=200), nullable=False),
        sa.Column("purl", sa.String(length=1000), nullable=True),
        sa.Column("cpe", sa.String(length=1000), nullable=True),
        sa.Column("bom_ref", sa.String(length=500), nullable=True),
        sa.Column("component_type", sa.String(length=50), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_asset_components_asset_id", "asset_components", ["asset_id"])
    op.create_index(
        "ix_asset_component_identity",
        "asset_components",
        ["ecosystem", "name", "version"],
    )
    op.create_table(
        "asset_exposures",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("component_id", sa.String(length=36), nullable=False),
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("revision_id", sa.String(length=36), nullable=False),
        sa.Column("enrichment_schema_version", sa.String(length=30), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("match_method", sa.String(length=50), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.ForeignKeyConstraint(["component_id"], ["asset_components.id"]),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"]),
        sa.ForeignKeyConstraint(["revision_id"], ["event_revisions.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("component_id", "event_id"),
    )
    op.create_index("ix_asset_exposures_asset_id", "asset_exposures", ["asset_id"])
    op.create_index("ix_asset_exposures_component_id", "asset_exposures", ["component_id"])
    op.create_index("ix_asset_exposures_event_id", "asset_exposures", ["event_id"])
    op.create_index("ix_asset_exposure_status", "asset_exposures", ["asset_id", "status"])
    op.create_table(
        "intelligence_comparisons",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("identifier", sa.String(length=100), nullable=False),
        sa.Column("field", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("observations", sa.JSON(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("identifier", "field"),
    )
    op.create_index(
        "ix_intelligence_comparisons_identifier", "intelligence_comparisons", ["identifier"]
    )
    op.create_index("ix_intelligence_comparisons_status", "intelligence_comparisons", ["status"])


def downgrade():
    op.drop_index("ix_intelligence_comparisons_status", table_name="intelligence_comparisons")
    op.drop_index("ix_intelligence_comparisons_identifier", table_name="intelligence_comparisons")
    op.drop_table("intelligence_comparisons")
    op.drop_index("ix_asset_exposure_status", table_name="asset_exposures")
    op.drop_index("ix_asset_exposures_event_id", table_name="asset_exposures")
    op.drop_index("ix_asset_exposures_component_id", table_name="asset_exposures")
    op.drop_index("ix_asset_exposures_asset_id", table_name="asset_exposures")
    op.drop_table("asset_exposures")
    op.drop_index("ix_asset_component_identity", table_name="asset_components")
    op.drop_index("ix_asset_components_asset_id", table_name="asset_components")
    op.drop_table("asset_components")
    op.drop_table("assets")
