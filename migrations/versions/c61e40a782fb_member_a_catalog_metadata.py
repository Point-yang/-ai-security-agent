"""Additional bounded metadata sources with exact raw evidence."""

import sqlalchemy as sa
from alembic import op

revision = "c61e40a782fb"
down_revision = "a730cf924be1"
branch_labels = depends_on = None


def upgrade():
    op.create_table(
        "catalog_items",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_id", sa.String(50), sa.ForeignKey("sources.id"), nullable=False),
        sa.Column("external_id", sa.String(200), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("source_url", sa.String(2000), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("source_updated_at", sa.DateTime(timezone=True)),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "raw_document_id", sa.String(36), sa.ForeignKey("raw_documents.id"), nullable=False
        ),
        sa.Column("evidence_locator", sa.Text(), nullable=False),
        sa.Column("normalized", sa.JSON(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.UniqueConstraint("source_id", "external_id"),
    )
    op.create_index("ix_catalog_items_source_id", "catalog_items", ["source_id"])
    op.create_index("ix_catalog_items_external_id", "catalog_items", ["external_id"])
    op.create_table(
        "catalog_revisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("item_id", sa.String(36), sa.ForeignKey("catalog_items.id"), nullable=False),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column(
            "raw_document_id", sa.String(36), sa.ForeignKey("raw_documents.id"), nullable=False
        ),
        sa.Column("evidence_locator", sa.Text(), nullable=False),
        sa.Column("normalized", sa.JSON(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("item_id", "number"),
    )
    op.create_index("ix_catalog_revisions_item_id", "catalog_revisions", ["item_id"])


def downgrade():
    op.drop_index("ix_catalog_revisions_item_id", table_name="catalog_revisions")
    op.drop_table("catalog_revisions")
    op.drop_index("ix_catalog_items_external_id", table_name="catalog_items")
    op.drop_index("ix_catalog_items_source_id", table_name="catalog_items")
    op.drop_table("catalog_items")
