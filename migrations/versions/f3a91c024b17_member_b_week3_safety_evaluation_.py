"""member B week3 safety evaluation metrics

Revision ID: f3a91c024b17
Revises: ea1a2de37f80
"""

import sqlalchemy as sa
from alembic import op

revision = "f3a91c024b17"
down_revision = "ea1a2de37f80"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("retrieval_evaluations", schema=None) as batch_op:
        batch_op.add_column(sa.Column("answerability_accuracy", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("constraint_pass_rate", sa.Float(), nullable=True))


def downgrade():
    with op.batch_alter_table("retrieval_evaluations", schema=None) as batch_op:
        batch_op.drop_column("constraint_pass_rate")
        batch_op.drop_column("answerability_accuracy")
