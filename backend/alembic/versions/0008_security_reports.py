"""Executive and technical security reports and posture analytics

Revision ID: 0008_security_reports
Revises: 0007_incident_management
Create Date: 2026-11-14

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0008_security_reports"
down_revision: str | None = "0007_incident_management"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    json_col = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")

    op.create_table(
        "security_reports",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("report_type", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("posture_score", sa.Float(), nullable=True),
        sa.Column("incident_id", sa.String(length=36), nullable=True),
        sa.Column("generated_by_id", sa.String(length=36), nullable=True),
        sa.Column("parameters", json_col, nullable=False),
        sa.Column("content", json_col, nullable=False),
        sa.Column("rendered_html", sa.Text(), nullable=True),
        sa.Column("rendered_markdown", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["generated_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_security_reports_report_type"), "security_reports", ["report_type"], unique=False)
    op.create_index(op.f("ix_security_reports_title"), "security_reports", ["title"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_security_reports_title"), table_name="security_reports")
    op.drop_index(op.f("ix_security_reports_report_type"), table_name="security_reports")
    op.drop_table("security_reports")
