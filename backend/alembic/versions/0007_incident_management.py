"""Incident management, timeline correlation, and comments

Revision ID: 0007_incident_management
Revises: 0006_digital_forensics
Create Date: 2026-11-14

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007_incident_management"
down_revision: str | None = "0006_digital_forensics"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Incidents table
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("incident_number", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("assigned_to", sa.String(length=128), nullable=True),
        sa.Column("lead_analyst", sa.String(length=128), nullable=True),
        sa.Column("root_cause", sa.Text(), nullable=True),
        sa.Column("containment_actions", sa.Text(), nullable=True),
        sa.Column("lessons_learned", sa.Text(), nullable=True),
        sa.Column("sla_breach", sa.Boolean(), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_incidents_incident_number"), "incidents", ["incident_number"], unique=True)
    op.create_index(op.f("ix_incidents_title"), "incidents", ["title"], unique=False)
    op.create_index(op.f("ix_incidents_severity"), "incidents", ["severity"], unique=False)
    op.create_index(op.f("ix_incidents_status"), "incidents", ["status"], unique=False)
    op.create_index(op.f("ix_incidents_asset_id"), "incidents", ["asset_id"], unique=False)

    # 2. Incident Timeline table
    op.create_table(
        "incident_timeline",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_incident_timeline_incident_id"), "incident_timeline", ["incident_id"], unique=False)

    # 3. Incident Comments table
    op.create_table(
        "incident_comments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("author", sa.String(length=128), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_incident_comments_incident_id"), "incident_comments", ["incident_id"], unique=False)

    # 4. Add incident_id to security_alerts
    op.add_column("security_alerts", sa.Column("incident_id", sa.String(length=36), nullable=True))
    op.create_foreign_key(
        "fk_security_alerts_incident_id",
        "security_alerts",
        "incidents",
        ["incident_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(op.f("ix_security_alerts_incident_id"), "security_alerts", ["incident_id"], unique=False)

    # 5. Add incident_id to forensic_artifacts
    op.add_column("forensic_artifacts", sa.Column("incident_id", sa.String(length=36), nullable=True))
    op.create_foreign_key(
        "fk_forensic_artifacts_incident_id",
        "forensic_artifacts",
        "incidents",
        ["incident_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(op.f("ix_forensic_artifacts_incident_id"), "forensic_artifacts", ["incident_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_forensic_artifacts_incident_id"), table_name="forensic_artifacts")
    op.drop_constraint("fk_forensic_artifacts_incident_id", "forensic_artifacts", type_="foreignkey")
    op.drop_column("forensic_artifacts", "incident_id")

    op.drop_index(op.f("ix_security_alerts_incident_id"), table_name="security_alerts")
    op.drop_constraint("fk_security_alerts_incident_id", "security_alerts", type_="foreignkey")
    op.drop_column("security_alerts", "incident_id")

    op.drop_index(op.f("ix_incident_comments_incident_id"), table_name="incident_comments")
    op.drop_table("incident_comments")

    op.drop_index(op.f("ix_incident_timeline_incident_id"), table_name="incident_timeline")
    op.drop_table("incident_timeline")

    op.drop_index(op.f("ix_incidents_asset_id"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_status"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_severity"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_title"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_incident_number"), table_name="incidents")
    op.drop_table("incidents")
