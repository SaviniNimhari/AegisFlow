"""Security monitoring events, detection rules, and alerts tables

Revision ID: 0004_security_monitoring
Revises: 0003_vulnerability_management
Create Date: 2026-11-13

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004_security_monitoring"
down_revision: str | None = "0003_vulnerability_management"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Create detection_rules table
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("rule_type", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), server_default="medium", nullable=False),
        sa.Column("is_enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("condition_config", sa.JSON(), nullable=False),
        sa.Column("mitre_attack_id", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_detection_rules_id"), "detection_rules", ["id"], unique=False)
    op.create_index(op.f("ix_detection_rules_name"), "detection_rules", ["name"], unique=True)
    op.create_index(op.f("ix_detection_rules_rule_type"), "detection_rules", ["rule_type"], unique=False)

    # 2. Create security_events table
    op.create_table(
        "security_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_ip", sa.String(length=45), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(length=64), nullable=True),
        sa.Column("asset_id", sa.String(length=36), nullable=True),
        sa.Column("raw_log", sa.Text(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_security_events_id"), "security_events", ["id"], unique=False)
    op.create_index(op.f("ix_security_events_event_type"), "security_events", ["event_type"], unique=False)
    op.create_index(op.f("ix_security_events_source"), "security_events", ["source"], unique=False)
    op.create_index(op.f("ix_security_events_source_ip"), "security_events", ["source_ip"], unique=False)
    op.create_index(op.f("ix_security_events_destination_ip"), "security_events", ["destination_ip"], unique=False)
    op.create_index(op.f("ix_security_events_username"), "security_events", ["username"], unique=False)
    op.create_index(op.f("ix_security_events_asset_id"), "security_events", ["asset_id"], unique=False)
    op.create_index(op.f("ix_security_events_timestamp"), "security_events", ["timestamp"], unique=False)

    # 3. Create security_alerts table
    op.create_table(
        "security_alerts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=16), server_default="medium", nullable=False),
        sa.Column("status", sa.String(length=20), server_default="open", nullable=False),
        sa.Column("confidence_score", sa.Float(), server_default="0.85", nullable=False),
        sa.Column("rule_id", sa.String(length=36), nullable=True),
        sa.Column("rule_name", sa.String(length=128), nullable=True),
        sa.Column("mitre_attack_id", sa.String(length=32), nullable=True),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("destination_ip", sa.String(length=45), nullable=True),
        sa.Column("target_user", sa.String(length=64), nullable=True),
        sa.Column("asset_id", sa.String(length=36), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("assigned_to", sa.String(length=128), nullable=True),
        sa.Column("resolution_notes", sa.Text(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["rule_id"], ["detection_rules.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_security_alerts_id"), "security_alerts", ["id"], unique=False)
    op.create_index(op.f("ix_security_alerts_title"), "security_alerts", ["title"], unique=False)
    op.create_index(op.f("ix_security_alerts_severity"), "security_alerts", ["severity"], unique=False)
    op.create_index(op.f("ix_security_alerts_status"), "security_alerts", ["status"], unique=False)
    op.create_index(op.f("ix_security_alerts_rule_id"), "security_alerts", ["rule_id"], unique=False)
    op.create_index(op.f("ix_security_alerts_source_ip"), "security_alerts", ["source_ip"], unique=False)
    op.create_index(op.f("ix_security_alerts_destination_ip"), "security_alerts", ["destination_ip"], unique=False)
    op.create_index(op.f("ix_security_alerts_target_user"), "security_alerts", ["target_user"], unique=False)
    op.create_index(op.f("ix_security_alerts_asset_id"), "security_alerts", ["asset_id"], unique=False)


def downgrade() -> None:
    op.drop_table("security_alerts")
    op.drop_table("security_events")
    op.drop_table("detection_rules")
