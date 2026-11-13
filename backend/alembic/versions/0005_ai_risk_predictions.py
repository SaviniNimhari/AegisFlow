"""AI risk intelligence and threat predictions table

Revision ID: 0005_ai_risk_predictions
Revises: 0004_security_monitoring
Create Date: 2026-11-13

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005_ai_risk_predictions"
down_revision: str | None = "0004_security_monitoring"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ai_threat_predictions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("risk_level", sa.String(length=32), nullable=False),
        sa.Column("anomaly_score", sa.Float(), nullable=False),
        sa.Column("threat_category", sa.String(length=64), nullable=False),
        sa.Column("model_name", sa.String(length=64), nullable=False),
        sa.Column("model_version", sa.String(length=32), nullable=False),
        sa.Column("feature_vector", sa.JSON(), nullable=False),
        sa.Column("shap_explanations", sa.JSON(), nullable=False),
        sa.Column("analyst_feedback", sa.String(length=32), nullable=False),
        sa.Column("analyst_notes", sa.Text(), nullable=True),
        sa.Column("reviewed_by", sa.String(length=128), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("event_id", sa.String(length=36), nullable=True),
        sa.Column("alert_id", sa.String(length=36), nullable=True),
        sa.Column("asset_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["event_id"], ["security_events.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["alert_id"], ["security_alerts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_ai_threat_predictions_risk_score"),
        "ai_threat_predictions",
        ["risk_score"],
        unique=False,
    )
    op.create_index(
        op.f("ix_ai_threat_predictions_risk_level"),
        "ai_threat_predictions",
        ["risk_level"],
        unique=False,
    )
    op.create_index(
        op.f("ix_ai_threat_predictions_analyst_feedback"),
        "ai_threat_predictions",
        ["analyst_feedback"],
        unique=False,
    )
    op.create_index(
        op.f("ix_ai_threat_predictions_event_id"),
        "ai_threat_predictions",
        ["event_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_ai_threat_predictions_alert_id"),
        "ai_threat_predictions",
        ["alert_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_ai_threat_predictions_asset_id"),
        "ai_threat_predictions",
        ["asset_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_ai_threat_predictions_asset_id"), table_name="ai_threat_predictions")
    op.drop_index(op.f("ix_ai_threat_predictions_alert_id"), table_name="ai_threat_predictions")
    op.drop_index(op.f("ix_ai_threat_predictions_event_id"), table_name="ai_threat_predictions")
    op.drop_index(op.f("ix_ai_threat_predictions_analyst_feedback"), table_name="ai_threat_predictions")
    op.drop_index(op.f("ix_ai_threat_predictions_risk_level"), table_name="ai_threat_predictions")
    op.drop_index(op.f("ix_ai_threat_predictions_risk_score"), table_name="ai_threat_predictions")
    op.drop_table("ai_threat_predictions")
