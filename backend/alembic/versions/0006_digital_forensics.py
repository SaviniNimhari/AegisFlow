"""Digital forensics artifacts, chain of custody logs, and yara rules

Revision ID: 0006_digital_forensics
Revises: 0005_ai_risk_predictions
Create Date: 2026-11-13

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006_digital_forensics"
down_revision: str | None = "0005_ai_risk_predictions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Forensic Artifacts table
    op.create_table(
        "forensic_artifacts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("original_path", sa.String(length=512), nullable=True),
        sa.Column("file_size_bytes", sa.Integer(), nullable=False),
        sa.Column("mime_type", sa.String(length=128), nullable=False),
        sa.Column("magic_header", sa.String(length=128), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("md5", sa.String(length=32), nullable=False),
        sa.Column("sha1", sa.String(length=40), nullable=False),
        sa.Column("entropy", sa.Float(), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("extracted_strings_sample", sa.JSON(), nullable=False),
        sa.Column("yara_matches", sa.JSON(), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=True),
        sa.Column("uploaded_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_forensic_artifacts_filename"), "forensic_artifacts", ["filename"], unique=False
    )
    op.create_index(
        op.f("ix_forensic_artifacts_sha256"), "forensic_artifacts", ["sha256"], unique=False
    )
    op.create_index(
        op.f("ix_forensic_artifacts_md5"), "forensic_artifacts", ["md5"], unique=False
    )
    op.create_index(
        op.f("ix_forensic_artifacts_verdict"), "forensic_artifacts", ["verdict"], unique=False
    )
    op.create_index(
        op.f("ix_forensic_artifacts_severity"), "forensic_artifacts", ["severity"], unique=False
    )
    op.create_index(
        op.f("ix_forensic_artifacts_asset_id"), "forensic_artifacts", ["asset_id"], unique=False
    )

    # 2. Chain of Custody Logs table
    op.create_table(
        "chain_of_custody_logs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("artifact_id", sa.String(length=36), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("performed_by", sa.String(length=128), nullable=False),
        sa.Column("details", sa.Text(), nullable=True),
        sa.Column("sha256_at_action", sa.String(length=64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["artifact_id"], ["forensic_artifacts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_chain_of_custody_logs_artifact_id"),
        "chain_of_custody_logs",
        ["artifact_id"],
        unique=False,
    )

    # 3. YARA Rules table
    op.create_table(
        "yara_rules",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("rule_source", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("threat_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.Column("author", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_yara_rules_name"), "yara_rules", ["name"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_yara_rules_name"), table_name="yara_rules")
    op.drop_table("yara_rules")
    op.drop_index(op.f("ix_chain_of_custody_logs_artifact_id"), table_name="chain_of_custody_logs")
    op.drop_table("chain_of_custody_logs")
    op.drop_index(op.f("ix_forensic_artifacts_asset_id"), table_name="forensic_artifacts")
    op.drop_index(op.f("ix_forensic_artifacts_severity"), table_name="forensic_artifacts")
    op.drop_index(op.f("ix_forensic_artifacts_verdict"), table_name="forensic_artifacts")
    op.drop_index(op.f("ix_forensic_artifacts_md5"), table_name="forensic_artifacts")
    op.drop_index(op.f("ix_forensic_artifacts_sha256"), table_name="forensic_artifacts")
    op.drop_index(op.f("ix_forensic_artifacts_filename"), table_name="forensic_artifacts")
    op.drop_table("forensic_artifacts")
