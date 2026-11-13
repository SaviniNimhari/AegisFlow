"""Asset inventory and attack surface table

Revision ID: 0002_asset_inventory
Revises: 0001_initial_users
Create Date: 2026-11-12

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002_asset_inventory"
down_revision: str | None = "0001_initial_users"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("mac_address", sa.String(length=17), nullable=True),
        sa.Column("asset_type", sa.String(length=32), server_default="server", nullable=False),
        sa.Column("criticality", sa.String(length=16), server_default="medium", nullable=False),
        sa.Column("status", sa.String(length=16), server_default="active", nullable=False),
        sa.Column("environment", sa.String(length=32), server_default="production", nullable=False),
        sa.Column("os_family", sa.String(length=64), nullable=True),
        sa.Column("os_version", sa.String(length=64), nullable=True),
        sa.Column("open_ports", sa.JSON(), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("owner", sa.String(length=128), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_assets_id"), "assets", ["id"], unique=False)
    op.create_index(op.f("ix_assets_name"), "assets", ["name"], unique=False)
    op.create_index(op.f("ix_assets_hostname"), "assets", ["hostname"], unique=False)
    op.create_index(op.f("ix_assets_ip_address"), "assets", ["ip_address"], unique=False)
    op.create_index(op.f("ix_assets_asset_type"), "assets", ["asset_type"], unique=False)
    op.create_index(op.f("ix_assets_criticality"), "assets", ["criticality"], unique=False)
    op.create_index(op.f("ix_assets_status"), "assets", ["status"], unique=False)
    op.create_index(op.f("ix_assets_environment"), "assets", ["environment"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_assets_environment"), table_name="assets")
    op.drop_index(op.f("ix_assets_status"), table_name="assets")
    op.drop_index(op.f("ix_assets_criticality"), table_name="assets")
    op.drop_index(op.f("ix_assets_asset_type"), table_name="assets")
    op.drop_index(op.f("ix_assets_ip_address"), table_name="assets")
    op.drop_index(op.f("ix_assets_hostname"), table_name="assets")
    op.drop_index(op.f("ix_assets_name"), table_name="assets")
    op.drop_index(op.f("ix_assets_id"), table_name="assets")
    op.drop_table("assets")
