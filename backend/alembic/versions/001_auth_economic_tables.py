"""add auth economic and audit tables

Revision ID: 001_auth_economic
Revises: None
Create Date: 2026-05-11 00:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "001_auth_economic"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("username", sa.String(50), unique=True, nullable=False, index=True),
        sa.Column("hashed_password", sa.String(200), nullable=False),
        sa.Column("role", sa.String(20), nullable=False, server_default="viewer"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.Column("totp_secret", sa.String(100), nullable=True),
        sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.text("0")),
    )

    op.create_table(
        "token_blacklist",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("jti", sa.String(100), unique=True, nullable=False, index=True),
        sa.Column("username", sa.String(50), nullable=False, index=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("username", sa.String(50), nullable=False, index=True),
        sa.Column("action", sa.String(100), nullable=False, index=True),
        sa.Column("resource", sa.String(200), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(50), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), index=True),
    )

    op.create_table(
        "login_failures",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("username", sa.String(50), nullable=False, index=True),
        sa.Column("ip_address", sa.String(50), nullable=True),
        sa.Column("failed_at", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "economic_impacts",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("sector", sa.String(50), nullable=False, index=True),
        sa.Column("estimated_loss", sa.Float(), nullable=False),
        sa.Column("affected_users", sa.Integer(), nullable=False),
        sa.Column("geographic_scope", sa.Text(), nullable=True),
        sa.Column("duration_days", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("intelligence_source_ids", sa.Text(), nullable=True),
        sa.Column("threat_categories", sa.Text(), nullable=True),
        sa.Column("assessed_at", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "market_transactions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("sector", sa.String(50), nullable=False, index=True),
        sa.Column("tx_type", sa.String(20), nullable=False),
        sa.Column("amount", sa.Float(), nullable=False),
        sa.Column("price", sa.Float(), nullable=False),
        sa.Column("total_value", sa.Float(), nullable=False),
        sa.Column("fee", sa.Float(), nullable=False),
        sa.Column("from_entity", sa.String(128), nullable=True),
        sa.Column("to_entity", sa.String(128), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("intelligence_ids", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "market_states",
        sa.Column("sector", sa.String(50), primary_key=True),
        sa.Column("sector_name", sa.String(50), nullable=False),
        sa.Column("price_index", sa.Float(), nullable=False),
        sa.Column("volume_24h", sa.Float(), nullable=False),
        sa.Column("volatility", sa.Float(), nullable=False),
        sa.Column("trend", sa.String(20), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("market_cap_estimate", sa.Float(), nullable=False),
        sa.Column("active_entities", sa.Integer(), nullable=False),
        sa.Column("last_updated", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "economic_alerts",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("sector", sa.String(50), nullable=False, index=True),
        sa.Column("alert_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("related_intelligence_ids", sa.Text(), nullable=True),
        sa.Column("economic_impact_ids", sa.Text(), nullable=True),
        sa.Column("is_resolved", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("economic_alerts")
    op.drop_table("market_states")
    op.drop_table("market_transactions")
    op.drop_table("economic_impacts")
    op.drop_table("login_failures")
    op.drop_table("audit_log")
    op.drop_table("token_blacklist")
    op.drop_table("users")
