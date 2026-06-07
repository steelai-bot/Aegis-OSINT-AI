"""add persistent tool execution approvals

Revision ID: 0006_tool_execution_approvals
Revises: 0005_audit_events
Create Date: 2026-06-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0006_tool_execution_approvals"
down_revision: str | None = "0005_audit_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tool_execution_approvals",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("plugin_name", sa.String(length=100), nullable=True),
        sa.Column("target_type", sa.String(length=50), nullable=True),
        sa.Column("target_hash", sa.String(length=64), nullable=True),
        sa.Column("execution_mode", sa.String(length=50), nullable=False),
        sa.Column("authorized_scope", sa.String(length=2048), nullable=True),
        sa.Column("reason", sa.String(length=2048), nullable=True),
        sa.Column("requested_by", sa.String(length=255), nullable=True),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("max_uses", sa.Integer(), nullable=False),
        sa.Column("use_count", sa.Integer(), nullable=False),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(op.f("ix_tool_execution_approvals_token_hash"), "tool_execution_approvals", ["token_hash"])
    op.create_index(op.f("ix_tool_execution_approvals_status"), "tool_execution_approvals", ["status"])
    op.create_index(op.f("ix_tool_execution_approvals_plugin_name"), "tool_execution_approvals", ["plugin_name"])
    op.create_index(op.f("ix_tool_execution_approvals_target_type"), "tool_execution_approvals", ["target_type"])
    op.create_index(op.f("ix_tool_execution_approvals_target_hash"), "tool_execution_approvals", ["target_hash"])
    op.create_index(op.f("ix_tool_execution_approvals_execution_mode"), "tool_execution_approvals", ["execution_mode"])
    op.create_index(op.f("ix_tool_execution_approvals_requested_by"), "tool_execution_approvals", ["requested_by"])
    op.create_index(op.f("ix_tool_execution_approvals_approved_by"), "tool_execution_approvals", ["approved_by"])
    op.create_index(op.f("ix_tool_execution_approvals_expires_at"), "tool_execution_approvals", ["expires_at"])
    op.create_index(op.f("ix_tool_execution_approvals_used_at"), "tool_execution_approvals", ["used_at"])
    op.create_index(op.f("ix_tool_execution_approvals_revoked_at"), "tool_execution_approvals", ["revoked_at"])
    op.create_index(op.f("ix_tool_execution_approvals_created_at"), "tool_execution_approvals", ["created_at"])
    op.create_index(
        "ix_tool_execution_approvals_lookup",
        "tool_execution_approvals",
        ["status", "plugin_name", "target_type"],
    )


def downgrade() -> None:
    op.drop_table("tool_execution_approvals")