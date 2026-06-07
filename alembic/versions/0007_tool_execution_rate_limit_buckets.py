"""add tool execution rate limit buckets

Revision ID: 0007_tool_execution_rate_limit_buckets
Revises: 0006_tool_execution_approvals
Create Date: 2026-06-07
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0007_tool_execution_rate_limit_buckets"
down_revision: str | None = "0006_tool_execution_approvals"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tool_execution_rate_limit_buckets",
        sa.Column("key", sa.String(length=255), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_index(
        op.f("ix_tool_execution_rate_limit_buckets_window_start"),
        "tool_execution_rate_limit_buckets",
        ["window_start"],
    )
    op.create_index(
        "ix_tool_execution_rate_limit_buckets_updated_at",
        "tool_execution_rate_limit_buckets",
        ["updated_at"],
    )


def downgrade() -> None:
    op.drop_table("tool_execution_rate_limit_buckets")
