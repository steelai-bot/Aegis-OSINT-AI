"""add agent context and task result persistence

Revision ID: 0002_agent_persistence
Revises: 0001_initial_schema
Create Date: 2026-06-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0002_agent_persistence"
down_revision: str | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "agent_context_snapshots",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=True),
        sa.Column("target", sa.String(length=2048), nullable=False),
        sa.Column("target_type", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("findings_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_agent_context_snapshots_investigation_id"),
        "agent_context_snapshots",
        ["investigation_id"],
    )
    op.create_index(
        op.f("ix_agent_context_snapshots_status"),
        "agent_context_snapshots",
        ["status"],
    )
    op.create_index(
        op.f("ix_agent_context_snapshots_target_type"),
        "agent_context_snapshots",
        ["target_type"],
    )

    op.create_table(
        "agent_task_results",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=True),
        sa.Column("context_snapshot_id", sa.UUID(), nullable=True),
        sa.Column("agent_name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("findings_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["context_snapshot_id"], ["agent_context_snapshots.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_agent_task_results_agent_name"), "agent_task_results", ["agent_name"])
    op.create_index(
        op.f("ix_agent_task_results_context_snapshot_id"),
        "agent_task_results",
        ["context_snapshot_id"],
    )
    op.create_index(
        op.f("ix_agent_task_results_investigation_id"),
        "agent_task_results",
        ["investigation_id"],
    )
    op.create_index(op.f("ix_agent_task_results_status"), "agent_task_results", ["status"])


def downgrade() -> None:
    op.drop_table("agent_task_results")
    op.drop_table("agent_context_snapshots")
