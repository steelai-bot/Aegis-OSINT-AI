"""add passive collection run tracking

Revision ID: 0004_collection_runs
Revises: 0003_finding_threat_intel_metadata
Create Date: 2026-06-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0004_collection_runs"
down_revision: str | None = "0003_finding_threat_intel_metadata"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "collection_runs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("run_scope", sa.String(length=50), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=True),
        sa.Column("target_id", sa.UUID(), nullable=True),
        sa.Column("target", sa.String(length=2048), nullable=True),
        sa.Column("target_type", sa.String(length=50), nullable=True),
        sa.Column("plugin_name", sa.String(length=100), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("enrich", sa.Boolean(), nullable=False),
        sa.Column("config_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("result_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("error_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("persisted_count", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_collection_runs_run_scope"), "collection_runs", ["run_scope"])
    op.create_index(op.f("ix_collection_runs_investigation_id"), "collection_runs", ["investigation_id"])
    op.create_index(op.f("ix_collection_runs_target_id"), "collection_runs", ["target_id"])
    op.create_index(op.f("ix_collection_runs_target_type"), "collection_runs", ["target_type"])
    op.create_index(op.f("ix_collection_runs_plugin_name"), "collection_runs", ["plugin_name"])
    op.create_index(op.f("ix_collection_runs_status"), "collection_runs", ["status"])
    op.create_index(op.f("ix_collection_runs_started_at"), "collection_runs", ["started_at"])
    op.create_index(op.f("ix_collection_runs_completed_at"), "collection_runs", ["completed_at"])


def downgrade() -> None:
    op.drop_table("collection_runs")
