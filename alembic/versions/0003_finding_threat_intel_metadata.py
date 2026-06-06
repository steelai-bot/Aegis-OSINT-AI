"""add threat intelligence metadata to findings

Revision ID: 0003_finding_threat_intel_metadata
Revises: 0002_agent_persistence
Create Date: 2026-06-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0003_finding_threat_intel_metadata"
down_revision: str | None = "0002_agent_persistence"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("threat_category", sa.String(length=50), nullable=False, server_default="unknown"))
    op.add_column("findings", sa.Column("indicator_type", sa.String(length=50), nullable=False, server_default="unknown"))
    op.add_column("findings", sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("breach_date", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("threat_actor", sa.String(length=255), nullable=True))
    op.add_column("findings", sa.Column("campaign_id", sa.String(length=255), nullable=True))
    op.add_column("findings", sa.Column("source_url", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("collector_plugin", sa.String(length=100), nullable=False, server_default=""))
    op.add_column(
        "findings",
        sa.Column("raw_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.add_column("findings", sa.Column("enriched", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column(
        "findings",
        sa.Column("enrichment_data", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.add_column("findings", sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"))
    op.add_column("findings", sa.Column("exploitability", sa.String(length=20), nullable=False, server_default="unknown"))
    op.add_column("findings", sa.Column("remediation_status", sa.String(length=30), nullable=False, server_default="open"))
    op.add_column("findings", sa.Column("remediation_notes", sa.Text(), nullable=True))

    op.execute("UPDATE findings SET first_seen = created_at WHERE first_seen IS NULL")
    op.execute("UPDATE findings SET last_seen = updated_at WHERE last_seen IS NULL")
    op.alter_column("findings", "first_seen", nullable=False)
    op.alter_column("findings", "last_seen", nullable=False)

    for column_name in (
        "threat_category",
        "indicator_type",
        "first_seen",
        "last_seen",
        "breach_date",
        "threat_actor",
        "campaign_id",
        "collector_plugin",
        "enriched",
        "risk_score",
        "remediation_status",
    ):
        op.create_index(op.f(f"ix_findings_{column_name}"), "findings", [column_name])

    for column_name in (
        "threat_category",
        "indicator_type",
        "collector_plugin",
        "raw_evidence",
        "enriched",
        "enrichment_data",
        "risk_score",
        "exploitability",
        "remediation_status",
    ):
        op.alter_column("findings", column_name, server_default=None)


def downgrade() -> None:
    for column_name in (
        "remediation_status",
        "risk_score",
        "enriched",
        "collector_plugin",
        "campaign_id",
        "threat_actor",
        "breach_date",
        "last_seen",
        "first_seen",
        "indicator_type",
        "threat_category",
    ):
        op.drop_index(op.f(f"ix_findings_{column_name}"), table_name="findings")

    for column_name in (
        "remediation_notes",
        "remediation_status",
        "exploitability",
        "risk_score",
        "enrichment_data",
        "enriched",
        "raw_evidence",
        "collector_plugin",
        "source_url",
        "campaign_id",
        "threat_actor",
        "breach_date",
        "last_seen",
        "first_seen",
        "indicator_type",
        "threat_category",
    ):
        op.drop_column("findings", column_name)