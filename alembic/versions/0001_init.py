"""Schema inicial: findings, source_runs, source_state, pii_records.

Revision ID: 0001
Revises:
Create Date: 2026-08-14
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("dedup_hash", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("leak_type", sa.String(length=32), nullable=False),
        sa.Column("victim_name", sa.String(length=512), nullable=False),
        sa.Column("victim_domain", sa.String(length=255), nullable=True),
        sa.Column("country", sa.String(length=64), nullable=True),
        sa.Column("sector", sa.String(length=128), nullable=True),
        sa.Column("actor", sa.String(length=128), nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("raw_ref", sa.Text(), nullable=True),
        sa.Column("ar_match_reason", sa.JSON(), nullable=False),
        sa.Column("ar_match_detail", sa.JSON(), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("dedup_hash", name="uq_findings_dedup_hash"),
    )
    op.create_index("ix_findings_discovered_at", "findings", ["discovered_at"])
    op.create_index("ix_findings_source", "findings", ["source"])
    op.create_index("ix_findings_sector", "findings", ["sector"])
    op.create_index("ix_findings_actor", "findings", ["actor"])
    op.create_index("ix_findings_severity", "findings", ["severity"])

    op.create_table(
        "source_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("items_fetched", sa.Integer(), nullable=False),
        sa.Column("items_matched", sa.Integer(), nullable=False),
        sa.Column("items_persisted", sa.Integer(), nullable=False),
        sa.Column("error", sa.String(length=500), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_source_runs_source_started", "source_runs", ["source", "started_at"])

    op.create_table(
        "source_state",
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("cursor", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("source"),
    )

    # Tabla separada y cifrada. Queda creada siempre, pero solo se escribe con
    # STORE_PII=true (ver src/leaks/privacy/).
    op.create_table(
        "pii_records",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("payload_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_pii_records_finding", "pii_records", ["finding_id"])
    op.create_index("ix_pii_records_expires", "pii_records", ["expires_at"])


def downgrade() -> None:
    op.drop_table("pii_records")
    op.drop_table("source_state")
    op.drop_table("source_runs")
    op.drop_table("findings")
