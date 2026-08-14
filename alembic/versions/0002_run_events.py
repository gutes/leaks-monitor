"""Bitácora de actividad del pipeline (consola del frontend).

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-14
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "run_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("level", sa.String(length=16), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=True),
        sa.Column("message", sa.String(length=500), nullable=False),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("bytes_received", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_run_events_id_desc", "run_events", ["id"])
    op.create_index("ix_run_events_occurred_at", "run_events", ["occurred_at"])


def downgrade() -> None:
    op.drop_index("ix_run_events_occurred_at", table_name="run_events")
    op.drop_index("ix_run_events_id_desc", table_name="run_events")
    op.drop_table("run_events")
