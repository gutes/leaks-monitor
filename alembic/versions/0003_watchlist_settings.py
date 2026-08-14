"""Watchlist gestionable y configuración en caliente.

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-14
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "watchlist_entries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("sector", sa.String(length=64), nullable=False),
        sa.Column("label", sa.String(length=128), nullable=False),
        sa.Column("critical", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("origin", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("kind", "value", name="uq_watchlist_kind_value"),
    )
    op.create_index("ix_watchlist_sector", "watchlist_entries", ["sector"])
    op.create_index("ix_watchlist_enabled", "watchlist_entries", ["enabled"])

    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )


def downgrade() -> None:
    op.drop_table("app_settings")
    op.drop_index("ix_watchlist_enabled", table_name="watchlist_entries")
    op.drop_index("ix_watchlist_sector", table_name="watchlist_entries")
    op.drop_table("watchlist_entries")
