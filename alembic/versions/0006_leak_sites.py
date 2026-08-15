"""Catálogo de sitios de leaks y sus dominios.

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "leak_sites",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("group_name", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("fqdn", sa.String(length=255), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=True),
        sa.Column("available", sa.Boolean(), nullable=False),
        sa.Column("sources", sa.JSON(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_available_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("group_name", "fqdn", name="uq_leak_sites_group_fqdn"),
    )
    op.create_index("ix_leak_sites_group", "leak_sites", ["group_name"])
    op.create_index("ix_leak_sites_first_seen", "leak_sites", ["first_seen_at"])
    op.create_index("ix_leak_sites_available", "leak_sites", ["available"])


def downgrade() -> None:
    op.drop_table("leak_sites")
