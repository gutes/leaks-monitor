"""Marca de alerta enviada por hallazgo.

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("alerted_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_findings_alerted_at", "findings", ["alerted_at"])


def downgrade() -> None:
    op.drop_index("ix_findings_alerted_at", table_name="findings")
    op.drop_column("findings", "alerted_at")
