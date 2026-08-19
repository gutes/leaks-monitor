"""Marca de infraestructura crítica en las víctimas regionales.

Aditiva y nullable-friendly: las filas existentes quedan en `false` y la
primera corrida las reclasifica contra `data/watchlist-regional/`.

Revision ID: 0012
Revises: 0011
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "regional_victims",
        sa.Column("critical", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "regional_victims", sa.Column("regional_sector", sa.String(length=64), nullable=True)
    )
    op.create_index("ix_regional_victims_critical", "regional_victims", ["critical"])


def downgrade() -> None:
    op.drop_index("ix_regional_victims_critical", table_name="regional_victims")
    op.drop_column("regional_victims", "regional_sector")
    op.drop_column("regional_victims", "critical")
