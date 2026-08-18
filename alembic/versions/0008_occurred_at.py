"""Antigüedad real del hallazgo, separada del día en que lo importamos.

Revision ID: 0008
Revises: 0007
Create Date: 2026-08-18
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("occurred_at_basis", sa.String(length=16), nullable=True))
    op.add_column(
        "findings",
        sa.Column("backfill", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_findings_occurred_at", "findings", ["occurred_at"])

    # Puesta al día de lo ya cargado.
    #
    # Las fuentes que sí fechan (ransomware.live, ransomlook, dls-monitor)
    # tienen en `discovered_at` la fecha de publicación real: se adopta como
    # `occurred_at` con base `feed`.
    op.execute(
        """
        UPDATE findings
           SET occurred_at = discovered_at,
               occurred_at_basis = 'feed'
         WHERE source <> 'hudsonrock'
        """
    )
    # Hudson Rock tenía la fecha de la consulta, no la del compromiso: era una
    # fecha inventada. Se deja sin fecha y la próxima corrida la resuelve bien.
    op.execute(
        """
        UPDATE findings
           SET occurred_at = NULL,
               occurred_at_basis = 'sin_dato'
         WHERE source = 'hudsonrock'
        """
    )


def downgrade() -> None:
    op.drop_index("ix_findings_occurred_at", table_name="findings")
    op.drop_column("findings", "backfill")
    op.drop_column("findings", "occurred_at_basis")
    op.drop_column("findings", "occurred_at")
