"""Hueco de cobertura por corrida y fuente.

Dos columnas nulables en `source_runs`: el tramo que la fuente publicó y que
nosotros no llegamos a ver. Nulo = sin hueco, que es el caso normal.

Compatible hacia atrás: el código viejo ignora las columnas nuevas y el nuevo
las lee como `NULL` en las filas históricas. Bajar la revisión las borra sin
tocar el resto de la telemetría.

Revision ID: 0014
Revises: 0013
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("source_runs") as batch:
        batch.add_column(sa.Column("gap_from", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("gap_to", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("source_runs") as batch:
        batch.drop_column("gap_to")
        batch.drop_column("gap_from")
