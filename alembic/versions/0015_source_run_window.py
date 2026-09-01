"""Ventana que expuso la fuente en cada corrida.

Dos columnas nulables en `source_runs`: el tramo que el feed alcanzaba a
mostrar. Es lo que permite ajustar la cadencia de sondeo y el umbral de huecos
con datos medidos en vez de con una estimación de un día puntual.

Compatible hacia atrás: nulas en las filas históricas, ignoradas por el código
viejo. Bajar la revisión las borra sin tocar el resto de la telemetría.

Revision ID: 0015
Revises: 0014
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("source_runs") as batch:
        batch.add_column(sa.Column("window_from", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("window_to", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("source_runs") as batch:
        batch.drop_column("window_to")
        batch.drop_column("window_from")
