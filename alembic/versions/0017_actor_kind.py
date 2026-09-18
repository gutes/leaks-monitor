"""De qué universo viene cada actor de la adyacencia.

Hasta acá `adjacent_actors` tenía una sola población —bandas de ransomware con
data leak site, que es lo único que trae ransomware.live— y el score está
calibrado sobre esa cadencia. Con los foros y Telegram alimentando la sección
entran brokers de acceso y grupos hacktivistas, que publican de otra forma: un
post vendiendo acceso a cinco sistemas es UN post, no cinco víctimas.

Mezclarlos en un solo ranking haría que un vendedor ruidoso le ganara a LockBit
y que el score dijera algo distinto según la fila. La columna los separa en dos
carriles y deja que la UI los muestre aparte.

Las filas existentes quedan en `dls`: al 2026-09-18 todas las víctimas
regionales de la base vienen de ransomware.live, así que el backfill es exacto
y no una suposición.

Revision ID: 0017
Revises: 0016
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("adjacent_actors") as batch:
        batch.add_column(
            sa.Column("kind", sa.String(length=16), nullable=False, server_default="dls")
        )


def downgrade() -> None:
    with op.batch_alter_table("adjacent_actors") as batch:
        batch.drop_column("kind")
