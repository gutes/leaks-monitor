"""Consolida los hallazgos de Hudson Rock duplicados por corrida.

El adapter fechaba con `now()` y `compute_dedup_hash` usa
`discovered_at.date()`, así que cada día que se consultaba el mismo dominio
nacía un hallazgo nuevo. Una sola corrida dejó 13 dominios con dos filas.

El adapter ya usa la fecha que declara el proveedor, con lo cual no se vuelven
a generar. Esta migración limpia los que quedaron.

Criterio: por cada `(source, victim_domain)` se conserva **la fila más rica** —
la que tiene detalle de exposición, y entre esas la más reciente— y se le
traslada el `first_seen_at` más viejo del grupo, para no perder desde cuándo lo
venimos observando. Las demás se borran.

Solo toca `source = 'hudsonrock'`: los otros feeds fechan de verdad y ahí dos
filas del mismo dominio en días distintos son dos publicaciones distintas.

Revision ID: 0013
Revises: 0012
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    conexion = op.get_bind()

    grupos = conexion.execute(
        sa.text(
            "SELECT victim_domain FROM findings "
            "WHERE source = 'hudsonrock' AND victim_domain IS NOT NULL "
            "GROUP BY victim_domain HAVING COUNT(*) > 1"
        )
    ).fetchall()

    for (dominio,) in grupos:
        filas = conexion.execute(
            sa.text(
                "SELECT id, first_seen_at, exposure_detail IS NOT NULL AS rica "
                "FROM findings WHERE source = 'hudsonrock' AND victim_domain = :d "
                "ORDER BY rica DESC, discovered_at DESC, id DESC"
            ),
            {"d": dominio},
        ).fetchall()
        if len(filas) < 2:
            continue

        conservada = filas[0]
        primero = min(f.first_seen_at for f in filas if f.first_seen_at is not None)

        conexion.execute(
            sa.text("UPDATE findings SET first_seen_at = :f WHERE id = :i"),
            {"f": primero, "i": conservada.id},
        )
        conexion.execute(
            sa.text("DELETE FROM findings WHERE id IN :ids").bindparams(
                sa.bindparam("ids", expanding=True)
            ),
            {"ids": [f.id for f in filas[1:]]},
        )


def downgrade() -> None:
    """No se puede deshacer: las filas borradas eran duplicados sin dato propio."""
