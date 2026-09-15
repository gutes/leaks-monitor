"""Tipo de la taxonomía del CERT.ar por hallazgo.

Dos columnas nulables en `findings`: el slug del tipo y por qué se asignó. La
clasificación y el nivel de criticidad NO se guardan — se derivan del catálogo
(`leaks.taxonomy.cert_ar`), así que si el CERT publica otra versión de la guía
no quedan filas viejas contradiciendo la tabla vigente.

Nulas en las filas históricas hasta que corra el backfill. Compatible hacia
atrás: el código viejo las ignora.

Revision ID: 0016
Revises: 0015
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("taxonomy_type", sa.String(length=48), nullable=True))
        batch.add_column(sa.Column("taxonomy_basis", sa.String(length=160), nullable=True))
    op.create_index("ix_findings_taxonomy_type", "findings", ["taxonomy_type"])


def downgrade() -> None:
    op.drop_index("ix_findings_taxonomy_type", table_name="findings")
    with op.batch_alter_table("findings") as batch:
        batch.drop_column("taxonomy_basis")
        batch.drop_column("taxonomy_type")
