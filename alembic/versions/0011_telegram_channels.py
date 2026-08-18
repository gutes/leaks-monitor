"""Canales de Telegram bajo vigilancia.

Tabla nueva, ninguna existente tocada. Bajar la revisión la borra sin afectar
al resto del pipeline.

Revision ID: 0011
Revises: 0010
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "telegram_channels",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("handle", sa.String(length=128), nullable=False, unique=True),
        sa.Column("actor", sa.String(length=128), nullable=True),
        sa.Column("kind", sa.String(length=64), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("origin", sa.String(length=16), nullable=False, server_default="user"),
        # Deshabilitado por defecto: importar un catálogo no puede convertirse
        # en cientos de pedidos que nadie pidió.
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_post_id", sa.String(length=160), nullable=True),
        sa.Column("last_fetch_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_telegram_channels_enabled", "telegram_channels", ["enabled"])
    op.create_index("ix_telegram_channels_actor", "telegram_channels", ["actor"])


def downgrade() -> None:
    op.drop_table("telegram_channels")
