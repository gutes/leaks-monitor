"""Tablas de la sección de adyacencia.

Dos tablas nuevas y ninguna columna tocada en `findings`: la adyacencia es un
subsistema aparte y esta migración lo deja explícito. Bajar la revisión las
borra sin afectar en nada al pipeline argentino.

Revision ID: 0010
Revises: 0009
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "regional_victims",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("country", sa.String(length=2), nullable=False),
        sa.Column("victim_name", sa.String(length=512), nullable=False),
        sa.Column("victim_domain", sa.String(length=255), nullable=True),
        sa.Column("sector", sa.String(length=128), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "actor", "country", "victim_name", "occurred_at", name="uq_regional_victim"
        ),
    )
    op.create_index("ix_regional_victims_actor", "regional_victims", ["actor"])
    op.create_index("ix_regional_victims_country", "regional_victims", ["country"])
    op.create_index("ix_regional_victims_occurred", "regional_victims", ["occurred_at"])

    op.create_table(
        "adjacent_actors",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor", sa.String(length=128), nullable=False, unique=True),
        sa.Column("victims_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("countries", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("hit_ar", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("ar_victims", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("score_breakdown", sa.JSON(), nullable=False),
        sa.Column("score_prev", sa.Float(), nullable=True),
        sa.Column("score_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("alerted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_adjacent_actors_score", "adjacent_actors", ["score"])
    op.create_index("ix_adjacent_actors_hit_ar", "adjacent_actors", ["hit_ar"])


def downgrade() -> None:
    op.drop_table("adjacent_actors")
    op.drop_table("regional_victims")
