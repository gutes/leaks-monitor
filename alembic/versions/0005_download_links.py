"""Enlaces a los datos filtrados por hallazgo.

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("download_links", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "download_links")
