"""Alembic environment. Migrations are raw-SQL revisions (op.execute) so the
expand/contract steps are explicit and reviewable. Offline mode
(`alembic upgrade head --sql`) renders the full DDL without a live database,
which is how the chain is validated in environments without Postgres."""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

url = (
    os.environ.get("SOC_DATABASE_URL")
    or config.get_main_option("sqlalchemy.url")
    or "postgresql+psycopg://soc:soc-local-dev@localhost:15432/soc_triage"
)


def run_migrations_offline() -> None:
    context.configure(
        url=url,
        target_metadata=None,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    cfg = config.get_section(config.config_ini_section, {})
    cfg["sqlalchemy.url"] = url
    connectable = engine_from_config(cfg, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=None)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
