from logging.config import fileConfig
import os
import sys

from sqlalchemy import engine_from_config, pool
from alembic import context
from dotenv import load_dotenv

# ensure project root on path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# load environment variables from project .env for Alembic CLI usage on host
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

from app.database import Base
from app import models  # noqa: F401
from app.settings import settings

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# build DB URL from settings; allow override via ALEMBIC_DATABASE_URL when running on host
raw_url = os.getenv("ALEMBIC_DATABASE_URL") or str(settings.DATABASE_URL)
if "+asyncpg" in raw_url:
    raw_url = raw_url.replace("+asyncpg", "+psycopg")
config.set_main_option("sqlalchemy.url", raw_url)
url = raw_url


def run_migrations_offline() -> None:
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
