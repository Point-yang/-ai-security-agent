from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from zhidu.db import make_engine
from zhidu.models import Base


def test_initial_migration_roundtrip(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'migration.db'}"
    monkeypatch.setenv("ZHIDU_DATABASE_URL", url)
    config = Config(str(Path("alembic.ini").resolve()))
    command.upgrade(config, "head")
    engine = make_engine(url)
    assert set(inspect(engine).get_table_names()) == set(Base.metadata.tables) | {"alembic_version"}
    command.check(config)
    command.downgrade(config, "base")
    assert inspect(engine).get_table_names() == ["alembic_version"]
    command.upgrade(config, "head")
    assert "event_revisions" in inspect(engine).get_table_names()
    engine.dispose()
