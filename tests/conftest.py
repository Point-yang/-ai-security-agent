import json
from pathlib import Path

import pytest

from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.models import Base
from zhidu.storage import BlobStore


@pytest.fixture
def require_historic_files():
    """Historical corpus snapshots are optional in the portable source release."""

    def require(*paths):
        missing = [str(path) for path in paths if not Path(path).exists()]
        if missing:
            pytest.skip("Historical snapshot files not bundled: " + ", ".join(missing))

    return require


@pytest.fixture
def settings(tmp_path):
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        raw_dir=tmp_path / "raw",
        agent_checkpoint_path=tmp_path / "agent-checkpoints.sqlite",
        admin_key="test-admin",
        github_token="",
        llm_provider="extractive",
        deepseek_api_key="",
    )


@pytest.fixture
def database(settings):
    engine = make_engine(settings.database_url)
    Base.metadata.create_all(engine)
    yield make_sessions(engine)
    engine.dispose()


@pytest.fixture
def store(settings):
    return BlobStore(settings.raw_dir)


@pytest.fixture
def advisory():
    return json.loads(Path("examples/ghsa-demo-v1.json").read_text())
