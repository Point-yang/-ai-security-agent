from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ZHIDU_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./data/zhidu.db"
    monitor_config: Path = Path("config/sources.json")
    raw_dir: Path = Path("data/raw")
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    embedding_cache: Path = Path("data/models")
    embedding_manifest: Path = Path("data/models/manifest.json")
    rag_config: Path = Path("config/member-b-week6-router-v2.json")
    llm_provider: Literal["extractive", "deepseek", "model"] = "extractive"
    deepseek_api_key: SecretStr = SecretStr("")
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-v4-flash"
    deepseek_timeout_seconds: float = Field(default=30, ge=1, le=120)
    deepseek_max_tokens: int = Field(default=1800, ge=256, le=8192)
    llm_temperature: float = Field(default=0, ge=0, le=2)
    agent_backend: Literal["legacy", "langchain", "workflow", "auto", "team"] = "workflow"
    agent_max_model_calls: int = Field(default=5, ge=1, le=8)
    agent_max_tool_calls: int = Field(default=6, ge=1, le=6)
    agent_max_output_chars: int = Field(default=24000, ge=1000, le=24000)
    agent_deadline_seconds: float = Field(default=30, ge=1, le=60)
    agent_final_reserve_seconds: float = Field(default=8, ge=1, le=30)
    agent_model_provider: Literal["deepseek", "openai_compatible", "ollama"] = "deepseek"
    agent_model_name: str | None = None
    agent_model_base_url: str | None = None
    agent_model_api_key: SecretStr = SecretStr("")
    agent_checkpoint_path: Path = Path("data/agent-checkpoints.sqlite")
    model_pricing_path: Path = Path("config/model-pricing.json")
    submission_evidence_path: Path = Path("config/submission-evidence.json")
    rag_turn_lease_seconds: float = Field(default=180, ge=30, le=900)
    rag_turn_duplicate_wait_seconds: float = Field(default=2, ge=0, le=30)
    human_review_dir: Path = Path("data/week6-human-review")
    github_token: SecretStr = SecretStr("")
    github_api_version: str = "2026-03-10"
    admin_key: SecretStr = SecretStr("")
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
