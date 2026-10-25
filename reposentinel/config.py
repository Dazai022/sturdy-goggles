from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment and an optional .env file."""

    model_config = SettingsConfigDict(
        env_prefix="REPOSENTINEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        enable_decoding=False,
    )

    database_path: Path = Path("reposentinel.db")
    github_token: SecretStr | None = None
    allowed_repositories: list[str] = Field(default_factory=list)
    github_api_url: str = "https://api.github.com"
    timezone: str = "Asia/Kolkata"
    schedule_start: str = "19:00"
    schedule_end: str = "23:00"
    ollama_endpoint: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5-coder:3b"
    ollama_timeout_seconds: float = 120.0
    ollama_max_retries: int = 2
    ollama_retry_backoff_seconds: float = 0.5
    analysis_max_source_bytes: int = 200_000
    github_timeout_seconds: float = 30.0
    scan_max_files: int = 100
    scan_max_file_bytes: int = 100_000
    scan_max_source_bytes: int = 2_000_000
    scan_stale_after_seconds: float = 900.0
    proposal_max_diff_bytes: int = 100_000
    supported_source_extensions: list[str] = Field(default_factory=lambda: [
        ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs", ".rb", ".php", ".cs", ".cpp", ".c",
    ])

    @field_validator("allowed_repositories", mode="before")
    @classmethod
    def parse_repositories(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip().lower() for item in value.split(",") if item.strip()]
        return value

    @field_validator("supported_source_extensions", mode="before")
    @classmethod
    def parse_extensions(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip().lower() for item in value.split(",") if item.strip()]
        return value

    @field_validator("github_api_url")
    @classmethod
    def validate_api_url(cls, value: str) -> str:
        return value.rstrip("/")

    @field_validator("ollama_endpoint")
    @classmethod
    def validate_ollama_endpoint(cls, value: str) -> str:
        return value.rstrip("/")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
