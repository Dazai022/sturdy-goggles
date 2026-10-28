from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, field_validator, model_validator
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
    api_token: SecretStr | None = None
    github_app_slug: str | None = None
    github_app_id: int | None = None
    github_app_private_key: SecretStr | None = None
    github_app_private_key_path: Path | None = None
    github_app_client_id: str | None = None
    github_app_client_credential: SecretStr | None = None
    github_app_oauth_redirect_uri: str | None = None
    github_app_redirect_uri: str | None = None
    github_oauth_client_id: str | None = None
    github_oauth_client_credential: SecretStr | None = None
    github_oauth_redirect_uri: str | None = None
    github_oauth_url: str = "https://github.com"
    github_token_encryption_key: SecretStr | None = None
    github_app_state_key: SecretStr | None = None
    github_app_token_skew_seconds: int = 60
    github_app_max_retries: int = 2
    github_app_retry_backoff_seconds: float = 0.5
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

    @field_validator("github_app_id")
    @classmethod
    def validate_app_id(cls, value: int | None) -> int | None:
        if value is not None and value <= 0:
            raise ValueError("github_app_id must be positive")
        return value

    @field_validator("github_app_token_skew_seconds")
    @classmethod
    def validate_token_skew(cls, value: int) -> int:
        if not 1 <= value <= 600:
            raise ValueError("github_app_token_skew_seconds must be between 1 and 600")
        return value

    @field_validator("github_app_max_retries")
    @classmethod
    def validate_app_retries(cls, value: int) -> int:
        if not 0 <= value <= 5:
            raise ValueError("github_app_max_retries must be between 0 and 5")
        return value

    @model_validator(mode="after")
    def validate_github_app_user_auth(self) -> "Settings":
        if self.github_app_client_id or self.github_app_client_credential:
            if not self.github_app_client_id or not self.github_app_client_credential:
                raise ValueError("GitHub App client ID and client credential must be configured together")
            if not self.github_app_oauth_redirect_uri:
                raise ValueError("github_app_oauth_redirect_uri is required for GitHub App user authorization")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
