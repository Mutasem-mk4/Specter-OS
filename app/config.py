"""
Specter-OS — Configuration & Settings
Loads all environment variables with validation.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # LLM Provider
    llm_provider: str = Field(default="ollama", alias="LLM_PROVIDER") # "ollama" or "gemini"
    ollama_base_url: str = Field(default="http://localhost:11434", alias="OLLAMA_BASE_URL")
    gemini_api_key: str = Field(default="", alias="GEMINI_API_KEY")
    specter_llm_model: str = Field(default="llama3.1", alias="SPECTER_LLM_MODEL")

    # Server
    host: str = Field(default="0.0.0.0", alias="HOST")
    port: int = Field(default=8000, alias="PORT")
    debug: bool = Field(default=False, alias="DEBUG")

    # Database
    database_url: str = Field(
        default="sqlite+aiosqlite:///./specter.db",
        alias="DATABASE_URL",
    )

    # Security
    specter_secret_key: str = Field(
        default="change_me_in_production",
        alias="SPECTER_SECRET_KEY",
    )

    # Reports
    reports_dir: str = Field(default="./reports", alias="REPORTS_DIR")

    # Attack Configuration
    max_concurrent_attacks: int = Field(default=5, alias="MAX_CONCURRENT_ATTACKS")
    attack_turn_timeout: int = Field(default=30, alias="ATTACK_TURN_TIMEOUT")
    max_attack_turns: int = Field(default=10, alias="MAX_ATTACK_TURNS")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
