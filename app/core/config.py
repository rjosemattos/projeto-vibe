"""Configuration settings for Prompt Sanitizer."""

from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    model_config = SettingsConfigDict(
        env_prefix="PROMPT_SANITIZER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "Prompt Sanitizer"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Payload and input safety limits
    MAX_PAYLOAD_BYTES: int = 51200  # 50 KB max request body
    MAX_PROMPT_LENGTH: int = 50000  # 50,000 chars max prompt length

    # Security settings
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost",
        "http://localhost:8000",
        "http://127.0.0.1",
        "http://127.0.0.1:8000",
    ]

    # Logging
    LOG_LEVEL: str = "INFO"

    # Encryption and Privacy Settings
    ENCRYPTION_KEY: str = ""
    BLIND_INDEX_KEY: str = ""


settings = Settings()

# Keep CORS aligned with a custom PORT (the web UI is same-origin, but this avoids surprises)
for _origin in (f"http://localhost:{settings.PORT}", f"http://127.0.0.1:{settings.PORT}"):
    if _origin not in settings.ALLOWED_ORIGINS:
        settings.ALLOWED_ORIGINS.append(_origin)

