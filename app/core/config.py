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

    # Authentication (hosted mode). When disabled, the app behaves as a local single-user tool.
    AUTH_ENABLED: bool = False
    DB_PATH: str = ""  # defaults to <data dir>/app.db
    SESSION_IDLE_MINUTES: int = 30
    SESSION_MAX_HOURS: int = 12
    COOKIE_SECURE: bool = True  # set False only for plain-HTTP local testing of auth
    MIN_PASSWORD_LENGTH: int = 12
    MAX_FAILED_LOGINS: int = 5
    LOCKOUT_MINUTES: int = 15
    RATE_LIMIT_LOGIN_PER_MIN: int = 10
    RATE_LIMIT_API_PER_MIN: int = 120
    TRUST_PROXY_HEADERS: bool = False  # honor X-Forwarded-For (only behind your own reverse proxy)
    ALLOWED_HOSTS: List[str] = ["*"]

    # Encryption and Privacy Settings
    ENCRYPTION_KEY: str = ""
    BLIND_INDEX_KEY: str = ""

    # Supabase & PostgreSQL (Vercel / Cloud Deployment)
    DATABASE_URL: str = ""
    SUPABASE_URL: str = ""
    SUPABASE_ANON_KEY: str = ""
    SUPABASE_JWT_SECRET: str = ""
    ALLOWED_EMAIL_DOMAINS: List[str] = ["cesar.school"]


settings = Settings()

import os
# Allow standard un-prefixed cloud env vars (e.g. Supabase and Vercel defaults)
if not settings.DATABASE_URL:
    settings.DATABASE_URL = os.getenv("DATABASE_URL", "")
if not settings.SUPABASE_URL:
    settings.SUPABASE_URL = os.getenv("SUPABASE_URL", os.getenv("NEXT_PUBLIC_SUPABASE_URL", ""))
if not settings.SUPABASE_ANON_KEY:
    settings.SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY", ""))
if not settings.SUPABASE_JWT_SECRET:
    settings.SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "")
if os.getenv("ALLOWED_EMAIL_DOMAINS"):
    settings.ALLOWED_EMAIL_DOMAINS = [d.strip().lower() for d in os.getenv("ALLOWED_EMAIL_DOMAINS", "").split(",") if d.strip()]

# Keep CORS aligned with a custom PORT (the web UI is same-origin, but this avoids surprises)
for _origin in (f"http://localhost:{settings.PORT}", f"http://127.0.0.1:{settings.PORT}"):
    if _origin not in settings.ALLOWED_ORIGINS:
        settings.ALLOWED_ORIGINS.append(_origin)

