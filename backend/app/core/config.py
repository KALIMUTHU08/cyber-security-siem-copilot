from __future__ import annotations

import json
from typing import Any, List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# Production origin (Vercel deployment).  Included in defaults so the app
# works even when CORS_ORIGINS is not explicitly set in the environment.
# ---------------------------------------------------------------------------
_VERCEL_ORIGIN = "https://siem-copilot-tawny.vercel.app"

_DEFAULT_ORIGINS: List[str] = [
    _VERCEL_ORIGIN,
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
]


def _parse_cors_origins(raw: str) -> List[str]:
    """Parse CORS_ORIGINS from any env-var format without crashing.

    Accepts:
        JSON array  : '["https://example.com","http://localhost:5173"]'
        Bare URL    : 'https://example.com'
        CSV         : 'https://example.com,http://localhost:5173'

    Trailing slashes are stripped so browser-sent Origin headers match exactly.
    Returns the compiled default list when the string is empty.
    """
    raw = raw.strip()
    if not raw:
        return list(_DEFAULT_ORIGINS)

    # JSON array
    if raw.startswith("["):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(o).strip().rstrip("/") for o in parsed if str(o).strip()]
        except json.JSONDecodeError:
            pass  # fall through to comma-split

    # Comma-separated or single bare URL
    return [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]


class Settings(BaseSettings):
    PROJECT_NAME: str = "Cyber Security SIEM Copilot"
    API_V1_STR: str = "/api"
    DEBUG: bool = True

    # -----------------------------------------------------------------------
    # CORS
    # -----------------------------------------------------------------------
    # Declared as `str` (via validation_alias) so pydantic-settings reads it
    # as a plain string.  If it were typed as List[str] pydantic-settings
    # would attempt JSON.loads() before our code runs, crashing on bare URLs.
    #
    # Access the resolved list via settings.CORS_ORIGINS (a @property).
    # Set CORS_ORIGINS in Render dashboard as any of:
    #   '["https://siem-copilot-tawny.vercel.app"]'      JSON array
    #   'https://siem-copilot-tawny.vercel.app'           bare URL
    #   'https://example.com,http://localhost:5173'       comma-separated
    # The Vercel production origin is in the default so the app works even
    # when the env var is absent.
    # -----------------------------------------------------------------------
    cors_origins_str: str = Field(default="", validation_alias="CORS_ORIGINS")

    @property
    def CORS_ORIGINS(self) -> List[str]:
        """Parsed list of allowed origins for FastAPI CORSMiddleware."""
        return _parse_cors_origins(self.cors_origins_str)

    # Database (SQLite default; set DATABASE_URL for Postgres in production)
    DATABASE_URL: str = "sqlite:///./siem_copilot.db"

    # -----------------------------------------------------------------------
    # Authentication / JWT
    # -----------------------------------------------------------------------
    # IMPORTANT: Set a strong, random SECRET_KEY in production via environment
    # variable. The default below is ONLY for local development. Never commit
    # a real secret to source code.
    SECRET_KEY: str = "dev-insecure-change-me-set-SECRET_KEY-in-env"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Initial admin account seeded on first startup (empty DB only).
    # Supply real values via env vars; never hardcode credentials in source.
    DEFAULT_ADMIN_EMAIL: str = "admin@siem.local"
    DEFAULT_ADMIN_PASSWORD: str = ""  # MUST be set via DEFAULT_ADMIN_PASSWORD env var

    # Login brute-force protection: max failures before 5-minute lockout
    LOGIN_MAX_FAILURES: int = 5
    LOGIN_LOCKOUT_SECONDS: int = 300

    # Optional LLM (deterministic template fallback used when empty)
    OPENAI_API_KEY: str = ""
    OPENAI_BASE_URL: str = ""
    LLM_MODEL: str = "gpt-4o-mini"

    # Detection Rule Thresholds (Configurable)
    BRUTE_FORCE_THRESHOLD: int = 10
    BRUTE_FORCE_WINDOW_SECONDS: int = 60

    PORT_SCAN_PORT_THRESHOLD: int = 15
    PORT_SCAN_WINDOW_SECONDS: int = 30

    CREDENTIAL_SPRAY_USER_THRESHOLD: int = 5
    CREDENTIAL_SPRAY_WINDOW_SECONDS: int = 300

    DISTRIBUTED_ATTACK_IP_THRESHOLD: int = 3
    DISTRIBUTED_ATTACK_WINDOW_SECONDS: int = 600

    OFF_HOURS_START: int = 0   # 00:00
    OFF_HOURS_END: int = 6     # 06:00

    # Correlation Window (Minutes)
    INCIDENT_CORRELATION_WINDOW_MINUTES: int = 30

    model_config = SettingsConfigDict(
        populate_by_name=True,
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()