from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Cyber Security SIEM Copilot"
    API_V1_STR: str = "/api"
    DEBUG: bool = True
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
    ]
    
    # Database (SQLite default)
    DATABASE_URL: str = "sqlite:///./siem_copilot.db"
    
    # Optional LLM
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
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
