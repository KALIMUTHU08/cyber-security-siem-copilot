"""
Configuration settings for the controlled dummy target application.
Safe, local-only configuration for demonstration of SIEM detection pipeline.
"""

import os
from pathlib import Path

# Load local .env if present
env_file = Path(__file__).parent / ".env"
if env_file.exists():
    with open(env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

# Configuration parameters
SIEM_INGEST_URL = os.getenv("SIEM_INGEST_URL", "http://127.0.0.1:8000/api/logs/upload")
DUMMY_APP_HOST = "127.0.0.1"  # Ground rule: STRICTLY local-only
DUMMY_APP_PORT = int(os.getenv("DUMMY_APP_PORT", "5000"))
AUTO_FORWARD = os.getenv("AUTO_FORWARD", "false").lower() in ("1", "true", "yes")
SIEM_API_TOKEN = os.getenv("SIEM_API_TOKEN", "")

# Local log storage path
LOG_DIR = Path(__file__).parent / "logs"
LOG_FILE = LOG_DIR / "dummy_app_events.jsonl"
