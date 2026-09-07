import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

APP_NAME = "ShieldWAF"
APP_VERSION = "1.0.0"

DB_PATH = os.environ.get("SHIELDWAF_DB_PATH", str(BASE_DIR / "shieldwaf.db"))
CORS_ORIGINS = os.environ.get("SHIELDWAF_CORS_ORIGINS", "http://localhost:5173").split(",")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")

# The upstream application this WAF protects when run as a reverse proxy.
UPSTREAM_TARGET = os.environ.get("SHIELDWAF_UPSTREAM", "http://localhost:9000")
