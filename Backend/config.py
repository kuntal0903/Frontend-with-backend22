"""
Configuration Settings

WHY THIS FILE EXISTS:
    Central configuration management for the entire application.
    All tuneable parameters live here — no hardcoded values anywhere else.

WHAT IT DOES:
    - Loads settings from environment variables / .env file
    - Provides typed, validated configuration via Pydantic BaseSettings
    - Exposes domain-module-specific settings (timeouts, concurrency, ports)

DESIGN:
    Single Settings instance is created at module load time.
    All other modules import `settings` — never read env vars directly.
"""
import os
from typing import List
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application-wide configuration loaded from environment or .env file."""

    # ── Application ──────────────────────────────────────────────────
    PROJECT_NAME: str = "ASM Platform"
    VERSION: str = "1.0.0"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    API_V1_PREFIX: str = "/api/v1"

    # ── Database ─────────────────────────────────────────────────────
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite+aiosqlite:////tmp/asm.db" if os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME") else "sqlite+aiosqlite:///./asm.db"
    )

    # ── Domain Scan Settings ─────────────────────────────────────────
    SCAN_TIMEOUT_SECONDS: int = 300          # Max total scan duration
    COLLECTOR_TIMEOUT_SECONDS: int = 30      # Per-collector timeout
    MAX_CONCURRENT_COLLECTORS: int = 10      # asyncio.Semaphore limit
    HTTP_REQUEST_TIMEOUT: int = 15           # aiohttp per-request timeout

    # ── User-Agent for outbound requests ─────────────────────────────
    USER_AGENT: str = (
        "Mozilla/5.0 (compatible; ASMBot/1.0; "
        "+https://github.com/asm-platform)"
    )

    # ── Port Scanning ────────────────────────────────────────────────
    DEFAULT_PORTS: List[int] = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        465, 587, 993, 995, 1433, 1521, 2049, 2083, 2087, 2096,
        3306, 3389, 5432, 5900, 6379, 8000, 8008, 8080, 8443, 8888,
        9090, 9200, 9300, 27017,
    ]
    PORT_SCAN_CONCURRENCY: int = 50          # Semaphore for port checks
    PORT_CONNECT_TIMEOUT: float = 3.0        # Per-port TCP timeout
    BANNER_READ_TIMEOUT: float = 2.0         # Service banner grab

    # ── Subdomain Discovery ──────────────────────────────────────────
    SUBDOMAIN_BRUTEFORCE_ENABLED: bool = True
    SUBDOMAIN_WORDLIST_SIZE: str = "small"   # small | medium | large

    # ── CORS ─────────────────────────────────────────────────────────
    CORS_ORIGINS: List[str] = ["*"]

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


settings = Settings()
